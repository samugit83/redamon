"""
GHSA-6x4h-rj84-v2fm: the scanner key ran a command in the agent container.

Up to 7.7.2, `/mcp/test` and `/mcp/reload` took `require_internal_auth_only`, which
accepts SCANNER_API_KEY, the key every target-facing scan container holds. With it,
`/mcp/test` spawned a caller-chosen stdio command inside the agent (root, holding
the master, Postgres and Neo4j credentials) and re-spawned it with `os.environ` for
its diagnostic, returning the child's stderr: the reporter's proof of concept read
`INTERNAL_API_KEY` back in the HTTP answer. `/mcp/reload` replaced the MCP server set
of the agent every user shares.

These tests replay the reporter's two requests against the real handlers and a real
child process. The child also appends to a marker file, so a refusal is proven to
spawn nothing, and the master-key replay (which must run it) shows the file would
catch a spawn. Reported by @mappygrid.
"""
import os
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "dummy-master-key-ghsa-6x4h"
SCANNER = "dummy-scanner-key-ghsa-6x4h"
KEYS = {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}

# The reporter's child, verbatim, after one added statement that records the spawn.
POC_CODE = (
    "import os,sys;open(sys.argv[1],'a').write('ran\\n');"
    "sys.stderr.write('TEST-MARKER '+os.environ.get('INTERNAL_API_KEY','<none>'));sys.exit(1)"
)

with patch.dict(os.environ, KEYS):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402
import llm_guard  # noqa: E402
import machine_credential as mc  # noqa: E402


def _poc_test_body(marker: str) -> dict:
    return {
        "id": "scanner_probe", "name": "scanner probe", "transport": "stdio",
        "command": sys.executable, "args": ["-c", POC_CODE, marker], "enabled": True,
    }


def _poc_reload_body() -> dict:
    return {"userMcpServers": [{
        "id": "test_server", "name": "test server", "transport": "stdio",
        "command": "python3", "args": ["-c", "import sys;sys.stderr.write('test')"],
        "enabled": True,
    }]}


def _scan_container_headers() -> dict:
    """Every credential a scan container can present: the scanner key, its scan's job
    credential and a sandbox run credential, all validly signed."""
    far = 4_102_444_800
    job = mc.mint({"aud": "scan", "ten": "u1", "pid": "p1", "job": "j1", "exp": far},
                  mc.derive_key(MASTER, mc.JOB_CREDENTIAL_LABEL))
    run = mc.mint({"aud": "graph", "ten": "u1", "pid": "p1", "run": "r1", "exp": far},
                  mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL))
    return {"x-internal-key": SCANNER, "x-redamon-job": job, "x-redamon-run": run}


REFUSED_CALLERS = {
    "scanner key": {"x-internal-key": SCANNER},
    "scan container's whole credential set": _scan_container_headers(),
    "no key": {},
    "wrong key": {"x-internal-key": "wrong"},
}


class _FakeOrchestrator:
    def __init__(self):
        self.reloads = []

    async def reload_mcp_manifests(self, user_servers_raw=None, owner_id=None):
        self.reloads.append((user_servers_raw, owner_id))
        return {"servers": [], "loaded": True}


class _Agent(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, KEYS)
        env.start()
        self.addCleanup(env.stop)
        llm_guard.reset_state()
        self.orchestrator = _FakeOrchestrator()
        orch = patch.object(api, "orchestrator", self.orchestrator)
        orch.start()
        self.addCleanup(orch.stop)
        from fastapi.testclient import TestClient
        self.client = TestClient(api.app)
        self.fresh()

    def fresh(self):
        """A new marker and no recorded reload, so each subtest judges only its own call."""
        out_dir = tempfile.mkdtemp(prefix="ghsa-6x4h-")
        # The stdio launcher may start the child as an unprivileged user (GHSA-8whg):
        # a 0700 directory of root's would hide every spawn from the marker.
        os.chmod(out_dir, 0o777)
        self.marker = os.path.join(out_dir, "spawned")
        self.orchestrator.reloads.clear()

    def spawns(self) -> int:
        try:
            return Path(self.marker).read_text().count("ran")
        except FileNotFoundError:
            return 0


class ScannerKeyIsAKnownCredentialTests(_Agent):
    def test_the_scanner_key_is_one_the_agent_recognises(self):
        """So each 401 below is the route's decision, not an unknown key."""
        self.assertTrue(llm_guard._key_ok(SCANNER))
        self.assertNotEqual(SCANNER, MASTER)


class McpTestPocTests(_Agent):
    def test_the_reporters_request_is_refused_and_spawns_nothing(self):
        for who, headers in REFUSED_CALLERS.items():
            with self.subTest(caller=who):
                self.fresh()
                r = self.client.post("/mcp/test", json=_poc_test_body(self.marker), headers=headers)
                self.assertEqual(r.status_code, 401, r.text)
                self.assertNotIn("TEST-MARKER", r.text)
                self.assertNotIn(MASTER, r.text)
                self.assertEqual(self.spawns(), 0, "the draft's command ran")

    def test_without_a_master_key_the_route_is_closed_to_the_scanner_key(self):
        for weak in ("", "changeme"):
            with self.subTest(master=weak or "<unset>"), patch.dict(os.environ, {"INTERNAL_API_KEY": weak}):
                self.fresh()
                r = self.client.post("/mcp/test", json=_poc_test_body(self.marker),
                                     headers={"x-internal-key": SCANNER})
                self.assertEqual(r.status_code, 503, r.text)
                self.assertEqual(self.spawns(), 0)

    def test_the_master_key_runs_it_and_the_child_never_holds_the_master_key(self):
        r = self.client.post("/mcp/test", json=_poc_test_body(self.marker),
                             headers={"x-internal-key": MASTER})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["ok"])
        # The client spawn and the diagnostic re-spawn: the marker does see spawns.
        self.assertEqual(self.spawns(), 2, body)
        # The diagnostic still returns the child's stderr, and that child had no key.
        self.assertIn("TEST-MARKER <none>", body["error"])
        self.assertNotIn(MASTER, r.text)
        self.assertNotIn(SCANNER, r.text)


class McpReloadPocTests(_Agent):
    def test_the_reporters_request_is_refused_and_the_shared_toolset_is_untouched(self):
        for who, headers in REFUSED_CALLERS.items():
            with self.subTest(caller=who):
                self.fresh()
                r = self.client.post("/mcp/reload", json=_poc_reload_body(), headers=headers)
                self.assertEqual(r.status_code, 401, r.text)
                self.assertEqual(self.orchestrator.reloads, [])

    def test_the_master_key_reaches_the_orchestrator(self):
        body = _poc_reload_body()
        r = self.client.post("/mcp/reload", json=body, headers={"x-internal-key": MASTER})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orchestrator.reloads, [(body["userMcpServers"], None)])


class McpManifestTests(_Agent):
    def test_the_manifest_refuses_every_scan_container_credential(self):
        for who, headers in REFUSED_CALLERS.items():
            with self.subTest(caller=who):
                self.assertEqual(self.client.get("/mcp/manifest", headers=headers).status_code, 401)
        self.assertEqual(
            self.client.get("/mcp/manifest", headers={"x-internal-key": MASTER}).status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)

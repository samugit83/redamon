"""
The agent routes whose open use is code execution or another tenant's data are
master-key only and FAIL-CLOSED: the workspace file API, the Metasploit session
proxy and agent-session stop.

The agent port is published on 0.0.0.0:8090. Before this gate any host that
could reach it read, wrote and deleted every project's workspace, and sent
commands into the operator's Metasploit sessions (and, through a newline, to
the kali-sandbox shell). The kali-sandbox holds the SCANNER key and faces the
target, so that key must not open these routes either.

Run in-container: ./agentic/run_tests.sh tests/test_agent_route_auth.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

import api  # noqa: E402
import workspace_fs  # noqa: E402
from llm_guard import require_configured_master_auth  # noqa: E402

MASTER = "master-key-for-test"
SCANNER = "scanner-key-for-test"

LOCKED_ROUTES = {
    ("POST", "/agent-session/stop"),
    ("GET", "/workspace/list"),
    ("GET", "/workspace/tree"),
    ("GET", "/workspace/download"),
    ("POST", "/workspace/rename"),
    ("DELETE", "/workspace"),
    ("POST", "/workspace/reset"),
    ("GET", "/workspace/jobs"),
    ("POST", "/workspace/jobs/{job_id}/cancel"),
    ("GET", "/workspace/jobs/{job_id}"),
    ("POST", "/workspace/upload-sessions"),
    ("PUT", "/workspace/upload-sessions/{upload_id}/chunk"),
    ("POST", "/workspace/upload-sessions/{upload_id}/commit"),
    ("DELETE", "/workspace/upload-sessions/{upload_id}"),
    ("POST", "/workspace/project-purge"),
    ("POST", "/workspace/import-url/resolve"),
    ("POST", "/workspace/import-url"),
    ("POST", "/workspace/import-url/resync"),
    ("POST", "/workspace/upload"),
    ("POST", "/workspace/mkdir"),
    ("POST", "/workspace/bulk-archive"),
    ("GET", "/workspace/archive-download"),
    ("GET", "/workspace/preview"),
    ("GET", "/workspace/properties"),
    ("GET", "/sessions"),
    ("POST", "/sessions/{session_id}/interact"),
    ("POST", "/sessions/{session_id}/kill"),
    ("POST", "/jobs/{job_id}/kill"),
    ("POST", "/session-chat-map"),
    ("POST", "/non-msf-sessions"),
}


def _route_deps():
    """(method, path) -> the dependency callables declared on that route."""
    out = {}
    for r in api.app.routes:
        # FastAPI keeps an included APIRouter as one nested entry; walk its routes
        # too, or a router-mounted /workspace route would escape both checks.
        inner = getattr(r, "original_router", None)
        for route in (inner.routes if inner is not None else [r]):
            for m in getattr(route, "methods", None) or ():
                out[(m, route.path)] = [d.dependency for d in getattr(route, "dependencies", [])]
    return out


class LockedRoutesDeclareTheGate(unittest.TestCase):
    def test_every_locked_route_requires_the_configured_master_key(self):
        deps = _route_deps()
        missing = sorted(k for k in LOCKED_ROUTES if k not in deps)
        self.assertEqual(missing, [], f"locked routes no longer registered: {missing}")
        ungated = sorted(k for k in LOCKED_ROUTES if require_configured_master_auth not in deps[k])
        self.assertEqual(ungated, [], f"routes reachable without the master key: {ungated}")

    def test_no_workspace_or_session_route_escapes_the_list(self):
        # A new /workspace or Metasploit-session route added later must be
        # gated too, not silently left open on the published port.
        sensitive = {
            k for k in _route_deps()
            if k[1] == "/workspace" or k[1].startswith(("/workspace/", "/sessions", "/jobs/"))
        }
        self.assertEqual(sorted(sensitive - LOCKED_ROUTES), [])


class GateBehaviour(unittest.TestCase):
    """Drive the real dependency through TestClient on a route with no side effect
    outside a temp workspace root."""

    def setUp(self):
        from fastapi.testclient import TestClient

        self._tmp = tempfile.TemporaryDirectory()
        (Path(self._tmp.name) / "p1" / "notes").mkdir(parents=True)
        self._root = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", Path(self._tmp.name))
        self._root.start()
        self.client = TestClient(api.app)
        self.url = "/workspace/list?projectId=p1&path=."

    def tearDown(self):
        self._root.stop()
        self._tmp.cleanup()

    def _get(self, env, headers=None):
        with mock.patch.dict(os.environ, env, clear=False):
            return self.client.get(self.url, headers=headers or {})

    def test_refuses_when_no_master_key_is_configured(self):
        # Fail-CLOSED: no key means nobody.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INTERNAL_API_KEY", None)
            resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 503)

    def test_compose_default_key_is_not_a_credential(self):
        # docker-compose falls back to INTERNAL_API_KEY=changeme; presenting that
        # same string must not unlock the route.
        resp = self._get({"INTERNAL_API_KEY": "changeme"}, {"x-internal-key": "changeme"})
        self.assertEqual(resp.status_code, 503)

    def test_no_header_is_unauthorized(self):
        resp = self._get({"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER})
        self.assertEqual(resp.status_code, 401)

    def test_scanner_key_is_unauthorized(self):
        resp = self._get({"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER},
                         {"x-internal-key": SCANNER})
        self.assertEqual(resp.status_code, 401)

    def test_master_key_reaches_the_route(self):
        resp = self._get({"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER},
                         {"x-internal-key": MASTER})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("notes", [e["name"] for e in resp.json()["entries"]])

    def test_session_interact_never_reaches_kali_without_the_key(self):
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}, clear=False), \
                mock.patch("httpx.AsyncClient") as client_cls:
            resp = self.client.post("/sessions/1/interact", json={"command": "id"})
        self.assertEqual(resp.status_code, 401)
        client_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()

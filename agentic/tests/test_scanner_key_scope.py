"""
The scanner key opens only the scan containers' routes (NF-01, steps 1.9, 1.15, 1.16).

SCANNER_API_KEY sits in every target-facing scan container. Step 1.9 moves every route
whose only caller is the webapp (the master T15 list) to `require_configured_master_auth`:
the master key, fail-closed. Step 1.15 moved the in-sandbox routes to run credentials;
step 1.16 moved the scan routes (`/llm/*`, `/jev/*`) to job credentials: since then no
route accepts the bare scanner key at all.

The walk below is behavioural: every `llm_guard` dependency a route declares is called
with a request carrying only the scanner key, and the route accepts that key when all
of them let it through.
"""
import asyncio
import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import HTTPException  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from starlette.requests import Request  # noqa: E402

MASTER = "master-key-for-scope-test"
SCANNER = "scanner-key-for-scope-test"
KEYS = {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}

# The routes only the webapp calls (phase_01_hardening.md, step 1.9).
MASTER_LIST = [
    ("POST", "/emergency-stop-all"),
    ("GET", "/mcp/manifest"),
    ("POST", "/mcp/reload"),
    ("POST", "/mcp/test"),
    ("GET", "/files"),
    ("POST", "/models"),
    ("POST", "/llm-provider/test"),
    ("POST", "/tradecraft/verify"),
    ("POST", "/guardrail/check-target"),
    ("POST", "/graph/nl-query"),
    ("GET", "/graph/schema-doc"),
    ("GET", "/kali/toolbox"),
]

# The scan containers' routes: the scanner key opens them only beside a job credential.
SCAN_ROUTE_PREFIXES = ("/llm/", "/jev/")

GATE_503 = "INTERNAL_API_KEY is not configured"

with patch.dict(os.environ, KEYS):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402
import llm_guard  # noqa: E402
import machine_credential  # noqa: E402


def _route(method: str, path: str) -> APIRoute:
    for r in api.app.routes:
        if isinstance(r, APIRoute) and r.path == path and method in r.methods:
            return r
    raise AssertionError(f"{method} {path} is not registered")


def _guard_calls(route: APIRoute) -> list:
    """Every llm_guard dependency of the route, router-level ones included, in order."""
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop(0)
        call = dep.call
        if getattr(call, "__module__", "") == "llm_guard" and call not in out:
            out.append(call)
        stack.extend(dep.dependencies)
    return out


def _request(headers: dict) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    scope = {
        "type": "http", "method": "POST", "path": "/", "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 1),
    }
    return Request(scope, receive)


def _accepts(route: APIRoute, headers: dict) -> bool:
    async def run():
        req = _request(headers)
        for call in _guard_calls(route):
            try:
                await call(req)
            except HTTPException:
                return False
        return True

    return asyncio.run(run())


def _guarded_routes() -> list:
    return [r for r in api.app.routes if isinstance(r, APIRoute) and _guard_calls(r)]


class _Keys(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(os.environ, KEYS)
        self._env.start()
        self.addCleanup(self._env.stop)
        llm_guard.reset_state()
        from fastapi.testclient import TestClient
        self.client = TestClient(api.app)

    def _call(self, method: str, path: str, key):
        headers = {"x-internal-key": key} if key else {}
        if method == "GET":
            return self.client.get(path, headers=headers)
        # A body the handlers refuse (422) once the gate let it through: nothing runs.
        return self.client.post(path, headers=headers, json=[])


class MasterListTests(_Keys):
    def test_every_route_of_the_master_list_declares_the_configured_master_gate(self):
        for method, path in MASTER_LIST:
            with self.subTest(path=path):
                self.assertIn(llm_guard.require_configured_master_auth, _guard_calls(_route(method, path)))

    def test_scanner_key_refused_on_every_route_of_the_master_list(self):
        for method, path in MASTER_LIST:
            with self.subTest(path=path):
                self.assertEqual(self._call(method, path, SCANNER).status_code, 401)
                self.assertEqual(self._call(method, path, None).status_code, 401)
                self.assertEqual(self._call(method, path, "wrong").status_code, 401)

    def test_master_key_accepted(self):
        for method, path in MASTER_LIST:
            with self.subTest(path=path):
                r = self._call(method, path, MASTER)
                self.assertNotIn(r.status_code, (401, 403), r.text)
                self.assertNotIn(GATE_503, r.text)

    def test_without_a_configured_master_key_the_routes_are_closed(self):
        for weak in ("", "changeme"):
            with patch.dict(os.environ, {"INTERNAL_API_KEY": weak}):
                for method, path in MASTER_LIST:
                    with self.subTest(path=path, master=weak or "<unset>"):
                        r = self._call(method, path, SCANNER)
                        self.assertEqual(r.status_code, 503)
                        self.assertIn(GATE_503, r.text)

    def test_billed_routes_keep_the_llm_limits(self):
        for path in ("/models", "/llm-provider/test", "/tradecraft/verify",
                     "/guardrail/check-target", "/graph/nl-query"):
            with self.subTest(path=path):
                self.assertIn(llm_guard.require_internal_auth, _guard_calls(_route("POST", path)))


class WholeAppTests(_Keys):
    def test_the_walk_sees_the_guards(self):
        """The behavioural walk is not vacuous: it sees routes, and tells keys apart."""
        routes = _guarded_routes()
        self.assertGreater(len(routes), 60)
        stop = _route("POST", "/emergency-stop-all")
        self.assertTrue(_accepts(stop, {"x-internal-key": MASTER}))
        self.assertFalse(_accepts(stop, {"x-internal-key": SCANNER}))
        scan = _route("POST", "/llm/nuclei-tags")
        self.assertFalse(_accepts(scan, {"x-internal-key": SCANNER}))
        job = machine_credential.mint(
            {"aud": "scan", "ten": "u1", "pid": "p1", "job": "j1", "exp": 4_102_444_800},
            machine_credential.derive_key(MASTER, machine_credential.JOB_CREDENTIAL_LABEL))
        # The gate also asks the webapp who owns the credential's project now.
        with patch.object(llm_guard, "_job_project_owner", return_value="u1"):
            self.assertTrue(_accepts(scan, {"x-internal-key": SCANNER, "x-redamon-job": job}))

    def test_no_route_outside_the_scan_routes_accepts_the_bare_scanner_key(self):
        open_ = [
            f"{sorted(r.methods)} {r.path}" for r in _guarded_routes()
            if not r.path.startswith(SCAN_ROUTE_PREFIXES)
            and _accepts(r, {"x-internal-key": SCANNER})
        ]
        self.assertEqual(open_, [])

    def test_no_route_in_app_routes_accepts_the_bare_scanner_key(self):
        open_ = [
            f"{sorted(r.methods)} {r.path}" for r in _guarded_routes()
            if _accepts(r, {"x-internal-key": SCANNER})
        ]
        self.assertEqual(open_, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

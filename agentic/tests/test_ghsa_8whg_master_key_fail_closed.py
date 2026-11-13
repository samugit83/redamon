"""
GHSA-8whg-rvcr-r88r: an agent started without keys ran commands for anyone.

Up to 7.7.2 `require_master_internal_auth` admitted EVERY caller when
INTERNAL_API_KEY was unset or the compose default `changeme`, and `/mcp/test` sat
behind `require_internal_auth_only`, whose `_key_ok` did the same. The agent port is
published on 0.0.0.0, `/kali/exec` runs `bash -c` in the sandbox and `/mcp/test`
spawned a caller-chosen stdio command inside the agent, so a plain
`docker compose up` without generated keys was unauthenticated code execution from
the network. Reported by @recuon.

These tests replay those requests against the real app with no key and with
`changeme`, and prove nothing runs. Then they walk every route, so a master-key
route cannot fail open again.
"""
import asyncio
import inspect
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
import llm_guard  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.requests import Request  # noqa: E402

MASTER = "dummy-master-key-ghsa-8whg"
SCANNER = "dummy-scanner-key-ghsa-8whg"
JOB = "a" * 32

#: Every way an install can be "keyless": the variable absent, or the compose default.
KEYLESS_ENVS = ({}, {"INTERNAL_API_KEY": "changeme"})
#: What an attacker on the network would send to a keyless agent.
ATTACKER_HEADERS = ({}, {"x-internal-key": "changeme"}, {"x-internal-key": "anything"})

FAIL_CLOSED_MASTER_DEPS = {
    llm_guard.require_master_internal_auth,
    llm_guard.require_configured_master_auth,
    llm_guard.require_master_auth_route_refuses_weak,
    llm_guard.require_master_or_job_credential,
    llm_guard.require_master_or_run_credential,
}
FAIL_OPEN_KEY_DEPS = {llm_guard.require_internal_auth, llm_guard.require_internal_auth_only}

#: The only routes whose handler answers a keyless agent itself. Adding one is a
#: decision: its handler must refuse before doing anything (checked below).
ROUTES_THAT_REFUSE_WEAK_KEYS_THEMSELVES = {
    ("POST", "/graph/multi-mute/suggest"),
    ("GET", "/plugins/skill-parts"),
    ("POST", "/plugins/skill-parts/validate"),
    ("POST", "/plugins/text/validate"),
    ("POST", "/plugins/llm/invoke"),
}


def _keyless(env: dict):
    """os.environ with no usable master or scanner key, plus `env`."""
    patcher = mock.patch.dict(os.environ, env, clear=False)
    patcher.start()
    for name in ("INTERNAL_API_KEY", "SCANNER_API_KEY"):
        if name not in env:
            os.environ.pop(name, None)
    return patcher


def _api_routes():
    # FastAPI 0.16x keeps an included router (/plugins, workspace import, loop)
    # as one `_IncludedRouter` entry of app.routes, so the walk descends into it.
    found = []

    def walk(routes):
        for route in routes:
            if isinstance(route, APIRoute):
                found.append(route)
            elif getattr(route, "original_router", None) is not None:
                walk(route.original_router.routes)

    walk(api.app.router.routes)
    return found


def _deps(route) -> set:
    # `route.dependant` holds the route's own and its router's dependencies.
    return {d.call for d in route.dependant.dependencies}


def _request(headers: dict) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": raw,
                    "client": ("203.0.113.9", 4444)})


def _status(dep, headers: dict) -> int:
    try:
        asyncio.run(dep(_request(headers)))
        return 200
    except llm_guard.HTTPException as exc:
        return exc.status_code


class _ExplodingRegistry:
    """Any use means the command was admitted."""

    def __getattr__(self, name):
        raise AssertionError(f"job registry used ({name}): the command was admitted")


class KeylessAgentRunsNothing(unittest.TestCase):
    """The reporter's requests, sent to an agent that has no key."""

    def setUp(self):
        self.client = TestClient(api.app)

    def test_kali_exec_refuses_and_runs_nothing(self):
        with mock.patch.object(api.job_runner, "get_registry", lambda: _ExplodingRegistry()):
            for env in KEYLESS_ENVS:
                for headers in ATTACKER_HEADERS:
                    patcher = _keyless(env)
                    try:
                        start = self.client.post("/kali/exec", headers=headers,
                                                 json={"project_id": "p1", "command": "id"})
                        poll = self.client.get(f"/kali/exec/{JOB}?project_id=p1", headers=headers)
                        cancel = self.client.post(f"/kali/exec/{JOB}/cancel?project_id=p1",
                                                  headers=headers)
                    finally:
                        patcher.stop()
                    for resp in (start, poll, cancel):
                        self.assertEqual(resp.status_code, 503, (env, headers, resp.text))
                        self.assertIn("INTERNAL_API_KEY", resp.json()["detail"])

    def test_mcp_test_refuses_and_spawns_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "spawned"
            body = {
                "id": "probe", "name": "probe", "transport": "stdio", "enabled": True,
                "command": sys.executable,
                "args": ["-c", "import sys;open(sys.argv[1],'a').write('ran')", str(marker)],
            }
            for env in KEYLESS_ENVS:
                for headers in ATTACKER_HEADERS:
                    patcher = _keyless(env)
                    try:
                        resp = self.client.post("/mcp/test", headers=headers, json=body)
                    finally:
                        patcher.stop()
                    self.assertEqual(resp.status_code, 503, (env, headers, resp.text))
            self.assertFalse(marker.exists(), "a keyless /mcp/test spawned the stdio command")

    def test_master_only_routes_refuse_before_their_handler(self):
        probes = (
            ("get", "/agent-sessions/live", None),
            ("post", "/graph/node-filters/apply", {"project_id": "p1", "user_id": "u1"}),
            ("post", "/graph/node-filters/preview", {"project_id": "p1", "user_id": "u1"}),
            ("post", "/triage/runs/stop", {"user_id": "u1", "project_id": "p1"}),
        )
        for env in KEYLESS_ENVS:
            patcher = _keyless(env)
            try:
                for method, path, body in probes:
                    resp = getattr(self.client, method)(path, json=body) if body else \
                        getattr(self.client, method)(path)
                    self.assertEqual(resp.status_code, 503, (env, path, resp.text))
            finally:
                patcher.stop()


class MasterDependencies(unittest.TestCase):

    def test_master_dependencies_refuse_every_caller_without_a_key(self):
        for dep in (llm_guard.require_master_internal_auth, llm_guard.require_configured_master_auth):
            for env in KEYLESS_ENVS:
                patcher = _keyless(env)
                try:
                    for headers in ATTACKER_HEADERS:
                        self.assertEqual(_status(dep, headers), 503, (dep.__name__, env, headers))
                finally:
                    patcher.stop()

    def test_master_dependencies_take_the_master_key_alone(self):
        env = {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}
        for dep in (llm_guard.require_master_internal_auth, llm_guard.require_configured_master_auth,
                    llm_guard.require_master_auth_route_refuses_weak):
            with mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(_status(dep, {"x-internal-key": MASTER}), 200, dep.__name__)
                self.assertEqual(_status(dep, {"x-internal-key": SCANNER}), 401, dep.__name__)
                self.assertEqual(_status(dep, {}), 401, dep.__name__)
                self.assertEqual(_status(dep, {"x-internal-key": "changeme"}), 401, dep.__name__)

    def test_mcp_test_refuses_the_scanner_key(self):
        """The reporter's sandbox path: the scanner key the kali container held."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "spawned"
            body = {
                "id": "probe", "name": "probe", "transport": "stdio", "enabled": True,
                "command": sys.executable,
                "args": ["-c", "import sys;open(sys.argv[1],'a').write('ran')", str(marker)],
            }
            env = {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}
            with mock.patch.dict(os.environ, env, clear=False):
                resp = TestClient(api.app).post("/mcp/test", headers={"x-internal-key": SCANNER},
                                                json=body)
            self.assertEqual(resp.status_code, 401, resp.text)
            self.assertFalse(marker.exists())


class NoRouteFailsOpen(unittest.TestCase):
    """Walks every route of the agent, including the included /plugins router."""

    def test_the_key_or_scanner_check_never_stands_alone(self):
        # _key_ok admits every caller when no key is set, so it is safe only
        # behind a master-key dependency that refuses a keyless agent.
        lonely = [
            (sorted(r.methods), r.path) for r in _api_routes()
            if _deps(r) & FAIL_OPEN_KEY_DEPS and not _deps(r) & FAIL_CLOSED_MASTER_DEPS
        ]
        self.assertEqual(lonely, [])

    def test_the_self_refusing_dependency_is_used_only_where_the_handler_refuses(self):
        using = set()
        for route in _api_routes():
            if llm_guard.require_master_auth_route_refuses_weak not in _deps(route):
                continue
            for method in route.methods:
                using.add((method, route.path))
            source = inspect.getsource(route.endpoint)
            self.assertIn("master_key_is_weak()", source,
                          f"{route.path} leaves a keyless agent to a handler that never refuses it")
        self.assertEqual(using, ROUTES_THAT_REFUSE_WEAK_KEYS_THEMSELVES)

    def test_the_self_refusing_routes_answer_503_without_a_key(self):
        client = TestClient(api.app)
        for env in KEYLESS_ENVS:
            patcher = _keyless(env)
            try:
                resp = client.get("/plugins/skill-parts")
                self.assertEqual(resp.status_code, 503, resp.text)
                resp = client.post("/plugins/text/validate",
                                   json={"text": "a", "baseText": "b", "maxChars": 5})
                self.assertEqual(resp.status_code, 503, resp.text)
            finally:
                patcher.stop()

    def test_kali_exec_and_mcp_routes_take_a_fail_closed_master_dependency(self):
        for method, path in (("POST", "/kali/exec"), ("GET", "/kali/exec/{job_id}"),
                             ("POST", "/kali/exec/{job_id}/cancel"), ("POST", "/mcp/test"),
                             ("POST", "/mcp/reload"), ("GET", "/mcp/manifest")):
            route = next(r for r in _api_routes() if r.path == path and method in r.methods)
            deps = _deps(route)
            self.assertTrue(deps & {llm_guard.require_master_internal_auth,
                                    llm_guard.require_configured_master_auth}, path)
            self.assertFalse(deps & FAIL_OPEN_KEY_DEPS, path)
            self.assertNotIn(llm_guard.require_master_auth_route_refuses_weak, deps, path)


if __name__ == "__main__":
    unittest.main()

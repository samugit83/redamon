"""
The traffic routes take a run credential, never the scanner key (NF-01, HD-19).

proxy_brain's `redamon` SDK reached /traffic/exec, /traffic/replay and
/traffic/browser with the scanner key, which every root shell in the sandbox
could read. The agent now mints a 15-minute `traffic` run credential for each
proxy_brain call, passed beside the REDAMON_CTX tag; the routes take
`require_master_or_run_credential('traffic')` and keep the tag check, whose user
and project must equal the credential's. The tag itself is unchanged (DV-28).

Run: ./agentic/run_tests.sh tests/test_traffic_run_credential.py
"""
import asyncio
import os
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from fastapi.testclient import TestClient  # noqa: E402

import llm_guard  # noqa: E402
import machine_credential as mc  # noqa: E402
from redamon_ctx import sign_tag  # noqa: E402

MASTER = "master-key-for-traffic-credential-tests"
SCANNER = "scanner-key-for-traffic-credential-tests"


def _tag(user_id="uA", project_id="pA", phase="exploitation"):
    return sign_tag({"source": "agent", "user_id": user_id, "project_id": project_id,
                     "session_id": "s1", "tool": "proxy_brain", "phase": phase}, MASTER)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with mock.patch("api.lifespan", fake_lifespan):
            import api as api_module
        cls.api = api_module
        cls.client = TestClient(api_module.app)

    def setUp(self):
        self._e = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER})
        self._e.start()
        import traffic_tools
        self.queries = []

        async def fake_query(sql, params):
            self.queries.append(params)
            return []

        self._q = mock.patch.object(traffic_tools, "_query", new=fake_query)
        self._q.start()
        self._t = mock.patch("traffic_tools.fetch_transaction", new=mock.AsyncMock(return_value=None))
        self.fetch = self._t.start()

    def tearDown(self):
        self._t.stop()
        self._q.stop()
        self._e.stop()

    @staticmethod
    def cred(ten="uA", pid="pA", aud="traffic"):
        return mc.mint_run_credential(aud, ten, pid, "s1", mc.TRAFFIC_TTL_SECONDS)

    def post(self, path, body, **headers):
        return self.client.post(path, json=body, headers=headers)


_ROUTES = {
    "/traffic/exec": lambda ctx: {"ctx": ctx, "op": "sitemap"},
    "/traffic/replay": lambda ctx: {"ctx": ctx, "op": "replay", "id": "t1"},
    "/traffic/browser": lambda ctx: {"ctx": ctx, "action": "open", "origin_id": "t1"},
}


class TrafficRoutes(_Base):
    def test_traffic_routes_refuse_the_scanner_key(self):
        for path, body in _ROUTES.items():
            for headers in ({"X-Internal-Key": SCANNER}, {}):
                with self.subTest(path=path, headers=sorted(headers)):
                    res = self.post(path, body(_tag()), **headers)
                    self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(self.queries, [])
        self.fetch.assert_not_awaited()

    def test_accept_a_run_credential_whose_ids_match_the_ctx_tag(self):
        res = self.post("/traffic/exec", _ROUTES["/traffic/exec"](_tag()), **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(self.queries)
        # The gate passed, then each route's own checks run: no origin -> 404.
        for path in ("/traffic/replay", "/traffic/browser"):
            with self.subTest(path=path):
                res = self.post(path, _ROUTES[path](_tag()), **{"X-Redamon-Run": self.cred()})
                self.assertEqual(res.status_code, 404, res.text)
        self.assertEqual(self.fetch.await_count, 2)

    def test_refuse_a_mismatch(self):
        for ten, pid in (("uB", "pA"), ("uA", "pB")):
            for path, body in _ROUTES.items():
                with self.subTest(path=path, ten=ten, pid=pid):
                    with self.assertLogs("api", level="WARNING") as logs:
                        res = self.post(path, body(_tag()), **{"X-Redamon-Run": self.cred(ten=ten, pid=pid)})
                    self.assertEqual(res.status_code, 403, res.text)
                    self.assertEqual(res.json()["code"], "run_credential_ctx_mismatch")
                    self.assertTrue(any("[rbac] run credential refused reason=ctx_mismatch" in line
                                        for line in logs.output), logs.output)
        self.assertEqual(self.queries, [])
        self.fetch.assert_not_awaited()

    def test_a_graph_credential_does_not_open_traffic(self):
        res = self.post("/traffic/exec", _ROUTES["/traffic/exec"](_tag()), **{"X-Redamon-Run": self.cred(aud="graph")})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_wrong_audience")

    def test_the_tag_check_still_runs_with_a_credential(self):
        res = self.post("/traffic/exec", _ROUTES["/traffic/exec"](""), **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 401)
        self.assertIn("ctx", res.json()["error"])

    def test_the_master_key_path_is_unchanged(self):
        res = self.post("/traffic/exec", _ROUTES["/traffic/exec"](_tag(user_id="uZ")), **{"X-Internal-Key": MASTER})
        self.assertEqual(res.status_code, 200, res.text)

    def test_the_routes_declare_the_traffic_gate(self):
        gate = llm_guard.require_master_or_run_credential("traffic")
        for path in _ROUTES:
            route = next(r for r in self.api.app.routes if getattr(r, "path", None) == path)
            deps = [d.dependency for d in route.dependencies]
            self.assertIn(gate, deps, path)
            self.assertNotIn(llm_guard.require_internal_auth_only, deps, path)


# --- the agent mints one for every proxy_brain call ------------------------------
class ProxyBrainGetsACredential(unittest.TestCase):
    def _executor(self):
        from tools import PhaseAwareToolExecutor
        ex = PhaseAwareToolExecutor(mcp_manager=mock.MagicMock(), graph_tool=None)
        tool = mock.AsyncMock()
        tool.name = "proxy_brain"
        tool.ainvoke.return_value = "ok"
        ex._all_tools["proxy_brain"] = tool
        return ex, tool

    def _run(self, ex, args, tenant=("uA", "pA", "sess-1")):
        from agent_context import set_tenant_context

        async def go():
            set_tenant_context(*tenant)
            return await ex.execute("proxy_brain", args, phase="informational")
        return asyncio.new_event_loop().run_until_complete(go())

    def test_proxy_brain_gets_a_traffic_credential_bound_to_the_runs_tenant(self):
        ex, tool = self._executor()
        before = int(time.time())
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}):
            self._run(ex, {"code": "print(1)", "_redamon_run": "llm-forged", "_redamon_ctx": "llm-forged"})
            sent = tool.ainvoke.call_args.args[0]
            claims = mc.verify_run_credential(sent["_redamon_run"], "traffic")
        self.assertEqual((claims["ten"], claims["pid"], claims["run"]), ("uA", "pA", "sess-1"))
        self.assertGreaterEqual(claims["exp"], before + mc.TRAFFIC_TTL_SECONDS)
        self.assertLessEqual(claims["exp"], int(time.time()) + mc.TRAFFIC_TTL_SECONDS)
        self.assertNotEqual(sent["_redamon_ctx"], "llm-forged")
        self.assertEqual(sent["code"], "print(1)")

    def test_no_credential_no_run(self):
        ex, tool = self._executor()
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}), \
                mock.patch("machine_credential.mint_run_credential", side_effect=mc.CredentialRefused("weak_master_key")):
            out = self._run(ex, {"code": "print(1)"})
        self.assertFalse(out["success"])
        self.assertIn("run credential", out["error"])
        tool.ainvoke.assert_not_called()

    def test_other_tools_get_no_credential(self):
        from tools import PhaseAwareToolExecutor
        ex = PhaseAwareToolExecutor(mcp_manager=mock.MagicMock(), graph_tool=None)
        tool = mock.AsyncMock()
        tool.name = "kali_shell"
        tool.ainvoke.return_value = "ok"
        ex._all_tools["kali_shell"] = tool

        async def go():
            from agent_context import set_tenant_context
            set_tenant_context("uA", "pA", "sess-1")
            return await ex.execute("kali_shell", {"command": "id"}, phase="informational")
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}):
            asyncio.new_event_loop().run_until_complete(go())
        self.assertNotIn("_redamon_run", tool.ainvoke.call_args.args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

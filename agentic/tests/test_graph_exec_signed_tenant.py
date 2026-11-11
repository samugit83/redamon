"""
The graph read proxy takes its tenant from a signed run credential (HD-21, SH-36, NF-01).

/graph/exec and /text-to-cypher accepted the bare scanner key and ran as whatever
user and project the body named, so a root shell in the sandbox read any tenant's
graph and billed any user's model key. Now each takes
`require_master_or_run_credential('graph')`: the master key (the webapp, which
derives the tenant from its own database) keeps the body's ids; a run credential
(the Kali terminal's redagraph) decides the tenant, the project and the key owner,
and the body's ids are ignored; the scanner key alone opens neither. A graph
credential is good only while the terminal socket it was handed to is open (the
proxy records its run on the socket), so one copied out of the shared sandbox
dies with that terminal rather than 12 hours later.

Run: ./agentic/run_tests.sh tests/test_graph_exec_signed_tenant.py
"""
import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from fastapi.responses import JSONResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import llm_guard  # noqa: E402
import machine_credential as mc  # noqa: E402

MASTER = "master-key-for-graph-credential-tests"
SCANNER = "scanner-key-for-graph-credential-tests"
LABELLED = "MATCH (d:Domain) RETURN d.name AS name"


class _FakeSocket:
    """A proxied browser socket: /ws/close closes it."""

    def __init__(self):
        self.closed = None

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


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
        llm_guard.reset_state()
        self.ran = []

        def respond(final, params):
            self.ran.append((final, params))
            return JSONResponse(content={"records": []})

        self._r = mock.patch.object(self.api, "_graph_exec_respond", side_effect=respond)
        self._r.start()
        # A graph credential is good only while the terminal it was handed to is open.
        self.terminal = self.open_terminal()

    def tearDown(self):
        self.api.PROXIED_SOCKETS.remove(self.terminal)
        self._r.stop()
        self._e.stop()
        llm_guard.reset_state()

    def open_terminal(self, sub="uA", pid="pA", run="term-1"):
        ws = _FakeSocket()
        self.api.PROXIED_SOCKETS.add(ws, "kali-terminal", {"sub": sub, "pid": pid, "sid": "s1"}, run=run)
        self.addCleanup(self.api.PROXIED_SOCKETS.remove, ws)
        return ws

    @staticmethod
    def cred(ten="uA", pid="pA", aud="graph", ttl=600, now=None, run="term-1"):
        return mc.mint_run_credential(aud, ten, pid, run, ttl, now=now)

    def exec_(self, body, **headers):
        return self.client.post("/graph/exec", json=body, headers=headers)


class GraphExec(_Base):
    def test_run_credential_decides_the_tenant(self):
        res = self.exec_({"op": "types", "user_id": "uA", "project_id": "pA"}, **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 200, res.text)
        [(_final, params)] = self.ran
        self.assertEqual(params, {"tenant_user_id": "uA", "tenant_project_id": "pA"})

    def test_body_tenant_ignored_with_a_credential(self):
        res = self.exec_({"op": "cypher", "cypher": LABELLED, "user_id": "victim", "project_id": "victim-p"},
                         **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 200, res.text)
        [(final, params)] = self.ran
        self.assertEqual(params, {"tenant_user_id": "uA", "tenant_project_id": "pA"})
        self.assertIn("$tenant_user_id", final)
        self.assertNotIn("victim", final)

    def test_scanner_key_alone_refused(self):
        body = {"op": "types", "user_id": "uA", "project_id": "pA"}
        for headers in ({"X-Internal-Key": SCANNER}, {}, {"X-Internal-Key": SCANNER, "X-Redamon-Run": "forged.token"}):
            with self.subTest(headers=sorted(headers)):
                res = self.exec_(body, **headers)
                self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(self.ran, [])

    def test_master_key_keeps_the_body_tenant(self):
        res = self.exec_({"op": "types", "user_id": "uB", "project_id": "pB", "source": "mcp"},
                         **{"X-Internal-Key": MASTER})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(self.ran[0][1], {"tenant_user_id": "uB", "tenant_project_id": "pB"})

    def test_master_key_with_a_credential_too_is_still_the_master(self):
        res = self.exec_({"op": "types", "user_id": "uB", "project_id": "pB"},
                         **{"X-Internal-Key": MASTER, "X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(self.ran[0][1], {"tenant_user_id": "uB", "tenant_project_id": "pB"})

    def test_an_expired_credential_is_refused_and_logged(self):
        expired = self.cred(ttl=60, now=1_000_000_000)
        with self.assertLogs("llm_guard", level="WARNING") as logs:
            res = self.exec_({"op": "types", "user_id": "uA", "project_id": "pA"}, **{"X-Redamon-Run": expired})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_expired")
        self.assertTrue(any("[rbac] run credential refused reason=expired" in line for line in logs.output),
                        logs.output)
        self.assertEqual(self.ran, [])

    def test_a_traffic_credential_does_not_open_the_graph(self):
        res = self.exec_({"op": "types", "user_id": "uA", "project_id": "pA"},
                         **{"X-Redamon-Run": self.cred(aud="traffic")})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_wrong_audience")

    def test_a_weak_master_key_closes_the_route(self):
        token = self.cred()
        for weak in ("", "changeme"):
            with self.subTest(master=weak), mock.patch.dict(os.environ, {"INTERNAL_API_KEY": weak}):
                res = self.exec_({"op": "types", "user_id": "uA", "project_id": "pA"}, **{"X-Redamon-Run": token})
                self.assertEqual(res.status_code, 503)
        self.assertEqual(self.ran, [])

    def test_the_write_guard_still_holds_for_a_credential(self):
        res = self.exec_({"op": "cypher", "cypher": "MATCH (d:Domain) DETACH DELETE d", "user_id": "uA",
                          "project_id": "pA"}, **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 403)
        self.assertEqual(self.ran, [])


class TextToCypher(_Base):
    def setUp(self):
        super().setUp()
        self.manager = object()
        self._b = mock.patch.object(self.api, "_build_cypher_manager", new=mock.AsyncMock(return_value=self.manager))
        self._g = mock.patch.object(self.api, "_generate_validated_cypher",
                                    new=mock.AsyncMock(return_value=LABELLED))
        self.build = self._b.start()
        self.generate = self._g.start()

    def tearDown(self):
        self._g.stop()
        self._b.stop()
        super().tearDown()

    def ask(self, **headers):
        return self.client.post("/text-to-cypher", headers=headers, json={
            "question": "list domains", "user_id": "victim", "project_id": "victim-p", "for_graph_view": False})

    def test_text_to_cypher_bills_the_credentials_tenant_not_the_body_user(self):
        res = self.ask(**{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 200, res.text)
        self.build.assert_awaited_once_with("uA", "pA")
        self.assertEqual(self.generate.await_args.args[2:4], ("uA", "pA"))
        # The spend cap counts the credential's tenant, not the body's user.
        self.assertIn("uA", llm_guard._daily_cap._state)
        self.assertNotIn("victim", llm_guard._daily_cap._state)

    def test_master_key_keeps_the_body_user(self):
        res = self.ask(**{"X-Internal-Key": MASTER})
        self.assertEqual(res.status_code, 200, res.text)
        self.build.assert_awaited_once_with("victim", "victim-p")

    def test_scanner_key_alone_refused(self):
        self.assertEqual(self.ask(**{"X-Internal-Key": SCANNER}).status_code, 401)
        self.assertEqual(self.ask().status_code, 401)
        self.build.assert_not_awaited()

    def test_a_credential_is_still_rate_limited(self):
        token = self.cred()
        with mock.patch.object(llm_guard._daily_cap, "cap", 1):
            self.assertEqual(self.ask(**{"X-Redamon-Run": token}).status_code, 200)
            self.assertEqual(self.ask(**{"X-Redamon-Run": token}).status_code, 429)

    def test_a_closed_terminals_credential_bills_nobody(self):
        token = self.cred()
        self.api.PROXIED_SOCKETS.remove(self.terminal)
        res = self.ask(**{"X-Redamon-Run": token})
        self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_closed")
        self.build.assert_not_awaited()
        # Refused before the token bucket and the daily cap count a call for the tenant.
        self.assertNotIn("uA", llm_guard._daily_cap._state)


class TheCredentialDiesWithItsTerminal(_Base):
    """HD-19: a copied graph credential stops working when its terminal closes, not 12 hours later."""

    def body(self):
        return {"op": "types", "user_id": "uA", "project_id": "pA"}

    def test_a_closed_terminal_socket_refuses_its_credential(self):
        token = self.cred()
        self.assertEqual(self.exec_(self.body(), **{"X-Redamon-Run": token}).status_code, 200)
        self.api.PROXIED_SOCKETS.remove(self.terminal)
        with self.assertLogs("llm_guard", level="WARNING") as logs:
            res = self.exec_(self.body(), **{"X-Redamon-Run": token})
        self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_closed")
        self.assertTrue(any("[rbac] run credential refused reason=closed aud=graph" in line
                            for line in logs.output), logs.output)
        self.assertEqual(len(self.ran), 1)

    def test_ws_close_ends_the_credential_of_the_sockets_it_closes(self):
        token = self.cred()
        self.assertEqual(self.exec_(self.body(), **{"X-Redamon-Run": token}).status_code, 200)
        res = self.client.post("/ws/close", json={"user_id": "uA", "kinds": ["kali-terminal"]},
                               headers={"X-Internal-Key": MASTER})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["by_kind"], {"kali-terminal": 1})
        self.assertIsNotNone(self.terminal.closed)
        res = self.exec_(self.body(), **{"X-Redamon-Run": token})
        self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_closed")

    def test_a_run_no_open_terminal_was_handed_is_refused(self):
        res = self.exec_(self.body(), **{"X-Redamon-Run": self.cred(run="never-opened")})
        self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_closed")
        self.assertEqual(self.ran, [])

    def test_another_users_or_projects_open_terminal_does_not_keep_it_alive(self):
        self.api.PROXIED_SOCKETS.remove(self.terminal)
        self.open_terminal(sub="uB", pid="pA", run="term-1")
        self.open_terminal(sub="uA", pid="pB", run="term-1")
        res = self.exec_(self.body(), **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(self.ran, [])

    def test_an_open_terminal_with_no_credential_keeps_none_alive(self):
        self.api.PROXIED_SOCKETS.remove(self.terminal)
        self.open_terminal(run=None)
        res = self.exec_(self.body(), **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 401, res.text)

    def test_the_master_key_needs_no_open_terminal(self):
        self.api.PROXIED_SOCKETS.remove(self.terminal)
        res = self.exec_(self.body(), **{"X-Internal-Key": MASTER})
        self.assertEqual(res.status_code, 200, res.text)

    def test_without_a_liveness_check_a_graph_credential_is_refused(self):
        # Fail closed: a process that never said which terminals are open honours none.
        with mock.patch.dict(llm_guard._RUN_LIVENESS, clear=True):
            res = self.exec_(self.body(), **{"X-Redamon-Run": self.cred()})
        self.assertEqual(res.status_code, 401, res.text)
        self.assertEqual(res.json()["detail"]["code"], "run_credential_closed")


class RouteGates(_Base):
    def _deps(self, path):
        for r in self.api.app.routes:
            if getattr(r, "path", None) == path:
                return [d.dependency for d in getattr(r, "dependencies", [])]
        self.fail(f"{path} not registered")

    def test_the_graph_routes_declare_the_graph_gate(self):
        graph = llm_guard.require_master_or_run_credential("graph")
        billed = llm_guard.require_master_or_run_credential("graph", billed=True)
        self.assertIn(graph, self._deps("/graph/exec"))
        self.assertIn(billed, self._deps("/text-to-cypher"))
        for path in ("/graph/exec", "/text-to-cypher"):
            deps = self._deps(path)
            self.assertNotIn(llm_guard.require_internal_auth, deps, path)
            self.assertNotIn(llm_guard.require_internal_auth_only, deps, path)

    def test_the_gate_is_one_callable_per_audience(self):
        self.assertIs(llm_guard.require_master_or_run_credential("graph"),
                      llm_guard.require_master_or_run_credential("graph"))
        self.assertIsNot(llm_guard.require_master_or_run_credential("graph"),
                         llm_guard.require_master_or_run_credential("traffic"))
        with self.assertRaises(ValueError):
            llm_guard.require_master_or_run_credential("scan")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""
Text-to-Cypher keeps the graph tenant apart from the key owner (RBAC step 4.6, NF-11, SH-35).

A shared project's graph nodes carry its OWNER's user id, while the person asking may be
someone else (a collaborator, from Phase 5 on). The two ids used to be one, `user_id`: whose
provider key pays and whose nodes the generated query is scoped to. Now `tenant_user_id` names
the graph tenant and `user_id` the key owner (and the rate-limit bucket). The webapp resolves
both from its database and sends the owner for both in Phase 4; a caller that sends no
`tenant_user_id` (redagraph, the MCP server today) gets the old answer, the tenant being
`user_id`. With a terminal's run credential the credential decides both, and the body's ids,
`tenant_user_id` included, are ignored.

Run: ./agentic/run_tests.sh tests/test_text_to_cypher_tenant.py
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

MASTER = "master-key-for-text-to-cypher-tenant-tests"
LABELLED = "MATCH (d:Domain) RETURN d.name AS name"


def _load_api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with mock.patch("api.lifespan", fake_lifespan):
        import api as api_module
    return api_module


class _Socket:
    async def close(self, code=1000, reason=""):
        pass


class TextToCypherRoute(unittest.TestCase):
    """The HTTP route, with the manager and the generator doubled: which id goes where."""

    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()
        cls.client = TestClient(cls.api.app)

    def setUp(self):
        self._e = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})
        self._e.start()
        llm_guard.reset_state()
        self._b = mock.patch.object(self.api, "_build_cypher_manager", new=mock.AsyncMock(return_value=object()))
        self._g = mock.patch.object(self.api, "_generate_validated_cypher", new=mock.AsyncMock(return_value=LABELLED))
        self.build = self._b.start()
        self.generate = self._g.start()

    def tearDown(self):
        self._g.stop()
        self._b.stop()
        self._e.stop()
        llm_guard.reset_state()

    def ask(self, body, **headers):
        return self.client.post("/text-to-cypher", headers=headers, json={"question": "list domains", **body})

    def test_text_to_cypher_scopes_the_graph_to_tenant_user_id(self):
        res = self.ask({"user_id": "key-owner", "tenant_user_id": "project-owner", "project_id": "p1"},
                       **{"X-Internal-Key": MASTER})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json(), {"cypher": LABELLED})
        # The generated query is validated (and so scoped) under the project's owner...
        self.assertEqual(self.generate.await_args.args[2:4], ("project-owner", "p1"))
        # ...while the model and its key are resolved for the key owner.
        self.build.assert_awaited_once_with("key-owner", "p1")

    def test_the_key_owner_is_billed_not_the_tenant(self):
        self.ask({"user_id": "key-owner", "tenant_user_id": "project-owner", "project_id": "p1"},
                 **{"X-Internal-Key": MASTER})
        self.assertIn("key-owner", llm_guard._daily_cap._state)
        self.assertNotIn("project-owner", llm_guard._daily_cap._state)

    def test_without_tenant_user_id_the_tenant_is_user_id_as_before(self):
        for body in ({"user_id": "u1", "project_id": "p1"},
                     {"user_id": "u1", "project_id": "p1", "tenant_user_id": None},
                     {"user_id": "u1", "project_id": "p1", "tenant_user_id": ""}):
            with self.subTest(body=body):
                self.build.reset_mock()
                self.generate.reset_mock()
                res = self.ask(body, **{"X-Internal-Key": MASTER})
                self.assertEqual(res.status_code, 200, res.text)
                self.build.assert_awaited_once_with("u1", "p1")
                self.assertEqual(self.generate.await_args.args[2:4], ("u1", "p1"))

    def test_a_run_credential_decides_tenant_and_key_owner_and_ignores_the_body_tenant(self):
        ws = _Socket()
        self.api.PROXIED_SOCKETS.add(ws, "kali-terminal", {"sub": "uA", "pid": "pA", "sid": "s1"}, run="term-t")
        self.addCleanup(self.api.PROXIED_SOCKETS.remove, ws)
        token = mc.mint_run_credential("graph", "uA", "pA", "term-t", 600)
        res = self.ask({"user_id": "victim", "tenant_user_id": "victim", "project_id": "victim-p"},
                       **{"X-Redamon-Run": token})
        self.assertEqual(res.status_code, 200, res.text)
        self.build.assert_awaited_once_with("uA", "pA")
        self.assertEqual(self.generate.await_args.args[2:4], ("uA", "pA"))

    def test_the_request_model_declares_the_tenant_optional(self):
        req = self.api.TextToCypherRequest(question="q", user_id="u1", project_id="p1")
        self.assertIsNone(req.tenant_user_id)
        self.assertEqual(
            self.api.TextToCypherRequest(question="q", user_id="u1", project_id="p1",
                                         tenant_user_id="owner").tenant_user_id,
            "owner",
        )


class _Manager:
    """The three manager calls the generator makes; records the scope it was asked for."""

    def __init__(self):
        self.scoped = []

    async def _generate_cypher(self, question, **_kw):
        return LABELLED

    def _find_disallowed_write_operation(self, cypher):
        return None

    def _scope_query(self, cypher, user_id, project_id):
        self.scoped.append((user_id, project_id))
        return f"/* scoped */ {cypher}"


class GeneratorScope(unittest.IsolatedAsyncioTestCase):
    """The validation run inside the generator: scoped and executed under the tenant it is given."""

    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    async def test_the_validation_query_runs_under_the_tenant(self):
        ran = []
        manager = _Manager()
        with mock.patch.object(self.api, "_graph_exec_run", side_effect=lambda q, params, limit: ran.append(params)):
            cypher = await self.api._generate_validated_cypher(manager, "q", "project-owner", "p1", True)
        self.assertEqual(cypher, LABELLED)
        self.assertEqual(manager.scoped, [("project-owner", "p1")])
        self.assertEqual(ran, [{"tenant_user_id": "project-owner", "tenant_project_id": "p1"}])


class NlQueryTenant(unittest.IsolatedAsyncioTestCase):
    """/graph/nl-query (the MCP server's NL path): the same split, rows executed under the tenant."""

    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    async def _drive(self, req):
        seen = {}

        async def manager(user_id, project_id):
            seen["build"] = (user_id, project_id)
            return object()

        async def gen(mgr, question, tenant_user_id, project_id, for_graph_view):
            seen["generate"] = (tenant_user_id, project_id)
            return LABELLED

        def capture(final, params):
            seen["final"] = final
            seen["params"] = params
            return JSONResponse(content={"records": []})

        with mock.patch.object(self.api, "_build_cypher_manager", manager), \
             mock.patch.object(self.api, "_generate_validated_cypher", gen), \
             mock.patch.object(self.api, "_graph_exec_respond", capture):
            resp = await self.api.graph_nl_query(req)
        return resp, seen

    async def test_rows_are_scoped_to_tenant_user_id_and_the_key_is_user_ids(self):
        resp, seen = await self._drive(self.api.GraphNlQueryRequest(
            question="list domains", user_id="key-owner", tenant_user_id="project-owner", project_id="p1"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(seen["build"], ("key-owner", "p1"))
        self.assertEqual(seen["generate"], ("project-owner", "p1"))
        self.assertEqual(seen["params"], {"tenant_user_id": "project-owner", "tenant_project_id": "p1"})
        self.assertIn("$tenant_user_id", seen["final"])

    async def test_without_tenant_user_id_the_tenant_is_user_id_as_before(self):
        resp, seen = await self._drive(self.api.GraphNlQueryRequest(
            question="list domains", user_id="u1", project_id="p1"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(seen["build"], ("u1", "p1"))
        self.assertEqual(seen["generate"], ("u1", "p1"))
        self.assertEqual(seen["params"], {"tenant_user_id": "u1", "tenant_project_id": "p1"})


if __name__ == "__main__":
    unittest.main()

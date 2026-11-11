"""The two agent endpoints the inbound MCP server calls.

/graph/nl-query   natural language -> tenant-scoped ROWS, in one call
/graph/schema-doc the graph schema INCLUDING its semantics

Both exist so the MCP route never asserts a tenant of its own and never talks
to Neo4j itself: it resolves a personal access token to one user, and everything
after that is scoped server-side here.

The behaviours pinned here are the ones whose absence produces a FALSE NEGATIVE
in a security tool: an execution failure reported as an empty result, or a
generation failure the caller retries by re-running instead of rephrasing.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


def _route(path, method):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return r
    return None


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class RoutesRegisteredTests(unittest.TestCase):
    def test_nl_query_is_registered_and_billed_auth_gated(self):
        route = _route("/graph/nl-query", "POST")
        self.assertIsNotNone(route)
        # It spends the project owner's LLM key, so it needs the token bucket
        # and daily cap, not just a key check; the key is the master's (NF-01).
        self.assertIn("require_internal_auth", _dep_names(route))
        self.assertIn("require_configured_master_auth", _dep_names(route))

    def test_schema_doc_is_registered_and_auth_gated(self):
        route = _route("/graph/schema-doc", "GET")
        self.assertIsNotNone(route)
        deps = _dep_names(route)
        # The master key only (NF-01), no LLM bucket: it costs no LLM call and
        # is a cheap, high-frequency read, so the bucket must not throttle it.
        self.assertIn("require_configured_master_auth", deps)
        self.assertNotIn("require_internal_auth", deps)
        self.assertNotIn("require_internal_auth_only", deps)


class SchemaDocTests(unittest.IsolatedAsyncioTestCase):
    async def test_it_serves_the_generator_prompt_content(self):
        """The schema served is the composed document: the invariant rules from
        TEXT_TO_CYPHER_SYSTEM with the generated schema spliced in at the marker.

        Asserting equality with TEXT_TO_CYPHER_SYSTEM alone was right while that
        constant held the node blocks; it no longer does, and comparing against
        it would now pass only if the schema had gone missing.
        """
        from graph_schema_prompt import build_schema_document

        resp = await api.graph_schema_doc()
        self.assertEqual(_body(resp)["schema"], build_schema_document())

    async def test_it_carries_semantics_not_just_label_names(self):
        schema = _body(await api.graph_schema_doc())["schema"]
        # The distinction the tool exists to explain.
        self.assertIn("Vulnerability", schema)
        self.assertIn("CVE", schema)
        self.assertGreater(len(schema), 2000, "a bare label list, not the semantics")

    async def test_it_is_not_the_database_global_visualization_call(self):
        # db.schema.visualization() has no semantics and reflects labels created
        # by OTHER tenants.
        schema = _body(await api.graph_schema_doc())["schema"]
        self.assertNotIn("db.schema.visualization", schema)

    async def test_it_needs_no_database(self):
        # The one graph tool that still answers when Neo4j is down.
        def explode():
            raise AssertionError("schema-doc touched the database")

        with mock.patch.object(api, "_graph_exec_get_driver", side_effect=explode):
            resp = await api.graph_schema_doc()
        self.assertEqual(resp.status_code, 200)


class NlQueryTests(unittest.IsolatedAsyncioTestCase):
    def _req(self, **over):
        return api.GraphNlQueryRequest(
            question=over.pop("question", "list ip addresses"),
            user_id=over.pop("user_id", "u1"),
            project_id=over.pop("project_id", "p1"),
        )

    async def test_missing_tenant_is_refused_before_any_llm_call(self):
        called = []
        with mock.patch.object(api, "_build_cypher_manager", side_effect=lambda *a: called.append(a)):
            resp = await api.graph_nl_query(self._req(user_id=""))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(called, [])

    async def test_a_generation_failure_is_labelled_stage_generate(self):
        async def boom(*a, **kw):
            raise api._CypherSetupError(422, "Could not generate a valid query.")

        with mock.patch.object(api, "_build_cypher_manager", boom):
            resp = await api.graph_nl_query(self._req())

        body = _body(resp)
        self.assertEqual(resp.status_code, 422)
        # The caller must know rephrasing is the fix, not retrying.
        self.assertEqual(body["stage"], "generate")

    async def test_a_generation_failure_is_never_an_empty_result(self):
        async def boom(*a, **kw):
            raise api._CypherSetupError(500, "Failed to connect to the graph database.")

        with mock.patch.object(api, "_build_cypher_manager", boom):
            resp = await api.graph_nl_query(self._req())

        self.assertNotEqual(resp.status_code, 200)
        self.assertNotIn("records", _body(resp))

    async def test_an_execution_failure_is_labelled_stage_execute(self):
        from fastapi.responses import JSONResponse

        async def manager(*a, **kw):
            return object()

        async def gen(*a, **kw):
            return "MATCH (i:IP) RETURN i.address"

        def failed_exec(final, params):
            return JSONResponse(status_code=413, content={"error": "result too large, narrow your query"})

        with mock.patch.object(api, "_build_cypher_manager", manager), \
             mock.patch.object(api, "_generate_validated_cypher", gen), \
             mock.patch.object(api, "_graph_exec_respond", failed_exec):
            resp = await api.graph_nl_query(self._req())

        body = _body(resp)
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(body["stage"], "execute")
        # The generated query travels back so the caller can see what failed.
        self.assertIn("cypher", body)

    async def test_the_happy_path_returns_rows_and_the_generated_cypher(self):
        from fastapi.responses import JSONResponse

        async def manager(*a, **kw):
            return object()

        async def gen(*a, **kw):
            return "MATCH (i:IP) RETURN i.address"

        def ok_exec(final, params):
            return JSONResponse(content={"records": [{"i.address": "10.0.0.1"}]})

        with mock.patch.object(api, "_build_cypher_manager", manager), \
             mock.patch.object(api, "_generate_validated_cypher", gen), \
             mock.patch.object(api, "_graph_exec_respond", ok_exec):
            resp = await api.graph_nl_query(self._req())

        body = _body(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body["records"], [{"i.address": "10.0.0.1"}])
        self.assertEqual(body["cypher"], "MATCH (i:IP) RETURN i.address")

    async def test_the_executed_query_is_tenant_scoped_not_the_raw_cypher(self):
        from fastapi.responses import JSONResponse

        seen = {}

        async def manager(*a, **kw):
            return object()

        async def gen(*a, **kw):
            return "MATCH (i:IP) RETURN i.address"

        def capture(final, params):
            seen["final"] = final
            seen["params"] = params
            return JSONResponse(content={"records": []})

        with mock.patch.object(api, "_build_cypher_manager", manager), \
             mock.patch.object(api, "_generate_validated_cypher", gen), \
             mock.patch.object(api, "_graph_exec_respond", capture):
            await api.graph_nl_query(self._req(user_id="u1", project_id="p1"))

        self.assertIn("$tenant_user_id", seen["final"])
        self.assertIn("$tenant_project_id", seen["final"])
        self.assertEqual(seen["params"]["tenant_user_id"], "u1")
        self.assertEqual(seen["params"]["tenant_project_id"], "p1")

    async def _drive(self, generated, exec_fn):
        async def manager(*a, **kw):
            return object()

        async def gen(*a, **kw):
            return generated

        with mock.patch.object(api, "_build_cypher_manager", manager), \
             mock.patch.object(api, "_generate_validated_cypher", gen), \
             mock.patch.object(api, "_graph_exec_respond", exec_fn):
            return await api.graph_nl_query(self._req())

    async def test_an_unscopable_query_refuses_rather_than_running_unfiltered(self):
        def must_not_run(final, params):
            raise AssertionError("an unscoped query reached the database")

        # `Muted` is a reserved dual-label; scope_query refuses any query naming
        # it, because a suppressed finding must not be selectable.
        resp = await self._drive("MATCH (n:Muted) RETURN n", must_not_run)

        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp)["stage"], "generate")

    async def test_an_unlabelled_pattern_is_SCOPED_not_left_open(self):
        """Regression: `MATCH (n)` once bypassed the tenant filter entirely and
        returned another project's data. scope_query now scopes it."""
        from fastapi.responses import JSONResponse

        seen = {}

        def capture(final, params):
            seen["final"] = final
            return JSONResponse(content={"records": []})

        resp = await self._drive("MATCH (n) RETURN n", capture)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("$tenant_user_id", seen["final"])
        self.assertIn("$tenant_project_id", seen["final"])
        self.assertNotIn("MATCH (n) RETURN", seen["final"])

    async def test_it_asks_for_values_not_whole_nodes(self):
        from fastapi.responses import JSONResponse

        captured = {}

        async def manager(*a, **kw):
            return object()

        async def gen(mgr, question, user_id, project_id, for_graph_view):
            captured["for_graph_view"] = for_graph_view
            return "MATCH (i:IP) RETURN i.address"

        with mock.patch.object(api, "_build_cypher_manager", manager), \
             mock.patch.object(api, "_generate_validated_cypher", gen), \
             mock.patch.object(api, "_graph_exec_respond",
                               lambda f, p: JSONResponse(content={"records": []})):
            await api.graph_nl_query(self._req())

        # An external agent wants the values it asked about, not render nodes.
        self.assertFalse(captured["for_graph_view"])


if __name__ == "__main__":
    unittest.main()

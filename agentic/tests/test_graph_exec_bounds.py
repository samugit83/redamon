"""P0-4 — the graph read path must be bounded.

Every guard on /graph/exec was about WHAT may be read (read-only, labelled
pattern, tenant scope); none bounded HOW MUCH. `op: "cypher"` injected no limit
and materialised every record into a list, and the driver carried no transaction
timeout. One read-only Cartesian product passes every existing guard and pins
Neo4j, which the graph screen, the agent and every running scan share.

Three separate bounds, because each stops a different cost:
  transaction timeout -> server work
  record cap          -> transfer
  serialised-byte cap -> memory (the webapp runs under mem_limit: 1g)

Deliberately NOT a rewritten `LIMIT`: appending one breaks UNION, aggregations
and subqueries, and would mean trusting a second Cypher parser.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


class _FakeRecord(dict):
    def keys(self):
        return list(super().keys())

    def __getitem__(self, k):
        return super().__getitem__(k)


class _FakeResult:
    """Counts how many records the caller actually pulled."""

    def __init__(self, n):
        self._n = n
        self.pulled = 0

    def __iter__(self):
        for i in range(self._n):
            self.pulled += 1
            yield _FakeRecord({"i": i})


class _FakeSession:
    def __init__(self, result):
        self._result = result
        self.last_query = None
        self.last_params = None

    def run(self, query, params):
        self.last_query = query
        self.last_params = params
        return self._result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, session):
        self._session = session
        self.session_kwargs = None

    def session(self, **kwargs):
        # The real driver takes default_access_mode; recording it lets the
        # read-only assertion below check what was actually asked for.
        self.session_kwargs = kwargs
        return self._session


def _driver_with(n_records):
    result = _FakeResult(n_records)
    session = _FakeSession(result)
    return _FakeDriver(session), session, result


# --- env knobs ---------------------------------------------------------------

class EnvKnobTests(unittest.TestCase):
    def test_defaults_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("GRAPH_EXEC_MAX_RECORDS", "GRAPH_EXEC_MAX_BYTES", "NEO4J_QUERY_TIMEOUT_MS"):
                os.environ.pop(k, None)
            self.assertEqual(api._graph_exec_max_records(), 1000)
            self.assertEqual(api._graph_exec_max_bytes(), 2 * 1024 * 1024)
            self.assertEqual(api._graph_query_timeout_seconds(), 120.0)

    def test_garbage_and_zero_fall_back_to_the_default_never_to_no_limit(self):
        for bad in ("", "abc", "0", "-5"):
            with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_RECORDS": bad}):
                self.assertEqual(api._graph_exec_max_records(), 1000)

    def test_a_valid_value_is_honoured(self):
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_RECORDS": "7"}):
            self.assertEqual(api._graph_exec_max_records(), 7)

    def test_timeout_shares_the_webapp_env_var_and_default(self):
        with mock.patch.dict(os.environ, {"NEO4J_QUERY_TIMEOUT_MS": "5000"}):
            self.assertEqual(api._graph_query_timeout_seconds(), 5.0)


# --- transaction timeout -----------------------------------------------------

class TransactionTimeoutTests(unittest.TestCase):
    def test_every_read_carries_a_transaction_timeout(self):
        driver, session, _ = _driver_with(1)
        with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
            api._graph_exec_run("MATCH (n:IP) RETURN n", {})
        # neo4j.Query, not a bare string: that is what carries the timeout.
        self.assertEqual(getattr(session.last_query, "timeout", None), 120.0)

    def test_the_timeout_follows_the_env_var(self):
        driver, session, _ = _driver_with(1)
        with mock.patch.dict(os.environ, {"NEO4J_QUERY_TIMEOUT_MS": "3000"}):
            with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
                api._graph_exec_run("MATCH (n:IP) RETURN n", {})
        self.assertEqual(session.last_query.timeout, 3.0)

    def test_the_query_text_is_passed_through_unmodified(self):
        # The bounds must NOT rewrite the caller's Cypher.
        cypher = "MATCH (a:IP) RETURN a UNION MATCH (b:Host) RETURN b"
        driver, session, _ = _driver_with(0)
        with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
            api._graph_exec_run(cypher, {})
        self.assertEqual(str(session.last_query.text), cypher)
        self.assertNotIn("LIMIT", str(session.last_query.text))


# --- record cap --------------------------------------------------------------

class RecordCapTests(unittest.TestCase):
    def test_a_result_under_the_cap_is_not_truncated(self):
        driver, _, _ = _driver_with(3)
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_RECORDS": "10"}):
            with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
                records, truncated = api._graph_exec_run("MATCH (n:IP) RETURN n", {})
        self.assertEqual(len(records), 3)
        self.assertFalse(truncated)

    def test_a_result_over_the_cap_is_cut_and_flagged(self):
        driver, _, _ = _driver_with(50)
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_RECORDS": "5"}):
            with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
                records, truncated = api._graph_exec_run("MATCH (n:IP) RETURN n", {})
        self.assertEqual(len(records), 5)
        self.assertTrue(truncated)

    def test_the_cursor_is_not_drained_past_the_cap(self):
        # The whole point: stop pulling, rather than materialise everything and
        # slice afterwards (which costs the full read anyway).
        driver, _, result = _driver_with(10_000)
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_RECORDS": "5"}):
            with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
                api._graph_exec_run("MATCH (n:IP) RETURN n", {})
        self.assertLessEqual(result.pulled, 6, "the cursor was drained past the cap")

    def test_an_explicit_cap_overrides_the_env(self):
        driver, _, _ = _driver_with(10)
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_RECORDS": "1000"}):
            with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
                records, truncated = api._graph_exec_run("MATCH (n:IP) RETURN n", {}, 1)
        self.assertEqual(len(records), 1)
        self.assertTrue(truncated)


# --- byte cap ----------------------------------------------------------------

class ByteCapTests(unittest.TestCase):
    def test_a_small_payload_is_returned(self):
        payload = api._graph_exec_payload([{"a": 1}], False)
        self.assertEqual(payload, {"records": [{"a": 1}]})

    def test_truncated_is_reported_in_the_payload(self):
        payload = api._graph_exec_payload([{"a": 1}], True)
        self.assertTrue(payload["truncated"])

    def test_the_flag_is_absent_rather_than_false_when_complete(self):
        self.assertNotIn("truncated", api._graph_exec_payload([{"a": 1}], False))

    def test_an_oversized_payload_fails_loudly_instead_of_truncating_silently(self):
        big = [{"blob": "x" * 4096} for _ in range(64)]
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_BYTES": "1024"}):
            with self.assertRaises(api.GraphResultTooLarge):
                api._graph_exec_payload(big, False)

    def test_the_oversized_error_reports_both_numbers(self):
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_BYTES": "10"}):
            try:
                api._graph_exec_payload([{"blob": "x" * 500}], False)
            except api.GraphResultTooLarge as e:
                self.assertEqual(e.limit, 10)
                self.assertGreater(e.size, 10)
            else:
                self.fail("expected GraphResultTooLarge")


# --- the endpoint's responses ------------------------------------------------

class GraphExecResponseTests(unittest.TestCase):
    def test_an_oversized_result_is_a_413_naming_the_remedy(self):
        import json

        driver, _, _ = _driver_with(200)
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MAX_BYTES": "50"}):
            with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
                resp = api._graph_exec_respond("MATCH (n:IP) RETURN n", {})
        self.assertEqual(resp.status_code, 413)
        self.assertIn("narrow your query", json.loads(resp.body)["error"])

    def test_a_driver_failure_does_not_leak_detail_to_the_caller(self):
        import json

        def boom():
            raise RuntimeError("bolt://neo4j:7687 auth failed for user neo4j")

        with mock.patch.object(api, "_graph_exec_get_driver", side_effect=boom):
            resp = api._graph_exec_respond("MATCH (n:IP) RETURN n", {})
        body = json.loads(resp.body)
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("neo4j", body["error"].lower())
        self.assertNotIn("bolt", body["error"].lower())

    def test_a_driver_failure_logs_neither_the_query_nor_a_value(self):
        # A Neo4j syntax error quotes the query, and a parse error the value it failed on
        # (`date(s.name)` logs the host name): the query here is a model's (AI Navigator).
        class CypherSyntaxError(Exception):
            code = "Neo.ClientError.Statement.SyntaxError"

        def boom():
            raise CypherSyntaxError('Text cannot be parsed to a Date\n"probe-value-7731"\n'
                                    '"MATCH (s:Subdomain) RETURN probe_query_4412"')

        with mock.patch.object(api, "_graph_exec_get_driver", side_effect=boom):
            with self.assertLogs(api.logger, level="ERROR") as logs:
                resp = api._graph_exec_respond("MATCH (s:Subdomain) RETURN probe_query_4412", {})
        self.assertEqual(resp.status_code, 500)
        logged = "\n".join(logs.output)
        self.assertNotIn("probe-value-7731", logged)
        self.assertNotIn("probe_query_4412", logged)
        self.assertIn("Neo.ClientError.Statement.SyntaxError", logged)
        self.assertIn("CypherSyntaxError", logged)


# --- MCP concurrency ceiling --------------------------------------------------

class McpConcurrencyTests(unittest.TestCase):
    def setUp(self):
        api._graph_exec_mcp_sem = None

    def tearDown(self):
        api._graph_exec_mcp_sem = None

    def test_the_ceiling_defaults_to_five(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GRAPH_EXEC_MCP_CONCURRENCY", None)
            self.assertEqual(api._graph_exec_mcp_semaphore()._value, 5)

    def test_the_ceiling_is_configurable(self):
        with mock.patch.dict(os.environ, {"GRAPH_EXEC_MCP_CONCURRENCY": "4"}):
            self.assertEqual(api._graph_exec_mcp_semaphore()._value, 4)

    def test_source_defaults_to_empty_so_existing_callers_are_unthrottled(self):
        body = api.GraphExecRequest(op="types", user_id="u1", project_id="p1")
        self.assertEqual(body.source, "")

    def test_source_mcp_is_accepted(self):
        body = api.GraphExecRequest(op="types", user_id="u1", project_id="p1", source="mcp")
        self.assertEqual(body.source, "mcp")


if __name__ == "__main__":
    unittest.main()


class SummaryOpTests(unittest.TestCase):
    """`op: "summary"` returns early, so it must take the concurrency ceiling
    itself rather than at the shared exit the other ops use."""

    def test_it_runs_three_fixed_queries(self):
        from graph_db.coverage_stamps import COVERAGE_SUMMARY_CYPHER

        driver, session, _ = _driver_with(2)
        seen = []
        real = api._graph_exec_run

        def spy(final, params, max_records=None):
            seen.append(final)
            return real(final, params, max_records)

        with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver), \
             mock.patch.object(api, "_graph_exec_run", spy):
            resp = api._graph_exec_summary({"tenant_user_id": "u1", "tenant_project_id": "p1"})

        self.assertEqual(resp.status_code, 200)
        # All three are server-controlled constants, never caller input: the
        # label census, the relationship census and the BaseURL coverage counts.
        self.assertEqual(seen, [api._GRAPH_SUMMARY_NODES_CYPHER, api._GRAPH_SUMMARY_RELS_CYPHER,
                                COVERAGE_SUMMARY_CYPHER])

    def test_it_returns_the_coverage_block(self):
        import json

        def fake_run(final, params, max_records=None):
            if "BaseURL" in final:
                return [{"js_recon_complete": 2, "js_recon_not_scanned": 1}], False
            return [], False

        with mock.patch.object(api, "_graph_exec_run", fake_run):
            resp = api._graph_exec_summary({"tenant_user_id": "u1", "tenant_project_id": "p1"})
        body = json.loads(resp.body)
        self.assertEqual(body["coverage"]["js_recon"]["complete"], 2)
        self.assertEqual(body["coverage"]["js_recon"]["not_scanned"], 1)
        self.assertEqual(body["coverage"]["nuclei"], {"recorded": False})

    def test_an_unreadable_coverage_count_drops_the_block_not_the_census(self):
        # The counts are still true, so the census answers; a coverage block
        # read as all-zero would be the "never scanned" false negative again.
        import json

        def fake_run(final, params, max_records=None):
            if "BaseURL" in final:
                raise RuntimeError("timeout")
            return [{"label": "IP", "count": 3}], False

        with mock.patch.object(api, "_graph_exec_run", fake_run):
            resp = api._graph_exec_summary({"tenant_user_id": "u1", "tenant_project_id": "p1"})
        body = json.loads(resp.body)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body["nodes"], [{"label": "IP", "count": 3}])
        self.assertNotIn("coverage", body)

    def test_both_queries_carry_the_tenant_key_and_the_exclusions(self):
        for cypher in (api._GRAPH_SUMMARY_NODES_CYPHER, api._GRAPH_SUMMARY_RELS_CYPHER):
            self.assertIn("$tenant_user_id", cypher)
            self.assertIn("$tenant_project_id", cypher)
            self.assertIn("Muted", cypher)
            self.assertIn("stale_since IS NULL", cypher)

    def test_it_projects_counts_only_never_values(self):
        for cypher in (api._GRAPH_SUMMARY_NODES_CYPHER, api._GRAPH_SUMMARY_RELS_CYPHER):
            self.assertIn("count(*)", cypher)
            # No whole-node or property projection: sample values are live
            # target data and must not leak into an agent's context.
            self.assertNotIn("RETURN n ", cypher)
            self.assertNotIn("RETURN n,", cypher)

    def test_a_failure_is_a_500_with_no_detail(self):
        import json

        def boom():
            raise RuntimeError("bolt://neo4j:7687 refused")

        with mock.patch.object(api, "_graph_exec_get_driver", side_effect=boom):
            resp = api._graph_exec_summary({"tenant_user_id": "u1", "tenant_project_id": "p1"})

        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("bolt", json.loads(resp.body)["error"].lower())


class ReadOnlySessionTests(unittest.TestCase):
    """REGRESSION: /graph/exec ran in a WRITE session (audit finding F2).

    The read-only guard is a regex over the query text, and a regex cannot be
    the only thing between LLM-generated Cypher and a write: `\\u0043REATE`
    inside a string literal reads as CREATE to Neo4j and as nothing to the
    regex, and `apoc.cypher.runMany` then executes it. Asking the DATABASE for
    a read-only session moves the guarantee out of our parser and into the
    engine, which cannot be fooled by how the text is spelled.
    """

    def test_the_session_is_opened_READ_ONLY(self):
        from neo4j import READ_ACCESS

        driver, _, _ = _driver_with(1)
        with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
            api._graph_exec_run("MATCH (n:IP) RETURN n", {})

        self.assertEqual(
            driver.session_kwargs.get("default_access_mode"),
            READ_ACCESS,
            "graph/exec must open a READ session; the driver default is WRITE",
        )

    def test_the_summary_op_is_read_only_too(self):
        from neo4j import READ_ACCESS

        driver, _, _ = _driver_with(1)
        with mock.patch.object(api, "_graph_exec_get_driver", return_value=driver):
            api._graph_exec_summary({"tenant_user_id": "u1", "tenant_project_id": "p1"})

        self.assertEqual(driver.session_kwargs.get("default_access_mode"), READ_ACCESS)

"""
Tests for the redagraph CLI and its tenant-scoping helpers.

Covers:
- graph_db.tenant_filter (unit)
- mcp/servers/redagraph.py helpers + parser (unit)
- mcp/servers/terminal_server.py _read_init_frame (integration with mock WS)
"""
import asyncio
import importlib.util
import io
import json
import os
import sys
import types
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_module(dotted_name: str, file_path: str):
    """Load a module from an absolute file path, registering it in sys.modules."""
    spec = importlib.util.spec_from_file_location(dotted_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[dotted_name] = module
    spec.loader.exec_module(module)
    return module


# Stub `graph_db` package so the host-side import does not pull in neo4j_client
# (which requires the `neo4j` driver, only present in the container).
_graph_db_stub = types.ModuleType("graph_db")
_graph_db_stub.__path__ = [os.path.join(REPO_ROOT, "graph_db")]
sys.modules["graph_db"] = _graph_db_stub

# redagraph._agent_post does `import requests`; ensure it is importable in the
# test env (stub if the host lacks it) so tests can patch `requests.post`.
try:
    import requests  # noqa: F401
except Exception:
    _requests_stub = types.ModuleType("requests")

    class _RequestException(Exception):
        pass

    _requests_stub.RequestException = _RequestException
    _requests_stub.post = lambda *a, **k: None
    sys.modules["requests"] = _requests_stub

tf = _load_module("graph_db.tenant_filter", os.path.join(REPO_ROOT, "graph_db", "tenant_filter.py"))
rg = _load_module("redagraph", os.path.join(REPO_ROOT, "mcp", "servers", "redagraph.py"))
ts = _load_module("terminal_server", os.path.join(REPO_ROOT, "mcp", "servers", "terminal_server.py"))


# =============================================================================
# graph_db.tenant_filter
# =============================================================================
class TestInjectTenantFilter(unittest.TestCase):
    def test_simple_label_no_props(self):
        out = tf.inject_tenant_filter("MATCH (d:Domain) RETURN d", "U", "P")
        self.assertEqual(
            out,
            "MATCH (d:Domain&!Muted {user_id: $tenant_user_id, "
            "project_id: $tenant_project_id}) RETURN d",
        )

    def test_label_with_existing_props(self):
        out = tf.inject_tenant_filter('MATCH (d:Domain {name: "x.com"}) RETURN d', "U", "P")
        self.assertIn("name:", out)
        self.assertIn("user_id: $tenant_user_id", out)
        self.assertIn("project_id: $tenant_project_id", out)

    def test_label_with_empty_braces(self):
        out = tf.inject_tenant_filter("MATCH (d:Domain {}) RETURN d", "U", "P")
        self.assertIn("user_id: $tenant_user_id", out)
        self.assertNotIn(", ,", out)

    def test_multiple_nodes_in_path(self):
        q = "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, s"
        out = tf.inject_tenant_filter(q, "U", "P")
        self.assertEqual(out.count("user_id: $tenant_user_id"), 2)
        self.assertEqual(out.count("project_id: $tenant_project_id"), 2)

    def test_unlabelled_node_is_scoped(self):
        # Was previously left alone, which let `MATCH (n) WHERE n:Package` read
        # every tenant's nodes. See TestCrossTenantLeakRegression below.
        out = tf.inject_tenant_filter("MATCH (n) RETURN n", "U", "P")
        self.assertEqual(
            out,
            "MATCH (n:!Muted {user_id: $tenant_user_id, "
            "project_id: $tenant_project_id}) RETURN n",
        )

    def test_anonymous_with_label_only_is_scoped(self):
        out = tf.inject_tenant_filter("MATCH (:Subdomain) RETURN count(*)", "U", "P")
        self.assertEqual(
            out,
            "MATCH (:Subdomain&!Muted {user_id: $tenant_user_id, "
            "project_id: $tenant_project_id}) RETURN count(*)",
        )

    def test_relationship_brackets_are_not_touched(self):
        q = "MATCH (d:Domain)-[r:HAS_PORT]->(p:Port) RETURN r"
        out = tf.inject_tenant_filter(q, "U", "P")
        self.assertNotIn("r:HAS_PORT {", out)
        self.assertIn("(p:Port&!Muted {user_id: $tenant_user_id", out)

    def test_already_scoped_pattern_is_not_doubled(self):
        once = tf.inject_tenant_filter("MATCH (p:Package) RETURN p", "U", "P")
        twice = tf.inject_tenant_filter(once, "U", "P")
        self.assertEqual(once, twice)
        self.assertEqual(twice.count("user_id: $tenant_user_id"), 1)


class TestCrossTenantLeakRegression(unittest.TestCase):
    """Every node-pattern shape must be scoped, not just `(var:Label)`.

    The old regex `\\((\\w+):(\\w+)...\\)` matched only that one shape. Live on
    2026-08-11 an agent asked for "all malicious packages", the model emitted
    `MATCH (n) WHERE n:MalPackageFinding ...`, nothing was injected, and the
    answer contained a finding belonging to a different project.
    """

    LEAK_SHAPES = {
        "unlabelled variable": "MATCH (n) WHERE n:Package RETURN n",
        "multi label": "MATCH (n:Package:Npm) RETURN n",
        "backtick label": "MATCH (n:`Mal Package`) RETURN n",
        "unlabelled with props": 'MATCH (n {name: "x"}) RETURN n',
        "label without variable": "MATCH (:Subdomain) RETURN count(*)",
        "anonymous endpoint": "MATCH (p:Package)-[:DEPENDS_ON]->() RETURN p",
        "second pattern unlabelled": "MATCH (p:Package) OPTIONAL MATCH (n) RETURN p, n",
        "label expression": "MATCH (n:Package|MalPackageFinding) RETURN n",
    }

    def test_every_leak_shape_is_scoped(self):
        for name, query in self.LEAK_SHAPES.items():
            with self.subTest(shape=name):
                out = tf.scope_query(query, "U", "P")
                self.assertIsNone(
                    tf.find_unscoped_node_pattern(out),
                    f"{name} still has an unscoped pattern: {out}",
                )

    def test_the_live_leaking_query(self):
        """The exact query that returned another project's malicious package."""
        query = (
            "MATCH (n)\n"
            "WHERE n:JsReconFinding OR n:Secret OR n:MultiscannerFinding\n"
            "   OR (n:MalPackageFinding AND (n.advisory_id STARTS WITH 'MAL-'"
            " OR any(a IN coalesce(n.aliases,[]) WHERE a STARTS WITH 'MAL-')))\n"
            "OPTIONAL MATCH (pkg:Package)-[:FLAGGED_AS]->(n)\n"
            "RETURN labels(n)[0] AS node_type, pkg.name AS package\n"
        )
        out = tf.scope_query(query, "U", "P")
        self.assertIsNone(tf.find_unscoped_node_pattern(out))
        # The driving MATCH is what leaked; it must carry the tenant keys.
        self.assertIn(
            "MATCH (n:!Muted {user_id: $tenant_user_id, project_id: $tenant_project_id})",
            out,
        )

    def test_unscoped_query_is_refused_not_executed(self):
        for malformed in ("MATCH (n:) RETURN n", "MATCH (n:A&) RETURN n",
                          "MATCH (n:A::B) RETURN n"):
            with self.subTest(query=malformed):
                with self.assertRaises(tf.TenantScopeError) as ctx:
                    # A pattern the grammar cannot parse must fail closed. A
                    # half-written label expression must NOT be silently
                    # completed into `(n:!Muted {tenant})`, which would turn a
                    # query Neo4j rejects into one returning the whole project.
                    tf.scope_query(malformed, "U", "P")
                self.assertIn("could not be scoped", str(ctx.exception))

    def test_unbalanced_parentheses_are_refused(self):
        # The scanner skips a pattern whose closing paren is missing, so such a
        # query could otherwise reach Neo4j with nothing injected.
        with self.assertRaises(tf.TenantScopeError):
            tf.scope_query("MATCH (n:(A|B) RETURN n", "U", "P")

    def test_find_unscoped_reports_the_offending_pattern(self):
        self.assertIsNone(
            tf.find_unscoped_node_pattern(
                "MATCH (p:Package {user_id: $tenant_user_id, project_id: $tenant_project_id}) RETURN p"
            )
        )
        self.assertEqual(
            tf.find_unscoped_node_pattern("MATCH (p:Package) RETURN p"), "(p:Package)"
        )


class TestScopingDoesNotBreakValidQueries(unittest.TestCase):
    """Function calls and expressions must not be mistaken for node patterns.

    `collect(p)` and `(p)` are the same characters; getting this wrong either
    corrupts a valid query or rejects it. Each of these executed successfully
    against Neo4j 5 after scoping.
    """

    VALID = [
        "MATCH (p:Package) RETURN count(*) AS c",
        "MATCH (p:Package) RETURN collect(p.name) AS names",
        "MATCH (d:Domain)-[r:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, r, s",
        "MATCH (p:Package) RETURN coalesce(p.purl, p.name) AS id ORDER BY id LIMIT 10",
        "CALL { MATCH (p:Package) RETURN count(p) AS c } RETURN c",
        "MATCH (p:Package) WHERE EXISTS { MATCH (p)-[:FLAGGED_AS]->(m:MalPackageFinding) } RETURN p",
        "MATCH (p:Package) WHERE COUNT { (p)-[:HAS_VULNERABILITY]->(v:Vulnerability) } > 2 RETURN p",
        "MATCH (p:Package) RETURN toLower(p.name) AS n, substring(p.version, 0, 3) AS v",
        "MATCH path = (a:Domain)-[:HAS_SUBDOMAIN*1..3]->(b:Subdomain) RETURN path LIMIT 5",
        "MATCH (p:Package) WITH p, count(*) AS c WHERE c > 1 RETURN p.name, c",
        "MATCH (p:Package) RETURN (p) AS node",
    ]

    def test_valid_queries_are_not_refused(self):
        for query in self.VALID:
            with self.subTest(query=query):
                tf.scope_query(query, "U", "P")  # must not raise

    def test_function_calls_are_not_rewritten(self):
        out = tf.scope_query("MATCH (p:Package) RETURN collect(p.name) AS names", "U", "P")
        self.assertIn("collect(p.name)", out)

    def test_string_literal_is_not_treated_as_a_pattern(self):
        out = tf.scope_query("MATCH (p:Package) WHERE p.name CONTAINS 'MATCH (x)' RETURN p", "U", "P")
        self.assertIn("'MATCH (x)'", out)
        self.assertEqual(out.count("user_id: $tenant_user_id"), 1)

    def test_comment_is_not_treated_as_a_pattern(self):
        out = tf.scope_query("MATCH (p:Package) // MATCH (q)\nRETURN p", "U", "P")
        self.assertEqual(out.count("user_id: $tenant_user_id"), 1)


class TestHasLabelledNodePattern(unittest.TestCase):
    """The /graph/exec least-privilege gate: the worker must name its labels.

    Isolation does not rely on this any more (scope_query scopes unlabelled
    patterns too), but a compromised kali-sandbox should still not be able to
    dump every node type with a bare `MATCH (n)`.
    """

    def test_bare_match_has_no_label(self):
        self.assertFalse(tf.has_labelled_node_pattern("MATCH (n) RETURN n"))
        self.assertFalse(tf.has_labelled_node_pattern("MATCH (n) WHERE n:Package RETURN n"))

    def test_labelled_forms_accepted(self):
        for query in (
            "MATCH (p:Package) RETURN p",
            "MATCH (:Subdomain) RETURN count(*)",
            "MATCH (n:`Mal Package`) RETURN n",
            "MATCH (p:Package) OPTIONAL MATCH (n) RETURN p, n",
        ):
            with self.subTest(query=query):
                self.assertTrue(tf.has_labelled_node_pattern(query))

    def test_second_unlabelled_pattern_is_still_scoped(self):
        """The gate passes, and scoping must still cover the unlabelled half."""
        query = "MATCH (p:Package) OPTIONAL MATCH (n) RETURN p, n"
        self.assertTrue(tf.has_labelled_node_pattern(query))
        out = tf.scope_query(query, "U", "P")
        self.assertEqual(out.count("user_id: $tenant_user_id"), 2)


class TestFindDisallowedWriteOperation(unittest.TestCase):
    READ_OK = [
        "MATCH (n:Foo) RETURN n",
        "OPTIONAL MATCH (n:Foo)-[r]->(m) RETURN n, m",
        "CALL db.labels()",
        "CALL db.schema.visualization()",
        "WITH 1 AS x RETURN x",
        "UNWIND [1,2,3] AS i RETURN i",
    ]
    WRITES = {
        "CREATE (n:Foo)": "CREATE",
        "MATCH (n:Foo) SET n.x = 1": "SET",
        "MATCH (n:Foo) DELETE n": "DELETE",
        "MATCH (n:Foo) DETACH DELETE n": "DETACH DELETE",
        "MATCH (n:Foo) REMOVE n.x": "REMOVE",
        "MERGE (n:Foo {id: 1})": "MERGE",
        "DROP INDEX foo": "DROP",
        "GRANT TRAVERSE ON GRAPH * TO role": "GRANT",
        "LOAD CSV FROM 'x.csv' AS r RETURN r": "LOAD CSV",
        "CALL apoc.create.node([], {})": "apoc.create",
        "CALL apoc.cypher.runWrite('CREATE ()')": "apoc.cypher",
        "CALL dbms.security.createUser('a','b')": "dbms.",
        # S8/E8: apoc.atomic.* mutates in place and must be blocked too.
        "CALL apoc.atomic.add(n, 'x', 1)": "apoc.atomic",
    }

    def test_read_only_returns_none(self):
        for q in self.READ_OK:
            with self.subTest(q=q):
                self.assertIsNone(tf.find_disallowed_write_operation(q))

    def test_writes_detected(self):
        for q, expected_substring in self.WRITES.items():
            with self.subTest(q=q):
                hit = tf.find_disallowed_write_operation(q)
                self.assertIsNotNone(hit, f"Should reject: {q}")
                self.assertIn(expected_substring.split()[0].lower(), hit.lower())

    def test_case_insensitive(self):
        self.assertIsNotNone(tf.find_disallowed_write_operation("create (n:Foo)"))
        self.assertIsNotNone(tf.find_disallowed_write_operation("MaTcH (n) SeT n.x = 1"))

    def test_word_boundary_no_false_positive_on_property_name(self):
        # `set_value` should NOT trigger SET (regex \b prevents it because _ is a word char)
        self.assertIsNone(tf.find_disallowed_write_operation("MATCH (n:Foo) RETURN n.set_value"))
        self.assertIsNone(tf.find_disallowed_write_operation("MATCH (n:Foo) RETURN n.create_time"))

    def test_known_limitation_property_name_equals_keyword(self):
        # Pre-existing behaviour: if a property is literally named SET/CREATE
        # the word-boundary regex fires. Documented, not fixed in this CLI.
        self.assertIsNotNone(tf.find_disallowed_write_operation("MATCH (n:Foo) RETURN n.SET"))


# =============================================================================
# redagraph helpers
# =============================================================================
class TestToPlain(unittest.TestCase):
    def test_none(self):
        self.assertEqual(rg._to_plain(None), "")

    def test_str(self):
        self.assertEqual(rg._to_plain("hello"), "hello")

    def test_int(self):
        self.assertEqual(rg._to_plain(42), "42")

    def test_dict_serialises(self):
        out = rg._to_plain({"a": 1, "b": "x"})
        self.assertIn('"a"', out)
        self.assertIn('"b"', out)

    def test_list_serialises(self):
        self.assertEqual(rg._to_plain([1, 2]), "[1, 2]")


class _FakeRecord:
    """Minimal stand-in for neo4j.Record.

    Supports .keys() and __getitem__ which is all _emit / _record_to_dict use.
    """
    def __init__(self, mapping):
        self._mapping = dict(mapping)

    def keys(self):
        return list(self._mapping.keys())

    def __getitem__(self, key):
        return self._mapping[key]


class _FakeNode:
    """Duck-type stand-in for neo4j.graph.Node."""
    def __init__(self, labels, props):
        self.labels = frozenset(labels)
        self._props = dict(props)
    def items(self):
        return self._props.items()


class _FakeRelationship:
    def __init__(self, rel_type, props, nodes=("a", "b")):
        self.type = rel_type
        self._props = dict(props)
        self.nodes = nodes
    def items(self):
        return self._props.items()


class TestCoerce(unittest.TestCase):
    def test_primitives_passthrough(self):
        for v in (None, True, 1, 2.5, "x"):
            self.assertEqual(rg._coerce(v), v)

    def test_node_serialises(self):
        n = _FakeNode(["Subdomain"], {"name": "x.com", "user_id": "U"})
        out = rg._coerce(n)
        self.assertEqual(out["_kind"], "node")
        self.assertEqual(out["labels"], ["Subdomain"])
        self.assertEqual(out["properties"]["name"], "x.com")

    def test_relationship_serialises(self):
        r = _FakeRelationship("HAS_SUBDOMAIN", {"since": "2026"})
        out = rg._coerce(r)
        self.assertEqual(out["_kind"], "relationship")
        self.assertEqual(out["type"], "HAS_SUBDOMAIN")
        self.assertEqual(out["properties"]["since"], "2026")

    def test_list_of_nodes(self):
        out = rg._coerce([_FakeNode(["A"], {}), _FakeNode(["B"], {})])
        self.assertEqual([n["labels"] for n in out], [["A"], ["B"]])

    def test_nested_dict(self):
        out = rg._coerce({"k": _FakeNode(["A"], {"x": 1})})
        self.assertEqual(out["k"]["properties"]["x"], 1)

    def test_record_to_dict_uses_coerce(self):
        rec = _FakeRecord({"n": _FakeNode(["Domain"], {"name": "x.com"})})
        out = rg._record_to_dict(rec)
        self.assertEqual(out["n"]["_kind"], "node")
        self.assertEqual(out["n"]["properties"]["name"], "x.com")


class TestEmit(unittest.TestCase):
    def test_plain_single_column(self):
        recs = [_FakeRecord({"name": "a.com"}), _FakeRecord({"name": "b.com"})]
        buf = io.StringIO()
        rg._emit(recs, "plain", buf)
        self.assertEqual(buf.getvalue(), "a.com\nb.com\n")

    def test_plain_multi_column_uses_tsv_to_stdout_header_to_stderr(self):
        recs = [_FakeRecord({"k": "a", "v": 1})]
        buf = io.StringIO()
        with mock.patch("sys.stderr", new_callable=io.StringIO) as fake_err:
            rg._emit(recs, "plain", buf)
        self.assertEqual(buf.getvalue(), "a\t1\n")
        self.assertIn("k\tv", fake_err.getvalue())

    def test_json_ndjson(self):
        recs = [_FakeRecord({"name": "a"}), _FakeRecord({"name": "b"})]
        buf = io.StringIO()
        rg._emit(recs, "json", buf)
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), {"name": "a"})

    def test_tsv_with_header(self):
        recs = [_FakeRecord({"k": "a", "v": "b"})]
        buf = io.StringIO()
        rg._emit(recs, "tsv", buf)
        self.assertEqual(buf.getvalue(), "k\tv\na\tb\n")

    def test_empty_records(self):
        buf = io.StringIO()
        rg._emit([], "plain", buf)
        self.assertEqual(buf.getvalue(), "")

    def test_plain_single_column_of_nodes_emits_all_props(self):
        # Output must reflect what the LLM was asked to RETURN. Whole nodes
        # render as `key=value key=value ...` — all attributes survive.
        recs = [
            _FakeRecord({"s": _FakeNode(["Subdomain"], {"name": "a.com", "status": "200"})}),
        ]
        buf = io.StringIO()
        rg._emit(recs, "plain", buf)
        line = buf.getvalue().rstrip("\n")
        self.assertIn("name=a.com", line)
        self.assertIn("status=200", line)

    def test_plain_scalar_is_unchanged(self):
        recs = [_FakeRecord({"name": "a.com"})]
        buf = io.StringIO()
        rg._emit(recs, "plain", buf)
        self.assertEqual(buf.getvalue(), "a.com\n")


class TestRequireTenant(unittest.TestCase):
    def test_exits_when_missing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as cm:
                rg._require_tenant()
            self.assertEqual(cm.exception.code, 2)

    def test_returns_pair_when_set(self):
        env = {"REDAMON_USER_ID": "U", "REDAMON_PROJECT_ID": "P"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(rg._require_tenant(), ("U", "P"))

    def test_blank_strings_treated_as_missing(self):
        env = {"REDAMON_USER_ID": "  ", "REDAMON_PROJECT_ID": "P"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit):
                rg._require_tenant()


class TestParser(unittest.TestCase):
    def setUp(self):
        self.p = rg.build_parser()

    def test_whoami(self):
        ns = self.p.parse_args(["whoami"])
        self.assertEqual(ns.cmd, "whoami")

    def test_ls_defaults(self):
        ns = self.p.parse_args(["ls", "Subdomain"])
        self.assertEqual(ns.node_type, "Subdomain")
        self.assertEqual(ns.attr, "name")
        self.assertEqual(ns.limit, 0)

    def test_ls_with_attr_and_limit(self):
        ns = self.p.parse_args(["ls", "Endpoint", "-a", "baseurl", "--limit", "50"])
        self.assertEqual(ns.attr, "baseurl")
        self.assertEqual(ns.limit, 50)

    def test_cypher(self):
        ns = self.p.parse_args(["cypher", "MATCH (n:Foo) RETURN n"])
        self.assertEqual(ns.query, "MATCH (n:Foo) RETURN n")

    def test_ask_with_show(self):
        ns = self.p.parse_args(["ask", "how many subs", "--show"])
        self.assertEqual(ns.question, ["how many subs"])
        self.assertTrue(ns.show)

    def test_ask_unquoted_multi_word(self):
        # Regression: `redagraph ask domain list` must not error.
        ns = self.p.parse_args(["ask", "domain", "list"])
        self.assertEqual(ns.question, ["domain", "list"])

    def test_format_choices(self):
        ns = self.p.parse_args(["--format", "json", "whoami"])
        self.assertEqual(ns.format, "json")
        with self.assertRaises(SystemExit):
            self.p.parse_args(["--format", "yaml", "whoami"])

    def test_output_flag(self):
        ns = self.p.parse_args(["-o", "/tmp/x.txt", "whoami"])
        self.assertEqual(ns.output, "/tmp/x.txt")


def _fake_resp(status, payload):
    r = mock.MagicMock()
    r.status_code = status
    r.json.return_value = payload
    r.text = json.dumps(payload)
    return r


class TestExecuteProxy(unittest.TestCase):
    """_execute proxies to the agent's /graph/exec; the agent enforces read-only
    + tenant scoping. The CLI must send the right op and surface the agent's
    rejections with the right exit codes (write/label = 3, transport = 4)."""

    def test_sends_cypher_op_and_returns_records(self):
        with mock.patch("requests.post", return_value=_fake_resp(200, {"records": [{"x": 1}]})) as post:
            recs = rg._execute("MATCH (n:Foo) RETURN n.x AS x", "U", "P")
        self.assertEqual(recs, [{"x": 1}])
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["op"], "cypher")
        self.assertEqual(body["cypher"], "MATCH (n:Foo) RETURN n.x AS x")
        self.assertEqual(body["user_id"], "U")
        self.assertEqual(body["project_id"], "P")
        # The URL must hit the agent's /graph/exec, NEVER a database.
        self.assertIn("/graph/exec", post.call_args.args[0])

    def test_server_write_rejection_exits_3(self):
        with mock.patch("requests.post", return_value=_fake_resp(403, {"error": "write operation rejected (CREATE); read-only"})):
            with self.assertRaises(SystemExit) as cm:
                rg._execute("CREATE (n:Foo)", "U", "P")
        self.assertEqual(cm.exception.code, 3)

    def test_server_label_rejection_exits_3(self):
        with mock.patch("requests.post", return_value=_fake_resp(400, {"error": "no labelled node pattern; cannot scope"})):
            with self.assertRaises(SystemExit) as cm:
                rg._execute("MATCH (n) RETURN n", "U", "P")
        self.assertEqual(cm.exception.code, 3)

    def test_unreachable_agent_exits_4(self):
        import requests as _rq
        with mock.patch("requests.post", side_effect=_rq.RequestException("down")):
            with self.assertRaises(SystemExit) as cm:
                rg._execute("MATCH (n:Foo) RETURN n", "U", "P")
        self.assertEqual(cm.exception.code, 4)

    def test_worker_holds_no_neo4j_creds(self):
        # DP5: redagraph must not read Neo4j credentials or open a driver.
        src = open(os.path.join(REPO_ROOT, "mcp", "servers", "redagraph.py")).read()
        self.assertNotIn("NEO4J_PASSWORD", src)
        self.assertNotIn("GraphDatabase", src)


class TestCmdTypesProxied(unittest.TestCase):
    """cmd_types / cmd_schema run as fixed server-side ops (no client Cypher)."""

    def test_types_sends_types_op(self):
        with mock.patch("requests.post", return_value=_fake_resp(200, {"records": []})) as post:
            args = types.SimpleNamespace(format="plain")
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                rg.cmd_types(args, "U", "P")
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["op"], "types")
        self.assertEqual(body["user_id"], "U")
        self.assertEqual(body["project_id"], "P")
        self.assertNotIn("cypher", body)  # worker does not supply the query

    def test_schema_sends_schema_op(self):
        with mock.patch("requests.post", return_value=_fake_resp(200, {"records": []})) as post:
            args = types.SimpleNamespace(format="plain")
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                rg.cmd_schema(args, "U", "P")
        self.assertEqual(post.call_args.kwargs["json"]["op"], "schema")


# =============================================================================
# terminal_server._read_init_frame
# =============================================================================
class _FakeWS:
    """Minimal websocket stub for _read_init_frame: queue of messages to recv()."""
    def __init__(self, messages, raise_timeout_after=False):
        self._messages = list(messages)
        self._raise_timeout_after = raise_timeout_after

    async def recv(self):
        if not self._messages:
            if self._raise_timeout_after:
                # Simulate hanging — wait_for will time out.
                await asyncio.sleep(10)
            raise RuntimeError("no more messages")
        return self._messages.pop(0)


class TestReadInitFrame(unittest.TestCase):
    def _run(self, ws, timeout=0.5):
        return asyncio.run(ts._read_init_frame(ws, timeout=timeout))

    def test_init_frame_parsed(self):
        ws = _FakeWS([json.dumps({"type": "init", "user_id": "U", "project_id": "P"})])
        env, replay = self._run(ws)
        self.assertEqual(env, {"REDAMON_USER_ID": "U", "REDAMON_PROJECT_ID": "P"})
        self.assertEqual(replay, b"")

    def test_init_with_blank_user_is_skipped(self):
        ws = _FakeWS([json.dumps({"type": "init", "user_id": "", "project_id": "P"})])
        env, replay = self._run(ws)
        self.assertNotIn("REDAMON_USER_ID", env)
        self.assertEqual(env.get("REDAMON_PROJECT_ID"), "P")
        self.assertEqual(replay, b"")

    def test_non_init_json_is_replayed(self):
        msg = json.dumps({"type": "resize", "rows": 24, "cols": 80})
        ws = _FakeWS([msg])
        env, replay = self._run(ws)
        self.assertEqual(env, {})
        self.assertEqual(replay, msg.encode("utf-8"))

    def test_raw_keystroke_is_replayed(self):
        ws = _FakeWS([b"ls\n"])
        env, replay = self._run(ws)
        self.assertEqual(env, {})
        self.assertEqual(replay, b"ls\n")

    def test_invalid_json_is_replayed_as_bytes(self):
        ws = _FakeWS(["not json at all"])
        env, replay = self._run(ws)
        self.assertEqual(env, {})
        self.assertEqual(replay, b"not json at all")

    def test_timeout_returns_empty(self):
        ws = _FakeWS([], raise_timeout_after=True)
        env, replay = self._run(ws, timeout=0.05)
        self.assertEqual(env, {})
        self.assertEqual(replay, b"")


class TestRedagraphSendsScannerKey(unittest.TestCase):
    """S8/I8: redagraph presents X-Internal-Key: SCANNER_API_KEY on /graph/exec."""

    def _capture_post(self):
        captured = {}

        class _Resp:
            status_code = 200
            def json(self_inner):
                return {"records": []}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers or {}
            return _Resp()

        return captured, fake_post

    def test_sends_scanner_key_when_set(self):
        captured, fake_post = self._capture_post()
        with mock.patch("requests.post", fake_post), \
             mock.patch.dict(os.environ, {"SCANNER_API_KEY": "scoped-key-xyz"}):
            rg._agent_post({"op": "types", "user_id": "u", "project_id": "p"})
        self.assertEqual(captured["headers"].get("X-Internal-Key"), "scoped-key-xyz")

    def test_no_header_when_unset(self):
        captured, fake_post = self._capture_post()
        env = {k: v for k, v in os.environ.items() if k != "SCANNER_API_KEY"}
        with mock.patch("requests.post", fake_post), \
             mock.patch.dict(os.environ, env, clear=True):
            rg._agent_post({"op": "types", "user_id": "u", "project_id": "p"})
        self.assertNotIn("X-Internal-Key", captured["headers"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

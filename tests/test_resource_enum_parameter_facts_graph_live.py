"""LIVE-Neo4j proof that the resource writer keeps parameter facts it did not observe (D5).

update_graph_from_resource_enum is the one Endpoint/Parameter writer every crawler
and most partial tools share. A caller hands it only what its own tool saw: FFuf
and Kiterunner find paths but never look at parameters, Arjun names parameters
but sees no form, urlscan's partial writes carry no form either. What such a
caller did not observe must keep what an earlier writer stored:

- Endpoint.has_parameters only goes from false to true;
- each *_param_count keeps the stored count when the caller counted none at that
  position (or no count at all), and a count the caller did measure replaces it,
  as urls_found and a Parameter's sample_values already do (R-27);
- Parameter.source is first-writer provenance, as Endpoint.source is (R-27);
- a body Parameter's input_type and required, and a path Parameter's required,
  keep the stored value when the caller did not say.

A node the writer creates still gets the defaults it always got.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_resource_enum_parameter_facts_graph_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
Only example.com names are used.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()

HOST = "app.example.com"
BASE = f"https://{HOST}"
NO_PARAMS = {"query": [], "body": [], "path": []}


def _crawl(endpoints: dict) -> dict:
    """A resource_enum recon payload for BASE: {path: endpoint entry}."""
    return {"domain": "example.com", "subdomains": [HOST], "metadata": {},
            "resource_enum": {"by_base_url": {BASE: {"endpoints": endpoints}}, "forms": [],
                              "scan_metadata": {}, "summary": {}}}


def _counts(query=0, body=0, path=0):
    return {"query": query, "body": body, "path": path, "total": query + body + path}


def _katana_search():
    """A crawl saw /search?q=... and counted one query parameter."""
    return {"methods": ["GET"], "category": "search", "sources": ["katana"], "urls_found": 4,
            "parameters": {"query": [{"name": "q", "type": "string", "category": "search_params",
                                      "sample_values": ["shoes"]}], "body": [], "path": []},
            "parameter_count": _counts(query=1)}


def _form_login():
    """A crawl parsed the login form: a required password field."""
    return {"methods": ["POST"], "category": "authentication", "sources": ["katana"],
            "parameters": {"query": [], "path": [], "body": [
                {"name": "password", "type": "string", "category": "auth_params",
                 "input_type": "password", "required": True}]},
            "parameter_count": _counts(body=1)}


def _ffuf(sources=("ffuf",)):
    """FFuf's shape: a path it found, no parameter looked at."""
    return {"methods": ["GET"], "category": "other", "sources": list(sources),
            "parameters": dict(NO_PARAMS), "parameter_count": _counts(), "urls_found": 1}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestResourceWriterKeepsUnobservedParameterFactsLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.uid = "u-d5res-itest"
        self.pid = f"p-d5res-itest-{uuid.uuid4().hex[:8]}"

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n {project_id: $p}) DETACH DELETE n", p=self.pid)

    def _write(self, endpoints: dict):
        stats = self.client.update_graph_from_resource_enum(_crawl(endpoints), self.uid, self.pid)
        self.assertEqual(stats["errors"], [])
        return stats

    def _endpoint(self, path, method="GET"):
        with self.client.driver.session() as s:
            row = s.run("""MATCH (e:Endpoint {path: $path, method: $method, baseurl: $b,
                                              user_id: $u, project_id: $p})
                           RETURN properties(e) AS props""",
                        path=path, method=method, b=BASE, u=self.uid, p=self.pid).single()
            return row["props"] if row else None

    def _parameter(self, name, position, path):
        with self.client.driver.session() as s:
            row = s.run("""MATCH (p:Parameter {name: $n, position: $pos, endpoint_path: $path,
                                               baseurl: $b, user_id: $u, project_id: $p})
                           RETURN properties(p) AS props""",
                        n=name, pos=position, path=path, b=BASE, u=self.uid, p=self.pid).single()
            return row["props"] if row else None

    @staticmethod
    def _param_facts(props):
        return (props["has_parameters"], props["query_param_count"],
                props["body_param_count"], props["path_param_count"])

    # -- Endpoint: has_parameters and the counts -------------------------------

    def test_a_tool_that_looked_at_no_parameter_keeps_the_counts(self):
        self._write({"/search": _katana_search()})

        self._write({"/search": _ffuf()})

        search = self._endpoint("/search")
        self.assertEqual(self._param_facts(search), (True, 1, 0, 0))
        self.assertEqual(search["sources"], ["katana", "ffuf"])

    def test_a_caller_with_no_count_at_all_keeps_the_counts(self):
        self._write({"/search": _katana_search()})

        self._write({"/search": {"methods": ["GET"], "category": "other", "sources": ["gau"]}})

        self.assertEqual(self._param_facts(self._endpoint("/search")), (True, 1, 0, 0))

    def test_a_count_at_one_position_leaves_the_other_positions(self):
        self._write({"/search": _katana_search()})

        # Arjun found a body parameter on the same path and counted only that.
        self._write({"/search": {"methods": ["GET"], "category": "other", "sources": ["arjun"],
                                 "parameters": {"query": [], "path": [], "body": [
                                     {"name": "token", "type": "string", "category": "other",
                                      "sample_values": []}]},
                                 "parameter_count": _counts(body=1)}})

        self.assertEqual(self._param_facts(self._endpoint("/search")), (True, 1, 1, 0))

    def test_a_count_the_caller_measured_replaces_the_stored_one(self):
        self._write({"/search": _katana_search()})
        recrawl = _katana_search()
        recrawl["parameters"]["query"].append({"name": "page", "type": "integer", "category": "other"})
        recrawl["parameter_count"] = _counts(query=2)

        self._write({"/search": recrawl})

        self.assertEqual(self._param_facts(self._endpoint("/search")), (True, 2, 0, 0))

    # -- Parameter: source, input_type, required --------------------------------

    def test_parameter_source_stays_the_first_writers(self):
        with self.client.driver.session() as s:
            # What urlscan's own writer leaves on a parameter it found first.
            s.run("""MERGE (p:Parameter {name: 'q', position: 'query', endpoint_path: '/search',
                                         baseurl: $b, user_id: $u, project_id: $p})
                     ON CREATE SET p.source = 'urlscan', p.is_injectable = false""",
                  b=BASE, u=self.uid, p=self.pid)

        self._write({"/search": _katana_search()})

        q = self._parameter("q", "query", "/search")
        self.assertEqual((q["source"], q["category"], q["sample_values"]),
                         ("urlscan", "search_params", ["shoes"]))

    def test_a_parameter_no_writer_stamped_gets_the_writers_source(self):
        with self.client.driver.session() as s:
            # Nuclei's DAST writer creates a Parameter and records no source.
            s.run("""MERGE (p:Parameter {name: 'q', position: 'query', endpoint_path: '/search',
                                         baseurl: $b, user_id: $u, project_id: $p})
                     SET p.is_injectable = true""",
                  b=BASE, u=self.uid, p=self.pid)

        self._write({"/search": _katana_search()})

        q = self._parameter("q", "query", "/search")
        self.assertEqual((q["source"], q["is_injectable"]), ("resource_enum", True))

    def test_a_body_parameter_keeps_the_form_facts_a_later_tool_did_not_see(self):
        self._write({"/login": _form_login()})

        # Arjun's shape: the name, a guessed type, no input type, no required flag.
        self._write({"/login": {"methods": ["POST"], "category": "other", "sources": ["arjun"],
                                "parameters": {"query": [], "path": [], "body": [
                                    {"name": "password", "type": "string", "category": "other",
                                     "sample_values": []}]},
                                "parameter_count": _counts(body=1)}})

        password = self._parameter("password", "body", "/login")
        self.assertEqual((password["input_type"], password["required"], password["category"]),
                         ("password", True, "auth_params"))

    def test_form_facts_a_later_tool_did_see_replace_the_stored_ones(self):
        self._write({"/login": _form_login()})
        changed = _form_login()
        changed["parameters"]["body"][0].update(input_type="text", required=False)

        self._write({"/login": changed})

        password = self._parameter("password", "body", "/login")
        self.assertEqual((password["input_type"], password["required"]), ("text", False))

    def test_a_path_parameter_keeps_required_a_later_tool_did_not_state(self):
        # An API specification that leaves "required" off a path parameter.
        self._write({"/users/{id}": {"methods": ["GET"], "category": "api", "sources": ["openapi"],
                                     "parameters": {"query": [], "body": [], "path": [
                                         {"name": "id", "type": "integer", "category": "id_params",
                                          "required": False}]},
                                     "parameter_count": _counts(path=1)}})

        self._write({"/users/{id}": {"methods": ["GET"], "category": "api", "sources": ["kiterunner"],
                                     "parameters": {"query": [], "body": [], "path": [
                                         {"name": "id", "type": "string", "category": "other"}]},
                                     "parameter_count": _counts(path=1)}})

        self.assertIs(self._parameter("id", "path", "/users/{id}")["required"], False)

    # -- a node the writer creates ---------------------------------------------

    def test_a_fresh_node_gets_the_writer_defaults(self):
        self._write({
            "/about": {"methods": ["GET"], "sources": ["gau"]},
            "/signup": {"methods": ["POST"], "sources": ["arjun"],
                        "parameters": {"query": [], "body": [{"name": "email"}],
                                       "path": [{"name": "plan"}]},
                        "parameter_count": _counts(body=1, path=1)},
        })

        self.assertEqual(self._param_facts(self._endpoint("/about")), (False, 0, 0, 0))
        self.assertEqual(self._param_facts(self._endpoint("/signup", "POST")), (True, 0, 1, 1))
        email = self._parameter("email", "body", "/signup")
        self.assertEqual((email["source"], email["input_type"], email["required"]),
                         ("resource_enum", "text", False))
        plan = self._parameter("plan", "path", "/signup")
        self.assertEqual((plan["source"], plan["required"]), ("resource_enum", True))


if __name__ == "__main__":
    unittest.main()

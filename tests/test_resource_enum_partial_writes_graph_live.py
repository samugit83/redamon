"""LIVE-Neo4j proof that partial writes keep what they did not measure (R-27, D5).

The unit tests check the Cypher text; only a real database proves the values:

- the partial Endpoint AI Classifier's own writer sets the AI fields and leaves
  every crawl field (category, urls_found, source, sample_values, counts,
  updated_at) as the crawl stored it, never creates a node, never touches
  another project, and its "non-llm" never replaces a type another source found;
- update_graph_from_resource_enum, fed by a partial tool that did not measure
  urls_found, a parameter's category or its sample values (GAU, Arjun), keeps
  the stored ones, while a fresh node still gets the writer's defaults and a
  tool that did measure them still replaces them.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_resource_enum_partial_writes_graph_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
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


def _crawl(endpoints: dict) -> dict:
    """A resource_enum recon payload for BASE: {path: endpoint entry}."""
    return {"domain": "example.com", "subdomains": [HOST], "metadata": {},
            "resource_enum": {"by_base_url": {BASE: {"endpoints": endpoints}}, "forms": [],
                              "scan_metadata": {}, "summary": {}}}


def _katana_login():
    """What a crawl measured on /login: a specific category, 7 URLs, a seen value."""
    return {"methods": ["GET"], "category": "authentication", "sources": ["katana"],
            "urls_found": 7,
            "parameters": {"query": [{"name": "user", "type": "string", "category": "auth_params",
                                      "sample_values": ["alice"]}], "body": [], "path": []},
            "parameter_count": {"total": 1, "query": 1, "body": 0, "path": 0}}


def _katana_chat():
    return {"methods": ["POST"], "category": "api", "sources": ["katana"], "urls_found": 2,
            "parameters": {"query": [], "path": [],
                           "body": [{"name": "messages", "type": "string", "category": "other"}]},
            "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestPartialWritesKeepUnmeasuredFieldsLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.uid = "u-r27-itest"
        self.pid = f"p-r27-itest-{uuid.uuid4().hex[:8]}"
        self.other_pid = f"{self.pid}-other"

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.project_id IN [$a, $b] DETACH DELETE n", a=self.pid, b=self.other_pid)

    def _endpoint(self, path, method="GET", pid=None):
        with self.client.driver.session() as s:
            row = s.run("""MATCH (e:Endpoint {path: $path, method: $method, baseurl: $b,
                                              user_id: $u, project_id: $p})
                           RETURN properties(e) AS props""",
                        path=path, method=method, b=BASE, u=self.uid, p=pid or self.pid).single()
            return row["props"] if row else None

    def _parameter(self, name, position, path, pid=None):
        with self.client.driver.session() as s:
            row = s.run("""MATCH (p:Parameter {name: $n, position: $pos, endpoint_path: $path,
                                               baseurl: $b, user_id: $u, project_id: $p})
                           RETURN properties(p) AS props""",
                        n=name, pos=position, path=path, b=BASE, u=self.uid, p=pid or self.pid).single()
            return row["props"] if row else None

    def _count(self, label):
        with self.client.driver.session() as s:
            return s.run(f"MATCH (n:{label} {{user_id: $u, project_id: $p}}) RETURN count(n) AS n",
                         u=self.uid, p=self.pid).single()["n"]

    def _classify(self, endpoints: dict) -> dict:
        return self.client.update_graph_from_endpoint_ai_classifier({BASE: {"endpoints": endpoints}},
                                                                    self.uid, self.pid)

    # -- the classifier's own writer -----------------------------------------

    def test_the_classifier_sets_only_the_ai_fields(self):
        self.client.update_graph_from_resource_enum(
            _crawl({"/login": _katana_login(), "/v1/chat/completions": _katana_chat()}), self.uid, self.pid)
        login_before = self._endpoint("/login")
        user_before = self._parameter("user", "query", "/login")

        stats = self._classify({
            "/login": {"methods": ["GET"], "ai_interface_type": "non-llm",
                       "parameters": {"query": [{"name": "user"}]}},
            "/v1/chat/completions": {"methods": ["POST"], "ai_interface_type": "llm-chat",
                                     "parameters": {"body": [{"name": "messages",
                                                              "is_ai_prompt_injectable": True}]}},
        })

        self.assertEqual(stats["errors"], [])
        self.assertEqual((stats["endpoints_annotated"], stats["parameters_annotated"]), (2, 1))
        self.assertEqual(self._endpoint("/login"), {**login_before, "ai_interface_type": "non-llm"})
        self.assertEqual(self._parameter("user", "query", "/login"), user_before)
        self.assertEqual(self._endpoint("/v1/chat/completions", "POST")["ai_interface_type"], "llm-chat")
        self.assertIs(self._parameter("messages", "body", "/v1/chat/completions")["is_ai_prompt_injectable"],
                      True)

    def test_the_classifier_never_creates_a_node(self):
        self.client.update_graph_from_resource_enum(_crawl({"/login": _katana_login()}), self.uid, self.pid)
        before = (self._count("Endpoint"), self._count("Parameter"))

        stats = self._classify({"/v1/chat/completions": {
            "methods": ["POST"], "ai_interface_type": "llm-chat",
            "parameters": {"body": [{"name": "messages", "is_ai_prompt_injectable": True}]}}})

        self.assertEqual((stats["endpoints_annotated"], stats["parameters_annotated"]), (0, 0))
        self.assertEqual((self._count("Endpoint"), self._count("Parameter")), before)

    def test_non_llm_never_replaces_a_type_another_source_found(self):
        self.client.update_graph_from_resource_enum(
            _crawl({"/": {"methods": ["GET"], "category": "other", "sources": ["katana"]},
                    "/about": {"methods": ["GET"], "category": "other", "sources": ["katana"]},
                    "/api/chat": {"methods": ["GET"], "category": "api", "sources": ["katana"]}}),
            self.uid, self.pid)
        with self.client.driver.session() as s:
            # What AI Surface Recon's live chat probe leaves on a host root.
            s.run("""MATCH (e:Endpoint {path: '/', baseurl: $b, user_id: $u, project_id: $p})
                     SET e.ai_interface_type = 'llm-chat'""", b=BASE, u=self.uid, p=self.pid)
            s.run("""MATCH (e:Endpoint {path: '/api/chat', baseurl: $b, user_id: $u, project_id: $p})
                     SET e.ai_interface_type = 'non-llm'""", b=BASE, u=self.uid, p=self.pid)

        self._classify({"/": {"methods": ["GET"], "ai_interface_type": "non-llm"},
                        "/about": {"methods": ["GET"], "ai_interface_type": "non-llm"},
                        "/api/chat": {"methods": ["GET"], "ai_interface_type": "llm-chat"}})

        self.assertEqual(self._endpoint("/")["ai_interface_type"], "llm-chat")
        self.assertEqual(self._endpoint("/about")["ai_interface_type"], "non-llm")
        self.assertEqual(self._endpoint("/api/chat")["ai_interface_type"], "llm-chat")

    def test_a_field_the_classifier_left_out_keeps_the_stored_value(self):
        self.client.update_graph_from_resource_enum(_crawl({"/rag/ingest": {
            "methods": ["POST"], "category": "upload", "sources": ["katana"],
            "ai_interface_type": "rag-ingest", "is_ai_rag_ingest": True}}), self.uid, self.pid)

        # The path sub-toggle off: the classifier stamps no type, only the RAG flag.
        self._classify({"/rag/ingest": {"methods": ["POST"], "is_ai_rag_ingest": True}})

        props = self._endpoint("/rag/ingest", "POST")
        self.assertEqual((props["ai_interface_type"], props["is_ai_rag_ingest"]), ("rag-ingest", True))

    def test_another_projects_identical_endpoint_is_untouched(self):
        for pid in (self.pid, self.other_pid):
            self.client.update_graph_from_resource_enum(
                _crawl({"/v1/chat/completions": _katana_chat()}), self.uid, pid)

        self._classify({"/v1/chat/completions": {
            "methods": ["POST"], "ai_interface_type": "llm-chat",
            "parameters": {"body": [{"name": "messages", "is_ai_prompt_injectable": True}]}}})

        self.assertIsNone(self._endpoint("/v1/chat/completions", "POST", self.other_pid).get("ai_interface_type"))
        self.assertIsNone(self._parameter("messages", "body", "/v1/chat/completions",
                                          self.other_pid).get("is_ai_prompt_injectable"))

    # -- the shared crawl writer's safety net ---------------------------------

    def test_a_partial_tool_that_did_not_measure_keeps_the_crawl_values(self):
        self.client.update_graph_from_resource_enum(_crawl({"/login": _katana_login()}), self.uid, self.pid)

        # GAU's shape: no urls_found, an "other" guess, a parameter with no
        # category and no sample values.
        self.client.update_graph_from_resource_enum(_crawl({"/login": {
            "methods": ["GET"], "category": "other", "sources": ["gau"],
            "parameters": {"query": [{"name": "user", "type": "string"}], "body": [], "path": []},
            "parameter_count": {"total": 1, "query": 1, "body": 0, "path": 0}}}), self.uid, self.pid)

        login = self._endpoint("/login")
        self.assertEqual((login["category"], login["urls_found"], login["source"]),
                         ("authentication", 7, "resource_enum"))
        self.assertEqual(login["sources"], ["katana", "gau"])
        user = self._parameter("user", "query", "/login")
        self.assertEqual((user["category"], user["sample_values"]), ("auth_params", ["alice"]))

    def test_a_tool_that_measured_them_still_replaces_them(self):
        self.client.update_graph_from_resource_enum(_crawl({"/login": _katana_login()}), self.uid, self.pid)
        recrawl = _katana_login()
        recrawl["urls_found"] = 3
        recrawl["parameters"]["query"][0].update(category="id_params", sample_values=["bob"])

        self.client.update_graph_from_resource_enum(_crawl({"/login": recrawl}), self.uid, self.pid)

        self.assertEqual(self._endpoint("/login")["urls_found"], 3)
        user = self._parameter("user", "query", "/login")
        self.assertEqual((user["category"], user["sample_values"]), ("id_params", ["bob"]))

    def test_a_fresh_node_gets_the_writer_defaults(self):
        self.client.update_graph_from_resource_enum(_crawl({"/search": {
            "methods": ["GET"], "sources": ["gau"],
            "parameters": {"query": [{"name": "q"}], "body": [], "path": []}}}), self.uid, self.pid)

        search = self._endpoint("/search")
        self.assertEqual((search["category"], search["urls_found"], search["source"]),
                         ("other", 1, "resource_enum"))
        q = self._parameter("q", "query", "/search")
        self.assertEqual((q["category"], q["sample_values"]), ("other", []))

    def test_source_stays_the_first_writers(self):
        with self.client.driver.session() as s:
            s.run("""MERGE (e:Endpoint {path: '/', method: 'GET', baseurl: $b, user_id: $u, project_id: $p})
                     SET e.source = 'http_probe'""", b=BASE, u=self.uid, p=self.pid)

        self.client.update_graph_from_resource_enum(
            _crawl({"/": {"methods": ["GET"], "category": "other", "sources": ["katana"]}}),
            self.uid, self.pid)

        root = self._endpoint("/")
        self.assertEqual((root["source"], root["sources"]), ("http_probe", ["katana"]))


if __name__ == "__main__":
    unittest.main()

"""LIVE-Neo4j run of the partial Endpoint AI Classifier over a crawled graph (R-27).

The unit test (test_partial_endpoint_ai_classifier_writes.py) checks which
fields the module's Cypher assigns; this one runs the real module, with the real
_prepare_scope, against a real database and reads the values back: a crawl's
category, urls_found, source and sample values survive the classification, the
run's in-scope endpoints get their AI tags, and the endpoints of a scan root the
run does not cover, or of a host the RoE excludes, are left exactly as they were.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD --entrypoint python redamon-recon \\
    -m pytest tests/test_partial_endpoint_ai_classifier_graph_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
Only example.com / example.org names are used.
"""
from __future__ import annotations

import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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

ROOT, OTHER_ROOT = "example.com", "example.org"
IN_SCOPE = "https://app.example.com"
OTHER_GROUP = "https://shop.example.org"
ROE_EXCLUDED = "https://legacy.example.com"
CRAWLED = (IN_SCOPE, OTHER_GROUP, ROE_EXCLUDED)


def _crawl(base: str) -> dict:
    """What a full run's crawl wrote on one host: a login form and a chat API."""
    host = base.split("://", 1)[1]
    login = {"methods": ["GET"], "category": "authentication", "sources": ["katana"], "urls_found": 7,
             "parameters": {"query": [{"name": "user", "type": "string", "category": "auth_params",
                                       "sample_values": ["alice"]}], "body": [], "path": []},
             "parameter_count": {"total": 1, "query": 1, "body": 0, "path": 0}}
    chat = {"methods": ["POST"], "category": "api", "sources": ["katana"], "urls_found": 3,
            "parameters": {"query": [], "path": [],
                           "body": [{"name": "messages", "type": "string", "category": "other"}]},
            "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0}}
    return {"domain": host, "subdomains": [host], "metadata": {},
            "resource_enum": {"by_base_url": {base: {"endpoints": {"/login": login,
                                                                   "/v1/chat/completions": chat}}},
                              "forms": [], "scan_metadata": {}, "summary": {}}}


def _settings() -> dict:
    groups = [{"scanRoot": r, "orgDomain": r, "mode": "enumerate", "includeRoot": True,
               "exactHosts": []} for r in (ROOT, OTHER_ROOT)]
    return {"TARGET_DOMAIN": ROOT, "IP_MODE": False, "DOMAIN_BATCH_MODE": True,
            "VERIFY_DOMAIN_OWNERSHIP": False, "ROE_ENABLED": True,
            "ROE_EXCLUDED_HOSTS": ["legacy.example.com"], "SCOPE_GROUPS": groups}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestPartialEndpointAiClassifierLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.uid = "u-r27-classifier-itest"
        self.pid = f"p-r27-classifier-itest-{uuid.uuid4().hex[:8]}"
        for base in CRAWLED:
            self.client.update_graph_from_resource_enum(_crawl(base), self.uid, self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n {project_id: $p}) DETACH DELETE n", p=self.pid)

    def _snapshot(self) -> dict:
        """{(label, baseurl, path, method-or-name): properties} for the project."""
        with self.client.driver.session() as s:
            rows = s.run("""
                MATCH (n {user_id: $u, project_id: $p}) WHERE n:Endpoint OR n:Parameter
                RETURN labels(n)[0] AS label, n.baseurl AS b, coalesce(n.path, n.endpoint_path) AS path,
                       coalesce(n.method, n.name) AS key, properties(n) AS props""",
                         u=self.uid, p=self.pid)
            return {(r["label"], r["b"], r["path"], r["key"]): r["props"] for r in rows}

    def _classify(self):
        import recon.partial_recon as pr
        from recon.partial_recon_modules.endpoint_ai_classification import run_endpoint_ai_classifier

        cfg = {"tool_id": "EndpointAiClassifier", "domains": [ROOT], "include_graph_targets": True}
        self.assertEqual(pr._prepare_scope(cfg, _settings(), self.pid), {})
        env = {"USER_ID": self.uid, "PROJECT_ID": self.pid, "NEO4J_URI": _URI,
               "NEO4J_USER": _USER, "NEO4J_PASSWORD": _PASSWORD}
        with mock.patch.dict("os.environ", env):
            return run_endpoint_ai_classifier(cfg)

    def test_only_the_ai_fields_change_and_only_on_the_runs_hosts(self):
        before = self._snapshot()

        self.assertIsNone(self._classify())

        after = self._snapshot()
        self.assertEqual(set(after), set(before), "the classifier created or deleted a node")
        changed = {key: {f: after[key].get(f) for f in set(after[key]) | set(before[key])
                         if after[key].get(f) != before[key].get(f)}
                   for key in after if after[key] != before[key]}
        self.assertEqual(changed, {
            ("Endpoint", IN_SCOPE, "/login", "GET"): {"ai_interface_type": "non-llm"},
            ("Endpoint", IN_SCOPE, "/v1/chat/completions", "POST"): {"ai_interface_type": "llm-chat"},
            ("Parameter", IN_SCOPE, "/v1/chat/completions", "messages"): {"is_ai_prompt_injectable": True},
        })

    def test_the_crawl_values_survive(self):
        self._classify()

        after = self._snapshot()
        login = after[("Endpoint", IN_SCOPE, "/login", "GET")]
        self.assertEqual((login["category"], login["urls_found"], login["source"], login["sources"]),
                         ("authentication", 7, "resource_enum", ["katana"]))
        user = after[("Parameter", IN_SCOPE, "/login", "user")]
        self.assertEqual((user["category"], user["sample_values"]), ("auth_params", ["alice"]))


if __name__ == "__main__":
    unittest.main()

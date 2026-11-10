"""LIVE-Neo4j proof of R-49: a dependency-confusion finding sits on its host.

The unit test (recon/tests/test_js_recon_dependency_host.py) drives the writer
through a fake session. Only a real database proves the stored node: the
string list ``source_urls`` is accepted, the finding hangs off
BaseURL -> js_file, and the end-of-run prune reads its host (kept when js_recon
could not re-check that host, deleted when the host was re-checked).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_js_recon_dependency_host_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

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

BASE = "https://app.depconf-itest.test"
APP_JS = f"{BASE}/static/js/main.js"
ADMIN_JS = "https://admin.depconf-itest.test/assets/admin.js"


def _payload():
    return {
        "domain": "depconf-itest.test", "domains": ["depconf-itest.test"],
        "subdomains": ["app.depconf-itest.test", "admin.depconf-itest.test"],
        "js_recon": {
            "scan_metadata": {"scan_timestamp": "2026-11-11T00:00:00Z"},
            # The producer's shape (recon/helpers/js_recon/dependency.py).
            "dependencies": [{
                "id": "itest-depconf-1", "finding_type": "dependency_confusion",
                "package_name": "@acme/internal-ui", "scope": "@acme", "npm_exists": False,
                "severity": "critical", "confidence": "high",
                "title": "Dependency confusion: @acme/internal-ui not on public npm",
                "detail": "Package @acme/internal-ui is imported in JS but does not exist on npm.",
                "source_urls": [APP_JS, ADMIN_JS],
            }],
        },
    }


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestDependencyHostLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "depconf-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.pid = "depconf-itest-%s" % uuid.uuid4().hex[:10]
        with self.client.driver.session() as s:
            for url in (BASE, "https://admin.depconf-itest.test"):
                s.run("MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})",
                      url=url, uid=self.user, pid=self.pid)
        self.client.update_graph_from_js_recon(_payload(), self.user, self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n", pid=self.pid)

    def _one(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, pid=self.pid, **params).single()

    def _finding(self):
        rec = self._one("MATCH (f:JsReconFinding {project_id: $pid, finding_type: 'dependency_confusion'}) "
                        "RETURN properties(f) AS p")
        return rec["p"] if rec else None

    def _prune(self, **kw):
        from graph_db.mixins.base_mixin import run_timestamp
        return self.client.prune_unseen_findings(self.user, self.pid, ["js_recon"], run_timestamp(), **kw)

    def test_the_finding_carries_its_host_and_files(self):
        props = self._finding()
        self.assertEqual(props["base_url"], "https://admin.depconf-itest.test")
        self.assertEqual(props["source_url"], ADMIN_JS)
        self.assertEqual(props["source_urls"], [ADMIN_JS, APP_JS])

    def test_the_finding_hangs_off_its_baseurl_through_its_file(self):
        rec = self._one(
            "MATCH (b:BaseURL {project_id: $pid})-[:HAS_JS_FILE]->(file:JsReconFinding {finding_type: 'js_file'})"
            "-[:HAS_JS_FINDING]->(f:JsReconFinding {finding_type: 'dependency_confusion'}) "
            "RETURN collect(b.url) AS bases, collect(file.source_url) AS files")
        self.assertEqual(rec["bases"], ["https://admin.depconf-itest.test"])
        self.assertEqual(rec["files"], [ADMIN_JS])

    def test_a_rerun_refreshes_rather_than_duplicates(self):
        self.client.update_graph_from_js_recon(_payload(), self.user, self.pid)
        self.assertEqual(self._one(
            "MATCH (f:JsReconFinding {project_id: $pid}) WHERE f.finding_type <> 'js_file' "
            "RETURN count(f) AS c")["c"], 1)

    def test_a_host_js_recon_could_not_recheck_keeps_it(self):
        stats = self._prune(keep_hosts=["admin.depconf-itest.test"])
        self.assertIsNotNone(self._finding())
        self.assertEqual(stats["pruned"], 0)

    def test_another_host_cut_does_not_keep_it(self):
        self._prune(keep_hosts=["unrelated.depconf-itest.test"])
        self.assertIsNone(self._finding())

    def test_a_checked_host_prunes_it_and_an_unchecked_one_does_not(self):
        self._prune(only_hosts=["unrelated.depconf-itest.test"])
        self.assertIsNotNone(self._finding())
        self._prune(only_hosts=["admin.depconf-itest.test"])
        self.assertIsNone(self._finding())


if __name__ == "__main__":
    unittest.main()

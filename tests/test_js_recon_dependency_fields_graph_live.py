"""LIVE-Neo4j proof of S-19: a dependency finding stores its scope, npm answer
and recommendation.

The unit test (recon/tests/test_js_recon_dependency_fields.py) drives the
writer through a fake session. Only a real database proves what is stored:
``npm_exists`` false and true, and no property at all (never false) for a
finding without an npm answer, which ``SET += {npm_exists: null}`` gives.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_js_recon_dependency_fields_graph_live.py -v

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

BASE = "https://app.depfields-itest.test"
APP_JS = f"{BASE}/static/js/main.js"


def _finding(fid, name, **fields):
    """The producer's shape (recon/helpers/js_recon/dependency.py)."""
    return {"id": fid, "finding_type": "dependency_confusion", "package_name": name,
            "severity": "critical", "confidence": "high", "title": name, "detail": name,
            "source_urls": [APP_JS], **fields}


def _payload(dependencies):
    return {
        "domain": "depfields-itest.test", "domains": ["depfields-itest.test"],
        "subdomains": ["app.depfields-itest.test"],
        "js_recon": {"scan_metadata": {"scan_timestamp": "2026-11-11T00:00:00Z"},
                     "dependencies": dependencies},
    }


MISSING = _finding("itest-depconf-missing", "@acme/internal-ui", scope="@acme", npm_exists=False,
                   recommendation="Register @acme/internal-ui on npm as a placeholder or use a private registry.")
PUBLISHED = _finding("itest-depconf-exists", "@acme/billing-core", scope="@acme", npm_exists=True,
                     severity="high", recommendation="Verify npm ownership of @acme/billing-core.")
NO_ANSWER = _finding("itest-depconf-legacy", "@acme/legacy")


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestDependencyFieldsLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "depfields-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.pid = "depfields-itest-%s" % uuid.uuid4().hex[:10]
        with self.client.driver.session() as s:
            s.run("MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})",
                  url=BASE, uid=self.user, pid=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n", pid=self.pid)

    def _stored(self):
        with self.client.driver.session() as s:
            rows = s.run("MATCH (f:JsReconFinding {user_id: $uid, project_id: $pid, "
                         "finding_type: 'dependency_confusion'}) RETURN properties(f) AS p",
                         uid=self.user, pid=self.pid)
            return {r["p"]["package_name"]: r["p"] for r in rows}

    def test_each_finding_stores_its_scope_npm_answer_and_recommendation(self):
        self.client.update_graph_from_js_recon(_payload([MISSING, PUBLISHED]), self.user, self.pid)
        stored = self._stored()
        self.assertIs(stored["@acme/internal-ui"]["npm_exists"], False)
        self.assertIs(stored["@acme/billing-core"]["npm_exists"], True)
        self.assertEqual({p["package_scope"] for p in stored.values()}, {"@acme"})
        self.assertEqual(stored["@acme/billing-core"]["recommendation"],
                         "Verify npm ownership of @acme/billing-core.")

    def test_a_finding_without_an_npm_answer_has_no_npm_exists_property(self):
        self.client.update_graph_from_js_recon(_payload([NO_ANSWER]), self.user, self.pid)
        props = self._stored()["@acme/legacy"]
        self.assertNotIn("npm_exists", props)
        self.assertNotIn("recommendation", props)
        self.assertEqual(props["package_scope"], "@acme")


if __name__ == "__main__":
    unittest.main()

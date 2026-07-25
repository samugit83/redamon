"""Integration test: cache_scan findings -> Neo4j graph.

Requires a reachable Neo4j (NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD env).
Skips automatically if the database is not reachable, so it is safe in CI.

Run inside the recon image with host networking:
  docker run --rm --network host \
    -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=... \
    --entrypoint python3 redamon-recon:latest \
    -m unittest recon.tests.test_cache_scan_integration -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from graph_db import Neo4jClient
from graph_db.mixins.cache_mixin import CacheMixin

_UID = "itest-cache-user"
_PID = "itest-cache-project"
_RECON_JOB_PARAMS = {
    "recon_job_id": "job-cache-123",
    "recon_job_started_at": "2026-07-24T10:11:12Z",
}


def _neo4j_available() -> bool:
    try:
        with Neo4jClient() as c:
            return c.verify_connection()
    except Exception:
        return False


def _sample_recon(findings):
    return {"cache_scan": {"findings": findings}}


def _finding(url="https://shop.itest/home", header="X-Forwarded-Host", impact="open_redirect"):
    return {
        "endpoint_url": url,
        "technique": "unkeyed_header",
        "vector_type": "header",
        "cache_header": header,
        "cache_param": "",
        "impact": impact,
        "confidence": 0.97,
        "confidence_tier": "Confirmed",
        "severity": "high",
        "cvss_score": 7.4,
        "cache_signals": ["x-cache: hit", "age: 12"],
        "cache_buster": "rdmncb=cb1",
        "source_engine": "wcvs",
        "evidence": {
            "baseline_hash": "aaa", "poisoned_hash": "bbb", "clean_validation_hash": "ccc",
            "poc_link": f"{url}?rdmncb=cb1", "curl_verify": "curl ...", "canary": "rdmnX.invalid",
        },
        "cross_vantage": False,
    }


class _FakeResult:
    pass


class _FakeSession:
    def __init__(self):
        self.queries = []

    def run(self, query, **params):
        self.queries.append((query, params))
        return _FakeResult()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _FakeCacheClient(CacheMixin):
    def __init__(self, session):
        self.driver = _FakeDriver(session)

    def _recon_job_params(self):
        return dict(_RECON_JOB_PARAMS)


def _assert_seen_stamped(test_case, query, alias):
    test_case.assertIn(
        f"{alias}.first_seen = coalesce("
        f"{alias}.first_seen, datetime($recon_job_started_at))",
        query,
    )
    test_case.assertIn(
        f"{alias}.first_seen_job_id = coalesce("
        f"{alias}.first_seen_job_id, $recon_job_id)",
        query,
    )
    test_case.assertIn(
        f"{alias}.last_seen = datetime($recon_job_started_at)",
        query,
    )
    test_case.assertIn(f"{alias}.last_seen_job_id = $recon_job_id", query)


class TestCacheScanSeenStamping(unittest.TestCase):
    def test_every_cache_node_write_is_seen_stamped_with_job_params(self):
        session = _FakeSession()
        stats = _FakeCacheClient(session).update_graph_from_cache_scan(
            _sample_recon([_finding()]), _UID, _PID
        )
        self.assertEqual(stats["errors"], [])

        self.assertEqual(len(session.queries), 2)
        vuln_query, vuln_params = session.queries[0]
        wiring_query, wiring_params = session.queries[1]

        self.assertIn("SET v += $props", vuln_query)
        _assert_seen_stamped(self, vuln_query, "v")
        self.assertIn("MERGE (bu:BaseURL", wiring_query)
        self.assertIn("MERGE (e:Endpoint", wiring_query)
        _assert_seen_stamped(self, wiring_query, "bu")
        _assert_seen_stamped(self, wiring_query, "e")

        for params in (vuln_params, wiring_params):
            for name, value in _RECON_JOB_PARAMS.items():
                self.assertEqual(params.get(name), value)

        for relationship in ("HAS_ENDPOINT", "HAS_VULNERABILITY"):
            self.assertIn(relationship, wiring_query)
        self.assertNotIn("r.first_seen", wiring_query)
        self.assertNotIn("r.last_seen", wiring_query)


@unittest.skipUnless(_neo4j_available(), "Neo4j not reachable")
class TestCacheScanGraphIntegration(unittest.TestCase):
    @staticmethod
    def _wipe():
        with Neo4jClient() as c, c.driver.session() as s:
            s.run("MATCH (n {user_id:$u, project_id:$p}) DETACH DELETE n", u=_UID, p=_PID)

    def setUp(self):
        # Each test starts from a clean project so node counts are deterministic.
        self._wipe()

    @classmethod
    def tearDownClass(cls):
        cls._wipe()

    def _count_vulns(self):
        with Neo4jClient() as c, c.driver.session() as s:
            r = s.run(
                "MATCH (v:Vulnerability {user_id:$u, project_id:$p, source:'cache_poisoning'}) RETURN count(v) AS n",
                u=_UID, p=_PID,
            )
            return r.single()["n"]

    def test_creates_vulnerability_and_relationships(self):
        with Neo4jClient() as c:
            stats = c.update_graph_from_cache_scan(_sample_recon([_finding()]), _UID, _PID)
        self.assertEqual(stats["vulnerabilities_created"], 1)
        self.assertEqual(self._count_vulns(), 1)

        # Verify the Endpoint + BaseURL wiring and persisted props.
        with Neo4jClient() as c, c.driver.session() as s:
            rec = s.run(
                """
                MATCH (bu:BaseURL {user_id:$u, project_id:$p})-[:HAS_ENDPOINT]->(e:Endpoint)
                      -[:HAS_VULNERABILITY]->(v:Vulnerability {source:'cache_poisoning'})
                RETURN v.cache_header AS header, v.cache_impact AS impact,
                       v.confidence_tier AS tier, v.poc_link AS poc, bu.url AS baseurl,
                       v.cache_vector_type AS vtype
                """, u=_UID, p=_PID,
            ).single()
        self.assertIsNotNone(rec, "Endpoint/BaseURL/Vulnerability chain not wired")
        self.assertEqual(rec["header"], "X-Forwarded-Host")
        self.assertEqual(rec["impact"], "open_redirect")
        self.assertEqual(rec["tier"], "Confirmed")
        self.assertEqual(rec["vtype"], "header")  # vector_type persisted (graph completeness)
        self.assertTrue(rec["poc"])
        # BaseURL also directly linked (host-level)
        with Neo4jClient() as c, c.driver.session() as s:
            n = s.run(
                "MATCH (bu:BaseURL {user_id:$u, project_id:$p})-[:HAS_VULNERABILITY]->(v:Vulnerability {source:'cache_poisoning'}) RETURN count(*) AS n",
                u=_UID, p=_PID,
            ).single()["n"]
        self.assertGreaterEqual(n, 1)

    def test_detection_mode_persisted(self):
        # A non-reflective (differential) finding must persist detection_mode +
        # the differential_change evidence end-to-end.
        finding = _finding(header="X-Forwarded-Proto")
        finding["detection_mode"] = "differential"
        finding["confidence_tier"] = "Strong"
        finding["evidence"]["differential_change"] = "location"
        with Neo4jClient() as c:
            c.update_graph_from_cache_scan(_sample_recon([finding]), _UID, _PID)
        with Neo4jClient() as c, c.driver.session() as s:
            rec = s.run(
                """
                MATCH (v:Vulnerability {user_id:$u, project_id:$p, source:'cache_poisoning'})
                RETURN v.detection_mode AS mode, v.evidence AS ev
                """, u=_UID, p=_PID,
            ).single()
        self.assertEqual(rec["mode"], "differential")
        self.assertIn("location", rec["ev"])  # differential_change survived in evidence JSON

    def test_merge_is_idempotent(self):
        # Same finding twice -> still one Vulnerability (deterministic id MERGE).
        with Neo4jClient() as c:
            c.update_graph_from_cache_scan(_sample_recon([_finding()]), _UID, _PID)
            c.update_graph_from_cache_scan(_sample_recon([_finding()]), _UID, _PID)
        self.assertEqual(self._count_vulns(), 1)

    def test_distinct_vectors_distinct_nodes(self):
        with Neo4jClient() as c:
            c.update_graph_from_cache_scan(_sample_recon([
                _finding(header="X-Forwarded-Host"),
                _finding(header="X-Host"),
            ]), _UID, _PID)
        self.assertGreaterEqual(self._count_vulns(), 2)

    def test_empty_findings_no_error(self):
        with Neo4jClient() as c:
            stats = c.update_graph_from_cache_scan(_sample_recon([]), _UID, _PID)
        self.assertEqual(stats["vulnerabilities_created"], 0)
        self.assertEqual(stats["errors"], [])


if __name__ == "__main__":
    unittest.main()

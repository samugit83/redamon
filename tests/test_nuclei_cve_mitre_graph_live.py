"""LIVE-Neo4j: a nuclei finding reaches its CVE and the CVE's CWE / CAPEC (R-35).

The unit tests (recon/tests/test_nuclei_cve_mitre_graph.py) follow the writes
the writer sends; this runs them against Neo4j, where the MERGEs, the stale-edge
delete and the coalesce-only CVE fields actually execute.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_nuclei_cve_mitre_graph_live.py -v

Everything it creates is scoped to a throwaway tenant, plus CVE, MitreData and
Capec reference nodes with throwaway ids; all are deleted in tearDown.
"""

import copy
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

HOST = "www.example.com"

CHAIN = """
MATCH (v:Vulnerability {source: 'nuclei', user_id: $u, project_id: $p})
      -[:INCLUDES_CVE]->(c:CVE)-[:HAS_CWE]->(m:MitreData)-[:HAS_CAPEC]->(cap:Capec)
RETURN v.id AS vuln, c.id AS cve, m.id AS mitre, cap.capec_id AS capec
"""


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveNucleiCveMitreCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        n = int(run, 16) % 100000
        self.uid = f"r35-{run}"
        self.pid = f"R35_{run}"
        self.cve = f"CVE-1999-{n:05d}1"
        self.other_cve = f"CVE-1999-{n:05d}2"
        self.cwe = f"CWE-9{n:05d}"
        self.capec = f"CAPEC-9{n:05d}"
        self.mitre = f"{self.cve}-{self.cwe}"

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
            s.run("MATCH (c:CVE) WHERE c.id IN [$a, $b] DETACH DELETE c",
                  a=self.cve, b=self.other_cve)
            s.run("MATCH (m:MitreData {id: $m}) DETACH DELETE m", m=self.mitre)
            s.run("MATCH (c:Capec {capec_id: $c}) DETACH DELETE c", c=self.capec)

    def _recon(self, cve_id, enriched):
        finding = {
            "template_id": "r35-live-template",
            "name": "Live test path traversal",
            "severity": "high",
            "matched_at": f"http://{HOST}/cgi-bin/x",
            "cves": [{"id": cve_id, "cvss": 7.5, "url": "ignored"}],
            "cvss_score": 7.5,
            "raw": {"host": HOST, "ip": "192.0.2.10"},
        }
        all_cve = {"id": cve_id, "cvss": 7.5}
        if enriched:
            all_cve["mitre_attack"] = {"enriched": True, "cwe_hierarchy": {
                "id": self.cwe, "name": "Live test weakness", "mapping": "ALLOWED",
                "related_capec": [{"id": self.capec, "name": "Live test pattern"}],
            }}
        return {
            "domain": "example.com",
            "subdomains": [HOST],
            "vuln_scan": {"scan_metadata": {}, "discovered_urls": {},
                          "by_target": {HOST: {"findings": [finding]}},
                          "all_cves": [all_cve]},
        }

    def _write(self, recon):
        stats = self.client.update_graph_from_vuln_scan(copy.deepcopy(recon), self.uid, self.pid)
        self.assertEqual(stats["errors"], [])

    def _count(self, query, **params):
        with self.client.driver.session() as s:
            return s.run(query, u=self.uid, p=self.pid, **params).single()["n"]

    def test_phase_a_then_phase_b_build_the_chain_once(self):
        self._write(self._recon(self.cve, enriched=False))
        with self.client.driver.session() as s:
            self.assertEqual(list(s.run(CHAIN, u=self.uid, p=self.pid)), [])

        self._write(self._recon(self.cve, enriched=True))
        self._write(self._recon(self.cve, enriched=True))

        with self.client.driver.session() as s:
            rows = [dict(r) for r in s.run(CHAIN, u=self.uid, p=self.pid)]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["cve"], rows[0]["mitre"], rows[0]["capec"]),
                         (self.cve, self.mitre, self.capec))
        edges = {
            "INCLUDES_CVE": "MATCH (:Vulnerability {user_id: $u, project_id: $p})"
                            "-[r:INCLUDES_CVE]->(:CVE {id: $c}) RETURN count(r) AS n",
            "HAS_CWE": "MATCH (:CVE {id: $c})-[r:HAS_CWE]->(:MitreData {id: $m}) "
                       "RETURN count(r) AS n",
            "HAS_CAPEC": "MATCH (:MitreData {id: $m})-[r:HAS_CAPEC]->(:Capec {capec_id: $cap}) "
                         "RETURN count(r) AS n",
        }
        for rel, query in edges.items():
            with self.subTest(rel=rel):
                self.assertEqual(self._count(query, c=self.cve, m=self.mitre, cap=self.capec), 1)

    def test_the_reference_nodes_carry_no_tenant_stamp(self):
        self._write(self._recon(self.cve, enriched=True))
        with self.client.driver.session() as s:
            row = s.run(
                "MATCH (c:CVE {id: $c}), (m:MitreData {id: $m}), (cap:Capec {capec_id: $cap}) "
                "RETURN c.user_id AS cu, m.user_id AS mu, cap.user_id AS capu, c.source AS source",
                c=self.cve, m=self.mitre, cap=self.capec).single()
        self.assertEqual((row["cu"], row["mu"], row["capu"]), (None, None, None))
        self.assertEqual(row["source"], "nuclei")

    def test_an_nvd_written_cve_keeps_its_fields(self):
        with self.client.driver.session() as s:
            s.run("CREATE (:CVE {id: $c, cvss: 9.8, source: 'nvd', description: 'from NVD'})",
                  c=self.cve)
        self._write(self._recon(self.cve, enriched=False))
        with self.client.driver.session() as s:
            row = s.run("MATCH (c:CVE {id: $c}) RETURN c.cvss AS cvss, c.source AS source, "
                        "c.description AS d", c=self.cve).single()
        self.assertEqual((row["cvss"], row["source"], row["d"]), (9.8, "nvd", "from NVD"))

    def test_a_cve_the_template_no_longer_cites_loses_its_edge(self):
        self._write(self._recon(self.cve, enriched=False))
        self._write(self._recon(self.other_cve, enriched=False))
        with self.client.driver.session() as s:
            cited = {r["id"] for r in s.run(
                "MATCH (v:Vulnerability {source: 'nuclei', user_id: $u, project_id: $p})"
                "-[:INCLUDES_CVE]->(c:CVE) RETURN c.id AS id", u=self.uid, p=self.pid)}
        self.assertEqual(cited, {self.other_cve})


if __name__ == "__main__":
    unittest.main()

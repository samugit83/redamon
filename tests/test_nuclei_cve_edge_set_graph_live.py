"""LIVE-Neo4j: a nuclei finding's INCLUDES_CVE edges are exactly the CVEs it cites now.

R-35 links a nuclei Vulnerability to the CVEs its template cites. A later scan
whose finding cites fewer CVEs, or none at all, must leave the Vulnerability
linked to exactly what it cites now: the edge to a CVE it no longer names goes,
while the shared CVE / MitreData / Capec nodes, their own CWE / CAPEC chain, and
every other finding's edge to the same CVE stay.

The unit test (recon/tests/test_nuclei_cve_edge_set.py) follows the delete the
writer sends; only a database proves which edges are left.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_nuclei_cve_edge_set_graph_live.py -v

Everything it creates is scoped to two throwaway tenants, plus CVE, MitreData
and Capec reference nodes with throwaway ids; all are deleted in tearDown.
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

CITED = """
MATCH (v:Vulnerability {source: 'nuclei', user_id: $u, project_id: $p})
      -[:INCLUDES_CVE]->(c:CVE)
RETURN c.id AS id
"""


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveNucleiCveEdgeSetCase(unittest.TestCase):
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
        self.uid = f"mitre-{run}"
        self.pid = f"MITRE_{run}"
        self.other_pid = f"MITRE_{run}_B"
        self.cve_a = f"CVE-1998-{n:05d}1"
        self.cve_b = f"CVE-1998-{n:05d}2"
        self.cwe = f"CWE-8{n:05d}"
        self.capec = f"CAPEC-8{n:05d}"
        self.mitre = f"{self.cve_a}-{self.cwe}"

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id IN [$p, $q] DETACH DELETE n",
                  u=self.uid, p=self.pid, q=self.other_pid)
            s.run("MATCH (c:CVE) WHERE c.id IN [$a, $b] DETACH DELETE c",
                  a=self.cve_a, b=self.cve_b)
            s.run("MATCH (m:MitreData {id: $m}) DETACH DELETE m", m=self.mitre)
            s.run("MATCH (c:Capec {capec_id: $c}) DETACH DELETE c", c=self.capec)

    def _recon(self, *cve_ids):
        finding = {
            "template_id": "mitre-live-template",
            "name": "Live test path traversal",
            "severity": "high",
            "matched_at": f"http://{HOST}/cgi-bin/x",
            "cves": [{"id": cid, "cvss": 7.5, "url": "ignored"} for cid in cve_ids],
            "cvss_score": 7.5,
            "raw": {"host": HOST, "ip": "192.0.2.10"},
        }
        all_cves = []
        for cid in cve_ids:
            entry = {"id": cid, "cvss": 7.5}
            if cid == self.cve_a:
                entry["mitre_attack"] = {"enriched": True, "cwe_hierarchy": {
                    "id": self.cwe, "name": "Live test weakness", "mapping": "ALLOWED",
                    "related_capec": [{"id": self.capec, "name": "Live test pattern"}],
                }}
            all_cves.append(entry)
        return {
            "domain": "example.com",
            "subdomains": [HOST],
            "vuln_scan": {"scan_metadata": {}, "discovered_urls": {},
                          "by_target": {HOST: {"findings": [finding]}},
                          "all_cves": all_cves},
        }

    def _write(self, recon, project_id=None):
        stats = self.client.update_graph_from_vuln_scan(
            copy.deepcopy(recon), self.uid, project_id or self.pid)
        self.assertEqual(stats["errors"], [])

    def _cited(self, project_id=None):
        with self.client.driver.session() as s:
            return {r["id"] for r in s.run(CITED, u=self.uid, p=project_id or self.pid)}

    def _one(self, query, **params):
        with self.client.driver.session() as s:
            return s.run(query, **params).single()

    def test_a_finding_that_cites_no_cve_any_more_keeps_no_edge(self):
        self._write(self._recon(self.cve_a, self.cve_b))
        self.assertEqual(self._cited(), {self.cve_a, self.cve_b})

        self._write(self._recon())

        self.assertEqual(self._cited(), set())

    def test_a_finding_that_cites_only_malformed_ids_keeps_no_edge(self):
        self._write(self._recon(self.cve_a))
        self._write(self._recon("CVE-21-1", "not-a-cve"))
        self.assertEqual(self._cited(), set())

    def test_a_finding_that_cites_fewer_cves_keeps_only_those(self):
        self._write(self._recon(self.cve_a, self.cve_b))
        self._write(self._recon(self.cve_b))
        self.assertEqual(self._cited(), {self.cve_b})

    def test_the_shared_reference_nodes_and_their_chain_stay(self):
        self._write(self._recon(self.cve_a, self.cve_b))
        self._write(self._recon())

        row = self._one(
            "OPTIONAL MATCH (a:CVE {id: $a}) OPTIONAL MATCH (b:CVE {id: $b}) "
            "OPTIONAL MATCH (a)-[hc:HAS_CWE]->(m:MitreData {id: $m})"
            "-[hp:HAS_CAPEC]->(cap:Capec {capec_id: $cap}) "
            "RETURN a IS NOT NULL AS a, b IS NOT NULL AS b, "
            "hc IS NOT NULL AS has_cwe, hp IS NOT NULL AS has_capec",
            a=self.cve_a, b=self.cve_b, m=self.mitre, cap=self.capec)
        self.assertEqual(dict(row), {"a": True, "b": True, "has_cwe": True, "has_capec": True})

    def test_another_tenant_and_another_finding_keep_their_edges(self):
        # The same template on the same URL gives the same finding id in every
        # project, so only the tenant keys tell the two Vulnerabilities apart.
        self._write(self._recon(self.cve_a), project_id=self.other_pid)
        self._write(self._recon(self.cve_a))
        with self.client.driver.session() as s:
            s.run("MATCH (c:CVE {id: $a}) "
                  "CREATE (:Vulnerability {id: 'shodan-mitre-live', source: 'shodan', "
                  "user_id: $u, project_id: $p})-[:INCLUDES_CVE]->(c)",
                  a=self.cve_a, u=self.uid, p=self.pid)

        self._write(self._recon())

        self.assertEqual(self._cited(), set())
        self.assertEqual(self._cited(self.other_pid), {self.cve_a})
        row = self._one(
            "MATCH (:Vulnerability {id: 'shodan-mitre-live', user_id: $u, project_id: $p})"
            "-[r:INCLUDES_CVE]->(:CVE {id: $a}) RETURN count(r) AS n",
            u=self.uid, p=self.pid, a=self.cve_a)
        self.assertEqual(row["n"], 1)


if __name__ == "__main__":
    unittest.main()

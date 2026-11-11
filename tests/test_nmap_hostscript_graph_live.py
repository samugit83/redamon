"""LIVE-Neo4j: a host-level NSE finding (R-30) hangs off its existing IP.

nmap reports host-rule scripts (smb-vuln-ms17-010...) under <hostscript>; the
parser gives them ``host_level: true`` and port 0, and update_graph_from_nmap
MERGEs them on port_number 0 and links them from their IP with
HAS_VULNERABILITY. It MATCHes the IP and never creates one, and a second ingest
of the same run converges.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_nmap_hostscript_graph_live.py -v

Everything it creates is scoped to a throwaway tenant, plus one CVE id unique
to the run, and deleted in tearDown.
"""

import os
import random
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

IP = "192.0.2.20"
UNKNOWN_IP = "192.0.2.21"
SCRIPT = "smb-vuln-ms17-010"


def _nmap_scan(cve, ip=IP):
    return {
        "by_host": {},
        "services_detected": [],
        "nse_vulns": [{"host": ip, "ip": ip, "port": 0, "host_level": True,
                       "script_id": SCRIPT, "state": "VULNERABLE",
                       "output": f"VULNERABLE: ms17-010 IDs: CVE:{cve}", "cve": cve}],
    }


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveNmapHostLevelCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"nmaphs-{run}"
        self.pid = f"NMAPHS_{run}"
        # A CVE id no real record has, unique to this run, so deleting it
        # touches nothing another project links to.
        self.cve = f"CVE-2099-{random.randint(100000, 999999)}"
        with self.client.driver.session() as s:
            s.run("CREATE (:IP {address: $a, user_id: $u, project_id: $p})",
                  a=IP, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
            s.run("MATCH (c:CVE {id: $c}) DETACH DELETE c", c=self.cve)

    def test_a_host_level_finding_is_one_node_owned_by_its_ip(self):
        for _ in range(2):  # a re-ingest must converge, not duplicate
            stats = self.client.update_graph_from_nmap({"nmap_scan": _nmap_scan(self.cve)},
                                                       self.uid, self.pid)
            self.assertFalse(stats.get("errors"), stats)
            self.assertEqual(stats.get("host_level_links"), 1, stats)
        with self.client.driver.session() as s:
            rows = [dict(r) for r in s.run(
                """
                MATCH (v:Vulnerability {name: $name, user_id: $u, project_id: $p})
                OPTIONAL MATCH (i:IP {user_id: $u, project_id: $p})-[:HAS_VULNERABILITY]->(v)
                OPTIONAL MATCH (v)-[:AFFECTS]->(port:Port)
                OPTIONAL MATCH (v)-[:HAS_CVE]->(c:CVE)
                RETURN v.host_level AS host_level, v.port_number AS port_number,
                       v.ip_address AS ip_address, v.source AS source, v.id AS id,
                       collect(DISTINCT i.address) AS ips, count(DISTINCT port) AS ports,
                       collect(DISTINCT c.id) AS cves
                """, name=SCRIPT, u=self.uid, p=self.pid)]
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertIs(row["host_level"], True)
        self.assertEqual(row["port_number"], 0)
        self.assertEqual(row["ip_address"], IP)
        self.assertEqual(row["source"], "nmap_nse")
        self.assertTrue(row["id"].startswith("nse-"))
        self.assertEqual(row["ips"], [IP])
        self.assertEqual(row["ports"], 0)
        self.assertEqual(row["cves"], [self.cve])

    def test_an_ip_the_graph_does_not_hold_is_never_created(self):
        stats = self.client.update_graph_from_nmap(
            {"nmap_scan": _nmap_scan(self.cve, ip=UNKNOWN_IP)}, self.uid, self.pid)
        self.assertFalse(stats.get("errors"), stats)
        self.assertFalse(stats.get("host_level_links"), stats)
        with self.client.driver.session() as s:
            ips = s.run("MATCH (i:IP {address: $a, user_id: $u, project_id: $p}) "
                        "RETURN count(i) AS n", a=UNKNOWN_IP, u=self.uid, p=self.pid).single()["n"]
        self.assertEqual(ips, 0)


if __name__ == "__main__":
    unittest.main()

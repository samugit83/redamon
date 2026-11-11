"""LIVE-Neo4j: an address only FOFA or ZoomEye tied to a name is no partial-run target (S-2).

FOFA and ZoomEye report a hostname with the address their crawl saw, which
may be years old and someone else's now, and write it as Subdomain
-[:RESOLVES_TO]-> IP with an open Port. recon/tests/test_partial_forward_dns.py
pins that every partial builder's Cypher carries `r.source IS NULL`, and
tests/test_urlscan_writers.py that both writers stamp `source` when they create
the edge. Only a real graph shows the two meet: the real writers seed the
edges, the real builders read them back, and the passive addresses reach no
target list, while the address DNS wrote does. The AI surface partial run,
which reads every IP with a Port, keeps only active-scan ports.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD -e HOME=/tmp --entrypoint python \\
    redamon-recon:latest -m pytest tests/test_partial_passive_edges_graph_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
Addresses are TEST-NET only.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
import uuid

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_RECON)
for _p in (_REPO, _RECON):
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

ROOT = "example.test"
WWW = "www.example.test"
CURRENT = "198.51.100.70"    # what DNS resolved this run
FOFA_OLD = "198.51.100.71"   # what FOFA's crawl once saw for the name
ZOOMEYE_OLD = "198.51.100.72"
BUILDERS = ("_build_recon_data_from_graph", "_build_port_scan_data_from_graph",
            "_build_http_probe_data_from_graph", "_build_vuln_scan_data_from_graph")


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestPartialPassiveEdgesGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("NEO4J_USER", _USER)
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "s2-passive-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.pid = "s2-passive-itest-%s" % uuid.uuid4().hex[:10]
        # What DNS and the port scan leave: the name, its current address, 443 open.
        self._run("""
            MERGE (d:Domain {name: $root, user_id: $uid, project_id: $pid})
            MERGE (s:Subdomain {name: $www, user_id: $uid, project_id: $pid})
            SET s.status = 'resolved'
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            MERGE (s)-[:BELONGS_TO]->(d)
            MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
            MERGE (s)-[r:RESOLVES_TO]->(i)
            SET r.record_type = 'A'
            MERGE (p:Port {number: 443, protocol: 'tcp', ip_address: $ip, user_id: $uid, project_id: $pid})
            SET p.state = 'open', p.passive_only = false
            MERGE (i)-[:HAS_PORT]->(p)
            """, root=ROOT, www=WWW, ip=CURRENT)
        recon = {"domain": ROOT, "domains": [ROOT]}
        self.client.update_graph_from_fofa(dict(recon, fofa={"results": [
            {"ip": FOFA_OLD, "port": 8443, "host": f"{WWW}:8443", "server": "nginx"}]}),
            self.user, self.pid)
        self.client.update_graph_from_zoomeye(dict(recon, zoomeye={"results": [
            {"ip": ZOOMEYE_OLD, "port": 2222, "protocol": "tcp", "hostname": WWW, "app": "openssh"}]}),
            self.user, self.pid)

    def tearDown(self):
        self._run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n")

    def _run(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, pid=self.pid, uid=self.user, **params).data()

    def test_the_passive_writers_left_a_sourced_edge_and_an_open_port(self):
        rows = self._run("""
            MATCH (:Subdomain {name: $www, project_id: $pid})-[r:RESOLVES_TO]->(i:IP)
            OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
            RETURN i.address AS ip, r.source AS source, collect(p.number) AS ports
            ORDER BY ip""", www=WWW)
        self.assertEqual(rows, [
            {"ip": CURRENT, "source": None, "ports": [443]},
            {"ip": FOFA_OLD, "source": "fofa_dns", "ports": [8443]},
            {"ip": ZOOMEYE_OLD, "source": "zoomeye_dns", "ports": [2222]},
        ])

    def test_no_partial_builder_targets_a_passive_address(self):
        from unittest import mock
        from recon.partial_recon_modules import graph_builders as gb
        env = {"NEO4J_URI": _URI, "NEO4J_USER": _USER, "NEO4J_PASSWORD": _PASSWORD}
        with mock.patch.dict(os.environ, env):
            for name in BUILDERS:
                with self.subTest(builder=name):
                    out = json.dumps(getattr(gb, name)([ROOT], self.user, self.pid,
                                                       include_root_domain=True), default=str)
                    self.assertNotIn(FOFA_OLD, out)
                    self.assertNotIn(ZOOMEYE_OLD, out)
                    if name in ("_build_recon_data_from_graph", "_build_port_scan_data_from_graph"):
                        self.assertIn(CURRENT, out, "control: the DNS address is read")

    def test_the_ai_surface_port_read_keeps_active_ports_only(self):
        active = self.client.active_open_ports(self.user, self.pid, [CURRENT, FOFA_OLD, ZOOMEYE_OLD])
        self.assertEqual(active, {CURRENT: {443}})


if __name__ == "__main__":
    unittest.main()

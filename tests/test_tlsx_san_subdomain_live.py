"""LIVE-Neo4j proof that a certificate SAN mints no Subdomain (D2, R-2).

update_graph_from_tlsx MERGEd a Subdomain for every SAN under a scan root, so a
name the scan refused (RoE-excluded, unlisted in an EXACT group, never resolved)
became a Subdomain with a COVERS_HOST edge and no BELONGS_TO, and partial
Naabu, httpx and Nuclei read it back as a target. The writer now links a
certificate only to a Subdomain the tenant's graph already holds; the
certificate's san list keeps every name. The mocked test
(recon/tests/test_tlsx_san_subdomain_admission.py) pins the statements; only a
real database proves the lookup creates nothing, links what exists and stays in
its tenant.

Skipped unless the neo4j driver is importable AND a database answers:

  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest -q tests/test_tlsx_san_subdomain_live.py

Every node is scoped to throwaway user and project ids and deleted in tearDown.
"""

import json
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

ROOT = "example.com"
KEPT = "api.example.com"
EXCLUDED = "shop.example.com"
FOREIGN = "cdn.example.net"
IP = "192.0.2.10"
PORT = 8443


def _payload():
    """Built by the real parser, so the SAN key is whatever tlsx emits."""
    from recon.main_recon_modules.tls_scan import _parse_tlsx_output
    line = json.dumps({
        "host": KEPT, "ip": IP, "port": str(PORT), "probe_status": True,
        "tls_version": "tls13", "subject_cn": KEPT, "subject_dn": f"CN={KEPT}",
        "subject_an": [KEPT, EXCLUDED, FOREIGN],
        "issuer_cn": "Example CA", "issuer_dn": "CN=Example CA",
        "serial": "01", "fingerprint_hash": {"sha256": "cd" * 32},
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
    })
    by_target = _parse_tlsx_output(line, {f"{KEPT}:{PORT}": IP})
    return {"domain": ROOT, "tlsx": {"by_target": by_target}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class CertificateSansMintNoSubdomain(unittest.TestCase):
    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"tlsxsan-{run}"
        self.pid = f"TLSXSAN_{run}"
        self.other_pid = f"TLSXSAN_OTHER_{run}"
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)
        with self.client.driver.session() as s:
            s.run(
                """
                MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                MERGE (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                               user_id: $uid, project_id: $pid})
                MERGE (i)-[:HAS_PORT]->(p)
                """,
                ip=IP, port=PORT, uid=self.uid, pid=self.pid).consume()

    def tearDown(self):
        try:
            with self.client.driver.session() as s:
                s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid).consume()
        finally:
            self.client.close()

    def _discovered(self, name, pid=None):
        """What the late-name DNS step writes for a name the merge admitted."""
        with self.client.driver.session() as s:
            s.run(
                """
                MERGE (d:Domain {name: $root, user_id: $uid, project_id: $pid})
                MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                  ON CREATE SET s.source = 'tlsx'
                MERGE (s)-[:BELONGS_TO]->(d)
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                """,
                root=ROOT, name=name, uid=self.uid, pid=pid or self.pid).consume()

    def _rows(self, cypher, **params):
        with self.client.driver.session() as s:
            return [r.values() for r in s.run(cypher, uid=self.uid, **params)]

    def _subdomains(self, pid=None):
        return sorted(r[0] for r in self._rows(
            "MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) RETURN s.name",
            pid=pid or self.pid))

    def _covered(self):
        return sorted(r[0] for r in self._rows(
            "MATCH (:Certificate {user_id: $uid, project_id: $pid})-[:COVERS_HOST]->(s:Subdomain) "
            "RETURN s.name", pid=self.pid))

    def test_a_san_with_no_subdomain_in_the_graph_creates_none(self):
        self._discovered(KEPT)
        stats = self.client.update_graph_from_tlsx(_payload(), self.uid, self.pid)

        self.assertEqual(stats["errors"], [])
        self.assertEqual(self._subdomains(), [KEPT],
                         "the certificate minted a Subdomain the scan never admitted")
        self.assertEqual(self._covered(), [KEPT])

    def test_the_certificate_keeps_every_name(self):
        self.client.update_graph_from_tlsx(_payload(), self.uid, self.pid)
        (san,), = self._rows(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c.san", pid=self.pid)
        self.assertEqual(sorted(san), sorted([KEPT, EXCLUDED, FOREIGN]))

    def test_an_empty_graph_gets_no_subdomain_and_none_floats(self):
        self.client.update_graph_from_tlsx(_payload(), self.uid, self.pid)

        self.assertEqual(self._subdomains(), [])
        floating = self._rows(
            "MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) "
            "WHERE NOT (s)-[:BELONGS_TO]->(:Domain) RETURN s.name", pid=self.pid)
        self.assertEqual(floating, [])

    def test_the_link_never_crosses_into_another_project(self):
        self._discovered(EXCLUDED, pid=self.other_pid)
        self.client.update_graph_from_tlsx(_payload(), self.uid, self.pid)

        self.assertEqual(self._subdomains(), [])
        self.assertEqual(self._covered(), [])
        self.assertEqual(self._rows(
            "MATCH (c:Certificate)-[:COVERS_HOST]->(:Subdomain {user_id: $uid, project_id: $other}) "
            "RETURN count(c)", other=self.other_pid), [[0]])

    def test_a_linked_subdomain_keeps_its_provenance(self):
        self._discovered(KEPT)
        self.client.update_graph_from_tlsx(_payload(), self.uid, self.pid)
        self.client.update_graph_from_tlsx(_payload(), self.uid, self.pid)

        self.assertEqual(self._rows(
            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s.source",
            name=KEPT, pid=self.pid), [["tlsx"]])
        self.assertEqual(self._rows(
            "MATCH (:Certificate {user_id: $uid, project_id: $pid})-[r:COVERS_HOST]->() "
            "RETURN count(r)", pid=self.pid), [[1]])


if __name__ == "__main__":
    unittest.main(verbosity=2)

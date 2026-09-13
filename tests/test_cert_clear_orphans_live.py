"""LIVE-Neo4j proof for CF4: a cleared certificate leaves no orphan Subdomain.

tlsx promotes in-scope SAN names into `Subdomain` nodes (`source='tlsx_san'`),
which means the certificate is the ONLY reason some of those hosts are in the
graph at all. Two ways that can rot:

  * a recon re-run clears and rescans, and a name that has since been dropped
    from the cert stays behind forever as a host we claim to have found;
  * a cross-scanner clear deletes the certificate and leaves its SAN-only
    Subdomains dangling with no edge and no evidence.

A dangling Subdomain is not cosmetic: it feeds the next scan's target list, so
the pipeline keeps probing a hostname no certificate vouches for any more.

Only a real database proves it, because the clear is one big `DETACH DELETE`
with label/source exclusions and the promotion is a `MERGE`.

Run:
  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_cert_clear_orphans_live -v
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

_IP = "203.0.113.5"
_PORT = 993


def _payload(sans, fingerprint="aabbccdd"):
    """Built through the real parser, so the SAN key is whatever tlsx emits."""
    from recon.main_recon_modules.tls_scan import _parse_tlsx_output
    line = json.dumps({
        "host": "mail.acme.test", "ip": _IP, "port": str(_PORT),
        "probe_status": True, "tls_version": "tls13",
        "subject_cn": "mail.acme.test", "subject_dn": "CN=mail.acme.test",
        "subject_an": sans,
        "issuer_cn": "R3", "issuer_dn": "CN=R3, O=Lets Encrypt",
        "serial": "01AB", "fingerprint_hash": {"sha256": fingerprint},
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
    })
    by_target = _parse_tlsx_output(line, {f"mail.acme.test:{_PORT}": _IP})
    return {"domain": "acme.test", "tlsx": {"by_target": by_target}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class CertificateClearLeavesNoOrphans(unittest.TestCase):
    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"certclear-{run}"
        self.pid = f"CERTCLEAR_{run}"
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)
        self._seed_port_scan()

    def _seed_port_scan(self):
        with self.client.driver.session() as s:
            s.run(
                """
                MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                  ON CREATE SET i.source = 'dnsx'
                MERGE (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                               user_id: $uid, project_id: $pid})
                  ON CREATE SET p.source = 'naabu'
                MERGE (i)-[:HAS_PORT]->(p)
                """,
                ip=_IP, port=_PORT, uid=self.uid, pid=self.pid).consume()

    def tearDown(self):
        try:
            with self.client.driver.session() as s:
                s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid).consume()
        finally:
            self.client.close()

    def _subdomains(self):
        with self.client.driver.session() as s:
            return sorted(r["n"] for r in s.run(
                "MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) RETURN s.name AS n",
                uid=self.uid, pid=self.pid))

    def _count(self, cypher, **params):
        with self.client.driver.session() as s:
            rec = s.run(cypher, uid=self.uid, pid=self.pid, **params).single()
            return rec[0] if rec else None

    # -- CF4 ---------------------------------------------------------------
    def test_a_san_dropped_from_the_cert_does_not_survive_a_clear_and_rescan(self):
        self.client.update_graph_from_tlsx(
            _payload(["mail.acme.test", "imap.acme.test"]), self.uid, self.pid)
        self.assertEqual(self._subdomains(), ["imap.acme.test", "mail.acme.test"])

        # The operator re-runs recon. The cert has been re-issued without imap.
        self.client.clear_recon_data(self.uid, self.pid)
        self._seed_port_scan()
        self.client.update_graph_from_tlsx(
            _payload(["mail.acme.test"], fingerprint="11223344"), self.uid, self.pid)

        self.assertEqual(
            self._subdomains(), ["mail.acme.test"],
            "a hostname whose only evidence was the previous certificate survived "
            "the clear and is still being fed to the next scan")

    def test_the_clear_removes_the_san_only_subdomains_with_the_certificate(self):
        self.client.update_graph_from_tlsx(
            _payload(["mail.acme.test", "imap.acme.test"]), self.uid, self.pid)
        self.client.clear_recon_data(self.uid, self.pid)
        self.assertEqual(self._subdomains(), [])
        self.assertEqual(
            self._count("MATCH (c:Certificate {user_id: $uid, project_id: $pid}) "
                        "RETURN count(c)"), 0)

    def test_no_subdomain_is_left_without_evidence_after_the_clear_and_rescan(self):
        """The structural form of the same invariant: every Subdomain still in
        the graph must hang off something (a cert, an IP, a domain), never float."""
        self.client.update_graph_from_tlsx(
            _payload(["mail.acme.test", "imap.acme.test", "smtp.acme.test"]),
            self.uid, self.pid)
        self.client.clear_recon_data(self.uid, self.pid)
        self._seed_port_scan()
        self.client.update_graph_from_tlsx(_payload(["mail.acme.test"]), self.uid, self.pid)

        floating = self._count(
            "MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) "
            "WHERE NOT (s)--() RETURN collect(s.name)")
        self.assertEqual(floating, [], f"edgeless Subdomain(s) left behind: {floating}")

    def test_a_gvm_only_certificate_clear_does_not_strand_recon_subdomains(self):
        """clear_gvm_data deletes certificates GVM alone observed. A recon-owned
        Subdomain that happened to be covered by one must stay: recon still owns
        it, and deleting it here would silently shrink the next scan's scope."""
        self.client.update_graph_from_tlsx(
            _payload(["mail.acme.test", "imap.acme.test"]), self.uid, self.pid)
        with self.client.driver.session() as s:
            s.run(
                """
                MATCH (sd:Subdomain {name: 'imap.acme.test', user_id: $uid, project_id: $pid})
                MERGE (c:Certificate {cert_key: 'sha256:gvmonly', user_id: $uid, project_id: $pid})
                  ON CREATE SET c.source = 'gvm', c.observed_by = ['gvm']
                MERGE (c)-[:COVERS_HOST]->(sd)
                """,
                uid=self.uid, pid=self.pid).consume()

        self.client.clear_gvm_data(self.uid, self.pid)

        self.assertEqual(self._subdomains(), ["imap.acme.test", "mail.acme.test"])
        self.assertEqual(
            self._count("MATCH (c:Certificate {cert_key: 'sha256:gvmonly', "
                        "user_id: $uid, project_id: $pid}) RETURN count(c)"), 0,
            "the GVM-only certificate should have been deleted")
        self.assertEqual(
            self._count("MATCH (c:Certificate {user_id: $uid, project_id: $pid}) "
                        "RETURN count(c)"), 1,
            "tlsx's certificate must survive a GVM clear")


if __name__ == "__main__":
    unittest.main(verbosity=2)

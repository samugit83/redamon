"""LIVE-Neo4j proof for the Phase 0.6 "free wins" graph writes.

Both of these were data the pipeline ALREADY paid for and then dropped:

  * httpx runs -jarm by default (~10 extra TLS handshakes per target) and
    writes the fingerprint at the URL level. The certificate writer read it
    from tls.certificate, where it never is, so it was discarded every scan.
  * Shodan returns a full ssl block per service (CN, issuer, serial, expiry,
    JARM, JA3S) from a handshake IT performed. It was parsed away entirely.

Both are MATCH/MERGE graph writes, so only a real database proves they land.

Run:
  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_cert_free_wins_graph_live -v
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


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class FreeWinCertificateWrites(unittest.TestCase):
    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"freewin-{run}"
        self.pid = f"FREEWIN_{run}"
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)

    def tearDown(self):
        try:
            with self.client.driver.session() as s:
                s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid).consume()
        finally:
            self.client.close()

    def _one(self, cypher, **params):
        with self.client.driver.session() as s:
            rec = s.run(cypher, uid=self.uid, pid=self.pid, **params).single()
            return rec[0] if rec else None

    # -- 0.6b: httpx JARM --------------------------------------------------
    def test_httpx_jarm_lands_on_the_certificate(self):
        """httpx writes jarm at the URL level, not inside tls.certificate."""
        recon = {"http_probe": {"by_url": {"https://mail.acme.test": {
            "host": "mail.acme.test", "ip": "203.0.113.9", "status_code": 200,
            "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
            "tls": {"version": "tls13", "cipher": "TLS_AES_256_GCM_SHA384",
                    "certificate": {"subject_cn": "mail.acme.test",
                                    "issuer": ["Lets Encrypt"],
                                    "not_before": "2026-01-01T00:00:00Z",
                                    "not_after": "2027-01-01T00:00:00Z",
                                    "san": ["mail.acme.test"]}},
        }}}}
        self.client.update_graph_from_http_probe(recon, self.uid, self.pid)
        jarm = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c.jarm")
        self.assertTrue(jarm, "httpx's JARM was dropped again")
        self.assertTrue(jarm.startswith("29d3fd"))

    def test_httpx_certificate_is_anchored_to_its_baseurl(self):
        recon = {"http_probe": {"by_url": {"https://mail.acme.test": {
            "host": "mail.acme.test", "ip": "203.0.113.9", "status_code": 200,
            "tls": {"certificate": {"subject_cn": "mail.acme.test",
                                    "issuer": ["Lets Encrypt"],
                                    "san": ["mail.acme.test"]}},
        }}}}
        self.client.update_graph_from_http_probe(recon, self.uid, self.pid)
        n = self._one(
            "MATCH (:BaseURL {user_id: $uid, project_id: $pid})"
            "-[:HAS_CERTIFICATE]->(c:Certificate) RETURN count(c)")
        self.assertEqual(n, 1)

    # -- 0.6c: Shodan ssl block --------------------------------------------
    def _shodan_recon(self):
        return {"domain": "acme.test", "shodan": {"hosts": [{
            "ip": "203.0.113.10", "ports": [8443],
            "services": [{
                "port": 8443, "transport": "tcp", "product": "nginx",
                "ssl": {
                    "subject_cn": "shodan.acme.test",
                    "issuer": "R3, Lets Encrypt", "issuer_cn": "R3",
                    "serial": "42", "expired": False,
                    "not_before": "2026-01-01", "not_after": "2027-01-01",
                    "fingerprint_sha256": "ddeeff",
                    "jarm": "shodanjarm", "ja3s": "shodanja3s",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "versions": ["TLSv1.2", "TLSv1.3"],
                },
            }],
        }]}}

    def test_shodan_ssl_block_becomes_a_certificate_node(self):
        self.client.update_graph_from_shodan(self._shodan_recon(), self.uid, self.pid)
        key = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c.cert_key")
        self.assertEqual(key, "sha256:ddeeff",
                         "Shodan's certificate is still being thrown away")

    def test_shodan_certificate_carries_the_fingerprints_and_provenance(self):
        self.client.update_graph_from_shodan(self._shodan_recon(), self.uid, self.pid)
        with self.client.driver.session() as s:
            c = s.run("MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c",
                      uid=self.uid, pid=self.pid).single()["c"]
        self.assertEqual(c["jarm"], "shodanjarm")
        self.assertEqual(c["ja3s"], "shodanja3s")
        self.assertEqual(c["serial"], "42")
        self.assertEqual(c["source"], "shodan")
        self.assertIn("shodan", c["observed_by"])

    def test_shodan_certificate_is_anchored_to_its_ip(self):
        self.client.update_graph_from_shodan(self._shodan_recon(), self.uid, self.pid)
        n = self._one(
            "MATCH (:IP {address: '203.0.113.10', user_id: $uid, project_id: $pid})"
            "-[:HAS_CERTIFICATE]->(c:Certificate) RETURN count(c)")
        self.assertEqual(n, 1)

    def test_a_shodan_service_without_ssl_writes_no_certificate(self):
        recon = self._shodan_recon()
        del recon["shodan"]["hosts"][0]["services"][0]["ssl"]
        self.client.update_graph_from_shodan(recon, self.uid, self.pid)
        n = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN count(c)")
        self.assertEqual(n, 0)

    def test_shodan_and_httpx_observing_one_certificate_converge_on_one_node(self):
        """The whole point of the shared cert_key: same fingerprint, one node,
        both names in observed_by."""
        self.client.update_graph_from_shodan(self._shodan_recon(), self.uid, self.pid)
        recon = {"http_probe": {"by_url": {"https://shodan.acme.test": {
            "host": "shodan.acme.test", "ip": "203.0.113.10", "status_code": 200,
            "tls": {"certificate": {"subject_cn": "shodan.acme.test",
                                    "fingerprint_sha256": "ddeeff",
                                    "san": ["shodan.acme.test"]}},
        }}}}
        self.client.update_graph_from_http_probe(recon, self.uid, self.pid)
        n = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN count(c)")
        self.assertEqual(n, 1, "one certificate observed twice produced two nodes")
        observers = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c.observed_by")
        self.assertIn("shodan", observers)
        self.assertIn("http_probe", observers)


if __name__ == "__main__":
    unittest.main()

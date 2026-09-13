"""LIVE-Neo4j proof for Phase 0.55: cross-source SAN parity.

Re-keying certificates on `cert_key` means two scanners that observe the SAME
certificate now converge on ONE node instead of forking on subject_cn. That
convergence is only a win if the node they converge on keeps the richest view
of the cert. The property most at risk is `san`: consumers downstream
(scope expansion, shared-infra clustering, the SAN backfill) read it, and a
scanner that reports the cert but no SAN list must not be able to erase a SAN
list another scanner already stored.

Both writers MERGE on cert_key and `SET c += $props`, so only a real database
proves which value survives.

Run:
  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_cert_san_parity_live -v
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

# One certificate, two scanners. Same fingerprint => same cert_key.
_FP = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff"
_CN = "www.acme.test"
_ISSUER = "R3, Lets Encrypt"
_NB = "2026-01-01T00:00:00Z"
_NA = "2027-01-01T00:00:00Z"
_SAN = ["www.acme.test", "acme.test", "shop.acme.test"]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class CrossSourceSanParity(unittest.TestCase):
    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"sanparity-{run}"
        self.pid = f"SANPARITY_{run}"
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)

    def tearDown(self):
        try:
            with self.client.driver.session() as s:
                s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid).consume()
        finally:
            self.client.close()

    def _certs(self):
        with self.client.driver.session() as s:
            return [r["c"] for r in s.run(
                "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c",
                uid=self.uid, pid=self.pid)]

    def _the_cert(self):
        certs = self._certs()
        self.assertEqual(len(certs), 1,
                         f"expected the two sources to converge on 1 node, got {len(certs)}")
        return certs[0]

    # -- inputs ------------------------------------------------------------
    def _censys(self, san=_SAN):
        tls = {
            "subject_cn": _CN, "issuer": _ISSUER, "fingerprint": _FP,
            "not_before": _NB, "not_after": _NA,
            "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
        }
        if san is not None:
            tls["san"] = san
        return {"domain": "acme.test", "censys": {"hosts": [{
            "ip": "203.0.113.20",
            "services": [{"port": 443, "transport_protocol": "TCP",
                          "service_name": "HTTPS", "tls": tls}],
        }]}}

    def _httpx(self, san=_SAN):
        cert = {
            "subject_cn": _CN, "issuer": [_ISSUER], "fingerprint_sha256": _FP,
            "not_before": _NB, "not_after": _NA,
        }
        if san is not None:
            cert["san"] = san
        return {"http_probe": {"by_url": {"https://www.acme.test": {
            "host": _CN, "ip": "203.0.113.20", "status_code": 200,
            "tls": {"version": "tls13", "cipher": "TLS_AES_256_GCM_SHA384",
                    "certificate": cert},
        }}}}

    # -- 0.55: the two sources agree ---------------------------------------
    def test_both_sources_reporting_the_same_san_converge_on_one_node(self):
        self.client.update_graph_from_censys(self._censys(), self.uid, self.pid)
        self.client.update_graph_from_http_probe(self._httpx(), self.uid, self.pid)
        c = self._the_cert()
        self.assertEqual(sorted(c["san"]), sorted(_SAN))
        self.assertEqual(c["cert_key"], f"sha256:{_FP}")
        self.assertEqual(sorted(c["observed_by"]), ["censys", "http_probe"])
        # source is first-writer provenance and must not be re-pointed.
        self.assertEqual(c["source"], "censys")

    def test_san_is_identical_whichever_source_writes_first(self):
        self.client.update_graph_from_http_probe(self._httpx(), self.uid, self.pid)
        httpx_first = sorted(self._the_cert()["san"])
        with self.client.driver.session() as s:
            s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid).consume()

        self.client.update_graph_from_censys(self._censys(), self.uid, self.pid)
        censys_first = sorted(self._the_cert()["san"])
        self.assertEqual(httpx_first, censys_first)
        self.assertEqual(httpx_first, sorted(_SAN))

    # -- 0.55: the two sources disagree ------------------------------------
    def test_an_httpx_observation_without_sans_does_not_erase_the_censys_sans(self):
        """httpx reports the cert but no SAN list (seen on hosts that present a
        bare leaf). It must not blank out SANs a previous source stored."""
        self.client.update_graph_from_censys(self._censys(), self.uid, self.pid)
        self.client.update_graph_from_http_probe(self._httpx(san=None), self.uid, self.pid)
        c = self._the_cert()
        self.assertEqual(sorted(c["san"]), sorted(_SAN),
                         "an empty httpx SAN list wiped the SANs censys had stored")

    def test_a_censys_observation_without_sans_does_not_erase_the_httpx_sans(self):
        self.client.update_graph_from_http_probe(self._httpx(), self.uid, self.pid)
        self.client.update_graph_from_censys(self._censys(san=None), self.uid, self.pid)
        c = self._the_cert()
        self.assertEqual(sorted(c["san"]), sorted(_SAN),
                         "an empty censys SAN list wiped the SANs httpx had stored")

    def test_an_httpx_observation_with_extra_sans_is_not_discarded(self):
        """The reverse direction: a richer later observation must still land."""
        self.client.update_graph_from_censys(self._censys(san=["acme.test"]), self.uid, self.pid)
        self.client.update_graph_from_http_probe(self._httpx(), self.uid, self.pid)
        c = self._the_cert()
        self.assertEqual(sorted(c["san"]), sorted(_SAN))


if __name__ == "__main__":
    unittest.main(verbosity=2)

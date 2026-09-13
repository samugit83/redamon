"""LIVE-Neo4j proof that the tlsx graph write actually lands (strategy row 8).

The fake-session tests assert the SHAPE of the Cypher. They cannot prove Neo4j
agrees, and two of the three writes here are MATCH-based, which fail SILENTLY:

  * Service enrichment MATCHes on (port_number, ip_address). The plan warned
    that keying by_target on the IP tlsx RETURNS rather than the IP we scanned
    makes this match nothing and the enrichment vanish with no error.
  * COVERS_HOST must exist for in-scope SAN names and must NOT be created for
    foreign ones.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_tlsx_graph_live -v

Everything is scoped to throwaway project ids and deleted in tearDown, so it is
safe against a populated database.
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

# The fixture is produced by the REAL parser from a real tlsx JSONL line, not
# hand-built. A hand-built by_target dict drifts from what the parser actually
# emits -- that is precisely the bug that left the vhost SAN candidate source
# dead in production for months (it read a key nothing wrote).
_TLSX_JSON_LINE = json.dumps({
    "host": "mail.acme.test", "ip": "203.0.113.5", "port": "993",
    "probe_status": True,
    "tls_version": "tls12", "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "key_exchange": "ecdhe", "tls_connection": "ctls",
    "subject_cn": "mail.acme.test", "subject_dn": "CN=mail.acme.test",
    "subject_org": ["Acme"],
    "subject_an": ["mail.acme.test", "imap.acme.test", "foreign.example.org"],
    "issuer_cn": "R3", "issuer_dn": "CN=R3, O=Lets Encrypt",
    "issuer_org": ["Lets Encrypt"],
    "serial": "01AB", "fingerprint_hash": {"sha256": "aabbccdd"},
    "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
})


def _tlsx_payload(scanned_ip="203.0.113.5", port=993, overrides=None):
    from recon.main_recon_modules.tls_scan import _parse_tlsx_output
    by_target = _parse_tlsx_output(
        _TLSX_JSON_LINE, {f"mail.acme.test:{port}": scanned_ip})
    if overrides:
        by_target[f"{scanned_ip}:{port}"].update(overrides)
    return {"domain": "acme.test", "tlsx": {"by_target": by_target}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TlsxGraphWriteLive(unittest.TestCase):
    IP = "203.0.113.5"
    PORT = 993

    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"tlsx-{run}"
        self.pid = f"TLSX_A_{run}"
        self.client = Neo4jClient()
        # The port scan already ran: an IP, its Port, and the statically-named
        # Service tlsx is supposed to enrich (never rename).
        with self.client.driver.session() as s:
            s.run(
                """
                MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                MERGE (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                               user_id: $uid, project_id: $pid})
                MERGE (i)-[:HAS_PORT]->(p)
                MERGE (svc:Service {name: 'unknown', port_number: $port, ip_address: $ip,
                                    user_id: $uid, project_id: $pid})
                SET svc.product = 'dovecot', svc.version = '2.3'
                MERGE (p)-[:RUNS_SERVICE]->(svc)
                """,
                ip=self.IP, port=self.PORT, uid=self.uid, pid=self.pid).consume()

    def tearDown(self):
        try:
            with self.client.driver.session() as s:
                s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        finally:
            self.client.close()

    def _write(self, payload=None):
        return self.client.update_graph_from_tlsx(
            payload or _tlsx_payload(), self.uid, self.pid)

    def _one(self, cypher, **params):
        with self.client.driver.session() as s:
            rec = s.run(cypher, uid=self.uid, pid=self.pid, **params).single()
            return rec[0] if rec else None

    # -- Certificate + IP anchor -------------------------------------------
    def test_certificate_node_is_written_and_keyed_on_the_fingerprint(self):
        self._write()
        key = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c.cert_key")
        self.assertEqual(key, "sha256:aabbccdd")

    def test_certificate_is_anchored_to_the_scanned_ip(self):
        self._write()
        n = self._one(
            "MATCH (:IP {address: $ip, user_id: $uid, project_id: $pid})"
            "-[:HAS_CERTIFICATE]->(c:Certificate) RETURN count(c)", ip=self.IP)
        self.assertEqual(n, 1, "IP -[:HAS_CERTIFICATE]-> Certificate did not land")

    def test_certificate_carries_its_posture_and_provenance(self):
        self._write()
        with self.client.driver.session() as s:
            c = s.run("MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c",
                      uid=self.uid, pid=self.pid).single()["c"]
        self.assertEqual(c["source"], "tlsx")
        self.assertIn("tlsx", c["observed_by"])
        self.assertEqual(c["issuer_cn"], "R3")
        self.assertEqual(c["serial"], "01AB")
        self.assertFalse(c["expired"])

    def test_a_false_hygiene_flag_is_written_not_dropped(self):
        """The props filter drops "" / [] so a SAN-less observation cannot erase
        stored SANs. `False` must survive it: a missing `expired` reads back as
        None, which is indistinguishable from "not expired" for every consumer
        that does a truthiness check, so absence would silently downgrade posture."""
        self._write()
        with self.client.driver.session() as s:
            c = s.run("MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN c",
                      uid=self.uid, pid=self.pid).single()["c"]
        for flag in ("expired", "self_signed", "mismatched", "wildcard"):
            self.assertIn(flag, c.keys(), f"{flag}=False was filtered out of cert_props")
            self.assertIs(c[flag], False)

    # -- H7: enum data must not poison the Service write --------------------
    def test_cipher_enum_does_not_destroy_the_service_enrichment(self):
        """tlsx reports cipher_enum as a list of MAPS, and Neo4j refuses a list
        of maps as a property, so `SET svc += $props` was rejected wholesale:
        enabling the weak-cipher toggle silently wiped tls, tls_version,
        tls_cipher and tls_service_hint off every Service, and the error went
        into a stats list nothing printed."""
        payload = _tlsx_payload(overrides={
            "cipher_enum": [
                {"version": "tls12", "ciphers": {}},
                {"version": "tls10", "ciphers": {"insecure": ["TLS_RSA_WITH_RC4_128_SHA"]}},
            ],
            "version_enum": ["tls12", "tls10"],
        })
        stats = self._write(payload)
        self.assertEqual(stats["errors"], [], "the Service write still fails")
        self.assertEqual(stats["services_enriched"], 1,
                         "the Service enrichment was lost with cipher_enum on")

        with self.client.driver.session() as s:
            svc = s.run(
                "MATCH (svc:Service {port_number: $port, user_id: $uid, project_id: $pid}) "
                "RETURN svc", port=self.PORT, uid=self.uid, pid=self.pid).single()["svc"]
        self.assertTrue(svc["tls"])
        self.assertEqual(svc["tls_service_hint"], "imaps")
        self.assertEqual(svc["tls_versions_supported"], ["tls12", "tls10"])
        self.assertEqual(svc["tls_ciphers_weak"], ["TLS_RSA_WITH_RC4_128_SHA"],
                         "the envelopes were stored raw, or the names were dropped")

    def test_an_enum_with_no_weak_cipher_stores_nothing_rather_than_empty_envelopes(self):
        payload = _tlsx_payload(overrides={
            "cipher_enum": [{"version": "tls12", "ciphers": {}}],
        })
        stats = self._write(payload)
        self.assertEqual(stats["errors"], [])
        with self.client.driver.session() as s:
            svc = s.run(
                "MATCH (svc:Service {port_number: $port, user_id: $uid, project_id: $pid}) "
                "RETURN svc", port=self.PORT, uid=self.uid, pid=self.pid).single()["svc"]
        self.assertNotIn("tls_ciphers_weak", svc.keys())
        self.assertTrue(svc["tls"], "the rest of the enrichment must still land")

    # -- COVERS_HOST --------------------------------------------------------
    def test_covers_host_edges_exist_for_in_scope_san_names(self):
        self._write()
        names = self._one(
            "MATCH (:Certificate {user_id: $uid, project_id: $pid})-[:COVERS_HOST]->(s:Subdomain) "
            "RETURN collect(s.name)")
        self.assertIn("mail.acme.test", names)
        self.assertIn("imap.acme.test", names)

    def test_foreign_san_never_becomes_a_covered_subdomain(self):
        """The SAN list is chosen by the target; an out-of-scope name must not
        be promoted into this project's graph as a Subdomain."""
        self._write()
        names = self._one(
            "MATCH (:Certificate {user_id: $uid, project_id: $pid})-[:COVERS_HOST]->(s:Subdomain) "
            "RETURN collect(s.name)")
        self.assertNotIn("foreign.example.org", names)

    # -- Service enrichment (the silent-MATCH risk) --------------------------
    def test_service_is_enriched_not_renamed(self):
        self._write()
        with self.client.driver.session() as s:
            svc = s.run(
                "MATCH (svc:Service {port_number: $port, ip_address: $ip, "
                "user_id: $uid, project_id: $pid}) RETURN svc",
                port=self.PORT, ip=self.IP, uid=self.uid, pid=self.pid).single()["svc"]
        self.assertTrue(svc["tls"])
        self.assertEqual(svc["tls_version"], "tls12")
        self.assertEqual(svc["tls_cipher"], "TLS_RSA_WITH_AES_128_CBC_SHA")
        # name is part of the Service MERGE key: changing it orphans the node.
        self.assertEqual(svc["name"], "unknown")
        # nmap's detection must survive a tlsx run.
        self.assertEqual(svc["product"], "dovecot")

    def test_service_carries_the_tls_service_hint(self):
        """Phase 2's actual deliverable: naming what speaks TLS on a non-HTTP
        port. 993 is IMAPS. Without this the hint is computed in memory and
        dropped on the floor, and the graph still says 'unknown'."""
        self._write()
        hint = self._one(
            "MATCH (svc:Service {port_number: $port, ip_address: $ip, "
            "user_id: $uid, project_id: $pid}) RETURN svc.tls_service_hint",
            port=self.PORT, ip=self.IP)
        self.assertEqual(hint, "imaps")

    def test_service_count_is_unchanged_by_a_tlsx_run(self):
        before = self._one(
            "MATCH (svc:Service {user_id: $uid, project_id: $pid}) RETURN count(svc)")
        self._write()
        after = self._one(
            "MATCH (svc:Service {user_id: $uid, project_id: $pid}) RETURN count(svc)")
        self.assertEqual(before, after, "tlsx created a duplicate Service")

    # -- Failed probe --------------------------------------------------------
    def test_failed_handshake_is_recorded_on_the_service(self):
        payload = _tlsx_payload(overrides={
            "probe_status": False, "error": "no tls",
            "subject_cn": None, "fingerprint_sha256": None})
        self._write(payload)
        with self.client.driver.session() as s:
            svc = s.run(
                "MATCH (svc:Service {port_number: $port, ip_address: $ip, "
                "user_id: $uid, project_id: $pid}) RETURN svc",
                port=self.PORT, ip=self.IP, uid=self.uid, pid=self.pid).single()["svc"]
        self.assertTrue(svc["tls_probe_failed"])
        self.assertEqual(svc["tls_probe_error"], "no tls")

    # -- Legacy reconcile must not cross scanner boundaries ------------------
    def _legacy_cert(self, source, cn="mail.acme.test", key="legacy:mail.acme.test:9999"):
        with self.client.driver.session() as s:
            s.run(
                """CREATE (c:Certificate {cert_key: $key, subject_cn: $cn, source: $source,
                                          user_id: $uid, project_id: $pid})""",
                key=key, cn=cn, source=source, uid=self.uid, pid=self.pid).consume()

    def test_legacy_reconcile_does_not_delete_another_scanners_certificate(self):
        """The reconcile removes the pre-migration duplicate of the cert being
        written. It matched on subject_cn alone, with no source guard -- so a
        GVM certificate that predates the re-key (still legacy-keyed) and merely
        SHARES a common name was DETACH DELETEd by a recon scan. That is exactly
        the cross-source data loss Phase 0.3 exists to prevent, reintroduced on
        the legacy path.
        """
        self._legacy_cert("gvm")
        self._write()
        n = self._one(
            "MATCH (c:Certificate {cert_key: 'legacy:mail.acme.test:9999', "
            "user_id: $uid, project_id: $pid}) RETURN count(c)")
        self.assertEqual(n, 1, "a recon scan deleted GVM's legacy certificate")

    def test_legacy_reconcile_still_removes_our_own_pre_migration_duplicate(self):
        """Control: the reconcile must still do its job for recon's own rows,
        or partial recon leaves a duplicate per certificate forever."""
        self._legacy_cert("http_probe")
        self._write()
        n = self._one(
            "MATCH (c:Certificate {cert_key: 'legacy:mail.acme.test:9999', "
            "user_id: $uid, project_id: $pid}) RETURN count(c)")
        self.assertEqual(n, 0, "the legacy duplicate was not reconciled away")

    # -- Idempotency + tenancy ----------------------------------------------
    def test_running_twice_leaves_one_certificate(self):
        self._write()
        self._write()
        n = self._one(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN count(c)")
        self.assertEqual(n, 1, "second tlsx run duplicated the certificate")

    def test_write_is_scoped_to_its_own_tenant(self):
        self._write()
        other = self._one(
            "MATCH (c:Certificate {project_id: $other}) RETURN count(c)",
            other=f"{self.pid}_OTHER")
        self.assertEqual(other, 0)


if __name__ == "__main__":
    unittest.main()

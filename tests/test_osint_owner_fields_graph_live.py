"""LIVE-Neo4j proof that passive OSINT writers leave other writers' fields alone.

tests/test_osint_writers_keep_owner_fields.py pins the Cypher through a fake
session; only a real database proves the order of events end to end:

  * DNS wrote a Subdomain `resolved`, http_probe another one an HTTP code;
    Censys reverse DNS, OTX passive DNS and FOFA then report the same names.
    Both keep their status and discovery source, and the silent `resolved`
    host still becomes `no_http` at http_probe (audit L-2);
  * a Service the port scan made keeps its (absent) source when a passive
    provider enriches it, while the provider's own banner lands (L-2).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_osint_owner_fields_graph_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic")):
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

DOMAIN = "example.com"
IP = "198.51.100.50"
SILENT = "silent.example.com"    # DNS resolved it; it will not answer HTTP
LIVE = "www.example.com"         # http_probe already wrote its status code
NEW = "mail.example.com"         # only the passive sources know it


def _recon(key, payload):
    return {"domain": DOMAIN, "domains": [DOMAIN], key: payload}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestOsintOwnerFieldsGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "osint-owner-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.pid = "osint-owner-itest-%s" % uuid.uuid4().hex[:10]
        # The shape DNS, http_probe and the port scan leave before GROUP 3b.
        self._run("""
            MERGE (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
            MERGE (s1:Subdomain {name: $silent, user_id: $uid, project_id: $pid})
            SET s1.status = 'resolved'
            MERGE (s2:Subdomain {name: $live, user_id: $uid, project_id: $pid})
            SET s2.status = '200', s2.source = 'crt.sh'
            MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
            MERGE (p:Port {number: 22, protocol: 'tcp', ip_address: $ip, user_id: $uid, project_id: $pid})
            SET p.state = 'open'
            MERGE (svc:Service {name: 'ssh', port_number: 22, ip_address: $ip,
                                user_id: $uid, project_id: $pid})
            MERGE (i)-[:HAS_PORT]->(p)
            MERGE (p)-[:RUNS_SERVICE]->(svc)
            """, domain=DOMAIN, silent=SILENT, live=LIVE, ip=IP)

    def tearDown(self):
        self._run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n")

    def _run(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, pid=self.pid, uid=self.user, **params).data()

    def _sub(self, name):
        rows = self._run("MATCH (s:Subdomain {name: $name, project_id: $pid}) "
                         "RETURN s.status AS status, s.source AS source", name=name)
        return (rows[0]["status"], rows[0]["source"]) if rows else None

    def _passive_sightings(self):
        self.client.update_graph_from_censys(_recon("censys", {"hosts": [
            {"ip": IP, "reverse_dns_names": [SILENT, LIVE, NEW]}]}), self.user, self.pid)
        self.client.update_graph_from_otx(_recon("otx", {"ip_reports": [
            {"ip": IP, "passive_dns": [{"hostname": SILENT, "record_type": "A"},
                                       {"hostname": LIVE, "record_type": "A"}]}]}),
            self.user, self.pid)
        self.client.update_graph_from_fofa(_recon("fofa", {"results": [
            {"ip": IP, "port": 443, "host": f"{SILENT}:443"},
            {"ip": IP, "port": 443, "host": f"{LIVE}:443"}]}), self.user, self.pid)

    def test_a_passive_sighting_keeps_the_status_and_source_dns_and_http_wrote(self):
        self._passive_sightings()
        self.assertEqual(self._sub(SILENT), ("resolved", None))
        self.assertEqual(self._sub(LIVE), ("200", "crt.sh"))
        # A name only Censys knows is still created as an unverified censys name.
        self.assertEqual(self._sub(NEW), ("unverified", "censys_rdns"))

    def test_the_silent_resolved_host_still_becomes_no_http(self):
        self._passive_sightings()
        self.client.update_graph_from_http_probe({
            "domain": DOMAIN, "subdomains": [SILENT, LIVE],
            "http_probe": {"by_host": {LIVE: {"status_codes": [200], "live_urls": []}}},
        }, self.user, self.pid)
        self.assertEqual(self._sub(SILENT)[0], "no_http")
        self.assertEqual(self._sub(LIVE)[0], "200")

    def test_a_scanned_service_keeps_its_source_and_takes_the_providers_fields(self):
        self.client.update_graph_from_censys(_recon("censys", {"hosts": [
            {"ip": IP, "services": [{"port": 22, "service_name": "ssh",
                                     "banner": "SSH-2.0-OpenSSH_8.9"}]}]}), self.user, self.pid)
        self.client.update_graph_from_criminalip(_recon("criminalip", {"ip_reports": [
            {"ip": IP, "ports": [{"port": 22, "app_name": "ssh", "app_version": "8.9"}]}]}),
            self.user, self.pid)
        rows = self._run("MATCH (svc:Service {name: 'ssh', port_number: 22, project_id: $pid}) "
                         "RETURN svc.source AS source, svc.version AS version")
        self.assertEqual(rows, [{"source": None, "version": "8.9"}])
        # A Service Censys is the first to report names Censys.
        self.client.update_graph_from_censys(_recon("censys", {"hosts": [
            {"ip": IP, "services": [{"port": 8080, "service_name": "http"}]}]}), self.user, self.pid)
        rows = self._run("MATCH (svc:Service {name: 'http', port_number: 8080, project_id: $pid}) "
                         "RETURN svc.source AS source")
        self.assertEqual(rows, [{"source": "censys"}])


if __name__ == "__main__":
    unittest.main()

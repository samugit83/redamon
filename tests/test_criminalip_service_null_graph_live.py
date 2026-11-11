"""LIVE-Neo4j: a CriminalIP port without a version or banner leaves the Service's alone (S-15).

update_graph_from_criminalip MERGEs Service {name: app_name, port, ip} and then
runs a plain `SET svc.version = $version, svc.banner = $banner`. CriminalIP
lists many ports with an app_name and no app_version / banner, and a null SET
in Cypher REMOVEs the property: the version nmap measured and the banner
Censys or ZoomEye stored on that same Service are deleted. The other passive
writers guard every field (FOFA's CASE WHEN, ZoomEye's and Censys's
non-empty `svc += $props`).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_criminalip_service_null_graph_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in ("/repo", "/repo/agentic", _REPO, os.path.join(_REPO, "agentic")):
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

DOMAIN = "example.test"
IP = "198.51.100.61"
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1"


def _recon(key, payload):
    return {"domain": DOMAIN, "domains": [DOMAIN], key: payload}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestCriminalIpServiceNullGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "cip-null-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.pid = "cip-null-itest-%s" % uuid.uuid4().hex[:10]
        # What the port scan leaves: an open 22/tcp running ssh.
        self._run("""
            MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
            MERGE (p:Port {number: 22, protocol: 'tcp', ip_address: $ip, user_id: $uid, project_id: $pid})
            SET p.state = 'open'
            MERGE (svc:Service {name: 'ssh', port_number: 22, ip_address: $ip,
                                user_id: $uid, project_id: $pid})
            MERGE (i)-[:HAS_PORT]->(p)
            MERGE (p)-[:RUNS_SERVICE]->(svc)
            """, ip=IP)

    def tearDown(self):
        self._run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n")

    def _run(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, pid=self.pid, uid=self.user, **params).data()

    def _svc(self, name, port):
        rows = self._run("MATCH (svc:Service {name: $name, port_number: $port, project_id: $pid}) "
                         "RETURN svc.version AS version, svc.banner AS banner", name=name, port=port)
        self.assertEqual(len(rows), 1, rows)
        return rows[0]

    def _criminalip(self, port, app_name, app_version=None, banner=None):
        self.client.update_graph_from_criminalip(_recon("criminalip", {"ip_reports": [
            {"ip": IP, "ports": [{"port": port, "socket": "tcp", "app_name": app_name,
                                  "app_version": app_version, "banner": banner}]}]}),
            self.user, self.pid)

    def test_nmaps_version_and_censys_banner_survive_a_bare_criminalip_port(self):
        self.client.update_graph_from_nmap({"domain": DOMAIN, "nmap_scan": {"by_host": {
            IP: {"ip": IP, "port_details": [{"port": 22, "product": "OpenSSH", "version": "8.9p1"}]}}}},
            self.user, self.pid)
        self.client.update_graph_from_censys(_recon("censys", {"hosts": [
            {"ip": IP, "services": [{"port": 22, "service_name": "ssh", "banner": SSH_BANNER}]}]}),
            self.user, self.pid)
        self.assertEqual(self._svc("ssh", 22), {"version": "8.9p1", "banner": SSH_BANNER})

        self._criminalip(22, "SSH")
        self.assertEqual(self._svc("ssh", 22), {"version": "8.9p1", "banner": SSH_BANNER},
                         "a CriminalIP port with no version/banner deleted the measured ones")

    def test_zoomeyes_product_service_survives_a_bare_criminalip_port(self):
        self.client.update_graph_from_zoomeye(_recon("zoomeye", {"results": [
            {"ip": IP, "port": 443, "protocol": "tcp", "app": "nginx", "version": "1.24.0",
             "banner": "HTTP/1.1 200 OK"}]}), self.user, self.pid)
        self.assertEqual(self._svc("nginx", 443), {"version": "1.24.0", "banner": "HTTP/1.1 200 OK"})

        self._criminalip(443, "nginx")
        self.assertEqual(self._svc("nginx", 443), {"version": "1.24.0", "banner": "HTTP/1.1 200 OK"})

    def test_control_a_criminalip_version_still_lands(self):
        self._criminalip(22, "ssh", app_version="9.6", banner="SSH-2.0-OpenSSH_9.6")
        self.assertEqual(self._svc("ssh", 22), {"version": "9.6", "banner": "SSH-2.0-OpenSSH_9.6"})


if __name__ == "__main__":
    unittest.main()

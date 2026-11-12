"""LIVE-Neo4j proof that httpx's answer on a two-address name lands on the right address (S-20).

tests/test_http_port_two_address_host.py pins the parameters; only a real
database proves the graph a domain run leaves: the port scan writes
two.example.com's X 192.0.2.10 (80, 443) and Y 192.0.2.20 (443, 8443), then
httpx answers on :80, :443 and :8443 and names X for every URL, as v1.12 does
when X is the first resolved address and refuses 8443.

  * Port 8443 exists only under Y, with no HAS_PORT from X;
  * Y's 8443 runs the Service that serves https://two.example.com:8443;
  * no Port hangs off an IP whose address it does not carry;
  * the other tenant's graph is untouched.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_http_port_two_address_host_graph_live.py -v

Everything is scoped to throwaway ids and DETACH DELETEd in teardown.
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

HOST = "two.example.com"
X, Y = "192.0.2.10", "192.0.2.20"


def _detail(port, ip):
    return {"port": port, "protocol": "tcp", "service": "https" if port != 80 else "http", "ip": ip}


def _recon(reported=X):
    urls = [f"http://{HOST}", f"https://{HOST}", f"https://{HOST}:8443"]
    return {
        "domain": "example.com",
        "metadata": {"root_domain": "example.com"},
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}},
                "subdomains": {HOST: {"ips": {"ipv4": [X, Y], "ipv6": []}, "has_records": True}}},
        "port_scan": {
            "by_ip": {X: {"ip": X, "hostnames": [HOST], "ports": [80, 443]},
                      Y: {"ip": Y, "hostnames": [HOST], "ports": [443, 8443]}},
            "by_host": {HOST: {"host": HOST, "ip": X, "ports": [80, 443, 8443],
                               "port_details": [_detail(80, X), _detail(443, X),
                                                _detail(443, Y), _detail(8443, Y)]}},
        },
        "http_probe": {"by_url": {u: {"url": u, "host": HOST, "ip": reported, "status_code": 200}
                                  for u in urls}},
    }


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "Neo4j not reachable")
class TestHttpPortTwoAddressLive(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.http_mixin import HttpMixin
        from graph_db.mixins.recon.port_mixin import PortMixin

        class _Graph(PortMixin, HttpMixin):
            def __init__(self, drv):
                self.driver = drv

        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.graph = _Graph(self.driver)
        self.uid = f"s20-http-live-{uuid.uuid4().hex[:8]}"
        self.pid, self.other = f"{self.uid}-p", f"{self.uid}-q"
        with self.driver.session() as s:
            for pid in (self.pid, self.other):
                s.run("UNWIND $ips AS ip CREATE (:IP {address: ip, user_id: $uid, project_id: $pid})",
                      ips=[X, Y], uid=self.uid, pid=pid)
        stats = self.graph.update_graph_from_port_scan(_recon(), self.uid, self.pid)
        self.assertEqual(stats["errors"], [])

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        self.driver.close()

    def _rows(self, query, pid=None, **params):
        with self.driver.session() as s:
            return [r.data() for r in s.run(query, uid=self.uid, pid=pid or self.pid, **params)]

    def _ports_of(self, ip, pid=None):
        return sorted(r["n"] for r in self._rows(
            "MATCH (:IP {address: $ip, user_id: $uid, project_id: $pid})-[:HAS_PORT]->(p:Port) "
            "RETURN p.number AS n", pid=pid, ip=ip))

    def test_8443_lands_on_the_address_that_serves_it(self):
        stats = self.graph.update_graph_from_http_probe(_recon(), self.uid, self.pid)
        self.assertEqual(stats["errors"], [])
        self.assertEqual(self._ports_of(X), [80, 443])
        self.assertEqual(self._ports_of(Y), [443, 8443])
        self.assertEqual(self._rows(
            "MATCH (p:Port {number: 8443, user_id: $uid, project_id: $pid}) "
            "RETURN p.ip_address AS ip, p.passive_only AS passive"), [{"ip": Y, "passive": False}])

    def test_the_service_chain_hangs_off_y(self):
        self.graph.update_graph_from_http_probe(_recon(), self.uid, self.pid)
        rows = self._rows(
            "MATCH (i:IP {user_id: $uid, project_id: $pid})-[:HAS_PORT]->(p:Port {number: 8443})"
            "-[:RUNS_SERVICE]->(svc:Service)-[:SERVES_URL]->(u:BaseURL) "
            "RETURN i.address AS ip, svc.ip_address AS svc_ip, u.url AS url")
        self.assertEqual(rows, [{"ip": Y, "svc_ip": Y, "url": f"https://{HOST}:8443"}])
        self.assertEqual(self._rows(
            "MATCH (svc:Service {ip_address: $ip, port_number: 8443, user_id: $uid, project_id: $pid}) "
            "RETURN count(svc) AS n", ip=X), [{"n": 0}])

    def test_no_port_hangs_off_another_address(self):
        self.graph.update_graph_from_http_probe(_recon(), self.uid, self.pid)
        self.assertEqual(self._rows(
            "MATCH (i:IP {user_id: $uid, project_id: $pid})-[:HAS_PORT]->(p:Port) "
            "WHERE p.ip_address <> i.address RETURN count(*) AS n"), [{"n": 0}])

    def test_the_other_tenant_is_untouched(self):
        self.graph.update_graph_from_http_probe(_recon(), self.uid, self.pid)
        self.assertEqual(self._ports_of(X, pid=self.other), [])
        self.assertEqual(self._ports_of(Y, pid=self.other), [])

    def test_httpx_naming_y_gives_the_same_graph(self):
        self.graph.update_graph_from_http_probe(_recon(reported=Y), self.uid, self.pid)
        self.assertEqual(self._ports_of(X), [80, 443])
        self.assertEqual(self._ports_of(Y), [443, 8443])


if __name__ == "__main__":
    unittest.main()

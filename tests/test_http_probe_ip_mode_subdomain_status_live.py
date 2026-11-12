"""LIVE-Neo4j proof that IP-mode Subdomain nodes get their HTTP status (L-18).

tests/test_http_probe_ip_mode_subdomain_status.py pins the statements through a
fake session; this runs the real writers on a real graph in run order:

  * update_graph_from_ip_recon writes each target's label Subdomain
    (`203-0-113-10`), status `resolved`, as run_ip_recon's dict asks;
  * update_graph_from_http_probe with by_host keyed by the IP literal (what
    httpx reports for an address) sets the label's status and status codes,
    and creates no Subdomain named after the address;
  * a name the selection rule scanned (a Subdomain of its own name, written by
    the IP-hostnames writer) gets its status from its late probe, keyed by the
    name.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_http_probe_ip_mode_subdomain_status_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
Documentation ranges and reserved names only.
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

T1, T2 = "203.0.113.10", "203.0.113.11"
L1, L2 = "203-0-113-10", "203-0-113-11"
APP = "app.example.com"


def _host(name, codes):
    url = f"https://{name}/"
    return {"hostname": name, "urls": [url], "live_urls": [url] if codes else [],
            "technologies": [], "servers": [], "status_codes": codes}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestHttpProbeIpModeSubdomainStatusLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "http-status-ipmode-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.pid = "http-status-ipmode-itest-%s" % uuid.uuid4().hex[:10]
        self.mock = f"ip-targets.{self.pid}"
        self.metadata = {"ip_mode": True, "root_domain": self.mock, "target": self.mock,
                         "expanded_ips": [T1, T2], "ip_to_hostname": {T1: L1, T2: L2}}
        self.client.update_graph_from_ip_recon({
            "metadata": dict(self.metadata),
            "domain": self.mock,
            "subdomains": [L1, L2],
            "dns": {"domain": {}, "subdomains": {
                label: {"has_records": True, "is_mock": True, "actual_ip": ip,
                        "ips": {"ipv4": [ip], "ipv6": []}, "records": {}}
                for ip, label in ((T1, L1), (T2, L2))}},
            "whois": {"ip_whois": {}},
        }, self.user, self.pid)

    def tearDown(self):
        self._run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n")

    def _run(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, pid=self.pid, uid=self.user, **params).data()

    def _sub(self, name):
        rows = self._run("MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) "
                         "RETURN s.status AS status, s.status_codes AS codes", name=name)
        return (rows[0]["status"], rows[0]["codes"]) if rows else None

    def _probe_write(self, by_host, subdomains, **metadata):
        by_url = {u: {"host": h, "ip": T1, "status_code": (info["status_codes"] or [None])[0]}
                  for h, info in by_host.items() for u in info["urls"]}
        stats = self.client.update_graph_from_http_probe({
            "metadata": {**self.metadata, **metadata},
            "domain": self.mock,
            "subdomains": subdomains,
            "http_probe": {"scan_metadata": {}, "by_url": by_url, "by_host": by_host},
        }, self.user, self.pid)
        self.assertEqual(stats["errors"], [])

    def test_the_label_takes_the_status_httpx_reported_for_its_address(self):
        self.assertEqual(self._sub(L1), ("resolved", None))
        self._probe_write({T1: _host(T1, [200, 404])}, [L1, L2])
        self.assertEqual(self._sub(L1), ("200", [200, 404]))
        # The silent target is still swept to no_http.
        self.assertEqual(self._sub(L2), ("no_http", None))

    def test_no_subdomain_is_named_after_an_address(self):
        self._probe_write({T1: _host(T1, [200])}, [L1, L2])
        rows = self._run("MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) "
                         "WHERE s.name IN $ips RETURN s.name AS name", ips=[T1, T2])
        self.assertEqual(rows, [])

    def test_a_scanned_name_gets_its_status_from_its_late_probe(self):
        self._run("""
            MATCH (d:Domain {name: $mock, user_id: $uid, project_id: $pid})
            MERGE (s:Subdomain {name: $app, user_id: $uid, project_id: $pid})
            ON CREATE SET s.status = 'resolved', s.source = 'ip_hostname_selection'
            """, mock=self.mock, app=APP)
        self._probe_write({APP: _host(APP, [404])}, [APP], ip_mode_hosts={APP: "example.com"})
        self.assertEqual(self._sub(APP), ("404", [404]))
        self.assertEqual(self._sub(L1), ("resolved", None))


if __name__ == "__main__":
    unittest.main()

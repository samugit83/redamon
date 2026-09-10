"""LIVE-Neo4j proof of the Origin-IP Discovery graph write + fronted-host count.

The unit tests prove `stable_vuln_id` is deterministic and tenant-salted, but
only a real database proves the Cypher is VALID on Neo4j 5.x and that:

  * update_graph_from_origin_discovery creates IP + HAS_ORIGIN + Vulnerability,
    is idempotent on re-run, keeps tenants separate, and leaves no orphan edge
    after the project is wiped (strategy row 2);
  * an origin exposure CONVERGES onto the same Vulnerability node the
    security-check producer writes for the same (type, url, ip) in one tenant -
    one node, not two (strategy row 3 + regression for the port-less-url fix);
  * get_graph_inputs_for_tool('OriginDiscovery') counts a host as fronted from
    the Endpoint node's is_cdn / favicon_hash (where httpx records it) and from a
    CDN IP - NOT from BaseURL, which never carries those (strategy row 4 +
    regression: the BaseURL query counted 0).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_origin_discovery_graph_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
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


def _origin_payload(host, ip, port=443, method="favicon_hash", source="shodan"):
    return {"origin_discovery": {"confirmed": [{
        "type": "waf_bypass", "severity": "high",
        "name": "Origin Server Exposed (CDN Bypass)",
        "subdomain": host, "matched_ip": ip,
        "url": f"https://{ip}:{port}",           # port-full probe url
        "origin_discovery_method": method, "origin_source": source,
        "confidence_score": 91.0, "cdn_fronting": "cloudflare",
        "port": port, "match_method": "host-header",
        "evidence": f"{host} -> {ip}:{port}", "source": "origin_discovery",
    }], "candidates_meta": {}}}


def _security_check_waf_payload(host, ip):
    return {"vuln_scan": {"security_checks": {"findings": [{
        "type": "waf_bypass", "severity": "high",
        "name": "WAF Bypass via Direct IP Access",
        "url": f"https://{ip}",                  # port-less url the check emits
        "matched_ip": ip, "hostname": host,
        "evidence": "WAF on subdomain but not IP",
    }]}}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestOriginDiscoveryGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "od-itest-user"
        cls.pid_a = "od-itest-a-%s" % uuid.uuid4().hex[:10]
        cls.pid_b = "od-itest-b-%s" % uuid.uuid4().hex[:10]

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.client.driver.session() as s:
                for pid in (cls.pid_a, cls.pid_b):
                    s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n", pid=pid)
        finally:
            cls.client.close()

    def _count(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, **params).single()[0]

    # -- row 2: write, idempotency, tenant isolation, no orphan on wipe ------
    def test_write_creates_nodes_idempotent_isolated_and_wipes_clean(self):
        host, ip = "www.acme-itest.test", "45.33.32.10"
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_a)

        self.assertEqual(self._count(
            "MATCH (i:IP {address:$ip, project_id:$pid}) WHERE i.origin_confirmed = true RETURN count(i)",
            ip=ip, pid=self.pid_a), 1, "origin IP node not created / not flagged")
        self.assertEqual(self._count(
            "MATCH (:Subdomain {name:$h, project_id:$pid})-[r:HAS_ORIGIN]->(:IP {address:$ip, project_id:$pid}) RETURN count(r)",
            h=host, ip=ip, pid=self.pid_a), 1, "HAS_ORIGIN edge not created")
        self.assertEqual(self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', project_id:$pid}) RETURN count(v)",
            pid=self.pid_a), 1, "Vulnerability not created")

        # idempotent re-run -> still exactly one of each
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_a)
        self.assertEqual(self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', project_id:$pid}) RETURN count(v)",
            pid=self.pid_a), 1, "re-run duplicated the Vulnerability")
        self.assertEqual(self._count(
            "MATCH (:Subdomain {name:$h, project_id:$pid})-[r:HAS_ORIGIN]->(:IP) RETURN count(r)",
            h=host, pid=self.pid_a), 1, "re-run duplicated HAS_ORIGIN")

        # tenant B, SAME host+ip -> a separate Vulnerability node (tenant-salted id).
        # Scope to THIS ip so a sibling test's data in pid_b can't skew the count.
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_b)
        ids = self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', matched_ip:$ip}) WHERE v.project_id IN [$a,$b] "
            "RETURN count(DISTINCT v.id)", ip=ip, a=self.pid_a, b=self.pid_b)
        self.assertEqual(ids, 2, "cross-tenant Vulnerability id collision (F1)")

        # wipe A -> no A nodes, no orphan HAS_ORIGIN survives
        self.client.clear_project_data(self.user, self.pid_a)
        self.assertEqual(self._count(
            "MATCH (n) WHERE n.project_id = $pid RETURN count(n)", pid=self.pid_a), 0,
            "project wipe left nodes behind")
        self.assertEqual(self._count(
            "MATCH (:Subdomain {project_id:$pid})-[r:HAS_ORIGIN]->() RETURN count(r)", pid=self.pid_a), 0,
            "orphan HAS_ORIGIN survived the wipe")

    # -- row 3: convergence with the security-check producer (one node) ------
    def test_converges_with_security_check_producer(self):
        host, ip = "shop.acme-itest.test", "45.33.32.20"
        self.client.update_graph_from_vuln_scan(_security_check_waf_payload(host, ip), self.user, self.pid_b)
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_b)
        n = self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', matched_ip:$ip, project_id:$pid}) RETURN count(v)",
            ip=ip, pid=self.pid_b)
        self.assertEqual(n, 1, "security_check + origin_discovery did NOT converge -> report double-count (F4)")

    # -- row 4: fronted count reads Endpoint/IP, not BaseURL -----------------
    def test_fronted_count_reads_endpoint_not_baseurl(self):
        pid = "od-itest-fc-%s" % uuid.uuid4().hex[:8]
        dom = "fc-%s.test" % uuid.uuid4().hex[:6]
        try:
            with self.client.driver.session() as s:
                s.run("MERGE (d:Domain {name:$dom, user_id:$u, project_id:$p})", dom=dom, u=self.user, p=pid)
                # s1: Endpoint is_cdn=true (the httpx CDN flag lives on Endpoint)
                s.run("""
                    MATCH (d:Domain {name:$dom, project_id:$p})
                    MERGE (s1:Subdomain {name:$s1, user_id:$u, project_id:$p}) MERGE (d)-[:HAS_SUBDOMAIN]->(s1)
                    MERGE (b1:BaseURL {url:'https://s1', user_id:$u, project_id:$p}) MERGE (s1)-[:HAS_BASEURL]->(b1)
                    MERGE (e1:Endpoint {url:'https://s1/', user_id:$u, project_id:$p}) SET e1.is_cdn=true
                    MERGE (b1)-[:HAS_ENDPOINT]->(e1)
                """, dom=dom, u=self.user, p=pid, s1="s1."+dom)
                # s2: Endpoint favicon_hash only (no is_cdn)
                s.run("""
                    MATCH (d:Domain {name:$dom, project_id:$p})
                    MERGE (s2:Subdomain {name:$s2, user_id:$u, project_id:$p}) MERGE (d)-[:HAS_SUBDOMAIN]->(s2)
                    MERGE (b2:BaseURL {url:'https://s2', user_id:$u, project_id:$p}) MERGE (s2)-[:HAS_BASEURL]->(b2)
                    MERGE (e2:Endpoint {url:'https://s2/', user_id:$u, project_id:$p}) SET e2.favicon_hash=12345
                    MERGE (b2)-[:HAS_ENDPOINT]->(e2)
                """, dom=dom, u=self.user, p=pid, s2="s2."+dom)
                # s3: resolves to a CDN IP
                s.run("""
                    MATCH (d:Domain {name:$dom, project_id:$p})
                    MERGE (s3:Subdomain {name:$s3, user_id:$u, project_id:$p}) MERGE (d)-[:HAS_SUBDOMAIN]->(s3)
                    MERGE (i:IP {address:'104.16.1.1', user_id:$u, project_id:$p}) SET i.is_cdn=true
                    MERGE (s3)-[:RESOLVES_TO]->(i)
                """, dom=dom, u=self.user, p=pid, s3="s3."+dom)
                # s4: plain endpoint + non-CDN IP -> NOT fronted
                s.run("""
                    MATCH (d:Domain {name:$dom, project_id:$p})
                    MERGE (s4:Subdomain {name:$s4, user_id:$u, project_id:$p}) MERGE (d)-[:HAS_SUBDOMAIN]->(s4)
                    MERGE (b4:BaseURL {url:'https://s4', user_id:$u, project_id:$p}) MERGE (s4)-[:HAS_BASEURL]->(b4)
                    MERGE (e4:Endpoint {url:'https://s4/', user_id:$u, project_id:$p})
                    MERGE (b4)-[:HAS_ENDPOINT]->(e4)
                    MERGE (i4:IP {address:'45.33.32.99', user_id:$u, project_id:$p})
                    MERGE (s4)-[:RESOLVES_TO]->(i4)
                """, dom=dom, u=self.user, p=pid, s4="s4."+dom)

            res = self.client.get_graph_inputs_for_tool("OriginDiscovery", self.user, pid)
            self.assertEqual(res.get("fronted_count"), 3,
                             "fronted_count must read Endpoint.is_cdn/favicon + CDN IP (was 0 on BaseURL)")
        finally:
            with self.client.driver.session() as s:
                s.run("MATCH (n) WHERE n.project_id = $p DETACH DELETE n", p=pid)


if __name__ == "__main__":
    unittest.main()

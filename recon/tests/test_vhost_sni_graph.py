"""
Integration tests for VhostSniMixin -- writes against a REAL Neo4j instance.

Auto-skips when Neo4j is unreachable.

Run inside the agent container (graph_db is baked there):
    docker exec redamon-agent python -m pytest /app/recon/tests/test_vhost_sni_graph.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
import uuid

# Path setup — project root is /app inside the agent container, but the test
# may also run from a host checkout.
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)


def _neo4j_available() -> bool:
    try:
        import neo4j  # noqa: F401
        from graph_db import Neo4jClient
        with Neo4jClient() as c:
            return c.verify_connection()
    except Exception:
        return False


NEO4J_OK = _neo4j_available()


@unittest.skipUnless(NEO4J_OK, "Neo4j not reachable -- skipping graph integration tests")
class TestVhostSniGraphMixin(unittest.TestCase):
    """End-to-end Cypher writes against a live Neo4j."""

    @classmethod
    def setUpClass(cls):
        from graph_db import Neo4jClient
        cls.uid = f"test-user-{uuid.uuid4()}"
        cls.pid = f"test-project-{uuid.uuid4()}"
        cls.client = Neo4jClient()

    @classmethod
    def tearDownClass(cls):
        # Wipe everything created by this test tenant
        try:
            with cls.client.driver.session() as session:
                session.run(
                    """
                    MATCH (n {user_id: $uid, project_id: $pid})
                    DETACH DELETE n
                    """,
                    uid=cls.uid, pid=cls.pid,
                )
        finally:
            cls.client.close()

    def setUp(self):
        # Fresh tenant slate per test
        with self.client.driver.session() as session:
            session.run(
                """
                MATCH (n {user_id: $uid, project_id: $pid})
                DETACH DELETE n
                """,
                uid=self.uid, pid=self.pid,
            )
            # Seed Domain + Subdomain + IP that the mixin can attach Vulnerabilities to
            session.run(
                """
                MERGE (d:Domain {name: 'example.com', user_id: $uid, project_id: $pid})
                MERGE (s:Subdomain {name: 'admin.example.com', user_id: $uid, project_id: $pid})
                MERGE (s2:Subdomain {name: 'orphan.example.com', user_id: $uid, project_id: $pid})
                MERGE (i:IP {address: '1.2.3.4', user_id: $uid, project_id: $pid})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                MERGE (d)-[:HAS_SUBDOMAIN]->(s2)
                MERGE (s)-[:RESOLVES_TO]->(i)
                """,
                uid=self.uid, pid=self.pid,
            )

    # --------------------------------------------------------------------
    # 1. IP enrichment
    # --------------------------------------------------------------------
    def test_ip_enrichment_props_written(self):
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {
                    "1.2.3.4": {
                        "ip": "1.2.3.4",
                        "baseline": {"status": 403, "size": 548},
                        "anomaly_count": 2,
                        "is_reverse_proxy": True,
                        "hosts_hidden_vhosts": True,
                    },
                },
                "findings": [],
                "discovered_baseurls": [],
            },
        }
        stats = self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        self.assertEqual(stats["ips_enriched"], 1)

        with self.client.driver.session() as session:
            rec = session.run(
                "MATCH (i:IP {address: '1.2.3.4', user_id: $uid, project_id: $pid}) RETURN i",
                uid=self.uid, pid=self.pid,
            ).single()
            ip = rec["i"]
            self.assertTrue(ip["vhost_sni_tested"])
            self.assertEqual(ip["vhost_baseline_status"], 403)
            self.assertEqual(ip["vhost_baseline_size"], 548)
            self.assertEqual(ip["hidden_vhost_count"], 2)
            self.assertTrue(ip["is_reverse_proxy"])

    def test_ip_enrichment_includes_candidates_and_ports_tested(self):
        """vhost_candidates_tested + vhost_ports_tested are written for completeness."""
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {
                    "1.2.3.4": {
                        "ip": "1.2.3.4",
                        "baseline": {"status": 200, "size": 100},
                        "candidates_tested": 247,
                        "ports_tested": 2,
                        "anomaly_count": 0,
                        "is_reverse_proxy": False,
                        "hosts_hidden_vhosts": False,
                    },
                },
                "findings": [],
                "discovered_baseurls": [],
            },
        }
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        with self.client.driver.session() as session:
            rec = session.run(
                "MATCH (i:IP {address: '1.2.3.4', user_id: $uid, project_id: $pid}) RETURN i",
                uid=self.uid, pid=self.pid,
            ).single()
            ip = rec["i"]
            self.assertEqual(ip["vhost_candidates_tested"], 247)
            self.assertEqual(ip["vhost_ports_tested"], 2)

    # --------------------------------------------------------------------
    # 2. Vulnerability creation + Subdomain attach
    # --------------------------------------------------------------------
    def test_l7_finding_creates_vuln_attached_to_subdomain(self):
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_admin_example_com_1_2_3_4_443_l7",
                    "name": "Hidden Virtual Host: admin.example.com",
                    "type": "hidden_vhost",
                    "severity": "medium",
                    "source": "vhost_sni_enum",
                    "hostname": "admin.example.com",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "scheme": "https",
                    "layer": "L7",
                    "baseline_status": 403,
                    "baseline_size": 548,
                    "observed_status": 200,
                    "observed_size": 4823,
                    "size_delta": 4275,
                    "internal_pattern_match": "admin",
                    "description": "Test description",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        stats = self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        self.assertEqual(stats["vulnerabilities_created"], 1)
        self.assertEqual(stats["subdomains_enriched"], 1)
        self.assertGreaterEqual(stats["relationships_created"], 1)

        with self.client.driver.session() as session:
            rec = session.run(
                """
                MATCH (s:Subdomain {name: 'admin.example.com', user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE v.source = 'vhost_sni_enum'
                RETURN s, v
                """,
                uid=self.uid, pid=self.pid,
            ).single()
            self.assertIsNotNone(rec, "Vulnerability not attached to Subdomain")
            v = rec["v"]
            s = rec["s"]
            self.assertEqual(v["type"], "hidden_vhost")
            self.assertEqual(v["severity"], "medium")
            self.assertEqual(v["layer"], "L7")
            self.assertEqual(v["hostname"], "admin.example.com")
            self.assertEqual(v["internal_pattern_match"], "admin")
            self.assertEqual(s["vhost_routing_layer"], "L7")
            self.assertTrue(s["vhost_hidden"])
            self.assertFalse(s["sni_routed"])

    # --------------------------------------------------------------------
    # 3. host_header_bypass also attaches to IP
    # --------------------------------------------------------------------
    def test_host_header_bypass_also_attaches_to_ip(self):
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_admin_example_com_1_2_3_4_443_both",
                    "name": "Routing Inconsistency: admin.example.com",
                    "type": "host_header_bypass",
                    "severity": "high",
                    "source": "vhost_sni_enum",
                    "hostname": "admin.example.com",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "scheme": "https",
                    "layer": "both",
                    "baseline_status": 403,
                    "baseline_size": 548,
                    "observed_status": 200,
                    "observed_size": 1000,
                    "size_delta": 452,
                    "internal_pattern_match": "admin",
                    "description": "L7 vs L4 disagree",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        stats = self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        self.assertEqual(stats["vulnerabilities_created"], 1)

        with self.client.driver.session() as session:
            # Subdomain attachment
            sub_attach = session.run(
                """
                MATCH (s:Subdomain {name: 'admin.example.com', user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability {type: 'host_header_bypass'})
                RETURN count(v) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            # IP attachment
            ip_attach = session.run(
                """
                MATCH (i:IP {address: '1.2.3.4', user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability {type: 'host_header_bypass'})
                RETURN count(v) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            self.assertEqual(sub_attach, 1)
            self.assertEqual(ip_attach, 1)

    # --------------------------------------------------------------------
    # 4. BaseURL created for discovered hidden vhosts
    # --------------------------------------------------------------------
    def test_discovered_baseurl_created_with_relationships(self):
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [],
                "discovered_baseurls": ["https://hidden.example.com:8443"],
            },
        }
        stats = self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        self.assertEqual(stats["baseurls_created"], 1)

        with self.client.driver.session() as session:
            rec = session.run(
                """
                MATCH (s:Subdomain {name: 'hidden.example.com', user_id: $uid, project_id: $pid})-[:HAS_BASE_URL]->(b:BaseURL)
                RETURN b
                """,
                uid=self.uid, pid=self.pid,
            ).single()
            self.assertIsNotNone(rec)
            b = rec["b"]
            self.assertEqual(b["url"], "https://hidden.example.com:8443")
            self.assertEqual(b["scheme"], "https")
            self.assertEqual(b["port"], 8443)
            self.assertEqual(b["discovery_source"], "vhost_sni_enum")

    # --------------------------------------------------------------------
    # 5. Idempotency: re-running same finding doesn't duplicate
    # --------------------------------------------------------------------
    def test_idempotent_re_run_merges(self):
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_admin_example_com_1_2_3_4_443_l7",
                    "name": "Hidden Virtual Host: admin.example.com",
                    "type": "hidden_vhost",
                    "severity": "medium",
                    "source": "vhost_sni_enum",
                    "hostname": "admin.example.com",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "layer": "L7",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        # Re-run with later timestamp; should update last_seen, not duplicate
        recon["vhost_sni"]["findings"][0]["discovered_at"] = "2026-04-26T14:00:00Z"
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)

        with self.client.driver.session() as session:
            count = session.run(
                """
                MATCH (v:Vulnerability {project_id: $pid, source: 'vhost_sni_enum'})
                RETURN count(v) AS c
                """,
                pid=self.pid,
            ).single()["c"]
            self.assertEqual(count, 1, "Re-run created a duplicate Vulnerability node")

    # --------------------------------------------------------------------
    # 6. Defensive Subdomain creation when one doesn't exist
    # --------------------------------------------------------------------
    def test_creates_subdomain_node_when_missing(self):
        # The seed has 'admin.example.com' but NOT 'totally-new.example.com'.
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_totally_new_example_com_1_2_3_4_443_l7",
                    "name": "Hidden Virtual Host: totally-new.example.com",
                    "type": "hidden_vhost",
                    "severity": "low",
                    "source": "vhost_sni_enum",
                    "hostname": "totally-new.example.com",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "layer": "L7",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)

        with self.client.driver.session() as session:
            rec = session.run(
                """
                MATCH (s:Subdomain {name: 'totally-new.example.com', user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN s, v
                """,
                uid=self.uid, pid=self.pid,
            ).single()
            self.assertIsNotNone(rec, "Subdomain was not auto-created")
            self.assertEqual(rec["s"]["source"], "vhost_sni_enum")

    # --------------------------------------------------------------------
    # 6b. Newly invented Subdomain is wired into Domain + IP (no orphans)
    # --------------------------------------------------------------------
    def test_new_subdomain_linked_to_parent_domain_and_ip(self):
        """When vhost_sni invents a Subdomain, it must BELONG_TO the parent
        Domain and RESOLVE_TO the IP it was discovered on -- otherwise the
        new node + its Vulnerability become an orphan island in the graph view."""
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_brand_new_example_com_1_2_3_4_443_l7",
                    "name": "Hidden Virtual Host: brand-new.example.com",
                    "type": "hidden_vhost",
                    "severity": "medium",
                    "source": "vhost_sni_enum",
                    "hostname": "brand-new.example.com",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "layer": "L7",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)

        with self.client.driver.session() as session:
            belongs = session.run(
                """
                MATCH (s:Subdomain {name: 'brand-new.example.com', user_id: $uid, project_id: $pid})-[:BELONGS_TO]->(d:Domain {name: 'example.com'})
                RETURN count(d) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            has_sub = session.run(
                """
                MATCH (d:Domain {name: 'example.com', user_id: $uid, project_id: $pid})-[:HAS_SUBDOMAIN]->(s:Subdomain {name: 'brand-new.example.com'})
                RETURN count(s) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            resolves = session.run(
                """
                MATCH (s:Subdomain {name: 'brand-new.example.com', user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(i:IP {address: '1.2.3.4'})
                RETURN count(i) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            self.assertEqual(belongs, 1, "Subdomain not linked BELONGS_TO Domain")
            self.assertEqual(has_sub, 1, "Domain not linked HAS_SUBDOMAIN to Subdomain")
            self.assertEqual(resolves, 1, "Subdomain not linked RESOLVES_TO IP")

    def test_subdomain_outside_target_domain_only_links_to_ip(self):
        """If the discovered hostname does NOT fall under the project's target
        domain (e.g. a co-hosted third-party vhost), do not force a fake parent
        link -- but still link to the IP so it isn't a fully-orphan node."""
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_unrelated_co_uk_1_2_3_4_443_l7",
                    "name": "Hidden Virtual Host: unrelated.co.uk",
                    "type": "hidden_vhost",
                    "severity": "info",
                    "source": "vhost_sni_enum",
                    "hostname": "unrelated.co.uk",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "layer": "L7",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)

        with self.client.driver.session() as session:
            belongs = session.run(
                """
                MATCH (s:Subdomain {name: 'unrelated.co.uk', user_id: $uid, project_id: $pid})-[:BELONGS_TO]->(:Domain)
                RETURN count(*) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            resolves = session.run(
                """
                MATCH (s:Subdomain {name: 'unrelated.co.uk', user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(:IP {address: '1.2.3.4'})
                RETURN count(*) AS c
                """,
                uid=self.uid, pid=self.pid,
            ).single()["c"]
            self.assertEqual(belongs, 0, "Should not invent a Domain link for off-target host")
            self.assertEqual(resolves, 1, "Off-target host still needs an IP anchor")

    # --------------------------------------------------------------------
    # 7. Empty input is a no-op
    # --------------------------------------------------------------------
    def test_empty_findings_no_writes(self):
        recon = {"domain": "example.com", "vhost_sni": {"by_ip": {}, "findings": [], "discovered_baseurls": []}}
        stats = self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)
        self.assertEqual(stats["vulnerabilities_created"], 0)
        self.assertEqual(stats["baseurls_created"], 0)

    # --------------------------------------------------------------------
    # 8. Multi-tenancy isolation
    # --------------------------------------------------------------------
    def test_writes_are_tenant_scoped(self):
        recon = {
            "domain": "example.com",
            "vhost_sni": {
                "by_ip": {},
                "findings": [{
                    "id": "vhost_sni_admin_example_com_1_2_3_4_443_l7",
                    "name": "Hidden Virtual Host",
                    "type": "hidden_vhost",
                    "severity": "low",
                    "source": "vhost_sni_enum",
                    "hostname": "admin.example.com",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "layer": "L7",
                    "discovered_at": "2026-04-25T14:00:00Z",
                }],
                "discovered_baseurls": [],
            },
        }
        self.client.update_graph_from_vhost_sni(recon, self.uid, self.pid)

        # Different tenant should see ZERO vhost_sni Vulnerabilities
        with self.client.driver.session() as session:
            other_pid = f"other-project-{uuid.uuid4()}"
            count = session.run(
                """
                MATCH (v:Vulnerability {project_id: $pid, source: 'vhost_sni_enum'})
                RETURN count(v) AS c
                """,
                pid=other_pid,
            ).single()["c"]
            self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()

"""Integration tests against a LIVE Neo4j.

Exercises the real driver path: target loader reads seeded AI endpoints, the
normalizer writes a Vulnerability and links it via HAS_VULNERABILITY, re-runs
dedup on the deterministic id, and the BaseURL fallback fires when no Endpoint
matches. Uses an isolated project id and cleans up before/after.

Skips automatically when no Neo4j is reachable, so it is safe in CI. Run with
the Neo4j creds in env and host networking:

    docker run --rm --network host \
      -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=changeme123 \
      -v "$PWD/ai_attack_surface_scan:/app/ai_attack_surface_scan" \
      redamon-ai-attack-surface:latest \
      python -m unittest ai_attack_surface_scan.tests.test_integration_graph -v
"""
import unittest

import graph
import target_loader as tl
from normalizer import Finding, finding_id, make_dummy_finding, write_finding

UID = "aiatk-itest-user"
PID = "aiatk-itest-proj"


def _reachable() -> bool:
    try:
        d = graph.make_driver()
        ok = graph.verify_connection(d)
        d.close()
        return ok
    except Exception:
        return False


@unittest.skipUnless(_reachable(), "no Neo4j reachable")
class TestGraphIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = graph.make_driver()

    @classmethod
    def tearDownClass(cls):
        cls._wipe(cls.driver)
        cls.driver.close()

    @staticmethod
    def _wipe(driver):
        with driver.session() as s:
            s.run("MATCH (n {project_id:$pid}) DETACH DELETE n", pid=PID)

    def setUp(self):
        self._wipe(self.driver)

    def _seed_endpoint(self, baseurl, path, iface="llm-chat"):
        with self.driver.session() as s:
            s.run(
                """
                MERGE (b:BaseURL {url:$baseurl, user_id:$uid, project_id:$pid})
                MERGE (e:Endpoint {baseurl:$baseurl, path:$path, user_id:$uid, project_id:$pid})
                  SET e.method='POST', e.ai_interface_type=$iface, e.ai_model_family_guess='qwen'
                MERGE (b)-[:HAS_ENDPOINT]->(e)
                """,
                baseurl=baseurl, path=path, iface=iface, uid=UID, pid=PID,
            )

    def _count(self, cypher, **kw):
        with self.driver.session() as s:
            return s.run(cypher, **kw).single()[0]

    # --- target loader --- #
    def test_load_all_ai_reads_seeded(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        with self.driver.session() as s:
            targets = tl.load_targets(s, UID, PID)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ai_interface_type, "llm-chat")
        self.assertEqual(targets[0].path, "/v1/chat/completions")

    def test_load_all_ai_excludes_non_llm_sentinel(self):
        # recon stamps every crawled endpoint; only chat endpoints are attackable.
        self._seed_endpoint("http://h:8000", "/v1/chat/completions", iface="llm-chat")
        self._seed_endpoint("http://h:8000", "/about", iface="non-llm")
        self._seed_endpoint("http://h:8000", "/v1/embeddings", iface="llm-embedding")
        with self.driver.session() as s:
            targets = tl.load_targets(s, UID, PID)  # headless: no explicit selection
        paths = sorted(t.path for t in targets)
        self.assertEqual(paths, ["/v1/chat/completions"])  # non-llm + embedding excluded

    def test_load_selected_enriches_from_graph(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        with self.driver.session() as s:
            targets = tl.load_targets(
                s, UID, PID,
                selected=[{"baseurl": "http://h:8000", "path": "/v1/chat/completions"}])
        self.assertEqual(targets[0].ai_model_family_guess, "qwen")

    def _orphan_count(self) -> int:
        return self._count(
            "MATCH (v:Vulnerability {project_id:$pid}) WHERE NOT (v)--() RETURN count(v)",
            pid=PID)

    # --- normalizer linkage --- #
    def test_write_finding_links_to_endpoint(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        target = tl.Target(baseurl="http://h:8000", path="/v1/chat/completions",
                           ai_interface_type="llm-chat")
        f = make_dummy_finding(target, "skeleton", "itest")
        with self.driver.session() as s:
            status = write_finding(s, f, UID, PID)
        self.assertEqual(status, "existing")
        edges = self._count(
            "MATCH (:Endpoint {project_id:$pid})-[r:HAS_VULNERABILITY]->(:Vulnerability) RETURN count(r)",
            pid=PID)
        self.assertEqual(edges, 1)
        self.assertEqual(self._orphan_count(), 0)

    def test_write_finding_is_idempotent(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        target = tl.Target(baseurl="http://h:8000", path="/v1/chat/completions")
        f = make_dummy_finding(target, "skeleton", "itest")
        with self.driver.session() as s:
            write_finding(s, f, UID, PID)
            write_finding(s, f, UID, PID)  # same deterministic id -> MERGE
        vulns = self._count("MATCH (v:Vulnerability {project_id:$pid}) RETURN count(v)", pid=PID)
        self.assertEqual(vulns, 1)

    def test_materialises_endpoint_under_existing_baseurl(self):
        # Seed only a BaseURL (no Endpoint on the attacked path). The normalizer
        # must CREATE the missing Endpoint under that BaseURL and link to it
        # (never fall back to an orphan-prone bare-BaseURL link).
        with self.driver.session() as s:
            s.run("MERGE (b:BaseURL {url:$u, user_id:$uid, project_id:$pid})",
                  u="http://h:8000", uid=UID, pid=PID)
        f = Finding(source="skeleton", chip="prompt-injection", name="n",
                    baseurl="http://h:8000", path="/missing", ai_owasp_llm_id="LLM01",
                    ai_payload_class="x")
        with self.driver.session() as s:
            status = write_finding(s, f, UID, PID)
        self.assertEqual(status, "created")
        # the new Endpoint hangs off the *existing* (reused) BaseURL...
        self.assertEqual(self._count(
            "MATCH (:BaseURL {url:'http://h:8000', project_id:$pid})-[:HAS_ENDPOINT]->"
            "(e:Endpoint {path:'/missing'}) RETURN count(e)", pid=PID), 1)
        # ...and the finding links to that Endpoint, marked synthetic.
        self.assertEqual(self._count(
            "MATCH (e:Endpoint {path:'/missing', project_id:$pid})-[:HAS_VULNERABILITY]->(:Vulnerability) "
            "WHERE e.source='ai_attack_target' RETURN count(e)", pid=PID), 1)
        self.assertEqual(self._orphan_count(), 0)

    # --- regression: custom (off-graph) targets must never orphan --- #
    def test_custom_hostname_materialises_connected_chain(self):
        # Nothing seeded: a fully custom hostname target. Expect the full anchor
        # chain Domain -> Subdomain -> BaseURL -> Endpoint -> Vulnerability.
        target = tl.Target(baseurl="http://newhost.example.com", path="/v1/chat/completions",
                           ai_interface_type="llm-chat", ai_model_ids=["qwen2.5"])
        f = Finding(source="garak", chip="prompt-injection", name="pi",
                    baseurl="http://newhost.example.com", path="/v1/chat/completions",
                    ai_owasp_llm_id="LLM01", ai_payload_class="garak-promptinject")
        with self.driver.session() as s:
            status = write_finding(s, f, UID, PID, target=target)
        self.assertEqual(status, "created")
        chain = self._count(
            """
            MATCH (d:Domain {name:'example.com', project_id:$pid})-[:HAS_SUBDOMAIN]->
                  (s:Subdomain {name:'newhost.example.com'})-[:HAS_BASE_URL]->
                  (b:BaseURL {url:'http://newhost.example.com'})-[:HAS_ENDPOINT]->
                  (e:Endpoint {path:'/v1/chat/completions'})-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN count(v)
            """, pid=PID)
        self.assertEqual(chain, 1)
        # the materialised endpoint carries the target's AI annotations + provenance
        self.assertEqual(self._count(
            "MATCH (e:Endpoint {path:'/v1/chat/completions', project_id:$pid}) "
            "WHERE e.source='ai_attack_target' AND e.ai_interface_type='llm-chat' "
            "AND e.ai_attack_synthetic=true RETURN count(e)", pid=PID), 1)
        self.assertEqual(self._orphan_count(), 0)

    def test_custom_ip_target_anchors_to_ip(self):
        # A raw-IP target (the real E2E shape: http://172.25.0.1:11435). No
        # Subdomain is fabricated; the IP anchors the component via the vuln.
        f = Finding(source="garak", chip="prompt-injection", name="pi",
                    baseurl="http://172.25.0.1:11435", path="/v1/chat/completions",
                    ai_owasp_llm_id="LLM01", ai_payload_class="garak-promptinject")
        with self.driver.session() as s:
            status = write_finding(s, f, UID, PID)
        self.assertEqual(status, "created")
        self.assertEqual(self._count(
            "MATCH (ip:IP {address:'172.25.0.1', project_id:$pid})-[:HAS_VULNERABILITY]->(:Vulnerability) "
            "RETURN count(ip)", pid=PID), 1)
        self.assertEqual(self._count(
            "MATCH (:BaseURL {url:'http://172.25.0.1:11435', project_id:$pid})-[:HAS_ENDPOINT]->"
            "(:Endpoint)-[:HAS_VULNERABILITY]->(:Vulnerability) RETURN count(*)", pid=PID), 1)
        self.assertEqual(self._count(
            "MATCH (s:Subdomain {project_id:$pid}) RETURN count(s)", pid=PID), 0)
        self.assertEqual(self._orphan_count(), 0)

    def test_never_orphans_across_mixed_targets(self):
        # The core invariant: across existing, custom-hostname and custom-IP
        # targets, NO Vulnerability is ever left without an edge.
        self._seed_endpoint("http://known:8000", "/v1/chat/completions")
        findings = [
            Finding(source="garak", chip="prompt-injection", name="a",
                    baseurl="http://known:8000", path="/v1/chat/completions",
                    ai_owasp_llm_id="LLM01", ai_payload_class="garak-dan"),
            Finding(source="pyrit", chip="jailbreak", name="b",
                    baseurl="http://custom.example.org", path="/chat",
                    ai_owasp_llm_id="LLM01", ai_payload_class="pyrit-crescendo"),
            Finding(source="promptfoo", chip="prompt-injection", name="c",
                    baseurl="http://10.1.2.3:9000", path="/v1/chat/completions",
                    ai_owasp_llm_id="LLM01", ai_payload_class="promptfoo-base64"),
        ]
        with self.driver.session() as s:
            for f in findings:
                write_finding(s, f, UID, PID)
        self.assertEqual(self._count(
            "MATCH (v:Vulnerability {project_id:$pid}) RETURN count(v)", pid=PID), 3)
        self.assertEqual(self._orphan_count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

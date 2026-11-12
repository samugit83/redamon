"""LIVE-Neo4j: every triage fact and finding query still runs, with the new columns.

The triage fixes added columns to the finding queries (`v.detection_method`,
`s.validation_info`) and reworked two fact queries (FFuf's 'auth' category and
the injectable_auth_hosts precedence). The unit tests read the query TEXT; a
query Neo4j rejects fails the whole triage run. This executes every one of
them, and the single-finding variant, against a real database.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_fix_fact_queries_graph_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import json
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

VALIDATION_INFO = json.dumps({"status": "invalid", "valid": False,
                              "info": "status=401", "error": ""})


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveFactQueriesCase(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"factq-{run}"
        self.pid = f"FACTQ_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with self.driver.session() as s:
            s.run(
                """
                CREATE (b:BaseURL {url: 'https://app.factq.test', user_id: $u, project_id: $p})
                CREATE (e:Endpoint {path: '/login', method: 'GET',
                                    baseurl: 'https://app.factq.test', category: 'auth',
                                    user_id: $u, project_id: $p})
                CREATE (pa:Parameter {name: 'user', is_injectable: true,
                                      user_id: $u, project_id: $p})
                CREATE (b)-[:HAS_ENDPOINT]->(e)
                CREATE (e)-[:HAS_PARAMETER]->(pa)
                CREATE (v:Vulnerability {id: 'waf', source: 'security_check',
                                         type: 'waf_bypass', name: 'WAF Bypass',
                                         severity: 'medium', detection_method: 'static_headers',
                                         user_id: $u, project_id: $p, updated_at: datetime()})
                CREATE (b)-[:HAS_VULNERABILITY]->(v)
                CREATE (x:Secret {id: 'sec', source: 'js_recon', secret_type: 'Stripe Secret Key',
                                  key_type: 'payment', validation_status: 'invalid',
                                  validation_info: $vinfo, base_url: 'https://app.factq.test',
                                  user_id: $u, project_id: $p, updated_at: datetime()})
                """, u=self.uid, p=self.pid, vinfo=VALIDATION_INFO)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
        self.driver.close()

    def _run(self, query, **params):
        with self.driver.session() as s:
            return [dict(r) for r in s.run(query, userId=self.uid, projectId=self.pid, **params)]

    def test_every_project_fact_query_runs(self):
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES

        for q in PROJECT_FACT_QUERIES:
            with self.subTest(query=q["name"]):
                self._run(q["query"])

    def test_every_finding_query_and_its_single_finding_variant_runs(self):
        from cypherfix_triage.fact_queries import FINDING_QUERIES, finding_query_by_id

        for q in FINDING_QUERIES:
            with self.subTest(query=q["name"]):
                self._run(q["query"])
                self._run(finding_query_by_id(q), findingId="none")

    def test_a_waf_bypass_row_carries_its_detection_method(self):
        from cypherfix_triage.fact_queries import FINDING_QUERIES

        query = next(q for q in FINDING_QUERIES if q["name"] == "vulnerabilities")["query"]
        rows = {r["id"]: r for r in self._run(query)}
        self.assertEqual(rows["waf"]["detection_method"], "static_headers")
        self.assertEqual(rows["waf"]["type"], "waf_bypass")

    def test_a_secret_row_carries_its_validation_info(self):
        from cypherfix_triage.fact_queries import FINDING_QUERIES

        query = next(q for q in FINDING_QUERIES if q["name"] == "secrets")["query"]
        rows = {r["id"]: r for r in self._run(query)}
        self.assertEqual(rows["sec"]["validation_info"], VALIDATION_INFO)

    def test_different_secrets_of_one_category_on_one_host_are_separate_groups(self):
        from cypherfix_triage import grouping
        from cypherfix_triage.fact_queries import FINDING_QUERIES

        with self.driver.session() as s:
            s.run("""
                UNWIND $rows AS row
                CREATE (x:Secret {id: row.id, source: 'js_recon', key_type: 'cloud',
                                  secret_type: row.type, matched_text: row.value,
                                  sample: 'redacted', base_url: row.host,
                                  user_id: $u, project_id: $p, updated_at: datetime()})
                """, u=self.uid, p=self.pid, rows=[
                {"id": "gk", "type": "GCP API Key", "value": "AIzaSyD-EXAMPLEKEY0000000000000000000",
                 "host": "https://app.factq.test"},
                {"id": "ak", "type": "AWS Access Key ID", "value": "AKIAIOSFODNN7EXAMPLE",
                 "host": "https://app.factq.test"},
                {"id": "ak2", "type": "AWS Access Key ID", "value": "AKIAIOSFODNN7EXAMPLE",
                 "host": "https://cdn.factq.test"},
            ])
        query = next(q for q in FINDING_QUERIES if q["name"] == "secrets")["query"]
        rows = {r["id"]: r for r in self._run(query)}
        keys = {i: grouping.group_key(rows[i]) for i in ("gk", "ak", "ak2")}
        self.assertNotEqual(keys["gk"], keys["ak"])
        self.assertEqual(keys["ak"], keys["ak2"])
        self.assertEqual(rows["gk"]["detector_name"], "GCP API Key")

    def _gone(self):
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES

        query = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "gone_hosts")["query"]
        rows = self._run(query)
        self.assertEqual(len(rows), 1)
        return set(rows[0]["hosts"])

    def test_an_ip_a_subdomain_resolves_to_is_not_gone(self):
        # No open port and no endpoint, but DNS still points at it.
        with self.driver.session() as s:
            s.run("""
                CREATE (sd:Subdomain {name: 'www.factq.test', user_id: $u, project_id: $p})
                CREATE (ip:IP {address: '192.0.2.10', user_id: $u, project_id: $p})
                CREATE (sd)-[:RESOLVES_TO]->(ip)
                CREATE (:IP {address: '192.0.2.11', user_id: $u, project_id: $p})
                CREATE (:Subdomain {name: 'old.factq.test', user_id: $u, project_id: $p})
                """, u=self.uid, p=self.pid)
        gone = self._gone()
        self.assertNotIn("192.0.2.10", gone)
        self.assertNotIn("www.factq.test", gone)
        # Controls: nothing resolves to or from these, no port, no endpoint.
        self.assertIn("192.0.2.11", gone)
        self.assertIn("old.factq.test", gone)

    def test_a_host_the_run_skipped_is_unknown_not_gone(self):
        with self.driver.session() as s:
            s.run("""
                CREATE (:Domain {name: 'factq.test', user_id: $u, project_id: $p,
                                 recon_skipped_hosts: ['Skipped.factq.test:443',
                                                       '[2001:db8::5]:8443', '192.0.2.12']})
                CREATE (:Subdomain {name: 'skipped.factq.test', user_id: $u, project_id: $p})
                CREATE (:IP {address: '2001:db8::5', user_id: $u, project_id: $p})
                CREATE (:IP {address: '192.0.2.12', user_id: $u, project_id: $p})
                CREATE (:Subdomain {name: 'unskipped.factq.test', user_id: $u, project_id: $p})
                """, u=self.uid, p=self.pid)
            # Another project's coverage record must not shelter this one's hosts.
            s.run("""
                CREATE (:Domain {name: 'factq.test', user_id: $u, project_id: $other,
                                 recon_skipped_hosts: ['unskipped.factq.test:443']})
                """, u=self.uid, other=self.pid + "_other")
        try:
            gone = self._gone()
        finally:
            with self.driver.session() as s:
                s.run("MATCH (n {project_id: $other}) DETACH DELETE n", other=self.pid + "_other")
        self.assertNotIn("skipped.factq.test", gone)
        self.assertNotIn("2001:db8::5", gone)
        self.assertNotIn("192.0.2.12", gone)
        self.assertIn("unskipped.factq.test", gone)

    def _facts(self, *names):
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES, build_project_facts

        return build_project_facts({q["name"]: self._run(q["query"])
                                    for q in PROJECT_FACT_QUERIES if q["name"] in names})

    def test_the_gate_reads_a_skipped_port_apart_from_a_skipped_host(self):
        with self.driver.session() as s:
            s.run("""
                CREATE (:Domain {name: 'factq.test', user_id: $u, project_id: $p,
                                 recon_skipped_hosts: ['Skipped.factq.test:443', '[2001:db8::5]:8443',
                                                       'Whole.factq.test']})
                CREATE (:Domain {name: 'factq.test', user_id: $u, project_id: $other,
                                 recon_skipped_hosts: ['other.factq.test:443']})
                """, u=self.uid, p=self.pid, other=self.pid + "_other")
        try:
            facts = self._facts("skipped_hosts")
        finally:
            with self.driver.session() as s:
                s.run("MATCH (n {project_id: $other}) DETACH DELETE n", other=self.pid + "_other")
        self.assertEqual(facts.skipped_ports, {("skipped.factq.test", 443), ("2001:db8::5", 8443)})
        self.assertEqual(facts.skipped_hosts, {"whole.factq.test"})

    def test_a_name_carries_the_tags_of_the_ips_it_resolves_to(self):
        with self.driver.session() as s:
            s.run("""
                CREATE (own:Subdomain {name: 'own.factq.test', user_id: $u, project_id: $p})
                CREATE (edge:Subdomain {name: 'edge.factq.test', user_id: $u, project_id: $p})
                CREATE (mixed:Subdomain {name: 'mixed.factq.test', user_id: $u, project_id: $p})
                CREATE (d:IP {address: '192.0.2.20', ownership: 'dedicated', user_id: $u, project_id: $p})
                CREATE (e:IP {address: '198.51.100.20', ownership: 'shared_edge', user_id: $u, project_id: $p})
                CREATE (n:IP {address: '203.0.113.20', user_id: $u, project_id: $p})
                CREATE (own)-[:RESOLVES_TO]->(d)
                CREATE (edge)-[:RESOLVES_TO]->(e)
                // A PTR answer Shodan recorded is not current DNS.
                CREATE (edge)-[:RESOLVES_TO {source: 'shodan_rdns'}]->(d)
                CREATE (mixed)-[:RESOLVES_TO]->(d)
                CREATE (mixed)-[:RESOLVES_TO]->(n)
                """, u=self.uid, p=self.pid)
        facts = self._facts("name_ownership")
        self.assertEqual(facts.name_ownership, {"own.factq.test": {"dedicated"},
                                                "edge.factq.test": {"shared_edge"},
                                                "mixed.factq.test": {"dedicated", ""}})


if __name__ == "__main__":
    unittest.main()

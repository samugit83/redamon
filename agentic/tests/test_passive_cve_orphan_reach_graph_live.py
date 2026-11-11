"""LIVE-Neo4j: the board's real query tells a passive CVE whose IP left the graph.

The unit file (test_passive_cve_orphan_reach.py) reads the query TEXT. This runs
the real `vulnerabilities` finding query and the project fact queries against
a database, the way a triage run does, and scores the rows:

- a Shodan CVE whose IP node is gone (a full run's asset clear) and whose
  stored `port_confirmed` is true reads reach unknown and R capped;
- a Shodan CVE still under its IP keeps its port verdict;
- another project's IP at the same address does not count as this one's;
- a finding with no `target_ip` gets no verdict (null), as before.

Hosts are RFC 5737 addresses. Everything it creates is scoped to a throwaway
tenant and deleted in tearDown. Self-skips unless the driver imports and a
database answers:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/agentic \\
    -e PYTHONPATH=/repo/agentic:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_passive_cve_orphan_reach_graph_live.py -v
"""

import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_SKIP_REASON = None
try:
    import neo4j as _neo4j
except ImportError:
    _neo4j = None
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _neo4j is not None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _alive() -> bool:
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD), connection_timeout=3)
        drv.verify_connectivity()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _alive()

LEFT = "198.51.100.40"
STILL_HERE = "198.51.100.41"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class ThePassiveCveOfAnIpThatLeftTheGraph(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"orphan-{run}"
        self.pid = f"ORPHAN_{run}"
        self.other = f"{self.pid}_other"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with self.driver.session() as s:
            s.run(
                """
                CREATE (ip:IP {address: $here, user_id: $u, project_id: $p})
                CREATE (pt:Port {number: 22, protocol: 'tcp', ip_address: $here,
                                 user_id: $u, project_id: $p})
                CREATE (ip)-[:HAS_PORT]->(pt)
                CREATE (kept:Vulnerability {id: 'shodan-CVE-2021-23017-' + $here,
                        source: 'shodan_api', name: 'CVE-2021-23017',
                        cves: ['CVE-2021-23017'], cisa_kev: true, severity: 'critical',
                        cvss_score: 9.8, detection_method: 'passive_version_match',
                        target_ip: $here, target_port: 22, port_confirmed: true,
                        user_id: $u, project_id: $p, updated_at: datetime()})
                CREATE (ip)-[:HAS_VULNERABILITY]->(kept)
                CREATE (:Vulnerability {id: 'shodan-CVE-2021-23017-' + $left,
                        source: 'shodan_api', name: 'CVE-2021-23017',
                        cves: ['CVE-2021-23017'], cisa_kev: true, severity: 'critical',
                        cvss_score: 9.8, detection_method: 'passive_version_match',
                        target_ip: $left, target_port: 22, port_confirmed: true,
                        user_id: $u, project_id: $p, updated_at: datetime()})
                CREATE (:Vulnerability {id: 'no-ip', source: 'security_check',
                        name: 'missing_hsts', type: 'missing_hsts', severity: 'info',
                        user_id: $u, project_id: $p, updated_at: datetime()})
                CREATE (:IP {address: $left, user_id: $u, project_id: $other})
                """, u=self.uid, p=self.pid, other=self.other, here=STILL_HERE, left=LEFT)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)
        self.driver.close()

    def _run(self, query, **params):
        with self.driver.session() as s:
            return [dict(r) for r in s.run(query, userId=self.uid, projectId=self.pid, **params)]

    def _board(self):
        from cypherfix_triage.fact_queries import (
            FINDING_QUERIES, PROJECT_FACT_QUERIES, build_project_facts, normalise_finding_row)

        facts = build_project_facts({q["name"]: self._run(q["query"])
                                     for q in PROJECT_FACT_QUERIES})
        query = next(q for q in FINDING_QUERIES if q["name"] == "vulnerabilities")["query"]
        rows = {r["id"]: normalise_finding_row(r) for r in self._run(query)}
        return rows, facts

    def test_the_row_says_whether_its_ip_is_in_this_projects_graph(self):
        rows, _ = self._board()
        self.assertIs(rows[f"shodan-CVE-2021-23017-{LEFT}"]["target_ip_in_graph"], False)
        self.assertIs(rows[f"shodan-CVE-2021-23017-{STILL_HERE}"]["target_ip_in_graph"], True)
        self.assertIsNone(rows["no-ip"]["target_ip_in_graph"])

    def test_the_orphan_reads_reach_unknown_and_its_neighbour_does_not(self):
        from cypherfix_triage import score_model as sm

        rows, facts = self._board()
        orphan = rows[f"shodan-CVE-2021-23017-{LEFT}"]
        self.assertEqual(orphan["triage_host"], LEFT)
        self.assertNotIn(LEFT, facts.gone_hosts)
        result = sm.score(orphan, facts)
        self.assertEqual(result.state, sm.STATE_OPEN)
        self.assertIsNone(result.tier_inputs.gates["reachable_now"])
        self.assertTrue(result.tier_inputs.passive_unconfirmed)
        self.assertEqual(result.reach.value, sm.LEFT_TARGET_MAX_REACH)

        kept = sm.score(rows[f"shodan-CVE-2021-23017-{STILL_HERE}"], facts)
        self.assertIs(kept.tier_inputs.gates["reachable_now"], True)
        self.assertFalse(kept.tier_inputs.passive_unconfirmed)
        self.assertEqual(kept.reach.value, 1.0)

    def test_the_single_finding_read_carries_the_column(self):
        from cypherfix_triage.fact_queries import FINDING_QUERIES, finding_query_by_id

        query_def = next(q for q in FINDING_QUERIES if q["name"] == "vulnerabilities")
        rows = self._run(finding_query_by_id(query_def),
                         findingId=f"shodan-CVE-2021-23017-{LEFT}")
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["target_ip_in_graph"], False)


if __name__ == "__main__":
    unittest.main()

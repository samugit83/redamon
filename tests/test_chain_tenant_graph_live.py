"""LIVE-Neo4j proof that a run never writes into another tenant's attack chain (review of RBAC 5.3).

A chain id is the browser's session id; a reader of a shared project sees the owner's. The
hermetic tests (agentic/tests/test_chain_tenant_scope.py) pin the Cypher; only a real database
with the uniqueness constraints proves the end state:

  * a second tenant creating a chain with the owner's chain id changes nothing on the owner's
    chain (attack_path_type, tenant, CHAIN_TARGETS) and adds no chain of its own;
  * its first step neither lands nor hangs off the owner's chain;
  * the owner's own step still lands and links (HAS_STEP), with a full-length or a short id.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_chain_tenant_graph_live.py -v

Everything is scoped to throwaway ids and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (_REPO, os.path.join(_REPO, "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

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


def _step(step_id, chain_id, user_id, project_id, prev=None):
    return dict(step_id=step_id, chain_id=chain_id, prev_step_id=prev, user_id=user_id, project_id=project_id,
                iteration=1, phase="informational", tool_name="execute_curl", tool_args_summary="", thought="",
                reasoning="", output_summary="", output_analysis="", success=True, error_message=None,
                duration_ms=1, extracted_info={"primary_target": "198.51.100.7"})


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestChainTenantGraphLive(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.owner, self.pid = f"chainten-owner-{run}", f"CHAINTEN_P_{run}"
        self.reader, self.reader_pid = f"chainten-reader-{run}", f"CHAINTEN_R_{run}"
        self.chain = f"chainten-session-{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with self.driver.session() as s:
            s.run(
                """
                CREATE (:IP {address: '198.51.100.7', user_id: $o, project_id: $p})
                CREATE (:IP {address: '198.51.100.7', user_id: $r, project_id: $rp})
                """,
                o=self.owner, p=self.pid, r=self.reader, rp=self.reader_pid,
            )

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id IN [$o, $r] DETACH DELETE n", o=self.owner, r=self.reader)
        self.driver.close()

    def _chain(self, user_id, project_id, attack_path_type):
        from orchestrator_helpers.chain_graph_writer import _write_attack_chain
        _write_attack_chain(_URI, _USER, _PASSWORD, chain_id=self.chain, user_id=user_id, project_id=project_id,
                            title="t", objective="o", attack_path_type=attack_path_type,
                            target_host="198.51.100.7", target_port=None, target_cves=[])

    def _one(self, query, **params):
        with self.driver.session() as s:
            return s.run(query, **params).single()

    def test_another_tenant_never_writes_into_the_owner_s_chain(self):
        from orchestrator_helpers.chain_graph_writer import _write_step
        self._chain(self.owner, self.pid, "cve_exploit")
        with self.assertLogs("orchestrator_helpers.chain_graph_writer", "WARNING") as logs:
            self._chain(self.reader, self.reader_pid, "xss")
            _write_step(_URI, _USER, _PASSWORD, **_step(uuid.uuid4().hex, self.chain, self.reader, self.reader_pid))
        self.assertEqual(sum("[rbac] chain_tenant_mismatch" in line for line in logs.output), 2, logs.output)

        row = self._one(
            """
            MATCH (ac:AttackChain {chain_id: $c})
            OPTIONAL MATCH (ac)-[:CHAIN_TARGETS]->(t)
            OPTIONAL MATCH (ac)-[:HAS_STEP]->(s)
            RETURN count(DISTINCT ac) AS chains, collect(DISTINCT ac.user_id) AS tenants,
                   collect(DISTINCT ac.attack_path_type) AS paths,
                   collect(DISTINCT t.project_id) AS target_projects, count(DISTINCT s) AS steps
            """,
            c=self.chain,
        )
        self.assertEqual(row["chains"], 1)
        self.assertEqual(row["tenants"], [self.owner])
        self.assertEqual(row["paths"], ["cve_exploit"], "ON MATCH SET never reaches the owner's chain")
        self.assertEqual(row["target_projects"], [self.pid])
        self.assertEqual(row["steps"], 0)
        self.assertEqual(self._one("MATCH (s:ChainStep {user_id: $r}) RETURN count(s) AS n", r=self.reader)["n"], 0)

    def test_the_owner_s_own_steps_land_and_link_whatever_their_id_length(self):
        from orchestrator_helpers.chain_graph_writer import _write_step
        self._chain(self.owner, self.pid, "cve_exploit")
        first, second = uuid.uuid4().hex, uuid.uuid4().hex[:8]
        _write_step(_URI, _USER, _PASSWORD, **_step(first, self.chain, self.owner, self.pid))
        _write_step(_URI, _USER, _PASSWORD, **_step(second, self.chain, self.owner, self.pid, prev=first))
        row = self._one(
            """
            MATCH (ac:AttackChain {chain_id: $c, user_id: $o, project_id: $p})-[:HAS_STEP]->(a:ChainStep)
                  -[:NEXT_STEP]->(b:ChainStep)
            OPTIONAL MATCH (a)-[:STEP_TARGETED]->(ip:IP)
            RETURN a.step_id AS a, b.step_id AS b, collect(ip.project_id) AS targets
            """,
            c=self.chain, o=self.owner, p=self.pid,
        )
        self.assertIsNotNone(row)
        self.assertEqual((row["a"], row["b"]), (first, second))
        self.assertEqual(row["targets"], [self.pid], "the step bridges to its own project's IP only")


if __name__ == "__main__":
    unittest.main(verbosity=2)

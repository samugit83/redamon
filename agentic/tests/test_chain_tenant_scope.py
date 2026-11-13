"""
Every attack-chain write is scoped to the run's tenant and project (review of RBAC step 5.3).

A chain's id is the ticket's `sid`, a session id the browser chooses. A person who can read a
shared project's graph sees its chain ids, so a run of theirs on another project could name the
owner's chain id: the writer used to MERGE the AttackChain by chain_id alone (its ON MATCH SET then
rewrote the owner's attack_path_type and its CHAIN_TARGETS bridged to the other project's nodes)
and to link the first step to whichever chain held the id. Now every chain and step write keys on
chain_id or step_id AND the tenant's user_id AND project_id, and a chain id that another tenant or
project holds is refused (`[rbac] chain_tenant_mismatch`), never merged into.

Step ids were 32 bits (`uuid4()[:8]`) under a database-wide uniqueness constraint, and every
ChainStep MERGE/MATCH keyed on the id alone, so an accidental collision attached this run's
findings to another tenant's step. New steps get full-length ids; MERGE/MATCH carry the tenant
and the project, so an old short id keeps working inside its own project.

Run: ./agentic/run_tests.sh tests/test_chain_tenant_scope.py
"""
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC_DIR))

import orchestrator_helpers.chain_graph_writer as cg  # noqa: E402
from state import ExecutionStep  # noqa: E402

NEO4J = ("bolt://unused", "neo4j", "pw")
OWNER, PID = "owner-1", "p-owner"
OTHER, OTHER_PID = "reader-1", "p-reader"
CHAIN = "s-owner-session"
SHORT_STEP = "abcd1234"
WRITER_SRC = (_AGENTIC_DIR / "orchestrator_helpers" / "chain_graph_writer.py").read_text()
NODES = _AGENTIC_DIR / "orchestrator_helpers" / "nodes"


class _Result:
    def __init__(self, record):
        self._record = record

    def single(self):
        return self._record


class _Session:
    """Records every query; answers the foreign-chain probe as told, a finding create with a row."""

    def __init__(self, foreign: bool):
        self.foreign = foreign
        self.ran = []

    def run(self, cypher, params=None, **kw):
        self.ran.append((cypher, params if params is not None else kw))
        if cypher == cg.CHAIN_HELD_ELSEWHERE_CYPHER:
            return _Result({"chain_id": CHAIN} if self.foreign else None)
        if "RETURN f.finding_id AS fid" in cypher:
            return _Result({"fid": "f-1"})
        return _Result(None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _run(write, *, foreign=False, **kwargs):
    session = _Session(foreign)
    with mock.patch.object(cg, "_get_driver"), mock.patch.object(cg, "_session", return_value=session):
        write(*NEO4J, **kwargs)
    return session


def _attack_chain(user_id=OTHER, project_id=OTHER_PID):
    return dict(chain_id=CHAIN, user_id=user_id, project_id=project_id, title="t", objective="o",
                attack_path_type="xss", target_host="host.test", target_port=443, target_cves=["CVE-2000-0001"])


def _step(prev_step_id=None, user_id=OTHER, project_id=OTHER_PID, step_id=SHORT_STEP):
    return dict(step_id=step_id, chain_id=CHAIN, prev_step_id=prev_step_id, user_id=user_id,
                project_id=project_id, iteration=1, phase="informational", tool_name="execute_curl",
                tool_args_summary="", thought="", reasoning="", output_summary="", output_analysis="",
                success=True, error_message=None, duration_ms=1,
                extracted_info={"primary_target": "192.0.2.1", "ports": [443], "vulnerabilities": ["CVE-2000-0001"],
                                "technologies": ["nginx"]})


def _finding(user_id=OTHER, project_id=OTHER_PID):
    return dict(finding_id="f-1", chain_id=CHAIN, step_id=SHORT_STEP, user_id=user_id, project_id=project_id,
                finding_type="custom", severity="high", title="t", description="", evidence="", confidence=80,
                phase="informational", iteration=1, related_cves=[], related_ips=[])


def _failure(user_id=OTHER, project_id=OTHER_PID):
    return dict(failure_id="fl-1", chain_id=CHAIN, step_id=SHORT_STEP, user_id=user_id, project_id=project_id,
                failure_type="tool_error", tool_name="execute_curl", error_category="", error_message="",
                lesson_learned="", retry_possible=True, phase="informational", iteration=1)


def _decision(user_id=OTHER, project_id=OTHER_PID):
    return dict(decision_id="d-1", chain_id=CHAIN, step_id=SHORT_STEP, user_id=user_id, project_id=project_id,
                decision_type="phase_transition", from_state="informational", to_state="exploitation",
                reason="", made_by="user", approved=True, iteration=1)


def _exploit(user_id=OTHER, project_id=OTHER_PID):
    return dict(chain_id=CHAIN, step_id=SHORT_STEP, user_id=user_id, project_id=project_id,
                attack_type="cve_exploit", target_ip="192.0.2.1", target_port=443, cve_ids=["CVE-2000-0001"],
                metasploit_module=None, payload=None, session_id=None, username=None, password_found=None,
                evidence="", execution_trace=[], iteration=1)


WRITERS = {
    "AttackChain": (cg._write_attack_chain, _attack_chain),
    "ChainStep": (cg._write_step, _step),
    "ChainFinding": (cg._write_finding, _finding),
    "ChainFailure": (cg._write_failure, _failure),
    "ChainDecision": (cg._write_decision, _decision),
    "exploit success": (cg._write_exploit_success, _exploit),
}


def _node_maps(cypher: str, label: str):
    """The property map of every `(<var>:<label> {...})` pattern in a query."""
    return re.findall(r"\(\w*:" + label + r" \{([^}]*)\}\)", cypher)


class AChainIdHeldElsewhereIsRefused(unittest.TestCase):
    def test_every_chain_writer_refuses_another_tenant_s_chain_logs_it_and_writes_nothing(self):
        for name, (write, kwargs) in WRITERS.items():
            with self.subTest(writer=name):
                with self.assertLogs(cg.logger, "WARNING") as logs:
                    session = _run(write, foreign=True, **kwargs())
                self.assertEqual([c for c, _ in session.ran], [cg.CHAIN_HELD_ELSEWHERE_CYPHER],
                                 "only the probe runs: no MERGE, CREATE or link")
                self.assertTrue(any("[rbac] chain_tenant_mismatch" in line for line in logs.output), logs.output)
                probe = session.ran[0][1]
                self.assertEqual((probe["chain_id"], probe["user_id"], probe["project_id"]), (CHAIN, OTHER, OTHER_PID))

    def test_the_probe_finds_a_chain_of_another_tenant_or_of_another_project(self):
        probe = cg.CHAIN_HELD_ELSEWHERE_CYPHER
        self.assertIn("MATCH (ac:AttackChain {chain_id: $chain_id})", probe)
        self.assertIn("ac.user_id", probe)
        self.assertIn("ac.project_id", probe)
        self.assertRegex(probe, r"<> \$user_id\s+OR\s+.*<> \$project_id")

    def test_the_tenant_s_own_chain_is_written(self):
        for name, (write, kwargs) in WRITERS.items():
            with self.subTest(writer=name):
                session = _run(write, foreign=False, **kwargs(user_id=OWNER, project_id=PID))
                self.assertGreater(len(session.ran), 1, "past the probe the write goes on")


class TheChainIsCreatedOnTheTenantTriple(unittest.TestCase):
    def test_the_attack_chain_merge_keys_on_chain_tenant_and_project(self):
        session = _run(cg._write_attack_chain, **_attack_chain(user_id=OWNER, project_id=PID))
        cypher, params = session.ran[1]
        self.assertIn("MERGE (ac:AttackChain {chain_id: $chain_id, user_id: $user_id, project_id: $project_id})",
                      cypher)
        self.assertNotIn("MERGE (ac:AttackChain {chain_id: $chain_id})", cypher)
        self.assertEqual((params["chain_id"], params["user_id"], params["project_id"]), (CHAIN, OWNER, PID))
        # The bridges reach only the tenant's project (CVE is a global reference node).
        for label in ("IP", "Subdomain", "Domain"):
            for props in _node_maps(cypher, label):
                self.assertIn("user_id: $user_id", props)
                self.assertIn("project_id: $project_id", props)


class EveryStepWriteCarriesTheTenant(unittest.TestCase):
    def _assert_scoped(self, session):
        seen = 0
        for cypher, params in session.ran:
            if cypher == cg.CHAIN_HELD_ELSEWHERE_CYPHER:
                continue
            for label in ("ChainStep", "AttackChain"):
                for props in _node_maps(cypher, label):
                    seen += 1
                    self.assertRegex(props, r"user_id: \$(user_id|uid)", f"{label} {{{props}}} in {cypher}")
                    self.assertRegex(props, r"project_id: \$(project_id|pid)", f"{label} {{{props}}} in {cypher}")
                    tenant = params.get("user_id", params.get("uid"))
                    project = params.get("project_id", params.get("pid"))
                    self.assertEqual((tenant, project), (OWNER, PID))
        return seen

    def test_the_first_step_links_to_the_tenant_s_chain_and_its_bridges_to_the_tenant_s_step(self):
        session = _run(cg._write_step, **_step(user_id=OWNER, project_id=PID))
        self.assertGreaterEqual(self._assert_scoped(session), 6, "MERGE, HAS_STEP (chain + step), 4 bridges")
        self.assertTrue(any("[:HAS_STEP]" in c for c, _ in session.ran))

    def test_a_later_step_links_to_its_predecessor_in_the_tenant_s_project(self):
        session = _run(cg._write_step, **_step(prev_step_id="0f0f0f0f", user_id=OWNER, project_id=PID))
        self.assertGreaterEqual(self._assert_scoped(session), 7)
        self.assertTrue(any("[:NEXT_STEP]" in c for c, _ in session.ran))

    def test_findings_failures_decisions_and_exploits_attach_to_the_tenant_s_step(self):
        for name in ("ChainFinding", "ChainFailure", "ChainDecision", "exploit success"):
            with self.subTest(writer=name):
                write, kwargs = WRITERS[name]
                session = _run(write, **kwargs(user_id=OWNER, project_id=PID))
                self.assertGreaterEqual(self._assert_scoped(session), 1)

    def test_no_query_in_the_writer_matches_a_step_or_a_chain_by_its_id_alone(self):
        """Finds the next writer that forgets: only the foreign-chain probe names a chain id alone."""
        patterns = 0
        for label, key in (("ChainStep", "step_id"), ("AttackChain", "chain_id")):
            for props in _node_maps(WRITER_SRC, label):
                if not props.startswith(key):
                    continue
                patterns += 1
                if label == "AttackChain" and props == "chain_id: $chain_id":
                    continue
                self.assertIn("user_id:", props, f"{label} {{{props}}}")
                self.assertIn("project_id:", props, f"{label} {{{props}}}")
        self.assertGreaterEqual(patterns, 20, "the scan must see the writes it guards")
        self.assertEqual(WRITER_SRC.count("MATCH (ac:AttackChain {chain_id: $chain_id})"), 1, "the probe only")


class NewStepIdsAreFullLength(unittest.TestCase):
    def test_an_execution_step_gets_a_full_uuid(self):
        step = ExecutionStep(iteration=1, phase="informational", thought="t", reasoning="r")
        self.assertGreaterEqual(len(step.step_id.replace("-", "")), 32)

    def test_no_node_cuts_a_step_id_short(self):
        offenders = [f"{p.name}:{n}" for p in sorted(NODES.glob("*.py"))
                     for n, line in enumerate(p.read_text().splitlines(), 1)
                     if re.search(r"step_id\W.*uuid4\(\)[^\n]*\[:\d+\]", line)]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Phase 0 security hotfixes for the triage and codefix agents.

Each test names a hole the review found, not an implementation detail:

- the triage `query_graph` tool ran LLM-written Cypher in a WRITE session with
  no tenant filter at all, despite a docstring claiming otherwise;
- two static collection queries walked through the shared CVE node into other
  tenants' ExploitGvm and Technology rows;
- the codefix filesystem tools joined `repo_path / file_path` with no
  containment, so `../` reached the agent container's own secrets;
- the fix repository came from LLM-written remediation text;
- a codefix session accepted any remediation id, including another project's;
- an unanswered approval prompt auto-ACCEPTED the change after 300 s;
- provider exceptions (which carry keys) were sent to the browser and logged
  with their traceback unredacted;
- the rationale batch was the first N rows in query order, not the top N.

Run: ./agentic/run_tests.sh tests/test_triage_security_hardening.py
"""

import asyncio
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db.tenant_filter import TenantScopeError  # noqa: E402

from cypherfix_codefix.state import CodeFixState  # noqa: E402
from cypherfix_codefix.tools.edit_tool import github_edit  # noqa: E402
from cypherfix_codefix.tools.glob_tool import github_glob  # noqa: E402
from cypherfix_codefix.tools.list_dir_tool import github_list_dir  # noqa: E402
from cypherfix_codefix.tools.read_tool import github_read  # noqa: E402
from cypherfix_codefix.tools.repo_paths import (  # noqa: E402
    RepoPathError,
    resolve_in_repo,
)
from cypherfix_codefix.tools.write_tool import github_write  # noqa: E402
from cypherfix_errors import safe_error  # noqa: E402
from cypherfix_triage.prompts.cypher_queries import (  # noqa: E402
    SCORING_QUERIES,
    TRIAGE_QUERIES,
)
from cypherfix_triage.tools import TriageNeo4jToolManager  # noqa: E402


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# S1: the triage query_graph tool
# ---------------------------------------------------------------------------
class _RecordingManager(TriageNeo4jToolManager):
    """Captures what would have reached Neo4j instead of connecting."""

    def __init__(self):
        super().__init__("u1", "p1")
        self.executed = []

    async def _execute(self, cypher, params):
        self.executed.append((cypher, params))
        return []


class TestTriageQueryGraphIsScoped(unittest.TestCase):
    def setUp(self):
        self.mgr = _RecordingManager()

    def test_write_clause_is_refused(self):
        with self.assertRaises(TenantScopeError):
            run(self.mgr.run_query("MATCH (v:Vulnerability) DETACH DELETE v"))
        self.assertEqual(self.mgr.executed, [])

    def test_apoc_write_procedure_is_refused(self):
        with self.assertRaises(TenantScopeError):
            run(self.mgr.run_query(
                "CALL apoc.create.node(['X'], {a: 1}) YIELD node RETURN node"))
        self.assertEqual(self.mgr.executed, [])

    def test_unlabelled_match_is_tenant_scoped_not_run_bare(self):
        """The old code ran this verbatim and returned the whole database.
        `scope_query` scopes an unlabelled pattern rather than refusing it."""
        run(self.mgr.run_query("MATCH (n) RETURN n LIMIT 5"))
        cypher, _ = self.mgr.executed[0]
        self.assertIn("$tenant_user_id", cypher)
        self.assertIn("$tenant_project_id", cypher)

    def test_naming_the_muted_label_is_refused(self):
        with self.assertRaises(TenantScopeError):
            run(self.mgr.run_query(
                "MATCH (v:Vulnerability) WHERE v:Muted RETURN v.id"))
        self.assertEqual(self.mgr.executed, [])

    def test_a_legal_read_is_tenant_filtered_before_it_runs(self):
        run(self.mgr.run_query("MATCH (v:Vulnerability) RETURN v.id"))
        self.assertEqual(len(self.mgr.executed), 1)
        cypher, params = self.mgr.executed[0]
        self.assertNotEqual(cypher, "MATCH (v:Vulnerability) RETURN v.id")
        self.assertIn("tenant_user_id", cypher)
        self.assertEqual(params["tenant_user_id"], "u1")
        self.assertEqual(params["tenant_project_id"], "p1")

    def test_static_queries_do_not_go_through_the_tool_path(self):
        """An unlabelled static query still runs: it is repo-authored, and the
        label requirement exists only for what the model writes."""
        run(self.mgr.run_static_query("MATCH (n) RETURN n"))
        self.assertEqual(len(self.mgr.executed), 1)
        cypher, params = self.mgr.executed[0]
        self.assertEqual(cypher, "MATCH (n) RETURN n")
        self.assertEqual(params, {"userId": "u1", "projectId": "p1"})


# ---------------------------------------------------------------------------
# S4: the two cross-tenant collection queries
# ---------------------------------------------------------------------------
class TestCollectionQueriesStayInTenant(unittest.TestCase):
    """Every per-project label must carry the tenant keys in its own pattern.

    CVE / MitreData / Capec are shared reference nodes, so a traversal through
    one leaves the project unless the node on the far side is anchored.
    """

    #: Reference nodes shared by every project; they carry no tenant keys.
    GLOBAL_LABELS = ("CVE", "MitreData", "Capec")

    PER_PROJECT_LABELS = (
        "Vulnerability", "ExploitGvm", "Technology", "Secret", "JsReconFinding",
        "GithubSecret", "GithubSensitiveFile", "MultiscannerFinding",
        "MalPackageFinding", "ChainFinding", "ChainStep", "AttackChain",
        "Certificate", "Domain", "GithubHunt", "Package",
    )

    @staticmethod
    def _clauses(query):
        """MATCH / OPTIONAL MATCH clauses, continuation lines folded in."""
        clauses, current = [], None
        for line in query.splitlines():
            stripped = line.strip()
            if stripped.startswith(("MATCH", "OPTIONAL MATCH")):
                if current:
                    clauses.append(current)
                current = stripped
            elif current is not None:
                if stripped.startswith(("RETURN", "WITH", "UNWIND", "CALL")):
                    clauses.append(current)
                    current = None
                else:
                    current += " " + stripped
        if current:
            clauses.append(current)
        return clauses

    def _leaks(self, query):
        """Per-project patterns reached THROUGH a shared reference node.

        Traversing a relationship from an already-anchored node stays inside the
        project, because relationships never cross one. A global CVE node is the
        exception: it belongs to everybody, so anything matched on the far side
        of it needs its own tenant keys or the traversal walks into another
        tenant's data. That is exactly how S4 read other projects' ExploitGvm
        counts and Technology names.
        """
        import re
        global_vars = {
            m.group(1)
            for m in re.finditer(
                r"\(\s*(\w+)\s*:\s*(?:%s)\b" % "|".join(self.GLOBAL_LABELS), query)
        }
        bad = []
        for clause in self._clauses(query):
            touches_global = any(
                re.search(r"\(\s*%s\s*[:)]" % re.escape(var), clause)
                for var in global_vars
            ) or any(f":{label}" in clause for label in self.GLOBAL_LABELS)
            if not touches_global:
                continue
            for match in re.finditer(r"\(\s*\w*\s*:\s*(\w+)([^)]*)\)", clause):
                if match.group(1) not in self.PER_PROJECT_LABELS:
                    continue
                if "$userId" not in match.group(2):
                    bad.append(f"{match.group(0)} in: {clause}")
        return bad

    def test_no_static_query_reads_another_tenant_through_a_cve(self):
        for query_def in list(TRIAGE_QUERIES) + list(SCORING_QUERIES):
            with self.subTest(query=query_def["name"]):
                self.assertEqual(self._leaks(query_def["query"]), [])

    def test_cve_chains_anchors_exploitgvm(self):
        query = next(q for q in TRIAGE_QUERIES if q["name"] == "cve_chains")["query"]
        self.assertIn("ExploitGvm {user_id: $userId, project_id: $projectId}", query)

    def test_exploits_anchors_technology(self):
        query = next(q for q in TRIAGE_QUERIES if q["name"] == "exploits")["query"]
        self.assertIn("Technology {user_id: $userId, project_id: $projectId}", query)


# ---------------------------------------------------------------------------
# S5: codefix path confinement
# ---------------------------------------------------------------------------
class _FsBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = Path(self.tmp) / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
        self.outside = Path(self.tmp) / "secret.txt"
        self.outside.write_text("NEO4J_PASSWORD=hunter2\n", encoding="utf-8")
        self.state = CodeFixState()
        self.state.repo_path = self.repo

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestPathConfinement(_FsBase):
    def test_resolve_accepts_a_path_inside_the_repo(self):
        self.assertEqual(
            resolve_in_repo(self.repo, "src/app.py"),
            (self.repo / "src" / "app.py").resolve(),
        )

    def test_resolve_refuses_parent_traversal(self):
        with self.assertRaises(RepoPathError):
            resolve_in_repo(self.repo, "../secret.txt")

    def test_resolve_refuses_an_absolute_path(self):
        with self.assertRaises(RepoPathError):
            resolve_in_repo(self.repo, str(self.outside))

    def test_resolve_refuses_a_symlink_pointing_out(self):
        link = self.repo / "escape"
        try:
            link.symlink_to(self.outside)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(RepoPathError):
            resolve_in_repo(self.repo, "escape")

    def test_read_refuses_to_leave_the_repo(self):
        out = run(github_read(self.state, "../secret.txt"))
        self.assertIn("refused", out)
        self.assertNotIn("hunter2", out)

    def test_write_refuses_to_leave_the_repo(self):
        out = run(github_write(self.state, "../../pwned.txt", "x"))
        self.assertIn("refused", out)
        self.assertFalse((Path(self.tmp).parent / "pwned.txt").exists())

    def test_edit_refuses_to_leave_the_repo(self):
        self.state.files_read.add("../secret.txt")
        out = run(github_edit(self.state, "../secret.txt", "hunter2", "x"))
        self.assertIn("refused", out)
        self.assertIn("hunter2", self.outside.read_text())

    def test_glob_refuses_to_leave_the_repo(self):
        out = run(github_glob(self.state, "*.txt", path=".."))
        self.assertIn("refused", out)

    def test_list_dir_refuses_to_leave_the_repo(self):
        out = run(github_list_dir(self.state, ".."))
        self.assertIn("refused", out)

    def test_an_absolute_path_does_not_silently_replace_the_repo_root(self):
        out = run(github_read(self.state, str(self.outside)))
        self.assertIn("relative", out)


# ---------------------------------------------------------------------------
# S5: a rejected diff block must not survive on disk
# ---------------------------------------------------------------------------
class TestRejectedBlockIsReverted(_FsBase):
    def setUp(self):
        super().setUp()
        self.state.settings.require_approval = True
        self.state.streaming_callback = AsyncMock()

    def _orchestrator(self):
        from cypherfix_codefix.orchestrator import CodeFixOrchestrator
        orch = CodeFixOrchestrator.__new__(CodeFixOrchestrator)
        orch.state = self.state
        return orch

    def test_reverting_restores_the_file_and_drops_it_from_the_commit(self):
        run(github_read(self.state, "src/app.py"))
        run(github_edit(self.state, "src/app.py", "print('hi')", "os.system('x')"))
        self.assertIn("src/app.py", self.state.files_modified)

        self._orchestrator()._revert_block(self.state.pending_block_id)

        self.assertEqual(
            (self.repo / "src" / "app.py").read_text(), "print('hi')\n")
        self.assertNotIn("src/app.py", self.state.files_modified)
        self.assertEqual(self.state.diff_blocks[0].status, "rejected")


class TestApprovalTimeoutRejects(unittest.TestCase):
    def test_an_unanswered_prompt_rejects_instead_of_accepting(self):
        from cypherfix_codefix.orchestrator import CodeFixOrchestrator
        orch = CodeFixOrchestrator.__new__(CodeFixOrchestrator)
        orch.approval_future = None
        decision = run(orch._await_block_approval(timeout=0.01))
        self.assertEqual(decision["decision"], "reject")


# ---------------------------------------------------------------------------
# S7: no provider text on the socket, no secrets in the traceback
# ---------------------------------------------------------------------------
class TestErrorsAreCodes(unittest.TestCase):
    def test_every_code_has_a_fixed_sentence(self):
        for code in ("llm_error", "save_failed", "internal_error"):
            self.assertTrue(safe_error(code))

    def test_an_unknown_code_still_says_something_safe(self):
        message = safe_error("no_such_code")
        self.assertTrue(message)
        self.assertNotIn("no_such_code", message)

    def test_the_message_never_carries_the_exception(self):
        self.assertNotIn("Traceback", safe_error("llm_error"))


class TestLogRedaction(unittest.TestCase):
    def _format(self, record):
        from logging_config import RedactingFilter
        RedactingFilter().filter(record)
        return logging.Formatter("%(message)s").format(record)

    def test_a_key_in_the_message_is_redacted(self):
        record = logging.LogRecord(
            "t", logging.ERROR, __file__, 1,
            "auth failed for tvly-abcdefghijklmnopqrstuvwx", None, None)
        self.assertNotIn("tvly-abcdefghij", self._format(record))

    def test_a_google_key_is_redacted(self):
        record = logging.LogRecord(
            "t", logging.ERROR, __file__, 1,
            "key=AIzaSyA1234567890abcdefghijklmnopqrstu", None, None)
        self.assertNotIn("AIzaSyA1234567890", self._format(record))

    def test_an_xai_key_is_redacted(self):
        record = logging.LogRecord(
            "t", logging.ERROR, __file__, 1,
            "xai-abcdefghijklmnopqrstuvwxyz01", None, None)
        self.assertNotIn("xai-abcdefghij", self._format(record))

    def test_a_key_inside_the_traceback_is_redacted(self):
        """The provider puts the key in the exception it raises, and
        logger.exception() writes that through exc_info, not the message."""
        try:
            raise ValueError("bad key tvly-abcdefghijklmnopqrstuvwx")
        except ValueError:
            record = logging.LogRecord(
                "t", logging.ERROR, __file__, 1, "call failed", None,
                sys.exc_info())
        text = self._format(record)
        self.assertIn("Traceback", text)
        self.assertNotIn("tvly-abcdefghij", text)


# ---------------------------------------------------------------------------
# L5: the LLM batch is the top N by score
# ---------------------------------------------------------------------------
class TestFindingsAreOrderedByScore(unittest.TestCase):
    """L5 was: the LLM batch was the first N rows in Neo4j's return order,
    because the caller discarded what the sort returned. Step A now sorts in
    place, and the review takes its budget off the front of that list."""

    def test_step_a_returns_findings_worst_first(self):
        import inspect
        from cypherfix_triage.orchestrator import TriageOrchestrator
        source = inspect.getsource(TriageOrchestrator._score)
        self.assertIn("scored.sort(", source)
        self.assertIn('-r["score"]', source)

    def test_the_review_budget_takes_the_highest_scoring_findings(self):
        import inspect
        from cypherfix_triage.orchestrator import TriageOrchestrator
        source = inspect.getsource(TriageOrchestrator._review)
        self.assertIn("candidates.sort(", source)
        self.assertIn("candidates[:budget]", source)


if __name__ == "__main__":
    unittest.main()

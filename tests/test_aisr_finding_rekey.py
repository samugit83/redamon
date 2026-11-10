"""tooling/scripts/aisr_finding_rekey.py (recon audit L-9).

AI Surface MCP YARA findings were keyed without their rule, so several rules on
one server's instructions (or one tool) were one node; they are now one per
rule. The script moves an old node to the id of the rule its stored name gives,
with the mute, the Priority Board layers (a person's DECISION included), the
agent's CONFIRMS proof edges, the un-mute exemptions, the fix items and the
captured transactions. Fake Neo4j and Postgres sessions.
"""
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tooling.scripts import aisr_finding_rekey as rk  # noqa: E402

UID, PID = "u-aisr", "p-aisr"
BASE = "http://mcp.example.com:8080"
PATHS = ["/mcp", "/sse", "/"]


def _old(ftype, tool, base=BASE, path="/mcp"):
    return "aisr_" + hashlib.sha256(f"{ftype}|{base}|{path}|{tool}".encode()).hexdigest()[:16]


def _new(ftype, tool, rule, base=BASE, path="/mcp"):
    return "aisr_" + hashlib.sha256(
        f"{ftype}|{base}|{path}|{tool}|{rule}".encode()).hexdigest()[:16]


SERVER_OLD = _old("mcp_prompt_injection", None)
SERVER_NEW = _new("mcp_prompt_injection", None, "mcp_imperative_override")
ENDPOINT = {"baseurl": BASE, "path": "/mcp"}


class FakeSession:
    def __init__(self, old=(), nodes=None):
        self.old = list(old)
        self.nodes = nodes or {}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if query is rk.OLD_FINDINGS:
            return list(self.old)
        if query is rk.READ_PAIR:
            return [{"id": i, **self.nodes[i]} for i in (params["old"], params["new"])
                    if i in self.nodes]
        return []

    def writes(self):
        return [(q, p) for q, p in self.calls if q not in (rk.OLD_FINDINGS, rk.READ_PAIR)]


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = [("id",), ("user_id",)]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.log.append(("sql", " ".join(sql.split()), params))

    def fetchall(self):
        return self.conn.rows


class FakeConn:
    def __init__(self, rows=((PID, UID),)):
        self.rows = list(rows)
        self.log = []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.log.append(("commit",))


def _row(fid, name, ftype="mcp_prompt_injection", parents=(ENDPOINT,)):
    return {"id": fid, "type": ftype, "name": name, "parents": list(parents)}


SERVER_ROW = _row(SERVER_OLD, "MCP server instructions: mcp_imperative_override")
PROJECT = {"id": PID, "user_id": UID}

DECIDED = {"id": SERVER_OLD, "source": "ai_surface_recon", "user_id": UID, "project_id": PID,
           "name": "MCP server instructions: mcp_imperative_override",
           "triage_status": "likely_noise", "triage_source": "human",
           "muted_at": "2026-10-01T00:00:00Z", "muted_by": "user-1",
           "updated_at": "2026-10-01T00:00:00Z"}


def _plan(*rows):
    return rk.plan_project(FakeSession(rows), PROJECT, PATHS)


class TestPlan(unittest.TestCase):
    def test_a_server_instruction_finding_moves_to_its_stored_rule(self):
        plan = _plan(SERVER_ROW)
        self.assertEqual(plan["rekeys"], [{
            "old_id": SERVER_OLD, "new_id": SERVER_NEW, "type": "mcp_prompt_injection",
            "tool": None, "rule": "mcp_imperative_override"}])
        self.assertEqual(plan["unmapped"], [])

    def test_a_tool_finding_keeps_a_tool_name_that_looks_like_the_separator(self):
        tool = "odd': name"
        fid = _old("mcp_tool_poisoning", tool)
        plan = _plan(_row(fid, f"MCP tool '{tool}': mcp_hidden_instructions",
                          ftype="mcp_tool_poisoning"))
        (r,) = plan["rekeys"]
        self.assertEqual((r["tool"], r["rule"]), (tool, "mcp_hidden_instructions"))
        self.assertEqual(r["new_id"], _new("mcp_tool_poisoning", tool, "mcp_hidden_instructions"))

    def test_a_baseurl_parent_is_tried_on_every_mcp_probe_path(self):
        fid = _old("mcp_prompt_injection", None, path="/sse")
        plan = _plan(_row(fid, "MCP server instructions: mcp_exfiltration_hint",
                          parents=[{"baseurl": BASE, "path": None}]))
        self.assertEqual(plan["rekeys"][0]["new_id"],
                         _new("mcp_prompt_injection", None, "mcp_exfiltration_hint", path="/sse"))

    def test_a_node_already_on_the_new_key_is_not_listed(self):
        plan = _plan(_row(SERVER_NEW, "MCP server instructions: mcp_imperative_override"))
        self.assertEqual(plan, {"rekeys": [], "unmapped": []})

    def test_an_id_no_parent_explains_is_left_alone(self):
        plan = _plan(_row(SERVER_OLD, "MCP server instructions: mcp_imperative_override",
                          parents=[{"baseurl": "http://other.example.com", "path": "/mcp"}]))
        self.assertEqual(plan["rekeys"], [])
        self.assertEqual([u["old_id"] for u in plan["unmapped"]], [SERVER_OLD])

    def test_a_name_with_no_rule_is_left_alone(self):
        plan = _plan(_row(SERVER_OLD, "MCP server instructions: <script>"))
        self.assertEqual([u["reason"] for u in plan["unmapped"]], ["its name names no rule"])

    def test_only_yara_kinds_of_this_source_are_read(self):
        session = FakeSession([])
        rk.plan_project(session, PROJECT, PATHS)
        (_, params), = session.calls
        self.assertNotIn("mcp_annotation_mismatch", params["types"])
        self.assertIn("mcp_prompt_injection", params["types"])
        self.assertIn("v.source = 'ai_surface_recon'", rk.OLD_FINDINGS)

    def test_every_query_is_scoped_to_one_project_and_leaves_updated_at_alone(self):
        for name in ("OLD_FINDINGS", "READ_PAIR", "RENAME", "MERGE_ONTO_NEW", "COPY_PROOF",
                     "DELETE_OLD"):
            query = getattr(rk, name)
            with self.subTest(query=name):
                self.assertIn("$pid", query)
                self.assertNotIn("updated_at", query)
                self.assertNotIn("triage_score", query)


class TestRekeyGraph(unittest.TestCase):
    REKEY = {"old_id": SERVER_OLD, "new_id": SERVER_NEW, "type": "mcp_prompt_injection",
             "tool": None, "rule": "mcp_imperative_override"}

    def test_no_new_node_yet_renames_in_place(self):
        s = FakeSession(nodes={SERVER_OLD: {"muted": True, "props": dict(DECIDED)}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, self.REKEY), "renamed")
        (query, params), = s.writes()
        self.assertIs(query, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["pid"]), (SERVER_OLD, SERVER_NEW, PID))

    def test_after_a_scan_the_mute_the_decision_and_the_proof_move_onto_the_new_node(self):
        s = FakeSession(nodes={
            SERVER_OLD: {"muted": True, "props": dict(DECIDED)},
            SERVER_NEW: {"muted": False, "props": {"triage_ai_verdict": "real",
                                                   "triage_base_tier": "T3"}},
        })
        self.assertEqual(rk.rekey_graph(s, UID, PID, self.REKEY), "merged")
        writes = s.writes()
        merge_query, merge = writes[0]
        self.assertTrue(merge_query.startswith(rk.MERGE_ONTO_NEW.split("{remove}")[0]))
        self.assertEqual(merge["carried"]["triage_status"], "likely_noise")
        self.assertEqual(merge["carried"]["muted_by"], "user-1")
        self.assertNotIn("updated_at", merge["carried"])
        self.assertTrue(merge["mute"])
        self.assertIn("keep.triage_ai_verdict", merge_query.split("REMOVE", 1)[1].split("\n", 1)[0])
        self.assertEqual([q for q, _ in writes][1:], [rk.COPY_PROOF, rk.DELETE_OLD])

    def test_an_old_node_already_gone_is_nothing(self):
        s = FakeSession(nodes={})
        self.assertEqual(rk.rekey_graph(s, UID, PID, self.REKEY), "gone")
        self.assertEqual(s.writes(), [])


class TestRekeyPostgres(unittest.TestCase):
    def test_every_row_naming_the_old_id_follows_it(self):
        conn = FakeConn()
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, {"old_id": SERVER_OLD, "new_id": SERVER_NEW})
        sql = [(q, p) for kind, q, p in conn.log if kind == "sql"]
        tables = [q.split()[1] if q.startswith("UPDATE") else q.split()[2] for q, _ in sql]
        self.assertEqual(tables, ["node_filter_exemptions", "node_filter_exemptions",
                                  "remediations", "captured_http_transactions"])
        for query, params in sql:
            self.assertIn("project_id = %(pid)s", query)
            self.assertEqual((params["pid"], params["old"], params["new"]),
                             (PID, SERVER_OLD, SERVER_NEW))
            self.assertEqual(params["label"], "Vulnerability")


class TestRun(unittest.TestCase):
    def test_a_dry_run_changes_nothing_and_says_what_it_would_do(self):
        s = FakeSession([SERVER_ROW], nodes={SERVER_OLD: {"muted": True, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), None, apply=False, probe_paths=PATHS,
                         out=lines.append)
        self.assertEqual(s.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [])
        self.assertEqual(len([e for e in conn.log if e[0] == "sql"]), 1, "only the project list")
        text = "\n".join(lines)
        self.assertIn(f"{SERVER_OLD} -> {SERVER_NEW} (dry run)", text)
        self.assertIn(f"{PID}: 1 to re-key (1 on server instructions, 0 on tools), 0 left alone",
                      text)
        self.assertEqual(summary[PID]["outcomes"], [])

    def test_apply_writes_postgres_first_then_the_graph(self):
        s = FakeSession([SERVER_ROW], nodes={SERVER_OLD: {"muted": False, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), PID, apply=True, probe_paths=PATHS,
                         out=lines.append)
        self.assertIn(("commit",), conn.log)
        commit_at = conn.log.index(("commit",))
        self.assertTrue(any(e[0] == "sql" and "remediations" in e[1]
                            for e in conn.log[:commit_at]))
        self.assertEqual(summary[PID]["outcomes"], ["renamed"])
        self.assertIn("done: 1 renamed", "\n".join(lines))

    def test_a_tool_name_is_never_echoed_raw(self):
        tool = "evil\x1b[2Jtool"
        fid = _old("mcp_tool_poisoning", tool)
        s = FakeSession([_row(fid, f"MCP tool '{tool}': mcp_hidden_instructions",
                              ftype="mcp_tool_poisoning")])
        lines = []
        rk.run(FakeConn(), FakeDriver(s), None, apply=False, probe_paths=PATHS, out=lines.append)
        self.assertNotIn("\x1b", "\n".join(lines))

    def test_nothing_left_is_nothing_to_do(self):
        lines = []
        self.assertEqual(rk.run(FakeConn(), FakeDriver(FakeSession([])), None, apply=True,
                                probe_paths=PATHS, out=lines.append), {})
        self.assertIn("re-keyed 0 finding(s) in 0 project(s)", lines[-1])

    def test_a_blank_project_id_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn(), FakeDriver(FakeSession()), " ", apply=False, probe_paths=PATHS)


class TestMain(unittest.TestCase):
    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["webapp"]), \
                patch.object(rk, "_connect", side_effect=AssertionError("must not connect")):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)


if __name__ == "__main__":
    unittest.main()

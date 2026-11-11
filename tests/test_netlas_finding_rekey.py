"""tooling/scripts/netlas_finding_rekey.py (plan 04.5).

Netlas CVEs were keyed on the bare CVE id, one node per CVE per project, under
the Service they were seen on; they are now one per CVE, IP and port. The
script carries the mute, the Priority Board layers (a person's DECISION
included), the agent's CONFIRMS proof edges, the un-mute exemptions, the fix
items and the captured transactions over to the new id(s). Fake Neo4j and
Postgres sessions; addresses are RFC 5737.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tooling.scripts import netlas_finding_rekey as rk  # noqa: E402

UID, PID = "u-netlas", "p-netlas"
CVE = "CVE-2018-15473"
A, B = "198.51.100.70", "198.51.100.71"


def new_id(ip, port=22):
    return f"netlas-{CVE}-{ip}-{port}"


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
        if query is rk.READ_NODES:
            return [{"id": i, **self.nodes[i]} for i in params["ids"] if i in self.nodes]
        return []

    def writes(self):
        return [(q, p) for q, p in self.calls if q not in (rk.OLD_FINDINGS, rk.READ_NODES)]


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


def _old_row(*targets):
    return {"id": CVE, "targets": [{"ip": ip, "port": port} for ip, port in targets]}


def _rekey(*ips):
    return {"old_id": CVE, "cve": CVE, "targets": [
        {"ip": ip, "port": 22, "new_id": new_id(ip)} for ip in ips]}


DECIDED = {"id": CVE, "source": "netlas", "name": CVE, "user_id": UID, "project_id": PID,
           "triage_status": "likely_noise", "triage_source": "human",
           "muted_at": "2026-10-01T00:00:00Z", "muted_by": "user-1",
           "updated_at": "2026-10-01T00:00:00Z"}


class TestPlan(unittest.TestCase):
    def test_one_service_is_one_new_id(self):
        plan = rk.plan_project(FakeSession([_old_row((A, 22))]), {"id": PID, "user_id": UID})
        self.assertEqual(plan["rekeys"], [_rekey(A)])
        self.assertEqual(plan["unmapped"], [])

    def test_several_services_are_one_new_id_each(self):
        plan = rk.plan_project(FakeSession([_old_row((B, 22), (A, 22), (A, 22))]),
                               {"id": PID, "user_id": UID})
        self.assertEqual([t["new_id"] for t in plan["rekeys"][0]["targets"]],
                         [new_id(A), new_id(B)])

    def test_no_service_parent_is_unattributable(self):
        plan = rk.plan_project(FakeSession([_old_row()]), {"id": PID, "user_id": UID})
        self.assertEqual((plan["rekeys"], plan["unmapped"]), ([], [{"old_id": CVE, "kept": False}]))

    def test_the_new_id_is_the_writers(self):
        from graph_db.mixins.osint_mixin import netlas_vuln_id
        self.assertEqual(netlas_vuln_id(CVE, A, 22), new_id(A))

    def test_every_query_is_scoped_to_one_project(self):
        for name in ("OLD_FINDINGS", "READ_NODES", "RENAME", "CREATE_COPY", "MERGE_ONTO_NEW",
                     "COPY_PROOF", "DELETE_OLD", "DELETE_UNATTRIBUTABLE"):
            query = getattr(rk, name)
            with self.subTest(query=name):
                self.assertIn("$pid", query)
                self.assertNotIn("updated_at", query)
        self.assertIn("v.source = 'netlas'", rk.OLD_FINDINGS)


class TestRekeyGraph(unittest.TestCase):
    def test_one_ip_renames_in_place(self):
        s = FakeSession(nodes={CVE: {"muted": True, "props": dict(DECIDED)}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, _rekey(A)), "renamed")
        (query, params), = s.writes()
        self.assertIs(query, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["ip"], params["port"]),
                         (CVE, new_id(A), A, 22))

    def test_several_ips_copy_the_mute_the_decision_and_the_proof_to_each(self):
        s = FakeSession(nodes={CVE: {"muted": True, "props": dict(DECIDED)}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, _rekey(A, B)), "split")
        writes = s.writes()
        copies = [p for q, p in writes if q is rk.CREATE_COPY]
        self.assertEqual([p["props"]["id"] for p in copies], [new_id(A), new_id(B)])
        for params, ip in zip(copies, (A, B)):
            self.assertTrue(params["muted"])
            props = params["props"]
            self.assertEqual((props["triage_status"], props["triage_source"], props["muted_by"]),
                             ("likely_noise", "human", "user-1"))
            self.assertEqual((props["target_ip"], props["target_port"]), (ip, 22))
            self.assertEqual(props["updated_at"], DECIDED["updated_at"], "updated_at is never moved")
        self.assertEqual([p["new"] for q, p in writes if q is rk.COPY_PROOF], [new_id(A), new_id(B)])
        self.assertEqual([q for q, _ in writes][-1], rk.DELETE_OLD)

    def test_after_a_scan_the_block_moves_onto_the_new_node(self):
        s = FakeSession(nodes={
            CVE: {"muted": True, "props": dict(DECIDED)},
            new_id(A): {"muted": False, "props": {"triage_ai_verdict": "real",
                                                  "triage_base_tier": "T3"}},
        })
        self.assertEqual(rk.rekey_graph(s, UID, PID, _rekey(A)), "merged")
        writes = s.writes()
        merge_query, merge = next((q, p) for q, p in writes if q.startswith(
            rk.MERGE_ONTO_NEW.split("{remove}")[0]))
        self.assertEqual(merge["carried"]["triage_status"], "likely_noise")
        self.assertEqual(merge["carried"]["muted_by"], "user-1")
        self.assertTrue(merge["mute"])
        removed = merge_query.split("REMOVE", 1)[1].split("\n", 1)[0]
        self.assertIn("keep.triage_ai_verdict", removed)
        self.assertIn(rk.COPY_PROOF, [q for q, _ in writes])
        self.assertEqual([q for q, _ in writes][-1], rk.DELETE_OLD)
        self.assertNotIn(rk.CREATE_COPY, [q for q, _ in writes])

    def test_an_old_node_already_gone_is_nothing(self):
        s = FakeSession(nodes={})
        self.assertEqual(rk.rekey_graph(s, UID, PID, _rekey(A)), "gone")
        self.assertEqual(s.writes(), [])


class TestRekeyPostgres(unittest.TestCase):
    def test_every_row_naming_the_old_id_follows_it(self):
        conn = FakeConn()
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, _rekey(A, B))
        sql = [entry for entry in conn.log if entry[0] == "sql"]
        inserts = [p for _, q, p in sql if q.startswith("INSERT INTO node_filter_exemptions")]
        self.assertEqual([p["new"] for p in inserts], [new_id(A), new_id(B)])
        self.assertEqual(len({p["row_id"] for p in inserts}), 2)
        deletes = [q for _, q, _ in sql if q.startswith("DELETE FROM node_filter_exemptions")]
        self.assertEqual(len(deletes), 1)
        remediation = next(p for _, q, p in sql if q.startswith("UPDATE remediations"))
        self.assertEqual((remediation["old"], remediation["new_ids"]), (CVE, [new_id(A), new_id(B)]))
        captured_q, captured = next((q, p) for _, q, p in sql
                                    if q.startswith("UPDATE captured_http_transactions"))
        self.assertIn("m.ip IN (t.target_ip, t.host)", captured_q)
        self.assertIn(f'"ip": "{B}"', captured["targets"])
        for _, query, params in sql:
            self.assertIn("project_id = %(pid)s", query)
            self.assertEqual(params["pid"], PID)


class TestRun(unittest.TestCase):
    def test_a_dry_run_changes_nothing(self):
        s = FakeSession([_old_row((A, 22), (B, 22))],
                        nodes={CVE: {"muted": True, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), None, apply=False, out=lines.append)
        self.assertEqual(s.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [])
        self.assertEqual(len([e for e in conn.log if e[0] == "sql"]), 1, "only the project list")
        self.assertIn("(dry run)", "\n".join(lines))
        self.assertIn(f"{PID}: 1 to re-key (0 on one IP, 1 on several), 0 unattributable", "\n".join(lines))
        self.assertEqual(summary[PID]["outcomes"], [])

    def test_apply_writes_postgres_first_then_the_graph(self):
        s = FakeSession([_old_row((A, 22))], nodes={CVE: {"muted": False, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), PID, apply=True, out=lines.append)
        self.assertIn(("commit",), conn.log)
        self.assertEqual(summary[PID]["outcomes"], ["renamed"])
        self.assertIn("done: 1 renamed", "\n".join(lines))

    def test_nothing_left_is_nothing_to_do(self):
        conn, lines = FakeConn(), []
        self.assertEqual(rk.run(conn, FakeDriver(FakeSession([])), None, apply=True,
                                out=lines.append), {})
        self.assertIn("re-keyed 0 finding(s) in 0 project(s)", lines[-1])

    def test_a_blank_project_id_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn(), FakeDriver(FakeSession()), " ", apply=False)


class PruningSession(FakeSession):
    """Answers the unattributable-row delete as the graph would: the ids in
    `kept` survive it (stamped stale), every other one is deleted."""

    def __init__(self, old=(), kept=()):
        super().__init__(old)
        self.kept = set(kept)

    def run(self, query, **params):
        result = super().run(query, **params)
        if "DETACH DELETE" in query and "ids" in params:
            ids = set(params["ids"])
            return [{"deleted": len(ids - self.kept), "kept": len(ids & self.kept)}]
        return result


def _unattributable(kept=False):
    return {"id": CVE, "targets": [], "kept": kept}


class TestUnattributable(unittest.TestCase):
    """A bare-id finding with no Service carrying an IP and port has nothing to
    re-key to, and names no IP, so since passive CVEs are pruned only on the IPs
    their lookup decided (5ec9ac12) no scan with Netlas on ever prunes it."""

    def _deletes(self, session):
        return [(q, p) for q, p in session.writes() if "DETACH DELETE" in q]

    def test_apply_deletes_one_nobody_touched(self):
        s = PruningSession([_unattributable()])
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), PID, apply=True, out=lines.append)
        (query, params), = self._deletes(s)
        self.assertEqual((params["uid"], params["pid"], params["ids"]), (UID, PID, [CVE]))
        self.assertEqual(summary[PID]["unattributable"], {"deleted": 1, "kept": 0})
        self.assertIn("done: 1 deleted", "\n".join(lines))
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [],
                         "a delete moves no Postgres row")

    def test_apply_keeps_what_a_person_or_the_agent_touched_stale(self):
        s = PruningSession([_unattributable(kept=True)], kept=[CVE])
        lines = []
        summary = rk.run(FakeConn(), FakeDriver(s), PID, apply=True, out=lines.append)
        self.assertEqual(summary[PID]["unattributable"], {"deleted": 0, "kept": 1})
        text = "\n".join(lines)
        self.assertIn("keep, stamped stale", text)
        self.assertIn("done: 1 kept stale", text)

    def test_a_dry_run_lists_them_and_deletes_nothing(self):
        s = PruningSession([_unattributable(), {**_unattributable(kept=True), "id": "CVE-2020-0001"}],
                           kept=["CVE-2020-0001"])
        lines = []
        summary = rk.run(FakeConn(), FakeDriver(s), None, apply=False, out=lines.append)
        self.assertEqual(s.writes(), [])
        text = "\n".join(lines)
        self.assertIn(f"{CVE} hangs off no Service with an IP and port", text)
        self.assertIn("-> delete (dry run)", text)
        self.assertIn("-> keep, stamped stale", text)
        self.assertNotIn("the next full scan prunes it", text)
        self.assertIn(f"{PID}: 0 to re-key (0 on one IP, 0 on several), 2 unattributable", text)
        self.assertNotIn("unattributable", summary[PID])

    def test_the_plan_reads_the_prunes_keep_rule(self):
        plan = rk.plan_project(FakeSession([_unattributable(kept=True)]), {"id": PID, "user_id": UID})
        self.assertEqual(plan["unmapped"], [{"old_id": CVE, "kept": True}])

    def test_the_delete_spares_what_the_scan_prune_spares(self):
        from graph_db.node_filters.guards import GUARD_KEEP_CHECK
        s = PruningSession([_unattributable()])
        rk.run(FakeConn(), FakeDriver(s), PID, apply=True, out=lambda _l: None)
        (query, _), = self._deletes(s)
        self.assertIn(GUARD_KEEP_CHECK, query)
        self.assertIn("n:Muted AND NOT coalesce(n.muted_by, '') STARTS WITH 'rule:'", query)
        self.assertLess(query.index("SET n._prune_lock = true"), query.index("n:Muted"),
                        "the write lock comes before the mute is read")
        self.assertIn("SET n.stale_since = coalesce(n.stale_since, datetime())", query)
        self.assertIn("user_id: $uid, project_id: $pid", query)
        self.assertIn("n.source = 'netlas'", query)
        self.assertIn("NOT EXISTS", query, "a row a Service now attributes is never deleted")
        self.assertNotIn("updated_at", query)
        self.assertIn(GUARD_KEEP_CHECK, rk.OLD_FINDINGS, "the dry run lists what --apply keeps")

    def test_the_docstring_no_longer_promises_a_prune(self):
        self.assertNotIn("the next full scan prunes it", rk.__doc__)


class TestMain(unittest.TestCase):
    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["webapp"]), \
                patch.object(rk, "_connect", side_effect=AssertionError("must not connect")):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)


if __name__ == "__main__":
    unittest.main()

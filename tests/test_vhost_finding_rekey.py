"""tooling/scripts/vhost_finding_rekey.py (recon audit R-46).

VHost/SNI finding ids folded every non-alphanumeric character to "_", so
dev-api.example.com and dev.api.example.com (or 2001:db8::a and 2001:db8::b)
were one node. They are now a hash of the exact hostname, IP, port and layer.
The script moves an old node to the id of the hostname and IP it stores, with
the mute, the Priority Board layers (a person's DECISION included), the agent's
CONFIRMS proof edges, the un-mute exemptions, the fix items and the captured
transactions, and drops the edge of the other collided name. Fake Neo4j and
Postgres sessions.
"""
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tooling.scripts import vhost_finding_rekey as rk  # noqa: E402

UID, PID = "u-vhost", "p-vhost"
IP = "192.0.2.10"


def _folded(hostname, ip, port, layer):
    return "vhost_sni_{h}_{i}_{p}_{l}".format(
        h=re.sub(r"[^a-z0-9]", "_", hostname.lower()), i=re.sub(r"[^0-9.]", "_", ip),
        p=port, l=layer.lower())


OLD = _folded("dev-api.example.com", IP, 443, "L7")
NEW = rk.new_finding_id("dev-api.example.com", IP, 443, "L7")
SIBLING_NEW = rk.new_finding_id("dev.api.example.com", IP, 443, "L7")


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


def _row(fid=OLD, hostname="dev-api.example.com", ip=IP, port=443, layer="L7", parents=None):
    if parents is None:
        parents = [{"kind": "name", "key": hostname}]
    return {"id": fid, "hostname": hostname, "ip": ip, "port": port, "layer": layer,
            "parents": parents}


#: The node both names wrote; dev-api.example.com wrote last, so it is the name
#: the node shows and the one a person judged.
COLLIDED_ROW = _row(parents=[{"kind": "name", "key": "dev-api.example.com"},
                             {"kind": "name", "key": "dev.api.example.com"},
                             {"kind": "ip", "key": IP}])
PROJECT = {"id": PID, "user_id": UID}

DECIDED = {"id": OLD, "source": "vhost_sni_enum", "user_id": UID, "project_id": PID,
           "hostname": "dev-api.example.com", "name": "Hidden Virtual Host: dev-api.example.com",
           "triage_status": "likely_noise", "triage_source": "human",
           "muted_at": "2026-10-01T00:00:00Z", "muted_by": "user-1",
           "updated_at": "2026-10-01T00:00:00Z"}


def _plan(*rows):
    return rk.plan_project(FakeSession(rows), PROJECT)


class TestIds(unittest.TestCase):
    def test_the_old_form_collided_and_the_new_one_does_not(self):
        self.assertEqual(rk.old_finding_id("dev-api.example.com", IP, 443, "L7"),
                         rk.old_finding_id("dev.api.example.com", IP, 443, "L7"))
        self.assertNotEqual(NEW, SIBLING_NEW)
        self.assertEqual(rk.old_finding_id("x.example.com", "2001:db8::a", 443, "L4"),
                         rk.old_finding_id("x.example.com", "2001:db8::b", 443, "L4"))
        self.assertNotEqual(rk.new_finding_id("x.example.com", "2001:db8::a", 443, "L4"),
                            rk.new_finding_id("x.example.com", "2001:db8::b", 443, "L4"))


class TestPlan(unittest.TestCase):
    def test_a_folded_id_moves_to_the_hash_of_what_the_node_stores(self):
        plan = _plan(_row())
        self.assertEqual(plan["rekeys"], [{
            "old_id": OLD, "new_id": NEW, "hostname": "dev-api.example.com", "ip": IP,
            "port": 443, "layer": "L7", "siblings": {"names": [], "addrs": []}}])
        self.assertEqual(plan["unmapped"], [])

    def test_a_collided_node_goes_to_its_stored_name_and_lists_the_other(self):
        (r,) = _plan(COLLIDED_ROW)["rekeys"]
        self.assertEqual(r["new_id"], NEW)
        self.assertNotEqual(r["new_id"], SIBLING_NEW)
        self.assertEqual(r["siblings"], {"names": ["dev.api.example.com"], "addrs": []})

    def test_a_collided_ipv6_address_is_listed_and_its_own_ip_is_not(self):
        row = _row(fid=_folded("x.example.com", "2001:db8::a", 443, "L4"),
                   hostname="x.example.com", ip="2001:db8::a", layer="L4",
                   parents=[{"kind": "ip", "key": "2001:db8::a"},
                            {"kind": "ip", "key": "2001:db8::b"},
                            {"kind": "ip", "key": "192.0.2.99"}])
        (r,) = _plan(row)["rekeys"]
        self.assertEqual(r["new_id"], rk.new_finding_id("x.example.com", "2001:db8::a", 443, "L4"))
        self.assertEqual(r["siblings"], {"names": [], "addrs": ["2001:db8::b"]})

    def test_an_unrelated_parent_is_never_a_sibling(self):
        row = _row(parents=[{"kind": "name", "key": "dev-api.example.com"},
                            {"kind": "name", "key": "example.com"},
                            {"kind": "name", "key": "other.example.com"}])
        (r,) = _plan(row)["rekeys"]
        self.assertEqual(r["siblings"], {"names": [], "addrs": []})

    def test_a_node_already_on_the_new_key_is_not_listed(self):
        self.assertEqual(_plan(_row(fid=NEW)), {"rekeys": [], "unmapped": []})

    def test_an_id_its_fields_do_not_explain_is_left_alone(self):
        plan = _plan(_row(fid=_folded("other.example.com", IP, 443, "L7")))
        self.assertEqual(plan["rekeys"], [])
        self.assertEqual([u["old_id"] for u in plan["unmapped"]],
                         [_folded("other.example.com", IP, 443, "L7")])

    def test_a_node_missing_a_field_is_left_alone(self):
        plan = _plan(_row(layer=None))
        self.assertEqual(plan["rekeys"], [])
        self.assertEqual(len(plan["unmapped"]), 1)

    def test_only_this_source_is_read(self):
        session = FakeSession([])
        rk.plan_project(session, PROJECT)
        (_, params), = session.calls
        self.assertEqual((params["uid"], params["pid"]), (UID, PID))
        self.assertIn("v.source = 'vhost_sni_enum'", rk.OLD_FINDINGS)

    def test_every_query_is_scoped_to_one_project_and_leaves_updated_at_alone(self):
        for name in ("OLD_FINDINGS", "READ_PAIR", "RENAME", "MERGE_ONTO_NEW", "COPY_PROOF",
                     "DELETE_OLD", "DROP_SIBLING_EDGES"):
            query = getattr(rk, name)
            with self.subTest(query=name):
                self.assertIn("$pid", query)
                self.assertIn("$uid", query)
                self.assertNotIn("updated_at", query)
                self.assertNotIn("triage_score", query)


class TestRekeyGraph(unittest.TestCase):
    def _rekey(self, siblings=None):
        return {"old_id": OLD, "new_id": NEW, "hostname": "dev-api.example.com", "ip": IP,
                "port": 443, "layer": "L7",
                "siblings": siblings or {"names": [], "addrs": []}}

    def test_no_new_node_yet_renames_in_place(self):
        s = FakeSession(nodes={OLD: {"muted": True, "props": dict(DECIDED)}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, self._rekey()), "renamed")
        (query, params), = s.writes()
        self.assertIs(query, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["pid"]), (OLD, NEW, PID))

    def test_a_rename_drops_the_edge_of_the_other_collided_name(self):
        s = FakeSession(nodes={OLD: {"muted": True, "props": dict(DECIDED)}})
        sib = {"names": ["dev.api.example.com"], "addrs": []}
        self.assertEqual(rk.rekey_graph(s, UID, PID, self._rekey(sib)), "renamed")
        (rename, _), (drop, params) = s.writes()
        self.assertIs(rename, rk.RENAME)
        self.assertIs(drop, rk.DROP_SIBLING_EDGES)
        self.assertEqual((params["new"], params["names"], params["addrs"]),
                         (NEW, ["dev.api.example.com"], []))

    def test_after_a_scan_the_mute_the_decision_and_the_proof_move_onto_the_new_node(self):
        s = FakeSession(nodes={
            OLD: {"muted": True, "props": dict(DECIDED)},
            NEW: {"muted": False, "props": {"triage_ai_verdict": "real",
                                            "triage_base_tier": "T3"}},
        })
        self.assertEqual(rk.rekey_graph(s, UID, PID, self._rekey(
            {"names": ["dev.api.example.com"], "addrs": []})), "merged")
        writes = s.writes()
        merge_query, merge = writes[0]
        self.assertTrue(merge_query.startswith(rk.MERGE_ONTO_NEW.split("{remove}")[0]))
        self.assertEqual(merge["carried"]["triage_status"], "likely_noise")
        self.assertEqual(merge["carried"]["muted_by"], "user-1")
        self.assertNotIn("updated_at", merge["carried"])
        self.assertTrue(merge["mute"])
        self.assertIn("keep.triage_ai_verdict", merge_query.split("REMOVE", 1)[1].split("\n", 1)[0])
        # The old node is deleted with its edges, the sibling's included.
        self.assertEqual([q for q, _ in writes][1:], [rk.COPY_PROOF, rk.DELETE_OLD])
        self.assertIn("DETACH DELETE", rk.DELETE_OLD)

    def test_an_old_node_already_gone_is_nothing(self):
        s = FakeSession(nodes={})
        self.assertEqual(rk.rekey_graph(s, UID, PID, self._rekey()), "gone")
        self.assertEqual(s.writes(), [])


class TestRekeyPostgres(unittest.TestCase):
    def test_every_row_naming_the_old_id_follows_it(self):
        conn = FakeConn()
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, {"old_id": OLD, "new_id": NEW})
        sql = [(q, p) for kind, q, p in conn.log if kind == "sql"]
        tables = [q.split()[1] if q.startswith("UPDATE") else q.split()[2] for q, _ in sql]
        self.assertEqual(tables, ["node_filter_exemptions", "node_filter_exemptions",
                                  "remediations", "captured_http_transactions"])
        for query, params in sql:
            self.assertIn("project_id = %(pid)s", query)
            self.assertEqual((params["pid"], params["old"], params["new"]), (PID, OLD, NEW))
            self.assertEqual(params["label"], "Vulnerability")


class TestRun(unittest.TestCase):
    def test_a_dry_run_changes_nothing_and_says_what_it_would_do(self):
        s = FakeSession([COLLIDED_ROW], nodes={OLD: {"muted": True, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), None, apply=False, out=lines.append)
        self.assertEqual(s.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [])
        self.assertEqual(len([e for e in conn.log if e[0] == "sql"]), 1, "only the project list")
        text = "\n".join(lines)
        self.assertIn(f"{OLD} -> {NEW} (dry run)", text)
        self.assertIn("also collided with dev.api.example.com", text)
        self.assertIn(f"{PID}: 1 to re-key (1 with a collided name or address), 0 left alone",
                      text)
        self.assertIn("would re-key 1 finding(s) in 1 project(s)", lines[-1])
        self.assertEqual(summary[PID]["outcomes"], [])

    def test_apply_writes_postgres_first_then_the_graph(self):
        s = FakeSession([_row()], nodes={OLD: {"muted": False, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), PID, apply=True, out=lines.append)
        self.assertIn(("commit",), conn.log)
        commit_at = conn.log.index(("commit",))
        self.assertTrue(any(e[0] == "sql" and "remediations" in e[1]
                            for e in conn.log[:commit_at]))
        self.assertEqual(summary[PID]["outcomes"], ["renamed"])
        self.assertIn("done: 1 renamed", "\n".join(lines))

    def test_a_second_run_finds_nothing(self):
        s = FakeSession([_row(fid=NEW)], nodes={NEW: {"muted": False, "props": {}}})
        conn, lines = FakeConn(), []
        self.assertEqual(rk.run(conn, FakeDriver(s), None, apply=True, out=lines.append), {})
        self.assertEqual(s.writes(), [])
        self.assertIn("re-keyed 0 finding(s) in 0 project(s)", lines[-1])

    def test_a_hostname_is_never_echoed_raw(self):
        host = "evil\x1b[2J.example.com"
        s = FakeSession([_row(fid=_folded(host, IP, 443, "L7"), hostname=host)])
        lines = []
        rk.run(FakeConn(), FakeDriver(s), None, apply=False, out=lines.append)
        self.assertNotIn("\x1b", "\n".join(lines))

    def test_a_blank_project_id_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn(), FakeDriver(FakeSession()), " ", apply=False)


class TestMain(unittest.TestCase):
    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["webapp"]), \
                patch.object(rk, "_connect", side_effect=AssertionError("must not connect")):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)

    def test_a_blank_project_is_refused_before_anything_runs(self):
        with patch.object(rk, "_connect", side_effect=AssertionError("must not connect")), \
                self.assertRaises(SystemExit):
            rk.main(["--project", " "])


if __name__ == "__main__":
    unittest.main()

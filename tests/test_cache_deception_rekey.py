"""tooling/scripts/cache_deception_rekey.py (recon-audit R-28).

The native web-cache-deception finding was keyed on its random plant URL, so
every run wrote a new node. The script moves each old node to the id keyed on
the page and the URL shape that leaked, collapses several old nodes for one id
into one, and carries the mute, the Priority Board layers (a person's DECISION
included), the CONFIRMS proof edges, the un-mute exemptions, the fix items and
the captured transactions with them. A fake, stateful Neo4j session and a fake
Postgres; hosts are reserved .test names.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from graph_db.mixins.cache_mixin import CacheMixin, cache_vuln_id  # noqa: E402
from tooling.scripts import cache_deception_rekey as rk  # noqa: E402

UID, PID = "u-wcd", "p-wcd"
PAGE = "https://shop.test/account"
PLANT_1 = f"{PAGE}/rdmn1a2b3c.css"
PLANT_2 = f"{PAGE}/rdmn4d5e6f.css"
PLANT_3 = f"{PAGE}/rdmn0a0b0c.css"


def old_id(plant, vector="static-suffix"):
    return cache_vuln_id(UID, PID, "cache_deception", plant, vector)


NEW_ID = cache_vuln_id(UID, PID, "cache_deception", PAGE, "static-suffix:/.css")


def old_node(plant, seen, muted=False, **props):
    return {"muted": muted, "props": {
        "id": old_id(plant), "vulnerability_id": old_id(plant), "source": "cache_poisoning",
        "cache_technique": "cache_deception", "detection_mode": "deception",
        "cache_header": "", "cache_param": "static-suffix", "endpoint": plant, "matched_at": plant,
        "poc_link": plant, "name": "Web Cache Poisoning via static-suffix",
        "user_id": UID, "project_id": PID, "updated_at": seen, **props}}


DECIDED = {"triage_status": "likely_noise", "triage_source": "human", "triage_reason": "test bed"}
MUTE = {"muted_at": "2026-10-01T00:00:00Z", "muted_by": "user-1", "muted_reason": "lab"}


class _Result(list):
    def single(self):
        return self[0] if self else None


class FakeGraph:
    """Applies the script's writes to a dict, so every read sees the writes before it."""

    def __init__(self, nodes=(), plants=(), events=None):
        self.nodes = {n["props"]["id"]: {"muted": n["muted"], "props": dict(n["props"])} for n in nodes}
        self.plants = list(plants)
        self.calls = []
        self.events = events if events is not None else []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if query not in (rk.OLD_FINDINGS, rk.READ_NODES, rk.PLANT_ENDPOINTS):
            self.events.append("graph write")
        if query is rk.OLD_FINDINGS:
            return _Result({"id": i, "endpoint": n["props"].get("endpoint"),
                            "cache_header": n["props"].get("cache_header"),
                            "cache_param": n["props"].get("cache_param"),
                            "seen": n["props"].get("updated_at")}
                           for i, n in sorted(self.nodes.items())
                           if n["props"].get("detection_mode") == "deception")
        if query is rk.READ_NODES:
            return _Result({"id": i, "muted": self.nodes[i]["muted"],
                            "props": dict(self.nodes[i]["props"])}
                           for i in params["ids"] if i in self.nodes)
        if query is rk.PLANT_ENDPOINTS:
            return _Result(self.plants)
        if query is rk.DELETE_PLANTS:
            n, self.plants = len(self.plants), []
            return _Result([{"n": n}])
        if query is rk.RENAME:
            node = self.nodes.pop(params["old"])
            node["props"].update(id=params["new"], vulnerability_id=params["new"],
                                 endpoint=params["endpoint"], matched_at=params["endpoint"],
                                 cache_param=params["cache_param"])
            self.nodes[params["new"]] = node
        elif query.startswith(rk.MERGE_ONTO_NEW.split("{remove}")[0]):
            keep = self.nodes[params["new"]]
            if "REMOVE" in query:
                for prop in query.split("REMOVE", 1)[1].split("\n", 1)[0].split(","):
                    keep["props"].pop(prop.strip().split(".", 1)[1], None)
            keep["props"].update(params["carried"])
            keep["muted"] = keep["muted"] or params["mute"]
        elif query is rk.DELETE_OLD:
            self.nodes.pop(params["old"], None)
        return _Result()

    def writes(self):
        reads = (rk.OLD_FINDINGS, rk.READ_NODES, rk.PLANT_ENDPOINTS)
        return [(q, p) for q, p in self.calls if q not in reads]


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
    def __init__(self, rows=((PID, UID),), events=None):
        self.rows = list(rows)
        self.log = []
        self.events = events if events is not None else []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.log.append(("commit",))
        self.events.append("commit")


class TestPlan(unittest.TestCase):
    def test_the_old_id_is_the_old_writers(self):
        # The guard recognises a node by recomputing its id: cache_vuln_id must
        # still be the formula the writer used before R-28.
        self.assertEqual(cache_vuln_id("u", "p", "cache_deception",
                                       "https://shop.test/account/rdmn1a2b3c.css", "static-suffix"),
                         "cache_u_p_cache_deception_https___shop_test__account_rdmn1a2b3c_css_static-suffix")

    def test_a_slash_plant_moves_to_the_page_and_its_shape(self):
        plan = rk.plan_finding(UID, PID, old_id(PLANT_1), PLANT_1, "static-suffix")
        self.assertEqual(plan, {"old_id": old_id(PLANT_1), "new_id": NEW_ID, "page_url": PAGE,
                                "cache_param": "static-suffix:/.css"})

    def test_a_semicolon_plant_keeps_its_delimiter(self):
        plant = f"{PAGE};rdmn1a2b3c.js"
        # urlparse ends the path at ';', so the old id already named the page.
        self.assertEqual(old_id(plant), cache_vuln_id(UID, PID, "cache_deception", PAGE, "static-suffix"))
        plan = rk.plan_finding(UID, PID, old_id(plant), plant, "static-suffix")
        self.assertEqual(plan["new_id"],
                         cache_vuln_id(UID, PID, "cache_deception", PAGE, "static-suffix:;.js"))
        self.assertNotEqual(plan["new_id"], NEW_ID)

    def test_a_plant_on_the_site_root_names_the_root(self):
        for plant in ("https://shop.test/rdmn1a2b3c.jpg", "https://shop.test/;rdmn1a2b3c.jpg"):
            with self.subTest(plant=plant):
                plan = rk.plan_finding(UID, PID, old_id(plant), plant, "static-suffix")
                self.assertEqual(plan["page_url"], "https://shop.test/")

    def test_the_new_id_is_the_one_the_writer_writes(self):
        writer = CacheMixin()
        writer.driver = FakeDriver(FakeGraph())
        writer.update_graph_from_cache_scan({"cache_scan": {"findings": [{
            "endpoint_url": PAGE, "technique": "cache_deception", "vector_type": "path",
            "cache_header": "", "cache_param": "static-suffix:/.css", "impact": "deception",
            "detection_mode": "deception", "evidence": {"poc_link": PLANT_1}}]}}, UID, PID)
        self.assertEqual(writer.driver._session.calls[0][1]["id"], NEW_ID)

    def test_findings_not_keyed_on_a_plant_are_left_alone(self):
        self.assertIsNone(rk.plan_finding(UID, PID, NEW_ID, PAGE, "static-suffix:/.css"))
        # A plant-looking URL under an id the old writer did not build.
        self.assertIsNone(rk.plan_finding(UID, PID, "imported-id", PLANT_1, "static-suffix"))
        self.assertIsNone(rk.plan_finding(UID, PID, old_id(PLANT_1), None, "static-suffix"))

    def test_several_old_nodes_group_on_one_new_id_most_recent_first(self):
        graph = FakeGraph([old_node(PLANT_1, "2026-10-01T00:00:00Z"),
                           old_node(PLANT_2, "2026-10-03T00:00:00Z"),
                           old_node(PLANT_3, "2026-10-02T00:00:00Z")],
                          plants=[{"baseurl": "https://shop.test", "path": "/account/rdmn1a2b3c.css"}])
        plan = rk.plan_project(graph, {"id": PID, "user_id": UID})
        (group,) = plan["rekeys"]
        self.assertEqual(group["new_id"], NEW_ID)
        self.assertEqual([o["old_id"] for o in group["old"]],
                         [old_id(PLANT_2), old_id(PLANT_3), old_id(PLANT_1)])
        self.assertEqual(len(plan["plants"]), 1)
        self.assertEqual(graph.writes(), [])

    def test_every_query_is_scoped_to_one_project(self):
        for name in ("OLD_FINDINGS", "READ_NODES", "RENAME", "MERGE_ONTO_NEW", "COPY_PROOF",
                     "DELETE_OLD", "REPARENT", "PLANT_ENDPOINTS", "DELETE_PLANTS"):
            query = getattr(rk, name)
            with self.subTest(query=name):
                self.assertIn("$pid", query)
                self.assertIn("$uid", query)
                self.assertNotIn("updated_at", query.replace("toString(v.updated_at)", ""))
                self.assertNotIn("triage_score", query)
        self.assertIn("v.detection_mode = 'deception'", rk.OLD_FINDINGS)
        self.assertIn("e.source = 'cache_poisoning'", rk.PLANT_ENDPOINTS)

    def test_the_plant_endpoint_pattern_matches_only_plants(self):
        import re
        plant = re.compile(rk.PLANT_ENDPOINT_PATH)
        self.assertTrue(plant.fullmatch("/account/rdmn1a2b3c.css"))
        self.assertTrue(plant.fullmatch("/rdmn1a2b3c.jpg"))
        for path in ("/account", "/static/app.css", "/account/rdmncb.css", "/a/rdmn1a2b3c.css.map"):
            self.assertIsNone(plant.fullmatch(path), path)


class TestRekeyGraph(unittest.TestCase):
    def _group(self, *plants):
        return {"new_id": NEW_ID, "page_url": PAGE, "cache_param": "static-suffix:/.css",
                "old": [{"old_id": old_id(p), "seen": ""} for p in plants]}

    def test_one_old_node_is_renamed_in_place(self):
        graph = FakeGraph([old_node(PLANT_1, "2026-10-01T00:00:00Z", muted=True, **DECIDED, **MUTE)])
        self.assertEqual(rk.rekey_graph(graph, UID, PID, self._group(PLANT_1)), ["renamed"])
        (rename, params), (reparent, where) = graph.writes()
        self.assertIs(rename, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["endpoint"], params["cache_param"]),
                         (old_id(PLANT_1), NEW_ID, PAGE, "static-suffix:/.css"))
        self.assertIs(reparent, rk.REPARENT)
        self.assertEqual((where["baseurl"], where["path"]), ("https://shop.test", "/account"))
        node = graph.nodes[NEW_ID]
        self.assertTrue(node["muted"])
        self.assertEqual((node["props"]["triage_status"], node["props"]["muted_by"]),
                         ("likely_noise", "user-1"))
        self.assertEqual(node["props"]["updated_at"], "2026-10-01T00:00:00Z")
        self.assertEqual(node["props"]["poc_link"], PLANT_1, "the plant URL stays the reproduction")

    def test_several_old_nodes_collapse_onto_the_most_recent(self):
        # The last run's node (unmuted, rules only) is kept; an older stale node a
        # person muted and judged gives it the mute, the decision and its proof.
        graph = FakeGraph([
            old_node(PLANT_2, "2026-10-03T00:00:00Z", triage_base_tier="T2", triage_ai_verdict="not_reviewed"),
            old_node(PLANT_1, "2026-10-01T00:00:00Z", muted=True, stale_since="2026-10-02",
                     **DECIDED, **MUTE),
        ])
        outcomes = rk.rekey_graph(graph, UID, PID, self._group(PLANT_2, PLANT_1))
        self.assertEqual(outcomes, ["renamed", "merged"])
        self.assertEqual(list(graph.nodes), [NEW_ID])
        node = graph.nodes[NEW_ID]
        self.assertTrue(node["muted"])
        self.assertEqual((node["props"]["triage_status"], node["props"]["triage_source"],
                          node["props"]["muted_by"]), ("likely_noise", "human", "user-1"))
        self.assertNotIn("triage_base_tier", node["props"], "the layers move as one block")
        self.assertNotIn("stale_since", node["props"], "the keeper was seen by the last run")
        self.assertEqual(node["props"]["updated_at"], "2026-10-03T00:00:00Z")
        writes = [q for q, _ in graph.writes()]
        self.assertEqual(writes[0], rk.RENAME)
        self.assertTrue(writes[1].startswith(rk.MERGE_ONTO_NEW.split("{remove}")[0]))
        self.assertEqual(writes[2:], [rk.COPY_PROOF, rk.DELETE_OLD, rk.REPARENT])

    def test_of_two_decisions_the_most_recent_one_stays(self):
        graph = FakeGraph([
            old_node(PLANT_2, "2026-10-03T00:00:00Z", triage_status="confirmed", triage_source="human"),
            old_node(PLANT_1, "2026-10-01T00:00:00Z", **DECIDED),
        ])
        rk.rekey_graph(graph, UID, PID, self._group(PLANT_2, PLANT_1))
        self.assertEqual(graph.nodes[NEW_ID]["props"]["triage_status"], "confirmed")

    def test_the_mute_is_carried_once_from_the_most_recent_muted_node(self):
        graph = FakeGraph([
            old_node(PLANT_2, "2026-10-03T00:00:00Z"),
            old_node(PLANT_3, "2026-10-02T00:00:00Z", muted=True, muted_by="user-2"),
            old_node(PLANT_1, "2026-10-01T00:00:00Z", muted=True, muted_by="user-1"),
        ])
        rk.rekey_graph(graph, UID, PID, self._group(PLANT_2, PLANT_3, PLANT_1))
        node = graph.nodes[NEW_ID]
        self.assertTrue(node["muted"])
        self.assertEqual(node["props"]["muted_by"], "user-2")

    def test_a_node_the_scan_already_wrote_is_the_keeper(self):
        scanned = {"muted": False, "props": {"id": NEW_ID, "source": "cache_poisoning",
                                             "triage_ai_verdict": "real", "endpoint": PAGE,
                                             "updated_at": "2026-11-11T00:00:00Z"}}
        graph = FakeGraph([old_node(PLANT_1, "2026-10-01T00:00:00Z", muted=True, **DECIDED, **MUTE)])
        graph.nodes[NEW_ID] = scanned
        self.assertEqual(rk.rekey_graph(graph, UID, PID, self._group(PLANT_1)), ["merged"])
        self.assertNotIn(rk.RENAME, [q for q, _ in graph.writes()])
        node = graph.nodes[NEW_ID]
        self.assertEqual((node["muted"], node["props"]["triage_status"]), (True, "likely_noise"))
        self.assertNotIn("triage_ai_verdict", node["props"])
        self.assertEqual(node["props"]["endpoint"], PAGE)

    def test_old_nodes_already_gone_are_nothing(self):
        graph = FakeGraph()
        self.assertEqual(rk.rekey_graph(graph, UID, PID, self._group(PLANT_1, PLANT_2)), ["gone", "gone"])
        self.assertEqual(graph.writes(), [])


class TestRekeyPostgres(unittest.TestCase):
    def test_every_row_naming_an_old_id_follows_it(self):
        conn = FakeConn()
        group = {"new_id": NEW_ID, "old": [{"old_id": old_id(PLANT_2)}, {"old_id": old_id(PLANT_1)}]}
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, group)
        sql = [entry for entry in conn.log if entry[0] == "sql"]
        self.assertEqual(len(sql), 8)
        inserts = [p for _, q, p in sql if q.startswith("INSERT INTO node_filter_exemptions")]
        self.assertEqual([(p["old"], p["new"]) for p in inserts],
                         [(old_id(PLANT_2), NEW_ID), (old_id(PLANT_1), NEW_ID)])
        self.assertEqual(len({p["row_id"] for p in inserts}), 2)
        for table in ("DELETE FROM node_filter_exemptions", "UPDATE remediations",
                      "UPDATE captured_http_transactions"):
            self.assertEqual(len([q for _, q, _ in sql if q.startswith(table)]), 2, table)
        remediation = next(q for _, q, _ in sql if q.startswith("UPDATE remediations"))
        self.assertIn("array_remove", remediation, "a second old id must not duplicate the new one")
        for _, query, params in sql:
            self.assertIn("project_id = %(pid)s", query)
            self.assertEqual(params["pid"], PID)


class TestRun(unittest.TestCase):
    def _graph(self, events=None):
        return FakeGraph([old_node(PLANT_2, "2026-10-03T00:00:00Z"),
                          old_node(PLANT_1, "2026-10-01T00:00:00Z", muted=True, **DECIDED, **MUTE)],
                         plants=[{"baseurl": "https://shop.test", "path": "/account/rdmn4d5e6f.css"}],
                         events=events)

    def test_a_dry_run_changes_nothing(self):
        graph, conn, lines = self._graph(), FakeConn(), []
        summary = rk.run(conn, FakeDriver(graph), None, apply=False, out=lines.append)
        self.assertEqual(graph.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [])
        self.assertEqual(len([e for e in conn.log if e[0] == "sql"]), 1, "only the project list")
        text = "\n".join(lines)
        self.assertIn("(dry run)", text)
        self.assertIn(f"{PID}: 2 finding(s) to re-key onto 1 id(s), 1 plant Endpoint(s)", text)
        self.assertEqual(summary[PID]["outcomes"], [])

    def test_apply_writes_postgres_first_then_the_graph_and_is_idempotent(self):
        events, lines = [], []
        graph, conn = self._graph(events), FakeConn(events=events)
        summary = rk.run(conn, FakeDriver(graph), PID, apply=True, out=lines.append)
        # Postgres first: a run that dies half-way re-plans from the graph's old ids.
        self.assertEqual(events[0], "commit")
        self.assertIn("graph write", events)
        self.assertEqual(summary[PID]["outcomes"], ["renamed", "merged"])
        self.assertEqual(summary[PID]["plants_deleted"], 1)
        self.assertIn("done: 1 renamed, 1 merged, 1 plant Endpoint(s) deleted", "\n".join(lines))
        self.assertEqual(list(graph.nodes), [NEW_ID])
        self.assertTrue(graph.nodes[NEW_ID]["muted"])

        again, more = FakeConn(), []
        self.assertEqual(rk.run(again, FakeDriver(graph), PID, apply=True, out=more.append), {})
        self.assertIn("re-keyed 0 finding(s) in 0 project(s)", more[-1])
        self.assertEqual([e for e in again.log if e[0] == "commit"], [])

    def test_a_blank_project_id_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn(), FakeDriver(FakeGraph()), " ", apply=False)


class TestMain(unittest.TestCase):
    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["webapp"]), \
                patch.object(rk, "_connect", side_effect=AssertionError("must not connect")):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)

    def test_a_blank_project_is_refused(self):
        with self.assertRaises(SystemExit):
            rk.main(["--project", " "])


if __name__ == "__main__":
    unittest.main()

"""The graph half of an ownership transfer: retenant_project (RBAC step 5.12, SH-15).

A transfer sets Project.userId to the new owner, and the graph keys every entity
node on (natural key, user_id, project_id), so the project's nodes must follow.
A label the re-tenant misses stays under the old owner: the new owner sees a
partial graph and the old one keeps a hidden copy. A scope it widens moves
another project's data. A half-done move splits the project between two tenants.

So the mixin runs here against an in-memory graph that interprets its statements
and enforces every uniqueness key of graph_db/schema_keys.py, seeded with nodes
of EVERY label the schema places declare (the catalog, the key declaration and
the tenant indexes), never a hand-written list. A statement the fake does not
recognise fails the test rather than passing silently.

The Cypher itself runs against a real Neo4j in tests/rbac_retenant_live.sh.

Run: python -m pytest tests/test_graph_retenant.py   (inside the agent image)
"""

import contextlib
import copy
import io
import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.tenancy_mixin import (  # noqa: E402
    RETENANT_BATCH,
    TENANT_LABELS,
    RetenantError,
    TenancyMixin,
)
from graph_db.schema import ADDITIONAL_INDEXES, TENANT_INDEXES  # noqa: E402
from graph_db.schema_catalog import DOCUMENTED  # noqa: E402
from graph_db.schema_keys import KEY_CONSTRAINTS  # noqa: E402
from graph_db.tenant_filter import GLOBAL_REFERENCE_LABELS  # noqa: E402

OLD, NEW, OTHER = "user-old-owner", "user-new-owner", "user-elsewhere"
PID, SIBLING, FOREIGN = "proj-moving", "proj-sibling", "proj-foreign"

#: Every label the catalog documents as per-project data: the expected re-tenant
#: set, read from a different schema place than the mixin's own derivation.
SCHEMA_TENANT_LABELS = frozenset(DOCUMENTED) - frozenset(GLOBAL_REFERENCE_LABELS)
REFERENCE = frozenset(GLOBAL_REFERENCE_LABELS)
KEYS = {k["label"]: tuple(k["key_properties"]) for k in KEY_CONSTRAINTS}
TENANT_TAIL = ("user_id", "project_id")
#: A label from an older schema that a database may still hold; only the
#: label-free sweep can find it.
LEGACY_LABEL = "GithubFinding"


class FakeConstraintError(Exception):
    pass


class FakeNeo4jError(Exception):
    pass


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def single(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


_REFS = r"(?P<refs>n:`\w+`(?: OR n:`\w+`)*)"
_PREFLIGHT_NODES = re.compile(
    r"^MATCH \(n\)\s+WHERE n\.user_id = \$uid AND n\.project_id = \$pid\s+"
    rf"AND NOT \({_REFS}\)\s+"
    r"RETURN elementId\(n\) AS id, labels\(n\) AS labels$")
_PREFLIGHT_RELS = re.compile(
    r"^MATCH \(\)-\[r\]->\(\)\s+WHERE r\.user_id = \$uid AND r\.project_id = \$pid\s+"
    r"RETURN elementId\(r\) AS id$")
_CONFLICT = re.compile(
    r"^MATCH \(a:`(?P<label>\w+)` \{user_id: \$src, project_id: \$pid\}\)\s+"
    r"MATCH \(b:`(?P=label)` \{(?P<keys>(?:\w+: a\.\w+, )*)user_id: \$dst, project_id: \$pid\}\)\s+"
    r"RETURN count\(a\) AS c$")
_MOVE_LABEL = re.compile(
    r"^MATCH \(n:`(?P<label>\w+)` \{user_id: \$src, project_id: \$pid\}\)\s+"
    r"WHERE NOT elementId\(n\) IN \$keep\s+"
    r"WITH n LIMIT \$batch\s+SET n\.user_id = \$dst\s+RETURN count\(n\) AS c$")
_MOVE_ANY = re.compile(
    r"^MATCH \(n\)\s+WHERE n\.user_id = \$src AND n\.project_id = \$pid\s+"
    rf"AND NOT \({_REFS}\) AND NOT elementId\(n\) IN \$keep\s+"
    r"WITH n LIMIT \$batch\s+SET n\.user_id = \$dst\s+"
    r"RETURN count\(n\) AS c, collect\(labels\(n\)\) AS labels$")
_MOVE_RELS = re.compile(
    r"^MATCH \(\)-\[r\]->\(\)\s+WHERE r\.user_id = \$src AND r\.project_id = \$pid"
    r" AND NOT elementId\(r\) IN \$keep_rels\s+"
    r"WITH r LIMIT \$batch\s+SET r\.user_id = \$dst\s+RETURN count\(r\) AS c$")


def _at(item, uid, pid):
    return item["props"].get("user_id") == uid and item["props"].get("project_id") == pid


class FakeGraph:
    """Nodes and relationships with Neo4j's statement atomicity: a statement that
    violates a uniqueness key, or that a test makes fail, changes nothing."""

    def __init__(self):
        self.nodes = []
        self.rels = []
        self.keys = dict(KEYS)
        self.statements = []
        self.writes = 0
        self.fail_when = None  # (write ordinal, query, params) -> bool

    def add_node(self, labels, **props):
        node = {"eid": f"n{len(self.nodes)}", "labels": set(labels), "props": props}
        self.nodes.append(node)
        return node

    def add_rel(self, start, rel_type, end, **props):
        self.rels.append({"eid": f"r{len(self.rels)}", "type": rel_type,
                          "start": start["eid"], "end": end["eid"], "props": props})

    def snapshot(self):
        return copy.deepcopy((self.nodes, self.rels))

    def tenant_count(self, label, uid, pid):
        return sum(1 for n in self.nodes if label in n["labels"] and _at(n, uid, pid))

    def project_nodes_at(self, uid, pid):
        return [n for n in self.nodes if _at(n, uid, pid) and not n["labels"] & REFERENCE]

    def _check_unique(self):
        for label, keys in self.keys.items():
            seen = set()
            for n in self.nodes:
                if label not in n["labels"]:
                    continue
                values = tuple(n["props"].get(k) for k in keys)
                if any(v is None for v in values):
                    continue  # a uniqueness constraint skips a node missing a key property
                if values in seen:
                    raise FakeConstraintError(f"{label} {values} already exists")
                seen.add(values)

    def _write(self, query, params, items):
        """Apply `SET x.user_id = $dst` to `items`, all or nothing."""
        ordinal = self.writes
        self.writes += 1
        if self.fail_when and self.fail_when(ordinal, query, params):
            raise FakeNeo4jError(f"injected failure on write {ordinal}")
        before = [dict(x["props"]) for x in items]
        for x in items:
            x["props"]["user_id"] = params["dst"]
        try:
            self._check_unique()
        except FakeConstraintError:
            for x, props in zip(items, before):
                x["props"] = props
            raise

    def run(self, query, params):
        query = query.strip()
        self.statements.append((query, dict(params)))
        if m := _PREFLIGHT_NODES.match(query):
            refs = set(re.findall(r"n:`(\w+)`", m["refs"]))
            return FakeResult([{"id": n["eid"], "labels": sorted(n["labels"])} for n in self.nodes
                               if _at(n, params["uid"], params["pid"]) and not n["labels"] & refs])
        if _PREFLIGHT_RELS.match(query):
            return FakeResult([{"id": r["eid"]} for r in self.rels
                               if _at(r, params["uid"], params["pid"])])
        if m := _CONFLICT.match(query):
            label = m["label"]
            keys = re.findall(r"(\w+): a\.(\w+)", m["keys"])
            assert all(k == v for k, v in keys), query
            assert tuple(k for k, _ in keys) + TENANT_TAIL == self.keys[label], query
            hits = sum(
                1
                for a in self.nodes if label in a["labels"] and _at(a, params["src"], params["pid"])
                for b in self.nodes if label in b["labels"] and _at(b, params["dst"], params["pid"])
                and all(a["props"].get(k) is not None
                        and a["props"].get(k) == b["props"].get(k) for k, _ in keys))
            return FakeResult([{"c": hits}])
        if m := _MOVE_LABEL.match(query):
            batch = [n for n in self.nodes if m["label"] in n["labels"]
                     and _at(n, params["src"], params["pid"])
                     and n["eid"] not in params["keep"]][:params["batch"]]
            self._write(query, params, batch)
            return FakeResult([{"c": len(batch)}])
        if m := _MOVE_ANY.match(query):
            refs = set(re.findall(r"n:`(\w+)`", m["refs"]))
            batch = [n for n in self.nodes if not n["labels"] & refs
                     and _at(n, params["src"], params["pid"])
                     and n["eid"] not in params["keep"]][:params["batch"]]
            labels = [sorted(n["labels"]) for n in batch]
            self._write(query, params, batch)
            return FakeResult([{"c": len(batch), "labels": labels}])
        if _MOVE_RELS.match(query):
            batch = [r for r in self.rels if _at(r, params["src"], params["pid"])
                     and r["eid"] not in params["keep_rels"]][:params["batch"]]
            self._write(query, params, batch)
            return FakeResult([{"c": len(batch)}])
        raise AssertionError(f"statement the fake graph does not know:\n{query}")


class FakeSession:
    def __init__(self, graph):
        self.graph = graph

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        return self.graph.run(query, params)


class FakeDriver:
    def __init__(self, graph):
        self.graph = graph
        self.sessions = 0

    def session(self):
        self.sessions += 1
        return FakeSession(self.graph)


class Client(TenancyMixin):
    """The mixin alone over the fake driver; the real client composes it with the
    others, and BaseMixin.__init__ (which opens a real connection) is not called."""

    def __init__(self, graph):
        self.driver = FakeDriver(graph)


def _key_values(label, tag):
    """Identifying property values distinct per node, so two seeded nodes never
    collide by accident."""
    return {k: f"{label}-{k}-{tag}" for k in KEYS.get(label, ()) if k not in TENANT_TAIL}


def seed(nodes_per_label=3):
    """A project under the old owner with nodes of every schema tenant label, a
    sibling project of the same owner, another tenant's project, the global
    reference nodes (two still carrying a legacy tenant stamp), a legacy label,
    a muted finding and relationships, one of them stamped with the tenant."""
    g = FakeGraph()
    moving = {}
    for label in sorted(SCHEMA_TENANT_LABELS):
        moving[label] = [
            g.add_node([label], user_id=OLD, project_id=PID, updated_at="2026-11-01T00:00:00Z",
                       **_key_values(label, f"{PID}-{i}"))
            for i in range(nodes_per_label)
        ]
        g.add_node([label], user_id=OLD, project_id=SIBLING, **_key_values(label, f"{SIBLING}-0"))
        g.add_node([label], user_id=OTHER, project_id=FOREIGN, **_key_values(label, f"{FOREIGN}-0"))
    muted = g.add_node(["Vulnerability", "Muted"], user_id=OLD, project_id=PID, muted_by=OLD,
                       **_key_values("Vulnerability", "muted"))
    g.add_node([LEGACY_LABEL], user_id=OLD, project_id=PID, id="legacy-1")
    cve = g.add_node(["CVE"], id="CVE-0000-0001")
    g.add_node(["CVE"], id="CVE-0000-0002", user_id=OLD, project_id=PID)
    g.add_node(["MitreData"], id="CWE-0", user_id=OLD, project_id=PID)
    g.add_rel(moving["Domain"][0], "HAS_SUBDOMAIN", moving["Subdomain"][0])
    g.add_rel(moving["Technology"][0], "HAS_KNOWN_CVE", cve)
    g.add_rel(moving["Subdomain"][0], "RESOLVES_TO", moving["IP"][0], user_id=OLD, project_id=PID)
    g.add_rel(muted, "FOUND_AT", moving["Endpoint"][0])
    return g


#: Seeded nodes of the moving project: 3 per label, the muted finding, the legacy node.
SEEDED_MOVING = 3 * len(SCHEMA_TENANT_LABELS) + 2


def quiet(fn, *args, **kwargs):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = fn(*args, **kwargs)
    return result, out.getvalue()


def retenant(graph, *args, **kwargs):
    return quiet(Client(graph).retenant_project, *args, **kwargs)[0]


def outside_project(graph):
    """Every node and relationship that is not the moving project's own."""
    nodes = [n for n in graph.nodes
             if n["props"].get("project_id") != PID or n["labels"] <= REFERENCE]
    rels = [r for r in graph.rels if r["props"].get("project_id") != PID]
    return copy.deepcopy((nodes, rels))


class TestTheLabelSetComesFromTheSchema(unittest.TestCase):
    def test_every_documented_project_label_and_no_reference_label(self):
        self.assertEqual(set(TENANT_LABELS), set(SCHEMA_TENANT_LABELS))
        self.assertFalse(set(TENANT_LABELS) & REFERENCE)

    def test_every_label_keyed_on_the_tenant_is_moved(self):
        keyed = {k["label"] for k in KEY_CONSTRAINTS
                 if tuple(k["key_properties"][-2:]) == TENANT_TAIL}
        self.assertTrue(keyed)
        self.assertLessEqual(keyed, set(TENANT_LABELS))

    def test_every_label_with_a_tenant_index_is_moved(self):
        indexed = set()
        for stmt in TENANT_INDEXES + ADDITIONAL_INDEXES:
            m = re.search(r"FOR \((\w+):(\w+)\) ON \(\1\.user_id, \1\.project_id\)", stmt)
            if m:
                indexed.add(m.group(2))
        self.assertTrue(indexed)
        self.assertLessEqual(indexed, set(TENANT_LABELS))

    def test_the_chain_labels_are_moved_although_their_key_has_no_tenant(self):
        for label in ("AttackChain", "ChainStep", "ChainFinding", "ChainDecision", "ChainFailure"):
            self.assertIn(label, TENANT_LABELS)
            self.assertNotIn("user_id", KEYS[label])

    def test_a_global_label_without_tenant_is_not_moved(self):
        self.assertNotIn("KBChunk", TENANT_LABELS)

    def test_the_batch_is_the_spec_size(self):
        self.assertEqual(RETENANT_BATCH, 5000)

    def test_the_client_composes_the_mixin(self):
        from graph_db.neo4j_client import Neo4jClient
        self.assertTrue(issubclass(Neo4jClient, TenancyMixin))
        self.assertTrue(callable(getattr(Neo4jClient, "retenant_project", None)))


class TestAcceptMovesTheGraph(unittest.TestCase):
    def test_every_label_moves_to_the_new_owner(self):
        g = seed()
        result = retenant(g, PID, OLD, NEW)
        for label in sorted(SCHEMA_TENANT_LABELS):
            with self.subTest(label=label):
                expected = 3 + (1 if label == "Vulnerability" else 0)
                self.assertEqual(g.tenant_count(label, NEW, PID), expected)
                self.assertEqual(g.tenant_count(label, OLD, PID), 0)
                self.assertEqual(result["nodes"][label], expected)
        self.assertEqual(g.project_nodes_at(OLD, PID), [])

    def test_the_muted_finding_moves_and_keeps_its_mute(self):
        g = seed()
        retenant(g, PID, OLD, NEW)
        muted = [n for n in g.nodes if "Muted" in n["labels"]]
        self.assertEqual(len(muted), 1)
        self.assertEqual(muted[0]["props"]["user_id"], NEW)
        self.assertEqual(muted[0]["props"]["muted_by"], OLD, "the mute still names who muted")

    def test_a_label_outside_the_schema_is_swept_and_reported(self):
        g = seed()
        result, out = quiet(Client(g).retenant_project, PID, OLD, NEW)
        self.assertEqual(g.tenant_count(LEGACY_LABEL, NEW, PID), 1)
        self.assertEqual(result["unlisted"], {LEGACY_LABEL: 1})
        self.assertIn("[rbac] retenant", out)
        self.assertIn(LEGACY_LABEL, out)

    def test_a_relationship_stamped_with_the_tenant_moves(self):
        g = seed()
        result = retenant(g, PID, OLD, NEW)
        stamped = [r for r in g.rels if r["props"].get("project_id") == PID]
        self.assertEqual([r["props"]["user_id"] for r in stamped], [NEW])
        self.assertEqual(result["relationships"], 1)

    def test_only_user_id_changes(self):
        g = seed()
        old_nodes, old_rels = g.snapshot()
        retenant(g, PID, OLD, NEW)
        self.assertEqual([n["eid"] for n in g.nodes], [n["eid"] for n in old_nodes],
                         "no node recreated or deleted")

        def without_tenant(props):
            return {k: v for k, v in props.items() if k != "user_id"}

        for old, new in zip(old_nodes, g.nodes):
            self.assertEqual(new["labels"], old["labels"])
            self.assertEqual(without_tenant(new["props"]), without_tenant(old["props"]),
                             "ids, updated_at and attribution stay as they were")
        self.assertEqual(len(g.rels), len(old_rels))
        for old, new in zip(old_rels, g.rels):
            self.assertEqual((new["eid"], new["type"], new["start"], new["end"]),
                             (old["eid"], old["type"], old["start"], old["end"]))
            self.assertEqual(without_tenant(new["props"]), without_tenant(old["props"]))

    def test_node_ids_keep_the_tenant_they_were_minted_under(self):
        g = FakeGraph()
        minted = f"github-hunt-{OLD}-{PID}"
        g.add_node(["GithubHunt"], id=minted, user_id=OLD, project_id=PID)
        retenant(g, PID, OLD, NEW)
        self.assertEqual(g.nodes[0]["props"], {"id": minted, "user_id": NEW, "project_id": PID})

    def test_the_result_counts_and_times_the_move(self):
        g = seed()
        result = retenant(g, PID, OLD, NEW)
        self.assertEqual(result["total_nodes"], SEEDED_MOVING)
        self.assertEqual(sum(result["nodes"].values()) + sum(result["unlisted"].values()),
                         SEEDED_MOVING)
        self.assertEqual((result["project_id"], result["from_user_id"], result["to_user_id"]),
                         (PID, OLD, NEW))
        self.assertEqual(result["already_at_target"], {})
        self.assertIsInstance(result["elapsed_ms"], int)


class TestRetenantTouchesOnlyThatProject(unittest.TestCase):
    def test_sibling_project_other_tenant_and_reference_nodes_unchanged(self):
        g = seed()
        before = outside_project(g)
        retenant(g, PID, OLD, NEW)
        self.assertEqual(outside_project(g), before)

    def test_a_reference_node_with_a_legacy_tenant_stamp_is_left_alone(self):
        g = seed()
        retenant(g, PID, OLD, NEW)
        stamped = [n for n in g.nodes if n["labels"] & REFERENCE and "user_id" in n["props"]]
        self.assertEqual(len(stamped), 2)
        self.assertTrue(all(n["props"]["user_id"] == OLD for n in stamped))

    def test_every_statement_is_scoped_to_the_project_and_writes_only_user_id(self):
        g = seed()
        g.add_node(["Port"], **_key_values("Port", "x"), user_id=NEW, project_id=PID)
        retenant(g, PID, OLD, NEW)
        kinds = set()
        for query, params in g.statements:
            with self.subTest(query=query.splitlines()[0]):
                self.assertEqual(params["pid"], PID)
                self.assertRegex(query, r"project_id(: | = )\$pid")
                self.assertNotRegex(query.upper(), r"\b(DELETE|DETACH|CREATE|MERGE|REMOVE)\b")
                # Node patterns only; `NOT (n:`CVE` OR ...)` is the reference exclusion.
                for label in re.findall(r"\(\w+:`(\w+)` \{", query):
                    self.assertIn(label, TENANT_LABELS)
                for clause in re.findall(r"\bSET\s+([^\n]+)", query):
                    self.assertRegex(clause, r"^[nr]\.user_id = \$dst$")
            kinds.add(next(name for name, rx in (
                ("preflight-nodes", _PREFLIGHT_NODES), ("preflight-rels", _PREFLIGHT_RELS),
                ("conflict", _CONFLICT), ("move-label", _MOVE_LABEL),
                ("move-any", _MOVE_ANY), ("move-rels", _MOVE_RELS)) if rx.match(query)))
        self.assertEqual(len(kinds), 6, "every statement kind was checked")

    def test_the_label_free_statements_exclude_every_reference_label(self):
        g = seed()
        retenant(g, PID, OLD, NEW)
        label_free = [q for q, _ in g.statements if _MOVE_ANY.match(q) or _PREFLIGHT_NODES.match(q)]
        self.assertEqual(len(label_free), 2)
        for q in label_free:
            self.assertEqual(set(re.findall(r"n:`(\w+)`", q)), set(REFERENCE))


class TestBatches(unittest.TestCase):
    def test_each_label_moves_in_batches_until_none_is_left(self):
        g = seed(nodes_per_label=5)
        result = retenant(g, PID, OLD, NEW, batch_size=2)
        domain_moves = [p for q, p in g.statements
                        if (m := _MOVE_LABEL.match(q)) and m["label"] == "Domain"]
        self.assertEqual(len(domain_moves), 3, "2 + 2 + 1: the short batch ends the loop")
        self.assertTrue(all(p["batch"] == 2 for p in domain_moves))
        self.assertEqual(result["nodes"]["Domain"], 5)
        self.assertEqual(g.tenant_count("Domain", OLD, PID), 0)

    def test_the_default_batch_is_5000(self):
        g = seed(nodes_per_label=1)
        retenant(g, PID, OLD, NEW)
        moves = [p for q, p in g.statements if _MOVE_LABEL.match(q)]
        self.assertTrue(moves)
        self.assertTrue(all(p["batch"] == 5000 for p in moves))

    def test_an_exact_multiple_asks_once_more_and_stops_on_zero(self):
        g = FakeGraph()
        for i in range(4):
            g.add_node(["Domain"], name=f"d{i}", user_id=OLD, project_id=PID)
        retenant(g, PID, OLD, NEW, batch_size=2)
        domain_moves = [p for q, p in g.statements
                        if (m := _MOVE_LABEL.match(q)) and m["label"] == "Domain"]
        self.assertEqual(len(domain_moves), 3)
        self.assertEqual(g.tenant_count("Domain", NEW, PID), 4)


class TestIdempotent(unittest.TestCase):
    def test_the_same_transfer_twice_moves_nothing_the_second_time(self):
        g = seed()
        retenant(g, PID, OLD, NEW)
        after_first = g.snapshot()
        second = retenant(g, PID, OLD, NEW)
        self.assertEqual(g.snapshot(), after_first)
        self.assertEqual(second["total_nodes"], 0)
        self.assertEqual(second["nodes"], {})
        self.assertEqual(second["unlisted"], {})
        self.assertEqual(second["relationships"], 0)
        self.assertEqual(sum(second["already_at_target"].values()), SEEDED_MOVING)

    def test_a_retry_completes_an_interrupted_move(self):
        g = seed()
        for n in g.nodes:  # an earlier attempt died after moving the Domain label
            if "Domain" in n["labels"] and n["props"].get("project_id") == PID:
                n["props"]["user_id"] = NEW
        result = retenant(g, PID, OLD, NEW)
        self.assertEqual(result["already_at_target"], {"Domain": 3})
        self.assertNotIn("Domain", result["nodes"])
        self.assertEqual(g.project_nodes_at(OLD, PID), [])

    def test_running_it_back_restores_the_graph(self):
        g = seed()
        before = g.snapshot()
        retenant(g, PID, OLD, NEW)
        retenant(g, PID, NEW, OLD)
        self.assertEqual(g.snapshot(), before)


class TestConflictsAreRefusedBeforeAnyWrite(unittest.TestCase):
    def test_a_twin_under_the_new_owner_refuses_and_changes_nothing(self):
        g = seed()
        twin_of = next(n for n in g.nodes if "Port" in n["labels"] and _at(n, OLD, PID))
        g.add_node(["Port"], **{**twin_of["props"], "user_id": NEW})
        before = g.snapshot()
        with self.assertRaises(RetenantError) as ctx:
            retenant(g, PID, OLD, NEW)
        self.assertEqual(ctx.exception.code, "retenant_conflict")
        self.assertEqual(ctx.exception.conflicts, {"Port": 1})
        self.assertEqual(g.writes, 0)
        self.assertEqual(g.snapshot(), before)

    def test_nodes_under_the_new_owner_that_do_not_collide_are_no_conflict(self):
        g = seed()
        g.add_node(["Port"], **_key_values("Port", "unrelated"), user_id=NEW, project_id=PID)
        result = retenant(g, PID, OLD, NEW)
        self.assertEqual(result["already_at_target"], {"Port": 1})
        self.assertEqual(g.tenant_count("Port", NEW, PID), 4)

    def test_only_labels_already_holding_target_nodes_are_compared(self):
        g = seed()
        retenant(g, PID, OLD, NEW)
        self.assertFalse([q for q, _ in g.statements if _CONFLICT.match(q)])

    def test_a_label_keyed_on_a_global_id_is_never_compared(self):
        g = seed()
        g.add_node(["ChainStep"], step_id="elsewhere", user_id=NEW, project_id=PID)
        retenant(g, PID, OLD, NEW)
        self.assertFalse([q for q, _ in g.statements if _CONFLICT.match(q)])


class TestAPartialFailureLeavesTheGraphAsItWas(unittest.TestCase):
    def test_a_failure_at_any_write_runs_the_move_back(self):
        clean = seed()
        retenant(clean, PID, OLD, NEW, batch_size=2)
        total = clean.writes
        self.assertGreater(total, len(SCHEMA_TENANT_LABELS))
        for k in sorted({0, 1, total // 2, total - 2, total - 1}):
            with self.subTest(failing_write=k):
                g = seed()
                before = g.snapshot()
                g.fail_when = lambda i, q, p, k=k: i == k
                with self.assertRaises(RetenantError) as ctx:
                    retenant(g, PID, OLD, NEW, batch_size=2)
                self.assertEqual(ctx.exception.code, "retenant_failed")
                self.assertIsInstance(ctx.exception.__cause__, FakeNeo4jError)
                self.assertEqual(g.snapshot(), before)

    def test_the_failure_is_logged_for_the_operator(self):
        g = seed()
        g.fail_when = lambda i, q, p: i == 3
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(RetenantError):
            Client(g).retenant_project(PID, OLD, NEW)
        self.assertIn("[rbac] retenant failed", out.getvalue())
        self.assertIn(PID, out.getvalue())

    def test_a_key_collision_during_the_move_runs_it_back(self):
        g = seed()
        g.add_node([LEGACY_LABEL], user_id=NEW, project_id=PID, id="legacy-1")
        g.keys[LEGACY_LABEL] = ("id", "user_id", "project_id")
        before = g.snapshot()
        with self.assertRaises(RetenantError) as ctx:
            retenant(g, PID, OLD, NEW)
        self.assertEqual(ctx.exception.code, "retenant_failed")
        self.assertIsInstance(ctx.exception.__cause__, FakeConstraintError)
        self.assertEqual(g.snapshot(), before)

    def test_the_run_back_leaves_what_was_already_at_the_target(self):
        g = seed()
        for n in g.nodes:  # an earlier attempt died after moving the Domain label
            if "Domain" in n["labels"] and n["props"].get("project_id") == PID:
                n["props"]["user_id"] = NEW
        g.add_rel(g.nodes[0], "RESOLVES_TO", g.nodes[1], user_id=NEW, project_id=PID)
        before = g.snapshot()
        g.fail_when = lambda i, q, p: i == 7
        with self.assertRaises(RetenantError) as ctx:
            retenant(g, PID, OLD, NEW)
        self.assertEqual(ctx.exception.code, "retenant_failed")
        self.assertEqual(g.snapshot(), before)

    def test_the_run_back_uses_a_fresh_session(self):
        g = seed()
        g.fail_when = lambda i, q, p: i == 5
        client = Client(g)
        with self.assertRaises(RetenantError):
            quiet(client.retenant_project, PID, OLD, NEW)
        self.assertEqual(client.driver.sessions, 2)

    def test_a_failed_run_back_reports_the_split_and_a_retry_completes(self):
        g = seed()
        g.fail_when = lambda i, q, p: i >= 4
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(RetenantError) as ctx:
            Client(g).retenant_project(PID, OLD, NEW)
        err = ctx.exception
        self.assertEqual(err.code, "retenant_rollback_failed")
        self.assertIn("[rbac] retenant rollback failed", out.getvalue())
        moved_before_failure = sum(err.moved["nodes"].values())
        self.assertGreater(moved_before_failure, 0)
        self.assertEqual(len(g.project_nodes_at(NEW, PID)), moved_before_failure,
                         "the graph is split, and the error says how far the move got")
        g.fail_when = None
        retenant(g, PID, OLD, NEW)
        self.assertEqual(g.project_nodes_at(OLD, PID), [])
        self.assertEqual(len(g.project_nodes_at(NEW, PID)), SEEDED_MOVING)


class TestArguments(unittest.TestCase):
    def test_missing_or_equal_tenants_are_refused_without_a_statement(self):
        for args in ((PID, OLD, OLD), ("", OLD, NEW), (PID, "", NEW), (PID, OLD, ""),
                     (None, OLD, NEW), (PID, OLD, None), (PID, 7, NEW)):
            with self.subTest(args=args):
                g = seed()
                with self.assertRaises(RetenantError) as ctx:
                    retenant(g, *args)
                self.assertEqual(ctx.exception.code, "retenant_invalid")
                self.assertEqual(g.statements, [])

    def test_a_batch_size_below_one_is_refused(self):
        for size in (0, -1, True):
            with self.subTest(batch_size=size):
                g = seed()
                with self.assertRaises(RetenantError) as ctx:
                    retenant(g, PID, OLD, NEW, batch_size=size)
                self.assertEqual(ctx.exception.code, "retenant_invalid")
                self.assertEqual(g.statements, [])


if __name__ == "__main__":
    unittest.main()

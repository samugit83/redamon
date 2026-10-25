"""
Unit tests for graph_diff — Scan Timeline delta tool.

Hermetic: the pure diff functions run on synthetic snapshot payloads; the
phase gate and executor-refusal tests stub the heavy langchain/neo4j imports
exactly like tests/test_executor_workspace_wiring.py does (per-file isolation
makes the stubs safe). No Neo4j, no Postgres.

Run with: python3 -m unittest tests.test_graph_diff -v
"""
from __future__ import annotations

import os
import re
import sys
import time
import unittest
from types import ModuleType
from unittest.mock import MagicMock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

# --- stubs (same shape as test_executor_workspace_wiring.py) ---------------
_STUBS = [
    "httpx",
    "langchain_core", "langchain_core.tools", "langchain_core.language_models",
    "langchain_core.messages",
    "langchain_mcp_adapters", "langchain_mcp_adapters.client",
    "langchain_neo4j",
    "graph_db", "graph_db.tenant_filter",
    "prompts",
]
for mod_name in _STUBS:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()
sys.modules["graph_db.tenant_filter"].find_disallowed_write_operation = lambda *a, **kw: None
sys.modules["graph_db.tenant_filter"].inject_tenant_filter = lambda c, *a, **kw: c
sys.modules["prompts"].TEXT_TO_CYPHER_SYSTEM = ""
if isinstance(sys.modules.get("graph_db"), MagicMock):
    sys.modules["graph_db"].resource_governor.governor_enabled = lambda: False


def _identity_tool(fn=None, **_kw):
    if callable(fn):
        return fn
    return lambda f: f


sys.modules["langchain_core.tools"].tool = _identity_tool

import graph_diff_tool as gdt  # noqa: E402  (light: stdlib only at import time)


# --- snapshot payload helpers ----------------------------------------------

def node(labels, props, export_id):
    return {"labels": list(labels), "properties": props, "_exportId": export_id}


def rel(rtype, start_id, end_id):
    return {"type": rtype, "startExportId": start_id, "endExportId": end_id}


def payload(nodes, rels):
    return {"nodes": nodes, "relationships": rels}


SNAP_A = payload(
    [
        node(["Subdomain"], {"name": "a.example.com", "updated_at": "2026-01-01"}, "n1"),
        node(["Subdomain"], {"name": "b.example.com"}, "n2"),
        node(["IP"], {"address": "10.0.0.1"}, "n3"),
        node(["Port"], {"ip_address": "10.0.0.1", "number": 443, "protocol": "tcp",
                        "state": "open"}, "n4"),
        node(["Port"], {"ip_address": "10.0.0.1", "number": 22, "protocol": "tcp"}, "n5"),
    ],
    [
        rel("RESOLVES_TO", "n1", "n3"),
        rel("RESOLVES_TO", "n2", "n3"),
    ],
)

# Fixture contract (checked exactly by the tests below):
#   +2 Subdomain added (c., d.), 1 Subdomain removed (b.),
#   1 Port changed (443 open->filtered), 1 Port unchanged,
#   1 IP only volatile-changed (updated_at) -> NOT a change,
#   1 rel added (c.->10.0.0.1), 1 rel removed (b.->10.0.0.1).
SNAP_B = payload(
    [
        # same subdomain, different export id AND different volatile stamp —
        # identity is name, so this MATCHES n1 and is not "added".
        node(["Subdomain"], {"name": "a.example.com", "updated_at": "2026-02-02"}, "x1"),
        node(["Subdomain"], {"name": "c.example.com"}, "x2"),
        node(["Subdomain"], {"name": "d.example.com"}, "x3"),
        # b.example.com gone (removed)
        node(["IP"], {"address": "10.0.0.1", "updated_at": "2026-02-02"}, "x4"),
        node(["Port"], {"ip_address": "10.0.0.1", "number": 443, "protocol": "tcp",
                        "state": "filtered"}, "x5"),
        node(["Port"], {"ip_address": "10.0.0.1", "number": 22, "protocol": "tcp"}, "x6"),
    ],
    [
        rel("RESOLVES_TO", "x1", "x4"),
        rel("RESOLVES_TO", "x2", "x4"),
        # n2/b.example.com rel gone with its node
    ],
)


class TestComputeDiff(unittest.TestCase):
    def test_added_removed_changed_exact(self):
        diff = gdt.compute_diff(SNAP_A, SNAP_B)
        nodes = diff["nodes"]
        self.assertEqual(nodes["added"]["Subdomain"]["count"], 2)
        self.assertEqual(sorted(nodes["added"]["Subdomain"]["examples"]),
                         ["c.example.com", "d.example.com"])
        self.assertEqual(nodes["removed"]["Subdomain"]["count"], 1)
        self.assertEqual(nodes["removed"]["Subdomain"]["examples"], ["b.example.com"])
        self.assertEqual(nodes["changed"]["Port"]["count"], 1)
        self.assertEqual(nodes["changed"]["Port"]["examples"][0]["fields"], ["state"])

    def test_volatile_change_not_reported(self):
        # 10.0.0.1 differs ONLY by updated_at -> must not appear as changed.
        diff = gdt.compute_diff(SNAP_A, SNAP_B)
        self.assertNotIn("IP", diff["nodes"]["changed"])

    def test_identity_is_properties_not_export_ids(self):
        # a.example.com changed export id n1 -> x1 and still matches.
        diff = gdt.compute_diff(SNAP_A, SNAP_B)
        self.assertEqual(diff["nodes"]["added"]["Subdomain"]["count"], 2)  # not 3
        # Port identity includes protocol: same number, other protocol is a
        # different node.
        a = payload([node(["Port"], {"ip_address": "10.0.0.1", "number": 53,
                                     "protocol": "udp"}, "p1")], [])
        b = payload([node(["Port"], {"ip_address": "10.0.0.1", "number": 53,
                                     "protocol": "tcp"}, "p2")], [])
        d2 = gdt.compute_diff(a, b)
        self.assertEqual(d2["summary"]["totals"]["nodes_added"], 1)
        self.assertEqual(d2["summary"]["totals"]["nodes_removed"], 1)

    def test_relationships_diff(self):
        diff = gdt.compute_diff(SNAP_A, SNAP_B)
        self.assertEqual(diff["relationships"]["added"], {"RESOLVES_TO": 1})
        self.assertEqual(diff["relationships"]["removed"], {"RESOLVES_TO": 1})

    def test_summary_totals_and_sort(self):
        diff = gdt.compute_diff(SNAP_A, SNAP_B)
        t = diff["summary"]["totals"]
        self.assertEqual(t["nodes_added"], 2)
        self.assertEqual(t["nodes_removed"], 1)
        self.assertEqual(t["nodes_changed"], 1)
        by_label = diff["summary"]["by_label"]
        self.assertEqual(by_label[0]["label"], "Subdomain")  # 3 events > Port 1
        totals = [e["total"] for e in by_label]
        self.assertEqual(totals, sorted(totals, reverse=True))
        self.assertIn("+2 new", gdt.one_line_summary(diff))

    def test_identical_snapshots_empty_delta(self):
        diff = gdt.compute_diff(SNAP_A, SNAP_A)
        self.assertEqual(diff["summary"]["totals"],
                         {"nodes_added": 0, "nodes_removed": 0, "nodes_changed": 0,
                          "relationships_added": 0, "relationships_removed": 0})

    def test_benchmark_100k_nodes_under_10s(self):
        n = 100_000
        a_nodes = [node(["Subdomain"], {"name": f"host{i}.example.com"}, f"a{i}")
                   for i in range(n)]
        # Fresh dicts for side B (a shallow list() would share the property
        # dicts and hide the changes from the differ).
        b_nodes = [node(["Subdomain"], dict(x["properties"]), x["_exportId"])
                   for x in a_nodes[2000:]]  # first 2000 of A removed
        b_nodes += [node(["Subdomain"], {"name": f"new{i}.example.com"}, f"b{i}")
                    for i in range(2000)]
        for x in b_nodes[4000:6000]:
            x["properties"]["cdn"] = "cloudflare"
        t0 = time.monotonic()
        diff = gdt.compute_diff(payload(a_nodes, []), payload(b_nodes, []))
        elapsed = time.monotonic() - t0
        self.assertEqual(diff["summary"]["totals"]["nodes_added"], 2000)
        self.assertEqual(diff["summary"]["totals"]["nodes_removed"], 2000)
        self.assertEqual(diff["summary"]["totals"]["nodes_changed"], 2000)
        self.assertLess(elapsed, 10.0, f"100k-node diff took {elapsed:.1f}s (budget 10s)")


class TestLiveCaptureSemantics(unittest.TestCase):
    def test_functional_label_skips_muted(self):
        self.assertEqual(gdt.functional_label(["Muted", "Subdomain"]), "Subdomain")

    def test_session_labels_excluded_list_matches_webapp(self):
        self.assertEqual(gdt.SESSION_LABELS,
                         ["AttackChain", "ChainStep", "ChainFinding",
                          "ChainDecision", "ChainFailure"])

    def test_live_capture_uses_identity_keyed_relationships(self):
        records = [
            {"labels": ["Subdomain"], "props": {"name": "a.example.com"}},
            {"labels": ["IP"], "props": {"address": "10.0.0.1"}},
        ]
        rel_records = [
            {"rel_type": "RESOLVES_TO",
             "start_labels": ["Subdomain"], "start_props": {"name": "a.example.com"},
             "end_labels": ["IP"], "end_props": {"address": "10.0.0.1"}},
        ]

        def query_fn(cypher, params=None):
            self.assertIn("MATCH", cypher)
            if "rel_type" in cypher:
                return rel_records
            return records

        snap = gdt.capture_live_snapshot(query_fn, "u1", "p1")
        self.assertEqual(len(snap["nodes"]), 2)
        self.assertEqual(snap["relationships"][0]["type"], "RESOLVES_TO")
        # And it diffs against a snapshot payload using export ids cleanly.
        other = payload([node(["Subdomain"], {"name": "a.example.com"}, "z1")], [])
        diff = gdt.compute_diff(other, snap)
        self.assertEqual(diff["summary"]["totals"]["nodes_added"], 1)
        self.assertEqual(diff["relationships"]["added"], {"RESOLVES_TO": 1})


class TestReadOnlyByConstruction(unittest.TestCase):
    """DOD: READ-ONLY tuyệt đối — reviewer-grep automated."""

    def test_module_source_has_no_write_operations(self):
        src = open(gdt.__file__, encoding="utf-8").read()
        found = re.findall(r"\b(CREATE|MERGE|DETACH\s+DELETE|DELETE|REMOVE|SET)\b", src)
        self.assertEqual(found, [], f"write-operation keywords found in graph_diff_tool: {found}")

    def test_cypher_constants_are_match_only(self):
        for cypher in (gdt.LIVE_CAPTURE_CYPHER, gdt.LIVE_CAPTURE_RELS_CYPHER):
            self.assertTrue(cypher.lstrip().startswith("MATCH"))
            self.assertNotRegex(cypher, r"\b(CREATE|MERGE|DETACH|DELETE|REMOVE|SET)\b")


class TestPhaseGateInformationalOnly(unittest.TestCase):
    """DOD: test âm — graph_diff chỉ informational."""

    def test_tool_phase_map_entry(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        self.assertEqual(DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"].get("graph_diff"),
                         ["informational"])

    def test_is_tool_allowed_matrix(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase("graph_diff", "informational"))
        self.assertFalse(is_tool_allowed_in_phase("graph_diff", "exploitation"))
        self.assertFalse(is_tool_allowed_in_phase("graph_diff", "post_exploitation"))


class TestExecutorRefusal(unittest.IsolatedAsyncioTestCase):
    """DOD: gọi tool ở phase exploitation → bị từ chối, không chạm Neo4j."""

    def setUp(self):
        import tools as tools_module
        self.executor = tools_module.PhaseAwareToolExecutor(
            mcp_manager=MagicMock(), graph_tool=None,
        )
        self.assertIn("graph_diff", self.executor._all_tools)
        # Under the stubs the langchain @tool decorator is an identity shim, so
        # the registered entry is a bare coroutine function; give it the
        # .ainvoke surface the executor's dispatch expects.
        raw = self.executor._all_tools["graph_diff"]

        class _ToolShim:
            async def ainvoke(self, args):
                return await raw(**args)

        self.executor._all_tools["graph_diff"] = _ToolShim()

    async def test_refused_outside_informational(self):
        result = await self.executor.execute(
            "graph_diff", {"mode": "last_two"}, phase="exploitation",
        )
        self.assertFalse(result["success"])
        self.assertIn("not allowed", result["error"])
        self.assertIn("informational", result["error"])
        self.assertIsNone(result["output"])

    async def test_dispatch_reaches_tool_without_stack(self):
        # In informational the dispatch reaches the tool itself; an unknown
        # mode returns a structured JSON error without touching any database.
        import agent_context
        agent_context.current_user_id.set("u-test")
        agent_context.current_project_id.set("p-test")
        result = await self.executor.execute(
            "graph_diff", {"mode": "nonsense"}, phase="informational",
        )
        self.assertTrue(result["success"])
        self.assertIn("unknown mode", result["output"])


if __name__ == "__main__":
    unittest.main()

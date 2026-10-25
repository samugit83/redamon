"""
Unit tests for bloodhound_ingest — hermetic.

Parser/streamer/normalizer run on synthetic BloodHound-4 collector data; the
phase gate, DANGEROUS_TOOLS membership, acknowledged-refusal and path-safety
tests stub the heavy imports exactly like tests/test_executor_workspace_wiring.
No Neo4j, no Postgres (the recorder run_write captures Cypher instead).

Run with: python3 -m unittest tests.test_bloodhound_ingest -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from types import ModuleType
from unittest.mock import MagicMock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

# Real import BEFORE the stubs below replace sys.modules["prompts"] with a
# MagicMock (which would shadow the package for `prompts.tool_registry`).
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402

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

import bloodhound_ingest_tool as bhi  # noqa: E402

import workspace_fs  # noqa: E402  (path safety tests point it at a temp root)


# --- synthetic BloodHound-4 fixtures (domain corp.example.com) --------------

USER = {
    "ObjectIdentifier": "S-1-5-21-1000-1105",
    "Properties": {
        "name": "JSMITH@CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM",
        "samaccountname": "jsmith", "enabled": True,
    },
    "MemberOf": [{"ObjectIdentifier": "S-1-5-21-1000-1108", "ObjectType": "Group"}],
}
GROUP_NESTED = {
    "ObjectIdentifier": "S-1-5-21-1000-1108",
    "Properties": {"name": "HELP DESK@CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM"},
    "MemberOf": [{"ObjectIdentifier": "S-1-5-21-1000-512", "ObjectType": "Group"}],
    "Members": [
        {"ObjectIdentifier": "S-1-5-21-1000-1105", "ObjectType": "User"},
    ],
}
COMPUTER = {
    "ObjectIdentifier": "S-1-5-21-1000-2101",
    "Properties": {"name": "WS01.CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM",
                   "operatingsystem": "Windows 10 Pro"},
    "Sessions": [{"UserId": "S-1-5-21-1000-1105", "ComputerId": "S-1-5-21-1000-2101"}],
}


def write_collector_dir(tmp: str):
    files = {}
    for suffix, data in (
        ("users.json", [USER]),
        ("groups.json", [GROUP_NESTED]),
        ("computers.json", [COMPUTER]),
    ):
        path = os.path.join(tmp, f"20261025120000_{suffix}")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"data": data, "meta": {"type": suffix[:-5], "count": len(data),
                                              "version": 4}}, fh)
        files[suffix] = path
    return files


class TestParser(unittest.TestCase):
    def test_normalize_user(self):
        props = bhi.normalize_record("user", USER)
        self.assertEqual(props["object_identifier"], "S-1-5-21-1000-1105")
        self.assertEqual(props["name"], "JSMITH@CORP.EXAMPLE.COM")
        self.assertEqual(props["domain"], "CORP.EXAMPLE.COM")
        self.assertTrue(props["enabled"])

    def test_malformed_records_return_none(self):
        self.assertIsNone(bhi.normalize_record("user", {}))
        self.assertIsNone(bhi.normalize_record("user", {"Properties": "garbage"}))
        self.assertIsNone(bhi.normalize_record(
            "user", {"ObjectIdentifier": "S-1", "Properties": {"nodomain": 1}}))

    def test_edges_memberof_members_session(self):
        edges = bhi.extract_edges("user", USER)
        self.assertIn(("ADUser", "S-1-5-21-1000-1105", "MEMBER_OF",
                       "ADGroup", "S-1-5-21-1000-1108"), edges)
        edges_g = bhi.extract_edges("group", GROUP_NESTED)
        self.assertIn(("ADGroup", "S-1-5-21-1000-1108", "MEMBER_OF",
                       "ADGroup", "S-1-5-21-1000-512"), edges_g)
        self.assertIn(("ADGroup", "S-1-5-21-1000-1108", "HAS_MEMBER",
                       "ADUser", "S-1-5-21-1000-1105"), edges_g)
        edges_c = bhi.extract_edges("computer", COMPUTER)
        self.assertIn(("ADUser", "S-1-5-21-1000-1105", "HAS_SESSION",
                       "ADComputer", "S-1-5-21-1000-2101"), edges_c)

    def test_legacy_string_session(self):
        legacy = {"ObjectIdentifier": "S-1-5-21-1000-2101", "Properties":
                  {"name": "WS02.CORP.EXAMPLE.COM"}, "Sessions": ["CORP\\jsmith"]}
        edges = bhi.extract_edges("computer", legacy)
        self.assertEqual(edges, [("ADUser", "CORP\\JSMITH", "HAS_SESSION",
                                  "ADComputer", "S-1-5-21-1000-2101")])

    def test_classify_file(self):
        self.assertEqual(bhi.classify_file("2026_users.json"), "user")
        self.assertEqual(bhi.classify_file("SharpHound_groups.json"), "group")
        self.assertEqual(bhi.classify_file("20261025_computers.json"), "computer")
        self.assertIsNone(bhi.classify_file("20261025_domains.json"))
        self.assertIsNone(bhi.classify_file("notes.txt"))


class TestStreaming(unittest.TestCase):
    def test_iter_data_array_yields_only_data_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x_users.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"data": [USER, GROUP_NESTED], "meta": {"type": "users"}}, fh)
            got = list(bhi.iter_data_array(path))
            self.assertEqual(len(got), 2)
            self.assertEqual(got[0]["ObjectIdentifier"], USER["ObjectIdentifier"])

    def test_iter_handles_multi_chunk_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big_users.json")
            records = [{"ObjectIdentifier": f"S-1-5-21-1000-{1000+i}",
                        "Properties": {"name": f"U{i:06d}@CORP.EXAMPLE.COM",
                                       "pad": "x" * 512}}
                       for i in range(3000)]
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"data": records, "meta": {}}, fh)
            # tiny chunk size forces many reads per record
            got = list(bhi.iter_data_array(path, chunk_size=4096))
            self.assertEqual(len(got), 3000)
            self.assertEqual(got[-1]["Properties"]["name"],
                             "U002999@CORP.EXAMPLE.COM")

    def test_no_data_marker_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "weird.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"something": [1,2,3], "meta": {}}')
            self.assertEqual(list(bhi.iter_data_array(path)), [])


class TestIngestFilesViaRecorder(unittest.TestCase):
    def test_counts_and_cypher_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = write_collector_dir(tmp)
            run_log = []

            def run_write(cypher, params):
                run_log.append((cypher, params))

            counts = bhi.ingest_files(
                run_write, "u1", "p1",
                [(files["users.json"], "user"), (files["groups.json"], "group"),
                 (files["computers.json"], "computer")],
            )
            self.assertEqual(counts["records"], 3)
            self.assertEqual(counts["skipped"], 0)
            self.assertEqual(counts["nodes_ADUser"], 1)
            self.assertEqual(counts["nodes_ADGroup"], 1)
            self.assertEqual(counts["nodes_ADComputer"], 1)
            self.assertEqual(counts["rels_MEMBER_OF"], 2)
            self.assertEqual(counts["rels_HAS_MEMBER"], 1)
            self.assertEqual(counts["rels_HAS_SESSION"], 1)
            merged = " ".join(c for c, _ in run_log)
            self.assertIn("MERGE (n:ADUser", merged)
            self.assertIn("MERGE (a)-[r:MEMBER_OF]->(b)", merged)
            for cypher, params in run_log:
                self.assertEqual(params["user_id"], "u1")
                self.assertEqual(params["project_id"], "p1")
            # Second ingest queues the same batches (MERGE idempotence is
            # asserted on a real database in the integration file).
            counts2 = bhi.ingest_files(
                run_write, "u1", "p1",
                [(files["users.json"], "user"), (files["groups.json"], "group"),
                 (files["computers.json"], "computer")],
            )
            self.assertEqual(counts2["nodes_ADUser"], counts["nodes_ADUser"])


class TestPathSafety(unittest.TestCase):
    def setUp(self):
        import pathlib

        import agent_context

        self._orig = workspace_fs.WORKSPACE_ROOT
        self.tmp = tempfile.mkdtemp(prefix="wi2-ws-")
        # _workspace_root() derives from current_project_id; give this test a
        # project scope and put the collectors under it.
        agent_context.current_project_id.set("p-ws2")
        self.ws_root = __import__("pathlib").Path(self.tmp) / "p-ws2"
        self.ws_root.mkdir(parents=True, exist_ok=True)
        workspace_fs.WORKSPACE_ROOT = pathlib.Path(self.tmp)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            bhi.collect_files("../../etc/passwd")

    def test_absolute_outside_workspace_rejected(self):
        with self.assertRaises(ValueError):
            bhi.collect_files("/etc/passwd")

    def test_missing_path_rejected(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            bhi.collect_files("nope/does_not_exist_users.json")

    def test_directory_and_single_file(self):
        write_collector_dir(str(self.ws_root))
        found = bhi.collect_files(".")
        self.assertEqual(len(found), 3)
        kinds = {k for _, k in found}
        self.assertEqual(kinds, {"user", "group", "computer"})
        single = bhi.collect_files("20261025120000_users.json")
        self.assertEqual(single[0][1], "user")


class TestPhaseAndDanger(unittest.TestCase):
    def test_phase_map_post_exploitation_only(self):
        from project_settings import DEFAULT_AGENT_SETTINGS, is_tool_allowed_in_phase
        self.assertEqual(DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"].get("bloodhound_ingest"),
                         ["post_exploitation"])
        self.assertFalse(is_tool_allowed_in_phase("bloodhound_ingest", "informational"))
        self.assertFalse(is_tool_allowed_in_phase("bloodhound_ingest", "exploitation"))
        self.assertTrue(is_tool_allowed_in_phase("bloodhound_ingest", "post_exploitation"))

    def test_is_dangerous(self):
        from project_settings import DANGEROUS_TOOLS
        self.assertIn("bloodhound_ingest", DANGEROUS_TOOLS)

    def test_registry_entry_complete(self):
        entry = TOOL_REGISTRY.get("bloodhound_ingest")
        self.assertIsNotNone(entry)
        for field in ("purpose", "when_to_use", "args_format", "description"):
            self.assertIn(field, entry)
        self.assertGreaterEqual(len(entry["description"]), 100)


class TestExecutorRefusalAndAckGate(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        import tools as tools_module
        self.executor = tools_module.PhaseAwareToolExecutor(
            mcp_manager=MagicMock(), graph_tool=None,
        )
        self.assertIn("bloodhound_ingest", self.executor._all_tools)
        raw = self.executor._all_tools["bloodhound_ingest"]

        class _ToolShim:
            async def ainvoke(self, args):
                return await raw(**args)

        self.executor._all_tools["bloodhound_ingest"] = _ToolShim()

    async def test_refused_outside_post_exploitation(self):
        for phase in ("informational", "exploitation"):
            result = await self.executor.execute(
                "bloodhound_ingest", {"path": "x_users.json", "acknowledged": True},
                phase=phase,
            )
            self.assertFalse(result["success"], phase)
            self.assertIn("not allowed", result["error"])

    async def test_acknowledged_false_refuses_without_touching_neo4j(self):
        # No NEO4J_URI in this process: if the tool tried to connect before the
        # acknowledgement check, the test would fail with a config error
        # instead of the clean refusal.
        import agent_context
        agent_context.current_user_id.set("u-test")
        agent_context.current_project_id.set("p-test")
        result = await self.executor.execute(
            "bloodhound_ingest", {"path": "x_users.json"}, phase="post_exploitation",
        )
        self.assertTrue(result["success"])
        self.assertIn("acknowledged", result["output"])
        self.assertIn("dangerous", result["output"])


if __name__ == "__main__":
    unittest.main()

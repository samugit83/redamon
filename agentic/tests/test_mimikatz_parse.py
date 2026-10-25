"""
Unit tests for mimikatz_parse — hermetic.

The parser is a pure function; fixtures are SYNTHETIC transcripts for domain
corp.example.com (no real credentials). Log-safety DOD: the serialized tool
response and captured stdout must never contain a fixture secret value, and
the module must not log at all. Phase gate / DANGEROUS_TOOLS / acknowledged
refusal follow the stub pattern of test_executor_workspace_wiring.py.

Run with: python3 -m unittest tests.test_mimikatz_parse -v
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402  (before stubs)

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

import mimikatz_parse_tool as mpt  # noqa: E402

import workspace_fs  # noqa: E402

# --- SYNTHETIC fixture values (corp.example.com; NOT real credentials) ------

JSMITH_NTLM = "abc123def456abc123def456abc12345"
JSMITH_LM = "def456abc123def456abc123def45678"
JSMITH_SHA1 = "aa11bb22cc33dd44ee55"
JSMITH_CLEAR = "Sup3rSynthetic!"
ADMIN_NTLM = "0123456789abcdef0123456789abcdef"
SVCWEB_NTLM = "fedcba9876543210fedcba9876543210"
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
ALL_SECRETS = [JSMITH_NTLM, JSMITH_LM, JSMITH_SHA1, JSMITH_CLEAR, ADMIN_NTLM,
               SVCWEB_NTLM]

LOGONPASSWORDS = f"""
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : Interactive from 1
User Name         : jsmith
Domain            : CORP
Logon Server      : DC01
    msv1_0:
     * Username : jsmith
     * Domain   : CORP
     * LM       : {EMPTY_LM}
     * NTLM     : {JSMITH_NTLM}
     * SHA1     : {JSMITH_SHA1}
    wdigest:
     * Username : jsmith
     * Domain   : CORP
     * Password : {JSMITH_CLEAR}
"""

SAM_DUMP = f"""
Domain : CORP
RID  : 000001f4 (500)
User : Administrator
  Hash LM  : {JSMITH_LM}
  Hash NTLM: {ADMIN_NTLM}
"""

DCSYNC = f"""
[DC] 'corp.example.com' will be the domain
[DC] 'DC01.corp.example.com' will be the DC server

Object RDN           : svc-web

** SAM ACCOUNT **
SamAccountName         : svc-web
objectSid              : S-1-5-21-1000-1106
Hash NTLM: {SVCWEB_NTLM}
lm  - 0: {JSMITH_LM}
"""


class TestParserThreeFormats(unittest.TestCase):
    def test_logonpasswords(self):
        creds = mpt.parse_mimikatz(LOGONPASSWORDS)
        by = {(c["kind"], c["value"]): c for c in creds}
        self.assertIn(("ntlm", JSMITH_NTLM), by)
        self.assertEqual(by[("ntlm", JSMITH_NTLM)]["username"], "jsmith")
        self.assertEqual(by[("ntlm", JSMITH_NTLM)]["domain"], "CORP")
        self.assertIn(("sha1", JSMITH_SHA1), by)
        self.assertIn(("plaintext", JSMITH_CLEAR), by)
        # The empty-LM sentinel must be skipped, not stored.
        kinds_values = {(c["kind"], c["value"]) for c in creds}
        self.assertNotIn(("lm", EMPTY_LM), kinds_values)

    def test_lsadump_sam(self):
        creds = mpt.parse_mimikatz(SAM_DUMP)
        by = {(c["kind"], c["value"]): c for c in creds}
        self.assertIn(("ntlm", ADMIN_NTLM), by)
        self.assertEqual(by[("ntlm", ADMIN_NTLM)]["username"], "Administrator")
        self.assertEqual(by[("ntlm", ADMIN_NTLM)]["rid"], 500)
        self.assertIn(("lm", JSMITH_LM), by)

    def test_lsadump_dcsync(self):
        creds = mpt.parse_mimikatz(DCSYNC)
        by = {(c["kind"], c["value"]): c for c in creds}
        self.assertIn(("ntlm", SVCWEB_NTLM), by)
        self.assertEqual(by[("ntlm", SVCWEB_NTLM)]["username"], "svc-web")
        self.assertEqual(by[("ntlm", SVCWEB_NTLM)]["domain"], "corp.example.com")
        self.assertIn(("lm", JSMITH_LM), by)

    def test_garbage_and_incomplete_never_crash(self):
        self.assertEqual(mpt.parse_mimikatz(""), [])
        self.assertEqual(mpt.parse_mimikatz("\x00\x01 random noise\n[[[\n"), [])
        self.assertEqual(mpt.parse_mimikatz("Total 0\nNo credentials\n"), [])
        # A password line with no principal in scope is not reusable -> skipped.
        self.assertEqual(mpt.parse_mimikatz(f" * Password : orphan{JSMITH_CLEAR}\n"), [])

    def test_duplicates_collapsed(self):
        twice = LOGONPASSWORDS + LOGONPASSWORDS
        creds = mpt.parse_mimikatz(twice)
        keys = [(c["kind"], c["value"], c["username"], c["domain"]) for c in creds]
        self.assertEqual(len(keys), len(set((k[0], k[1], k[2].lower(), k[3].lower())
                                            for k in keys)))


class TestSummarizeCountsOnly(unittest.TestCase):
    def test_summary_shape(self):
        summary = mpt.summarize(mpt.parse_mimikatz(LOGONPASSWORDS))
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_kind"]["ntlm"], 1)
        self.assertEqual(summary["by_kind"]["sha1"], 1)
        self.assertEqual(summary["by_kind"]["plaintext"], 1)
        # Counts only: no secret value may serialize into the summary.
        self.assertNotIn(JSMITH_NTLM, json.dumps(summary))
        self.assertNotIn(JSMITH_CLEAR, json.dumps(summary))


class TestLogSafetyDOD(unittest.TestCase):
    """DOD: không credential nào rơi vào log công khai."""

    def test_ingest_summary_and_stdout_carry_no_secret_values(self):
        creds = mpt.parse_mimikatz(LOGONPASSWORDS + SAM_DUMP + DCSYNC)
        run_log = []

        def run_write(cypher, params):
            run_log.append((cypher, params))

        buf = io.StringIO()
        with redirect_stdout(buf):
            summary = mpt.ingest_credentials(run_write, "u1", "p1", creds,
                                             origin_host="ws01.corp.example.com")
        serialized = json.dumps(summary) + buf.getvalue()
        for secret in ALL_SECRETS + [EMPTY_LM]:
            self.assertNotIn(secret, serialized, f"secret leaked into output/log")
        # Params DO carry values (they go to Neo4j, the allowed place) — the
        # public surface (summary/stdout) is what must stay clean.

    def test_module_has_no_logging(self):
        src = open(mpt.__file__, encoding="utf-8").read()
        self.assertIsNone(re.search(r"\b(logging|logger|print)\s*\(", src),
                          "mimikatz_parse must not log (values could leak)")


class TestPathSafety(unittest.TestCase):
    def setUp(self):
        import pathlib

        import agent_context

        self._orig = workspace_fs.WORKSPACE_ROOT
        self.tmp = tempfile.mkdtemp(prefix="wi3-ws-")
        agent_context.current_project_id.set("p-ws3")
        self.ws_root = pathlib.Path(self.tmp) / "p-ws3"
        self.ws_root.mkdir(parents=True, exist_ok=True)
        workspace_fs.WORKSPACE_ROOT = pathlib.Path(self.tmp)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            mpt._read_workspace_file("../../etc/passwd")

    def test_reads_workspace_file(self):
        (self.ws_root / "dump.txt").write_text(LOGONPASSWORDS, encoding="utf-8")
        text = mpt._read_workspace_file("dump.txt")
        self.assertIn("sekurlsa", text)


class TestPhaseAndDanger(unittest.TestCase):
    def test_phase_map_post_exploitation_only(self):
        from project_settings import DEFAULT_AGENT_SETTINGS, is_tool_allowed_in_phase
        self.assertEqual(DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"].get("mimikatz_parse"),
                         ["post_exploitation"])
        self.assertFalse(is_tool_allowed_in_phase("mimikatz_parse", "informational"))
        self.assertFalse(is_tool_allowed_in_phase("mimikatz_parse", "exploitation"))
        self.assertTrue(is_tool_allowed_in_phase("mimikatz_parse", "post_exploitation"))

    def test_is_dangerous(self):
        from project_settings import DANGEROUS_TOOLS
        self.assertIn("mimikatz_parse", DANGEROUS_TOOLS)

    def test_registry_entry_complete(self):
        entry = TOOL_REGISTRY.get("mimikatz_parse")
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
        self.assertIn("mimikatz_parse", self.executor._all_tools)
        raw = self.executor._all_tools["mimikatz_parse"]

        class _ToolShim:
            async def ainvoke(self, args):
                return await raw(**args)

        self.executor._all_tools["mimikatz_parse"] = _ToolShim()

    async def test_refused_outside_post_exploitation(self):
        for phase in ("informational", "exploitation"):
            result = await self.executor.execute(
                "mimikatz_parse", {"path": "dump.txt", "acknowledged": True},
                phase=phase,
            )
            self.assertFalse(result["success"], phase)
            self.assertIn("not allowed", result["error"])

    async def test_acknowledged_false_refuses_without_touching_neo4j(self):
        # No NEO4J_URI here: reaching for a connection would fail the test
        # with a config error instead of the clean refusal.
        import agent_context
        agent_context.current_user_id.set("u-test")
        agent_context.current_project_id.set("p-test")
        result = await self.executor.execute(
            "mimikatz_parse", {"path": "dump.txt"}, phase="post_exploitation",
        )
        self.assertTrue(result["success"])
        self.assertIn("acknowledged", result["output"])
        self.assertIn("dangerous", result["output"])


if __name__ == "__main__":
    unittest.main()

"""
Integration tests for mimikatz_parse on a REAL Neo4j (acceptance).

DOD coverage:
  - E2E tool call (workspace file -> parse -> Credential nodes + ORIGIN edge to
    a host the graph already knows); fixtures are synthetic corp.example.com
    transcripts
  - idempotency: same transcript twice -> identical counts
  - log-safety on the E2E path: the tool RESPONSE contains no secret value
    while the graph DOES hold it
  - acknowledged=False -> refusal, graph unchanged

Self-skips unless REDAMON_TEST_NEO4J_URI is set. Use a THROWAWAY Neo4j.

Run with: python -m pytest tests/mimikatz_parse_integration.py -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

_NEO4J_URI = os.environ.get("REDAMON_TEST_NEO4J_URI", "")
_NEO4J_USER = os.environ.get("REDAMON_TEST_NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.environ.get("REDAMON_TEST_NEO4J_PASSWORD", "")

if not _NEO4J_URI:
    raise unittest.SkipTest("REDAMON_TEST_NEO4J_URI not set — needs a throwaway Neo4j")

os.environ["NEO4J_URI"] = _NEO4J_URI
os.environ["NEO4J_USER"] = _NEO4J_USER
os.environ["NEO4J_PASSWORD"] = _NEO4J_PASSWORD

from neo4j import GraphDatabase  # noqa: E402

import mimikatz_parse_tool as mpt  # noqa: E402
import workspace_fs  # noqa: E402

HOST = "ws01.corp.example.com"
JSMITH_NTLM = "abc123def456abc123def456abc12345"
JSMITH_CLEAR = "Sup3rSynthetic!"
ADMIN_NTLM = "0123456789abcdef0123456789abcdef"
SECRETS = [JSMITH_NTLM, JSMITH_CLEAR, ADMIN_NTLM]

TRANSCRIPT = f"""
Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : Interactive from 1
User Name         : jsmith
Domain            : CORP
    msv1_0:
     * Username : jsmith
     * Domain   : CORP
     * NTLM     : {JSMITH_NTLM}
    wdigest:
     * Username : jsmith
     * Domain   : CORP
     * Password : {JSMITH_CLEAR}

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: {ADMIN_NTLM}
"""


class MimikatzParseIntegration(unittest.TestCase):
    def setUp(self):
        import asyncio

        import agent_context

        self.user_id = f"wi3-u-{uuid.uuid4().hex[:8]}"
        self.project_id = f"wi3-p-{uuid.uuid4().hex[:8]}"
        agent_context.current_user_id.set(self.user_id)
        agent_context.current_project_id.set(self.project_id)

        self.driver = GraphDatabase.driver(_NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASSWORD))
        self.session = self.driver.session()
        self.addCleanup(self._cleanup)
        # The origin host must pre-exist for the ORIGIN edge to attach.
        self.session.run(
            "CREATE (:Subdomain {name: $host, user_id: $u, project_id: $p})",
            host=HOST, u=self.user_id, p=self.project_id).consume()

        self._orig_ws = workspace_fs.WORKSPACE_ROOT
        self.tmp = tempfile.mkdtemp(prefix="wi3-ws-")
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        root = Path(self.tmp) / self.project_id
        root.mkdir(parents=True, exist_ok=True)
        (root / "dump.txt").write_text(TRANSCRIPT, encoding="utf-8")

        self.tool = mpt.build_mimikatz_parse_tool()

    def _cleanup(self):
        self.session.run(
            "MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
            u=self.user_id, p=self.project_id).consume()
        self.session.close()
        self.driver.close()
        workspace_fs.WORKSPACE_ROOT = self._orig_ws

    def _call(self, acknowledged=True):
        import asyncio

        if hasattr(self.tool, "ainvoke"):
            out = asyncio.run(self.tool.ainvoke(
                {"path": "dump.txt", "origin_host": HOST, "acknowledged": acknowledged}))
        else:
            out = asyncio.run(self.tool(path="dump.txt", origin_host=HOST,
                                        acknowledged=acknowledged))
        return json.loads(out)

    def cred_counts(self):
        rec = self.session.run(
            "MATCH (c:Credential) WHERE c.user_id = $u AND c.project_id = $p "
            "OPTIONAL MATCH (c)-[r:ORIGIN]->() "
            "RETURN count(DISTINCT c) AS creds, count(DISTINCT r) AS origins",
            u=self.user_id, p=self.project_id).single()
        return (rec["creds"], rec["origins"])

    def test_e2e_counts_only_response_and_graph_holds_values(self):
        summary = self._call()
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_kind"]["ntlm"], 2)
        self.assertEqual(summary["by_kind"]["plaintext"], 1)
        # Log-safety DOD on the E2E response:
        for secret in SECRETS:
            self.assertNotIn(secret, json.dumps(summary))
        # The graph DOES hold the full values (that is the allowed place).
        stored = self.session.run(
            "MATCH (c:Credential {value: $v, user_id: $u, project_id: $p}) "
            "RETURN count(c) AS n", v=JSMITH_NTLM, u=self.user_id,
            p=self.project_id).single()
        self.assertEqual(stored["n"], 1)
        # Nodes + ORIGIN edges to the known host.
        self.assertEqual(self.cred_counts(), (3, 3))

    def test_idempotent_rerun(self):
        self._call()
        before = self.cred_counts()
        summary2 = self._call()
        self.assertEqual(summary2["total"], 3)
        self.assertEqual(self.cred_counts(), before)

    def test_acknowledged_false_refusal_leaves_graph_unchanged(self):
        before = self.cred_counts()
        payload = self._call(acknowledged=False)
        self.assertIn("error", payload)
        self.assertIn("acknowledged", payload["error"])
        self.assertEqual(self.cred_counts(), before)


if __name__ == "__main__":
    unittest.main()

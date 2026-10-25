"""
Integration tests for bloodhound_ingest on a REAL Neo4j (acceptance).

DOD coverage:
  - ingest fixture collector files (corp.example.com, synthetic) -> AD nodes +
    relationships appear, tenant-scoped
  - idempotency: ingest the SAME files twice -> node/relationship counts equal
  - pathfinder DOD: shortestPath from a normal user to Domain Admins over the
    ingested MEMBER_OF edges exists (the bhgraph CLI equivalent; bhgraph lives
    in the Kali image, not the agent image, so the proof is the equivalent
    Cypher over the same data)
  - approval-refusal DOD: acknowledged=False -> error, graph counts unchanged
  - tenant isolation: another project sees none of the nodes

Self-skips unless REDAMON_TEST_NEO4J_URI is set. Use a THROWAWAY Neo4j.

Run with: python -m pytest tests/bloodhound_ingest_integration.py -v
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
import uuid

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

_NEO4J_URI = os.environ.get("REDAMON_TEST_NEO4J_URI", "")
_NEO4J_USER = os.environ.get("REDAMON_TEST_NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.environ.get("REDAMON_TEST_NEO4J_PASSWORD", "")

if not _NEO4J_URI:
    raise unittest.SkipTest("REDAMON_TEST_NEO4J_URI not set — needs a throwaway Neo4j")

from neo4j import GraphDatabase  # noqa: E402

import bloodhound_ingest_tool as bhi  # noqa: E402

S_USER = "S-1-5-21-1000-1105"
S_HELPDESK = "S-1-5-21-1000-1108"
S_DA = "S-1-5-21-1000-512"
S_COMP = "S-1-5-21-1000-2101"


def fixture_dir() -> str:
    users = [{
        "ObjectIdentifier": S_USER,
        "Properties": {"name": "JSMITH@CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM",
                       "samaccountname": "jsmith", "enabled": True},
        "MemberOf": [{"ObjectIdentifier": S_HELPDESK, "ObjectType": "Group"}],
    }]
    groups = [
        {"ObjectIdentifier": S_HELPDESK,
         "Properties": {"name": "HELP DESK@CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM"},
         "MemberOf": [{"ObjectIdentifier": S_DA, "ObjectType": "Group"}],
         "Members": [{"ObjectIdentifier": S_USER, "ObjectType": "User"}]},
        {"ObjectIdentifier": S_DA,
         "Properties": {"name": "DOMAIN ADMINS@CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM",
                        "admincount": 1},
         "Members": [{"ObjectIdentifier": S_HELPDESK, "ObjectType": "Group"}]},
    ]
    computers = [{
        "ObjectIdentifier": S_COMP,
        "Properties": {"name": "WS01.CORP.EXAMPLE.COM", "domain": "CORP.EXAMPLE.COM",
                       "operatingsystem": "Windows 10 Pro"},
        "Sessions": [{"UserId": S_USER, "ComputerId": S_COMP}],
    }]
    tmp = tempfile.mkdtemp(prefix="wi2-bh-")
    for suffix, data in (("users", users), ("groups", groups), ("computers", computers)):
        with open(os.path.join(tmp, f"20261025120000_{suffix}.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"data": data, "meta": {"type": suffix, "count": len(data),
                                              "version": 4}}, fh)
    return tmp


class BloodhoundIngestIntegration(unittest.TestCase):
    def setUp(self):
        self.user_id = f"wi2-u-{uuid.uuid4().hex[:8]}"
        self.project_id = f"wi2-p-{uuid.uuid4().hex[:8]}"
        self.driver = GraphDatabase.driver(_NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASSWORD))
        self.session = self.driver.session()
        self.addCleanup(self._cleanup)
        self.files_dir = fixture_dir()

    def _cleanup(self):
        self.session.run(
            "MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
            u=self.user_id, p=self.project_id).consume()
        self.session.close()
        self.driver.close()

    def _files(self):
        return [
            (os.path.join(self.files_dir, "20261025120000_users.json"), "user"),
            (os.path.join(self.files_dir, "20261025120000_groups.json"), "group"),
            (os.path.join(self.files_dir, "20261025120000_computers.json"), "computer"),
        ]

    def _ingest(self):
        return bhi.ingest_files(
            lambda cypher, params: self.session.run(cypher, params).consume(),
            self.user_id, self.project_id, self._files(),
        )

    def counts(self):
        rec = self.session.run(
            "MATCH (n) WHERE n.user_id = $u AND n.project_id = $p "
            "OPTIONAL MATCH (n)-[r]->(m) WHERE m.user_id = $u AND m.project_id = $p "
            "RETURN count(DISTINCT n) AS nodes, count(DISTINCT r) AS rels",
            u=self.user_id, p=self.project_id).single()
        return (rec["nodes"], rec["rels"])

    def test_ingest_creates_ad_graph_and_is_idempotent(self):
        counts1 = self._ingest()
        self.assertEqual(counts1["nodes_ADUser"], 1)
        self.assertEqual(counts1["nodes_ADGroup"], 2)
        self.assertEqual(counts1["nodes_ADComputer"], 1)
        before = self.counts()
        # 4 nodes; 5 rels: MEMBER_OF x2 (jsmith->Help Desk, Help Desk->DA),
        # HAS_MEMBER x2 (Help Desk->jsmith, DA->Help Desk), HAS_SESSION x1.
        self.assertEqual(before, (4, 5))

        # Idempotency DOD: same files again -> identical graph size.
        counts2 = self._ingest()
        after = self.counts()
        self.assertEqual(before, after)
        self.assertEqual(counts2["nodes_ADGroup"], counts1["nodes_ADGroup"])

    def test_pathfinder_shortest_path_to_domain_admins(self):
        self._ingest()
        rec = self.session.run(
            "MATCH (u:ADUser {object_identifier: $sid, user_id: $u, project_id: $p}) "
            "MATCH (g:ADGroup {object_identifier: $da, user_id: $u, project_id: $p}) "
            "MATCH path = shortestPath((u)-[:MEMBER_OF*1..]->(g)) "
            "RETURN [n IN nodes(path) | coalesce(n.name, n.object_identifier)] AS hops",
            sid=S_USER, da=S_DA, u=self.user_id, p=self.project_id).single()
        self.assertIsNotNone(rec, "no path from jsmith to Domain Admins after ingest")
        self.assertEqual(len(rec["hops"]), 3)
        self.assertIn("DOMAIN ADMINS@CORP.EXAMPLE.COM", rec["hops"])

    def test_acknowledged_false_refusal_leaves_graph_unchanged(self):
        before = self.counts()
        tool = bhi.build_bloodhound_ingest_tool()
        out = asyncio.run(tool.ainvoke({
            "path": self.files_dir, "acknowledged": False,
            "__user_id": self.user_id,  # not read; contextvars drive tenancy
        })) if hasattr(tool, "ainvoke") else asyncio.run(
            tool(path=self.files_dir, acknowledged=False))
        payload = json.loads(out)
        self.assertIn("error", payload)
        self.assertIn("acknowledged", payload["error"])
        self.assertEqual(self.counts(), before)

    def test_tenant_isolation(self):
        self._ingest()
        other = self.session.run(
            "MATCH (n:ADUser) WHERE n.user_id = $u AND n.project_id = 'other-project' "
            "RETURN count(n) AS c", u=self.user_id).single()
        self.assertEqual(other["c"], 0)


if __name__ == "__main__":
    unittest.main()

"""
Integration tests for graph_diff against a REAL Neo4j (acceptance).

Covers what the hermetic unit file cannot:
  - live capture + diff on a real graph (added/removed/changed/relationships)
  - idempotence: running capture+diff repeatedly leaves the graph byte-for-byte
    unchanged (node/rel counts identical) — graph_diff is read-only
  - the ScanVersion loader round-trip (Postgres) with real gzip snapshot bytes

Self-skips unless REDAMON_TEST_NEO4J_URI is set (loader half also needs
REDAMON_TEST_PG_DSN). Point these at a THROWAWAY stack, never production:
the loader half INSERTs and DELETEs a scan_versions row. The tests write
fixture nodes directly through the driver — the graph_diff tool itself only
ever reads.

Run with: python -m pytest tests/graph_diff_integration.py -v
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import unittest
import uuid

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

_NEO4J_URI = os.environ.get("REDAMON_TEST_NEO4J_URI", "")
_NEO4J_USER = os.environ.get("REDAMON_TEST_NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.environ.get("REDAMON_TEST_NEO4J_PASSWORD", "")
_PG_DSN = os.environ.get("REDAMON_TEST_PG_DSN", "")

if not _NEO4J_URI:
    raise unittest.SkipTest("REDAMON_TEST_NEO4J_URI not set — needs a throwaway Neo4j")

from neo4j import GraphDatabase  # noqa: E402

import graph_diff_tool as gdt  # noqa: E402


class GraphDiffIntegrationBase(unittest.TestCase):
    def setUp(self):
        self.user_id = f"wi1-u-{uuid.uuid4().hex[:8]}"
        self.project_id = f"wi1-p-{uuid.uuid4().hex[:8]}"
        self.driver = GraphDatabase.driver(
            _NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASSWORD)
        )
        self.session = self.driver.session()
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.session.run(
            "MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
            u=self.user_id, p=self.project_id,
        ).consume()
        self.session.close()
        self.driver.close()

    def query_fn(self, cypher, params=None):
        return [dict(r) for r in self.session.run(cypher, params or {})]

    def counts(self):
        rec = self.session.run(
            "MATCH (n) WHERE n.user_id = $u AND n.project_id = $p "
            "OPTIONAL MATCH (n)-[r]->() WHERE n.user_id = $u AND n.project_id = $p "
            "RETURN count(DISTINCT n) AS nodes, count(r) AS rels",
            u=self.user_id, p=self.project_id,
        ).single()
        return (rec["nodes"], rec["rels"])

    def seed(self):
        self.session.run(
            "CREATE (s:Subdomain {name: $name, user_id: $u, project_id: $p}) "
            "CREATE (i:IP {address: $ip, user_id: $u, project_id: $p}) "
            "CREATE (s)-[:RESOLVES_TO]->(i)",
            name="live.example.com", ip="10.9.8.7", u=self.user_id, p=self.project_id,
        ).consume()


class TestLiveCaptureAndDiff(GraphDiffIntegrationBase):
    def test_added_changed_removed_and_relationships(self):
        self.seed()
        snap_a = gdt.capture_live_snapshot(self.query_fn, self.user_id, self.project_id)

        # Mutate: +1 node, change 1 prop, delete nothing yet, +1 rel target node.
        self.session.run(
            "MATCH (i:IP {address: $ip, user_id: $u, project_id: $p}) "
            "SET i.cidr = '10.9.8.0/24' "
            "WITH i "
            "CREATE (s2:Subdomain {name: 'fresh.example.com', user_id: $u, project_id: $p}) "
            "CREATE (s2)-[:RESOLVES_TO]->(i)",
            ip="10.9.8.7", u=self.user_id, p=self.project_id,
        ).consume()
        snap_b = gdt.capture_live_snapshot(self.query_fn, self.user_id, self.project_id)
        diff = gdt.compute_diff(snap_a, snap_b)
        self.assertEqual(diff["summary"]["totals"]["nodes_added"], 1)
        self.assertEqual(diff["summary"]["totals"]["nodes_changed"], 1)
        self.assertEqual(diff["summary"]["totals"]["nodes_removed"], 0)
        self.assertEqual(diff["relationships"]["added"], {"RESOLVES_TO": 1})

        # Remove a node -> next diff reports it gone with its relationship.
        self.session.run(
            "MATCH (s:Subdomain {name: 'fresh.example.com', user_id: $u, project_id: $p}) "
            "DETACH DELETE s",
            u=self.user_id, p=self.project_id,
        ).consume()
        snap_c = gdt.capture_live_snapshot(self.query_fn, self.user_id, self.project_id)
        diff2 = gdt.compute_diff(snap_b, snap_c)
        self.assertEqual(diff2["summary"]["totals"]["nodes_removed"], 1)
        self.assertEqual(diff2["relationships"]["removed"], {"RESOLVES_TO": 1})

    def test_session_labels_excluded_from_live_capture(self):
        self.session.run(
            "CREATE (:AttackChain {name: 'chain-x', user_id: $u, project_id: $p}) "
            "CREATE (:Subdomain {name: 'real.example.com', user_id: $u, project_id: $p})",
            u=self.user_id, p=self.project_id,
        ).consume()
        snap = gdt.capture_live_snapshot(self.query_fn, self.user_id, self.project_id)
        labels = [gdt.functional_label(n["labels"]) for n in snap["nodes"]]
        self.assertEqual(sorted(labels), ["Subdomain"])


class TestIdempotence(GraphDiffIntegrationBase):
    def test_repeated_diff_leaves_graph_unchanged(self):
        self.seed()
        before = self.counts()
        snap1 = gdt.capture_live_snapshot(self.query_fn, self.user_id, self.project_id)
        diff1 = gdt.compute_diff(snap1, snap1)
        snap2 = gdt.capture_live_snapshot(self.query_fn, self.user_id, self.project_id)
        diff2 = gdt.compute_diff(snap1, snap2)
        after = self.counts()
        self.assertEqual(before, after)
        self.assertEqual(diff1["summary"]["totals"]["nodes_added"], 0)
        self.assertEqual(diff2["summary"]["totals"],
                         {"nodes_added": 0, "nodes_removed": 0, "nodes_changed": 0,
                          "relationships_added": 0, "relationships_removed": 0})
        self.assertEqual(diff1["summary"]["side_b"]["nodes"],
                         diff2["summary"]["side_b"]["nodes"])


@unittest.skipUnless(_PG_DSN, "REDAMON_TEST_PG_DSN not set — loader half skipped")
class TestScanVersionLoader(unittest.TestCase):
    """Round-trip real gzip snapshot bytes through scan_versions (throwaway PG)."""

    def setUp(self):
        import psycopg

        self.project_id = f"wi1-pg-{uuid.uuid4().hex[:8]}"
        self.conn = psycopg.connect(_PG_DSN, autocommit=True)
        self.addCleanup(self._cleanup)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_versions ("
            "id text PRIMARY KEY, project_id text, seq int, label text, "
            "is_current boolean, node_count int, link_count int, "
            "snapshot bytea, created_at timestamptz DEFAULT now(), "
            "updated_at timestamptz DEFAULT now())"
        )
        self.payload = {
            "nodes": [
                {"labels": ["Subdomain"], "properties": {"name": "pg.example.com"},
                 "_exportId": "e1"},
            ],
            "relationships": [],
        }
        blob = gzip.compress(json.dumps(self.payload).encode("utf-8"))
        self.conn.execute(
            "INSERT INTO scan_versions (id, project_id, seq, label, is_current, snapshot) "
            "VALUES (%s, %s, %s, %s, false, %s)",
            (f"v-{self.project_id}", self.project_id, 7, "wi1 fixture", blob),
        )

    def _cleanup(self):
        self.conn.execute("DELETE FROM scan_versions WHERE project_id = %s",
                          (self.project_id,))
        self.conn.close()

    def test_load_by_seq_and_by_id(self):
        by_seq = gdt.load_version_snapshot(self.project_id, "7", dsn=_PG_DSN)
        self.assertEqual(by_seq["version"]["label"], "wi1 fixture")
        self.assertEqual(by_seq["payload"], self.payload)
        by_id = gdt.load_version_snapshot(
            self.project_id, f"v-{self.project_id}", dsn=_PG_DSN)
        self.assertEqual(by_id["payload"], self.payload)

    def test_unknown_version_raises_lookup_error(self):
        with self.assertRaises(LookupError):
            gdt.load_version_snapshot(self.project_id, "999", dsn=_PG_DSN)

    def test_list_versions_newest_first(self):
        versions = gdt.list_versions(self.project_id, dsn=_PG_DSN)
        self.assertEqual(versions[0]["seq"], 7)
        self.assertFalse(versions[0]["is_current"])


if __name__ == "__main__":
    unittest.main()

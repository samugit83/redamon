"""R-38, hermetic half: the prune and the revive read a restored `updated_at`.

A project export or scan-version snapshot stores DateTimes as ISO strings, and
graphs restored before the restore wrote DateTimes back keep them. Compared
with a DateTime a string is null in Cypher, so those findings were never
pruned, never stamped stale and never revived. The live proof is
tests/test_restored_timestamps_prune_graph_live.py; this pins, without Neo4j,
that both queries carry the string fallback and which strings it reads.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins import base_mixin  # noqa: E402
from graph_db.mixins.base_mixin import BaseMixin  # noqa: E402


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.queries.append((query, params))
        result = MagicMock()
        result.single.return_value = {"pruned": 0, "stale": 0, "revived": 0}
        return result


def _queries(**kwargs):
    client = BaseMixin.__new__(BaseMixin)
    queries = []
    client.driver = MagicMock()
    client.driver.session.side_effect = lambda: _Session(queries)
    client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00", **kwargs)
    return queries


class TestTheStringFallback(unittest.TestCase):
    def test_the_prune_reads_a_restored_string(self):
        revive, prune = _queries()
        self.assertIn(base_mixin._RESTORED_UPDATED_AT + " < datetime($since)", prune[0])
        self.assertIn("n.updated_at IS NULL OR n.updated_at < datetime($since)", prune[0])

    def test_the_revive_reads_a_restored_string(self):
        revive, _ = _queries()
        self.assertIn(base_mixin._RESTORED_UPDATED_AT + " >= datetime($since)", revive[0])
        self.assertIn("REMOVE n.stale_since", revive[0])

    def test_the_string_is_parsed_only_after_its_shape_is_checked(self):
        """datetime() raises on what it cannot parse, which would fail the
        whole prune: the CASE reads it only when the shape is right."""
        expr = base_mixin._RESTORED_UPDATED_AT
        self.assertTrue(expr.startswith("CASE WHEN n.updated_at IS :: STRING AND n.updated_at =~ '"))
        self.assertTrue(expr.endswith("THEN datetime(n.updated_at) END"))
        self.assertNotIn("\\", expr, "a backslash would need Cypher escaping")


class TestWhichStringsAreRead(unittest.TestCase):
    def _reads(self, value):
        return re.fullmatch(base_mixin._ISO_DATETIME, value) is not None

    def test_every_writer_s_shape_is_read(self):
        for value in (
            "2026-10-01T08:30:15Z",                # graphSerialize.ts
            "2026-10-01T08:30:15.123Z",            # JavaScript toISOString
            "2026-10-01T08:30:15.123456+00:00",    # Python isoformat()
            "2026-10-01T08:30:15+02:00",
            "2026-10-01T08:30:15.804000000Z",      # Cypher toString(datetime())
            "2026-10-01T08:30:15",                 # naive isoformat(): read as UTC
            "2026-10-01T08:30",
        ):
            with self.subTest(value=value):
                self.assertTrue(self._reads(value))

    def test_what_is_no_timestamp_is_not_parsed(self):
        for value in ("", "unknown", "2026-10-01", "2026-13-01T00:00:00Z",
                      "2026-10-01T24:00:00Z", "2026-10-01T08:30:15Z; DROP", "1696149015",
                      "2026-10-01 08:30:15"):
            with self.subTest(value=value):
                self.assertFalse(self._reads(value))


if __name__ == "__main__":
    unittest.main()

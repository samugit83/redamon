"""The positive-coverage prune query (design decision D1), without Neo4j.

`prune_unseen_findings(..., only_hosts=, types=)` deletes a source's stale
findings only on the hosts it re-checked, and only of the given types. A call
with neither is the older source-level query, byte for byte, so every caller
that has not adopted D1 behaves exactly as before. The Cypher's hostname
reading is proven against a real graph in tests/test_positive_prune_graph_live.py.
"""

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

SINCE = "2026-01-01T00:00:00+00:00"


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"pruned": 2, "stale": 1, "revived": 3}
        return result


def _prune(**kwargs):
    client = BaseMixin.__new__(BaseMixin)
    calls = []
    client.driver = MagicMock()
    client.driver.session.side_effect = lambda: _Session(calls)
    stats = client.prune_unseen_findings("u1", "p1", ["nuclei"], SINCE, **kwargs)
    return stats, calls


class TestNotAdoptedIsUnchanged(unittest.TestCase):
    def test_a_call_without_only_hosts_or_types_is_the_source_level_query(self):
        _, legacy = _prune(keep_hosts=["a.example.com"])
        _, explicit = _prune(keep_hosts=["a.example.com"], only_hosts=None, types=None)
        self.assertEqual(legacy, explicit)
        prune_query, params = legacy[1]
        self.assertNotIn("$only_hosts", prune_query)
        self.assertNotIn("$types", prune_query)
        self.assertEqual(set(params), {"uid", "pid", "sources", "since", "keep_patterns"})


class TestOnlyHosts(unittest.TestCase):
    def test_the_prune_is_limited_to_the_re_checked_hostnames(self):
        _, calls = _prune(only_hosts=["B.example.com", "a.example.com.", "198.51.100.7"])
        prune_query, params = calls[1]
        self.assertIn(base_mixin._ONLY_HOSTS_CLAUSE, prune_query)
        self.assertEqual(params["only_hosts"], ["198.51.100.7", "a.example.com", "b.example.com"])

    def test_a_kept_host_still_wins(self):
        _, calls = _prune(keep_hosts=["a.example.com"], only_hosts=["a.example.com"])
        prune_query, params = calls[1]
        self.assertIn("AND NOT any(rx IN $keep_patterns", prune_query)
        self.assertLess(prune_query.index("$keep_patterns"), prune_query.index("SET n._prune_lock"))
        self.assertLess(prune_query.index("$only_hosts"), prune_query.index("SET n._prune_lock"))
        self.assertIn("keep_patterns", params)

    def test_no_re_checked_host_prunes_nothing_but_still_revives(self):
        for only in ([], (), ["evil host", "a|b", "x'); DROP"]):
            with self.subTest(only=only):
                stats, calls = _prune(only_hosts=only)
                self.assertEqual(len(calls), 1, "only the revive runs")
                self.assertIn("REMOVE n.stale_since", calls[0][0])
                self.assertEqual(stats, {"pruned": 0, "stale": 0, "revived": 3})

    def test_host_values_travel_as_a_parameter(self):
        _, calls = _prune(only_hosts=["a.example.com"])
        self.assertNotIn("a.example.com", calls[1][0])

    def test_each_host_field_is_read(self):
        for field in base_mixin._KEEP_HOST_FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"toLower(toStringOrNull(n.{field}))", base_mixin._ONLY_HOSTS_CLAUSE)


class TestTypes(unittest.TestCase):
    def test_the_prune_is_limited_to_the_check_s_finding_types(self):
        _, calls = _prune(only_hosts=["a.example.com"], types=("missing_hsts",))
        prune_query, params = calls[1]
        self.assertIn("AND coalesce(n.type, '') IN $types", prune_query)
        self.assertEqual(params["types"], ["missing_hsts"])

    def test_no_type_prunes_nothing(self):
        stats, calls = _prune(only_hosts=["a.example.com"], types=())
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats["pruned"], 0)


if __name__ == "__main__":
    unittest.main()

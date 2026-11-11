"""R-49 follow-up: the prune reads a finding's hosts from its list fields too.

A dependency-confusion finding names every JS file that imports its package
in `source_urls`, on up to five hosts, while its scalar host fields
(`source_url`, `base_url`) name the first file only. The keep clause and the
positive-coverage lookup read scalars only (`toStringOrNull` of a list is
null), so a host only the list named never kept the finding: a run that cut
that host but re-checked the first one deleted it.

These pin the Cypher the prune sends (no Neo4j); what it does on a real graph
is proven in tests/test_prune_list_host_fields_graph_live.py.
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
        result.single.return_value = {"pruned": 1, "stale": 0, "revived": 0}
        return result


def _prune(**kwargs):
    client = BaseMixin.__new__(BaseMixin)
    calls = []
    client.driver = MagicMock()
    client.driver.session.side_effect = lambda: _Session(calls)
    client.prune_unseen_findings("u1", "p1", ["js_recon"], SINCE, **kwargs)
    return calls


def _list_read(field):
    return f"[x IN n.{field} | toLower(toStringOrNull(x))]"


class TestTheListFields(unittest.TestCase):
    def test_a_dependency_finding_s_files_are_a_host_field(self):
        self.assertIn("source_urls", base_mixin._KEEP_HOST_LIST_FIELDS)
        self.assertFalse(set(base_mixin._KEEP_HOST_LIST_FIELDS) & set(base_mixin._KEEP_HOST_FIELDS))

    def test_the_keep_clause_reads_every_element(self):
        prune_query, params = _prune(keep_hosts=["b.example.com"])[1]
        keep = prune_query[prune_query.index("AND NOT any(rx IN $keep_patterns"):
                           prune_query.index("SET n._prune_lock")]
        for field in base_mixin._KEEP_HOST_LIST_FIELDS:
            with self.subTest(field=field):
                self.assertIn(_list_read(field), keep)
        # A null element must not turn the whole keep test null (which keeps
        # every finding): each one is read as '' when it is not a string.
        self.assertIn("coalesce(v, '') =~ rx", keep)
        self.assertEqual(params["keep_patterns"], base_mixin.keep_host_patterns(["b.example.com"]))

    def test_the_scalar_keep_checks_are_unchanged(self):
        prune_query, _ = _prune(keep_hosts=["b.example.com"])[1]
        for field in base_mixin._KEEP_HOST_FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"coalesce(toLower(toStringOrNull(n.{field})), '') =~ rx", prune_query)

    def test_the_re_checked_lookup_reads_every_element(self):
        for field in base_mixin._KEEP_HOST_LIST_FIELDS:
            with self.subTest(field=field):
                self.assertIn(_list_read(field), base_mixin._ONLY_HOSTS_CLAUSE)
        prune_query, params = _prune(only_hosts=["a.example.com"])[1]
        self.assertIn(base_mixin._ONLY_HOSTS_CLAUSE, prune_query)
        self.assertEqual(params["only_hosts"], ["a.example.com"])

    def test_a_scalar_left_in_a_list_field_is_read_not_iterated(self):
        """Iterating a string fails the statement, and with it the whole prune."""
        for field in base_mixin._KEEP_HOST_LIST_FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"CASE WHEN n.{field} IS :: LIST<ANY> NOT NULL",
                              base_mixin._ONLY_HOSTS_CLAUSE)

    def test_no_keep_host_and_no_only_hosts_reads_no_list(self):
        prune_query, params = _prune()[1]
        self.assertNotIn("source_urls", prune_query)
        self.assertEqual(set(params), {"uid", "pid", "sources", "since"})


class TestTheQueryStaysScopedAndChunked(unittest.TestCase):
    def test_every_prune_query_is_tenant_scoped(self):
        for kwargs in ({"keep_hosts": ["b.example.com"]}, {"only_hosts": ["a.example.com"]},
                       {"keep_hosts": ["b.example.com"], "only_hosts": ["a.example.com"]}):
            with self.subTest(**{k: tuple(v) for k, v in kwargs.items()}):
                calls = _prune(**kwargs)
                self.assertEqual(len(calls), 2)
                for query, params in calls:
                    self.assertIn("n.user_id = $uid AND n.project_id = $pid", query)
                    self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_hosts_travel_as_parameters_in_chunks(self):
        hosts = [f"h{i}_x.example.com" for i in range(250)]
        prune_query, params = _prune(keep_hosts=hosts, only_hosts=hosts)[1]
        self.assertEqual(len(params["keep_patterns"]), 3)
        self.assertEqual(len(params["only_hosts"]), 250)
        self.assertNotIn("h0_x", prune_query)

    def test_the_restored_timestamp_comparison_is_kept(self):
        prune_query, _ = _prune(keep_hosts=["b.example.com"], only_hosts=["a.example.com"])[1]
        self.assertIn(base_mixin._RESTORED_UPDATED_AT + " < datetime($since)", prune_query)


if __name__ == "__main__":
    unittest.main()

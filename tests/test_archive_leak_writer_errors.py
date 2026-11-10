"""The resource writer reports its archive-leak sub-writer's item errors (R-20).

`update_graph_from_resource_enum` writes the web archives' leaks
(Vulnerability / Secret {source: 'url_archive'}) through
`update_graph_from_archive_leaks`, which records a failed finding in its own
stats["errors"]. Those were dropped, so the recon pipeline, which degrades a
writer's sources only on the errors the writer returns, never saw them and
the prune deleted the url_archive findings that failed to refresh.

Neo4j is a fake session.
"""
import os
import sys
import unittest
from collections import defaultdict

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402


class _Result:
    def single(self):
        return defaultdict(int)

    def __iter__(self):
        return iter(())

    def consume(self):
        return None


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, *a, **kw):
        return _Result()


class _Driver:
    def session(self, *a, **kw):
        return _Session()


class _Writer(ResourceMixin):
    def __init__(self, leaks_stats=None, leaks_raise=None):
        self.driver = _Driver()
        self.leaks_stats = leaks_stats or {}
        self.leaks_raise = leaks_raise

    def update_graph_from_archive_leaks(self, recon_data, user_id, project_id):
        if self.leaks_raise:
            raise self.leaks_raise
        return self.leaks_stats


RECON = {"domain": "example.com", "subdomains": ["www.example.com"],
         "resource_enum": {"by_base_url": {},
                           "archive_leaks": {"findings": [{"type": "leaked_link"}]}}}


class TestArchiveLeakErrors(unittest.TestCase):
    def test_the_sub_writers_item_errors_reach_the_returned_stats(self):
        stats = _Writer({"findings_written": 1, "secrets_written": 0, "errors": [
            "urlscan finding leaked_link: ConstraintError"]}).update_graph_from_resource_enum(
                RECON, "u1", "p1")
        self.assertIn("Archive leaks: urlscan finding leaked_link: ConstraintError",
                      stats["errors"])
        self.assertEqual(stats["archive_findings_written"], 1)

    def test_a_clean_sub_writer_adds_no_error(self):
        stats = _Writer({"findings_written": 2, "secrets_written": 1, "errors": []}) \
            .update_graph_from_resource_enum(RECON, "u1", "p1")
        self.assertFalse([e for e in stats["errors"] if e.startswith("Archive leaks")])
        self.assertEqual(stats["secrets_created"], 1)

    def test_a_sub_writer_that_raises_is_still_reported(self):
        stats = _Writer(leaks_raise=RuntimeError("boom")).update_graph_from_resource_enum(
            RECON, "u1", "p1")
        self.assertIn("Archive leaks failed: boom", stats["errors"])


if __name__ == "__main__":
    unittest.main()

"""The urlscan graph writers: what reaches Neo4j, with the tenant triple on every
MERGE and no raw value anywhere.

`SET n += $props` hides property names from the hermetic schema scan
(recon/tests/test_graph_writes_documented.py), so these tests assert the names
themselves, on the Cypher and its parameters.

Fixture names are example.test only; tokens are invented.
"""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

TOK = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"


class _Session:
    def __init__(self, single=None):
        self.calls = []
        self._single = single

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = self._single
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self, single=None):
        self.session = _Session(single)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _recon(urlscan):
    base = {"results_count": 1, "entries": [], "urls_with_paths": []}
    base.update(urlscan)
    return {"domain": "example.test", "domains": ["example.test"], "urlscan": base}


class TestQuarantinedEndpoints(unittest.TestCase):
    ROW = {"base_url": "https://auth.example.test", "path": "/password/reset/{token}",
           "masked_url": "https://auth.example.test/password/reset/{token}?lang=***",
           "param_names": ["lang"], "reasons": ["one_time_link", "path_token"], "field": "page"}

    def _write(self, rows):
        w = _Writer(single={"n": 1})
        stats = w.update_graph_from_urlscan_enrichment(_recon({"quarantined_urls": rows}), "u1", "p1")
        return w, stats

    def _quarantine_calls(self, w):
        return [(q, p) for q, p in w.session.calls if "e.quarantined = true" in q]

    def test_flagged_with_a_plain_set_and_no_full_url(self):
        w, stats = self._write([self.ROW])
        (query, params), = self._quarantine_calls(w)
        self.assertIn("REMOVE e.full_url", query)
        self.assertNotIn("ON CREATE SET e.quarantined", query)
        self.assertIn("REMOVE p.sample_value, p.sample_values", query)
        self.assertEqual(params["path"], "/password/reset/{token}")
        self.assertEqual(params["names"], ["lang"])
        self.assertEqual(stats["endpoints_quarantined"], 1)

    def test_tenant_triple_on_every_merge(self):
        w, _ = self._write([self.ROW])
        (query, params), = self._quarantine_calls(w)
        for merge in [line for line in query.splitlines() if "MERGE (" in line and ":" in line
                      and "{" in line]:
            if "Endpoint" in merge or "Parameter" in merge:
                self.assertIn("user_id: $uid", query)
                self.assertIn("project_id: $pid", query)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_no_value_reaches_the_graph(self):
        w, _ = self._write([dict(self.ROW, masked_url=self.ROW["masked_url"])])
        self.assertNotIn(TOK, json.dumps([p for _q, p in w.session.calls], default=str))


if __name__ == "__main__":
    unittest.main()

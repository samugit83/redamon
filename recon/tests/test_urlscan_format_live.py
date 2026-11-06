"""Live: urlscan.io's real search answer still matches the urlscan lab's schema (plan §10.1).

One anonymous search on the reserved example.com (page.domain:example.com, size
5), validated against testing/guinea_pigs/urlscan_lab/fake_urlscan/
urlscan_search.schema.json, the file the lab's fake urlscan is checked against.
A violation means urlscan changed its format and the fake is now wrong, so it
fails; no network, a rate limit or a urlscan outage skip. Stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import socket
import unittest
import urllib.error
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[2] / "testing" / "guinea_pigs" / "urlscan_lab"
URL = "https://urlscan.io/api/v1/search/?q=page.domain%3Aexample.com&size=5"
RATE_HEADERS = ("x-rate-limit-scope", "x-rate-limit-action", "x-rate-limit-window", "x-rate-limit-limit",
                "x-rate-limit-remaining", "x-rate-limit-reset", "x-rate-limit-reset-after")


def _schema_check():
    spec = importlib.util.spec_from_file_location("uslab_schema_check", LAB / "fake_urlscan" / "schema_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealUrlscanAnswerMatchesTheLabSchema(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            socket.getaddrinfo("urlscan.io", 443)
        except OSError:
            raise unittest.SkipTest("offline: urlscan.io does not resolve")
        req = urllib.request.Request(URL, headers={"User-Agent": "RedAmon-urlscan-lab-format-check/1",
                                                   "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                cls.status = resp.status
                cls.headers = {k.lower(): v for k, v in resp.headers.items()}
                cls.body = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                raise unittest.SkipTest(f"urlscan.io answered {e.code}: try again later")
            # Anything else (401, 403) means anonymous search itself changed,
            # which every keyless assumption of the plan rests on.
            raise AssertionError(f"urlscan.io refused an anonymous search: HTTP {e.code}") from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise unittest.SkipTest(f"urlscan.io unreachable: {e}")
        cls.schema_check = _schema_check()

    def test_the_answer_validates_against_the_lab_schema(self):
        self.assertEqual(self.status, 200)
        self.assertEqual(self.schema_check.check_search(self.body), [])

    def test_anonymous_rules_the_schema_cannot_express(self):
        body = self.body
        self.assertIn("search_date_limit_days", body, "anonymous answers carry the date limit")
        self.assertLessEqual(len(body["results"]), 5)
        if body["has_more"]:
            self.assertGreaterEqual(body["total"], 10_000, "has_more is true only above the 10,000 cap")
        sorts = [tuple(r["sort"]) for r in body["results"]]
        self.assertEqual(sorts, sorted(sorts, reverse=True), "newest first")
        for r in body["results"]:
            self.assertEqual(r["_id"], r["task"]["uuid"])
            self.assertEqual(r["sort"][1], r["task"]["uuid"])
            self.assertNotIn("verdicts", r, "verdicts need a key")

    def test_every_answer_carries_the_rate_limit_headers(self):
        missing = [h for h in RATE_HEADERS if h not in self.headers]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()

"""urlscan search: paging, caps, the run's search budget and the breaker keys.

Facts checked live in Nov 2026 that this pins:
  - without a key one search returns at most 100 visits, whatever `size` asks;
  - `has_more` is true only above 10,000 matches and does not mean "next page";
  - `search_after=<sort[0]>,<sort[1]>` continues with older visits.
B29/F3: RedAmon sent one search, so a keyless project saw only the newest 100.
B35: the code fallback (500) disagreed with the real default.
B36: the keyed main query asked a redundant `OR page.domain:*.X`.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402


def _visit(i: int) -> dict:
    uuid = f"00000000-0000-0000-0000-{i:012d}"
    ms = 1_790_000_000_000 - i * 60_000
    return {"task": {"uuid": uuid, "time": f"2026-10-{1 + i % 28:02d}T00:00:00.000Z",
                     "url": f"https://www.example.test/p{i}"},
            "page": {"url": f"https://www.example.test/p{i}", "domain": "www.example.test",
                     "ip": "192.0.2.10", "status": "200"},
            "_id": uuid, "sort": [ms, uuid]}


class FakeUrlscan:
    """Answers like urlscan: newest first, `total` capped at 10,000, `has_more`
    only above it, 100 per page without a key, `search_after` paging."""

    def __init__(self, count: int, *, fail_on_call: dict | None = None):
        self.visits = [_visit(i) for i in range(count)]
        self.calls = []
        self.fail_on_call = fail_on_call or {}

    def __call__(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": dict(params or {}), "keyed": bool(headers)})
        resp = MagicMock()
        resp.headers = {}
        status = self.fail_on_call.get(len(self.calls))
        if status:
            resp.status_code = status
            resp.json.return_value = {"message": "x", "status": status}
            return resp
        start = 0
        after = (params or {}).get("search_after")
        if after:
            ms, uuid = after.split(",", 1)
            start = next(i for i, v in enumerate(self.visits) if v["sort"][1] == uuid) + 1
        size = int((params or {}).get("size", 100))
        if not headers:
            size = min(size, 100)
        page = self.visits[start:start + size]
        resp.status_code = 200
        resp.json.return_value = {
            "results": page, "total": min(len(self.visits), 10000),
            "has_more": len(self.visits) > 10000,
            "search_date_limit_days": 30 if not headers else None,
        }
        return resp


def _settings(**kw):
    base = {"URLSCAN_ENABLED": True, "URLSCAN_API_KEY": ""}
    base.update(kw)
    return base


def _run(fake, **settings):
    with patch.object(u.requests, "get", side_effect=fake):
        out = u.run_urlscan_enrichment({"domain": "example.test", "metadata": {}}, _settings(**settings))
    return out["urlscan"]


class TestPaging(unittest.TestCase):
    def tearDown(self):
        u.end_search_budget()

    def test_b29_keyless_pages_100_at_a_time_with_search_after(self):
        fake = FakeUrlscan(250)
        data = _run(fake)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual([c["params"]["size"] for c in fake.calls], [100, 100, 100])
        self.assertNotIn("search_after", fake.calls[0]["params"])
        self.assertEqual(fake.calls[1]["params"]["search_after"],
                         ",".join(str(v) for v in fake.visits[99]["sort"]))
        self.assertEqual(data["results_count"], 250)
        self.assertEqual(len(data["entries"]), 250)
        cov = data["coverage"]
        self.assertFalse(cov["truncated"])
        self.assertEqual((cov["searches_used"], cov["search_date_limit_days"]), (3, 30))
        self.assertTrue(cov["oldest_seen"])

    def test_has_more_false_does_not_stop_paging(self):
        fake = FakeUrlscan(150)  # has_more is false, a second page still exists
        self.assertEqual(_run(fake)["results_count"], 150)
        self.assertEqual(len(fake.calls), 2)

    def test_keyless_cap_is_1000_even_with_a_saved_50000(self):
        fake = FakeUrlscan(2500)
        data = _run(fake, URLSCAN_MAX_RESULTS=50000)
        self.assertEqual(data["results_count"], 1000)
        self.assertEqual(len(fake.calls), 10)
        self.assertTrue(data["coverage"]["truncated"])
        self.assertEqual(data["coverage"]["cut_reason"], "result cap reached")

    def test_keyed_cap_is_10000_one_search(self):
        fake = FakeUrlscan(12000)
        data = _run(fake, URLSCAN_API_KEY="lab-key", URLSCAN_MAX_RESULTS=50000)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["params"]["size"], 10000)
        self.assertEqual(data["results_count"], 10000)

    def test_b35_missing_setting_defaults_to_10000(self):
        self.assertEqual(u.effective_max_results({}, keyed=True), 10000)
        self.assertEqual(u.effective_max_results({"URLSCAN_MAX_RESULTS": "bad"}, keyed=True), 10000)
        self.assertEqual(u.effective_max_results({"URLSCAN_MAX_RESULTS": 300}, keyed=False), 300)

    def test_b36_keyed_main_query_has_no_wildcard_clause(self):
        fake = FakeUrlscan(5)
        _run(fake, URLSCAN_API_KEY="lab-key")
        self.assertEqual(fake.calls[0]["params"]["q"], "page.domain:example.test")

    @patch("recon.helpers.circuit_breaker._sleep", lambda s: None)
    def test_429_on_page_2_keeps_page_1_and_marks_the_gap(self):
        fake = FakeUrlscan(250, fail_on_call={2: 429, 3: 429})
        with patch.object(cb, "note_degraded", wraps=cb.note_degraded) as noted:
            data = _run(fake)
        self.assertEqual(data["results_count"], 100)
        self.assertFalse(data.get("rate_limited"))
        self.assertTrue(data["coverage"]["truncated"])
        self.assertEqual(data["coverage"]["cut_reason"], "rate limited")
        sources = [set(c.kwargs.get("sources") or ()) for c in noted.call_args_list]
        self.assertIn({"urlscan_leak", "urlscan"}, sources)


class TestSearchBudget(unittest.TestCase):
    def tearDown(self):
        u.end_search_budget()

    def test_one_counter_across_roots_with_first_pages_reserved(self):
        budget = u.start_search_budget({"URLSCAN_MAX_SEARCHES": 3}, ["a.test", "b.test"])
        fake = FakeUrlscan(500)
        with patch.object(u.requests, "get", side_effect=fake):
            first = u._urlscan_search("a.test", "", 1000, budget=budget)
            second = u._urlscan_search("b.test", "", 1000, budget=budget)
        # a.test may take one more page, never b.test's reserved first page.
        self.assertEqual((first.searches, len(first)), (2, 200))
        self.assertTrue(first.truncated and first.budget_exhausted)
        self.assertEqual((second.searches, len(second)), (1, 100))
        self.assertEqual(budget.used, 3)
        self.assertEqual(len(fake.calls), 3)

    def test_extra_callers_come_after_first_pages(self):
        budget = u.start_search_budget({"URLSCAN_MAX_SEARCHES": 2,
                                        "URLSCAN_REDIRECT_SEARCH": True}, ["a.test"])
        self.assertFalse(budget.take("hash"))            # both first pages still reserved
        self.assertTrue(budget.take("search", "a.test", first=True))
        self.assertTrue(budget.take("redirect", "a.test", first=True))
        self.assertFalse(budget.take("search", "a.test"))
        self.assertTrue(budget.exhausted)

    def test_spent_budget_records_a_gap_and_keeps_the_findings(self):
        u.start_search_budget({"URLSCAN_MAX_SEARCHES": 1}, ["other.test"])
        fake = FakeUrlscan(10)
        with patch.object(cb, "note_degraded", wraps=cb.note_degraded) as noted:
            data = _run(fake, URLSCAN_MAX_SEARCHES=1)
        self.assertEqual(fake.calls, [])
        self.assertEqual(data["results_count"], 0)
        self.assertEqual(data["coverage"]["cut_reason"], "search budget reached")
        call = noted.call_args_list[0]
        self.assertEqual(set(call.kwargs["sources"]), {"urlscan_leak", "urlscan"})
        self.assertIn("search budget reached", call.kwargs["reason"])

    def test_without_a_started_run_each_call_has_its_own_budget(self):
        u.end_search_budget()
        self.assertIsNot(u.search_budget({}), u.search_budget({}))


class TestBreakerKeys(unittest.TestCase):
    """A refused extra query (400, or 403 with a key: a plan-gated query) stays on
    its own breaker: it neither switches the main search off nor rejects the key."""

    def _resp(self, status):
        r = MagicMock()
        r.status_code = status
        r.headers = {}
        r.json.return_value = {"results": [], "total": 0}
        return r

    def test_refused_extra_query_does_not_open_the_main_search(self):
        for status, key in ((400, ""), (403, ""), (403, "lab-key")):
            cb.reset_registry()
            with patch.object(u.requests, "get", return_value=self._resp(status)):
                for _ in range(6):
                    u.urlscan_search("task.apexDomain:a.test", key, breaker_key="urlscan:redirect",
                                     caller="redirect", local_refusals=True)
            main = cb.get_breaker("urlscan:search", label="URLScan", parent="urlscan")
            self.assertTrue(main.allow(), (status, key))
            self.assertFalse(cb.get_breaker("urlscan", label="URLScan").is_fatal, (status, key))

    def test_keyed_403_on_an_extra_query_does_not_reject_the_key(self):
        pool = MagicMock()
        with patch.object(cb.KeyPool, "reject", return_value=False) as reject, \
                patch.object(u.requests, "get", return_value=self._resp(403)):
            u.urlscan_search("hash:" + "a" * 64, "lab-key", breaker_key="urlscan:hash",
                             caller="hash", page=False, local_refusals=True)
        reject.assert_not_called()
        del pool

    def test_keyed_401_on_the_main_search_still_rejects_the_key(self):
        with patch.object(cb.KeyPool, "reject", return_value=False) as reject, \
                patch.object(u.requests, "get", return_value=self._resp(401)):
            u._urlscan_search("a.test", "bad-key")
        reject.assert_called()


class TestPartialAcceptsTruncatedResults(unittest.TestCase):
    """Partial recon retries a rate-limited root; a root that read page 1 and was
    cut on page 2 is a result to write, not a retry."""

    def tearDown(self):
        u.end_search_budget()

    @patch("recon.helpers.circuit_breaker._sleep", lambda s: None)
    def test_truncated_is_not_rate_limited(self):
        fake = FakeUrlscan(250, fail_on_call={2: 429, 3: 429})
        with patch.object(u.requests, "get", side_effect=fake):
            data = u.run_urlscan_discovery_only("example.test", _settings())
        self.assertFalse(data.get("rate_limited"))
        self.assertEqual(data["results_count"], 100)


if __name__ == "__main__":
    unittest.main()

"""Item 1: the outbound-redirect search (URLSCAN_REDIRECT_SEARCH, off by default).

One extra search, task.apexDomain:X AND NOT page.apexDomain:X, on the org; only
visits that started on the scan root and ended outside the org are kept; the
other site is a label (origin only), never scanned; the open-redirect rule runs
on the raw values in memory; sign-in flows are no open redirect. Hosts are
example.test and other.test.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.display_only import strip_display_only  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402

T1 = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"


def _visit(start, end, uuid="r1", time="2026-10-01T00:00:00.000Z"):
    end_host = end.split("/")[2]
    return {"task": {"url": start, "domain": start.split("/")[2], "time": time, "uuid": uuid,
                     "visibility": "public"},
            "page": {"url": end, "domain": end_host, "ip": "192.88.97.99", "status": "200"}}


class FakeUrlscan:
    def __init__(self, main=(), redirect=(), redirect_status=200):
        self.main, self.redirect, self.redirect_status = list(main), list(redirect), redirect_status
        self.calls = []

    def __call__(self, url, params=None, headers=None, timeout=None):
        q = params["q"]
        self.calls.append(q)
        resp = MagicMock()
        resp.headers = {}
        if q.startswith("task.apexDomain:"):
            resp.status_code = self.redirect_status
            results = self.redirect
        else:
            resp.status_code = 200
            results = self.main
        resp.json.return_value = {"results": results, "total": len(results)}
        return resp


def _run(fake, domain="example.test", org="example.test", **settings):
    base = {"URLSCAN_ENABLED": True, "URLSCAN_REDIRECT_SEARCH": True}
    base.update(settings)
    with patch.object(u.requests, "get", side_effect=fake):
        return u.run_urlscan_discovery_only(domain, base, org)


REDIRECTS = [
    _visit("https://app.example.test/go?url=https://outsider.other.test/x", "https://outsider.other.test/x", "a"),
    _visit("https://auth.example.test/authorize?client_id=c&redirect_uri=https://idp.other.test/cb&state=s",
           "https://idp.other.test/login", "b"),
    _visit("https://elsewhere.test/go", "https://outsider.other.test/", "c"),
    _visit("https://app.example.test/a", "https://shop.example.test/b", "d"),
    _visit(f"https://new.example.test/reset?token={T1}&next=https%3A%2F%2Fmirror.other.test%2F",
           "https://mirror.other.test/", "e"),
]


def test_switch_off_is_one_search_as_today():
    fake = FakeUrlscan()
    _run(fake, URLSCAN_REDIRECT_SEARCH=False)
    assert fake.calls == ["page.domain:example.test"]


def test_the_second_query_is_exact_on_the_org():
    fake = FakeUrlscan()
    _run(fake, domain="api.example.test", org="example.test")
    assert fake.calls == ["page.domain:api.example.test",
                          "task.apexDomain:example.test AND NOT page.apexDomain:example.test"]


def test_only_starts_on_the_root_ending_outside_the_org():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    starts = {r["start_url"].split("?")[0] for r in data["redirect_entries"]}
    assert "https://app.example.test/go" in starts
    assert not [s for s in starts if "elsewhere" in s or s.endswith("/a")]


def test_values_masked_and_the_other_site_is_its_origin():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    blob = json.dumps(strip_display_only(data))
    assert T1 not in blob and "outsider.other.test/x" not in blob
    go = next(r for r in data["redirect_entries"] if r["path"] == "/go")
    assert go["start_url"] == "https://app.example.test/go?url=***"
    assert go["unmasked_start_url"] == "https://app.example.test/go?url=https://outsider.other.test/x"
    assert go["end_origin"] == "https://outsider.other.test" and go["param_names"] == ["url"]
    ext = [e for e in data["external_domains"] if e["source"] == "urlscan_redirect"]
    assert {e["url"] for e in ext} <= {"https://outsider.other.test", "https://idp.other.test",
                                      "https://mirror.other.test"}


def test_redirect_entries_never_reach_the_request_lists():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    assert data["urls_with_paths"] == []


def test_n1_open_redirect_proven_by_the_visit():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    opens = {(o["host"], o["param_name"], o["destination_domain"]) for o in data["open_redirects"]}
    assert ("app.example.test", "url", "outsider.other.test") in opens
    assert ("new.example.test", "next", "mirror.other.test") in opens
    assert not [o for o in data["open_redirects"] if o["host"] == "auth.example.test"]
    f = next(f for f in data["findings"] if f["type"] == "open_redirect_seen" and f["kind"] == "url")
    assert f["props"] == {"param_name": "url", "destination_domain": "outsider.other.test",
                          "unmasked_url": "https://app.example.test/go?url=https://outsider.other.test/x"}
    assert f["url"] == "https://app.example.test/go?url=***"


def test_an_end_domain_in_no_parameter_is_no_open_redirect():
    data = _run(FakeUrlscan(redirect=[_visit("https://app.example.test/x?id=5", "https://outsider.other.test/")]))
    assert data["open_redirects"] == []


def test_a_quarantined_start_keeps_its_scan_and_link_and_is_quarantined():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    o = next(o for o in data["open_redirects"] if o["host"] == "new.example.test")
    assert o["scan_id"] == "e"
    assert o["unmasked_url"].startswith(f"https://new.example.test/reset?token={T1}")
    assert any(r["path"] == "/reset" for r in data["quarantined_urls"])
    assert any(f["type"] == "leaked_one_time_link" for f in data["findings"])


def test_new_start_hosts_get_listed_for_an_ip_less_subdomain():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    assert "new.example.test" in data["redirect_start_hosts"]
    assert all(e["ip"] != "192.88.97.99" for e in data["entries"])


def test_runs_when_the_main_search_is_empty_not_when_rate_limited():
    data = _run(FakeUrlscan(redirect=REDIRECTS))
    assert data["results_count"] == 0 and data["redirect_entries"]

    class Limited(FakeUrlscan):
        def __call__(self, url, params=None, headers=None, timeout=None):
            resp = super().__call__(url, params, headers, timeout)
            if not params["q"].startswith("task."):
                resp.status_code = 429
            return resp
    fake = Limited(redirect=REDIRECTS)
    with patch("recon.helpers.circuit_breaker._sleep", lambda s: None):
        _run(fake)
    assert not [q for q in fake.calls if q.startswith("task.")]


def test_a_refused_redirect_query_leaves_the_main_search_on():
    fake = FakeUrlscan(redirect_status=400)
    for _ in range(6):
        _run(fake)
    assert cb.get_breaker("urlscan:search", label="URLScan", parent="urlscan").allow()

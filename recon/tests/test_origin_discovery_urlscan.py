"""Item 7: urlscan as a source for Origin Discovery, and the own-file check.

urlscan only proposes suspects (old addresses from the visits the URLScan
module already downloaded; visits that loaded the site's own build file);
the module's filter and live check decide. The file check helps every source.
Nothing here leaves the test: searches, downloads, ports and TLS are stubbed.
Names are example.test; addresses are 192.88.97.0/24 and Cloudflare's 104.16/12.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import origin_discovery as od  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as us  # noqa: E402

HOST = "shop.example.test"
EDGE = "104.16.1.1"
SHA = "4be1" + "0" * 56 + "d07"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def refuse(*_a, **_k):
        raise OSError("network disabled in unit tests")
    monkeypatch.setattr(od, "_tls_handshake_cert", refuse)
    cb.reset_registry()
    yield
    cb.reset_registry()


def _settings(**over):
    s = {"ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_KEYLESS": False,
         "ORIGIN_DISCOVERY_SCANNERS": False, "ORIGIN_DISCOVERY_PASSIVE_DNS": False,
         "ORIGIN_DISCOVERY_URLSCAN": True, "URLSCAN_ENABLED": True,
         "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25, "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
         "ORIGIN_DISCOVERY_THRESHOLD": 60, "ORIGIN_DISCOVERY_TIMEOUT": 3,
         "ORIGIN_DISCOVERY_WORKERS": 2, "ORIGIN_DISCOVERY_RATE": 0}
    s.update(over)
    return s


def _entry(ip, when, domain=HOST):
    return {"domain": domain, "ip": ip, "scan_time": when}


def _combined(entries=(), js_urls=()):
    return {"domain": "example.test", "domains": ["example.test"],
            "http_probe": {"by_url": {f"https://{HOST}": {
                "host": HOST, "ip": EDGE, "is_cdn": True, "cdn": "cloudflare", "status_code": 200}}},
            "urlscan": {"entries": list(entries)}, "resource_enum": {"js_urls": list(js_urls)}}


def _source(combined=None, **settings):
    ctx = od._RunCtx(_settings(**settings))
    return od._UrlscanSource(combined or _combined(), ctx), ctx


class TestTheSwitch(unittest.TestCase):
    def test_off_or_urlscan_off_never_contacts_urlscan(self):
        for over in ({"ORIGIN_DISCOVERY_URLSCAN": False}, {"URLSCAN_ENABLED": False}):
            self.assertFalse(od._urlscan_source_on(_settings(**over)))
            with patch.object(od, "_select_fronted_hosts", return_value={HOST: {"resolved_ips": {EDGE}}}), \
                    patch.object(od, "_favicon_hash_for_host", return_value=None), \
                    patch.object(us, "urlscan_search") as search, \
                    patch.object(od, "_fetch", return_value=None):
                od.run_origin_discovery_enrichment_isolated(
                    _combined([_entry("192.88.97.7", "2025-12-20T00:00:00Z")]), _settings(**over))
            search.assert_not_called()
        self.assertTrue(od._urlscan_source_on(_settings()))


class TestOldAddresses(unittest.TestCase):
    def test_newest_first_without_cdn_current_or_other_hosts_at_most_five(self):
        rows = [_entry(f"192.88.97.{i}", f"2026-0{i}-01T00:00:00Z") for i in range(1, 8)]
        rows += [_entry("104.16.9.9", "2026-09-01T00:00:00Z"),          # Cloudflare
                 _entry("192.88.97.50", "2026-09-02T00:00:00Z"),        # current
                 _entry("192.88.97.60", "2026-09-03T00:00:00Z", domain="www.example.test"),
                 _entry("192.88.97.61", "2026-09-04T00:00:00Z", domain="x.other.test")]
        src, _ = _source(_combined(rows))
        got = src.history(HOST, {"resolved_ips": {EDGE, "192.88.97.50"}}, flagged=set())
        self.assertEqual(got, [("192.88.97.7", "2026-07-01"), ("192.88.97.6", "2026-06-01"),
                               ("192.88.97.5", "2026-05-01"), ("192.88.97.4", "2026-04-01"),
                               ("192.88.97.3", "2026-03-01")])

    def test_it_runs_first_and_the_date_rides_on_the_finding(self):
        combined = _combined([_entry("192.88.97.7", "2025-12-20T00:00:00Z")])
        ref = {"text": "hello shop", "status": 200, "headers": {}, "cookies": "", "html": "", "final_url": ""}
        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
                patch.object(od, "_resolve_ips", return_value=set()), \
                patch.object(od, "_compare_certs", return_value=0.0), \
                patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
                patch.object(od, "_fetch", return_value=ref):
            out = od.run_origin_discovery_enrichment_isolated(combined, _settings())
        f, = out["confirmed"]
        self.assertEqual((f["origin_source"], f["origin_discovery_method"]), ("urlscan_history", "ip_history"))
        self.assertEqual(f["urlscan_seen_at"], "2025-12-20")
        self.assertIn("urlscan_history, seen 2025-12-20", f["evidence"])

    def test_the_cap_cannot_push_urlscan_out(self):
        ctx = od._RunCtx(_settings(ORIGIN_DISCOVERY_MAX_CANDIDATES=1, ORIGIN_DISCOVERY_KEYLESS=True))
        src = od._UrlscanSource(_combined([_entry("192.88.97.7", "2025-12-20T00:00:00Z")]), ctx)
        meta: dict = {}
        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
                patch.object(od, "_discover_via_subdomains", return_value=["192.88.97.20"]), \
                patch.object(od, "_discover_via_email_records", return_value=[]), \
                patch.object(od, "_discover_via_crtsh", return_value=[]):
            cands = od._gather_candidates(HOST, {"resolved_ips": {EDGE}}, ctx, meta, key="example.test",
                                          urlscan=src)
        kept = od._dedup_and_filter(cands, {"resolved_ips": {EDGE}}, ctx, meta)
        self.assertEqual(kept, [("192.88.97.7", "urlscan_history")])


class TestOwnFile(unittest.TestCase):
    def _pick(self, html, js_urls=(), in_scope=lambda h: h.endswith(".example.test")):
        return od._own_script(HOST, html, f"https://{HOST}/", list(js_urls), in_scope)

    def test_the_qualifying_file(self):
        html = '<script src="/assets/app.8f3a91c2.js"></script>'
        self.assertEqual(self._pick(html), f"https://{HOST}/assets/app.8f3a91c2.js")
        self.assertEqual(self._pick("", ["https://static.example.test/js/index-BXy7a9Qe.js"]),
                         "https://static.example.test/js/index-BXy7a9Qe.js")

    def test_shared_unbuilt_and_third_party_files_do_not(self):
        for src in ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.8f3a91c2.js",
                    "/_next/static/chunks/framework-2c79e2a64abdb08b.js",
                    "/js/vendor.8f3a91c2.js", "/js/app.js", "/js/app.settings.js",
                    "https://cdn.thirdparty.test/app.8f3a91c2.js"):
            self.assertIsNone(self._pick(f'<script src="{src}"></script>'), src)

    def test_main_app_index_bundle_first(self):
        html = ('<script src="/a/chunk.1a2b3c4d5e.js"></script>'
                '<script src="/a/main.9f8e7d6c5b.js"></script>')
        self.assertTrue(self._pick(html).endswith("/a/main.9f8e7d6c5b.js"))

    def test_no_file_no_search(self):
        src, _ = _source()
        with patch.object(us, "urlscan_search") as search:
            self.assertEqual(src.file_suspects(HOST, None), ([], ""))
        search.assert_not_called()


def _visit(domain, ip, when="2026-10-01T00:00:00Z"):
    return {"page": {"domain": domain, "ip": ip}, "task": {"time": when}}


class TestFileSearch(unittest.TestCase):
    OWN = {"url": f"https://{HOST}/assets/app.8f3a91c2.js", "path": "/assets/app.8f3a91c2.js",
           "host": HOST, "name": "app.8f3a91c2.js", "sha256": SHA}

    def test_the_query_and_the_filters(self):
        src, _ = _source()
        visits = [_visit("192.88.97.20", "192.88.97.20"), _visit("old.example.test", "192.88.97.21"),
                  _visit("partner.other.test", "192.88.97.22")]
        with patch.object(us, "urlscan_search", return_value=us.SearchResults(visits)) as search, \
                patch.object(od._UrlscanSource, "in_scope", lambda self, h: h.endswith(".example.test")):
            got, source = src.file_suspects(HOST, self.OWN)
        self.assertEqual(search.call_args.args[0], f"hash:{SHA}")
        kw = search.call_args.kwargs
        self.assertEqual((kw["breaker_key"], kw["page"], kw["local_refusals"], kw["caller"]),
                         ("urlscan:hash", False, True, "hash"))
        self.assertEqual(source, "urlscan_hash")
        self.assertEqual(got, [("192.88.97.20", "2026-10-01"), ("192.88.97.21", "2026-10-01")])

    def test_a_shared_file_counts_for_nothing(self):
        src, _ = _source()
        visits = [_visit(f"site{i}.other{i}.test", f"192.88.97.{i}") for i in range(6)]
        visits.append(_visit("192.88.97.99", "192.88.97.99"))
        with patch.object(us, "urlscan_search", return_value=us.SearchResults(visits)):
            self.assertEqual(src.file_suspects(HOST, self.OWN)[0], [])

    def test_filename_only_after_an_empty_hash_search_and_at_most_three(self):
        src, _ = _source()
        with patch.object(us, "urlscan_search", return_value=us.SearchResults([])) as search:
            src.file_suspects(HOST, self.OWN)
            for i in range(3):
                src.file_suspects(f"h{i}.example.test", {**self.OWN, "sha256": f"{i}" * 64})
        queries = [c.args[0] for c in search.call_args_list]
        self.assertEqual(queries, [f"hash:{SHA}", 'filename:"app.8f3a91c2.js"', f"hash:{'0' * 64}"])

    def test_hosts_sharing_the_file_share_the_search(self):
        src, _ = _source()
        with patch.object(us, "urlscan_search", return_value=us.SearchResults([_visit("192.88.97.20", "192.88.97.20")])) as s:
            src.file_suspects(HOST, self.OWN)
            src.file_suspects("www.example.test", self.OWN)
        self.assertEqual(s.call_count, 1)

    def test_a_refused_hash_search_leaves_the_main_search_alone(self):
        resp = type("R", (), {"status_code": 403, "headers": {}, "json": lambda self: {}, "text": "",
                              "ok": False})()
        with patch.object(us.requests, "get", return_value=resp):
            us.urlscan_search(f"hash:{SHA}", "", breaker_key="urlscan:hash", caller="hash", page=False,
                              local_refusals=True, budget=us.SearchBudget(10))
        self.assertFalse(us._breaker(us.MAIN_BREAKER).is_open)
        self.assertFalse(us._breaker(us.MAIN_BREAKER).is_fatal)


class TestFileCheck(unittest.TestCase):
    OWN = TestFileSearch.OWN
    REF = {"text": "", "status": 200, "headers": {}, "cookies": ""}   # a single-page app

    def _score(self, served, ref=None, waf=False):
        page = {"text": "<div id=root>", "status": 200, "cookies": "",
                "headers": {"server": "cloudflare", "cf-ray": "1"} if waf else {}}
        ctx = od._RunCtx(_settings())
        with patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
                patch.object(od, "_compare_certs", return_value=0.0), \
                patch.object(od, "_fetch", return_value=page), \
                patch.object(od, "_file_sha256", return_value=served) as dl:
            got = od._score_candidate(HOST, ref or self.REF, "192.88.97.7", ctx, own_file=self.OWN)
        return got, dl

    def test_the_same_file_confirms_at_85_even_below_the_threshold(self):
        got, dl = self._score(SHA)
        self.assertEqual((got["file_match"], got["confidence_score"] >= 85), (True, True))
        dl.assert_called_once()
        url, host_header = dl.call_args.args[:2]
        self.assertEqual((url, host_header), (f"https://192.88.97.7:443{self.OWN['path']}", HOST))

    def test_a_different_file_leaves_the_page_score(self):
        got, _ = self._score("f" * 64)
        self.assertIsNone(got)
        ref = {"text": "<div id=root>", "status": 200, "headers": {}, "cookies": ""}
        page_only, _ = self._score("f" * 64, ref=ref)
        self.assertFalse(page_only["file_match"])

    def test_waf_headers_still_skip(self):
        got, dl = self._score(SHA, waf=True)
        self.assertIsNone(got)
        dl.assert_not_called()

    def test_a_foreign_default_certificate_still_caps_at_79(self):
        ctx = od._RunCtx(_settings())
        with patch.object(od, "_score_candidate", return_value={"port": 443, "confidence_score": 92.0,
                                                                "file_match": True}), \
                patch.object(od, "_default_cert_check", return_value=("foreign", "")):
            got = od._confirm_candidate(HOST, self.REF, "192.88.97.7", ctx, own_file=self.OWN)
        self.assertEqual(got["confidence_score"], 79.0)

    def test_the_download_never_follows_a_redirect_nor_reads_past_20_mb(self):
        class _Raw:
            def __init__(self, n):
                self.n = n

            def read(self, limit, decode_content=True):
                return b"x" * min(self.n, limit)

        class _Resp:
            def __init__(self, n, status=200):
                self.status_code, self.headers, self.raw = status, {}, _Raw(n)

            def close(self):
                pass
        ctx = od._RunCtx(_settings())
        url = "https://192.88.97.7/a.js"
        with patch.object(od, "is_url_safe_to_probe", return_value=True):
            with patch.object(od.requests, "get", return_value=_Resp(10)) as get:
                self.assertEqual(len(od._file_sha256(url, HOST, ctx)), 64)
            self.assertIs(get.call_args.kwargs["allow_redirects"], False)
            self.assertEqual(get.call_args.kwargs["headers"]["Host"], HOST)
            with patch.object(od.requests, "get", return_value=_Resp(od._MAX_OWN_FILE_BYTES + 5)):
                self.assertIsNone(od._file_sha256(url, HOST, ctx))
            with patch.object(od.requests, "get", return_value=_Resp(10, status=302)):
                self.assertIsNone(od._file_sha256(url, HOST, ctx))
        with patch.object(od, "is_url_safe_to_probe", return_value=False), \
                patch.object(od.requests, "get") as get:
            self.assertIsNone(od._file_sha256("https://10.0.0.5/a.js", "", ctx))
        get.assert_not_called()


class TestWiring(unittest.TestCase):
    def test_labels_keyed_providers_and_partial_inputs(self):
        self.assertEqual(od._METHOD_LABEL["urlscan_hash"], "file_hash")
        self.assertIn("urlscan", od._KEYED_PROVIDERS)
        src = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "origin_enrichment.py").read_text()
        self.assertIn("-[r:HISTORICALLY_RESOLVED_TO {source: 'urlscan'}]->(i:IP)", src)
        self.assertIn("finding_type: 'js_file'", src)
        self.assertIn("scope.keeps(host)", src)

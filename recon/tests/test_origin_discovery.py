"""
Unit tests for Origin-IP Discovery (recon/main_recon_modules/origin_discovery.py).

Covers the hardening invariants that make this tool safe to point at a client:
  - G11 SSRF: non-routable / metadata / unparseable candidate IPs are dropped
    BEFORE any probe and never recorded (the highest-priority test).
  - G2 RoE: excluded candidate IPs are dropped.
  - G3 budget: keyed-search budget stops keyed sources; cached hits don't draw it.
  - Per-target cache: N hosts sharing one domain hit each keyed API once.
  - Weighted scoring crosses / fails ORIGIN_DISCOVERY_THRESHOLD with real fields.
  - Never-raise: a source that throws is recorded and the module still returns.
  - Keyless-only run works with zero keys.
  - The _isolated wrapper returns only the payload and does not mutate its input.
  - stable_vuln_id is process-stable (G1) and the origin id converges with the
    security-check producer for the same (type, url, ip).

All network is mocked; no real target data anywhere.

Run: python -m pytest recon/tests/test_origin_discovery.py -v
"""
import copy
import unittest
from unittest.mock import patch, MagicMock

from recon.main_recon_modules import origin_discovery as od


def _settings(**over):
    s = {
        "ORIGIN_DISCOVERY_ENABLED": True,
        "ORIGIN_DISCOVERY_KEYLESS": True,
        "ORIGIN_DISCOVERY_SCANNERS": True,
        "ORIGIN_DISCOVERY_PASSIVE_DNS": True,
        "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25,
        "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
        "ORIGIN_DISCOVERY_THRESHOLD": 60,
        "ORIGIN_DISCOVERY_TIMEOUT": 3,
        "ORIGIN_DISCOVERY_WORKERS": 4,
        "ORIGIN_DISCOVERY_RATE": 0,
        "ROE_ENABLED": False,
        "ROE_EXCLUDED_HOSTS": [],
    }
    s.update(over)
    return s


def _fronted_result(host="www.example.com", edge_ip="104.16.1.1", favicon=12345):
    return {
        "http_probe": {"by_url": {
            f"https://{host}": {
                "host": host, "ip": edge_ip, "is_cdn": True,
                "cdn": "cloudflare", "favicon_hash": favicon, "status_code": 200,
            }
        }}
    }


class TestSSRFFilter(unittest.TestCase):
    """G11 — the safety-critical drop. Untrusted candidate IPs never get probed."""

    def _ctx(self):
        return od._RunCtx(_settings())

    def test_non_routable_and_metadata_dropped(self):
        ctx = self._ctx()
        candidates = {
            "169.254.169.254": "dns",   # cloud metadata (link-local)
            "10.0.0.5": "shodan",       # RFC1918 private
            "127.0.0.1": "spf",         # loopback
            "not-an-ip": "otx",         # unparseable -> fail closed
            "8.8.8.8": "censys",        # routable, kept
        }
        entry = {"resolved_ips": set()}
        meta = {}
        kept = od._dedup_and_filter(candidates, entry, ctx, meta)
        kept_ips = [ip for ip, _ in kept]
        self.assertEqual(kept_ips, ["8.8.8.8"])
        # 169.254 + 10.0.0.5 + 127.0.0.1 + the unparseable one (fail-closed) = 4
        self.assertEqual(meta["dropped"]["ssrf"], 4)
        self.assertNotIn("not-an-ip", kept_ips)

    def test_cdn_and_current_resolution_dropped(self):
        ctx = self._ctx()
        candidates = {
            "104.16.99.99": "shodan",   # inside Cloudflare range -> edge, not origin
            "45.33.32.20": "dns",       # equals current DNS resolution -> the edge
            "45.33.32.10": "crtsh",     # routable, non-CDN -> kept
        }
        entry = {"resolved_ips": {"45.33.32.20"}}
        meta = {}
        kept = [ip for ip, _ in od._dedup_and_filter(candidates, entry, ctx, meta)]
        self.assertEqual(kept, ["45.33.32.10"])
        self.assertEqual(meta["dropped"]["cdn"], 1)
        self.assertEqual(meta["dropped"]["current_resolution"], 1)

    def test_roe_excluded_dropped(self):
        ctx = od._RunCtx(_settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["45.33.32.0/24"]))
        candidates = {"45.33.32.7": "dns", "8.8.8.8": "censys"}
        meta = {}
        kept = [ip for ip, _ in od._dedup_and_filter(candidates, {"resolved_ips": set()}, ctx, meta)]
        self.assertEqual(kept, ["8.8.8.8"])
        self.assertEqual(meta["dropped"]["roe"], 1)

    def test_end_to_end_never_probes_dropped_ip(self):
        """A planted metadata/internal IP must never reach the _fetch probe."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)
        probed = []

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            probed.append(url)
            return {"text": "x", "status": 200, "headers": {}, "cookies": ""}

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["169.254.169.254", "10.0.0.5"]), \
             patch.object(od, "_discover_via_email_records", return_value=["127.0.0.1"]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        # every candidate was internal -> nothing kept, nothing probed
        self.assertEqual(out["confirmed"], [])
        self.assertEqual(probed, [])


class TestScoring(unittest.TestCase):
    def test_status_adjustment(self):
        self.assertAlmostEqual(od._status_adjustment(200, 200), 0.05)
        self.assertAlmostEqual(od._status_adjustment(404, 404), -0.10)
        self.assertAlmostEqual(od._status_adjustment(200, 500), -0.20)
        self.assertAlmostEqual(od._status_adjustment(301, 302), 0.0)

    def test_overall_score_weights(self):
        # perfect html + cert + headers, matching 200 -> 1.0 (clamped, +0.05 bonus)
        self.assertAlmostEqual(od._overall_score(1.0, 1.0, 1.0, 200, 200), 1.0)
        # html only
        self.assertAlmostEqual(od._overall_score(1.0, 0.0, 0.0, 301, 302), 0.60)

    def test_confirm_crosses_threshold(self):
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)
        ref = {"text": "hello origin body", "status": 200,
               "headers": {"server": "nginx"}, "cookies": ""}
        cand = {"text": "hello origin body", "status": 200,
                "headers": {"server": "nginx"}, "cookies": ""}

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            return ref if url.startswith("https://www.example.com") else cand

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["8.8.8.8"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.0), \
             patch.object(od, "_port_open", return_value=True), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(len(out["confirmed"]), 1)
        f = out["confirmed"][0]
        self.assertEqual(f["matched_ip"], "8.8.8.8")
        self.assertEqual(f["type"], "waf_bypass")
        self.assertEqual(f["source"], "origin_discovery")
        self.assertGreater(f["confidence_score"], 60)

    def test_below_threshold_not_confirmed(self):
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            if url.startswith("https://www.example.com"):
                return {"text": "a" * 500, "status": 200, "headers": {"server": "nginx"}, "cookies": ""}
            return {"text": "z" * 500, "status": 404, "headers": {}, "cookies": ""}

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["8.8.8.8"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.0), \
             patch.object(od, "_port_open", return_value=True), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(out["confirmed"], [])

    def test_waf_headered_candidate_rejected(self):
        """A candidate whose response still carries a WAF header is not a bypass."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            base = {"text": "same body", "status": 200, "cookies": ""}
            if url.startswith("https://www.example.com"):
                return {**base, "headers": {"server": "nginx"}}
            return {**base, "headers": {"server": "nginx", "cf-ray": "abc"}}  # still edge

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["8.8.8.8"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.0), \
             patch.object(od, "_port_open", return_value=True), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(out["confirmed"], [])


class TestReferenceRedirect(unittest.TestCase):
    def test_reference_fetch_follows_redirects(self):
        """Regression (F2): the trusted reference fetch MUST follow redirects, or a
        301-fronted host yields an empty reference body and every origin is missed.
        Candidate probes must still NOT follow (SSRF) — asserted by other tests."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            if url.startswith("https://www.example.com"):
                # the fronted host 301s: body is only non-empty if redirects followed
                body = "shared origin body" if allow_redirects else ""
                return {"text": body, "status": 200, "headers": {"server": "nginx"}, "cookies": ""}
            return {"text": "shared origin body", "status": 200, "headers": {"server": "nginx"}, "cookies": ""}

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["8.8.8.8"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.0), \
             patch.object(od, "_port_open", return_value=True), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(len(out["confirmed"]), 1,
                         "reference fetch did not follow the 301 -> origin silently missed")


class TestCacheAndBudget(unittest.TestCase):
    def test_cache_one_call_for_shared_domain(self):
        ctx = od._RunCtx(_settings())
        calls = {"n": 0}

        def _producer():
            calls["n"] += 1
            return ["8.8.8.8"]

        r1 = ctx.cached("shodan", "hostname:www.example.com", _producer)
        r2 = ctx.cached("shodan", "hostname:www.example.com", _producer)
        self.assertEqual(r1, r2)
        self.assertEqual(calls["n"], 1)  # second call served from cache

    def test_budget_stops_keyed_and_cache_does_not_draw(self):
        ctx = od._RunCtx(_settings(ORIGIN_DISCOVERY_MAX_SEARCH_CALLS=1))
        self.assertTrue(ctx.budget.take())
        self.assertFalse(ctx.budget.take())   # only 1 allowed
        # a cached hit re-served does not call take()
        ctx._cache[("shodan", "q")] = ["1.2.3.4"]
        self.assertEqual(ctx.cached("shodan", "q", lambda: ["nope"]), ["1.2.3.4"])
        self.assertEqual(ctx.budget.remaining, 0)


class TestSources(unittest.TestCase):
    def test_email_records_spf_and_mx(self):
        ctx = od._RunCtx(_settings())
        fake_dns = MagicMock()

        class _RR:
            def __init__(self, s): self._s = s; self.strings = None; self.exchange = s
            def __str__(self): return self._s

        def _resolve(name, rtype):
            if rtype == "TXT":
                return [_RR('"v=spf1 ip4:8.8.8.0/30 ip4:9.9.9.9 include:x -all"')]
            if rtype == "MX":
                return [_RR("mail.example.com"), _RR("aspmx.l.google.com")]  # google skipped
            raise Exception("no")
        fake_dns.resolver.resolve.side_effect = _resolve

        with patch.dict("sys.modules", {"dns": fake_dns, "dns.resolver": fake_dns.resolver}), \
             patch.object(od, "_resolve_ips", return_value={"7.7.7.7"}):
            ips = set(od._discover_via_email_records("example.com", ctx))
        self.assertIn("9.9.9.9", ips)          # single ip4
        self.assertIn("8.8.8.1", ips)          # expanded from /30
        self.assertIn("7.7.7.7", ips)          # non-google MX resolved

    def test_never_raise_source_recorded(self):
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", side_effect=RuntimeError("boom")), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        meta = out["candidates_meta"]["www.example.com"]
        self.assertIn("dns", meta["errors"])
        self.assertEqual(out["confirmed"], [])  # did not crash

    def test_keyless_only_no_keys(self):
        """With no keys and scanners/passive off, keyless still runs and returns cleanly."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)
        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=[]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(out["confirmed"], [])
        self.assertIn("www.example.com", out["candidates_meta"])


class TestGatingAndIsolation(unittest.TestCase):
    def test_disabled_returns_empty(self):
        out = od.run_origin_discovery_enrichment_isolated(_fronted_result(), _settings(ORIGIN_DISCOVERY_ENABLED=False))
        self.assertEqual(out, {"confirmed": [], "candidates_meta": {}})

    def test_no_fronted_hosts(self):
        combined = {"http_probe": {"by_url": {"https://x.com": {"host": "x.com", "ip": "8.8.8.8", "is_cdn": False}}}}
        out = od.run_origin_discovery_enrichment_isolated(combined, _settings())
        self.assertEqual(out["confirmed"], [])

    def test_isolated_does_not_mutate_input(self):
        combined = _fronted_result()
        snapshot = copy.deepcopy(combined)
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)
        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=[]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]):
            payload = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(combined, snapshot)                 # input untouched
        self.assertNotIn("origin_discovery", combined)       # only the snapshot got it
        self.assertIn("confirmed", payload)


class TestStableVulnId(unittest.TestCase):
    def test_process_stable_and_converges(self):
        from graph_db.mixins.recon.vuln_mixin import stable_vuln_id
        a = stable_vuln_id("waf_bypass", "https://8.8.8.8", "8.8.8.8", "u1", "p1")
        b = stable_vuln_id("waf_bypass", "https://8.8.8.8", "8.8.8.8", "u1", "p1")
        self.assertEqual(a, b)                          # deterministic (not process-random)
        self.assertEqual(len(a), 12)
        self.assertNotEqual(a, stable_vuln_id("waf_bypass", "https://9.9.9.9", "9.9.9.9", "u1", "p1"))

    def test_tenant_salt_prevents_cross_tenant_collision(self):
        """F1: the SAME (type,url,ip) in two tenants must NOT share a Vulnerability id."""
        from graph_db.mixins.recon.vuln_mixin import stable_vuln_id
        a = stable_vuln_id("waf_bypass", "https://1.2.3.4", "1.2.3.4", "userA", "projA")
        b = stable_vuln_id("waf_bypass", "https://1.2.3.4", "1.2.3.4", "userB", "projB")
        self.assertNotEqual(a, b)
        # ... but the same exposure within one tenant still converges (security_check
        # and origin_discovery both land on one node) and re-runs are idempotent.
        again = stable_vuln_id("waf_bypass", "https://1.2.3.4", "1.2.3.4", "userA", "projA")
        self.assertEqual(a, again)


class TestRegistrableDomain(unittest.TestCase):
    def test_multi_label_public_suffix(self):
        # F3: www.acme.co.uk must resolve to acme.co.uk, not co.uk
        self.assertEqual(od._registrable_domain("www.acme.co.uk"), "acme.co.uk")
        self.assertEqual(od._registrable_domain("shop.acme.com.au"), "acme.com.au")
        self.assertEqual(od._registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(od._registrable_domain("example.com"), "example.com")
        self.assertEqual(od._registrable_domain("acme.co.uk"), "acme.co.uk")


class TestNoRedirectFollow(unittest.TestCase):
    def test_fetch_does_not_follow_redirects(self):
        """F2: candidate probes must not follow a 3xx (SSRF pivot past the G11 gate)."""
        captured = {}

        class _Resp:
            status_code = 301
            headers = {"Location": "http://169.254.169.254/"}
            def __init__(self): self.raw = MagicMock(); self.raw.read.return_value = b""
            def close(self): pass

        def _fake_get(url, **kwargs):
            captured.update(kwargs)
            return _Resp()

        ctx = od._RunCtx(_settings())
        with patch.object(od.requests, "get", side_effect=_fake_get):
            od._fetch("https://1.2.3.4:443", "", ctx)
        self.assertIs(captured.get("allow_redirects"), False)


class TestCacheDoesNotPoison(unittest.TestCase):
    def test_empty_result_not_cached(self):
        """F4: an empty (often transient-error) result is not cached, so later hosts retry."""
        ctx = od._RunCtx(_settings())
        calls = {"n": 0}

        def _producer():
            calls["n"] += 1
            return []      # simulate a transient failure that a producer swallows to []

        ctx.cached("otx", "example.com", _producer)
        ctx.cached("otx", "example.com", _producer)
        self.assertEqual(calls["n"], 2)             # re-queried, not served a poisoned []
        # a non-empty result IS cached (still one call for N hosts sharing a key)
        calls["n"] = 0
        ctx.cached("otx", "good.com", lambda: (calls.__setitem__("n", calls["n"] + 1) or ["1.2.3.4"]))
        r = ctx.cached("otx", "good.com", lambda: (calls.__setitem__("n", calls["n"] + 1) or ["9.9.9.9"]))
        self.assertEqual(calls["n"], 1)
        self.assertEqual(r, ["1.2.3.4"])


class TestPortPrecheck(unittest.TestCase):
    def test_closed_ports_skipped(self):
        """F6: a candidate whose ports are all closed is never HTTP/TLS-probed."""
        ctx = od._RunCtx(_settings())
        ref = {"text": "body", "status": 200, "headers": {}, "cookies": ""}
        fetched = []
        with patch.object(od, "_port_open", return_value=False), \
             patch.object(od, "_fetch", side_effect=lambda *a, **k: fetched.append(a) or ref):
            match = od._score_candidate("www.example.com", ref, "8.8.8.8", ctx)
        self.assertIsNone(match)
        self.assertEqual(fetched, [])   # no HTTP probe when no port is open


class TestFaviconHash(unittest.TestCase):
    def test_prefers_existing_hash(self):
        ctx = od._RunCtx(_settings())
        # a hash already on the http_probe entry is used verbatim, no self-fetch
        self.assertEqual(od._favicon_hash_for_host("www.example.com", 987654, ctx), 987654)


if __name__ == "__main__":
    unittest.main()


class TestIPv6Candidate(unittest.TestCase):
    def test_url_host_brackets_ipv6(self):
        # F1: IPv6 literals must be bracketed for a valid URL; IPv4 untouched.
        self.assertEqual(od._url_host("2001:4860:4860::8888"), "[2001:4860:4860::8888]")
        self.assertEqual(od._url_host("45.33.32.10"), "45.33.32.10")

    def test_ipv6_candidate_probed_with_bracketed_url(self):
        """F1: an IPv6 candidate reaches _fetch with a bracketed (parseable) URL,
        instead of `https://2001:...:443` which requests rejects as InvalidURL."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)
        probed = []

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            probed.append(url)
            return {"text": "shared", "status": 200, "headers": {"server": "nginx"}, "cookies": ""}

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["2001:4860:4860::8888"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.0), \
             patch.object(od, "_port_open", return_value=True), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            od.run_origin_discovery_enrichment_isolated(combined, s)
        candidate_urls = [u for u in probed if "2001:4860" in u]
        self.assertTrue(candidate_urls, "IPv6 candidate was never probed")
        self.assertTrue(all("[2001:4860:4860::8888]" in u for u in candidate_urls),
                        f"IPv6 URL not bracketed: {candidate_urls}")


class TestEmptyReferenceCertConfirm(unittest.TestCase):
    def test_confirms_on_exact_cert_when_reference_has_no_html(self):
        """F4: an API/empty-body fronted host gives no HTML to compare; a strong
        cert match (>=0.5) must still confirm the origin instead of silently missing it."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            if url.startswith("https://www.example.com"):
                return {"text": "", "status": 200, "headers": {}, "cookies": ""}   # empty reference
            return {"text": "some body", "status": 200, "headers": {}, "cookies": ""}

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["45.33.32.10"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.6), \
             patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(len(out["confirmed"]), 1, "empty-reference origin missed despite an exact cert match")
        self.assertGreaterEqual(out["confirmed"][0]["confidence_score"], 50)

    def test_no_confirm_on_weak_cert_when_reference_empty(self):
        """The empty-reference path must NOT confirm on a weak cert (< 0.5)."""
        combined = _fronted_result()
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)

        def _fake_fetch(url, host_header, ctx, allow_redirects=False):
            if url.startswith("https://www.example.com"):
                return {"text": "", "status": 200, "headers": {}, "cookies": ""}
            return {"text": "some body", "status": 200, "headers": {}, "cookies": ""}

        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_discover_via_subdomains", return_value=["45.33.32.10"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_compare_certs", return_value=0.25), \
             patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
             patch.object(od, "_fetch", side_effect=_fake_fetch):
            out = od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(out["confirmed"], [])


class TestKeylessPerDomainCache(unittest.TestCase):
    def test_crtsh_runs_once_for_two_hosts_of_one_domain(self):
        """F2: crt.sh (and subdomain/email) must be memoized by registrable domain,
        so two fronted subdomains of one domain don't each re-run it."""
        combined = {"http_probe": {"by_url": {
            "https://www.example.com": {"host": "www.example.com", "ip": "104.16.1.1", "is_cdn": True, "cdn": "cloudflare"},
            "https://api.example.com": {"host": "api.example.com", "ip": "104.16.1.2", "is_cdn": True, "cdn": "cloudflare"},
        }}}
        s = _settings(ORIGIN_DISCOVERY_SCANNERS=False, ORIGIN_DISCOVERY_PASSIVE_DNS=False)
        crtsh = MagicMock(return_value=["45.33.32.10"])
        with patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_resolve_ips", return_value=set()), \
             patch.object(od, "_discover_via_subdomains", return_value=[]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", crtsh), \
             patch.object(od, "_port_open", return_value=False), \
             patch.object(od, "_fetch", return_value=None):   # fully offline; only cache matters
            od.run_origin_discovery_enrichment_isolated(combined, s)
        self.assertEqual(crtsh.call_count, 1, "crt.sh re-ran per host instead of caching by domain")

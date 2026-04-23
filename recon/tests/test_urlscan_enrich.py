"""
Unit tests for URLScan.io Passive Enrichment Module (recon/main_recon_modules/urlscan_enrich.py).

Tests verify:
  - URL path parsing (_parse_url_path)
  - Domain extraction from URLs (_extract_domain_from_url)
  - API search function (_urlscan_search) with mocked HTTP responses
  - Feature gating (disabled, IP mode, empty domain)
  - Subdomain discovery and root domain exclusion
  - IP collection and deduplication
  - Domain age tracking (max across results)
  - URL deduplication (seen_urls set)
  - Output structure validation
  - Error handling (rate limit, network errors, bad JSON)

Run with: python -m pytest recon/tests/test_urlscan_enrich.py -v
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add recon dir to path
_recon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main_recon_modules")
sys.path.insert(0, _recon_dir)

from urlscan_enrich import (
    _parse_url_path,
    _extract_domain_from_url,
    _urlscan_search,
    run_urlscan_enrichment,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

URLSCAN_RESULT_1 = {
    "page": {
        "url": "https://app.example.com/login?next=/dashboard",
        "domain": "app.example.com",
        "ip": "93.184.216.34",
        "asn": "AS15133",
        "asnname": "Edgecast",
        "country": "US",
        "server": "nginx/1.21.6",
        "status": "200",  # Real API returns string
        "title": "Login - Example",
        "tlsIssuer": "R3",
        "tlsValidDays": 90,
        "tlsValidFrom": "2026-01-01T00:00:00Z",
        "tlsAgeDays": 30,
        "domainAgeDays": 365,
        "apexDomainAgeDays": 3650,
    },
    "task": {"time": "2026-03-01T12:00:00Z"},
    "screenshot": "https://urlscan.io/screenshots/abc123.png",
}

URLSCAN_RESULT_2 = {
    "page": {
        "url": "https://api.example.com/v1/users",
        "domain": "api.example.com",
        "ip": "93.184.216.35",
        "asn": "AS15133",
        "asnname": "Edgecast",
        "country": "US",
        "server": "gunicorn",
        "status": 200,
        "title": "API Docs",
        "tlsIssuer": "R3",
        "tlsValidDays": 90,
        "tlsValidFrom": "2026-02-01T00:00:00Z",
        "tlsAgeDays": 15,
        "domainAgeDays": 400,
        "apexDomainAgeDays": 3700,
    },
    "task": {"time": "2026-03-10T08:00:00Z"},
    "screenshot": "https://urlscan.io/screenshots/def456.png",
}

URLSCAN_RESULT_ROOT = {
    "page": {
        "url": "https://example.com/",
        "domain": "example.com",
        "ip": "93.184.216.34",
        "asn": "AS15133",
        "asnname": "Edgecast",
        "country": "US",
        "server": "nginx",
        "status": 200,
        "title": "Example Domain",
        "domainAgeDays": 300,
        "apexDomainAgeDays": 3600,
    },
    "task": {"time": "2026-02-15T10:00:00Z"},
    "screenshot": "",
}

URLSCAN_RESULT_DUPLICATE_URL = {
    "page": {
        "url": "https://app.example.com/login?next=/dashboard",
        "domain": "app.example.com",
        "ip": "93.184.216.34",
        "asn": "AS15133",
        "asnname": "Edgecast",
        "country": "US",
        "server": "nginx/1.21.6",
        "status": 200,
        "title": "Login - Example",
        "domainAgeDays": 100,
        "apexDomainAgeDays": 3000,
    },
    "task": {"time": "2026-03-05T06:00:00Z"},
    "screenshot": "",
}


def _make_combined_result(domain="example.com", ip_mode=False):
    """Create a minimal combined_result for testing."""
    return {
        "domain": domain,
        "metadata": {
            "ip_mode": ip_mode,
            "modules_executed": [],
        },
        "subdomains": [],
    }


def _enabled_settings(**overrides):
    """Return settings with URLSCAN_ENABLED=True."""
    base = {
        "URLSCAN_ENABLED": True,
        "URLSCAN_MAX_RESULTS": 500,
        "URLSCAN_API_KEY": "",
    }
    base.update(overrides)
    return base


def _disabled_settings():
    """Return settings with URLSCAN_ENABLED=False."""
    return {"URLSCAN_ENABLED": False}


# ─── Tests: _parse_url_path ──────────────────────────────────────────────────

class TestParseUrlPath(unittest.TestCase):
    """Tests for _parse_url_path() helper."""

    def test_url_with_path(self):
        result = _parse_url_path("https://example.com/login")
        self.assertIsNotNone(result)
        self.assertEqual(result["base_url"], "https://example.com")
        self.assertEqual(result["path"], "/login")
        self.assertEqual(result["params"], {})
        self.assertEqual(result["full_url"], "https://example.com/login")

    def test_url_with_path_and_query(self):
        result = _parse_url_path("https://example.com/search?q=test&page=1")
        self.assertIsNotNone(result)
        self.assertEqual(result["path"], "/search")
        self.assertEqual(result["params"], {"q": "test", "page": "1"})

    def test_url_with_query_only(self):
        """Root path with query params should still be returned."""
        result = _parse_url_path("https://example.com/?lang=en")
        self.assertIsNotNone(result)
        self.assertEqual(result["path"], "/")
        self.assertEqual(result["params"], {"lang": "en"})

    def test_root_url_returns_none(self):
        """Root path without query should return None (not meaningful)."""
        result = _parse_url_path("https://example.com/")
        self.assertIsNone(result)

    def test_root_url_no_slash_returns_none(self):
        result = _parse_url_path("https://example.com")
        self.assertIsNone(result)

    def test_multi_value_query_param(self):
        result = _parse_url_path("https://example.com/api?id=1&id=2")
        self.assertIsNotNone(result)
        self.assertEqual(result["params"]["id"], ["1", "2"])

    def test_blank_query_param(self):
        result = _parse_url_path("https://example.com/page?debug=")
        self.assertIsNotNone(result)
        self.assertEqual(result["params"]["debug"], "")

    def test_invalid_url_returns_none(self):
        result = _parse_url_path("")
        self.assertIsNone(result)

    def test_deep_path(self):
        result = _parse_url_path("https://example.com/api/v2/users/123")
        self.assertIsNotNone(result)
        self.assertEqual(result["path"], "/api/v2/users/123")
        self.assertEqual(result["base_url"], "https://example.com")


# ─── Tests: _extract_domain_from_url ─────────────────────────────────────────

class TestExtractDomainFromUrl(unittest.TestCase):
    """Tests for _extract_domain_from_url() helper."""

    def test_matching_subdomain(self):
        result = _extract_domain_from_url("https://app.example.com/path", "example.com")
        self.assertEqual(result, "app.example.com")

    def test_root_domain(self):
        result = _extract_domain_from_url("https://example.com/path", "example.com")
        self.assertEqual(result, "example.com")

    def test_non_matching_domain(self):
        result = _extract_domain_from_url("https://evil.com/path", "example.com")
        self.assertIsNone(result)

    def test_partial_match_rejected(self):
        """notexample.com should not match example.com."""
        result = _extract_domain_from_url("https://notexample.com/path", "example.com")
        self.assertIsNone(result)

    def test_empty_url(self):
        result = _extract_domain_from_url("", "example.com")
        self.assertIsNone(result)

    def test_malformed_url(self):
        result = _extract_domain_from_url("not-a-url", "example.com")
        self.assertIsNone(result)


# ─── Tests: _urlscan_search ──────────────────────────────────────────────────

class TestUrlscanSearch(unittest.TestCase):
    """Tests for _urlscan_search() with mocked HTTP responses."""

    @patch("urlscan_enrich.requests.get")
    def test_successful_search(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": [URLSCAN_RESULT_1, URLSCAN_RESULT_2]}
        mock_get.return_value = mock_resp

        results = _urlscan_search("example.com", "", 500)
        self.assertEqual(len(results), 2)

        # Verify request params
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        self.assertEqual(call_kwargs.kwargs["params"]["q"], "domain:example.com")
        self.assertEqual(call_kwargs.kwargs["params"]["size"], 500)
        self.assertEqual(call_kwargs.kwargs["headers"], {})

    @patch("urlscan_enrich.requests.get")
    def test_search_with_api_key(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": []}
        mock_get.return_value = mock_resp

        _urlscan_search("example.com", "my-secret-key", 100)

        call_kwargs = mock_get.call_args
        self.assertEqual(call_kwargs.kwargs["headers"]["API-Key"], "my-secret-key")

    @patch("urlscan_enrich.requests.get")
    def test_rate_limit_returns_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        results = _urlscan_search("example.com", "", 500)
        self.assertEqual(results, [])

    @patch("urlscan_enrich.requests.get")
    def test_server_error_returns_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_get.return_value = mock_resp

        results = _urlscan_search("example.com", "", 500)
        self.assertEqual(results, [])

    @patch("urlscan_enrich.requests.get")
    def test_network_error_returns_empty(self, mock_get):
        import requests as req
        mock_get.side_effect = req.RequestException("Connection refused")

        results = _urlscan_search("example.com", "", 500)
        self.assertEqual(results, [])

    @patch("urlscan_enrich.requests.get")
    def test_max_results_capped_at_10000(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": []}
        mock_get.return_value = mock_resp

        _urlscan_search("example.com", "", 99999)
        call_kwargs = mock_get.call_args
        self.assertEqual(call_kwargs.kwargs["params"]["size"], 10000)


# ─── Tests: run_urlscan_enrichment ───────────────────────────────────────────

class TestRunUrlscanEnrichment(unittest.TestCase):
    """Tests for the main run_urlscan_enrichment() function."""

    def test_disabled_returns_unchanged(self):
        """When disabled, should return combined_result without urlscan key."""
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _disabled_settings())
        self.assertNotIn("urlscan", result)

    def test_ip_mode_skipped(self):
        """IP mode should skip URLScan (it indexes by domain)."""
        cr = _make_combined_result(ip_mode=True)
        result = run_urlscan_enrichment(cr, _enabled_settings())
        self.assertNotIn("urlscan", result)

    def test_empty_domain_skipped(self):
        cr = _make_combined_result(domain="")
        result = run_urlscan_enrichment(cr, _enabled_settings())
        self.assertNotIn("urlscan", result)

    @patch("urlscan_enrich._urlscan_search")
    def test_no_results_returns_empty_structure(self, mock_search):
        mock_search.return_value = []
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertIn("urlscan", result)
        self.assertEqual(result["urlscan"]["results_count"], 0)
        self.assertEqual(result["urlscan"]["subdomains_discovered"], [])
        self.assertEqual(result["urlscan"]["ips_discovered"], [])
        self.assertEqual(result["urlscan"]["urls_with_paths"], [])
        self.assertEqual(result["urlscan"]["entries"], [])

    @patch("urlscan_enrich._urlscan_search")
    def test_subdomain_discovery(self, mock_search):
        """Should discover subdomains from page.domain and URL hostname."""
        mock_search.return_value = [URLSCAN_RESULT_1, URLSCAN_RESULT_2, URLSCAN_RESULT_ROOT]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        subs = result["urlscan"]["subdomains_discovered"]
        self.assertIn("app.example.com", subs)
        self.assertIn("api.example.com", subs)
        # Root domain should NOT be in subdomains
        self.assertNotIn("example.com", subs)

    @patch("urlscan_enrich._urlscan_search")
    def test_ip_collection(self, mock_search):
        mock_search.return_value = [URLSCAN_RESULT_1, URLSCAN_RESULT_2]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        ips = result["urlscan"]["ips_discovered"]
        self.assertIn("93.184.216.34", ips)
        self.assertIn("93.184.216.35", ips)
        self.assertEqual(len(ips), 2)

    @patch("urlscan_enrich._urlscan_search")
    def test_ip_deduplication(self, mock_search):
        """Same IP from multiple results should appear once."""
        mock_search.return_value = [URLSCAN_RESULT_1, URLSCAN_RESULT_ROOT]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        ips = result["urlscan"]["ips_discovered"]
        self.assertEqual(ips.count("93.184.216.34"), 1)

    @patch("urlscan_enrich._urlscan_search")
    def test_domain_age_takes_max(self, mock_search):
        """Domain age should be the max across all results."""
        mock_search.return_value = [URLSCAN_RESULT_1, URLSCAN_RESULT_2, URLSCAN_RESULT_ROOT]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        # RESULT_2 has domainAgeDays=400 (max), RESULT_1 has 365, ROOT has 300
        self.assertEqual(result["urlscan"]["domain_age_days"], 400)
        # RESULT_2 has apexDomainAgeDays=3700 (max)
        self.assertEqual(result["urlscan"]["apex_domain_age_days"], 3700)

    @patch("urlscan_enrich._urlscan_search")
    def test_url_deduplication(self, mock_search):
        """Duplicate URLs should only generate one urls_with_paths entry."""
        mock_search.return_value = [URLSCAN_RESULT_1, URLSCAN_RESULT_DUPLICATE_URL]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        paths = result["urlscan"]["urls_with_paths"]
        # Both results have the same URL, should only appear once
        full_urls = [p["full_url"] for p in paths]
        self.assertEqual(full_urls.count("https://app.example.com/login?next=/dashboard"), 1)

    @patch("urlscan_enrich._urlscan_search")
    def test_root_url_excluded_from_paths(self, mock_search):
        """Root URLs (/) should not appear in urls_with_paths."""
        mock_search.return_value = [URLSCAN_RESULT_ROOT]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertEqual(result["urlscan"]["urls_with_paths"], [])

    @patch("urlscan_enrich._urlscan_search")
    def test_entries_count_matches_results(self, mock_search):
        """Each API result should produce exactly one entry (no dedup on entries)."""
        mock_search.return_value = [URLSCAN_RESULT_1, URLSCAN_RESULT_2, URLSCAN_RESULT_DUPLICATE_URL]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertEqual(result["urlscan"]["results_count"], 3)
        self.assertEqual(len(result["urlscan"]["entries"]), 3)

    @patch("urlscan_enrich._urlscan_search")
    def test_entry_structure(self, mock_search):
        """Verify each entry has all expected keys."""
        mock_search.return_value = [URLSCAN_RESULT_1]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        entry = result["urlscan"]["entries"][0]
        expected_keys = {
            "url", "domain", "ip", "asn", "asn_name", "country",
            "server", "status", "title", "tls_issuer", "tls_valid_days",
            "tls_valid_from", "tls_age_days", "domain_age_days",
            "screenshot_url", "scan_time",
        }
        self.assertEqual(set(entry.keys()), expected_keys)
        self.assertEqual(entry["url"], "https://app.example.com/login?next=/dashboard")
        self.assertEqual(entry["ip"], "93.184.216.34")
        self.assertEqual(entry["server"], "nginx/1.21.6")
        self.assertEqual(entry["status"], "200")  # Converted to string
        self.assertEqual(entry["screenshot_url"], "https://urlscan.io/screenshots/abc123.png")

    @patch("urlscan_enrich._urlscan_search")
    def test_urls_with_paths_structure(self, mock_search):
        """Verify urls_with_paths entries have correct parsed structure."""
        mock_search.return_value = [URLSCAN_RESULT_1]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        paths = result["urlscan"]["urls_with_paths"]
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["full_url"], "https://app.example.com/login?next=/dashboard")
        self.assertEqual(p["base_url"], "https://app.example.com")
        self.assertEqual(p["path"], "/login")
        self.assertEqual(p["params"], {"next": "/dashboard"})

    @patch("urlscan_enrich._urlscan_search")
    def test_api_key_passed_through(self, mock_search):
        """API key from settings should be passed to _urlscan_search."""
        mock_search.return_value = []
        cr = _make_combined_result()
        run_urlscan_enrichment(cr, _enabled_settings(URLSCAN_API_KEY="test-key"))

        mock_search.assert_called_once_with("example.com", "test-key", 500)

    @patch("urlscan_enrich._urlscan_search")
    def test_max_results_passed_through(self, mock_search):
        mock_search.return_value = []
        cr = _make_combined_result()
        run_urlscan_enrichment(cr, _enabled_settings(URLSCAN_MAX_RESULTS=100))

        mock_search.assert_called_once_with("example.com", "", 100)

    @patch("urlscan_enrich._urlscan_search")
    def test_missing_page_fields_handled(self, mock_search):
        """Results with minimal/missing page fields should not crash."""
        minimal_result = {
            "page": {"url": "https://example.com/page", "domain": "example.com"},
            "task": {},
        }
        mock_search.return_value = [minimal_result]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertEqual(result["urlscan"]["results_count"], 1)
        entry = result["urlscan"]["entries"][0]
        self.assertEqual(entry["ip"], "")
        self.assertEqual(entry["server"], "")
        self.assertIsNone(entry["tls_valid_days"])
        self.assertIsNone(entry["domain_age_days"])

    @patch("urlscan_enrich._urlscan_search")
    def test_domain_age_none_when_no_results_report_it(self, mock_search):
        """If no results have domainAgeDays, it should remain None."""
        result_no_age = {
            "page": {"url": "https://example.com/test", "domain": "example.com", "ip": "1.2.3.4"},
            "task": {},
        }
        mock_search.return_value = [result_no_age]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertIsNone(result["urlscan"]["domain_age_days"])
        self.assertIsNone(result["urlscan"]["apex_domain_age_days"])

    @patch("urlscan_enrich._urlscan_search")
    def test_subdomains_sorted(self, mock_search):
        """Subdomains should be sorted alphabetically."""
        mock_search.return_value = [URLSCAN_RESULT_2, URLSCAN_RESULT_1]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        subs = result["urlscan"]["subdomains_discovered"]
        self.assertEqual(subs, sorted(subs))

    @patch("urlscan_enrich._urlscan_search")
    def test_ips_sorted(self, mock_search):
        """IPs should be sorted."""
        mock_search.return_value = [URLSCAN_RESULT_2, URLSCAN_RESULT_1]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        ips = result["urlscan"]["ips_discovered"]
        self.assertEqual(ips, sorted(ips))


# ─── Tests: Edge Cases ───────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """Edge case tests for urlscan enrichment."""

    @patch("urlscan_enrich._urlscan_search")
    def test_empty_page_url_skipped_for_paths(self, mock_search):
        """Entry with empty URL should not appear in urls_with_paths."""
        result_empty_url = {
            "page": {"url": "", "domain": "example.com", "ip": "1.2.3.4"},
            "task": {},
        }
        mock_search.return_value = [result_empty_url]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertEqual(result["urlscan"]["urls_with_paths"], [])

    @patch("urlscan_enrich._urlscan_search")
    def test_foreign_domain_not_discovered(self, mock_search):
        """Out-of-scope domains should not leak subdomains, IPs, or URL paths."""
        foreign_result = {
            "page": {
                "url": "https://evil.com/phishing?token=abc",
                "domain": "evil.com",
                "ip": "10.0.0.1",
                "domainAgeDays": 9999,
            },
            "task": {},
        }
        mock_search.return_value = [foreign_result]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        # Foreign domain should not appear as subdomain
        self.assertEqual(result["urlscan"]["subdomains_discovered"], [])
        # Foreign IP should NOT be collected (in-scope gate)
        self.assertEqual(result["urlscan"]["ips_discovered"], [])
        # Foreign URL paths should NOT be collected
        self.assertEqual(result["urlscan"]["urls_with_paths"], [])
        # Foreign domain age should NOT affect our domain age
        self.assertIsNone(result["urlscan"]["domain_age_days"])
        # Entry is still recorded (raw data preservation)
        self.assertEqual(len(result["urlscan"]["entries"]), 1)

    @patch("urlscan_enrich._urlscan_search")
    def test_status_converted_to_string(self, mock_search):
        """HTTP status should be converted to string (int → str)."""
        mock_search.return_value = [URLSCAN_RESULT_1]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertIsInstance(result["urlscan"]["entries"][0]["status"], str)
        self.assertEqual(result["urlscan"]["entries"][0]["status"], "200")

    @patch("urlscan_enrich._urlscan_search")
    def test_combined_result_not_mutated_when_disabled(self, mock_search):
        """Disabled enrichment should return the exact same dict."""
        cr = _make_combined_result()
        original_keys = set(cr.keys())
        result = run_urlscan_enrichment(cr, _disabled_settings())
        self.assertEqual(set(result.keys()), original_keys)
        mock_search.assert_not_called()

    @patch("urlscan_enrich._urlscan_search")
    def test_partial_domain_not_discovered_as_subdomain(self, mock_search):
        """notexample.com should NOT be discovered as a subdomain of example.com."""
        false_match_result = {
            "page": {
                "url": "https://notexample.com/page",
                "domain": "notexample.com",
                "ip": "10.0.0.1",
            },
            "task": {},
        }
        mock_search.return_value = [false_match_result]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertEqual(result["urlscan"]["subdomains_discovered"], [])

    @patch("urlscan_enrich._urlscan_search")
    def test_null_status_becomes_empty_string(self, mock_search):
        """If API returns null status, it should become '' not 'None'."""
        result_null_status = {
            "page": {"url": "https://example.com/test", "domain": "example.com", "status": None},
            "task": {},
        }
        mock_search.return_value = [result_null_status]
        cr = _make_combined_result()
        result = run_urlscan_enrichment(cr, _enabled_settings())

        self.assertEqual(result["urlscan"]["entries"][0]["status"], "")


if __name__ == "__main__":
    unittest.main()

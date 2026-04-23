"""
Unit tests for FOFA OSINT enrichment (recon/main_recon_modules/fofa_enrich.py).

Mocks requests.get for https://fofa.info/api/v1/search/all.

Coverage:
  - _fofa_auth_params()         — email:key split, plain key, edge cases
  - _parse_fofa_rows()          — 27-field rows, short rows, non-list rows, port coercion
  - _extract_ips_from_recon()   — domain IPs, subdomain IPs, IP mode expanded_ips
  - run_fofa_enrichment()       — domain mode, IP mode, disabled, no key, rate limit,
                                  HTTP errors, API error flag, max results, request exception
  - run_fofa_enrichment_isolated() — returns fofa subdict, does NOT mutate input (deepcopy)
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))

from fofa_enrich import (
    _extract_ips_from_recon,
    _fofa_auth_params,
    _parse_fofa_rows,
    run_fofa_enrichment,
    run_fofa_enrichment_isolated,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_row(
    ip="1.2.3.4",
    port="443",
    host="sub.example.com",
    domain="example.com",
    title="Test Page",
    server="nginx",
    protocol="https",
    country="US",
    country_name="United States",
    region="Virginia",
    city="Ashburn",
    isp="Amazon.com, Inc.",
    as_number="16509",
    as_organization="Amazon.com",
    os="Linux",
    product="nginx",
    version="1.19.0",
    jarm="27d40d40d00040d00042d43d000000",
    tls_version="TLSv1.3",
    certs_subject_cn="*.example.com",
    certs_subject_org="Example Inc",
    certs_issuer_cn="DigiCert Inc",
    certs_valid="true",
    icon_hash="-1234567890",
    cname="cdn.example.com",
    fid="abc123",
    lastupdatetime="2026-03-01T00:00:00Z",
) -> list:
    """Build a 27-element FOFA result row matching FOFA_FIELDS order."""
    return [
        ip, port, host, domain, title, server, protocol,
        country, country_name, region, city,
        isp, as_number, as_organization, os,
        product, version, jarm, tls_version,
        certs_subject_cn, certs_subject_org, certs_issuer_cn, certs_valid,
        icon_hash, cname, fid, lastupdatetime,
    ]


def _fofa_success_body(rows=None) -> dict:
    if rows is None:
        rows = [_full_row()]
    return {"error": False, "size": len(rows), "results": rows}


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _combined_result(ip_mode: bool = False, ips: list[str] | None = None) -> dict:
    ipv4 = ips if ips is not None else ["1.2.3.4"]
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": ip_mode, "modules_executed": [], "expanded_ips": ipv4 if ip_mode else []},
        "dns": {"domain": {"ips": {"ipv4": ipv4}}, "subdomains": {}},
    }


def _settings(**overrides) -> dict:
    base = {
        "FOFA_ENABLED": True,
        "FOFA_API_KEY": "fofa-key",
        "FOFA_KEY_ROTATOR": None,
        "FOFA_MAX_RESULTS": 100,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _fofa_auth_params
# ---------------------------------------------------------------------------

class TestFofaAuthParams(unittest.TestCase):
    """_fofa_auth_params splits email:key or returns key-only."""

    def test_plain_key_returns_key_only(self):
        result = _fofa_auth_params("myapikey123")
        self.assertEqual(result, {"key": "myapikey123"})

    def test_email_key_format_splits_correctly(self):
        result = _fofa_auth_params("user@example.com:myapikey123")
        self.assertEqual(result, {"email": "user@example.com", "key": "myapikey123"})

    def test_email_key_with_whitespace_stripped(self):
        result = _fofa_auth_params("  user@example.com : myapikey123  ")
        self.assertEqual(result, {"email": "user@example.com", "key": "myapikey123"})

    def test_only_first_colon_is_separator(self):
        # Key itself may have a colon — only the FIRST colon separates email from key
        result = _fofa_auth_params("user@example.com:key:withcolon")
        self.assertEqual(result["email"], "user@example.com")
        self.assertEqual(result["key"], "key:withcolon")

    def test_empty_key_returns_key_only(self):
        result = _fofa_auth_params("")
        self.assertEqual(result, {"key": ""})


# ---------------------------------------------------------------------------
# _parse_fofa_rows
# ---------------------------------------------------------------------------

class TestParseFofaRows(unittest.TestCase):
    """_parse_fofa_rows converts FOFA array-of-arrays into list[dict]."""

    def test_full_row_all_fields_present(self):
        data = _fofa_success_body()
        rows, total = _parse_fofa_rows(data)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        # Core identity fields
        self.assertEqual(r["ip"], "1.2.3.4")
        self.assertEqual(r["port"], 443)
        self.assertEqual(r["host"], "sub.example.com")
        self.assertEqual(r["domain"], "example.com")
        # Web/service fields
        self.assertEqual(r["title"], "Test Page")
        self.assertEqual(r["server"], "nginx")
        self.assertEqual(r["protocol"], "https")
        # Geo fields
        self.assertEqual(r["country"], "US")
        self.assertEqual(r["country_name"], "United States")
        self.assertEqual(r["region"], "Virginia")
        self.assertEqual(r["city"], "Ashburn")
        # Network fields
        self.assertEqual(r["isp"], "Amazon.com, Inc.")
        self.assertEqual(r["as_number"], "16509")
        self.assertEqual(r["as_organization"], "Amazon.com")
        self.assertEqual(r["os"], "Linux")
        # Product/version
        self.assertEqual(r["product"], "nginx")
        self.assertEqual(r["version"], "1.19.0")
        # TLS fingerprinting
        self.assertEqual(r["jarm"], "27d40d40d00040d00042d43d000000")
        self.assertEqual(r["tls_version"], "TLSv1.3")
        # Certificate fields
        self.assertEqual(r["certs_subject_cn"], "*.example.com")
        self.assertEqual(r["certs_subject_org"], "Example Inc")
        self.assertEqual(r["certs_issuer_cn"], "DigiCert Inc")
        self.assertEqual(r["certs_valid"], "true")
        # Other fields
        self.assertEqual(r["icon_hash"], "-1234567890")
        self.assertEqual(r["cname"], "cdn.example.com")
        self.assertEqual(r["fid"], "abc123")
        self.assertEqual(r["lastupdatetime"], "2026-03-01T00:00:00Z")

    def test_total_comes_from_size_field(self):
        data = {"error": False, "size": 42, "results": [_full_row()]}
        _, total = _parse_fofa_rows(data)
        self.assertEqual(total, 42)

    def test_total_falls_back_to_row_count_when_size_missing(self):
        data = {"error": False, "results": [_full_row(), _full_row()]}
        _, total = _parse_fofa_rows(data)
        self.assertEqual(total, 2)

    def test_port_coerced_to_int(self):
        row = _full_row(port="8080")
        rows, _ = _parse_fofa_rows({"results": [row]})
        self.assertEqual(rows[0]["port"], 8080)
        self.assertIsInstance(rows[0]["port"], int)

    def test_port_zero_when_empty(self):
        row = _full_row(port="")
        rows, _ = _parse_fofa_rows({"results": [row]})
        self.assertEqual(rows[0]["port"], 0)

    def test_port_zero_when_invalid(self):
        row = _full_row(port="notanumber")
        rows, _ = _parse_fofa_rows({"results": [row]})
        self.assertEqual(rows[0]["port"], 0)

    def test_none_string_fields_become_empty_string(self):
        row = _full_row()
        row[4] = None   # title field is None
        row[5] = None   # server field is None
        rows, _ = _parse_fofa_rows({"results": [row]})
        self.assertEqual(rows[0]["title"], "")
        self.assertEqual(rows[0]["server"], "")

    def test_short_row_fills_missing_fields_with_empty_string(self):
        # Row with only ip, port, host — the other 24 fields should be ""
        short_row = ["1.2.3.4", "80", "example.com"]
        rows, _ = _parse_fofa_rows({"results": [short_row]})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 80)
        self.assertEqual(rows[0]["host"], "example.com")
        # All missing fields must be empty string
        for field in ("domain", "title", "server", "protocol", "country", "country_name",
                      "region", "city", "isp", "as_number", "as_organization", "os",
                      "product", "version", "jarm", "tls_version", "certs_subject_cn",
                      "certs_subject_org", "certs_issuer_cn", "certs_valid",
                      "icon_hash", "cname", "fid", "lastupdatetime"):
            self.assertEqual(rows[0][field], "", f"field '{field}' should be empty string")

    def test_non_list_rows_are_skipped(self):
        data = {"error": False, "size": 2, "results": [
            {"ip": "1.2.3.4"},   # dict — must be skipped
            "just a string",     # string — must be skipped
            _full_row(),         # valid list
        ]}
        rows, _ = _parse_fofa_rows(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")

    def test_empty_results(self):
        rows, total = _parse_fofa_rows({"error": False, "size": 0, "results": []})
        self.assertEqual(rows, [])
        self.assertEqual(total, 0)

    def test_all_27_keys_present_in_every_row(self):
        from fofa_enrich import _FOFA_FIELD_NAMES
        rows, _ = _parse_fofa_rows({"results": [_full_row()]})
        for field in _FOFA_FIELD_NAMES:
            self.assertIn(field, rows[0], f"field '{field}' missing from parsed row")


# ---------------------------------------------------------------------------
# _extract_ips_from_recon
# ---------------------------------------------------------------------------

class TestExtractIps(unittest.TestCase):
    """_extract_ips_from_recon extracts IPs from various combined_result shapes."""

    def test_domain_ips(self):
        cr = {
            "dns": {"domain": {"ips": {"ipv4": ["1.1.1.1", "2.2.2.2"]}}, "subdomains": {}},
            "metadata": {"ip_mode": False},
        }
        result = _extract_ips_from_recon(cr)
        self.assertIn("1.1.1.1", result)
        self.assertIn("2.2.2.2", result)

    def test_subdomain_ips(self):
        cr = {
            "dns": {
                "domain": {"ips": {"ipv4": []}},
                "subdomains": {
                    "a.example.com": {"ips": {"ipv4": ["3.3.3.3"]}},
                    "b.example.com": {"ips": {"ipv4": ["4.4.4.4"]}},
                },
            },
            "metadata": {"ip_mode": False},
        }
        result = _extract_ips_from_recon(cr)
        self.assertIn("3.3.3.3", result)
        self.assertIn("4.4.4.4", result)

    def test_deduplication(self):
        cr = {
            "dns": {
                "domain": {"ips": {"ipv4": ["1.1.1.1"]}},
                "subdomains": {"a.example.com": {"ips": {"ipv4": ["1.1.1.1"]}}},
            },
            "metadata": {"ip_mode": False},
        }
        result = _extract_ips_from_recon(cr)
        self.assertEqual(result.count("1.1.1.1"), 1)

    def test_ip_mode_uses_expanded_ips(self):
        cr = {
            "dns": {"domain": {"ips": {"ipv4": []}}, "subdomains": {}},
            "metadata": {"ip_mode": True, "expanded_ips": ["5.5.5.5", "6.6.6.6"]},
        }
        result = _extract_ips_from_recon(cr)
        self.assertIn("5.5.5.5", result)
        self.assertIn("6.6.6.6", result)

    def test_empty_dns_returns_empty_list(self):
        cr = {"dns": {}, "metadata": {"ip_mode": False}}
        result = _extract_ips_from_recon(cr)
        self.assertEqual(result, [])

    def test_result_is_sorted(self):
        cr = {
            "dns": {"domain": {"ips": {"ipv4": ["10.0.0.2", "10.0.0.1"]}}, "subdomains": {}},
            "metadata": {"ip_mode": False},
        }
        result = _extract_ips_from_recon(cr)
        self.assertEqual(result, sorted(result))


# ---------------------------------------------------------------------------
# run_fofa_enrichment — domain mode
# ---------------------------------------------------------------------------

class TestFofaEnrichDomainMode(unittest.TestCase):

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_success_adds_fofa_key(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        out = run_fofa_enrichment(_combined_result(), _settings())
        self.assertIn("fofa", out)
        self.assertEqual(len(out["fofa"]["results"]), 1)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_all_new_fields_in_result_row(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        out = run_fofa_enrichment(_combined_result(), _settings())
        row = out["fofa"]["results"][0]
        for field in ("country_name", "region", "isp", "as_number", "as_organization",
                      "os", "product", "version", "jarm", "tls_version",
                      "certs_subject_cn", "certs_subject_org", "certs_issuer_cn",
                      "certs_valid", "icon_hash", "cname", "fid", "lastupdatetime"):
            self.assertIn(field, row, f"field '{field}' missing from enrichment result")

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_domain_query_uses_correct_endpoint(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings())
        url = mock_get.call_args[0][0]
        self.assertEqual(url, "https://fofa.info/api/v1/search/all")

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_domain_query_base64_encoded(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings())
        params = mock_get.call_args[1]["params"]
        decoded = base64.b64decode(params["qbase64"]).decode("utf-8")
        self.assertEqual(decoded, 'domain="example.com"')

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_plain_api_key_sends_key_param_only(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings(FOFA_API_KEY="plainkey"))
        params = mock_get.call_args[1]["params"]
        self.assertEqual(params["key"], "plainkey")
        self.assertNotIn("email", params)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_email_key_format_sends_both_params(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings(FOFA_API_KEY="user@example.com:theapikey"))
        params = mock_get.call_args[1]["params"]
        self.assertEqual(params["email"], "user@example.com")
        self.assertEqual(params["key"], "theapikey")

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_max_results_caps_output(self, mock_get, _sleep):
        # API returns 5 rows, but max is 3
        rows = [_full_row(ip=f"1.2.3.{i}") for i in range(5)]
        mock_get.return_value = _mock_response(200, _fofa_success_body(rows=rows))
        out = run_fofa_enrichment(_combined_result(), _settings(FOFA_MAX_RESULTS=3))
        self.assertEqual(len(out["fofa"]["results"]), 3)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_total_hint_from_api_size(self, mock_get, _sleep):
        body = {"error": False, "size": 9999, "results": [_full_row()]}
        mock_get.return_value = _mock_response(200, body)
        out = run_fofa_enrichment(_combined_result(), _settings())
        self.assertEqual(out["fofa"]["total"], 9999)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_no_domain_skips_query(self, mock_get, _sleep):
        cr = _combined_result()
        cr["domain"] = ""
        out = run_fofa_enrichment(cr, _settings())
        mock_get.assert_not_called()
        self.assertEqual(out["fofa"]["results"], [])

    def test_disabled_returns_unchanged(self):
        cr = _combined_result()
        out = run_fofa_enrichment(cr, _settings(FOFA_ENABLED=False))
        self.assertNotIn("fofa", out)

    def test_missing_api_key_returns_unchanged(self):
        cr = _combined_result()
        out = run_fofa_enrichment(cr, _settings(FOFA_API_KEY=""))
        self.assertNotIn("fofa", out)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_rate_limit_429_returns_empty(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="slow down")
        out = run_fofa_enrichment(_combined_result(), _settings())
        self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_http_error_returns_empty(self, mock_get, _sleep):
        for code in (400, 401, 403, 500, 503):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                out = run_fofa_enrichment(_combined_result(), _settings())
                self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_api_error_flag_returns_empty(self, mock_get, _sleep):
        body = {"error": True, "errmsg": "invalid API key"}
        mock_get.return_value = _mock_response(200, body)
        out = run_fofa_enrichment(_combined_result(), _settings())
        self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_empty_api_results_returns_empty(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"error": False, "size": 0, "results": []})
        out = run_fofa_enrichment(_combined_result(), _settings())
        self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_request_exception_handled(self, mock_get, _sleep):
        import requests as req_mod
        mock_get.side_effect = req_mod.exceptions.ConnectionError("timeout")
        out = run_fofa_enrichment(_combined_result(), _settings())
        self.assertIn("fofa", out)
        self.assertEqual(out["fofa"]["results"], [])


# ---------------------------------------------------------------------------
# run_fofa_enrichment — IP mode
# ---------------------------------------------------------------------------

class TestFofaEnrichIpMode(unittest.TestCase):

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_ip_mode_queries_each_ip(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        cr = _combined_result(ip_mode=True, ips=["1.2.3.4", "5.6.7.8"])
        run_fofa_enrichment(cr, _settings())
        self.assertEqual(mock_get.call_count, 2)
        queries = []
        for c in mock_get.call_args_list:
            qb64 = c[1]["params"]["qbase64"]
            queries.append(base64.b64decode(qb64).decode())
        self.assertIn('ip="1.2.3.4"', queries)
        self.assertIn('ip="5.6.7.8"', queries)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_ip_mode_stops_after_max_results(self, mock_get, _sleep):
        # Return 2 rows per IP. With 4 IPs and max=3, only 2 IPs should be queried.
        two_row_body = _fofa_success_body(rows=[
            _full_row(ip="1.2.3.4"),
            _full_row(ip="1.2.3.5"),
        ])
        mock_get.return_value = _mock_response(200, two_row_body)
        cr = _combined_result(ip_mode=True, ips=["1.2.3.4", "5.6.7.8", "9.0.0.1", "9.0.0.2"])
        out = run_fofa_enrichment(cr, _settings(FOFA_MAX_RESULTS=3))
        self.assertLessEqual(len(out["fofa"]["results"]), 3)
        self.assertLessEqual(mock_get.call_count, 2)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_ip_mode_rate_limit_stops_all_queries(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="rate limited")
        cr = _combined_result(ip_mode=True, ips=["1.2.3.4", "5.6.7.8"])
        out = run_fofa_enrichment(cr, _settings())
        # Only one request made before stopping on 429
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_ip_mode_aggregates_across_ips(self, mock_get, _sleep):
        def response_for_call(*args, **kwargs):
            qb64 = kwargs["params"]["qbase64"]
            q = base64.b64decode(qb64).decode()
            ip = q.split('"')[1]
            return _mock_response(200, _fofa_success_body(rows=[_full_row(ip=ip)]))

        mock_get.side_effect = response_for_call
        cr = _combined_result(ip_mode=True, ips=["1.2.3.4", "5.6.7.8"])
        out = run_fofa_enrichment(cr, _settings())
        result_ips = {r["ip"] for r in out["fofa"]["results"]}
        self.assertIn("1.2.3.4", result_ips)
        self.assertIn("5.6.7.8", result_ips)


# ---------------------------------------------------------------------------
# run_fofa_enrichment — key rotator
# ---------------------------------------------------------------------------

class TestFofaKeyRotator(unittest.TestCase):

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_rotator_key_used_when_available(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rotated-key"
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings(FOFA_API_KEY="", FOFA_KEY_ROTATOR=rotator))
        params = mock_get.call_args[1]["params"]
        self.assertEqual(params["key"], "rotated-key")

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_rotator_tick_called_after_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rot-key"
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings(FOFA_API_KEY="", FOFA_KEY_ROTATOR=rotator))
        rotator.tick.assert_called()

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_fallback_to_settings_key_when_rotator_has_no_keys(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = False
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        run_fofa_enrichment(_combined_result(), _settings(FOFA_API_KEY="fallback-key", FOFA_KEY_ROTATOR=rotator))
        params = mock_get.call_args[1]["params"]
        self.assertEqual(params["key"], "fallback-key")


# ---------------------------------------------------------------------------
# run_fofa_enrichment_isolated
# ---------------------------------------------------------------------------

class TestFofaEnrichIsolated(unittest.TestCase):

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_returns_fofa_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        sub = run_fofa_enrichment_isolated(_combined_result(), _settings())
        self.assertIn("results", sub)
        self.assertEqual(len(sub["results"]), 1)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_does_not_mutate_original_combined_result(self, mock_get, _sleep):
        """deepcopy ensures the caller's combined_result is never modified."""
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        original = _combined_result()
        original_keys = set(original.keys())
        run_fofa_enrichment_isolated(original, _settings())
        self.assertNotIn("fofa", original)
        self.assertEqual(set(original.keys()), original_keys)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_nested_mutation_not_propagated(self, mock_get, _sleep):
        """Verify deepcopy: nested dicts in original are not shared with snapshot."""
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        original = _combined_result()
        original_ips = list(original["dns"]["domain"]["ips"]["ipv4"])
        run_fofa_enrichment_isolated(original, _settings())
        self.assertEqual(original["dns"]["domain"]["ips"]["ipv4"], original_ips)

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_returns_empty_dict_when_disabled(self, mock_get, _sleep):
        sub = run_fofa_enrichment_isolated(_combined_result(), _settings(FOFA_ENABLED=False))
        self.assertEqual(sub, {})
        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()

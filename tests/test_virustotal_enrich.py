"""
Unit tests for VirusTotal enrichment (recon/main_recon_modules/virustotal_enrich.py).

Covers:
- _extract_ips_from_recon: domain mode, subdomain IPs, ip_mode
- _effective_key: plain key, rotator priority, empty
- _parse_domain_attrs: full fields, missing fields, None input, asn coercion, popularity_ranks extraction
- _parse_ip_attrs: full fields, missing fields, None input, asn int/str coercion
- _vt_get: 200, 404, 429 retry-once, other errors, network exception, no key
- run_virustotal_enrichment: disabled, no key, domain+IP success (all new fields), ip_mode skip domain,
  max_targets limiting, partial IP 404, throttle sleep, exception resilience, key rotator tick
- run_virustotal_enrichment_isolated: returns sub-dict, does not mutate original
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))

from virustotal_enrich import (
    _effective_key,
    _extract_ips_from_recon,
    _parse_domain_attrs,
    _parse_ip_attrs,
    _vt_get,
    run_virustotal_enrichment,
    run_virustotal_enrichment_isolated,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _combined_result(ips: list[str] | None = None) -> dict:
    ipv4 = ips if ips is not None else ["1.2.3.4"]
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ipv4}}, "subdomains": {}},
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _vt_domain_body() -> dict:
    """Full realistic VT v3 domain response with all fields the parser reads."""
    return {
        "data": {
            "attributes": {
                "reputation": 5,
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 10,
                    "timeout": 0,
                },
                "categories": {"Forcepoint ThreatSeeker": "technology"},
                "registrar": "GoDaddy",
                "total_votes": {"harmless": 120, "malicious": 3},
                "tags": ["phishing", "malware"],
                "last_analysis_date": 1704067200,
                "jarm": "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4",
                "popularity_ranks": {
                    "Alexa": {"rank": 15234},
                    "Cisco Umbrella": {"rank": 8901},
                    "Majestic": {"rank": 22000},
                },
                "last_dns_records_date": 1703980800,
                "last_https_certificate_date": 1703894400,
            },
        },
    }


def _vt_ip_body() -> dict:
    """Full realistic VT v3 IP response with all fields the parser reads."""
    return {
        "data": {
            "attributes": {
                "reputation": -5,
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 15,
                    "timeout": 0,
                },
                "asn": 12345,
                "as_owner": "TestOrg",
                "country": "US",
                "total_votes": {"harmless": 80, "malicious": 7},
                "tags": ["scanner", "vpn"],
                "last_analysis_date": 1704067200,
                "network": "44.224.0.0/11",
                "regional_internet_registry": "ARIN",
                "continent": "NA",
                "jarm": "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4",
            },
        },
    }


def _default_settings(**overrides) -> dict:
    base = {
        "VIRUSTOTAL_ENABLED": True,
        "VIRUSTOTAL_API_KEY": "vt-key",
        "VIRUSTOTAL_KEY_ROTATOR": None,
        "VIRUSTOTAL_RATE_LIMIT": 4,
        "VIRUSTOTAL_MAX_TARGETS": 20,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _extract_ips_from_recon
# ---------------------------------------------------------------------------

class TestExtractIps(unittest.TestCase):

    def test_domain_ipv4(self):
        cr = {"dns": {"domain": {"ips": {"ipv4": ["1.1.1.1", "2.2.2.2"]}}, "subdomains": {}}, "metadata": {}}
        self.assertEqual(_extract_ips_from_recon(cr), ["1.1.1.1", "2.2.2.2"])

    def test_subdomain_ipv4(self):
        cr = {
            "dns": {
                "domain": {"ips": {"ipv4": []}},
                "subdomains": {
                    "sub1.example.com": {"ips": {"ipv4": ["3.3.3.3"]}},
                    "sub2.example.com": {"ips": {"ipv4": ["4.4.4.4"]}},
                },
            },
            "metadata": {},
        }
        result = _extract_ips_from_recon(cr)
        self.assertIn("3.3.3.3", result)
        self.assertIn("4.4.4.4", result)

    def test_deduplication(self):
        cr = {
            "dns": {
                "domain": {"ips": {"ipv4": ["1.1.1.1"]}},
                "subdomains": {"a": {"ips": {"ipv4": ["1.1.1.1"]}}},
            },
            "metadata": {},
        }
        self.assertEqual(_extract_ips_from_recon(cr), ["1.1.1.1"])

    def test_ip_mode_uses_expanded_ips(self):
        cr = {
            "dns": {"domain": {"ips": {"ipv4": []}}, "subdomains": {}},
            "metadata": {"ip_mode": True, "expanded_ips": ["10.0.0.1", "10.0.0.2"]},
        }
        self.assertEqual(_extract_ips_from_recon(cr), ["10.0.0.1", "10.0.0.2"])

    def test_empty(self):
        cr = {"dns": {"domain": {}, "subdomains": {}}, "metadata": {}}
        self.assertEqual(_extract_ips_from_recon(cr), [])


# ---------------------------------------------------------------------------
# _effective_key
# ---------------------------------------------------------------------------

class TestEffectiveKey(unittest.TestCase):

    def test_plain_key(self):
        self.assertEqual(_effective_key("abc", None), "abc")

    def test_plain_key_stripped(self):
        self.assertEqual(_effective_key("  abc  ", None), "abc")

    def test_empty_key(self):
        self.assertEqual(_effective_key("", None), "")

    def test_rotator_wins_over_plain(self):
        rot = MagicMock()
        rot.has_keys = True
        rot.current_key = "rotated-key"
        self.assertEqual(_effective_key("plain", rot), "rotated-key")

    def test_rotator_no_keys_falls_back_to_plain(self):
        rot = MagicMock()
        rot.has_keys = False
        self.assertEqual(_effective_key("plain", rot), "plain")

    def test_rotator_none_current_key(self):
        rot = MagicMock()
        rot.has_keys = True
        rot.current_key = None
        self.assertEqual(_effective_key("plain", rot), "")


# ---------------------------------------------------------------------------
# _parse_domain_attrs
# ---------------------------------------------------------------------------

class TestParseDomainAttrs(unittest.TestCase):

    def test_none_input(self):
        self.assertIsNone(_parse_domain_attrs(None))

    def test_empty_dict(self):
        self.assertIsNone(_parse_domain_attrs({}))

    def test_full_body(self):
        result = _parse_domain_attrs(_vt_domain_body())
        self.assertIsNotNone(result)
        self.assertEqual(result["reputation"], 5)
        self.assertEqual(result["analysis_stats"]["malicious"], 1)
        self.assertEqual(result["analysis_stats"]["suspicious"], 2)
        self.assertEqual(result["analysis_stats"]["harmless"], 60)
        self.assertEqual(result["analysis_stats"]["undetected"], 10)
        self.assertEqual(result["categories"]["Forcepoint ThreatSeeker"], "technology")
        self.assertEqual(result["registrar"], "GoDaddy")
        self.assertEqual(result["total_votes"]["harmless"], 120)
        self.assertEqual(result["total_votes"]["malicious"], 3)
        self.assertEqual(result["tags"], ["phishing", "malware"])
        self.assertEqual(result["last_analysis_date"], 1704067200)
        self.assertEqual(result["jarm"], "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4")
        self.assertEqual(result["popularity_alexa"], 15234)
        self.assertEqual(result["popularity_umbrella"], 8901)
        self.assertEqual(result["last_dns_records_date"], 1703980800)
        self.assertEqual(result["last_https_certificate_date"], 1703894400)

    def test_missing_optional_fields_default_to_none_or_empty(self):
        body = {"data": {"attributes": {"reputation": 0}}}
        result = _parse_domain_attrs(body)
        self.assertEqual(result["reputation"], 0)
        self.assertEqual(result["analysis_stats"], {})
        self.assertEqual(result["categories"], {})
        self.assertIsNone(result["registrar"])
        self.assertEqual(result["total_votes"], {})
        self.assertEqual(result["tags"], [])
        self.assertIsNone(result["last_analysis_date"])
        self.assertIsNone(result["jarm"])
        self.assertIsNone(result["popularity_alexa"])
        self.assertIsNone(result["popularity_umbrella"])
        self.assertIsNone(result["last_dns_records_date"])
        self.assertIsNone(result["last_https_certificate_date"])

    def test_popularity_ranks_partial(self):
        body = {"data": {"attributes": {
            "popularity_ranks": {"Alexa": {"rank": 999}},
        }}}
        result = _parse_domain_attrs(body)
        self.assertEqual(result["popularity_alexa"], 999)
        self.assertIsNone(result["popularity_umbrella"])

    def test_popularity_ranks_missing_rank_key(self):
        body = {"data": {"attributes": {
            "popularity_ranks": {"Alexa": {}, "Cisco Umbrella": {"rank": 42}},
        }}}
        result = _parse_domain_attrs(body)
        self.assertIsNone(result["popularity_alexa"])
        self.assertEqual(result["popularity_umbrella"], 42)


# ---------------------------------------------------------------------------
# _parse_ip_attrs
# ---------------------------------------------------------------------------

class TestParseIpAttrs(unittest.TestCase):

    def test_none_input(self):
        self.assertIsNone(_parse_ip_attrs(None))

    def test_empty_dict(self):
        self.assertIsNone(_parse_ip_attrs({}))

    def test_full_body(self):
        result = _parse_ip_attrs(_vt_ip_body())
        self.assertIsNotNone(result)
        self.assertEqual(result["reputation"], -5)
        self.assertEqual(result["analysis_stats"]["malicious"], 3)
        self.assertEqual(result["analysis_stats"]["suspicious"], 1)
        self.assertEqual(result["analysis_stats"]["harmless"], 50)
        self.assertEqual(result["analysis_stats"]["undetected"], 15)
        self.assertEqual(result["asn"], 12345)
        self.assertEqual(result["as_owner"], "TestOrg")
        self.assertEqual(result["country"], "US")
        self.assertEqual(result["total_votes"]["harmless"], 80)
        self.assertEqual(result["total_votes"]["malicious"], 7)
        self.assertEqual(result["tags"], ["scanner", "vpn"])
        self.assertEqual(result["last_analysis_date"], 1704067200)
        self.assertEqual(result["network"], "44.224.0.0/11")
        self.assertEqual(result["regional_internet_registry"], "ARIN")
        self.assertEqual(result["continent"], "NA")
        self.assertEqual(result["jarm"], "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4")

    def test_asn_string_coerced_to_int(self):
        body = {"data": {"attributes": {"asn": "16509"}}}
        result = _parse_ip_attrs(body)
        self.assertIsInstance(result["asn"], int)
        self.assertEqual(result["asn"], 16509)

    def test_asn_invalid_string_becomes_none(self):
        body = {"data": {"attributes": {"asn": "not-a-number"}}}
        result = _parse_ip_attrs(body)
        self.assertIsNone(result["asn"])

    def test_missing_optional_fields_default_to_none_or_empty(self):
        body = {"data": {"attributes": {"reputation": 0}}}
        result = _parse_ip_attrs(body)
        self.assertEqual(result["reputation"], 0)
        self.assertEqual(result["analysis_stats"], {})
        self.assertIsNone(result["asn"])
        self.assertIsNone(result["as_owner"])
        self.assertIsNone(result["country"])
        self.assertEqual(result["total_votes"], {})
        self.assertEqual(result["tags"], [])
        self.assertIsNone(result["last_analysis_date"])
        self.assertIsNone(result["network"])
        self.assertIsNone(result["regional_internet_registry"])
        self.assertIsNone(result["continent"])
        self.assertIsNone(result["jarm"])


# ---------------------------------------------------------------------------
# _vt_get
# ---------------------------------------------------------------------------

class TestVtGet(unittest.TestCase):

    @patch("virustotal_enrich.requests.get")
    def test_no_key_returns_none(self, mock_get):
        result = _vt_get("domains/example.com", "", None)
        self.assertIsNone(result)
        mock_get.assert_not_called()

    @patch("virustotal_enrich.requests.get")
    def test_200_returns_json(self, mock_get):
        mock_get.return_value = _mock_response(200, {"data": "ok"})
        result = _vt_get("domains/example.com", "key", None)
        self.assertEqual(result, {"data": "ok"})
        called_url = mock_get.call_args[0][0]
        self.assertIn("domains/example.com", called_url)
        self.assertEqual(mock_get.call_args[1]["headers"]["x-apikey"], "key")

    @patch("virustotal_enrich.requests.get")
    def test_404_returns_none(self, mock_get):
        mock_get.return_value = _mock_response(404)
        result = _vt_get("domains/unknown.com", "key", None)
        self.assertIsNone(result)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_429_sleeps_and_retries_once(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rate limited")
        result = _vt_get("domains/example.com", "key", None)
        self.assertIsNone(result)
        # first 429 → sleep 65s → retry → second 429 → give up
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once_with(65)

    @patch("virustotal_enrich.requests.get")
    def test_500_returns_none(self, mock_get):
        mock_get.return_value = _mock_response(500, {}, text="server error")
        result = _vt_get("domains/example.com", "key", None)
        self.assertIsNone(result)

    @patch("virustotal_enrich.requests.get")
    def test_request_exception_returns_none(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.RequestException("connection refused")
        result = _vt_get("domains/example.com", "key", None)
        self.assertIsNone(result)

    @patch("virustotal_enrich.requests.get")
    def test_rotator_tick_called_on_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {"data": {}})
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"
        _vt_get("domains/example.com", "", rotator)
        rotator.tick.assert_called_once()


# ---------------------------------------------------------------------------
# run_virustotal_enrichment — control flow
# ---------------------------------------------------------------------------

class TestRunVirustotalEnrichment(unittest.TestCase):

    @patch("virustotal_enrich.requests.get")
    def test_disabled_skips_entirely(self, mock_get):
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, _default_settings(VIRUSTOTAL_ENABLED=False))
        self.assertNotIn("virustotal", out)
        mock_get.assert_not_called()

    @patch("virustotal_enrich.requests.get")
    def test_no_api_key_skips(self, mock_get):
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, _default_settings(VIRUSTOTAL_API_KEY=""))
        self.assertNotIn("virustotal", out)
        mock_get.assert_not_called()

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_success_domain_and_ip_all_fields(self, mock_get, _sleep):
        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            if "/ip_addresses/" in url:
                return _mock_response(200, _vt_ip_body())
            return _mock_response(404)

        mock_get.side_effect = side
        out = run_virustotal_enrichment(_combined_result(), _default_settings())

        self.assertIn("virustotal", out)
        vt = out["virustotal"]

        # --- domain report ---
        dr = vt["domain_report"]
        self.assertIsNotNone(dr)
        self.assertEqual(dr["domain"], "example.com")
        self.assertEqual(dr["reputation"], 5)
        self.assertEqual(dr["analysis_stats"]["malicious"], 1)
        self.assertEqual(dr["analysis_stats"]["suspicious"], 2)
        self.assertEqual(dr["analysis_stats"]["harmless"], 60)
        self.assertEqual(dr["analysis_stats"]["undetected"], 10)
        self.assertEqual(dr["categories"]["Forcepoint ThreatSeeker"], "technology")
        self.assertEqual(dr["registrar"], "GoDaddy")
        self.assertEqual(dr["total_votes"]["harmless"], 120)
        self.assertEqual(dr["total_votes"]["malicious"], 3)
        self.assertEqual(dr["tags"], ["phishing", "malware"])
        self.assertEqual(dr["last_analysis_date"], 1704067200)
        self.assertEqual(dr["jarm"], "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4")
        self.assertEqual(dr["popularity_alexa"], 15234)
        self.assertEqual(dr["popularity_umbrella"], 8901)
        self.assertEqual(dr["last_dns_records_date"], 1703980800)
        self.assertEqual(dr["last_https_certificate_date"], 1703894400)

        # --- ip report ---
        self.assertEqual(len(vt["ip_reports"]), 1)
        ipr = vt["ip_reports"][0]
        self.assertEqual(ipr["ip"], "1.2.3.4")
        self.assertEqual(ipr["reputation"], -5)
        self.assertEqual(ipr["analysis_stats"]["malicious"], 3)
        self.assertEqual(ipr["analysis_stats"]["suspicious"], 1)
        self.assertEqual(ipr["asn"], 12345)
        self.assertEqual(ipr["as_owner"], "TestOrg")
        self.assertEqual(ipr["country"], "US")
        self.assertEqual(ipr["total_votes"]["harmless"], 80)
        self.assertEqual(ipr["total_votes"]["malicious"], 7)
        self.assertEqual(ipr["tags"], ["scanner", "vpn"])
        self.assertEqual(ipr["last_analysis_date"], 1704067200)
        self.assertEqual(ipr["network"], "44.224.0.0/11")
        self.assertEqual(ipr["regional_internet_registry"], "ARIN")
        self.assertEqual(ipr["continent"], "NA")
        self.assertEqual(ipr["jarm"], "27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4")

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_ip_mode_skips_domain_report(self, mock_get, _sleep):
        def side(url, **_kw):
            if "/ip_addresses/" in url:
                return _mock_response(200, _vt_ip_body())
            return _mock_response(404)

        mock_get.side_effect = side
        cr = {
            "domain": "example.com",
            "metadata": {"ip_mode": True, "expanded_ips": ["5.5.5.5"], "modules_executed": []},
            "dns": {"domain": {"ips": {"ipv4": []}}, "subdomains": {}},
        }
        out = run_virustotal_enrichment(cr, _default_settings())
        self.assertIsNone(out["virustotal"]["domain_report"])
        self.assertEqual(len(out["virustotal"]["ip_reports"]), 1)
        for c in mock_get.call_args_list:
            self.assertNotIn("/domains/", c[0][0])

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_max_targets_limits_ip_requests(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _vt_ip_body())
        ips = [f"93.184.{i}.1" for i in range(1, 11)]  # 10 IPs
        cr = _combined_result(ips=ips)
        cr["domain"] = ""  # skip domain request
        out = run_virustotal_enrichment(cr, _default_settings(VIRUSTOTAL_MAX_TARGETS=3))
        self.assertEqual(len(out["virustotal"]["ip_reports"]), 3)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_max_targets_zero_skips_all_ips(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _vt_ip_body())
        cr = _combined_result(ips=["1.2.3.4", "5.6.7.8"])
        cr["domain"] = ""
        out = run_virustotal_enrichment(cr, _default_settings(VIRUSTOTAL_MAX_TARGETS=0))
        self.assertEqual(out["virustotal"]["ip_reports"], [])

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_throttle_sleep_between_requests(self, mock_get, mock_sleep):
        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            return _mock_response(200, _vt_ip_body())

        mock_get.side_effect = side
        run_virustotal_enrichment(_combined_result(), _default_settings(VIRUSTOTAL_RATE_LIMIT=4))
        # throttle = 60/4 = 15.0 — must sleep before the IP request
        throttle_calls = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 15.0]
        self.assertGreaterEqual(len(throttle_calls), 1)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_partial_ip_404_continues(self, mock_get, _sleep):
        call_count = {"n": 0}

        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _mock_response(404)
            return _mock_response(200, _vt_ip_body())

        mock_get.side_effect = side
        cr = _combined_result(ips=["1.1.1.1", "2.2.2.2"])
        out = run_virustotal_enrichment(cr, _default_settings())
        # first IP 404 → skipped; second IP success
        self.assertEqual(len(out["virustotal"]["ip_reports"]), 1)
        self.assertEqual(out["virustotal"]["ip_reports"][0]["ip"], "2.2.2.2")

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_domain_404_still_processes_ips(self, mock_get, _sleep):
        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(404)
            return _mock_response(200, _vt_ip_body())

        mock_get.side_effect = side
        out = run_virustotal_enrichment(_combined_result(), _default_settings())
        self.assertIsNone(out["virustotal"]["domain_report"])
        self.assertEqual(len(out["virustotal"]["ip_reports"]), 1)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_exception_inside_loop_still_writes_virustotal_key(self, mock_get, _sleep):
        mock_get.side_effect = Exception("unexpected crash")
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, _default_settings())
        # Key must be present even after exception
        self.assertIn("virustotal", out)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_key_rotator_tick_called_per_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"

        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            return _mock_response(200, _vt_ip_body())

        mock_get.side_effect = side
        run_virustotal_enrichment(
            _combined_result(),
            _default_settings(VIRUSTOTAL_KEY_ROTATOR=rotator, VIRUSTOTAL_API_KEY=""),
        )
        # 1 domain + 1 IP = 2 ticks
        self.assertEqual(rotator.tick.call_count, 2)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_rate_limit_429_backs_off_60s(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        out = run_virustotal_enrichment(_combined_result(), _default_settings())
        self.assertIsNone(out["virustotal"]["domain_report"])
        self.assertEqual(out["virustotal"]["ip_reports"], [])
        long_sleeps = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 65]
        self.assertGreaterEqual(len(long_sleeps), 1)


# ---------------------------------------------------------------------------
# run_virustotal_enrichment_isolated
# ---------------------------------------------------------------------------

class TestRunVirustotalEnrichmentIsolated(unittest.TestCase):

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_returns_virustotal_subdict(self, mock_get, _sleep):
        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            return _mock_response(200, _vt_ip_body())

        mock_get.side_effect = side
        sub = run_virustotal_enrichment_isolated(_combined_result(), _default_settings())
        self.assertIn("domain_report", sub)
        self.assertIn("ip_reports", sub)
        self.assertNotIn("domain", sub)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_does_not_mutate_original(self, mock_get, _sleep):
        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            return _mock_response(200, _vt_ip_body())

        mock_get.side_effect = side
        original = _combined_result()
        run_virustotal_enrichment_isolated(original, _default_settings())
        self.assertNotIn("virustotal", original)

    @patch("virustotal_enrich.requests.get")
    def test_empty_result_when_disabled(self, mock_get):
        sub = run_virustotal_enrichment_isolated(
            _combined_result(), _default_settings(VIRUSTOTAL_ENABLED=False)
        )
        self.assertEqual(sub, {})
        mock_get.assert_not_called()

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_all_new_ip_fields_present_in_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _vt_ip_body())
        cr = _combined_result()
        cr["domain"] = ""  # skip domain
        sub = run_virustotal_enrichment_isolated(cr, _default_settings())
        ipr = sub["ip_reports"][0]
        for field in ("total_votes", "tags", "last_analysis_date", "network",
                      "regional_internet_registry", "continent", "jarm"):
            self.assertIn(field, ipr, f"missing field: {field}")

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_all_new_domain_fields_present_in_subdict(self, mock_get, _sleep):
        def side(url, **_kw):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            return _mock_response(404)

        mock_get.side_effect = side
        cr = _combined_result(ips=[])
        sub = run_virustotal_enrichment_isolated(cr, _default_settings())
        dr = sub["domain_report"]
        for field in ("total_votes", "tags", "last_analysis_date", "jarm",
                      "popularity_alexa", "popularity_umbrella",
                      "last_dns_records_date", "last_https_certificate_date", "registrar"):
            self.assertIn(field, dr, f"missing domain field: {field}")


if __name__ == "__main__":
    unittest.main()

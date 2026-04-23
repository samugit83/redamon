"""
Unit tests for Netlas OSINT enrichment (recon/main_recon_modules/netlas_enrich.py).

Mocks requests.get for https://app.netlas.io/api/responses/.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))

from netlas_enrich import (
    _netlas_item_to_result,
    _parse_netlas_body,
    run_netlas_enrichment,
    run_netlas_enrichment_isolated,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _combined_result() -> dict:
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}}, "subdomains": {}},
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _netlas_body() -> dict:
    """Rich fixture that exercises every field path in _netlas_item_to_result."""
    return {
        "items": [
            {
                "data": {
                    "host": "1.2.3.4",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "protocol": "https",
                    "isp": "TestISP",
                    "http": {"title": "Test", "status_code": 200},
                    "geo": {
                        "country": "US",
                        "city": "Ashburn",
                        "latitude": 39.04,
                        "longitude": -77.49,
                        "time_zone": "America/New_York",
                        "asn": {"number": "AS14618", "route": "44.224.0.0/11"},
                    },
                    "whois": {"asn": {"name": "AMAZON-AES"}},
                    "ssh": {"banner": "SSH-2.0-OpenSSH_8.9"},
                    "cve": [
                        {"name": "CVE-2021-44228", "base_score": 10.0, "severity": "CRITICAL", "has_exploit": True},
                        {"name": "CVE-2022-0001", "base_score": 5.5, "severity": "Medium", "has_exploit": False},
                    ],
                },
            },
        ],
        "count": 1,
    }


# ---------------------------------------------------------------------------
# Unit tests for _netlas_item_to_result (the field-mapping core)
# ---------------------------------------------------------------------------

class TestNetlasItemToResult(unittest.TestCase):
    """Direct unit tests for the _netlas_item_to_result parser."""

    def _full_data(self) -> dict:
        return _netlas_body()["items"][0]["data"]

    # --- happy-path: all fields present ---

    def test_basic_fields(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(row["host"], "1.2.3.4")
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["port"], 443)
        self.assertEqual(row["protocol"], "https")
        self.assertEqual(row["isp"], "TestISP")

    def test_http_fields(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(row["title"], "Test")
        self.assertEqual(row["http_status_code"], 200)

    def test_geolocation_fields(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(row["country"], "US")
        self.assertEqual(row["city"], "Ashburn")
        self.assertAlmostEqual(row["latitude"], 39.04)
        self.assertAlmostEqual(row["longitude"], -77.49)
        self.assertEqual(row["timezone"], "America/New_York")

    def test_asn_from_geo(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(row["asn_number"], "AS14618")
        self.assertEqual(row["asn_route"], "44.224.0.0/11")

    def test_asn_name_from_whois(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(row["asn_name"], "AMAZON-AES")

    def test_ssh_banner(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(row["banner"], "SSH-2.0-OpenSSH_8.9")

    def test_cve_list_parsed(self):
        row = _netlas_item_to_result(self._full_data())
        self.assertEqual(len(row["cve_list"]), 2)

        cve0 = row["cve_list"][0]
        self.assertEqual(cve0["id"], "CVE-2021-44228")
        self.assertEqual(cve0["base_score"], 10.0)
        self.assertEqual(cve0["severity"], "critical")   # lowercased
        self.assertTrue(cve0["has_exploit"])

        cve1 = row["cve_list"][1]
        self.assertEqual(cve1["id"], "CVE-2022-0001")
        self.assertEqual(cve1["severity"], "medium")     # lowercased
        self.assertFalse(cve1["has_exploit"])

    # --- CVE edge cases ---

    def test_cve_id_via_name_key(self):
        data = {"ip": "1.1.1.1", "cve": [{"name": "CVE-2023-1234", "severity": "high"}]}
        row = _netlas_item_to_result(data)
        self.assertEqual(row["cve_list"][0]["id"], "CVE-2023-1234")

    def test_cve_id_fallback_to_id_key(self):
        data = {"ip": "1.1.1.1", "cve": [{"id": "CVE-2023-9999"}]}
        row = _netlas_item_to_result(data)
        self.assertEqual(row["cve_list"][0]["id"], "CVE-2023-9999")

    def test_cve_without_id_skipped(self):
        data = {"ip": "1.1.1.1", "cve": [{"severity": "high"}]}
        row = _netlas_item_to_result(data)
        self.assertEqual(row["cve_list"], [])

    def test_cve_non_dict_item_skipped(self):
        data = {"ip": "1.1.1.1", "cve": ["bad", None, {"name": "CVE-2023-0001"}]}
        row = _netlas_item_to_result(data)
        self.assertEqual(len(row["cve_list"]), 1)
        self.assertEqual(row["cve_list"][0]["id"], "CVE-2023-0001")

    def test_no_cve_field(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1"})
        self.assertEqual(row["cve_list"], [])

    # --- banner priority ---

    def test_banner_picks_first_match(self):
        # Both ssh and ftp present; ssh comes first in the loop
        data = {"ip": "1.1.1.1", "ssh": {"banner": "SSH-banner"}, "ftp": {"banner": "FTP-banner"}}
        row = _netlas_item_to_result(data)
        self.assertEqual(row["banner"], "SSH-banner")

    def test_banner_falls_through_to_ftp(self):
        data = {"ip": "1.1.1.1", "ftp": {"banner": "FTP-banner"}}
        row = _netlas_item_to_result(data)
        self.assertEqual(row["banner"], "FTP-banner")

    def test_no_banner_empty_string(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1"})
        self.assertEqual(row["banner"], "")

    def test_banner_proto_block_not_dict_ignored(self):
        data = {"ip": "1.1.1.1", "ssh": "not-a-dict"}
        row = _netlas_item_to_result(data)
        self.assertEqual(row["banner"], "")

    # --- port / protocol edge cases ---

    def test_port_string_coerced(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "port": "80"})
        self.assertEqual(row["port"], 80)

    def test_port_invalid_becomes_zero(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "port": "not-a-port"})
        self.assertEqual(row["port"], 0)

    def test_port_none_becomes_zero(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1"})
        self.assertEqual(row["port"], 0)

    def test_protocol_fallback_to_prot7(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "prot7": "ftp"})
        self.assertEqual(row["protocol"], "ftp")

    def test_protocol_prefers_protocol_over_prot7(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "protocol": "https", "prot7": "ftp"})
        self.assertEqual(row["protocol"], "https")

    # --- missing / malformed nested blocks ---

    def test_none_input_returns_none(self):
        self.assertIsNone(_netlas_item_to_result(None))

    def test_non_dict_input_returns_none(self):
        self.assertIsNone(_netlas_item_to_result("string"))
        self.assertIsNone(_netlas_item_to_result(42))

    def test_empty_dict_returns_row_with_defaults(self):
        row = _netlas_item_to_result({})
        self.assertIsNotNone(row)
        self.assertEqual(row["ip"], "")
        self.assertEqual(row["port"], 0)
        self.assertEqual(row["country"], "")
        self.assertEqual(row["city"], "")
        self.assertIsNone(row["latitude"])
        self.assertIsNone(row["longitude"])
        self.assertEqual(row["cve_list"], [])
        self.assertEqual(row["banner"], "")
        self.assertIsNone(row["http_status_code"])

    def test_geo_block_not_dict_gracefully_handled(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "geo": "bad"})
        self.assertEqual(row["country"], "")
        self.assertEqual(row["asn_number"], "")

    def test_geo_asn_not_dict_gracefully_handled(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "geo": {"asn": "bad"}})
        self.assertEqual(row["asn_number"], "")
        self.assertEqual(row["asn_route"], "")

    def test_whois_block_not_dict_gracefully_handled(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "whois": "bad"})
        self.assertEqual(row["asn_name"], "")

    def test_http_block_not_dict_gracefully_handled(self):
        row = _netlas_item_to_result({"ip": "1.1.1.1", "http": "bad"})
        self.assertEqual(row["title"], "")
        self.assertIsNone(row["http_status_code"])

    def test_return_keys_complete(self):
        """Every expected key is present in the returned dict."""
        row = _netlas_item_to_result({})
        expected_keys = {
            "host", "ip", "port", "protocol", "title", "http_status_code",
            "country", "city", "latitude", "longitude", "timezone",
            "isp", "asn_name", "asn_number", "asn_route",
            "banner", "cve_list",
        }
        self.assertEqual(set(row.keys()), expected_keys)


# ---------------------------------------------------------------------------
# Unit tests for _parse_netlas_body
# ---------------------------------------------------------------------------

class TestParseNetlasBody(unittest.TestCase):

    def test_none_body(self):
        rows, total = _parse_netlas_body(None)
        self.assertEqual(rows, [])
        self.assertEqual(total, 0)

    def test_empty_body(self):
        rows, total = _parse_netlas_body({})
        self.assertEqual(rows, [])
        self.assertEqual(total, 0)

    def test_total_prefers_total_key(self):
        body = {"items": [], "total": 99, "count": 5}
        _, total = _parse_netlas_body(body)
        self.assertEqual(total, 99)

    def test_total_falls_back_to_count(self):
        body = {"items": [], "count": 42}
        _, total = _parse_netlas_body(body)
        self.assertEqual(total, 42)

    def test_total_falls_back_to_len(self):
        body = _netlas_body()
        del body["count"]
        rows, total = _parse_netlas_body(body)
        self.assertEqual(total, len(rows))

    def test_non_dict_item_skipped(self):
        body = {"items": ["bad", None, {"data": {"ip": "1.1.1.1"}}]}
        rows, _ = _parse_netlas_body(body)
        self.assertEqual(len(rows), 1)

    def test_item_with_no_data_key(self):
        body = {"items": [{"other": "stuff"}]}
        rows, _ = _parse_netlas_body(body)
        # _netlas_item_to_result({}) returns a row with empty values (not None), so it's included
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "")

    def test_rich_body_parsed(self):
        rows, total = _parse_netlas_body(_netlas_body())
        self.assertEqual(len(rows), 1)
        self.assertEqual(total, 1)
        row = rows[0]
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["city"], "Ashburn")
        self.assertEqual(row["asn_number"], "AS14618")
        self.assertEqual(len(row["cve_list"]), 2)
        self.assertEqual(row["banner"], "SSH-2.0-OpenSSH_8.9")


# ---------------------------------------------------------------------------
# Integration tests: run_netlas_enrichment / run_netlas_enrichment_isolated
# ---------------------------------------------------------------------------

class TestNetlasEnrich(unittest.TestCase):
    """Netlas responses enrichment with mocked HTTP."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "NETLAS_ENABLED": True,
            "NETLAS_API_KEY": "nl-key",
            "NETLAS_KEY_ROTATOR": rotator,
            "NETLAS_MAX_RESULTS": 100,
        }
        base.update(overrides)
        return base

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _netlas_body())
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings())

        self.assertIn("netlas", out)
        rows = out["netlas"]["results"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["host"], "1.2.3.4")
        self.assertEqual(row["ip"], "1.2.3.4")
        self.assertEqual(row["port"], 443)
        self.assertEqual(row["protocol"], "https")
        self.assertEqual(row["title"], "Test")
        self.assertEqual(row["http_status_code"], 200)
        self.assertEqual(row["country"], "US")
        self.assertEqual(row["city"], "Ashburn")
        self.assertEqual(row["isp"], "TestISP")
        self.assertEqual(row["asn_number"], "AS14618")
        self.assertEqual(row["asn_route"], "44.224.0.0/11")
        self.assertEqual(row["asn_name"], "AMAZON-AES")
        self.assertEqual(row["banner"], "SSH-2.0-OpenSSH_8.9")
        self.assertEqual(len(row["cve_list"]), 2)

        mock_get.assert_called_once()
        url = mock_get.call_args[0][0]
        self.assertTrue(url.startswith("https://app.netlas.io/api/responses/"))
        headers = mock_get.call_args[1].get("headers") or {}
        self.assertEqual(headers.get("X-API-Key"), "nl-key")

    @patch("netlas_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings(NETLAS_API_KEY=""))
        self.assertNotIn("netlas", out)
        mock_get.assert_not_called()

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_netlas_enrichment(cr, self._settings())
                self.assertEqual(out["netlas"]["results"], [])

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_rate_limit(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings())
        self.assertEqual(out["netlas"]["results"], [])

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"items": [], "count": 0})
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings())
        self.assertEqual(out["netlas"]["results"], [])

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_key_rotator_tick_after_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"
        mock_get.return_value = _mock_response(200, _netlas_body())
        run_netlas_enrichment(_combined_result(), self._settings(rotator=rotator, NETLAS_API_KEY=""))
        rotator.tick.assert_called_once()

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _netlas_body())
        combined = _combined_result()
        sub = run_netlas_enrichment_isolated(combined, self._settings())
        self.assertIn("results", sub)
        self.assertEqual(len(sub["results"]), 1)
        self.assertNotIn("netlas", combined)

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_disabled_skips_enrichment(self, mock_get, _sleep):
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings(NETLAS_ENABLED=False))
        self.assertNotIn("netlas", out)
        mock_get.assert_not_called()

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_ip_mode_queries_per_ip(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _netlas_body())
        cr = {
            "domain": "",
            "metadata": {"ip_mode": True, "expanded_ips": ["93.184.1.1", "93.184.1.2"]},
            "dns": {},
        }
        run_netlas_enrichment(cr, self._settings())
        self.assertEqual(mock_get.call_count, 2)
        calls = [mock_get.call_args_list[i][1]["params"]["q"] for i in range(2)]
        self.assertIn("host:93.184.1.1", calls)
        self.assertIn("host:93.184.1.2", calls)

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_ip_mode_stops_on_rate_limit(self, mock_get, _sleep):
        mock_get.side_effect = [
            _mock_response(200, _netlas_body()),
            _mock_response(429, {}, text="rl"),
        ]
        cr = {
            "domain": "",
            "metadata": {"ip_mode": True, "expanded_ips": ["93.184.1.1", "93.184.1.2", "93.184.1.3"]},
            "dns": {},
        }
        run_netlas_enrichment(cr, self._settings())
        # Stops after the 429, so only 2 calls made (not 3)
        self.assertEqual(mock_get.call_count, 2)

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_no_domain_in_domain_mode_skips(self, mock_get, _sleep):
        cr = {"domain": "", "metadata": {"ip_mode": False}, "dns": {}}
        out = run_netlas_enrichment(cr, self._settings())
        mock_get.assert_not_called()
        self.assertEqual(out["netlas"]["results"], [])


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for ZoomEye enrichment (recon/main_recon_modules/zoomeye_enrich.py).

Mocks requests.get for https://api.zoomeye.ai/host/search.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))

from zoomeye_enrich import (
    _geoinfo_asn,
    _geoinfo_city,
    _geoinfo_country,
    _geoinfo_isp,
    _geoinfo_latlon,
    run_zoomeye_enrichment,
    run_zoomeye_enrichment_isolated,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _combined_result() -> dict:
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}}, "subdomains": {}},
    }


def _ip_mode_combined_result() -> dict:
    return {
        "domain": "",
        "metadata": {"ip_mode": True, "expanded_ips": ["5.6.7.8", "9.10.11.12"]},
        "dns": {"domain": {"ips": {"ipv4": []}}, "subdomains": {}},
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _full_match() -> dict:
    """A maximally-populated ZoomEye match record covering all extracted fields."""
    return {
        "ip": "1.2.3.4",
        "hostname": "host.example.com",
        "rdns": "rdns.example.com",
        "update_time": "2026-03-01T12:00:00",
        "ssl": {"jarm": "jarm-fingerprint", "ja3s": "ja3s-fingerprint"},
        "portinfo": {
            "port": 443,
            "protocol": "tcp",
            "app": "nginx",
            "service": "http",
            "product": "nginx",
            "version": "1.24.0",
            "title": "My Site",
            "banner": "HTTP/1.1 200 OK",
            "os": "Linux",
            "device": "server",
            "hostname": "portinfo-host.example.com",
            "rdns": "portinfo-rdns.example.com",
        },
        "geoinfo": {
            "country": {"names": {"en": "United States"}},
            "city": {"names": {"en": "Ashburn"}},
            "location": {"lat": 39.04, "lng": -77.49},
            "asn": 16509,
            "isp": "Amazon.com, Inc.",
        },
    }


def _minimal_match() -> dict:
    """A minimal match with only ip + port, no optional fields."""
    return {
        "ip": "2.3.4.5",
        "portinfo": {"port": 80},
    }


def _zoomeye_body(matches=None) -> dict:
    return {"total": len(matches or []), "matches": matches or [_full_match()]}


# ---------------------------------------------------------------------------
# Geo-helper unit tests
# ---------------------------------------------------------------------------

class TestGeoHelpers(unittest.TestCase):

    def test_country_string(self):
        self.assertEqual(_geoinfo_country({"country": "US"}), "US")

    def test_country_names_dict(self):
        geo = {"country": {"names": {"en": "United States", "zh": "美国"}}}
        self.assertEqual(_geoinfo_country(geo), "United States")

    def test_country_code_fallback(self):
        self.assertEqual(_geoinfo_country({"country": {"code": "US"}}), "US")

    def test_country_none(self):
        self.assertEqual(_geoinfo_country(None), "")
        self.assertEqual(_geoinfo_country({}), "")

    def test_city_string(self):
        self.assertEqual(_geoinfo_city({"city": "London"}), "London")

    def test_city_names_dict(self):
        self.assertEqual(_geoinfo_city({"city": {"names": {"en": "Ashburn"}}}), "Ashburn")

    def test_city_none(self):
        self.assertEqual(_geoinfo_city(None), "")
        self.assertEqual(_geoinfo_city({}), "")

    def test_latlon_normal(self):
        geo = {"location": {"lat": 39.04, "lng": -77.49}}
        lat, lon = _geoinfo_latlon(geo)
        self.assertAlmostEqual(lat, 39.04)
        self.assertAlmostEqual(lon, -77.49)

    def test_latlon_latitude_longitude_keys(self):
        geo = {"location": {"latitude": 51.5, "longitude": -0.1}}
        lat, lon = _geoinfo_latlon(geo)
        self.assertAlmostEqual(lat, 51.5)
        self.assertAlmostEqual(lon, -0.1)

    def test_latlon_missing(self):
        self.assertEqual(_geoinfo_latlon(None), (None, None))
        self.assertEqual(_geoinfo_latlon({}), (None, None))
        self.assertEqual(_geoinfo_latlon({"location": {}}), (None, None))

    def test_latlon_zero_treated_as_none(self):
        # lat=0, lng=0 returns (None, None) because 0.0 or False
        lat, lon = _geoinfo_latlon({"location": {"lat": 0, "lng": 0}})
        self.assertIsNone(lat)
        self.assertIsNone(lon)

    def test_asn_string(self):
        self.assertEqual(_geoinfo_asn({"asn": 16509}), "16509")

    def test_asn_missing(self):
        self.assertEqual(_geoinfo_asn(None), "")
        self.assertEqual(_geoinfo_asn({}), "")

    def test_isp_primary(self):
        self.assertEqual(_geoinfo_isp({"isp": "Amazon"}), "Amazon")

    def test_isp_organization_fallback(self):
        self.assertEqual(_geoinfo_isp({"organization": "AWS"}), "AWS")

    def test_isp_aso_fallback(self):
        self.assertEqual(_geoinfo_isp({"aso": "ASO-NAME"}), "ASO-NAME")

    def test_isp_missing(self):
        self.assertEqual(_geoinfo_isp(None), "")
        self.assertEqual(_geoinfo_isp({}), "")


# ---------------------------------------------------------------------------
# Enrichment module tests
# ---------------------------------------------------------------------------

class TestZoomeyeEnrich(unittest.TestCase):

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "ZOOMEYE_ENABLED": True,
            "ZOOMEYE_API_KEY": "ze-key",
            "ZOOMEYE_KEY_ROTATOR": rotator,
            "ZOOMEYE_MAX_RESULTS": 10,
        }
        base.update(overrides)
        return base

    # ------------------------------------------------------------------
    # Basic contract
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_disabled_skips(self, mock_get, _sleep):
        cr = _combined_result()
        out = run_zoomeye_enrichment(cr, self._settings(ZOOMEYE_ENABLED=False))
        self.assertNotIn("zoomeye", out)
        mock_get.assert_not_called()

    @patch("zoomeye_enrich.requests.get")
    def test_missing_api_key_skips(self, mock_get):
        cr = _combined_result()
        out = run_zoomeye_enrichment(cr, self._settings(ZOOMEYE_API_KEY=""))
        self.assertNotIn("zoomeye", out)
        mock_get.assert_not_called()

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_no_domain_in_domain_mode(self, mock_get, _sleep):
        cr = _combined_result()
        cr["domain"] = ""
        out = run_zoomeye_enrichment(cr, self._settings())
        self.assertIn("zoomeye", out)
        self.assertEqual(out["zoomeye"]["results"], [])
        mock_get.assert_not_called()

    # ------------------------------------------------------------------
    # New fields — portinfo
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_portinfo_full_fields_extracted(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]

        self.assertEqual(row["app"], "nginx")
        self.assertEqual(row["service"], "http")
        self.assertEqual(row["product"], "nginx")
        self.assertEqual(row["version"], "1.24.0")
        self.assertEqual(row["title"], "My Site")
        self.assertEqual(row["banner"], "HTTP/1.1 200 OK")
        self.assertEqual(row["os"], "Linux")
        self.assertEqual(row["device"], "server")
        self.assertEqual(row["protocol"], "tcp")
        self.assertEqual(row["port"], 443)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_protocol_defaults_to_tcp_when_missing(self, mock_get, _sleep):
        match = _minimal_match()  # portinfo has no protocol key
        mock_get.return_value = _mock_response(200, _zoomeye_body([match]))
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["protocol"], "tcp")

    # ------------------------------------------------------------------
    # New fields — geoinfo
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_geoinfo_fields_extracted(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]

        self.assertEqual(row["country"], "United States")
        self.assertEqual(row["city"], "Ashburn")
        self.assertAlmostEqual(row["latitude"], 39.04)
        self.assertAlmostEqual(row["longitude"], -77.49)
        self.assertEqual(row["asn"], "16509")
        self.assertEqual(row["isp"], "Amazon.com, Inc.")

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_missing_geoinfo_fields_are_empty(self, mock_get, _sleep):
        match = _minimal_match()  # no geoinfo key
        mock_get.return_value = _mock_response(200, _zoomeye_body([match]))
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]

        self.assertEqual(row["country"], "")
        self.assertEqual(row["city"], "")
        self.assertIsNone(row["latitude"])
        self.assertIsNone(row["longitude"])
        self.assertEqual(row["asn"], "")
        self.assertEqual(row["isp"], "")

    # ------------------------------------------------------------------
    # New fields — root-level (hostname, rdns, update_time, ssl)
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_root_hostname_takes_precedence_over_portinfo(self, mock_get, _sleep):
        """Root m.hostname should win over portinfo.hostname."""
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["hostname"], "host.example.com")  # root level

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_portinfo_hostname_used_when_root_missing(self, mock_get, _sleep):
        match = _full_match()
        del match["hostname"]  # remove root hostname
        mock_get.return_value = _mock_response(200, _zoomeye_body([match]))
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["hostname"], "portinfo-host.example.com")

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_root_rdns_extracted(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["rdns"], "rdns.example.com")  # root level

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_update_time_extracted(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["update_time"], "2026-03-01T12:00:00")

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_ssl_fields_extracted(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["ssl_jarm"], "jarm-fingerprint")
        self.assertEqual(row["ssl_ja3s"], "ja3s-fingerprint")

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_ssl_fields_empty_when_absent(self, mock_get, _sleep):
        match = _full_match()
        del match["ssl"]
        mock_get.return_value = _mock_response(200, _zoomeye_body([match]))
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        row = out["zoomeye"]["results"][0]
        self.assertEqual(row["ssl_jarm"], "")
        self.assertEqual(row["ssl_ja3s"], "")

    # ------------------------------------------------------------------
    # HTTP error handling
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                out = run_zoomeye_enrichment(_combined_result(), self._settings())
                self.assertEqual(out["zoomeye"]["results"], [])

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_rate_limit_retries_once_then_returns_empty(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        self.assertEqual(out["zoomeye"]["results"], [])
        backoff_calls = [c for c in mock_sleep.call_args_list if c.args and c.args[0] == 2]
        self.assertGreaterEqual(len(backoff_calls), 1)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_empty_matches_list(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"total": 0, "matches": []})
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        self.assertEqual(out["zoomeye"]["results"], [])

    # ------------------------------------------------------------------
    # API key / auth header
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_api_key_header_is_api_key_not_bearer(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        run_zoomeye_enrichment(_combined_result(), self._settings())
        headers = mock_get.call_args[1].get("headers") or {}
        self.assertEqual(headers.get("API-KEY"), "ze-key")
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-API-Key", headers)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_key_rotator_tick_called(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        run_zoomeye_enrichment(_combined_result(), self._settings(rotator=rotator, ZOOMEYE_API_KEY=""))
        rotator.tick.assert_called()

    # ------------------------------------------------------------------
    # IP mode
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_ip_mode_queries_each_ip(self, mock_get, _sleep):
        def side_effect(*args, **kwargs):
            q = kwargs.get("params", {}).get("query", "")
            ip = q.replace("ip:", "")
            body = _zoomeye_body([{
                "ip": ip, "portinfo": {"port": 22, "protocol": "tcp"},
                "geoinfo": {}, "ssl": {},
            }])
            return _mock_response(200, body)

        mock_get.side_effect = side_effect
        cr = _ip_mode_combined_result()
        out = run_zoomeye_enrichment(cr, self._settings())

        self.assertIn("zoomeye", out)
        result_ips = {r["ip"] for r in out["zoomeye"]["results"]}
        self.assertEqual(result_ips, {"5.6.7.8", "9.10.11.12"})

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_ip_mode_uses_ip_query_syntax(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        cr = _ip_mode_combined_result()
        run_zoomeye_enrichment(cr, self._settings())

        for c in mock_get.call_args_list:
            q = (c[1].get("params") or {}).get("query", "")
            self.assertTrue(q.startswith("ip:"), f"Expected ip: query, got: {q!r}")

    # ------------------------------------------------------------------
    # Total count
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_total_from_api_body(self, mock_get, _sleep):
        body = {"total": 999, "matches": [_full_match()]}
        mock_get.return_value = _mock_response(200, body)
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        self.assertEqual(out["zoomeye"]["total"], 999)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_total_falls_back_to_result_count(self, mock_get, _sleep):
        body = {"matches": [_full_match()]}  # no total field
        mock_get.return_value = _mock_response(200, body)
        out = run_zoomeye_enrichment(_combined_result(), self._settings())
        self.assertGreaterEqual(out["zoomeye"]["total"], 1)

    # ------------------------------------------------------------------
    # Isolated wrapper — deepcopy doesn't mutate original
    # ------------------------------------------------------------------

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_isolated_returns_zoomeye_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        combined = _combined_result()
        # MAX_RESULTS=1 so pagination stops after the first match
        sub = run_zoomeye_enrichment_isolated(combined, self._settings(ZOOMEYE_MAX_RESULTS=1))

        self.assertIn("results", sub)
        self.assertEqual(len(sub["results"]), 1)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_isolated_does_not_mutate_original(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        combined = _combined_result()
        run_zoomeye_enrichment_isolated(combined, self._settings())
        # deepcopy: the original must NOT have a 'zoomeye' key added
        self.assertNotIn("zoomeye", combined)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_isolated_returns_empty_dict_on_no_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"total": 0, "matches": []})
        sub = run_zoomeye_enrichment_isolated(_combined_result(), self._settings())
        self.assertIn("results", sub)
        self.assertEqual(sub["results"], [])


if __name__ == "__main__":
    unittest.main()

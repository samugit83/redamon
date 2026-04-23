"""
Unit tests for OTX (AlienVault) enrichment (recon/main_recon_modules/otx_enrich.py).

Mocks requests.get for https://otx.alienvault.com/api/v1/indicators/*.
Covers:
  - Anonymous mode (no API key)
  - All helper functions: _otx_pulse_details, _otx_passive_dns_records,
    _otx_domain_passive_dns_ips, _otx_malware_samples, _otx_url_count
  - All 8 API endpoints (IPv4: general/passive_dns/malware/url_list;
    domain: general/passive_dns/malware/url_list)
  - New ip_report fields: pulse_details, passive_dns (rich), malware, url_count
  - New domain_report fields: pulse_details, historical_ips, malware, url_count
  - deepcopy isolation (isolated wrapper must not mutate original)
  - TLP severity ranking
  - Rate-limit / HTTP error behaviour
  - Key rotator tick count
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))

from otx_enrich import (
    run_otx_enrichment,
    run_otx_enrichment_isolated,
    _otx_pulse_details,
    _otx_passive_dns_records,
    _otx_domain_passive_dns_ips,
    _otx_malware_samples,
    _otx_url_count,
    _TLP_ORDER,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _combined_result(ip_mode: bool = False) -> dict:
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": ip_mode, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}}, "subdomains": {}},
    }


def _combined_result_no_domain() -> dict:
    return {
        "domain": "",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ["5.6.7.8"]}}, "subdomains": {}},
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _otx_general_body_full() -> dict:
    """Full general body with pulse details, adversary, malware families, TLP, attack IDs."""
    return {
        "pulse_info": {
            "count": 3,
            "pulses": [
                {
                    "id": "pulse-001",
                    "name": "APT28 C2",
                    "adversary": "APT28",
                    "malware_families": [
                        {"display_name": "Sofacy", "id": "sofacy"},
                        {"display_name": "X-Agent"},
                    ],
                    "attack_ids": [
                        {"id": "T1566"},
                        {"id": "T1059"},
                    ],
                    "tags": ["apt", "russia"],
                    "TLP": "amber",
                    "author_name": "analyst",
                    "targeted_countries": ["US", "UK"],
                    "modified": "2024-01-01T00:00:00",
                },
                {
                    "id": "pulse-002",
                    "name": "Generic Malware",
                    "adversary": "",
                    "malware_families": [{"display_name": "Mimikatz"}],
                    "attack_ids": [{"id": "T1003"}],
                    "tags": ["credential"],
                    "TLP": "green",
                    "author_name": "vendor",
                    "targeted_countries": [],
                    "modified": "2024-02-01T00:00:00",
                },
                {
                    # no pulse_id → should be skipped for graph nodes but still counted
                    "name": "No ID Pulse",
                    "adversary": "Lazarus",
                    "malware_families": [],
                    "attack_ids": [],
                    "tags": ["nk"],
                    "TLP": "red",
                    "author_name": "anon",
                },
            ],
        },
        "reputation": 7,
        "geo": {
            "country_name": "United States",
            "country_code": "US",
            "city": "Ashburn",
            "asn": "AS14618",
            "latitude": 39.0,
            "longitude": -77.5,
        },
    }


def _otx_passive_dns_body_full() -> dict:
    return {
        "passive_dns": [
            {"hostname": "sub.example.com", "first": "2023-01-01", "last": "2024-01-01", "record_type": "A", "asn": "AS12345"},
            {"hostname": "other.org", "first": "2022-06-01", "last": "2023-06-01", "record_type": "A", "asn": ""},
            # Duplicate — should be deduplicated
            {"hostname": "sub.example.com", "first": "2021-01-01", "last": "2021-06-01", "record_type": "A"},
        ]
    }


def _otx_malware_body() -> dict:
    return {
        "data": [
            {"hash": "a" * 64, "type": "pe32", "file_name": "payload.exe"},
            {"hash": "b" * 32, "type": "elf", "file_name": "dropper"},
            {"hash": "", "type": "doc"},  # empty hash → should be skipped
        ]
    }


def _otx_url_list_body() -> dict:
    return {
        "url_list": [
            {"url": "http://example.com/path1"},
            {"url": "http://example.com/path2"},
            {"url": "http://example.com/path3"},
        ]
    }


def _otx_domain_passive_dns_body() -> dict:
    return {
        "passive_dns": [
            {"address": "10.0.0.1", "first": "2023-01-01", "last": "2024-01-01", "record_type": "A"},
            {"address": "10.0.0.2", "first": "2022-01-01", "last": "2023-01-01", "record_type": "A"},
            # Duplicate
            {"address": "10.0.0.1", "first": "2020-01-01"},
        ]
    }


def _otx_domain_general_body() -> dict:
    return {
        "pulse_info": {
            "count": 2,
            "pulses": [
                {
                    "id": "domain-pulse-001",
                    "name": "Phishing Campaign",
                    "adversary": "TA505",
                    "malware_families": [{"display_name": "Dridex"}],
                    "attack_ids": [{"id": "T1566"}],
                    "tags": ["phishing"],
                    "TLP": "white",
                    "author_name": "intel",
                    "targeted_countries": ["DE"],
                    "modified": "2024-03-01T00:00:00",
                }
            ],
        },
        "whois": {
            "registrar": "GoDaddy",
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "registrant_email": "admin@example.com",
        },
    }


# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------

class TestOtxPulseDetails(unittest.TestCase):
    """Tests for _otx_pulse_details()."""

    def test_none_body_returns_empty(self):
        r = _otx_pulse_details(None)
        self.assertEqual(r["adversaries"], [])
        self.assertEqual(r["malware_families"], [])
        self.assertEqual(r["tlp"], "")
        self.assertEqual(r["attack_ids"], [])
        self.assertEqual(r["tags"], [])
        self.assertEqual(r["pulses"], [])

    def test_empty_body_returns_empty(self):
        r = _otx_pulse_details({})
        self.assertEqual(r["adversaries"], [])

    def test_full_body_adversaries(self):
        r = _otx_pulse_details(_otx_general_body_full())
        # APT28 and Lazarus (from no-id pulse) both extracted
        self.assertIn("APT28", r["adversaries"])
        self.assertIn("Lazarus", r["adversaries"])
        # Empty adversary not included
        self.assertNotIn("", r["adversaries"])

    def test_full_body_malware_families(self):
        r = _otx_pulse_details(_otx_general_body_full())
        self.assertIn("Sofacy", r["malware_families"])
        self.assertIn("X-Agent", r["malware_families"])
        self.assertIn("Mimikatz", r["malware_families"])

    def test_full_body_attack_ids(self):
        r = _otx_pulse_details(_otx_general_body_full())
        self.assertIn("T1566", r["attack_ids"])
        self.assertIn("T1059", r["attack_ids"])
        self.assertIn("T1003", r["attack_ids"])

    def test_tlp_most_restrictive(self):
        # pulses have amber, green, red → most restrictive = red
        r = _otx_pulse_details(_otx_general_body_full())
        self.assertEqual(r["tlp"], "red")

    def test_tlp_order_coverage(self):
        """Verify _TLP_ORDER defines expected severity ranks."""
        self.assertGreater(_TLP_ORDER["red"], _TLP_ORDER["amber"])
        self.assertGreater(_TLP_ORDER["amber"], _TLP_ORDER["green"])
        self.assertGreater(_TLP_ORDER["green"], _TLP_ORDER["white"])

    def test_pulse_records_with_id_only(self):
        r = _otx_pulse_details(_otx_general_body_full())
        # Only pulses with 'id' field become graph node records
        pulse_ids = [p["pulse_id"] for p in r["pulses"]]
        self.assertIn("pulse-001", pulse_ids)
        self.assertIn("pulse-002", pulse_ids)
        # Third pulse has no id → not in records
        self.assertEqual(len(r["pulses"]), 2)

    def test_pulse_record_fields(self):
        r = _otx_pulse_details(_otx_general_body_full())
        p1 = next(p for p in r["pulses"] if p["pulse_id"] == "pulse-001")
        self.assertEqual(p1["name"], "APT28 C2")
        self.assertEqual(p1["adversary"], "APT28")
        self.assertIn("Sofacy", p1["malware_families"])
        self.assertIn("T1566", p1["attack_ids"])
        self.assertEqual(p1["tlp"], "amber")
        self.assertEqual(p1["author_name"], "analyst")
        self.assertIn("US", p1["targeted_countries"])

    def test_max_pulses_limit(self):
        body = {
            "pulse_info": {
                "count": 5,
                "pulses": [
                    {"id": f"p-{i}", "name": f"Pulse {i}", "adversary": f"Actor{i}",
                     "malware_families": [], "attack_ids": [], "tags": [], "TLP": "white",
                     "author_name": "", "targeted_countries": [], "modified": ""}
                    for i in range(5)
                ],
            }
        }
        r = _otx_pulse_details(body, max_pulses=3)
        self.assertEqual(len(r["pulses"]), 3)

    def test_tags_deduplication_and_limit(self):
        pulses = [
            {"id": f"p{i}", "name": f"P{i}", "adversary": "", "malware_families": [],
             "attack_ids": [], "tags": [f"tag{j}" for j in range(25)],
             "TLP": "white", "author_name": "", "targeted_countries": [], "modified": ""}
            for i in range(2)
        ]
        body = {"pulse_info": {"count": 2, "pulses": pulses}}
        r = _otx_pulse_details(body)
        # Tags capped at 20 in the aggregate
        self.assertLessEqual(len(r["tags"]), 20)

    def test_malware_families_as_plain_strings(self):
        """Malware families can be plain strings, not just dicts."""
        body = {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {"id": "p1", "name": "Test", "adversary": "",
                     "malware_families": ["WannaCry", "NotPetya"],
                     "attack_ids": [], "tags": [], "TLP": "white",
                     "author_name": "", "targeted_countries": [], "modified": ""}
                ]
            }
        }
        r = _otx_pulse_details(body)
        self.assertIn("WannaCry", r["malware_families"])
        self.assertIn("NotPetya", r["malware_families"])

    def test_attack_ids_as_plain_strings(self):
        body = {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {"id": "p1", "name": "Test", "adversary": "",
                     "malware_families": [],
                     "attack_ids": ["T1055", "T1071"],
                     "tags": [], "TLP": "green",
                     "author_name": "", "targeted_countries": [], "modified": ""}
                ]
            }
        }
        r = _otx_pulse_details(body)
        self.assertIn("T1055", r["attack_ids"])
        self.assertIn("T1071", r["attack_ids"])


class TestOtxPassiveDnsRecords(unittest.TestCase):
    """Tests for _otx_passive_dns_records()."""

    def test_none_returns_empty(self):
        self.assertEqual(_otx_passive_dns_records(None), [])

    def test_empty_returns_empty(self):
        self.assertEqual(_otx_passive_dns_records({}), [])

    def test_full_body_parsing(self):
        r = _otx_passive_dns_records(_otx_passive_dns_body_full())
        hostnames = [x["hostname"] for x in r]
        self.assertIn("sub.example.com", hostnames)
        self.assertIn("other.org", hostnames)

    def test_deduplication(self):
        r = _otx_passive_dns_records(_otx_passive_dns_body_full())
        hostnames = [x["hostname"] for x in r]
        # sub.example.com appears twice in fixture but should be deduplicated
        self.assertEqual(hostnames.count("sub.example.com"), 1)

    def test_temporal_metadata_preserved(self):
        r = _otx_passive_dns_records(_otx_passive_dns_body_full())
        sub = next(x for x in r if x["hostname"] == "sub.example.com")
        self.assertEqual(sub["first"], "2023-01-01")
        self.assertEqual(sub["last"], "2024-01-01")
        self.assertEqual(sub["record_type"], "A")
        self.assertEqual(sub["asn"], "AS12345")

    def test_missing_temporal_fields_default_to_empty(self):
        body = {"passive_dns": [{"hostname": "x.com"}]}
        r = _otx_passive_dns_records(body)
        self.assertEqual(r[0]["first"], "")
        self.assertEqual(r[0]["last"], "")
        self.assertEqual(r[0]["record_type"], "")
        self.assertEqual(r[0]["asn"], "")

    def test_invalid_records_skipped(self):
        body = {"passive_dns": [None, 42, {}, {"hostname": "valid.com"}]}
        r = _otx_passive_dns_records(body)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["hostname"], "valid.com")


class TestOtxDomainPassiveDnsIps(unittest.TestCase):
    """Tests for _otx_domain_passive_dns_ips()."""

    def test_none_returns_empty(self):
        self.assertEqual(_otx_domain_passive_dns_ips(None), [])

    def test_empty_returns_empty(self):
        self.assertEqual(_otx_domain_passive_dns_ips({}), [])

    def test_full_body_parsing(self):
        r = _otx_domain_passive_dns_ips(_otx_domain_passive_dns_body())
        addresses = [x["address"] for x in r]
        self.assertIn("10.0.0.1", addresses)
        self.assertIn("10.0.0.2", addresses)

    def test_deduplication(self):
        r = _otx_domain_passive_dns_ips(_otx_domain_passive_dns_body())
        addresses = [x["address"] for x in r]
        self.assertEqual(addresses.count("10.0.0.1"), 1)

    def test_temporal_metadata_preserved(self):
        r = _otx_domain_passive_dns_ips(_otx_domain_passive_dns_body())
        ip1 = next(x for x in r if x["address"] == "10.0.0.1")
        self.assertEqual(ip1["first"], "2023-01-01")
        self.assertEqual(ip1["last"], "2024-01-01")
        self.assertEqual(ip1["record_type"], "A")


class TestOtxMalwareSamples(unittest.TestCase):
    """Tests for _otx_malware_samples()."""

    def test_none_returns_empty(self):
        self.assertEqual(_otx_malware_samples(None), [])

    def test_empty_data_key_returns_empty(self):
        self.assertEqual(_otx_malware_samples({"data": []}), [])

    def test_full_body_parsing(self):
        r = _otx_malware_samples(_otx_malware_body())
        hashes = [x["hash"] for x in r]
        self.assertIn("a" * 64, hashes)
        self.assertIn("b" * 32, hashes)

    def test_empty_hash_skipped(self):
        r = _otx_malware_samples(_otx_malware_body())
        hashes = [x["hash"] for x in r]
        self.assertNotIn("", hashes)

    def test_hash_type_detection(self):
        r = _otx_malware_samples(_otx_malware_body())
        sha256_entry = next(x for x in r if x["hash"] == "a" * 64)
        md5_entry = next(x for x in r if x["hash"] == "b" * 32)
        self.assertEqual(sha256_entry["hash_type"], "sha256")
        self.assertEqual(md5_entry["hash_type"], "md5")

    def test_file_type_and_name(self):
        r = _otx_malware_samples(_otx_malware_body())
        pe_entry = next(x for x in r if x["hash"] == "a" * 64)
        self.assertEqual(pe_entry["file_type"], "pe32")
        self.assertEqual(pe_entry["file_name"], "payload.exe")

    def test_max_samples_limit(self):
        body = {"data": [{"hash": "c" * 64, "type": "pe32"} for _ in range(30)]}
        r = _otx_malware_samples(body, max_samples=5)
        self.assertEqual(len(r), 5)


class TestOtxUrlCount(unittest.TestCase):
    """Tests for _otx_url_count()."""

    def test_none_returns_zero(self):
        self.assertEqual(_otx_url_count(None), 0)

    def test_empty_returns_zero(self):
        self.assertEqual(_otx_url_count({}), 0)

    def test_url_list_count(self):
        self.assertEqual(_otx_url_count(_otx_url_list_body()), 3)

    def test_empty_url_list_returns_zero(self):
        self.assertEqual(_otx_url_count({"url_list": []}), 0)

    def test_count_field_fallback(self):
        self.assertEqual(_otx_url_count({"count": 42}), 42)


# ---------------------------------------------------------------------------
# Integration tests (full run_otx_enrichment with mocked HTTP)
# ---------------------------------------------------------------------------

class TestOtxEnrichIntegration(unittest.TestCase):
    """Full pipeline tests with mocked requests.get."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "OTX_ENABLED": True,
            "OTX_API_KEY": "otx-test-key",
            "OTX_KEY_ROTATOR": rotator,
        }
        base.update(overrides)
        return base

    def _url_path(self, url: str) -> str:
        return url.replace("https://otx.alienvault.com/api/v1/indicators", "")

    def _full_side_effect(self, url, **_kwargs):
        path = self._url_path(url)
        if "/IPv4/1.2.3.4/general" in path:
            return _mock_response(200, _otx_general_body_full())
        if "/IPv4/1.2.3.4/passive_dns" in path:
            return _mock_response(200, _otx_passive_dns_body_full())
        if "/IPv4/1.2.3.4/malware" in path:
            return _mock_response(200, _otx_malware_body())
        if "/IPv4/1.2.3.4/url_list" in path:
            return _mock_response(200, _otx_url_list_body())
        if "/domain/example.com/general" in path:
            return _mock_response(200, _otx_domain_general_body())
        if "/domain/example.com/passive_dns" in path:
            return _mock_response(200, _otx_domain_passive_dns_body())
        if "/domain/example.com/malware" in path:
            return _mock_response(200, _otx_malware_body())
        if "/domain/example.com/url_list" in path:
            return _mock_response(200, _otx_url_list_body())
        return _mock_response(404, {})

    # ── Disabled ─────────────────────────────────────────────────────────────

    @patch("otx_enrich.requests.get")
    def test_disabled_skips_all(self, mock_get):
        cr = _combined_result()
        out = run_otx_enrichment(cr, {"OTX_ENABLED": False})
        self.assertNotIn("otx", out)
        mock_get.assert_not_called()

    # ── Anonymous mode ────────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_anonymous_mode_no_auth_header(self, mock_get, _sleep):
        """Without an API key, requests must NOT include X-OTX-API-KEY."""
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings(OTX_API_KEY=""))

        self.assertIn("otx", out)
        # Inspect every call — none should have the auth header
        for c in mock_get.call_args_list:
            headers = c.kwargs.get("headers", {})
            self.assertNotIn("X-OTX-API-KEY", headers, f"Auth header found in anonymous call: {c}")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_authenticated_mode_sends_auth_header(self, mock_get, _sleep):
        """With an API key, all requests must include X-OTX-API-KEY."""
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        run_otx_enrichment(cr, self._settings())

        for c in mock_get.call_args_list:
            headers = c.kwargs.get("headers", {})
            self.assertEqual(headers.get("X-OTX-API-KEY"), "otx-test-key")

    # ── IP report fields ──────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_base_fields(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())

        reports = out["otx"]["ip_reports"]
        self.assertEqual(len(reports), 1)
        r = reports[0]
        self.assertEqual(r["ip"], "1.2.3.4")
        self.assertEqual(r["pulse_count"], 3)
        self.assertEqual(r["reputation"], 7)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_geo(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        geo = out["otx"]["ip_reports"][0]["geo"]
        self.assertEqual(geo["country_name"], "United States")
        self.assertEqual(geo["country_code"], "US")
        self.assertEqual(geo["city"], "Ashburn")
        self.assertEqual(geo["asn"], "AS14618")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_pulse_details(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        pd = out["otx"]["ip_reports"][0]["pulse_details"]
        self.assertIn("APT28", pd["adversaries"])
        self.assertIn("Sofacy", pd["malware_families"])
        self.assertIn("T1566", pd["attack_ids"])
        self.assertEqual(pd["tlp"], "red")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_passive_dns_rich(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        pdns = out["otx"]["ip_reports"][0]["passive_dns"]
        hostnames = [x["hostname"] for x in pdns]
        self.assertIn("sub.example.com", hostnames)
        self.assertIn("other.org", hostnames)
        # Check temporal metadata on one record
        sub = next(x for x in pdns if x["hostname"] == "sub.example.com")
        self.assertEqual(sub["first"], "2023-01-01")
        self.assertEqual(sub["record_type"], "A")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_passive_dns_hostnames_legacy(self, mock_get, _sleep):
        """passive_dns_hostnames legacy field preserved for backward compat."""
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        hostnames = out["otx"]["ip_reports"][0]["passive_dns_hostnames"]
        self.assertIsInstance(hostnames, list)
        self.assertIn("sub.example.com", hostnames)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_malware(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        malware = out["otx"]["ip_reports"][0]["malware"]
        hashes = [x["hash"] for x in malware]
        self.assertIn("a" * 64, hashes)
        self.assertIn("b" * 32, hashes)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_report_url_count(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        self.assertEqual(out["otx"]["ip_reports"][0]["url_count"], 3)

    # ── Domain report fields ──────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_domain_report_base_fields(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        dr = out["otx"]["domain_report"]
        self.assertEqual(dr["domain"], "example.com")
        self.assertEqual(dr["pulse_count"], 2)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_domain_report_whois(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        whois = out["otx"]["domain_report"]["whois"]
        self.assertEqual(whois["registrar"], "GoDaddy")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_domain_report_pulse_details(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        pd = out["otx"]["domain_report"]["pulse_details"]
        self.assertIn("TA505", pd["adversaries"])
        self.assertIn("Dridex", pd["malware_families"])
        self.assertEqual(pd["tlp"], "white")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_domain_report_historical_ips(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        hist = out["otx"]["domain_report"]["historical_ips"]
        addresses = [x["address"] for x in hist]
        self.assertIn("10.0.0.1", addresses)
        self.assertIn("10.0.0.2", addresses)
        # Deduplicated
        self.assertEqual(addresses.count("10.0.0.1"), 1)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_domain_report_malware(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        malware = out["otx"]["domain_report"]["malware"]
        self.assertGreater(len(malware), 0)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_domain_report_url_count(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        self.assertEqual(out["otx"]["domain_report"]["url_count"], 3)

    # ── IP mode ───────────────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_ip_mode_skips_domain_enrichment(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result(ip_mode=True)
        out = run_otx_enrichment(cr, self._settings())
        # Domain endpoint should NOT be called in IP mode
        for c in mock_get.call_args_list:
            self.assertNotIn("/domain/", self._url_path(c.args[0]))
        # But IP reports should still exist
        self.assertEqual(len(out["otx"]["ip_reports"]), 1)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_no_domain_skips_domain_enrichment(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result_no_domain()
        out = run_otx_enrichment(cr, self._settings())
        # No /domain/ calls
        for c in mock_get.call_args_list:
            self.assertNotIn("/domain/", self._url_path(c.args[0]))
        self.assertEqual(out["otx"]["domain_report"]["domain"], "")

    # ── All 8 endpoints called ────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_all_8_endpoints_called(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        cr = _combined_result()
        run_otx_enrichment(cr, self._settings())

        called_paths = [self._url_path(c.args[0]) for c in mock_get.call_args_list]
        expected = [
            "/IPv4/1.2.3.4/general",
            "/IPv4/1.2.3.4/passive_dns",
            "/IPv4/1.2.3.4/malware",
            "/IPv4/1.2.3.4/url_list",
            "/domain/example.com/general",
            "/domain/example.com/passive_dns",
            "/domain/example.com/malware",
            "/domain/example.com/url_list",
        ]
        for expected_path in expected:
            self.assertTrue(
                any(expected_path in p for p in called_paths),
                f"Expected endpoint not called: {expected_path}\nActual: {called_paths}",
            )

    # ── HTTP error handling ───────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_http_error_on_general_skips_ip(self, mock_get, _sleep):
        """When IPv4/general returns 4xx/5xx, that IP is skipped."""
        for code in (401, 403, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="error")
                cr = _combined_result()
                out = run_otx_enrichment(cr, self._settings())
                self.assertEqual(out["otx"]["ip_reports"], [])

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_404_on_secondary_endpoints_returns_empty_data(self, mock_get, _sleep):
        """404 on malware/url_list yields empty list/count, not a skip."""
        def side_effect(url, **_kwargs):
            path = self._url_path(url)
            if "/IPv4/1.2.3.4/general" in path:
                return _mock_response(200, _otx_general_body_full())
            # All other endpoints 404
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        r = out["otx"]["ip_reports"][0]
        self.assertEqual(r["malware"], [])
        self.assertEqual(r["url_count"], 0)

    # ── Rate limit ────────────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_rate_limit_stops_enrichment(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="Too Many Requests")
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        # Rate limit on first call — no ip_reports collected
        self.assertEqual(out["otx"]["ip_reports"], [])

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_rate_limit_mid_ip_stops_remaining_endpoints(self, mock_get, _sleep):
        """Rate limit on passive_dns should stop malware and url_list calls."""
        def side_effect(url, **_kwargs):
            path = self._url_path(url)
            if "/IPv4/1.2.3.4/general" in path:
                return _mock_response(200, _otx_general_body_full())
            if "/IPv4/1.2.3.4/passive_dns" in path:
                return _mock_response(429, {}, text="rl")
            return _mock_response(200, {})

        mock_get.side_effect = side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())

        called_paths = [self._url_path(c.args[0]) for c in mock_get.call_args_list]
        # malware and url_list should NOT be called after rate limit
        self.assertFalse(any("/IPv4/1.2.3.4/malware" in p for p in called_paths))
        self.assertFalse(any("/IPv4/1.2.3.4/url_list" in p for p in called_paths))
        # But the IP report IS present (general was OK)
        self.assertEqual(len(out["otx"]["ip_reports"]), 1)

    # ── Key rotator ───────────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_key_rotator_tick_per_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"
        mock_get.side_effect = self._full_side_effect
        run_otx_enrichment(_combined_result(), self._settings(rotator=rotator, OTX_API_KEY=""))
        # 8 endpoints → 8 ticks (1 per successful HTTP call)
        self.assertEqual(rotator.tick.call_count, 8)

    # ── deepcopy isolation ────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_isolated_does_not_mutate_original(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        combined = _combined_result()
        original_dns = combined["dns"]["domain"]["ips"]["ipv4"].copy()
        sub = run_otx_enrichment_isolated(combined, self._settings())
        # Original must not have 'otx' key
        self.assertNotIn("otx", combined)
        # Original nested structure must be unchanged
        self.assertEqual(combined["dns"]["domain"]["ips"]["ipv4"], original_dns)
        # But the returned dict must have ip_reports
        self.assertIn("ip_reports", sub)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_isolated_returns_otx_subdict(self, mock_get, _sleep):
        mock_get.side_effect = self._full_side_effect
        sub = run_otx_enrichment_isolated(_combined_result(), self._settings())
        self.assertIn("ip_reports", sub)
        self.assertIn("domain_report", sub)
        # Must not be a full combined_result
        self.assertNotIn("domain", sub)
        self.assertNotIn("dns", sub)

    # ── Multiple IPs ──────────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_multiple_ips_all_enriched(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._url_path(url)
            if "/IPv4/" in path and "/general" in path:
                return _mock_response(200, {"pulse_info": {"count": 1, "pulses": []}, "reputation": 0})
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        cr = {
            "domain": "",
            "metadata": {"ip_mode": False},
            "dns": {
                "domain": {"ips": {"ipv4": ["1.1.1.1", "2.2.2.2"]}},
                "subdomains": {},
            },
        }
        out = run_otx_enrichment(cr, self._settings())
        ips = [r["ip"] for r in out["otx"]["ip_reports"]]
        self.assertIn("1.1.1.1", ips)
        self.assertIn("2.2.2.2", ips)

    # ── Request exception ─────────────────────────────────────────────────────

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_network_exception_handled_gracefully(self, mock_get, _sleep):
        import requests as req_lib
        mock_get.side_effect = req_lib.RequestException("Connection refused")
        cr = _combined_result()
        # Must not raise — returns with empty ip_reports
        out = run_otx_enrichment(cr, self._settings())
        self.assertIn("otx", out)
        self.assertEqual(out["otx"]["ip_reports"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

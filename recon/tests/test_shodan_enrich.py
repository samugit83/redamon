"""
Unit tests for Shodan Pipeline Enrichment Module (recon/main_recon_modules/shodan_enrich.py).

Tests verify:
  - IP extraction from domain-mode and IP-mode combined_result structures
  - Host lookup response parsing (both dict and list vulns formats)
  - Reverse DNS response parsing
  - Domain DNS response parsing
  - Passive CVE extraction (with and without prior host data)
  - Feature gating (each toggle independently controls its feature)
  - API key gating (no key → skip enrichment)
  - Graph update data structure compatibility

Run with: python -m pytest recon/tests/test_shodan_enrich.py -v
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add recon dir to path
_recon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main_recon_modules")
sys.path.insert(0, _recon_dir)

from shodan_enrich import (
    _extract_ips_from_recon,
    _run_host_lookup,
    _run_reverse_dns,
    _run_domain_dns,
    _extract_passive_cves,
    run_shodan_enrichment,
)


# ─── Realistic Shodan API response fixtures ─────────────────────────────────

SHODAN_HOST_RESPONSE = {
    "ip_str": "93.184.216.34",
    "ip": 1572395042,
    "os": "Linux 5.4",
    "isp": "Edgecast",
    "org": "Verizon Digital Media",
    "country_name": "United States",
    "country_code": "US",
    "city": "Los Angeles",
    "ports": [80, 443],
    "hostnames": ["www.example.com"],
    "domains": ["example.com"],
    "vulns": ["CVE-2021-44228", "CVE-2021-41773"],
    "data": [
        {
            "port": 80,
            "transport": "tcp",
            "product": "Apache",
            "version": "2.4.49",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n",
            "_shodan": {"module": "http", "id": "abc123", "crawler": "abc"},
        },
        {
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.21.6",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.21.6\r\n",
            "_shodan": {"module": "https", "id": "def456", "crawler": "def"},
        },
    ],
}

SHODAN_HOST_RESPONSE_VULNS_DICT = {
    "ip_str": "10.0.0.1",
    "os": None,
    "isp": "PrivateISP",
    "org": "PrivateOrg",
    "country_name": "Germany",
    "city": "Berlin",
    "ports": [22],
    "vulns": {"CVE-2023-12345": {}, "CVE-2023-67890": {"verified": True}},
    "data": [
        {
            "port": 22,
            "transport": "tcp",
            "product": "OpenSSH",
            "version": "8.9",
            "data": "SSH-2.0-OpenSSH_8.9\r\n",
            "_shodan": {"module": "ssh"},
        },
    ],
}

SHODAN_HOST_RESPONSE_MINIMAL = {
    "ip_str": "10.0.0.2",
    "ports": [8080],
    "data": [
        {
            "port": 8080,
            "transport": "tcp",
            "data": "HTTP/1.0 503 Service Unavailable\r\n",
            "_shodan": {"module": "http"},
        },
    ],
}

SHODAN_REVERSE_DNS_RESPONSE = {
    "93.184.216.34": ["www.example.com", "example.com"],
    "1.1.1.1": ["one.one.one.one"],
    "10.0.0.5": [],
}

SHODAN_DOMAIN_DNS_RESPONSE = {
    "domain": "example.com",
    "tags": [],
    "subdomains": ["www", "api", "mail"],
    "more": False,
    "data": [
        {"subdomain": "www", "type": "A", "value": "93.184.216.34", "last_seen": "2026-03-10T00:00:00"},
        {"subdomain": "api", "type": "A", "value": "93.184.216.35", "last_seen": "2026-03-10T00:00:00"},
        {"subdomain": "", "type": "MX", "value": "mail.example.com", "last_seen": "2026-03-10T00:00:00"},
        {"subdomain": "", "type": "NS", "value": "ns1.example.com", "last_seen": "2026-03-10T00:00:00"},
    ],
}


# ─── Combined result fixtures ───────────────────────────────────────────────

def _make_domain_combined_result():
    """Realistic combined_result from domain mode after domain_discovery."""
    return {
        "metadata": {
            "scan_type": "domain_discovery",
            "target": "example.com",
            "root_domain": "example.com",
            "ip_mode": False,
            "modules_executed": ["whois", "domain_discovery", "dns_resolution"],
        },
        "domain": "example.com",
        "subdomains": ["www.example.com", "api.example.com"],
        "dns": {
            "domain": {
                "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
                "ips": {"ipv4": ["93.184.216.34"], "ipv6": []},
                "has_records": True,
            },
            "subdomains": {
                "www.example.com": {
                    "records": {"A": ["93.184.216.34"]},
                    "ips": {"ipv4": ["93.184.216.34"], "ipv6": []},
                    "has_records": True,
                },
                "api.example.com": {
                    "records": {"A": ["93.184.216.35"]},
                    "ips": {"ipv4": ["93.184.216.35"], "ipv6": []},
                    "has_records": True,
                },
            },
        },
    }


def _make_ip_combined_result():
    """Realistic combined_result from IP mode after ip_recon."""
    return {
        "metadata": {
            "ip_mode": True,
            "target_ips": ["10.0.0.0/30"],
            "expanded_ips": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "modules_executed": ["ip_recon"],
        },
        "domain": "ip-targets.proj123",
        "dns": {
            "domain": {},
            "subdomains": {
                "router.local": {
                    "ips": {"ipv4": ["10.0.0.1"], "ipv6": []},
                    "has_records": True,
                },
            },
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractIps(unittest.TestCase):
    """Tests for _extract_ips_from_recon()."""

    def test_domain_mode_extracts_root_and_subdomain_ips(self):
        result = _make_domain_combined_result()
        ips = _extract_ips_from_recon(result)
        self.assertIn("93.184.216.34", ips)
        self.assertIn("93.184.216.35", ips)
        self.assertEqual(len(ips), 2)

    def test_ip_mode_extracts_expanded_ips(self):
        result = _make_ip_combined_result()
        ips = _extract_ips_from_recon(result)
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)
        self.assertIn("10.0.0.3", ips)
        self.assertEqual(len(ips), 3)

    def test_deduplicates_ips(self):
        """Same IP from root domain and subdomain should appear once."""
        result = _make_domain_combined_result()
        ips = _extract_ips_from_recon(result)
        self.assertEqual(ips.count("93.184.216.34"), 1)

    def test_empty_dns_returns_empty(self):
        result = {"metadata": {}, "dns": {}}
        ips = _extract_ips_from_recon(result)
        self.assertEqual(ips, [])

    def test_skips_empty_ip_strings(self):
        result = {
            "metadata": {},
            "dns": {
                "domain": {"ips": {"ipv4": ["1.2.3.4", "", None]}},
                "subdomains": {},
            },
        }
        ips = _extract_ips_from_recon(result)
        self.assertEqual(ips, ["1.2.3.4"])

    def test_returns_sorted(self):
        result = _make_domain_combined_result()
        ips = _extract_ips_from_recon(result)
        self.assertEqual(ips, sorted(ips))


class TestRunHostLookup(unittest.TestCase):
    """Tests for _run_host_lookup() — parsing Shodan /shodan/host/{ip} responses."""

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_parses_full_response(self, mock_sleep, mock_get):
        """Correctly parses all fields from a full host response."""
        mock_get.return_value = SHODAN_HOST_RESPONSE
        hosts = _run_host_lookup(["93.184.216.34"], "test-key")

        self.assertEqual(len(hosts), 1)
        h = hosts[0]
        self.assertEqual(h["ip"], "93.184.216.34")
        self.assertEqual(h["os"], "Linux 5.4")
        self.assertEqual(h["isp"], "Edgecast")
        self.assertEqual(h["org"], "Verizon Digital Media")
        self.assertEqual(h["country_name"], "United States")
        self.assertEqual(h["city"], "Los Angeles")
        self.assertEqual(h["ports"], [80, 443])
        # vulns as list
        self.assertIn("CVE-2021-44228", h["vulns"])
        self.assertIn("CVE-2021-41773", h["vulns"])
        self.assertEqual(len(h["vulns"]), 2)

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_parses_vulns_as_dict(self, mock_sleep, mock_get):
        """Handles vulns field when returned as dict (keys are CVE IDs)."""
        mock_get.return_value = SHODAN_HOST_RESPONSE_VULNS_DICT
        hosts = _run_host_lookup(["10.0.0.1"], "test-key")

        h = hosts[0]
        self.assertIn("CVE-2023-12345", h["vulns"])
        self.assertIn("CVE-2023-67890", h["vulns"])
        self.assertIsInstance(h["vulns"], list)

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_parses_services(self, mock_sleep, mock_get):
        """Correctly extracts service data from data[] array."""
        mock_get.return_value = SHODAN_HOST_RESPONSE
        hosts = _run_host_lookup(["93.184.216.34"], "test-key")

        services = hosts[0]["services"]
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]["port"], 80)
        self.assertEqual(services[0]["transport"], "tcp")
        self.assertEqual(services[0]["product"], "Apache")
        self.assertEqual(services[0]["version"], "2.4.49")
        self.assertIn("Apache/2.4.49", services[0]["banner"])
        self.assertEqual(services[0]["module"], "http")

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_handles_minimal_response(self, mock_sleep, mock_get):
        """Handles host with no os, org, city, vulns, product fields."""
        mock_get.return_value = SHODAN_HOST_RESPONSE_MINIMAL
        hosts = _run_host_lookup(["10.0.0.2"], "test-key")

        h = hosts[0]
        self.assertIsNone(h["os"])
        self.assertIsNone(h["isp"])
        self.assertIsNone(h["org"])
        self.assertEqual(h["vulns"], [])
        # Service without product
        self.assertEqual(h["services"][0]["product"], "")

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_skips_404_ips(self, mock_sleep, mock_get):
        """IPs returning None (404) are skipped."""
        mock_get.side_effect = [SHODAN_HOST_RESPONSE, None, SHODAN_HOST_RESPONSE_MINIMAL]
        hosts = _run_host_lookup(["1.1.1.1", "10.0.0.99", "10.0.0.2"], "test-key")
        self.assertEqual(len(hosts), 2)

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_rate_limits_between_calls(self, mock_sleep, mock_get):
        """Sleeps 1 second between each host lookup."""
        mock_get.return_value = SHODAN_HOST_RESPONSE
        _run_host_lookup(["1.1.1.1", "2.2.2.2", "3.3.3.3"], "test-key")
        self.assertEqual(mock_sleep.call_count, 3)

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_banner_truncated_to_500(self, mock_sleep, mock_get):
        """Banner data is truncated to 500 chars."""
        resp = {
            "ports": [80],
            "data": [{
                "port": 80, "transport": "tcp",
                "data": "X" * 1000,
                "_shodan": {"module": "http"},
            }],
        }
        mock_get.return_value = resp
        hosts = _run_host_lookup(["1.1.1.1"], "test-key")
        self.assertEqual(len(hosts[0]["services"][0]["banner"]), 500)


class TestRunReverseDns(unittest.TestCase):
    """Tests for _run_reverse_dns()."""

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_parses_response(self, mock_sleep, mock_get):
        mock_get.return_value = SHODAN_REVERSE_DNS_RESPONSE
        result = _run_reverse_dns(["93.184.216.34", "1.1.1.1", "10.0.0.5"], "test-key")

        self.assertIn("93.184.216.34", result)
        self.assertEqual(result["93.184.216.34"], ["www.example.com", "example.com"])
        self.assertIn("1.1.1.1", result)
        self.assertEqual(result["1.1.1.1"], ["one.one.one.one"])
        # Empty hostnames should be excluded
        self.assertNotIn("10.0.0.5", result)

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_batches_100_ips(self, mock_sleep, mock_get):
        """Batches IPs in groups of 100."""
        mock_get.return_value = {}
        ips = [f"10.0.{i // 256}.{i % 256}" for i in range(250)]
        _run_reverse_dns(ips, "test-key")
        # 250 IPs = 3 batches (100 + 100 + 50)
        self.assertEqual(mock_get.call_count, 3)

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_handles_api_failure(self, mock_sleep, mock_get):
        mock_get.return_value = None
        result = _run_reverse_dns(["1.1.1.1"], "test-key")
        self.assertEqual(result, {})


class TestRunDomainDns(unittest.TestCase):
    """Tests for _run_domain_dns()."""

    @patch('shodan_enrich._shodan_get')
    def test_parses_response(self, mock_get):
        mock_get.return_value = SHODAN_DOMAIN_DNS_RESPONSE
        result = _run_domain_dns("example.com", "test-key")

        self.assertEqual(result["subdomains"], ["www", "api", "mail"])
        self.assertEqual(len(result["records"]), 4)
        # Check first record
        r0 = result["records"][0]
        self.assertEqual(r0["subdomain"], "www")
        self.assertEqual(r0["type"], "A")
        self.assertEqual(r0["value"], "93.184.216.34")

    @patch('shodan_enrich._shodan_get')
    def test_handles_api_failure(self, mock_get):
        mock_get.return_value = None
        result = _run_domain_dns("example.com", "test-key")
        self.assertEqual(result, {})

    @patch('shodan_enrich._shodan_get')
    def test_handles_empty_data(self, mock_get):
        mock_get.return_value = {"domain": "example.com", "subdomains": [], "data": []}
        result = _run_domain_dns("example.com", "test-key")
        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["records"], [])


class TestExtractPassiveCves(unittest.TestCase):
    """Tests for _extract_passive_cves()."""

    def test_extracts_from_existing_hosts(self):
        """When host data exists, extracts CVEs without new API calls."""
        hosts = [
            {"ip": "1.1.1.1", "vulns": ["CVE-2021-44228", "CVE-2021-41773"]},
            {"ip": "2.2.2.2", "vulns": ["CVE-2021-44228"]},  # Duplicate CVE, different IP
        ]
        cves = _extract_passive_cves(hosts, ["1.1.1.1", "2.2.2.2"], "test-key")

        self.assertEqual(len(cves), 3)
        cve_ids = [(c["cve_id"], c["ip"]) for c in cves]
        self.assertIn(("CVE-2021-44228", "1.1.1.1"), cve_ids)
        self.assertIn(("CVE-2021-41773", "1.1.1.1"), cve_ids)
        self.assertIn(("CVE-2021-44228", "2.2.2.2"), cve_ids)

    def test_deduplicates_same_cve_same_ip(self):
        """Same CVE+IP combination only appears once."""
        hosts = [
            {"ip": "1.1.1.1", "vulns": ["CVE-2021-44228", "CVE-2021-44228"]},
        ]
        cves = _extract_passive_cves(hosts, ["1.1.1.1"], "test-key")
        self.assertEqual(len(cves), 1)

    @patch('shodan_enrich._internetdb_get')
    @patch('shodan_enrich.time.sleep')
    def test_does_lookups_when_no_hosts(self, mock_sleep, mock_idb):
        """When no host data, queries InternetDB directly for CVEs."""
        mock_idb.return_value = {
            "vulns": ["CVE-2023-99999"],
            "ports": [80], "hostnames": [], "cpes": [], "tags": [],
        }
        cves = _extract_passive_cves([], ["10.0.0.1"], "test-key")
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["cve_id"], "CVE-2023-99999")
        self.assertEqual(cves[0]["source"], "internetdb")

    @patch('shodan_enrich._internetdb_get')
    @patch('shodan_enrich.time.sleep')
    def test_handles_vulns_as_list_in_standalone(self, mock_sleep, mock_idb):
        """Standalone CVE lookups via InternetDB handle vulns as list format."""
        mock_idb.return_value = {
            "vulns": ["CVE-2023-11111", "CVE-2023-22222"],
            "ports": [443], "hostnames": [], "cpes": [], "tags": [],
        }
        cves = _extract_passive_cves([], ["10.0.0.1"], "test-key")
        self.assertEqual(len(cves), 2)

    def test_empty_hosts_no_vulns(self):
        hosts = [{"ip": "1.1.1.1", "vulns": []}]
        cves = _extract_passive_cves(hosts, ["1.1.1.1"], "test-key")
        self.assertEqual(cves, [])


class TestRunShodanEnrichment(unittest.TestCase):
    """Integration tests for run_shodan_enrichment() — feature gating and output structure."""

    @patch('shodan_enrich._run_host_lookup')
    @patch('shodan_enrich._run_reverse_dns')
    @patch('shodan_enrich._run_domain_dns')
    @patch('shodan_enrich._extract_passive_cves')
    def test_all_features_enabled(self, mock_cves, mock_ddns, mock_rdns, mock_host):
        """All 4 features run when all toggles are on."""
        mock_host.return_value = [{"ip": "1.1.1.1", "vulns": []}]
        mock_rdns.return_value = {"1.1.1.1": ["dns.example.com"]}
        mock_ddns.return_value = {"subdomains": ["www"], "records": []}
        mock_cves.return_value = []

        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": True,
            "SHODAN_DOMAIN_DNS": True,
            "SHODAN_PASSIVE_CVES": True,
        }
        result = run_shodan_enrichment(result, settings)

        mock_host.assert_called_once()
        mock_rdns.assert_called_once()
        mock_ddns.assert_called_once()
        mock_cves.assert_called_once()
        self.assertIn("shodan", result)
        self.assertIsInstance(result["shodan"]["hosts"], list)
        self.assertIsInstance(result["shodan"]["reverse_dns"], dict)
        self.assertIsInstance(result["shodan"]["domain_dns"], dict)
        self.assertIsInstance(result["shodan"]["cves"], list)

    @patch('shodan_enrich._run_host_lookup')
    @patch('shodan_enrich._run_reverse_dns')
    @patch('shodan_enrich._run_domain_dns')
    @patch('shodan_enrich._extract_passive_cves')
    def test_only_host_lookup(self, mock_cves, mock_ddns, mock_rdns, mock_host):
        """Only host lookup runs when only that toggle is on."""
        mock_host.return_value = []

        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": False,
            "SHODAN_DOMAIN_DNS": False,
            "SHODAN_PASSIVE_CVES": False,
        }
        result = run_shodan_enrichment(result, settings)

        mock_host.assert_called_once()
        mock_rdns.assert_not_called()
        mock_ddns.assert_not_called()
        mock_cves.assert_not_called()

    @patch('shodan_enrich._run_host_lookup')
    @patch('shodan_enrich._run_domain_dns')
    def test_domain_dns_skipped_in_ip_mode(self, mock_ddns, mock_host):
        """Domain DNS is skipped when in IP mode even if toggle is on."""
        mock_host.return_value = []

        result = _make_ip_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": False,
            "SHODAN_DOMAIN_DNS": True,
            "SHODAN_PASSIVE_CVES": False,
        }
        result = run_shodan_enrichment(result, settings)

        mock_ddns.assert_not_called()

    @patch('shodan_enrich._internetdb_get')
    @patch('shodan_enrich.time.sleep')
    def test_no_api_key_falls_back_to_internetdb(self, mock_sleep, mock_idb):
        """No API key → falls back to InternetDB (free), enrichment still runs."""
        mock_idb.return_value = {"ports": [80], "vulns": [], "hostnames": [], "cpes": [], "tags": []}
        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": True,
            "SHODAN_DOMAIN_DNS": True,
            "SHODAN_PASSIVE_CVES": True,
        }
        result = run_shodan_enrichment(result, settings)
        # Enrichment runs via InternetDB fallback — shodan key IS present
        self.assertIn("shodan", result)
        self.assertIsInstance(result["shodan"]["hosts"], list)
        # InternetDB was called (for host lookup and/or reverse DNS)
        self.assertTrue(mock_idb.called)

    def test_all_toggles_off_skips(self):
        """All toggles off → enrichment skipped."""
        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": False,
            "SHODAN_REVERSE_DNS": False,
            "SHODAN_DOMAIN_DNS": False,
            "SHODAN_PASSIVE_CVES": False,
        }
        result = run_shodan_enrichment(result, settings)
        self.assertNotIn("shodan", result)

    @patch('shodan_enrich._run_host_lookup')
    @patch('shodan_enrich._extract_passive_cves')
    def test_passive_cves_reuses_host_data(self, mock_cves, mock_host):
        """Passive CVEs receives host data when host lookup also ran."""
        host_data = [{"ip": "1.1.1.1", "vulns": ["CVE-2021-44228"]}]
        mock_host.return_value = host_data
        mock_cves.return_value = [{"cve_id": "CVE-2021-44228", "ip": "1.1.1.1"}]

        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": False,
            "SHODAN_DOMAIN_DNS": False,
            "SHODAN_PASSIVE_CVES": True,
        }
        run_shodan_enrichment(result, settings)

        # _extract_passive_cves should receive the host data
        mock_cves.assert_called_once()
        call_args = mock_cves.call_args
        self.assertEqual(call_args[0][0], host_data)  # hosts arg


class TestShodanGet(unittest.TestCase):
    """Tests for _shodan_get() HTTP helper."""

    @patch('shodan_enrich.requests.get')
    def test_200_returns_json(self, mock_get):
        from shodan_enrich import _shodan_get
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"test": True}
        mock_get.return_value = mock_resp

        result = _shodan_get("/test", "key123")
        self.assertEqual(result, {"test": True})
        # Verify key is passed as param
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        self.assertIn("key", call_kwargs.kwargs.get("params", call_kwargs[1].get("params", {})))

    @patch('shodan_enrich.requests.get')
    def test_404_returns_none(self, mock_get):
        from shodan_enrich import _shodan_get
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = _shodan_get("/shodan/host/10.0.0.1", "key123")
        self.assertIsNone(result)

    @patch('shodan_enrich.requests.get')
    def test_401_raises_api_key_error(self, mock_get):
        from shodan_enrich import _shodan_get, ShodanApiKeyError
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        with self.assertRaises(ShodanApiKeyError):
            _shodan_get("/test", "bad-key")

    @patch('shodan_enrich.requests.get')
    def test_403_raises_api_key_error(self, mock_get):
        """403 (requires membership) aborts immediately like 401."""
        from shodan_enrich import _shodan_get, ShodanApiKeyError
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp

        with self.assertRaises(ShodanApiKeyError):
            _shodan_get("/test", "free-key")

    @patch('shodan_enrich.time.sleep')
    @patch('shodan_enrich.requests.get')
    def test_429_sleeps_and_returns_none(self, mock_get, mock_sleep):
        from shodan_enrich import _shodan_get
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        result = _shodan_get("/test", "key123")
        self.assertIsNone(result)
        mock_sleep.assert_called_once_with(2)

    @patch('shodan_enrich.requests.get')
    def test_network_error_returns_none(self, mock_get):
        from shodan_enrich import _shodan_get
        import requests
        mock_get.side_effect = requests.ConnectionError("connection refused")

        result = _shodan_get("/test", "key123")
        self.assertIsNone(result)


class TestOutputStructureForGraph(unittest.TestCase):
    """Verify output structure matches what update_graph_from_shodan() expects."""

    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_host_entry_has_required_fields(self, mock_sleep, mock_get):
        """Each host entry has all fields needed by graph update."""
        mock_get.return_value = SHODAN_HOST_RESPONSE
        hosts = _run_host_lookup(["93.184.216.34"], "key")

        h = hosts[0]
        # Fields read by update_graph_from_shodan
        required_fields = ["ip", "os", "isp", "org", "country_name", "city", "services", "vulns"]
        for f in required_fields:
            self.assertIn(f, h, f"Missing field: {f}")

        # Service fields
        svc = h["services"][0]
        svc_fields = ["port", "transport", "product", "version", "banner", "module"]
        for f in svc_fields:
            self.assertIn(f, svc, f"Missing service field: {f}")

    def test_cve_entry_has_required_fields(self):
        """Each CVE entry has fields needed by graph update."""
        hosts = [{"ip": "1.1.1.1", "vulns": ["CVE-2021-44228"]}]
        cves = _extract_passive_cves(hosts, ["1.1.1.1"], "key")

        cve = cves[0]
        self.assertIn("cve_id", cve)
        self.assertIn("ip", cve)
        self.assertTrue(cve["cve_id"].startswith("CVE-"))

    @patch('shodan_enrich._shodan_get')
    def test_domain_dns_record_has_required_fields(self, mock_get):
        """Each DNS record has fields needed by graph update."""
        mock_get.return_value = SHODAN_DOMAIN_DNS_RESPONSE
        result = _run_domain_dns("example.com", "key")

        record = result["records"][0]
        self.assertIn("subdomain", record)
        self.assertIn("type", record)
        self.assertIn("value", record)


class TestGracefulErrorHandling(unittest.TestCase):
    """Tests for graceful error handling — pipeline must never crash from Shodan errors."""

    @patch('shodan_enrich._run_host_lookup')
    def test_invalid_api_key_aborts_gracefully(self, mock_host):
        """Invalid API key (401) aborts Shodan but returns combined_result intact."""
        from shodan_enrich import ShodanApiKeyError
        mock_host.side_effect = ShodanApiKeyError("401 Unauthorized")

        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "bad-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": True,
            "SHODAN_DOMAIN_DNS": False,
            "SHODAN_PASSIVE_CVES": False,
        }
        result = run_shodan_enrichment(result, settings)

        # Should still have shodan key with empty data
        self.assertIn("shodan", result)
        self.assertEqual(result["shodan"]["hosts"], [])
        self.assertEqual(result["shodan"]["reverse_dns"], {})
        # Original data must be intact
        self.assertIn("dns", result)
        self.assertEqual(result["domain"], "example.com")

    @patch('shodan_enrich._run_host_lookup')
    def test_unexpected_exception_caught(self, mock_host):
        """Unexpected exceptions are caught and pipeline continues."""
        mock_host.side_effect = RuntimeError("unexpected JSON parse error")

        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": False,
            "SHODAN_DOMAIN_DNS": False,
            "SHODAN_PASSIVE_CVES": False,
        }
        # Should NOT raise
        result = run_shodan_enrichment(result, settings)

        self.assertIn("shodan", result)
        self.assertEqual(result["domain"], "example.com")

    @patch('shodan_enrich._run_host_lookup')
    @patch('shodan_enrich._run_reverse_dns')
    def test_partial_failure_preserves_earlier_data(self, mock_rdns, mock_host):
        """If reverse DNS fails, host lookup data is still preserved."""
        mock_host.return_value = [{"ip": "1.1.1.1", "os": "Linux", "vulns": [],
                                   "isp": "Test", "org": "Test", "country_name": "US",
                                   "city": "NY", "ports": [80], "services": []}]
        mock_rdns.side_effect = RuntimeError("network timeout")

        result = _make_domain_combined_result()
        settings = {
            "SHODAN_API_KEY": "test-key",
            "SHODAN_HOST_LOOKUP": True,
            "SHODAN_REVERSE_DNS": True,
            "SHODAN_DOMAIN_DNS": False,
            "SHODAN_PASSIVE_CVES": False,
        }
        result = run_shodan_enrichment(result, settings)

        # Host data should be preserved even though rdns failed
        self.assertEqual(len(result["shodan"]["hosts"]), 1)
        self.assertEqual(result["shodan"]["hosts"][0]["ip"], "1.1.1.1")

    @patch('shodan_enrich._internetdb_get')
    @patch('shodan_enrich._shodan_get')
    @patch('shodan_enrich.time.sleep')
    def test_401_on_first_ip_falls_back_to_internetdb(self, mock_sleep, mock_get, mock_idb):
        """401 on first IP falls back to InternetDB for remaining IPs."""
        from shodan_enrich import ShodanApiKeyError
        mock_get.side_effect = ShodanApiKeyError("401")
        mock_idb.return_value = {"ports": [22], "vulns": [], "hostnames": [], "cpes": [], "tags": []}

        hosts = _run_host_lookup(["1.1.1.1", "2.2.2.2", "3.3.3.3"], "bad-key")

        # Should have tried Shodan API only once (first IP), then switched to InternetDB
        self.assertEqual(mock_get.call_count, 1)
        # InternetDB should be called for all 3 IPs (first IP retried via InternetDB after fallback)
        self.assertEqual(mock_idb.call_count, 3)
        # All hosts should be returned from InternetDB
        self.assertEqual(len(hosts), 3)
        for host in hosts:
            self.assertEqual(host["source"], "internetdb")


if __name__ == '__main__':
    unittest.main()

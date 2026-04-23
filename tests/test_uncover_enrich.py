"""Tests for recon/main_recon_modules/uncover_enrich.py"""
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon', 'main_recon_modules'))

from uncover_enrich import (
    _build_provider_config,
    _deduplicate_results,
    _extract_hosts_and_ips,
    _build_queries,
    merge_uncover_into_pipeline,
    run_uncover_expansion,
    run_uncover_expansion_isolated,
)


class TestBuildProviderConfig(unittest.TestCase):

    def test_empty_settings_returns_shodan_idb_only(self):
        config, engines = _build_provider_config({})
        self.assertEqual(config, {})
        self.assertEqual(engines, ['shodan-idb'])

    def test_shodan_key_adds_engine(self):
        config, engines = _build_provider_config({'SHODAN_API_KEY': 'key123'})
        self.assertIn('shodan', config)
        self.assertIn('shodan', engines)
        self.assertNotIn('shodan-idb', engines)

    def test_censys_needs_both_token_and_org(self):
        config, engines = _build_provider_config({'CENSYS_API_TOKEN': 'tok'})
        self.assertNotIn('censys', engines)
        config, engines = _build_provider_config({
            'CENSYS_API_TOKEN': 'tok',
            'CENSYS_ORG_ID': 'org',
        })
        self.assertIn('censys', engines)
        self.assertEqual(config['censys'], ['tok:org'])

    def test_google_needs_both_key_and_cx(self):
        config, engines = _build_provider_config({'UNCOVER_GOOGLE_API_KEY': 'gkey'})
        self.assertNotIn('google', engines)
        config, engines = _build_provider_config({
            'UNCOVER_GOOGLE_API_KEY': 'gkey',
            'UNCOVER_GOOGLE_API_CX': 'gcx',
        })
        self.assertIn('google', engines)
        self.assertEqual(config['google'], ['gkey:gcx'])

    def test_all_engines_configured(self):
        settings = {
            'SHODAN_API_KEY': 's1',
            'CENSYS_API_TOKEN': 'ct', 'CENSYS_ORG_ID': 'co',
            'FOFA_API_KEY': 'f1',
            'ZOOMEYE_API_KEY': 'z1',
            'NETLAS_API_KEY': 'n1',
            'CRIMINALIP_API_KEY': 'c1',
            'UNCOVER_QUAKE_API_KEY': 'q1',
            'UNCOVER_HUNTER_API_KEY': 'h1',
            'UNCOVER_PUBLICWWW_API_KEY': 'pw1',
            'UNCOVER_HUNTERHOW_API_KEY': 'hh1',
            'UNCOVER_GOOGLE_API_KEY': 'gk', 'UNCOVER_GOOGLE_API_CX': 'gc',
            'UNCOVER_ONYPHE_API_KEY': 'o1',
            'UNCOVER_DRIFTNET_API_KEY': 'd1',
        }
        config, engines = _build_provider_config(settings)
        expected = [
            'shodan', 'censys', 'fofa', 'zoomeye', 'netlas',
            'criminalip', 'quake', 'hunter', 'publicwww', 'hunterhow',
            'google', 'onyphe', 'driftnet',
        ]
        for e in expected:
            self.assertIn(e, engines, f"{e} missing from engines")
        self.assertNotIn('shodan-idb', engines)


class TestDeduplicateResults(unittest.TestCase):

    def test_dedup_by_ip_port(self):
        results = [
            {'ip': '1.2.3.4', 'port': 80, 'source': 'shodan'},
            {'ip': '1.2.3.4', 'port': 80, 'source': 'censys'},
            {'ip': '1.2.3.4', 'port': 443, 'source': 'shodan'},
            {'ip': '5.6.7.8', 'port': 80, 'source': 'fofa'},
        ]
        deduped = _deduplicate_results(results)
        self.assertEqual(len(deduped), 3)
        self.assertEqual(deduped[0]['source'], 'shodan')

    def test_skips_empty_ip(self):
        results = [
            {'ip': '', 'port': 80},
            {'ip': '1.2.3.4', 'port': 80},
        ]
        deduped = _deduplicate_results(results)
        self.assertEqual(len(deduped), 1)


class TestExtractHostsAndIps(unittest.TestCase):

    def test_filters_non_routable(self):
        results = [
            {'ip': '10.0.0.1', 'port': 80, 'host': 'internal.example.com'},
            {'ip': '93.184.216.34', 'port': 443, 'host': 'www.example.com'},
            {'ip': '100.64.1.5', 'port': 8080, 'host': 'cgnat.example.com'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(
            results, 'example.com', {}
        )
        self.assertIn('93.184.216.34', ips)
        self.assertNotIn('10.0.0.1', ips)
        self.assertNotIn('100.64.1.5', ips)

    def test_extracts_in_scope_hostnames(self):
        results = [
            {'ip': '93.184.216.34', 'port': 443, 'host': 'sub.example.com'},
            {'ip': '1.2.3.4', 'port': 80, 'host': 'other.net'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(
            results, 'example.com', {}
        )
        self.assertIn('sub.example.com', hosts)
        self.assertNotIn('other.net', hosts)

    def test_collects_ports_per_ip(self):
        results = [
            {'ip': '93.184.216.34', 'port': 80},
            {'ip': '93.184.216.34', 'port': 443},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(
            results, 'example.com', {}
        )
        self.assertEqual(sorted(ip_ports.get('93.184.216.34', [])), [80, 443])


class TestBuildQueries(unittest.TestCase):

    def test_basic_domain(self):
        queries = _build_queries('example.com', {})
        self.assertEqual(queries, ['example.com'])

    def test_with_whois_org(self):
        queries = _build_queries('example.com', {'_WHOIS_ORG': 'Example Inc.'})
        self.assertEqual(len(queries), 2)
        self.assertIn('ssl:"Example Inc."', queries)

    def test_skips_na_org(self):
        queries = _build_queries('example.com', {'_WHOIS_ORG': 'N/A'})
        self.assertEqual(len(queries), 1)


class TestMergeIntoPipeline(unittest.TestCase):

    def test_merge_new_subdomains(self):
        combined = {"dns": {"subdomains": {}}, "domain": "example.com"}
        uncover_data = {
            "hosts": ["new.example.com", "api.example.com"],
            "ips": ["1.2.3.4"],
            "ip_ports": {"1.2.3.4": [80, 443]},
        }
        count = merge_uncover_into_pipeline(combined, uncover_data, "example.com")
        self.assertGreater(count, 0)
        self.assertIn("new.example.com", combined["dns"]["subdomains"])
        self.assertIn("api.example.com", combined["dns"]["subdomains"])
        self.assertEqual(
            combined["dns"]["subdomains"]["new.example.com"]["source"],
            "uncover",
        )

    def test_no_duplicate_subdomains(self):
        combined = {
            "dns": {"subdomains": {"existing.example.com": {"ips": {"ipv4": []}}}},
            "domain": "example.com",
        }
        uncover_data = {
            "hosts": ["existing.example.com", "new.example.com"],
            "ips": [],
            "ip_ports": {},
        }
        count = merge_uncover_into_pipeline(combined, uncover_data, "example.com")
        self.assertGreater(count, 0)

    def test_empty_data(self):
        combined = {"dns": {"subdomains": {}}}
        count = merge_uncover_into_pipeline(combined, {}, "example.com")
        self.assertEqual(count, 0)


class TestRunUncoverExpansion(unittest.TestCase):

    def test_disabled_returns_empty(self):
        result = run_uncover_expansion({}, {'UNCOVER_ENABLED': False})
        self.assertEqual(result, {})

    def test_no_keys_returns_empty(self):
        result = run_uncover_expansion(
            {"domain": "example.com"},
            {'UNCOVER_ENABLED': True},
        )
        self.assertEqual(result, {})

    @patch('uncover_enrich.subprocess.run')
    def test_parses_json_output(self, mock_run):
        output_lines = [
            json.dumps({"ip": "93.184.216.34", "port": 443, "host": "www.example.com", "source": "shodan"}),
            json.dumps({"ip": "93.184.216.35", "port": 80, "host": "api.example.com", "source": "censys"}),
        ]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\n".join(output_lines)
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        settings = {
            'UNCOVER_ENABLED': True,
            'SHODAN_API_KEY': 'test_key',
            'UNCOVER_MAX_RESULTS': 100,
        }
        combined = {
            "domain": "example.com",
            "metadata": {"modules_executed": []},
        }
        result = run_uncover_expansion(combined, settings)
        self.assertIn("ips", result)
        self.assertIn("hosts", result)

    @patch('uncover_enrich.subprocess.run')
    def test_timeout_returns_partial(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=600)
        settings = {
            'UNCOVER_ENABLED': True,
            'SHODAN_API_KEY': 'test_key',
            'UNCOVER_MAX_RESULTS': 100,
        }
        combined = {
            "domain": "example.com",
            "metadata": {"modules_executed": []},
        }
        result = run_uncover_expansion(combined, settings)
        self.assertIsInstance(result, dict)


class TestMergeIpMetadata(unittest.TestCase):

    def test_merge_expands_metadata_ips(self):
        combined = {
            "dns": {"subdomains": {}},
            "domain": "example.com",
            "metadata": {"expanded_ips": ["9.9.9.9"]},
        }
        uncover_data = {
            "hosts": [],
            "ips": ["1.2.3.4", "9.9.9.9"],
            "ip_ports": {"1.2.3.4": [80]},
        }
        merge_uncover_into_pipeline(combined, uncover_data, "example.com")
        expanded = combined["metadata"]["expanded_ips"]
        self.assertIn("1.2.3.4", expanded)
        self.assertIn("9.9.9.9", expanded)
        # no duplicates
        self.assertEqual(expanded.count("9.9.9.9"), 1)

    def test_merge_creates_metadata_if_missing(self):
        combined = {"dns": {"subdomains": {}}, "domain": "example.com"}
        uncover_data = {"hosts": [], "ips": ["1.2.3.4"], "ip_ports": {}}
        merge_uncover_into_pipeline(combined, uncover_data, "example.com")
        self.assertIn("1.2.3.4", combined["metadata"]["expanded_ips"])


class TestRunUncoverExpansionIsolated(unittest.TestCase):

    def test_does_not_mutate_original(self):
        combined = {
            "domain": "example.com",
            "dns": {"subdomains": {"existing.example.com": {}}},
            "metadata": {"modules_executed": []},
        }
        original_keys = set(combined.keys())
        result = run_uncover_expansion_isolated(
            combined, {'UNCOVER_ENABLED': False}
        )
        self.assertEqual(result, {})
        self.assertEqual(set(combined.keys()), original_keys)

    @patch('uncover_enrich.subprocess.run')
    @patch('uncover_enrich.os.path.isfile', return_value=True)
    @patch('uncover_enrich.tempfile.mkdtemp', return_value='/tmp/redamon/test_iso')
    @patch('uncover_enrich.os.makedirs')
    @patch('uncover_enrich.shutil.rmtree')
    def test_returns_uncover_data(self, mock_rmtree, mock_makedirs,
                                  mock_mkdtemp, mock_isfile, mock_run):
        output_lines = [
            json.dumps({"ip": "93.184.216.34", "port": 443,
                         "host": "www.example.com", "source": "shodan"}),
        ]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file reading
        m = unittest.mock.mock_open(read_data="\n".join(output_lines) + "\n")
        with patch('builtins.open', m):
            settings = {
                'UNCOVER_ENABLED': True,
                'SHODAN_API_KEY': 'test_key',
                'UNCOVER_MAX_RESULTS': 100,
            }
            combined = {
                "domain": "example.com",
                "metadata": {"modules_executed": []},
            }
            result = run_uncover_expansion_isolated(combined, settings)

        self.assertIsInstance(result, dict)
        # Original combined should NOT have "uncover" key
        self.assertNotIn("uncover", combined)


class TestRunUncoverExpansionReturnFields(unittest.TestCase):

    @patch('uncover_enrich.subprocess.run')
    @patch('uncover_enrich.os.path.isfile', return_value=True)
    @patch('uncover_enrich.tempfile.mkdtemp', return_value='/tmp/redamon/test_fields')
    @patch('uncover_enrich.os.makedirs')
    @patch('uncover_enrich.shutil.rmtree')
    def test_result_contains_all_expected_keys(self, mock_rmtree, mock_makedirs,
                                                mock_mkdtemp, mock_isfile, mock_run):
        output_lines = [
            json.dumps({"ip": "93.184.216.34", "port": 443,
                         "host": "www.example.com", "source": "shodan"}),
            json.dumps({"ip": "93.184.216.35", "port": 80,
                         "host": "api.example.com", "source": "censys"}),
        ]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        m = unittest.mock.mock_open(read_data="\n".join(output_lines) + "\n")
        with patch('builtins.open', m):
            settings = {
                'UNCOVER_ENABLED': True,
                'SHODAN_API_KEY': 'key1',
                'CENSYS_API_TOKEN': 'tok',
                'CENSYS_ORG_ID': 'org',
                'UNCOVER_MAX_RESULTS': 100,
            }
            combined = {
                "domain": "example.com",
                "metadata": {"modules_executed": []},
            }
            result = run_uncover_expansion(combined, settings)

        expected_keys = {"hosts", "ips", "ip_ports", "urls", "sources",
                         "source_counts", "total_raw", "total_deduped"}
        self.assertTrue(expected_keys.issubset(set(result.keys())),
                        f"Missing keys: {expected_keys - set(result.keys())}")
        self.assertIsInstance(result["sources"], list)
        self.assertIsInstance(result["source_counts"], dict)
        self.assertIsInstance(result["total_raw"], int)
        self.assertIsInstance(result["total_deduped"], int)

    @patch('uncover_enrich.subprocess.run')
    def test_no_domain_returns_empty(self, mock_run):
        settings = {
            'UNCOVER_ENABLED': True,
            'SHODAN_API_KEY': 'test_key',
        }
        combined = {"domain": "", "metadata": {"modules_executed": []}}
        result = run_uncover_expansion(combined, settings)
        self.assertEqual(result, {})
        mock_run.assert_not_called()


class TestDeduplicateEdgeCases(unittest.TestCase):

    def test_non_numeric_port(self):
        results = [
            {'ip': '1.2.3.4', 'port': 'abc'},
            {'ip': '1.2.3.4', 'port': None},
        ]
        deduped = _deduplicate_results(results)
        # Both have port=0 after coercion, so dedup to 1
        self.assertEqual(len(deduped), 1)

    def test_empty_list(self):
        self.assertEqual(_deduplicate_results([]), [])

    def test_preserves_order(self):
        results = [
            {'ip': '1.1.1.1', 'port': 80, 'source': 'a'},
            {'ip': '2.2.2.2', 'port': 443, 'source': 'b'},
            {'ip': '3.3.3.3', 'port': 22, 'source': 'c'},
        ]
        deduped = _deduplicate_results(results)
        self.assertEqual([r['source'] for r in deduped], ['a', 'b', 'c'])


class TestExtractHostsEdgeCases(unittest.TestCase):

    def test_strips_trailing_dot(self):
        results = [
            {'ip': '93.184.216.34', 'port': 80, 'host': 'sub.example.com.'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('sub.example.com', hosts)

    def test_case_insensitive_host(self):
        results = [
            {'ip': '93.184.216.34', 'port': 80, 'host': 'Sub.Example.COM'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('sub.example.com', hosts)

    def test_host_same_as_ip_excluded(self):
        results = [
            {'ip': '93.184.216.34', 'port': 80, 'host': '93.184.216.34'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertEqual(hosts, [])


class TestGoogleEngineHandling(unittest.TestCase):
    """Google puts URLs in the ip field -- verify we extract host and capture URL."""

    def test_google_url_in_ip_extracts_host(self):
        results = [
            {'ip': 'https://sub.example.com/page', 'port': 0,
             'host': 'sub.example.com', 'source': 'google'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('sub.example.com', hosts)
        # URL-as-IP should NOT end up in the IP list
        self.assertEqual(ips, [])

    def test_google_url_in_ip_captured_as_url(self):
        results = [
            {'ip': 'https://sub.example.com/path', 'port': 0,
             'host': '', 'source': 'google'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('https://sub.example.com/path', urls)
        self.assertIn('sub.example.com', hosts)
        self.assertEqual(ips, [])

    def test_google_out_of_scope_url_filtered(self):
        results = [
            {'ip': 'https://other.net/page', 'port': 0,
             'host': 'other.net', 'source': 'google'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertEqual(hosts, [])
        self.assertEqual(urls, [])  # out of scope


class TestPublicWWWHandling(unittest.TestCase):
    """PublicWWW returns no IP -- verify host-only results are kept."""

    def test_publicwww_dedup_by_host(self):
        results = [
            {'ip': '', 'port': 0, 'host': 'sub.example.com',
             'url': 'https://sub.example.com/a', 'source': 'publicwww'},
            {'ip': '', 'port': 0, 'host': 'sub.example.com',
             'url': 'https://sub.example.com/b', 'source': 'publicwww'},
        ]
        deduped = _deduplicate_results(results)
        # Same (host, port=0) -> dedup to 1
        self.assertEqual(len(deduped), 1)

    def test_publicwww_host_extracted(self):
        results = [
            {'ip': '', 'port': 0, 'host': 'sub.example.com',
             'url': 'https://sub.example.com/page', 'source': 'publicwww'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('sub.example.com', hosts)
        self.assertIn('https://sub.example.com/page', urls)

    def test_publicwww_host_from_url_fallback(self):
        results = [
            {'ip': '', 'port': 0, 'host': '',
             'url': 'https://api.example.com/v1', 'source': 'publicwww'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('api.example.com', hosts)
        self.assertIn('https://api.example.com/v1', urls)


class TestUrlCollection(unittest.TestCase):
    """Verify url field is collected from engines that populate it."""

    def test_censys_url_captured(self):
        results = [
            {'ip': '1.2.3.4', 'port': 443, 'host': 'www.example.com',
             'url': 'https://www.example.com/', 'source': 'censys'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertIn('https://www.example.com/', urls)
        self.assertIn('1.2.3.4', ips)
        self.assertIn('www.example.com', hosts)

    def test_out_of_scope_url_filtered(self):
        results = [
            {'ip': '1.2.3.4', 'port': 80, 'host': 'other.net',
             'url': 'https://other.net/page', 'source': 'censys'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertEqual(urls, [])

    def test_non_http_url_ignored(self):
        results = [
            {'ip': '1.2.3.4', 'port': 21, 'host': 'ftp.example.com',
             'url': 'ftp://ftp.example.com', 'source': 'censys'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertEqual(urls, [])

    def test_empty_url_ignored(self):
        results = [
            {'ip': '1.2.3.4', 'port': 80, 'host': 'www.example.com',
             'url': '', 'source': 'shodan'},
        ]
        ips, hosts, ip_ports, urls = _extract_hosts_and_ips(results, 'example.com', {})
        self.assertEqual(urls, [])


if __name__ == '__main__':
    unittest.main()

"""Tests for recon/main_recon_modules/ip_filter.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon', 'main_recon_modules'))

from ip_filter import is_non_routable_ip, collect_cdn_ips, filter_ips_for_enrichment


class TestIsNonRoutableIp(unittest.TestCase):

    def test_private_rfc1918_class_a(self):
        self.assertTrue(is_non_routable_ip("10.0.0.1"))

    def test_private_rfc1918_class_b(self):
        self.assertTrue(is_non_routable_ip("172.16.0.1"))

    def test_private_rfc1918_class_c(self):
        self.assertTrue(is_non_routable_ip("192.168.1.1"))

    def test_loopback(self):
        self.assertTrue(is_non_routable_ip("127.0.0.1"))

    def test_link_local(self):
        self.assertTrue(is_non_routable_ip("169.254.1.1"))

    def test_cgnat(self):
        self.assertTrue(is_non_routable_ip("100.64.1.5"))
        self.assertTrue(is_non_routable_ip("100.127.255.254"))

    def test_multicast(self):
        self.assertTrue(is_non_routable_ip("224.0.0.1"))

    def test_unspecified(self):
        self.assertTrue(is_non_routable_ip("0.0.0.0"))

    def test_reserved(self):
        self.assertTrue(is_non_routable_ip("240.0.0.1"))

    def test_public_ip_is_routable(self):
        self.assertFalse(is_non_routable_ip("93.184.216.34"))
        self.assertFalse(is_non_routable_ip("8.8.8.8"))
        self.assertFalse(is_non_routable_ip("1.1.1.1"))

    def test_invalid_ip_treated_as_non_routable(self):
        self.assertTrue(is_non_routable_ip("not-an-ip"))
        self.assertTrue(is_non_routable_ip(""))

    def test_ipv6_loopback(self):
        self.assertTrue(is_non_routable_ip("::1"))

    def test_ipv6_public(self):
        self.assertFalse(is_non_routable_ip("2607:f8b0:4004:800::200e"))


class TestCollectCdnIps(unittest.TestCase):

    def test_collects_from_port_scan(self):
        combined = {
            "port_scan": {
                "by_ip": {
                    "1.2.3.4": {"is_cdn": True},
                    "5.6.7.8": {"is_cdn": False},
                    "9.10.11.12": {},
                }
            }
        }
        cdn = collect_cdn_ips(combined)
        self.assertEqual(cdn, {"1.2.3.4"})

    def test_collects_from_http_probe(self):
        combined = {
            "http_probe": {
                "by_url": {
                    "https://cdn.example.com": {"is_cdn": True, "ip": "1.2.3.4"},
                    "https://api.example.com": {"is_cdn": False, "ip": "5.6.7.8"},
                }
            }
        }
        cdn = collect_cdn_ips(combined)
        self.assertEqual(cdn, {"1.2.3.4"})

    def test_merges_both_sources(self):
        combined = {
            "port_scan": {"by_ip": {"1.1.1.1": {"is_cdn": True}}},
            "http_probe": {"by_url": {"https://x.com": {"is_cdn": True, "ip": "2.2.2.2"}}},
        }
        cdn = collect_cdn_ips(combined)
        self.assertEqual(cdn, {"1.1.1.1", "2.2.2.2"})

    def test_empty_combined_result(self):
        self.assertEqual(collect_cdn_ips({}), set())

    def test_skips_http_probe_entry_without_ip(self):
        combined = {
            "http_probe": {
                "by_url": {"https://x.com": {"is_cdn": True}},
            }
        }
        cdn = collect_cdn_ips(combined)
        self.assertEqual(cdn, set())


class TestFilterIpsForEnrichment(unittest.TestCase):

    def test_filters_private_and_cdn(self):
        combined = {
            "port_scan": {"by_ip": {"5.6.7.8": {"is_cdn": True}}},
        }
        ips = ["10.0.0.1", "5.6.7.8", "93.184.216.34"]
        result = filter_ips_for_enrichment(ips, combined, "Test")
        self.assertEqual(result, ["93.184.216.34"])

    def test_all_public_no_cdn(self):
        result = filter_ips_for_enrichment(
            ["8.8.8.8", "1.1.1.1"], {}, "Test"
        )
        self.assertEqual(result, ["8.8.8.8", "1.1.1.1"])

    def test_empty_list(self):
        result = filter_ips_for_enrichment([], {}, "Test")
        self.assertEqual(result, [])

    def test_all_filtered(self):
        result = filter_ips_for_enrichment(
            ["10.0.0.1", "192.168.1.1"], {}, "Test"
        )
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()

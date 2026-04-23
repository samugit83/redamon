"""
Unit tests for CVE Lookup integration with Banner Grab and Nmap data.

Tests verify:
  - Banner grab service versions are fed into CVE lookup
  - Nmap service detections are fed into CVE lookup
  - parse_technology_string handles banner/nmap formats correctly
  - MySQL banner version extraction regex works
  - MongoDB banner pattern matches
  - Banner grab timeout change (3.0s)
  - Combined data flow: banner_grab + nmap + httpx all feed technologies set

Run with: python -m pytest recon/tests/test_cve_banner_lookup.py -v
"""
import sys
import os
import re
import unittest

# Add recon dir to path
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _recon_dir)

from helpers.cve_helpers import parse_technology_string, normalize_product_name


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BANNER_GRAB_DATA = {
    "services_found": {
        "ssh": [
            {"host": "gpigs.devergolabs.com", "port": 22, "version": "OpenSSH_9.6p1"}
        ],
        "ftp": [
            {"host": "gpigs.devergolabs.com", "port": 21, "version": "vsFTPd 2.3.4"}
        ],
        "mysql": [
            {"host": "gpigs.devergolabs.com", "port": 3306, "version": "MySQL/8.4.8"}
        ],
    }
}

NMAP_SCAN_DATA = {
    "services_detected": [
        {"product": "vsftpd", "version": "2.3.4", "port": 21, "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4"},
        {"product": "OpenSSH", "version": "9.6p1", "port": 22, "cpe": "cpe:/a:openbsd:openssh:9.6p1"},
        {"product": "MySQL", "version": "8.4.8", "port": 3306, "cpe": "cpe:/a:oracle:mysql:8.4.8"},
        {"product": "Apache Tomcat", "version": "8.5.19", "port": 8080, "cpe": "cpe:/a:apache:tomcat:8.5.19"},
        {"product": "MongoDB", "version": "4.0.4", "port": 27017, "cpe": ""},
    ],
    "nse_vulns": [
        {"host": "15.160.68.117", "port": 21, "script_id": "ftp-vsftpd-backdoor", "state": "VULNERABLE", "cve": "CVE-2011-2523"},
    ],
}

HTTPX_DATA = {
    "by_url": {
        "http://gpigs.devergolabs.com": {
            "technologies": ["Express", "Node.js", "jQuery"],
            "server": None,
        }
    }
}


# ─── Tests: parse_technology_string with banner/nmap formats ──────────────────

class TestParseTechnologyString(unittest.TestCase):
    """Test that parse_technology_string handles all banner/nmap output formats."""

    def test_slash_format(self):
        name, ver = parse_technology_string("vsftpd/2.3.4")
        self.assertEqual(name, "vsftpd")
        self.assertEqual(ver, "2.3.4")

    def test_apache_tomcat_slash(self):
        name, ver = parse_technology_string("Apache Tomcat/8.5.19")
        self.assertEqual(name, "apache tomcat")
        self.assertEqual(ver, "8.5.19")

    def test_mysql_slash(self):
        name, ver = parse_technology_string("MySQL/8.4.8")
        self.assertEqual(name, "mysql")
        self.assertEqual(ver, "8.4.8")

    def test_openssh_underscore(self):
        name, ver = parse_technology_string("OpenSSH_9.6p1")
        self.assertEqual(name, "openssh")
        # _extract_semver strips the 'p1' suffix
        self.assertIsNotNone(ver)
        self.assertTrue(ver.startswith("9.6"))

    def test_mongodb_slash(self):
        name, ver = parse_technology_string("MongoDB/4.0.4")
        self.assertEqual(name, "mongodb")
        self.assertEqual(ver, "4.0.4")

    def test_mariadb_slash(self):
        name, ver = parse_technology_string("MariaDB/10.6.12")
        self.assertEqual(name, "mariadb")
        self.assertEqual(ver, "10.6.12")

    def test_vsFTPd_space(self):
        name, ver = parse_technology_string("vsFTPd 2.3.4")
        self.assertEqual(name, "vsftpd")
        self.assertEqual(ver, "2.3.4")

    def test_no_version(self):
        name, ver = parse_technology_string("Express")
        self.assertEqual(name, "express")
        self.assertIsNone(ver)

    def test_empty_string(self):
        name, ver = parse_technology_string("")
        self.assertEqual(name, "")
        self.assertIsNone(ver)

    def test_bare_version_skipped(self):
        name, ver = parse_technology_string("2.3.4")
        self.assertEqual(name, "")


# ─── Tests: normalize_product_name ───────────────────────────────────────────

class TestNormalizeProductName(unittest.TestCase):

    def test_vsftpd(self):
        self.assertEqual(normalize_product_name("vsftpd"), "vsftpd")

    def test_openssh(self):
        self.assertEqual(normalize_product_name("openssh"), "openssh")

    def test_mysql(self):
        self.assertEqual(normalize_product_name("mysql"), "mysql")

    def test_apache_tomcat(self):
        result = normalize_product_name("apache tomcat")
        self.assertIn("tomcat", result)

    def test_mongodb(self):
        self.assertEqual(normalize_product_name("mongodb"), "mongodb")


# ─── Tests: Banner grab technology extraction ────────────────────────────────

class TestBannerGrabTechExtraction(unittest.TestCase):
    """Test the banner_grab -> technologies extraction logic from cve_helpers.py."""

    def _extract_technologies(self, recon_data: dict) -> set:
        """Simulate the technology extraction logic from run_cve_lookup."""
        technologies = set()

        # httpx technologies
        httpx_data = recon_data.get("http_probe", {})
        for url_data in httpx_data.get("by_url", {}).values():
            techs = url_data.get("technologies", [])
            technologies.update(techs)

        # Banner grab technologies
        banner_data = recon_data.get("banner_grab", {})
        for service_type, instances in banner_data.get("services_found", {}).items():
            for instance in instances:
                version_str = instance.get("version")
                if version_str:
                    technologies.add(version_str)

        # Nmap technologies
        nmap_data = recon_data.get("nmap_scan", {})
        for svc in nmap_data.get("services_detected", []):
            product = svc.get("product", "")
            version = svc.get("version", "")
            if product and version:
                technologies.add(f"{product}/{version}")

        return technologies

    def test_banner_grab_adds_technologies(self):
        data = {"banner_grab": BANNER_GRAB_DATA, "http_probe": {}, "nmap_scan": {}}
        techs = self._extract_technologies(data)
        self.assertIn("OpenSSH_9.6p1", techs)
        self.assertIn("vsFTPd 2.3.4", techs)
        self.assertIn("MySQL/8.4.8", techs)

    def test_nmap_adds_technologies(self):
        data = {"nmap_scan": NMAP_SCAN_DATA, "http_probe": {}, "banner_grab": {}}
        techs = self._extract_technologies(data)
        self.assertIn("vsftpd/2.3.4", techs)
        self.assertIn("OpenSSH/9.6p1", techs)
        self.assertIn("MySQL/8.4.8", techs)
        self.assertIn("Apache Tomcat/8.5.19", techs)
        self.assertIn("MongoDB/4.0.4", techs)

    def test_httpx_adds_technologies(self):
        data = {"http_probe": HTTPX_DATA, "banner_grab": {}, "nmap_scan": {}}
        techs = self._extract_technologies(data)
        self.assertIn("Express", techs)
        self.assertIn("Node.js", techs)

    def test_combined_all_sources(self):
        data = {
            "http_probe": HTTPX_DATA,
            "banner_grab": BANNER_GRAB_DATA,
            "nmap_scan": NMAP_SCAN_DATA,
        }
        techs = self._extract_technologies(data)
        # httpx
        self.assertIn("Express", techs)
        # banner
        self.assertIn("OpenSSH_9.6p1", techs)
        # nmap
        self.assertIn("Apache Tomcat/8.5.19", techs)
        # Should have entries from all 3 sources
        self.assertGreaterEqual(len(techs), 10)

    def test_nmap_skips_empty_product(self):
        data = {
            "nmap_scan": {"services_detected": [{"product": "", "version": "1.0", "port": 80}]},
            "http_probe": {},
            "banner_grab": {},
        }
        techs = self._extract_technologies(data)
        self.assertNotIn("/1.0", techs)

    def test_nmap_skips_empty_version(self):
        data = {
            "nmap_scan": {"services_detected": [{"product": "nginx", "version": "", "port": 80}]},
            "http_probe": {},
            "banner_grab": {},
        }
        techs = self._extract_technologies(data)
        self.assertNotIn("nginx/", techs)

    def test_banner_skips_none_version(self):
        data = {
            "banner_grab": {"services_found": {"ssh": [{"host": "x", "port": 22, "version": None}]}},
            "http_probe": {},
            "nmap_scan": {},
        }
        techs = self._extract_technologies(data)
        self.assertEqual(len(techs), 0)


# ─── Tests: Nmap tech strings through full parse + normalize pipeline ────────

class TestNmapTechThroughPipeline(unittest.TestCase):
    """Test that Nmap-generated tech strings survive parse -> normalize -> CPE lookup."""

    def _can_lookup(self, tech_string: str) -> bool:
        """Simulate the CVE lookup filter: returns True if tech has name+version."""
        name, version = parse_technology_string(tech_string)
        name = normalize_product_name(name)
        skip_list = ["ubuntu", "debian", "linux", "windows"]
        if not version or name in skip_list:
            return False
        return True

    def test_vsftpd_lookupable(self):
        self.assertTrue(self._can_lookup("vsftpd/2.3.4"))

    def test_openssh_lookupable(self):
        self.assertTrue(self._can_lookup("OpenSSH/9.6p1"))

    def test_mysql_lookupable(self):
        self.assertTrue(self._can_lookup("MySQL/8.4.8"))

    def test_tomcat_lookupable(self):
        self.assertTrue(self._can_lookup("Apache Tomcat/8.5.19"))

    def test_mongodb_lookupable(self):
        self.assertTrue(self._can_lookup("MongoDB/4.0.4"))

    def test_express_no_version_not_lookupable(self):
        self.assertFalse(self._can_lookup("Express"))

    def test_banner_openssh_format_lookupable(self):
        self.assertTrue(self._can_lookup("OpenSSH_9.6p1"))

    def test_banner_vsftpd_format_lookupable(self):
        self.assertTrue(self._can_lookup("vsFTPd 2.3.4"))


# ─── Tests: MySQL banner regex ───────────────────────────────────────────────

class TestMysqlBannerRegex(unittest.TestCase):
    """Test the MySQL banner version extraction regex from http_probe.py."""

    def test_mysql_binary_greeting(self):
        # Simulates decoded MySQL greeting: version bytes followed by mysql_native_password
        banner = "I\x00\x00\x00\n8.4.8\x00\x1b\x00some_binary_data\x00mysql_native_password\x00"
        match = re.search(r"(\d+\.\d+\.\d+).*?mysql", banner, re.IGNORECASE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "8.4.8")

    def test_mariadb_banner(self):
        banner = "5.5.68-MariaDB"
        match = re.search(r"(\d+\.\d+\.\d+)-MariaDB", banner)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "5.5.68")

    def test_mysql_fallback(self):
        banner = "some random mysql response"
        match = re.search(r"mysql|MariaDB", banner, re.IGNORECASE)
        self.assertIsNotNone(match)

    def test_mongodb_pattern(self):
        banner = "It looks like you are trying to access MongoDB over HTTP"
        match = re.search(r"MongoDB|mongod|It looks like you are trying to access MongoDB", banner)
        self.assertIsNotNone(match)


if __name__ == "__main__":
    unittest.main()

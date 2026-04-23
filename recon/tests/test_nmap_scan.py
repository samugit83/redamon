"""
Unit tests for Nmap Scanner Module (recon/main_recon_modules/nmap_scan.py).

Tests verify:
  - Target extraction from port_scan data (build_nmap_targets)
  - Nmap command building (build_nmap_command)
  - XML output parsing (parse_nmap_xml) with realistic Nmap output
  - NSE vulnerability and CVE extraction
  - Service detection normalization
  - Host timeout seconds suffix handling
  - Edge cases: empty data, no open ports, filtered ports, missing service elements

Run with: python -m pytest recon/tests/test_nmap_scan.py -v
"""
import sys
import os
import unittest
import tempfile
from pathlib import Path

# Add recon dir to path
_recon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main_recon_modules")
sys.path.insert(0, _recon_dir)

from nmap_scan import (
    build_nmap_targets,
    build_nmap_command,
    parse_nmap_xml,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

REALISTIC_PORT_SCAN = {
    "port_scan": {
        "by_host": {
            "gpigs.devergolabs.com": {
                "host": "gpigs.devergolabs.com",
                "ip": "15.160.68.117",
                "ports": [21, 22, 80, 3306, 4000, 8080, 8888, 9090, 27017],
                "port_details": [
                    {"port": 21, "protocol": "tcp", "service": "ftp"},
                    {"port": 22, "protocol": "tcp", "service": "ssh"},
                    {"port": 80, "protocol": "tcp", "service": "http"},
                    {"port": 3306, "protocol": "tcp", "service": "mysql"},
                    {"port": 4000, "protocol": "tcp", "service": "terabase"},
                    {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
                    {"port": 8888, "protocol": "tcp", "service": "http-alt"},
                    {"port": 9090, "protocol": "tcp", "service": "prometheus"},
                    {"port": 27017, "protocol": "tcp", "service": "mongodb"},
                ],
            }
        },
        "by_ip": {
            "15.160.68.117": {
                "ip": "15.160.68.117",
                "hostnames": ["gpigs.devergolabs.com"],
                "ports": [21, 22, 80, 3306, 4000, 8080, 8888, 9090, 27017],
            }
        },
        "ip_to_hostnames": {
            "15.160.68.117": ["gpigs.devergolabs.com"]
        },
        "all_ports": [21, 22, 80, 3306, 4000, 8080, 8888, 9090, 27017],
    }
}

NMAP_XML_FULL = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script vuln -p 21,22,80,3306,8080 -T3 15.160.68.117" start="1711720000" version="7.94SVN">
  <host starttime="1711720001" endtime="1711720060">
    <status state="up" reason="syn-ack"/>
    <address addr="15.160.68.117" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10">
          <cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe>
        </service>
        <script id="ftp-vsftpd-backdoor" output="VULNERABLE: vsFTPd version 2.3.4 backdoor command execution. State: VULNERABLE (Exploitable). IDs: CVE:CVE-2011-2523"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.5" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Node.js Express framework" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.4.8" method="probed" conf="10">
          <cpe>cpe:/a:oracle:mysql:8.4.8</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache Tomcat" version="8.5.19" method="probed" conf="10">
          <cpe>cpe:/a:apache:tomcat:8.5.19</cpe>
        </service>
        <script id="http-vuln-cve2017-12617" output="VULNERABLE: Apache Tomcat Remote Code Execution via JSP Upload. State: VULNERABLE. IDs: CVE:CVE-2017-12617"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered" reason="no-response"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_EMPTY = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94SVN">
</nmaprun>"""

NMAP_XML_NO_SERVICE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94SVN">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_NOT_VULNERABLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94SVN">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6p1"/>
        <script id="vulners" output="NOT VULNERABLE: OpenSSH 9.6p1 has no known critical vulnerabilities"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


# ─── Tests: build_nmap_targets ────────────────────────────────────────────────

class TestBuildNmapTargets(unittest.TestCase):

    def test_extracts_ips_and_ports(self):
        ips, ports, ip_map = build_nmap_targets(REALISTIC_PORT_SCAN, {})
        self.assertEqual(ips, ["15.160.68.117"])
        self.assertIn("21", ports)
        self.assertIn("80", ports)
        self.assertIn("27017", ports)
        self.assertEqual(ip_map["15.160.68.117"], ["gpigs.devergolabs.com"])

    def test_empty_port_scan(self):
        ips, ports, ip_map = build_nmap_targets({}, {})
        self.assertEqual(ips, [])
        self.assertEqual(ports, "")
        self.assertEqual(ip_map, {})

    def test_no_ports(self):
        data = {"port_scan": {"by_ip": {"1.2.3.4": {"ip": "1.2.3.4", "ports": []}}, "by_host": {}}}
        ips, ports, ip_map = build_nmap_targets(data, {})
        self.assertEqual(ips, ["1.2.3.4"])
        self.assertEqual(ports, "")

    def test_deduplicates_ports(self):
        data = {
            "port_scan": {
                "by_ip": {"1.2.3.4": {"ip": "1.2.3.4", "ports": [80, 443]}},
                "by_host": {"host.com": {"ip": "1.2.3.4", "ports": [80, 8080]}},
            }
        }
        ips, ports, ip_map = build_nmap_targets(data, {})
        port_list = ports.split(",")
        self.assertEqual(sorted(port_list), ["443", "80", "8080"])

    def test_multiple_ips(self):
        data = {
            "port_scan": {
                "by_ip": {
                    "1.1.1.1": {"ip": "1.1.1.1", "ports": [80]},
                    "2.2.2.2": {"ip": "2.2.2.2", "ports": [443]},
                },
                "by_host": {},
            }
        }
        ips, ports, ip_map = build_nmap_targets(data, {})
        self.assertEqual(sorted(ips), ["1.1.1.1", "2.2.2.2"])


# ─── Tests: build_nmap_command ────────────────────────────────────────────────

class TestBuildNmapCommand(unittest.TestCase):

    def test_default_command(self):
        cmd = build_nmap_command("1.2.3.4", "21,22,80", "/tmp/out.xml", {})
        self.assertEqual(cmd[0], "nmap")
        self.assertIn("-sV", cmd)
        self.assertIn("--script", cmd)
        self.assertIn("vuln", cmd)
        self.assertIn("-oX", cmd)
        self.assertIn("/tmp/out.xml", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("21,22,80", cmd)
        self.assertIn("1.2.3.4", cmd)

    def test_version_detection_disabled(self):
        cmd = build_nmap_command("1.2.3.4", "80", "/tmp/out.xml", {"NMAP_VERSION_DETECTION": False})
        self.assertNotIn("-sV", cmd)

    def test_script_scan_disabled(self):
        cmd = build_nmap_command("1.2.3.4", "80", "/tmp/out.xml", {"NMAP_SCRIPT_SCAN": False})
        self.assertNotIn("--script", cmd)
        self.assertNotIn("vuln", cmd)

    def test_timing_template(self):
        cmd = build_nmap_command("1.2.3.4", "80", "/tmp/out.xml", {"NMAP_TIMING_TEMPLATE": "T2"})
        self.assertIn("-T2", cmd)

    def test_timing_template_plain_number(self):
        cmd = build_nmap_command("1.2.3.4", "80", "/tmp/out.xml", {"NMAP_TIMING_TEMPLATE": "3"})
        self.assertIn("-T3", cmd)

    def test_host_timeout_integer_gets_suffix(self):
        cmd = build_nmap_command("1.2.3.4", "80", "/tmp/out.xml", {"NMAP_HOST_TIMEOUT": 300})
        self.assertIn("--host-timeout", cmd)
        idx = cmd.index("--host-timeout")
        self.assertEqual(cmd[idx + 1], "300s")

    def test_host_timeout_string_preserved(self):
        cmd = build_nmap_command("1.2.3.4", "80", "/tmp/out.xml", {"NMAP_HOST_TIMEOUT": "5m"})
        idx = cmd.index("--host-timeout")
        self.assertEqual(cmd[idx + 1], "5m")


# ─── Tests: parse_nmap_xml ───────────────────────────────────────────────────

class TestParseNmapXml(unittest.TestCase):

    def _write_xml(self, content: str) -> str:
        """Write XML content to a temp file and return path."""
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        return path

    def test_parse_full_output(self):
        path = self._write_xml(NMAP_XML_FULL)
        try:
            result = parse_nmap_xml(path, {"15.160.68.117": ["gpigs.devergolabs.com"]})

            # Should use hostname as key
            self.assertIn("gpigs.devergolabs.com", result["by_host"])
            host = result["by_host"]["gpigs.devergolabs.com"]
            self.assertEqual(host["ip"], "15.160.68.117")

            # Should have 5 open ports (filtered port 443 excluded)
            self.assertEqual(len(host["ports"]), 5)
            self.assertIn(21, host["ports"])
            self.assertIn(8080, host["ports"])
            self.assertNotIn(443, host["ports"])  # filtered, should be excluded

            # Service detection
            services = result["services_detected"]
            products = {s["product"] for s in services}
            self.assertIn("vsftpd", products)
            self.assertIn("OpenSSH", products)
            self.assertIn("MySQL", products)
            self.assertIn("Apache Tomcat", products)

            # Version extraction
            vsftpd = next(s for s in services if s["product"] == "vsftpd")
            self.assertEqual(vsftpd["version"], "2.3.4")
            self.assertEqual(vsftpd["port"], 21)
            self.assertEqual(vsftpd["cpe"], "cpe:/a:vsftpd:vsftpd:2.3.4")

            tomcat = next(s for s in services if s["product"] == "Apache Tomcat")
            self.assertEqual(tomcat["version"], "8.5.19")

            mysql = next(s for s in services if s["product"] == "MySQL")
            self.assertEqual(mysql["version"], "8.4.8")

            # NSE vulnerabilities
            vulns = result["nse_vulns"]
            self.assertEqual(len(vulns), 2)

            vsftpd_vuln = next(v for v in vulns if v["script_id"] == "ftp-vsftpd-backdoor")
            self.assertEqual(vsftpd_vuln["state"], "VULNERABLE")
            self.assertEqual(vsftpd_vuln["cve"], "CVE-2011-2523")
            self.assertEqual(vsftpd_vuln["port"], 21)

            tomcat_vuln = next(v for v in vulns if v["script_id"] == "http-vuln-cve2017-12617")
            self.assertEqual(tomcat_vuln["cve"], "CVE-2017-12617")
            self.assertEqual(tomcat_vuln["port"], 8080)

            # Nmap version
            self.assertEqual(result["nmap_version"], "7.94SVN")
        finally:
            os.unlink(path)

    def test_parse_empty_output(self):
        path = self._write_xml(NMAP_XML_EMPTY)
        try:
            result = parse_nmap_xml(path, {})
            self.assertEqual(result["by_host"], {})
            self.assertEqual(result["services_detected"], [])
            self.assertEqual(result["nse_vulns"], [])
        finally:
            os.unlink(path)

    def test_parse_no_service_element(self):
        path = self._write_xml(NMAP_XML_NO_SERVICE)
        try:
            result = parse_nmap_xml(path, {})
            host = result["by_host"]["10.0.0.1"]
            self.assertEqual(host["ports"], [9999])
            # Port open but no service detected
            pd = host["port_details"][0]
            self.assertEqual(pd["port"], 9999)
            self.assertEqual(pd["product"], "")
            self.assertEqual(pd["version"], "")
            # No services detected (no product)
            self.assertEqual(result["services_detected"], [])
        finally:
            os.unlink(path)

    def test_not_vulnerable_scripts_excluded(self):
        path = self._write_xml(NMAP_XML_NOT_VULNERABLE)
        try:
            result = parse_nmap_xml(path, {})
            # "NOT VULNERABLE" should be skipped
            self.assertEqual(result["nse_vulns"], [])
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        result = parse_nmap_xml("/tmp/nonexistent_nmap.xml", {})
        self.assertEqual(result["by_host"], {})

    def test_ip_fallback_when_no_hostname(self):
        path = self._write_xml(NMAP_XML_NO_SERVICE)
        try:
            result = parse_nmap_xml(path, {})  # empty ip_to_hostnames
            # Should use IP as key
            self.assertIn("10.0.0.1", result["by_host"])
        finally:
            os.unlink(path)

    def test_port_details_sorted(self):
        path = self._write_xml(NMAP_XML_FULL)
        try:
            result = parse_nmap_xml(path, {"15.160.68.117": ["host"]})
            host = result["by_host"]["host"]
            ports = [pd["port"] for pd in host["port_details"]]
            self.assertEqual(ports, sorted(ports))
        finally:
            os.unlink(path)


# ─── Tests: Edge cases ───────────────────────────────────────────────────────

class TestNmapEdgeCases(unittest.TestCase):

    def test_multiple_cves_in_script_output(self):
        xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94SVN">
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.49"/>
        <script id="http-vuln-multi" output="VULNERABLE: Multiple CVEs found. CVE-2021-41773 CVE-2021-42013"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, 'w') as f:
            f.write(xml)
        try:
            result = parse_nmap_xml(path, {})
            vuln = result["nse_vulns"][0]
            # Should extract first CVE
            self.assertEqual(vuln["cve"], "CVE-2021-41773")
        finally:
            os.unlink(path)

    def test_script_output_in_port_details(self):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, 'w') as f:
            f.write(NMAP_XML_FULL)
        try:
            result = parse_nmap_xml(path, {"15.160.68.117": ["host"]})
            host = result["by_host"]["host"]
            ftp_pd = next(pd for pd in host["port_details"] if pd["port"] == 21)
            self.assertIn("ftp-vsftpd-backdoor", ftp_pd["scripts"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

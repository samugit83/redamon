"""
RedAmon - Masscan Integration Tests
====================================
Tests for the masscan port scanner module and its pipeline integration:

1. _is_mock_hostname — mock hostname detection
2. resolve_targets_to_ips — DNS data → IP target extraction
3. build_masscan_command — command construction from settings
4. parse_masscan_output — NDJSON parsing into normalized structure
5. merge_port_scan_results — Naabu+Masscan result merging
6. run_masscan_scan — full scan lifecycle (mocked subprocess)
7. run_masscan_scan_isolated — thread-safe wrapper
"""

import json
import os
import sys
import copy
import types
import tempfile
import unittest
import importlib.util
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

# Stub helpers.iana_services to avoid pulling in dns.resolver via helpers/__init__.py
_iana_stub = types.ModuleType("helpers.iana_services")
_iana_stub.get_service_name_friendly = lambda port, protocol="tcp": {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 3306: "MySQL",
}.get(port, f"port-{port}")
sys.modules.setdefault("helpers", types.ModuleType("helpers"))
sys.modules["helpers.iana_services"] = _iana_stub

# Now load masscan_scan via importlib to avoid triggering helpers/__init__.py
_spec = importlib.util.spec_from_file_location(
    "recon.main_recon_modules.masscan_scan",
    str(PROJECT_ROOT / "recon" / "masscan_scan.py"),
)
masscan_mod = importlib.util.module_from_spec(_spec)
sys.modules["recon.main_recon_modules.masscan_scan"] = masscan_mod
_spec.loader.exec_module(masscan_mod)

_is_mock_hostname = masscan_mod._is_mock_hostname
resolve_targets_to_ips = masscan_mod.resolve_targets_to_ips
build_masscan_command = masscan_mod.build_masscan_command
parse_masscan_output = masscan_mod.parse_masscan_output
run_masscan_scan = masscan_mod.run_masscan_scan
run_masscan_scan_isolated = masscan_mod.run_masscan_scan_isolated
_empty_result = masscan_mod._empty_result


# ---------------------------------------------------------------------------
# Helper: Build a minimal recon_data dict for domain-mode tests
# ---------------------------------------------------------------------------
def _domain_recon_data(
    domain="example.com",
    domain_ips=None,
    subdomains=None,
):
    if domain_ips is None:
        domain_ips = ["93.184.216.34"]
    dns = {
        "domain": {
            "ips": {
                "ipv4": domain_ips,
                "ipv6": [],
            }
        },
        "subdomains": subdomains or {},
    }
    return {"domain": domain, "dns": dns}


def _ndjson_line(ip, port, proto="tcp", status="open", rec_type="status"):
    """Build one masscan NDJSON status line."""
    return json.dumps({
        "ip": ip,
        "timestamp": "1700000000",
        "port": port,
        "proto": proto,
        "rec_type": rec_type,
        "data": {"status": status, "reason": "syn-ack", "ttl": 64},
    })


def _ndjson_banner(ip, port, banner_text="SSH-2.0-OpenSSH"):
    """Build one masscan NDJSON banner line."""
    return json.dumps({
        "ip": ip,
        "timestamp": "1700000000",
        "port": port,
        "proto": "tcp",
        "rec_type": "banner",
        "data": {"banner": banner_text},
    })


# ========================================================================
# 1. _is_mock_hostname
# ========================================================================
class TestIsMockHostname(unittest.TestCase):

    def test_ipv4_mock(self):
        self.assertTrue(_is_mock_hostname("10-0-0-1", "10.0.0.1"))

    def test_ipv4_real_ptr(self):
        self.assertFalse(_is_mock_hostname("host1.example.com", "10.0.0.1"))

    def test_ipv6_mock(self):
        self.assertTrue(_is_mock_hostname("2001-db8--1", "2001:db8::1"))

    def test_ipv6_real(self):
        self.assertFalse(_is_mock_hostname("ns1.example.com", "2001:db8::1"))

    def test_ip_itself_is_not_mock(self):
        self.assertFalse(_is_mock_hostname("10.0.0.1", "10.0.0.1"))

    def test_empty_hostname(self):
        self.assertFalse(_is_mock_hostname("", "10.0.0.1"))


# ========================================================================
# 2. resolve_targets_to_ips
# ========================================================================
class TestResolveTargetsToIps(unittest.TestCase):

    def test_root_domain_only(self):
        data = _domain_recon_data(domain="example.com", domain_ips=["1.2.3.4"])
        ips, mapping = resolve_targets_to_ips(data)
        self.assertIn("1.2.3.4", ips)
        self.assertEqual(mapping["1.2.3.4"], ["example.com"])

    def test_subdomains_with_records(self):
        data = _domain_recon_data(
            domain="example.com",
            domain_ips=["1.2.3.4"],
            subdomains={
                "api.example.com": {
                    "has_records": True,
                    "ips": {"ipv4": ["5.6.7.8"], "ipv6": []},
                },
                "dead.example.com": {
                    "has_records": False,
                    "ips": {"ipv4": ["9.9.9.9"], "ipv6": []},
                },
            },
        )
        ips, mapping = resolve_targets_to_ips(data)
        self.assertIn("5.6.7.8", ips)
        self.assertNotIn("9.9.9.9", ips)
        self.assertEqual(mapping["5.6.7.8"], ["api.example.com"])

    def test_shared_ip_between_domain_and_subdomain(self):
        data = _domain_recon_data(
            domain="example.com",
            domain_ips=["1.2.3.4"],
            subdomains={
                "www.example.com": {
                    "has_records": True,
                    "ips": {"ipv4": ["1.2.3.4"], "ipv6": []},
                }
            },
        )
        ips, mapping = resolve_targets_to_ips(data)
        self.assertEqual(len(ips), 1)
        self.assertIn("example.com", mapping["1.2.3.4"])
        self.assertIn("www.example.com", mapping["1.2.3.4"])

    def test_empty_dns_data(self):
        ips, mapping = resolve_targets_to_ips({"domain": "", "dns": {}})
        self.assertEqual(ips, [])
        self.assertEqual(mapping, {})

    def test_no_domain_key(self):
        ips, mapping = resolve_targets_to_ips({})
        self.assertEqual(ips, [])
        self.assertEqual(mapping, {})


# ========================================================================
# 3. build_masscan_command
# ========================================================================
class TestBuildMasscanCommand(unittest.TestCase):

    def test_default_top_ports(self):
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {})
        self.assertEqual(cmd[0], "masscan")
        self.assertIn("-iL", cmd)
        self.assertIn("--top-ports", cmd)
        idx = cmd.index("--top-ports")
        self.assertEqual(cmd[idx + 1], "1000")

    def test_custom_ports_overrides_top_ports(self):
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {
            "MASSCAN_CUSTOM_PORTS": "80,443,8080",
            "MASSCAN_TOP_PORTS": "100",
        })
        self.assertIn("-p", cmd)
        self.assertNotIn("--top-ports", cmd)
        idx = cmd.index("-p")
        self.assertEqual(cmd[idx + 1], "80,443,8080")

    def test_full_port_range(self):
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {
            "MASSCAN_TOP_PORTS": "full",
        })
        self.assertIn("-p", cmd)
        idx = cmd.index("-p")
        self.assertEqual(cmd[idx + 1], "0-65535")

    def test_full_port_range_integer_input(self):
        """Ensure integer MASSCAN_TOP_PORTS doesn't crash (str() wrapping)."""
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {
            "MASSCAN_TOP_PORTS": 100,
        })
        self.assertIn("--top-ports", cmd)
        idx = cmd.index("--top-ports")
        self.assertEqual(cmd[idx + 1], "100")

    def test_rate_wait_retries(self):
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {
            "MASSCAN_RATE": 5000,
            "MASSCAN_WAIT": 15,
            "MASSCAN_RETRIES": 3,
        })
        self.assertIn("--rate", cmd)
        self.assertEqual(cmd[cmd.index("--rate") + 1], "5000")
        self.assertEqual(cmd[cmd.index("--wait") + 1], "15")
        self.assertEqual(cmd[cmd.index("--retries") + 1], "3")

    def test_banners_flag(self):
        cmd_off = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {"MASSCAN_BANNERS": False})
        cmd_on = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {"MASSCAN_BANNERS": True})
        self.assertNotIn("--banners", cmd_off)
        self.assertIn("--banners", cmd_on)

    def test_output_format_is_ndjson(self):
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {})
        self.assertIn("-oD", cmd)
        self.assertNotIn("-oJ", cmd)

    def test_exclude_targets_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "out.ndjson")
            cmd = build_masscan_command("/tmp/t.txt", out_file, {
                "MASSCAN_EXCLUDE_TARGETS": "10.0.0.1, 192.168.0.0/24",
            })
            self.assertIn("--excludefile", cmd)
            exclude_path = cmd[cmd.index("--excludefile") + 1]
            self.assertTrue(os.path.exists(exclude_path))
            with open(exclude_path) as f:
                lines = [l.strip() for l in f.readlines()]
            self.assertIn("10.0.0.1", lines)
            self.assertIn("192.168.0.0/24", lines)

    def test_empty_exclude_targets_no_flag(self):
        cmd = build_masscan_command("/tmp/t.txt", "/tmp/o.ndjson", {
            "MASSCAN_EXCLUDE_TARGETS": "  ",
        })
        self.assertNotIn("--excludefile", cmd)


# ========================================================================
# 4. parse_masscan_output — NDJSON format
# ========================================================================
class TestParseMasscanOutput(unittest.TestCase):

    def _write_ndjson(self, lines):
        """Write NDJSON lines to a temp file and return its path."""
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.ndjson', delete=False)
        for line in lines:
            f.write(line + "\n")
        f.close()
        self._tmpfiles.append(f.name)
        return f.name

    def setUp(self):
        self._tmpfiles = []

    def tearDown(self):
        for f in self._tmpfiles:
            try:
                os.unlink(f)
            except OSError:
                pass

    def test_single_open_port(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 80),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["host.example.com"]})

        self.assertEqual(result["all_ports"], [80])
        self.assertIn("host.example.com", result["by_host"])
        host = result["by_host"]["host.example.com"]
        self.assertEqual(host["ports"], [80])
        self.assertEqual(host["ip"], "10.0.0.1")
        self.assertEqual(len(host["port_details"]), 1)
        self.assertEqual(host["port_details"][0]["port"], 80)
        self.assertEqual(host["port_details"][0]["protocol"], "tcp")

        self.assertIn("10.0.0.1", result["by_ip"])
        self.assertEqual(result["by_ip"]["10.0.0.1"]["ports"], [80])

    def test_multiple_ports_same_ip(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 443),
            _ndjson_line("10.0.0.1", 80),
            _ndjson_line("10.0.0.1", 22),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["host1.example.com"]})
        self.assertEqual(result["all_ports"], [22, 80, 443])
        self.assertEqual(result["by_host"]["host1.example.com"]["ports"], [22, 80, 443])
        self.assertEqual(result["by_ip"]["10.0.0.1"]["ports"], [22, 80, 443])

    def test_multiple_ips(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 80),
            _ndjson_line("10.0.0.2", 443),
        ])
        result = parse_masscan_output(path, {
            "10.0.0.1": ["host1.example.com"],
            "10.0.0.2": ["host2.example.com"],
        })
        self.assertEqual(len(result["by_ip"]), 2)
        self.assertEqual(len(result["by_host"]), 2)
        self.assertEqual(result["summary"]["ips_scanned"], 2)

    def test_ip_with_no_hostname_mapping(self):
        """IPs without hostname mapping should use IP as host key."""
        path = self._write_ndjson([
            _ndjson_line("10.0.0.5", 22),
        ])
        result = parse_masscan_output(path, {})
        self.assertIn("10.0.0.5", result["by_host"])
        host = result["by_host"]["10.0.0.5"]
        self.assertEqual(host["host"], "10.0.0.5")
        self.assertEqual(host["ip"], "10.0.0.5")
        self.assertEqual(host["ports"], [22])

    def test_banner_records_skipped(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 22),
            _ndjson_banner("10.0.0.1", 22, "SSH-2.0-OpenSSH_8.9"),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        self.assertEqual(result["by_host"]["h1"]["ports"], [22])
        self.assertEqual(len(result["by_host"]["h1"]["port_details"]), 1)

    def test_closed_port_skipped(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 80, status="open"),
            _ndjson_line("10.0.0.1", 81, status="closed"),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        self.assertEqual(result["all_ports"], [80])

    def test_duplicate_port_deduplicated(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 80),
            _ndjson_line("10.0.0.1", 80),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        self.assertEqual(result["by_host"]["h1"]["ports"], [80])
        self.assertEqual(len(result["by_host"]["h1"]["port_details"]), 1)

    def test_port_zero_accepted(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 0),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        self.assertIn(0, result["all_ports"])

    def test_malformed_json_skipped(self):
        path = self._write_ndjson([
            "not json at all",
            _ndjson_line("10.0.0.1", 80),
            "{broken",
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        self.assertEqual(result["all_ports"], [80])

    def test_comment_lines_skipped(self):
        path = self._write_ndjson([
            "# this is a comment",
            _ndjson_line("10.0.0.1", 80),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        self.assertEqual(result["all_ports"], [80])

    def test_empty_file(self):
        path = self._write_ndjson([])
        result = parse_masscan_output(path, {})
        self.assertEqual(result, _empty_result())

    def test_nonexistent_file(self):
        result = parse_masscan_output("/nonexistent/path/file.ndjson", {})
        self.assertEqual(result, _empty_result())

    def test_summary_counts(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 80),
            _ndjson_line("10.0.0.1", 443),
            _ndjson_line("10.0.0.2", 22),
        ])
        result = parse_masscan_output(path, {
            "10.0.0.1": ["h1"],
            "10.0.0.2": ["h2"],
        })
        s = result["summary"]
        self.assertEqual(s["hosts_scanned"], 2)
        self.assertEqual(s["ips_scanned"], 2)
        self.assertEqual(s["hosts_with_open_ports"], 2)
        self.assertEqual(s["total_open_ports"], 3)
        self.assertEqual(s["unique_port_count"], 3)

    def test_shared_ip_multiple_hostnames(self):
        """An IP mapped to multiple hostnames should appear in by_host for each."""
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 80),
        ])
        result = parse_masscan_output(path, {
            "10.0.0.1": ["host1.example.com", "host2.example.com"],
        })
        self.assertIn("host1.example.com", result["by_host"])
        self.assertIn("host2.example.com", result["by_host"])
        self.assertEqual(result["by_host"]["host1.example.com"]["ports"], [80])
        self.assertEqual(result["by_host"]["host2.example.com"]["ports"], [80])
        self.assertEqual(result["summary"]["total_open_ports"], 2)

    def test_port_details_sorted(self):
        path = self._write_ndjson([
            _ndjson_line("10.0.0.1", 8080),
            _ndjson_line("10.0.0.1", 22),
            _ndjson_line("10.0.0.1", 443),
        ])
        result = parse_masscan_output(path, {"10.0.0.1": ["h1"]})
        ports = [pd["port"] for pd in result["by_host"]["h1"]["port_details"]]
        self.assertEqual(ports, [22, 443, 8080])


# ========================================================================
# 5. merge_port_scan_results
# ========================================================================

# Re-implement merge for test isolation (avoids loading main.py which has heavy side effects)
def _merge_port_scan_results(combined_result: dict) -> None:
    """Copy of merge_port_scan_results for test isolation."""
    masscan_data = combined_result.get("masscan_scan")
    if not masscan_data:
        return
    port_scan = combined_result.get("port_scan")
    if not port_scan:
        combined_result["port_scan"] = {
            "scan_metadata": masscan_data.get("scan_metadata", {}),
            "by_host": dict(masscan_data.get("by_host", {})),
            "by_ip": dict(masscan_data.get("by_ip", {})),
            "all_ports": list(masscan_data.get("all_ports", [])),
            "ip_to_hostnames": dict(masscan_data.get("ip_to_hostnames", {})),
            "summary": dict(masscan_data.get("summary", {})),
        }
        return
    for host, mdata in masscan_data.get("by_host", {}).items():
        if host not in port_scan["by_host"]:
            port_scan["by_host"][host] = mdata
        else:
            existing = port_scan["by_host"][host]
            for port in mdata.get("ports", []):
                if port not in existing["ports"]:
                    existing["ports"].append(port)
            for pd in mdata.get("port_details", []):
                if pd["port"] not in [x["port"] for x in existing.get("port_details", [])]:
                    existing.setdefault("port_details", []).append(pd)
            existing["ports"].sort()
            if "port_details" in existing:
                existing["port_details"].sort(key=lambda x: x["port"])
    for ip, mdata in masscan_data.get("by_ip", {}).items():
        if ip not in port_scan["by_ip"]:
            port_scan["by_ip"][ip] = mdata
        else:
            existing = port_scan["by_ip"][ip]
            for port in mdata.get("ports", []):
                if port not in existing["ports"]:
                    existing["ports"].append(port)
            for hn in mdata.get("hostnames", []):
                if hn not in existing.get("hostnames", []):
                    existing.setdefault("hostnames", []).append(hn)
            existing["ports"].sort()
    merged_ports = sorted(set(port_scan.get("all_ports", []) + masscan_data.get("all_ports", [])))
    port_scan["all_ports"] = merged_ports
    for ip, hosts in masscan_data.get("ip_to_hostnames", {}).items():
        existing_hosts = port_scan.setdefault("ip_to_hostnames", {}).setdefault(ip, [])
        for h in (hosts if isinstance(hosts, list) else [hosts]):
            if h not in existing_hosts:
                existing_hosts.append(h)
    existing_meta = port_scan.get("scan_metadata", {})
    scanners = existing_meta.get("scanners", ["naabu"])
    if "masscan" not in scanners:
        scanners.append("masscan")
    existing_meta["scanners"] = scanners
    by_host = port_scan["by_host"]
    by_ip = port_scan["by_ip"]
    port_scan["summary"] = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h.get("ports")]),
        "total_open_ports": sum(len(h.get("ports", [])) for h in by_host.values()),
        "unique_ports": merged_ports,
        "unique_port_count": len(merged_ports),
        "cdn_hosts": len([h for h in by_host.values() if h.get("is_cdn")]),
    }


def _naabu_port_scan():
    """Build a minimal Naabu-shaped port_scan dict."""
    return {
        "scan_metadata": {"scan_type": "syn", "rate_limit": 1000},
        "by_host": {
            "example.com": {
                "host": "example.com", "ip": "1.2.3.4",
                "ports": [80], "port_details": [{"port": 80, "protocol": "tcp", "service": "HTTP"}],
                "cdn": None, "is_cdn": False,
            },
        },
        "by_ip": {
            "1.2.3.4": {"ip": "1.2.3.4", "hostnames": ["example.com"], "ports": [80], "cdn": None, "is_cdn": False},
        },
        "all_ports": [80],
        "ip_to_hostnames": {"1.2.3.4": ["example.com"]},
        "summary": {"hosts_scanned": 1, "total_open_ports": 1, "unique_port_count": 1},
    }


def _masscan_scan_data():
    """Build a minimal Masscan-shaped masscan_scan dict."""
    return {
        "scan_metadata": {"scanner": "masscan", "scan_type": "syn"},
        "by_host": {
            "example.com": {
                "host": "example.com", "ip": "1.2.3.4",
                "ports": [443], "port_details": [{"port": 443, "protocol": "tcp", "service": "HTTPS"}],
                "cdn": None, "is_cdn": False,
            },
            "api.example.com": {
                "host": "api.example.com", "ip": "5.6.7.8",
                "ports": [8080], "port_details": [{"port": 8080, "protocol": "tcp", "service": "HTTP-ALT"}],
                "cdn": None, "is_cdn": False,
            },
        },
        "by_ip": {
            "1.2.3.4": {"ip": "1.2.3.4", "hostnames": ["example.com"], "ports": [443], "cdn": None, "is_cdn": False},
            "5.6.7.8": {"ip": "5.6.7.8", "hostnames": ["api.example.com"], "ports": [8080], "cdn": None, "is_cdn": False},
        },
        "all_ports": [443, 8080],
        "ip_to_hostnames": {"1.2.3.4": ["example.com"], "5.6.7.8": ["api.example.com"]},
        "summary": {"hosts_scanned": 2, "total_open_ports": 2, "unique_port_count": 2},
    }


class TestMergePortScanResults(unittest.TestCase):

    def test_no_masscan_data_noop(self):
        combined = {"port_scan": _naabu_port_scan()}
        _merge_port_scan_results(combined)
        self.assertEqual(combined["port_scan"]["all_ports"], [80])

    def test_masscan_only_promotes_to_port_scan(self):
        combined = {"masscan_scan": _masscan_scan_data()}
        _merge_port_scan_results(combined)
        self.assertIn("port_scan", combined)
        self.assertEqual(sorted(combined["port_scan"]["all_ports"]), [443, 8080])
        self.assertIn("api.example.com", combined["port_scan"]["by_host"])

    def test_both_scanners_merge_dedup(self):
        combined = {
            "port_scan": _naabu_port_scan(),
            "masscan_scan": _masscan_scan_data(),
        }
        _merge_port_scan_results(combined)

        ps = combined["port_scan"]
        host = ps["by_host"]["example.com"]
        self.assertEqual(sorted(host["ports"]), [80, 443])
        self.assertEqual(len(host["port_details"]), 2)
        ports_in_details = sorted(pd["port"] for pd in host["port_details"])
        self.assertEqual(ports_in_details, [80, 443])

        self.assertIn("api.example.com", ps["by_host"])
        self.assertEqual(sorted(ps["all_ports"]), [80, 443, 8080])

    def test_duplicate_port_not_doubled(self):
        naabu = _naabu_port_scan()
        masscan = _masscan_scan_data()
        masscan["by_host"]["example.com"]["ports"] = [80, 443]
        masscan["by_host"]["example.com"]["port_details"] = [
            {"port": 80, "protocol": "tcp", "service": "HTTP"},
            {"port": 443, "protocol": "tcp", "service": "HTTPS"},
        ]
        masscan["by_ip"]["1.2.3.4"]["ports"] = [80, 443]
        combined = {"port_scan": naabu, "masscan_scan": masscan}
        _merge_port_scan_results(combined)

        host = combined["port_scan"]["by_host"]["example.com"]
        self.assertEqual(sorted(host["ports"]), [80, 443])
        self.assertEqual(len(host["port_details"]), 2)

    def test_scanners_list_updated(self):
        combined = {
            "port_scan": _naabu_port_scan(),
            "masscan_scan": _masscan_scan_data(),
        }
        _merge_port_scan_results(combined)
        meta = combined["port_scan"]["scan_metadata"]
        self.assertIn("scanners", meta)
        self.assertIn("naabu", meta["scanners"])
        self.assertIn("masscan", meta["scanners"])

    def test_summary_recalculated(self):
        combined = {
            "port_scan": _naabu_port_scan(),
            "masscan_scan": _masscan_scan_data(),
        }
        _merge_port_scan_results(combined)
        s = combined["port_scan"]["summary"]
        self.assertEqual(s["hosts_scanned"], 2)
        self.assertEqual(s["total_open_ports"], 3)
        self.assertEqual(s["unique_port_count"], 3)

    def test_by_ip_hostnames_merged(self):
        combined = {
            "port_scan": _naabu_port_scan(),
            "masscan_scan": _masscan_scan_data(),
        }
        _merge_port_scan_results(combined)
        self.assertIn("5.6.7.8", combined["port_scan"]["by_ip"])
        self.assertEqual(combined["port_scan"]["by_ip"]["5.6.7.8"]["hostnames"], ["api.example.com"])


# ========================================================================
# 6. run_masscan_scan — mocked subprocess
# ========================================================================
class TestRunMasscanScan(unittest.TestCase):

    def _base_settings(self):
        return {
            "MASSCAN_ENABLED": True,
            "MASSCAN_RATE": 1000,
            "MASSCAN_TOP_PORTS": "100",
            "MASSCAN_CUSTOM_PORTS": "",
            "MASSCAN_BANNERS": False,
            "MASSCAN_WAIT": 5,
            "MASSCAN_RETRIES": 1,
            "MASSCAN_EXCLUDE_TARGETS": "",
        }

    def _base_recon_data(self):
        return _domain_recon_data(domain="example.com", domain_ips=["1.2.3.4"])

    def test_disabled_skips(self):
        data = self._base_recon_data()
        result = run_masscan_scan(data, settings={"MASSCAN_ENABLED": False})
        self.assertNotIn("masscan_scan", result)

    def test_tor_skips(self):
        settings = self._base_settings()
        settings["USE_TOR_FOR_RECON"] = True
        data = self._base_recon_data()
        result = run_masscan_scan(data, settings=settings)
        self.assertNotIn("masscan_scan", result)

    def test_missing_binary_skips(self):
        with patch.object(masscan_mod, "is_masscan_installed", return_value=False):
            data = self._base_recon_data()
            result = run_masscan_scan(data, settings=self._base_settings())
            self.assertNotIn("masscan_scan", result)

    def test_no_targets_skips(self):
        data = {"domain": "", "dns": {}}
        settings = self._base_settings()
        with patch.object(masscan_mod, "is_masscan_installed", return_value=True):
            result = run_masscan_scan(data, settings=settings)
        self.assertNotIn("masscan_scan", result)

    def test_successful_scan(self):
        ndjson_content = "\n".join([
            _ndjson_line("1.2.3.4", 80),
            _ndjson_line("1.2.3.4", 443),
        ])

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = 0

        def write_output_side_effect(*args, **kwargs):
            cmd = args[0]
            for i, arg in enumerate(cmd):
                if arg == "-oD" and i + 1 < len(cmd):
                    with open(cmd[i + 1], 'w') as f:
                        f.write(ndjson_content)
            return mock_proc

        with patch.object(masscan_mod, "is_masscan_installed", return_value=True), \
             patch.object(masscan_mod.subprocess, "Popen", side_effect=write_output_side_effect):
            data = self._base_recon_data()
            result = run_masscan_scan(data, settings=self._base_settings())

        self.assertIn("masscan_scan", result)
        ms = result["masscan_scan"]
        self.assertEqual(ms["scan_metadata"]["scanner"], "masscan")
        self.assertEqual(sorted(ms["all_ports"]), [80, 443])
        self.assertIn("example.com", ms["by_host"])

    def test_permission_denied(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "error: permission denied (raw socket)")
        mock_proc.returncode = 1

        with patch.object(masscan_mod, "is_masscan_installed", return_value=True), \
             patch.object(masscan_mod.subprocess, "Popen", return_value=mock_proc):
            data = self._base_recon_data()
            result = run_masscan_scan(data, settings=self._base_settings())
        self.assertNotIn("masscan_scan", result)

    def test_ip_mode_mock_hostname_replaced(self):
        """In IP mode, mock hostnames like '10-0-0-1' are replaced with actual IP."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = 0

        def write_output(cmd, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "-oD" and i + 1 < len(cmd):
                    with open(cmd[i + 1], 'w') as f:
                        f.write(_ndjson_line("10.0.0.1", 22) + "\n")
            return mock_proc

        data = {
            "domain": "ip-targets.test",
            "dns": {"domain": {}, "subdomains": {}},
            "metadata": {
                "ip_mode": True,
                "expanded_ips": ["10.0.0.1"],
                "ip_to_hostname": {"10.0.0.1": "10-0-0-1"},
            },
        }
        with patch.object(masscan_mod, "is_masscan_installed", return_value=True), \
             patch.object(masscan_mod.subprocess, "Popen", side_effect=write_output):
            result = run_masscan_scan(data, settings=self._base_settings())
        self.assertIn("masscan_scan", result)
        self.assertIn("10.0.0.1", result["masscan_scan"]["by_host"])
        self.assertNotIn("10-0-0-1", result["masscan_scan"]["by_host"])

    def test_ip_mode_real_ptr_preserved(self):
        """In IP mode, real PTR hostnames are preserved."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = 0

        def write_output(cmd, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "-oD" and i + 1 < len(cmd):
                    with open(cmd[i + 1], 'w') as f:
                        f.write(_ndjson_line("10.0.0.1", 80) + "\n")
            return mock_proc

        data = {
            "domain": "ip-targets.test",
            "dns": {"domain": {}, "subdomains": {}},
            "metadata": {
                "ip_mode": True,
                "expanded_ips": ["10.0.0.1"],
                "ip_to_hostname": {"10.0.0.1": "server1.example.com"},
            },
        }
        with patch.object(masscan_mod, "is_masscan_installed", return_value=True), \
             patch.object(masscan_mod.subprocess, "Popen", side_effect=write_output):
            result = run_masscan_scan(data, settings=self._base_settings())
        self.assertIn("server1.example.com", result["masscan_scan"]["by_host"])


# ========================================================================
# 7. run_masscan_scan_isolated — thread safety
# ========================================================================
class TestRunMasscanScanIsolated(unittest.TestCase):

    def test_does_not_mutate_input(self):
        data = _domain_recon_data()
        original = copy.deepcopy(data)
        run_masscan_scan_isolated(data, settings={"MASSCAN_ENABLED": False})
        self.assertEqual(data, original)

    def test_returns_masscan_scan_dict(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = 0

        def write_output(cmd, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "-oD" and i + 1 < len(cmd):
                    with open(cmd[i + 1], 'w') as f:
                        f.write(_ndjson_line("1.2.3.4", 80) + "\n")
            return mock_proc

        data = _domain_recon_data(domain="example.com", domain_ips=["1.2.3.4"])
        with patch.object(masscan_mod, "is_masscan_installed", return_value=True), \
             patch.object(masscan_mod.subprocess, "Popen", side_effect=write_output):
            result = run_masscan_scan_isolated(data, settings={
                "MASSCAN_ENABLED": True,
                "MASSCAN_TOP_PORTS": "100",
                "MASSCAN_RATE": 1000,
            })
        self.assertIsInstance(result, dict)
        self.assertIn("by_host", result)
        self.assertIn("by_ip", result)
        self.assertNotIn("masscan_scan", data)

    def test_returns_empty_dict_when_disabled(self):
        data = _domain_recon_data()
        result = run_masscan_scan_isolated(data, settings={"MASSCAN_ENABLED": False})
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()

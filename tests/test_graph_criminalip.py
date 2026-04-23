"""
Unit tests for Neo4jClient.update_graph_from_criminalip().

All Neo4j driver interactions are mocked — no live database required.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "graph_db"))
sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Stub out the neo4j package and dotenv before importing neo4j_client,
# since neither is installed in the host test environment (they live inside
# the Docker container). We only need the class definition — the driver is
# fully mocked in every test.
# ---------------------------------------------------------------------------
import types

_neo4j_stub = types.ModuleType("neo4j")
_neo4j_stub.GraphDatabase = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_stub)

_dotenv_stub = types.ModuleType("dotenv")
_dotenv_stub.load_dotenv = lambda *a, **kw: None
sys.modules.setdefault("dotenv", _dotenv_stub)


# ---------------------------------------------------------------------------
# Helpers — build recon payloads matching criminalip_enrich.py output schema
# ---------------------------------------------------------------------------

USER_ID = "user1"
PROJECT_ID = "proj1"


def _ip_report(
    ip="1.2.3.4",
    inbound="5",
    outbound="1",
    is_vpn=True,
    is_proxy=False,
    is_tor=False,
    is_hosting=True,
    is_cloud=False,
    is_mobile=False,
    is_darkweb=False,
    is_scanner=False,
    is_snort=True,
    org_name="TestOrg",
    country="US",
    city="New York",
    latitude=40.7128,
    longitude=-74.0060,
    asn_name="TestNet",
    asn_no=12345,
    ports=None,
    vulnerabilities=None,
    categories=None,
    ids_count=3,
    scanning_count=12,
) -> dict:
    return {
        "ip": ip,
        "score": {"inbound": inbound, "outbound": outbound},
        "issues": {
            "is_vpn": is_vpn, "is_proxy": is_proxy, "is_tor": is_tor,
            "is_hosting": is_hosting, "is_cloud": is_cloud,
            "is_mobile": is_mobile, "is_darkweb": is_darkweb,
            "is_scanner": is_scanner, "is_snort": is_snort,
        },
        "whois": {
            "org_name": org_name, "country": country, "city": city,
            "latitude": latitude, "longitude": longitude,
            "asn_name": asn_name, "asn_no": asn_no,
        },
        "ports": ports if ports is not None else [
            {"port": 80, "socket": "tcp", "protocol": "HTTP",
             "app_name": "Apache", "app_version": "2.4.29", "banner": "HTTP/1.1 200"},
            {"port": 443, "socket": "tcp", "protocol": "HTTPS",
             "app_name": "Apache", "app_version": "2.4.29", "banner": None},
        ],
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [
            {"cve_id": "CVE-2023-25690", "description": "HTTP Request Smuggling",
             "cvssv2_score": 0.0, "cvssv3_score": 9.8,
             "app_name": "Apache", "app_version": "2.4.29"},
        ],
        "categories": categories if categories is not None else ["malware", "scanner"],
        "ids_count": ids_count,
        "scanning_count": scanning_count,
    }


def _domain_report(domain="example.com", score="high", grade="B", abuse_count=5) -> dict:
    return {
        "domain": domain,
        "risk": {"score": score, "grade": grade, "abuse_record_count": abuse_count,
                 "current_service": "web"},
    }


_UNSET = object()


def _recon_data(ip_reports=_UNSET, domain_report=_UNSET) -> dict:
    return {
        "criminalip": {
            "ip_reports": ip_reports if ip_reports is not _UNSET else [_ip_report()],
            "domain_report": domain_report if domain_report is not _UNSET else _domain_report(),
        }
    }


# ---------------------------------------------------------------------------
# Mock Neo4j session factory
# ---------------------------------------------------------------------------

def _make_driver_mock():
    """Return a mocked Neo4j driver + session context manager."""
    session_mock = MagicMock()
    session_mock.__enter__ = MagicMock(return_value=session_mock)
    session_mock.__exit__ = MagicMock(return_value=False)
    driver_mock = MagicMock()
    driver_mock.session.return_value = session_mock
    return driver_mock, session_mock


# ---------------------------------------------------------------------------
# Import Neo4jClient without connecting to a real database
# ---------------------------------------------------------------------------

def _make_client(driver_mock) -> "Neo4jClient":
    from neo4j_client import Neo4jClient
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = driver_mock
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestUpdateGraphFromCriminalip(unittest.TestCase):

    def setUp(self):
        self.driver, self.session = _make_driver_mock()
        self.client = _make_client(self.driver)

    def _run(self, recon_data=None):
        if recon_data is None:
            recon_data = _recon_data()
        return self.client.update_graph_from_criminalip(recon_data, USER_ID, PROJECT_ID)

    # ── Stats returned ──────────────────────────────────────────────────────

    def test_returns_stats_dict_with_expected_keys(self):
        stats = self._run()
        for key in ("ips_enriched", "ports_merged", "services_created",
                    "vulnerabilities_created", "cves_created",
                    "domains_updated", "relationships_created", "errors"):
            self.assertIn(key, stats)

    def test_full_enrichment_counts(self):
        stats = self._run()
        self.assertEqual(stats["ips_enriched"], 1)
        self.assertEqual(stats["ports_merged"], 2)        # port 80 and 443
        self.assertEqual(stats["services_created"], 2)    # Apache on both ports
        self.assertEqual(stats["vulnerabilities_created"], 1)
        self.assertEqual(stats["cves_created"], 1)
        self.assertEqual(stats["domains_updated"], 1)
        self.assertEqual(stats["errors"], [])

    def test_no_errors_on_valid_data(self):
        stats = self._run()
        self.assertEqual(stats["errors"], [])

    # ── Empty / missing data ────────────────────────────────────────────────

    def test_empty_criminalip_key_records_error(self):
        stats = self._run({"criminalip": {}})
        self.assertIn("No criminalip data", stats["errors"][0])
        self.session.run.assert_not_called()

    def test_missing_criminalip_key_records_error(self):
        stats = self._run({})
        self.assertIn("No criminalip data", stats["errors"][0])
        self.session.run.assert_not_called()

    def test_no_domain_report_still_processes_ips(self):
        data = _recon_data(domain_report=None)
        stats = self.client.update_graph_from_criminalip(data, USER_ID, PROJECT_ID)
        self.assertEqual(stats["ips_enriched"], 1)
        self.assertEqual(stats["domains_updated"], 0)

    def test_no_ip_reports_still_processes_domain(self):
        data = _recon_data(ip_reports=[])
        stats = self.client.update_graph_from_criminalip(data, USER_ID, PROJECT_ID)
        self.assertEqual(stats["ips_enriched"], 0)
        self.assertEqual(stats["domains_updated"], 1)

    def test_ip_report_without_ip_is_skipped(self):
        rep = _ip_report()
        del rep["ip"]
        stats = self._run(_recon_data(ip_reports=[rep]))
        self.assertEqual(stats["ips_enriched"], 0)

    def test_non_dict_ip_report_is_skipped(self):
        stats = self._run(_recon_data(ip_reports=["not_a_dict"]))
        self.assertEqual(stats["ips_enriched"], 0)

    # ── IP node props ────────────────────────────────────────────────────────

    def test_ip_node_receives_all_criminalip_props(self):
        self._run()
        # Collect all props dicts passed to MERGE IP SET calls
        all_props = {}
        for c in self.session.run.call_args_list:
            kwargs = c.kwargs if c.kwargs else {}
            if "props" in kwargs:
                all_props.update(kwargs["props"])

        self.assertTrue(all_props.get("criminalip_enriched"))
        self.assertEqual(all_props["criminalip_score_inbound"], "5")
        self.assertEqual(all_props["criminalip_score_outbound"], "1")
        # Flags
        self.assertIs(all_props["criminalip_is_vpn"], True)
        self.assertIs(all_props["criminalip_is_proxy"], False)
        self.assertIs(all_props["criminalip_is_hosting"], True)
        self.assertIs(all_props["criminalip_is_cloud"], False)
        self.assertIs(all_props["criminalip_is_snort"], True)
        # Whois
        self.assertEqual(all_props["criminalip_org_name"], "TestOrg")
        self.assertEqual(all_props["criminalip_country"], "US")
        self.assertEqual(all_props["criminalip_city"], "New York")
        self.assertAlmostEqual(all_props["criminalip_latitude"], 40.7128)
        self.assertAlmostEqual(all_props["criminalip_longitude"], -74.0060)
        self.assertEqual(all_props["criminalip_asn_name"], "TestNet")
        self.assertEqual(all_props["criminalip_asn_no"], 12345)
        # Counts
        self.assertEqual(all_props["criminalip_ids_count"], 3)
        self.assertEqual(all_props["criminalip_scanning_count"], 12)
        # Categories (JSON)
        cats = json.loads(all_props["criminalip_categories"])
        self.assertIn("malware", cats)
        self.assertIn("scanner", cats)

    def test_null_whois_fields_not_written_to_props(self):
        rep = _ip_report()
        rep["whois"]["city"] = None
        rep["whois"]["latitude"] = None
        self._run(_recon_data(ip_reports=[rep]))
        all_props = {}
        for c in self.session.run.call_args_list:
            if c.kwargs and "props" in c.kwargs:
                all_props.update(c.kwargs["props"])
        self.assertNotIn("criminalip_city", all_props)
        self.assertNotIn("criminalip_latitude", all_props)

    def test_empty_categories_not_written(self):
        rep = _ip_report(categories=[])
        self._run(_recon_data(ip_reports=[rep]))
        all_props = {}
        for c in self.session.run.call_args_list:
            if c.kwargs and "props" in c.kwargs:
                all_props.update(c.kwargs["props"])
        self.assertNotIn("criminalip_categories", all_props)

    # ── Domain node ──────────────────────────────────────────────────────────

    def test_domain_node_gets_risk_props(self):
        self._run()
        # Find the domain SET call
        domain_call = None
        for c in self.session.run.call_args_list:
            query = c.args[0] if c.args else ""
            if "criminalip_risk_score" in query:
                domain_call = c
                break
        self.assertIsNotNone(domain_call, "Domain risk SET query not found")
        kwargs = domain_call.kwargs
        self.assertEqual(kwargs["risk_score"], "high")
        self.assertEqual(kwargs["risk_grade"], "B")
        self.assertEqual(kwargs["abuse_count"], 5)
        self.assertEqual(kwargs["current_service"], "web")
        self.assertEqual(kwargs["name"], "example.com")

    def test_domain_report_with_missing_risk_key_is_skipped(self):
        data = _recon_data(domain_report={"domain": "example.com", "risk": {}})
        # Empty risk dict is still valid — query runs with None values
        stats = self.client.update_graph_from_criminalip(data, USER_ID, PROJECT_ID)
        # Should not raise, domain_report IS present so it attempts to update
        self.assertEqual(stats["domains_updated"], 1)

    def test_domain_report_without_domain_key_is_skipped(self):
        data = _recon_data(domain_report={"risk": {"score": "high"}})
        stats = self.client.update_graph_from_criminalip(data, USER_ID, PROJECT_ID)
        self.assertEqual(stats["domains_updated"], 0)

    # ── Ports ────────────────────────────────────────────────────────────────

    def test_port_merges_use_correct_number_and_protocol(self):
        self._run()
        port_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "HAS_PORT" in c.args[0]
        ]
        self.assertEqual(len(port_queries), 2)
        port_nums = {c.kwargs["port"] for c in port_queries}
        self.assertIn(80, port_nums)
        self.assertIn(443, port_nums)
        for c in port_queries:
            self.assertEqual(c.kwargs["protocol"], "tcp")
            self.assertEqual(c.kwargs["ip"], "1.2.3.4")

    def test_port_with_zero_number_is_skipped(self):
        ports = [{"port": 0, "socket": "tcp", "app_name": "nginx", "app_version": None, "banner": None}]
        stats = self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        self.assertEqual(stats["ports_merged"], 0)

    def test_port_with_non_numeric_number_is_skipped(self):
        ports = [{"port": "not_a_number", "socket": "tcp", "app_name": None, "app_version": None, "banner": None}]
        stats = self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        self.assertEqual(stats["ports_merged"], 0)

    def test_port_with_no_app_name_does_not_create_service(self):
        ports = [{"port": 8080, "socket": "tcp", "protocol": None,
                  "app_name": None, "app_version": None, "banner": None}]
        stats = self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        self.assertEqual(stats["ports_merged"], 1)
        self.assertEqual(stats["services_created"], 0)

    # ── Services ─────────────────────────────────────────────────────────────

    def test_service_nodes_created_for_ports_with_app_name(self):
        self._run()
        svc_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "RUNS_SERVICE" in c.args[0]
        ]
        self.assertEqual(len(svc_queries), 2)
        svc_names = {c.kwargs["svc_name"] for c in svc_queries}
        self.assertEqual(svc_names, {"apache"})  # app_name.lower()

    def test_service_name_is_lowercased_app_name(self):
        ports = [{"port": 22, "socket": "tcp", "protocol": "SSH",
                  "app_name": "OpenSSH", "app_version": "7.6", "banner": "SSH-2.0"}]
        self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        svc_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "RUNS_SERVICE" in c.args[0]
        ]
        self.assertEqual(len(svc_queries), 1)
        self.assertEqual(svc_queries[0].kwargs["svc_name"], "openssh")

    def test_service_version_passed_correctly(self):
        ports = [{"port": 22, "socket": "tcp", "protocol": "SSH",
                  "app_name": "OpenSSH", "app_version": "7.6p1", "banner": None}]
        self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        svc_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "RUNS_SERVICE" in c.args[0]
        ]
        self.assertEqual(svc_queries[0].kwargs["version"], "7.6p1")

    def test_service_banner_truncated_to_500_chars(self):
        long_banner = "X" * 600
        ports = [{"port": 80, "socket": "tcp", "protocol": "HTTP",
                  "app_name": "nginx", "app_version": None, "banner": long_banner}]
        self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        svc_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "RUNS_SERVICE" in c.args[0]
        ]
        self.assertLessEqual(len(svc_queries[0].kwargs["banner"]), 500)

    def test_service_null_banner_passed_as_none(self):
        ports = [{"port": 80, "socket": "tcp", "protocol": "HTTP",
                  "app_name": "nginx", "app_version": None, "banner": None}]
        self._run(_recon_data(ip_reports=[_ip_report(ports=ports)]))
        svc_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "RUNS_SERVICE" in c.args[0]
        ]
        self.assertIsNone(svc_queries[0].kwargs["banner"])

    # ── Vulnerabilities / CVEs ───────────────────────────────────────────────

    def test_vulnerability_node_created_with_correct_id(self):
        self._run()
        vuln_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "Vulnerability" in c.args[0] and "MERGE" in c.args[0]
               and "HAS_VULNERABILITY" not in c.args[0]
               and "INCLUDES_CVE" not in c.args[0]
        ]
        self.assertEqual(len(vuln_queries), 1)
        self.assertEqual(vuln_queries[0].kwargs["vuln_id"],
                         "criminalip-CVE-2023-25690-1.2.3.4")
        self.assertEqual(vuln_queries[0].kwargs["cve_id"], "CVE-2023-25690")
        self.assertAlmostEqual(vuln_queries[0].kwargs["cvss"], 9.8)

    def test_cve_node_created_with_description(self):
        self._run()
        cve_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "CVE" in c.args[0] and "MERGE" in c.args[0]
               and "INCLUDES_CVE" not in c.args[0]
               and "Vulnerability" not in c.args[0]
        ]
        self.assertEqual(len(cve_queries), 1)
        self.assertEqual(cve_queries[0].kwargs["cve_id"], "CVE-2023-25690")
        self.assertEqual(cve_queries[0].kwargs["description"], "HTTP Request Smuggling")

    def test_ip_has_vulnerability_relationship_created(self):
        self._run()
        rel_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "HAS_VULNERABILITY" in c.args[0]
        ]
        self.assertEqual(len(rel_queries), 1)
        self.assertEqual(rel_queries[0].kwargs["ip"], "1.2.3.4")
        self.assertEqual(rel_queries[0].kwargs["vuln_id"],
                         "criminalip-CVE-2023-25690-1.2.3.4")

    def test_includes_cve_relationship_created(self):
        self._run()
        rel_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "INCLUDES_CVE" in c.args[0]
        ]
        self.assertEqual(len(rel_queries), 1)
        self.assertEqual(rel_queries[0].kwargs["vuln_id"],
                         "criminalip-CVE-2023-25690-1.2.3.4")
        self.assertEqual(rel_queries[0].kwargs["cve_id"], "CVE-2023-25690")

    def test_vulnerability_without_cve_id_is_skipped(self):
        vulns = [{"description": "no cve", "cvssv3_score": 5.0}]
        stats = self._run(_recon_data(ip_reports=[_ip_report(vulnerabilities=vulns)]))
        self.assertEqual(stats["vulnerabilities_created"], 0)
        self.assertEqual(stats["cves_created"], 0)

    def test_empty_vulnerabilities_list_produces_no_vuln_nodes(self):
        stats = self._run(_recon_data(ip_reports=[_ip_report(vulnerabilities=[])]))
        self.assertEqual(stats["vulnerabilities_created"], 0)
        self.assertEqual(stats["cves_created"], 0)

    def test_cvss_prefers_v3_over_v2(self):
        vulns = [{"cve_id": "CVE-2021-1234", "cvssv2_score": 5.0,
                  "cvssv3_score": 9.1, "app_name": "nginx", "app_version": "1.0"}]
        self._run(_recon_data(ip_reports=[_ip_report(vulnerabilities=vulns)]))
        vuln_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "Vulnerability" in c.args[0] and "MERGE" in c.args[0]
               and "HAS_VULNERABILITY" not in c.args[0]
               and "INCLUDES_CVE" not in c.args[0]
        ]
        self.assertAlmostEqual(vuln_queries[0].kwargs["cvss"], 9.1)

    def test_cvss_falls_back_to_v2_when_v3_is_zero(self):
        vulns = [{"cve_id": "CVE-2021-5678", "cvssv2_score": 6.5,
                  "cvssv3_score": 0.0, "app_name": "nginx", "app_version": "1.0"}]
        self._run(_recon_data(ip_reports=[_ip_report(vulnerabilities=vulns)]))
        vuln_queries = [
            c for c in self.session.run.call_args_list
            if c.args and "Vulnerability" in c.args[0] and "MERGE" in c.args[0]
               and "HAS_VULNERABILITY" not in c.args[0]
               and "INCLUDES_CVE" not in c.args[0]
        ]
        self.assertAlmostEqual(vuln_queries[0].kwargs["cvss"], 6.5)

    # ── Multiple IPs ─────────────────────────────────────────────────────────

    def test_multiple_ip_reports_all_processed(self):
        reports = [
            _ip_report(ip="1.1.1.1", ports=[{"port": 80, "socket": "tcp", "protocol": "HTTP",
                                               "app_name": "nginx", "app_version": "1.0", "banner": None}],
                       vulnerabilities=[]),
            _ip_report(ip="2.2.2.2", ports=[{"port": 22, "socket": "tcp", "protocol": "SSH",
                                               "app_name": "OpenSSH", "app_version": "7.6", "banner": None}],
                       vulnerabilities=[]),
        ]
        stats = self._run(_recon_data(ip_reports=reports))
        self.assertEqual(stats["ips_enriched"], 2)
        self.assertEqual(stats["ports_merged"], 2)
        self.assertEqual(stats["services_created"], 2)

    # ── Error isolation ──────────────────────────────────────────────────────

    def test_session_error_on_ip_captured_in_stats_not_raised(self):
        self.session.run.side_effect = Exception("neo4j down")
        stats = self._run()
        self.assertGreater(len(stats["errors"]), 0)
        # Should not propagate the exception
        self.assertFalse(any("Traceback" in e for e in stats["errors"]))

    def test_cve_error_captured_per_cve_not_per_ip(self):
        call_count = [0]

        def selective_fail(*args, **kwargs):
            query = args[0] if args else ""
            if "CVE" in query and "INCLUDES_CVE" not in query and "HAS_VULNERABILITY" not in query:
                raise Exception("CVE insert failed")
            return MagicMock()

        self.session.run.side_effect = selective_fail
        stats = self._run()
        # CVE error is captured, but IP enrichment still completed
        cve_errors = [e for e in stats["errors"] if "CVE" in e]
        self.assertGreater(len(cve_errors), 0)


if __name__ == "__main__":
    unittest.main()

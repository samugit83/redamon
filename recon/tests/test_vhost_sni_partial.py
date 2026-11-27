"""
Tests for run_vhost_sni_partial — the partial-recon entry point that lets
users run VHost/SNI on demand
from the workflow graph or the section button.

These tests mock:
  - get_settings          (so we don't hit the webapp API)
  - run_vhost_sni_enrichment (the actual scanner, tested elsewhere)
  - Neo4jClient            (so we don't hit a real Neo4j)
  - _build_vuln_scan_data_from_graph (the graph reader)

…and verify the orchestration logic:
  - User subdomains are validated (in-scope / valid hostname)
  - User IPs are validated (IP / CIDR)
  - include_graph_targets=False starts with empty recon_data
  - Forces VHOST_SNI_ENABLED=True
  - settings_overrides are applied
  - Bails if no targets at all
  - Calls update_graph_from_vhost_sni after the scan

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_partial.py -v
"""

from __future__ import annotations

import pytest
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _setup_mocks(neo4j_connected=True, scanner_findings=None):
    """Build the standard mock pack used by every test below."""
    if scanner_findings is None:
        scanner_findings = []

    mock_settings = {
        "VHOST_SNI_ENABLED": False,    # will be force-enabled by run_vhost_sni_partial
        "VHOST_SNI_TIMEOUT": 3,
        "VHOST_SNI_TEST_L7": True,
        "VHOST_SNI_TEST_L4": True,
        "VHOST_SNI_USE_DEFAULT_WORDLIST": True,
        "VHOST_SNI_USE_GRAPH_CANDIDATES": True,
        "VHOST_SNI_INJECT_DISCOVERED": True,
        "VHOST_SNI_CUSTOM_WORDLIST": "",
        "VHOST_SNI_MAX_CANDIDATES_PER_IP": 2000,
        "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
        "VHOST_SNI_CONCURRENCY": 20,
    }

    def fake_runner(combined_result, settings=None):
        # Mimic the real runner's contract: write into combined_result["vhost_sni"]
        combined_result["vhost_sni"] = {
            "by_ip": {},
            "findings": scanner_findings,
            "discovered_baseurls": [],
            "summary": {"ips_tested": 1, "candidates_total": 5, "anomalies_l7": len(scanner_findings),
                        "anomalies_l4": 0, "high_severity": 0, "medium_severity": 0,
                        "low_severity": 0, "info_severity": 0},
            "scan_metadata": {"duration_sec": 0.5},
        }
        return combined_result

    fake_recon_data = {
        "domain": "example.com",
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "http_probe": {"by_url": {}, "by_host": {}, "live_urls": []},
        "port_scan": {"by_host": {}},
    }

    mock_client = MagicMock()
    mock_client.verify_connection.return_value = neo4j_connected
    mock_client.update_graph_from_vhost_sni.return_value = {
        "vulnerabilities_created": len(scanner_findings),
        "subdomains_enriched": len(scanner_findings),
        "ips_enriched": 1,
        "baseurls_created": 0,
        "relationships_created": 1,
        "errors": [],
    }
    mock_session = MagicMock()
    mock_session.run.return_value.single.return_value = {"name": "admin.example.com"}
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
    mock_client.driver = mock_driver

    mock_neo4j_cls = MagicMock()
    mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
    mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_graph_db = MagicMock()
    mock_graph_db.Neo4jClient = mock_neo4j_cls

    return {
        "get_settings": MagicMock(return_value=mock_settings),
        "runner": MagicMock(side_effect=fake_runner),
        "graph_data": MagicMock(return_value=fake_recon_data),
        "neo4j_cls": mock_neo4j_cls,
        "client": mock_client,
        "graph_db_module": mock_graph_db,
    }


class TestRunVhostSniPartial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["USER_ID"] = "test-user"
        os.environ["PROJECT_ID"] = "test-project"

    def _run(self, config, neo4j_connected=True, scanner_findings=None):
        mocks = _setup_mocks(neo4j_connected=neo4j_connected, scanner_findings=scanner_findings)
        from recon.partial_recon_modules import vulnerability_scanning as vs
        with patch.object(vs, "_build_vuln_scan_data_from_graph", mocks["graph_data"]), \
             patch.dict(sys.modules, {"graph_db": mocks["graph_db_module"]}), \
             patch("recon.project_settings.get_settings", mocks["get_settings"]), \
             patch("recon.main_recon_modules.vhost_sni_enum.run_vhost_sni_enrichment", mocks["runner"]):
            vs.run_vhost_sni_partial(config)
        return mocks

    # --------------------------------------------------------------
    # Force-enable + settings override
    # --------------------------------------------------------------
    def test_force_enables_vhost_sni(self):
        mocks = self._run({"domain": "example.com", "user_targets": {"subdomains": ["admin.example.com"], "ips": []}})
        # Inspect the settings dict passed into the runner
        settings_arg = mocks["runner"].call_args.kwargs["settings"]
        self.assertTrue(settings_arg["VHOST_SNI_ENABLED"])

    def test_settings_overrides_applied(self):
        mocks = self._run({
            "domain": "example.com",
            "user_targets": {"subdomains": ["admin.example.com"], "ips": []},
            "settings_overrides": {"VHOST_SNI_TIMEOUT": 99, "VHOST_SNI_TEST_L4": False},
        })
        settings_arg = mocks["runner"].call_args.kwargs["settings"]
        self.assertEqual(settings_arg["VHOST_SNI_TIMEOUT"], 99)
        self.assertFalse(settings_arg["VHOST_SNI_TEST_L4"])

    # --------------------------------------------------------------
    # Subdomain validation
    # --------------------------------------------------------------
    def test_in_scope_subdomain_accepted(self):
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": ["admin.example.com"], "ips": []}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertIn("admin.example.com", recon_data_arg["subdomains"])

    def test_out_of_scope_subdomain_rejected(self):
        # Pair the bad subdomain with a valid IP target so the scan can still proceed
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": ["admin.acme.io", "good.example.com"], "ips": []}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertNotIn("admin.acme.io", recon_data_arg["subdomains"])
        self.assertIn("good.example.com", recon_data_arg["subdomains"])

    def test_invalid_hostname_rejected(self):
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": ["admin .example.com", "good.example.com"], "ips": []}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertNotIn("admin .example.com", recon_data_arg["subdomains"])
        self.assertIn("good.example.com", recon_data_arg["subdomains"])

    def test_apex_domain_accepted(self):
        # Subdomain == apex is in-scope per the validator
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": ["example.com"], "ips": []}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertIn("example.com", recon_data_arg["subdomains"])

    # --------------------------------------------------------------
    # IP validation
    # --------------------------------------------------------------
    def test_valid_ip_added_as_target(self):
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": [], "ips": ["10.0.0.1"]}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertIn("10.0.0.1", recon_data_arg["port_scan"]["by_host"])

    def test_invalid_ip_rejected(self):
        # Pair with a valid IP so the scan still has something to chew on
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": [], "ips": ["not-an-ip", "1.2.3.4"]}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertNotIn("not-an-ip", recon_data_arg["port_scan"]["by_host"])
        self.assertIn("1.2.3.4", recon_data_arg["port_scan"]["by_host"])

    def test_cidr_accepted(self):
        # _is_ip_or_cidr accepts /24-/32 v4 ranges
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": [], "ips": ["10.0.0.0/30"]}})
        recon_data_arg = mocks["runner"].call_args.args[0]
        self.assertIn("10.0.0.0/30", recon_data_arg["port_scan"]["by_host"])

    # --------------------------------------------------------------
    # include_graph_targets gating
    # --------------------------------------------------------------
    def test_include_graph_targets_true_calls_graph_reader(self):
        mocks = self._run({"domain": "example.com",
                           "include_graph_targets": True,
                           "user_targets": {"subdomains": ["admin.example.com"], "ips": []}})
        mocks["graph_data"].assert_called_once_with(
            ["example.com"], "test-user", "test-project",
            include_root_domain=False, domain_groups=None,
        )

    def test_include_graph_targets_false_skips_graph_reader(self):
        mocks = self._run({"domain": "example.com",
                           "include_graph_targets": False,
                           "user_targets": {"subdomains": ["admin.example.com"], "ips": ["10.0.0.1"]}})
        mocks["graph_data"].assert_not_called()

    # --------------------------------------------------------------
    # Bail conditions
    # --------------------------------------------------------------
    def test_bails_when_no_targets_at_all(self):
        # No graph data, no custom subdomains, no custom IPs -> sys.exit(1)
        mocks = _setup_mocks()
        # Graph reader returns the empty fake_recon_data (no IPs, no subs)
        from recon.partial_recon_modules import vulnerability_scanning as vs
        with patch.object(vs, "_build_vuln_scan_data_from_graph", mocks["graph_data"]), \
             patch.dict(sys.modules, {"graph_db": mocks["graph_db_module"]}), \
             patch("recon.project_settings.get_settings", mocks["get_settings"]), \
             patch("recon.main_recon_modules.vhost_sni_enum.run_vhost_sni_enrichment", mocks["runner"]):
            with self.assertRaises(SystemExit) as cm:
                vs.run_vhost_sni_partial({
                    "domain": "example.com",
                    "include_graph_targets": True,
                    "user_targets": {"subdomains": [], "ips": []},
                })
            self.assertEqual(cm.exception.code, 1)
        # Runner should NOT have been called
        mocks["runner"].assert_not_called()

    # --------------------------------------------------------------
    # Graph update wiring
    # --------------------------------------------------------------
    def test_calls_update_graph_from_vhost_sni(self):
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": ["admin.example.com"], "ips": []}},
                          scanner_findings=[{
                              "id": "vhost_sni_admin", "hostname": "admin.example.com",
                              "ip": "1.2.3.4", "port": 443, "layer": "L7",
                              "type": "hidden_vhost", "severity": "low",
                          }])
        mocks["client"].update_graph_from_vhost_sni.assert_called_once()
        # Confirm the recon_data passed in carries vhost_sni results
        call_kwargs = mocks["client"].update_graph_from_vhost_sni.call_args.kwargs
        if "recon_data" in call_kwargs:
            recon_data = call_kwargs["recon_data"]
        else:
            recon_data = mocks["client"].update_graph_from_vhost_sni.call_args.args[0]
        self.assertIn("vhost_sni", recon_data)

    # --------------------------------------------------------------
    # The graph reader's real shape
    # --------------------------------------------------------------
    def _run_with_graph(self, config):
        # What _build_vuln_scan_data_from_graph really returns: port_scan holds
        # by_ip only. The fixture above carries by_host and so hid a KeyError
        # that crashed every graph-backed run.
        mocks = _setup_mocks()
        mocks["graph_data"].return_value = {
            "domain": "example.com",
            "subdomains": ["www.example.com"],
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                    "subdomains": {"www.example.com": {
                        "ips": {"ipv4": ["192.0.2.10"], "ipv6": []}, "has_records": True}}},
            "metadata": {"include_root_domain": True},
            "http_probe": {"by_url": {}},
            "port_scan": {"by_ip": {}},
            "resource_enum": {"by_base_url": {}, "discovered_urls": []},
        }
        from recon.partial_recon_modules import vulnerability_scanning as vs
        with patch.object(vs, "_build_vuln_scan_data_from_graph", mocks["graph_data"]), \
             patch.dict(sys.modules, {"graph_db": mocks["graph_db_module"]}), \
             patch("recon.project_settings.get_settings", mocks["get_settings"]), \
             patch("recon.main_recon_modules.vhost_sni_enum.run_vhost_sni_enrichment", mocks["runner"]):
            vs.run_vhost_sni_partial(config)
        return mocks["runner"].call_args[0][0]

    def test_graph_targets_without_by_host_still_scan(self):
        scanned = self._run_with_graph({"domain": "example.com", "include_graph_targets": True})
        self.assertEqual(scanned["port_scan"]["by_host"], {})
        self.assertIn("www.example.com", scanned["dns"]["subdomains"])

    def test_user_ips_land_in_by_host_on_top_of_graph_targets(self):
        scanned = self._run_with_graph({"domain": "example.com", "include_graph_targets": True,
                                        "user_targets": {"subdomains": [], "ips": ["192.0.2.20"]}})
        self.assertIn("192.0.2.20", scanned["port_scan"]["by_host"])

    def test_neo4j_unavailable_does_not_crash(self):
        mocks = self._run({"domain": "example.com",
                           "user_targets": {"subdomains": ["admin.example.com"], "ips": []}},
                          neo4j_connected=False)
        # Runner should still have been called even though Neo4j is down
        mocks["runner"].assert_called_once()
        # update_graph should NOT have been called
        mocks["client"].update_graph_from_vhost_sni.assert_not_called()


if __name__ == "__main__":
    unittest.main()

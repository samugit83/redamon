"""B01: a host the RoE excludes is never a target, full or partial run.

merge_group_hosts filtered RoE exclusions out of the subdomain LIST only; the
dns.subdomains map kept the host with its records and IPs, and the port scan,
the httpx DNS fallback, nuclei, the takeover module and the security checks all
read that map. In partial runs the graph builders applied no RoE at all.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main import merge_group_hosts  # noqa: E402
from recon.helpers.target_helpers import extract_targets_from_recon  # noqa: E402

ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["excluded.example.test", "203.0.113.0/28"]}


def _dns(ip):
    return {"ips": {"ipv4": [ip], "ipv6": []}, "has_records": True}


def _discovery():
    return {
        "subdomains": ["app.example.test", "excluded.example.test", "deep.excluded.example.test"],
        "dns": {"domain": {}, "subdomains": {
            "app.example.test": _dns("198.51.100.10"),
            "excluded.example.test": _dns("198.51.100.20"),
            "deep.excluded.example.test": _dns("198.51.100.21"),
        }},
        "subdomain_status_map": {"app.example.test": "resolved",
                                 "excluded.example.test": "resolved"},
    }


def _info(**kw):
    base = {"include_root_domain": False, "full_subdomains": [], "root_domain": "example.test"}
    base.update(kw)
    return base


class TestB01FullRun:
    def test_b01_excluded_host_is_in_neither_list_nor_dns_map(self):
        out = merge_group_hosts(_discovery(), _info(), "example.test", ROE, dns_enabled=False)
        for host in ("excluded.example.test", "deep.excluded.example.test"):
            assert host not in out["subdomains"]
            assert host not in out["dns"]["subdomains"]
            assert host not in out["status_map"]
        assert "app.example.test" in out["dns"]["subdomains"]

    def test_b01_no_target_list_built_from_the_merge_holds_it(self):
        out = merge_group_hosts(_discovery(), _info(), "example.test", ROE, dns_enabled=False)
        recon = {"domain": "example.test", "dns": out["dns"],
                 "metadata": {"include_root_domain": False, "scope_mode": "x"}}
        ips, hostnames, _map = extract_targets_from_recon(recon)
        assert "excluded.example.test" not in hostnames
        assert "198.51.100.20" not in ips and "198.51.100.21" not in ips

    def test_b01_an_excluded_host_resolved_later_is_dropped_too(self):
        def resolver(root, hosts, **_kw):
            return {"subdomains": {h: _dns("198.51.100.30") for h in hosts}}
        info = _info(full_subdomains=["excluded.example.test", "listed.example.test"])
        out = merge_group_hosts({"subdomains": [], "dns": {}}, info, "example.test", ROE,
                                dns_enabled=True, resolver=resolver)
        assert "excluded.example.test" not in out["dns"]["subdomains"]
        assert "excluded.example.test" not in out["subdomains"]
        assert "listed.example.test" in out["dns"]["subdomains"]

    def test_roe_off_keeps_everything(self):
        out = merge_group_hosts(_discovery(), _info(), "example.test",
                                {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": ROE["ROE_EXCLUDED_HOSTS"]},
                                dns_enabled=False)
        assert "excluded.example.test" in out["dns"]["subdomains"]


class TestB01PartialRun:
    """The builders read the graph and receive no settings: the run's RoE set
    (partial_recon._prepare_scope) is what they consult."""

    def setup_method(self):
        from recon.partial_recon_modules import helpers
        helpers.set_run_roe(ROE)

    def teardown_method(self):
        from recon.partial_recon_modules import helpers
        helpers.set_run_roe({})

    def test_b01_graph_scope_drops_an_excluded_host(self):
        from recon.partial_recon_modules.graph_builders import _GraphScope
        scope = _GraphScope(["example.test"], None, include_root_domain=False)
        assert scope.keeps("app.example.test", "example.test")
        assert not scope.keeps("excluded.example.test", "example.test")
        assert not scope.keeps("deep.excluded.example.test", "example.test")
        assert scope.root_of("excluded.example.test") is None

    def test_b01_builder_skips_excluded_hosts_and_ips(self):
        from recon.partial_recon_modules import graph_builders as gb
        rows = [
            {"root": "example.test", "subdomain": "app.example.test", "address": "198.51.100.10", "version": "ipv4"},
            {"root": "example.test", "subdomain": "app.example.test", "address": "203.0.113.5", "version": "ipv4"},
            {"root": "example.test", "subdomain": "excluded.example.test", "address": "198.51.100.20", "version": "ipv4"},
        ]
        session = MagicMock()
        session.run.return_value = rows
        client = MagicMock()
        client.__enter__.return_value = client
        client.verify_connection.return_value = True
        client.driver.session.return_value.__enter__.return_value = session
        with patch("graph_db.Neo4jClient", return_value=client):
            data = gb._build_recon_data_from_graph(["example.test"], "u", "p")
        subs = data["dns"]["subdomains"]
        assert "excluded.example.test" not in subs
        assert subs["app.example.test"]["ips"]["ipv4"] == ["198.51.100.10"]

    def test_prepare_scope_sets_the_run_roe(self):
        from recon import partial_recon
        from recon.partial_recon_modules import helpers
        helpers.set_run_roe({})
        settings = {**ROE, "TARGET_DOMAIN": "example.test"}
        config = {"domain": "example.test", "domains": ["example.test"]}
        with patch.object(partial_recon, "_refusal_reason", return_value=None), \
                patch.object(partial_recon, "settings_project_roots", return_value=["example.test"]):
            partial_recon._prepare_scope(config, settings, "p")
        assert helpers.roe_excluded("excluded.example.test")
        assert helpers.roe_excluded("203.0.113.3")
        assert not helpers.roe_excluded("app.example.test")

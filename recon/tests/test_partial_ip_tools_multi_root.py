"""Partial Naabu, Masscan, Nmap, Httpx, Shodan and OsintEnrichment over several roots.

  - the port and HTTP tools scan every root in one pass: the builders receive
    all of the run's roots and each root's group scope;
  - a custom hostname is accepted under ANY root (not just the first) and is
    attached to its own root's Domain; a hostname under no root is skipped;
  - httpx keeps a result under any root (its own scope filter used to read
    recon_data["domain"] and so dropped every other root's results);
  - Shodan and OsintEnrichment look the domain itself up (Shodan domain DNS, OTX
    and VirusTotal domain reports, ...), so they run once per root, and each pass
    carries every root so a host under another root is not written as external.

Fixture roots are alpha.test / beta.test / gamma.test only.
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import helpers, http_probing, osint_enrichment, port_scanning  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]
GROUPS = [{"rootDomain": r, "prefixes": ["*"], "batch": True} for r in ROOTS]
BASE = {"_settings": {}, "domains": ROOTS, "domain": ROOTS[0], "domain_groups": GROUPS}


class _Session:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.log.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


@pytest.fixture
def graph(monkeypatch):
    """A fake graph_db whose client records every session query."""
    log = []
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.driver.session.side_effect = lambda: _Session(log)
    for method in ("update_graph_from_port_scan", "update_graph_from_nmap",
                   "update_graph_from_http_probe", "update_graph_from_shodan",
                   "update_graph_from_otx"):
        getattr(client, method).return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    monkeypatch.setattr(helpers.time, "sleep", lambda *_: None)   # run_per_root pacing
    return log, client


def _dns_recon(roots, ip="10.0.1.1"):
    return {
        "domain": roots[0], "domains": list(roots),
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {f"www.{roots[0]}": {"ips": {"ipv4": [ip], "ipv6": []}, "has_records": True}}},
        "metadata": {"include_root_domain": False},
    }


def _port_recon(roots):
    recon = _dns_recon(roots)
    recon["port_scan"] = {"by_ip": {"10.0.1.1": {"ip": "10.0.1.1", "hostnames": [f"www.{roots[0]}"],
                                                  "ports": [443], "port_details": []}},
                          "by_host": {}, "ip_to_hostnames": {}, "all_ports": [443],
                          "scan_metadata": {}, "summary": {}}
    return recon


# --- Naabu / Masscan ----------------------------------------------------------------

class TestPortScanners:
    def _run(self, monkeypatch, graph, **config):
        builder = MagicMock(side_effect=lambda roots, *a, **kw: _dns_recon(roots))
        monkeypatch.setattr(port_scanning, "_build_recon_data_from_graph", builder)
        monkeypatch.setattr(port_scanning, "_resolve_hostname",
                            lambda h: {"ipv4": ["10.9.9.9"], "ipv6": []})
        with patch("recon.main_recon_modules.port_scan.run_port_scan",
                   side_effect=lambda rd, output_file=None, settings=None: rd):
            port_scanning.run_naabu({**BASE, **config})
        return builder

    def test_every_root_and_group_reach_the_builder(self, monkeypatch, graph):
        builder = self._run(monkeypatch, graph)
        args, kwargs = builder.call_args
        assert args[0] == ROOTS and kwargs["domain_groups"] == GROUPS

    def test_a_hostname_under_the_second_root_attaches_to_it(self, monkeypatch, graph):
        log, _ = graph
        self._run(monkeypatch, graph, user_targets={
            "subdomains": ["new.beta.test", "x.other.test"], "ips": [], "ip_attach_to": None})
        attach = [p for q, p in log if "HAS_SUBDOMAIN" in q]
        assert [(p["sub"], p["domain"]) for p in attach] == [("new.beta.test", "beta.test")]

    def test_a_hostname_under_no_root_is_skipped(self, monkeypatch, graph, capsys):
        log, _ = graph
        self._run(monkeypatch, graph, user_targets={
            "subdomains": ["x.other.test"], "ips": [], "ip_attach_to": None})
        assert not any(p.get("name") == "x.other.test" for _, p in log)
        assert "outside the project's domains: x.other.test" in capsys.readouterr().out

    def test_generic_ips_attach_through_the_roots(self, monkeypatch, graph):
        _, client = graph
        self._run(monkeypatch, graph, user_targets={
            "subdomains": [], "ips": ["203.0.113.9"], "ip_attach_to": None})
        assert client.create_user_input_node.call_args.kwargs["domain"] == ROOTS


class TestNmapAndHttpx:
    def test_nmap_builds_over_every_root(self, monkeypatch, graph):
        builder = MagicMock(side_effect=lambda roots, *a, **kw: _port_recon(roots))
        monkeypatch.setattr(port_scanning, "_build_port_scan_data_from_graph", builder)
        with patch("recon.main_recon_modules.nmap_scan.run_nmap_scan",
                   side_effect=lambda rd, output_file=None, settings=None: rd):
            port_scanning.run_nmap(dict(BASE))
        assert builder.call_args.args[0] == ROOTS
        assert builder.call_args.kwargs["domain_groups"] == GROUPS

    def test_httpx_builds_over_every_root_and_accepts_a_root_2_hostname(self, monkeypatch, graph):
        log, _ = graph
        builder = MagicMock(side_effect=lambda roots, *a, **kw: _port_recon(roots))
        monkeypatch.setattr(http_probing, "_build_port_scan_data_from_graph", builder)
        monkeypatch.setattr(http_probing, "_resolve_hostname",
                            lambda h: {"ipv4": ["10.9.9.9"], "ipv6": []})
        with patch("recon.main_recon_modules.http_probe.run_http_probe",
                   side_effect=lambda rd, output_file=None, settings=None: rd):
            http_probing.run_httpx({**BASE, "user_targets": {
                "subdomains": ["shop.gamma.test"], "ips": [], "ports": [], "ip_attach_to": None}})
        assert builder.call_args.args[0] == ROOTS
        attach = [(p["sub"], p["domain"]) for q, p in log if "HAS_SUBDOMAIN" in q]
        assert attach == [("shop.gamma.test", "gamma.test")]


class TestHttpxScopeFilter:
    def test_the_scope_is_every_root_of_a_partial_run(self):
        from recon.main_recon_modules.http_probe import httpx_scope_roots
        assert httpx_scope_roots({"domain": "alpha.test", "domains": ROOTS}) == ROOTS
        assert httpx_scope_roots({"domain": "alpha.test"}) == "alpha.test"
        assert httpx_scope_roots({"metadata": {"root_domain": "beta.test"}}) == "beta.test"

    def test_a_host_under_any_root_is_in_scope(self):
        from recon.main_recon_modules.http_probe import is_host_in_scope
        assert is_host_in_scope("www.beta.test", ROOTS)
        assert is_host_in_scope("gamma.test", ROOTS)
        assert not is_host_in_scope("www.other.test", ROOTS)
        assert is_host_in_scope("www.alpha.test", "alpha.test")      # the single-root form
        assert not is_host_in_scope("www.beta.test", "alpha.test")
        assert not is_host_in_scope("10.0.0.1", ROOTS)               # an IP only as a run address (L-6)
        assert is_host_in_scope("10.0.0.1", ROOTS, run_addresses=frozenset({"10.0.0.1"}))
        assert not is_host_in_scope("www.beta.test", [])

    def test_parsing_keeps_a_second_roots_result_and_drops_an_outsiders(self):
        from recon.main_recon_modules.http_probe import parse_httpx_output
        lines = [
            {"url": "https://www.beta.test", "input": "www.beta.test", "status_code": 200},
            {"url": "https://www.other.test", "input": "www.other.test", "status_code": 200},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write("\n".join(json.dumps(line) for line in lines))
        try:
            result = parse_httpx_output(f.name, root_domain=ROOTS)
        finally:
            os.unlink(f.name)
        assert "https://www.beta.test" in result["by_url"]
        assert "https://www.other.test" not in result["by_url"]


# --- Shodan / OsintEnrichment, one pass per root -------------------------------------

def _builder_by_root(ips):
    """One IP per root that has one; a root missing from `ips` has no targets."""
    def build(roots, *a, **kw):
        root = roots[0]
        recon = _dns_recon([root], ip=ips.get(root, "0.0.0.0"))
        if root not in ips:
            recon["dns"]["subdomains"] = {}
        return recon
    return build


class TestShodanPerRoot:
    def _run(self, monkeypatch, graph, ips, **config):
        seen = []

        def enrich(cr, settings):
            seen.append((cr["domain"], list(cr["domains"]), json.loads(json.dumps(cr["dns"]))))
            cr["shodan"] = {"hosts": [{"ip": "1.1.1.1"}], "reverse_dns": {}}
            return cr

        monkeypatch.setattr(osint_enrichment, "_build_recon_data_from_graph", MagicMock(side_effect=_builder_by_root(ips)))
        with patch("recon.main_recon_modules.shodan_enrich.run_shodan_enrichment", side_effect=enrich):
            statuses = osint_enrichment.run_shodan({**BASE, **config})
        return statuses, seen

    def test_each_root_gets_its_own_lookup(self, monkeypatch, graph):
        statuses, seen = self._run(monkeypatch, graph, {"alpha.test": "10.0.1.1", "beta.test": "10.0.2.1",
                                                         "gamma.test": "10.0.3.1"})
        assert [s[0] for s in seen] == ROOTS
        assert all(s[1] == ROOTS for s in seen)
        assert statuses == {r: "ok" for r in ROOTS}

    def test_the_writer_sees_the_scanned_root_and_every_root(self, monkeypatch, graph):
        _, client = graph
        self._run(monkeypatch, graph, {"beta.test": "10.0.2.1"})
        written = client.update_graph_from_shodan.call_args.kwargs["recon_data"]
        assert written["domain"] == "beta.test" and written["domains"] == ROOTS

    def test_a_root_without_ips_is_no_results_not_a_failure(self, monkeypatch, graph):
        statuses, seen = self._run(monkeypatch, graph, {"beta.test": "10.0.2.1"})
        assert statuses == {"alpha.test": "no_results", "beta.test": "ok", "gamma.test": "no_results"}
        assert [s[0] for s in seen] == ["beta.test"]

    def test_custom_ips_are_looked_up_once(self, monkeypatch, graph):
        _, seen = self._run(monkeypatch, graph, {r: "10.0.0.9" for r in ROOTS},
                            user_targets={"ips": ["203.0.113.5"], "ip_attach_to": None})
        with_ip = [s[0] for s in seen if "203.0.113.5" in s[2]["domain"]["ips"]["ipv4"]]
        assert with_ip == ["alpha.test"]

    def test_custom_ips_go_with_their_subdomains_root(self, monkeypatch, graph):
        _, seen = self._run(monkeypatch, graph, {r: "10.0.0.9" for r in ROOTS},
                            user_targets={"ips": ["203.0.113.5"], "ip_attach_to": "api.gamma.test"})
        with_ip = [s[0] for s in seen if "api.gamma.test" in s[2]["subdomains"]]
        assert with_ip == ["gamma.test"]


class TestOsintPerRoot:
    def test_each_root_is_enriched_separately(self, monkeypatch, graph):
        seen = []

        def otx(cr, settings):
            seen.append((cr["domain"], list(cr["domains"])))
            return {"ip_reports": [{"ip": "1.1.1.1"}]}

        monkeypatch.setattr(osint_enrichment, "_build_recon_data_from_graph",
                            MagicMock(side_effect=_builder_by_root({r: "10.0.0.9" for r in ROOTS})))
        with patch("recon.main_recon_modules.otx_enrich.run_otx_enrichment_isolated", side_effect=otx):
            statuses = osint_enrichment.run_osint_enrichment({**BASE, "_settings": {"OTX_ENABLED": True}})
        assert sorted(s[0] for s in seen) == ROOTS
        assert all(s[1] == ROOTS for s in seen)
        assert statuses == {r: "ok" for r in ROOTS}

    def test_no_enabled_source_is_no_results_for_every_root(self, monkeypatch, graph):
        statuses = osint_enrichment.run_osint_enrichment({**BASE, "_settings": {}})
        assert statuses == {r: "no_results" for r in ROOTS}

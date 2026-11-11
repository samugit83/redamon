"""The port/service security checks get what they need from both pipelines.

- run_security_checks takes the RoE exclusion list, since the port checks read
  IPs straight from the port scan; both callers pass it when RoE is on.
- Partial recon's vuln-scan builder carries no open ports, so the partial
  security-check run loads them from the graph's Port nodes; without them the
  port checks probe nothing.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import vuln_scan as vs  # noqa: E402
from recon.partial_recon_modules import graph_builders, vulnerability_scanning  # noqa: E402

ROOTS = ["alpha.test"]
BASE = {"_settings": {}, "domains": ROOTS, "domain": ROOTS[0]}


# --------------------------------------------------------------------------- #
# Full pipeline: run_vuln_scan forwards the RoE list to run_security_checks
# --------------------------------------------------------------------------- #
@pytest.fixture
def full_pipeline(monkeypatch):
    seen = {}

    def fake_security(**kwargs):
        seen.update(kwargs)
        return {"security_checks": {"findings": []}}

    monkeypatch.setattr(vs, "is_docker_installed", lambda: False)
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "run_security_checks", fake_security)
    return seen


def _vuln_settings(**extra):
    base = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "CVE_LOOKUP_ENABLED": False,
            "SECURITY_CHECK_ENABLED": True, "NUCLEI_MAX_RUNTIME": 0}
    base.update(extra)
    return base


class TestFullPipelineRoE:
    def test_the_exclusion_list_reaches_the_checks_when_roe_is_on(self, full_pipeline):
        vs.run_vuln_scan({"domain": "alpha.test", "http_probe": {"by_url": {}}},
                         settings=_vuln_settings(ROE_ENABLED=True,
                                                 ROE_EXCLUDED_HOSTS=["10.0.0.9"]))
        assert full_pipeline["roe_excluded_hosts"] == ["10.0.0.9"]

    @pytest.mark.parametrize("extra", [{}, {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": ["10.0.0.9"]},
                                       {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []}])
    def test_nothing_is_passed_without_an_active_list(self, full_pipeline, extra):
        vs.run_vuln_scan({"domain": "alpha.test", "http_probe": {"by_url": {}}},
                         settings=_vuln_settings(**extra))
        assert full_pipeline["roe_excluded_hosts"] is None


# --------------------------------------------------------------------------- #
# Partial pipeline
# --------------------------------------------------------------------------- #
class _Record(dict):
    pass


def _graph_module(rows=(), fail=False):
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    if fail:
        session.run.side_effect = RuntimeError("neo4j down")
    else:
        session.run.return_value = [_Record(r) for r in rows]
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.driver.session.return_value = session
    client.update_graph_from_vuln_scan.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    return module, session, client


class TestGraphOpenPorts:
    def test_returns_each_ips_open_ports_tenant_scoped(self, monkeypatch):
        module, session, _ = _graph_module([{"ip": "10.0.0.1", "ports": [6379, 22, 22]},
                                            {"ip": "10.0.0.2", "ports": []}])
        monkeypatch.setitem(sys.modules, "graph_db", module)
        out = graph_builders.graph_open_ports(["10.0.0.2", "10.0.0.1"], "u1", "p1")
        assert out == {"10.0.0.1": [22, 6379]}
        query, params = session.run.call_args.args[0], session.run.call_args.kwargs
        assert "{user_id: $uid, project_id: $pid}" in query
        assert params["uid"] == "u1" and params["pid"] == "p1"
        assert params["ips"] == ["10.0.0.1", "10.0.0.2"]

    def test_never_raises(self, monkeypatch):
        module, _, _ = _graph_module(fail=True)
        monkeypatch.setitem(sys.modules, "graph_db", module)
        assert graph_builders.graph_open_ports(["10.0.0.1"], "u1", "p1") == {}

    def test_no_ips_no_query(self, monkeypatch):
        module, session, _ = _graph_module()
        monkeypatch.setitem(sys.modules, "graph_db", module)
        assert graph_builders.graph_open_ports([], "u1", "p1") == {}
        session.run.assert_not_called()


def _partial_recon():
    return {
        "domain": ROOTS[0], "domains": ROOTS, "subdomains": [],
        "dns": {"domain": {"ips": {"ipv4": ["10.0.0.1"], "ipv6": []}, "has_records": True},
                "subdomains": {}},
        "http_probe": {"by_url": {}},
        "port_scan": {"by_ip": {"10.0.0.1": {"ip": "10.0.0.1", "hostnames": [], "ports": [],
                                             "is_cdn": False, "cdn": None, "asn": None}}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
        "metadata": {"include_root_domain": True},
    }


class TestPartialSecurityChecks:
    def _run(self, monkeypatch, settings, open_ports):
        module, _, _ = _graph_module()
        monkeypatch.setitem(sys.modules, "graph_db", module)
        monkeypatch.setattr(vulnerability_scanning, "_build_vuln_scan_data_from_graph",
                            MagicMock(return_value=_partial_recon()))
        monkeypatch.setattr(vulnerability_scanning, "partial_settings", lambda config: settings)
        loader = MagicMock(return_value=open_ports)
        monkeypatch.setattr(vulnerability_scanning, "graph_open_ports", loader)
        seen = {}

        def fake_security(**kwargs):
            seen.update(kwargs)
            seen["ports"] = {ip: list(e["ports"])
                             for ip, e in kwargs["recon_data"]["port_scan"]["by_ip"].items()}
            return {"security_checks": {"findings": []}}

        with patch("recon.helpers.run_security_checks", side_effect=fake_security):
            vulnerability_scanning.run_security_checks_partial(dict(BASE))
        return seen, loader

    def test_the_graphs_open_ports_reach_the_port_checks(self, monkeypatch):
        seen, loader = self._run(monkeypatch, {}, {"10.0.0.1": [6379, 6443]})
        assert loader.call_args.args[0] == ["10.0.0.1"]
        assert seen["ports"] == {"10.0.0.1": [6379, 6443]}

    def test_the_roe_list_reaches_the_checks(self, monkeypatch):
        seen, _ = self._run(monkeypatch, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["10.0.0.9"]}, {})
        assert seen["roe_excluded_hosts"] == ["10.0.0.9"]

    @pytest.mark.parametrize("ip_mode", [pytest.param(False, id="domain"), pytest.param(True, id="ip-mode")])
    def test_with_every_port_check_off_only_a_domain_run_loads_the_ports_as_web_evidence(
            self, monkeypatch, ip_mode):
        """A domain run's web checks probe only the web ports its data shows
        live (S-28), so the graph's open ports are loaded with every port
        check off too, and those checks stay off. IP mode loads them for the
        port checks alone."""
        if ip_mode:
            dict_ = _partial_recon()
            dict_["metadata"].update(ip_mode=True, expanded_ips=["10.0.0.1"])
            monkeypatch.setattr(sys.modules[__name__], "_partial_recon", lambda: dict_)
        port_checks = ("admin_port_exposed", "database_exposed", "redis_no_auth",
                       "kubernetes_api_exposed", "smtp_open_relay")
        off = {f"SECURITY_CHECK_{c.upper()}": False for c in port_checks}
        seen, loader = self._run(monkeypatch, off, {"10.0.0.1": [6379]})
        if ip_mode:
            loader.assert_not_called()
            assert seen["ports"] == {"10.0.0.1": []}
        else:
            assert loader.call_args.args[0] == ["10.0.0.1"]
            assert seen["ports"] == {"10.0.0.1": [6379]}
        assert not any(seen["enabled_checks"][c] for c in port_checks)
        assert seen["roe_excluded_hosts"] is None

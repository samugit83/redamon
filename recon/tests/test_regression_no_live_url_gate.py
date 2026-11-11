"""Regression: with no live HTTP URL, takeover and the port checks never ran (R-22).

`should_skip_active_scans` skips GROUP 5 and all of GROUP 6 Phase A when httpx
found no live URL. Two things in there need none:

  - Subdomain Takeover reads the names and their CNAMEs (Subjack, BadDNS), so a
    group of dangling names, the case it exists for, was the one never checked;
  - the port and service checks (admin and database ports, Redis without auth,
    SMTP open relay, Kubernetes API) read the port scan, so a database server
    with no web server (an IP-mode project on 6379) never got "Redis Without
    Authentication";
  - the org DNS checks (SPF, DMARC, DNSSEC, zone transfer) ask resolvers and
    nameservers, so a group with no live URL never re-checked its org.

And every source the skip stopped from running recorded nothing, so the prune
read "not reported" as "gone": their earlier findings were deleted. Now
takeover runs whenever it is on, `_maybe_run_port_checks` runs the port checks
in every skip branch (as `_maybe_run_cert_hygiene` does for the certificates),
and `_note_gate_skipped` keeps the skipped sources' findings on the group's
hosts. `_maybe_run_dns_checks` runs the org DNS checks there too, and the port
checks run under the same host-health scope as in the full path, so a host
down on :80 and :443 keeps its findings. A tool switched off by configuration
still prunes as before.

Every scanner, the Redis socket and Neo4j are fakes; run_ip_recon,
run_domain_recon, the port checks and the prune are real.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

import dns.resolver as dns_resolver  # noqa: E402
import dns.xfr as dns_xfr  # noqa: E402

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402

IP = "192.0.2.10"
NAME = "192-0-2-10"  # IP mode's placeholder name for an IP with no PTR
OTHER_IP = "198.51.100.40"

PORT_SCAN = {"scan_metadata": {"ports_config": "6379"}, "by_host": {}, "all_ports": [6379],
             "summary": {}, "ip_to_hostnames": {},
             "by_ip": {IP: {"ip": IP, "hostnames": [], "ports": [6379], "port_details": []}}}
NO_LIVE_URL = {"by_url": {}, "by_host": {}, "summary": {"live_urls": 0, "total_hosts": 0}}

# A database server: naabu finds 6379, httpx finds nothing. Only the phases
# under test run.
SETTINGS = {
    "DNS_ENABLED": False, "WHOIS_ENABLED": False, "SHODAN_ENABLED": False,
    "NAABU_ENABLED": True, "MASSCAN_ENABLED": False, "NMAP_ENABLED": False,
    "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False, "UNCOVER_ENABLED": False,
    "HTTPX_ENABLED": True, "IP_ATTRIBUTION_ENABLED": False, "URLSCAN_ENABLED": False,
    "SECURITY_CHECK_ENABLED": True,
    "SECURITY_CHECK_ADMIN_PORT_EXPOSED": True, "SECURITY_CHECK_DATABASE_EXPOSED": True,
    "SECURITY_CHECK_REDIS_NO_AUTH": True, "SECURITY_CHECK_KUBERNETES_API_EXPOSED": True,
    "SECURITY_CHECK_SMTP_OPEN_RELAY": True,
    "AI_SURFACE_RECON_ENABLED": False, "JS_RECON_ENABLED": False,
    "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROUTE_EXPOSURE_ENABLED": False, "ROE_ENABLED": False,
}
SCAN_MODULES = ["port_scan", "http_probe", "resource_enum", "vuln_scan"]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': [IP],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': list(SCAN_MODULES),
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", list(SCAN_MODULES))
        yield rm


class _Redis:
    """The Redis socket: answers PING with PONG, and logs where it was opened."""

    def __init__(self, opened):
        self.opened = opened

    def __call__(self, address, timeout=None):
        self.opened.append(address)
        return self

    def send(self, data):
        assert data == b"PING\r\n"

    def recv(self, _size):
        return b"+PONG\r\n"

    def close(self):
        pass


class _Run:
    """One pipeline run with the scanners faked; what it probed, ran and queued."""

    def __init__(self, rm, monkeypatch):
        self.rm = rm
        self.opened, self.queued, self.takeover, self.nuclei, self.phase_a = [], [], [], [], []
        monkeypatch.setattr(sc.socket, "create_connection", _Redis(self.opened))
        monkeypatch.setattr(rm, "run_port_scan_isolated", lambda *a, **k: _copy(PORT_SCAN))
        monkeypatch.setattr(rm, "run_http_probe", self._httpx)
        monkeypatch.setattr(rm, "run_vuln_scan", self._nuclei)
        monkeypatch.setattr(rm, "run_resource_enum", self._nuclei)
        monkeypatch.setattr(st, "run_subdomain_takeover", self._takeover)
        monkeypatch.setattr(rm, "_graph_update_bg",
                            lambda name, data, *a: self.queued.append((name, _copy(data))))

    @staticmethod
    def _httpx(combined, output_file=None, settings=None):
        combined["http_probe"] = _copy(NO_LIVE_URL)
        return combined

    def _nuclei(self, combined, output_file=None, settings=None):
        self.nuclei.append(1)
        return combined

    def _takeover(self, snapshot, output_file=None, settings=None):
        self.takeover.append(sorted((snapshot.get("dns") or {}).get("subdomains") or {}))
        snapshot["subdomain_takeover"] = {"findings": [], "summary": {"total": 0}}
        return snapshot

    def queued_names(self):
        return [name for name, _ in self.queued]

    def security_findings(self):
        found = []
        for name, data in self.queued:
            if name == "update_graph_from_vuln_scan":
                found = ((data.get("vuln_scan") or {}).get("security_checks") or {}).get("findings")
        return found or []


def _copy(value):
    import copy
    return copy.deepcopy(value)


def _ip_run(rm, monkeypatch, **settings):
    run = _Run(rm, monkeypatch)
    run.result = rm.run_ip_recon([IP], dict(SETTINGS, **settings))
    return run


class TestRegressionNoLiveUrl:
    def test_the_skip_still_fires(self, recon_main, monkeypatch):
        run = _ip_run(recon_main, monkeypatch)
        assert run.result["metadata"]["active_scans_skipped"] is True
        assert run.nuclei == []  # nuclei and resource enumeration have nothing to read

    def test_regression_redis_without_auth_is_found_with_no_web_server(self, recon_main,
                                                                        monkeypatch):
        run = _ip_run(recon_main, monkeypatch)
        assert run.opened == [(IP, 6379)]
        found = {(f["type"], f.get("ip"), f.get("port")) for f in run.security_findings()}
        assert ("redis_no_auth", IP, 6379) in found
        assert ("database_exposed", IP, 6379) in found
        assert "update_graph_from_vuln_scan" in run.queued_names()
        stored = run.result["vuln_scan"]["security_checks"]
        assert stored["summary"]["total_findings"] == len(stored["findings"]) == 2

    def test_regression_takeover_never_ran_with_no_live_url(self, recon_main, monkeypatch):
        run = _ip_run(recon_main, monkeypatch)
        assert run.takeover == [[NAME]]
        assert "update_graph_from_subdomain_takeover" in run.queued_names()
        assert "subdomain_takeover" in run.result["metadata"]["modules_executed"]

    def test_regression_the_skipped_sources_were_pruned(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch, GRAPHQL_SECURITY_ENABLED=True, VHOST_SNI_ENABLED=True,
                WEB_CACHE_POISON_ENABLED=True, ORIGIN_DISCOVERY_ENABLED=True,
                ROUTE_EXPOSURE_ENABLED=True)
        report = cb.coverage_report()
        for source in ("nuclei", "vuln_scan", "resource_enum", "jsluice", "url_archive",
                       "graphql_scan", "graphql_cop", "vhost_sni_enum", "cache_poisoning",
                       "wcvs", "origin_discovery", "route_exposure"):
            assert set(report.keep_hostnames(source)) == {IP, NAME}, source
        # By host, never the whole source: a Domain batch's groups that had live
        # URLs still prune them.
        assert not report.degraded_sources
        # Takeover ran, and the sources that ran are not kept.
        for source in ("takeover_scan", "js_recon", "http_probe", "nmap_nse"):
            assert report.keep_hostnames(source) == (), source


class TestSecurityCheckCoverage:
    def test_the_port_checks_record_what_they_checked(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch)
        report = cb.coverage_report()
        assert report.checked_hostnames("security_check", "redis_no_auth") == (IP,)
        assert report.checked_hostnames("security_check", "smtp_open_relay") == (IP,)
        # The checks that need a web server are kept on the group's names; the
        # address the port checks just read is theirs to prune.
        assert report.keep_hostnames("security_check") == (NAME,)

    def test_the_prune_keeps_the_skipped_and_prunes_the_checked(self, recon_main, monkeypatch):
        rm = recon_main
        _ip_run(rm, monkeypatch)
        prunes = []

        class _Graph:
            def __call__(self, *a, **k):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def verify_connection(self):
                return True

            def backfill_passive_cve_hosts(self, *a):
                return 0

            def backfill_security_check_domains(self, *a):
                return 0

            def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(),
                                      **kw):
                prunes.append((sorted(sources), tuple(keep_hosts), kw))

        monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", True)
        monkeypatch.setattr(rm, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
        monkeypatch.setattr(rm, "_COVERAGE_WRITE_FAILED", False)
        rm._prune_recon_findings()
        nuclei = [keep for sources, keep, _ in prunes if "nuclei" in sources]
        assert nuclei and all(set(keep) == {IP, NAME} for keep in nuclei)
        redis = [kw for sources, _, kw in prunes
                 if sources == ["security_check"] and kw.get("types") == ("redis_no_auth",)]
        assert redis == [{"only_hosts": (IP,), "types": ("redis_no_auth",)}]


class TestSwitchedOffByConfiguration:
    def test_security_checks_off_send_no_probe_and_keep_nothing(self, recon_main, monkeypatch):
        run = _ip_run(recon_main, monkeypatch, SECURITY_CHECK_ENABLED=False)
        assert run.opened == [] and run.security_findings() == []
        assert cb.coverage_report().keep_hostnames("security_check") == ()

    def test_a_probe_turned_off_is_not_sent(self, recon_main, monkeypatch):
        run = _ip_run(recon_main, monkeypatch, SECURITY_CHECK_REDIS_NO_AUTH=False)
        assert run.opened == []
        assert {f["type"] for f in run.security_findings()} == {"database_exposed"}

    def test_takeover_off_does_not_run(self, recon_main, monkeypatch):
        run = _ip_run(recon_main, monkeypatch, SUBDOMAIN_TAKEOVER_ENABLED=False)
        assert run.takeover == []

    def test_a_phase_a_tool_off_prunes_as_before(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch)
        report = cb.coverage_report()
        for source in ("graphql_scan", "vhost_sni_enum", "cache_poisoning", "origin_discovery",
                       "route_exposure"):
            assert report.keep_hostnames(source) == (), source

    def test_vuln_scan_out_of_the_modules_keeps_nothing_of_it(self, recon_main, monkeypatch):
        monkeypatch.setattr(recon_main, "SCAN_MODULES", ["port_scan", "http_probe"])
        run = _ip_run(recon_main, monkeypatch)
        assert run.opened == []
        report = cb.coverage_report()
        assert report.keep_hostnames("nuclei") == ()
        assert report.keep_hostnames("security_check") == ()

    def test_with_a_live_url_nothing_is_kept(self, recon_main, monkeypatch):
        run = _Run(recon_main, monkeypatch)

        def live(combined, output_file=None, settings=None):
            combined["http_probe"] = {"by_url": {f"http://{IP}:6379": {}},
                                      "summary": {"live_urls": 1, "total_hosts": 1}}
            return combined

        monkeypatch.setattr(recon_main, "run_http_probe", live)
        recon_main.run_ip_recon([IP], dict(SETTINGS))
        assert run.nuclei == [1, 1]  # resource enumeration, then nuclei
        assert run.takeover == [[NAME]]
        assert cb.coverage_report().keep_hostnames("nuclei") == ()


class TestNewTrafficRules:
    """The port checks send only what they send in the full path."""

    def _result(self):
        return {"metadata": {"modules_executed": []}, "dns": {"domain": {}, "subdomains": {}},
                "port_scan": _copy(PORT_SCAN)}

    def test_an_roe_excluded_address_is_never_probed(self, recon_main, monkeypatch, tmp_path):
        opened = []
        monkeypatch.setattr(sc.socket, "create_connection", _Redis(opened))
        monkeypatch.setattr(recon_main, "_graph_update_bg", lambda *a: None)
        out = recon_main._maybe_run_port_checks(
            self._result(), dict(SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[IP]),
            tmp_path / "r.json")
        assert opened == []
        assert "vuln_scan" not in out

    def test_stealth_mode_sends_no_probe(self, recon_main, monkeypatch, tmp_path):
        from recon.project_settings import apply_stealth_overrides
        opened = []
        monkeypatch.setattr(sc.socket, "create_connection", _Redis(opened))
        monkeypatch.setattr(recon_main, "_graph_update_bg", lambda *a: None)
        stealth = apply_stealth_overrides(dict(SETTINGS, STEALTH_MODE=True))
        assert stealth["SECURITY_CHECK_REDIS_NO_AUTH"] is False
        recon_main._maybe_run_port_checks(self._result(), stealth, tmp_path / "r.json")
        assert opened == []

    def test_a_crash_keeps_security_check_and_never_stops_the_scan(self, recon_main,
                                                                   monkeypatch, tmp_path):
        monkeypatch.setattr(sc, "run_port_service_checks",
                            mock.Mock(side_effect=RuntimeError("boom")))
        out = recon_main._maybe_run_port_checks(self._result(), dict(SETTINGS),
                                                tmp_path / "r.json")
        assert "port_checks" in out["metadata"]["phase_errors"]
        assert "security_check" in cb.coverage_report().degraded_sources

    def test_port_findings_join_the_certificate_findings(self, recon_main, monkeypatch, tmp_path):
        monkeypatch.setattr(sc.socket, "create_connection", _Redis([]))
        monkeypatch.setattr(recon_main, "_graph_update_bg", lambda *a: None)
        result = self._result()
        result["vuln_scan"] = {"security_checks": {
            "findings": [{"type": "tls_expired", "severity": "high", "hostname": "a.example.com"}],
            "checks_enabled": {"tls_expired": True}}}
        out = recon_main._maybe_run_port_checks(result, dict(SETTINGS), tmp_path / "r.json")
        types = sorted(f["type"] for f in out["vuln_scan"]["security_checks"]["findings"])
        assert types == ["database_exposed", "redis_no_auth", "tls_expired"]


class TestTheCoverageNotes:
    def test_every_note_has_a_token_shaped_source_and_module(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch, GRAPHQL_SECURITY_ENABLED=True, WEB_CACHE_POISON_ENABLED=True)
        gaps = cb.coverage_report().gaps
        assert gaps
        for gap in gaps:
            assert TOKEN.match(gap["source"]) and TOKEN.match(gap["module"]), gap
            assert "no live" in gap["reason"]

    def test_no_host_means_no_note(self, recon_main):
        recon_main._note_gate_skipped({"metadata": {}, "dns": {}}, dict(SETTINGS))
        assert not cb.coverage_report().degraded

    def test_the_legacy_path_notes_no_phase_a_tool(self, recon_main):
        # It never runs Phase A, and keeps those sources whole already.
        result = {"metadata": {}, "dns": {}, "port_scan": _copy(PORT_SCAN)}
        recon_main._note_gate_skipped(result, dict(SETTINGS, GRAPHQL_SECURITY_ENABLED=True),
                                      phase_a=False)
        report = cb.coverage_report()
        assert report.keep_hostnames("nuclei") == (IP,)
        assert report.keep_hostnames("graphql_scan") == ()

    def test_a_fault_keeps_the_sources_whole(self, recon_main, monkeypatch):
        monkeypatch.setattr(recon_main, "_gate_skip_hosts", mock.Mock(side_effect=KeyError("x")))
        recon_main._note_gate_skipped({}, dict(SETTINGS))
        assert {"nuclei", "security_check", "resource_enum"} <= cb.coverage_report().degraded_sources

    def test_every_phase_a_tool_that_needs_a_live_url_is_listed(self, recon_main):
        source = (PROJECT_ROOT / "recon" / "main.py").read_text()
        added = dict(re.findall(
            r"_?settings\.get\('(\w+)', False\):\n\s+from [\w.]+ import \w+\n"
            r"\s+(?:phase_a_tools|ip_phase_a)\['(\w+)'\]", source))
        tools = {tool: key for key, tool in added.items()}
        assert set(tools) - {"subdomain_takeover"} == set(recon_main._LIVE_URL_PHASE_A)
        for tool, key in recon_main._LIVE_URL_PHASE_A.items():
            assert tools[tool] == key
            assert tool in recon_main._PHASE_FINDING_SOURCES


class _Rdata:
    def __init__(self, text):
        self.text = self.target = self.address = text

    def __str__(self):
        return self.text

    def to_text(self):
        return self.text


#: The org's DNS: no SPF record, DMARC and DNSSEC in place, one nameserver.
ORG = "example.com"
NS = f"ns1.{ORG}"
NS_IP = "198.51.100.53"
ORG_DNS = {
    (ORG, "TXT"): dns_resolver.NoAnswer,
    (f"_dmarc.{ORG}", "TXT"): ['"v=DMARC1; p=reject"'],
    (ORG, "DNSKEY"): ["257 3 13 AAAA"],
    (ORG, "NS"): [f"{NS}."],
    (NS, "A"): [NS_IP],
    (NS, "AAAA"): dns_resolver.NoAnswer,
}


class _Dns:
    """dns.resolver.resolve and the zone transfer, faked; what each was asked."""

    def __init__(self, monkeypatch, table=None):
        self.table, self.asked, self.transfers = dict(table or ORG_DNS), [], []
        monkeypatch.setattr(sc.dns.resolver, "resolve", self.resolve)
        monkeypatch.setattr(sc.dns.query, "xfr", self.xfr)
        monkeypatch.setattr(sc.dns.zone, "from_xfr", self.from_xfr)

    def resolve(self, name, rtype, *a, **k):
        self.asked.append((str(name), rtype))
        outcome = self.table.get((str(name), rtype), dns_resolver.NXDOMAIN)
        if isinstance(outcome, type) and issubclass(outcome, BaseException):
            raise outcome()
        return [_Rdata(t) for t in outcome]

    def xfr(self, where, zone, *a, **k):
        self.transfers.append((where, str(zone)))
        return where

    @staticmethod
    def from_xfr(_where, *a, **k):
        raise dns_xfr.TransferError(5)  # refused: a verdict, clean


def _domain_main(tmp_path, monkeypatch, **settings):
    with mock.patch('recon.project_settings.get_settings', return_value={
            'TARGET_DOMAIN': ORG, 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
            'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
            'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': list(SCAN_MODULES),
            'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': ''}):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    from recon.main_recon_modules import domain_recon
    monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(rm, "SCAN_MODULES", list(SCAN_MODULES))
    monkeypatch.setattr(rm, "_settings", dict(SETTINGS, DNS_ENABLED=True, **settings))
    monkeypatch.setattr(domain_recon, "resolve_all_dns", lambda root, subs, **k: {
        "domain": {}, "subdomains": {f"db.{ORG}": {
            "has_records": True, "ips": {"ipv4": [IP], "ipv6": []},
            "records": {"A": [IP]}}}})
    return rm


def _domain_run(tmp_path, monkeypatch, table=None, **settings):
    rm = _domain_main(tmp_path, monkeypatch, **settings)
    run, dns = _Run(rm, monkeypatch), _Dns(monkeypatch, table)
    target_info = rm.parse_target(ORG, ["db."])
    run.result = rm.run_domain_recon(ORG, target_info=target_info, discovery_enabled=False)
    return run, dns


class TestDomainMode:
    def test_regression_takeover_and_port_checks_run_with_no_live_url(self, tmp_path,
                                                                      monkeypatch):
        run, _ = _domain_run(tmp_path, monkeypatch)
        assert run.result["metadata"]["active_scans_skipped"] is True
        assert run.nuclei == []
        assert run.takeover == [[f"db.{ORG}"]]
        assert run.opened == [(IP, 6379)]
        assert "redis_no_auth" in {f["type"] for f in run.security_findings()}
        assert set(cb.coverage_report().keep_hostnames("nuclei")) == {IP, f"db.{ORG}"}


class TestDownHosts:
    def test_regression_a_host_down_on_80_and_443_lost_its_port_findings(self, recon_main,
                                                                         monkeypatch):
        # Down on both web ports: run_port_service_checks skips it, as in the
        # full path, where run_security_checks' scope records it as skipped.
        monkeypatch.setattr(cb.host_health, "is_down", lambda target: IP in str(target))
        run = _ip_run(recon_main, monkeypatch)
        assert run.opened == []
        report = cb.coverage_report()
        assert IP in report.keep_hostnames("security_check")
        assert any(g["source"] == "security_check" and g["module"] == "security_checks"
                   for g in report.gaps)
        assert report.checked_hostnames("security_check", "redis_no_auth") == ()

    def test_a_host_that_is_up_records_nothing_skipped(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch)
        assert IP not in cb.coverage_report().keep_hostnames("security_check")

    def test_the_scope_is_closed_after_the_run(self, recon_main, monkeypatch):
        _ip_run(recon_main, monkeypatch)
        assert sc._HH_SCOPE is None

    def test_the_scope_is_closed_after_a_crash(self, monkeypatch):
        monkeypatch.setattr(sc, "run_port_service_checks", mock.Mock(side_effect=RuntimeError("boom")))
        with pytest.raises(RuntimeError):
            sc.run_port_checks_only({"port_scan": _copy(PORT_SCAN)}, {"redis_no_auth": True})
        assert sc._HH_SCOPE is None


class TestOrgDnsChecks:
    def test_regression_the_org_dns_checks_never_ran_with_no_live_url(self, tmp_path,
                                                                      monkeypatch):
        from recon.helpers.org_work import claimed_orgs
        run, dns = _domain_run(tmp_path, monkeypatch)
        found = {(f["type"], f.get("domain")) for f in run.security_findings()}
        assert ("spf_missing", ORG) in found
        assert {(ORG, "TXT"), (f"_dmarc.{ORG}", "TXT"), (ORG, "DNSKEY"), (ORG, "NS")} <= set(dns.asked)
        assert dns.transfers == [(NS_IP, ORG)]
        report = cb.coverage_report()
        for check in ("spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer"):
            assert report.checked_hostnames("security_check", check) == (ORG,), check
        # Claimed: the prune's unchecked-org rule no longer keeps them.
        assert claimed_orgs("dns_checks") == [ORG]

    def test_a_clean_org_writes_no_dns_finding_and_still_counts_as_checked(self, tmp_path,
                                                                           monkeypatch):
        table = {**ORG_DNS, (ORG, "TXT"): ['"v=spf1 -all"']}
        run, _ = _domain_run(tmp_path, monkeypatch, table)
        assert not {f["type"] for f in run.security_findings()} & {
            "spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer"}
        assert cb.coverage_report().checked_hostnames("security_check", "spf_missing") == (ORG,)

    def test_stealth_sends_no_zone_transfer(self, tmp_path, monkeypatch):
        from recon.project_settings import apply_stealth_overrides
        stealth = apply_stealth_overrides(dict(SETTINGS, STEALTH_MODE=True,
                                               SECURITY_CHECK_ZONE_TRANSFER=True))
        assert stealth["SECURITY_CHECK_ZONE_TRANSFER"] is False
        run, dns = _domain_run(tmp_path, monkeypatch, STEALTH_MODE=True,
                               SECURITY_CHECK_ZONE_TRANSFER=False)
        assert dns.transfers == [] and (ORG, "NS") not in dns.asked
        assert (ORG, "TXT") in dns.asked

    def test_an_roe_excluded_nameserver_is_never_asked(self, tmp_path, monkeypatch):
        run, dns = _domain_run(tmp_path, monkeypatch, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[NS])
        assert dns.transfers == []
        assert (NS, "A") not in dns.asked
        # No verdict: the org's earlier zone transfer finding is kept.
        assert cb.coverage_report().checked_hostnames("security_check", "zone_transfer") == ()

    def test_an_roe_excluded_org_gets_no_dns_check(self, recon_main, monkeypatch, tmp_path):
        dns = _Dns(monkeypatch)
        monkeypatch.setattr(recon_main, "_graph_update_bg", lambda *a: None)
        result = {"domain": ORG, "metadata": {"org_domain": ORG}, "dns": {}}
        recon_main._maybe_run_dns_checks(
            result, dict(SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[ORG]), tmp_path / "r.json")
        assert dns.asked == []

    def test_dns_checks_switched_off_send_nothing(self, tmp_path, monkeypatch):
        off = {f"SECURITY_CHECK_{t.upper()}": False for t in sc.DNS_CHECK_TYPES}
        run, dns = _domain_run(tmp_path, monkeypatch, **off)
        assert dns.asked == []

    def test_ip_mode_has_no_org_to_check(self, recon_main, monkeypatch):
        dns = _Dns(monkeypatch)
        _ip_run(recon_main, monkeypatch)
        assert dns.asked == []

    def test_an_org_already_checked_this_run_is_not_checked_again(self, recon_main,
                                                                  monkeypatch, tmp_path):
        from recon.helpers.org_work import claim_org
        claim_org("dns_checks", ORG)
        dns = _Dns(monkeypatch)
        result = {"domain": ORG, "metadata": {"org_domain": ORG}, "dns": {}}
        recon_main._maybe_run_dns_checks(result, dict(SETTINGS), tmp_path / "r.json")
        assert dns.asked == []

    def test_the_checked_org_prunes_its_own_dns_findings(self, recon_main):
        # The apex is a target and the org: the DNS checks re-checked it, so
        # security_check keeps no finding there; its address stays kept.
        from recon.helpers.org_work import claim_org
        claim_org("dns_checks", ORG)
        result = {"domain": ORG, "metadata": {"include_root_domain": True, "org_domain": ORG},
                  "dns": {"domain": {"ips": {"ipv4": [OTHER_IP], "ipv6": []}}, "subdomains": {}}}
        recon_main._note_gate_skipped(result, dict(SETTINGS))
        report = cb.coverage_report()
        assert report.keep_hostnames("security_check") == (OTHER_IP,)
        assert set(report.keep_hostnames("nuclei")) == {ORG, OTHER_IP}

    def test_a_crash_keeps_security_check_whole(self, recon_main, monkeypatch, tmp_path):
        monkeypatch.setattr(sc, "run_dns_checks_only", mock.Mock(side_effect=RuntimeError("boom")))
        result = {"domain": ORG, "metadata": {"org_domain": ORG}, "dns": {}}
        out = recon_main._maybe_run_dns_checks(result, dict(SETTINGS), tmp_path / "r.json")
        assert "dns_checks" in out["metadata"]["phase_errors"]
        assert "security_check" in cb.coverage_report().degraded_sources

    def test_dns_findings_join_the_port_findings(self, tmp_path, monkeypatch):
        run, _ = _domain_run(tmp_path, monkeypatch)
        stored = run.result["vuln_scan"]["security_checks"]
        types = {f["type"] for f in stored["findings"]}
        assert {"redis_no_auth", "database_exposed", "spf_missing"} <= types
        assert stored["summary"]["total_findings"] == len(stored["findings"])


def _skip_branches():
    tree = ast.parse((PROJECT_ROOT / "recon" / "main.py").read_text())
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name)
            and node.test.id == "skip_active_scans"]


def test_every_skip_branch_runs_the_port_checks_and_keeps_what_it_skipped():
    branches = _skip_branches()
    assert len(branches) == 3
    for branch in branches:
        called = {node.func.id for stmt in branch.body for node in ast.walk(stmt)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        assert {"_maybe_run_port_checks", "_maybe_run_dns_checks",
                "_note_gate_skipped"} <= called, branch.lineno

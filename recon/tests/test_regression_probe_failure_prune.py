"""Regression: a tlsx or httpx failure read as "nothing found" (R-21).

tlsx is the only certificate source for a non-HTTP TLS port (993, 636, 8883),
and the TLS-hygiene findings (`source: security_check`) are built from its
answer. When tlsx timed out, its partial output was thrown away; when its runner
was missing or it exited with nothing, the run carried an empty answer and noted
no gap. Either way the prune read the missing `tls_expired` as "fixed" and
deleted it.

httpx returned silently when Docker was missing, the image pull failed, the probe
exited with nothing or raised. The pipeline still listed `http_probe` as
executed, and with no `http_probe` payload the live-URL gate saw nothing to
skip: GROUP 5 and Phase A ran on an empty URL list, so nuclei, the security
checks and graphql reported nothing and their findings were pruned.

Now tlsx parses what it got before the timeout and keeps its security_check
findings on every target it did not answer; httpx records the failure (a phase
error and a degraded `http_probe`), the gate skips the scanners that need a
probed URL and keeps their findings by host, and `modules_executed` lists only
the probes that ran.

Only subprocess / docker I/O, the port scan and the Phase A scanners are fakes;
run_tlsx_enrichment, run_http_probe, run_ip_recon, run_domain_recon, the gate
and the prune are real.
"""
from __future__ import annotations

import copy
import inspect
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402
from recon.main_recon_modules import http_probe as hp  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402
from recon.main_recon_modules import tls_scan  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

IP = "192.0.2.10"
NAME = "192-0-2-10"  # IP mode's placeholder name for an IP with no PTR
OTHER_IP = "198.51.100.40"
MAIL = "mail.example.com"

# --------------------------------------------------------------------------- #
# tlsx
# --------------------------------------------------------------------------- #
# Two targets: a name on 993 that serves an expired certificate, and a bare
# address on 636. The target builder is fixed so the private-target skip does
# not decide which documentation address is scanned.
TLSX_LINES = [f"{MAIL}:993", f"{OTHER_IP}:636"]
TLSX_META = {f"{MAIL}:993": IP, f"{OTHER_IP}:636": OTHER_IP}
EXPIRED_ROW = json.dumps({
    "host": MAIL, "ip": IP, "port": "993", "probe_status": True,
    "tls_version": "tls12", "cipher": "TLS_AES_128_GCM_SHA256",
    "subject_cn": MAIL, "subject_an": [MAIL], "subject_dn": f"CN={MAIL}",
    "issuer_dn": "CN=Lab CA", "issuer_cn": "Lab CA",
    "not_before": "2020-01-01T00:00:00Z", "not_after": "2021-01-01T00:00:00Z",
    "fingerprint_hash": {"sha256": "ab" * 32},
})
LDAPS_ROW = json.dumps({
    "host": OTHER_IP, "ip": OTHER_IP, "port": "636", "probe_status": True,
    "tls_version": "tls13", "subject_cn": "ldap.example.com",
    "subject_an": ["ldap.example.com"], "not_after": "2099-01-01T00:00:00Z",
    "fingerprint_hash": {"sha256": "cd" * 32},
})


class _Proc:
    """subprocess.Popen for the docker CLI: each communicate() takes the next step."""

    def __init__(self, *steps, returncode=0):
        self.steps, self.returncode, self.killed = list(steps), returncode, False

    def communicate(self, timeout=None):
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return self.returncode


def _tlsx_combined():
    return {"metadata": {}, "port_scan": {
        "by_ip": {IP: {"ip": IP, "hostnames": [MAIL], "ports": [993]},
                  OTHER_IP: {"ip": OTHER_IP, "hostnames": [], "ports": [636]}},
        "by_host": {}}}


def _tlsx(monkeypatch, popen, settings=None, isolated=False):
    monkeypatch.setattr(tls_scan, "_build_tlsx_targets",
                        lambda combined, s: (list(TLSX_LINES), dict(TLSX_META)))
    monkeypatch.setattr(tls_scan.subprocess, "Popen", popen)
    combined = _tlsx_combined()
    if isolated:
        return combined, tls_scan.run_tlsx_enrichment_isolated(combined, settings or {})
    return tls_scan.run_tlsx_enrichment(combined, settings or {})


def _security_keep():
    return set(cb.coverage_report().keep_hostnames("security_check"))


class TestTlsxFailure:
    def test_regression_a_timeout_threw_away_what_tlsx_had_answered(self, monkeypatch):
        proc = _Proc(subprocess.TimeoutExpired("docker", 5), (EXPIRED_ROW + "\n", ""))
        out = _tlsx(monkeypatch, mock.Mock(return_value=proc), {"TLSX_RUN_TIMEOUT": 5})
        assert proc.killed
        cert = out["tlsx"]["by_target"][f"{IP}:993"]
        assert cert["expired"] is True and cert["host"] == MAIL
        # The partial answer still makes its finding.
        found = sc.run_tls_data_checks(out, {})
        assert ("tls_expired", MAIL) in {(f["type"], f.get("hostname")) for f in found}
        meta = out["tlsx"]["scan_metadata"]
        assert meta["timed_out"] is True and meta["unchecked_targets"] == 1

    def test_regression_a_timeout_pruned_the_targets_tlsx_never_reached(self, monkeypatch):
        proc = _Proc(subprocess.TimeoutExpired("docker", 5), (EXPIRED_ROW + "\n", ""))
        _tlsx(monkeypatch, mock.Mock(return_value=proc), {"TLSX_RUN_TIMEOUT": 5})
        report = cb.coverage_report()
        # Kept on the target it never answered, for security_check alone; the
        # answered one prunes as on a clean run.
        assert _security_keep() == {OTHER_IP}
        assert report.keep_hostnames("nuclei") == ()
        assert not report.degraded_sources
        assert any(g["source"] == "security_check" and g["module"] == "tlsx"
                   for g in report.gaps)

    def test_regression_a_missing_runner_read_as_no_certificate(self, monkeypatch):
        out = _tlsx(monkeypatch, mock.Mock(side_effect=FileNotFoundError("docker")))
        assert _security_keep() == {MAIL, OTHER_IP}
        assert out["tlsx"]["by_target"] == {}
        assert "tlsx" in out["metadata"]["phase_errors"]
        assert out["tlsx"]["scan_metadata"]["error"]

    def test_regression_an_exit_with_no_output_read_as_no_certificate(self, monkeypatch):
        proc = _Proc(("", "docker: Error response from daemon"), returncode=125)
        out = _tlsx(monkeypatch, mock.Mock(return_value=proc))
        assert _security_keep() == {MAIL, OTHER_IP}
        assert "125" in out["metadata"]["phase_errors"]["tlsx"]

    def test_regression_a_write_failure_kept_nothing(self, monkeypatch):
        def full_disk(self, *a, **k):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(tls_scan.Path, "write_text", full_disk)
        out = _tlsx(monkeypatch, mock.Mock(side_effect=AssertionError("never started")))
        assert _security_keep() == {MAIL, OTHER_IP}
        assert "tlsx" in out["metadata"]["phase_errors"]

    def test_a_crash_before_the_targets_are_known_keeps_the_whole_source(self, monkeypatch):
        def boom(combined, settings):
            raise RuntimeError("malformed port data")

        monkeypatch.setattr(tls_scan, "_build_tlsx_targets", boom)
        out = tls_scan.run_tlsx_enrichment(_tlsx_combined(), {})
        assert "security_check" in cb.coverage_report().degraded_sources
        assert "tlsx" in out["metadata"]["phase_errors"]

    def test_the_isolated_wrapper_carries_the_failure(self, monkeypatch):
        combined, payload = _tlsx(monkeypatch, mock.Mock(side_effect=FileNotFoundError("x")),
                                  isolated=True)
        assert payload["scan_metadata"]["error"]
        assert payload["scan_metadata"]["unchecked_targets"] == 2
        assert _security_keep() == {MAIL, OTHER_IP}
        assert combined == _tlsx_combined()

    def test_a_clean_run_keeps_nothing(self, monkeypatch):
        proc = _Proc((EXPIRED_ROW + "\n" + LDAPS_ROW + "\n", ""))
        out = _tlsx(monkeypatch, mock.Mock(return_value=proc))
        assert not cb.coverage_report().degraded
        assert "phase_errors" not in out["metadata"]
        assert "timed_out" not in out["tlsx"]["scan_metadata"]

    def test_a_target_tlsx_answered_with_a_failed_handshake_is_checked(self, monkeypatch):
        refused = json.dumps({"host": OTHER_IP, "ip": OTHER_IP, "port": "636",
                              "probe_status": False, "error": "connection refused"})
        proc = _Proc(subprocess.TimeoutExpired("docker", 5),
                     (EXPIRED_ROW + "\n" + refused + "\n", ""))
        _tlsx(monkeypatch, mock.Mock(return_value=proc), {"TLSX_RUN_TIMEOUT": 5})
        assert not cb.coverage_report().degraded

    def test_no_eligible_target_is_not_a_gap(self, monkeypatch):
        popen = mock.Mock(side_effect=AssertionError("nothing to scan"))
        monkeypatch.setattr(tls_scan.subprocess, "Popen", popen)
        out = tls_scan.run_tlsx_enrichment({"metadata": {}, "port_scan": {"by_ip": {}}}, {})
        assert out["tlsx"]["summary"]["targets"] == 0
        assert not cb.coverage_report().degraded
        assert "phase_errors" not in out["metadata"]

    def test_the_tlsx_command_is_unchanged(self, monkeypatch):
        proc = _Proc((EXPIRED_ROW + "\n" + LDAPS_ROW + "\n", ""))
        popen = mock.Mock(return_value=proc)
        _tlsx(monkeypatch, popen)
        (cmd,), _ = popen.call_args
        targets_file = cmd[cmd.index("-l") + 1]
        # The name a timeout kills the container by (R-9) differs per run.
        i = cmd.index("--name")
        assert cmd[i + 1].startswith("tlsx-")
        cmd = cmd[:i] + cmd[i + 2:]
        assert cmd == tls_scan.build_tlsx_command(targets_file, str(Path(targets_file).parent), {})


# --------------------------------------------------------------------------- #
# httpx
# --------------------------------------------------------------------------- #
class _Docker:
    """The docker CLI as run_http_probe calls it, with one failure switched on."""

    def __init__(self, monkeypatch, *, installed=True, running=True, pull_ok=True,
                 popen=None):
        self.calls = []
        self.pull_ok, self.running = pull_ok, running
        which = hp.shutil.which
        monkeypatch.setattr(hp.shutil, "which",
                            lambda name, *a, **k: ("/usr/bin/docker" if installed else None)
                            if name == "docker" else which(name, *a, **k))
        monkeypatch.setattr(hp.subprocess, "run", self.run)
        self.popen = popen or mock.Mock(side_effect=AssertionError("httpx never starts"))
        monkeypatch.setattr(hp.subprocess, "Popen", self.popen)

    def run(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(cmd, 0 if self.running else 1, "", "")
        if cmd[:2] == ["docker", "images"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["docker", "pull"]:
            return subprocess.CompletedProcess(cmd, 0 if self.pull_ok else 1, "",
                                               "manifest unknown")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def _http_recon():
    return {"domain": "example.com", "metadata": {"root_domain": "example.com"},
            "port_scan": {"by_host": {f"www.example.com": {
                "ip": IP, "port_details": [{"port": 80, "service": "http"}]}},
                "by_ip": {IP: {"ip": IP, "hostnames": ["www.example.com"], "ports": [80]}}}}


def _http_degraded(result) -> str:
    assert "http_probe" not in result
    assert "http_probe" in cb.coverage_report().degraded_sources
    return result["metadata"]["phase_errors"]["http_probe"]


class TestHttpxFailure:
    def test_regression_an_image_pull_failure_read_as_no_live_url(self, monkeypatch):
        docker = _Docker(monkeypatch, pull_ok=False)
        result = hp.run_http_probe(_http_recon(), settings={})
        assert "image" in _http_degraded(result)
        assert ["docker", "pull", "projectdiscovery/httpx:latest"] in docker.calls
        docker.popen.assert_not_called()

    def test_regression_docker_missing_read_as_no_live_url(self, monkeypatch):
        _Docker(monkeypatch, installed=False)
        _http_degraded(hp.run_http_probe(_http_recon(), settings={}))

    def test_regression_docker_down_read_as_no_live_url(self, monkeypatch):
        _Docker(monkeypatch, running=False)
        _http_degraded(hp.run_http_probe(_http_recon(), settings={}))

    def test_regression_a_probe_that_exits_with_nothing(self, monkeypatch):
        proc = _Proc(("", "docker: invalid reference format"), returncode=125)
        docker = _Docker(monkeypatch, popen=mock.Mock(return_value=proc))
        result = hp.run_http_probe(_http_recon(), settings={})
        assert "invalid reference format" in _http_degraded(result)
        (cmd,), _ = docker.popen.call_args
        assert cmd[:2] == ["docker", "run"] and "-json" in cmd

    def test_regression_a_probe_that_raises(self, monkeypatch):
        _Docker(monkeypatch, popen=mock.Mock(side_effect=OSError("fork failed")))
        assert "fork failed" in _http_degraded(hp.run_http_probe(_http_recon(), settings={}))

    def test_regression_a_budget_stop_with_nothing_written(self, monkeypatch):
        proc = _Proc(subprocess.TimeoutExpired("docker", 1))
        docker = _Docker(monkeypatch, popen=mock.Mock(return_value=proc))
        result = hp.run_http_probe(_http_recon(), settings={})
        assert "budget" in _http_degraded(result)
        assert proc.killed
        assert any(c[:2] == ["docker", "kill"] for c in docker.calls)

    def test_nothing_to_probe_is_not_a_failure(self, monkeypatch):
        _Docker(monkeypatch)
        result = hp.run_http_probe({"metadata": {}, "dns": {"subdomains": {}}}, settings={})
        assert "http_probe" not in result
        assert "phase_errors" not in result["metadata"]
        assert not cb.coverage_report().degraded

    def test_a_new_probe_forgets_an_earlier_runs_failure(self, monkeypatch):
        # The legacy path reloads the previous run's file, phase errors and all.
        _Docker(monkeypatch)
        stale = {"metadata": {"phase_errors": {"http_probe": "image pull failed"}},
                 "dns": {"subdomains": {}}}
        result = hp.run_http_probe(stale, settings={})
        assert "http_probe" not in result["metadata"]["phase_errors"]


# --------------------------------------------------------------------------- #
# The pipeline: the gate, modules_executed and the prune
# --------------------------------------------------------------------------- #
PORT_SCAN = {"scan_metadata": {"ports_config": "6379"}, "by_host": {}, "all_ports": [6379],
             "summary": {}, "ip_to_hostnames": {},
             "by_ip": {IP: {"ip": IP, "hostnames": [], "ports": [6379], "port_details": []}}}
SETTINGS = {
    "DNS_ENABLED": False, "WHOIS_ENABLED": False, "SHODAN_ENABLED": False,
    "NAABU_ENABLED": True, "MASSCAN_ENABLED": False, "NMAP_ENABLED": False,
    "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False, "UNCOVER_ENABLED": False,
    "HTTPX_ENABLED": True, "IP_ATTRIBUTION_ENABLED": False, "URLSCAN_ENABLED": False,
    "SECURITY_CHECK_ENABLED": True, "BANNER_GRAB_ENABLED": False,
    "AI_SURFACE_RECON_ENABLED": False, "JS_RECON_ENABLED": False,
    "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": True, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROUTE_EXPOSURE_ENABLED": False, "ROE_ENABLED": False,
    "TLSX_INJECT_HOSTNAMES": False,
}
SCAN_MODULES = ["port_scan", "http_probe", "resource_enum", "vuln_scan"]
ORG = "example.com"
DB = f"db.{ORG}"


def _main_module(monkeypatch, tmp_path, stub):
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(rm, "SCAN_MODULES", list(SCAN_MODULES))
    return rm


_STUB = {
    'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': [IP],
    'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
    'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': list(SCAN_MODULES),
    'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
    'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
    'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
}


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    yield _main_module(monkeypatch, tmp_path, _STUB)


class _Redis:
    def __call__(self, address, timeout=None):
        return self

    def send(self, data):
        pass

    def recv(self, _size):
        return b"+PONG\r\n"

    def close(self):
        pass


class _Pipeline:
    """The scanners around the probes, faked; what ran and what was queued."""

    def __init__(self, rm, monkeypatch):
        self.scanned, self.queued = [], []
        monkeypatch.setattr(sc.socket, "create_connection", _Redis())
        monkeypatch.setattr(rm, "run_port_scan_isolated", lambda *a, **k: copy.deepcopy(PORT_SCAN))
        monkeypatch.setattr(rm, "run_vuln_scan", self._scanner("nuclei"))
        monkeypatch.setattr(vs, "run_vuln_scan", self._scanner("nuclei"))
        monkeypatch.setattr(rm, "run_resource_enum", self._scanner("resource_enum"))
        monkeypatch.setattr(st, "run_subdomain_takeover", self._scanner("takeover"))
        import recon.graphql_scan as gq
        monkeypatch.setattr(gq, "run_graphql_scan_isolated",
                            lambda combined, settings: self.scanned.append("graphql") or {})
        monkeypatch.setattr(rm, "_graph_update_bg",
                            lambda name, data, *a: self.queued.append(name))

    def _scanner(self, label):
        def run(combined, output_file=None, settings=None):
            self.scanned.append(label)
            return combined
        return run


def _executed(result):
    return result["metadata"]["modules_executed"]


class TestIpModePipeline:
    def test_regression_a_failed_httpx_ran_the_scanners_on_nothing(self, recon_main,
                                                                   monkeypatch):
        run = _Pipeline(recon_main, monkeypatch)
        _Docker(monkeypatch, pull_ok=False)
        result = recon_main.run_ip_recon([IP], dict(SETTINGS))
        assert run.scanned == []  # nuclei, resource enumeration and graphql never ran on nothing
        assert result["metadata"]["active_scans_skipped"] is True
        assert "http_probe" in result["metadata"]["active_scans_skip_reason"]
        assert "http_probe" not in _executed(result)

    def test_regression_a_failed_httpx_pruned_the_scanners_findings(self, recon_main,
                                                                   monkeypatch):
        _Pipeline(recon_main, monkeypatch)
        _Docker(monkeypatch, pull_ok=False)
        recon_main.run_ip_recon([IP], dict(SETTINGS))
        report = cb.coverage_report()
        assert "http_probe" in report.degraded_sources
        for source in ("nuclei", "vuln_scan", "resource_enum", "graphql_scan", "graphql_cop"):
            assert set(report.keep_hostnames(source)) == {IP, NAME}, source
        # The port checks re-checked the address, but httpx did not: its web
        # findings there are not theirs to prune.
        assert set(report.keep_hostnames("security_check")) == {IP, NAME}

    def test_a_probe_that_ran_is_listed_and_keeps_nothing(self, recon_main, monkeypatch):
        run = _Pipeline(recon_main, monkeypatch)

        def live(combined, output_file=None, settings=None):
            combined["http_probe"] = {"by_url": {f"http://{IP}": {}},
                                      "summary": {"live_urls": 1, "total_hosts": 1}}
            return combined

        monkeypatch.setattr(recon_main, "run_http_probe", live)
        result = recon_main.run_ip_recon([IP], dict(SETTINGS))
        assert "http_probe" in _executed(result)
        assert "nuclei" in run.scanned
        assert cb.coverage_report().keep_hostnames("nuclei") == ()

    def test_regression_a_failed_tlsx_was_listed_as_executed(self, recon_main, monkeypatch):
        _Pipeline(recon_main, monkeypatch)
        monkeypatch.setattr(tls_scan, "_build_tlsx_targets",
                            lambda combined, s: ([f"{IP}:6379"], {f"{IP}:6379": IP}))
        monkeypatch.setattr(tls_scan.subprocess, "Popen",
                            mock.Mock(side_effect=FileNotFoundError("docker")))
        result = recon_main.run_ip_recon([IP], dict(SETTINGS, TLSX_ENABLED=True,
                                                    HTTPX_ENABLED=False))
        assert "tlsx" not in _executed(result)
        assert IP in cb.coverage_report().keep_hostnames("security_check")

    def test_a_tlsx_phase_crash_keeps_its_source(self, recon_main, monkeypatch):
        _Pipeline(recon_main, monkeypatch)
        monkeypatch.setattr(tls_scan, "run_tlsx_enrichment",
                            mock.Mock(side_effect=RuntimeError("boom")))
        result = recon_main.run_ip_recon([IP], dict(SETTINGS, TLSX_ENABLED=True,
                                                    HTTPX_ENABLED=False))
        assert "tlsx" not in _executed(result)
        assert result["metadata"]["phase_errors"]["tlsx"] == "boom"
        assert "security_check" in cb.coverage_report().degraded_sources

    def test_httpx_switched_off_is_not_a_failure(self, recon_main, monkeypatch):
        run = _Pipeline(recon_main, monkeypatch)
        result = recon_main.run_ip_recon([IP], dict(SETTINGS, HTTPX_ENABLED=False))
        assert "active_scans_skipped" not in result["metadata"]
        assert "nuclei" in run.scanned
        assert "http_probe" not in cb.coverage_report().degraded_sources


class TestDomainModePipeline:
    def _run(self, tmp_path, monkeypatch, **settings):
        rm = _main_module(monkeypatch, tmp_path, dict(
            _STUB, TARGET_DOMAIN=ORG, IP_MODE=False, TARGET_IPS=[]))
        from recon.main_recon_modules import domain_recon
        monkeypatch.setattr(rm, "_settings", dict(SETTINGS, DNS_ENABLED=True,
                                                  SECURITY_CHECK_SPF_MISSING=False,
                                                  SECURITY_CHECK_DMARC_MISSING=False,
                                                  SECURITY_CHECK_DNSSEC_MISSING=False,
                                                  SECURITY_CHECK_ZONE_TRANSFER=False,
                                                  **settings))
        monkeypatch.setattr(domain_recon, "resolve_all_dns", lambda root, subs, **k: {
            "domain": {}, "subdomains": {DB: {
                "has_records": True, "ips": {"ipv4": [IP], "ipv6": []},
                "records": {"A": [IP]}}}})
        run = _Pipeline(rm, monkeypatch)
        result = rm.run_domain_recon(ORG, target_info=rm.parse_target(ORG, ["db."]),
                                     discovery_enabled=False)
        return run, result

    def test_regression_a_failed_httpx_ran_the_scanners_on_nothing(self, tmp_path,
                                                                   monkeypatch):
        _Docker(monkeypatch, pull_ok=False)
        run, result = self._run(tmp_path, monkeypatch)
        assert run.scanned == []
        assert result["metadata"]["active_scans_skipped"] is True
        assert "http_probe" not in _executed(result)
        report = cb.coverage_report()
        assert "http_probe" in report.degraded_sources
        for source in ("nuclei", "security_check", "graphql_scan"):
            assert set(report.keep_hostnames(source)) == {IP, DB}, source


class TestEveryCallSite:
    def test_no_probe_is_listed_as_executed_unconditionally(self, recon_main):
        source = inspect.getsource(recon_main)
        for module in ("http_probe", "tlsx"):
            assert f'["modules_executed"].append("{module}")' not in source, module

    def test_tlsx_has_a_phase_entry(self, recon_main):
        assert recon_main._PHASE_FINDING_SOURCES["tlsx"] == ("security_check",)

    def test_the_crawlers_that_still_run_keep_their_findings_too(self, recon_main):
        result = {"metadata": {"phase_errors": {"http_probe": "Docker daemon is not running"}},
                  "port_scan": copy.deepcopy(PORT_SCAN)}
        recon_main._note_gate_skipped(result, dict(SETTINGS, JS_RECON_ENABLED=True,
                                                   AI_SURFACE_RECON_ENABLED=True))
        report = cb.coverage_report()
        for source in ("js_recon", "ai_surface_recon", "nuclei", "security_check"):
            assert IP in report.keep_hostnames(source), source
        assert all(g["reason"] == "http_probe failed, no host probed" for g in report.gaps)

    def test_with_no_live_url_the_crawlers_prune_as_before(self, recon_main):
        recon_main._note_gate_skipped({"metadata": {}, "port_scan": copy.deepcopy(PORT_SCAN)},
                                      dict(SETTINGS, JS_RECON_ENABLED=True,
                                           AI_SURFACE_RECON_ENABLED=True))
        report = cb.coverage_report()
        assert report.keep_hostnames("js_recon") == ()
        assert report.keep_hostnames("ai_surface_recon") == ()
        # The address the port checks read is theirs to prune.
        assert IP not in report.keep_hostnames("security_check")

    def test_the_gate_skips_on_a_failed_probe_only(self, recon_main):
        skip, why = recon_main.should_skip_active_scans(
            {"metadata": {"phase_errors": {"http_probe": "image pull failed"}}})
        assert skip and "image pull failed" in why
        assert recon_main.should_skip_active_scans({"metadata": {}}) == (False, "")

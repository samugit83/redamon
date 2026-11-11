"""The late-name scan of an IP-mode run's selected hostnames (P4, design §5.5).

The hostnames hook selects names whose every current address is a target and
pins that answer. The late scan then works on the pinned answer only: no second
lookup (B-28), no non-routable drop (an IP-mode target may be private, D-13), no
second port scan (every target IP was already scanned), a target IP the port
scan did not report counts as scanned with zero open ports (and gets no
guessed-port probe), and the httpx probe it does run keeps its results because
the names are in the run's scope list. A failure notes every name degraded so
the end-of-run prune keeps their earlier findings, and reports the http_probe
phase through the caller's hook.

The port scan and httpx are injected: nothing is resolved or sent.
Documentation ranges (RFC 5737, RFC 3849), the private 10.0.0.0/8 and reserved
names only.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import late_names as ln  # noqa: E402
from recon.helpers.target_admission import target_set  # noqa: E402

T1, T2, PRIV, V6 = "203.0.113.10", "203.0.113.11", "10.0.0.5", "2001:db8::10"
FOREIGN = "198.51.100.7"
APP, SHOP, INTRA = "app.example.com", "shop.example.com", "intra.example.com"
TARGETS = target_set([T1, T2, PRIV, V6])


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _recon(**extra):
    run = {
        "domain": "ip-targets.cmlatenamesipmode000000001",
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2, PRIV, V6],
                     "subdomain_filter": [T1, T2, PRIV, V6, APP, SHOP, INTRA],
                     "ip_mode_hosts": {APP: "example.com", SHOP: "example.com", INTRA: "example.com"}},
        "subdomains": [APP, SHOP, INTRA],
        "dns": {"domain": {}, "subdomains": {}},
        "port_scan": {
            "by_ip": {T1: {"ip": T1, "hostnames": [], "ports": [443]},
                      PRIV: {"ip": PRIV, "hostnames": [], "ports": [8080]}},
            "by_host": {T1: {"host": T1, "ip": T1, "ports": [443], "port_details": [
                            {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx"}]},
                        PRIV: {"host": PRIV, "ip": PRIV, "ports": [8080], "port_details": [
                            {"port": 8080, "protocol": "tcp", "service": "http-proxy"}]}},
            "all_ports": [443, 8080]},
        "http_probe": {"by_url": {f"https://{T1}": {"host": T1, "ip": T1, "status_code": 200}},
                       "by_host": {T1: {"hostname": T1, "urls": [f"https://{T1}"], "live_urls": [f"https://{T1}"]}},
                       "technologies_found": {}, "servers_found": {},
                       "summary": {"total_urls_probed": 1, "live_urls": 1, "total_hosts": 1}},
    }
    run.update(extra)
    return run


class _Probe:
    """httpx stand-in: answers every name it is given from `rows`."""

    def __init__(self, rows=None, fail=None):
        self.rows, self.fail, self.calls = rows or {}, fail, []

    def __call__(self, sub, output_file=None, settings=None):
        if self.fail:
            raise self.fail
        self.calls.append({"names": sorted(sub.get("subdomains") or []), "settings": settings,
                           "port_scan": copy.deepcopy(sub.get("port_scan")),
                           "filter": list((sub.get("metadata") or {}).get("subdomain_filter") or [])})
        by_url = {u: r for u, r in self.rows.items() if r["host"] in sub["subdomains"]}
        sub["http_probe"] = {
            "by_url": by_url,
            "by_host": {r["host"]: {"hostname": r["host"], "urls": [u], "live_urls": [u]} for u, r in by_url.items()},
            "technologies_found": {}, "servers_found": {}, "external_domains": [],
            "summary": {"total_urls_probed": len(by_url)},
        }


def _scan(run, names, pinned, probe, **kw):
    return ln.scan_late_names(run, names, kw.pop("settings", {}), probe_http=True, label="IpNames",
                              pinned=pinned, targets=TARGETS, http_prober=probe,
                              port_scanner=kw.pop("port_scanner", _no_port_scan), **kw)


def _no_port_scan(*_a, **_k):
    raise AssertionError("IP mode never port-scans a name: every target IP was scanned")


def test_the_pinned_answer_is_used_and_nothing_is_resolved(monkeypatch):
    def no_lookup(*_a, **_k):
        raise AssertionError("no second lookup in IP mode (B-28)")

    monkeypatch.setattr("recon.main_recon_modules.domain_recon.dns_lookup", no_lookup)
    run = _recon()
    probe = _Probe({f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200}})
    sub = _scan(run, [APP], {APP: [T1]}, probe)
    entry = run["dns"]["subdomains"][APP]
    assert entry["ips"] == {"ipv4": [T1], "ipv6": []} and entry["has_records"] is True
    assert sub["dns"]["subdomains"][APP]["ips"]["ipv4"] == [T1]


def test_a_private_target_is_kept_where_discovery_would_drop_it():
    run = _recon()
    probe = _Probe({f"http://{INTRA}:8080": {"host": INTRA, "ip": PRIV, "status_code": 200}})
    sub = _scan(run, [INTRA], {INTRA: [PRIV]}, probe)
    assert sub is not None and INTRA in run["dns"]["subdomains"]
    assert probe.calls[0]["names"] == [INTRA]


def test_an_ipv6_answer_lands_in_ipv6():
    run = _recon()
    _scan(run, [APP], {APP: [T1, V6]}, _Probe())
    assert run["dns"]["subdomains"][APP]["ips"] == {"ipv4": [T1], "ipv6": [V6]}


@pytest.mark.parametrize("answer", [[FOREIGN], [T1, FOREIGN], [], ["127.0.0.1"]])
def test_a_pin_off_the_targets_is_never_scanned(answer, capsys):
    run = _recon()
    probe = _Probe()
    assert _scan(run, [APP], {APP: answer}, probe) is None
    assert APP not in run["dns"]["subdomains"] and probe.calls == []
    assert f"Dropped late name {APP}" in capsys.readouterr().out


def test_names_take_the_ports_of_their_addresses_without_a_port_scan():
    run = _recon()
    probe = _Probe({f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200}})
    sub = _scan(run, [APP], {APP: [T1]}, probe)
    row = run["port_scan"]["by_host"][APP]
    assert row["ports"] == [443] and row["port_details"][0]["product"] == "nginx"
    assert APP in run["port_scan"]["by_ip"][T1]["hostnames"]
    assert probe.calls[0]["port_scan"]["by_host"][APP]["ports"] == [443]
    assert set(sub["http_probe"]["by_url"]) == {f"https://{APP}"}


def test_a_target_ip_the_port_scan_did_not_report_counts_as_zero_open_ports():
    """T2 had no open port: the name is scanned (nothing to probe), never
    port-scanned again and never handed to httpx's guessed-port fallback."""
    run = _recon()
    probe = _Probe()
    sub = _scan(run, [SHOP], {SHOP: [T2]}, probe)
    assert sub is not None
    assert run["port_scan"]["by_host"][SHOP]["ports"] == []
    assert T2 not in run["port_scan"]["by_ip"]          # no empty row invented
    assert probe.calls == []                            # nothing to probe
    assert sub["late_probed"] == []


def test_only_names_with_open_ports_are_probed_and_the_subset_carries_the_port_scan():
    run = _recon()
    probe = _Probe({f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200}})
    sub = _scan(run, [APP, SHOP], {APP: [T1], SHOP: [T2]}, probe)
    assert [c["names"] for c in probe.calls] == [[APP]]
    assert probe.calls[0]["port_scan"] is not None
    assert sub["late_probed"] == [APP]


def test_without_any_port_scan_the_names_follow_the_ips_dns_fallback():
    """A run with no port scanner at all probed its IPs on guessed ports; its
    names get the same, still on their pinned target addresses."""
    run = _recon()
    del run["port_scan"]
    probe = _Probe()
    sub = _scan(run, [APP], {APP: [T1]}, probe)
    assert [c["names"] for c in probe.calls] == [[APP]]
    assert probe.calls[0]["port_scan"] is None
    assert sub["late_probed"] == [APP]


def test_the_probe_reports_the_address_and_keeps_the_names_in_scope():
    run = _recon()
    probe = _Probe({f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200}})
    _scan(run, [APP], {APP: [T1]}, probe, settings={"HTTPX_PROBE_IP": False})
    # The post-probe guard needs the address httpx reached.
    assert probe.calls[0]["settings"]["HTTPX_PROBE_IP"] is True
    assert APP in probe.calls[0]["filter"]
    assert f"https://{APP}" in run["http_probe"]["by_url"]
    assert f"https://{T1}" in run["http_probe"]["by_url"]


def test_httpx_off_scans_dns_and_ports_only():
    run = _recon()
    probe = _Probe()
    sub = _scan(run, [APP], {APP: [T1]}, probe, settings={"HTTPX_ENABLED": False})
    assert probe.calls == [] and "http_probe" not in sub and sub["late_probed"] == []


def test_a_failure_notes_every_name_degraded_and_tells_the_caller(capsys):
    run = _recon()
    seen = []
    sub = _scan(run, [APP, SHOP], {APP: [T1], SHOP: [T2]}, _Probe(fail=RuntimeError("docker gone")),
                on_error=seen.append)
    assert sub is None
    assert [type(e).__name__ for e in seen] == ["RuntimeError"]
    report = circuit_breaker.coverage_report()
    assert set(report.keep_hostnames()) >= {APP, SHOP}
    assert "[!][IpNames] late-name scan failed" in capsys.readouterr().out


def test_a_failure_without_an_error_hook_still_notes_the_names():
    assert _scan(_recon(), [APP], {APP: [T1]}, _Probe(fail=RuntimeError("x"))) is None
    assert APP in circuit_breaker.coverage_report().keep_hostnames()


def test_a_failing_error_hook_never_raises():
    def boom(_e):
        raise ValueError("hook")

    assert _scan(_recon(), [APP], {APP: [T1]}, _Probe(fail=RuntimeError("x")), on_error=boom) is None


def test_domain_mode_keeps_its_own_path(monkeypatch):
    """Without `targets` nothing changes: give_dns, attach_known_ports and the
    port scan of unscanned addresses run as before."""
    calls = []
    monkeypatch.setattr(ln, "give_dns", lambda c, names, s, lookup=None: calls.append("dns") or [])
    assert ln.scan_late_names({"dns": {"subdomains": {}}}, [APP], {}, probe_http=True, label="SAN") is None
    assert calls == ["dns"]


def test_a_probe_with_no_answer_leaves_no_http_block():
    def silent(sub, output_file=None, settings=None):
        return None

    sub = _scan(_recon(), [APP], {APP: [T1]}, silent)
    assert "http_probe" not in sub and sub["late_probed"] == [APP]


def test_a_zero_port_name_the_port_scan_already_lists_keeps_its_row():
    run = _recon()
    run["port_scan"]["by_host"][SHOP] = {"host": SHOP, "ip": T2, "ports": [], "port_details": [], "seen": True}
    _scan(run, [SHOP], {SHOP: [T2]}, _Probe())
    assert run["port_scan"]["by_host"][SHOP]["seen"] is True


def test_the_default_prober_is_the_pipelines_httpx(monkeypatch):
    calls = []
    monkeypatch.setattr("recon.main_recon_modules.http_probe.run_http_probe",
                        lambda sub, output_file=None, settings=None: calls.append(sorted(sub["subdomains"])))
    ln.scan_late_names(_recon(), [APP], {}, probe_http=True, label="IpNames", pinned={APP: [T1]},
                       targets=TARGETS)
    assert calls == [[APP]]


def test_recount_ignores_rows_without_a_status():
    http = {"by_url": {"a": {"status_code": None}, "b": "junk", "c": {"status_code": 302}}, "by_host": {"h": "x"}}
    ln._recount(http)
    assert http["summary"]["by_status_code"] == {"302": 1}
    assert http["summary"]["live_urls"] == 1 and http["summary"]["cdn_hosts"] == 0


def test_drop_http_rows_removes_a_host_and_recounts():
    http = {"by_url": {f"https://{APP}": {"host": APP, "status_code": 200, "technologies": ["nginx"]},
                       f"https://{T1}": {"host": T1, "status_code": 200, "technologies": ["nginx"]}},
            "by_host": {APP: {"urls": [f"https://{APP}"]}, T1: {"urls": [f"https://{T1}"]}},
            "technologies_found": {"nginx": [f"https://{APP}", f"https://{T1}"], "php": [f"https://{APP}"]},
            "servers_found": {"nginx": [f"https://{APP}"]},
            "summary": {"total_urls_probed": 2, "live_urls": 2, "total_hosts": 2, "filtered_out_of_scope": 3}}
    assert ln.drop_http_rows(http, APP) == [f"https://{APP}"]
    assert set(http["by_url"]) == {f"https://{T1}"} and set(http["by_host"]) == {T1}
    assert http["technologies_found"] == {"nginx": [f"https://{T1}"]}
    assert http["servers_found"] == {}
    s = http["summary"]
    assert (s["total_urls_probed"], s["live_urls"], s["total_hosts"], s["technology_count"],
            s["filtered_out_of_scope"]) == (1, 1, 1, 1, 3)
    assert ln.drop_http_rows({}, APP) == []

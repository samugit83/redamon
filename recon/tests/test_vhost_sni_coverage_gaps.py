"""VHost/SNI records what it could not check (R-46).

The prune deletes a vhost_sni_enum finding the run did not report again unless
its host was noted as not checked. A port whose baseline failed, an IP whose
probing raised and a run with no curl binary used to record nothing, so the
earlier "Hidden Virtual Host" findings there were deleted although nobody
re-checked them. Each is now a coverage note: by host, for this source only
(curl answering nothing proves nothing to the other tools), or the whole source
when curl is missing.

Only I/O is mocked: the curl wrapper and the curl availability probe.
"""
from __future__ import annotations

import re
from unittest import mock

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import vhost_sni_enum as v

IP = "192.0.2.30"
OTHER_IP = "192.0.2.31"
PAGE = {"status": 200, "size": 100, "body_hash": "live", "canon_hash": "live", "title": None}

#: The Recon Delta drops a run's whole gap list when one source breaks this shape.
_TOKEN = re.compile(r"[a-z0-9_]{1,64}")


def _curl(dead_baselines=()):
    """A stand-in for _curl_probe: every probe answers the same page, except the
    baseline (no Host, no SNI) of the "ip:port" keys in ``dead_baselines``."""
    def probe(scheme, host_header, sni_hostname, target, port, timeout):
        if host_header is None and sni_hostname is None and v._port_key(target, port) in dead_baselines:
            return None
        return dict(PAGE)

    def call(*args, **kwargs):
        names = ("scheme", "host_header", "sni_hostname", "target", "port", "timeout")
        return probe(**{**dict(zip(names, args)), **kwargs})
    return call


def _probe_one(ip=IP, ports=(443, 8443), dead_baselines=()):
    with mock.patch.object(v, "_curl_probe", _curl(dead_baselines)):
        return v._probe_single_ip(
            ip=ip,
            ports=[{"port": p, "protocol": "tcp", "scheme": "https"} for p in ports],
            apex_domain="example.com",
            default_prefixes=[],
            custom_lines=["admin", "wiki"],
            graph_candidates=[],
            test_l7=True,
            test_l4=True,
            timeout=1,
            concurrency=1,
            size_tolerance=50,
            max_candidates=2000,
        )


def _combined(*ips):
    return {
        "domain": "example.com",
        "port_scan": {"by_host": {ip: {"ip": ip, "ports": [
            {"port": 443, "scheme": "https"}, {"port": 8443, "scheme": "https"}]} for ip in ips}},
    }


SETTINGS = {
    "VHOST_SNI_ENABLED": True,
    "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
    "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
    "VHOST_SNI_INJECT_DISCOVERED": False,
    "VHOST_SNI_CUSTOM_WORDLIST": "admin\nwiki",
    "VHOST_SNI_CONCURRENCY": 1,
}


def _gap_sources(report):
    return [g["source"] for g in report.gaps]


# ---------------------------------------------------------------------------
# A failed baseline
# ---------------------------------------------------------------------------
def test_a_failed_baseline_lists_its_port_as_not_checked():
    out = _probe_one(dead_baselines={f"{IP}:8443"})
    assert out.get("unchecked_ports") == [f"{IP}:8443"]
    # Not "unreachable": curl's silence does not prove the port down for the
    # other tools, so it must not be cut for every source.
    assert "unreachable_ports" not in out
    assert out["ports_tested"] == 1


def test_a_port_whose_baseline_answers_is_not_listed():
    out = _probe_one()
    assert "unchecked_ports" not in out
    assert out["ports_tested"] == 2


def test_a_failed_baseline_keeps_the_ips_vhost_findings_only():
    with mock.patch.object(v, "_is_curl_available", return_value=True), \
            mock.patch.object(v, "_curl_probe", _curl({f"{IP}:8443"})):
        out = v.run_vhost_sni_enrichment(_combined(IP, OTHER_IP), dict(SETTINGS))

    payload = out["vhost_sni"]
    assert payload["unchecked_ports"] == [f"{IP}:8443"]
    report = cb.coverage_report()
    assert IP in report.keep_hostnames("vhost_sni_enum")
    assert OTHER_IP not in report.keep_hostnames("vhost_sni_enum")
    # Every other source re-checked the IP: their stale findings there still go.
    assert IP not in report.keep_hostnames("nuclei")
    assert "vhost_sni_enum" not in report.degraded_sources
    assert "vhost_sni_enum" in _gap_sources(report)
    assert all(_TOKEN.fullmatch(s) for s in _gap_sources(report))


# ---------------------------------------------------------------------------
# An IP whose probing raised
# ---------------------------------------------------------------------------
def test_an_ip_whose_probing_raised_keeps_its_vhost_findings():
    real = v._probe_single_ip

    def flaky(**kwargs):
        if kwargs["ip"] == IP:
            raise RuntimeError("thread pool exploded")
        return real(**kwargs)

    with mock.patch.object(v, "_is_curl_available", return_value=True), \
            mock.patch.object(v, "_curl_probe", _curl()), \
            mock.patch.object(v, "_probe_single_ip", side_effect=flaky):
        out = v.run_vhost_sni_enrichment(_combined(IP, OTHER_IP), dict(SETTINGS))

    payload = out["vhost_sni"]
    assert IP not in payload["by_ip"]
    assert OTHER_IP in payload["by_ip"]
    assert payload["unchecked_ports"] == [f"{IP}:443", f"{IP}:8443"]
    report = cb.coverage_report()
    assert IP in report.keep_hostnames("vhost_sni_enum")
    assert OTHER_IP not in report.keep_hostnames("vhost_sni_enum")
    assert IP not in report.keep_hostnames("nuclei")
    assert "vhost_sni_enum" not in report.degraded_sources
    assert all(_TOKEN.fullmatch(s) for s in _gap_sources(report))


def test_a_clean_run_notes_nothing():
    with mock.patch.object(v, "_is_curl_available", return_value=True), \
            mock.patch.object(v, "_curl_probe", _curl()):
        out = v.run_vhost_sni_enrichment(_combined(IP), dict(SETTINGS))
    assert "unchecked_ports" not in out["vhost_sni"]
    report = cb.coverage_report()
    assert not report.degraded
    assert report.keep_hostnames("vhost_sni_enum") == ()


# ---------------------------------------------------------------------------
# No curl binary
# ---------------------------------------------------------------------------
def test_no_curl_degrades_the_whole_source():
    with mock.patch.object(v, "_is_curl_available", return_value=False), \
            mock.patch.object(v, "_curl_probe", side_effect=AssertionError("no probe without curl")):
        out = v.run_vhost_sni_enrichment(_combined(IP), dict(SETTINGS))
    assert out["vhost_sni"]["scan_metadata"]["skipped_reason"] == "curl_unavailable"
    report = cb.coverage_report()
    assert "vhost_sni_enum" in report.degraded_sources
    # Only this source: the others ran.
    assert report.degraded_sources == frozenset({"vhost_sni_enum"})
    assert all(_TOKEN.fullmatch(s) for s in _gap_sources(report))


def test_switched_off_notes_nothing():
    with mock.patch.object(v, "_is_curl_available", return_value=False):
        v.run_vhost_sni_enrichment(_combined(IP), {"VHOST_SNI_ENABLED": False})
    assert not cb.coverage_report().degraded

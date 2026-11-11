"""Regression (R-2, gap 3c): Nuclei re-gates the crawler and probe URLs through the RoE.

`run_vuln_scan` builds its targets with `target_helpers.build_target_urls`:
the crawler's base and endpoint URLs (source 1), the URLs httpx answered
(source 2), then the DNS names neither covers (source 3). Only source 3 came
from the admission-gated DNS extractor, so a URL on a name resolving into an
RoE exclusion, on the excluded address itself, or on a name the RoE lists,
still reached the Nuclei target file when the crawler or httpx had seen it
(a redirect, a link, a probe run before the exclusion was added). The DAST
pass's crawler URLs were never gated either.

Each test reads the target files the Nuclei container is handed. Only Docker
and the Nuclei passes are replaced. With no exclusion in force every list is
the one built without RoE keys at all.
Reserved names and documentation ranges only; no Docker, no network.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"   # resolves into the excluded range
EXCLUDED_RANGE = "198.51.100.0/24"

NUCLEI = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
          "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0}


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _live(*urls):
    return {u: {"url": u, "status_code": 200} for u in urls}


def _endpoint():
    return {"/search": {"methods": ["GET"], "parameters": {"query": [{"name": "q"}]}}}


def _recon() -> dict:
    """A domain-mode run whose crawler and httpx reached the legacy host."""
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {WWW: _sub(WWW_IP), LEGACY: _sub(LEGACY_IP)},
        },
        "http_probe": {"by_url": _live(f"https://{WWW}", f"https://{LEGACY}", f"http://{LEGACY_IP}")},
        "resource_enum": {
            "by_base_url": {f"https://{WWW}": {"endpoints": _endpoint()},
                            f"https://{LEGACY}": {"endpoints": _endpoint()}},
            "discovered_urls": [f"https://{WWW}/search?q=1", f"https://{LEGACY}/search?q=1",
                                f"http://{LEGACY_IP}/item?id=2"],
        },
    }


def _hosts(urls) -> set:
    return {(urlparse(u).hostname or "").lower() for u in urls}


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _nuclei_targets(settings, recon=None) -> dict:
    """{pass label: the URLs written to the target file its container reads}."""
    from recon.main_recon_modules import vuln_scan as vs
    seen = {}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        target_file = Path(output_file).parent / f"targets_{label.lower()}.txt"
        seen[label] = target_file.read_text().split()
        return [], [], 1.0, 0

    with mock.patch.object(vs, "is_docker_installed", return_value=True), \
         mock.patch.object(vs, "is_docker_running", return_value=True), \
         mock.patch.object(vs, "pull_nuclei_docker_image", return_value=True), \
         mock.patch.object(vs, "ensure_templates_volume", return_value=True), \
         mock.patch.object(vs, "_execute_nuclei_pass", side_effect=fake_pass):
        vs.run_vuln_scan(recon or _recon(), settings={**NUCLEI, **settings})
    return seen


def test_regression_a_crawled_or_probed_url_on_an_excluded_address_never_reaches_nuclei():
    targets = _nuclei_targets(_roe(EXCLUDED_RANGE))["DETECTION"]
    assert {LEGACY, LEGACY_IP}.isdisjoint(_hosts(targets))
    assert f"https://{WWW}" in targets and f"https://{WWW}/search?q=1" in targets


def test_regression_the_dast_pass_gets_no_crawled_url_on_an_excluded_address():
    targets = _nuclei_targets({**_roe(EXCLUDED_RANGE), "NUCLEI_DAST_MODE": True})
    assert targets["DAST"] == [f"https://{WWW}/search?q=1"]
    assert {LEGACY, LEGACY_IP}.isdisjoint(_hosts(targets["DETECTION"]))


def test_a_name_the_roe_lists_is_dropped_from_the_crawler_and_probe_urls_too():
    hosts = _hosts(_nuclei_targets(_roe(LEGACY))["DETECTION"])
    assert LEGACY not in hosts
    # The address is not excluded by a name entry: httpx reached it by itself.
    assert {WWW, LEGACY_IP} <= hosts


def test_the_refusal_is_a_coverage_gap_of_nuclei():
    _nuclei_targets(_roe(EXCLUDED_RANGE))
    gaps = [g for g in circuit_breaker.coverage_report().gaps
            if g["source"] == "roe_excluded" and g["module"] == "nuclei"]
    assert gaps and gaps[0]["skipped"] >= 2


def _ip_mode_recon(target, crawled_hosts, probed=True):
    return {
        "domain": "", "metadata": {"ip_mode": True, "expanded_ips": [target]},
        "dns": {"domain": {}, "subdomains": {target.replace(".", "-"): _sub(target)}},
        "http_probe": {"by_url": _live(f"http://{target}") if probed else {}},
        "resource_enum": {"by_base_url": {f"http://{h}": {"endpoints": _endpoint()}
                                          for h in crawled_hosts},
                          "discovered_urls": []},
    }


def test_nuclei_does_not_start_when_the_gate_leaves_it_no_url():
    recon = _ip_mode_recon("192.0.2.10", ["192.0.2.99"], probed=False)
    assert _nuclei_targets({"IP_MODE": True}, recon) == {}


@pytest.mark.parametrize("settings", [_roe(), {"ROE_ENABLED": False,
                                                "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, LEGACY]}])
def test_the_targets_are_unchanged_without_an_exclusion(settings):
    baseline = _nuclei_targets({"NUCLEI_DAST_MODE": True})
    assert _nuclei_targets({**settings, "NUCLEI_DAST_MODE": True}) == baseline
    assert {LEGACY, LEGACY_IP} <= _hosts(baseline["DETECTION"])
    assert {LEGACY, LEGACY_IP} <= _hosts(baseline["DAST"])


def test_ip_mode_sends_nuclei_no_crawled_url_outside_the_target_list():
    target = "192.0.2.10"
    recon = _ip_mode_recon(target, ["192.0.2.99", target])
    targets = _nuclei_targets({"IP_MODE": True}, recon)["DETECTION"]
    assert _hosts(targets) == {target}

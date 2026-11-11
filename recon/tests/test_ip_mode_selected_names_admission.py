"""The target gate admits an IP-mode run's selected hostnames, and only them (P4).

Once the hostnames hook has selected a name, it is in the run's DNS block with
the selection rule's pinned answer, in its subdomains, its scope list
(subdomain_filter) and metadata.ip_mode_hosts. Every tool that resolves names
itself goes through the gate: httpx and the crawlers through admit_urls, the
JS-recon downloads / redirect hops / source maps through ip_mode_url_admission.

A name's addresses in IP mode are the pinned answer only. The port scan's
name maps (by_host, by_ip hostnames, ip_to_hostnames) merely echo it, and a
name they carry without DNS is no proof of where it resolves (P0b verify
carry-forward): such a name is refused. A recorded name is never admitted, and
neither is a selected one the post-probe guard withdrew.

Documentation ranges and reserved names only.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import ip_hostnames as ih  # noqa: E402
from recon.helpers.target_admission import admit_urls, ip_mode_url_admission, known_addresses  # noqa: E402

T1, T2, FOREIGN = "203.0.113.10", "203.0.113.11", "198.51.100.7"
APP, OLD, ECHO = "app.example.com", "old.example.com", "echo.example.com"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _recon():
    labels = {T1: "203-0-113-10", T2: "203-0-113-11"}
    return {
        "domain": "ip-targets.cmselectedadmission00000001",
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2],
                     "subdomain_filter": [T1, T2, *labels.values()]},
        "subdomains": list(labels.values()),
        "dns": {"domain": {}, "subdomains": {
            label: {"is_mock": True, "actual_ip": ip, "has_records": True,
                    "ips": {"ipv4": [ip], "ipv6": []}, "records": {}} for ip, label in labels.items()}},
        # A name the port scan's maps carry without any DNS answer behind it.
        "port_scan": {"by_host": {ECHO: {"host": ECHO, "ip": T1, "ports": [443]}},
                      "by_ip": {T1: {"ip": T1, "hostnames": [ECHO], "ports": [443]}},
                      "ip_to_hostnames": {T1: [ECHO]}},
        "ip_hostnames": {"candidates": {
            APP: {"ips_seen": [T1], "org_domain": "example.com", "reason": "scanned"},
            OLD: {"ips_seen": [T1], "org_domain": "example.com", "reason": "record_only"}}},
    }


def _selected():
    recon = _recon()
    ih.insert_selected(recon, [APP], {APP: {"org_domain": "example.com"}}, {APP: [T1]})
    return recon


def test_ip_mode_names_have_only_their_dns_addresses():
    known = known_addresses(_selected())
    assert known[APP] == [T1]
    assert known["203-0-113-10"] == [T1]
    assert ECHO not in known


def test_domain_mode_still_reads_the_port_scan_maps():
    recon = _recon()
    recon["metadata"]["ip_mode"] = False
    assert known_addresses(recon)[ECHO] == [T1]


def test_admit_urls_keeps_a_selected_name_and_refuses_an_echoed_one():
    urls = [f"https://{APP}/", f"https://{ECHO}/", f"https://{OLD}/", f"https://{T1}/"]
    kept, _ = admit_urls(None, _selected(), urls, module="httpx", record=False)
    assert kept == [f"https://{APP}/", f"https://{T1}/"]


def test_url_admission_admits_the_selected_name_only():
    admit = ip_mode_url_admission(_selected(), resolve=lambda host: [T1])
    assert admit(f"https://{APP}/app.js") is True
    assert admit(f"https://{OLD}/app.js") is False      # recorded: never a target (I-4)
    assert admit(f"https://{ECHO}/app.js") is False


def test_url_admission_refuses_a_selected_name_that_moved_since():
    admit = ip_mode_url_admission(_selected(), resolve=lambda host: [FOREIGN])
    assert admit(f"https://{APP}/") is False


def test_a_withdrawn_name_is_refused_everywhere():
    recon = _selected()
    ih.withdraw_selected(recon, APP)
    assert ip_mode_url_admission(recon, resolve=lambda host: [T1])(f"https://{APP}/") is False
    assert admit_urls(None, recon, [f"https://{APP}/"], module="httpx", record=False)[0] == []
    assert APP not in known_addresses(recon)

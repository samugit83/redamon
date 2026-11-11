"""The IP-mode target set is built once per run, not once per item.

Building a TargetSet from a /16 takes about a third of a second, and a builder
that asked the gate once per address (tlsx did, per IP) turned a large project
into hours of CPU. target_admission.target_set memoises the set by its list, and
every per-item loop asks the gate once. This file counts constructions across
every IP-mode builder run on one recon dict: one in total.

Documentation ranges (RFC 5737) and reserved names only.
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker, target_admission  # noqa: E402
from recon_settings.ip_hostnames import TargetSet  # noqa: E402

N = 300


def _ips(n=N):
    return [f"198.51.100.{i}" if i < 250 else f"203.0.113.{i - 250}" for i in range(1, n + 1)]


def _recon(ips):
    from recon.helpers.ip_placeholders import placeholder_for
    subs = {placeholder_for(ip): {"has_records": True, "is_mock": True, "actual_ip": ip,
                                  "ips": {"ipv4": [ip], "ipv6": []}} for ip in ips}
    names = {f"host{i}.example.com": ip for i, ip in enumerate(ips)}
    for name, ip in names.items():
        subs[name] = {"has_records": True, "ips": {"ipv4": [ip], "ipv6": []}}
    return {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "expanded_ips": list(ips), "filtered_mode": True,
                     "scope_mode": "exact", "include_root_domain": False,
                     "subdomain_filter": [*ips, *subs]},
        "subdomains": list(subs),
        "dns": {"domain": {}, "subdomains": subs},
        "port_scan": {
            "by_ip": {ip: {"ip": ip, "ports": [22, 993, 6333], "hostnames": [n]}
                      for n, ip in names.items()},
            "by_host": {**{ip: {"host": ip, "ip": ip, "ports": [22, 993, 6333],
                                "port_details": [{"port": 993, "service": "imaps"}]} for ip in ips},
                        **{n: {"host": n, "ip": ip, "ports": [22],
                               "port_details": [{"port": 22, "service": "ssh"}]} for n, ip in names.items()}},
        },
        "http_probe": {"by_url": {f"https://{ip}": {"url": f"https://{ip}", "ip": ip, "status_code": 200}
                                  for ip in ips}},
    }


@pytest.fixture
def built(monkeypatch):
    circuit_breaker.reset_registry()
    target_admission._TARGET_SETS.clear()
    calls = []
    original = TargetSet.from_entries.__func__

    def counting(cls, entries):
        calls.append(len(list(entries)))
        return original(cls, entries)

    monkeypatch.setattr(TargetSet, "from_entries", classmethod(counting))
    yield calls
    target_admission._TARGET_SETS.clear()
    circuit_breaker.reset_registry()


def test_tlsx_builds_the_set_once_for_every_address(built, monkeypatch):
    from recon.main_recon_modules.tls_scan import _build_tlsx_targets
    contexts = []
    real = target_admission.admission_context
    monkeypatch.setattr(target_admission, "admission_context",
                        lambda *a, **k: contexts.append(1) or real(*a, **k))
    lines, _ = _build_tlsx_targets(_recon(_ips()), {"TLSX_MAX_TARGETS": 10_000})
    assert len(lines) == 3 * N          # three TLS-candidate ports on each address
    assert built == [N]
    # The gate is asked a fixed number of times, not once per address: each
    # ask hashes the whole target list.
    assert len(contexts) <= 2


def test_every_ip_mode_builder_shares_one_set(built):
    from recon.helpers import security_checks
    from recon.helpers.target_admission import ip_mode_url_admission
    from recon.helpers.target_helpers import extract_targets_from_recon as dns_targets
    from recon.main_recon_modules import (ai_surface_recon, http_probe, ip_attribution,
                                          nmap_scan, port_scan, tls_scan, vhost_sni_enum)
    ips = _ips()
    recon = _recon(ips)

    port_scan.extract_targets_from_recon(recon)
    dns_targets(recon)
    nmap_scan.build_nmap_targets(recon, {})
    tls_scan._build_tlsx_targets(recon, {})
    http_probe._run_addresses(recon, [f"https://{ip}" for ip in ips])
    with mock.patch.object(http_probe, "grab_banner_for_target",
                           side_effect=lambda t, *a, **k: {"host": t[2], "port": t[1]}):
        http_probe.run_banner_grab(recon, {"BANNER_GRAB_THREADS": 4})
    target_admission.admit_urls(None, recon, [f"https://{ip}" for ip in ips], module="httpx")
    security_checks._ip_mode_hosts(recon, [f"host{i}.example.com" for i in range(N)], ips,
                                   {f"host{i}.example.com": [ip] for i, ip in enumerate(ips)})
    vhost_sni_enum._collect_ip_targets(recon)
    ip_attribution._run_ips(recon, {})
    session = mock.Mock()
    session.get.return_value = mock.Mock(status_code=404, text="")
    ai_surface_recon._confirm_vector_dbs(recon, session, 1)
    admit = ip_mode_url_admission(
        recon, resolve=lambda host: [ips[0]] if host == "host0.example.com" else ["192.0.2.250"])
    assert all(admit(f"http://{ip}/a.js") for ip in ips)
    assert all(admit(f"http://host{i}.example.com/") is (i == 0) for i in range(N))

    assert built == [N]


def test_a_different_list_is_a_different_set(built):
    first = target_admission.target_set(["203.0.113.1"])
    assert target_admission.target_set(("203.0.113.1",)) is first
    second = target_admission.target_set(["203.0.113.2"])
    assert second is not first and "203.0.113.2" in second and "203.0.113.2" not in first
    assert built == [1, 1]


def test_the_memo_keeps_only_a_few_lists(built):
    for i in range(target_admission._TARGET_SETS_MAX + 3):
        target_admission.target_set([f"203.0.113.{i + 1}"])
    assert len(target_admission._TARGET_SETS) == target_admission._TARGET_SETS_MAX
    # The oldest was dropped: asking again builds it again.
    target_admission.target_set(["203.0.113.1"])
    assert len(built) == target_admission._TARGET_SETS_MAX + 4

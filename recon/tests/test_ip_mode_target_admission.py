"""The IP-mode rule inside the one target gate (recon/helpers/target_admission.py).

An IP-mode run's targets are addresses (``metadata.expanded_ips``, after the RoE
filter). Every builder already calls ``admit_targets``; in IP mode it admits an
address only when it is a target (CIDR-aware, any IPv6 spelling), a name only
when it has a known address and every one is a target, and an IP-mode label
only as the address it stands for. The rule is membership, never routability:
a private target passes (D-13). Domain mode through the gate is unchanged
(fixtures/target_admission_vectors.json and test_target_admission.py).

Documentation ranges (RFC 5737 / RFC 3849), the private 10.0.0.0/8 and
reserved names only.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.target_admission import (  # noqa: E402
    REASON_OUTSIDE_TARGETS,
    REASON_ROE_EXCLUDED,
    admission_context,
    admit_host_targets,
    admit_ip_map,
    admit_targets,
    admit_urls,
    clamp_to_targets,
    forward_verdict,
    ip_mode_targets,
    ip_mode_url_admission,
    is_target,
    target_set,
)

T1, T2, FOREIGN = "203.0.113.1", "203.0.113.2", "198.51.100.7"
V6 = "2001:db8::1"


def _recon(expanded=(T1, T2), **extra):
    meta = {"ip_mode": True, "expanded_ips": list(expanded)}
    meta.update(extra.pop("metadata", {}))
    return {"metadata": meta, **extra}


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


# ---------------------------------------------------------------------------
# The context
# ---------------------------------------------------------------------------

def test_ip_mode_with_a_target_list_is_never_inert():
    ctx = admission_context(None, _recon())
    assert ctx.active and ctx.targets is not None and not ctx.excluded


def test_domain_mode_stays_inert():
    assert not admission_context(None, {"metadata": {"ip_mode": False, "expanded_ips": [T1]}}).active
    assert ip_mode_targets({"metadata": {"ip_mode": False}}) is None
    assert ip_mode_targets(None) is None


def test_an_ip_mode_dict_with_no_declared_list_admits_nothing(capsys):
    # I-6: every full and partial builder declares the list
    # (test_partial_ip_mode_metadata_guard.py), so a dict without one is a
    # bug to fail closed on, never a domain run.
    undeclared = {"metadata": {"ip_mode": True}}
    ctx = admission_context(None, undeclared)
    assert ctx.active and ctx.targets is not None and T1 not in ctx.targets
    adm = admit_targets(None, undeclared, ips=[T1], names={"www.example.com": [T1]},
                        module="naabu", record=False)
    assert adm.ips == [] and adm.names == {}
    assert {r.reason for r in adm.refusals} == {REASON_OUTSIDE_TARGETS}
    assert clamp_to_targets(undeclared, [T1, T2]) == []
    assert admit_host_targets(None, undeclared, {T1}, {"www.example.com"},
                              {T1: ["www.example.com"]}, module="naabu", record=False) == (set(), set(), {})
    admit = ip_mode_url_admission(undeclared, resolve=lambda _host: [T1])
    assert admit is not None and not admit(f"http://{T1}/") and not admit("http://www.example.com/")
    out = capsys.readouterr().out
    assert out.count("declares no target list") == 1


def test_a_declared_empty_list_admits_nothing():
    adm = admit_targets(None, _recon(expanded=()), ips=[T1], names={"www.example.com": [T1]},
                        module="naabu", record=False)
    assert adm.ips == [] and adm.names == {}
    assert {r.reason for r in adm.refusals} == {REASON_OUTSIDE_TARGETS}


@pytest.mark.parametrize("address, expected", [
    (T1, True), ("203.0.113.001", False), (FOREIGN, False),
    ("2001:DB8:0::1", True), (f"[{V6}]", True), ("2001:db8::2", False),
    ("not-an-ip", False), ("", False),
])
def test_membership_is_canonical(address, expected):
    targets = target_set([T1, V6])
    assert is_target(address, targets) is expected


def test_a_cidr_entry_means_its_hosts():
    targets = target_set(["192.0.2.0/30"])
    assert is_target("192.0.2.1", targets) and is_target("192.0.2.2", targets)
    assert not is_target("192.0.2.0", targets)       # network address
    assert not is_target("192.0.2.3", targets)       # broadcast


# ---------------------------------------------------------------------------
# admit_targets in IP mode
# ---------------------------------------------------------------------------

def test_an_address_outside_the_targets_is_refused():
    adm = admit_targets(None, _recon(), ips=[T1, FOREIGN, T2], module="naabu", record=False)
    assert adm.ips == [T1, T2]
    assert [(r.target, r.reason) for r in adm.refusals] == [(FOREIGN, REASON_OUTSIDE_TARGETS)]


def test_a_private_target_passes_membership_not_routability():
    adm = admit_targets(None, _recon(expanded=("10.0.0.5",)), ips=["10.0.0.5", "10.0.0.6"],
                        module="tlsx", record=False)
    assert adm.ips == ["10.0.0.5"]
    assert adm.refused() == ["10.0.0.6"]


def test_a_name_whose_every_address_is_a_target_is_admitted():
    adm = admit_targets(None, _recon(), names={"www.example.com": [T1, T2]}, module="httpx",
                        resolves_names=True, record=False)
    assert adm.names == {"www.example.com": [T1, T2]} and adm.refusals == []


def test_a_ptr_name_pointing_outside_is_refused_with_its_address():
    adm = admit_targets(None, _recon(), names={"www.example.com": [FOREIGN]}, module="naabu",
                        record=False)
    assert adm.names == {} and adm.split == {} and adm.ips == []
    assert [(r.target, r.reason, r.name) for r in adm.refusals] == [
        (FOREIGN, REASON_OUTSIDE_TARGETS, "www.example.com"),
        ("www.example.com", REASON_OUTSIDE_TARGETS, ""),
    ]


def test_a_mixed_name_is_reachable_by_its_target_address_only():
    adm = admit_targets(None, _recon(), names={"mixed.example.com": [T1, FOREIGN]},
                        module="httpx", resolves_names=True, record=False)
    assert adm.names == {}
    assert adm.split == {"mixed.example.com": [T1]}
    assert ("mixed.example.com", REASON_OUTSIDE_TARGETS) in [(r.target, r.reason) for r in adm.refusals]
    # A tool that only takes addresses (naabu) gets no name refusal for it.
    naabu = admit_targets(None, _recon(), names={"mixed.example.com": [T1, FOREIGN]},
                          module="naabu", record=False)
    assert "mixed.example.com" not in naabu.refused()


def test_a_name_with_no_known_address_is_refused():
    adm = admit_targets(None, _recon(), names={"ghost.example.com": []}, module="httpx",
                        record=False)
    assert adm.names == {}
    assert [(r.target, r.reason, r.detail) for r in adm.refusals] == [
        ("ghost.example.com", REASON_OUTSIDE_TARGETS, "no known address")]


def test_a_label_is_only_the_address_it_stands_for():
    adm = admit_targets(None, _recon(), names={"203-0-113-1": [T1], "198-51-100-7": [FOREIGN]},
                        module="httpx", resolves_names=True, record=False)
    assert adm.names == {} and adm.split == {}
    assert adm.ips == [T1]
    assert [(r.target, r.reason) for r in adm.refusals] == [(FOREIGN, REASON_OUTSIDE_TARGETS)]


def test_the_roe_is_asked_before_the_target_list():
    settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["198.51.100.0/24"]}
    adm = admit_targets(settings, _recon(), ips=[T1, FOREIGN, "192.0.2.9"], module="naabu",
                        record=False)
    assert adm.ips == [T1]
    assert [(r.target, r.reason) for r in adm.refusals] == [
        (FOREIGN, REASON_ROE_EXCLUDED), ("192.0.2.9", REASON_OUTSIDE_TARGETS)]


def test_an_ip_mode_refusal_is_logged_once_and_never_noted(capsys):
    for _ in range(2):
        admit_targets(None, _recon(), ips=[FOREIGN], names={"www.example.com": [FOREIGN]},
                      module="naabu")
    out = capsys.readouterr().out.splitlines()
    assert [line for line in out if line.startswith("[-][")] == [
        "[-][IpMode] naabu: not sent to 3 host(s) outside the IP target list: "
        "198.51.100.7 (www.example.com), www.example.com, 198.51.100.7"]
    # Not a target is a decision, not a coverage gap: the prune is unchanged.
    assert [dict(g) for g in circuit_breaker.coverage_report().gaps] == []


# ---------------------------------------------------------------------------
# The adapters the builders call
# ---------------------------------------------------------------------------

def test_host_targets_drop_foreign_answers_and_hand_no_label_as_a_name():
    recon = _recon()
    ips, hostnames, ip_map = admit_host_targets(
        None, recon, {T1, T2, FOREIGN},
        {"203-0-113-1", "203-0-113-2", "198-51-100-7", "www.example.com", "ok.example.com"},
        {T1: ["203-0-113-1", "ok.example.com"], T2: ["203-0-113-2"], FOREIGN: ["www.example.com",
                                                                               "198-51-100-7"]},
        module="naabu", record=False)
    assert ips == {T1, T2}
    # A label of a target stays listed (the URL builders skip labels; the
    # prune's keep list knows the host by it); a non-target's label does not.
    assert hostnames == {"ok.example.com", "203-0-113-1", "203-0-113-2"}
    # The map is what tools are handed names from: no label there.
    assert ip_map == {T1: ["ok.example.com"]}


def test_ip_map_keeps_the_target_addresses_and_their_names():
    ips, ip_map, _ = admit_ip_map(None, _recon(), [T1, FOREIGN, T2],
                                  {T1: ["203-0-113-1"], T2: [T2], FOREIGN: ["www.example.com"]},
                                  module="nmap", record=False)
    assert ips == [T1, T2]
    assert ip_map == {T2: [T2]}


def test_urls_keep_target_literals_and_target_names_only():
    recon = _recon(dns={"subdomains": {"ok.example.com": {"ips": {"ipv4": [T1]}},
                                       "www.example.com": {"ips": {"ipv4": [FOREIGN]}}}})
    urls = [f"https://{T1}", f"http://{FOREIGN}:8080", "https://203-0-113-1",
            "https://ok.example.com", "https://www.example.com", f"https://[{V6}]:8443"]
    kept, _ = admit_urls(None, _recon(expanded=(T1, V6), dns=recon["dns"]), urls, module="httpx",
                         record=False)
    assert kept == [f"https://{T1}", "https://ok.example.com", f"https://[{V6}]:8443"]


def test_urls_in_domain_mode_come_back_untouched():
    urls = ["https://www.example.com", f"http://{FOREIGN}"]
    kept, _ = admit_urls(None, {"metadata": {"ip_mode": False}}, urls, module="httpx")
    assert kept is urls


# ---------------------------------------------------------------------------
# The helpers the address-only readers call
# ---------------------------------------------------------------------------

def test_clamp_keeps_order_in_ip_mode_and_everything_otherwise():
    assert clamp_to_targets(_recon(), [T2, FOREIGN, T1]) == [T2, T1]
    assert clamp_to_targets({"metadata": {}}, [T2, FOREIGN]) == [T2, FOREIGN]


@pytest.mark.parametrize("answer, verdict", [
    ([T1], None),
    ([T1, T2], None),
    ([], "no_current_resolution"),
    ([T1, FOREIGN], "resolves_outside_targets"),
    (["127.0.0.1"], "never_scannable_address"),
    (["2001:DB8::1"], None),
])
def test_forward_verdict_is_the_selection_rule(answer, verdict):
    assert forward_verdict(answer, target_set([T1, T2, V6])) == verdict


def test_an_undeclared_list_still_admits_nothing_when_its_log_fails(monkeypatch):
    monkeypatch.setattr(circuit_breaker, "run_cache", lambda *_a: 1 / 0)
    assert clamp_to_targets({"metadata": {"ip_mode": True}}, [T1]) == []


def test_url_admission_is_none_outside_ip_mode():
    assert ip_mode_url_admission({"metadata": {"ip_mode": False}}) is None
    assert ip_mode_url_admission(None) is None


def test_url_admission_admits_targets_and_scope_names_that_resolve_to_them():
    recon = _recon(subdomains=["203-0-113-1", "app.example.com"],
                   metadata={"subdomain_filter": [T1, T2, "203-0-113-1", "app.example.com",
                                                  "moved.example.com"]})
    answers = {"app.example.com": [T1], "moved.example.com": [FOREIGN]}
    asked = []

    def resolve(host):
        asked.append(host)
        return answers.get(host, [])

    admit = ip_mode_url_admission(recon, resolve=resolve)
    assert admit(f"http://{T1}/app.js") is True
    assert admit(f"http://{FOREIGN}/app.js") is False          # a literal outside
    assert admit("https://app.example.com/a.js") is True        # a scope name on a target
    assert admit("https://APP.example.com./b.js") is True       # resolved once, cached
    assert admit("https://moved.example.com/") is False         # resolves outside now
    assert admit("https://cdn.thirdparty.test/x.js") is False   # not a run name: never resolved
    assert admit("http://203-0-113-1/") is False                # a label is no host
    assert admit("not a url") is False
    assert asked == ["app.example.com", "moved.example.com"]


def test_url_admission_refuses_a_name_that_does_not_resolve():
    recon = _recon(subdomains=["gone.example.com"])
    assert ip_mode_url_admission(recon, resolve=lambda host: [])("https://gone.example.com/") is False


def test_url_admission_default_resolver_fails_closed(monkeypatch):
    import socket
    from recon.helpers import target_admission

    def fail(*_a, **_k):
        raise OSError("no resolver")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert target_admission._resolve("app.example.com") == []
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_a, **_k: [(10, 1, 6, "", (f"{V6}%3", 0, 0, 3)), (2, 1, 6, "", (T1, 0))])
    assert target_admission._resolve("app.example.com") == [V6, T1]
    admit = ip_mode_url_admission(_recon(expanded=(T1, V6), subdomains=["app.example.com"]))
    assert admit("https://app.example.com/") is True


def test_two_labels_for_one_address_admit_it_once():
    # Two spellings of one IPv6 label (a raw entry and its expansion).
    adm = admit_targets(None, _recon(expanded=(V6,)), names={"2001-db8--1": [V6], "2001-DB8--1": [V6]},
                        module="naabu", record=False)
    assert adm.ips == [V6] and adm.names == {} and adm.refusals == []


def test_url_admission_ignores_junk_in_the_scope_lists():
    recon = _recon(subdomains=[None, 42, "", "app.example.com"])
    admit = ip_mode_url_admission(recon, resolve=lambda host: [T1])
    assert admit("https://app.example.com/") is True

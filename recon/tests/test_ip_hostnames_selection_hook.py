"""The hostnames hook of an IP-mode run, selection part (P4, design §5.4 steps 3-9).

M4 (record_filter) scans the names its include entries admit and its exclude
entries do not; M1 (scan_all) every name, except names on, or resolving to, a
shared CDN edge, and only with IP attribution (D-14: absent, crashed or missing
on the IP means attribution_unavailable). Every selected name resolves (A and
AAAA only) to target addresses alone; that answer is pinned and used by the
late scan. The resolver breaker is armed with a canary before the first lookup.
The cap keeps the first names in sorted order. Names cut for the cap, the
resolver or DNS off are noted degraded so the prune keeps their earlier
findings. Selected names join the run's DNS block, subdomains, scope list and
metadata.ip_mode_hosts before the late scan; the post-probe guard withdraws one
whose probe answered from an address outside the targets (moved_during_scan).

DNS, the resolver breaker and the late scan are injected. Documentation ranges
(RFC 5737, RFC 3849), the private 10.0.0.0/8 and reserved names only.
"""
from __future__ import annotations

import copy
import random
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import ip_hostnames as ih  # noqa: E402
from recon_settings.ip_hostnames import TargetSet  # noqa: E402

T1, T2, T3, PRIV, V6 = "203.0.113.10", "203.0.113.11", "203.0.113.12", "10.0.0.5", "2001:db8::10"
FOREIGN = "198.51.100.7"
APP, SHOP, OLD, BLOG, EDGE = ("app.example.com", "shop.example.com", "old.example.com",
                              "blog.other.test", "cdn.example.com")
MOCK = "ip-targets.cmselectionhook00000000001"
TARGETS = [T1, T2, T3, PRIV, V6]


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    circuit_breaker.reset_registry()
    armed = []
    monkeypatch.setattr(ih, "_arm_resolver", lambda canary: armed.append(canary) or True)
    yield armed
    circuit_breaker.reset_registry()


def _recon(ptr=None, **parts):
    labels = {ip: ip.replace(".", "-").replace(":", "-") for ip in TARGETS}
    run = {
        "domain": MOCK,
        "metadata": {"ip_mode": True, "expanded_ips": list(TARGETS), "root_domain": MOCK,
                     "ip_to_hostname": dict(labels), "subdomain_filter": [*TARGETS, *labels.values()]},
        "subdomains": list(labels.values()),
        "subdomain_count": len(labels),
        "dns": {"domain": {}, "subdomains": {
            label: {"is_mock": True, "actual_ip": ip, "has_records": True,
                    "ips": {"ipv4": [] if ":" in ip else [ip], "ipv6": [ip] if ":" in ip else []}, "records": {}}
            for ip, label in labels.items()}},
        "ip_hostnames": {"ptr": ptr if ptr is not None else {T1: [APP, OLD, BLOG], T2: [SHOP]}},
        "port_scan": {"by_ip": {T1: {"ip": T1, "hostnames": [], "ports": [443]}},
                      "by_host": {T1: {"host": T1, "ip": T1, "ports": [443], "port_details": [{"port": 443}]}}},
    }
    run.update(copy.deepcopy(parts))
    return run


def _settings(mode="record_filter", **extra):
    base = {"IP_MODE": True, "IP_HOSTNAME_MODE": mode, "IP_HOSTNAME_INCLUDE": ["*.example.com"],
            "IP_HOSTNAME_EXCLUDE": [], "IP_HOSTNAME_MAX_SCANNED": 100, "DNS_ENABLED": True,
            "IP_HOSTNAME_SCAN_ALL_CONFIRMED": mode == "scan_all"}
    base.update(extra)
    return base


def _dns(table):
    asked = []

    def resolve(name):
        asked.append(name)
        answer = table.get(name, [])
        if isinstance(answer, Exception):
            raise answer
        return list(answer)

    resolve.asked = asked
    return resolve


class _Late:
    """The late scan stand-in: records its call, answers with by_url rows."""

    def __init__(self, rows=None, result=True, fail=None):
        self.rows, self.result, self.fail, self.calls = rows or {}, result, fail, []

    def __call__(self, run, names, pinned, targets):
        self.calls.append({"names": list(names), "pinned": copy.deepcopy(pinned), "targets": targets,
                           "dns": sorted(run["dns"]["subdomains"]),
                           "filter": list(run["metadata"]["subdomain_filter"]),
                           "hosts": dict(run["metadata"].get("ip_mode_hosts") or {})})
        if self.fail:
            raise self.fail
        if not self.result:
            return None
        rows = {u: r for u, r in self.rows.items() if r["host"] in names}
        http = {"by_url": copy.deepcopy(rows),
                "by_host": {r["host"]: {"hostname": r["host"], "urls": [u]} for u, r in rows.items()},
                "technologies_found": {}, "servers_found": {}}
        run.setdefault("http_probe", {"by_url": {}, "by_host": {}})
        run["http_probe"]["by_url"].update(copy.deepcopy(rows))
        run["http_probe"]["by_host"].update(copy.deepcopy(http["by_host"]))
        return {"subdomains": list(names), "http_probe": http, "late_probed": sorted({r["host"] for r in rows.values()})}


def _step(run, settings, table=None, late=None):
    resolve = _dns(table if table is not None else {APP: [T1], SHOP: [T2], OLD: [T1], BLOG: [T1]})
    late = late if late is not None else _Late()
    block = ih.hostname_step(run, settings, resolve=resolve, late_scan=late)
    return block, resolve, late


def _reasons(block):
    return {n: c["reason"] for n, c in block["candidates"].items()}


# ---------------------------------------------------------------------------
# M4: include - exclude
# ---------------------------------------------------------------------------

def test_m4_scans_the_included_names_minus_the_excluded_ones():
    run = _recon()
    block, resolve, late = _step(run, _settings(IP_HOSTNAME_EXCLUDE=[OLD]))
    assert _reasons(block) == {APP: "scanned", SHOP: "scanned", OLD: "filter_excluded",
                               BLOG: "filter_no_match"}
    # Only names that passed the filters were looked up.
    assert sorted(resolve.asked) == [APP, SHOP]
    assert late.calls[0]["names"] == [APP, SHOP]
    assert late.calls[0]["pinned"] == {APP: [T1], SHOP: [T2]}
    assert isinstance(late.calls[0]["targets"], TargetSet)


def test_m4_unreadable_exclude_entry_scans_nothing():
    block, resolve, late = _step(_recon(), _settings(IP_HOSTNAME_EXCLUDE=["203.0.113.10"]))
    assert set(_reasons(block).values()) == {"invalid_filter"}
    assert resolve.asked == [] and late.calls == []


def test_m4_with_a_policy_that_cannot_be_read_scans_nothing():
    block, _, late = _step(_recon(), _settings(IP_HOSTNAME_INCLUDE="*.example.com"))
    assert set(_reasons(block).values()) == {"invalid_filter"} and late.calls == []


def test_selected_names_join_the_scope_before_the_late_scan():
    run = _recon()
    _, _, late = _step(run, _settings(IP_HOSTNAME_INCLUDE=[APP]))
    call = late.calls[0]
    # Inserted BEFORE the late scan (B-28): httpx keeps their results.
    assert APP in call["dns"] and APP in call["filter"] and call["hosts"] == {APP: "example.com"}
    entry = run["dns"]["subdomains"][APP]
    assert entry == {"has_records": True, "ips": {"ipv4": [T1], "ipv6": []}, "records": {"A": [T1]},
                     "source": "ip_hostname_selection", "ip_mode": True}
    assert APP in run["subdomains"] and run["subdomain_count"] == len(run["subdomains"])
    assert run["metadata"]["ip_mode_hosts"] == {APP: "example.com"}
    # Recorded names stay out of every scope list (I-4).
    for name in (SHOP, OLD, BLOG):
        assert name not in run["dns"]["subdomains"] and name not in run["metadata"]["subdomain_filter"]


def test_a_recording_mode_sets_no_selection_metadata():
    run = _recon()
    _step(run, _settings("record_only"))
    assert "ip_mode_hosts" not in run["metadata"]


# ---------------------------------------------------------------------------
# M1: all, minus shared edges, with attribution (D-14)
# ---------------------------------------------------------------------------

def _attribution(edge=(), failed=(), skip=()):
    by_ip = {}
    for ip in TARGETS:
        if ip in skip:
            continue
        if ip in failed:
            by_ip[ip] = {"ownership": "unknown", "ownership_reasons": ["attribution failed"]}
        else:
            by_ip[ip] = {"ownership": "shared_edge" if ip in edge else "dedicated", "ownership_reasons": []}
    return {"by_ip": by_ip}


def test_m1_scans_every_name_except_those_on_a_shared_edge():
    run = _recon(ip_attribution=_attribution(edge=[T2]))
    block, _, late = _step(run, _settings("scan_all"))
    assert _reasons(block) == {APP: "scanned", OLD: "scanned", BLOG: "scanned", SHOP: "shared_edge_ip"}
    assert late.calls[0]["names"] == [APP, BLOG, OLD]


def test_m1_refuses_a_name_resolving_to_a_shared_edge_target():
    run = _recon(ip_attribution=_attribution(edge=[T2]))
    block, _, _ = _step(run, _settings("scan_all"), table={APP: [T2], OLD: [T1], BLOG: [T1], SHOP: [T2]})
    assert _reasons(block)[APP] == "shared_edge_ip"
    assert block["candidates"][APP]["resolves_to_now"] == [T2]


def test_m1_without_attribution_scans_nothing():
    block, resolve, late = _step(_recon(), _settings("scan_all"))
    assert set(_reasons(block).values()) == {"attribution_unavailable"}
    assert resolve.asked == [] and late.calls == []


def test_m1_attribution_crashed_on_an_ip_refuses_the_names_seen_there():
    run = _recon(ip_attribution=_attribution(failed=[T1]))
    block, _, _ = _step(run, _settings("scan_all"))
    assert _reasons(block) == {APP: "attribution_unavailable", OLD: "attribution_unavailable",
                               BLOG: "attribution_unavailable", SHOP: "scanned"}


def test_m1_an_ip_attribution_never_reached_counts_as_failed():
    """The step writes its key even when it crashed before listing any IP: a
    target missing from by_ip has no attribution, so its names are refused."""
    run = _recon(ip_attribution=_attribution(skip=[T2]))
    block, _, _ = _step(run, _settings("scan_all"))
    assert _reasons(block)[SHOP] == "attribution_unavailable"
    assert _reasons(block)[APP] == "scanned"
    empty = _recon(ip_attribution={"by_ip": {}})
    block, _, _ = _step(empty, _settings("scan_all"))
    assert set(_reasons(block).values()) == {"attribution_unavailable"}


def test_m1_unconfirmed_records_and_scans_nothing(capsys):
    run = _recon(ip_attribution=_attribution())
    block, resolve, late = _step(run, _settings("scan_all", IP_HOSTNAME_SCAN_ALL_CONFIRMED=False))
    assert set(_reasons(block).values()) == {"record_only"}
    assert resolve.asked == [] and late.calls == []
    assert block["mode"] == "scan_all"
    assert "[!][IpNames] scan_all is not confirmed: every name is recorded, none is scanned" \
        in capsys.readouterr().out


# ---------------------------------------------------------------------------
# DNS: off, resolver down (canary), answers
# ---------------------------------------------------------------------------

def test_dns_off_refuses_and_notes_the_names_degraded(_fresh_run):
    block, resolve, late = _step(_recon(), _settings(DNS_ENABLED=False))
    assert _reasons(block) == {APP: "dns_disabled", SHOP: "dns_disabled", OLD: "dns_disabled",
                               BLOG: "filter_no_match"}
    assert resolve.asked == [] and late.calls == [] and _fresh_run == []
    keep = set(circuit_breaker.coverage_report().keep_hostnames())
    assert {APP, SHOP, OLD} <= keep and BLOG not in keep


def test_the_canary_is_armed_before_the_first_lookup(monkeypatch):
    order = []
    monkeypatch.setattr(ih, "_arm_resolver", lambda canary: order.append(("arm", canary)) or True)
    resolve = _dns({APP: [T1]})

    def tracked(name):
        order.append(("lookup", name))
        return resolve(name)

    ih.hostname_step(_recon(), _settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.other.test"]),
                     resolve=tracked, late_scan=_Late())
    assert order[0] == ("arm", "example.com")
    assert all(kind == "lookup" for kind, _ in order[1:])


def test_m1_canary_is_the_first_candidates_org(monkeypatch, _fresh_run):
    run = _recon(ip_attribution=_attribution())
    _step(run, _settings("scan_all"))
    assert _fresh_run == ["example.com"]  # app.example.com sorts first


def test_resolver_down_refuses_and_notes_the_names_degraded(monkeypatch):
    monkeypatch.setattr(ih, "_arm_resolver", lambda canary: False)
    block, resolve, late = _step(_recon(), _settings())
    assert _reasons(block)[APP] == "resolver_unavailable"
    assert resolve.asked == [] and late.calls == []
    assert {APP, SHOP, OLD} <= set(circuit_breaker.coverage_report().keep_hostnames())


def test_a_lookup_that_fails_refuses_that_name_only():
    block, _, _ = _step(_recon(), _settings(), table={APP: OSError("SERVFAIL"), SHOP: [T2], OLD: [T1]})
    assert _reasons(block)[APP] == "resolver_unavailable" and _reasons(block)[SHOP] == "scanned"
    assert APP in circuit_breaker.coverage_report().keep_hostnames()


def test_mixed_answers():
    block, _, late = _step(_recon(), _settings(), table={APP: [T1, FOREIGN], SHOP: [T2, V6], OLD: []})
    assert _reasons(block)[APP] == "resolves_outside_targets"
    assert _reasons(block)[SHOP] == "scanned" and _reasons(block)[OLD] == "no_current_resolution"
    # The pinned answer is canonical and sorted as text.
    assert late.calls[0]["pinned"] == {SHOP: [V6, T2]}
    cand = block["candidates"]
    assert (cand[APP]["resolves_to_now"], cand[APP]["resolves_here"]) == ([FOREIGN, T1], False)
    assert (cand[SHOP]["resolves_to_now"], cand[SHOP]["resolves_here"]) == ([V6, T2], True)
    assert "resolves_to_now" not in cand[BLOG]


def test_a_private_target_is_allowed():
    block, _, _ = _step(_recon(ptr={PRIV: ["intra.example.com"]}), _settings(),
                        table={"intra.example.com": [PRIV]})
    assert _reasons(block) == {"intra.example.com": "scanned"}


def test_a_never_scannable_answer_is_refused():
    block, _, _ = _step(_recon(), _settings(), table={APP: ["127.0.0.1"], SHOP: [T2], OLD: [T1]})
    assert _reasons(block)[APP] == "never_scannable_address"


# ---------------------------------------------------------------------------
# Guardrail, RoE, cap
# ---------------------------------------------------------------------------

def test_hard_blocked_and_roe_excluded_names_are_never_resolved(monkeypatch):
    monkeypatch.setattr(ih, "is_hard_blocked", lambda name: (name == APP, "protected"))
    block, resolve, _ = _step(_recon(), _settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[SHOP]))
    assert _reasons(block)[APP] == "hard_blocked" and _reasons(block)[SHOP] == "roe_excluded"
    assert APP not in resolve.asked and SHOP not in resolve.asked


def test_the_cap_keeps_the_first_names_in_sorted_order_whatever_the_input_order():
    names = [f"n{i:02d}.example.com" for i in range(6)]
    table = {n: [T1] for n in names}
    results = []
    for _ in range(3):
        shuffled = random.Random(len(results)).sample(names, len(names))
        block, _, late = _step(_recon(ptr={T1: shuffled}), _settings(IP_HOSTNAME_MAX_SCANNED=2), table=table)
        results.append((late.calls[0]["names"], _reasons(block)))
    assert all(r == results[0] for r in results)
    assert results[0][0] == names[:2]
    assert {n for n, r in results[0][1].items() if r == "cap_reached"} == set(names[2:])
    assert set(names[2:]) <= set(circuit_breaker.coverage_report().keep_hostnames())


def test_a_zero_cap_scans_nothing():
    block, resolve, late = _step(_recon(), _settings(IP_HOSTNAME_MAX_SCANNED=0))
    assert {r for r in _reasons(block).values()} == {"cap_reached", "filter_no_match"}
    assert resolve.asked == [] and late.calls == []


def test_degraded_names_are_bare_hostnames_the_prune_matches():
    _step(_recon(), _settings(DNS_ENABLED=False))
    report = circuit_breaker.coverage_report()
    assert APP in report.skipped_hostnames()
    assert any(g["source"] == "ip_hostnames" for g in report.gaps)


# ---------------------------------------------------------------------------
# Post-probe guard (I-1 c)
# ---------------------------------------------------------------------------

def test_a_name_whose_probe_answered_off_the_targets_is_withdrawn(capsys):
    rows = {f"https://{APP}": {"host": APP, "ip": FOREIGN, "status_code": 200},
            f"https://{SHOP}": {"host": SHOP, "ip": T2, "status_code": 200}}
    run = _recon()
    run["port_scan"]["by_host"][APP] = {"host": APP, "ip": T1, "ports": [443]}
    run["port_scan"]["by_ip"][T1]["hostnames"] = [APP]
    block, _, _ = _step(run, _settings(), late=_Late(rows))
    assert _reasons(block)[APP] == "moved_during_scan" and _reasons(block)[SHOP] == "scanned"
    assert f"https://{APP}" not in run["http_probe"]["by_url"]
    assert APP not in run["http_probe"]["by_host"]
    for where in (run["dns"]["subdomains"], run["subdomains"], run["metadata"]["subdomain_filter"],
                  run["metadata"]["ip_mode_hosts"], run["port_scan"]["by_host"]):
        assert APP not in where
    assert APP not in run["port_scan"]["by_ip"][T1]["hostnames"]
    assert SHOP in run["metadata"]["ip_mode_hosts"]
    assert f"[!][IpNames] {APP} answered from {FOREIGN}, outside the target IPs: its results are dropped" \
        in capsys.readouterr().out


def test_a_probe_that_reported_no_address_is_withdrawn_too():
    rows = {f"https://{APP}": {"host": APP, "ip": None, "status_code": 200}}
    block, _, _ = _step(_recon(), _settings(IP_HOSTNAME_INCLUDE=[APP]), late=_Late(rows))
    assert _reasons(block)[APP] == "moved_during_scan"


def test_the_guard_also_cleans_the_subset_the_graph_gets():
    rows = {f"https://{APP}": {"host": APP, "ip": FOREIGN, "status_code": 200},
            f"https://{SHOP}": {"host": SHOP, "ip": T2, "status_code": 200}}
    late = _Late(rows)
    captured = {}

    def keep(run, names, pinned, targets):
        captured["sub"] = late(run, names, pinned, targets)
        return captured["sub"]

    run = _recon()
    ih.hostname_step(run, _settings(), resolve=_dns({APP: [T1], SHOP: [T2], OLD: [T1]}), late_scan=keep)
    assert set(captured["sub"]["http_probe"]["by_url"]) == {f"https://{SHOP}"}
    assert APP not in captured["sub"]["subdomains"]
    # The http writer stamps the subset's summary on the Domain: the run's.
    assert captured["sub"]["http_probe"]["summary"] == run["http_probe"]["summary"]
    assert run["http_probe"]["summary"]["total_urls_probed"] == 1


def test_a_name_with_no_answer_from_the_probe_stays_scanned():
    block, _, _ = _step(_recon(), _settings(IP_HOSTNAME_INCLUDE=[SHOP]), late=_Late({}))
    assert _reasons(block)[SHOP] == "scanned"


def test_a_late_scan_that_raises_keeps_the_selection_and_notes_the_names(capsys):
    block, _, _ = _step(_recon(), _settings(), late=_Late(fail=RuntimeError("boom")))
    assert _reasons(block)[APP] == "scanned"
    assert {APP, SHOP, OLD} <= set(circuit_breaker.coverage_report().keep_hostnames())
    assert "[!][IpNames] Late scan of the selected hostnames failed (RuntimeError)" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Counts and logs
# ---------------------------------------------------------------------------

def test_counts_per_ip_and_summary():
    rows = {f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200}}
    block, _, _ = _step(_recon(), _settings(IP_HOSTNAME_EXCLUDE=[OLD]), late=_Late(rows))
    assert block["by_ip"][T1]["found"] == 3
    assert (block["by_ip"][T1]["scanned"], block["by_ip"][T1]["recorded"]) == (1, 2)
    assert (block["by_ip"][T2]["scanned"], block["by_ip"][T2]["recorded"]) == (1, 0)
    s = block["summary"]
    assert (s["found"], s["scanned"], s["recorded"], s["probed"], s["live"]) == (4, 2, 2, 1, 1)
    assert s["reasons"] == {"scanned": 2, "filter_excluded": 1, "filter_no_match": 1}


def test_log_lines(capsys):
    rows = {f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200}}
    _step(_recon(), _settings(IP_HOSTNAME_EXCLUDE=[OLD]), late=_Late(rows))
    lines = [l for l in capsys.readouterr().out.splitlines() if "[IpNames]" in l]
    assert lines == [
        "[*][IpNames] Mode: record_filter (include 1, exclude 1)",
        f"[*][IpNames] {T1}: 3 found (ptr 3) → 1 scanned, 2 recorded (1 filter_excluded, 1 filter_no_match)",
        f"[*][IpNames] {T2}: 1 found (ptr 1) → 1 scanned, 0 recorded",
        "[+][IpNames] Total: 4 found on 2 of 5 IPs → 2 scanned, 2 recorded; 1 probed by httpx, 1 live",
    ]


def test_scan_all_mode_line(capsys):
    _step(_recon(ip_attribution=_attribution()), _settings("scan_all"))
    assert "[*][IpNames] Mode: scan_all (shared CDN edges never scanned)" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# The default resolver: A and AAAA only, through the breaker, fail closed
# ---------------------------------------------------------------------------

class _Answer(list):
    pass


class _RR:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


def test_the_resolver_asks_a_and_aaaa_only():
    import dns.resolver
    asked = []

    def resolve(name, rtype, **_k):
        asked.append((name, rtype))
        if rtype == "AAAA":
            raise dns.resolver.NoAnswer()
        return _Answer([_RR(T1)])

    with mock.patch("dns.resolver.resolve", side_effect=resolve):
        assert ih.dns_resolver({})(APP) == [T1]
    assert asked == [(APP, "A"), (APP, "AAAA")]


def test_the_resolver_raises_when_the_breaker_opens_so_the_name_is_refused():
    import dns.resolver
    from recon.main_recon_modules.domain_recon import resolver_breaker
    with mock.patch("dns.resolver.resolve", side_effect=dns.resolver.LifetimeTimeout()), \
            mock.patch.object(resolver_breaker, "note_transient", return_value=True), \
            mock.patch.object(resolver_breaker, "is_open", return_value=False):
        with pytest.raises(ih.ResolverDown):
            ih.dns_resolver({})(APP)
    with mock.patch.object(resolver_breaker, "is_open", return_value=True):
        with pytest.raises(ih.ResolverDown):
            ih.dns_resolver({})(APP)


def test_the_resolver_never_guesses_after_its_retries():
    import dns.resolver
    from recon.main_recon_modules.domain_recon import resolver_breaker
    sleeps = []
    with mock.patch("dns.resolver.resolve", side_effect=dns.resolver.NoNameservers()), \
            mock.patch.object(resolver_breaker, "note_transient", return_value=False), \
            mock.patch.object(resolver_breaker, "is_open", return_value=False), \
            mock.patch.object(ih.time, "sleep", side_effect=sleeps.append):
        with pytest.raises(ih.ResolverDown):
            ih.dns_resolver({"DNS_MAX_RETRIES": 2})(APP)
    assert sleeps == [1]


def test_nxdomain_is_an_empty_answer():
    import dns.resolver
    with mock.patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        assert ih.dns_resolver({})(APP) == []


def test_arm_resolver_sets_the_canary_and_rechecks(monkeypatch):
    from recon.main_recon_modules.domain_recon import resolver_breaker
    calls = []
    monkeypatch.undo()  # the autouse stub of _arm_resolver
    with mock.patch.object(resolver_breaker, "set_canary", side_effect=lambda n: calls.append(("canary", n))), \
            mock.patch.object(resolver_breaker, "recheck", side_effect=lambda: calls.append(("recheck",)) or True), \
            mock.patch.object(resolver_breaker, "is_open", return_value=False):
        assert ih._arm_resolver("example.com") is True
    assert calls == [("canary", "example.com"), ("recheck",)]
    with mock.patch.object(resolver_breaker, "set_canary"), mock.patch.object(resolver_breaker, "recheck"), \
            mock.patch.object(resolver_breaker, "is_open", return_value=True):
        assert ih._arm_resolver("example.com") is False


def test_unreadable_dns_settings_fall_back_to_safe_values():
    assert ih._workers({"DNS_MAX_WORKERS": "lots"}) == 1
    assert ih._workers({"DNS_MAX_WORKERS": 500}) == 20
    import dns.resolver
    asked = []
    with mock.patch("dns.resolver.resolve", side_effect=lambda n, t, **k: asked.append(t) or _Answer()):
        assert ih.dns_resolver({"DNS_MAX_RETRIES": "x"})(APP) == []
    assert asked == ["A", "AAAA"]


def test_insert_is_idempotent_and_withdraw_tolerates_odd_shapes():
    run = _recon()
    ih.insert_selected(run, [APP], {APP: {"org_domain": "example.com"}}, {APP: [T1]})
    ih.insert_selected(run, [APP], {APP: {"org_domain": "example.com"}}, {APP: [T1]})
    assert run["subdomains"].count(APP) == 1 and run["metadata"]["subdomain_filter"].count(APP) == 1
    odd = {"subdomains": "x", "dns": {"subdomains": []}, "metadata": {"ip_mode_hosts": []},
           "port_scan": {"by_ip": {T1: "junk"}}, "http_probe": "x"}
    ih.withdraw_selected(odd, APP, sub={"subdomains": [APP]})
    assert odd["subdomains"] == "x"


def test_the_default_late_scan_is_the_pinned_late_names_scan(monkeypatch):
    from recon.helpers import late_names
    seen = {}
    monkeypatch.setattr(late_names, "scan_late_names",
                        lambda run, names, settings, **kw: seen.update(names=names, **kw) or None)
    ih.hostname_step(_recon(), _settings(IP_HOSTNAME_INCLUDE=[APP]), resolve=_dns({APP: [T1]}))
    assert seen["names"] == [APP] and seen["pinned"] == {APP: [T1]} and seen["label"] == "IpNames"
    assert seen["probe_http"] is True and isinstance(seen["targets"], TargetSet)


# ---------------------------------------------------------------------------
# The main.py step: late scan through _late_names, writes after the guard
# ---------------------------------------------------------------------------

@pytest.fixture
def rm(tmp_path, monkeypatch):
    stub = {
        "TARGET_DOMAIN": "", "SUBDOMAIN_LIST": [], "IP_MODE": True, "TARGET_IPS": [T1],
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": [],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": "cmselectionhook00000000001",
        "VERIFY_DOMAIN_OWNERSHIP": False, "STEALTH_MODE": False,
        "OWNERSHIP_TOKEN": "", "OWNERSHIP_TXT_PREFIX": "",
    }
    with mock.patch("recon.project_settings.get_settings", return_value=dict(stub)):
        for name in [m for m in list(sys.modules) if m in ("recon.main", "main")]:
            del sys.modules[name]
        import recon.main as module
        monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path)
        yield module


def test_the_step_scans_through_the_ip_mode_late_names_and_writes_after_the_guard(rm, monkeypatch):
    from recon.helpers import late_names
    seen = {}

    def fake_scan(run, names, settings, *, probe_http, label, pinned=None, targets=None, on_error=None, **_k):
        seen.update(names=list(names), pinned=pinned, targets=targets, probe_http=probe_http, label=label,
                    on_error=on_error)
        rows = {f"https://{APP}": {"host": APP, "ip": T1, "status_code": 200},
                f"https://{SHOP}": {"host": SHOP, "ip": FOREIGN, "status_code": 200}}
        run.setdefault("http_probe", {"by_url": {}, "by_host": {}})["by_url"].update(copy.deepcopy(rows))
        return {"subdomains": list(names), "http_probe": {"by_url": copy.deepcopy(rows), "by_host": {}},
                "late_probed": list(names)}

    monkeypatch.setattr(late_names, "scan_late_names", fake_scan)
    monkeypatch.setattr(ih, "dns_resolver", lambda settings: _dns({APP: [T1], SHOP: [T2], OLD: [T1]}))
    writes = []
    run = _recon()
    with mock.patch.object(rm, "_graph_update_bg", side_effect=lambda name, data, *a: writes.append((name, copy.deepcopy(data)))), \
            mock.patch.object(rm, "save_recon_file"):
        rm._ip_hostnames_step(run, _settings(), Path("/tmp/out.json"))
    assert seen["names"] == [APP, OLD, SHOP] and seen["probe_http"] is True and seen["label"] == "IpNames"
    assert seen["pinned"] == {APP: [T1], OLD: [T1], SHOP: [T2]} and isinstance(seen["targets"], TargetSet)
    assert [w for w, _ in writes] == ["update_graph_from_ip_hostnames", "update_graph_from_http_probe"]
    names_block = writes[0][1]["ip_hostnames"]["candidates"]
    assert names_block[SHOP]["reason"] == "moved_during_scan" and names_block[APP]["reason"] == "scanned"
    assert set(writes[1][1]["http_probe"]["by_url"]) == {f"https://{APP}"}
    # A failed late scan reports the http_probe phase, whose findings the prune then keeps.
    with mock.patch.object(rm, "_note_phase_error") as phase:
        seen["on_error"](RuntimeError("x"))
    phase.assert_called_once()
    assert phase.call_args.args[0] == "http_probe"


def test_late_names_in_ip_mode_takes_selected_names_only_and_writes_nothing(rm, monkeypatch):
    from recon.helpers import late_names
    seen = {}
    monkeypatch.setattr(late_names, "scan_late_names",
                        lambda run, names, settings, **kw: seen.update(names=names, **kw) or {"subdomains": names})
    run = _recon()
    ih.insert_selected(run, [APP], {APP: {"org_domain": "example.com"}}, {APP: [T1]})
    run["dns"]["subdomains"]["stray.example.com"] = {"has_records": True, "ips": {"ipv4": [T1], "ipv6": []}}
    before = set(run["dns"]["subdomains"]) - {APP, "stray.example.com"}
    with mock.patch.object(rm, "_graph_update_bg") as queue, mock.patch.object(rm, "save_recon_file") as save:
        sub = rm._late_names(run, before, _settings(), Path("/tmp/out.json"), after_port_scan=True,
                             probe_http=True, label="IpNames")
    assert seen["names"] == [APP] and seen["pinned"] == {APP: [T1]}
    assert isinstance(seen["targets"], TargetSet)
    assert sub == {"subdomains": [APP]}
    queue.assert_not_called()
    save.assert_not_called()

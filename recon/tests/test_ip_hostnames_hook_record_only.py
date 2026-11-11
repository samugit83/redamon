"""The hostnames hook of an IP-mode run, record part (P3, design §5.4 steps 1-2).

M2 (ip_only) skips the hook with one line. M3 (record_only) collects every
candidate, gives each the rule's reason (record_only, or the guardrail / RoE
code that comes first), adds nothing to the scope lists, logs one line per IP
that has a name and a total, bounds the volume per target IP and per run
(decision D-23: live sources first, then dated sources newest first, then by
name; what is cut is counted, never written), counts each IP's candidates
into IP attribution's current_dns_names (D-10) and queues the graph writer.
The scanning modes (M4, M1) are test_ip_hostnames_selection_hook.py's.

The hook itself is pure data; the main.py step is driven with mocks for the
graph queue and the recon file. Documentation ranges and reserved names only.
"""
from __future__ import annotations

import copy
import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import ip_hostnames as ih  # noqa: E402

T1, T2, T3 = "203.0.113.10", "203.0.113.11", "203.0.113.12"
MOCK = "ip-targets.cmhookrecordonly0000000001"


def _recon(**parts):
    parts = copy.deepcopy(parts)  # the hook writes into its own block
    labels = {ip: ip.replace(".", "-") for ip in (T1, T2, T3)}
    return {
        "domain": MOCK,
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2, T3], "root_domain": MOCK,
                     "ip_to_hostname": dict(labels),
                     "subdomain_filter": [T1, T2, T3, *labels.values()]},
        "subdomains": list(labels.values()),
        "dns": {"domain": {}, "subdomains": {
            label: {"is_mock": True, "actual_ip": ip, "has_records": True,
                    "ips": {"ipv4": [ip], "ipv6": []}, "records": {}}
            for ip, label in labels.items()}},
        **parts,
    }


def _settings(mode="record_only", **extra):
    return {"IP_MODE": True, "IP_HOSTNAME_MODE": mode, **extra}


SOURCES = dict(
    ip_hostnames={"ptr": {T1: ["web.example.com"]}},
    tlsx={"by_target": {f"{T1}:443": {"scanned_ip": T1, "subject_cn": "web.example.com",
                                      "san_raw": ["web.example.com", "app.example.com"]}}},
    otx={"ip_reports": [{"ip": T2, "passive_dns": [
        {"hostname": "old.example.org", "first": "2024-01-01", "last": "2025-06-01"}]}]},
)


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def test_ip_only_skips_with_one_line_and_collects_nothing(capsys):
    recon = _recon(**SOURCES)
    block = ih.hostname_step(recon, _settings("ip_only"))
    assert block is recon["ip_hostnames"]
    assert capsys.readouterr().out.strip() == "[-][IpNames] IP only: hostname discovery off"
    assert block["mode"] == "ip_only"
    assert block["candidates"] == {} and block["by_ip"] == {}
    assert block["summary"] == {
        "found": 0, "scanned": 0, "recorded": 0, "truncated": 0, "ips_with_names": 0, "reasons": {}}


def test_an_unknown_or_missing_mode_is_ip_only(capsys):
    for settings in ({"IP_MODE": True}, _settings("everything")):
        assert ih.hostname_step(_recon(**SOURCES), settings)["candidates"] == {}
    assert "IP only: hostname discovery off" in capsys.readouterr().out


def test_domain_mode_is_not_touched(capsys):
    recon = {"domain": "example.com", "metadata": {}, **copy.deepcopy(SOURCES)}
    assert ih.hostname_step(recon, {"IP_HOSTNAME_MODE": "record_only"}) is None
    assert capsys.readouterr().out == ""
    assert "candidates" not in recon["ip_hostnames"]


def test_record_only_records_every_candidate_and_adds_nothing_to_scope():
    recon = _recon(**SOURCES)
    before = {k: repr(recon[k]) for k in ("subdomains", "dns")}
    meta_before = {k: repr(recon["metadata"][k]) for k in ("subdomain_filter", "ip_to_hostname")}
    block = ih.hostname_step(recon, _settings())
    assert block is recon["ip_hostnames"]
    assert block["mode"] == "record_only"
    assert sorted(block["candidates"]) == ["app.example.com", "old.example.org", "web.example.com"]
    assert {c["reason"] for c in block["candidates"].values()} == {"record_only"}
    assert {k: repr(recon[k]) for k in ("subdomains", "dns")} == before
    assert {k: repr(recon["metadata"][k]) for k in ("subdomain_filter", "ip_to_hostname")} == meta_before
    assert "ip_mode_hosts" not in recon["metadata"]
    # The PTR answers GROUP 1 left there are kept as evidence.
    assert block["ptr"] == {T1: ["web.example.com"]}


def test_the_candidate_carries_its_evidence():
    block = ih.hostname_step(_recon(**SOURCES), _settings())
    web = block["candidates"]["web.example.com"]
    assert web == {
        "ips_seen": [T1], "sources": ["ptr", "tlsx_cn", "tlsx_san"],
        "first_seen": None, "last_seen": None, "cert_covers": True,
        "org_domain": "example.com", "on_shared_edge": None,
        "seen_on": {T1: {"sources": ["ptr", "tlsx_cn", "tlsx_san"], "first_seen": None,
                         "last_seen": None, "cert_covers": True}},
        "reason": "record_only",
    }
    old = block["candidates"]["old.example.org"]
    assert (old["first_seen"], old["last_seen"], old["cert_covers"]) == ("2024-01-01", "2025-06-01", False)


def test_counts_per_ip_and_summary():
    block = ih.hostname_step(_recon(**SOURCES), _settings())
    assert block["by_ip"] == {
        T1: {"found": 2, "scanned": 0, "recorded": 2, "truncated": 0,
             "reasons": {"record_only": 2}, "sources": {"cert": 2, "ptr": 1}},
        T2: {"found": 1, "scanned": 0, "recorded": 1, "truncated": 0,
             "reasons": {"record_only": 1}, "sources": {"otx": 1}},
    }
    assert block["summary"] == {"found": 3, "scanned": 0, "recorded": 3, "truncated": 0,
                                "ips_with_names": 2, "reasons": {"record_only": 3}}


def test_the_guardrail_and_the_roe_come_before_record_only(monkeypatch):
    monkeypatch.setattr(ih, "is_hard_blocked",
                        lambda name: (name == "web.example.com", "protected"))
    block = ih.hostname_step(_recon(**SOURCES), _settings(
        ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["*.example.org"]))
    reasons = {n: c["reason"] for n, c in block["candidates"].items()}
    assert reasons == {"web.example.com": "hard_blocked", "old.example.org": "roe_excluded",
                       "app.example.com": "record_only"}


def test_the_roe_list_is_ignored_when_the_roe_is_off():
    block = ih.hostname_step(_recon(**SOURCES), _settings(
        ROE_ENABLED=False, ROE_EXCLUDED_HOSTS=["*.example.org"]))
    assert block["candidates"]["old.example.org"]["reason"] == "record_only"


def test_on_shared_edge_follows_ip_attribution():
    recon = _recon(**SOURCES, ip_attribution={"by_ip": {
        T1: {"ownership": "shared_edge", "current_dns_names": 0},
        T2: {"ownership": "unknown", "current_dns_names": 0}}})
    block = ih.hostname_step(recon, _settings())
    assert block["candidates"]["web.example.com"]["on_shared_edge"] is True
    assert block["candidates"]["old.example.org"]["on_shared_edge"] is False


# ---------------------------------------------------------------------------
# D-10: current_dns_names counts the candidates on each IP in the record modes
# ---------------------------------------------------------------------------

def test_current_dns_names_counts_the_candidates_seen_on_each_ip():
    recon = _recon(**SOURCES, ip_attribution={"by_ip": {
        T1: {"ownership": "unknown", "current_dns_names": 0},
        T2: {"ownership": "unknown", "current_dns_names": 0},
        T3: {"ownership": "unknown", "current_dns_names": 0},
        "junk": "junk"}})
    ih.hostname_step(recon, _settings())
    by_ip = recon["ip_attribution"]["by_ip"]
    assert [by_ip[ip]["current_dns_names"] for ip in (T1, T2, T3)] == [2, 1, 0]


def test_ip_only_leaves_current_dns_names_at_zero():
    recon = _recon(**SOURCES, ip_attribution={"by_ip": {T1: {"ownership": "unknown", "current_dns_names": 0}}})
    ih.hostname_step(recon, _settings("ip_only"))
    assert recon["ip_attribution"]["by_ip"][T1]["current_dns_names"] == 0


# ---------------------------------------------------------------------------
# Logs (design §7)
# ---------------------------------------------------------------------------

def test_log_lines(capsys):
    ih.hostname_step(_recon(**SOURCES), _settings())
    lines = [l for l in capsys.readouterr().out.splitlines() if "[IpNames]" in l]
    assert lines == [
        "[*][IpNames] Mode: record_only",
        f"[*][IpNames] {T1}: 2 found (cert 2, ptr 1) → 0 scanned, 2 recorded (2 record_only)",
        f"[*][IpNames] {T2}: 1 found (otx 1) → 0 scanned, 1 recorded (1 record_only)",
        "[+][IpNames] Total: 3 found on 2 of 3 IPs → 0 scanned, 3 recorded",
    ]


def test_a_run_without_names_prints_the_total_only(capsys):
    ih.hostname_step(_recon(), _settings())
    lines = [l for l in capsys.readouterr().out.splitlines() if "[IpNames]" in l]
    assert lines == ["[*][IpNames] Mode: record_only",
                     "[+][IpNames] Total: 0 found on 0 of 3 IPs → 0 scanned, 0 recorded"]


def test_reasons_in_the_line_are_most_frequent_first(monkeypatch, capsys):
    monkeypatch.setattr(ih, "is_hard_blocked", lambda name: (name.startswith("z"), "protected"))
    ih.hostname_step(_recon(ip_hostnames={"ptr": {T1: ["a.example.com", "za.example.com", "zb.example.com"]}}),
                     _settings())
    out = capsys.readouterr().out
    assert f"{T1}: 3 found (ptr 3) → 0 scanned, 3 recorded (2 hard_blocked, 1 record_only)" in out


# ---------------------------------------------------------------------------
# Volume bound (D-23)
# ---------------------------------------------------------------------------

def _many(ip, count, prefix="n"):
    return [f"{prefix}{i:03d}.example.com" for i in range(count)]


def test_the_module_bounds_are_the_decided_ones():
    assert (ih.MAX_CANDIDATES_PER_IP, ih.MAX_CANDIDATES_PER_RUN) == (500, 20000)


def test_the_per_ip_bound_keeps_live_then_newest_then_by_name(monkeypatch, capsys):
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_IP", 4)
    recon = _recon(
        ip_hostnames={"ptr": {T1: ["zz-live.example.com"]}},
        otx={"ip_reports": [{"ip": T1, "passive_dns": [
            {"hostname": "a-old.example.com", "last": "2020-01-01"},
            {"hostname": "b-new.example.com", "last": "2026-01-01"},
            {"hostname": "c-mid.example.com", "last": "2023-01-01"},
            {"hostname": "d-undated.example.com"},
            {"hostname": "e-undated.example.com"},
        ]}]},
    )
    block = ih.hostname_step(recon, _settings())
    assert sorted(block["candidates"]) == ["a-old.example.com", "b-new.example.com",
                                           "c-mid.example.com", "zz-live.example.com"]
    assert block["by_ip"][T1]["truncated"] == 2
    assert block["by_ip"][T1]["found"] == 4
    assert block["summary"]["truncated"] == 2
    out = capsys.readouterr().out
    assert (f"{T1}: 4 found (ptr 1, otx 3) → 0 scanned, 4 recorded (4 record_only) "
            "(+2 not kept: per-IP limit)") in out
    assert "Total: 4 found on 1 of 3 IPs → 0 scanned, 4 recorded; 2 not kept (volume limit)" in out


def test_a_name_cut_on_one_ip_is_kept_on_another(monkeypatch):
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_IP", 1)
    recon = _recon(ip_hostnames={"ptr": {T1: ["a.example.com", "b.example.com"],
                                         T2: ["b.example.com"]}})
    block = ih.hostname_step(recon, _settings())
    assert block["candidates"]["b.example.com"]["ips_seen"] == [T2]
    assert list(block["candidates"]["b.example.com"]["seen_on"]) == [T2]
    assert block["by_ip"][T1]["truncated"] == 1
    # b is still recorded (on T2): only names kept nowhere count as truncated.
    assert block["summary"]["truncated"] == 0


def test_the_per_run_bound_cuts_whole_names_and_counts_them_per_ip(monkeypatch, capsys):
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_RUN", 3)
    recon = _recon(ip_hostnames={"ptr": {T1: _many(T1, 3, "a")}},
                   otx={"ip_reports": [{"ip": T2, "passive_dns": [
                       {"hostname": n, "last": "2026-01-01"} for n in _many(T2, 2, "b")]}]})
    block = ih.hostname_step(recon, _settings())
    # The three live PTR names win; both dated passive-DNS names are cut.
    assert sorted(block["candidates"]) == _many(T1, 3, "a")
    assert block["summary"]["truncated"] == 2
    assert block["by_ip"][T2] == {"found": 0, "scanned": 0, "recorded": 0, "truncated": 2,
                                  "reasons": {}, "sources": {}}
    out = capsys.readouterr().out
    assert f"{T2}: 0 found → 0 scanned, 0 recorded (+2 not kept: per-run limit)" in out


def test_the_bound_is_deterministic_under_shuffled_input(monkeypatch):
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_IP", 5)
    names = _many(T1, 12)
    first = ih.hostname_step(_recon(ip_hostnames={"ptr": {T1: names}}), _settings())
    second = ih.hostname_step(_recon(ip_hostnames={"ptr": {T1: list(reversed(names))}}), _settings())
    assert sorted(first["candidates"]) == sorted(second["candidates"]) == names[:5]


# ---------------------------------------------------------------------------
# The main.py step
# ---------------------------------------------------------------------------

@pytest.fixture
def rm(tmp_path, monkeypatch):
    stub = {
        "TARGET_DOMAIN": "", "SUBDOMAIN_LIST": [], "IP_MODE": True, "TARGET_IPS": [T1],
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": [],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": "cmhookrecordonly0000000001",
        "VERIFY_DOMAIN_OWNERSHIP": False, "STEALTH_MODE": False,
        "OWNERSHIP_TOKEN": "", "OWNERSHIP_TXT_PREFIX": "",
    }
    with mock.patch("recon.project_settings.get_settings", return_value=dict(stub)):
        for name in [m for m in list(sys.modules) if m in ("recon.main", "main")]:
            del sys.modules[name]
        import recon.main as module
        monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path)
        yield module


def _step(rm, recon, settings):
    writes, saves = [], []
    with mock.patch.object(rm, "_graph_update_bg", side_effect=lambda name, data, *a: writes.append((name, data))), \
            mock.patch.object(rm, "save_recon_file", side_effect=lambda data, path: saves.append(path)):
        rm._ip_hostnames_step(recon, settings, Path("/tmp/out.json"))
    return [w for w, _ in writes], saves, writes


def test_the_step_queues_the_writer_and_the_attribution_counts(rm):
    recon = _recon(**SOURCES, ip_attribution={"by_ip": {T1: {"ownership": "unknown", "current_dns_names": 0}}})
    names, saves, writes = _step(rm, recon, _settings())
    assert names == ["update_graph_from_ip_hostnames", "update_graph_from_ip_attribution"]
    assert saves == [Path("/tmp/out.json")]
    # The writer gets the recorded names; the attribution its new count.
    assert "web.example.com" in writes[0][1]["ip_hostnames"]["candidates"]
    assert writes[1][1]["ip_attribution"]["by_ip"][T1]["current_dns_names"] == 2
    assert "ip_hostnames" in recon["metadata"]["modules_executed"]


def test_the_step_without_attribution_queues_the_writer_only(rm):
    names, _, _ = _step(rm, _recon(**SOURCES), _settings())
    assert names == ["update_graph_from_ip_hostnames"]


def test_ip_only_queues_the_writer_for_the_run_mode_alone(rm):
    recon = _recon(**SOURCES, ip_attribution={"by_ip": {T1: {"ownership": "unknown", "current_dns_names": 0}}})
    names, saves, writes = _step(rm, recon, _settings("ip_only"))
    # The writer stamps the run's mode on the mock root; there is no name to
    # record and no count to change, so the attribution is not written again.
    assert names == ["update_graph_from_ip_hostnames"]
    assert writes[0][1]["ip_hostnames"]["mode"] == "ip_only"
    assert writes[0][1]["ip_hostnames"]["candidates"] == {}
    assert saves == [Path("/tmp/out.json")]
    assert "ip_hostnames" not in recon["metadata"].get("modules_executed", [])


def test_domain_mode_has_no_hostname_step(rm):
    recon = {"domain": "example.com", "metadata": {"ip_mode": False}}
    names, saves, _ = _step(rm, recon, {"IP_HOSTNAME_MODE": "record_only"})
    assert names == [] and saves == []


def test_a_hook_failure_is_a_phase_error_never_a_crash(rm, capsys):
    recon = _recon(**SOURCES)
    with mock.patch.object(ih, "hostname_step", side_effect=RuntimeError("boom")):
        names, saves, _ = _step(rm, recon, _settings())
    assert names == [] and saves == []
    assert recon["metadata"]["phase_errors"]["ip_hostnames"] == "boom"
    assert "[!][IpNames] Hostname recording failed (RuntimeError): no name is recorded this run" \
        in capsys.readouterr().out


def test_the_step_sits_after_the_netlas_write_and_before_the_active_scan_gate(rm):
    body = inspect.getsource(rm.run_ip_recon)
    netlas = body.index("_write_netlas(combined_result)")
    hook = body.index("_ip_hostnames_step(combined_result, settings, output_file)")
    gate = body.index("should_skip_active_scans(combined_result)")
    assert netlas < hook < gate
    # Pipeline progress headers are GROUP lines only; the hook prints none.
    assert "GROUP" not in inspect.getsource(rm._ip_hostnames_step)

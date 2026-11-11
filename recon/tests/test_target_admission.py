"""The target-admission gate (design decision D2, R-2's foundation).

``admit_targets`` checks names against the RoE host entries and every address
a name resolved to against the RoE IP/CIDR entries, so a name resolving into
an excluded range is no longer a target (R-2). The rule table is
fixtures/target_admission_vectors.json; the tests here pin what the table
cannot: the gate is inert with no exclusion (same objects, no log, no note),
each refusal is logged once and noted under `roe_excluded`, a name with no
known address is a coverage gap the prune keeps, and the two adapters the
builders call keep their input order.
Reserved names and documentation ranges only.
"""
import json
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.target_admission import (  # noqa: E402
    REASON_ROE_EXCLUDED,
    REASON_ROE_UNRESOLVED,
    admission_context,
    admit_host_targets,
    admit_ip_map,
    admit_targets,
    admit_urls,
    known_addresses,
)

VECTORS = json.loads((Path(__file__).resolve().parent / "fixtures"
                      / "target_admission_vectors.json").read_text())["vectors"]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _settings(excluded, enabled=True):
    return {"ROE_ENABLED": enabled, "ROE_EXCLUDED_HOSTS": list(excluded)}


def _gaps():
    return [dict(g) for g in circuit_breaker.coverage_report().gaps]


@pytest.mark.parametrize("v", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(v):
    recon = {"metadata": {"ip_mode": v.get("ip_mode", False),
                          "expanded_ips": v.get("expanded_ips", [])}}
    adm = admit_targets(_settings(v["roe"], v.get("enabled", True)), recon,
                        names=v.get("names", {}), ips=v.get("ips", []),
                        module="naabu", resolves_names=v.get("resolves_names", False))
    exp = v["expect"]
    assert adm.names == exp["names"]
    assert adm.split == exp["split"]
    assert adm.ips == exp["ips"]
    assert [[r.target, r.reason] for r in adm.refusals] == exp["refused"]


# --------------------------------------------------------------------------
# Inert with no exclusion
# --------------------------------------------------------------------------

@pytest.mark.parametrize("settings", [
    {},
    _settings([]),
    _settings(["198.51.100.0/24", "pay.example.com"], enabled=False),
], ids=["no_roe_keys", "empty_list", "switched_off"])
def test_no_exclusion_hands_back_the_same_objects_and_records_nothing(settings, capsys):
    ips = ["192.0.2.6", "198.51.100.20"]
    ip_map = {"192.0.2.6": ["www.example.com"], "198.51.100.20": ["pay.example.com"]}
    urls = ["https://pay.example.com", "http://198.51.100.20:8080", "http://new.example.com"]

    names = {"www.example.com", "pay.example.com", "new.example.com"}
    got_ips, got_map, _ = admit_ip_map(settings, {}, ips, ip_map, module="masscan")
    got_urls, adm = admit_urls(settings, {}, urls, module="httpx")
    triple = admit_host_targets(settings, {}, set(ips), names, ip_map, module="dns_targets")

    assert got_ips is ips and got_map is ip_map and got_urls is urls
    assert triple[1] is names and triple[2] is ip_map
    assert adm.refusals == []
    assert capsys.readouterr().out == ""
    assert _gaps() == []


def test_settings_switch_wins_over_the_recon_dict_copy():
    stamped = {"metadata": {"roe": _settings(["198.51.100.0/24"])}}
    assert admission_context({}, stamped).active
    assert admission_context(None, stamped).ip_rules
    assert not admission_context(_settings(["x"], enabled=False), stamped).active


@pytest.mark.parametrize("entry,ip_rule", [
    ("198.51.100.0/24", True), ("198.51.100.20", True), ("198.51.100.20/", True),
    ("198.51.100.0/255.255.255.0", True), ("2001:db8::/32", True), ("[2001:db8::1]", True),
    ("pay.example.com", False), ("*.example.com", False), ("0.5", False),
    ("https://pay.example.com/login", False),
])
def test_ip_rules_detection(entry, ip_rule):
    assert admission_context(_settings([entry])).ip_rules is ip_rule


# --------------------------------------------------------------------------
# Logging and coverage notes
# --------------------------------------------------------------------------

def test_each_refusal_is_logged_once_and_noted_once_per_module(capsys):
    s = _settings(["198.51.100.0/24", "pay.example.com"])
    names = {"legacy.example.com": ["198.51.100.20"], "pay.example.com": ["192.0.2.5"],
             "www.example.com": ["192.0.2.6"]}
    admit_targets(s, {}, names=names, module="naabu")
    admit_targets(s, {}, names=names, module="naabu")
    admit_targets(s, {}, names=names, module="httpx", resolves_names=True)

    out = capsys.readouterr().out
    assert out.count("legacy.example.com") == 2      # its address line and its own refusal
    assert out.count("[-][RoE] naabu:") == 1
    assert "[-][RoE] httpx:" not in out             # nothing new to say
    assert "www.example.com" not in out

    gaps = {(g["source"], g["module"]): g for g in _gaps()}
    assert gaps[("roe_excluded", "naabu")]["skipped"] == 3
    assert gaps[("roe_excluded", "httpx")]["skipped"] == 3
    assert "legacy.example.com" in gaps[("roe_excluded", "naabu")]["reason"]
    assert all(TOKEN.match(g["source"]) for g in _gaps())
    # Excluded targets are a report gap only: nothing is kept from the prune.
    report = circuit_breaker.coverage_report()
    assert not report.degraded_sources and not report.skipped_hosts


def test_unresolved_name_is_a_gap_whose_findings_the_prune_keeps(capsys):
    s = _settings(["198.51.100.0/24"])
    adm = admit_targets(s, {}, names={"new.example.com": [], "www.example.com": ["192.0.2.6"]},
                        module="nuclei", resolves_names=True)

    assert adm.refused(REASON_ROE_UNRESOLVED) == ["new.example.com"]
    report = circuit_breaker.coverage_report()
    assert "new.example.com" in report.skipped_hostnames()
    for source in ("nuclei", "security_check", "js_recon"):
        assert "new.example.com" in report.keep_hostnames(source)
    gap = next(g for g in _gaps() if g["source"] == "roe_excluded")
    assert gap["module"] == "nuclei" and gap["hosts"] == 1
    assert "no known address" in capsys.readouterr().out


def test_record_false_computes_without_a_trace(capsys):
    adm = admit_targets(_settings(["198.51.100.0/24"]), {},
                        names={"legacy.example.com": ["198.51.100.20"], "new.example.com": []},
                        module="port_coverage", record=False)
    assert adm.refused() == ["198.51.100.20", "legacy.example.com", "new.example.com"]
    assert capsys.readouterr().out == ""
    assert _gaps() == []


def test_a_hostile_name_cannot_forge_a_log_line(capsys):
    adm = admit_targets(_settings(["198.51.100.0/24"]), {},
                        names={"evil\n[DEGRADED] forged.example.com": ["198.51.100.5"]},
                        module="naabu")
    out = capsys.readouterr().out
    assert len(adm.refusals) == 2
    assert "[DEGRADED]" not in out and out.count("\n") == 1


# --------------------------------------------------------------------------
# Adapters
# --------------------------------------------------------------------------

def test_ip_map_drops_excluded_addresses_and_addresses_of_excluded_names_only():
    s = _settings(["198.51.100.0/24", "pay.example.com"])
    ips = ["192.0.2.5", "198.51.100.20", "192.0.2.6", "192.0.2.7", "192.0.2.9"]
    ip_map = {
        "192.0.2.5": ["pay.example.com"],                       # only an excluded name
        "198.51.100.20": ["mixed.example.com"],                  # excluded address
        "192.0.2.7": ["mixed.example.com", "pay.example.com"],   # shared with an excluded name
        "192.0.2.6": ["www.example.com"],
    }
    got_ips, got_map, adm = admit_ip_map(s, {}, ips, ip_map, module="masscan")

    assert got_ips == ["192.0.2.6", "192.0.2.7", "192.0.2.9"]   # input order, bare .9 kept
    assert got_map == {"192.0.2.7": ["mixed.example.com"], "192.0.2.6": ["www.example.com"]}
    assert adm.split == {"mixed.example.com": ["192.0.2.7"]}


def test_ip_map_in_ip_mode_keeps_the_authorized_ip_of_an_excluded_ptr_name():
    recon = {"metadata": {"ip_mode": True, "expanded_ips": ["192.0.2.10", "192.0.2.11"]}}
    got_ips, got_map, _ = admit_ip_map(
        _settings(["ptr.example.com"]), recon, ["192.0.2.10", "192.0.2.11"],
        {"192.0.2.10": ["ptr.example.com"], "192.0.2.11": ["192.0.2.11"]}, module="nmap")
    assert got_ips == ["192.0.2.10", "192.0.2.11"]
    assert got_map == {"192.0.2.11": ["192.0.2.11"]}


def _recon():
    return {
        "domain": "example.com",
        "dns": {
            "domain": {"ips": {"ipv4": ["192.0.2.1"], "ipv6": []}},
            "subdomains": {
                "www.example.com": {"has_records": True, "ips": {"ipv4": ["192.0.2.6"], "ipv6": []}},
                "mixed.example.com": {"has_records": True,
                                      "ips": {"ipv4": ["198.51.100.20", "192.0.2.7"], "ipv6": []}},
                "v6.example.com": {"has_records": True, "ips": {"ipv4": [], "ipv6": ["2001:db8::6"]}},
                "txt.example.com": {"has_records": True, "ips": {"ipv4": [], "ipv6": []}},
            },
        },
        "port_scan": {
            "by_host": {"mixed.example.com": {"host": "mixed.example.com", "ip": "192.0.2.7"},
                        "graph.example.com": {"host": "graph.example.com", "ip": "",
                                              "port_details": [{"port": 443, "ip": "192.0.2.8"}]}},
            "ip_to_hostnames": {"192.0.2.9": ["partial.example.com"]},
            "by_ip": {"192.0.2.6": {"hostnames": ["WWW.example.com."]}},
        },
    }


def test_known_addresses_reads_dns_and_the_port_scan_maps():
    known = known_addresses(_recon())
    assert known["example.com"] == ["192.0.2.1"]
    assert known["mixed.example.com"] == ["198.51.100.20", "192.0.2.7"]
    assert known["graph.example.com"] == ["192.0.2.8"]
    assert known["partial.example.com"] == ["192.0.2.9"]
    assert known["www.example.com"] == ["192.0.2.6"]
    assert "txt.example.com" not in known


def test_urls_keep_order_and_drop_every_host_the_tool_could_reach_an_exclusion_through():
    urls = [
        "https://www.example.com",
        "https://mixed.example.com:8443",       # one address excluded: httpx could pick it
        "http://198.51.100.21:8080",            # an excluded literal
        "https://[2001:db8::6]",
        "http://txt.example.com",               # no known address
        "http://www.example.com:8080/",
        "not a url",
    ]
    got, adm = admit_urls(_settings(["198.51.100.0/24"]), _recon(), urls, module="httpx")

    assert got == ["https://www.example.com", "https://[2001:db8::6]",
                   "http://www.example.com:8080/", "not a url"]
    assert set(adm.refused(REASON_ROE_EXCLUDED)) == {"198.51.100.20", "mixed.example.com",
                                                       "198.51.100.21"}
    assert adm.refused(REASON_ROE_UNRESOLVED) == ["txt.example.com"]


def test_urls_with_host_entries_only_keep_unresolved_names():
    urls = ["http://txt.example.com", "https://mixed.example.com"]
    got, adm = admit_urls(_settings(["pay.example.com"]), _recon(), urls, module="httpx")
    assert got == urls and adm.refusals == []


def test_host_triple_keeps_only_names_a_tool_may_resolve_and_every_admitted_address():
    ips = {"192.0.2.1", "192.0.2.6", "198.51.100.20", "198.51.100.21", "192.0.2.7", "192.0.2.40"}
    names = {"example.com", "www.example.com", "legacy.example.com", "mixed.example.com",
             "txt.example.com"}
    ip_map = {"192.0.2.1": ["example.com"], "192.0.2.6": ["www.example.com"],
              "198.51.100.20": ["legacy.example.com"],
              "198.51.100.21": ["mixed.example.com"], "192.0.2.7": ["mixed.example.com"],
              "192.0.2.40": ["norecords.example.com"]}   # mapped, but not a hostname
    got_ips, got_names, got_map = admit_host_targets(
        _settings(["198.51.100.0/24"]), {}, ips, names, ip_map, module="dns_targets")

    assert got_names == {"example.com", "www.example.com"}
    assert got_ips == {"192.0.2.1", "192.0.2.6", "192.0.2.7", "192.0.2.40"}
    assert got_map == {"192.0.2.1": ["example.com"], "192.0.2.6": ["www.example.com"],
                       "192.0.2.7": ["mixed.example.com"],
                       "192.0.2.40": ["norecords.example.com"]}
    assert "txt.example.com" in circuit_breaker.coverage_report().skipped_hostnames()

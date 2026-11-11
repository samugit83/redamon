"""
Hostnames on target IPs: the seven policy settings through the recon loader.

Every webapp write path validates the policy; the loader is the second look at
the trust boundary (a row edited in the database, an import from an older
release, a restored version). These tests pin what it does with each kind of
row: the defaults, the fetch mapping, the refusals that stop a run rather than
scan names nobody approved, and the fallbacks that only ever narrow.

Run it inside the recon image, never with host pytest: `./redamon.sh test unit`, or this
one file from the repo root:
    docker run --rm -v "$PWD":/repo -w /repo/recon -e PYTHONPATH=/repo/recon:/repo -e HOME=/tmp \\
      --entrypoint python redamon-recon:latest \\
      /repo/tooling/scripts/pytest_isolated.py unit tests/test_ip_hostname_settings.py
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from recon import settings_registry as reg
from recon.project_settings import DEFAULT_SETTINGS, ScopeRefused, fetch_project_settings

KEYS = {
    "IP_HOSTNAME_MODE": "ipHostnameMode",
    "IP_HOSTNAME_INCLUDE": "ipHostnameInclude",
    "IP_HOSTNAME_EXCLUDE": "ipHostnameExclude",
    "IP_HOSTNAME_PASSIVE_EXPAND": "ipHostnamePassiveExpand",
    "IP_HOSTNAME_SCAN_ALL_CONFIRMED": "ipHostnameScanAllConfirmed",
    "IP_HOSTNAME_MAX_SCANNED": "ipHostnameMaxScanned",
    "IP_HOSTNAME_PASSIVE_MAX_NAMES": "ipHostnamePassiveMaxNames",
}


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _fetch(**row) -> dict:
    payload = {"userId": "u1", "ipMode": True, "targetIps": ["203.0.113.10"],
               "targetDomain": "", **row}
    with patch("requests.get", return_value=_Resp(payload)):
        return fetch_project_settings("p1", "http://webapp.invalid")


# --- defaults and registry -----------------------------------------------------------

def test_defaults_are_the_strictest_policy():
    assert DEFAULT_SETTINGS["IP_HOSTNAME_MODE"] == "ip_only"
    assert DEFAULT_SETTINGS["IP_HOSTNAME_INCLUDE"] == []
    assert DEFAULT_SETTINGS["IP_HOSTNAME_EXCLUDE"] == []
    assert DEFAULT_SETTINGS["IP_HOSTNAME_PASSIVE_EXPAND"] is True
    assert DEFAULT_SETTINGS["IP_HOSTNAME_SCAN_ALL_CONFIRMED"] is False
    assert DEFAULT_SETTINGS["IP_HOSTNAME_MAX_SCANNED"] == 100
    assert DEFAULT_SETTINGS["IP_HOSTNAME_PASSIVE_MAX_NAMES"] == 500


@pytest.mark.parametrize("runtime_key,column", sorted(KEYS.items()))
def test_each_key_is_a_rescopable_targeting_field(runtime_key, column):
    """create_only + rescope + tool targeting is what puts a field in
    update_project_scope, the queued-job fingerprint, and out of presets and
    RoE parsing (design §9)."""
    spec = reg.field(column)
    assert spec["runtime_key"] == runtime_key
    assert spec["tool"] == "targeting"
    assert spec["phase"] == "standalone"
    assert spec["traffic"] == "none"
    assert spec["mcp"] == "create_only"
    assert spec["rescope"] is True
    assert spec["group"] == "scope"
    assert spec["form_section"] == "TargetSection"
    assert spec["default"] == DEFAULT_SETTINGS[runtime_key]


def test_the_registry_closes_the_mode_vocabulary_and_bounds_the_caps():
    assert reg.field("ipHostnameMode")["values"] == ["ip_only", "record_only", "record_filter", "scan_all"]
    assert reg.bounds_for("IP_HOSTNAME_MAX_SCANNED") == (1, 2000)
    assert reg.bounds_for("IP_HOSTNAME_PASSIVE_MAX_NAMES") == (1, 10000)
    assert reg.field("ipHostnameInclude")["validator"] == "hostname"
    assert reg.field("ipHostnameExclude")["validator"] == "hostname"


# --- the fetch mapping ---------------------------------------------------------------

def test_a_row_without_the_columns_reads_the_defaults():
    """A webapp older than the columns sends none: the run is ip_only."""
    s = _fetch()
    for key in KEYS:
        assert s[key] == DEFAULT_SETTINGS[key], key


def test_every_column_reaches_its_runtime_key():
    s = _fetch(ipHostnameMode="record_filter", ipHostnameInclude=["*.example.com"],
               ipHostnameExclude=["old.example.com"], ipHostnamePassiveExpand=False,
               ipHostnameScanAllConfirmed=False, ipHostnameMaxScanned=7,
               ipHostnamePassiveMaxNames=9)
    assert s["IP_HOSTNAME_MODE"] == "record_filter"
    assert s["IP_HOSTNAME_INCLUDE"] == ["*.example.com"]
    assert s["IP_HOSTNAME_EXCLUDE"] == ["old.example.com"]
    assert s["IP_HOSTNAME_PASSIVE_EXPAND"] is False
    assert s["IP_HOSTNAME_MAX_SCANNED"] == 7
    assert s["IP_HOSTNAME_PASSIVE_MAX_NAMES"] == 9


def test_domain_mode_never_validates_the_policy():
    """The policy is ignored outside IP mode, so a leftover value on a domain
    project neither refuses its run nor is rewritten."""
    s = _fetch(ipMode=False, targetIps=[], targetDomain="example.com",
               ipHostnameMode="scan_all", ipHostnameScanAllConfirmed=False)
    assert s["IP_HOSTNAME_MODE"] == "scan_all"
    assert s["IP_MODE"] is False


# --- normalisation -------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["", "bogus", None, 3, "IP_ONLY"])
def test_an_unknown_mode_reads_as_ip_only(raw, capsys):
    s = _fetch(ipHostnameMode=raw)
    assert s["IP_HOSTNAME_MODE"] == "ip_only"
    assert "[!][IpNames] Unknown hostname mode" in capsys.readouterr().out


def test_include_entries_are_normalised_and_deduplicated():
    s = _fetch(ipHostnameMode="record_filter",
               ipHostnameInclude=[" *.Example.COM. ", "*example.com", "", "App.Example.org"])
    assert s["IP_HOSTNAME_INCLUDE"] == ["*.example.com", "app.example.org"]


def test_an_unreadable_include_entry_is_dropped_with_a_line(capsys):
    s = _fetch(ipHostnameMode="record_filter",
               ipHostnameInclude=["*.example.com", "203.0.113.9", "**.example.org", 7])
    assert s["IP_HOSTNAME_INCLUDE"] == ["*.example.com"]
    out = capsys.readouterr().out
    assert "Ignoring include entry '203.0.113.9': ip_literal" in out
    assert "Ignoring include entry '**.example.org': malformed_wildcard" in out


@pytest.mark.parametrize("suffix_entry", ["*.co.uk", "co.uk", "*.github.io"])
def test_a_public_suffix_include_entry_is_dropped(suffix_entry, capsys):
    s = _fetch(ipHostnameMode="record_filter", ipHostnameInclude=[suffix_entry, "*.example.com"])
    assert s["IP_HOSTNAME_INCLUDE"] == ["*.example.com"]
    assert "a public suffix reaches every registrant" in capsys.readouterr().out


def test_an_unreadable_exclude_entry_is_kept_so_nothing_is_scanned(capsys):
    """Dropping an exclude entry would widen what is scanned; keeping it makes
    the rule answer invalid_filter for every name (I-6)."""
    from recon_settings.ip_hostnames import TargetSet, evaluate

    s = _fetch(ipHostnameMode="record_filter", ipHostnameInclude=["*.example.com"],
               ipHostnameExclude=["old.example.com", "198.51.100.7"])
    assert s["IP_HOSTNAME_EXCLUDE"] == ["old.example.com", "198.51.100.7"]
    assert "no hostname is scanned this run" in capsys.readouterr().out
    ev = evaluate(
        {"app.example.com": {"ips_seen": ["203.0.113.10"], "org_domain": "example.com"}},
        mode="record_filter", include=s["IP_HOSTNAME_INCLUDE"], exclude=s["IP_HOSTNAME_EXCLUDE"],
        targets=TargetSet.from_entries(["203.0.113.10"]), shared_edge=set(),
        hard_blocked=lambda n: False, roe_excluded=lambda n: False,
        resolve=lambda n: ["203.0.113.10"], dns_enabled=True, resolver_up=True, cap=10,
        wildcard_zone=set())
    assert ev.selected == [] and ev.reasons["app.example.com"] == "invalid_filter"


def test_a_public_suffix_exclude_entry_is_kept():
    """An exclude entry only narrows, so a broad one is the operator's call."""
    s = _fetch(ipHostnameMode="record_filter", ipHostnameInclude=["*.example.co.uk"],
               ipHostnameExclude=["*.co.uk"])
    assert s["IP_HOSTNAME_EXCLUDE"] == ["*.co.uk"]


def test_the_lists_are_normalised_in_every_ip_mode():
    s = _fetch(ipHostnameMode="record_only", ipHostnameInclude=["*.EXAMPLE.com"],
               ipHostnameExclude=["Old.Example.com"])
    assert s["IP_HOSTNAME_INCLUDE"] == ["*.example.com"]
    assert s["IP_HOSTNAME_EXCLUDE"] == ["old.example.com"]


def test_a_non_list_exclude_outside_record_filter_reads_empty():
    s = _fetch(ipHostnameMode="record_only", ipHostnameExclude="old.example.com")
    assert s["IP_HOSTNAME_EXCLUDE"] == []


def test_a_non_list_include_reads_empty():
    s = _fetch(ipHostnameMode="record_only", ipHostnameInclude="*.example.com")
    assert s["IP_HOSTNAME_INCLUDE"] == []


@pytest.mark.parametrize("raw,expected", [
    (True, True), (False, False), ("true", False), (1, False), (None, False),
])
def test_only_a_literal_true_confirms_scan_all(raw, expected):
    s = _fetch(ipHostnameMode="record_only", ipHostnameScanAllConfirmed=raw)
    assert s["IP_HOSTNAME_SCAN_ALL_CONFIRMED"] is expected


@pytest.mark.parametrize("raw,expected", [(False, False), (True, True), ("no", True), (None, True)])
def test_passive_expand_must_be_a_boolean(raw, expected):
    s = _fetch(ipHostnamePassiveExpand=raw)
    assert s["IP_HOSTNAME_PASSIVE_EXPAND"] is expected


@pytest.mark.parametrize("key,column,raw,expected", [
    ("IP_HOSTNAME_MAX_SCANNED", "ipHostnameMaxScanned", 0, 1),
    ("IP_HOSTNAME_MAX_SCANNED", "ipHostnameMaxScanned", 999999, 2000),
    ("IP_HOSTNAME_MAX_SCANNED", "ipHostnameMaxScanned", "50", 100),
    ("IP_HOSTNAME_MAX_SCANNED", "ipHostnameMaxScanned", True, 100),
    ("IP_HOSTNAME_PASSIVE_MAX_NAMES", "ipHostnamePassiveMaxNames", -5, 1),
    ("IP_HOSTNAME_PASSIVE_MAX_NAMES", "ipHostnamePassiveMaxNames", 10001, 10000),
    ("IP_HOSTNAME_PASSIVE_MAX_NAMES", "ipHostnamePassiveMaxNames", 2.5, 500),
    ("IP_HOSTNAME_PASSIVE_MAX_NAMES", "ipHostnamePassiveMaxNames", 750, 750),
])
def test_a_cap_outside_its_bound_is_pulled_back(key, column, raw, expected, capsys):
    s = _fetch(**{column: raw})
    assert s[key] == expected
    if raw != expected:
        assert f"[!][IpNames] {key}" in capsys.readouterr().out


# --- refusals ------------------------------------------------------------------------

def test_scan_all_without_confirmation_refuses_the_run(capsys):
    with pytest.raises(ScopeRefused, match="not confirmed"):
        _fetch(ipHostnameMode="scan_all", ipHostnameScanAllConfirmed=False)
    assert "scan_all without its confirmation: refusing the run" in capsys.readouterr().out


def test_scan_all_with_confirmation_loads():
    s = _fetch(ipHostnameMode="scan_all", ipHostnameScanAllConfirmed=True)
    assert s["IP_HOSTNAME_MODE"] == "scan_all"
    assert s["IP_HOSTNAME_SCAN_ALL_CONFIRMED"] is True


def test_scan_all_on_a_third_party_engagement_refuses_the_run():
    """D-03: names on an IP are not covered by an address authorisation."""
    with pytest.raises(ScopeRefused, match="third_party"):
        _fetch(ipHostnameMode="scan_all", ipHostnameScanAllConfirmed=True,
               engagementKind="third_party")


def test_record_filter_on_a_third_party_engagement_loads():
    s = _fetch(ipHostnameMode="record_filter", ipHostnameInclude=["*.example.com"],
               engagementKind="third_party")
    assert s["IP_HOSTNAME_MODE"] == "record_filter"


def test_record_filter_without_include_refuses_the_run():
    with pytest.raises(ScopeRefused, match="no usable include entry"):
        _fetch(ipHostnameMode="record_filter", ipHostnameInclude=[])


def test_record_filter_whose_every_include_is_unusable_refuses_the_run():
    """Dropping the bad entries must not leave a record_filter scanning by an
    empty filter: there would be nothing the operator asked for."""
    with pytest.raises(ScopeRefused, match="no usable include entry"):
        _fetch(ipHostnameMode="record_filter", ipHostnameInclude=["*.co.uk", "203.0.113.1"])


def test_record_filter_with_an_unreadable_exclude_list_refuses_the_run():
    with pytest.raises(ScopeRefused, match="exclude list cannot be read"):
        _fetch(ipHostnameMode="record_filter", ipHostnameInclude=["*.example.com"],
               ipHostnameExclude="old.example.com")


def test_an_unknown_mode_never_refuses():
    """It reads as ip_only, which needs no confirmation and no include."""
    s = _fetch(ipHostnameMode="scan-all", ipHostnameInclude=[])
    assert s["IP_HOSTNAME_MODE"] == "ip_only"


def test_the_public_suffix_list_is_consulted_only_for_record_filter():
    """ip_only and record_only scan no name, so an unavailable suffix list must
    not refuse their run (_psl() raises ScopeRefused when it cannot load)."""
    with patch("recon.project_settings._psl", side_effect=ScopeRefused("psl down")):
        s = _fetch(ipHostnameMode="record_only", ipHostnameInclude=["*.example.com"])
    assert s["IP_HOSTNAME_INCLUDE"] == ["*.example.com"]

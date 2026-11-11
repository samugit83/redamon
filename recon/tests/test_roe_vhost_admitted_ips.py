"""The vhost/SNI enumerator never probes an address the RoE excludes (R-2, D2).

``_collect_ip_targets`` merges three sources into the IPs every curl probe is
pinned to: ``port_scan.by_host`` (a partial run's typed IPs and graph rows
land there too), every ``dns.subdomains`` address and the apex's. None of them
was checked against the RoE IP and CIDR entries, so a name resolving into an
excluded range had its address probed on 443 and 80, with the baseline, the
control probes and every candidate Host/SNI name.

Each test reads what curl is really handed: only ``subprocess.run`` (the
wire) is replaced, so the real target collection, baseline, control and
candidate probes run. With no RoE exclusion the targets are the ones built
without RoE keys at all.
Reserved names and documentation ranges only; no network.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.main_recon_modules import vhost_sni_enum as vsm  # noqa: E402

EXCLUDED_RANGE = "198.51.100.0/24"
APEX, APEX_IP = "example.com", "192.0.2.1"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"          # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
TYPED_BAD = "198.51.100.30"           # a partial run's typed IP / graph row in by_host
EXCLUDED = {LEGACY_IP, MIXED_BAD, TYPED_BAD}
ALLOWED = {APEX_IP, MIXED_OK, WWW_IP}

NO_ROE = [
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, LEGACY_IP]},
]


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _recon() -> dict:
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {LEGACY: _sub(LEGACY_IP), MIXED: _sub(MIXED_BAD, MIXED_OK), WWW: _sub(WWW_IP)},
        },
        "port_scan": {"by_host": {
            WWW: {"ip": WWW_IP, "ports": [{"port": 8443, "scheme": "https"}]},
            TYPED_BAD: {"ip": TYPED_BAD, "ports": [{"port": 443}]},
        }},
    }


def _vhost_settings(**extra) -> dict:
    return {
        "VHOST_SNI_ENABLED": True, "VHOST_SNI_TEST_L7": True, "VHOST_SNI_TEST_L4": True,
        "VHOST_SNI_USE_DEFAULT_WORDLIST": False, "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
        "VHOST_SNI_CUSTOM_WORDLIST": "admin.example.com", "VHOST_SNI_INJECT_DISCOVERED": False,
        "VHOST_SNI_CONCURRENCY": 4, "VHOST_SNI_TIMEOUT": 1, **extra,
    }


class Wire:
    """Stands in for curl: answers every probe with the same page, records the
    address each one was sent to (the URL's, or --resolve's for an SNI probe)."""

    def __init__(self):
        self.sent: list = []
        self._lock = threading.Lock()

    def run(self, cmd, *args, **kwargs):
        if "--resolve" in cmd:
            address = cmd[cmd.index("--resolve") + 1].split(":", 2)[2]
        else:
            address = cmd[-1].split("://", 1)[1].rsplit(":", 1)[0]
        with self._lock:
            self.sent.append(address.strip("[]"))
        out = b"<html>same page</html>" + vsm._PROBE_META_SENTINEL + b"200\t22\t\ttext/html"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=b"")

    def addresses(self) -> set:
        return set(self.sent)


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


@pytest.fixture
def wire(monkeypatch):
    w = Wire()
    monkeypatch.setattr(vsm.subprocess, "run", w.run)
    monkeypatch.setattr(vsm, "_is_curl_available", lambda: True)
    return w


def _roe_gaps() -> list:
    return [g for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


# ---------------------------------------------------------------------------
# The target collection
# ---------------------------------------------------------------------------

def test_no_excluded_address_is_a_target_whichever_source_brought_it():
    targets = vsm._collect_ip_targets(_recon(), _roe(EXCLUDED_RANGE))

    assert set(targets) == ALLOWED
    assert sorted(p["port"] for p in targets[WWW_IP]) == [80, 443, 8443]


def test_an_exact_ip_entry_drops_that_address_only():
    targets = vsm._collect_ip_targets(_recon(), _roe(LEGACY_IP))

    assert set(targets) == ALLOWED | {MIXED_BAD, TYPED_BAD}


def test_a_name_entry_leaves_the_addresses_alone():
    """A host entry is matched on names (the candidate scope); an address only
    by an IP or CIDR entry."""
    targets = vsm._collect_ip_targets(_recon(), _roe(LEGACY))

    assert set(targets) == ALLOWED | EXCLUDED


@pytest.mark.parametrize("settings", NO_ROE, ids=["roe-on-empty", "roe-off"])
def test_without_an_exclusion_the_targets_are_unchanged(settings):
    assert vsm._collect_ip_targets(_recon(), settings) == vsm._collect_ip_targets(_recon())
    assert set(vsm._collect_ip_targets(_recon(), settings)) == ALLOWED | EXCLUDED


def test_a_partial_builders_stamped_roe_applies_when_no_settings_are_handed():
    recon = _recon()
    recon["metadata"]["roe"] = _roe(EXCLUDED_RANGE)

    assert set(vsm._collect_ip_targets(recon)) == ALLOWED


# ---------------------------------------------------------------------------
# What curl is handed
# ---------------------------------------------------------------------------

def test_the_enumerator_never_probes_an_excluded_address(wire):
    settings = _vhost_settings(**_roe(EXCLUDED_RANGE))

    out = vsm.run_vhost_sni_enrichment_isolated(_recon(), settings)

    assert wire.sent, "nothing was probed"
    assert wire.addresses() == ALLOWED
    assert set(out["by_ip"]) <= ALLOWED
    gaps = _roe_gaps()
    assert {g["module"] for g in gaps} == {"vhost_sni"}
    assert sum(g.get("skipped", 0) for g in gaps) == len(EXCLUDED)


@pytest.mark.parametrize("settings", NO_ROE, ids=["roe-on-empty", "roe-off"])
def test_without_an_exclusion_every_address_is_probed(wire, settings):
    vsm.run_vhost_sni_enrichment_isolated(_recon(), _vhost_settings(**settings))

    assert wire.addresses() == ALLOWED | EXCLUDED
    assert _roe_gaps() == []


def test_a_partial_runs_typed_ip_in_an_excluded_range_is_never_probed(wire):
    from recon.partial_recon_modules import vulnerability_scanning as vs

    settings = _vhost_settings(**_roe(EXCLUDED_RANGE))
    client = MagicMock()
    client.verify_connection.return_value = False
    graph_db = MagicMock()
    graph_db.Neo4jClient.return_value.__enter__ = MagicMock(return_value=client)
    graph_db.Neo4jClient.return_value.__exit__ = MagicMock(return_value=False)
    config = {"domain": APEX, "include_graph_targets": False, "_settings": settings,
              "user_targets": {"subdomains": [], "ips": [TYPED_BAD, WWW_IP]}}
    with patch.dict(os.environ, {"USER_ID": "u-test", "PROJECT_ID": "p-test"}), \
         patch.dict(sys.modules, {"graph_db": graph_db}), \
         patch.object(vs, "attach_graph_ownership", lambda *_a, **_k: None):
        vs.run_vhost_sni_partial(config)

    assert wire.sent, "nothing was probed"
    assert wire.addresses() == {WWW_IP}

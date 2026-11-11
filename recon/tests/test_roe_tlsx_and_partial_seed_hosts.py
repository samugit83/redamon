"""tlsx gets only RoE-admitted names (R-2, design decision D2).

tlsx is handed ``name:port`` lines and resolves each name itself, so a name the
RoE refuses on one of its addresses can land on that address even when the
line was built from an allowed one.

Each test reads what the tool is really handed: the tlsx target file (only
``subprocess.Popen`` is replaced); a partial run's comes from the real
port-scan graph builder, over a fake Neo4j answering from a fixed set of rows.
With no RoE exclusion the target file is the one built without RoE keys at
all.
Reserved names and documentation ranges only; no Docker, no network.
"""
from __future__ import annotations

import copy
import re
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
from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"          # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
UNKNOWN = "unknown.example.com"                                     # no forward address in the graph
TLS_PORT = 993

NO_ROE = [
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, WWW]},
]


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _hosts(urls) -> set:
    return {(urlparse(u).hostname or "").lower() for u in urls}


def _roe_gaps(module: str) -> list:
    return [g for g in circuit_breaker.coverage_report().gaps
            if g.get("source") == "roe_excluded" and g.get("module") == module]


class _Stop(BaseException):
    """Escapes the modules' own `except Exception` once the input is read."""


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})
    yield
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})


# --------------------------------------------------------------------------
# tlsx: the target file (full run and partial run share _build_tlsx_targets)
# --------------------------------------------------------------------------

class _Proc:
    returncode = 0

    def communicate(self, timeout=None):
        return "", ""


def _tlsx_lines(combined: dict, settings: dict, stop: bool = False) -> list:
    """The lines written to the target file the tlsx container reads."""
    from recon.main_recon_modules import tls_scan
    seen = {"lines": []}

    def popen(cmd, *_a, **_k):
        seen["lines"] = Path(cmd[cmd.index("-l") + 1]).read_text().split()
        if stop:
            raise _Stop
        return _Proc()

    with _routable(), mock.patch.object(tls_scan.subprocess, "Popen", side_effect=popen):
        tls_scan.run_tlsx_enrichment(combined, settings)
    return seen["lines"]


def _routable():
    """tlsx skips non-routable addresses outside IP mode, and Python counts
    the documentation ranges as private."""
    return mock.patch("recon.main_recon_modules.ip_filter.is_non_routable_ip", return_value=False)


def _domain_run() -> dict:
    """A domain-mode run after the gated naabu: the port data lists a name
    under an allowed address while DNS also resolves it into the range (a
    mixed name), and a name DNS resolves only into the range under another
    allowed address (port data from a source that keys by name)."""
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {LEGACY: _sub(LEGACY_IP), MIXED: _sub(MIXED_BAD, MIXED_OK), WWW: _sub(WWW_IP)},
        },
        "port_scan": {"by_ip": {
            MIXED_OK: {"ip": MIXED_OK, "hostnames": [MIXED], "ports": [TLS_PORT]},
            WWW_IP: {"ip": WWW_IP, "hostnames": [LEGACY, WWW], "ports": [TLS_PORT]},
            APEX_IP: {"ip": APEX_IP, "hostnames": [APEX], "ports": [TLS_PORT]},
        }},
    }


def test_tlsx_never_gets_a_name_resolving_into_an_excluded_range():
    lines = _tlsx_lines(_domain_run(), _roe(EXCLUDED_RANGE))
    hosts = {line.rsplit(":", 1)[0] for line in lines}
    # tlsx resolves a name itself: a name with any excluded address is not
    # sent by name, its allowed address is handshaken as an IP.
    assert {LEGACY, MIXED}.isdisjoint(hosts)
    assert f"{MIXED_OK}:{TLS_PORT}" in lines
    assert f"{WWW}:{TLS_PORT}" in lines
    assert f"{APEX}:{TLS_PORT}" in lines
    assert {LEGACY_IP, MIXED_BAD}.isdisjoint(hosts)
    assert _roe_gaps("tlsx"), "the refusal is noted under the roe_excluded coverage source"


def test_tlsx_keeps_the_scanned_address_of_a_name_sent_as_its_ip():
    """The parser keys a reply on the address the line was built from."""
    from recon.main_recon_modules.tls_scan import _build_tlsx_targets
    with _routable():
        lines, meta = _build_tlsx_targets(_domain_run(), _roe(EXCLUDED_RANGE))
    assert meta[f"{MIXED_OK}:{TLS_PORT}"] == MIXED_OK
    assert meta[f"{WWW}:{TLS_PORT}"] == WWW_IP
    assert len(lines) == len(meta)


def test_tlsx_name_entries_still_exclude_by_name():
    lines = _tlsx_lines(_domain_run(), _roe(WWW))
    assert f"{WWW}:{TLS_PORT}" not in lines
    # No IP or CIDR entry: no address check, the names keep their lines.
    assert f"{MIXED}:{TLS_PORT}" in lines
    assert f"{LEGACY}:{TLS_PORT}" in lines


@pytest.mark.parametrize("settings", NO_ROE)
def test_tlsx_targets_are_unchanged_without_an_exclusion(settings):
    baseline = _tlsx_lines(_domain_run(), {})
    assert _tlsx_lines(_domain_run(), settings) == baseline
    assert {f"{MIXED}:{TLS_PORT}", f"{LEGACY}:{TLS_PORT}"} <= set(baseline)


def test_tlsx_in_ip_mode_stays_on_the_targets_under_an_exclusion():
    """P0b's IP-mode clamp is untouched: an address is a target or skipped,
    a name goes only when every address it has is a target."""
    run = _domain_run()
    run["metadata"].update(ip_mode=True, expanded_ips=[MIXED_OK, WWW_IP])
    run["port_scan"]["by_ip"][LEGACY_IP] = {"ip": LEGACY_IP, "hostnames": [LEGACY], "ports": [TLS_PORT]}
    for settings in ({}, _roe(EXCLUDED_RANGE)):
        lines = _tlsx_lines(copy.deepcopy(run), settings)
        assert sorted(lines) == sorted([f"{MIXED_OK}:{TLS_PORT}", f"{WWW}:{TLS_PORT}"])


# --------------------------------------------------------------------------
# A fake graph: the forward DNS, ports, BaseURLs and Endpoints of a project
# --------------------------------------------------------------------------

# (subdomain, address) forward-DNS rows the graph holds from an earlier run.
GRAPH_DNS = [(LEGACY, LEGACY_IP), (MIXED, MIXED_BAD), (MIXED, MIXED_OK), (WWW, WWW_IP)]
GRAPH_SUBDOMAINS = [LEGACY, MIXED, WWW, UNKNOWN]
GRAPH_BASEURLS = [f"https://{WWW}"]
GRAPH_ENDPOINTS = [f"https://{WWW}/app", f"https://{LEGACY}/admin", f"https://{MIXED}/login",
                   f"http://{LEGACY_IP}/status"]


class _Rows(list):
    def single(self):
        return self[0] if self else None


def _address_row(address):
    return {"address": address, "ip": address, "version": "IPv4", "is_cdn": False,
            "cdn_name": None, "asn": None,
            "ports": [{"number": TLS_PORT, "protocol": "tcp", "passive_only": False}]}


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **_params):
        rows = _Rows()
        if "AS host, i.address AS address" in cypher:
            rows.extend({"host": s, "address": a} for s, a in [(APEX, APEX_IP), *GRAPH_DNS])
        elif "$apex_roots" in cypher:
            rows.append({"root": APEX, **_address_row(APEX_IP)})
        elif re.search(r"AS sub\b", cypher):
            rows.extend({"root": APEX, "sub": s} for s in GRAPH_SUBDOMAINS)
        elif "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": list(GRAPH_SUBDOMAINS)})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            rows.extend({"root": APEX, "subdomain": s, **_address_row(a)} for s, a in GRAPH_DNS)
        elif "e.baseurl + e.path AS url" in cypher:
            rows.extend({"url": u} for u in GRAPH_ENDPOINTS)
        elif "(e:Endpoint)" in cypher or "USES_TECHNOLOGY" in cypher:
            pass
        elif "MATCH (b:BaseURL" in cypher:
            rows.extend({"url": u, "host": urlparse(u).hostname, "status_code": 200,
                         "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None}
                        for u in GRAPH_BASEURLS)
        return rows


class _Client:
    reachable = True

    def __init__(self, *_a, **_k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return self.reachable

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda **_k: _Session()
        return driver


def _run_settings(settings: dict) -> dict:
    run_settings = {"SUBDOMAIN_LIST": ["."], **settings}
    # What partial_recon._prepare_scope does before any module runs.
    partial_helpers.set_run_roe(run_settings)
    return run_settings


# --------------------------------------------------------------------------
# Partial tlsx: the port-scan graph builder, then the same target file
# --------------------------------------------------------------------------

def _partial_tlsx_lines(settings, monkeypatch) -> list:
    from recon.partial_recon_modules import tlsx_scanning
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    run_settings = _run_settings(settings)
    with pytest.raises(_Stop):
        _tlsx_lines_from(lambda: tlsx_scanning.run_tlsx(
            {"_settings": run_settings, "domains": [APEX], "domain": APEX}))
    return _LAST["lines"]


_LAST: dict = {}


def _tlsx_lines_from(run):
    from recon.main_recon_modules import tls_scan
    _LAST["lines"] = []

    def popen(cmd, *_a, **_k):
        _LAST["lines"] = Path(cmd[cmd.index("-l") + 1]).read_text().split()
        raise _Stop

    with _routable(), mock.patch.object(tls_scan.subprocess, "Popen", side_effect=popen):
        run()


def test_partial_tlsx_never_gets_a_name_with_one_excluded_address(monkeypatch):
    lines = _partial_tlsx_lines(_roe(EXCLUDED_RANGE), monkeypatch)
    hosts = {line.rsplit(":", 1)[0] for line in lines}
    assert {LEGACY, MIXED, LEGACY_IP, MIXED_BAD}.isdisjoint(hosts)
    assert f"{MIXED_OK}:{TLS_PORT}" in lines
    assert f"{WWW}:{TLS_PORT}" in lines


@pytest.mark.parametrize("settings", NO_ROE)
def test_partial_tlsx_targets_are_unchanged_without_an_exclusion(settings, monkeypatch):
    baseline = _partial_tlsx_lines({}, monkeypatch)
    assert _partial_tlsx_lines(settings, monkeypatch) == baseline
    assert f"{MIXED}:{TLS_PORT}" in baseline

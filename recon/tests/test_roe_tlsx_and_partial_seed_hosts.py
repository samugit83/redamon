"""tlsx, the partial archive sources and the partial ZAP endpoint seeds get only
RoE-admitted hosts (R-2, design decision D2).

tlsx is handed ``name:port`` lines and resolves each name itself, so a name the
RoE refuses on one of its addresses can land on that address even when the
line was built from an allowed one. Gau's URL verification and method probe
(httpx) request every archived URL whose host is in the list
``graph_target_hosts`` returns, which a partial run checked against the RoE by
name only. The ZAP Ajax Spider's endpoint seeds pass a scope check by name, and
then its own allowed-host filter, built from the admitted target URLs.

Each test reads what the tool is really handed: the tlsx target file (only
``subprocess.Popen`` is replaced), the URLs Gau's verifier receives and the
seeds ZAP would crawl after its own filters. Neo4j is a fake answering from a
fixed set of rows. With no RoE exclusion the lists are the ones built without
RoE keys at all.

Two strict xfails at the end pin what is still open: partial Nuclei through the
vuln-scan graph builder, and the security checks' missing address gate.
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


# --------------------------------------------------------------------------
# graph_target_hosts (partial Gau, ParamSpider)
# --------------------------------------------------------------------------

def _target_hosts(settings, monkeypatch, include_graph=True, reachable=True) -> list:
    from recon.partial_recon_modules.graph_builders import graph_target_hosts
    client = type("_C", (_Client,), {"reachable": reachable})
    monkeypatch.setattr("graph_db.Neo4jClient", client)
    _run_settings(settings)
    return graph_target_hosts("u1", "p1", [APEX], None, include_root_domain=True,
                              include_graph=include_graph)


def test_graph_target_hosts_drop_a_name_resolving_into_an_excluded_range(monkeypatch):
    hosts = _target_hosts(_roe(EXCLUDED_RANGE), monkeypatch)
    assert {LEGACY, MIXED}.isdisjoint(hosts)
    # Nothing shows a name with no known address stays off the range.
    assert UNKNOWN not in hosts
    assert {APEX, WWW} <= set(hosts)
    gaps = _roe_gaps("partial_graph_targets")
    assert gaps, "the refusal is noted under the roe_excluded coverage source"
    # The unknown name is "not checked", never "gone": its findings are kept.
    assert UNKNOWN in circuit_breaker.coverage_report().skipped_hosts


def test_graph_target_hosts_without_an_ip_entry_keep_a_name_with_no_address(monkeypatch):
    hosts = _target_hosts(_roe("other.example.com"), monkeypatch)
    assert {APEX, LEGACY, MIXED, WWW, UNKNOWN} <= set(hosts)


@pytest.mark.parametrize("settings", NO_ROE)
def test_graph_target_hosts_are_unchanged_without_an_exclusion(settings, monkeypatch):
    baseline = _target_hosts({}, monkeypatch)
    assert _target_hosts(settings, monkeypatch) == baseline
    assert {APEX, LEGACY, MIXED, WWW, UNKNOWN} <= set(baseline)


@pytest.mark.parametrize("include_graph,reachable", [(False, True), (True, False)])
def test_graph_target_hosts_without_graph_rows_still_gate_the_apex(include_graph, reachable, monkeypatch):
    # The apex's addresses are read for the gate even when the operator left
    # the graph's names out; with no graph at all the apex has no known
    # address and is refused (fail closed).
    hosts = _target_hosts(_roe(EXCLUDED_RANGE), monkeypatch, include_graph, reachable)
    assert hosts == ([APEX] if reachable else [])
    for settings in ({}, *NO_ROE, _roe("other.example.com")):
        assert _target_hosts(settings, monkeypatch, include_graph, reachable) == [APEX]


def test_graph_target_hosts_drop_an_apex_resolving_into_an_excluded_range(monkeypatch):
    hosts = _target_hosts(_roe(f"{APEX_IP}/32"), monkeypatch)
    assert APEX not in hosts
    assert {LEGACY, MIXED, WWW} <= set(hosts)


def test_graph_target_hosts_in_ip_mode_stay_on_the_targets(monkeypatch):
    """P0c's IP-mode rule is untouched: a name only when every address it
    resolves to is a target, never the synthetic root."""
    from recon.partial_recon_modules.graph_builders import graph_target_hosts
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    settings = {"IP_MODE": True, "TARGET_IPS": [MIXED_OK, WWW_IP], **_roe(EXCLUDED_RANGE)}
    partial_helpers.set_run_roe(settings)
    partial_helpers.set_run_ip_targets(settings)
    assert graph_target_hosts("u1", "p1", [APEX], None, include_root_domain=True) == [WWW]


class _StopVerify(BaseException):
    pass


def _gau_verified_urls(settings, monkeypatch) -> list:
    """The archived URLs partial Gau hands its httpx verifier."""
    import recon.helpers.resource_enum as resource_enum
    from recon.partial_recon_modules import web_crawling
    archived = [f"https://{h}/old" for h in (APEX, LEGACY, MIXED, WWW, UNKNOWN)]
    seen = {}

    def verify(urls, **_k):
        seen["urls"] = list(urls)
        raise _StopVerify

    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr(resource_enum, "pull_gau_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(resource_enum, "run_gau_discovery",
                        lambda domains, *_a, **_k: ([u for u in archived if urlparse(u).hostname in domains], {}))
    monkeypatch.setattr(resource_enum, "verify_gau_urls", verify)
    run_settings = _run_settings({"GAU_VERIFY_URLS": True, **settings})
    with pytest.raises(_StopVerify):
        web_crawling.run_gau({"_settings": run_settings, "domains": [APEX], "domain": APEX})
    return seen["urls"]


def test_partial_gau_never_verifies_a_url_on_a_name_resolving_into_an_excluded_range(monkeypatch):
    hosts = _hosts(_gau_verified_urls(_roe(EXCLUDED_RANGE), monkeypatch))
    assert {LEGACY, MIXED, UNKNOWN}.isdisjoint(hosts)
    assert {APEX, WWW} <= hosts


@pytest.mark.parametrize("settings", NO_ROE)
def test_partial_gau_verification_is_unchanged_without_an_exclusion(settings, monkeypatch):
    baseline = _gau_verified_urls({}, monkeypatch)
    assert _gau_verified_urls(settings, monkeypatch) == baseline
    assert {LEGACY, MIXED} <= _hosts(baseline)


# --------------------------------------------------------------------------
# Partial ZAP Ajax Spider: the endpoint seeds of base_urls_and_endpoints
# --------------------------------------------------------------------------

def _zap_seeds(settings, monkeypatch) -> list:
    """The seeds ZAP would crawl, after run_zap_ajax_spider's own filters."""
    import recon.helpers.resource_enum as resource_enum
    from recon.helpers.resource_enum import zap_ajax_spider_helpers as zap
    from recon.partial_recon_modules import web_crawling
    seen = {}

    def capped(seeds, _cap):
        seen["seeds"] = list(seeds)
        raise _Stop

    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr(resource_enum, "pull_zap_ajax_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(zap, "_cap_zap_seeds", capped)
    run_settings = _run_settings({"ZAP_AJAX_SPIDER_SEED_MODE": "base_urls_and_endpoints", **settings})
    with pytest.raises(_Stop):
        web_crawling.run_zap_ajax_spider_partial(
            {"_settings": run_settings, "domains": [APEX], "domain": APEX})
    return seen["seeds"]


def test_partial_zap_never_seeds_an_endpoint_on_a_name_resolving_into_an_excluded_range(monkeypatch):
    seeds = _zap_seeds(_roe(EXCLUDED_RANGE), monkeypatch)
    assert {LEGACY, MIXED, LEGACY_IP}.isdisjoint(_hosts(seeds))
    assert f"https://{WWW}/app" in seeds


@pytest.mark.parametrize("settings", NO_ROE)
def test_partial_zap_seeds_are_unchanged_without_an_exclusion(settings, monkeypatch):
    baseline = _zap_seeds({}, monkeypatch)
    assert _zap_seeds(settings, monkeypatch) == baseline
    assert {f"https://{LEGACY}/admin", f"https://{MIXED}/login"} <= set(baseline)


# --------------------------------------------------------------------------
# Still open (strict xfail pins): the vuln-scan graph builder and its readers
# --------------------------------------------------------------------------
#
# _build_vuln_scan_data_from_graph drops a name's RoE-excluded address from
# its DNS block, so the admission gate at partial Nuclei sees only the allowed
# address of a mixed name and sends the name, which Nuclei resolves itself.
# Keeping the address there for the gate (as the port-scan builder does) is
# blocked by a reader of the same block: run_security_checks, which partial
# Nuclei and partial SecurityChecks both reach, sends its direct-IP checks to
# every DNS address and its hostname checks to every name with records, and
# checks neither against the RoE IP and CIDR entries in domain mode. The full
# domain run hands it the run's whole DNS block, so the second pin is a live
# leak there today.

NUCLEI = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
          "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0,
          "MITRE_ENABLED": False}


def _partial_nuclei_targets(settings, monkeypatch) -> list:
    from recon.main_recon_modules import vuln_scan as vs
    from recon.partial_recon_modules import vulnerability_scanning
    seen = {}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        seen[label] = (Path(output_file).parent / f"targets_{label.lower()}.txt").read_text().split()
        raise _Stop

    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    run_settings = _run_settings({**NUCLEI, **settings})
    with mock.patch.object(vs, "is_docker_installed", return_value=True), \
         mock.patch.object(vs, "is_docker_running", return_value=True), \
         mock.patch.object(vs, "pull_nuclei_docker_image", return_value=True), \
         mock.patch.object(vs, "ensure_templates_volume", return_value=True), \
         mock.patch.object(vs, "_execute_nuclei_pass", side_effect=fake_pass):
        with pytest.raises(_Stop):
            vulnerability_scanning.run_nuclei({"_settings": run_settings, "domains": [APEX], "domain": APEX})
    return seen["DETECTION"]


@pytest.mark.xfail(strict=True, reason="R-2: the vuln-scan graph builder drops the excluded address "
                   "the gate needs; keeping it waits on the security checks' RoE address gate")
def test_partial_nuclei_never_gets_a_name_with_one_excluded_address(monkeypatch):
    hosts = _hosts(_partial_nuclei_targets(_roe(EXCLUDED_RANGE), monkeypatch))
    assert MIXED not in hosts
    assert WWW in hosts


def _security_check_targets(settings) -> tuple:
    """The addresses the direct-IP checks and the names the header checks get."""
    from recon.helpers import security_checks as sc
    probed_ips, checked_names = set(), set()

    def direct(ips, **_k):
        probed_ips.update(ips)
        return []

    def headers(hostnames, **_k):
        checked_names.update(hostnames)
        return []

    with mock.patch.object(sc, "run_direct_ip_checks", side_effect=direct), \
         mock.patch.object(sc, "run_security_headers_checks", side_effect=headers):
        sc.run_security_checks(_domain_run(), {"direct_ip_http": True, "missing_referrer_policy": True},
                               roe_excluded_hosts=settings.get("ROE_EXCLUDED_HOSTS"))
    return probed_ips, checked_names


def test_security_checks_reach_every_dns_address_without_an_exclusion():
    ips, names = _security_check_targets({})
    assert {LEGACY_IP, MIXED_BAD} <= ips
    assert {LEGACY, MIXED} <= names


def test_security_checks_never_reach_an_excluded_address():
    ips, names = _security_check_targets(_roe(EXCLUDED_RANGE))
    assert {LEGACY_IP, MIXED_BAD}.isdisjoint(ips)
    assert {LEGACY, MIXED}.isdisjoint(names)

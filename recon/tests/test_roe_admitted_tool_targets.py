"""Nuclei, the crawlers, the cache scan and the port-coverage reader get only
RoE-admitted targets (R-2, design decision D2).

The shared DNS extractor (``target_helpers.extract_targets_from_recon``) runs
the admission gate only when it is handed the run's settings (or a partial
builder's ``metadata.roe``). Its callers that feed a tool passed none, so a
name resolving into an RoE CIDR exclusion was still sent to Nuclei, the
crawlers and the cache scan through ``build_target_urls``' subdomain fallback,
and the Shodan port check counted an excluded address as "looked at, not open".

Each test reads what the tool is really handed: the Nuclei target file, the
seeds Katana gets, the URLs the cache scan probes, the URLs a partial crawler
or Kiterunner is built, and the port-coverage verdict. Only Docker, the tool
processes and Neo4j are replaced. With no RoE exclusion every list is the one
built without RoE keys at all.
Reserved names and documentation ranges only; no Docker, no network.
"""
from __future__ import annotations

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
from recon.helpers import target_helpers  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"          # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"

NO_ROE = [
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, WWW]},
]


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _recon() -> dict:
    """A domain-mode run after the gated httpx: only www answered."""
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {
                LEGACY: _sub(LEGACY_IP),
                MIXED: _sub(MIXED_BAD, MIXED_OK),
                WWW: _sub(WWW_IP),
            },
        },
        "http_probe": {"by_url": {f"https://{WWW}": {"url": f"https://{WWW}", "status_code": 200}}},
    }


def _hosts(urls) -> set:
    return {(urlparse(u).hostname or "").lower() for u in urls}


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


class _Stop(BaseException):
    """Escapes the modules' own `except Exception` once the input is read."""


# --------------------------------------------------------------------------
# Nuclei (run_vuln_scan)
# --------------------------------------------------------------------------

NUCLEI = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
          "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0}


def _nuclei_targets(settings, **extra) -> list:
    """The URLs written to the target file the Nuclei container reads."""
    from recon.main_recon_modules import vuln_scan as vs
    seen = {}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        target_file = Path(output_file).parent / f"targets_{label.lower()}.txt"
        seen[label] = target_file.read_text().split()
        return [], [], 1.0, 0

    with mock.patch.object(vs, "is_docker_installed", return_value=True), \
         mock.patch.object(vs, "is_docker_running", return_value=True), \
         mock.patch.object(vs, "pull_nuclei_docker_image", return_value=True), \
         mock.patch.object(vs, "ensure_templates_volume", return_value=True), \
         mock.patch.object(vs, "_execute_nuclei_pass", side_effect=fake_pass):
        vs.run_vuln_scan(_recon(), settings={**NUCLEI, **extra, **settings})
    assert "DETECTION" in seen, "the Nuclei detection pass never ran"
    return seen["DETECTION"]


def test_nuclei_never_gets_a_name_resolving_into_an_excluded_range():
    hosts = _hosts(_nuclei_targets(_roe(EXCLUDED_RANGE)))
    assert LEGACY not in hosts
    # Nuclei resolves a name itself, so a name with one excluded address is
    # not sent by name.
    assert MIXED not in hosts
    assert {WWW, APEX} <= hosts


def test_nuclei_with_every_ip_keeps_only_a_mixed_names_allowed_address():
    hosts = _hosts(_nuclei_targets(_roe(EXCLUDED_RANGE), NUCLEI_SCAN_ALL_IPS=True))
    assert MIXED_OK in hosts
    assert {LEGACY_IP, MIXED_BAD, LEGACY, MIXED}.isdisjoint(hosts)


@pytest.mark.parametrize("settings", NO_ROE)
def test_nuclei_targets_are_unchanged_without_an_exclusion(settings):
    baseline = _nuclei_targets({})
    assert _nuclei_targets(settings) == baseline
    assert {LEGACY, MIXED} <= _hosts(baseline)


# --------------------------------------------------------------------------
# Crawlers (run_resource_enum)
# --------------------------------------------------------------------------

CRAWL = {
    "KATANA_ENABLED": True, "KATANA_TIMEOUT": 30, "HAKRAWLER_ENABLED": False,
    "GAU_ENABLED": False, "PARAMSPIDER_ENABLED": False, "KITERUNNER_ENABLED": False,
    "JSLUICE_ENABLED": False, "FFUF_ENABLED": False, "ARJUN_ENABLED": False,
    "ZAP_AJAX_SPIDER_ENABLED": False, "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
}


def _crawler_seeds(settings):
    """The seed URLs and the allowed-host set Katana is started with."""
    import recon.main_recon_modules.resource_enum as re_mod
    seen = {}

    def katana(target_urls, *args, **_k):
        seen["urls"], seen["domains"] = list(target_urls), set(args[7])
        return [], {"external_domains": []}

    with mock.patch.object(re_mod, "run_katana_crawler", side_effect=katana), \
         mock.patch.object(re_mod, "pull_katana_docker_image", return_value=True), \
         mock.patch.object(re_mod, "is_docker_installed", return_value=True), \
         mock.patch.object(re_mod, "is_docker_running", return_value=True):
        re_mod.run_resource_enum(_recon(), settings={**CRAWL, **settings})
    assert seen, "Katana never ran"
    return seen["urls"], seen["domains"]


def test_the_crawlers_never_get_a_name_resolving_into_an_excluded_range():
    urls, domains = _crawler_seeds(_roe(EXCLUDED_RANGE))
    assert {LEGACY, MIXED}.isdisjoint(_hosts(urls))
    assert {LEGACY, MIXED}.isdisjoint(domains)
    assert {WWW, APEX} <= _hosts(urls)


@pytest.mark.parametrize("settings", NO_ROE)
def test_the_crawler_seeds_are_unchanged_without_an_exclusion(settings):
    baseline = _crawler_seeds({})
    assert _crawler_seeds(settings) == baseline
    assert {LEGACY, MIXED} <= _hosts(baseline[0])


# --------------------------------------------------------------------------
# Cache scan
# --------------------------------------------------------------------------

def _cache_urls(settings):
    from recon.cache_scan.scanner import _collect_target_urls
    return _collect_target_urls(_recon(), settings)


def test_the_cache_scan_never_gets_a_name_resolving_into_an_excluded_range():
    hosts = _hosts(_cache_urls(_roe(EXCLUDED_RANGE)))
    assert {LEGACY, MIXED}.isdisjoint(hosts)
    assert {WWW, APEX} <= hosts


@pytest.mark.parametrize("settings", NO_ROE)
def test_the_cache_scan_targets_are_unchanged_without_an_exclusion(settings):
    baseline = _cache_urls({})
    assert _cache_urls(settings) == baseline
    assert {LEGACY, MIXED} <= _hosts(baseline)


# --------------------------------------------------------------------------
# Port coverage (the Shodan port check's "looked at")
# --------------------------------------------------------------------------

def _port_scanned(scanner: str) -> dict:
    recon = _recon()
    section = {"scan_metadata": {"scanner": scanner, "ports_config": "80,443"},
               "by_ip": {WWW_IP: {"ports": [443]}}}
    recon["masscan_scan" if scanner == "masscan" else "port_scan"] = section
    return recon


@pytest.mark.parametrize("scanner", ["naabu", "masscan"])
def test_an_excluded_address_is_never_counted_as_looked_at(scanner):
    from recon.helpers.port_coverage import port_scan_coverage
    covers = port_scan_coverage(_port_scanned(scanner), _roe(EXCLUDED_RANGE))
    # The scan was never handed these addresses: unknown, never "closed".
    assert covers(LEGACY_IP, 443) is None
    assert covers(MIXED_BAD, 443) is None
    assert covers(MIXED_OK, 443) is False
    assert covers(WWW_IP, 443) is True


@pytest.mark.parametrize("scanner", ["naabu", "masscan"])
@pytest.mark.parametrize("settings", NO_ROE)
def test_port_coverage_is_unchanged_without_an_exclusion(scanner, settings):
    from recon.helpers.port_coverage import port_scan_coverage
    covers = port_scan_coverage(_port_scanned(scanner), settings)
    assert covers(LEGACY_IP, 443) is False
    assert covers(WWW_IP, 443) is True


# --------------------------------------------------------------------------
# Partial recon: the crawlers and Kiterunner, on the real graph builder
# --------------------------------------------------------------------------

# (subdomain, address) rows the graph holds from an earlier run.
GRAPH_DNS = [(LEGACY, LEGACY_IP), (MIXED, MIXED_BAD), (MIXED, MIXED_OK), (WWW, WWW_IP)]
GRAPH_BASEURLS = [f"https://{WWW}"]


class _Rows(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self, baseurls):
        self.baseurls = baseurls

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **_params):
        rows = _Rows()
        if "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": sorted({s for s, _ in GRAPH_DNS})})
        elif "$apex_roots" in cypher:
            rows.append({"root": APEX, "address": APEX_IP, "version": "IPv4"})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            rows.extend({"root": APEX, "subdomain": s, "address": a, "version": "IPv4"}
                        for s, a in GRAPH_DNS)
        elif "MATCH (b:BaseURL" in cypher:
            rows.extend({"url": u, "host": urlparse(u).hostname, "status_code": 200,
                         "content_type": "text/html"} for u in self.baseurls)
        return rows


def _graph_client(baseurls):
    class _Client:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return True

        @property
        def driver(self):
            driver = mock.MagicMock()
            driver.session.side_effect = lambda **_k: _Session(baseurls)
            return driver

    return _Client


PARTIAL = [
    ("recon.partial_recon_modules.web_crawling", "run_katana"),
    ("recon.partial_recon_modules.web_crawling", "run_hakrawler"),
    ("recon.partial_recon_modules.web_crawling", "run_zap_ajax_spider_partial"),
    ("recon.partial_recon_modules.web_crawling", "run_ffuf"),
    ("recon.partial_recon_modules.parameter_discovery", "run_kiterunner"),
]


def _partial_targets(module_name, entry, settings, monkeypatch, baseurls=GRAPH_BASEURLS):
    """The URL list a partial module builds for its tool, from the graph."""
    import importlib
    from recon.partial_recon_modules import helpers as partial_helpers
    module = importlib.import_module(module_name)
    seen = {}

    def built(*args, **kwargs):
        seen["urls"] = target_helpers.build_target_urls(*args, **kwargs)
        raise _Stop

    monkeypatch.setattr("graph_db.Neo4jClient", _graph_client(baseurls))
    monkeypatch.setattr(module, "build_target_urls", built)
    run_settings = {"SUBDOMAIN_LIST": ["."], **settings}
    # What partial_recon._prepare_scope does before any module runs.
    partial_helpers.set_run_roe(run_settings)
    try:
        with pytest.raises(_Stop):
            getattr(module, entry)({"_settings": run_settings, "domains": [APEX], "domain": APEX})
    finally:
        partial_helpers.set_run_roe({})
    return seen["urls"]


@pytest.mark.parametrize("module_name,entry", PARTIAL)
def test_a_partial_tool_never_gets_a_name_resolving_into_an_excluded_range(module_name, entry, monkeypatch):
    hosts = _hosts(_partial_targets(module_name, entry, _roe(EXCLUDED_RANGE), monkeypatch))
    assert LEGACY not in hosts
    assert WWW in hosts


@pytest.mark.parametrize("module_name,entry", PARTIAL)
@pytest.mark.parametrize("settings", NO_ROE)
def test_a_partial_tools_targets_are_unchanged_without_an_exclusion(module_name, entry, settings, monkeypatch):
    baseline = _partial_targets(module_name, entry, {}, monkeypatch)
    assert _partial_targets(module_name, entry, settings, monkeypatch) == baseline
    assert {LEGACY, MIXED, WWW} <= _hosts(baseline)


def test_partial_katana_is_started_without_the_excluded_name(monkeypatch):
    """The seeds the Katana container gets, not only the list built."""
    import recon.helpers.resource_enum as resource_enum
    from recon.partial_recon_modules import helpers as partial_helpers
    from recon.partial_recon_modules import web_crawling
    seen = {}

    def katana(target_urls, *_a, **_k):
        seen["urls"] = list(target_urls)
        raise _Stop

    monkeypatch.setattr("graph_db.Neo4jClient", _graph_client(GRAPH_BASEURLS))
    monkeypatch.setattr(resource_enum, "run_katana_crawler", katana)
    monkeypatch.setattr(resource_enum, "pull_katana_docker_image", lambda *_a, **_k: True)
    settings = {"SUBDOMAIN_LIST": ["."], **_roe(EXCLUDED_RANGE)}
    partial_helpers.set_run_roe(settings)
    try:
        with pytest.raises(_Stop):
            web_crawling.run_katana({"_settings": settings, "domains": [APEX], "domain": APEX})
    finally:
        partial_helpers.set_run_roe({})
    assert LEGACY not in _hosts(seen["urls"])
    assert WWW in _hosts(seen["urls"])


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R-2 follow-up: _build_http_probe_data_from_graph drops a name's excluded "
    "address before the gate sees it, so a name with one excluded and one allowed "
    "address looks wholly allowed and a partial crawler still resolves it by name"))
def test_a_partial_crawler_never_gets_a_name_with_one_excluded_address(monkeypatch):
    hosts = _hosts(_partial_targets(*PARTIAL[0], _roe(EXCLUDED_RANGE), monkeypatch))
    assert MIXED not in hosts


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R-2 follow-up: a graph BaseURL is checked against the RoE by its name only "
    "(graph_url_scope), so a BaseURL an earlier run wrote for a name resolving "
    "into an excluded range is still a partial crawler's seed"))
def test_a_partial_crawler_never_gets_a_graph_baseurl_resolving_into_an_excluded_range(monkeypatch):
    urls = _partial_targets(*PARTIAL[0], _roe(EXCLUDED_RANGE), monkeypatch,
                            baseurls=[*GRAPH_BASEURLS, f"https://{LEGACY}"])
    assert LEGACY not in _hosts(urls)

"""Passive CVE sources (Shodan, InternetDB, Netlas, CriminalIP) are pruned (plan 04.1).

Their findings were in no prune list, so a CVE stayed for ever once its IP left
the target, attached to nothing, and the board scored the orphan's reach higher
than it had been while attached. Now they are pruned like every recon source,
and the prune follows "switched off vs degraded":

  - switched off (the module disabled, no key configured): nothing is noted,
    so the prune removes the old findings;
  - the lookup asked about only some IPs: the IPs it could not ask about keep
    their findings (degrade by host), the others prune normally;
  - it could ask about nothing (a refused key, a crash, no IP at all): the
    whole source is kept.

Every provider and Neo4j is a fake. Addresses are RFC 5737.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES, RECON_FINDING_SOURCES  # noqa: E402
from recon.main_recon_modules import criminalip_enrich as cip  # noqa: E402
from recon.main_recon_modules import netlas_enrich as netlas  # noqa: E402
from recon.main_recon_modules import shodan_enrich as se  # noqa: E402

IPS = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"]
ANSWERED, UNANSWERED = IPS[:3], IPS[3:]
SHODAN_SOURCES = ("shodan_api", "internetdb", "shodan", "shodan_host_lookup")
_TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


def _recon(ips=IPS) -> dict:
    return {"domain": "example.com", "metadata": {"ip_mode": True, "expanded_ips": list(ips)},
            "dns": {"domain": {}, "subdomains": {}}}


class Resp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = text
        self.headers = {}

    def json(self):
        return self._body


def _ip_in(url: str, params: dict | None) -> str:
    for ip in IPS:
        if url.endswith("/" + ip) or ip in str(params or {}):
            return ip
    return ""


def _answers_for(answered, body=None):
    """requests.get: 200 for `answered`, a refused connection for the rest."""
    def get(url, params=None, **_kw):
        ip = _ip_in(url, params)
        if ip in answered:
            return Resp(200, body(ip) if callable(body) else (body or {}))
        raise ConnectionError("refused")
    return get


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(se.time, "sleep", lambda *_: None)
    monkeypatch.setattr(se, "filter_ips_for_enrichment", lambda ips, *_a, **_k: list(ips))
    monkeypatch.setattr(netlas, "filter_ips_for_enrichment", lambda ips, *_a, **_k: list(ips))
    monkeypatch.setattr(cip, "filter_ips_for_enrichment", lambda ips, *_a, **_k: list(ips))


def _kept(source: str) -> set:
    return set(cb.coverage_report().keep_hostnames(source))


def _passive_gaps() -> list:
    passive = {s for sources in PASSIVE_CVE_SOURCES.values() for s in sources}
    return sorted(g["source"] for g in cb.coverage_report().gaps if g["source"] in passive)


def _assert_tokens():
    """The Recon Delta drops a run's whole gap list over one malformed source."""
    passive = {s for sources in PASSIVE_CVE_SOURCES.values() for s in sources}
    for gap in cb.coverage_report().gaps:
        assert isinstance(gap["source"], str) and 0 < len(gap["source"]) <= 64, gap
        if gap["source"] in passive:
            assert _TOKEN.match(gap["source"]), gap


# ---------------------------------------------------------------------------
# The prune list
# ---------------------------------------------------------------------------

class TestThePruneList:
    def test_every_passive_cve_source_value_is_pruned(self):
        assert PASSIVE_CVE_SOURCES == {
            "shodan": SHODAN_SOURCES, "netlas": ("netlas",), "criminalip": ("criminalip",)}
        for sources in PASSIVE_CVE_SOURCES.values():
            assert set(sources) <= set(RECON_FINDING_SOURCES)

    def test_the_writers_stamp_only_those_values(self):
        osint = (PROJECT_ROOT / "graph_db" / "mixins" / "osint_mixin.py").read_text()
        shodan = (PROJECT_ROOT / "recon" / "main_recon_modules" / "shodan_enrich.py").read_text()
        assert '"source": "shodan_api"' in shodan and '"source": "internetdb"' in shodan
        assert 'cve_entry.get("source", "shodan")' in osint
        assert "v.source = 'criminalip'" in osint

    def test_the_graph_backfill_knows_the_same_ip_keyed_sources(self):
        import ast
        tree = ast.parse((PROJECT_ROOT / "graph_db" / "mixins" / "osint_mixin.py").read_text())
        backfilled = next(ast.literal_eval(n.value) for n in tree.body
                          if isinstance(n, ast.Assign)
                          and getattr(n.targets[0], "id", "") == "_IP_KEYED_PASSIVE_SOURCES")
        assert set(backfilled) == set(SHODAN_SOURCES) | {"criminalip"}

    def test_each_enricher_has_a_phase_entry(self, recon_main):
        for phase, sources in PASSIVE_CVE_SOURCES.items():
            assert recon_main._PHASE_FINDING_SOURCES[phase] == sources

    def test_a_crashed_phase_keeps_its_whole_source(self, recon_main):
        recon_main._note_phase_error("netlas")
        recon_main._note_phase_error("shodan")
        degraded = cb.coverage_report().degraded_sources
        assert {"netlas", *SHODAN_SOURCES} <= degraded
        assert "criminalip" not in degraded
        assert _passive_gaps() == ["netlas", "shodan"]
        _assert_tokens()


# ---------------------------------------------------------------------------
# Shodan / InternetDB
# ---------------------------------------------------------------------------

def _shodan(settings=None, ips=IPS):
    base = {"SHODAN_ENABLED": True, "SHODAN_HOST_LOOKUP": True, "SHODAN_PASSIVE_CVES": True,
            "SHODAN_API_KEY": "", "SHODAN_WORKERS": 1}
    se.run_shodan_enrichment(_recon(ips), {**base, **(settings or {})})


class TestShodanCoverage:
    def test_switched_off_notes_nothing(self):
        with mock.patch.object(se.requests, "get", side_effect=AssertionError("no call")):
            _shodan({"SHODAN_HOST_LOOKUP": False, "SHODAN_PASSIVE_CVES": False})
        assert not cb.coverage_report().degraded

    def test_passive_cves_switched_off_notes_nothing(self):
        with mock.patch.object(se.requests, "get", side_effect=_answers_for(ANSWERED)):
            _shodan({"SHODAN_PASSIVE_CVES": False})
        report = cb.coverage_report()
        assert not (set(SHODAN_SOURCES) & report.degraded_sources)
        assert not any(_kept(s) for s in SHODAN_SOURCES)

    def test_three_of_five_ips_keep_only_the_two_unqueried(self):
        with mock.patch.object(se.requests, "get", side_effect=_answers_for(ANSWERED)):
            _shodan()
        report = cb.coverage_report()
        assert not (set(SHODAN_SOURCES) & report.degraded_sources)
        for source in SHODAN_SOURCES:
            assert _kept(source) == set(UNANSWERED)
        assert _kept("nuclei") == set()
        assert _passive_gaps() == ["shodan"], "the report names the provider once"
        _assert_tokens()

    def test_no_data_is_an_answer(self):
        def get(url, params=None, **_kw):
            return Resp(404)
        with mock.patch.object(se.requests, "get", side_effect=get):
            _shodan()
        assert not cb.coverage_report().degraded_sources
        assert not _kept("internetdb")

    def test_every_ip_answered_degrades_nothing(self):
        body = {"ports": [22], "vulns": ["CVE-2018-15473"]}
        with mock.patch.object(se.requests, "get", side_effect=_answers_for(IPS, body)):
            _shodan()
        report = cb.coverage_report()
        assert not report.degraded_sources and not report.skipped_hosts

    def test_the_paid_api_path_tracks_its_answers_too(self):
        def get(url, params=None, **_kw):
            ip = _ip_in(url, params)
            if ip in UNANSWERED:
                raise ConnectionError("refused")
            return Resp(404) if ip == IPS[0] else Resp(200, {"ports": [22], "vulns": {}, "data": []})
        with mock.patch.object(se.requests, "get", side_effect=get):
            _shodan({"SHODAN_API_KEY": "synthetic-key-0000"})
        assert _kept("shodan_api") == set(UNANSWERED)
        assert not cb.coverage_report().degraded_sources

    def test_nothing_answered_keeps_the_whole_source(self):
        with mock.patch.object(se.requests, "get", side_effect=ConnectionError("down")):
            _shodan()
        assert set(SHODAN_SOURCES) <= cb.coverage_report().degraded_sources
        _assert_tokens()

    def test_no_ip_at_all_keeps_the_whole_source(self):
        with mock.patch.object(se.requests, "get", side_effect=AssertionError("no call")):
            _shodan(ips=[])
        assert set(SHODAN_SOURCES) <= cb.coverage_report().degraded_sources

    def test_ips_filtered_as_cdn_were_decided_not_skipped(self, monkeypatch):
        monkeypatch.setattr(se, "filter_ips_for_enrichment", lambda ips, *_a, **_k: [])
        with mock.patch.object(se.requests, "get", side_effect=AssertionError("no call")):
            _shodan()
        assert not cb.coverage_report().degraded

    def test_a_crash_keeps_the_whole_source(self, monkeypatch):
        monkeypatch.setattr(se, "_run_host_lookup", mock.Mock(side_effect=RuntimeError("boom")))
        _shodan()
        assert set(SHODAN_SOURCES) <= cb.coverage_report().degraded_sources


# ---------------------------------------------------------------------------
# Netlas
# ---------------------------------------------------------------------------

def _netlas(settings=None, ips=IPS, recon=None):
    base = {"NETLAS_ENABLED": True, "NETLAS_API_KEY": "synthetic-key-0000", "NETLAS_WORKERS": 1}
    netlas.run_netlas_enrichment(recon or _recon(ips), {**base, **(settings or {})})


def _netlas_rows(ip):
    return {"items": [{"data": {"ip": ip, "port": 22, "protocol": "ssh",
                                "cve": [{"name": "CVE-2018-15473", "base_score": 5.3}]}}],
            "total": 1}


class TestNetlasCoverage:
    def test_switched_off_notes_nothing(self):
        with mock.patch.object(netlas.requests, "get", side_effect=AssertionError("no call")):
            _netlas({"NETLAS_ENABLED": False})
        assert not cb.coverage_report().degraded

    def test_no_key_configured_notes_nothing(self):
        with mock.patch.object(netlas.requests, "get", side_effect=AssertionError("no call")):
            _netlas({"NETLAS_API_KEY": ""})
        assert not cb.coverage_report().degraded

    def test_three_of_five_ips_keep_only_the_two_unqueried(self):
        with mock.patch.object(netlas.requests, "get",
                               side_effect=_answers_for(ANSWERED, _netlas_rows)):
            _netlas()
        assert "netlas" not in cb.coverage_report().degraded_sources
        assert _kept("netlas") == set(UNANSWERED)
        _assert_tokens()

    def test_a_truncated_answer_keeps_that_ip(self):
        def body(ip):
            rows = _netlas_rows(ip)
            if ip == IPS[0]:
                rows["total"] = 500
            return rows
        with mock.patch.object(netlas.requests, "get", side_effect=_answers_for(IPS, body)):
            _netlas()
        assert _kept("netlas") == {IPS[0]}

    def test_a_refused_key_keeps_the_whole_source(self):
        with mock.patch.object(netlas.requests, "get",
                               return_value=Resp(400, text='{"detail": "API key not found"}')):
            _netlas()
        assert "netlas" in cb.coverage_report().degraded_sources

    def test_every_ip_answered_degrades_nothing(self):
        with mock.patch.object(netlas.requests, "get", side_effect=_answers_for(IPS, _netlas_rows)):
            _netlas()
        assert not cb.coverage_report().degraded_sources and not _kept("netlas")


# ---------------------------------------------------------------------------
# CriminalIP
# ---------------------------------------------------------------------------

def _criminalip(settings=None, ips=IPS):
    base = {"CRIMINALIP_ENABLED": True, "CRIMINALIP_API_KEY": "synthetic-key-0000",
            "CRIMINALIP_WORKERS": 1}
    cip.run_criminalip_enrichment(_recon(ips), {**base, **(settings or {})})


class TestCriminalIPCoverage:
    def test_switched_off_notes_nothing(self):
        with mock.patch.object(cip.requests, "get", side_effect=AssertionError("no call")):
            _criminalip({"CRIMINALIP_ENABLED": False})
        assert not cb.coverage_report().degraded

    def test_no_key_configured_notes_nothing(self):
        with mock.patch.object(cip.requests, "get", side_effect=AssertionError("no call")):
            _criminalip({"CRIMINALIP_API_KEY": ""})
        assert not cb.coverage_report().degraded

    def test_three_of_five_ips_keep_only_the_two_unqueried(self):
        with mock.patch.object(cip.requests, "get", side_effect=_answers_for(ANSWERED)):
            _criminalip()
        assert "criminalip" not in cb.coverage_report().degraded_sources
        assert _kept("criminalip") == set(UNANSWERED)
        _assert_tokens()

    def test_a_refused_key_keeps_the_whole_source(self):
        with mock.patch.object(cip.requests, "get", return_value=Resp(401)):
            _criminalip()
        assert "criminalip" in cb.coverage_report().degraded_sources

    def test_every_ip_answered_degrades_nothing(self):
        with mock.patch.object(cip.requests, "get", side_effect=_answers_for(IPS)):
            _criminalip()
        assert not cb.coverage_report().degraded


# ---------------------------------------------------------------------------
# The pipeline: the fan-in, and what the prune is asked to keep
# ---------------------------------------------------------------------------

@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': list(IPS),
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': [],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", [])
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", False)
        yield rm


IP_SETTINGS = {
    "DNS_ENABLED": False, "WHOIS_ENABLED": False, "SHODAN_ENABLED": True,
    "SHODAN_PASSIVE_CVES": True, "NAABU_ENABLED": False, "MASSCAN_ENABLED": False,
    "NMAP_ENABLED": False, "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": True,
    "NETLAS_ENABLED": True, "NETLAS_API_KEY": "synthetic-key-0000", "UNCOVER_ENABLED": False,
    "HTTPX_ENABLED": False, "SECURITY_CHECK_ENABLED": False, "AI_SURFACE_RECON_ENABLED": False,
    "JS_RECON_ENABLED": False, "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROE_ENABLED": False,
}


def _boom(*_a, **_k):
    raise RuntimeError("enricher exploded")


class TestTheFanIn:
    def test_a_crashed_enricher_keeps_its_findings(self, recon_main, monkeypatch):
        monkeypatch.setattr(se, "run_shodan_enrichment_isolated", _boom)
        monkeypatch.setattr(netlas, "run_netlas_enrichment_isolated", _boom)
        recon_main.run_ip_recon(list(IPS), dict(IP_SETTINGS))
        degraded = cb.coverage_report().degraded_sources
        assert {"netlas", *SHODAN_SOURCES} <= degraded

    def test_the_domain_pipeline_records_it_too(self, recon_main):
        import inspect
        body = inspect.getsource(recon_main.run_domain_recon)
        for marker in ('g3_futures["shodan"]', "osint_futures[name]"):
            block = body[body.index(marker):]
            block = block[:block.index("save_recon_file(")]
            assert "_note_phase_error(name)" in block, marker


class _Graph:
    def __init__(self):
        self.prunes = []
        self.backfilled = []

    def __call__(self, *a, **k):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, user_id, project_id):
        self.backfilled.append((user_id, project_id))
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(), **kw):
        self.prunes.append((list(sources), tuple(keep_hosts)))


class TestThePrune:
    def _prune(self, recon_main, monkeypatch):
        graph = _Graph()
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        monkeypatch.setattr(recon_main, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
        monkeypatch.setattr(recon_main, "_COVERAGE_WRITE_FAILED", False)
        recon_main._prune_recon_findings()
        return graph

    def test_a_partial_lookup_keeps_only_its_own_unqueried_ips(self, recon_main, monkeypatch):
        with mock.patch.object(cip.requests, "get", side_effect=_answers_for(ANSWERED)):
            _criminalip()
        graph = self._prune(recon_main, monkeypatch)
        keep = {s: set(k) for sources, k in graph.prunes for s in sources}
        assert keep["criminalip"] == set(UNANSWERED)
        assert keep["nuclei"] == set() and keep["netlas"] == set()

    def test_a_switched_off_source_is_pruned_with_the_rest(self, recon_main, monkeypatch):
        graph = self._prune(recon_main, monkeypatch)
        pruned = {s for sources, _ in graph.prunes for s in sources}
        assert {"netlas", "criminalip", *SHODAN_SOURCES} <= pruned

    def test_older_nodes_get_their_host_before_the_prune(self, recon_main, monkeypatch):
        graph = self._prune(recon_main, monkeypatch)
        assert graph.backfilled == [("u1", "p1")]

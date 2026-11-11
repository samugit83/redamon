"""Passive CVEs adopt the positive-coverage prune (D1, option b).

Shodan, Netlas and CriminalIP answer per IP. Before D1 a passive CVE was
pruned whenever its IP was not one the lookup failed to ask about, so a CVE
on an IP that left the run (a target removed, a name that stopped resolving)
was deleted although nothing had re-checked it. Now each lookup records the
IPs it decided about (`circuit_breaker.note_checked`), and the prune deletes a
passive CVE only on those:

  - an IP the lookup asked about and saw the whole answer for: pruned;
  - an IP its CDN / private-address filter dropped before the lookup: also
    decided (plan 04.1: an edge's CVEs describe the provider), so pruned;
  - an IP it asked about and got no answer for: kept (degraded by host);
  - an IP no longer in the run at all: kept until a run re-checks it.

Each case runs the real enricher (its HTTP calls mocked), the real
`note_cve_coverage` and the real end-of-run `_prune_recon_findings`; only
Neo4j is a fake, which applies the prune call it receives to an in-memory
set of an earlier run's findings. Addresses are RFC 5737.
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
from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES  # noqa: E402
from recon.helpers.passive_cve_coverage import note_cve_coverage  # noqa: E402
from recon.main_recon_modules import criminalip_enrich as cip  # noqa: E402
from recon.main_recon_modules import netlas_enrich as netlas  # noqa: E402
from recon.main_recon_modules import shodan_enrich as se  # noqa: E402

CLEAN = "198.51.100.1"        # asked, answered with no CVE
CDN = "198.51.100.4"          # in the run, dropped by the CDN filter before the lookup
UNANSWERED = "198.51.100.5"   # asked, no answer
GONE = "198.51.100.9"         # an earlier run's IP, no longer in this one
TARGETS = [CLEAN, CDN, UNANSWERED]
SHODAN_SOURCES = PASSIVE_CVE_SOURCES["shodan"]
SINCE = "2026-01-01T00:00:00+00:00"
_TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


# ---------------------------------------------------------------------------
# The providers (HTTP mocked) and the filter
# ---------------------------------------------------------------------------

class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = ""
        self.headers = {}

    def json(self):
        return self._body


def _ip_in(url: str, params) -> str:
    for ip in (CLEAN, CDN, UNANSWERED, GONE):
        if url.endswith("/" + ip) or ip in str(params or {}):
            return ip
    return ""


def _provider(clean_body):
    """CLEAN answers with `clean_body`, UNANSWERED refuses, nothing else is asked."""
    def get(url, params=None, **_kw):
        ip = _ip_in(url, params)
        if ip == CLEAN:
            return Resp(200, clean_body)
        if ip == UNANSWERED:
            raise ConnectionError("refused")
        raise AssertionError(f"looked up an IP the run must not ask about: {ip or url}")
    return get


def _drop_cdn(ips, *_a, **_k):
    return [ip for ip in ips if ip != CDN]


@pytest.fixture(autouse=True)
def _cdn_filter(monkeypatch):
    monkeypatch.setattr(se.time, "sleep", lambda *_: None)
    for module in (se, netlas, cip):
        monkeypatch.setattr(module, "filter_ips_for_enrichment", _drop_cdn)


def _ip_recon(ips=TARGETS) -> dict:
    return {"domain": "example.com", "metadata": {"ip_mode": True, "expanded_ips": list(ips)},
            "dns": {"domain": {}, "subdomains": {}}}


def _run_shodan():
    with mock.patch.object(se.requests, "get", side_effect=_provider({})):
        se.run_shodan_enrichment(_ip_recon(), {
            "SHODAN_ENABLED": True, "SHODAN_HOST_LOOKUP": True, "SHODAN_PASSIVE_CVES": True,
            "SHODAN_API_KEY": "", "SHODAN_WORKERS": 1})


def _run_netlas():
    with mock.patch.object(netlas.requests, "get",
                           side_effect=_provider({"items": [], "total": 0})):
        netlas.run_netlas_enrichment(_ip_recon(), {
            "NETLAS_ENABLED": True, "NETLAS_API_KEY": "synthetic-key-0000",
            "NETLAS_WORKERS": 1})


def _run_criminalip():
    with mock.patch.object(cip.requests, "get", side_effect=_provider({})):
        cip.run_criminalip_enrichment(_ip_recon(), {
            "CRIMINALIP_ENABLED": True, "CRIMINALIP_API_KEY": "synthetic-key-0000",
            "CRIMINALIP_WORKERS": 1})


# provider -> (enricher, the source values an earlier run's CVEs carry)
PROVIDERS = {
    "shodan": (_run_shodan, ("internetdb", "shodan_api")),
    "netlas": (_run_netlas, ("netlas",)),
    "criminalip": (_run_criminalip, ("criminalip",)),
}


# ---------------------------------------------------------------------------
# Neo4j: a fake that applies each prune call to an earlier run's findings
# ---------------------------------------------------------------------------

class FindingGraph:
    """Findings of an earlier run, none re-written by this one (all stale).

    A finding is deleted when the call names its source, its host is not
    kept, and, with `only_hosts`, its host is one of them: the contract
    `prune_unseen_findings` documents (its Cypher is proven live in
    tests/test_positive_prune_graph_live.py).
    """

    def __init__(self, findings):
        self.findings = {f["id"]: f for f in findings}
        self.calls = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, user_id, project_id):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(), *,
                              only_hosts=None, types=None, exclude_types=None):
        self.calls.append({"sources": sorted(sources), "keep_hosts": tuple(keep_hosts),
                           "only_hosts": only_hosts, "types": types,
                           "exclude_types": exclude_types})
        for fid, f in list(self.findings.items()):
            if f["source"] not in sources or f["host"] in keep_hosts:
                continue
            if only_hosts is not None and f["host"] not in only_hosts:
                continue
            if types is not None and f.get("type") not in types:
                continue
            if exclude_types and f.get("type") in exclude_types:
                continue
            del self.findings[fid]
        return {"pruned": 0, "stale": 0, "revived": 0}

    def surviving(self, source) -> set:
        return {f["host"] for f in self.findings.values() if f["source"] == source}


def _earlier_findings(sources) -> list:
    rows = [{"id": f"{s}-CVE-2018-15473-{ip}", "source": s, "host": ip}
            for s in sources for ip in (CLEAN, CDN, UNANSWERED, GONE)]
    # A source that keeps the source-level rule, so the prune visibly ran.
    rows.append({"id": f"nuclei-{GONE}", "source": "nuclei", "host": GONE})
    return rows


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': list(TARGETS),
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': [],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", [])
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", True)
        monkeypatch.setattr(rm, "_RUN_STARTED_AT", SINCE)
        monkeypatch.setattr(rm, "_COVERAGE_WRITE_FAILED", False)
        yield rm


def _run_and_prune(provider, recon_main, monkeypatch) -> FindingGraph:
    run, sources = PROVIDERS[provider]
    graph = FindingGraph(_earlier_findings(sources))
    monkeypatch.setattr("graph_db.Neo4jClient", graph)
    run()
    recon_main._prune_recon_findings()
    return graph


# ---------------------------------------------------------------------------
# The four cases, per provider, through the real enricher and the real prune
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", sorted(PROVIDERS))
class TestWhatThePruneKeeps:
    def test_a_cve_on_an_ip_that_left_the_run_is_kept(self, provider, recon_main, monkeypatch):
        graph = _run_and_prune(provider, recon_main, monkeypatch)
        for source in PROVIDERS[provider][1]:
            assert GONE in graph.surviving(source), source
        assert graph.surviving("nuclei") == set(), "the source-level prune still ran"

    def test_a_cve_on_an_ip_the_cdn_filter_dropped_is_pruned(self, provider, recon_main,
                                                             monkeypatch):
        graph = _run_and_prune(provider, recon_main, monkeypatch)
        for source in PROVIDERS[provider][1]:
            assert CDN not in graph.surviving(source), source

    def test_a_cve_on_an_ip_asked_without_an_answer_is_kept(self, provider, recon_main,
                                                            monkeypatch):
        graph = _run_and_prune(provider, recon_main, monkeypatch)
        for source in PROVIDERS[provider][1]:
            assert UNANSWERED in graph.surviving(source), source

    def test_a_cve_on_an_ip_asked_and_found_clean_is_pruned(self, provider, recon_main,
                                                            monkeypatch):
        graph = _run_and_prune(provider, recon_main, monkeypatch)
        for source in PROVIDERS[provider][1]:
            assert CLEAN not in graph.surviving(source), source

    def test_the_prune_is_asked_for_the_decided_ips_only(self, provider, recon_main,
                                                         monkeypatch):
        graph = _run_and_prune(provider, recon_main, monkeypatch)
        every = sorted(PASSIVE_CVE_SOURCES[provider])
        calls = [c for c in graph.calls if set(c["sources"]) & set(every)]
        assert calls == [{"sources": every, "keep_hosts": (UNANSWERED,),
                          "only_hosts": (CLEAN, CDN), "types": None,
                          "exclude_types": None}]


# ---------------------------------------------------------------------------
# note_cve_coverage itself
# ---------------------------------------------------------------------------

class TestTheCoverageRecord:
    def test_every_source_value_of_the_provider_records_the_decided_ips(self):
        note_cve_coverage("shodan", "shodan_enrich", [CLEAN, UNANSWERED], [CLEAN],
                          considered=[CLEAN, CDN, UNANSWERED])
        report = cb.coverage_report()
        assert report.positive_sources == frozenset(SHODAN_SOURCES)
        for source in SHODAN_SOURCES:
            assert report.checked_hostnames(source) == (CLEAN, CDN)
            assert report.keep_hostnames(source) == (UNANSWERED,)
        assert all(_TOKEN.match(s) for s in report.positive_sources)

    def test_recording_what_was_decided_is_not_a_coverage_gap(self):
        note_cve_coverage("netlas", "netlas_enrich", [CLEAN], [CLEAN], considered=[CLEAN, CDN])
        report = cb.coverage_report()
        assert not report.degraded and report.gaps == ()

    def test_an_ip_neither_considered_nor_asked_is_never_checked(self):
        note_cve_coverage("criminalip", "criminalip_enrich", [CLEAN], [CLEAN],
                          considered=[CLEAN, "", None])
        assert cb.coverage_report().checked_hostnames("criminalip") == (CLEAN,)

    def test_every_ip_filtered_still_decides_them(self):
        """Nothing left to ask about is not "no input": the filter decided."""
        note_cve_coverage("criminalip", "criminalip_enrich", [], [], considered=[CDN])
        report = cb.coverage_report()
        assert not report.degraded
        assert report.checked_hostnames("criminalip") == (CDN,)

    @pytest.mark.parametrize("cut", [{"failed": True}, {"no_input": True}, {"reached": False}])
    def test_a_lookup_cut_as_a_whole_prunes_none_of_them(self, cut):
        note_cve_coverage("netlas", "netlas_enrich", [CLEAN], [], considered=[CLEAN, CDN], **cut)
        report = cb.coverage_report()
        assert "netlas" in report.degraded_sources
        assert report.checked_hostnames("netlas") == ()

    def test_a_crashed_phase_records_nothing_checked(self, recon_main):
        recon_main._note_phase_error("shodan")
        report = cb.coverage_report()
        assert all(report.checked_hostnames(s) == () for s in SHODAN_SOURCES)

    def test_a_partial_run_reads_it_as_no_new_gap(self):
        """Partial recon never prunes; it reads the accumulator only to call a
        root degraded, and a checked record must not make it say so."""
        from recon.partial_recon_modules.helpers import _coverage_signature
        before = _coverage_signature()
        note_cve_coverage("shodan", "shodan_enrich", [CLEAN], [CLEAN], considered=[CLEAN, CDN])
        assert _coverage_signature() == before

"""Regression (R-45): origin discovery recorded nothing for a host it could not check.

A keyed search the run's budget refused, a fronted host that did not answer
the reference fetch, a source or candidate check that failed, and a host whose
processing raised all left the host reading as "checked, no origin". The
end-of-run prune then deleted its earlier `waf_bypass` findings. In a Domain
batch the budget is shared by every group, so the later groups lost theirs on
every run. Each such host is now cut for origin_discovery alone; a host checked
to the end with no origin still prunes.

Searches, fetches, DNS and Neo4j are fakes. Names are example.com, candidate
addresses RFC 5737 (the SSRF filter, not under test here, is opened for them).
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
from recon.main_recon_modules import origin_discovery as od  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as us  # noqa: E402

A, B = "a.example.com", "b.example.com"
EDGE = "104.16.1.1"
ORIGIN = "203.0.113.10"
SHA = "4be1" + "0" * 56 + "d07"
OWN = {"url": f"https://{A}/assets/app.8f3a91c2.js", "path": "/assets/app.8f3a91c2.js",
       "host": A, "name": "app.8f3a91c2.js", "sha256": SHA}
REFERENCE = {"text": "hello", "status": 200, "headers": {}, "cookies": "", "html": "",
             "final_url": f"https://{A}/"}


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def refuse(*_a, **_k):
        raise OSError("network disabled in unit tests")
    monkeypatch.setattr(od, "_tls_handshake_cert", refuse)
    monkeypatch.setattr(od, "_resolve_ips", lambda host: set())
    monkeypatch.setattr(od, "_favicon_hash_for_host", lambda host, existing, ctx: None)
    monkeypatch.setattr(od, "_discover_via_otx", lambda domain, ctx: [])
    cb.reset_registry()
    yield
    cb.reset_registry()


def _settings(**over):
    s = {"ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_KEYLESS": False,
         "ORIGIN_DISCOVERY_SCANNERS": False, "ORIGIN_DISCOVERY_PASSIVE_DNS": False,
         "ORIGIN_DISCOVERY_URLSCAN": False, "URLSCAN_ENABLED": False,
         "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25, "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
         "ORIGIN_DISCOVERY_THRESHOLD": 60, "ORIGIN_DISCOVERY_TIMEOUT": 3,
         "ORIGIN_DISCOVERY_WORKERS": 2, "ORIGIN_DISCOVERY_RATE": 0,
         "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": []}
    s.update(over)
    return s


def _combined(*hosts):
    return {"http_probe": {"by_url": {
        f"https://{h}": {"host": h, "ip": EDGE, "is_cdn": True, "cdn": "cloudflare",
                         "status_code": 200}
        for h in hosts}}}


def _censys_answer(*_a, **_k):
    return mock.MagicMock(status_code=200, headers={}, json=lambda: {"result": {"hits": []}})


def _censys_settings(**over):
    return _settings(ORIGIN_DISCOVERY_SCANNERS=True, CENSYS_API_TOKEN="tok", **over)


def _run(combined, settings):
    return od.run_origin_discovery_enrichment(combined, settings)["origin_discovery"]


def _one_candidate(**over):
    """The keyless DNS sources propose ORIGIN for every host."""
    return mock.patch.multiple(
        od, _discover_via_subdomains=mock.DEFAULT, _discover_via_email_records=mock.DEFAULT,
        _discover_via_crtsh=mock.DEFAULT, is_non_routable_ip=mock.DEFAULT, **over)


def _wire(mocks, crtsh=(ORIGIN,)):
    mocks["_discover_via_subdomains"].return_value = []
    mocks["_discover_via_email_records"].return_value = []
    mocks["_discover_via_crtsh"].return_value = list(crtsh)
    mocks["is_non_routable_ip"].return_value = False


def _origin_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "origin_discovery"]


class TestTheSearchBudget:
    def test_regression_a_host_the_budget_refused_keeps_its_findings(self):
        with mock.patch.object(od.requests, "post", side_effect=_censys_answer) as post:
            out = _run(_combined(A, B), _censys_settings(ORIGIN_DISCOVERY_MAX_SEARCH_CALLS=1))
        assert post.call_count == 1
        report = cb.coverage_report()
        assert report.keep_hostnames("origin_discovery") == (B,)
        assert "origin_discovery" not in report.degraded_sources
        # Cut for origin discovery alone: every other tool re-checked the host.
        assert report.keep_hostnames("nuclei") == ()
        assert "budget" in out["candidates_meta"][B]["unchecked"]
        assert "unchecked" not in out["candidates_meta"][A]
        assert any("budget" in g["reason"] for g in _origin_gaps())

    def test_regression_a_later_batch_group_keeps_its_findings(self):
        # A Domain batch's groups share one context, and so one budget.
        settings = _censys_settings(ORIGIN_DISCOVERY_MAX_SEARCH_CALLS=1)
        with mock.patch.object(od.requests, "post", side_effect=_censys_answer):
            _run(_combined(A), settings)
            _run(_combined(B), settings)
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (B,)

    def test_a_budget_that_lasts_keeps_no_host(self):
        with mock.patch.object(od.requests, "post", side_effect=_censys_answer):
            _run(_combined(A, B), _censys_settings())
        report = cb.coverage_report()
        assert report.keep_hostnames("origin_discovery") == ()
        assert not report.degraded

    def test_a_refused_urlscan_file_search_keeps_the_host(self):
        settings = _settings(ORIGIN_DISCOVERY_URLSCAN=True, URLSCAN_ENABLED=True,
                             ORIGIN_DISCOVERY_MAX_SEARCH_CALLS=1)
        od._run_ctx(settings).budget.take()
        with mock.patch.object(od, "_reference", return_value=REFERENCE), \
                mock.patch.object(od._UrlscanSource, "own_file", return_value=OWN), \
                mock.patch.object(us, "urlscan_search") as search:
            out = _run(_combined(A), settings)
        search.assert_not_called()
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A,)
        assert "budget" in out["candidates_meta"][A]["unchecked"]

    def test_a_capped_urlscan_file_search_is_not_cached_as_an_answer(self):
        ctx = od._RunCtx(_settings())
        ctx.budget = od._SearchBudget(0)
        src = od._UrlscanSource({}, ctx)
        with mock.patch.object(us, "urlscan_search") as search:
            assert src.file_suspects(A, OWN) == ([], "urlscan_hash")
            assert src.file_suspects(B, OWN) == ([], "urlscan_hash")
        search.assert_not_called()
        assert ctx.misses == 2


class TestTheReferenceFetch:
    def test_regression_a_host_that_did_not_answer_keeps_its_findings(self):
        with _one_candidate() as mocks, \
                mock.patch.object(od, "_reference", return_value=None), \
                mock.patch.object(od, "_confirm_candidate") as confirm:
            _wire(mocks)
            out = _run(_combined(A), _settings(ORIGIN_DISCOVERY_KEYLESS=True))
        confirm.assert_not_called()
        assert out["candidates_meta"][A]["candidates"] == [ORIGIN]
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A,)
        assert "reference" in out["candidates_meta"][A]["errors"]
        assert any("comparison" in g["reason"] for g in _origin_gaps())

    def test_with_urlscan_on_a_silent_host_keeps_its_findings_without_a_candidate(self):
        # The file clue needs the page: a host that did not answer was not asked it.
        settings = _settings(ORIGIN_DISCOVERY_URLSCAN=True, URLSCAN_ENABLED=True)
        with mock.patch.object(od, "_reference", return_value=None), \
                mock.patch.object(us, "urlscan_search") as search:
            out = _run(_combined(A), settings)
        search.assert_not_called()
        assert out["candidates_meta"][A]["candidates"] == []
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A,)

    def test_with_urlscan_on_a_host_that_answered_and_has_no_candidate_keeps_nothing(self):
        settings = _settings(ORIGIN_DISCOVERY_URLSCAN=True, URLSCAN_ENABLED=True)
        with mock.patch.object(od, "_reference", return_value=REFERENCE), \
                mock.patch.object(us, "urlscan_search") as search:
            _run(_combined(A), settings)
        search.assert_not_called()   # the page names no own file
        assert not cb.coverage_report().degraded


class TestFailures:
    def test_regression_a_host_whose_processing_raised_keeps_its_findings(self):
        with mock.patch.object(od, "_process_host", side_effect=RuntimeError("boom")):
            out = _run(_combined(A, B), _settings())
        assert out["candidates_meta"][A]["errors"]["fatal"] == "boom"
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A, B)

    def test_a_candidate_check_that_raised_keeps_the_host(self):
        with _one_candidate() as mocks, \
                mock.patch.object(od, "_reference", return_value=REFERENCE), \
                mock.patch.object(od, "_confirm_candidate", side_effect=OSError("reset")):
            _wire(mocks)
            out = _run(_combined(A), _settings(ORIGIN_DISCOVERY_KEYLESS=True))
        assert out["confirmed"] == []
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A,)

    def test_a_source_that_raised_keeps_the_host(self):
        with _one_candidate() as mocks:
            _wire(mocks)
            mocks["_discover_via_crtsh"].side_effect = RuntimeError("crt.sh down")
            out = _run(_combined(A), _settings(ORIGIN_DISCOVERY_KEYLESS=True))
        assert "crtsh" in out["candidates_meta"][A]["errors"]
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A,)

    def test_a_keyed_search_that_failed_keeps_the_host(self):
        failed = mock.MagicMock(status_code=503, headers={}, json=lambda: {})
        with mock.patch.object(od.requests, "post", return_value=failed):
            _run(_combined(A), _censys_settings())
        assert cb.coverage_report().keep_hostnames("origin_discovery") == (A,)


class TestCheckedHostsStillPrune:
    def test_a_host_checked_with_no_candidate_keeps_nothing(self):
        with _one_candidate() as mocks:
            _wire(mocks, crtsh=())
            out = _run(_combined(A), _settings(ORIGIN_DISCOVERY_KEYLESS=True))
        assert out["candidates_meta"][A]["candidates"] == []
        assert not cb.coverage_report().degraded

    def test_a_candidate_that_is_not_the_origin_keeps_nothing(self):
        with _one_candidate() as mocks, \
                mock.patch.object(od, "_reference", return_value=REFERENCE), \
                mock.patch.object(od, "_confirm_candidate", return_value=None) as confirm:
            _wire(mocks)
            _run(_combined(A), _settings(ORIGIN_DISCOVERY_KEYLESS=True))
        confirm.assert_called_once()
        assert not cb.coverage_report().degraded


class TestTheCoverageNote:
    def test_every_gap_source_is_a_token_the_recon_delta_accepts(self):
        with mock.patch.object(od, "_process_host", side_effect=RuntimeError("boom")):
            _run(_combined(A), _settings())
        with _one_candidate() as mocks, mock.patch.object(od, "_reference", return_value=None):
            _wire(mocks)
            _run(_combined(B), _settings(ORIGIN_DISCOVERY_KEYLESS=True))
        gaps = cb.coverage_report().gaps
        assert gaps
        assert all(re.fullmatch(r"[a-z0-9_]{1,64}", g["source"]) for g in gaps)


# ---------------------------------------------------------------------------
# The prune, end to end over a fake graph
# ---------------------------------------------------------------------------

@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        yield rm


def _stale_origin_finding(host, ip):
    """A `waf_bypass` finding as update_graph_from_origin_discovery stores it."""
    return {"source": "origin_discovery", "type": "waf_bypass", "hostname": host,
            "url": f"https://{ip}", "matched_at": f"https://{ip}", "matched_ip": ip,
            "probe_url": f"https://{ip}:443", "updated_at": "2025-12-01T00:00:00+00:00"}


class FakeGraph:
    """Keeps finding nodes and prunes them the way the Cypher does: a stale
    finding of a pruned source goes unless a host field matches a keep pattern."""

    def __init__(self, findings):
        self.findings = list(findings)

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

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(), **kw):
        from graph_db.mixins.base_mixin import _KEEP_HOST_FIELDS, keep_host_patterns
        patterns = [re.compile(p) for p in keep_host_patterns(keep_hosts)]

        def kept(node):
            return any(p.match(str(node.get(f) or "").lower())
                       for p in patterns for f in _KEEP_HOST_FIELDS)

        self.findings = [n for n in self.findings
                         if n["source"] not in sources or n["updated_at"] >= since or kept(n)]
        return {"pruned": 0, "stale": 0, "revived": 0}


class TestThePrune:
    def test_regression_the_refused_hosts_origin_finding_survives_the_prune(
            self, recon_main, monkeypatch):
        graph = FakeGraph([_stale_origin_finding(A, "203.0.113.10"),
                           _stale_origin_finding(B, "203.0.113.11")])
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        with mock.patch.object(od.requests, "post", side_effect=_censys_answer):
            _run(_combined(A, B), _censys_settings(ORIGIN_DISCOVERY_MAX_SEARCH_CALLS=1))
        recon_main._prune_recon_findings()
        # A was searched and no longer has an origin: gone. B was never asked.
        assert [n["hostname"] for n in graph.findings] == [B]

    def test_a_clean_run_still_prunes_every_host_it_checked(self, recon_main, monkeypatch):
        graph = FakeGraph([_stale_origin_finding(A, "203.0.113.10"),
                           _stale_origin_finding(B, "203.0.113.11")])
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        with mock.patch.object(od.requests, "post", side_effect=_censys_answer):
            _run(_combined(A, B), _censys_settings())
        recon_main._prune_recon_findings()
        assert graph.findings == []

"""Regression (R-47): the npm registry check and what the prune keeps.

A registry check that was skipped (the `npm` breaker open) or got no answer
used to return True, "the package is published". So for a run whose registry
egress was blocked or rate-limited, every package read as published, no
dependency-confusion finding came out, and the end-of-run prune deleted every
earlier one. The breaker trip reached no report either: js_recon's report
scope covered no breaker.

An unanswered check is now "not checked": no finding either way, and the
prune keeps the js_recon findings of the hosts that import the package (the
whole source when no fetched file imports it, since such a finding names no
host). A 404 is still a real answer and still a finding.

Downloads, the registry and Neo4j are fakes; the analyzers run for real.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.js_recon import dependency  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

APP, CDN, OTHER = "app.example.com", "cdn.example.com", "static.example.org"
PKG_IMPORT = "import ui from '@acme/internal-ui';\n"

# Every analyzer off but the dependency check: the run still goes end to end.
SETTINGS = {
    "JS_RECON_MAX_FILES": 500, "JS_RECON_REGEX_PATTERNS": False, "JS_RECON_SOURCE_MAPS": False,
    "JS_RECON_DEPENDENCY_CHECK": True, "JS_RECON_EXTRACT_ENDPOINTS": False,
    "JS_RECON_FRAMEWORK_DETECT": False, "JS_RECON_DOM_SINKS": False, "JS_RECON_DEV_COMMENTS": False,
    "JS_RECON_AI_SDK_DETECTION_ENABLED": False, "JS_RECON_VALIDATE_KEYS": False,
    "JS_RECON_VALIDATE_ENDPOINTS": False, "JS_RECON_TIMEOUT": 30,
    "JS_RECON_CONCURRENCY": 1,
}


@pytest.fixture(autouse=True)
def _fresh_npm_cache():
    """The registry answers are cached process-wide, like the breaker."""
    with dependency._npm_cache_lock:
        dependency._npm_cache.clear()
    yield
    with dependency._npm_cache_lock:
        dependency._npm_cache.clear()


def _resp(status):
    r = mock.MagicMock(status_code=status)
    r.json.return_value = {}
    return r


def _registry(answer):
    """Patch the registry call: a status code, or an exception to raise."""
    if isinstance(answer, int):
        return mock.patch.object(dependency.requests, "get", return_value=_resp(answer))
    return mock.patch.object(dependency.requests, "get", side_effect=answer)


def _combined(*hosts):
    return {"metadata": {}, "http_probe": {"by_url": {f"https://{h}": {"status_code": 200}
                                                       for h in hosts}},
            "resource_enum": {"discovered_urls": []}}


def _files(contents):
    """``{url: content}`` -> the downloader's fake, which returns them in that order."""
    def download(urls, work_dir, max_files, **_kw):
        return [{"url": u, "filepath": "", "content": contents[u], "headers": {},
                 "size": len(contents[u])} for u in urls[:max_files]]
    return download


def _run(contents, settings=None, uploads=()):
    urls = list(contents)
    combined = _combined(*{u.split("/")[2] for u in urls if u.startswith("https://")} or {APP})
    if uploads:
        combined["metadata"]["project_id"] = "p1"
    upload_files = [{"url": u, "filepath": "", "content": c, "headers": {}, "size": len(c)}
                    for u, c in uploads]
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=urls), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_files(contents)), \
            mock.patch.object(js_recon, "_load_uploaded_files", return_value=upload_files):
        return js_recon.run_js_recon(combined, dict(SETTINGS, **(settings or {})))["js_recon"]


class TestTheRegistryCheck:
    def test_regression_an_unanswered_check_is_not_checked(self):
        with _registry(requests.ConnectionError("blocked")):
            assert dependency._check_npm_registry("@acme/internal-ui") is None

    def test_regression_a_check_the_open_breaker_skipped_is_not_checked(self):
        with _registry(requests.ConnectionError("blocked")) as get:
            for i in range(cb.INTERNAL_THRESHOLD):
                dependency._check_npm_registry(f"@acme/p{i}")
            assert dependency._check_npm_registry("@acme/late") is None
        assert get.call_count == cb.INTERNAL_THRESHOLD

    def test_a_404_is_a_real_answer(self):
        with _registry(404):
            assert dependency._check_npm_registry("@acme/internal-ui") is False

    def test_a_200_is_a_real_answer(self):
        with _registry(200):
            assert dependency._check_npm_registry("@acme/internal-ui") is True

    def test_an_unanswered_check_is_not_cached(self):
        with _registry([requests.ConnectionError("x"), _resp(404)]) as get:
            assert dependency._check_npm_registry("@acme/internal-ui") is None
            assert dependency._check_npm_registry("@acme/internal-ui") is False
        assert get.call_count == 2


class TestRegistryOutageKeepsFindings:
    def test_regression_an_outage_keeps_the_importing_hosts_findings(self):
        with _registry(requests.ConnectionError("blocked")):
            out = _run({f"https://{APP}/main.js": PKG_IMPORT,
                        f"https://{OTHER}/clean.js": "var a = 1;\n"})
        assert out["dependencies"] == []
        report = cb.coverage_report()
        assert "js_recon" not in report.degraded_sources
        # Cut for js_recon alone, and only on the host whose file imports it.
        assert report.keep_hostnames("js_recon") == (APP,)
        assert report.keep_hostnames("nuclei") == ()

    def test_every_importing_host_is_kept_not_only_the_first(self):
        with _registry(requests.ConnectionError("blocked")):
            _run({f"https://{CDN}/vendor.js": PKG_IMPORT, f"https://{APP}/main.js": PKG_IMPORT})
        assert cb.coverage_report().keep_hostnames("js_recon") == (APP, CDN)

    def test_regression_the_open_breaker_reaches_the_coverage_record(self):
        imports = "".join(f"import p{i} from '@acme/pkg{i}';\n" for i in range(5))
        with _registry(requests.ConnectionError("blocked")) as get:
            out = _run({f"https://{APP}/main.js": imports})
        assert get.call_count == cb.INTERNAL_THRESHOLD
        npm = [g for g in cb.coverage_report().gaps if g["source"] == "npm"]
        assert len(npm) == 1 and npm[0]["module"] == "js_recon"
        assert npm[0]["skipped"] == 5 - cb.INTERNAL_THRESHOLD
        assert [e["source"] for e in out.get("degraded", [])] == ["npm"]

    def test_a_package_no_fetched_file_imports_keeps_the_whole_source(self):
        # An uploaded file's finding stores no host the prune could match.
        with _registry(requests.ConnectionError("blocked")):
            _run({f"https://{APP}/clean.js": "var a = 1;\n"},
                 uploads=[("upload://bundle.js", PKG_IMPORT)])
        assert "js_recon" in cb.coverage_report().degraded_sources

    def test_every_gap_source_is_a_token_the_recon_delta_accepts(self):
        imports = "".join(f"import p{i} from '@acme/pkg{i}';\n" for i in range(5))
        with _registry(requests.ConnectionError("blocked")):
            _run({f"https://{APP}/main.js": imports}, uploads=[("upload://b.js", PKG_IMPORT)])
        gaps = cb.coverage_report().gaps
        assert {g["source"] for g in gaps} >= {"npm", "js_recon"}
        assert all(re.fullmatch(r"[a-z0-9_]{1,64}", g["source"]) for g in gaps)


class TestARegistryThatAnswers:
    def test_a_404_is_a_finding_as_before_and_degrades_nothing(self):
        with _registry(404):
            out = _run({f"https://{APP}/main.js": PKG_IMPORT})
        [finding] = out["dependencies"]
        assert finding["package_name"] == "@acme/internal-ui"
        assert finding["npm_exists"] is False and finding["severity"] == "critical"
        assert finding["source_urls"] == [f"https://{APP}/main.js"]
        assert not cb.coverage_report().degraded

    def test_a_published_package_is_no_finding_and_degrades_nothing(self):
        with _registry(200):
            out = _run({f"https://{APP}/main.js": PKG_IMPORT})
        assert out["dependencies"] == []
        assert not cb.coverage_report().degraded

    def test_the_check_switched_off_degrades_nothing(self):
        with _registry(requests.ConnectionError("blocked")) as get:
            _run({f"https://{APP}/main.js": PKG_IMPORT},
                 settings={"JS_RECON_DEPENDENCY_CHECK": False})
        assert get.call_count == 0
        assert not cb.coverage_report().degraded


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': ["192.0.2.10"],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['js_recon'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        yield rm


def _prunes(rm, monkeypatch):
    calls = []

    class _Graph:
        def __call__(self, *a, **k):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def verify_connection(self):
            return True

        def backfill_passive_cve_hosts(self, *_a):
            return None

        def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(), **_kw):
            calls.append((list(sources), tuple(keep_hosts)))

    monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
    monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", True)
    monkeypatch.setattr(rm, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
    monkeypatch.setattr(rm, "_COVERAGE_WRITE_FAILED", False)
    rm._prune_recon_findings()
    return calls


class TestThePrune:
    def test_regression_an_outage_no_longer_prunes_the_importing_host(self, recon_main, monkeypatch):
        with _registry(requests.ConnectionError("blocked")):
            _run({f"https://{APP}/main.js": PKG_IMPORT, f"https://{OTHER}/clean.js": "var a=1;\n"})
        calls = _prunes(recon_main, monkeypatch)
        js = [keep for sources, keep in calls if "js_recon" in sources]
        assert js == [(APP,)]
        others = [keep for sources, keep in calls if "js_recon" not in sources]
        assert others and all(keep == () for keep in others)

    def test_a_registry_that_answered_prunes_as_before(self, recon_main, monkeypatch):
        with _registry(200):
            _run({f"https://{APP}/main.js": PKG_IMPORT})
        calls = _prunes(recon_main, monkeypatch)
        assert [keep for sources, keep in calls if "js_recon" in sources] == [()]

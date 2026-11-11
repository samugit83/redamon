"""Regression: the RoE ceiling never reached recon's own requests (R-8, decision D3).

`ROE_GLOBAL_MAX_RPS` only lowered the external tools' rate settings. The
security checks' requests (`_hh_get` / `_hh_post` / `_hh_request`, run by a
10-worker pool) went out unpaced, `check_no_rate_limiting` fired ten
back-to-back POSTs per login URL, GROUP 6 Phase A ran up to seven scanners at
once, each at the full ceiling, and nmap had no rate flag at all.

Now, with a ceiling: every security-check request takes a slot of the
process-wide pacer; the no-rate-limiting check (which cannot test a rate limit
while holding a rate) is skipped and recorded as not checked for its type, so
its earlier findings are kept; Phase A runs its scanners one after another;
nmap gets `--max-rate`. With no ceiling nothing changes.

HTTP, the clock and the graph are fakes. Hosts are under example.test.
"""
from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from graph_db.mixins import base_mixin  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402
from recon.main_recon_modules.nmap_scan import build_nmap_command  # noqa: E402

HOST = "app.example.test"
LOGIN = f"https://{HOST}/account/login"
CEILING_2 = {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2}
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]


@pytest.fixture(autouse=True)
def _fresh_process_pacer():
    request_pacer.reset()
    yield
    request_pacer.reset()


@pytest.fixture
def fake_time(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(request_pacer.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(request_pacer.time, "sleep", lambda s: now.__setitem__(0, now[0] + s))
    return now


def _resp(status=200, text="", headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.content = text.encode()
    r.cookies = None
    r.history = []
    return r


# ---------------------------------------------------------------------------
# Every security-check request takes a slot
# ---------------------------------------------------------------------------

class TestSecurityCheckRequestsArePaced:
    def test_each_requester_takes_a_slot(self, fake_time):
        request_pacer.configure(CEILING_2)
        stamps = []

        def record(name):
            return lambda *a, **k: stamps.append((name, fake_time[0])) or _resp()

        with mock.patch.object(sc.requests, "get", side_effect=record("get")), \
             mock.patch.object(sc.requests, "post", side_effect=record("post")), \
             mock.patch.object(sc.requests, "request", side_effect=record("request")):
            sc._hh_get(LOGIN, timeout=1)
            sc._hh_post(LOGIN, data={}, timeout=1)
            sc._hh_request("PURGE", LOGIN, timeout=1)
            sc._hh_get(LOGIN, timeout=1)

        assert stamps == [("get", 100.0), ("post", 100.5), ("request", 101.0), ("get", 101.5)]

    def test_a_request_that_fails_still_used_its_slot(self, fake_time):
        request_pacer.configure(CEILING_2)
        with mock.patch.object(sc.requests, "get", side_effect=sc.requests.ConnectionError("x")):
            with pytest.raises(sc.requests.ConnectionError):
                sc._hh_get(LOGIN, timeout=1)
        with mock.patch.object(sc.requests, "get", return_value=_resp()):
            sc._hh_get(LOGIN, timeout=1)
        assert fake_time[0] == 100.5

    def test_a_real_check_walks_its_redirects_at_the_ceiling(self, fake_time):
        """check_security_headers through _get_on_host: two on-host hops, two slots."""
        request_pacer.configure(CEILING_2)
        stamps = []
        answers = iter([_resp(301, headers={"Location": f"https://{HOST}/home"}), _resp(200)])

        def get(url, **kwargs):
            stamps.append((url, fake_time[0]))
            return next(answers)

        with mock.patch.object(sc.requests, "get", side_effect=get):
            sc.check_security_headers(HOST, timeout=1)
        assert stamps == [(f"https://{HOST}", 100.0), (f"https://{HOST}/home", 100.5)]

    def test_a_ten_worker_pool_holds_the_ceiling_together(self):
        rps, n = 40, 12
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        stamps, lock = [], threading.Lock()

        def get(url, **kwargs):
            with lock:
                stamps.append(time.monotonic())
            return _resp()

        start = time.monotonic()
        with mock.patch.object(sc.requests, "get", side_effect=get):
            with ThreadPoolExecutor(max_workers=10) as pool:
                list(pool.map(lambda i: sc._hh_get(f"https://h{i}.example.test/", timeout=1), range(n)))
        for k, stamp in enumerate(sorted(stamps)):
            assert stamp - start >= k / rps - 0.005

    @pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
    def test_no_ceiling_never_waits(self, monkeypatch, settings):
        request_pacer.configure(settings)

        def forbidden(*_a):
            raise AssertionError("no ceiling: the pacer must not read the clock or sleep")

        monkeypatch.setattr(request_pacer.time, "sleep", forbidden)
        monkeypatch.setattr(request_pacer.time, "monotonic", forbidden)
        with mock.patch.object(sc.requests, "get", return_value=_resp()) as get:
            for _ in range(20):
                sc._hh_get(LOGIN, timeout=1)
        assert get.call_count == 20


# ---------------------------------------------------------------------------
# check_no_rate_limiting under a ceiling: skipped, not checked, kept
# ---------------------------------------------------------------------------

def _rate_limit_run(enabled=True, hostnames=(HOST,)):
    recon_data = {"http_probe": {"by_url": {LOGIN: {"url": LOGIN}}}}
    get = mock.MagicMock(return_value=_resp(200, "<form>login</form>"))
    post = mock.MagicMock(return_value=_resp(401, "invalid credentials"))
    with mock.patch.object(sc.requests, "get", get), mock.patch.object(sc.requests, "post", post):
        findings = sc.run_rate_limit_checks(list(hostnames), recon_data,
                                            {"no_rate_limiting": enabled}, timeout=1, max_workers=1)
    return findings, get, post


RATE = {"source": "security_check", "type": "no_rate_limiting", "url": LOGIN, "matched_at": LOGIN}
HEADER = {"source": "security_check", "type": "missing_coop",
          "url": f"https://{HOST}", "matched_at": f"https://{HOST}"}


def _hostnames(finding):
    names = set()
    for field in base_mixin._KEEP_HOST_FIELDS:
        value = str(finding.get(field) or "").lower()
        if "://" in value:
            value = value.split("://", 1)[1]
        value = value.split("/", 1)[0]
        if value:
            names.add(cb.hostname_of(value))
    return names


def _prunes(call, finding):
    """What prune_unseen_findings does to one stored finding (the Cypher
    itself is proven in tests/test_positive_prune_graph_live.py)."""
    if finding["source"] not in call["sources"]:
        return False
    if call.get("types") is not None and finding["type"] not in call["types"]:
        return False
    if call.get("exclude_types") is not None and finding["type"] in call["exclude_types"]:
        return False
    names = _hostnames(finding)
    if names & set(call.get("keep_hosts") or ()):
        return False
    if call.get("only_hosts") is not None and not names & set(call["only_hosts"]):
        return False
    return True


class FakeGraph:
    def __init__(self):
        self.prunes = []

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

    def backfill_security_check_domains(self, user_id, project_id):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, **kwargs):
        self.prunes.append({"sources": list(sources), **kwargs})
        return {"pruned": 0, "stale": 0, "revived": 0}


STUB = {
    'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
    'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
    'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery', 'vuln_scan'],
    'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
    'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
    'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
}


@pytest.fixture
def recon_main(monkeypatch):
    with mock.patch('recon.project_settings.get_settings', return_value=dict(STUB)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        rm._RUN_ORGS.clear()
        yield rm
        rm._RUN_ORGS.clear()


@pytest.fixture
def graph(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


def _survivors(recon_main, graph, *findings):
    recon_main._prune_recon_findings()
    assert graph.prunes, "the prune ran"
    return [f for f in findings if not any(_prunes(c, f) for c in graph.prunes)]


class TestNoRateLimitingUnderACeiling:
    def test_the_burst_is_not_sent(self):
        request_pacer.configure(CEILING_2)
        findings, get, post = _rate_limit_run(hostnames=(HOST, "www.example.test"))
        assert findings == []
        get.assert_not_called()
        post.assert_not_called()

    def test_it_is_a_coverage_gap_for_its_type_only(self):
        request_pacer.configure(CEILING_2)
        _rate_limit_run(hostnames=(HOST, "www.example.test"))
        report = cb.coverage_report()
        (gap,) = report.gaps
        assert gap["source"] == "security_check"
        assert "no_rate_limiting" in gap["reason"] and "ceiling" in gap["reason"]
        assert gap["skipped"] == 2
        assert "security_check" not in report.degraded_sources
        assert report.checked_hostnames("security_check", "no_rate_limiting") == ()

    def test_its_earlier_finding_is_kept_while_the_other_types_prune(self, recon_main, graph):
        request_pacer.configure(CEILING_2)  # after recon.main's own configure at import
        _rate_limit_run()
        assert _survivors(recon_main, graph, RATE, HEADER) == [RATE]

    @pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
    def test_with_no_ceiling_it_runs_as_before(self, settings):
        request_pacer.configure(settings)
        findings, get, post = _rate_limit_run()
        assert post.call_count == 10
        assert [f["type"] for f in findings] == ["no_rate_limiting"]
        assert not cb.coverage_report().gaps

    def test_switched_off_it_records_nothing_and_prunes_as_before(self, recon_main, graph):
        request_pacer.configure(CEILING_2)
        findings, get, post = _rate_limit_run(enabled=False)
        assert findings == [] and post.call_count == 0
        assert not cb.coverage_report().gaps
        assert _survivors(recon_main, graph, RATE) == []


# ---------------------------------------------------------------------------
# GROUP 6 Phase A: one scanner at a time under a ceiling
# ---------------------------------------------------------------------------

class _Tools:
    def __init__(self, names, barrier=None):
        self.names = names
        self.events = []
        self.running = 0
        self.peak = 0
        self.lock = threading.Lock()
        self.barrier = barrier

    def tool(self, name):
        def run(snapshot, settings):
            with self.lock:
                self.running += 1
                self.peak = max(self.peak, self.running)
                self.events.append(f"{name}:start")
            if self.barrier is not None:
                self.barrier.wait(timeout=5)
            else:
                time.sleep(0.02)
            with self.lock:
                self.running -= 1
                self.events.append(f"{name}:end")
            return {"ran": name}
        return run

    def dict(self):
        return {name: self.tool(name) for name in self.names}


def _phase_a(rm, monkeypatch, tools, settings):
    monkeypatch.setattr(rm, "save_recon_file", lambda *a, **k: None)
    monkeypatch.setattr(rm, "_graph_update_bg", lambda *a, **k: None)
    combined = {"domain": "example.test", "metadata": {"modules_executed": []}}
    rm._run_phase_a_fan_out(tools.dict(), combined, settings, None)
    return combined


NAMES = ["vuln_scan", "graphql_scan", "vhost_sni", "cache_scan"]


class TestPhaseA:
    def test_a_ceiling_runs_the_scanners_one_after_another(self, recon_main, monkeypatch, capsys):
        tools = _Tools(NAMES)
        combined = _phase_a(recon_main, monkeypatch, tools, CEILING_2)
        assert tools.peak == 1
        assert tools.events == [e for n in NAMES for e in (f"{n}:start", f"{n}:end")]
        assert combined["metadata"]["modules_executed"] == NAMES
        assert all(combined[n] == {"ran": n} for n in NAMES)
        assert combined["metadata"].get("phase_errors", {}) == {}
        assert "[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning" in capsys.readouterr().out

    @pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
    def test_no_ceiling_keeps_them_parallel(self, recon_main, monkeypatch, settings):
        # Every tool waits for all the others: only a parallel fan-out gets past it.
        tools = _Tools(NAMES, barrier=threading.Barrier(len(NAMES)))
        combined = _phase_a(recon_main, monkeypatch, tools, settings)
        assert tools.peak == len(NAMES)
        assert combined["metadata"].get("phase_errors", {}) == {}
        assert sorted(combined["metadata"]["modules_executed"]) == sorted(NAMES)

    def test_a_failed_scanner_does_not_stop_the_next_one(self, recon_main, monkeypatch):
        tools = _Tools(["graphql_scan", "cache_scan"])
        run = tools.dict()

        def boom(*_a):
            raise RuntimeError("graphql exploded")

        monkeypatch.setattr(recon_main, "save_recon_file", lambda *a, **k: None)
        monkeypatch.setattr(recon_main, "_graph_update_bg", lambda *a, **k: None)
        monkeypatch.setattr(recon_main, "_note_phase_error", lambda *a, **k: None)
        combined = {"domain": "example.test", "metadata": {"modules_executed": []}}
        recon_main._run_phase_a_fan_out({"graphql_scan": boom, "cache_scan": run["cache_scan"]},
                                        combined, CEILING_2, None)
        assert combined["metadata"]["phase_errors"] == {"graphql_scan": "graphql exploded"}
        assert combined["cache_scan"] == {"ran": "cache_scan"}


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

class TestNmapMaxRate:
    @pytest.mark.parametrize("rps, flag", [(2, "2"), (0.5, "0.5"), (3.0, "3"), (150, "150")])
    def test_a_ceiling_adds_max_rate(self, rps, flag):
        cmd = build_nmap_command("192.0.2.10", "22,443", "/tmp/o.xml",
                                 {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        assert cmd.count("--max-rate") == 1
        assert cmd[cmd.index("--max-rate") + 1] == flag
        assert cmd[-1] == "192.0.2.10"

    @pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
    def test_no_ceiling_builds_the_same_command_as_before(self, settings):
        cmd = build_nmap_command("192.0.2.10", "22,443", "/tmp/o.xml", dict(settings))
        assert "--max-rate" not in cmd
        assert cmd == ["nmap", "-sV", "--script", "vuln", "-oX", "/tmp/o.xml", "-p", "22,443",
                       "-T3", "--host-timeout", "300s", "192.0.2.10"]


# ---------------------------------------------------------------------------
# GROUP 5's crawlers: one at a time under a ceiling
# ---------------------------------------------------------------------------

CRAWL_SETTINGS = {
    "KATANA_ENABLED": True, "KATANA_TIMEOUT": 30,
    "HAKRAWLER_ENABLED": True, "HAKRAWLER_TIMEOUT": 30, "HAKRAWLER_PARALLELISM": 1,
    "GAU_ENABLED": False, "PARAMSPIDER_ENABLED": False, "KITERUNNER_ENABLED": False,
    "JSLUICE_ENABLED": False, "FFUF_ENABLED": False, "ARJUN_ENABLED": False,
    "ZAP_AJAX_SPIDER_ENABLED": False, "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
}


def _crawl(settings, crawlers):
    import recon.main_recon_modules.resource_enum as re_mod
    pools = []

    class Recording(ThreadPoolExecutor):
        def __init__(self, max_workers=None, *a, **k):
            super().__init__(max_workers, *a, **k)
            self.submitted = []
            pools.append(self)

        def submit(self, fn, *args, **kwargs):
            self.submitted.append(fn)
            return super().submit(fn, *args, **kwargs)

    seeds = ["https://app.example.test"]
    with mock.patch.object(re_mod, "ThreadPoolExecutor", Recording), \
         mock.patch.object(re_mod, "run_katana_crawler", crawlers.tool("katana")), \
         mock.patch.object(re_mod, "run_hakrawler_crawler", crawlers.tool("hakrawler")), \
         mock.patch.object(re_mod, "pull_katana_docker_image", return_value=True), \
         mock.patch.object(re_mod, "pull_hakrawler_docker_image", return_value=True), \
         mock.patch.object(re_mod, "is_docker_installed", return_value=True), \
         mock.patch.object(re_mod, "is_docker_running", return_value=True), \
         mock.patch.object(re_mod, "extract_targets_from_recon",
                           return_value=(set(), {"app.example.test"}, {})), \
         mock.patch.object(re_mod, "build_target_urls", return_value=seeds):
        re_mod.run_resource_enum({"domain": "example.test"}, settings={**CRAWL_SETTINGS, **settings})
    (pool,) = [p for p in pools if crawlers.katana in p.submitted]
    return pool


class _Crawlers(_Tools):
    def tool(self, name):
        def run(*_a, **_k):
            with self.lock:
                self.running += 1
                self.peak = max(self.peak, self.running)
                self.events.append(f"{name}:start")
            if self.barrier is not None:
                self.barrier.wait(timeout=5)
            else:
                time.sleep(0.02)
            with self.lock:
                self.running -= 1
                self.events.append(f"{name}:end")
            return [], {"external_domains": []}
        setattr(self, name, run)
        return run


class TestCrawlers:
    def test_a_ceiling_runs_the_crawlers_one_after_another(self):
        crawlers = _Crawlers(["katana", "hakrawler"])
        pool = _crawl(CEILING_2, crawlers)
        assert pool._max_workers == 1
        assert crawlers.peak == 1
        assert crawlers.events == ["katana:start", "katana:end", "hakrawler:start", "hakrawler:end"]

    @pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
    def test_no_ceiling_keeps_the_pool_of_four(self, settings):
        # Both crawlers wait for each other: only the parallel pool gets past it.
        crawlers = _Crawlers(["katana", "hakrawler"], barrier=threading.Barrier(2))
        pool = _crawl(settings, crawlers)
        assert pool._max_workers == 4
        assert crawlers.peak == 2


# ---------------------------------------------------------------------------
# Partial recon configures the pacer from the settings it loads
# ---------------------------------------------------------------------------

class TestPartialRecon:
    @pytest.mark.parametrize("settings, ceiling", [
        (CEILING_2, 2.0),
        ({"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2}, 0.0),
    ], ids=["ceiling", "roe_off"])
    def test_main_configures_the_pacer_before_any_tool(self, monkeypatch, tmp_path, settings, ceiling):
        import json

        import recon.partial_recon as pr
        config = tmp_path / "partial.json"
        config.write_text(json.dumps({"tool_id": "SecurityChecks", "domains": ["example.test"],
                                      "include_graph_targets": False}))
        monkeypatch.setenv("PARTIAL_RECON_CONFIG", str(config))
        monkeypatch.setenv("USER_ID", "u1")
        monkeypatch.setenv("PROJECT_ID", "p1")
        monkeypatch.setattr("recon.graph_db_preflight.require_graph_db", lambda *_: None)
        monkeypatch.setattr(pr, "get_settings",
                            lambda: {"TARGET_DOMAIN": "example.test", "SUBDOMAIN_LIST": [], **settings})
        seen = []

        def stop_here(tool_id, s):
            # The first step after the settings load: the pacer is set by now.
            seen.append(request_pacer.ceiling())
            return "stopped by the test"

        monkeypatch.setattr(pr, "_stealth_refusal", stop_here)
        with pytest.raises(SystemExit):
            pr.main()
        assert seen == [ceiling]

"""
Unit tests for ZAP Ajax Spider resource enumeration integration.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path


def _load_zap_module():
    module_path = (
        Path(__file__).resolve().parents[1]
        / "helpers"
        / "resource_enum"
        / "zap_ajax_spider_helpers.py"
    )
    spec = importlib.util.spec_from_file_location("zap_ajax_spider_helpers_under_test", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_zap_ajax_header_parsing_and_masking():
    zap = _load_zap_module()

    parsed, invalid = zap.parse_zap_ajax_header_lines([
        "Authorization: Bearer secret-token",
        "Cookie: session=abc; csrftoken=xyz",
        "X-CSRF-Token: token",
        "Not a header",
        "",
    ])

    assert invalid == ["Not a header"]
    assert parsed == [
        {"name": "Authorization", "value": "Bearer secret-token", "line": "Authorization: Bearer secret-token"},
        {"name": "Cookie", "value": "session=abc; csrftoken=xyz", "line": "Cookie: session=abc; csrftoken=xyz"},
        {"name": "X-CSRF-Token", "value": "token", "line": "X-CSRF-Token: token"},
    ]
    assert zap.mask_zap_ajax_header_line("Authorization: Bearer secret-token") == "Authorization: ***"
    assert zap.mask_zap_ajax_header_line("Cookie: session=abc") == "Cookie: ***"


def test_zap_ajax_automation_plan_contains_replacer_spider_and_export_jobs():
    zap = _load_zap_module()
    headers, invalid = zap.parse_zap_ajax_header_lines(["Authorization: Bearer secret-token"])
    assert invalid == []

    plan = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com/dashboard",
        export_file_name="zap_ajax_urls.txt",
        headers=headers,
        exclude_patterns=["/logout"],
        max_duration=7,
        max_crawl_depth=4,
        max_crawl_states=100,
        number_of_browsers=1,
        browser_id="firefox-headless",
        event_wait=750,
        reload_wait=1250,
        click_default_elems=True,
        click_elems_once=True,
        random_inputs=False,
        logout_avoidance=True,
        scope_check="Strict",
    )

    assert 'name: "redamon-zap-ajax"' in plan
    assert "env:" in plan
    assert "  contexts:" in plan
    assert '    - name: "redamon-zap-ajax-context"' in plan
    assert '        - "/logout"' in plan
    assert 'type: "replacer"' in plan
    assert 'matchString: "Authorization"' in plan
    assert 'replacementString: "Bearer secret-token"' in plan
    assert "enabled: true" not in plan
    assert 'type: "spiderAjax"' in plan
    assert 'context: "redamon-zap-ajax-context"' in plan
    assert 'url: "https://app.example.com/dashboard"' in plan
    assert "maxDuration: 7" in plan
    assert "maxCrawlDepth: 4" in plan
    assert "maxCrawlStates: 100" in plan
    assert "inScopeOnly: true" in plan
    assert "logoutAvoidance: true" in plan
    assert 'scopeCheck: "Strict"' in plan
    assert 'type: "export"' in plan
    assert 'type: "url"' in plan
    assert 'type: "urls"' not in plan
    assert 'source: "all"' in plan
    assert 'fileName: "/zap/wrk/zap_ajax_urls.txt"' in plan


def test_zap_ajax_url_filtering_keeps_scope_and_reports_drops():
    zap = _load_zap_module()

    filtered, meta = zap.filter_zap_ajax_urls(
        [
            "https://app.example.com/api/users?id=1",
            "https://app.example.com/api/users?id=1",
            "https://app.example.com/logout",
            "https://app.example.com/static/app.png",
            "https://cdn.example.net/script.js",
            "not-a-url",
        ],
        allowed_hosts={"app.example.com"},
        exclude_patterns=["/logout", r"\.png$"],
        max_urls=10,
    )

    assert filtered == ["https://app.example.com/api/users?id=1"]
    assert meta["duplicates"] == 1
    assert meta["excluded_by_pattern"] == 2
    assert meta["out_of_scope"] == 1
    assert meta["invalid"] == 1


def test_zap_ajax_merge_preserves_raw_resource_enum_source():
    zap = _load_zap_module()

    existing = {
        "https://app.example.com": {
            "base_url": "https://app.example.com",
            "endpoints": {
                "/api/users": {
                    "path": "/api/users",
                    "methods": ["GET"],
                    "parameters": {"query": [], "body": [], "path": []},
                    "parameter_count": {"query": 0, "body": 0, "path": 0, "total": 0},
                    "category": "api",
                    "sources": ["katana"],
                    "sample_urls": ["https://app.example.com/api/users"],
                    "urls_found": 1,
                },
            },
            "summary": {
                "total_endpoints": 1,
                "total_parameters": 0,
                "methods": {"GET": 1},
                "categories": {"api": 1},
            },
        }
    }

    merged, stats = zap.merge_zap_ajax_into_by_base_url(
        [
            "https://app.example.com/api/users?id=1",
            "https://app.example.com/api/projects?sort=asc",
        ],
        existing,
    )

    users = merged["https://app.example.com"]["endpoints"]["/api/users"]
    projects = merged["https://app.example.com"]["endpoints"]["/api/projects"]

    assert stats["zap_ajax_spider_total"] == 2
    assert stats["zap_ajax_spider_new"] == 1
    assert stats["zap_ajax_spider_overlap"] == 1
    assert users["sources"] == ["katana", "zap_ajax_spider"]
    assert users["parameter_count"]["query"] == 1
    assert users["parameters"]["query"][0]["name"] == "id"
    assert projects["sources"] == ["zap_ajax_spider"]
    assert projects["parameters"]["query"][0]["name"] == "sort"


def test_zap_ajax_settings_defaults_and_stealth_override():
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides

    assert DEFAULT_SETTINGS["ZAP_AJAX_SPIDER_ENABLED"] is False
    assert DEFAULT_SETTINGS["ZAP_AJAX_SPIDER_DOCKER_IMAGE"] == "ghcr.io/zaproxy/zaproxy:stable"
    assert DEFAULT_SETTINGS["ZAP_AJAX_SPIDER_SEED_MODE"] == "base_urls"
    assert DEFAULT_SETTINGS["ZAP_AJAX_SPIDER_CUSTOM_HEADERS"] == []

    settings = DEFAULT_SETTINGS.copy()
    settings["STEALTH_MODE"] = True
    settings["ZAP_AJAX_SPIDER_ENABLED"] = True

    overridden = apply_stealth_overrides(settings)

    assert overridden["ZAP_AJAX_SPIDER_ENABLED"] is False


def test_zap_ajax_allocates_non_default_proxy_port():
    zap = _load_zap_module()

    port = zap._allocate_zap_proxy_port()

    assert isinstance(port, int)
    assert 0 < port < 65536
    assert port != 8080


def test_plan_gives_passive_scan_its_own_smaller_budget():
    """The passive-scan wait is a queue drain, not a second crawl."""
    zap = _load_zap_module()

    plan = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com/",
        export_file_name="export.txt",
        max_duration=30,
    )

    spider_budget = plan.split('type: "spiderAjax"')[1].split("maxDuration: ")[1].split("\n")[0]
    passive_budget = plan.split('type: "passiveScan-wait"')[1].split("maxDuration: ")[1].split("\n")[0]

    assert int(spider_budget) == 30
    assert int(passive_budget) == zap.PASSIVE_SCAN_MAX_MINUTES
    assert int(passive_budget) < int(spider_budget)


def test_seed_timeout_covers_spider_plus_passive_pass():
    """A seed's wall clock is spider + passive drain + startup, not spider alone."""
    zap = _load_zap_module()

    timeout = zap._zap_seed_timeout(30)

    assert timeout > 30 * 60
    assert timeout >= (30 + zap.PASSIVE_SCAN_MAX_MINUTES) * 60


def test_reflected_payload_inside_a_path_is_not_a_browser_seed():
    """A catch-all host turns one reflected payload into thousands of seeds."""
    zap = _load_zap_module()

    assert zap._reflected_payload_in_path(
        "http://api.example.com:8080/%5Cu003e%5Cu003cfigcaption%5Cu003eButtercup"
    )
    assert zap._reflected_payload_in_path("http://api.example.com/%3Cscript%3E")
    assert zap._reflected_payload_in_path("http://api.example.com/%253Cscript%253E")
    assert not zap._reflected_payload_in_path("http://api.example.com/api/v1/users")
    assert not zap._reflected_payload_in_path("http://api.example.com/a?b=1")
    # a real path that happens to mention the word is left alone
    assert not zap._reflected_payload_in_path("http://api.example.com/docs/figcaption")
    # a payload in the QUERY is a parameter value; the page is still worth crawling
    assert not zap._reflected_payload_in_path("http://shop.example.com/search?q=%3Cb%3E")


def test_zap_heap_is_sized_from_the_container_not_the_host(monkeypatch):
    """zap.sh sizes -Xmx from MemTotal on cgroup v2, so the heap must be pinned."""
    zap = _load_zap_module()

    monkeypatch.setattr(zap, "_zap_container_bytes", lambda: 3 * 1024 ** 3)
    heap = zap._zap_heap_mb()

    # 3 GiB x 0.9 safety - 1200 MB browser reserve - 300 MB JVM overhead.
    assert heap == 1264, f"3 GiB container -> 1264 MB heap, got {heap}"


def test_zap_heap_leaves_room_for_firefox_in_the_same_cgroup(monkeypatch):
    """The heap plus Firefox must fit the ceiling, or the kernel kills the JVM.
    Firefox headless is several processes (firefox-esr plus its content
    processes), measured at 0.82-1.20 GiB per browser."""
    zap = _load_zap_module()

    for gib in (2, 3, 4, 8):
        ceiling = gib * 1024 ** 3
        heap = zap._zap_heap_mb(ceiling)
        planned = heap + zap._ZAP_JVM_OVERHEAD_MB + zap._ZAP_BROWSER_RESERVE_MB
        assert planned * 1024 ** 2 < ceiling, (
            f"{gib} GiB container: heap {heap} MB + JVM overhead + Firefox reserve "
            f"= {planned} MB, which does not fit"
        )


def test_zap_heap_grows_with_the_container(monkeypatch):
    """A bigger ceiling must buy a bigger heap, not just more headroom."""
    zap = _load_zap_module()

    small = zap._zap_heap_mb(3 * 1024 ** 3)
    large = zap._zap_heap_mb(6 * 1024 ** 3)

    assert large > small, f"6 GiB heap {large} MB must exceed 3 GiB heap {small} MB"


def test_zap_heap_is_clamped_at_both_ends(monkeypatch):
    """Too small a ceiling degrades to the floor instead of an OOM kill."""
    zap = _load_zap_module()

    assert zap._zap_heap_mb(512 * 1024 ** 2) == zap._ZAP_HEAP_MIN_MB
    assert zap._zap_heap_mb(64 * 1024 ** 3) == zap._ZAP_HEAP_MAX_MB


def test_zap_container_falls_back_to_2_gib_when_the_governor_cannot_load(monkeypatch):
    import sys

    zap = _load_zap_module()
    # A None entry in sys.modules makes the import raise ImportError; the package
    # attribute must go too, or `from graph_db import resource_governor` finds it.
    monkeypatch.setitem(sys.modules, "graph_db.resource_governor", None)
    monkeypatch.setitem(sys.modules, "resource_governor", None)
    if "graph_db" in sys.modules:
        monkeypatch.delattr(sys.modules["graph_db"], "resource_governor", raising=False)

    assert zap._zap_container_bytes() == zap._DEFAULT_ZAP_CONTAINER_BYTES == 2 * 1024 ** 3
    assert zap._zap_heap_mb(zap._DEFAULT_ZAP_CONTAINER_BYTES) == zap._ZAP_HEAP_MIN_MB


def test_zap_container_passes_the_ceiling_it_sized_the_heap_from(monkeypatch):
    """--memory and -Xmx come from one number, so the heap is sized for the
    limit the container is actually given."""
    zap = _load_zap_module()
    captured = {}

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured.setdefault("cmds", []).append(list(cmd))
        return Result()

    monkeypatch.setattr(zap.subprocess, "run", fake_run)
    monkeypatch.setattr(zap, "_zap_container_bytes", lambda: 3 * 1024 ** 3)

    zap.run_zap_ajax_spider(
        ["https://example.com/"],          # target_urls
        "ghcr.io/zaproxy/zaproxy:stable",  # docker_image
        ["example.com"],                   # allowed_hosts
        [],                                # custom_headers
        [],                                # exclude_patterns
        1000,                              # max_urls
        10,                                # max_duration
        5,                                 # max_crawl_depth
        0,                                 # max_crawl_states
        1,                                 # number_of_browsers
        "firefox-headless",                # browser_id
        1000,                              # event_wait
        1000,                              # reload_wait
        True,                              # click_default_elems
        True,                              # click_elems_once
        False,                             # random_inputs
        True,                              # logout_avoidance
        "Strict",                          # scope_check
    )

    cmds = captured.get("cmds") or []
    assert cmds, "the crawl must spawn a container"
    cmd = cmds[0]

    assert "--memory" in cmd, "the container must be spawned with an explicit ceiling"
    mem = str(cmd[cmd.index("--memory") + 1])
    assert mem == str(3 * 1024 ** 3), (
        f"--memory {mem} must be the ceiling the heap was sized from"
    )

    xmx = next((a for a in cmd if a.startswith("-Xmx")), "")
    assert xmx == f"-Xmx{zap._zap_heap_mb(3 * 1024 ** 3)}m", (
        f"-Xmx {xmx} must match the ceiling"
    )


# --- run_zap_ajax_spider end to end, with docker replaced by a recorder -------------

def _run_spider(zap, seeds, **overrides):
    args = dict(
        target_urls=seeds,
        docker_image="ghcr.io/zaproxy/zaproxy:stable",
        allowed_hosts=[],
        custom_headers=[],
        exclude_patterns=[],
        max_urls=1000,
        max_duration=10,
        max_crawl_depth=5,
        max_crawl_states=0,
        number_of_browsers=1,
        browser_id="firefox-headless",
        event_wait=1000,
        reload_wait=1000,
        click_default_elems=True,
        click_elems_once=True,
        random_inputs=False,
        logout_avoidance=True,
        scope_check="Strict",
        parallelism=1,
    )
    args.update(overrides)
    return zap.run_zap_ajax_spider(**args)


class _DockerRecorder:
    """Stands in for subprocess.run: records every docker call, and can make
    `docker run` time out the way a stuck crawl does."""

    def __init__(self, run_times_out=False):
        self.calls = []
        self.run_times_out = run_times_out

    def __call__(self, cmd, **kwargs):
        import subprocess

        self.calls.append((list(cmd), kwargs))
        if cmd[:2] == ["docker", "run"] and self.run_times_out:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def runs(self):
        return [(cmd, kw) for cmd, kw in self.calls if cmd[:2] == ["docker", "run"]]


def _plans_built(monkeypatch, zap):
    """Record the seed and browser count of every automation plan the run builds."""
    built = []
    real = zap.build_zap_ajax_automation_plan

    def spy(**kwargs):
        built.append({"seed": kwargs["seed_url"], "browsers": kwargs["number_of_browsers"]})
        return real(**kwargs)

    monkeypatch.setattr(zap, "build_zap_ajax_automation_plan", spy)
    return built


def test_a_timed_out_seed_is_killed_by_the_name_it_was_started_with(monkeypatch):
    """subprocess.run's timeout kills only the docker CLI; the container must be
    killed by name or it keeps crawling while the next seed starts."""
    zap = _load_zap_module()
    docker = _DockerRecorder(run_times_out=True)
    monkeypatch.setattr(zap.subprocess, "run", docker)

    _, meta = _run_spider(zap, ["https://app.example.com/"])

    (run_cmd, _), = docker.runs()
    name = run_cmd[run_cmd.index("--name") + 1]
    assert name.startswith("redamon-zap-ajax-")
    kills = [cmd for cmd, _ in docker.calls if cmd[:2] == ["docker", "kill"]]
    assert kills == [["docker", "kill", name]]
    assert meta["seeds_failed"] == 1
    assert meta["errors"][0]["type"] == "timeout"


def test_a_seed_that_finishes_is_not_killed(monkeypatch):
    zap = _load_zap_module()
    docker = _DockerRecorder()
    monkeypatch.setattr(zap.subprocess, "run", docker)

    _run_spider(zap, ["https://app.example.com/"])

    assert not [cmd for cmd, _ in docker.calls if cmd[:2] == ["docker", "kill"]]


def test_each_seed_runs_with_a_timeout_that_covers_its_whole_plan(monkeypatch):
    zap = _load_zap_module()
    docker = _DockerRecorder()
    monkeypatch.setattr(zap.subprocess, "run", docker)

    _run_spider(zap, ["https://app.example.com/"], max_duration=10)

    (_, kwargs), = docker.runs()
    plan = zap.build_zap_ajax_automation_plan("https://app.example.com/", "e.txt", max_duration=10)
    plan_minutes = sum(int(m) for m in re.findall(r"maxDuration: (\d+)", plan))
    assert kwargs["timeout"] == zap._zap_seed_timeout(10)
    assert kwargs["timeout"] >= plan_minutes * 60


def test_the_seed_cap_gives_every_host_its_base_url_before_any_second_seed(monkeypatch):
    zap = _load_zap_module()
    monkeypatch.setattr(zap.subprocess, "run", _DockerRecorder())
    built = _plans_built(monkeypatch, zap)
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    # sorted like the callers sort: each base URL comes before its own endpoints
    seeds = sorted(
        [f"https://{h}" for h in hosts]
        + [f"https://{h}/p{i:03d}" for h in hosts for i in range(200)]
    )

    _, meta = _run_spider(zap, seeds, max_seeds=10)

    crawled = [b["seed"] for b in built]
    assert len(crawled) == 10
    assert {f"https://{h}" for h in hosts} <= set(crawled)
    assert meta["seeds_dropped_by_cap"] == len(seeds) - 10
    assert meta["hosts_dropped_by_cap"] == 0
    assert meta["seed_cap"] == 10


def test_hosts_the_cap_leaves_out_are_recorded_with_the_cap_as_the_reason(monkeypatch):
    """A host the cap left uncrawled was not re-checked by ZAP, so the run must
    say so (and the prune must keep its endpoints) instead of treating it as
    clean, and must not call it unreachable: the other crawlers reached it."""
    from recon.helpers import circuit_breaker

    zap = _load_zap_module()
    monkeypatch.setattr(zap.subprocess, "run", _DockerRecorder())
    notes = []
    monkeypatch.setattr(circuit_breaker, "note_degraded", lambda module, **kw: notes.append((module, kw)))
    seeds = [f"https://h{i:02d}.example.com/" for i in range(12)]

    _, meta = _run_spider(zap, seeds, max_seeds=10)

    assert meta["hosts_dropped_by_cap"] == 2
    assert notes == [("resource_enum", {
        "hosts": ["h10.example.com:443", "h11.example.com:443"],
        "host_source": "resource_enum",
        "source_only_hosts": True,
        "reason": "ZAP seed cap (10)",
    })]


def test_a_zero_or_invalid_seed_cap_falls_back_to_the_default_not_to_no_cap(monkeypatch):
    zap = _load_zap_module()
    seeds = [f"https://app.example.com/p{i}" for i in range(zap.ZAP_MAX_SEEDS_DEFAULT + 5)]

    for bad in (0, -1, None, "abc"):
        docker = _DockerRecorder()
        monkeypatch.setattr(zap.subprocess, "run", docker)
        _, meta = _run_spider(zap, seeds, max_seeds=bad)
        assert len(docker.runs()) == zap.ZAP_MAX_SEEDS_DEFAULT, bad
        assert meta["seed_cap"] == zap.ZAP_MAX_SEEDS_DEFAULT


def test_a_reflected_payload_in_the_path_never_reaches_a_container(monkeypatch):
    zap = _load_zap_module()
    monkeypatch.setattr(zap.subprocess, "run", _DockerRecorder())
    built = _plans_built(monkeypatch, zap)
    seeds = [
        "https://app.example.com/",
        "https://app.example.com/static/%3Cscript%3Ealert(1)%3C/script%3E",
        "https://app.example.com/search?q=%3Cb%3E",
    ]

    _, meta = _run_spider(zap, seeds)

    assert [b["seed"] for b in built] == [
        "https://app.example.com/",
        "https://app.example.com/search?q=%3Cb%3E",
    ]
    assert meta["reflected_path_seed_urls"] == 1
    assert {"reason": "reflected_payload_in_path"}.items() <= meta["dropped_seed_urls"][0].items()


def test_browsers_that_do_not_fit_the_container_are_reduced(monkeypatch):
    """Each browser is a separate Firefox: four of them plus a JVM cannot fit a
    3 GiB container, and asking for them anyway OOM-kills every seed."""
    zap = _load_zap_module()
    monkeypatch.setattr(zap.subprocess, "run", _DockerRecorder())
    monkeypatch.setattr(zap, "_zap_container_bytes", lambda: 3 * 1024 ** 3)
    built = _plans_built(monkeypatch, zap)

    _, meta = _run_spider(zap, ["https://app.example.com/"], number_of_browsers=4)

    assert built[0]["browsers"] == 1
    assert meta["browsers_used"] == 1
    assert meta["browsers_requested"] == 4


def test_heap_plus_every_browser_fits_the_container_at_any_size():
    zap = _load_zap_module()

    for gib in (3, 4, 6, 8, 16):
        ceiling = gib * 1024 ** 3
        for requested in (1, 2, 4, 10):
            browsers = zap._zap_browsers_that_fit(ceiling, requested)
            heap = zap._zap_heap_mb(ceiling, browsers)
            planned_mb = heap + zap._ZAP_JVM_OVERHEAD_MB + browsers * zap._ZAP_BROWSER_RESERVE_MB
            assert 1 <= browsers <= requested
            assert planned_mb * 1024 ** 2 < ceiling, (gib, requested, browsers, heap)
    # a big container keeps what was asked for
    assert zap._zap_browsers_that_fit(8 * 1024 ** 3, 4) == 4

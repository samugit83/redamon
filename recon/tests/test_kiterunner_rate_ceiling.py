"""Kiterunner under an RoE ceiling never runs past it (S-7).

run_kiterunner_discovery turns the (RoE-capped) KITERUNNER_RATE_LIMIT into
`--delay <1000/rate>ms` and passes KITERUNNER_CONNECTIONS / KITERUNNER_THREADS
(defaults 100 and 50, neither RoE-capped) as `-x` / `-j`. In kiterunner v1.0.2,
the release RedAmon downloads, `--delay` reaches kiterunner.Config.Delay
(pkg/kiterunner/config.go) and nothing ever reads it: no Sleep, ticker or
limiter exists in pkg/ (checked on the v1.0.2 tag). `-x` is connections per
host and `-j` hosts at once, so even `-x 1 -j 1` sends back to back as fast as
the target answers. A 3 rps engagement got up to 100 connections x 50 hosts at
full speed.

Nothing bounds kr's rate, so under a ceiling (the process-wide request pacer,
decision D3) Kiterunner does not run, and the run records a coverage gap for it:
not checked, never switched off. With no ceiling the command is unchanged.

kr itself is not run (run_with_heartbeat mocked); the binary and wordlist are
empty temp files.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

import pytest

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.helpers.resource_enum import kiterunner_helpers as kh  # noqa: E402

TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")
CEILING = {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 3}
TARGETS = ["https://app.example.test", "https://api.example.test", "not-a-url"]


@pytest.fixture(autouse=True)
def _pacer():
    request_pacer.reset()
    yield
    request_pacer.reset()


@pytest.fixture
def kr_files(tmp_path):
    binary = tmp_path / "kr"
    binary.write_text("")
    wordlist = tmp_path / "routes.kite"
    wordlist.write_text("")
    return str(binary), str(wordlist)


def _flag(cmd, name):
    return int(cmd[cmd.index(name) + 1]) if name in cmd else None


def _discover(kr_files, targets=TARGETS):
    launched = []

    def fake_run(cmd, **_kw):
        launched.append(list(cmd))
        return mock.MagicMock(returncode=0, stdout="", stderr="")

    binary, wordlist = kr_files
    with mock.patch.object(kh, "run_with_heartbeat", side_effect=fake_run):
        found = kh.run_kiterunner_discovery(
            targets, binary, wordlist, "routes",
            rate_limit=3, connections=100, timeout=10, scan_timeout=60, threads=50,
            ignore_status=[], match_status=[200], min_content_length=0, headers=[])
    return found, launched


def _kiterunner_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "kiterunner"]


def test_a_capped_run_is_not_left_to_a_delay_kr_ignores(kr_files):
    request_pacer.configure(CEILING)
    found, launched = _discover(kr_files)

    for cmd in launched:
        concurrency = (_flag(cmd, "-x") or 3) * (_flag(cmd, "-j") or 50)
        assert concurrency <= 1, (
            f"kr runs {concurrency} concurrent requests under a 3 rps ceiling; "
            f"its --delay is never applied: {cmd}")
    assert launched == [], "nothing bounds kr's request rate, so it must not run under a ceiling"
    assert found == []


def test_the_skip_is_a_coverage_gap_not_a_switch_off(kr_files, capsys):
    request_pacer.configure(CEILING)
    _discover(kr_files)

    (gap,) = _kiterunner_gaps()
    assert TOKEN.match(gap["source"])
    assert gap["module"] == "resource_enum"
    assert "3 rps RoE ceiling" in gap["reason"]
    assert gap["skipped"] == 2          # the two http(s) targets kr would have read
    report = cb.coverage_report()
    # An entry, not a source cut: Kiterunner writes no findings, and degrading
    # resource_enum on every capped run would keep its stale findings for good.
    assert report.degraded_sources == frozenset() and report.skipped_hosts == ()
    assert "[-][Kiterunner] Not run" in capsys.readouterr().out


def test_with_no_ceiling_the_command_is_unchanged(kr_files):
    found, launched = _discover(kr_files)

    (cmd,) = launched
    assert (_flag(cmd, "-x"), _flag(cmd, "-j")) == (100, 50)
    assert cmd[cmd.index("--delay") + 1] == "333ms"
    assert found == [] and _kiterunner_gaps() == []


def test_a_rate_with_roe_off_is_no_ceiling(kr_files):
    request_pacer.configure({"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 3})
    _, launched = _discover(kr_files)
    assert len(launched) == 1 and _kiterunner_gaps() == []


def test_the_full_pipeline_never_launches_kr_under_the_ceiling(kr_files):
    """The real run_resource_enum and Kiterunner wrapper, as main.py configures the pacer."""
    from recon.main_recon_modules import resource_enum

    settings = {
        **CEILING, "TARGET_DOMAIN": "example.test",
        "KATANA_ENABLED": False, "HAKRAWLER_ENABLED": False, "GAU_ENABLED": False,
        "PARAMSPIDER_ENABLED": False, "JSLUICE_ENABLED": False, "FFUF_ENABLED": False,
        "ARJUN_ENABLED": False, "ZAP_AJAX_SPIDER_ENABLED": False, "OPENAPI_ENABLED": False,
        "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
        "KITERUNNER_ENABLED": True, "KITERUNNER_WORDLISTS": ["a", "b"],
        "KITERUNNER_CONNECTIONS": 100, "KITERUNNER_THREADS": 50, "KITERUNNER_RATE_LIMIT": 3,
    }
    request_pacer.configure(settings)
    launched = []
    with mock.patch.object(resource_enum, "is_docker_installed", return_value=True), \
         mock.patch.object(resource_enum, "is_docker_running", return_value=True), \
         mock.patch.object(resource_enum, "extract_targets_from_recon",
                           return_value=(set(), {"app.example.test"}, {})), \
         mock.patch.object(resource_enum, "build_target_urls", return_value=["https://app.example.test"]), \
         mock.patch.object(resource_enum, "ensure_kiterunner_binary", return_value=kr_files), \
         mock.patch.object(kh, "run_with_heartbeat",
                           side_effect=lambda cmd, **_kw: launched.append(cmd)):
        out = resource_enum.run_resource_enum(
            {"domain": "example.test", "subdomains": ["app.example.test"]}, settings=settings)

    assert launched == []
    sources = {s for base in out["resource_enum"]["by_base_url"].values()
               for endpoint in base["endpoints"].values() for s in endpoint.get("sources") or []}
    assert "kiterunner" not in sources
    (gap,) = _kiterunner_gaps()
    assert gap["skipped"] == 2          # one target, two wordlists: one entry each, merged


@pytest.mark.parametrize("settings, runs", [(CEILING, 0), ({}, 1)], ids=["ceiling", "no_ceiling"])
def test_a_partial_kiterunner_run_follows_the_ceiling(kr_files, settings, runs):
    """The real partial module, after what partial_recon.main does first: configure
    the pacer from the settings it loaded (pinned in test_regression_roe_ceiling_in_process)."""
    from recon.partial_recon_modules import parameter_discovery

    config = {
        "_settings": {**settings, "KITERUNNER_WORDLISTS": ["a"], "KITERUNNER_DETECT_METHODS": False,
                      "KITERUNNER_CONNECTIONS": 100, "KITERUNNER_THREADS": 50},
        "domain": "example.test", "domains": ["example.test"],
        "include_graph_targets": False,
        "user_targets": {"urls": ["https://app.example.test"], "url_attach_to": "https://example.test"},
    }
    request_pacer.configure(config["_settings"])
    launched = []
    graph = mock.MagicMock()
    graph.return_value.__enter__.return_value.verify_connection.return_value = False
    with mock.patch("recon.helpers.resource_enum.ensure_kiterunner_binary", return_value=kr_files), \
         mock.patch.object(kh, "run_with_heartbeat",
                           side_effect=lambda cmd, **_kw: launched.append(cmd)
                           or mock.MagicMock(returncode=0, stdout="", stderr="")), \
         mock.patch("graph_db.Neo4jClient", graph):
        parameter_discovery.run_kiterunner(config)

    assert len(launched) == runs
    assert len(_kiterunner_gaps()) == 1 - runs

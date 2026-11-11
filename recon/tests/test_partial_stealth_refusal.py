"""Partial recon in a stealth project: a tool stealth switches off is refused (R-10).

Each partial module forces its own tool's switch on after get_settings()
applied the stealth profile, so without a refusal a partial FFuf ran at
FFUF_RATE 0 (unlimited) with 40 threads and a partial Masscan at 1000 pps on a
project the operator had put in stealth mode. partial_recon.main now refuses a
tool whose switch the registry's stealth profile sets to false, before any
target is read; a tool stealth only throttles (Katana, GAU, ParamSpider) runs
with the stealth values.

The settings are the real DEFAULT_SETTINGS passed through the real
apply_stealth_overrides, so the refused set follows the registry. Fixture roots
are reserved names only (alpha.test).
"""
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides  # noqa: E402
from recon_settings.loader import by_runtime_key, runtime_only, stealth_profile  # noqa: E402

PARTIAL_RECON = PROJECT_ROOT / "recon" / "partial_recon.py"
PARTIAL_MODULES = PROJECT_ROOT / "recon" / "partial_recon_modules"
TYPED_URL = "http://www.alpha.test/"


def _dispatched_tools() -> set:
    return set(re.findall(r'tool_id == "([A-Za-z]+)"', PARTIAL_RECON.read_text()))


def _settings(stealth: bool) -> dict:
    base = dict(DEFAULT_SETTINGS, TARGET_DOMAIN="alpha.test", SUBDOMAIN_LIST=[],
                STEALTH_MODE=stealth)
    return apply_stealth_overrides(base)


class _NoGraph:
    """graph_db.Neo4jClient with the database down: the writers skip."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return False


@pytest.fixture
def pr(monkeypatch):
    import recon.partial_recon as module
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", "p1")
    monkeypatch.setattr("recon.graph_db_preflight.require_graph_db", lambda *_: None)
    monkeypatch.setattr(module, "_cleanup_orphan_user_inputs", lambda *_: 0)
    monkeypatch.setattr(module, "_legacy_graph_refusal", lambda settings, uid, pid: None)
    monkeypatch.setattr(module, "_apply_node_filters", lambda started_at: None)
    monkeypatch.setattr("graph_db.Neo4jClient", _NoGraph)
    return module


def _run_main(pr, monkeypatch, config, settings):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(config, f)
    monkeypatch.setenv("PARTIAL_RECON_CONFIG", f.name)
    monkeypatch.setattr(pr, "get_settings", lambda: dict(settings))
    try:
        pr.main()
        return 0
    except SystemExit as e:
        return e.code
    finally:
        os.unlink(f.name)


def _typed_url_config(tool_id: str) -> dict:
    return {"tool_id": tool_id, "domains": ["alpha.test"], "include_graph_targets": False,
            "user_targets": {"urls": [TYPED_URL]}}


class TestFfufInStealth:
    def _run(self, pr, monkeypatch, stealth):
        calls = []

        def _discovery(*args, **kwargs):
            calls.append(args)
            return [], {}

        monkeypatch.setattr("recon.helpers.resource_enum.run_ffuf_discovery", _discovery)
        monkeypatch.setattr("recon.helpers.resource_enum.pull_ffuf_binary_check", lambda: True)
        code = _run_main(pr, monkeypatch, _typed_url_config("Ffuf"), _settings(stealth))
        return code, calls

    def test_stealth_refuses_partial_ffuf_before_any_command(self, pr, monkeypatch, capsys):
        code, calls = self._run(pr, monkeypatch, stealth=True)
        out = capsys.readouterr().out
        assert calls == [], "the ffuf command was built and run in stealth mode"
        assert code == 1
        assert "Ffuf is off in stealth mode" in out
        assert "Run report: Ffuf" in out and "Roots scanned (0): none" in out

    def test_without_stealth_partial_ffuf_runs_as_today(self, pr, monkeypatch, capsys):
        code, calls = self._run(pr, monkeypatch, stealth=False)
        assert code == 0
        assert len(calls) == 1
        target_urls, _wordlist, threads, rate = calls[0][:4]
        assert target_urls == [TYPED_URL]
        assert (threads, rate) == (DEFAULT_SETTINGS["FFUF_THREADS"], DEFAULT_SETTINGS["FFUF_RATE"])
        assert "off in stealth mode" not in capsys.readouterr().out


class TestThrottledToolsStillRun:
    def test_partial_katana_runs_with_the_stealth_rate(self, pr, monkeypatch):
        calls = []

        def _crawler(*args, **kwargs):
            calls.append(args)
            return [], {"external_domains": []}

        monkeypatch.setattr("recon.helpers.resource_enum.run_katana_crawler", _crawler)
        monkeypatch.setattr("recon.helpers.resource_enum.pull_katana_docker_image", lambda *_: True)
        settings = _settings(stealth=True)
        code = _run_main(pr, monkeypatch, _typed_url_config("Katana"), settings)
        assert code == 0
        assert len(calls) == 1
        target_urls, _image, depth, max_urls, rate = calls[0][:5]
        assert target_urls == [TYPED_URL]
        profile = stealth_profile()
        assert rate == profile["KATANA_RATE_LIMIT"]["set"] < DEFAULT_SETTINGS["KATANA_RATE_LIMIT"]
        assert depth == profile["KATANA_DEPTH"]["set"]
        assert max_urls == profile["KATANA_MAX_URLS"]["set"]


def _stealth_off_keys() -> set:
    return {k for k, rule in stealth_profile().items() if rule.get("set", None) is False}


class TestEveryStealthOffToolIsRefused:
    """Dispatch-level: whatever tool the stealth profile switches off never runs."""

    # The tools the audit found forcing their switch back on (R-10), plus
    # OpenAPI, which refused inside its module already.
    AUDITED = {"Masscan", "Hakrawler", "ZapAjaxSpider", "Ffuf", "Kiterunner", "VhostSni",
               "WebCachePoison", "RouteExposure", "OpenAPI"}
    # Stealth sets these tools' switch to true or only lowers their rates.
    THROTTLED = {"Katana", "Gau", "ParamSpider", "GraphqlScan", "Naabu", "Nmap", "Httpx",
                 "Nuclei", "SecurityChecks", "SubdomainDiscovery"}

    def _run(self, pr, monkeypatch, tool_id, stealth=True):
        dispatched = []
        monkeypatch.setattr(pr, "_dispatch", lambda t, cfg: dispatched.append(t))
        code = _run_main(pr, monkeypatch, {"tool_id": tool_id, "domains": ["alpha.test"]},
                         _settings(stealth))
        return code, dispatched

    @pytest.mark.parametrize("tool_id", sorted(AUDITED))
    def test_an_audited_tool_is_refused(self, pr, monkeypatch, capsys, tool_id):
        code, dispatched = self._run(pr, monkeypatch, tool_id)
        assert dispatched == [] and code == 1
        assert f"{tool_id} is off in stealth mode" in capsys.readouterr().out

    @pytest.mark.parametrize("tool_id", sorted(THROTTLED))
    def test_a_throttled_tool_still_runs(self, pr, monkeypatch, tool_id):
        code, dispatched = self._run(pr, monkeypatch, tool_id)
        assert dispatched == [tool_id] and code == 0

    @pytest.mark.parametrize("tool_id", sorted(AUDITED))
    def test_without_stealth_nothing_is_refused(self, pr, monkeypatch, tool_id):
        code, dispatched = self._run(pr, monkeypatch, tool_id, stealth=False)
        assert dispatched == [tool_id] and code == 0

    def test_the_refused_set_is_exactly_the_registrys_stealth_off_switches(self, pr):
        off = _stealth_off_keys()
        refused = {t for t in _dispatched_tools()
                   if pr._stealth_refusal(t, _settings(stealth=True))}
        expected = {t for t, keys in pr.PARTIAL_TOOL_SWITCHES.items() if set(keys) & off}
        assert refused == expected
        assert self.AUDITED <= refused
        assert not (self.THROTTLED & refused)

    def test_a_tool_with_no_switch_row_is_refused_in_stealth(self, pr):
        assert pr._stealth_refusal("NotATool", _settings(stealth=True))
        assert pr._stealth_refusal("NotATool", _settings(stealth=False)) is None


class TestTheSwitchMapStaysComplete:
    """PARTIAL_TOOL_SWITCHES names which switch each partial tool turns on; the
    stealth decision itself comes from the registry. These pin the map to the
    code, so a new partial tool or a new forced switch cannot skip the check."""

    def test_every_dispatched_tool_has_a_row(self, pr):
        assert _dispatched_tools() <= set(pr.PARTIAL_TOOL_SWITCHES)

    def test_every_switch_is_a_registry_key(self, pr):
        known = set(by_runtime_key()) | set(runtime_only())
        for tool_id, keys in pr.PARTIAL_TOOL_SWITCHES.items():
            assert keys, tool_id
            assert set(keys) <= known, tool_id

    def test_every_switch_a_partial_module_forces_on_is_mapped(self, pr):
        forced = set()
        pattern = re.compile(r"""['"]([A-Z0-9_]+_ENABLED)['"]\]?\s*(?:=|:)\s*True""")
        for path in PARTIAL_MODULES.glob("*.py"):
            forced |= set(pattern.findall(path.read_text()))
        mapped = {k for keys in pr.PARTIAL_TOOL_SWITCHES.values() for k in keys}
        assert forced, "the scan for forced switches matched nothing"
        assert forced <= mapped, sorted(forced - mapped)

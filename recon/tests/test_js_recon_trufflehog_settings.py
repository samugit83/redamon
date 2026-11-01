"""The two TruffleHog settings and how the others shape a run.

`JS_RECON_TRUFFLEHOG_ENABLED` off means no TruffleHog code runs at all. Key
validation (`JS_RECON_VALIDATE_KEYS`, which stealth forces off) decides
whether the sidecar verifies keys, and so whether it gets a network. The
result filter (`JS_RECON_TRUFFLEHOG_RESULTS`) applies only when keys are
verified; an empty or unreadable list means all three classes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon import project_settings as ps  # noqa: E402
from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

FILES = [{"url": "https://app.example.com/main.js", "content": "var a = 1;\n", "size": 11}]
BASE = {"JS_RECON_TIMEOUT": 60, "JS_RECON_SOURCE_MAPS": False, "JS_RECON_DEPENDENCY_CHECK": False}
ALL = set(th.RESULT_CLASSES)


def _analyse(settings):
    with mock.patch.object(js_recon.trufflehog_bridge, "run", return_value=th.ThRun("ran")) as run:
        js_recon._run_analysis(list(FILES), dict(BASE, **settings))
    return run


def test_the_defaults():
    # On for new projects since the plan's Phase 2 (step 2.6); a stored value wins.
    assert ps.DEFAULT_SETTINGS["JS_RECON_TRUFFLEHOG_ENABLED"] is True
    assert ps.DEFAULT_SETTINGS["JS_RECON_TRUFFLEHOG_RESULTS"] == ["verified", "unknown", "unverified"]


def test_disabled_calls_no_bridge_function():
    with mock.patch.object(js_recon, "trufflehog_bridge") as bridge:
        results = js_recon._run_analysis(list(FILES), dict(BASE, JS_RECON_TRUFFLEHOG_ENABLED=False))
    assert not bridge.method_calls
    assert "_trufflehog" not in results


def test_enabled_runs_on_the_analysed_files_with_verification_from_validate_keys():
    run = _analyse({"JS_RECON_TRUFFLEHOG_ENABLED": True, "JS_RECON_VALIDATE_KEYS": True,
                    "JS_RECON_CONCURRENCY": 12, "JS_RECON_VALIDATION_TIMEOUT": 7})
    kwargs = run.call_args.kwargs
    assert [f["url"] for f in run.call_args.args[0]] == [FILES[0]["url"]]
    assert (kwargs["verify"], kwargs["concurrency"], kwargs["validation_timeout"]) == (True, 12, 7)
    assert 15 <= kwargs["budget_s"] <= js_recon._TRUFFLEHOG_MAX_BUDGET_S


def test_stealth_turns_verification_off():
    settings = ps.apply_stealth_overrides({**ps.DEFAULT_SETTINGS, "STEALTH_MODE": True,
                                           "JS_RECON_TRUFFLEHOG_ENABLED": True})
    assert settings["JS_RECON_VALIDATE_KEYS"] is False
    run = _analyse({"JS_RECON_TRUFFLEHOG_ENABLED": True,
                    "JS_RECON_VALIDATE_KEYS": settings["JS_RECON_VALIDATE_KEYS"]})
    assert run.call_args.kwargs["verify"] is False


def test_the_filter_is_ignored_with_a_log_when_validation_is_off(capsys):
    assert js_recon._trufflehog_keep({"JS_RECON_TRUFFLEHOG_RESULTS": ["verified"]}, verify=False) is None
    assert "result filter ignored" in capsys.readouterr().out
    assert js_recon._trufflehog_keep({}, verify=False) is None
    assert "ignored" not in capsys.readouterr().out


def test_an_empty_or_unknown_list_is_the_default():
    for raw in ([], None, ["bogus"], ""):
        assert js_recon._trufflehog_keep({"JS_RECON_TRUFFLEHOG_RESULTS": raw}, verify=True) == ALL
    assert js_recon._trufflehog_keep({"JS_RECON_TRUFFLEHOG_RESULTS": ["Verified", " unknown "]},
                                     verify=True) == {"verified", "unknown"}


def test_the_fetch_maps_an_empty_list_to_the_default():
    # The settings golden master runs the real fetch over a row of empty values.
    import json
    golden = Path(__file__).resolve().parent / "fixtures" / "golden_settings"
    empty = json.loads((golden / "empty_strings_and_lists.json").read_text())
    assert empty["JS_RECON_TRUFFLEHOG_RESULTS"] == ["verified", "unknown", "unverified"]
    stealth = json.loads((golden / "stealth.json").read_text())
    assert stealth["JS_RECON_VALIDATE_KEYS"] is False

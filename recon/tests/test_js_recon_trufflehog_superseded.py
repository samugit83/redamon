"""Rules TruffleHog supersedes report only what it confirmed, and only when it ran.

`patterns.SUPERSEDED_BY_TRUFFLEHOG` names the rules that had false positives on
clean code while TruffleHog detects their key type at 99% or more (plan step
2.3). After a complete TruffleHog run, a hit of such a rule TruffleHog did not
match is dropped; a matched one stays a merged finding with its original regex
id, so its mute and verdict survive. A failed, skipped, stopped or disabled
TruffleHog leaves the rule reporting exactly as before. Values are synthetic.
"""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.js_recon import patterns  # noqa: E402
from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

URL = "https://app.example.com/assets/main.js"
rng = random.Random("superseded")
TRAVIS_A = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(22))
TRAVIS_B = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(22))
GH = "gh" + "p_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))
CONTENT = (f'const travisToken = "{TRAVIS_A}";\nconst travisCiToken = "{TRAVIS_B}";\n'
           f'const githubToken = "{GH}";\n')
SETTINGS = {"JS_RECON_VALIDATE_KEYS": False, "JS_RECON_TRUFFLEHOG_ENABLED": True}


@pytest.fixture(autouse=True)
def _isolated():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _run(status, matched=(TRAVIS_A,)):
    results = {"secrets": [s for s in patterns.scan_js_content(CONTENT, URL)[0] if s["category"] != "info"]}
    before = {s["matched_text"]: s["id"] for s in results["secrets"]}
    th_results = [th.ThResult(detector="TravisCI", verified=False, error="", raw=k, file="f_00001.js",
                              line=1, extra={}) for k in matched]
    run = th.ThRun(status, network="none", results=th_results if status == "ran" else [],
                   manifest={"f_00001.js": {"url": URL, "content": CONTENT}})
    record = js_recon._merge_trufflehog(results, run, [{"url": URL, "content": CONTENT}], SETTINGS)
    return results["secrets"], before, record


def _travis(secrets):
    return [s for s in secrets if s["name"] == "Travis CI Token"]


def test_the_set():
    assert patterns.SUPERSEDED_BY_TRUFFLEHOG == frozenset({"Travis CI Token"})
    assert th.mapped_name("TravisCI", TRAVIS_A) == "Travis CI Token"


def test_after_a_complete_run_only_the_confirmed_hit_stays_with_its_id():
    secrets, before, record = _run("ran")
    travis = _travis(secrets)
    assert [t["matched_text"] for t in travis if TRAVIS_A in t["matched_text"]]
    assert not [t for t in travis if TRAVIS_B in t["matched_text"]]
    kept = next(t for t in travis if TRAVIS_A in t["matched_text"])
    assert kept["id"] == before[kept["matched_text"]]
    assert kept["detection_method"] == "regex" and "TruffleHog:TravisCI" in kept["alternate_names"]
    assert record["superseded_dropped"] == 1
    # Other rules are untouched.
    assert any(s["name"] == "GitHub Token Classic" for s in secrets)


@pytest.mark.parametrize("status", ["failed", "skipped", "timed_out", "stopped", "truncated"])
def test_without_a_complete_run_the_rule_reports_as_before(status):
    secrets, before, record = _run(status)
    assert len(_travis(secrets)) == 2
    assert record["superseded_dropped"] == 0


def test_with_trufflehog_off_nothing_is_dropped():
    with mock.patch.object(js_recon.trufflehog_bridge, "run") as run:
        results = js_recon._run_analysis([{"url": URL, "content": CONTENT, "size": len(CONTENT)}],
                                         {"JS_RECON_TIMEOUT": 60, "JS_RECON_SOURCE_MAPS": False,
                                          "JS_RECON_DEPENDENCY_CHECK": False,
                                          "JS_RECON_TRUFFLEHOG_ENABLED": False})
    run.assert_not_called()
    assert len(_travis(results["secrets"])) == 2

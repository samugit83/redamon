"""What a TruffleHog run leaves in js_recon's output: the outcome record.

`scan_metadata.trufflehog` says how the run went (ran, skipped, failed,
timed_out, stopped, truncated) and holds counts, never a value. A run that did
not complete names itself in the coverage reason of the hosts it was given,
without changing their status: js_recon's own analysis of those files is
complete, so nothing is kept from the prune on its account (no
`_note_unchecked`). With the setting off there is no record at all. The
sidecar is mocked; downloads are fakes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.coverage_stamps import base_url_key  # noqa: E402
from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

APP, WWW = "app.example.com", "www.example.com"
APP_JS = [f"https://{APP}/assets/main.{n}.js" for n in (1, 2)]
SETTINGS = {
    "JS_RECON_MAX_FILES": 100, "JS_RECON_TIMEOUT": 60, "JS_RECON_VALIDATE_KEYS": False,
    "JS_RECON_SOURCE_MAPS": False, "JS_RECON_DEPENDENCY_CHECK": False,
    "JS_RECON_TRUFFLEHOG_ENABLED": True,
}


@pytest.fixture(autouse=True)
def _isolated():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _combined():
    return {"metadata": {}, "http_probe": {"by_url": {f"https://{h}": {"status_code": 200} for h in (APP, WWW)}},
            "resource_enum": {"discovered_urls": []}}


def _download(urls, work_dir, max_files, unreachable=None, **_kw):
    return [{"url": u, "filepath": "", "content": "var a = 1;\n", "headers": {}, "size": 11}
            for u in urls[:max_files]]


def _run(th_run=None, settings=None, run_side_effect=None):
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(APP_JS)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_download), \
            mock.patch.object(js_recon.trufflehog_bridge, "run",
                              return_value=th_run, side_effect=run_side_effect) as run, \
            mock.patch.object(js_recon, "_note_unchecked") as unchecked:
        out = js_recon.run_js_recon(_combined(), dict(SETTINGS, **(settings or {})))
    return out["js_recon"], run, unchecked


def _row(js, host):
    return js["scan_metadata"]["coverage"]["hosts"][base_url_key(f"https://{host}")]


STATUSES = [("ran", ""), ("skipped", "image_missing"), ("failed", "exit 1"), ("timed_out", "budget 50s"),
            ("stopped", "run stopping"), ("truncated", "output cap")]


@pytest.mark.parametrize("status,reason", STATUSES)
def test_one_record_per_status(status, reason):
    js, run, unchecked = _run(th.ThRun(status, reason, "none"))
    run.assert_called_once()
    record = js["scan_metadata"]["trufflehog"]
    assert (record["status"], record["reason"], record["network"]) == (status, reason, "none")
    for key in ("results", "merged", "new", "validated", "filtered", "verify_errors", "verification",
                "duration_s"):
        assert key in record
    assert "_input_urls" not in record
    row = _row(js, APP)
    assert row["status"] == "complete"
    if status in ("ran", "stopped"):
        assert "trufflehog" not in (row["reason"] or "")
    else:
        assert row["reason"] == f"trufflehog {status}: {reason}"
        assert record["analyzed_urls"] == APP_JS
    # A TruffleHog failure keeps nothing from the prune: its own earlier
    # findings are kept alive by the graph writer instead.
    unchecked.assert_not_called()


def test_no_record_when_the_setting_is_off():
    js, run, _ = _run(th.ThRun("ran"), settings={"JS_RECON_TRUFFLEHOG_ENABLED": False})
    run.assert_not_called()
    assert "trufflehog" not in js["scan_metadata"]


def test_a_crashing_run_is_failed_and_the_scan_goes_on():
    js, _, _ = _run(run_side_effect=RuntimeError("boom"))
    assert js["scan_metadata"]["trufflehog"]["status"] == "failed"
    assert js["scan_metadata"]["js_files_analyzed"] == 2


def test_the_reason_stays_off_hosts_it_was_not_given():
    js, _, _ = _run(th.ThRun("failed", "exit 1", "none"))
    assert "trufflehog" not in (_row(js, WWW)["reason"] or "")


def _results(n, errors, verified=0):
    return [th.ThResult(detector="Shodan", verified=i < verified, error="timeout" if i >= n - errors else "",
                        raw=f"{'k' * 30}{i:02d}", file="f_00001.js", line=1, extra={}) for i in range(n)]


def _manifest(n):
    content = " ".join(f'k{i}="{"k" * 30}{i:02d}";' for i in range(n))
    return {"f_00001.js": {"url": APP_JS[0], "content": content}}


@pytest.mark.parametrize("errors,expect", [(3, "degraded"), (2, "ok")])
def test_the_breaker_and_degraded_verification(errors, expect):
    recorded = []
    breaker = mock.Mock(record=lambda outcome, *a, **k: recorded.append(outcome))
    run = th.ThRun("ran", network="redamon-trufflehog-net", results=_results(6, errors), manifest=_manifest(6))
    with mock.patch.object(cb, "get_breaker", return_value=breaker) as get:
        js, _, _ = _run(run, settings={"JS_RECON_VALIDATE_KEYS": True})
    get.assert_called_with("secretval:trufflehog", label="SecretValidator", threshold=cb.INTERNAL_THRESHOLD)
    record = js["scan_metadata"]["trufflehog"]
    assert record["verification"] == expect
    assert record["network"] == "bridge"
    assert recorded == [cb.Outcome.TRANSIENT if expect == "degraded" else cb.Outcome.OK]


def test_no_breaker_without_verification():
    with mock.patch.object(cb, "get_breaker") as get:
        js, _, _ = _run(th.ThRun("ran", results=_results(6, 6), manifest=_manifest(6)))
    get.assert_not_called()
    assert js["scan_metadata"]["trufflehog"]["verification"] == "off"

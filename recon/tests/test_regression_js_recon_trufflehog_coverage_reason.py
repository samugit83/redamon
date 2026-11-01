"""R9: a TruffleHog failure names itself on the hosts it was given, only.

The coverage row (`BaseURL.js_recon_reason`) of a host whose files TruffleHog
was handed says "trufflehog <status>: <reason>" when the run did not complete.
A host it was not given (live, but no JavaScript) and an upload (no host)
carry no such text, and no row changes status: js_recon's own analysis of the
files is complete. The sidecar is mocked; downloads are fakes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.coverage_stamps import base_url_key  # noqa: E402
from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

APP, CDN, WWW = "app.example.com", "cdn.example.com", "www.example.com"
JS = [f"https://{APP}/assets/main.js", f"https://{CDN}/lib.js"]
SETTINGS = {"JS_RECON_TIMEOUT": 60, "JS_RECON_VALIDATE_KEYS": False, "JS_RECON_SOURCE_MAPS": False,
            "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_TRUFFLEHOG_ENABLED": True}


def _download(urls, work_dir, max_files, unreachable=None, **_kw):
    return [{"url": u, "filepath": "", "content": "var a = 1;\n", "headers": {}, "size": 11} for u in urls]


def _coverage(status, reason):
    combined = {"metadata": {"project_id": "p1"},
                "http_probe": {"by_url": {f"https://{h}": {"status_code": 200} for h in (APP, WWW)}}}
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(JS)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_download), \
            mock.patch.object(js_recon, "_load_uploaded_files", return_value=[
                {"url": "upload://keys.js", "filepath": "", "content": "var u = 2;\n", "headers": {}, "size": 11}]), \
            mock.patch.object(js_recon.trufflehog_bridge, "run", return_value=th.ThRun(status, reason)):
        out = js_recon.run_js_recon(combined, dict(SETTINGS))
    return out["js_recon"]["scan_metadata"]["coverage"]["hosts"]


def _row(hosts, host):
    return hosts[base_url_key(f"https://{host}")]


def test_the_reason_lands_on_the_given_hosts_only():
    hosts = _coverage("timed_out", "budget 50s")
    for host in (APP, CDN):
        assert _row(hosts, host)["reason"] == "trufflehog timed_out: budget 50s"
        assert _row(hosts, host)["status"] == "complete"
    assert "trufflehog" not in (_row(hosts, WWW)["reason"] or "")
    assert not any(k.startswith("upload") for k in hosts)


def test_a_completed_or_stopped_run_names_nothing():
    for status in ("ran", "stopped"):
        hosts = _coverage(status, "")
        assert not any("trufflehog" in (row["reason"] or "") for row in hosts.values())

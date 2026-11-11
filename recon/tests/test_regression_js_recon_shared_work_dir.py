"""Regression: concurrent scans shared one JS Recon work dir.

The dir was /tmp/redamon/js_recon_{pid}, and the recon process is pid 1 in
every scan container while /tmp/redamon is one host bind mount. Two scans
(two projects) wrote into the same dir, one's cleanup deleted the other's
JS ("JS work dir vanished"), and the supply-chain retire.js pass of project A
scanned project B's JavaScript into A's findings. Each run now owns a dir, and
retire.js reads only the dir its own run recorded.

Downloads, analysis and the DIRTY analyzer are fakes.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))
sys.path.insert(0, str(PROJECT_ROOT / "scanners"))

from recon.main_recon_modules import js_recon  # noqa: E402

KEEP_FOR_SUPPLY_CHAIN = {"SUPPLY_CHAIN_RECON_ENABLED": True}


@pytest.fixture
def scans(monkeypatch):
    """run(url, settings) -> combined_result, as a scan container would (pid 1)."""
    made = []
    registered = []

    def fake_download(urls, work_dir, **_kw):
        work_dir.mkdir(parents=True, exist_ok=True)
        made.append(work_dir)
        files = []
        for idx, url in enumerate(urls):
            path = work_dir / f"js_{idx}.js"
            path.write_text(f"// served by {url}\n")
            files.append({"url": url, "filepath": str(path), "content": path.read_text(),
                          "headers": {}, "size": path.stat().st_size})
        return files

    monkeypatch.setattr(os, "getpid", lambda: 1)
    monkeypatch.setattr(js_recon, "_download_js_files", fake_download)
    monkeypatch.setattr(js_recon, "_run_analysis", lambda files, s, **_kw: {"secrets": [], "endpoints": []})
    monkeypatch.setattr(js_recon, "_extract_subdomains", lambda *a, **k: ([], []))
    monkeypatch.setattr(js_recon, "_build_summary", lambda results: {})

    class _Atexit:
        @staticmethod
        def register(func, *args, **kwargs):
            registered.append(args[0] if args else None)

    monkeypatch.setattr(js_recon, "atexit", _Atexit, raising=False)

    def run(url, settings):
        monkeypatch.setattr(js_recon, "_collect_js_urls", lambda cr, s: [url])
        return js_recon.run_js_recon({"domain": "example.com", "metadata": {}}, settings)

    run.registered = registered
    run.made = made
    yield run
    for path in made:
        shutil.rmtree(path, ignore_errors=True)


class _Dispatch:
    """The analyzer: records the JS it was handed, nothing runs."""

    def __init__(self, root: Path):
        self.root = root
        self.seen = []

    def new_work_dir(self, prefix="sc-job"):
        path = self.root / prefix
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    def run_analyzer_job(self, job, work_dir, sc_common, **_kw):
        js_dir = Path(work_dir) / "js"
        self.seen = sorted(p.read_text() for p in js_dir.glob("*.js"))
        return {"artifact": None, "error": None}


class TestRegressionJsReconSharedWorkDir:
    def test_regression_js_recon_shared_work_dir(self, scans, tmp_path):
        project_a = scans("https://a.example/app.js", KEEP_FOR_SUPPLY_CHAIN)
        project_b = scans("https://b.example/app.js", KEEP_FOR_SUPPLY_CHAIN)
        dir_a = project_a["js_recon"]["work_dir"]
        dir_b = project_b["js_recon"]["work_dir"]
        assert dir_a and dir_b and dir_a != dir_b

        from recon.main_recon_modules import supply_chain_recon
        dispatch = _Dispatch(tmp_path)
        _, stats = supply_chain_recon.retire_js_harvest(project_a, dispatch=dispatch)
        assert stats["error"] is None
        assert dispatch.seen == ["// served by https://a.example/app.js\n"]

    def test_another_runs_cleanup_leaves_this_runs_dir(self, scans):
        kept = scans("https://b.example/app.js", KEEP_FOR_SUPPLY_CHAIN)
        scans("https://a.example/app.js", {})  # no supply chain: removes its own dir
        assert os.path.isdir(kept["js_recon"]["work_dir"])

    def test_a_dir_kept_for_the_supply_chain_goes_when_the_process_ends(self, scans):
        kept = scans("https://a.example/app.js", KEEP_FOR_SUPPLY_CHAIN)
        assert scans.registered == [kept["js_recon"]["work_dir"]]

    def test_a_dir_kept_for_debugging_stays(self, scans):
        scans("https://a.example/app.js", {"JS_RECON_KEEP_WORK_DIR": True,
                                           "SUPPLY_CHAIN_RECON_ENABLED": True})
        assert scans.registered == []

    def test_without_the_supply_chain_the_dir_is_removed_at_once(self, scans):
        result = scans("https://a.example/app.js", {})
        assert result["js_recon"]["work_dir"] is None
        assert not scans.made[-1].exists()
        assert scans.registered == []

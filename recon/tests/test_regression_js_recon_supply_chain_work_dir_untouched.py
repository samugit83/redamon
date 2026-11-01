"""R3: TruffleHog never writes into the work_dir the supply-chain stage reads.

GROUP 5.5 (supply-chain recon) hands js_recon's `work_dir` to retire.js as
exactly the JavaScript this run downloaded. TruffleHog stages its own copies
(source-map pseudo-files and uploads included) in a dir of its own, which is
gone when the run ends. The sidecar is mocked; downloads are fakes that write
the files where the real download does.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

URLS = [f"https://app.example.com/assets/{n}.js" for n in ("main", "chunk")]
SETTINGS = {"JS_RECON_TIMEOUT": 60, "JS_RECON_VALIDATE_KEYS": False, "JS_RECON_SOURCE_MAPS": False,
            "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_TRUFFLEHOG_ENABLED": True,
            "JS_RECON_KEEP_WORK_DIR": True}


def _download(urls, work_dir, max_files, unreachable=None, **_kw):
    work_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for i, u in enumerate(urls):
        path = work_dir / f"js_{i}.js"
        path.write_text("var a = 1;\n")
        out.append({"url": u, "filepath": str(path), "content": "var a = 1;\n", "headers": {}, "size": 11})
    return out


def test_work_dir_holds_exactly_the_downloads(tmp_path):
    seen = {}

    def sidecar(argv, *, name, budget_s):
        seen["stage"] = argv[argv.index("-v") + 1].split(":", 1)[0]
        return th.SidecarResult("ran")

    root = str(tmp_path / "tmp-redamon")
    os.makedirs(root)
    real_run = th.run
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(URLS)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_download), \
            mock.patch.object(js_recon, "_load_uploaded_files", return_value=[
                {"url": "upload://keys.js", "filepath": "", "content": "var u = 2;\n", "headers": {}, "size": 11}]), \
            mock.patch.object(js_recon.trufflehog_bridge, "run",
                              side_effect=lambda files, **kw: real_run(files, root=root, **kw)), \
            mock.patch.object(th, "image_available", return_value=True), \
            mock.patch.object(th, "run_sidecar", side_effect=sidecar):
        out = js_recon.run_js_recon({"metadata": {"project_id": "p1"}}, dict(SETTINGS))
    work_dir = Path(out["js_recon"]["work_dir"])
    try:
        assert sorted(os.listdir(work_dir)) == ["js_0.js", "js_1.js"]
        stage = Path(seen["stage"])
        assert work_dir not in stage.parents and stage != work_dir
        assert stage.name.startswith(th.STAGE_PREFIX)
        assert not stage.exists()
        assert out["js_recon"]["scan_metadata"]["trufflehog"]["status"] == "ran"
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

"""R2: a TruffleHog failure keeps its own findings alive, and nothing else.

When the sidecar fails, times out or its image is missing, TruffleHog found
nothing this run, which is not "the keys are gone": the graph writer refreshes
the earlier TruffleHog-only Secrets of the files it was given, so the
end-of-run prune keeps them. Regex findings get no such help: js_recon notes
no coverage gap for a TruffleHog failure (no `_note_unchecked`), so a regex
key that left the bundle is pruned as before. The recon output goes through
the real writer against a recording session; nothing reaches Neo4j.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

sys.modules.setdefault("dotenv", mock.MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402
from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

URLS = ["https://app.example.com/assets/main.js"]
GH = "gh" + "p_" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4"
SETTINGS = {"JS_RECON_TIMEOUT": 60, "JS_RECON_VALIDATE_KEYS": False, "JS_RECON_SOURCE_MAPS": False,
            "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_TRUFFLEHOG_ENABLED": True}


class _Result(list):
    def single(self):
        return {"linked": 0, "kept": 3, "enriched": 0}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return _Result()


class _Writer(JsReconMixin):
    def __init__(self):
        self.session_obj = _Session()
        self.driver = mock.MagicMock()
        self.driver.session.return_value = self.session_obj


def _download(urls, work_dir, max_files, unreachable=None, **_kw):
    return [{"url": u, "filepath": "", "content": f'const t = "{GH}";\n', "headers": {}, "size": 40} for u in urls]


def _scan(th_run):
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(URLS)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_download), \
            mock.patch.object(js_recon.trufflehog_bridge, "run", return_value=th_run), \
            mock.patch.object(js_recon, "_note_unchecked") as unchecked:
        out = js_recon.run_js_recon({"metadata": {"project_id": "p1"}, "domain": "example.com"}, dict(SETTINGS))
    writer = _Writer()
    writer.update_graph_from_js_recon(out, "u1", "p1")
    return writer.session_obj.calls, unchecked


def _keep_alive(calls):
    return [(q, kw) for q, kw in calls if "detection_method: 'trufflehog'" in q and "SET s.updated_at" in q]


def test_a_failure_keeps_only_trufflehog_findings_alive():
    for status, reason in (("failed", "exit 1"), ("timed_out", "budget 50s"), ("skipped", "image_missing")):
        calls, unchecked = _scan(th.ThRun(status, reason))
        ((query, kw),) = _keep_alive(calls)
        assert "user_id: $uid, project_id: $pid, source: 'js_recon'" in query
        assert kw["analyzed_urls"] == URLS
        # The regex finding is written (and so refreshed) only because this run
        # found it again; nothing else keeps a regex finding from the prune.
        assert not unchecked.called
        written = [kw for q, kw in calls if "MERGE (s:Secret" in q]
        assert [w["detection_method"] for w in written] == ["regex"]


def test_a_completed_run_needs_no_keep_alive():
    calls, _ = _scan(th.ThRun("ran"))
    assert _keep_alive(calls) == []

"""Partial JS Recon writes every finding its run produced (L-1).

run_jsrecon handed the graph writer a result only when it held a secret, an
endpoint or a covered host. A run with no covered host (uploaded files only, or
every host RoE-excluded) that found DOM sinks, dependency-confusion packages or
source maps returned early, and those findings were discarded. A run that found
nothing and covered nothing still writes nothing: a partial run never prunes,
so there is nothing for it to record.

The real run_jsrecon runs; run_js_recon (downloads and analysis), Neo4j and
the upload folder are the fakes. Names are under example.com only.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import js_analysis  # noqa: E402

ROOT = "example.com"
PID = "proj-jsgate"
UPLOAD_PREFIX = "/data/js-recon-uploads/"
SETTINGS = {"JS_RECON_ENABLED": False, "TARGET_DOMAIN": ROOT, "SUBDOMAIN_LIST": ["."]}

DOM_SINK = {"id": "dom-1", "type": "innerHTML", "severity": "medium", "confidence": "medium",
            "source_url": "upload://bundle.js", "line": 3, "evidence": "el.innerHTML = location.hash"}
DEPENDENCY = {"id": "dep-1", "package_name": "@example-internal/ui", "severity": "high",
              "confidence": "medium", "source_url": "https://www.example.com/static/app.js"}


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, *_a, **_k):
        return []


class _Client:
    written: list = []

    def __init__(self, *_a, **_k):
        self.driver = mock.MagicMock()
        self.driver.session.side_effect = lambda **_k: _Session()

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return True

    def update_graph_from_js_recon(self, recon_data, user_id, project_id):
        _Client.written.append(recon_data)
        return {}

    def create_user_input_node(self, *_a, **_k):
        return None

    def update_user_input_status(self, *_a, **_k):
        return None


@pytest.fixture
def graph(monkeypatch):
    _Client.written = []
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    return _Client.written


@pytest.fixture
def uploads(monkeypatch, tmp_path):
    """The project's upload folder, redirected from /data to a temp dir."""
    folder = tmp_path / PID
    folder.mkdir()
    real = js_analysis.Path

    def redirected(value, *rest):
        text = str(value)
        if text.startswith(UPLOAD_PREFIX):
            return tmp_path / text[len(UPLOAD_PREFIX):]
        return real(value, *rest)

    monkeypatch.setattr(js_analysis, "Path", redirected)
    return folder


def _js_result(**findings) -> dict:
    """What run_js_recon leaves under combined_result['js_recon']: no host was
    covered (the only files were uploads, or every host was RoE-excluded)."""
    return {
        "scan_metadata": {"mode": "post_recon", "js_files_analyzed": 1,
                          "coverage": {"at": "2026-11-11T08:00:00+00:00", "hosts": {}}},
        "secrets": [], "endpoints": [], "source_maps": [], "dependencies": [], "dom_sinks": [],
        "frameworks": [], "dev_comments": [], "cloud_assets": [], "emails": [],
        "ip_addresses": [], "object_references": [], "dev_references": [],
        "ai_sdk_findings": [], "discovered_subdomains": [], "external_domains": [],
        "summary": {}, **findings,
    }


def _run(config: dict, js_result: dict):
    seen = {}

    def fake_run_js_recon(combined_result, settings=None):
        seen["combined"] = combined_result
        combined_result["js_recon"] = js_result
        return combined_result

    cfg = {"domains": [ROOT], "domain": ROOT, "_settings": dict(SETTINGS), **config}
    with mock.patch("recon.main_recon_modules.js_recon.run_js_recon", side_effect=fake_run_js_recon):
        js_analysis.run_jsrecon(cfg)
    return seen


def test_an_upload_only_run_that_found_a_dom_sink_writes_it(graph, uploads):
    (uploads / "bundle.js").write_text("el.innerHTML = location.hash")
    _run({"include_graph_targets": False}, _js_result(dom_sinks=[DOM_SINK]))

    assert len(graph) == 1
    assert graph[0]["js_recon"]["dom_sinks"] == [DOM_SINK]


def test_a_run_whose_hosts_were_all_excluded_writes_its_dependency_findings(graph, uploads):
    seen = _run({"include_graph_targets": False,
                 "user_targets": {"urls": ["https://www.example.com/static/app.js"]}},
                _js_result(dependencies=[DEPENDENCY]))

    assert seen["combined"]["resource_enum"]["discovered_urls"] == ["https://www.example.com/static/app.js"]
    assert len(graph) == 1
    assert graph[0]["js_recon"]["dependencies"] == [DEPENDENCY]


@pytest.mark.parametrize("key, rows", [
    ("source_maps", [{"id": "sm-1", "source_url": "upload://bundle.js", "map_url": "upload://bundle.js.map"}]),
    ("frameworks", [{"name": "React", "source_url": "upload://bundle.js"}]),
    ("dev_comments", [{"id": "dc-1", "source_url": "upload://bundle.js", "text": "TODO remove"}]),
    ("emails", [{"value": "ops@example.com", "source_url": "upload://bundle.js"}]),
    ("cloud_assets", [{"url": "https://bucket.example.com", "source_url": "upload://bundle.js"}]),
])
def test_every_finding_category_reaches_the_writer(graph, uploads, key, rows):
    (uploads / "bundle.js").write_text("void 0")
    _run({"include_graph_targets": False}, _js_result(**{key: rows}))

    assert len(graph) == 1
    assert graph[0]["js_recon"][key] == rows


def test_an_upload_only_run_that_found_nothing_writes_nothing(graph, uploads):
    (uploads / "bundle.js").write_text("void 0")
    _run({"include_graph_targets": False}, _js_result())

    assert graph == []


def test_no_input_at_all_still_exits_before_analysis(graph, uploads):
    with pytest.raises(SystemExit) as exc:
        _run({"include_graph_targets": False}, _js_result(dom_sinks=[DOM_SINK]))
    assert exc.value.code == 1
    assert graph == []

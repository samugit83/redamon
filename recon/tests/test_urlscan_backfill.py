"""tooling/scripts/urlscan_backfill.py: the one-off mask of stored urlscan values.

Every case of the plan's §0 correction 15, on a recording session and a
temporary output folder: tokens masked or their Endpoint removed, old
RESOLVES_TO edges marked, orphan IPs deleted, recon JSON masked atomically with
no backup, a second run changing nothing, and no value ever printed.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

_spec = importlib.util.spec_from_file_location(
    "urlscan_backfill", PROJECT_ROOT / "tooling" / "scripts" / "urlscan_backfill.py")
bf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bf)

TOK = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"
ENDPOINTS = [
    {"eid": "e1", "baseurl": "https://auth.example.test", "path": "/reset",
     "full_url": f"https://auth.example.test/reset?token={TOK}", "sources": None},
    {"eid": "e2", "baseurl": "https://app.example.test", "path": "/invite/" + TOK,
     "full_url": None, "sources": ["katana"]},
    {"eid": "e3", "baseurl": "https://app.example.test", "path": "/search",
     "full_url": "https://app.example.test/search?q=shoes", "sources": None},
    {"eid": "e4", "baseurl": "https://app.example.test", "path": "/about",
     "full_url": "https://app.example.test/about", "sources": None},
]


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self, marker=False):
        self.marker = marker
        self.writes = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        if "RedamonSchemaMigration" in query and "MERGE" not in query:
            return _Result([{"c": 1 if self.marker else 0}])
        if "MERGE (m:RedamonSchemaMigration" in query:
            self.marker = True
            self.writes.append(("marker", params))
            return _Result([])
        if "RETURN DISTINCT n.user_id" in query:
            return _Result([{"uid": "u1", "pid": "p1"}])
        if "RETURN elementId(e) AS eid" in query:
            return _Result([dict(e) for e in ENDPOINTS])
        if "count(" in query:
            if "RETURN count(*)" in query:
                self.writes.append((query, params))
            return _Result([{"n": 2}])
        self.writes.append((query, params))
        return _Result([])


class _Driver:
    def __init__(self, session):
        self._s = session

    def session(self):
        return self._s


def test_endpoint_plans():
    assert bf.plan_endpoint(ENDPOINTS[0])[0] == "delete"
    assert bf.plan_endpoint(ENDPOINTS[1])[0] == "quarantine"
    assert bf.plan_endpoint(ENDPOINTS[2]) == ("mask", "https://app.example.test/search?q=***")
    assert bf.plan_endpoint(ENDPOINTS[3]) == ("keep", None)


def test_graph_dry_run_writes_nothing():
    s = _Session()
    totals = bf.backfill_graph(_Driver(s), apply=False)
    assert s.writes == [] and not s.marker
    assert (totals["endpoints_deleted"], totals["endpoints_quarantined"], totals["endpoints_masked"]) == (1, 1, 1)


def test_graph_apply_then_a_second_run_changes_nothing():
    s = _Session()
    totals = bf.backfill_graph(_Driver(s), apply=True)
    queries = [q for q, _p in s.writes if q != "marker"]
    assert any("DETACH DELETE p, e" in q for q in queries)
    assert any("SET e.quarantined = true" in q and "REMOVE e.full_url" in q for q in queries)
    assert any("SET e.full_url = $url" in q for q in queries)
    assert any("SET r.source = 'legacy_unknown'" in q and "r.record_type IS NULL" in q for q in queries)
    assert any("REMOVE p.sample_value" in q for q in queries)
    assert any("NOT (i)--()" in q and "DELETE i" in q for q in queries)
    for q, p in s.writes:
        if q != "marker":
            assert p.get("uid") == "u1" and p.get("pid") == "p1", q
    assert totals["edges_marked_legacy"] == 2 and s.marker
    before = len(s.writes)
    assert bf.backfill_graph(_Driver(s), apply=True) == {"skipped": "already applied"}
    assert len(s.writes) == before


def _doc():
    return {
        "urlscan": {
            "entries": [{"url": f"https://auth.example.test/reset?token={TOK}"}],
            "urls_with_paths": [{"full_url": f"https://app.example.test/x?k={TOK}",
                                 "params": {"k": TOK}}],
            "external_domains": [{"url": f"https://other.test/doc/{TOK}?a=1"}],
        },
        "external_domains_aggregated": [{"redirect_to_urls": [f"https://other.test/r?t={TOK}"],
                                         "redirect_from_urls": []}],
        "resource_enum": {"discovered_urls": [f"https://app.example.test/p?s={TOK}"],
                          "archived_urls": [f"https://app.example.test/password/reset/{TOK}"]},
    }


def test_json_masked_atomically_without_backup_and_once(tmp_path):
    (tmp_path / "recon_p1.json").write_text(json.dumps(_doc()))
    (tmp_path / "broken.json").write_text("{not json")
    out = io.StringIO()
    with redirect_stdout(out):
        counts = bf.backfill_json(tmp_path, apply=True)
    text = (tmp_path / "recon_p1.json").read_text()
    assert TOK not in text
    assert counts["files_changed"] == 1 and counts["files_unreadable"] == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == [".urlscan_backfill_v1", "broken.json", "recon_p1.json"]
    doc = json.loads(text)
    assert doc["urlscan"]["external_domains"][0]["url"] == "https://other.test"
    assert doc["resource_enum"]["archived_urls"] == ["https://app.example.test/password/reset/{token}"]
    assert bf.backfill_json(tmp_path, apply=True) == {"skipped": "already applied"}
    assert TOK not in out.getvalue()


def test_json_dry_run_changes_no_file(tmp_path):
    (tmp_path / "recon_p1.json").write_text(json.dumps(_doc()))
    bf.backfill_json(tmp_path, apply=False)
    assert TOK in (tmp_path / "recon_p1.json").read_text()
    assert not (tmp_path / ".urlscan_backfill_v1").exists()


def test_cli_prints_counts_only(tmp_path):
    (tmp_path / "recon_p1.json").write_text(json.dumps(_doc()))
    out = io.StringIO()
    with redirect_stdout(out):
        bf.main(["--output-dir", str(tmp_path), "--skip-graph"])
    assert TOK not in out.getvalue() and "values_masked" in out.getvalue()

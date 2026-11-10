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
        if "RETURN elementId(v) AS vid" in query:
            return _Result([])  # a read: no finding holds a leaked link here
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


class _TwoProjectSession(_Session):
    def run(self, query, **params):
        if "RETURN DISTINCT n.user_id" in query:
            return _Result([{"uid": "u1", "pid": "p1"}, {"uid": "u2", "pid": "p2"}])
        return super().run(query, **params)


def test_one_project_touches_only_that_project_and_leaves_no_marker():
    s = _TwoProjectSession()
    totals = bf.backfill_graph(_Driver(s), apply=True, project="p2")
    assert totals["projects"] == 1
    assert s.writes and all(p.get("pid") == "p2" for q, p in s.writes if q != "marker")
    assert not s.marker  # the deployment-wide run still happens


def test_one_project_runs_even_after_the_deployment_wide_run():
    s = _TwoProjectSession(marker=True)
    assert bf.backfill_graph(_Driver(s), apply=False, project="p1")["projects"] == 1


def test_one_project_masks_only_its_own_json_files(tmp_path):
    for name in ("recon_p1.json", "recon_p1__run7.json", "recon_p10.json", "recon_p2.json"):
        (tmp_path / name).write_text(json.dumps(_doc()))
    counts = bf.backfill_json(tmp_path, apply=True, project="p1")
    assert counts["files"] == 2
    assert TOK not in (tmp_path / "recon_p1.json").read_text()
    assert TOK not in (tmp_path / "recon_p1__run7.json").read_text()
    assert TOK in (tmp_path / "recon_p10.json").read_text()
    assert TOK in (tmp_path / "recon_p2.json").read_text()
    assert not (tmp_path / ".urlscan_backfill_v1").exists()


def test_cli_refuses_a_project_that_is_not_an_id(tmp_path):
    import pytest
    with pytest.raises(SystemExit):
        bf.main(["--output-dir", str(tmp_path), "--skip-graph", "--project", "p1*"])


def _finding_doc():
    leaked = f"https://auth.example.test/password/reset/{TOK}"
    return {
        "urlscan": {"urls_with_paths": [{"path": f"/password/reset/{TOK}", "params": {}}]},
        "vuln_scan": {"security_checks": {"findings": [{
            "type": "no_rate_limiting", "url": leaked, "endpoint": f"/password/reset/{TOK}",
            "description": f"Sent 10 requests to {leaked}. No 429 came back.",
        }], "by_type": {"no_rate_limiting": [{"url": leaked}]}}},
        "http_probe": {"by_url": {"https://app.example.test/about": {"title": "About"}}},
    }


def test_json_masks_a_leaked_link_wherever_an_old_scan_wrote_it():
    doc = _finding_doc()
    assert bf.mask_recon_document(doc) >= 4
    text = json.dumps(doc)
    assert TOK not in text
    finding = doc["vuln_scan"]["security_checks"]["findings"][0]
    assert finding["url"] == "https://auth.example.test/password/reset/{token}"
    assert finding["endpoint"] == "/password/reset/{token}"
    assert finding["description"] == ("Sent 10 requests to https://auth.example.test/password/reset/{token}. "
                                      "No 429 came back.")
    assert doc["urlscan"]["urls_with_paths"][0]["path"] == "/password/reset/{token}"
    # an ordinary link is left alone, and a second pass changes nothing
    assert "https://app.example.test/about" in doc["http_probe"]["by_url"]
    assert bf.mask_recon_document(doc) == 0


class _FindingSession(_Session):
    def run(self, query, **params):
        if "RETURN elementId(v) AS vid" in query:
            return _Result([
                {"vid": "v1", "props": {"id": "f-1", "url": f"https://auth.example.test/password/reset/{TOK}",
                                        "description": f"tested https://auth.example.test/password/reset/{TOK}",
                                        "severity": "medium"}},
                {"vid": "v2", "props": {"id": "f-2", "url": "https://app.example.test/login"}},
            ])
        return super().run(query, **params)


def test_graph_masks_the_findings_that_kept_a_leaked_link():
    s = _FindingSession()
    totals = bf.backfill_graph(_Driver(s), apply=True, project="p1")
    assert totals["findings_masked"] == 1
    sets = [p for q, p in s.writes if q != "marker" and "SET v += $changed" in q]
    assert len(sets) == 1 and sets[0]["vid"] == "v1" and sets[0]["pid"] == "p1"
    assert sets[0]["changed"] == {
        "url": "https://auth.example.test/password/reset/{token}",
        "description": "tested https://auth.example.test/password/reset/{token}",
    }
    assert TOK not in json.dumps(sets)


def test_graph_dry_run_counts_findings_and_writes_none():
    s = _FindingSession()
    assert bf.backfill_graph(_Driver(s), apply=False)["findings_masked"] == 1
    assert not [q for q, _p in s.writes if "SET v += $changed" in q]


def test_json_leaves_the_display_fields_whole():
    link = f"https://auth.example.test/password/reset/{TOK}"
    doc = {"urlscan": {"url_secrets": [{"masked_url": link, "unmasked_url": link, "secret_value": TOK}],
                       "findings": [{"url": link, "props": {"unmasked_urls": [link]}}]}}
    bf.mask_recon_document(doc)
    sec = doc["urlscan"]["url_secrets"][0]
    assert sec["unmasked_url"] == link and sec["secret_value"] == TOK
    assert TOK not in sec["masked_url"]
    assert doc["urlscan"]["findings"][0]["props"]["unmasked_urls"] == [link]
    assert TOK not in doc["urlscan"]["findings"][0]["url"]


class _DisplayFindingSession(_Session):
    def run(self, query, **params):
        if "RETURN elementId(v) AS vid" in query:
            link = f"https://auth.example.test/password/reset/{TOK}"
            return _Result([{"vid": "v1", "props": {"id": "f-1", "url": link, "unmasked_url": link,
                                                    "unmasked_urls": [link]}}])
        return super().run(query, **params)


def test_graph_leaves_the_display_fields_whole():
    s = _DisplayFindingSession()
    bf.backfill_graph(_Driver(s), apply=True, project="p1")
    changed, = [p["changed"] for q, p in s.writes if q != "marker" and "SET v += $changed" in q]
    assert set(changed) == {"url"}

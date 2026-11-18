"""A CVE archive's index on Postgres (the owner's decision Q-C of 2026-11-18, option A of NQ-6): the
real runner, pipeline and page store write the archive's CVE files as text-less entries keyed by
the owner and the resource; search's exact-entity wording finds a CVE the archive holds and no
text or fuzzy wording reads the index; Library now shows the archive's entry for a step that names
the CVE and for a CVE a finding confirmed; a page read of the entry answers through the CVE reader
and writes nothing.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

import project_settings as ps  # noqa: E402
import test_tradecraft_ingest_pipeline_integration as pipeline_it  # noqa: E402
from test_tradecraft_ingest_pipeline_integration import ingest, pg  # noqa: E402,F401
from test_tradecraft_search_integration import catalog, page, seed  # noqa: E402
from tradecraft import net, run_state, runtime  # noqa: E402
from tradecraft.ingest import pipeline  # noqa: E402
from tradecraft.library import hints, reader, search  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

URL = "https://github.com/tc-fixture/cve"
RAW = "https://raw.githubusercontent.com/tc-fixture/cve/main"
JSON = {"type.cve.pathPatterns": ["{year}/{cve}.json"]}
FILES = 4 + 4 + 1050
RUN_SETTINGS = {"TOOL_PHASE_MAP": {"tradecraft_lookup": ["informational", "exploitation", "post_exploitation"]},
                "TRADECRAFT_V2": True, "TRADECRAFT_ASK": True}


async def archive(pg, root, uid=None, rid=None):
    """The fixture archive ingested with a GitHub token (without one there is no index)."""
    with mock.patch.dict(pipeline_it.FIXTURE, {"secrets": {"github_token": "ghp_fake_token_for_tests",
                                                          "credentials": None}}):
        uid, rid, job, _model = await ingest(pg, root, URL, settings=JSON, uid=uid, rid=rid)
    assert job["status"] == "succeeded", job
    row = (await pg.sql("SELECT slug, generation FROM user_tradecraft_resources WHERE id = %s", rid))[0]
    entry = {"id": rid, "slug": row["slug"], "name": "trickest-like", "url": URL, "type": "cve-poc-db",
             "storage_mode": "live", "summary": "An archive.", "priority": "normal", "map_version": 3,
             "read_settings": JSON}
    return uid, rid, row["generation"], entry


def state(goal, **over):
    base = {"session_id": "s-1", "current_objective_index": 0, "attack_path_type": "path_traversal",
            "current_phase": "exploitation", "conversation_objectives": [{"content": "Read a file outside the web root"}],
            "todo_list": [{"id": "t1", "description": goal, "status": "in_progress", "priority": "high"}],
            "target_info": {"technologies": [], "vulnerabilities": []}}
    base.update(over)
    return base


def rows_of(note):
    return re.findall(r"^    (\S+:\d+)  (.*)$", note or "", flags=re.MULTILINE)


async def test_the_index_is_keyed_text_less_and_searched_by_cve_id_only(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid, rid, gen, entry = await archive(pg, root)
    rows = await pg.sql("SELECT title, url, entities, topics, stored_text, stored_bytes, search_vector IS NOT NULL AS sv, "
                        "breadcrumb FROM tradecraft_entries WHERE user_id = %s AND resource_id = %s AND generation = %s",
                        uid, rid, gen)
    assert len(rows) == FILES and all(r["stored_text"] is None and r["stored_bytes"] == 0 and r["sv"] for r in rows)
    one = next(r for r in rows if r["title"] == "CVE-2023-1050")
    assert (one["url"], one["entities"], one["topics"], one["breadcrumb"]) == (
        f"{RAW}/2023/CVE-2023-1050.json", ["CVE-2023-1050"], [], ["2023"])
    report = (await pg.sql("SELECT ingestion_report, sitemap FROM user_tradecraft_resources WHERE id = %s", rid))[0]
    assert report["ingestion_report"]["stopReason"] == f"cve index: {FILES} of {FILES} files"
    assert report["sitemap"] == {"owner": "tc-fixture", "repo": "cve", "branch": "main"}

    # Another account's copy of the same archive is its own rows, never read by this owner.
    other, other_rid, _g, other_entry = await archive(pg, padded_sites(tmp_path / "b"))
    assert other_rid != rid
    cat = catalog(uid, entry)
    found = await search.search(uid, cat, "exploit CVE-2023-1050 to read a file")
    assert found.verdict == "FOUND" and [h.card.title for h in found.hits] == ["CVE-2023-1050"]
    assert found.hits[0].card.page_id.startswith(entry["slug"] + ":")
    assert (await search.search(uid, catalog(uid, other_entry), "CVE-2023-1050")).hits == ()
    # Words alone never rank the index, and a neighbouring id is not this one.
    assert (await search.search(uid, cat, "cve 2023 json")).verdict == "NOT FOUND"
    assert (await search.search(uid, cat, "CVE-2023-1051")).verdict == "NOT FOUND"


async def test_library_now_shows_the_archives_entry_and_the_read_answers_with_the_cve(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid, rid, _gen, entry = await archive(pg, root)
    lib = await seed(pg, uid, [page(1, title="Directory traversal", topics=["path_traversal"]),
                               page(2, title="Apache HTTP Server path normalization", topics=["path_traversal"])],
                     slug="lib")
    ps._settings_ctx.set(RUN_SETTINGS)
    cat = catalog(uid, lib, entry, search_settings={"prompt.coverageMap": False})

    before, _ = await hints.library_now(state("Read a file outside the web root through the server's path handling"),
                                        cat)
    assert entry["slug"] + ":" not in (before or "")
    named, _ = await hints.library_now(state("Exploit CVE-2023-1050 to read a file outside the web root"), cat)
    rows = dict(rows_of(named))
    archive_rows = [p for p in rows if p.startswith(entry["slug"] + ":")]
    assert len(archive_rows) == 1 and "CVE-2023-1050" in rows[archive_rows[0]] and len(rows) <= hints.PAGES
    finding = {"finding_type": "vulnerability_confirmed", "related_cves": ["CVE-2021-0003"]}
    confirmed, _ = await hints.library_now(
        state("Read a file outside the web root", chain_findings_memory=[finding]), cat)
    assert any(p.startswith(entry["slug"] + ":") and "CVE-2021-0003" in t for p, t in rows_of(confirmed))

    # The row's page ID reads the CVE, live, and nothing is written.
    counts = "SELECT (SELECT count(*) FROM tradecraft_entries WHERE user_id = %s) AS e, " \
             "(SELECT count(*) FROM tradecraft_page_ids p JOIN user_tradecraft_resources r ON r.id = p.resource_id " \
             "WHERE r.user_id = %s) AS p"
    before_counts = await pg.sql(counts, uid, uid)
    run = {"session_id": "s-1", "current_objective_index": 0}
    with net.use_fetcher(FixtureFetcher(root)), runtime.use_store(Store()):
        assert runtime.bind_run_catalog(cat.model_dump())
        with run_state.bound(run):
            out = await reader.lookup(page=archive_rows[0])
            run.update(run_state.drain())
    assert f"url: {RAW}/2023/CVE-2023-1050.json" in out and "Synthetic entry CVE-2023-1050." in out
    assert run["tradecraft_seen_pages"] == [archive_rows[0]]
    assert await pg.sql(counts, uid, uid) == before_counts


async def seed_archive(pg, uid, slug, cves, priority="normal"):
    """A CVE archive of ``uid`` whose live index holds ``cves``, as ingestion writes it."""
    store = Store()
    rid = f"tc-r-{uuid.uuid4().hex[:12]}"
    await pg.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, map_version, "
                 "resource_type, summary, generation, priority, sitemap, updated_at) VALUES (%s, %s, %s, %s, %s, "
                 "'live', 3, 'cve-poc-db', 'An archive.', 1, %s, %s::jsonb, now())", rid, uid, slug, slug,
                 f"https://github.com/tc-fixture/{slug}", priority,
                 f'{{"owner": "tc-fixture", "repo": "{slug}", "branch": "main"}}')
    urls = {c: f"https://raw.githubusercontent.com/tc-fixture/{slug}/main/{c[4:8]}/{c}.md" for c in cves}
    ids = await store.allocate_page_ids(uid, rid, list(urls.values()))
    await store.write_entries(uid, rid, 1, [{"page_id": ids[u], "url": u, "title": c, "breadcrumb": [c[4:8]],
                                             "source": "tree", "entities": [c]} for c, u in urls.items()])
    return {"id": rid, "slug": slug, "name": slug, "url": f"https://github.com/tc-fixture/{slug}", "type": "cve-poc-db",
            "storage_mode": "live", "summary": "An archive.", "priority": priority, "map_version": 3}


@pytest.mark.parametrize("archives,chosen", [
    ([("zeta-cves", "normal"), ("alpha-cves", "normal")], "alpha-cves"),
    ([("zeta-cves", "normal"), ("alpha-cves", "low"), ("mid-cves", "high")], "mid-cves"),
])
async def test_two_or_three_archives_holding_the_cve_give_library_now_one_row(pg, archives, chosen):
    """Every archive holds the step's CVE: one row stands for it, from the archive of the highest
    priority, then the first by slug; the technique pages keep the other rows."""
    uid = await pg.user()
    lib = await seed(pg, uid, [page(1, title="Directory traversal", topics=["path_traversal"],
                                    entities=["CVE-2023-1050"]),
                               page(2, title="Apache path traversal payloads", topics=["path_traversal"],
                                    entities=["CVE-2023-1050"])], slug="lib")
    entries = [await seed_archive(pg, uid, slug, ["CVE-2023-1050", "CVE-2021-0003"], priority)
               for slug, priority in archives]
    ps._settings_ctx.set(RUN_SETTINGS)
    cat = catalog(uid, lib, *entries, search_settings={"prompt.coverageMap": False})
    note, _ = await hints.library_now(state("Exploit CVE-2023-1050 to read a file outside the web root"), cat)
    rows = rows_of(note)
    from_archives = [(p, t) for p, t in rows if not p.startswith("lib:")]
    assert len(from_archives) == 1 and from_archives[0][0].startswith(chosen + ":") and "CVE-2023-1050" in from_archives[0][1]
    assert [p for p, _t in rows if p.startswith("lib:")] and len(rows) <= hints.PAGES
    answer = await search.search(uid, cat, "CVE-2023-1050")
    assert [h.card.resource_slug for h in answer.hits if h.card.resource_slug != "lib"] == [chosen]


async def test_a_blocked_entry_lets_another_archive_stand_for_its_cve(pg):
    """The person blocked the chosen archive's file for a CVE in the Map: until the next refresh drops
    it, its entry is still in the map, and the other archive's copy is the one row shown."""
    uid = await pg.user()
    alpha = await seed_archive(pg, uid, "alpha-cves", ["CVE-2023-1050"])
    zeta = await seed_archive(pg, uid, "zeta-cves", ["CVE-2023-1050"])
    ps._settings_ctx.set(RUN_SETTINGS)
    cat = catalog(uid, alpha, zeta, search_settings={"prompt.coverageMap": False})
    hits = (await search.search(uid, cat, "CVE-2023-1050")).hits
    assert [h.card.resource_slug for h in hits] == ["alpha-cves"]
    await pg.sql("INSERT INTO tradecraft_curations (id, resource_id, url, blocked, updated_at) VALUES (%s, %s, %s, true, "
                 "now())", f"c-{uuid.uuid4().hex[:10]}", alpha["id"],
                 "https://raw.githubusercontent.com/tc-fixture/alpha-cves/main/2023/CVE-2023-1050.md")
    hits = (await search.search(uid, cat, "CVE-2023-1050")).hits
    assert [h.card.resource_slug for h in hits] == ["zeta-cves"]
    note, _ = await hints.library_now(state("Exploit CVE-2023-1050 to read a file outside the web root"), cat)
    assert [p.split(":")[0] for p, _t in rows_of(note)] == ["zeta-cves"]


async def test_a_listing_the_budget_cuts_keeps_a_whole_index_once_then_goes_live(pg, tmp_path, monkeypatch):
    """Through the real runner and store: a whole index; a refresh the time budget cuts fails with
    timeout and keeps it; the next refresh cut the same way goes live, so no archive is stuck."""
    root = padded_sites(tmp_path)
    uid, rid, gen, _entry = await archive(pg, root)

    def stop(state, started):
        asked = []

        async def should_stop():
            asked.append(1)
            return "time_budget" if len(asked) > 1 else ""
        return should_stop

    async def live_count():
        rows = await pg.sql("SELECT count(*) AS n FROM tradecraft_entries e JOIN user_tradecraft_resources r ON "
                            "r.id = e.resource_id AND e.generation = r.generation WHERE r.id = %s", rid)
        return rows[0]["n"]

    assert await live_count() == FILES
    monkeypatch.setattr(pipeline, "_reading_stop", stop)
    with mock.patch.dict(pipeline_it.FIXTURE, {"secrets": {"github_token": "ghp_fake_token_for_tests",
                                                          "credentials": None}}):
        _u, _r, first, _m = await ingest(pg, root, URL, settings=JSON, uid=uid, rid=rid)
        assert (first["status"], first["error_code"]) == ("failed", "timeout") and await live_count() == FILES
        row = (await pg.sql("SELECT last_error FROM user_tradecraft_resources WHERE id = %s", rid))[0]
        assert row["last_error"] == "timeout"
        _u, _r, second, _m = await ingest(pg, root, URL, settings=JSON, uid=uid, rid=rid)
    assert second["status"] == "succeeded" and await live_count() == 1050

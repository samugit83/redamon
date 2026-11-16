"""Cards, sections and the tree on Postgres (T2.3): page IDs stable across a refresh (R-330),
the search vectors filled by the triggers on every card and section (R-336), and the tree
written with its counts (R-334).

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

from test_tradecraft_ingest_pipeline_integration import ingest, pg  # noqa: E402,F401
from tradecraft_memory_store import PipelineModel, padded_sites  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
LIVE = ("SELECT e.* FROM tradecraft_entries e JOIN user_tradecraft_resources r ON r.id = e.resource_id "
        "AND r.user_id = e.user_id AND e.generation = r.generation WHERE e.resource_id = %s")


async def test_ids_stable_across_refresh(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid, rid, job, _ = await ingest(pg, root, WIKI)
    assert job["status"] == "succeeded"
    first = {r["url"]: r["page_id"] for r in await pg.sql(LIVE, rid)}
    cards_first = {r["url"]: (r["title"], r["breadcrumb"], r["headings"]) for r in await pg.sql(LIVE, rid)}
    _, _, job2, _ = await ingest(pg, root, WIKI, uid=uid, rid=rid, model=PipelineModel(summary="again"))
    assert job2["status"] == "succeeded"
    rows = await pg.sql(LIVE, rid)
    assert {r["generation"] for r in rows} == {2}
    assert {r["url"]: r["page_id"] for r in rows} == first
    assert {r["url"]: (r["title"], r["breadcrumb"], r["headings"]) for r in rows} == cards_first
    # The card pass filled the Live cards: headings and meta descriptions, no text.
    kerberoast = next(r for r in rows if r["url"] == WIKI + "kerberos/kerberoasting/")
    assert kerberoast["breadcrumb"] == ["kerberos"] and kerberoast["title_source"] == "real"
    assert kerberoast["headings"][0] == {"level": 1, "text": "Kerberos: Kerberoasting"}
    assert kerberoast["description_source"] == "meta" and kerberoast["stored_text"] is None
    assert "active_directory" in kerberoast["topics"]


async def test_vectors_filled(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid, rid, job, _ = await ingest(pg, root, WIKI, mode="stored", settings={"fetching.browserEnabled": False})
    assert job["status"] == "succeeded"
    entries = await pg.sql(LIVE, rid)
    assert entries and all(e["search_vector"] is not None for e in entries)
    sections = await pg.sql(
        "SELECT s.* FROM tradecraft_sections s JOIN user_tradecraft_resources r ON r.id = s.resource_id "
        "AND s.generation = r.generation WHERE s.resource_id = %s ORDER BY s.entry_id, s.ord", rid)
    assert sections and all(s["search_vector"] is not None and s["user_id"] == uid for s in sections)
    kerberoast = next(e for e in entries if e["url"] == WIKI + "kerberos/kerberoasting/")
    own = [s for s in sections if s["entry_id"] == kerberoast["id"]]
    assert [s["heading"] for s in own] == ["Kerberos: Kerberoasting", "How it works", "Examples"]
    assert [s["anchor"] for s in own] == ["kerberos-kerberoasting", "how-it-works", "examples"]
    # Stemming reaches the section text: "kerberoasting" is found by "kerberoast".
    hit = await pg.sql("SELECT count(*) AS n FROM tradecraft_sections WHERE resource_id = %s "
                       "AND search_vector @@ to_tsquery('english', 'roasting')", rid)
    assert hit[0]["n"] >= 1


async def test_tree_written_with_counts(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid, rid, job, _ = await ingest(pg, root, WIKI)
    assert job["status"] == "succeeded"
    nodes = await pg.sql(
        "SELECT t.* FROM tradecraft_tree_nodes t JOIN user_tradecraft_resources r ON r.id = t.resource_id "
        "AND t.generation = r.generation WHERE t.resource_id = %s", rid)
    by_path = {n["path"]: n for n in nodes}
    assert by_path["kerberos/"]["page_count"] == 7 and by_path["kerberos/"]["parent_path"] == ""
    assert all(n["user_id"] == uid and n["kind"] == "folder" for n in nodes)

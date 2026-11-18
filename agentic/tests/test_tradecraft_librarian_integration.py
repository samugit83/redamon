"""The librarian on Postgres (T7.3): run inside a tool node of a graph checkpointed by
``AsyncPostgresSaver``, it writes no checkpoint row (TD-12, EX-3); its tools search the real index
and read the stored sections, of the run's owner only.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TypedDict

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

from test_tradecraft_ingest_pipeline_integration import pg  # noqa: E402,F401
from test_tradecraft_librarian_graph import LibrarianModel  # noqa: E402
from test_tradecraft_search_integration import catalog, page, seed  # noqa: E402
from tradecraft import librarian  # noqa: E402

QUOTE = "SELECT count(*) FROM generate_series(1,5000000)"
NEED = "The WAF blocks SLEEP; another way to cause a delay on PostgreSQL"


def pages():
    return [
        page(1, title="PostgreSQL time based", sections=[
            ("Intro", "Notes on PostgreSQL."),
            ("Time based", f"Use a heavy query instead of SLEEP: AND 1=({QUOTE}) causes a measurable delay.")]),
        page(2, title="WAF bypass for SQL", sections=[("Bypass", "Comments get keywords past a WAF filter.")]),
    ]


def model_for(first_page_id):
    return LibrarianModel({
        "shortlist": {"pages": [first_page_id]},
        "judge": {"verdict": "FOUND", "confidence": "high", "also": [],
                  "picks": [{"page": first_page_id, "section": "Time based", "why": "a delay without SLEEP",
                             "quote": QUOTE}]},
    })


class S(TypedDict):
    q: str
    a: str


async def _counts(pool):
    out = {}
    async with pool.connection() as conn:
        for table in ("checkpoints", "checkpoint_writes", "checkpoint_blobs"):
            cur = await conn.execute(f"SELECT thread_id, checkpoint_ns FROM {table}")
            out[table] = [tuple(r) for r in await cur.fetchall()]
    return out


async def test_no_checkpoint_rows(pg):
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    from langgraph.graph import END, START, StateGraph
    from psycopg_pool import AsyncConnectionPool

    uid = await pg.user()
    res = await seed(pg, uid, pages(), slug="patt")
    cat = catalog(uid, res)
    first = (await pg.sql("SELECT p.id FROM tradecraft_page_ids p WHERE p.resource_id = %s AND p.url LIKE %s",
                          res["id"], "%/p1/"))[0]["id"]
    model = model_for(f"patt:{first}")
    answers = []

    async def think(state):
        return {}

    async def tool(state):
        answer = await librarian.ask(librarian.Request(need=state["q"]), owner_id=uid, person_id=uid, catalog=cat,
                                     llm=model)
        answers.append(answer)
        return {"a": librarian.render(answer)}

    pool = AsyncConnectionPool(conninfo=PG_URL, min_size=1, max_size=3,
                               kwargs={"autocommit": True, "prepare_threshold": 0}, open=False)
    await pool.open()
    try:
        saver = AsyncPostgresSaver(pool)
        await saver.setup()
        g = StateGraph(S)
        g.add_node("think", think)
        g.add_node("tool", tool)
        g.add_edge(START, "think")
        g.add_edge("think", "tool")
        g.add_edge("tool", END)
        main = g.compile(checkpointer=saver)
        thread = f"tc-librarian-parent-{uid}"
        before = await _counts(pool)
        result = await main.ainvoke({"q": NEED, "a": ""}, config={"configurable": {"thread_id": thread},
                                                                  "metadata": {"user_id": uid}})
        after = await _counts(pool)
    finally:
        await pool.close()

    answer = answers[0]
    assert answer.verdict == "FOUND" and answer.picks[0].excerpt == QUOTE and answer.model_calls == 2
    assert QUOTE in result["a"]
    for table in ("checkpoints", "checkpoint_writes", "checkpoint_blobs"):
        added = [r for r in after[table] if r not in before[table] or after[table].count(r) > before[table].count(r)]
        # Every row the run added is the main graph's own, in its own namespace.
        assert {t for t, _ns in added} <= {thread}, table
        assert all(ns == "" for _t, ns in added), table
        assert not any(t.startswith("tradecraft-librarian-") for t, _ns in after[table]), table
    assert any(t == thread for t, _ns in after["checkpoints"])
    # The model saw the librarian's own thread, never the parent's.
    assert all(c["configurable"]["thread_id"].startswith("tradecraft-librarian-") for c in model.configs)
    assert all(thread not in repr(c) for c in model.configs)


async def test_the_tools_on_postgres_read_the_owners_library_only(pg):
    owner, other = await pg.user(), await pg.user()
    mine = await seed(pg, owner, pages(), slug="patt")
    theirs = await seed(pg, other, pages(), slug="theirs")
    cat = catalog(owner, mine)
    tools = librarian.LibraryTools(owner, cat)
    found = await tools.search("heavy query delay postgresql")
    assert found.verdict in ("FOUND", "RELATED") and found.cards
    assert all(c.page_id.startswith("patt:") for c in found.cards)
    top = found.cards[0].page_id
    outline = await tools.outline(top)
    assert ("Time based", len(f"Use a heavy query instead of SLEEP: AND 1=({QUOTE}) causes a measurable delay.")) in outline
    assert QUOTE in await tools.read(top, "Time based")
    assert await tools.grep(top, "generate_series") and await tools.grep(top, "nothing like this") == []
    # Another user's page ID, even under a slug of this catalog, is not read.
    foreign = (await pg.sql("SELECT id FROM tradecraft_page_ids WHERE resource_id = %s", theirs["id"]))[0]["id"]
    assert await tools.outline(f"patt:{foreign}") is None and await tools.outline(f"theirs:{foreign}") is None

    answer = await librarian.ask(librarian.Request(need=NEED), owner_id=owner, person_id=owner, catalog=cat,
                                 llm=model_for(top))
    assert answer.verdict == "FOUND" and answer.picks[0].page_id == top
    assert answer.picks[0].breadcrumb[0] == "patt"

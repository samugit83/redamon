"""Library now on Postgres (owner decision 2026-11-17): the block's searches run through the real index
and the page store's pool, with the real scores deciding the threshold; they read only the run
owner's library and only the resources of the run's catalog (R-324), so another account's pages,
a resource the project turned off and a login resource left out of a collaborator's catalog are
never shown; a new goal replaces the block.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

import project_settings as ps  # noqa: E402
from test_tradecraft_ingest_pipeline_integration import pg  # noqa: E402,F401
from test_tradecraft_search_integration import catalog, page, seed  # noqa: E402
from tradecraft.contract import V2Catalog  # noqa: E402
from tradecraft.library import hints  # noqa: E402

RUN_SETTINGS = {"TOOL_PHASE_MAP": {"tradecraft_lookup": ["exploitation", "post_exploitation"]},
                "TRADECRAFT_V2": True, "TRADECRAFT_ASK": True}


def state(goal, **over):
    base = {"session_id": "s-1", "current_objective_index": 0, "attack_path_type": "sql_injection",
            "current_phase": "exploitation", "conversation_objectives": [{"content": "Assess the login form"}],
            "todo_list": [{"id": "t1", "description": goal, "status": "in_progress", "priority": "high"}],
            "target_info": {"technologies": ["PostgreSQL 14"], "vulnerabilities": []}}
    base.update(over)
    return base


def sqli(n, title, **cols):
    return page(n, title=title, **{"topics": ["sql_injection"], "technologies": ["postgresql"], "kinds": ["payloads"],
                                   **cols})


def slugs_of(note):
    return {p.split(":")[0] for p in re.findall(r"^    (\S+:\d+)  ", note or "", flags=re.MULTILINE)}


async def test_the_block_reads_only_the_run_owners_catalog(pg, caplog):
    uid, other = await pg.user(), await pg.user()
    mine = await seed(pg, uid, [
        sqli(1, "PostgreSQL time based blind SQL injection"), sqli(2, "PostgreSQL error based SQL injection"),
        sqli(3, "PostgreSQL stacked queries SQL injection"), sqli(4, "Boolean blind SQL injection on PostgreSQL"),
        page(5, title="Kerberoasting", topics=["active_directory"]),
    ], slug="mine")
    # The same owner's resources the run's catalog leaves out: one turned off in the project, and
    # one with a login that a collaborator's run may not use (the webapp's catalog decides both).
    off = await seed(pg, uid, [sqli(1, "PostgreSQL time based blind SQL injection, turned off")], slug="off")
    login = await seed(pg, uid, [sqli(1, "PostgreSQL time based blind SQL injection, behind a login")], slug="login")
    theirs = await seed(pg, other, [sqli(1, "PostgreSQL time based blind SQL injection, another account")],
                        slug="theirs")
    assert off and login and theirs
    ps._settings_ctx.set(RUN_SETTINGS)
    collaborator = V2Catalog.model_validate({**catalog(uid, mine, search_settings={"prompt.coverageMap": False})
                                            .model_dump(), "person_id": "collaborator-7"})

    with caplog.at_level(logging.INFO):
        note, updates = await hints.library_now(state("Confirm time based blind SQL injection"), collaborator)
        # The decoys hold the goal's exact words in their titles: had they been searched, they would lead.
        assert slugs_of(note) == {"mine"}
        assert "turned off" not in note and "behind a login" not in note and "another account" not in note
        assert "Kerberoasting" not in note
        first = re.findall(r"^    (mine:\d+)  ", note, flags=re.MULTILINE)

        # The owner's own run, with the login resource in its catalog, may see that one too.
        own = catalog(uid, mine, login, search_settings={"prompt.coverageMap": False})
        note_own, _ = await hints.library_now(state("Confirm time based blind SQL injection"), own)
        assert slugs_of(note_own) <= {"mine", "login"} and "turned off" not in note_own

        # A new goal searches again and replaces the block.
        later = {**state("Stacked queries SQL injection on PostgreSQL"), **updates}
        later["todo_list"] = [{"id": "t2", "description": "Stacked queries SQL injection on PostgreSQL",
                               "status": "in_progress", "priority": "high"}]
        note2, updates2 = await hints.library_now(later, collaborator)
    assert note2 and re.findall(r"^    (mine:\d+)  ", note2, flags=re.MULTILINE)[0] != first[0]
    assert "stacked queries" in note2.lower() and updates2["tradecraft_hint_count"] == 2
    assert not [r for r in caplog.records if "[tradecraft] library_now code=" in r.getMessage()]


async def test_a_page_whose_headings_alone_hold_the_steps_words_is_not_shown(pg):
    """FIX-ITER4: a long stored page about one technique, its headings full of planning words, fitted
    any step made of them (the e2e runs showed an SSRF skill page in path traversal, deserialization
    and smuggling steps). It is shown for a step that names its subject in its title, and for no
    step of planning words only."""
    uid = await pg.user()
    planning = ["Payload and detection patterns", "Bypass techniques", "Confirm the request", "Target endpoints",
                "Parameter discovery", "Response header signals"]
    lib = await seed(pg, uid, [
        page(1, title="Hunting request forgery", topics=["ssrf"], headings=[{"level": 2, "text": h} for h in planning],
             sections=[(h, f"{h}: probe the target endpoint, bypass the filter, confirm the payload in the response.")
                       for h in planning]),
        sqli(2, "PostgreSQL time based blind SQL injection"),
    ], slug="lib")
    ps._settings_ctx.set(RUN_SETTINGS)
    cat = catalog(uid, lib, search_settings={"prompt.coverageMap": False})
    planned, _ = await hints.library_now(
        state("Probe the endpoint parameter, bypass the filter and confirm the payload"), cat)
    assert "Hunting request forgery" not in (planned or "")
    named, _ = await hints.library_now(state("Confirm the request forgery through the URL parameter"), cat)
    assert "Hunting request forgery" in (named or "")


async def test_the_real_scores_keep_out_what_does_not_fit(pg):
    uid = await pg.user()
    lib = await seed(pg, uid, [
        sqli(1, "PostgreSQL time based blind SQL injection"),
        # The goal's words only in passing, in a page about something else.
        page(2, title="Kerberoasting", topics=["active_directory"],
             description="Unlike time based blind SQL injection, kerberoasting needs no form."),
    ], slug="lib")
    ps._settings_ctx.set(RUN_SETTINGS)
    cat = catalog(uid, lib, search_settings={"prompt.coverageMap": False})
    note, _ = await hints.library_now(state("Confirm time based blind SQL injection"), cat)
    rows = re.findall(r"^    lib:\d+  (.*)$", note, flags=re.MULTILINE)
    assert "Kerberoasting" not in note and len(rows) == 1 and "PostgreSQL time based blind SQL injection" in rows[0]
    nothing, updates = await hints.library_now(
        {**state("Pivot through the mail relay with an SPF gap"), "current_objective_index": 1,
         "conversation_objectives": [{"content": "x"}, {"content": "y"}]}, cat)
    assert nothing is None and updates["tradecraft_hint_count"] == 0

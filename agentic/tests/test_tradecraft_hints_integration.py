"""Library hints on Postgres (T8.1): the note's searches run at once through the real index and the
page store's pool, name only the run owner's pages (R-324), and a later note never repeats one.

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
from tradecraft.library import hints  # noqa: E402

RUN_SETTINGS = {"TOOL_PHASE_MAP": {"tradecraft_lookup": ["exploitation", "post_exploitation"]},
                "TRADECRAFT_V2": True, "TRADECRAFT_ASK": True}


def state(**over):
    base = {"session_id": "s-1", "current_objective_index": 0, "attack_path_type": "sql_injection",
            "current_phase": "exploitation",
            "conversation_objectives": [{"content": "Find a time-based blind SQL injection on the login form"}],
            "target_info": {"technologies": ["PostgreSQL 14"], "vulnerabilities": []}}
    base.update(over)
    return base


def sqli(n, title, **cols):
    return page(n, title=title, **{"topics": ["sql_injection"], "technologies": ["postgresql"], "kinds": ["payloads"],
                                   **cols})


def pages_of(note, slug):
    return re.findall(rf"^  ({re.escape(slug)}:\d+)$", note or "", flags=re.MULTILINE)


async def test_a_note_from_the_owners_library(pg, caplog):
    uid, other = await pg.user(), await pg.user()
    mine = await seed(pg, uid, [
        sqli(1, "PostgreSQL time based SQL injection"), sqli(2, "PostgreSQL error based SQL injection"),
        sqli(3, "PostgreSQL stacked queries SQL injection"), sqli(4, "PostgreSQL SQL injection out of band"),
        sqli(5, "SQL injection WAF bypass", kinds=["bypasses"]), page(6, title="Kerberoasting", topics=["active_directory"]),
    ], slug="mine")
    theirs = await seed(pg, other, [sqli(1, "PostgreSQL time based SQL injection, another account")], slug="theirs")
    cat = catalog(uid, mine, search_settings={"prompt.coverageMap": False})
    ps._settings_ctx.set(RUN_SETTINGS)

    with caplog.at_level(logging.WARNING):
        note, updates = await hints.maybe_hint(state(), cat)
        first = pages_of(note, "mine")
        assert note.startswith("Library suggestions (SQL injection · PostgreSQL):") and len(first) == 3
        assert "theirs" not in note and "another account" not in note and "Kerberoasting" not in note

        # A block, a CVE and a phase change at once: up to six searches together on the pool.
        later = {**state(), **updates, "current_phase": "post_exploitation",
                 "target_info": {"technologies": ["PostgreSQL 14"], "vulnerabilities": ["CVE-2024-1111"]},
                 "_current_step": {"step_id": "st-1", "tool_name": "execute_curl",
                                   "tool_output": "HTTP/1.1 403 Forbidden"}}
        assert len(hints.queries_for(*_profiles(later, updates))) >= 4
        note2, updates2 = await hints.maybe_hint(later, cat)
    second = pages_of(note2, "mine")
    assert second and not set(second) & set(first) and updates2["tradecraft_hint_count"] == 2
    assert "SQL injection WAF bypass" in note2 and "theirs" not in note2
    assert not [r for r in caplog.records if "[tradecraft] hint code=" in r.getMessage()]


def _profiles(st, updates):
    from tradecraft.library import profile

    previous = profile.Profile.from_log(next(e for e in updates["tradecraft_hint_log"] if e.get("kind") == "profile"))
    current = profile.build(st, previous)
    return current, previous, profile.checkpoints(previous, current)

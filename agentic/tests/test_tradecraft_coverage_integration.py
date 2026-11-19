"""The coverage counts on Postgres (T5.4, AC-72): they equal the tagged kept pages of the run's
resources, live generation only, for the owner's run and for a collaborator's (whose catalog the
webapp narrowed), never another user's; a statement past its timeout leaves the run without a map.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

from test_tradecraft_ingest_pipeline_integration import pg  # noqa: E402,F401
from test_tradecraft_search_integration import page, seed  # noqa: E402
from tradecraft.contract import V2Catalog  # noqa: E402
from tradecraft.library import coverage  # noqa: E402


def tagged(n, topics, kinds=(), techs=(), **cols):
    return page(n, topics=list(topics), kinds=list(kinds), technologies=list(techs), **cols)


def run_catalog(owner, person, resources):
    return V2Catalog.model_validate({"v2": True, "owner_id": owner, "person_id": person, "actor_id": None,
                                     "search": {}, "resources": resources})


async def counts(cat):
    # The binding runs the query synchronously; here off the test's event loop.
    return await asyncio.to_thread(coverage.coverage_for, cat)


async def test_counts_match_the_data_for_owner_and_collaborator(pg):
    owner, collaborator, stranger = await pg.user(), await pg.user(), await pg.user()
    wiki = await seed(pg, owner, [
        tagged(1, ["sql_injection"], ["payloads"], ["postgresql"]),
        tagged(2, ["sql_injection"], ["payloads", "bypasses"], ["postgresql", "mssql"]),
        tagged(3, ["sql_injection", "xss"], ["techniques"]),
        tagged(4, [], []),
        tagged(5, ["xss"], ["payloads"], status="dropped", drop_reason="outside the focus"),
    ], slug="wiki", generation=2)
    # An older generation of the same resource is not counted.
    await seed(pg, owner, [tagged(9, ["rce"], ["poc"])], rid=wiki["id"], generation=1)
    repo = await seed(pg, owner, [tagged(1, ["active_directory"], ["tool_commands"], ["windows"])], slug="repo")
    # Another user's resource with the same tags is never counted.
    await seed(pg, stranger, [tagged(1, ["sql_injection"], ["payloads"])], slug="theirs")
    cve = {"id": "tc-r-cve", "slug": "cves", "name": "CVES", "url": "https://cves.tc-fixture.test/",
           "type": "cve-poc-db", "storage_mode": "live", "map_version": 3}

    own = await counts(run_catalog(owner, owner, [wiki, repo, cve]))
    assert own["pages"] == 5
    assert {r["slug"]: r["pages"] for r in own["resources"]} == {"wiki": 4, "repo": 1, "cves": 0}
    sqli = own["topics"]["sql_injection"]
    assert sqli == {"pages": 3, "kinds": {"payloads": 2, "bypasses": 1, "techniques": 1},
                    "technologies": {"postgresql": 2, "mssql": 1}}
    assert own["topics"]["xss"]["pages"] == 1 and own["topics"]["active_directory"]["pages"] == 1
    assert "rce" not in own["topics"]
    text = coverage.render_map(own)
    assert " SQL injection: 3 pages · payloads 2, bypasses 1 · PostgreSQL, MSSQL" in text
    not_covered = next(ln for ln in text.splitlines() if ln.startswith(" Not covered:"))
    assert " CVE archive cves · look up by CVE ID" in text and "RCE" in not_covered and "XSS" not in not_covered

    # A collaborator's run: the webapp's catalog lists only what that person may use.
    theirs = await counts(run_catalog(owner, collaborator, [repo]))
    assert theirs["pages"] == 1 and set(theirs["topics"]) == {"active_directory"}


async def test_a_slow_statement_leaves_no_map(pg, monkeypatch):
    owner = await pg.user()
    res = await seed(pg, owner, [tagged(1, ["xss"])], slug="slow")
    monkeypatch.setattr(coverage, "COVERAGE_SQL", "SELECT pg_sleep(10), %(uid)s::text AS a, %(rids)s::text[] AS b")
    started = time.monotonic()
    assert await counts(run_catalog(owner, owner, [res])) is None
    assert time.monotonic() - started < 6

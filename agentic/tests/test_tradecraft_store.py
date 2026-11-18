"""The page store's rules, on a fake connection (T1.4).

Every statement is keyed by the owner (and the resource), reads take the live generation,
writes set ``updated_at``, the swap's transaction touches only the resource and the job,
and the pool is the small one on ``DATABASE_URL``. The same behaviours on a real Postgres:
``test_tradecraft_store_integration.py``.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import db, store  # noqa: E402
from tradecraft import schema_columns as sc  # noqa: E402
from tradecraft import settings as tc_settings  # noqa: E402
from tradecraft.store import STATEMENTS, UNKEYED_STATEMENTS, Store  # noqa: E402

STORE_SOURCE = Path(store.__file__).read_text(encoding="utf-8")
WHEN = datetime(2026, 1, 1, tzinfo=timezone.utc)
CONTENT_TABLES = (sc.TABLE_ENTRIES, sc.TABLE_SECTIONS, sc.TABLE_TREE, sc.TABLE_PAGE_IDS)


# --------------------------------------------------------------------------------------
# A fake connection: records every statement with the transaction it ran in
# --------------------------------------------------------------------------------------

class FakeCursor:
    def __init__(self, rows, rowcount):
        self._rows = list(rows)
        self.rowcount = rowcount

    async def fetchone(self):
        return self._rows[0] if self._rows else None

    async def fetchall(self):
        return list(self._rows)


class FakeDb:
    """``answer(name, params)`` -> (rows, rowcount) for the statement named ``name``."""

    def __init__(self, answer=None):
        self.answer = answer or (lambda name, params: ([], 0))
        self.executed: list[tuple[int, str, str, dict]] = []
        self.transactions = 0

    @staticmethod
    def name_of(sql: str) -> str:
        for name, text in STATEMENTS.items():
            if sql == text:
                return name
            if "{sets}" in text and sql.startswith(text.split("{sets}")[0]):
                return name
        raise AssertionError(f"a statement that is not in STATEMENTS ran: {sql[:80]}")

    @contextlib.asynccontextmanager
    async def connect(self):
        self.transactions += 1
        tx = self.transactions
        outer = self

        class Conn:
            async def execute(self, sql, params=None):
                name = outer.name_of(sql)
                outer.executed.append((tx, name, sql, dict(params or {})))
                rows, count = outer.answer(name, params or {})
                return FakeCursor(rows, count)

        yield Conn()

    def names(self):
        return [n for _tx, n, _sql, _p in self.executed]


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------------------
# Static rules over the statements
# --------------------------------------------------------------------------------------

def test_every_statement_names_user_id_except_the_unkeyed_ones():
    unkeyed = []
    for name, sql in STATEMENTS.items():
        keyed = re.search(r"\buser_id = %\(uid\)s", sql) or re.search(r"\buser_id = h\.user_id\b", sql)
        if not keyed:
            unkeyed.append(name)
    assert sorted(unkeyed) == sorted(UNKEYED_STATEMENTS)


def test_only_the_install_total_and_the_boot_scan_are_unkeyed():
    assert set(UNKEYED_STATEMENTS) == {"instance_stored_bytes", "expired_jobs"}
    # The install total returns one number, never a row of a user.
    assert re.fullmatch(r"SELECT COALESCE\(sum\(e\.stored_bytes\), 0\)::bigint AS total FROM .*",
                        STATEMENTS["instance_stored_bytes"])
    # The boot scan writes each job by id and owner after finding it.
    assert "j.id = x.id AND j.user_id = x.user_id" in STATEMENTS["expired_jobs"]
    assert "r.id = f.resource_id AND r.user_id = f.user_id" in STATEMENTS["expired_jobs"]


def test_every_execute_runs_a_named_statement():
    """No SQL is written inline: every execute takes a STATEMENTS entry, so the scans above
    see every statement the module can run."""
    calls = [n for n in ast.walk(ast.parse(STORE_SOURCE))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"]
    assert calls
    for call in calls:
        arg = call.args[0]
        if isinstance(arg, ast.Call):  # STATEMENTS["swap_resource"].replace("{sets}", sets)
            arg = arg.func.value
        assert isinstance(arg, ast.Subscript) and getattr(arg.value, "id", "") == "STATEMENTS", ast.dump(call)


def test_no_statement_reads_a_secret_column():
    for name, sql in STATEMENTS.items():
        for column in sc.RESOURCE_SECRET_COLUMNS:
            assert not re.search(rf"\b{column}\b", sql), name
    assert not set(store.SWAP_COLUMNS) & set(sc.RESOURCE_SECRET_COLUMNS)


def test_reads_take_the_live_generation():
    for name in ("entry_by_url", "entry_by_page_id", "in_map", "user_stored_bytes", "instance_stored_bytes"):
        assert "e.generation = r.generation" in STATEMENTS[name], name
    # Nothing a reader runs names a generation of its own choosing.
    for name in ("entry_by_url", "entry_by_page_id", "in_map", "resource", "curation"):
        assert "%(gen)s" not in STATEMENTS[name], name


def test_every_update_sets_updated_at():
    updates = 0
    for name, sql in STATEMENTS.items():
        # One "updated_at = now()" per UPDATE (the boot scan's CTE holds two).
        n = len(re.findall(r"\bUPDATE \w+(?: \w+)? SET ", sql))
        updates += n
        assert sql.count("updated_at = now()") >= n, name
    assert updates >= 12


def test_every_column_named_exists_in_the_schema_constants():
    known = set()
    for cols in sc.COLUMNS.values():
        known.update(cols)
    for name, _kind, _default in store.ENTRY_WRITE:
        assert name in sc.ENTRIES
    for name, _kind, _default in store.SECTION_WRITE:
        assert name in sc.SECTIONS
    for name, _kind, _default in store.TREE_WRITE:
        assert name in sc.TREE
    for column in store.SWAP_COLUMNS:
        assert column in sc.RESOURCES
    assert set(store.RESOURCE_ROW) <= set(sc.RESOURCES)


def test_purge_spares_the_live_generation_and_a_running_job_target():
    for name in ("purge_sections", "purge_tree", "purge_entries"):
        sql = STATEMENTS[name]
        assert "x.generation <> r.generation" in sql
        assert "j.target_generation = x.generation" in sql
        assert "LIMIT %(batch)s" in sql
    for name in ("discard_sections", "discard_tree", "discard_entries"):
        assert "x.generation <> r.generation" in STATEMENTS[name]


def test_a_job_ended_without_a_swap_records_the_1x_error_state():
    """M1 (TD-18, D-25): every end without a swap writes last_error and last_verified_at in one
    statement, as 1.x does after a verify, so a 1.x tab never shows "verifying..." for it."""
    assert "last_error = %(code)s, last_verified_at = %(at)s" in STATEMENTS["set_last_error"]
    never = STATEMENTS["set_error_if_never_verified"]
    assert "last_error = %(code)s, last_verified_at = %(at)s" in never and never.endswith("AND last_verified_at IS NULL")
    # A job that never reached the site keeps the time of the last real verify (1.x's rule
    # when its agent call fails) and sets one only on a resource never verified.
    assert "last_error = %(code)s, last_verified_at = COALESCE(last_verified_at, %(at)s)" in \
        STATEMENTS["set_error_without_fetch"]
    released = STATEMENTS["expired_jobs"].split("released AS")[1]
    assert "active_job_id = NULL, last_error = %(code)s, last_verified_at = COALESCE(r.last_verified_at, %(now)s)" in released


# --------------------------------------------------------------------------------------
# The pool
# --------------------------------------------------------------------------------------

def test_pool_cap():
    assert db.MAX_SIZE == 5 == tc_settings.constant("dbPoolSize")

    async def go():
        p = db.pool()
        try:
            assert p.max_size == 5 and p.min_size == 0
        finally:
            db.reset()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DATABASE_URL", "postgresql://u:p@db.invalid:5432/x")
        run(go())


def test_pool_uses_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@pg.invalid:5432/redamon")

    async def go():
        p = db.pool()
        try:
            assert p.conninfo == "postgresql://u:p@pg.invalid:5432/redamon"
            assert p.kwargs["autocommit"] is False
            # Prisma's DateTime columns hold UTC without a time zone.
            assert "-c TimeZone=UTC" in p.kwargs["options"]
            # Opened lazily: nothing connects until the first statement.
            assert p.closed
        finally:
            db.reset()

    run(go())


def test_no_database_url_refuses(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    async def go():
        db.reset()
        with pytest.raises(db.StoreUnavailable):
            db.pool()

    run(go())


def test_one_pool_per_event_loop(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@pg.invalid:5432/redamon")

    async def same_loop():
        return db.pool() is db.pool()

    try:
        assert run(same_loop())
        first = None

        async def remember():
            nonlocal first
            first = db.pool()

        run(remember())

        async def other():
            return db.pool() is not first

        assert run(other())
    finally:
        db.reset()


# --------------------------------------------------------------------------------------
# The swap
# --------------------------------------------------------------------------------------

def _resource_row(url="https://wiki.tc-fixture.test/", mode="stored", job="job-1"):
    return {"url": url, "storage_mode": mode, "active_job_id": job}


def test_swap_touches_only_resource_and_job():
    fake = FakeDb(lambda name, p: ([_resource_row()], 1) if name == "swap_lock" else ([], 1))
    answer = run(Store(fake.connect).swap(
        "u1", "r1", "job-1", 4, "https://wiki.tc-fixture.test/", "stored",
        {"summary": "s", "sitemap": {"pages": []}, "map_version": 3, "last_refreshed_at": WHEN}))
    assert answer == "swapped"
    assert fake.transactions == 1
    assert fake.names() == ["swap_lock", "swap_resource", "swap_job"]
    for _tx, _name, sql, _params in fake.executed:
        for table in CONTENT_TABLES:
            assert table not in sql
    swap_sql = fake.executed[1][2]
    assert "generation = %(gen)s" in swap_sql and "active_job_id = NULL" in swap_sql
    assert "summary = %(u_summary)s::text" in swap_sql and "sitemap = %(u_sitemap)s::jsonb" in swap_sql
    assert fake.executed[1][3]["u_sitemap"] == '{"pages":[]}'


@pytest.mark.parametrize("row,expected", [
    (None, "gone"),
    (_resource_row(job="job-2"), "lost"),
    (_resource_row(url="https://elsewhere.tc-fixture.test/"), "changed"),
    (_resource_row(mode="live"), "changed"),
])
def test_swap_writes_nothing_unless_the_row_still_matches(row, expected):
    fake = FakeDb(lambda name, p: ([row] if row else [], 1))
    answer = run(Store(fake.connect).swap("u1", "r1", "job-1", 4, "https://wiki.tc-fixture.test/", "stored", {}))
    assert answer == expected
    assert fake.names() == ["swap_lock"]


@pytest.mark.parametrize("flags", [{"summary_locked": True}, {"summary_source": "manual"}])
def test_swap_keeps_a_summary_the_row_protects(flags):
    """Finding A: the lock and the source are read from the row under the swap's lock, not from
    the job's copy taken when it started."""
    row = {**_resource_row(), "summary_locked": False, "summary_source": "generated", **flags}
    fake = FakeDb(lambda name, p: ([row], 1) if name == "swap_lock" else ([], 1))
    answer = run(Store(fake.connect).swap("u1", "r1", "job-1", 4, "https://wiki.tc-fixture.test/", "stored",
                                          {"summary": "generated", "summary_source": "generated", "map_version": 3}))
    assert answer == "swapped"
    sql, params = fake.executed[1][2], fake.executed[1][3]
    assert "summary =" not in sql and "summary_source =" not in sql and "u_summary" not in params
    assert "map_version = %(u_map_version)s::int" in sql
    assert "summary_locked, summary_source" in fake.executed[0][2]


def test_swap_refuses_a_column_outside_its_list():
    fake = FakeDb()
    for column in ("credentials", "github_token_override", "active_job_id", "user_id", "url"):
        with pytest.raises(ValueError):
            run(Store(fake.connect).swap("u1", "r1", "job-1", 4, "u", "live", {column: "x"}))
    assert fake.executed == []


# --------------------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("row,expected", [
    (None, True),                                           # the resource (and its job) was deleted
    ({"cancel_requested": True, "status": "running"}, True),
    ({"cancel_requested": False, "status": "failed"}, True),  # a takeover failed it
    ({"cancel_requested": False, "status": "running"}, False),
    ({"cancel_requested": False, "status": "queued"}, False),
])
def test_cancel_requested(row, expected):
    fake = FakeDb(lambda name, p: ([row] if row else [], 1 if row else 0))
    assert run(Store(fake.connect).cancel_requested("u1", "job-1")) is expected


def test_finish_releases_the_claim_in_the_same_transaction():
    fake = FakeDb(lambda name, p: ([], 1))
    assert run(Store(fake.connect).finish_job("u1", "job-1", "failed", "fetch_failed")) is True
    assert fake.names() == ["finish_job", "release_claim"]
    assert {tx for tx, *_ in fake.executed} == {1}
    assert fake.executed[0][3] == {"uid": "u1", "job": "job-1", "status": "failed", "code": "fetch_failed"}


def test_renew_leases_names_each_owner():
    fake = FakeDb(lambda name, p: ([{"id": "j1"}], 1))
    renewed = run(Store(fake.connect).renew_leases("inst", WHEN, [("u1", "j1"), ("u2", "j2")]))
    assert renewed == {"j1"}
    params = fake.executed[0][3]
    assert params["uids"] == ["u1", "u2"] and params["jobs"] == ["j1", "j2"] and params["instance"] == "inst"
    assert run(Store(FakeDb().connect).renew_leases("inst", WHEN, [])) == set()


def test_progress_is_stored_as_json_counts():
    fake = FakeDb(lambda name, p: ([], 1))
    run(Store(fake.connect).set_job_stage("u1", "j1", "build_map", {"done": 3, "total": 10, "unit": "pages"}))
    assert fake.executed[0][3]["progress"] == '{"done":3,"total":10,"unit":"pages"}'


# --------------------------------------------------------------------------------------
# Bulk writes and the purge
# --------------------------------------------------------------------------------------

def test_rows_get_every_column_with_defaults():
    rows = store._rows_for(store.ENTRY_WRITE, [{"page_id": 1, "url": "https://x.tc-fixture.test/a"}])
    assert rows[0]["title"] == "" and rows[0]["status"] == "kept" and rows[0]["topics"] == []
    assert rows[0]["stored_text"] is None and rows[0]["title_source"] == "guessed"
    assert set(rows[0]) == {n for n, _k, _d in store.ENTRY_WRITE}
    with pytest.raises(ValueError):
        store._rows_for(store.ENTRY_WRITE, [{"url": "https://x.tc-fixture.test/a"}])
    with pytest.raises(ValueError):
        store._rows_for(store.ENTRY_WRITE, [{"page_id": 1, "url": "u", "user_id": "someone-else"}])


def test_nul_characters_are_removed():
    assert store._clean({"a": ["x\x00y"], "b": "\x00"}) == {"a": ["xy"], "b": ""}
    assert "\\u0000" not in store._json({"t": "a\x00b"})


def test_batches_split_by_rows_and_bytes():
    rows = [{"stored_text": "x"} for _ in range(1200)]
    assert [len(b) for b in store._batches(rows)] == [500, 500, 200]
    big = [{"stored_text": "x" * (3 * 1024 * 1024)} for _ in range(5)]
    assert [len(b) for b in store._batches(big)] == [2, 2, 1]


def test_write_entries_maps_page_ids_to_entry_ids():
    def answer(name, params):
        import json
        rows = json.loads(params["rows"])
        return ([{"id": 100 + r["page_id"], "page_id": r["page_id"]} for r in rows], len(rows))

    fake = FakeDb(answer)
    out = run(Store(fake.connect).write_entries("u1", "r1", 3, [
        {"page_id": 1, "url": "https://x.tc-fixture.test/a"}, {"page_id": 2, "url": "https://x.tc-fixture.test/b"}]))
    assert out == {1: 101, 2: 102}
    assert fake.executed[0][3]["gen"] == 3 and fake.executed[0][3]["uid"] == "u1"


def test_write_after_delete_raises_resource_gone():
    fake = FakeDb(lambda name, p: ([], 0))
    with pytest.raises(store.ResourceGone):
        run(Store(fake.connect).write_entries("u1", "r1", 3, [{"page_id": 1, "url": "u"}]))
    with pytest.raises(store.ResourceGone):
        run(Store(fake.connect).allocate_page_ids("u1", "r1", ["u"]))


def test_purge_runs_in_batches_each_its_own_transaction():
    counts = {"purge_sections": [3, 3, 1], "purge_tree": [0], "purge_entries": [3, 2]}

    def answer(name, params):
        assert params["batch"] == 3
        return ([], counts[name].pop(0))

    fake = FakeDb(answer)
    deleted = run(Store(fake.connect).purge_old_generations("u1", "r1", batch=3))
    assert deleted == 3 + 3 + 1 + 0 + 3 + 2
    assert fake.names() == ["purge_sections"] * 3 + ["purge_tree"] + ["purge_entries"] * 2
    # One transaction per statement: no transaction holds the resource row across batches.
    assert [tx for tx, *_ in fake.executed] == list(range(1, 7))


def test_default_purge_batch_is_the_constant():
    assert store.PURGE_BATCH == 5000 == tc_settings.constant("purgeBatchRows")


def test_discarding_generation_zero_does_nothing():
    fake = FakeDb()
    assert run(Store(fake.connect).discard_generation("u1", "r1", 0)) == 0
    assert fake.executed == []


# --------------------------------------------------------------------------------------
# Every public method, run on the fake: each statement it sends is keyed
# --------------------------------------------------------------------------------------

def test_every_method_sends_only_keyed_statements():
    def answer(name, params):
        if name == "swap_lock":
            return ([_resource_row()], 1)
        if name in ("page_ids_for_urls",):
            return ([{"id": 1, "url": "u"}], 1)
        if name.startswith("write_"):
            import json
            rows = json.loads(params["rows"])
            return ([{"id": i + 1, "page_id": r.get("page_id", 0)} for i, r in enumerate(rows)], len(rows))
        if name.endswith("stored_bytes"):
            return ([{"total": 7}], 1)
        if name == "begin_generation":
            return ([{"target_generation": 2}], 1)
        return ([], 0)

    fake = FakeDb(answer)
    s = Store(fake.connect)

    async def everything():
        await s.accept_job("u1", "j", "inst", WHEN)
        await s.claim_job_for_run("u1", "j", "inst", WHEN)
        await s.renew_leases("inst", WHEN, [("u1", "j")])
        await s.cancel_requested("u1", "j")
        await s.request_cancel("u1", "j")
        await s.request_cancel_user("u1")
        await s.set_job_stage("u1", "j", "detect", None)
        await s.finish_job("u1", "j", "succeeded")
        await s.begin_generation("u1", "r1", "j")
        await s.resource("u1", "r1")
        await s.legacy_sitemap("u1", "r1")
        await s.set_last_error("u1", "r1", "j", "fetch_failed", WHEN)
        await s.set_error_if_never_verified("u1", "r1", "j", "cancelled", WHEN)
        await s.set_error_without_fetch("u1", "r1", "j", "queue_full", WHEN)
        await s.swap("u1", "r1", "job-1", 2, "https://wiki.tc-fixture.test/", "stored", {"summary": "x"})
        await s.allocate_page_ids("u1", "r1", ["u"])
        await s.write_entries("u1", "r1", 2, [{"page_id": 1, "url": "u"}])
        await s.write_sections("u1", "r1", 2, [{"entry_id": 1, "ord": 0, "level": 1, "text": "t"}])
        await s.write_tree("u1", "r1", 2, [{"path": "a", "parent_path": "", "label": "A"}])
        await s.user_stored_bytes("u1")
        await s.purge_old_generations("u1", "r1")
        await s.discard_generation("u1", "r1", 2)
        await s.entry_by_url("u1", "r1", "u")
        await s.entry_by_page_id("u1", 1)
        await s.in_map("u1", "r1", "u")
        await s.curation("u1", "r1", "u")
        await s.lookup_page_id("u1", 1)
        await s.min_page_id("u1", "r1")

    run(everything())
    for _tx, name, _sql, params in fake.executed:
        assert params.get("uid") == "u1" or params.get("uids") == ["u1"], name

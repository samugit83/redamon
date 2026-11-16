"""The page store: every read and write of the tradecraft tables the agent makes (TD-5).

Rules every statement here follows, held by ``tests/test_tradecraft_store.py``:

- It is keyed by the owner (``user_id``) and, where a resource is involved, by the resource.
  Two statements are not, by nature, and are named in ``UNKEYED_STATEMENTS``: the install's
  stored-bytes total (OQ-26, a number) and the boot-recovery scan of expired leases, which
  must find the jobs of every user and then writes each one by its id and owner.
- Reads of entries, sections and the tree join the resource row's live ``generation``; only
  the job writing its own generation names one.
- Writes set ``updated_at = now()`` themselves: Prisma's ``@updatedAt`` is client-side (D-30).
- The swap's transaction touches the resource row and the job row only. The rows of other
  generations are deleted afterwards in keyed batches, each its own transaction, so no
  transaction holds the resource row while thousands of rows go (D-51).
- No statement selects a secret column (``schema_columns.RESOURCE_SECRET_COLUMNS``).

Values only travel as parameters; table and column names come from ``schema_columns``.
JSON travels as text cast to ``jsonb``, so this module needs no driver import.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, AsyncContextManager, Callable, Iterable, Mapping, Optional, Sequence

from tradecraft import db
from tradecraft import schema_columns as sc
from tradecraft import settings as _settings
from tradecraft.library.page_ids import PageIdRow

R, J, P, E, S, T, C = (sc.TABLE_RESOURCES, sc.TABLE_JOBS, sc.TABLE_PAGE_IDS, sc.TABLE_ENTRIES,
                       sc.TABLE_SECTIONS, sc.TABLE_TREE, sc.TABLE_CURATIONS)

PURGE_BATCH = _settings.constant("purgeBatchRows")
UNFINISHED = "('queued','running')"

# The resource columns a reader gets: no secret, and no 1.x map (legacy_sitemap reads it).
RESOURCE_ROW = tuple(c for c in sc.RESOURCES if c != "sitemap")
ENTRY_ROW = tuple(c for c in sc.ENTRIES if c != "search_vector")

# What a swap may write on the resource row besides the generation and the claim. JSON
# columns are cast; anything else in `updates` is refused, a secret column above all.
SWAP_COLUMNS = {
    "summary": "text", "summary_source": "text", "sitemap": "jsonb", "resource_type": "text",
    "crawl_stopped_because": "text", "crawl_stats": "jsonb", "last_error": "text",
    "last_verified_at": "timestamptz", "last_refreshed_at": "timestamptz",
    "settings_snapshot": "jsonb", "settings_hash": "text", "ingestion_report": "jsonb",
    "map_version": "int", "legacy_map_hash": "text",
}

# Columns of a bulk write: name, SQL type, and the value a row that omits it gets. Every
# column is written (jsonb_to_recordset gives NULL for a missing key, and the NOT NULL
# columns' database defaults apply only to columns an INSERT leaves out); REQUIRED ones
# must be in each row. JSON arrays become text[] columns.
REQUIRED = object()
ENTRY_WRITE = (
    ("page_id", "int", REQUIRED), ("url", "text", REQUIRED), ("title", "text", ""),
    ("title_source", "text", "guessed"), ("breadcrumb", "text[]", []), ("headings", "jsonb", []),
    ("description", "text", ""), ("description_source", "text", ""), ("source", "text", ""),
    ("status", "text", "kept"), ("drop_reason", "text", ""), ("topics", "text[]", []), ("kinds", "text[]", []),
    ("technologies", "text[]", []), ("entities", "text[]", []), ("size_chars", "int", 0),
    ("stored_text", "text", None), ("stored_bytes", "int", 0), ("text_hash", "text", ""), ("etag", "text", ""),
    ("last_modified", "text", ""), ("fetched_at", "timestamptz", None),
)
SECTION_WRITE = (
    ("entry_id", "bigint", REQUIRED), ("ord", "int", REQUIRED), ("heading", "text", ""),
    ("level", "int", REQUIRED), ("anchor", "text", ""), ("text", "text", REQUIRED), ("chars", "int", 0),
)
TREE_WRITE = (
    ("path", "text", REQUIRED), ("parent_path", "text", REQUIRED), ("label", "text", REQUIRED),
    ("page_count", "int", 0), ("description", "text", ""), ("kind", "text", "folder"),
)
# Rows per bulk statement, and a byte budget so a batch of large stored pages stays small.
WRITE_BATCH_ROWS = 500
WRITE_BATCH_BYTES = 8 * 1024 * 1024
PAGE_ID_BATCH = 5000


def _cols(cols: Iterable[str], alias: str) -> str:
    return ", ".join(f"{alias}.{c}" for c in cols)


def _recordset(spec: Sequence[tuple[str, str, Any]]) -> str:
    return ", ".join(f"{name} {kind}" for name, kind, _ in spec)


def _names(spec: Sequence[tuple[str, str, Any]]) -> list[str]:
    return [name for name, _, _ in spec]


def _live(alias: str) -> str:
    """The join that keeps only the live generation of the row's own resource and owner."""
    return f"JOIN {R} r ON r.id = {alias}.resource_id AND r.user_id = {alias}.user_id AND {alias}.generation = r.generation"


def _claim(job: str) -> str:
    """A resource job holds the resource's claim (a user-level job has none)."""
    return (f"({job}.resource_id IS NULL OR EXISTS (SELECT 1 FROM {R} rc WHERE rc.id = {job}.resource_id "
            f"AND rc.user_id = {job}.user_id AND rc.active_job_id = {job}.id))")


def _purge(table: str) -> str:
    # Rows of a generation that is neither live nor the target of the resource's unfinished
    # job (a refresh writing its own generation while an earlier purge still runs).
    return (
        f"DELETE FROM {table} WHERE id IN (SELECT x.id FROM {table} x JOIN {R} r ON r.id = x.resource_id "
        f"AND r.user_id = x.user_id WHERE x.user_id = %(uid)s AND x.resource_id = %(rid)s "
        f"AND x.generation <> r.generation AND NOT EXISTS (SELECT 1 FROM {J} j WHERE j.resource_id = x.resource_id "
        f"AND j.user_id = x.user_id AND j.status IN {UNFINISHED} AND j.target_generation = x.generation) "
        f"LIMIT %(batch)s)"
    )


def _discard(table: str) -> str:
    return (
        f"DELETE FROM {table} WHERE id IN (SELECT x.id FROM {table} x JOIN {R} r ON r.id = x.resource_id "
        f"AND r.user_id = x.user_id WHERE x.user_id = %(uid)s AND x.resource_id = %(rid)s "
        f"AND x.generation = %(gen)s AND x.generation <> r.generation LIMIT %(batch)s)"
    )


STATEMENTS: dict[str, str] = {
    # --- jobs --------------------------------------------------------------------------
    "accept_job": (
        f"UPDATE {J} j SET owner_instance = %(instance)s, lease_until = %(until)s, updated_at = now() "
        f"WHERE j.id = %(job)s AND j.user_id = %(uid)s AND j.status = 'queued' AND {_claim('j')}"
    ),
    "claim_job_for_run": (
        f"UPDATE {J} j SET status = 'running', started_at = now(), lease_until = %(until)s, updated_at = now() "
        f"WHERE j.id = %(job)s AND j.user_id = %(uid)s AND j.status = 'queued' "
        f"AND j.owner_instance = %(instance)s AND {_claim('j')}"
    ),
    "renew_leases": (
        f"UPDATE {J} j SET lease_until = %(until)s, updated_at = now() "
        f"FROM unnest(%(uids)s::text[], %(jobs)s::text[]) AS h(user_id, id) "
        f"WHERE j.id = h.id AND j.user_id = h.user_id AND j.owner_instance = %(instance)s "
        f"AND j.status IN {UNFINISHED} RETURNING j.id"
    ),
    "cancel_requested": (
        f"SELECT cancel_requested, status FROM {J} WHERE id = %(job)s AND user_id = %(uid)s"
    ),
    "request_cancel": (
        f"UPDATE {J} SET cancel_requested = true, updated_at = now() "
        f"WHERE id = %(job)s AND user_id = %(uid)s AND status IN {UNFINISHED}"
    ),
    "request_cancel_user": (
        f"UPDATE {J} SET cancel_requested = true, updated_at = now() "
        f"WHERE user_id = %(uid)s AND status IN {UNFINISHED} RETURNING id"
    ),
    "set_job_stage": (
        f"UPDATE {J} SET stage = %(stage)s, progress = %(progress)s::jsonb, updated_at = now() "
        f"WHERE id = %(job)s AND user_id = %(uid)s AND status = 'running'"
    ),
    "finish_job": (
        f"UPDATE {J} SET status = %(status)s, error_code = %(code)s, finished_at = now(), lease_until = NULL, "
        f"updated_at = now() WHERE id = %(job)s AND user_id = %(uid)s AND status IN {UNFINISHED}"
    ),
    "release_claim": (
        f"UPDATE {R} SET active_job_id = NULL, updated_at = now() "
        f"WHERE user_id = %(uid)s AND active_job_id = %(job)s"
    ),
    "expired_jobs": (
        f"WITH expired AS (SELECT id, user_id FROM {J} WHERE status IN {UNFINISHED} "
        f"AND (lease_until IS NULL OR lease_until < %(now)s) ORDER BY id FOR UPDATE SKIP LOCKED), "
        f"failed AS (UPDATE {J} j SET status = 'failed', error_code = %(code)s, finished_at = now(), "
        f"lease_until = NULL, updated_at = now() FROM expired x WHERE j.id = x.id AND j.user_id = x.user_id "
        f"RETURNING j.id, j.user_id, j.resource_id, j.target_generation), "
        f"released AS (UPDATE {R} r SET active_job_id = NULL, last_error = %(code)s, "
        f"last_verified_at = COALESCE(r.last_verified_at, %(now)s), "
        f"updated_at = now() FROM failed f "
        f"WHERE r.id = f.resource_id AND r.user_id = f.user_id AND r.active_job_id = f.id RETURNING r.id) "
        f"SELECT id, user_id, resource_id, target_generation FROM failed ORDER BY id"
    ),
    "begin_generation": (
        f"UPDATE {J} j SET target_generation = GREATEST(r.generation, "
        f"COALESCE((SELECT max(j2.target_generation) FROM {J} j2 WHERE j2.user_id = r.user_id AND j2.resource_id = r.id), 0), "
        f"COALESCE((SELECT max(e.generation) FROM {E} e WHERE e.user_id = r.user_id AND e.resource_id = r.id), 0), "
        f"COALESCE((SELECT max(t.generation) FROM {T} t WHERE t.user_id = r.user_id AND t.resource_id = r.id), 0)"
        f") + 1, updated_at = now() FROM {R} r "
        f"WHERE j.id = %(job)s AND j.user_id = %(uid)s AND j.resource_id = r.id AND r.id = %(rid)s "
        f"AND r.user_id = %(uid)s AND r.active_job_id = j.id AND j.status = 'running' RETURNING j.target_generation"
    ),
    # --- the resource --------------------------------------------------------------------
    "resource": f"SELECT {', '.join(RESOURCE_ROW)} FROM {R} WHERE id = %(rid)s AND user_id = %(uid)s",
    "legacy_sitemap": (
        f"SELECT id, slug, url, resource_type, sitemap, map_version, storage_mode, has_login, generation "
        f"FROM {R} WHERE id = %(rid)s AND user_id = %(uid)s"
    ),
    # A job that ends without a swap records its end as 1.x does after a verify: the error and
    # the time, so a 1.x tab (switch off) shows an error card, never "verifying..." (TD-18).
    "set_last_error": (
        f"UPDATE {R} SET last_error = %(code)s, last_verified_at = %(at)s, updated_at = now() "
        f"WHERE id = %(rid)s AND user_id = %(uid)s AND active_job_id = %(job)s"
    ),
    # A job that never reached the site (a refused start): 1.x writes only the error and keeps
    # the time of the last real verify, setting one only so a never-verified card is not
    # "verifying..." for ever.
    "set_error_without_fetch": (
        f"UPDATE {R} SET last_error = %(code)s, last_verified_at = COALESCE(last_verified_at, %(at)s), "
        f"updated_at = now() WHERE id = %(rid)s AND user_id = %(uid)s AND active_job_id = %(job)s"
    ),
    "set_error_if_never_verified": (
        f"UPDATE {R} SET last_error = %(code)s, last_verified_at = %(at)s, updated_at = now() "
        f"WHERE id = %(rid)s AND user_id = %(uid)s AND active_job_id = %(job)s AND last_verified_at IS NULL"
    ),
    "swap_lock": (
        f"SELECT url, storage_mode, active_job_id, summary_locked, summary_source FROM {R} "
        f"WHERE id = %(rid)s AND user_id = %(uid)s FOR UPDATE"
    ),
    # swap_resource is completed with the SET list of the updates (swap_set).
    "swap_resource": (
        f"UPDATE {R} SET generation = %(gen)s, active_job_id = NULL, updated_at = now(){{sets}} "
        f"WHERE id = %(rid)s AND user_id = %(uid)s AND active_job_id = %(job)s"
    ),
    "swap_job": (
        f"UPDATE {J} SET status = %(status)s, error_code = %(code)s, stage = 'swap', finished_at = now(), "
        f"lease_until = NULL, updated_at = now() WHERE id = %(job)s AND user_id = %(uid)s"
    ),
    # --- writes of a job's own generation ---------------------------------------------
    "allocate_page_ids": (
        f"INSERT INTO {P} (resource_id, url) SELECT r.id, u.url FROM {R} r "
        f"CROSS JOIN unnest(%(urls)s::text[]) AS u(url) WHERE r.id = %(rid)s AND r.user_id = %(uid)s "
        f"ON CONFLICT (resource_id, url) DO NOTHING"
    ),
    "page_ids_for_urls": (
        f"SELECT p.id, p.url FROM {P} p JOIN {R} r ON r.id = p.resource_id "
        f"WHERE r.user_id = %(uid)s AND p.resource_id = %(rid)s AND p.url = ANY(%(urls)s::text[])"
    ),
    "write_entries": (
        f"INSERT INTO {E} (user_id, resource_id, generation, {', '.join(_names(ENTRY_WRITE))}) "
        f"SELECT r.user_id, r.id, %(gen)s, {_cols(_names(ENTRY_WRITE), 'x')} FROM {R} r "
        f"CROSS JOIN jsonb_to_recordset(%(rows)s::jsonb) AS x({_recordset(ENTRY_WRITE)}) "
        f"JOIN {P} p ON p.id = x.page_id AND p.resource_id = r.id "
        f"WHERE r.id = %(rid)s AND r.user_id = %(uid)s RETURNING id, page_id"
    ),
    "write_sections": (
        f"INSERT INTO {S} (resource_id, user_id, generation, {', '.join(_names(SECTION_WRITE))}) "
        f"SELECT r.id, r.user_id, %(gen)s, {_cols(_names(SECTION_WRITE), 'x')} FROM {R} r "
        f"CROSS JOIN jsonb_to_recordset(%(rows)s::jsonb) AS x({_recordset(SECTION_WRITE)}) "
        f"JOIN {E} e ON e.id = x.entry_id AND e.resource_id = r.id AND e.user_id = r.user_id AND e.generation = %(gen)s "
        f"WHERE r.id = %(rid)s AND r.user_id = %(uid)s RETURNING id"
    ),
    "write_tree": (
        f"INSERT INTO {T} (resource_id, user_id, generation, {', '.join(_names(TREE_WRITE))}) "
        f"SELECT r.id, r.user_id, %(gen)s, {_cols(_names(TREE_WRITE), 'x')} FROM {R} r "
        f"CROSS JOIN jsonb_to_recordset(%(rows)s::jsonb) AS x({_recordset(TREE_WRITE)}) "
        f"WHERE r.id = %(rid)s AND r.user_id = %(uid)s RETURNING id"
    ),
    # --- storage totals ----------------------------------------------------------------
    "user_stored_bytes": (
        f"SELECT COALESCE(sum(e.stored_bytes), 0)::bigint AS total FROM {E} e {_live('e')} "
        f"WHERE e.user_id = %(uid)s AND (%(exclude)s::text IS NULL OR e.resource_id <> %(exclude)s::text)"
    ),
    "instance_stored_bytes": (
        f"SELECT COALESCE(sum(e.stored_bytes), 0)::bigint AS total FROM {E} e {_live('e')}"
    ),
    # --- purge -------------------------------------------------------------------------
    "purge_sections": _purge(S),
    "purge_tree": _purge(T),
    "purge_entries": _purge(E),
    "discard_sections": _discard(S),
    "discard_tree": _discard(T),
    "discard_entries": _discard(E),
    # --- reads of the live generation --------------------------------------------------
    "entry_by_url": (
        f"SELECT {_cols(ENTRY_ROW, 'e')} FROM {E} e {_live('e')} "
        f"WHERE e.user_id = %(uid)s AND e.resource_id = %(rid)s AND e.url = %(url)s"
    ),
    "entry_by_page_id": (
        f"SELECT {_cols(ENTRY_ROW, 'e')} FROM {E} e {_live('e')} "
        f"WHERE e.user_id = %(uid)s AND e.page_id = %(page)s"
    ),
    "in_map": (
        f"SELECT EXISTS (SELECT 1 FROM {E} e {_live('e')} "
        f"WHERE e.user_id = %(uid)s AND e.resource_id = %(rid)s AND e.url = %(url)s) AS found"
    ),
    "curation": (
        f"SELECT {_cols(sc.CURATIONS, 'c')} FROM {C} c JOIN {R} r ON r.id = c.resource_id "
        f"WHERE r.user_id = %(uid)s AND c.resource_id = %(rid)s AND c.url = %(url)s"
    ),
    "lookup_page_id": (
        f"SELECT p.resource_id, p.url FROM {P} p JOIN {R} r ON r.id = p.resource_id "
        f"WHERE r.user_id = %(uid)s AND p.id = %(page)s"
    ),
    "min_page_id": (
        f"SELECT min(p.id) AS first FROM {P} p JOIN {R} r ON r.id = p.resource_id "
        f"WHERE r.user_id = %(uid)s AND p.resource_id = %(rid)s"
    ),
}

# Statements that cannot be keyed by one owner, and why (see the module docstring).
UNKEYED_STATEMENTS = {
    "instance_stored_bytes": "the install's storage ceiling (OQ-26): one number over every user",
    "expired_jobs": "boot recovery finds the expired jobs of every user, then writes each by id and owner",
}


SUMMARY_COLUMNS = ("summary", "summary_source")


def summary_is_kept(row: Mapping[str, Any]) -> bool:
    """A summary the person locked or wrote is never replaced by an ingestion. Read from the
    row under the swap's lock: the job's own copy of these flags is from when it started."""
    return bool(row.get("summary_locked")) or row.get("summary_source") == "manual"


def _swap_set(updates: Mapping[str, Any]) -> tuple[str, dict]:
    sets, params = "", {}
    for column, value in updates.items():
        kind = SWAP_COLUMNS[column]
        params[f"u_{column}"] = _json(value) if kind == "jsonb" else (_clean(value) if isinstance(value, str) else value)
        sets += f", {column} = %(u_{column})s::{kind}"
    return sets, params


class ResourceGone(Exception):
    """The resource was deleted while its job ran: the job writes nothing more (R-206)."""


def _clean(value: Any) -> Any:
    """Postgres text cannot hold NUL, and jsonb refuses ``\\u0000``: a page may contain one."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def _json(value: Any) -> str:
    return json.dumps(_clean(value), default=_json_default, ensure_ascii=False, separators=(",", ":"))


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"not JSON serialisable: {type(value).__name__}")


def _batches(rows: Sequence[Mapping[str, Any]], max_rows: int = WRITE_BATCH_ROWS,
             max_bytes: int = WRITE_BATCH_BYTES) -> Iterable[list[Mapping[str, Any]]]:
    batch: list[Mapping[str, Any]] = []
    size = 0
    for row in rows:
        row_size = len(str(row.get("stored_text") or row.get("text") or "")) + 512
        if batch and (len(batch) >= max_rows or size + row_size > max_bytes):
            yield batch
            batch, size = [], 0
        batch.append(row)
        size += row_size
    if batch:
        yield batch


def _rows_for(spec: Sequence[tuple[str, str, Any]], rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    names = _names(spec)
    out = []
    for row in rows:
        unknown = set(row) - set(names)
        if unknown:
            raise ValueError(f"unknown columns {sorted(unknown)}")
        full: dict[str, Any] = {}
        for name, _kind, default in spec:
            if name in row and row[name] is not None:
                full[name] = row[name]
            elif default is REQUIRED:
                raise ValueError(f"column {name} is required")
            else:
                full[name] = list(default) if isinstance(default, list) else default
        out.append(full)
    return out


class Store:
    """The page store, on the pool of ``db`` (or any ``connect()`` that yields a connection
    whose ``execute(sql, params)`` returns a cursor: the unit tests pass a fake one)."""

    def __init__(self, connect: Optional[Callable[[], AsyncContextManager[Any]]] = None) -> None:
        self._connect = connect or db.connection

    async def _one(self, name: str, params: Mapping[str, Any]) -> Optional[dict]:
        async with self._connect() as conn:
            cur = await conn.execute(STATEMENTS[name], params)
            return await cur.fetchone()

    async def _all(self, name: str, params: Mapping[str, Any]) -> list[dict]:
        async with self._connect() as conn:
            cur = await conn.execute(STATEMENTS[name], params)
            return list(await cur.fetchall())

    async def _count(self, name: str, params: Mapping[str, Any]) -> int:
        async with self._connect() as conn:
            cur = await conn.execute(STATEMENTS[name], params)
            return cur.rowcount

    # --- jobs ------------------------------------------------------------------------

    async def accept_job(self, user_id: str, job_id: str, instance: str, lease_until: datetime) -> bool:
        """Takes a queued job into this instance's queue, renewing its lease; false when the job
        is not queued or its resource's claim no longer names it."""
        return await self._count("accept_job", {"uid": user_id, "job": job_id, "instance": instance,
                                                "until": lease_until}) == 1

    async def claim_job_for_run(self, user_id: str, job_id: str, instance: str, lease_until: datetime) -> bool:
        """queued -> running, only for this instance's job that still holds the claim."""
        return await self._count("claim_job_for_run", {"uid": user_id, "job": job_id, "instance": instance,
                                                       "until": lease_until}) == 1

    async def renew_leases(self, instance: str, until: datetime, held: Iterable[tuple[str, str]]) -> set[str]:
        """Renews the leases of the jobs this instance holds, given as (user_id, job_id);
        returns the ids it renewed (a job missing there was finished or taken over)."""
        pairs = list(held)
        if not pairs:
            return set()
        rows = await self._all("renew_leases", {"instance": instance, "until": until,
                                                "uids": [u for u, _ in pairs], "jobs": [j for _, j in pairs]})
        return {r["id"] for r in rows}

    async def cancel_requested(self, user_id: str, job_id: str) -> bool:
        """True when a cancel was asked, or when the job is gone or already finished (its
        resource was deleted, or a takeover failed it): either way it must stop."""
        row = await self._one("cancel_requested", {"uid": user_id, "job": job_id})
        return row is None or bool(row["cancel_requested"]) or row["status"] not in ("queued", "running")

    async def request_cancel(self, user_id: str, job_id: str) -> bool:
        """Sets the cancel flag of an unfinished job; whichever copy runs it stops at its next check."""
        return await self._count("request_cancel", {"uid": user_id, "job": job_id}) == 1

    async def request_cancel_user(self, user_id: str) -> list[str]:
        """Sets the cancel flag of every unfinished job of the user; returns their ids."""
        return [r["id"] for r in await self._all("request_cancel_user", {"uid": user_id})]

    async def set_job_stage(self, user_id: str, job_id: str, stage: str,
                            progress: Optional[Mapping[str, Any]] = None) -> bool:
        return await self._count("set_job_stage", {"uid": user_id, "job": job_id, "stage": stage,
                                                   "progress": _json(dict(progress or {}))}) == 1

    async def finish_job(self, user_id: str, job_id: str, status: str, error_code: str = "") -> bool:
        """Closes an unfinished job and releases the claim it holds, in one transaction."""
        async with self._connect() as conn:
            cur = await conn.execute(STATEMENTS["finish_job"], {"uid": user_id, "job": job_id,
                                                                "status": status, "code": error_code})
            finished = cur.rowcount == 1
            await conn.execute(STATEMENTS["release_claim"], {"uid": user_id, "job": job_id})
        return finished

    async def fail_expired_leases(self, now: datetime, error_code: str = "agent_restarted") -> list[dict]:
        """Fails every queued or running job whose lease expired (no lease counts as expired)
        and releases their claims, recording the error on the 1.x columns of each resource it
        releases (``last_verified_at`` only where it is empty: nothing was verified); returns the
        jobs (id, user_id, resource_id, target_generation)."""
        return await self._all("expired_jobs", {"now": now, "code": error_code})

    async def begin_generation(self, user_id: str, resource_id: str, job_id: str) -> Optional[int]:
        """The generation this running job writes: above every number the resource has used,
        so a half-discarded generation is never written into again. None when the resource
        is gone or its claim no longer names the job."""
        row = await self._one("begin_generation", {"uid": user_id, "rid": resource_id, "job": job_id})
        return None if row is None else int(row["target_generation"])

    # --- the resource ------------------------------------------------------------------

    async def resource(self, user_id: str, resource_id: str) -> Optional[dict]:
        """The resource row with its live generation (no secret, no 1.x map), or None."""
        return await self._one("resource", {"uid": user_id, "rid": resource_id})

    async def legacy_sitemap(self, user_id: str, resource_id: str) -> Optional[dict]:
        """The 1.x ``sitemap`` with what reading it needs (URL, type, storage mode, login, live
        generation), or None when the resource is gone: one keyed read per lookup."""
        return await self._one("legacy_sitemap", {"uid": user_id, "rid": resource_id})

    async def set_last_error(self, user_id: str, resource_id: str, job_id: str, code: str, at: datetime) -> bool:
        """The end of a job that swapped nothing, on the 1.x columns: ``last_error`` and
        ``last_verified_at`` together (only while the claim names the job)."""
        return await self._count("set_last_error", {"uid": user_id, "rid": resource_id, "job": job_id,
                                                    "code": code, "at": at}) == 1

    async def set_error_without_fetch(self, user_id: str, resource_id: str, job_id: str, code: str,
                                      at: datetime) -> bool:
        """The end of a job that never reached the site: ``last_error``, and ``last_verified_at``
        only when the resource was never verified (as 1.x when its agent call fails)."""
        return await self._count("set_error_without_fetch", {"uid": user_id, "rid": resource_id, "job": job_id,
                                                             "code": code, "at": at}) == 1

    async def set_error_if_never_verified(self, user_id: str, resource_id: str, job_id: str, code: str,
                                          at: datetime) -> bool:
        """``set_last_error`` for a resource that was never verified (a first add): a cancelled
        add must not read "verifying..." for ever, a cancelled refresh leaves a good resource as it is."""
        return await self._count("set_error_if_never_verified", {"uid": user_id, "rid": resource_id, "job": job_id,
                                                                 "code": code, "at": at}) == 1

    async def swap(self, user_id: str, resource_id: str, job_id: str, generation: int, expected_url: str,
                   expected_storage_mode: str, updates: Mapping[str, Any], *, status: str = "succeeded",
                   error_code: str = "") -> str:
        """Makes ``generation`` the live one and closes the job, in one short transaction on
        the resource row and the job row only.

        ``gone``: the resource was deleted (nothing to write). ``lost``: its claim names
        another job (this one's lease expired and a new job took the resource). ``changed``:
        its URL or storage mode is no longer what the job built from (D-45). In those three
        cases nothing is written; the caller discards the generation and closes the job. A
        summary the row has locked or marked manual by then is left as it is (AC-40).
        """
        unknown = set(updates) - set(SWAP_COLUMNS)
        if unknown:
            raise ValueError(f"a swap cannot write {sorted(unknown)}")
        async with self._connect() as conn:
            cur = await conn.execute(STATEMENTS["swap_lock"], {"uid": user_id, "rid": resource_id})
            row = await cur.fetchone()
            if row is None:
                return "gone"
            if row["active_job_id"] != job_id:
                return "lost"
            if row["url"] != expected_url or row["storage_mode"] != expected_storage_mode:
                return "changed"
            if summary_is_kept(row):
                # The person wrote or locked the summary while the job ran: theirs stays.
                updates = {k: v for k, v in updates.items() if k not in SUMMARY_COLUMNS}
            sets, params = _swap_set(updates)
            params.update({"uid": user_id, "rid": resource_id, "job": job_id, "gen": generation,
                           "status": status, "code": error_code})
            await conn.execute(STATEMENTS["swap_resource"].replace("{sets}", sets), params)
            await conn.execute(STATEMENTS["swap_job"], params)
        return "swapped"

    # --- writes of a job's own generation ------------------------------------------------

    async def allocate_page_ids(self, user_id: str, resource_id: str, urls: Iterable[str]) -> dict[str, int]:
        """The page number of every canonical URL, created when new; kept across refreshes."""
        wanted = list(dict.fromkeys(_clean(u) for u in urls if u))
        out: dict[str, int] = {}
        for i in range(0, len(wanted), PAGE_ID_BATCH):
            chunk = wanted[i:i + PAGE_ID_BATCH]
            params = {"uid": user_id, "rid": resource_id, "urls": chunk}
            async with self._connect() as conn:
                await conn.execute(STATEMENTS["allocate_page_ids"], params)
                cur = await conn.execute(STATEMENTS["page_ids_for_urls"], params)
                rows = await cur.fetchall()
            if not rows:
                raise ResourceGone(resource_id)
            out.update({r["url"]: int(r["id"]) for r in rows})
        return out

    async def _write(self, name: str, spec: Sequence[tuple[str, str, Any]], user_id: str, resource_id: str,
                     generation: int, rows: Sequence[Mapping[str, Any]]) -> list[dict]:
        written: list[dict] = []
        for batch in _batches(_rows_for(spec, rows)):
            params = {"uid": user_id, "rid": resource_id, "gen": generation, "rows": _json(batch)}
            try:
                async with self._connect() as conn:
                    cur = await conn.execute(STATEMENTS[name], params)
                    got = list(await cur.fetchall())
            except db.ForeignKeyViolation as exc:
                raise ResourceGone(resource_id) from exc
            if len(got) != len(batch):
                if not await self.resource(user_id, resource_id):
                    raise ResourceGone(resource_id)
                raise ValueError(f"{name}: {len(batch) - len(got)} rows name a page or entry of another resource")
            written.extend(got)
        return written

    async def write_entries(self, user_id: str, resource_id: str, generation: int,
                            entries: Sequence[Mapping[str, Any]]) -> dict[int, int]:
        """Inserts the generation's entries; returns {page_id: entry id}. Raises ResourceGone
        when the resource was deleted meanwhile (the foreign keys refuse the rows)."""
        rows = await self._write("write_entries", ENTRY_WRITE, user_id, resource_id, generation, entries)
        return {int(r["page_id"]): int(r["id"]) for r in rows}

    async def write_sections(self, user_id: str, resource_id: str, generation: int,
                             sections: Sequence[Mapping[str, Any]]) -> int:
        return len(await self._write("write_sections", SECTION_WRITE, user_id, resource_id, generation, sections))

    async def write_tree(self, user_id: str, resource_id: str, generation: int,
                         nodes: Sequence[Mapping[str, Any]]) -> int:
        return len(await self._write("write_tree", TREE_WRITE, user_id, resource_id, generation, nodes))

    # --- storage totals ----------------------------------------------------------------

    async def user_stored_bytes(self, user_id: str, exclude_resource_id: Optional[str] = None) -> int:
        """Bytes stored in the live generations of the user's resources, without one resource
        (the one a refresh is about to replace)."""
        row = await self._one("user_stored_bytes", {"uid": user_id, "exclude": exclude_resource_id})
        return int(row["total"]) if row else 0

    async def instance_stored_bytes(self) -> int:
        row = await self._one("instance_stored_bytes", {})
        return int(row["total"]) if row else 0

    # --- purge -------------------------------------------------------------------------

    async def _batched_delete(self, names: Sequence[str], params: Mapping[str, Any], batch: int) -> int:
        total = 0
        for name in names:
            while True:
                deleted = await self._count(name, {**params, "batch": batch})
                total += deleted
                if deleted < batch:
                    break
        return total

    async def purge_old_generations(self, user_id: str, resource_id: str, batch: int = PURGE_BATCH) -> int:
        """Deletes the rows of every generation that is neither live nor being written, at most
        ``batch`` rows per statement, each statement its own transaction. Sections first, so
        an entry's delete never cascades into thousands of rows."""
        return await self._batched_delete(("purge_sections", "purge_tree", "purge_entries"),
                                          {"uid": user_id, "rid": resource_id}, batch)

    async def discard_generation(self, user_id: str, resource_id: str, generation: int,
                                 batch: int = PURGE_BATCH) -> int:
        """Deletes one generation that never went live (a failed or cancelled job's)."""
        if generation <= 0:
            return 0
        return await self._batched_delete(("discard_sections", "discard_tree", "discard_entries"),
                                          {"uid": user_id, "rid": resource_id, "gen": generation}, batch)

    # --- reads of the live generation ----------------------------------------------------

    async def entry_by_url(self, user_id: str, resource_id: str, url: str) -> Optional[dict]:
        return await self._one("entry_by_url", {"uid": user_id, "rid": resource_id, "url": url})

    async def entry_by_page_id(self, user_id: str, page_id: int) -> Optional[dict]:
        return await self._one("entry_by_page_id", {"uid": user_id, "page": page_id})

    async def in_map(self, user_id: str, resource_id: str, url: str) -> bool:
        """Whether ``url`` is an entry of the resource's live map (kept or dropped: both came
        from the site's own index)."""
        row = await self._one("in_map", {"uid": user_id, "rid": resource_id, "url": url})
        return bool(row and row["found"])

    async def curation(self, user_id: str, resource_id: str, url: str) -> Optional[dict]:
        return await self._one("curation", {"uid": user_id, "rid": resource_id, "url": url})

    # --- page IDs (library.page_ids.PageIdStore) ---------------------------------------

    async def lookup_page_id(self, owner_id: str, page_number: int) -> Optional[PageIdRow]:
        row = await self._one("lookup_page_id", {"uid": owner_id, "page": page_number})
        return PageIdRow(resource_id=row["resource_id"], url=row["url"]) if row else None

    async def min_page_id(self, owner_id: str, resource_id: str) -> Optional[int]:
        row = await self._one("min_page_id", {"uid": owner_id, "rid": resource_id})
        return int(row["first"]) if row and row["first"] is not None else None

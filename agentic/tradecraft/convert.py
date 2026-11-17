"""Converting an account's 1.x resources to 2.0 without crawling (phase 9, T9.1; §7.2, D-26, D-35).

``start(runner, user_id)`` opens one ``convert`` job for the account and converts, one resource at a
time in the background, every resource that needs it: one never converted (``map_version`` 1), or
one whose 1.x ``sitemap`` no longer has the hash its last 2.0 write recorded (a 1.x Refresh made while
the switch was off, D-26). It answers how many resources it queued.

Each resource is claimed like any job (a conditional update of ``active_job_id``): a resource whose
claim names an unfinished job is skipped, and the next sweep converts it. The conversion writes a
new generation from the 1.x map alone: every entry of every 1.x shape (``nav``, ``tree``, ``links``,
a PDF's ``pages``; a CVE archive's ``{owner, repo, branch}`` has none) becomes an entry with a page
ID, a title-only card (``source = "legacy"``), the rules' tags and its entities, and the person's
curations (blocks, pins, renames) apply as at any refresh. Nothing is downloaded and no model is
called. The swap sets ``map_version`` 2 and ``legacy_map_hash`` only while the claim, the URL, the
storage mode and the 1.x map are still the ones converted, so a write that raced it is never lost;
``storage_mode`` stays (Live).

A PDF (its map lists ``pages``) gets a ``pdf_convert`` job of its own: the document is downloaded
once, the pages its 1.x map lists are stored within the account's quota, and it becomes Stored
(§4.5: PDFs are always Stored). A PDF that cannot be downloaded, or that has a login (the agent never
reads a secret column, so it cannot send one), is converted from its titles like any resource and
stays Live: its pages are read live, as before, until a person refreshes it.

Idempotent (D-35): one unfinished ``convert`` job per account (an advisory lock serializes two starts
at once, from two copies or a switch-on during the boot sweep), and a converted resource no longer
needs it. Triggers: the webapp after the switch is turned on, and the agent's boot sweep
(``boot_sweep``).
"""

from __future__ import annotations

import urllib.parse
import uuid
from typing import Any, Optional

from logging_config import get_logger
from tradecraft import clock as tc_clock
from tradecraft import schema_columns as sc
from tradecraft import settings as tc_settings
from tradecraft.contract import ERROR_CODES, SITE_TYPES, JobContext, JobResource, JobStartRequest, Secrets, SettingsSnapshot
from tradecraft.ingest import builders, cards, curation, entities, fetch, legacy_map, sections, storage, tags, tree
from tradecraft.ingest.builders import Candidate
from tradecraft.ingest.detect import WEBSITE
from tradecraft.library import legacy_match
from tradecraft.store import ResourceGone, _json

logger = get_logger(__name__)

CONVERT = "convert"
PDF_CONVERT = "pdf_convert"
MAX_TITLE_CHARS = cards.MAX_TITLE_CHARS
# No model in a conversion: the rules alone tag, whatever the account chose for its refreshes.
_NO_MODEL = {"focus.tagEveryPage": "rules"}
# A PDF's pages are the ones its 1.x map lists, whatever range the account's settings name now.
_EVERY_PAGE = {"type.pdf.mapBy": "pages", "type.pdf.firstPage": 1, "type.pdf.lastPage": 0, "type.pdf.skipPages": []}

R, J, E, T, US = (sc.TABLE_RESOURCES, sc.TABLE_JOBS, sc.TABLE_ENTRIES, sc.TABLE_TREE, sc.TABLE_USER_SETTINGS)
UNFINISHED = "('queued','running')"
CANDIDATE_COLUMNS = ("id", "slug", "name", "url", "resource_type", "sitemap", "map_version", "legacy_map_hash",
                     "storage_mode", "has_login", "active_job_id")

STATEMENTS: dict[str, str] = {
    "candidates": f"SELECT {', '.join(CANDIDATE_COLUMNS)} FROM {R} WHERE user_id = %(uid)s ORDER BY id",
    "lock_account": "SELECT pg_advisory_xact_lock(hashtext(%(key)s))",
    "running_convert": (
        f"SELECT id FROM {J} WHERE user_id = %(uid)s AND kind = 'convert' AND status IN {UNFINISHED} "
        f"AND lease_until >= %(now)s"
    ),
    "open_job": (
        f"INSERT INTO {J} (id, user_id, resource_id, kind, status, stage, owner_instance, lease_until, "
        f"started_at, updated_at) VALUES (%(job)s, %(uid)s, %(rid)s, %(kind)s, 'running', 'convert', "
        f"%(instance)s, %(until)s, now(), now())"
    ),
    # A free resource, or one whose claim names a job that ended (a conversion whose agent died);
    # never one an unfinished job holds. Returns the generation to write: above every number the
    # resource has used, as begin_generation does for a job.
    "claim": (
        f"UPDATE {R} r SET active_job_id = %(job)s, updated_at = now() "
        f"WHERE r.id = %(rid)s AND r.user_id = %(uid)s AND (r.active_job_id IS NULL OR NOT EXISTS "
        f"(SELECT 1 FROM {J} j WHERE j.id = r.active_job_id AND j.user_id = r.user_id AND j.status IN {UNFINISHED})) "
        f"RETURNING GREATEST(r.generation, "
        f"COALESCE((SELECT max(j2.target_generation) FROM {J} j2 WHERE j2.user_id = r.user_id AND j2.resource_id = r.id), 0), "
        f"COALESCE((SELECT max(e.generation) FROM {E} e WHERE e.user_id = r.user_id AND e.resource_id = r.id), 0), "
        f"COALESCE((SELECT max(t.generation) FROM {T} t WHERE t.user_id = r.user_id AND t.resource_id = r.id), 0)"
        f") + 1 AS target"
    ),
    "set_target": (
        f"UPDATE {J} SET target_generation = %(gen)s, updated_at = now() WHERE id = %(job)s AND user_id = %(uid)s"
    ),
    "swap": (
        f"UPDATE {R} SET generation = %(gen)s, active_job_id = NULL, map_version = %(version)s, "
        f"legacy_map_hash = %(hash)s, storage_mode = %(mode)s, updated_at = now() "
        f"WHERE id = %(rid)s AND user_id = %(uid)s AND active_job_id = %(job)s AND url = %(url)s "
        f"AND storage_mode = %(was_mode)s AND sitemap = %(sitemap)s::jsonb"
    ),
    "release": (
        f"UPDATE {R} SET active_job_id = NULL, updated_at = now() "
        f"WHERE id = %(rid)s AND user_id = %(uid)s AND active_job_id = %(job)s"
    ),
    "account_ingestion": f"SELECT ingestion FROM {US} WHERE user_id = %(uid)s",
    "sweep_users": (
        f"SELECT s.user_id FROM {US} s WHERE s.v2_enabled "
        f"AND EXISTS (SELECT 1 FROM {R} r WHERE r.user_id = s.user_id) ORDER BY s.user_id"
    ),
}

# Statements that cannot be keyed by one owner, and why (as store.UNKEYED_STATEMENTS).
UNKEYED_STATEMENTS = {
    "sweep_users": "the boot sweep lists the accounts to convert; each is then converted by its own keyed statements",
}


# --------------------------------------------------------------------------------------
# The 1.x map as entries (pure)
# --------------------------------------------------------------------------------------

def _one_line(text: Any) -> str:
    return " ".join(str(text or "").split())


def _page_number(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def is_pdf(sitemap: Any) -> bool:
    """A 1.x PDF resource: its map lists ``pages`` (1.x stored it as ``agentic-crawl``)."""
    return isinstance(sitemap, dict) and isinstance(sitemap.get("pages"), list)


def _dedupe(entries: list[Candidate]) -> list[Candidate]:
    seen: set[str] = set()
    out = []
    for e in entries:
        if e.url not in seen:
            seen.add(e.url)
            out.append(e)
    return out


def legacy_candidates(resource_type: str, url: str, sitemap: Any) -> tuple[str, list[Candidate]]:
    """(site type, entries) of a 1.x map, every shape: ``nav`` (a wiki, GitBook, docs site or
    website), ``tree`` (a GitHub repository), ``links`` (an early crawl), ``pages`` (a PDF), and a CVE
    archive's metadata (no entry). Each path resolves to the URL 1.x reads it at
    (``legacy_match.resolve_path``), stored canonical; a site whose map is empty keeps its start
    page, the page 1.x read for it."""
    sitemap = sitemap if isinstance(sitemap, dict) else {}
    if is_pdf(sitemap):
        base = fetch.canonical_url(url)
        out = []
        for p in sitemap["pages"]:
            number = _page_number(p.get("page")) if isinstance(p, dict) else None
            if number is None:
                continue
            first = _one_line(p.get("firstLine"))[:MAX_TITLE_CHARS]
            out.append(Candidate(f"{base}#page={number}", first or f"Page {number}", "legacy", str(number),
                                 {"page": number, "first_line": first}))
        return "pdf", _dedupe(out)
    if resource_type == "cve-poc-db":
        return "cve-poc-db", []
    site_type = resource_type if resource_type in SITE_TYPES and resource_type != "pdf" else WEBSITE
    # Only the branch: with no nav or tree to search, each path resolves as itself (no O(n²) lookup).
    branch_only = {"branch": sitemap["branch"]} if sitemap.get("branch") else {}
    out = []
    for item in legacy_match.sitemap_entries(sitemap):
        path = item["path"].strip()
        target = legacy_match.resolve_path(site_type, url, branch_only, path) if path else url
        page = fetch.canonical_url(target)
        if not fetch.entry_url_ok(page):
            continue
        title = _one_line(item["title"]) or path or page
        out.append(Candidate(page, title[:MAX_TITLE_CHARS], "legacy", path))
    out = _dedupe(out)
    if not out and fetch.entry_url_ok(fetch.canonical_url(url)):
        host = urllib.parse.urlsplit(url).hostname or url
        out = [Candidate(fetch.canonical_url(url), f"{host} (homepage)", "legacy", "")]
    return site_type, out


def needs_conversion(row: dict) -> bool:
    """Never converted, or its 1.x map changed since the last 2.0 write (D-26)."""
    if int(row.get("map_version") or 1) < sc.MAP_VERSION_CONVERTED:
        return True
    return row.get("legacy_map_hash") != legacy_map.map_hash(row.get("sitemap") or {})


def title_cards(state: Any) -> list[dict]:
    """One title-only card per entry: no download, so no heading, description or real title."""
    out = []
    for entry in state.entries:
        card = cards._base_card(entry)
        # A repository's tree path names its folders; any other entry's URL path does.
        source = "tree" if state.site_type == "github-repo" and entry.source == "legacy" else entry.source
        card["breadcrumb"] = cards.breadcrumb_for(entry.url, entry.path, source, state.site_type, state.url)
        out.append(card)
    return out


# --------------------------------------------------------------------------------------
# The database
# --------------------------------------------------------------------------------------

async def _one(store: Any, name: str, params: dict) -> Optional[dict]:
    async with store._connect() as conn:
        cur = await conn.execute(STATEMENTS[name], params)
        return await cur.fetchone()


async def _all(store: Any, name: str, params: dict) -> list[dict]:
    async with store._connect() as conn:
        cur = await conn.execute(STATEMENTS[name], params)
        return list(await cur.fetchall())


async def _count(store: Any, name: str, params: dict) -> int:
    async with store._connect() as conn:
        cur = await conn.execute(STATEMENTS[name], params)
        return cur.rowcount


async def resources_to_convert(store: Any, user_id: str) -> list[dict]:
    return [r for r in await _all(store, "candidates", {"uid": user_id}) if needs_conversion(r)]


async def open_job(store: Any, user_id: str, instance: str, until: Any, *, resource_id: Optional[str] = None,
                   kind: str = CONVERT) -> Optional[str]:
    """A running job row of this copy; for ``convert``, None while the account already has one
    whose lease is live (another copy, or this one, is converting it)."""
    job_id = f"tc-{kind.replace('_', '-')}-{uuid.uuid4().hex}"
    async with store._connect() as conn:
        if kind == CONVERT:
            await conn.execute(STATEMENTS["lock_account"], {"key": f"tradecraft_convert:{user_id}"})
            cur = await conn.execute(STATEMENTS["running_convert"], {"uid": user_id, "now": tc_clock.now()})
            if await cur.fetchone() is not None:
                return None
        await conn.execute(STATEMENTS["open_job"], {"job": job_id, "uid": user_id, "rid": resource_id, "kind": kind,
                                                    "instance": instance, "until": until})
    return job_id


async def claim(store: Any, user_id: str, resource_id: str, job_id: str) -> Optional[int]:
    """The generation to write when the resource was claimed for ``job_id``; None when another
    job holds it or it is gone."""
    row = await _one(store, "claim", {"uid": user_id, "rid": resource_id, "job": job_id})
    return None if row is None else int(row["target"])


async def account_values(store: Any, user_id: str) -> dict:
    row = await _one(store, "account_ingestion", {"uid": user_id})
    stored = row.get("ingestion") if row else None
    return dict(stored) if isinstance(stored, dict) else {}


# --------------------------------------------------------------------------------------
# One resource
# --------------------------------------------------------------------------------------

def _request(job_id: str, kind: str, user_id: str, row: dict, values: dict, storage_mode: str) -> JobStartRequest:
    """What the ingestion stages read of a job, for a job no webapp started: no secret, no model.
    Built without validation: ``convert`` is no kind a start request may name."""
    resource = JobResource.model_construct(
        url=row["url"], slug=row["slug"], name=row.get("name") or row["slug"], storage_mode=storage_mode,
        forced_type="", type_options={}, focus={}, summary="", summary_source="generated", summary_locked=False,
        model="")
    return JobStartRequest.model_construct(
        job_id=job_id, user_id=user_id, resource_id=row["id"], kind=kind, actor_user_id=user_id,
        real_actor_user_id=None, bulk_id=None, settings=values,
        settings_snapshot=SettingsSnapshot.model_construct(values=values, provenance={}), settings_hash="0" * 16,
        resource=resource, secrets=Secrets())


async def _never() -> bool:
    return False


async def _no_stage(_stage: str, _progress: Any = None) -> None:
    return None


def _state(runner: Any, job_id: str, kind: str, user_id: str, row: dict, values: dict, generation: int,
           storage_mode: str) -> Any:
    from tradecraft.ingest.pipeline import IngestState  # the pipeline imports every stage

    settings = tc_settings.EffectiveSettings(values)
    ctx = JobContext(request=_request(job_id, kind, user_id, row, settings.values, storage_mode), settings=settings,
                     target_generation=generation, is_cancelled=_never, set_stage=_no_stage)
    return IngestState(ctx=ctx, store=runner.store, blocking=runner.run_blocking, build_llm=None,
                       started=tc_clock.monotonic(), url=row["url"], owner_id=user_id, resource_id=row["id"],
                       generation=generation, storage_mode=storage_mode)


async def _derive_and_write(state: Any) -> None:
    from tradecraft.ingest import pipeline

    for step in (tags.tag, entities.extract, tree.build):
        await step(state)
    await pipeline.write(state)


async def _swap(runner: Any, user_id: str, job_id: str, row: dict, generation: int, storage_mode: str) -> bool:
    swapped = await _count(runner.store, "swap", {
        "uid": user_id, "rid": row["id"], "job": job_id, "gen": generation, "version": sc.MAP_VERSION_CONVERTED,
        "hash": legacy_map.map_hash(row.get("sitemap") or {}), "mode": storage_mode, "url": row["url"],
        "was_mode": row["storage_mode"], "sitemap": _json(row.get("sitemap") or {})}) == 1
    if swapped:
        try:
            await runner.store.purge_old_generations(user_id, row["id"])
        except Exception as exc:
            logger.warning(f"[tradecraft] convert resource={row['id']} purge deferred error={type(exc).__name__}")
    return swapped


async def _give_up(runner: Any, user_id: str, job_id: str, row: dict, generation: int) -> None:
    await runner.store.discard_generation(user_id, row["id"], generation)
    await _count(runner.store, "release", {"uid": user_id, "rid": row["id"], "job": job_id})


async def convert_titles(runner: Any, user_id: str, job_id: str, row: dict, values: dict) -> str:
    """Converts one resource from its 1.x map under the claim of ``job_id``; returns "" when its
    new generation is live, else why not (a code, logged)."""
    generation = await claim(runner.store, user_id, row["id"], job_id)
    if generation is None:
        return "job_running"
    try:
        state = _state(runner, job_id, CONVERT, user_id, row, {**values, **_NO_MODEL}, generation, row["storage_mode"])
        state.site_type, state.entries = legacy_candidates(row.get("resource_type") or WEBSITE, row["url"],
                                                           row.get("sitemap"))
        await curation.apply(state)
        state.cards = title_cards(state)
        await _derive_and_write(state)
        if await _swap(runner, user_id, job_id, row, generation, row["storage_mode"]):
            return ""
        code = "resource_changed"
    except ResourceGone:
        code = "resource_deleted"
    await _give_up(runner, user_id, job_id, row, generation)
    return code


async def convert_pdf(runner: Any, user_id: str, row: dict, values: dict) -> str:
    """The ``pdf_convert`` job of one PDF: the document downloaded once, its listed pages stored,
    the resource Stored. Returns "" when it swapped; a download that fails returns its code and
    the caller converts the titles instead."""
    store = runner.store
    job_id = await open_job(store, user_id, runner.instance, runner.lease_until(), resource_id=row["id"],
                            kind=PDF_CONVERT)
    runner.hold(job_id, user_id)
    code = "internal_error"
    try:
        generation = await claim(store, user_id, row["id"], job_id)
        if generation is None:
            code = "job_running"
            return code
        await _count(store, "set_target", {"uid": user_id, "job": job_id, "gen": generation})
        settings_values = {**values, **_NO_MODEL, **_EVERY_PAGE}
        state = _state(runner, job_id, PDF_CONVERT, user_id, row, settings_values, generation, "stored")
        _site, listed = legacy_candidates("pdf", row["url"], row.get("sitemap"))
        page = await fetch.smart_fetch(row["url"], state.settings, allow_browser=False)
        state.visited += 1
        texts: dict[int, str] = {}
        if page.is_pdf:
            pages, _total, error = await runner.run_blocking(builders.pdf_pages, page.body, state.settings)
            texts = {} if error else {p["page"]: p["text"] or "" for p in pages}
        if not texts:
            code = page.error or "fetch_failed"
            await _give_up(runner, user_id, job_id, row, generation)
            return code
        if not listed:
            listed = [Candidate(f"{fetch.canonical_url(row['url'])}#page={n}", f"Page {n}", "legacy", str(n),
                                {"page": n, "first_line": ""}) for n in sorted(texts)]
        state.site_type = "pdf"
        # An empty text is "nothing to store" for the storage stage: it never downloads a page of a PDF.
        state.entries = [Candidate(e.url, e.title, "pdf", e.path,
                                   {**e.extra, "text": texts.get(e.extra.get("page"), "")}) for e in listed]
        try:
            await curation.apply(state)
            await storage.store(state)
            await cards.build(state)
            await sections.build(state)
            await _derive_and_write(state)
            swapped = await _swap(runner, user_id, job_id, row, generation, "stored")
        except ResourceGone:
            swapped, code = False, "resource_deleted"
        else:
            code = "" if swapped else "resource_changed"
        if not swapped:
            await _give_up(runner, user_id, job_id, row, generation)
        return code
    finally:
        code = code if not code or code in ERROR_CODES else "internal_error"
        await store.finish_job(user_id, job_id, "failed" if code else "succeeded", code)
        runner.release_hold(job_id)
        logger.info(f"[tradecraft] job {job_id} {'failed' if code else 'succeeded'} code={code}")


async def convert_one(runner: Any, user_id: str, job_id: str, row: dict, values: dict) -> str:
    if is_pdf(row.get("sitemap")) and not row.get("has_login"):
        code = await convert_pdf(runner, user_id, row, values)
        if code in ("", "job_running", "resource_deleted", "resource_changed"):
            return code
        logger.info(f"[tradecraft] convert resource={row['id']} pdf code={code}: converted from its titles")
    return await convert_titles(runner, user_id, job_id, row, values)


# --------------------------------------------------------------------------------------
# An account
# --------------------------------------------------------------------------------------

async def start(runner: Any, user_id: str) -> int:
    """Queues the conversion of the account's resources that need it; returns how many. 0 when
    none does, or when a conversion of the account already runs."""
    store = runner.store
    todo = await resources_to_convert(store, user_id)
    if not todo:
        return 0
    try:
        job_id = await open_job(store, user_id, runner.instance, runner.lease_until())
    except Exception as exc:  # the account was deleted meanwhile (the job's foreign key)
        logger.warning(f"[tradecraft] convert user not started error={type(exc).__name__}")
        return 0
    if job_id is None:
        return 0
    runner.hold(job_id, user_id)
    runner.spawn(lambda: _run(runner, user_id, job_id, todo), f"tradecraft-convert-{job_id}")
    logger.info(f"[tradecraft] job {job_id} queued code= resources={len(todo)}")
    return len(todo)


async def _run(runner: Any, user_id: str, job_id: str, todo: list[dict]) -> None:
    store = runner.store
    status, code, done, skipped = "succeeded", "", 0, 0
    try:
        values = await account_values(store, user_id)
        for i, row in enumerate(todo):
            if await store.cancel_requested(user_id, job_id):
                status, code = "cancelled", "cancelled"
                break
            await store.set_job_stage(user_id, job_id, "convert", {"done": i, "total": len(todo), "unit": "resources"})
            try:
                result = await convert_one(runner, user_id, job_id, row, values)
            except Exception as exc:
                result = "internal_error"
                logger.warning(f"[tradecraft] convert resource={row['id']} code=internal_error "
                               f"error={type(exc).__name__}")
            if result:
                skipped += 1
            else:
                done += 1
            logger.info(f"[tradecraft] convert resource={row['id']} code={result}")
    except Exception as exc:
        status, code = "failed", "internal_error"
        logger.warning(f"[tradecraft] job {job_id} failed code=internal_error error={type(exc).__name__}")
    finally:
        try:
            await store.finish_job(user_id, job_id, status, code)
        except Exception as exc:
            logger.warning(f"[tradecraft] job {job_id} not closed error={type(exc).__name__}")
        runner.release_hold(job_id)
        logger.info(f"[tradecraft] job {job_id} {status} code={code} converted={done} skipped={skipped}")


async def convert_user(user_id: str) -> int:
    """``POST /tradecraft/v2/users/{id}/convert``: the account's conversion on this copy's runner."""
    from tradecraft import jobs

    return await jobs.get_runner().convert(user_id)


async def sweep_users(store: Any) -> list[str]:
    return [r["user_id"] for r in await _all(store, "sweep_users", {})]


async def boot_sweep(runner: Any) -> int:
    """At the agent's start: the conversion of every account with 2.0 on that has a resource to
    convert. Returns how many resources were queued; never raises."""
    total = 0
    try:
        users = await sweep_users(runner.store)
    except Exception as exc:
        logger.warning(f"[tradecraft] convert sweep skipped error={type(exc).__name__}")
        return 0
    for user_id in users:
        try:
            total += await start(runner, user_id)
        except Exception as exc:
            logger.warning(f"[tradecraft] convert sweep user skipped error={type(exc).__name__}")
    logger.info(f"[tradecraft] convert sweep code= users={len(users)} resources={total}")
    return total

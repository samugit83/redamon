"""The ingestion pipeline: one job, from the resource's URL to a new live generation.

``run(ctx)`` is the job runner's entry (``contract.PipelineEntry``). The stage contract, in
order (``contract.JOB_STAGES``; each stage module exists from phase 1 and a later card fills
it, every one taking and returning the same ``IngestState``):

    fetch_home -> detect -> build_map (builders or crawl) -> curation.apply (T6.6)
    -> focus.select (T5.1) -> titles.apply (T6.1) -> incremental.plan (T6.2) -> storage.store
    -> cards.build (T2.3) -> sections.build (T2.3) -> tags.tag (T2.2, T5.1)
    -> entities.extract (T2.2) -> tree.build (T2.3) -> focus.content_check (T6.9)
    -> write -> summary.summarize -> report.build -> legacy_map.build -> store.swap

The job writes its own generation (``ctx.target_generation``) and swaps it in at the end; a
failure or a cancel leaves the previous one live (the runner discards what was written). With
``refreshing.onFailure`` at ``replace``, a refresh that fails or finds nothing swaps the empty
result in, as 1.x did. The job's progress, its report and ``lastError`` carry codes and
counts only: never a secret, page text or a URL.
"""

from __future__ import annotations

import collections
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from logging_config import get_logger
from tradecraft import clock
from tradecraft.contract import JobContext, JobOutcome, JobProgress
from tradecraft.ingest import (
    builders,
    cards,
    crawl,
    curation,
    entities,
    fetch,
    focus,
    incremental,
    legacy_map,
    report,
    sections,
    storage,
    summary,
    tags,
    titles,
    tree,
)
from tradecraft.ingest.builders import Candidate
from tradecraft.ingest.detect import WEBSITE, detect

logger = get_logger(__name__)

# The job error codes that end ingestion at once: a request that must not be repeated.
_REFUSALS = ("blocked_private_address", "userinfo_refused", "bad_url")
# A start page this short is not worth an entry of its own (1.x's homepage fallback).
_FALLBACK_MIN_CHARS = 200


class Cancelled(Exception):
    pass


@dataclass
class IngestState:
    """Everything a stage reads and writes. Stages add their results here; nothing here is
    shared between jobs."""

    ctx: JobContext
    store: Any
    blocking: Callable[..., Awaitable[Any]]
    build_llm: Optional[Callable[[str, str], Awaitable[Any]]]
    started: float = 0.0
    # The resource as the job was started.
    url: str = ""
    owner_id: str = ""
    resource_id: str = ""
    generation: int = 0
    storage_mode: str = "live"
    github_token: Optional[str] = None
    clean_args: tuple = (None, ())
    # fetch_home / detect / build_map
    home: Optional[fetch.FetchedPage] = None
    home_problem: str = ""
    site_type: str = WEBSITE
    meta: dict = field(default_factory=dict)
    index_kind: str = "none"
    crawl: Optional[crawl.CrawlResult] = None
    entries: list[Candidate] = field(default_factory=list)
    map_error: str = ""
    # later stages
    curations: list = field(default_factory=list)
    previous: dict = field(default_factory=dict)
    texts: dict = field(default_factory=dict)
    cards: list[dict] = field(default_factory=list)
    sections: dict = field(default_factory=dict)
    tree: list[dict] = field(default_factory=list)
    summary: Optional[str] = None
    report: Any = None
    legacy_sitemap: dict = field(default_factory=dict)
    legacy_type: str = WEBSITE
    legacy_hash: str = ""
    # report counters
    visited: int = 0
    store_downloads: int = 0
    store_download_failures: int = 0
    llm_calls: int = 0
    stop_reason: str = ""
    skipped: dict = field(default_factory=lambda: {"excluded": 0, "outOfScope": 0, "tooLittleText": 0,
                                                   "robots": 0, "outsideFocus": 0})
    stored_counts: dict = field(default_factory=lambda: {"pages": 0, "bytes": 0, "notStoredQuota": 0,
                                                         "notStoredSize": 0})
    errors: collections.Counter = field(default_factory=collections.Counter)
    _llm: Any = None
    _llm_built: bool = False

    @property
    def settings(self):
        return self.ctx.settings

    @property
    def request(self):
        return self.ctx.request

    def count_error(self, code: str) -> None:
        self.errors[code or "internal_error"] += 1

    async def check_cancelled(self) -> None:
        if await self.ctx.is_cancelled():
            raise Cancelled()

    async def stage(self, name: str, progress: Optional[JobProgress] = None) -> None:
        await self.check_cancelled()
        await self.ctx.set_stage(name, progress)

    async def progress(self, name: str, done: int, total: int, unit: str) -> None:
        await self.ctx.set_stage(name, JobProgress(done=done, total=total, unit=unit))

    async def clean(self, html: str) -> str:
        """HTML to Markdown on the job's thread pool, with the resource's content settings."""
        return await self.blocking(fetch.clean_page_args, html, *self.clean_args)

    def model_id(self) -> str:
        return self.request.resource.model or self.settings.str("summary.defaultModel")

    async def model(self) -> Any:
        """The owner's model for this job, built once; None when the resource names none."""
        if not self._llm_built:
            self._llm_built = True
            model_id = self.model_id()
            if model_id and self.build_llm is not None:
                self._llm = await self.build_llm(self.owner_id, model_id)
        return self._llm


async def _inline(fn: Callable[..., Any], *args: Any) -> Any:
    return fn(*args)


async def run(ctx: JobContext, *, store: Any = None, run_blocking: Optional[Callable[..., Awaitable[Any]]] = None,
              build_llm: Optional[Callable[[str, str], Awaitable[Any]]] = None) -> JobOutcome:
    if store is None:
        from tradecraft.store import Store
        store = Store()
    if build_llm is None:
        from tradecraft.models import build_ingest_llm
        build_llm = build_ingest_llm
    req = ctx.request
    secrets = req.secrets
    state = IngestState(
        ctx=ctx, store=store, blocking=run_blocking or _inline, build_llm=build_llm, started=clock.monotonic(),
        url=req.resource.url, owner_id=req.user_id, resource_id=req.resource_id, generation=ctx.target_generation,
        storage_mode=req.resource.storage_mode, github_token=secrets.github_token if secrets else None,
    )
    opts = fetch.content_options(ctx.settings)
    state.clean_args = (opts["body_selector"], opts["remove"])
    try:
        return await _run(state)
    except Cancelled:
        logger.info(f"[tradecraft] job {req.job_id} cancelled code=cancelled")
        return JobOutcome(status="cancelled", error_code="cancelled")


async def _run(state: IngestState) -> JobOutcome:
    await fetch_home(state)
    if state.home_problem in _REFUSALS:
        return JobOutcome(status="failed", error_code=state.home_problem)
    await detect_type(state)
    await build_map(state)
    for name, step in (("curation", curation.apply), ("focus", focus.select), ("titles", titles.apply),
                       ("incremental", incremental.plan)):
        await state.stage(name)
        await step(state)

    failure = failure_code(state)
    if failure and state.settings.str("refreshing.onFailure") == "keep":
        return JobOutcome(status="failed", error_code=failure)

    await state.stage("store")
    await storage.store(state)
    if not failure:
        failure = storage.failure_code(state)
        if failure and state.settings.str("refreshing.onFailure") == "keep":
            return JobOutcome(status="failed", error_code=failure)
    for name, step in (("cards", cards.build), ("sections", sections.build), ("tags", tags.tag),
                       ("entities", entities.extract), ("tree", tree.build), ("content_check", focus.content_check)):
        await state.stage(name)
        await step(state)
    await state.stage("write")
    await write(state)
    await state.stage("summary")
    await summary.summarize(state)
    await state.stage("report")
    await report.build(state)
    await state.stage("legacy_map")
    await legacy_map.build(state)
    await state.stage("swap")
    return await swap(state, failure)


# --------------------------------------------------------------------------------------
# The first three stages
# --------------------------------------------------------------------------------------

async def fetch_home(state: IngestState) -> None:
    await state.stage("fetch_home")
    home = await fetch.smart_fetch(state.url, state.settings, github_token=state.github_token, cleaner=state.clean)
    state.visited += 1
    state.home = home
    state.home_problem = fetch.homepage_problem(home, state.settings)
    if state.home_problem:
        state.count_error(state.home_problem)
    if home.truncated:
        state.count_error(fetch.PAGE_TOO_LARGE)


async def detect_type(state: IngestState) -> None:
    await state.stage("detect")
    forced = state.request.resource.forced_type
    if forced:
        state.site_type = forced
    elif state.home.is_pdf:
        state.site_type = "pdf"
    elif state.home_problem:
        # 1.x: a start page that failed or is thin is not classified; the crawl reads it.
        state.site_type = WEBSITE
    else:
        state.site_type = detect(state.url, state.home.html, state.home.status, state.settings)


async def build_map(state: IngestState) -> None:
    await state.stage("build_map")
    s, t = state.settings, state.site_type
    if t == "pdf":
        if not state.home.is_pdf:
            state.map_error = "fetch_failed"
            return
        result = await builders.build_pdf(state.url, state.home.body, s, blocking=state.blocking)
        _take(state, result)
    elif t != WEBSITE:
        forced = bool(state.request.resource.forced_type)
        result = await builders.build_known(
            t, state.url, s, github_token=state.github_token, home_html=state.home.html,
            home_final_url=state.home.final_url, blocking=state.blocking, forced=forced)
        _take(state, result)
        if result.retype and not forced:
            state.site_type = result.retype
            logger.info(f"[tradecraft] job {state.request.job_id} retyped code=")
    else:
        await _crawl(state)
    _drop_unstorable_urls(state)
    _homepage_fallback(state)


def _drop_unstorable_urls(state: IngestState) -> None:
    """The last guard before the page store: a URL the contract refuses (over 2,048 bytes, not
    http(s)) would fail the whole write at the page-ID index."""
    kept = [e for e in state.entries if fetch.entry_url_ok(e.url)]
    if len(kept) != len(state.entries):
        state.errors["url_too_long_or_bad"] += len(state.entries) - len(kept)
        state.entries = kept


def _take(state: IngestState, result: builders.MapResult) -> None:
    state.entries = list(result.entries)
    state.meta = dict(result.meta)
    state.index_kind = result.index_kind
    if result.error:
        state.map_error = result.error
        state.count_error(result.error)
    if result.note:
        logger.info(f"[tradecraft] job {state.request.job_id} build_map note={result.note}")


async def _crawl(state: IngestState) -> None:
    # Only the model-guided crawl needs the owner's model, and Auto only when the site has no
    # usable sitemap: a Rule-based or sitemap crawl whose model cannot be built still maps the
    # site, and only the summary is kept as it was.
    strategy = state.settings.str("crawl.strategy")
    llm, model_error = None, ""
    if strategy != "rules":
        try:
            llm = await state.model()
        except Exception as exc:
            model_error = crawl.error_code_of(exc)
    if model_error and strategy == "llm":
        state.map_error = model_error
        state.count_error(model_error)
        return

    async def progress(done: int, total: int) -> None:
        await state.progress("build_map", done, total, "pages")

    result = await crawl.crawl(state.url, state.settings, llm=llm, blocking=state.blocking,
                               cancel_check=state.ctx.is_cancelled, progress=progress)
    if result.stop_reason == "cancelled":
        raise Cancelled()
    if model_error:
        state.count_error(model_error)
        if result.stats.get("strategy") == "llm":
            # Auto found no usable sitemap, and its model-guided crawl had no model.
            state.map_error = model_error
            return
    state.crawl = result
    state.entries = list(result.entries)
    state.visited += int(result.stats.get("pages_fetched", 0))
    state.llm_calls += result.llm_calls
    for reason, n in result.skipped.items():
        state.skipped[reason] = state.skipped.get(reason, 0) + n
    for code, n in result.errors.items():
        state.errors[code] += n
    if result.error_code:
        state.count_error(result.error_code)
        if not result.entries:
            state.map_error = result.error_code


# A crawl that needed the owner's model and could not have it found nothing: its map is not
# replaced by the start page alone (the refresh fails and the previous map stays).
_MODEL_ERRORS = ("model_unavailable", "llm_budget_exhausted", "loop_model_not_supported_here")


def _homepage_fallback(state: IngestState) -> None:
    """1.x: an empty map of a site whose start page answered gets that page as its only entry
    (never for a PDF or a CVE archive, which are never listed this way)."""
    home = state.home
    if state.entries or state.site_type in ("pdf", "cve-poc-db") or home is None or state.map_error in _MODEL_ERRORS:
        return
    if not (0 < home.status < 400) or len(home.text or "") < _FALLBACK_MIN_CHARS:
        return
    host = urllib.parse.urlsplit(state.url).hostname or state.url
    source = "crawl" if state.site_type == WEBSITE else "nav"
    state.entries = [Candidate(fetch.canonical_url(state.url), f"{host} (homepage)", source, state.url)]
    if state.site_type != WEBSITE:
        state.count_error("map_empty_homepage_only")


def failure_code(state: IngestState) -> str:
    """The code of a refresh that failed or came back empty, or "" for a usable result. A
    CVE archive has no entries by design."""
    kept = [e for e in state.entries if e.extra.get("status", "kept") == "kept"]
    if kept or (state.site_type == "cve-poc-db" and not state.map_error):
        return ""
    return state.map_error or state.home_problem or "fetch_failed"


# --------------------------------------------------------------------------------------
# Writing the generation and swapping it in
# --------------------------------------------------------------------------------------

async def write(state: IngestState) -> None:
    if not state.cards:
        return
    st, owner, rid, gen = state.store, state.owner_id, state.resource_id, state.generation
    page_ids = await st.allocate_page_ids(owner, rid, [c["url"] for c in state.cards])
    rows = []
    for card in state.cards:
        row = dict(card)
        row["page_id"] = page_ids[card["url"]]
        stored = state.texts.get(card["url"])
        if stored is not None:
            row.update(stored_text=stored.text, stored_bytes=stored.bytes, text_hash=stored.text_hash,
                       size_chars=len(stored.text), fetched_at=stored.fetched_at.isoformat(),
                       etag=stored.etag, last_modified=stored.last_modified)
        rows.append(row)
    entry_ids = await st.write_entries(owner, rid, gen, rows)
    section_rows = []
    for url, secs in state.sections.items():
        entry_id = entry_ids.get(page_ids.get(url))
        if entry_id is not None:
            section_rows.extend(dict(sec, entry_id=entry_id) for sec in secs)
    if section_rows:
        await st.write_sections(owner, rid, gen, section_rows)
    if state.tree:
        await st.write_tree(owner, rid, gen, state.tree)


def swap_updates(state: IngestState, failure: str) -> dict:
    now = clock.now()
    req = state.request
    updates: dict = {
        "sitemap": state.legacy_sitemap,
        "resource_type": state.legacy_type,
        "crawl_stopped_because": state.crawl.stopped_because if state.crawl is not None else "",
        "crawl_stats": state.crawl.stats if state.crawl is not None else {},
        "last_error": failure or state.home_problem or "",
        "last_verified_at": now,
        "last_refreshed_at": now,
        "settings_snapshot": req.settings_snapshot.model_dump(),
        "settings_hash": req.settings_hash,
        "ingestion_report": state.report.model_dump(),
        "map_version": 3,
        "legacy_map_hash": state.legacy_hash,
    }
    new_summary = summary.summary_update(state)
    if new_summary is not None:
        updates["summary"] = new_summary
        updates["summary_source"] = "generated"
    elif failure and not summary.keeps_previous(state):
        # The "replace" policy: an empty result replaces the summary too, as 1.x did.
        updates["summary"] = ""
    return updates


async def swap(state: IngestState, failure: str) -> JobOutcome:
    req = state.request
    status, code = ("failed", failure) if failure else ("succeeded", "")
    answer = await state.store.swap(
        state.owner_id, state.resource_id, req.job_id, state.generation, req.resource.url,
        req.resource.storage_mode, swap_updates(state, failure), status=status, error_code=code)
    if answer == "swapped":
        return JobOutcome(status=status, error_code=code, report=state.report, swapped=True)
    code = {"gone": "resource_deleted", "changed": "resource_changed", "lost": "agent_lost"}[answer]
    return JobOutcome(status="failed", error_code=code, report=state.report)

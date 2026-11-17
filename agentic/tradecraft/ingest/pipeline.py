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

A model call the daily budget refused (``llm_budget_exhausted``, never retried) leaves the
result incomplete wherever it happened: a model-guided crawl stops after the pages it had, the
focus, the tags, the folder descriptions or the summary go without the model. The stages count
it and go on, and the job then fails with that code (``budget_failure``), so with the default
policy the previous version stays live instead of a smaller map or one without its tags, and
Save & refresh all stops its batch there (``jobs._stop_bulk``, R-027).
"""

from __future__ import annotations

import collections
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from logging_config import get_logger
from tradecraft import clock
from tradecraft import store as store_mod
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
from tradecraft.settings import EffectiveSettings

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
    repo_size_kb: Optional[int] = None
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
    folder_description_calls: int = 0
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
        # The job's login goes to the resource's own host on every request, and no stage uses
        # the browser while it is bound (§5, T6.4).
        with fetch.use_login(req.resource.url, secrets.credentials if secrets else None):
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

    failure = failure_code(state) or budget_failure(state)
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
    if not failure:
        failure = budget_failure(state)
        if failure and state.settings.str("refreshing.onFailure") == "keep":
            return JobOutcome(status="failed", error_code=failure)
    await state.stage("write")
    await write(state)
    await state.stage("summary")
    await summary.summarize(state)
    if not failure:
        failure = budget_failure(state)
        if failure and state.settings.str("refreshing.onFailure") == "keep":
            return JobOutcome(status="failed", error_code=failure)
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
    home = await fetch.smart_fetch(state.url, state.settings, github_token=state.github_token,
                                   allow_browser=browser_allowed(state), cleaner=state.clean)
    state.visited += 1
    state.home = home
    state.home_problem = fetch.homepage_problem(home, state.settings)
    if state.home_problem:
        state.count_error(state.home_problem)
    if home.truncated:
        state.count_error(fetch.PAGE_TOO_LARGE)


def browser_allowed(state: IngestState) -> bool:
    """§5: a resource with a login never uses the browser (``fetch`` refuses it too while the
    login is bound)."""
    return not fetch.has_login(state.request.secrets)


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
        reading_started = clock.monotonic()
        result = await builders.build_known(
            t, state.url, s, github_token=state.github_token, home_html=state.home.html,
            home_final_url=state.home.final_url, allow_browser=browser_allowed(state), blocking=state.blocking,
            forced=forced, should_stop=_reading_stop(state, reading_started))
        _take(state, result)
        if result.retype and not forced:
            state.site_type = result.retype
            logger.info(f"[tradecraft] job {state.request.job_id} retyped code=")
        if result.crawl_fallback and not state.entries and not state.map_error:
            await _crawl_instead(state, reading_started)
    else:
        await _crawl(state)
    _drop_unstorable_urls(state)
    _docs_start_page_only(state)
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
    state.repo_size_kb = result.repo_size_kb
    if result.report_stop:
        state.stop_reason = result.report_stop
    if result.error:
        state.map_error = result.error
        state.count_error(result.error)
    if result.note:
        logger.info(f"[tradecraft] job {state.request.job_id} build_map note={result.note}")


def _reading_stop(state: IngestState, started: float) -> builders.Stop:
    """What ends a builder's sitemap reading early: the job's cancel, and the crawl's time budget
    from ``started``, as the Auto crawl's own reading has them."""
    budget_sec = state.settings.int("crawl.timeBudgetSec")

    async def should_stop() -> str:
        if await state.ctx.is_cancelled():
            return "cancelled"
        return "time_budget" if clock.monotonic() - started >= budget_sec else ""

    return should_stop


async def _crawl(state: IngestState, settings: Optional[EffectiveSettings] = None,
                 started: Optional[float] = None) -> None:
    # Only the model-guided crawl needs the owner's model, and Auto only when the site has no
    # usable sitemap: a Rule-based or sitemap crawl whose model cannot be built still maps the
    # site, and only the summary is kept as it was.
    settings = settings or state.settings
    strategy = settings.str("crawl.strategy")
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

    result = await crawl.crawl(state.url, settings, llm=llm, blocking=state.blocking,
                               cancel_check=state.ctx.is_cancelled, progress=progress,
                               allow_browser=browser_allowed(state),
                               focus=focus.focus_of(state.request.resource.focus, settings), started=started)
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


_CRAWL_INSTEAD = "docs: no search index or sitemap, crawl"
# The words builders.build_docs reports when its reading spent the time budget.
_TIME_SPENT = "docs: no search index, time budget"


async def _crawl_instead(state: IngestState, reading_started: float) -> None:
    """A docs site whose search index and sitemaps listed nothing gets the crawl a website would
    get, with every rule and limit of the crawl, instead of a map of its homepage alone. The type
    stays: the report names the source (the crawl's own code in brackets, at most 57 characters).

    The docs builder has just read the site's sitemaps, in one budget and inside the resource's
    folder: Auto would read them again on a fresh budget and take the pages outside that folder,
    so the hand-off crawls model-guided instead (what Auto does with no usable sitemap), and stays
    in the folder. Its map is a docs map: the crawl stops at the docs limit, not the website's.

    The reading and the crawl share one time budget, from the reading's start: no check runs after
    a reading's last download, so the time left is measured here, and with none left there is no
    crawl (as Auto's own reading stops)."""
    s = state.settings
    if clock.monotonic() - reading_started >= s.int("crawl.timeBudgetSec"):
        state.stop_reason = _TIME_SPENT
        return
    state.stop_reason = _CRAWL_INSTEAD
    strategy = s.str("crawl.strategy")
    await _crawl(state, EffectiveSettings({
        **s.values, "crawl.stayInFolder": True, "crawl.strategy": "llm" if strategy == "auto" else strategy,
        "knownTypes.maxMapEntries.website": s.int("knownTypes.maxMapEntries.docs")}), started=reading_started)
    if state.crawl is not None:
        state.stop_reason = f"{_CRAWL_INSTEAD} ({state.crawl.stop_reason})"


# A crawl that needed the owner's model and could not have it found nothing: its map is not
# replaced by the start page alone (the refresh fails and the previous map stays).
_MODEL_ERRORS = ("model_unavailable", "llm_budget_exhausted", "loop_model_not_supported_here")


# A docs map that held nothing but its start page (counted in the report).
DOCS_START_PAGE_ONLY = "docs_start_page_only"


def _docs_start_page_only(state: IngestState) -> None:
    """A docs map is never its start page alone: a docs site whose index, sitemaps and crawl gave
    no other page is a failed refresh, so the previous version stays under the default policy and
    a first add fails instead of keeping a one-page map. The code says why: ``timeout`` when the
    time budget ran out, else ``fetch_failed`` (no page found)."""
    if state.site_type != "sphinx-docs" or state.map_error:
        return
    is_start = builders.same_page_as(state.url)
    if any(not is_start(e.url) for e in state.entries if e.extra.get("status", "kept") == "kept"):
        return
    timed_out = state.stop_reason == _TIME_SPENT or (state.crawl is not None and state.crawl.stop_reason == "time_budget")
    state.entries = []
    state.map_error = "timeout" if timed_out else "fetch_failed"
    state.count_error(DOCS_START_PAGE_ONLY)
    logger.info(f"[tradecraft] job {state.request.job_id} build_map code={state.map_error} note={DOCS_START_PAGE_ONLY}")


def _homepage_fallback(state: IngestState) -> None:
    """1.x: an empty map of a site whose start page answered gets that page as its only entry
    (never for a PDF or a CVE archive, which are never listed this way, nor for a docs site,
    whose map is never its start page alone)."""
    home = state.home
    if (state.entries or state.site_type in ("pdf", "cve-poc-db", "sphinx-docs") or home is None
            or state.map_error in _MODEL_ERRORS):
        return
    if not (0 < home.status < 400) or len(home.text or "") < _FALLBACK_MIN_CHARS:
        return
    host = urllib.parse.urlsplit(state.url).hostname or state.url
    source = "crawl" if state.site_type == WEBSITE else "nav"
    state.entries = [Candidate(fetch.canonical_url(state.url), f"{host} (homepage)", source, state.url)]
    if state.site_type != WEBSITE:
        state.count_error("map_empty_homepage_only")


BUDGET_EXHAUSTED = "llm_budget_exhausted"


def budget_failure(state: IngestState) -> str:
    """``llm_budget_exhausted`` when any stage counted a model call the daily budget refused,
    else "": what the job built without those calls is not a refresh to swap in."""
    return BUDGET_EXHAUSTED if state.errors.get(BUDGET_EXHAUSTED) else ""


def failure_code(state: IngestState) -> str:
    """The code of a refresh that failed or came back empty, or "" for a usable result. A map
    that failed to build fails the refresh whatever else its entries hold: curation adds the
    pinned pages to any map, an empty one included. A CVE archive has no entries by design, and a
    map whose pages the focus all dropped was read: its dropped entries are written, for the Map
    view."""
    if state.map_error:
        return state.map_error
    kept = [e for e in state.entries if e.extra.get("status", "kept") == "kept"]
    if kept or state.site_type == "cve-poc-db":
        return ""
    if any(e.extra.get("dropped_by") == "focus" for e in state.entries):
        return ""
    return state.home_problem or "fetch_failed"


# --------------------------------------------------------------------------------------
# Writing the generation and swapping it in
# --------------------------------------------------------------------------------------

async def write(state: IngestState) -> None:
    if not state.cards:
        return
    st, owner, rid, gen = state.store, state.owner_id, state.resource_id, state.generation
    page_ids = await st.allocate_page_ids(owner, rid, [c["url"] for c in state.cards])
    previous = incremental.previous_generation(state)
    rows, carried = [], []
    for card in state.cards:
        row = dict(card)
        row["page_id"] = page_ids[card["url"]]
        if row.pop("_carried", False) and previous is not None and row.get("status", "kept") == "kept":
            # Unchanged (T6.2): the text, its measures and its sections come from the live generation.
            carried.append({k: v for k, v in row.items() if k not in store_mod.CARRIED_FROM_PREVIOUS})
            continue
        stored = state.texts.get(card["url"])
        if stored is not None:
            row.update(stored_text=stored.text, stored_bytes=stored.bytes, text_hash=stored.text_hash,
                       size_chars=len(stored.text), fetched_at=stored.fetched_at.isoformat(),
                       etag=stored.etag, last_modified=stored.last_modified)
        rows.append(row)
    entry_ids = await st.write_entries(owner, rid, gen, rows) if rows else {}
    if carried:
        entry_ids.update(await st.copy_forward(owner, rid, previous, gen, carried))
    section_rows = []
    for url, secs in state.sections.items():
        entry_id = entry_ids.get(page_ids.get(url))
        if entry_id is not None:
            section_rows.extend(dict(sec, entry_id=entry_id) for sec in secs)
    if section_rows:
        await st.write_sections(owner, rid, gen, section_rows)
    if state.tree:
        await st.write_tree(owner, rid, gen, state.tree)
    # A block the person made while the job ran (T6.6): its text leaves this generation too.
    await curation.block_late(state)


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
        await curation.restore_late(state)
        return JobOutcome(status=status, error_code=code, report=state.report, swapped=True)
    code = {"gone": "resource_deleted", "changed": "resource_changed", "lost": "agent_lost"}[answer]
    return JobOutcome(status="failed", error_code=code, report=state.report)

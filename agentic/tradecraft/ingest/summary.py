"""Stage ``summary``: the text the agent reads to decide when to use a resource (§4.6).

1.x's single call and prompt, with its numbers as settings: ``summary.targetTokens`` (300
reads "250-350 tokens", 1.x's range), ``summary.homepageChars`` (6,000) and ``summary.titles``
(50), plus the person's ``summary.extraInstructions``. A PDF is summarised from its first five
pages, as in 1.x. The start page and the titles are wrapped as untrusted content.

A hand-written or locked summary is kept (no call is made). The call is made once: a failure
keeps the previous summary and counts its error code in the report (TD-20, no retry).

With a Focused ingestion focus (§6.14 step 5, T5.2) the same call describes the subset the focus
kept ("SQL injection subset of <site>: payloads and filter bypasses"), from the kept pages'
titles, so the agent does not look for pages that were dropped. No extra call is made.

``regenerate`` is the ``regenerate_summary`` job (§6.9, T4.1): the same call over the saved
map's titles and the start page read again, with no crawl; only the summary is swapped in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

from agent_in_the_loop.purpose import llm_purpose
from logging_config import get_logger
from orchestrator_helpers.json_utils import normalize_content
from prompt_safety import UNTRUSTED_OUTPUT_GUIDANCE, wrap_untrusted
from tradecraft import clock
from tradecraft.contract import ERROR_CODES, JobContext, JobOutcome
from tradecraft.ingest import fetch
from tradecraft.ingest.builders import Candidate
from tradecraft.ingest.crawl import error_code_of

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

PDF_SUMMARY_PAGES = 5


def focus_instruction(focus: Any, kept: int) -> str:
    """What the summary must say of a focused resource: only the subset its focus kept (a
    Regenerate reads the saved map, which holds the kept pages only)."""
    from tradecraft.ingest.focus import focus_lines

    return (
        f"This resource keeps only part of the site ({kept} pages), chosen by its owner's focus:\n"
        f"  {focus_lines(focus)}\n"
        "Describe that subset, not the whole site, and say so first (for example \"SQL injection subset of "
        "<site>: payloads and filter bypasses\"), so the agent does not look here for pages that were left out."
    )


def system_prompt(target_tokens: int, extra: str = "", focus_line: str = "") -> str:
    low, high = max(50, target_tokens - 50), target_tokens + 50
    prompt = (
        "You are summarizing a security-knowledge website so an autonomous "
        f"pentest agent can decide when to consult it. Output {low}-{high} tokens.\n"
        "Mention: domains covered (web, AD, cloud, mobile, ...), structure "
        "(per-CVE, per-payload, per-technique), and the kinds of pentest queries "
        "it answers best. No marketing language. No first person.\n\n"
        + UNTRUSTED_OUTPUT_GUIDANCE
    )
    if focus_line:
        prompt += "\n\n" + focus_line
    if extra.strip():
        prompt += "\n\nInstructions from the person who added this resource:\n" + extra.strip()
    return prompt


def user_message(url: str, site_type: str, body: str, titles: list[str], homepage_chars: int, n_titles: int) -> str:
    sample = "\n  - ".join(t[:80] for t in titles[:n_titles] if t)
    return (
        f"URL: {url}\n"
        f"Detected type: {site_type}\n\n"
        f"Homepage / README excerpt (first {homepage_chars} chars):\n"
        + wrap_untrusted((body or "")[:homepage_chars], "WEB_CONTENT") + "\n\n"
        + f"Sample page titles from sitemap (first {n_titles}):\n"
        + wrap_untrusted("  - " + sample, "WEB_CONTENT") + "\n"
    )


def keeps_previous(state: "IngestState") -> bool:
    resource = state.request.resource
    return resource.summary_locked or resource.summary_source == "manual"


def source_text(state: "IngestState") -> str:
    if state.site_type == "pdf":
        pages = [e.extra.get("text") or "" for e in state.entries[:PDF_SUMMARY_PAGES]]
        return "\n\n".join(pages)
    return state.home.text if state.home is not None else ""


async def summarize(state: "IngestState") -> "IngestState":
    """Sets ``state.summary`` to the new text, or leaves it None to keep the previous one."""
    if keeps_previous(state):
        return state
    s = state.settings
    body = source_text(state)
    titles = [e.title for e in state.entries if e.extra.get("status", "kept") == "kept"]
    if not body and not titles:
        return state
    try:
        llm = await state.model()
    except Exception as exc:
        state.count_error(error_code_of(exc))
        return state
    if llm is None:
        return state
    from tradecraft.ingest.focus import focus_of

    focus = focus_of(state.request.resource.focus, s)
    focus_line = focus_instruction(focus, len(titles)) if focus.filters else ""
    messages = [
        {"role": "system", "content": system_prompt(s.int("summary.targetTokens"), s.str("summary.extraInstructions"),
                                                    focus_line)},
        {"role": "user", "content": user_message(state.url, state.site_type, body, titles,
                                                 s.int("summary.homepageChars"), s.int("summary.titles"))},
    ]
    state.llm_calls += 1
    try:
        with llm_purpose("tradecraft_ingest", step="summary"):
            resp = await llm.ainvoke(messages)
    except Exception as exc:
        state.count_error(error_code_of(exc))
        return state
    text = normalize_content(getattr(resp, "content", "") or "").strip()
    if text:
        state.summary = text
    else:
        state.count_error("summary_empty")
    return state


def summary_update(state: "IngestState") -> Optional[str]:
    return None if keeps_previous(state) else state.summary


# --------------------------------------------------------------------------------------
# Regenerate summary
# --------------------------------------------------------------------------------------

def saved_map(row: dict, url: str) -> tuple[str, list[Candidate]]:
    """(site type, entries) of the resource's live map, read from the 1.x ``sitemap`` every 2.0
    ingestion also writes (TD-18): titles only, which is all the summary reads of a map."""
    sitemap = row.get("sitemap") if isinstance(row.get("sitemap"), dict) else {}
    if isinstance(sitemap.get("pages"), list):
        canonical = fetch.canonical_url(url)
        return "pdf", [Candidate(f"{canonical}#page={p.get('page')}", str(p.get("firstLine") or ""), "pdf",
                                 str(p.get("page")), {"page": p.get("page")})
                       for p in sitemap["pages"] if isinstance(p, dict) and p.get("page")]
    items = sitemap.get("tree") if isinstance(sitemap.get("tree"), list) else sitemap.get("nav")
    entries = [Candidate(str(it.get("path") or ""), str(it.get("title") or ""), "map", str(it.get("path") or ""))
               for it in (items if isinstance(items, list) else []) if isinstance(it, dict)]
    return str(row.get("resource_type") or "agentic-crawl"), entries


async def regenerate(ctx: JobContext, *, store: Any = None,
                     run_blocking: Optional[Callable[..., Awaitable[Any]]] = None,
                     build_llm: Optional[Callable[[str, str], Awaitable[Any]]] = None) -> JobOutcome:
    """A new generated summary for the resource as it is: its live map's titles, its start page
    fetched again (a PDF's first stored pages), the job's settings. Writes no generation: only
    ``summary`` and ``summary_source`` change, through the swap, which also leaves a summary the
    person locked or wrote meanwhile as it is. A locked or hand-written summary makes no call."""
    from tradecraft.ingest import pipeline  # it imports this module

    if store is None:
        from tradecraft.store import Store
        store = Store()
    if build_llm is None:
        from tradecraft.models import build_ingest_llm
        build_llm = build_ingest_llm
    req = ctx.request
    owner, rid = req.user_id, req.resource_id
    row = await store.legacy_sitemap(owner, rid)
    if row is None:
        return JobOutcome(status="failed", error_code="resource_deleted")
    state = pipeline.IngestState(
        ctx=ctx, store=store, blocking=run_blocking or pipeline._inline, build_llm=build_llm,
        started=clock.monotonic(), url=req.resource.url, owner_id=owner, resource_id=rid,
        generation=int(row.get("generation") or 0), storage_mode=req.resource.storage_mode,
        github_token=req.secrets.github_token if req.secrets else None)
    options = fetch.content_options(ctx.settings)
    state.clean_args = (options["body_selector"], options["remove"])
    try:
        await state.stage("summary")
        state.site_type, state.entries = saved_map(row, req.resource.url)
        if not keeps_previous(state):
            await _read_sources(state, store, has_login=bool(row.get("has_login")))
            await summarize(state)
            if state.summary is None:
                return JobOutcome(status="failed", error_code=_failure_code(state))
            await state.check_cancelled()
    except pipeline.Cancelled:
        return JobOutcome(status="cancelled", error_code="cancelled")
    updates = {} if state.summary is None else {"summary": state.summary, "summary_source": "generated"}
    answer = await store.swap(owner, rid, req.job_id, state.generation, req.resource.url,
                              req.resource.storage_mode, updates, status="succeeded")
    if answer == "swapped":
        return JobOutcome(status="succeeded", swapped=True)
    return JobOutcome(status="failed",
                      error_code={"gone": "resource_deleted", "changed": "resource_changed", "lost": "agent_lost"}[answer])


async def _read_sources(state: "IngestState", store: Any, *, has_login: bool) -> None:
    if state.site_type == "pdf":
        for entry in state.entries[:PDF_SUMMARY_PAGES]:
            stored = await store.entry_by_url(state.owner_id, state.resource_id, entry.url)
            entry.extra["text"] = (stored or {}).get("stored_text") or ""
        return
    # §5: a resource with a login never goes to the browser.
    state.home = await fetch.smart_fetch(state.url, state.settings, github_token=state.github_token,
                                         allow_browser=not has_login, cleaner=state.clean)
    if state.home.error or not (200 <= state.home.status < 400):
        state.count_error(fetch.homepage_problem(state.home, state.settings) or "fetch_failed")


def _failure_code(state: "IngestState") -> str:
    """Why no summary came back, as a job error code: the model's own code when it gave one."""
    for code in state.errors:
        if code in ERROR_CODES:
            return code
    if not state.entries and not (state.home and state.home.text):
        return "fetch_failed"
    if state.errors:
        return "internal_error"
    return "model_unavailable"

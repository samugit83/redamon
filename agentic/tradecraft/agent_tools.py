"""The tools a 2.0 run calls (TD-10): ``tradecraft_lookup``, which keeps its name and its
arguments and gains ``page``, ``section`` and ``part`` (Q8), ``tradecraft_search`` (Q7.1), and
``tradecraft_ask`` (Q9), the librarian. They are registered once in the executor (as ``tool_proxies``
stand-ins) and offered only to a run whose catalog is 2.0 (the companion set in ``project_settings``),
the librarian only while its owner's Librarian use is Agent decides; called in any other run, they
answer that they are not available.

Search and the librarian know the attack session from structured run data only (Q12): the
current skill's topic, the phase, the target's technologies as vocabulary ids, and its CVE ids
as the CVE pattern finds them. The executor nodes bind it with ``bind_session(state)`` next to the
run state, before the tools run.
"""

from __future__ import annotations

import asyncio
import contextvars
from dataclasses import replace
from typing import Any, Mapping, Optional, Union

from langchain_core.tools import tool

from agent_context import current_phase
from logging_config import get_logger
from tradecraft import librarian, overlay, run_state, runtime
from tradecraft.ingest import entities as entity_rules
from tradecraft.ingest.crawl import error_code_of
from tradecraft.librarian import graph as librarian_graph
from tradecraft.librarian.tools import Found, LibraryTools, narrowed
from tradecraft.library import reader, search, split
from tradecraft.library.types import (
    BROWSE_HEADER,
    BROWSE_LINE,
    BROWSE_MORE,
    READ_HINT,
    SEARCH_HIT,
    SEARCH_TRIED,
    BrowseLevel,
    SearchAnswer,
    format_search_header,
    wrap_untrusted,
)
from tradecraft.settings import EffectiveSettings
from tradecraft.vocab import load_vocab

logger = get_logger(__name__)

SEARCH_NOT_AVAILABLE =("Error: tradecraft_search is not available in this run (its Tradecraft library is not "
                        "2.0); use tradecraft_lookup.")
NEEDS_QUERY = ("Error: give tradecraft_search a query, or a resource (and a path) to browse, e.g. "
               'tradecraft_search(resource="patt", path="").')
NOT_FOUND_ADVICE = ("Nothing in the library matches. Do not retry these wordings; use web_search, or browse a "
                    "resource with tradecraft_search(resource=..., path=\"\").")
RELATED_ADVICE = "Related pages only: none clearly answers the need. Read the closest one by section, or refine."
CVE_BROWSE = ('CVE archive: look a CVE up with tradecraft_lookup(resource_id="{slug}", cve_id="CVE-YYYY-NNNNN"); '
              "it is not browsed.")
UNCONVERTED = ("Not searchable until converted to 2.0 (read with tradecraft_lookup(resource_id=..., query=...)): "
               "{slugs}.")
HIT_PATH_CHARS = 110
HIT_TEXT_CHARS = 90

ASK_NOT_AVAILABLE = ("Error: tradecraft_ask is not available in this run (its Tradecraft library is not 2.0, or "
                     "its owner chose Search only); use tradecraft_search.")
NEEDS_NEED = ('Error: give tradecraft_ask a need in a sentence, e.g. '
              'tradecraft_ask(need="the WAF blocks SLEEP; another way to cause a delay on PostgreSQL").')
ASK_LIMIT = ("Error: this run already asked the librarian {limit} times, its limit (Questions per agent run). "
             "Read the pages found so far with tradecraft_lookup, or use tradecraft_search.")
LIBRARY_TIMEOUT = "Error: the library did not answer within {secs} s; use tradecraft_search."
LIBRARY_ERROR = "Error: the library could not be searched (internal_error); use tradecraft_search."
OUTSIDE_RUN = "the librarian runs only inside an agent run: these are the plain search results"
MODEL_UNAVAILABLE = "the librarian model could not be used ({code}): these are the plain search results"
HARD_TIME_UP = "the time limit of {secs} s was reached: these are the plain search results"
# Seconds past the librarian's own stop for the free first pass and building the model; with the
# highest time limit (120 s) the whole call stays under the executor's 150 s for the tool.
ASK_GRACE_SEC = 5.0
MAX_SESSION_CVES = 20

_session: contextvars.ContextVar[Optional[search.Session]] = contextvars.ContextVar(
    "tradecraft_search_session", default=None)
_session_cves: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "tradecraft_session_cves", default=())


def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


def session_from_state(state: Mapping[str, Any]) -> search.Session:
    """The attack session search boosts by: the skill's topic when the skill is a vocabulary
    topic (a built-in skill), the phase, and the target's technologies the shipped list knows."""
    path = str(state.get("attack_path_type") or "")
    topic = path if path in load_vocab().topic_ids else None
    technologies = _get(state.get("target_info") or {}, "technologies") or []
    return search.Session(topic=topic, phase=state.get("current_phase") or None,
                          technologies=search.technologies_of(technologies))


def session_cves(state: Mapping[str, Any]) -> tuple[str, ...]:
    """The target's CVE ids from its structured recon data. ``vulnerabilities`` also holds free
    descriptions written from tool output, so only what the CVE pattern matches is kept."""
    found: list[str] = []
    for value in _get(state.get("target_info") or {}, "vulnerabilities") or []:
        if not isinstance(value, str):
            continue
        for cve in entity_rules.cve_ids(value):
            if cve not in found:
                found.append(cve)
    return tuple(found[:MAX_SESSION_CVES])


def bind_session(state: Mapping[str, Any]) -> search.Session:
    session = session_from_state(state)
    _session.set(session)
    _session_cves.set(session_cves(state))
    return session


def current_session() -> search.Session:
    session = _session.get()
    phase = current_phase.get() or None
    if session is None:
        return search.Session(phase=phase)
    return session if session.phase else search.Session(session.topic, phase, session.technologies)


# --------------------------------------------------------------------------------------
# The answers
# --------------------------------------------------------------------------------------

def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _kind_label(kinds: tuple) -> str:
    labels = {k["id"]: k["mapLabel"] for k in load_vocab().kinds}
    return ", ".join(labels.get(k, k) for k in kinds[:2]) or "page"


def render_search(query: str, answer: SearchAnswer, names: Mapping[str, str], unconverted: list[str]) -> str:
    """Q7.1's search answer: about 500 tokens for 8 results."""
    lines = [format_search_header(_clip(query, 120), answer.verdict, len(answer.hits), answer.total)]
    for n, hit in enumerate(answer.hits, 1):
        card = hit.card
        path = " › ".join([names.get(card.resource_slug, card.resource_slug), *card.breadcrumb, card.title])
        lines.append(SEARCH_HIT.format(n=n, page_id=card.page_id, breadcrumb=_clip(path, HIT_PATH_CHARS),
                                       description=_clip(hit.snippet or card.description or "-", HIT_TEXT_CHARS),
                                       kind=_kind_label(card.kinds)))
    if answer.hits:
        top = answer.hits[0]
        section = top.section or (top.card.headings[0] if top.card.headings else "")
        # The whole heading: following a hint whose heading was cut answered NO_SECTION.
        lines.append(READ_HINT.format(page_id=top.card.page_id, section=split.hint_value(section)))
    if answer.verdict == "NOT FOUND":
        lines += [SEARCH_TRIED.format(wordings=" | ".join(_clip(w, 80) for w in answer.wordings)), NOT_FOUND_ADVICE]
    elif answer.verdict == "RELATED":
        lines.append(RELATED_ADVICE)
    if unconverted:
        lines.append(UNCONVERTED.format(slugs=", ".join(unconverted)))
    return wrap_untrusted(lines)


def render_browse(level: BrowseLevel, resource: Any) -> str:
    """Q7.1's browse answer: one level, folders with counts and descriptions, then pages; the
    root with the resource's full summary."""
    lines = [BROWSE_HEADER.format(breadcrumb=" › ".join(level.breadcrumb), pages=level.page_count)]
    if level.summary is not None:
        lines.append(f"summary: {_clip(level.summary, 4000) or '(no summary)'}")
    # A CVE archive's pages are its index, CVE ids in file order: a list of the first ones says
    # nothing, and the archive is read by the CVE a finding names.
    archive = resource.type == "cve-poc-db"
    if archive:
        lines.append(CVE_BROWSE.format(slug=resource.slug))
    n = 0
    for folder in level.folders:
        n += 1
        lines.append(BROWSE_LINE.format(n=n, label=_clip(folder.label, 80), count=folder.page_count,
                                        description=_clip(folder.description, 100)).rstrip())
    for card in () if archive else level.pages:
        n += 1
        lines.append(f"{n:>2}. {card.page_id}  {_clip(card.title or card.url, 100)}")
    if level.more and not archive:
        lines.append(BROWSE_MORE.format(more=level.more))
    if level.folders:
        lines.append(f'browse: tradecraft_search(resource="{resource.slug}", path="{level.folders[0].path}")')
    if level.pages and not archive:
        lines.append(f'read: tradecraft_lookup(page="{level.pages[0].page_id}")')
    return wrap_untrusted(lines)


async def run_search(*, query: str = "", resource: Optional[str] = None, topic: Optional[str] = None,
                     kind: Optional[str] = None, technology: Optional[str] = None, path: Optional[str] = None,
                     index: Any = None) -> str:
    catalog = runtime.bound_catalog()
    if catalog is None:
        return SEARCH_NOT_AVAILABLE
    index = index if index is not None else runtime.run_index()
    query = (query or "").strip()
    try:
        if path is not None or (resource and not query):
            level = await search.browse(catalog.owner_id, catalog, resource or "", path or "", index=index)
            chosen = next(r for r in catalog.resources if r.slug == level.resource_slug)
            return render_browse(level, chosen)
        if not query:
            return NEEDS_QUERY
        answer = await search.search(catalog.owner_id, catalog, query, resource=resource, topic=topic, kind=kind,
                                     technology=technology, session=current_session(), index=index)
    except search.SearchError as exc:
        return f"Error: {exc}"
    names = {r.slug: (r.name or r.slug) for r in catalog.resources}
    scope = [r for r in catalog.resources if not resource or r.slug == resource]
    unconverted = sorted(r.slug for r in scope if r.map_version < 2 and r.type != "cve-poc-db")
    return render_search(query, answer, names, unconverted)


# --------------------------------------------------------------------------------------
# The librarian (Q9.2): limit, session data, free first pass, then the sub-graph
# --------------------------------------------------------------------------------------

def _library_tools(owner_id: str, catalog: Any, *, session: Optional[search.Session],
                   settings: EffectiveSettings) -> Any:
    return LibraryTools(owner_id, catalog, session=session, settings=settings)


def _build_model(model_id: str, providers: list) -> Any:
    from llm_builder import build_llm_from_providers
    return build_llm_from_providers(model_id, providers)


def _hard_limit_sec(settings: EffectiveSettings) -> float:
    return settings.int("librarian.timeLimitSec") + librarian_graph.HARD_STOP_GRACE_SEC + ASK_GRACE_SEC


def _loop_run(settings: Mapping[str, Any]) -> bool:
    """Whether this run is driven by Agent in the Loop. The librarian's own model never is (its
    builder refuses a loop model), so the run is asked: its main model, the project's model id, or
    a live loop scope of the session."""
    from agent_context import current_llm, current_log_session_id
    from agent_in_the_loop import is_loop_llm, is_loop_model

    if is_loop_llm(current_llm.get()) or is_loop_model(settings.get("OPENAI_MODEL")):
        return True
    try:
        from agent_in_the_loop.broker import get_broker
        return get_broker().scope_for_session(current_log_session_id.get()) is not None
    except Exception:
        # Unknown: no model call, as in a loop run.
        return True


def librarian_model() -> tuple[Any, str]:
    """(the owner's "Tradecraft librarian" model, "") for this run, or (None, why not).

    Read from the settings bound to the run's task only, never ``get_setting``, whose fallback
    outside a run is the last project loaded (R-405); a run's USER_SETTINGS and providers are its
    project owner's (Q10 "Shared projects"). No run state bound means no per-run limit can hold,
    so no model is built then either."""
    import project_settings as _ps
    from feature_models import feature_model

    settings = _ps._settings_ctx.get()
    if settings is None or run_state.current() is None:
        return None, OUTSIDE_RUN
    if _loop_run(settings):
        return None, librarian_graph.LOOP_RUN
    model_id = feature_model(settings.get("USER_SETTINGS") or {}, "tradecraft_librarian")
    if not model_id:
        return None, librarian_graph.NO_MODEL
    try:
        return _build_model(model_id, settings.get("USER_LLM_PROVIDERS") or []), ""
    except Exception as exc:
        code = error_code_of(exc)
        logger.warning(f"[tradecraft] librarian model unavailable code={code}")
        return None, MODEL_UNAVAILABLE.format(code=code)


def _scope_of(scope: Any) -> tuple[str, ...]:
    """Slugs from a list, or from one string of slugs separated by commas or spaces."""
    items = scope.replace(",", " ").split() if isinstance(scope, str) else (scope or [])
    out: list[str] = []
    for item in items:
        slug = str(item).strip().strip("`'\"")
        if slug and slug not in out:
            out.append(slug)
    return tuple(out[:20])


def ranked_first_pass(found: Found, collector: Optional[run_state.RunCollector], cves: tuple[str, ...]) -> Found:
    """The free first pass with the pages about the target's CVEs first and the pages this run
    already read or was suggested by a hint last (Q9.3): a boost, never a filter."""
    wanted = set(cves)
    hinted = collector.hinted() if collector is not None else set()

    def key(card: Any) -> tuple[bool, bool]:
        seen = card.page_id in hinted or (collector is not None and collector.has_seen(card.page_id))
        return seen, not (wanted & set(card.entities or ()))

    return Found(found.verdict, tuple(sorted(found.cards, key=key)))


def _with_reason(answer: Any, reason: str) -> Any:
    """The answer with ``reason`` as the line that says why the plain results answer: it replaces
    the sub-graph's "no model" line, which it also writes for a model the tool did not pass."""
    if not reason or reason == librarian_graph.NO_MODEL:
        return answer
    notes = tuple(n for n in answer.notes if n != librarian_graph.NO_MODEL)
    return replace(answer, notes=notes + (reason,))


async def run_ask(*, need: str, context: str = "", want: str = "any", scope: Any = None) -> str:
    catalog = runtime.bound_catalog()
    if catalog is None or not overlay.has_ask(catalog):
        return ASK_NOT_AVAILABLE
    need = " ".join(str(need or "").split())
    if not need:
        return NEEDS_NEED
    settings = EffectiveSettings(catalog.search or {}, scope="search")
    collector = run_state.current()
    if collector is not None:
        limit = settings.int("librarian.questionsPerRun")
        if collector.incr_within("ask", limit) is None:
            return ASK_LIMIT.format(limit=limit)
    request = librarian.Request(need=need, context=" ".join(str(context or "").split()),
                                want=str(want or "any").strip().lower(), scope=_scope_of(scope))
    session = current_session()
    tools = _library_tools(catalog.owner_id, narrowed(catalog, request.scope)[0], session=session,
                           settings=settings)
    kwargs = dict(owner_id=catalog.owner_id, person_id=catalog.person_id, catalog=catalog, session=session,
                  settings=settings, tools=tools)
    first: Optional[Found] = None

    async def go() -> Any:
        nonlocal first
        first = ranked_first_pass(await tools.search(need), collector, _session_cves.get())
        found = first.verdict != "NOT FOUND" and bool(first.cards)
        llm, reason = librarian_model() if found else (None, "")
        return _with_reason(await librarian.ask(request, llm=llm, first=first, **kwargs), reason)

    secs = settings.int("librarian.timeLimitSec")
    try:
        answer = await asyncio.wait_for(go(), timeout=_hard_limit_sec(settings))
    except asyncio.TimeoutError:
        if first is None:
            logger.warning("[tradecraft] ask code=timeout step=first_pass")
            return LIBRARY_TIMEOUT.format(secs=secs)
        logger.warning("[tradecraft] ask code=timeout")
        answer = _with_reason(await librarian.ask(request, llm=None, first=first, **kwargs),
                              HARD_TIME_UP.format(secs=secs))
    except Exception as exc:
        logger.warning(f"[tradecraft] ask code=internal_error error={type(exc).__name__}")
        return LIBRARY_ERROR
    if collector is not None:
        collector.record_seen(p.page_id for p in answer.picks)
    return librarian.render(answer)


# --------------------------------------------------------------------------------------
# The tools
# --------------------------------------------------------------------------------------

@tool
async def tradecraft_lookup(
    resource_id: str = "",
    query: str = "",
    cve_id: Optional[str] = None,
    section_path: Optional[str] = None,
    force_refresh: bool = False,
    page: Optional[str] = None,
    section: Optional[str] = None,
    part: Optional[int] = None,
) -> str:
    """Read one section of a page of the Tradecraft library.

    The resources and how to choose between the tradecraft tools are in the system prompt
    under TOOL_REGISTRY[tradecraft_lookup] and TOOL_REGISTRY[tradecraft_search].

    Args:
        page: a page ID from tradecraft_search, a hint or the librarian, such as "patt:412"
        section: a heading of that page (the result lists the others)
        part: the part of a long section to read (the result says how many)
        resource_id: slug of a resource, with query, when you have no page ID
        query: what you need; picks the page (with resource_id) or the section (with page)
        cve_id: with resource_id, the CVE to read from a cve-poc-db resource (a page ID of that CVE reads it too)
        section_path: skip the pick; force a path of the resource's map, or "page=N" for PDFs (any other address is refused)
        force_refresh: read a Stored resource's page from the site instead of its stored copy
    """
    return await reader.lookup(resource_id=resource_id or "", query=query or "", cve_id=cve_id,
                               section_path=section_path, force_refresh=bool(force_refresh), page=page,
                               section=section, part=part)


@tool
async def tradecraft_search(
    query: str = "",
    resource: Optional[str] = None,
    topic: Optional[str] = None,
    kind: Optional[str] = None,
    technology: Optional[str] = None,
    path: Optional[str] = None,
) -> str:
    """Search the Tradecraft library for pages, or browse one level of a resource's tree.

    Args:
        query: what to find (required unless browsing)
        resource: one resource's slug only
        topic: only pages of this topic (e.g. "SQL injection", "Active Directory")
        kind: only pages of this kind (payloads, bypasses, methodology, tool commands, PoC, write-ups)
        technology: only pages about this product or tool (e.g. "PostgreSQL")
        path: browse this level of the resource's tree ("" for its root); no query
    """
    return await run_search(query=query or "", resource=resource, topic=topic, kind=kind, technology=technology,
                            path=path)


@tool
async def tradecraft_ask(
    need: str,
    context: str = "",
    want: str = "any",
    scope: Optional[Union[list[str], str]] = None,
) -> str:
    """Ask the Tradecraft librarian for a vague need: it searches the library, reads the
    promising sections and answers up to three checked pages with exact excerpts.

    Args:
        need: what you need, in a sentence (e.g. "the WAF blocks SLEEP; another delay on PostgreSQL")
        context: what you know (the parameter, what works, what is blocked)
        want: payload, methodology, poc or any
        scope: resource slugs to limit it to (e.g. ["patt", "hacktricks"])
    """
    return await run_ask(need=need, context=context or "", want=want or "any", scope=scope)


lookup_tool = tradecraft_lookup
search_tool = tradecraft_search
ask_tool = tradecraft_ask

V2_TOOLS = {"tradecraft_lookup": lookup_tool, "tradecraft_search": search_tool, "tradecraft_ask": ask_tool}


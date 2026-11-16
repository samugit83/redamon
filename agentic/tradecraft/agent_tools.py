"""The tools a 2.0 run calls (TD-10): ``tradecraft_lookup``, which keeps its name and its
arguments and gains ``page``, ``section`` and ``part`` (Q8), and ``tradecraft_search`` (Q7.1),
new. Both are registered once in the executor (``registered_tools``) and offered only to a run
whose catalog is 2.0 (the companion set in ``project_settings``); called in any other run, they
answer that they are not available.

Search knows the attack session from structured run data only (Q12): the current skill's topic,
the phase, and the target's technologies as vocabulary ids. The executor nodes bind it with
``bind_session(state)`` next to the run state, before the tools run.
"""

from __future__ import annotations

import contextvars
from typing import Any, Mapping, Optional

from langchain_core.tools import tool

from agent_context import current_phase
from tradecraft import runtime
from tradecraft.library import reader, search
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
from tradecraft.vocab import load_vocab

SEARCH_NOT_AVAILABLE = ("Error: tradecraft_search is not available in this run (its Tradecraft library is not "
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

_session: contextvars.ContextVar[Optional[search.Session]] = contextvars.ContextVar(
    "tradecraft_search_session", default=None)


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


def bind_session(state: Mapping[str, Any]) -> search.Session:
    session = session_from_state(state)
    _session.set(session)
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
        lines.append(READ_HINT.format(page_id=top.card.page_id, section=_clip(section, 60).replace('"', "'")))
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
    if resource.type == "cve-poc-db":
        lines.append(CVE_BROWSE.format(slug=resource.slug))
    n = 0
    for folder in level.folders:
        n += 1
        lines.append(BROWSE_LINE.format(n=n, label=_clip(folder.label, 80), count=folder.page_count,
                                        description=_clip(folder.description, 100)).rstrip())
    for card in level.pages:
        n += 1
        lines.append(f"{n:>2}. {card.page_id}  {_clip(card.title or card.url, 100)}")
    if level.more:
        lines.append(BROWSE_MORE.format(more=level.more))
    if level.folders:
        lines.append(f'browse: tradecraft_search(resource="{resource.slug}", path="{level.folders[0].path}")')
    if level.pages:
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
        cve_id: required for a cve-poc-db resource
        section_path: skip the pick; force a specific path or "page=N" for PDFs
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


lookup_tool = tradecraft_lookup
search_tool = tradecraft_search

V2_TOOLS = {"tradecraft_lookup": lookup_tool, "tradecraft_search": search_tool}


def registered_tools() -> dict:
    """The 2.0 tools the executor registers once, whatever the run (T7.4 adds the librarian):
    in a run whose catalog is not 2.0 they answer that they are not available."""
    return {"tradecraft_search": search_tool}

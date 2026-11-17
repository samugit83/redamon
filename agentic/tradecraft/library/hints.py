"""Library now (owner decision 2026-11-17; it replaced T8.1's notes at fixed checkpoints): the
library's best pages for the agent's current goal, at the end of the think call's system
message, kept fresh, at no model cost.

The main agent's think node asks ``library_now(state, catalog)`` before its model call (Fireteam
members get none, Q13). When the goal or a fact of the session changed since the last check
(``profile.changes``), the agent's own code searches the run owner's library: the goal's words
through the free first pass (Q7.2) with the session (topic, phase, technologies), and the
session's newest CVE ids, which an exact match lets through. A page is kept when the search's
own scores pass the run's match strictness (``search.is_related``) and something of the goal is
in its title, breadcrumb or headings, or it names one of the CVE ids exactly, or its title is a
close fuzzy match (``fits``). Pages the run already read go; the best ``STANDING`` stay, and the
block shows the first ``constants.pagesPerHint`` (3) not read yet. Without a change there is no
search: the same block is shown again, a page dropping out once the agent reads it, and a new
search replaces it when the goal or the facts move on.

The block is in the system role and apart from the base prompt's text: ``with_note`` puts it at
the end of the call's one system message, after the prompt's cache tiers, so every cached
prefix stays as it was. Its header holds the goal as data (in quotes, one line, clipped); the
pages' resource names, breadcrumbs and titles come from the sites, so the rows sit inside an
untrusted block; no page text (descriptions, sections) is ever shown. The main instructions
carry the one rule that says how to use it (``library_rule``).

Limits: ``hints.perRun`` blocks per run (a block is a search's result whose pages differ from
the ones shown), at most ``MAX_REFRESHES`` searches per run, ``SEARCH_TIMEOUT_SEC`` per search.
Measurement, page IDs and counts only (never the goal or a title): ``[tradecraft] library_now
refresh=`` per search, ``shown=`` per think with a block, ``<page> read`` when the agent reads a
page a block showed (``run_state.record_seen``). It never fails the think node: an error or a
slow library shows no block and logs a code.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Mapping, Optional, Sequence

from logging_config import get_logger
from tradecraft import run_state
from tradecraft.ingest import entities as entity_rules
from tradecraft.library import profile
from tradecraft.library.types import Card, wrap_untrusted
from tradecraft.settings import EffectiveSettings, constant
from tradecraft.vocab import load_vocab

logger = get_logger(__name__)

PAGES = int(constant("pagesPerHint"))
# The pages a search keeps: the next ones step in, with no new search, as the agent reads.
STANDING = 2 * PAGES
# A search is about 50 ms on the card index; a run of 100 thinks changing goal at each one still
# costs the database a few seconds.
MAX_REFRESHES = 30
SEARCH_TIMEOUT_SEC = 3.0
CVE_QUERY = 3
GOAL_SHOWN_CHARS = 100
PATH_CHARS = 100
MATCH_WORDS = 6
MATCH_WORD_CHARS = 30

HEADER = 'Library now (for your current goal: "{goal}"):'
FOOTER = "If one fits your next step, read it with tradecraft_lookup(page=…) before acting."
RULE = (
    "6. **Your library.** Your Tradecraft library is curated by the user for this work. The active "
    "attack skill gives the method; the library gives the specifics for the step you are on. Before "
    "each new step, look at \"Library now\" at the end of this prompt (it is absent when nothing in the "
    "library matches your current goal): if a page there fits what you are about to do, read it first "
    "with tradecraft_lookup(page=...); if nothing fits, go on. In your `thought`, say in one short "
    "sentence, with no line break, which page you read or that nothing fit: \"Library: read <page id>.\" "
    "or \"Library: nothing fit.\""
)

# Words too common to tell a page apart: never shown as a match.
_STOP = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "into", "onto", "over", "via", "use", "using", "get",
    "can", "not", "are", "its", "our", "your", "you", "then", "than", "when", "what", "how", "all", "any",
    "try", "find", "test", "check", "run", "make", "next", "now", "step", "steps", "page",
})
_WORD = re.compile(r"[a-z0-9]+")


def offered(catalog: Any, phase: str) -> bool:
    """Whether the run has Library now in ``phase``: a 2.0 catalog with at least one resource
    active for this run, hints on, and ``tradecraft_lookup`` allowed in the phase."""
    if catalog is None or not getattr(catalog, "resources", None):
        return False
    if not EffectiveSettings(catalog.search or {}, scope="search").bool("hints.enabled"):
        return False
    from project_settings import is_tool_allowed_in_phase

    return is_tool_allowed_in_phase("tradecraft_lookup", phase)


def library_rule(catalog: Any, phase: str) -> str:
    """The main instructions' rule for the library, as the item after their fifth, or "" when
    the run has no Library now in ``phase``: then the prompt reads as it did without a library."""
    return f"\n{RULE}" if offered(catalog, phase) else ""


def with_note(system_content: Any, note: Optional[str]) -> Any:
    """The think call's system content with the block at its end: a text block of its own after
    the prompt's tiers (no cache_control, so every cached prefix stays as it was), or a trailing
    section of a plain prompt. Always one system message: a chat template that allows one leading
    system message (vLLM, LM Studio and llama.cpp serving Gemma 3, Mistral or Llama 2) answers a
    second one with HTTP 400, which is never retried and would end the run."""
    if not note:
        return system_content
    if isinstance(system_content, list):
        return [*system_content, {"type": "text", "text": note}]
    return f"{system_content}\n\n{note}" if system_content else note


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def shown_goal(goal: str) -> str:
    """The goal as the header shows it: one line, its double quotes made single, no run of angle
    brackets (a trusted line never looks like an untrusted block's marker), clipped."""
    return _clip(re.sub(r"[<>]{3,}", " ", str(goal or "")).replace('"', "'"), GOAL_SHOWN_CHARS)


def render(goal: str, rows: Sequence[Mapping[str, Any]]) -> str:
    width = max(len(r["page"]) for r in rows)
    lines = []
    for r in rows:
        line = f"  {r['page'].ljust(width)}  {r['path']}"
        if r.get("matches"):
            line += f"   matches: {', '.join(r['matches'])}"
        lines.append(line)
    return "\n".join([HEADER.format(goal=shown_goal(goal)), wrap_untrusted(lines), FOOTER])


def fits(cand: Any, th: Any) -> bool:
    """The threshold, from the search's own scores: related at the run's match strictness, and
    about something the goal names (one of its terms in the title, breadcrumb or headings), or an
    exact CVE id, or a close title."""
    from tradecraft.library import search

    return search.is_related(cand, th) and (cand.entity_match or cand.strong > 0 or cand.fuzzy >= th.fuzzy)


def _stem(word: str) -> str:
    for suffix in ("ing", "es", "ed", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[:-len(suffix)]
    return word


def _tokens(text: str) -> list[str]:
    from tradecraft.ingest.tags import normalize

    return _WORD.findall(normalize(text))


def matched_words(card: Card, focus: profile.Focus, query: str) -> list[str]:
    """The session's CVE ids the page names, the goal's words its card holds, then the session's
    topic and technologies it is tagged with: words of the goal and of the vocabulary, never the
    page's own."""
    vocab = load_vocab()
    cves = set(focus.cves) | set(entity_rules.cve_ids(query))
    out: list[str] = [c for c in card.entities if c in cves]
    have = {_stem(t) for t in _tokens(" ".join([card.title, *card.breadcrumb, *card.headings, card.description]))}
    for word in _tokens(query):
        if len(word) >= 3 and word not in _STOP and not word.isdigit() and _stem(word) in have and word not in out:
            out.append(word)
    named: list[str] = []
    if focus.topic and focus.topic in card.topics:
        named.append(next((t["label"] for t in vocab.topics if t["id"] == focus.topic), focus.topic))
    names = {t["id"]: t["name"] for t in vocab.technologies}
    named += [names.get(t, t) for t in focus.technologies if t in card.technologies]
    for name in named:
        # "SQL injection" says nothing more when "sql" and "injection" are already there.
        if name not in out and not set(_tokens(name)) <= set(out):
            out.append(name)
    return [_clip(w, MATCH_WORD_CHARS) for w in out[:MATCH_WORDS]]


async def _search(catalog: Any, settings: EffectiveSettings, focus: profile.Focus, excluded: set[str]) -> list[dict]:
    """The pages that fit the focus, best first, at most ``STANDING``, none already read: the goal's
    pass, with one page about the session's CVE ids among the first three when it has one."""
    from tradecraft import runtime
    from tradecraft.library import search

    index = runtime.run_index()
    if index is None:
        return []
    session = search.Session(topic=focus.topic, phase=focus.phase, technologies=focus.technologies)
    th = search.STRICTNESS.get(settings.str("search.strictness"), search.STRICTNESS["balanced"])
    query = profile.query_of(focus.goal)
    passes = {}
    if query:
        passes["goal"] = search.free_first_pass(catalog.owner_id, catalog, query, session=session,
                                                settings=settings, index=index)
    if focus.cves:
        passes["cve"] = search.free_first_pass(catalog.owner_id, catalog, " ".join(focus.cves[-CVE_QUERY:]),
                                               session=session, settings=settings, index=index)
    found = dict(zip(passes, await asyncio.gather(*passes.values())))
    by_id = {r.id: r for r in catalog.resources}

    def cards(candidates: Sequence[Any]) -> list[tuple[Card, Any]]:
        out = []
        for cand in sorted(candidates, key=search._order):
            resource = by_id.get(cand.row["resource_id"])
            if resource is not None:
                card = search.card_of(cand.row, resource)
                if card.page_id not in excluded:
                    out.append((card, resource))
        return out

    ranked = cards([c for c in found["goal"].candidates if fits(c, th)]) if "goal" in found else []
    pages = {card.page_id for card, _r in ranked}
    about_cve = next(((card, r) for card, r in cards([c for c in found["cve"].candidates if c.entity_match])
                      if card.page_id not in pages), None) if "cve" in found else None
    if about_cve is not None:
        ranked.insert(min(len(ranked), PAGES - 1), about_cve)
    rows = []
    for card, resource in ranked[:STANDING]:
        path = " › ".join([resource.name or resource.slug, *card.breadcrumb, card.title])
        rows.append({"page": card.page_id, "path": _clip(path, PATH_CHARS), "matches": matched_words(card, focus, query)})
    return rows


def _entry_of(saved: Mapping[str, Any]) -> dict:
    """The run's Library now entry as the think node left it, read like any input."""
    from tradecraft.library import page_ids

    def count(key: str) -> int:
        value = saved.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    def page(value: Any) -> bool:
        return isinstance(value, str) and value == value.strip() and page_ids.parse(value) is not None

    standing = []
    for row in saved.get("standing") or []:
        if isinstance(row, Mapping) and page(row.get("page")) and len(standing) < STANDING:
            matches = [_clip(m, MATCH_WORD_CHARS) for m in row.get("matches") or [] if isinstance(m, str)]
            standing.append({"page": row["page"], "path": _clip(row.get("path"), PATH_CHARS),
                             "matches": matches[:MATCH_WORDS]})
    shown = [p for p in saved.get("displayed") or [] if page(p)][:PAGES]
    return {"refreshes": count("refreshes"), "shown": count("shown"), "block": count("block"),
            "standing": standing, "displayed": shown, "limited": saved.get("limited") is True}


async def _refresh(entry: dict, collector: run_state.RunCollector, catalog: Any, settings: EffectiveSettings,
                   focus: profile.Focus, reasons: Sequence[str]) -> dict:
    """A new search for a changed focus. The block it replaces is gone whatever happens: it was
    for a goal or facts that no longer hold."""
    entry = {**entry, "standing": [], "block": 0}
    per_run = settings.int("hints.perRun")
    if collector.counts()["hint"] >= per_run or entry["refreshes"] >= MAX_REFRESHES:
        if not entry["limited"]:
            entry["limited"] = True
            logger.info(f"[tradecraft] library_now code=limit refreshes={entry['refreshes']} "
                        f"blocks={collector.counts()['hint']}")
        return entry
    entry["refreshes"] += 1
    excluded = set(collector.drain()["tradecraft_seen_pages"])
    try:
        rows = await asyncio.wait_for(_search(catalog, settings, focus, excluded), timeout=SEARCH_TIMEOUT_SEC)
    except asyncio.TimeoutError:
        logger.warning(f"[tradecraft] library_now code=timeout refresh={entry['refreshes']}")
        return entry
    except Exception as exc:
        logger.warning(f"[tradecraft] library_now code=internal_error error={type(exc).__name__}")
        return entry
    logger.info(f"[tradecraft] library_now refresh={entry['refreshes']} reason={'+'.join(reasons)} "
                f"found={len(rows)}")
    if not rows:
        return entry
    if [r["page"] for r in rows[:PAGES]] == entry["displayed"]:
        # The pages shown last: that block stands.
        return {**entry, "standing": rows, "block": collector.counts()["hint"]}
    block = collector.incr_within("hint", per_run)
    return {**entry, "standing": rows, "block": block} if block is not None else entry


async def library_now(state: Mapping[str, Any], catalog: Any) -> tuple[Optional[str], dict]:
    """(the block, the run-state values to return with the think node's state), or (None, {})
    when nothing changed: no library in this run or phase, hints off, or no block and no change."""
    if not offered(catalog, str(state.get("current_phase") or "informational")):
        return None, {}
    settings = EffectiveSettings(catalog.search or {}, scope="search")
    try:
        with run_state.bound(state) as collector:
            saved = collector.library_now() or {}
            previous = profile.Focus.from_log(saved.get("focus"))
            current = profile.build(state, previous)
            reasons = profile.changes(previous, current)
            entry = _entry_of(saved)
            if reasons:
                entry = await _refresh(entry, collector, catalog, settings, current, reasons)
            read = set(collector.drain()["tradecraft_seen_pages"])
            rows = [r for r in entry["standing"] if r["page"] not in read][:PAGES]
            note = render(current.goal, rows) if rows else None
            if note:
                entry["shown"] += 1
                entry["displayed"] = [r["page"] for r in rows]
                already = collector.hinted()
                for r in rows:
                    if r["page"] not in already:
                        collector.log_hint({"kind": "now", "page": r["page"], "block": entry["block"], "read": False})
                logger.info(f"[tradecraft] library_now shown={entry['shown']} block={entry['block']} "
                            f"pages={','.join(entry['displayed'])}")
            focus = current.to_log()
            if not reasons and not note and focus == saved.get("focus"):
                return None, {}
            collector.set_library_now({**entry, "focus": focus})
            return note, collector.drain()
    except Exception as exc:
        logger.warning(f"[tradecraft] library_now code=internal_error error={type(exc).__name__}")
        return None, {}

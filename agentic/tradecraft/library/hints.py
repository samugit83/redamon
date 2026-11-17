"""Library now (owner decision 2026-11-17; it replaced T8.1's notes at fixed checkpoints): the
library's best pages for the steps at hand, at the end of the think call's system message, kept
fresh, at no model cost.

The main agent's think node asks ``library_now(state, catalog)`` before its model call (Fireteam
members get none, Q13). The steps at hand (``profile.steps_of``) are the ones the agent is about
to take: the todo item in progress and the next pending one; a step's pages are there while it is
still the next one. Each step is searched once with the session's facts (topic, phase,
technologies, the catalog's resources) through the free first pass (Q7.2), and again only when
those facts change, or when the agent has read every page the search kept and it kept a full set
(more may fit); the CVE ids a finding confirmed get a search of their own. A page is kept when the
search's own scores pass the run's match strictness (``search.is_related``) and something of the
step is in its title, breadcrumb or headings, or it names a CVE id exactly, or its title is a close
fuzzy match (``fits``). Each search keeps its best ``STANDING`` pages not read yet; the block shows
``constants.pagesPerHint`` (3), the best of each step in turn, labelled by the step they fit. A
page the run read never comes back; one shown and not read may, for another step.

The block is in the system role and apart from the base prompt's text: ``with_note`` puts it at
the end of the call's one system message, after the prompt's cache tiers, so every cached prefix
stays as it was. Its trusted lines are fixed text. The steps (one line each, no hidden character,
clipped) and the rows sit inside an untrusted block: the model or the person wrote the steps, and
the pages' resource names, breadcrumbs and titles come from the sites. No page text (descriptions,
sections) is ever shown, and only the rows of resources the run's catalog holds at that think: a
resume binds the catalog again for the person resuming. The main instructions carry the one rule
that says how to use it (``library_rule``).

Cost: at most ``MAX_GOALS`` distinct steps searched per run (a step searched already is searched
again for new facts at no cost to it; at most one round of searches a think), ``SEARCH_TIMEOUT_SEC``
per round. ``hints.perRun`` bounded the old notes and does not apply. The block never vanishes
silently: a step past the cap, or whose search failed or was slow, gets a fixed notice (``NOTICES``),
and a step's pages stay while the step does, even when a search for new facts fails. Measurement,
page IDs and counts only (never a step or a title): ``[tradecraft] library_now refresh=`` per round
of searches, ``shown=`` per think with a block, ``<page> read`` when the agent reads a page a block
showed (``run_state.record_seen``). It never fails the think node.
"""

from __future__ import annotations

import asyncio
import hashlib
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
# A search is about 50 ms on the card index. A run of the default 100 thinks meets about one new
# step a think (its stated next action moves at each), the longest sessions seen fewer: 200 steps
# cost the database about 10-20 s over the whole run.
MAX_GOALS = 200
SEARCH_TIMEOUT_SEC = 3.0
CVE_QUERY = profile.SEARCHED_CVES
GOAL_SHOWN_CHARS = 100
PATH_CHARS = 100
MATCH_WORDS = 6
MATCH_WORD_CHARS = 30

# The trusted lines are fixed text: the steps, which the model or the person wrote (and target
# text can colour), are inside the untrusted block, each above the pages that fit it.
HEADER = "Library now (pages for the steps at hand):"
LABELS = {"now": "step in progress", "next": "next step", "finding": "confirmed finding"}
# The order a block takes each step's best page in: what is under way, what comes next, a CVE a
# finding confirmed.
ORDER = ("now", "next", "finding")
STEP_LINE = '  {label}: "{text}"'
FOOTER = "If one fits your next step, read it with tradecraft_lookup(page=…) before acting."
# Fixed text for a step that could not be searched: an empty prompt would read as "nothing in the
# library fits".
NOTICES = {
    "limit": "Library now: a step was not searched (search limit for this run); use tradecraft_search for it "
             "yourself.",
    "error": "Library now: a step was not searched (the library did not answer); use tradecraft_search for it "
             "yourself.",
}
RULE = (
    "6. **Your library.** Your Tradecraft library is curated by the user for this work. The active "
    "attack skill gives the method; the library gives the specifics for the steps at hand. Before each new "
    "step, look at \"Library now\" at the end of this prompt: it lists the library's pages for your step in "
    "progress and your next step (and a vulnerability a finding confirmed); it is absent when nothing in the "
    "library matches them, and it says so when a step could not be searched. If a page there fits what you are about to do, "
    "read it first with tradecraft_lookup(page=...); if nothing fits, go on. Whenever the active skill or any "
    "instruction asks you to get specifics (payloads, PoCs, exploit steps, commands) from your own knowledge, "
    "query_graph or web_search, check Library now first: a fitting page comes before those. In your "
    "`thought`, say in one short sentence, with no line break, which page you read or that nothing fit: "
    "\"Library: read <page id>.\" or \"Library: nothing fit.\""
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
    """The goal as the block shows it: one line, no hidden character (control, bidi or zero-width),
    its double quotes made single, clipped. The block's wrapper then breaks any marker in it."""
    return _clip(profile.one_line(str(goal or "")).replace('"', "'"), GOAL_SHOWN_CHARS)


def render(steps: Sequence[tuple[str, str]], rows: Sequence[Mapping[str, Any]]) -> str:
    """The block: each step that has rows, then its rows. ``steps`` are (label, text)."""
    width = max(len(r["page"]) for r in rows)
    lines = []
    for label, text in steps:
        mine = [r for r in rows if r["step"] == label]
        if not mine:
            continue
        lines.append(STEP_LINE.format(label=LABELS[label], text=shown_goal(text)))
        for r in mine:
            line = f"    {r['page'].ljust(width)}  {profile.one_line(r['path'])}"
            if r.get("matches"):
                line += f"   matches: {', '.join(r['matches'])}"
            lines.append(line)
    return "\n".join([HEADER, wrap_untrusted(lines), FOOTER])


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


def _session(focus: profile.Focus) -> Any:
    from tradecraft.library import search

    return search.Session(topic=focus.topic, phase=focus.phase, technologies=focus.technologies)


def facts_key(focus: profile.Focus, catalog: Any) -> str:
    """The facts a search reads besides its words, the resources it searches included: the same
    step with other facts, or in a catalog a resume bound again, is searched again."""
    slugs = tuple(sorted(r.slug for r in catalog.resources))
    return hashlib.sha256(repr((focus.topic, focus.phase, focus.technologies, slugs)).encode()).hexdigest()[:16]


def goal_key(goal: str) -> str:
    """A step as the cap counts it: its words, whatever their case or spacing."""
    return hashlib.sha256(" ".join(goal.lower().split()).encode()).hexdigest()[:16]


async def _pass(catalog: Any, settings: EffectiveSettings, focus: profile.Focus, query: str, *,
                exact: bool, read: set[str]) -> list[dict]:
    """One search's fitting pages not read yet, best first, at most ``STANDING``: for a step
    (``exact`` False), the pages ``fits`` keeps; for the confirmed CVE ids, only the pages naming
    one exactly. Read pages go before the cut, so the next fitting ones take their places."""
    from tradecraft import runtime
    from tradecraft.library import search

    index = runtime.run_index()
    if index is None or not query:
        return []
    th = search.STRICTNESS.get(settings.str("search.strictness"), search.STRICTNESS["balanced"])
    found = await search.free_first_pass(catalog.owner_id, catalog, query, session=_session(focus),
                                         settings=settings, index=index)
    by_id = {r.id: r for r in catalog.resources}
    rows: list[dict] = []
    for cand in sorted((c for c in found.candidates if (c.entity_match if exact else fits(c, th))), key=search._order):
        resource = by_id.get(cand.row["resource_id"])
        if resource is None:
            continue
        card = search.card_of(cand.row, resource)
        if card.page_id in read:
            continue
        path = " › ".join([resource.name or resource.slug, *card.breadcrumb, card.title])
        rows.append({"page": card.page_id, "path": _clip(path, PATH_CHARS),
                     "matches": matched_words(card, focus, query)})
        if len(rows) >= STANDING:
            break
    return rows


def _rows_of(saved: Any) -> list[dict]:
    from tradecraft.library import page_ids

    rows = []
    for row in saved if isinstance(saved, list) else []:
        page = row.get("page") if isinstance(row, Mapping) else None
        if isinstance(page, str) and page == page.strip() and page_ids.parse(page) and len(rows) < STANDING:
            matches = [_clip(m, MATCH_WORD_CHARS) for m in row.get("matches") or [] if isinstance(m, str)]
            rows.append({"page": page, "path": _clip(row.get("path"), PATH_CHARS), "matches": matches[:MATCH_WORDS]})
    return rows


def _entry_of(saved: Mapping[str, Any]) -> dict:
    """The run's Library now entry as the think node left it, read like any input: counts, the
    steps searched with their pages (``searched``: key, facts, rows, notice), the CVE search
    (``cve``), the steps counted against the cap (``goals``), the pages shown last."""
    def count(key: str) -> int:
        value = saved.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    def hexes(value: Any, cap: int) -> list[str]:
        return [v for v in value or [] if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{16}", v)][:cap] \
            if isinstance(value, list) else []

    def search_of(item: Any) -> Optional[dict]:
        if not isinstance(item, Mapping):
            return None
        key, facts = hexes([item.get("key")], 1), hexes([item.get("facts")], 1)
        if not facts:
            return None
        notice = item.get("notice") if item.get("notice") in NOTICES else ""
        ids = [c for c in item.get("ids") or [] if isinstance(c, str) and entity_rules.cve_ids(c) == [c]][:CVE_QUERY]
        return {"key": key[0] if key else "", "facts": facts[0], "rows": _rows_of(item.get("rows")), "notice": notice,
                "ids": ids}

    searched = [x for x in (search_of(i) for i in (saved.get("searched") or [])[:len(profile.STEP_LABELS)]) if x]
    displayed = [r["page"] for r in _rows_of([{"page": p} for p in saved.get("displayed") or []])][:PAGES]
    return {"refreshes": count("refreshes"), "shown": count("shown"), "goals": hexes(saved.get("goals"), MAX_GOALS),
            "limited": saved.get("limited") is True, "searched": [x for x in searched if x["key"]],
            "cve": search_of(saved.get("cve")), "displayed": displayed}


def _in_catalog(entry: dict, catalog: Any) -> dict:
    """The entry with only the rows of resources the run's catalog holds now. A resume binds the
    catalog again for the person resuming: a resource turned off since, or a login that person may
    not use (``catalog.ts``), is no longer in it, and its pages are never shown again."""
    from tradecraft.library import page_ids

    slugs = {r.slug for r in catalog.resources}

    def held(page: str) -> bool:
        parsed = page_ids.parse(page)
        return parsed is not None and parsed[0] in slugs

    def keep(item: Optional[dict]) -> Optional[dict]:
        return {**item, "rows": [r for r in item["rows"] if held(r["page"])]} if item else item

    return {**entry, "searched": [keep(x) for x in entry["searched"]], "cve": keep(entry["cve"]),
            "displayed": [p for p in entry["displayed"] if held(p)]}


def _spent(item: Optional[dict], read: set[str]) -> bool:
    """Whether the agent read every page a search kept, and it kept a full set (more may fit)."""
    return bool(item and len(item["rows"]) >= STANDING and all(r["page"] in read for r in item["rows"]))


async def _refresh(entry: dict, catalog: Any, settings: EffectiveSettings, focus: profile.Focus,
                   reasons: Sequence[str], read: set[str]) -> dict:
    """Searches the steps (and the confirmed CVE ids) that have no pages for the current facts, or
    whose kept pages were all read, in one round under one time limit. A step that cannot be
    searched (the cap, an error, the time limit) keeps the pages it had, which still fit it, or
    gets a notice."""
    facts = facts_key(focus, catalog)
    old = {x["key"]: x for x in entry["searched"]}
    searched: list[dict] = []
    jobs: dict[str, Any] = {}
    goals = list(entry["goals"])
    for _label, text in focus.steps:
        key = goal_key(text)
        had = old.get(key)
        if had is not None and had["facts"] == facts and not _spent(had, read):
            searched.append(had)
            continue
        if key not in goals and len(goals) >= MAX_GOALS:
            if not entry["limited"]:
                entry = {**entry, "limited": True}
                logger.info(f"[tradecraft] library_now code=limit goals={len(goals)}")
            searched.append({**(had or {"key": key, "rows": [], "ids": []}), "facts": facts,
                             "notice": "" if had and had["rows"] else "limit"})
            continue
        if key not in goals:
            goals.append(key)
        jobs[key] = _pass(catalog, settings, focus, profile.query_of(text), exact=False, read=read)
        searched.append({"key": key, "facts": facts, "rows": [], "notice": "", "ids": [], "_had": had})
    ids = list(focus.cves[-CVE_QUERY:])
    cve = entry["cve"] if (entry["cve"] and entry["cve"]["ids"] == ids and entry["cve"]["facts"] == facts
                           and not _spent(entry["cve"], read)) else None
    if ids and cve is None:
        jobs["cve"] = _pass(catalog, settings, focus, " ".join(ids), exact=True, read=read)
        cve = {"key": "", "facts": facts, "rows": [], "notice": "", "ids": ids, "_had": entry["cve"]}
    entry = {**entry, "goals": goals, "cve": cve if ids else None}
    if jobs:
        entry["refreshes"] += 1
        try:
            found = dict(zip(jobs, await asyncio.wait_for(asyncio.gather(*jobs.values()), timeout=SEARCH_TIMEOUT_SEC)))
        except asyncio.TimeoutError:
            logger.warning(f"[tradecraft] library_now code=timeout refresh={entry['refreshes']}")
            found = None
        except Exception as exc:
            logger.warning(f"[tradecraft] library_now code=internal_error error={type(exc).__name__}")
            found = None
        if found is not None:
            logger.info(f"[tradecraft] library_now refresh={entry['refreshes']} reason={'+'.join(reasons) or 'resume'} "
                        f"found={sum(len(r) for r in found.values())}")
        for item in [*searched, *([cve] if cve else [])]:
            if "_had" not in item:
                continue
            had = item.pop("_had")
            key = item["key"] or "cve"
            if found is not None:
                item["rows"] = found.get(key, [])
            elif had and had["rows"] and (had.get("ids") == item.get("ids") or item["key"]):
                item["rows"] = had["rows"]  # the same step: its pages still fit it
            else:
                item["notice"] = "error"
    return {**entry, "searched": searched}


def assemble(focus: profile.Focus, entry: dict, read: set[str]) -> list[dict]:
    """At most ``PAGES`` rows: each step's best page not read yet in ``ORDER``, then the next best
    of each, a page fitting two steps shown once, under the first."""
    by_key = {x["key"]: x for x in entry["searched"]}
    pools: dict[str, list[dict]] = {}
    for label, text in focus.steps:
        pools[label] = list((by_key.get(goal_key(text)) or {}).get("rows") or [])
    if entry["cve"]:
        pools["finding"] = list(entry["cve"]["rows"])
    rows: list[dict] = []
    taken: set[str] = set()
    for depth in range(STANDING):
        for label in ORDER:
            pool = [r for r in pools.get(label, []) if r["page"] not in read and r["page"] not in taken]
            if len(rows) < PAGES and pool:
                rows.append({**pool[0], "step": label})
                taken.add(pool[0]["page"])
        if len(rows) >= PAGES:
            break
    return rows


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
            entry = _in_catalog(_entry_of(saved), catalog)
            read = set(collector.drain()["tradecraft_seen_pages"])
            entry = await _refresh(entry, catalog, settings, current, reasons, read)
            rows = assemble(current, entry, read)
            steps = [*current.steps, *([("finding", ", ".join(entry["cve"]["ids"]))] if entry["cve"] else [])]
            shown = sorted(rows, key=lambda r: ORDER.index(r["step"]))
            block = render(sorted(steps, key=lambda s: ORDER.index(s[0])), shown) if rows else None
            notices = sorted({x["notice"] for x in [*entry["searched"], *([entry["cve"]] if entry["cve"] else [])]
                              if x["notice"] and not any(r["page"] for r in x["rows"] if r["page"] not in read)})
            note = "\n".join([*([block] if block else []), *(NOTICES[n] for n in notices)]) or None
            if rows:
                entry["shown"] += 1
                already = collector.hinted()
                fresh = [r["page"] for r in rows if r["page"] not in already]
                block_n = collector.incr("hint") if fresh else collector.counts()["hint"]
                for page in fresh:
                    collector.log_hint({"kind": "now", "page": page, "block": block_n, "read": False})
                entry["displayed"] = [r["page"] for r in shown]
                logger.info(f"[tradecraft] library_now shown={entry['shown']} block={block_n} "
                            f"pages={','.join(entry['displayed'])}")
            focus = current.to_log()
            if not reasons and not note and focus == saved.get("focus"):
                return None, {}
            collector.set_library_now({**entry, "focus": focus})
            return note, collector.drain()
    except Exception as exc:
        logger.warning(f"[tradecraft] library_now code=internal_error error={type(exc).__name__}")
        return None, {}

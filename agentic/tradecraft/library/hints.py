"""Library hints (Q6, T8.1): at key moments of an attack, one short system note naming 1-3 library
pages relevant now, at no model cost.

The main agent's think node asks ``maybe_hint(state, catalog)`` before its model call (Fireteam
members get none, Q13). A checkpoint (``profile.checkpoints``) leads to 3-6 searches built from
fixed patterns over the profile: the topic with each technology, with the vocabulary's keywords of
the user's message, the topic with "waf bypass filter evasion" once a block was seen, and each new
CVE id as an entity. They run through the free first pass (Q7.2) with the run's session; pages below
the match strictness, already suggested or already read are dropped, and the best
``constants.pagesPerHint`` (3) remain.

The note is in the system role, never part of a tool result, and apart from the base prompt's text:
``with_note`` puts it at the end of the think call's one system message, a text block of its own
after the prompt's cache tiers, or a trailing section of a plain prompt (R-363). Its trusted lines
hold only page IDs and names from the fixed lists (topics, technologies, "WAF seen"); titles and
breadcrumbs come from the sites, so they sit inside an untrusted block. CVE ids, which a target can
plant, are searched but never named in the note (Q6).

Limits: one note per think, ``hints.perRun`` notes per run counted on the run's collector (whose
values the think node returns with the state), never the same page twice. The skill line of T5.4
counts as the first hint when the chosen skill's topic is in the library (Q5). Each page suggested
is logged with ``read: false``; ``run_state.record_seen`` sets it when ``tradecraft_lookup`` or the
librarian returns that page (R-367). A hint never fails the think node: an error or a slow library
answers no note.
"""

from __future__ import annotations

import asyncio
from typing import Any, Mapping, Optional, Sequence

from logging_config import get_logger
from tradecraft import run_state
from tradecraft.library import profile
from tradecraft.library.types import Card, wrap_untrusted
from tradecraft.settings import EffectiveSettings, constant
from tradecraft.vocab import load_vocab

logger = get_logger(__name__)

PAGES = int(constant("pagesPerHint"))
MAX_QUERIES = 6
MAX_CVE_QUERIES = 3
HEADER_TECHS = 2
PATH_CHARS = 100
# The searches of one note together: about 50 ms on the card index (Q6); a slow database costs
# the think node no more than this.
SEARCH_TIMEOUT_SEC = 3.0
BLOCK_WORDS = "waf bypass filter evasion"
WAF_SEEN = "WAF seen"
LOOKUP_LINE = "  → tradecraft_lookup to read"
ASK_LINE = "  → tradecraft_lookup to read, tradecraft_ask for more"


def _topic_label(topic: str) -> str:
    return next((t["label"] for t in load_vocab().topics if t["id"] == topic), topic)


def _tech_name(tech: str) -> str:
    return next((t["name"] for t in load_vocab().technologies if t["id"] == tech), tech)


def _new_cves(current: profile.Profile, previous: Optional[profile.Profile]) -> list[str]:
    had = set(previous.cves) if previous else set()
    return [c for c in current.cves if c not in had]


def queries_for(current: profile.Profile, previous: Optional[profile.Profile], fired: Sequence[str]) -> list[str]:
    """3-6 searches from fixed patterns over the profile (Q6): vocabulary labels and names, the
    vocabulary's keywords, fixed words and pattern-checked CVE ids; nothing else."""
    topic = _topic_label(current.topic) if current.topic else ""
    techs = [_tech_name(t) for t in current.technologies[:HEADER_TECHS]]
    out: list[str] = []
    if current.blocked:
        out.append(f"{topic} {BLOCK_WORDS}".strip())
    out += _new_cves(current, previous)[:MAX_CVE_QUERIES]
    if topic:
        out += [f"{topic} {tech}" for tech in techs] or [topic]
        if current.keywords:
            out.append(" ".join([topic, *techs[:1], *current.keywords]))
    else:
        preferred = load_vocab().kind_preference_by_phase.get(current.phase, ())
        labels = {k["id"]: k["mapLabel"] for k in load_vocab().kinds}
        kind = labels.get(preferred[0], "") if preferred else ""
        out += [f"{tech} {kind}".strip() for tech in techs]
    queries: list[str] = []
    for query in out:
        if query and query not in queries:
            queries.append(query)
    return queries[:MAX_QUERIES]


async def _suggestions(catalog: Any, queries: Sequence[str], current: profile.Profile, settings: EffectiveSettings,
                       excluded: set[str]) -> list[Card]:
    """The best pages of the searches together (reciprocal rank fusion), above the match
    strictness, none already suggested or read."""
    from tradecraft import runtime
    from tradecraft.library import search

    index = runtime.run_index()
    if index is None:
        return []
    session = search.Session(topic=current.topic, phase=current.phase, technologies=current.technologies)
    passes = await asyncio.gather(*(
        search.free_first_pass(catalog.owner_id, catalog, query, session=session, settings=settings, index=index)
        for query in queries))
    by_id = {r.id: r for r in catalog.resources}
    strictness = settings.str("search.strictness")
    scores: dict[str, float] = {}
    cards: dict[str, Card] = {}
    for found in passes:
        _verdict, related = search.verdict_of(found.candidates, strictness)
        for position, cand in enumerate(related):
            resource = by_id.get(cand.row["resource_id"])
            if resource is None:
                continue
            card = search.card_of(cand.row, resource)
            if card.page_id in excluded:
                continue
            scores[card.page_id] = scores.get(card.page_id, 0.0) + 1.0 / (search.RRF_K + position + 1)
            cards.setdefault(card.page_id, card)
    best = sorted(scores, key=lambda p: (-scores[p], p))[:PAGES]
    return [cards[p] for p in best]


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def with_note(system_content: Any, note: Optional[str]) -> Any:
    """The think call's system content with the hint note at its end: a text block of its own after
    the prompt's tiers (no cache_control, so every cached prefix stays as it was), or a trailing
    section of a plain prompt. Always one system message: a chat template that allows one leading
    system message (vLLM, LM Studio and llama.cpp serving Gemma 3, Mistral or Llama 2) answers a
    second one with HTTP 400, which is never retried and would end the run."""
    if not note:
        return system_content
    if isinstance(system_content, list):
        return [*system_content, {"type": "text", "text": note}]
    return f"{system_content}\n\n{note}" if system_content else note


def render_note(current: profile.Profile, cards: Sequence[Card], has_ask: bool) -> str:
    """The note. Its header names the topic, technologies from the vocabulary and "WAF seen" only:
    a CVE id comes from the target's own text, so it never reaches a trusted line."""
    parts = [_topic_label(current.topic)] if current.topic else []
    parts += [_tech_name(t) for t in current.technologies[:HEADER_TECHS]]
    if current.blocked:
        parts.append(WAF_SEEN)
    lines = [f"Library suggestions ({' · '.join(parts)}):" if parts else "Library suggestions:"]
    lines += [f"  {card.page_id}" for card in cards]
    width = max(len(card.page_id) for card in cards)
    block = wrap_untrusted([f"  {card.page_id.ljust(width)}  {_clip(card.path(), PATH_CHARS)}" for card in cards])
    return "\n".join([*lines, block, ASK_LINE if has_ask else LOOKUP_LINE])


def _skill_line_shown(topic: Optional[str]) -> bool:
    from tradecraft.library.coverage import skill_line
    return bool(topic) and skill_line(topic) is not None


async def _note(collector: run_state.RunCollector, catalog: Any, settings: EffectiveSettings,
                current: profile.Profile, previous: Optional[profile.Profile], fired: tuple[str, ...]) -> Optional[str]:
    from project_settings import is_tool_allowed_in_phase

    per_run = settings.int("hints.perRun")
    if "skill" in fired and collector.counts()["hint"] == 0 and _skill_line_shown(current.topic):
        # Q5: the skill's prompt already holds the library's line for its topic, the run's first hint.
        if collector.incr_within("hint", per_run) is not None:
            collector.log_hint({"kind": "skill_line", "topic": current.topic})
            logger.info(f"[tradecraft] hint n=1 checkpoint=skill skill_line={current.topic}")
        fired = tuple(f for f in fired if f != "skill")
        if not fired:
            return None
    if collector.counts()["hint"] >= per_run:
        return None
    queries = queries_for(current, previous, fired)
    if not queries:
        return None
    excluded = set(collector.drain()["tradecraft_seen_pages"]) | collector.hinted()
    try:
        cards = await asyncio.wait_for(_suggestions(catalog, queries, current, settings, excluded),
                                       timeout=SEARCH_TIMEOUT_SEC)
    except asyncio.TimeoutError:
        logger.warning("[tradecraft] hint code=timeout")
        return None
    except Exception as exc:
        logger.warning(f"[tradecraft] hint code=internal_error error={type(exc).__name__}")
        return None
    if not cards:
        return None
    n = collector.incr_within("hint", per_run)
    if n is None:
        return None
    checkpoint = "+".join(fired)
    for card in cards:
        collector.log_hint({"kind": "hint", "page": card.page_id, "checkpoint": checkpoint, "n": n, "read": False})
    logger.info(f"[tradecraft] hint n={n} checkpoint={checkpoint} pages={','.join(c.page_id for c in cards)}")
    return render_note(current, cards, is_tool_allowed_in_phase("tradecraft_ask", current.phase))


async def maybe_hint(state: Mapping[str, Any], catalog: Any) -> tuple[Optional[str], dict]:
    """(the note, the run-state values to return with the think node's state), or (None, {}) when
    nothing changed: a 1.x run, no catalog bound to the run's task, hints off, or the phase offers
    no library tool."""
    if catalog is None or not getattr(catalog, "resources", None):
        return None, {}
    settings = EffectiveSettings(catalog.search or {}, scope="search")
    if not settings.bool("hints.enabled"):
        return None, {}
    from project_settings import is_tool_allowed_in_phase

    if not is_tool_allowed_in_phase("tradecraft_lookup", str(state.get("current_phase") or "informational")):
        return None, {}
    try:
        with run_state.bound(state) as collector:
            previous = profile.Profile.from_log(collector.profile())
            current = profile.build(state, previous)
            if current == previous:
                return None, {}
            fired = profile.checkpoints(previous, current)
            note = await _note(collector, catalog, settings, current, previous, fired) if fired else None
            # Saved even without a note: the checkpoint is spent, and a resume does not meet it again.
            collector.set_profile(current.to_log())
            return note, collector.drain()
    except Exception as exc:
        logger.warning(f"[tradecraft] hint code=internal_error error={type(exc).__name__}")
        return None, {}

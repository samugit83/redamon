"""Stage ``tags`` (T2.2; T5.1 adds the model pass): topics, kinds and technologies on every card.

Rules first, free (Q4 "Every page is tagged"): the vocabulary's ``keywords`` (topics),
``kindKeywords`` (kinds) and technology names and aliases, matched as whole words in the card's
title, breadcrumb and headings. "SQL" or "sqli" mean SQL injection, "Kerberos" Active Directory.
A page the rules leave without a topic goes to the model pass (``tag_by_model``, T5.1) when
``focus.tagEveryPage`` is ``rules_model`` (the default): the focus's title triage in its tag-only
form, batches of ``constants.titleTriageBatch`` titles with the resource's model, nothing dropped.
Tags the focus's triage already gave a page count first. Every tag is a vocabulary id, so the
coverage map can count them.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Optional, Sequence

from logging_config import get_logger
from tradecraft.vocab import load_vocab

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

_SEPARATORS = re.compile(r"[\s_\-/]+")


def normalize(text: str) -> str:
    """Lower case, with ``-``, ``_`` and ``/`` read as spaces: "SQL-Injection", "sql_injection"
    and "sql injection" are the same words."""
    return _SEPARATORS.sub(" ", str(text or "").lower()).strip()


class PhraseMatcher:
    """Which of a fixed set of phrases occur in a text as whole words, a plural ``s``/``es``
    allowed: "payload" matches "Payloads", "sql" never matches "mysql"."""

    def __init__(self, phrases: Mapping[str, Iterable[str]]):
        # One alternation per id; ids keep the order of the mapping.
        self._patterns: list[tuple[str, re.Pattern]] = []
        for key, words in phrases.items():
            alts = sorted({normalize(w) for w in words if normalize(w)}, key=len, reverse=True)
            if alts:
                body = "|".join(re.escape(a) for a in alts)
                self._patterns.append((key, re.compile(rf"(?<![a-z0-9])(?:{body})(?:e?s)?(?![a-z0-9])")))

    def find(self, text: str) -> list[str]:
        norm = normalize(text)
        return [key for key, pattern in self._patterns if pattern.search(norm)]


@functools.lru_cache(maxsize=1)
def _matchers() -> tuple[PhraseMatcher, PhraseMatcher, PhraseMatcher]:
    vocab = load_vocab()
    topics = PhraseMatcher({t: vocab.keywords.get(t, ()) for t in vocab.topic_ids})
    kinds = PhraseMatcher({k: vocab.kind_keywords.get(k, ()) for k in vocab.kind_ids})
    technologies = PhraseMatcher(technology_words())
    return topics, kinds, technologies


def technology_words() -> dict[str, list[str]]:
    """{technology id: its id, name and aliases}: the only names a technology is known by."""
    return {t["id"]: [t["id"], t["name"], *t.get("aliases", ())] for t in load_vocab().technologies}


@dataclass(frozen=True)
class Tags:
    topics: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()


def heading_texts(headings: Any) -> list[str]:
    """The text of each heading; a card stores ``[{level, text}]`` (a bare string is read too)."""
    out = []
    for h in headings or ():
        text = h.get("text") if isinstance(h, Mapping) else h
        if isinstance(text, str) and text.strip():
            out.append(text)
    return out


def classify(title: str, breadcrumb: Sequence[str] = (), headings: Sequence[str] = ()) -> Tags:
    """The rules' tags for a page from its title, breadcrumb and heading texts."""
    text = " | ".join([title or "", *[str(b) for b in breadcrumb or ()], *[str(h) for h in headings or ()]])
    topics, kinds, technologies = _matchers()
    return Tags(tuple(topics.find(text)), tuple(kinds.find(text)), tuple(technologies.find(text)))


def _merged(existing: Optional[Iterable[str]], found: Iterable[str]) -> list[str]:
    out = [t for t in existing or () if isinstance(t, str) and t]
    out += [t for t in found if t not in out]
    return out


async def tag(state: "IngestState") -> "IngestState":
    """Every card with its rules' tags, added to any it already has (a curation or the focus's
    triage may have set some); then the model pass for the kept cards left without a topic."""
    from_focus = {e.url: e.extra for e in state.entries if "focus_topics" in e.extra or "focus_kinds" in e.extra}
    untagged = []
    for card in state.cards:
        found = classify(card.get("title", ""), card.get("breadcrumb") or (), heading_texts(card.get("headings")))
        judged = from_focus.get(card.get("url"), {})
        card["topics"] = _merged(_merged(card.get("topics"), judged.get("focus_topics") or ()), found.topics)
        card["kinds"] = _merged(_merged(card.get("kinds"), judged.get("focus_kinds") or ()), found.kinds)
        card["technologies"] = _merged(card.get("technologies"), found.technologies)
        if not card["topics"]:
            untagged.append(card)
    if untagged and state.settings.str("focus.tagEveryPage") == "rules_model":
        await tag_by_model(state, untagged)
    return state


async def tag_by_model(state: "IngestState", cards: list[dict]) -> None:
    """Title tagging for the kept cards the rules could not classify: the triage's tag-only form,
    with the resource's model. A model error is counted and never retried (TD-20): the cards
    left keep no topic."""
    from tradecraft.ingest import focus
    from tradecraft.ingest.crawl import error_code_of

    cards = [c for c in cards if c.get("status", "kept") == "kept"]
    if not cards:
        return
    try:
        llm = await state.model()
    except Exception as exc:
        state.count_error(error_code_of(exc))
        return
    if llm is None:
        return

    async def before(done: int, total: int) -> None:
        await state.check_cancelled()
        await state.progress("tags", done, total, "entries")

    result = await focus.triage_titles(llm, [(c.get("title", ""), c.get("url", "")) for c in cards], drop=False,
                                       step="tagging", before_batch=before)
    state.llm_calls += result.calls
    for card, verdict in zip(cards, result.verdicts):
        if verdict is not None:
            card["topics"] = _merged(card.get("topics"), verdict.topics)
            card["kinds"] = _merged(card.get("kinds"), verdict.kinds)
    for _ in range(result.invalid):
        state.count_error("title_tagging_invalid")
    if result.error_code:
        state.count_error(result.error_code)
        logger.info(f"[tradecraft] job {state.request.job_id} tagging code={result.error_code}")

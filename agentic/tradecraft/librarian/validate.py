"""The code checks of the librarian's answers, and the text the agent receives (Q9.5, Q9.7, Q12).

A model's answer is only a proposal. Before anything reaches the agent:

- a page ID must come from the librarian's own search results (``known``), and a pick's page
  must be one it read: a page cannot name another page, and the model cannot invent one;
- a pick's excerpt must appear word for word (spacing aside) in the section text it read: a
  page cannot slip made-up text into the answer; a pick whose excerpt fails is no pick (its
  page, whose ID was checked, is listed as also relevant);
- a "why" line is one line of at most 160 characters, naming no page outside its own results;
  an excerpt is at most 600 characters;
- new queries are short strings, only ever bound as search parameters;
- the whole answer is at most ``constants.librarianAnswerMaxChars`` characters, inside the
  untrusted envelope, with the fixed header the chat's trail line reads (``types``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from tradecraft.library import split
from tradecraft.library.types import (
    LIBRARIAN_ALSO,
    LIBRARIAN_READ_MORE,
    LIBRARIAN_SEARCHED,
    LibrarianAnswer,
    LibrarianPick,
    format_librarian_header,
    wrap_untrusted,
)
from tradecraft.settings import constant

PAGES_RETURNED = int(constant("librarianPagesReturned"))
ANSWER_MAX = int(constant("librarianAnswerMaxChars"))
WHY_MAX = 160
QUOTE_MAX = 600
# A quote shorter than this proves nothing: a word or two appears on many pages.
QUOTE_MIN = 8
QUERIES_MAX = 3
QUERY_CHARS = 120
ALSO_MAX = 6
JUDGE_VERDICTS = ("FOUND", "PARTIAL", "NONE")
CONFIDENCES = ("high", "medium", "low")


def one_line(text: Any, limit: int) -> str:
    return " ".join(str(text or "").split())[:limit] if isinstance(text, (str, int, float)) else ""


def page_ids_in(values: Any, allowed: Sequence[str], limit: int) -> list[str]:
    """The strings of ``values`` that are page IDs of ``allowed``, once each, in order."""
    allowed_set = set(allowed)
    out: list[str] = []
    for v in values if isinstance(values, list) else ():
        if isinstance(v, str) and v.strip() in allowed_set and v.strip() not in out:
            out.append(v.strip())
    return out[:limit]


def shortlist_ids(data: Optional[Mapping[str, Any]], allowed: Sequence[str], limit: int) -> list[str]:
    return page_ids_in((data or {}).get("pages"), allowed, limit)


def plan_queries(data: Optional[Mapping[str, Any]], tried: Sequence[str]) -> list[str]:
    done = {" ".join(q.lower().split()) for q in tried}
    out: list[str] = []
    for q in (data or {}).get("queries") if isinstance((data or {}).get("queries"), list) else ():
        text = one_line(q, QUERY_CHARS) if isinstance(q, str) else ""
        if text and text.lower() not in done and text not in out:
            out.append(text)
    return out[:QUERIES_MAX]


@dataclass(frozen=True)
class Proposed:
    page: str
    section: str
    why: str
    quote: str


@dataclass(frozen=True)
class Judged:
    verdict: str
    confidence: str
    picks: tuple[Proposed, ...]
    also: tuple[str, ...]


def judge_answer(data: Optional[Mapping[str, Any]]) -> Optional[Judged]:
    """The judge's answer in its format, or None. Nothing is checked against the library here."""
    if not data or data.get("verdict") not in JUDGE_VERDICTS:
        return None
    picks = []
    for item in data.get("picks") if isinstance(data.get("picks"), list) else ():
        if isinstance(item, dict) and isinstance(item.get("page"), str):
            picks.append(Proposed(item["page"].strip(), one_line(item.get("section"), 200),
                                  one_line(item.get("why"), WHY_MAX), str(item.get("quote") or "")))
    also = tuple(a.strip() for a in data.get("also") if isinstance(a, str)) if isinstance(data.get("also"), list) else ()
    confidence = data.get("confidence") if data.get("confidence") in CONFIDENCES else "medium"
    return Judged(data["verdict"], confidence, tuple(picks), also)


# Anything shaped like a page ID, wherever it sits: next to an underscore, a letter of any script
# or in capitals it is still an ID the agent could read (no word boundaries).
_PAGE_ID_LIKE = re.compile(r"[a-z0-9][a-z0-9-]{0,199}:[0-9]{1,18}", re.IGNORECASE)


def scrub_ids(text: str, known: set) -> str:
    """``text`` with every page ID it names that is not one of ``known`` replaced: a "why" line
    is model output a page may have shaped, and only the librarian's own results are named."""
    return _PAGE_ID_LIKE.sub(lambda m: m.group(0) if m.group(0) in known else "[another page]", text)


def squash(text: str) -> str:
    return " ".join((text or "").split())


def quote_in(quote: str, text: str) -> bool:
    """Whether ``quote`` is in ``text`` word for word, line breaks and runs of spaces aside."""
    q = squash(quote).strip("\"'“”‘’ ")
    return len(q) >= QUOTE_MIN and q in squash(text)


def checked_picks(judged: Judged, known: set, read: Mapping[tuple[str, str], str],
                  crumbs: Mapping[str, tuple[str, ...]]) -> tuple[list[LibrarianPick], list[str]]:
    """(the picks that pass every check, at most ``PAGES_RETURNED``; the page IDs of the
    proposals that failed only their excerpt)."""
    picks: list[LibrarianPick] = []
    failed: list[str] = []
    for prop in judged.picks:
        if prop.page not in known or prop.page in {p.page_id for p in picks}:
            continue
        sections = [(name, text) for (page, name), text in read.items() if page == prop.page]
        if not sections:
            continue
        wanted = split.hint_value(prop.section).lower()
        ordered = sorted(sections, key=lambda s: split.hint_value(s[0]).lower() != wanted)
        hit = next(((name, text) for name, text in ordered if quote_in(prop.quote, text)), None)
        if hit is None:
            failed.append(prop.page)
            continue
        excerpt = squash(prop.quote).strip("\"'“”‘’ ")
        if len(excerpt) > QUOTE_MAX:
            excerpt = excerpt[:QUOTE_MAX].rsplit(" ", 1)[0] + " …"
        picks.append(LibrarianPick(page_id=prop.page, breadcrumb=crumbs.get(prop.page, ()), why=scrub_ids(prop.why, known),
                                   excerpt=excerpt, section=hit[0]))
        if len(picks) >= PAGES_RETURNED:
            break
    return picks, failed


def also_relevant(candidates: Sequence[str], known: set, exclude: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    for page in candidates:
        if page in known and page not in exclude and page not in out:
            out.append(page)
    return tuple(out[:ALSO_MAX])


# --------------------------------------------------------------------------------------
# The text the agent receives
# --------------------------------------------------------------------------------------

def _lines(answer: LibrarianAnswer, excerpt_max: int, also: bool, picks: int) -> list[str]:
    lines = [format_librarian_header(answer.verdict, answer.confidence, answer.model_calls, answer.pages_inspected,
                                     answer.seconds)]
    if answer.queries:
        lines.append(LIBRARIAN_SEARCHED.format(queries=", ".join(f'"{one_line(q, 80)}"' for q in answer.queries)))
    lines += [f"note: {one_line(n, 300)}" for n in answer.notes]
    lines.append("")
    for n, pick in enumerate(answer.picks[:picks], 1):
        path = " › ".join(one_line(c, 80) for c in (*pick.breadcrumb, pick.section or "") if c)
        lines.append(f"{n}. {pick.page_id}  {one_line(path, 300)}")
        if pick.why:
            lines.append(f"   why: {one_line(pick.why, WHY_MAX)}")
        if pick.excerpt:
            text = pick.excerpt if len(pick.excerpt) <= excerpt_max else pick.excerpt[:excerpt_max].rsplit(" ", 1)[0] + " …"
            lines.append(f'   excerpt: "{text}"')
    if also and answer.also_relevant:
        lines.append(LIBRARIAN_ALSO.format(page_ids=", ".join(answer.also_relevant)))
    if answer.picks:
        top = answer.picks[0]
        lines.append(LIBRARIAN_READ_MORE.format(page_id=top.page_id, section=split.hint_value(top.section or "")))
    elif answer.verdict == "NOT FOUND":
        lines.append("Nothing in the library answers this need. Do not repeat these searches; use web_search.")
    return lines


def render(answer: LibrarianAnswer) -> str:
    """The answer inside the untrusted envelope, at most ``ANSWER_MAX`` characters: excerpts are
    shortened first, then the also-relevant line, then the last picks."""
    # The last attempt holds one pick and lines of capped length: about 2,500 characters at
    # most, so the envelope is never cut.
    attempts = [(QUOTE_MAX, True, PAGES_RETURNED), (300, True, PAGES_RETURNED), (150, True, PAGES_RETURNED),
                (150, False, PAGES_RETURNED), (150, False, 2), (80, False, 1)]
    text = ""
    for excerpt_max, also, picks in attempts:
        text = wrap_untrusted(_lines(answer, excerpt_max, also, picks))
        if len(text) <= ANSWER_MAX:
            break
    return text

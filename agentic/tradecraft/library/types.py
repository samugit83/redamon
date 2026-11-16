"""Result types of the library and the text formats the agent reads (Q7.1, Q8, Q9.5).

Every tool result is wrapped in the untrusted envelope, whatever its source (Q12): the
repository's per-call random-nonce boundary (``prompt_safety.wrap_untrusted``), so page
text that imitates the closing marker stays inside. The header lines are fixed formats:
the agent learns them from its tool descriptions, and the webapp reads the librarian's
header back for the chat's trail line (T7.5), so the librarian header has a parser here
and its format must not change without both sides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Optional

from prompt_safety import wrap_untrusted as _wrap_with_nonce

# The envelope reads <<<UNTRUSTED_TRADECRAFT_RESULT id=NONCE>>> ... <<<END_UNTRUSTED_TRADECRAFT_RESULT id=NONCE>>>.
UNTRUSTED_LABEL = "TRADECRAFT_RESULT"
_OPENING = re.compile(rf"^<<<UNTRUSTED_{UNTRUSTED_LABEL} id=[0-9a-f]+>>>$")

SearchVerdict = Literal["FOUND", "RELATED", "NOT FOUND"]
LibrarianVerdict = Literal["FOUND", "PARTIAL", "NOT FOUND"]
Confidence = Literal["high", "medium", "low"]
SEARCH_VERDICTS = ("FOUND", "RELATED", "NOT FOUND")
LIBRARIAN_VERDICTS = ("FOUND", "PARTIAL", "NOT FOUND")
CONFIDENCES = ("high", "medium", "low")

# Q7.1: the first line of a search answer, then one line per hit, then how to read one.
SEARCH_HEADER = 'search: "{query}" · {verdict} · {shown} of {total} results'
SEARCH_HIT = "{n:>2}. {page_id}  {breadcrumb} — {description} ({kind})"
SEARCH_TRIED = "tried: {wordings}"
READ_HINT = 'read: tradecraft_lookup(page="{page_id}", section="{section}")'
# Q7.1: one level of a resource's tree.
BROWSE_HEADER = "{breadcrumb} · {pages} pages"
BROWSE_LINE = "{n:>2}. {label}/   ({count})  {description}"
BROWSE_MORE = "… {more} more"
# Q8 and Q1.2: a read.
READ_PAGE = "page: {page_id} · {breadcrumb}"
READ_SECTION = "section: {section} (part {part} of {parts}) · other sections: {others}"
READ_SOURCE = "source: {source}"
SOURCE_STORED = "stored copy from {date}"
SOURCE_LIVE = "live"
SOURCE_LIVE_NOT_STORED = "live (not stored)"
# Q9.5: the librarian's answer.
LIBRARIAN_HEADER = "librarian: {verdict} ({confidence}) · {calls} model calls · {pages} pages inspected · {secs} s"
LIBRARIAN_SEARCHED = "searched: {queries}"
LIBRARIAN_ALSO = "also relevant: {page_ids}"
LIBRARIAN_READ_MORE = 'read more: tradecraft_lookup(page="{page_id}", section="{section}")'


@dataclass(frozen=True)
class Card:
    """A page card (Q4): what search and the librarian's shortlist read, never page text."""

    page_id: str
    resource_slug: str
    url: str
    title: str
    title_source: str = "guessed"
    breadcrumb: tuple[str, ...] = ()
    headings: tuple[str, ...] = ()
    description: str = ""
    topics: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    entities: tuple[str, ...] = ()
    size_chars: int = 0
    fetched_at: Optional[str] = None
    storage_mode: str = "live"
    stored: bool = False

    def path(self) -> str:
        return " › ".join(self.breadcrumb + (self.title,)) if self.title else " › ".join(self.breadcrumb)


@dataclass(frozen=True)
class SearchHit:
    card: Card
    score: float
    # How many of the free first pass's wordings found it (a page found by several rises).
    wordings_matched: int = 1
    section: Optional[str] = None
    snippet: str = ""


@dataclass(frozen=True)
class SearchAnswer:
    verdict: SearchVerdict
    hits: tuple[SearchHit, ...]
    wordings: tuple[str, ...]
    total: int


@dataclass(frozen=True)
class BrowseFolder:
    path: str
    label: str
    page_count: int
    description: str = ""


@dataclass(frozen=True)
class BrowseLevel:
    resource_slug: str
    path: str
    breadcrumb: tuple[str, ...]
    page_count: int
    folders: tuple[BrowseFolder, ...] = ()
    pages: tuple[Card, ...] = ()
    more: int = 0
    # A resource's root level also shows its full summary (Q7.1).
    summary: Optional[str] = None


@dataclass(frozen=True)
class SectionRead:
    page_id: str
    breadcrumb: tuple[str, ...]
    section: str
    part: int
    parts: int
    other_sections: tuple[str, ...]
    source: str
    text: str
    truncated: bool = False


@dataclass(frozen=True)
class LibrarianPick:
    page_id: str
    breadcrumb: tuple[str, ...]
    why: str
    excerpt: str
    section: Optional[str] = None


@dataclass(frozen=True)
class LibrarianAnswer:
    verdict: LibrarianVerdict
    confidence: Confidence
    model_calls: int
    pages_inspected: int
    seconds: float
    queries: tuple[str, ...] = ()
    picks: tuple[LibrarianPick, ...] = ()
    also_relevant: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)


def format_search_header(query: str, verdict: str, shown: int, total: int) -> str:
    if verdict not in SEARCH_VERDICTS:
        raise ValueError(f"verdict must be one of {', '.join(SEARCH_VERDICTS)}")
    return SEARCH_HEADER.format(query=_one_line(query), verdict=verdict, shown=shown, total=total)


_SEARCH_HEADER_RE = re.compile(r'^search: "(?P<query>.*)" · (?P<verdict>FOUND|RELATED|NOT FOUND) · (?P<shown>\d+) of (?P<total>\d+) results$')


def parse_search_header(line: str) -> Optional[dict]:
    m = _SEARCH_HEADER_RE.match(line.strip())
    if not m:
        return None
    return {"query": m["query"], "verdict": m["verdict"], "shown": int(m["shown"]), "total": int(m["total"])}


def format_read_section(section: str, part: int, parts: int, others: tuple[str, ...] | list[str]) -> str:
    return READ_SECTION.format(section=_one_line(section), part=part, parts=parts,
                               others=", ".join(_one_line(o) for o in others) or "none")


_READ_SECTION_RE = re.compile(r"^section: (?P<section>.*) \(part (?P<part>\d+) of (?P<parts>\d+)\) · other sections: (?P<others>.*)$")


def parse_read_section(line: str) -> Optional[dict]:
    m = _READ_SECTION_RE.match(line.strip())
    if not m:
        return None
    others = [] if m["others"] == "none" else m["others"].split(", ")
    return {"section": m["section"], "part": int(m["part"]), "parts": int(m["parts"]), "others": others}


def format_source(kind: str, date: Optional[str] = None) -> str:
    """The read path's source label (Q1.2): ``stored``, ``live`` or ``live_not_stored``."""
    if kind == "stored":
        if not date:
            raise ValueError("a stored copy names its date")
        return SOURCE_STORED.format(date=date)
    if kind == "live":
        return SOURCE_LIVE
    if kind == "live_not_stored":
        return SOURCE_LIVE_NOT_STORED
    raise ValueError(f"unknown source {kind!r}")


@dataclass(frozen=True)
class LibrarianHeader:
    verdict: str
    confidence: str
    calls: int
    pages: int
    seconds: float


def format_librarian_header(verdict: str, confidence: str, calls: int, pages: int, seconds: float) -> str:
    if verdict not in LIBRARIAN_VERDICTS:
        raise ValueError(f"verdict must be one of {', '.join(LIBRARIAN_VERDICTS)}")
    if confidence not in CONFIDENCES:
        raise ValueError(f"confidence must be one of {', '.join(CONFIDENCES)}")
    return LIBRARIAN_HEADER.format(verdict=verdict, confidence=confidence, calls=calls, pages=pages, secs=f"{seconds:.1f}")


_LIBRARIAN_HEADER_RE = re.compile(
    r"^librarian: (?P<verdict>FOUND|PARTIAL|NOT FOUND) \((?P<confidence>high|medium|low)\) · "
    r"(?P<calls>\d+) model calls · (?P<pages>\d+) pages inspected · (?P<secs>\d+(?:\.\d+)?) s$"
)


def parse_librarian_header(line: str) -> Optional[LibrarianHeader]:
    """The librarian's first line, or None for anything else (the trail line reads it)."""
    m = _LIBRARIAN_HEADER_RE.match(line.strip())
    if not m:
        return None
    return LibrarianHeader(m["verdict"], m["confidence"], int(m["calls"]), int(m["pages"]), float(m["secs"]))


def wrap_untrusted(lines: list[str]) -> str:
    return _wrap_with_nonce("\n".join(lines), UNTRUSTED_LABEL)


def find_librarian_header(result: str) -> Optional[LibrarianHeader]:
    """The header of a librarian result: the first line inside its envelope, never a line
    further down (an excerpt could imitate one)."""
    lines = result.splitlines()
    if len(lines) < 2 or not _OPENING.match(lines[0].strip()):
        return None
    return parse_librarian_header(lines[1])


def _one_line(text: str) -> str:
    """A value placed inside a header line: one line, so a page title cannot forge a second header."""
    return " ".join(str(text).split())

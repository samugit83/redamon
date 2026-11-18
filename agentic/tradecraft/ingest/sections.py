"""Stage ``sections`` (T2.3): a stored page split by its headings (Q4 item 6, R-335).

Writes ``state.sections`` as {url: [{ord, heading, level, anchor, text, chars}]} for the pages
that have a stored copy; search reads inside them and a read returns one at a time. A Live
page keeps no text, so it has no section rows: reading splits it at read time with
``split_markdown``, the same function, so a Stored and a Live copy of a page split alike.

A section starts at a Markdown heading of level 1 to 3 (``#`` to ``###``); deeper headings stay
in their section. A line inside a fenced code block is never a heading, so a code block is
never split across sections. The text before the first heading is section 0 (level 0, no
heading) when it holds anything. Anchors are the heading's slug, numbered when repeated, so
the same page splits into the same anchors at every refresh.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

_HEADING = re.compile(r"^ {0,3}(#{1,3})[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_SLUG_DROP = re.compile(r"[^a-z0-9]+")
MAX_HEADING_CHARS = 200


@dataclass(frozen=True)
class Section:
    ord: int
    heading: str
    level: int
    anchor: str
    text: str

    @property
    def chars(self) -> int:
        return len(self.text)

    def row(self) -> dict:
        return {"ord": self.ord, "heading": self.heading, "level": self.level, "anchor": self.anchor,
                "text": self.text, "chars": self.chars}


def clean_heading(text: str) -> str:
    """A heading as one plain line: link syntax and emphasis marks dropped."""
    text = _LINK.sub(r"\1", text)
    text = re.sub(r"[*_`]+", "", text)
    return " ".join(text.split())[:MAX_HEADING_CHARS]


def slug(text: str) -> str:
    return _SLUG_DROP.sub("-", text.lower()).strip("-")[:80]


def split_markdown(text: str) -> list[Section]:
    """The page's sections, in order."""
    raw: list[tuple[str, int, list[str]]] = [("", 0, [])]
    fence = ""
    for line in (text or "").splitlines():
        fenced = _FENCE.match(line)
        if fence:
            raw[-1][2].append(line)
            if fenced and fenced.group(1)[0] == fence[0] and len(fenced.group(1)) >= len(fence):
                fence = ""
            continue
        if fenced:
            fence = fenced.group(1)
            raw[-1][2].append(line)
            continue
        heading = _HEADING.match(line)
        if heading and clean_heading(heading.group(2)):
            raw.append((clean_heading(heading.group(2)), len(heading.group(1)), []))
            continue
        raw[-1][2].append(line)

    out: list[Section] = []
    used: dict[str, int] = {}
    for heading, level, lines in raw:
        body = "\n".join(lines).strip("\n")
        if level == 0 and not body.strip():
            continue
        anchor = ""
        if heading:
            base = slug(heading) or "section"
            used[base] = used.get(base, 0) + 1
            anchor = base if used[base] == 1 else f"{base}-{used[base]}"
        out.append(Section(ord=len(out), heading=heading, level=level, anchor=anchor, text=body))
    return out


def headings_of(text: str, limit: int = 50) -> list[dict]:
    """The page's headings of levels 1-3, as a card stores them: [{level, text}]."""
    return [{"level": s.level, "text": s.heading} for s in split_markdown(text) if s.heading][:limit]


def _rows(text: str) -> list[dict]:
    return [s.row() for s in split_markdown(text)]


async def build(state: "IngestState") -> "IngestState":
    """The sections of every page this job stores; nothing for a Live resource."""
    for url, stored in state.texts.items():
        rows = await state.blocking(_rows, stored.text)
        if rows:
            state.sections[url] = rows
    return state

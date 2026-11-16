"""Reading one section at a time (Q8, T2.5): which section a read returns, and its parts.

A page is split by its headings with ``ingest.sections.split_markdown``, the function ingestion
splits a stored copy with, so a Live page split at read time and a Stored copy name the same
sections. A section longer than ``reading.charsPerRead`` is cut into parts at paragraph
boundaries; a fenced code block is never cut in the middle, and a part holds at most
``constants.codeBlocksPerRead`` (5) of them, the next ones starting the next part.
"""

from __future__ import annotations

import re
from typing import Optional, Sequence

from tradecraft.ingest.sections import Section, split_markdown
from tradecraft.settings import constant

CODE_BLOCKS_PER_READ = int(constant("codeBlocksPerRead"))
INTRO = "(intro)"
# A code block longer than this is cut after all: a part must stay under the agent's global
# limit of 40,000 characters per tool result.
MAX_PART_CHARS = 38_000
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_WORD = re.compile(r"[a-z0-9]+")

__all__ = ["Section", "split_markdown", "section_name", "pick_section", "parts", "INTRO"]


def section_name(section: Section) -> str:
    return section.heading or INTRO


def _words(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


def pick_section(sections: Sequence[Section], wanted: Optional[str] = None, query: str = "") -> Optional[Section]:
    """The section asked for (its heading or anchor, case-insensitive, else the first heading
    that contains the words asked), or the one that best matches ``query`` (its words in the
    heading count double), or the page's first section."""
    if not sections:
        return None
    if wanted:
        key = " ".join(wanted.split()).lower()
        for s in sections:
            if key in (section_name(s).lower(), s.anchor):
                return s
        for s in sections:
            if key and key in section_name(s).lower():
                return s
        return None
    asked = _words(query)
    if asked:
        best, best_score = None, 0.0
        for s in sections:
            score = 2 * len(asked & _words(s.heading)) + len(asked & _words(s.text))
            if score > best_score:
                best, best_score = s, score
        if best is not None:
            return best
    return next((s for s in sections if s.text.strip()), sections[0])


def _blocks(text: str) -> list[tuple[bool, str]]:
    """(is_code, text) blocks: fenced code blocks whole, prose by paragraph."""
    out: list[tuple[bool, str]] = []
    buf: list[str] = []
    fence = ""

    def flush(is_code: bool) -> None:
        if buf and "\n".join(buf).strip():
            out.append((is_code, "\n".join(buf)))
        buf.clear()

    for line in (text or "").splitlines():
        m = _FENCE.match(line)
        if fence:
            buf.append(line)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = ""
                flush(True)
            continue
        if m:
            flush(False)
            fence = m.group(1)
            buf.append(line)
            continue
        if not line.strip():
            flush(False)
            continue
        buf.append(line)
    flush(bool(fence))
    return out


def _cut(text: str, size: int) -> list[str]:
    """Prose longer than a part, cut at line ends, else at spaces, else hard."""
    pieces, rest = [], text
    while len(rest) > size:
        at = rest.rfind("\n", 0, size)
        if at < size // 2:
            at = rest.rfind(" ", 0, size)
        if at < size // 2:
            at = size
        pieces.append(rest[:at].rstrip())
        rest = rest[at:].lstrip()
    if rest:
        pieces.append(rest)
    return pieces


def parts(text: str, max_chars: int, max_code_blocks: int = CODE_BLOCKS_PER_READ) -> list[str]:
    """The section's text in parts of at most ``max_chars`` characters and ``max_code_blocks``
    code blocks; a code block is never cut (unless it alone passes ``MAX_PART_CHARS``)."""
    max_chars = max(1, int(max_chars))
    out: list[str] = []
    current: list[str] = []
    size = code = 0

    def close() -> None:
        nonlocal size, code
        if current:
            out.append("\n\n".join(current))
        current.clear()
        size = code = 0

    for is_code, block in _blocks(text):
        if is_code:
            if len(block) > MAX_PART_CHARS:
                block = block[:MAX_PART_CHARS] + "\n[... code block cut at the read limit ...]"
            if current and (size + len(block) + 2 > max_chars or code >= max_code_blocks):
                close()
            current.append(block)
            size += len(block) + 2
            code += 1
            continue
        for piece in (_cut(block, max_chars) if len(block) > max_chars else [block]):
            if current and size + len(piece) + 2 > max_chars:
                close()
            current.append(piece)
            size += len(piece) + 2
    close()
    return out or [""]

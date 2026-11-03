"""Render a step's messages as one text document for the driver.

Each message becomes a role header and its parts. A part is one text block (a
cache tier of the think prompt) or a whole string message, identified by the
first 16 hex of its SHA-256. A part the same driver already received in an
earlier step of the session is replaced by a one-line placeholder, so a 100 KB
system prompt whose eternal tier never changes is sent once per session.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

ROLE_HEADERS = {
    "system": "=== SYSTEM ===",
    "user": "=== USER ===",
    "assistant": "=== ASSISTANT (your earlier answer) ===",
}
NON_TEXT = "[non-text content omitted]"
# A placeholder is ~140 characters, so deduping a shorter part saves nothing.
MIN_DEDUP_CHARS = 512
LAST_INSTRUCTION_CHARS = 2000
_PAGE_NEWLINE_WINDOW = 2000


@dataclass(frozen=True)
class Part:
    sha: str
    text: str


@dataclass(frozen=True)
class RenderedMessage:
    role: str
    parts: tuple[Part, ...]


@dataclass(frozen=True)
class Span:
    """Where a part rendered in full sits in the document."""
    sha: str
    start: int
    end: int


def part_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def placeholder(sha: str) -> str:
    return (f"[[part {sha} unchanged since your previous step; call loop_get_step "
            f"with full=true if you no longer have it]]")


def _role(message: Any) -> str:
    kind = getattr(message, "type", "") or ""
    return {"system": "system", "human": "user", "ai": "assistant"}.get(kind, "user")


def _texts(content: Any) -> Iterable[str]:
    if isinstance(content, str):
        yield content
        return
    if isinstance(content, list):
        for block in content:
            if isinstance(block, str):
                yield block
            elif isinstance(block, dict) and block.get("type") == "text":
                yield str(block.get("text") or "")
            else:
                yield NON_TEXT
        return
    yield str(content or "")


def to_parts(messages: Iterable[Any]) -> list[RenderedMessage]:
    out = []
    for message in messages:
        parts = tuple(Part(part_sha(t), t) for t in _texts(getattr(message, "content", "")) if t)
        out.append(RenderedMessage(_role(message), parts))
    return out


def render(messages: list[RenderedMessage], *, delivered: set[str] | None,
           full: bool) -> tuple[str, list[Span]]:
    """The document, and the spans of the parts written out in full."""
    chunks: list[str] = []
    spans: list[Span] = []
    pos = 0

    def add(text: str) -> int:
        nonlocal pos
        start = pos
        chunks.append(text)
        pos += len(text)
        return start

    for i, message in enumerate(messages):
        if i:
            add("\n\n")
        add(ROLE_HEADERS.get(message.role, f"=== {message.role.upper()} ==="))
        for part in message.parts:
            add("\n\n")
            dedup = (not full and delivered is not None and part.sha in delivered
                     and len(part.text) >= MIN_DEDUP_CHARS)
            if dedup:
                add(placeholder(part.sha))
            else:
                start = add(part.text)
                spans.append(Span(part.sha, start, pos))
    return "".join(chunks), spans


def page(text: str, cursor: int, size: int) -> tuple[str, int | None]:
    """One page from ``cursor``; prefers to end on a newline near the window end."""
    cursor = max(0, cursor)
    if cursor >= len(text):
        return "", None
    end = min(len(text), cursor + size)
    if end < len(text):
        cut = text.rfind("\n", max(cursor + 1, end - _PAGE_NEWLINE_WINDOW), end)
        if cut > cursor:
            end = cut + 1
    return text[cursor:end], (end if end < len(text) else None)


def last_instruction(messages: list[RenderedMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return "\n\n".join(p.text for p in message.parts)[:LAST_INSTRUCTION_CHARS]
    return ""

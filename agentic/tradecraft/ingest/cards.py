"""Stage ``cards`` (T2.3 completes it): one page card per map entry.

A card is the entry row the store writes: title, URL, source, and later the breadcrumb,
headings and description (T2.3), topics, kinds and technologies (T2.2, T5.1) and entities
(T2.2). Phase 1 fills only the title, its source and the entry's source; every other field
keeps the store's default.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def build(state: "IngestState") -> "IngestState":
    """``state.cards``: one card per entry, in map order, with the title, the title's source
    (``real`` for a page's own title, which the crawl reads; ``guessed`` otherwise) and the
    entry's source."""
    state.cards = [
        {
            "url": e.url,
            "title": e.title,
            "title_source": "real" if e.source == "crawl" else "guessed",
            "source": e.source,
            "status": e.extra.get("status", "kept"),
            "drop_reason": e.extra.get("drop_reason", ""),
        }
        for e in state.entries
    ]
    return state

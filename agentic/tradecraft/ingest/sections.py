"""Stage ``sections`` (T2.3 fills it): a stored page split by its headings.

Writes ``state.sections`` as {url: [{ord, heading, level, anchor, text, chars}]} for the
stored pages, which reading by section and search use. Until T2.3 no section is made.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def build(state: "IngestState") -> "IngestState":
    """The state with its sections. Phase 1: unchanged."""
    return state

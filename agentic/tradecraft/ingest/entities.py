"""Stage ``entities`` (T2.2 fills it): CVE ids, tools and product names found on each card.

Until T2.2 the cards carry no entity.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def extract(state: "IngestState") -> "IngestState":
    """The cards with their entities. Phase 1: unchanged."""
    return state

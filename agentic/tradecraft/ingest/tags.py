"""Stage ``tags`` (T2.2 and T5.1 fill it): topics, kinds and technologies on every card.

Rules first (``vocab.keywords``, ``kindKeywords``, the technologies list); with
``focus.tagEveryPage`` at ``rules_model`` the model tags, from titles, what the rules left.
Until then the cards carry no tag.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def tag(state: "IngestState") -> "IngestState":
    """The cards with their tags. Phase 1: unchanged."""
    return state

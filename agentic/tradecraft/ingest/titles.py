"""Stage ``titles`` (T6.1 fills it): real page titles for the known types.

With ``knownTypes.realTitles`` on, fetches up to ``knownTypes.maxTitleFetches`` pages for their
``<title>`` and sets ``title_source = "real"``. Until T6.1 the titles stay the guessed ones
(from the sitemap slug or the menu text), as in 1.x.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def apply(state: "IngestState") -> "IngestState":
    """The entries with their titles. Phase 1: unchanged."""
    return state

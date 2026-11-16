"""Stage ``curation`` (T6.6 fills it): the person's map curation applied to the built map.

Pins add entries (source ``pin``), blocks drop them for good (never stored, never read),
renames set ``title_source = "renamed"``, and a page restored from a focus drop is kept.
Reads the resource's ``tradecraft_curations`` rows through the store, keyed by owner.
Until T6.6 the map is left as built.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def apply(state: "IngestState") -> "IngestState":
    """The map with the curation applied. Phase 1: unchanged."""
    return state

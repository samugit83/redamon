"""Stage ``incremental`` (T6.2 fills it): which pages a refresh downloads again.

With ``storage.incremental`` on, a page whose ETag, Last-Modified, sitemap date or text
fingerprint shows no change reuses the stored text of the live generation
(``extra["reuse"]``). Until T6.2 every stored page is downloaded again.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def plan(state: "IngestState") -> "IngestState":
    """The entries, each marked with what storage may reuse. Phase 1: unchanged."""
    return state

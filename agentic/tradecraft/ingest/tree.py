"""Stage ``tree`` (T2.3 fills it): the resource's folders or virtual topics.

Writes ``state.tree`` as [{path, parent_path, label, page_count, description, kind}] from the
navigation, the GitHub folders or the URL paths, with a one-line description per folder.
Until T2.3 the resource has no tree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def build(state: "IngestState") -> "IngestState":
    """The state with its tree. Phase 1: unchanged."""
    return state

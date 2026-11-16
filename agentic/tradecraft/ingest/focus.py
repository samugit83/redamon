"""Stages ``focus`` and ``content_check`` (T5.1 and T6.9 fill them): the ingestion focus.

``select`` keeps or drops each entry by the resource's focus (§6.14 steps 1-2: rules, then the
model on titles), setting ``extra["status"]`` to ``kept`` or ``dropped`` and
``extra["drop_reason"]``; ``content_check`` re-checks borderline stored pages by their text
(step 3, ``focus.maxContentChecks``). Until then every entry is kept (mode "everything",
today's behaviour).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


async def select(state: "IngestState") -> "IngestState":
    """The entries with their keep or drop decision. Phase 1: unchanged."""
    return state


async def content_check(state: "IngestState") -> "IngestState":
    """The entries with their keep or drop decision. Phase 1: unchanged."""
    return state

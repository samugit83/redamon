"""Stage ``report``: the ingestion report on the card (§3.3, the contract's ``IngestionReport``).

Counts and codes only: pages visited and kept, pages skipped by reason, why the crawl
stopped, model calls, the duration, what was stored and what was not, and errors counted by
code. Never a URL (it may carry a query string or a token), never page text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tradecraft import clock
from tradecraft.contract import IngestionReport, ReportError

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState

MAX_ERRORS = 50


async def build(state: "IngestState") -> "IngestState":
    kept = sum(1 for e in state.entries if e.extra.get("status", "kept") == "kept")
    errors = [ReportError(code=code, count=n) for code, n in sorted(state.errors.items())][:MAX_ERRORS]
    crawl = state.crawl
    state.report = IngestionReport(
        visited=state.visited,
        kept=kept,
        skipped=dict(state.skipped),
        stopReason=(crawl.stop_reason if crawl is not None else state.stop_reason)[:64],
        llmCalls=state.llm_calls,
        durationSec=round(max(0.0, clock.monotonic() - state.started), 1),
        stored=dict(state.stored_counts),
        errors=errors,
    )
    return state

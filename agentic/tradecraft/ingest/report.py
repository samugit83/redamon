"""Stage ``report``: the ingestion report on the card (§3.3, the contract's ``IngestionReport``).

Counts and codes only: pages visited and kept, pages skipped by reason, why the crawl
stopped (or which source built a docs map), model calls, the duration, what was stored and
what was not, and errors counted by code. Never a URL (it may carry a query string or a
token), never page text.

Two lines join it with the focus (T5.1): ``focus``, what the focus did (its mode, and in
Focused mode how many pages it kept, kept as maybe and dropped, §6.14 "Transparency"), and
``readiness`` (Q4): the share of the kept pages with a real title, with headings, with a
description and with a topic, in whole percents. When any is under ``READINESS_LOW`` the
report suggests a fix, as a flag the card turns into words: Stored mode for a Live resource
(its stored copy gives every page its headings and a description), a focus with content
checks for a Stored one (``suggestStored`` / ``suggestContentChecks``, 1; the contract's
readiness holds numbers only).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tradecraft import clock
from tradecraft.contract import IngestionReport, ReportError
from tradecraft.ingest import focus

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState

MAX_ERRORS = 50
READINESS_LOW = 50
# A title the page gave (or the person wrote) counts as real; a guess from a path does not.
REAL_TITLE_SOURCES = ("real", "renamed")


def _pct(n: int, total: int) -> int:
    return round(100 * n / total)


def readiness(cards: list[dict], storage_mode: str, site_type: str) -> dict:
    """Q4's readiness line over the kept cards; {} when none was kept (a CVE archive has no
    pages to search)."""
    kept = [c for c in cards if c.get("status", "kept") == "kept"]
    if not kept:
        return {}
    total = len(kept)
    line = {
        "realTitlesPct": _pct(sum(1 for c in kept if c.get("title_source") in REAL_TITLE_SOURCES), total),
        "headingsPct": _pct(sum(1 for c in kept if c.get("headings")), total),
        "descriptionPct": _pct(sum(1 for c in kept if (c.get("description") or "").strip()), total),
        "taggedPct": _pct(sum(1 for c in kept if c.get("topics")), total),
    }
    if min(line.values()) < READINESS_LOW:
        stored = storage_mode == "stored" or site_type == "pdf"
        line["suggestContentChecks" if stored else "suggestStored"] = 1
    return line


async def build(state: "IngestState") -> "IngestState":
    kept = sum(1 for e in state.entries if e.extra.get("status", "kept") == "kept")
    errors = [ReportError(code=code, count=n) for code, n in sorted(state.errors.items())][:MAX_ERRORS]
    crawl = state.crawl
    state.report = IngestionReport(
        visited=state.visited,
        kept=kept,
        skipped={**state.skipped, "outsideFocus": focus.dropped_count(state.entries)},
        # The pipeline's own reason names the source of a docs map, the crawl included when it built it.
        stopReason=(state.stop_reason or (crawl.report_stop_reason if crawl is not None else ""))[:64],
        llmCalls=state.llm_calls,
        durationSec=round(max(0.0, clock.monotonic() - state.started), 1),
        stored=dict(state.stored_counts),
        focus=focus.report_counts(state),
        readiness=readiness(state.cards, state.storage_mode, state.site_type),
        errors=errors,
    )
    return state

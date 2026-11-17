"""Stage ``curation`` (T6.6, §6.10, R-167, R-168, AC-14, AC-40): the person's map curation applied
to the map this refresh built, so pins, blocks and renames survive every refresh.

The resource's ``tradecraft_curations`` rows (read through the store, keyed by the owner), by
URL (canonical, as entries are stored):

- **blocked**: the entry leaves the map for good, before anything is stored, tagged or written;
  the read path refuses its URL from any source. A block made while this job runs is caught at
  the write: ``clear_blocked`` empties the stored text and sections the job wrote for it (the
  Map view's block reached only the rows that existed when it was made).
- **pinned** (a URL typed by the person, or a dropped page restored, which is pinned too): kept
  whatever the focus decides (``extra["pinned"]``, which ``focus`` never drops), and added with
  source ``pin`` when the refresh did not find it. A pin must be a URL an entry may hold; on a
  resource with a login it must also be on the resource's own host (§5: no page outside its
  map, and no login sent elsewhere), which the Map view already checks.
- **renamed**: the entry takes the person's title (``title_source = "renamed"``); the page's own
  title is never stored over it, and clearing the rename brings the page's back at the next
  refresh.

Unblocking deletes the row's ``blocked`` flag: the page comes back with the next refresh that finds it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from logging_config import get_logger
from tradecraft import net
from tradecraft.ingest import fetch
from tradecraft.ingest.builders import Candidate, title_from_slug

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

# The Map view's rename limit (W/src/lib/tradecraft/curation.ts RENAME_MAX).
RENAME_MAX = 300
# Types whose map is not a list of pages a URL can join: a PDF's pages and a CVE archive.
_NO_PINS = ("pdf", "cve-poc-db")


def _title(value: Any) -> str:
    return " ".join(str(value or "").split())[:RENAME_MAX]


def _restore(entry: Any) -> None:
    """A pinned page is kept: a drop by the focus-aware crawl is undone (the triage never drops it)."""
    entry.extra["pinned"] = True
    if entry.extra.get("status") == "dropped":
        entry.extra["status"] = "kept"
        entry.extra.pop("drop_reason", None)
        entry.extra.pop("dropped_by", None)
        entry.extra["focus_decision"] = "keep"


def _rename(entry: Any, title: str) -> None:
    entry.title = title
    entry.extra["title_source"] = "renamed"


async def apply(state: "IngestState") -> "IngestState":
    """The map with the curation applied: blocked entries out, pinned ones kept or added, renamed
    ones retitled."""
    rows = await state.store.curation_rows(state.owner_id, state.resource_id)
    state.curations = list(rows)
    if not rows:
        return state
    by_url: dict[str, dict] = {}
    for row in rows:
        by_url.setdefault(fetch.canonical_url(str(row.get("url") or "")), row)
    # The URL as the person typed it decides whether a pin may join (canonical form drops what it refuses).
    blocked = {url for url, row in by_url.items() if row.get("blocked")}
    before = len(state.entries)
    state.entries = [e for e in state.entries if e.url not in blocked]
    removed = before - len(state.entries)
    present = {e.url for e in state.entries}
    for entry in state.entries:
        row = by_url.get(entry.url)
        if row is None:
            continue
        if row.get("pinned") or row.get("restored_from_drop"):
            _restore(entry)
        title = _title(row.get("renamed_title"))
        if title:
            _rename(entry, title)
    added = refused = 0
    if state.site_type not in _NO_PINS:
        for url, row in by_url.items():
            if url in present or url in blocked or not (row.get("pinned") or row.get("restored_from_drop")):
                continue
            if not _pin_ok(state, str(row.get("url") or "")):
                refused += 1
                continue
            entry = Candidate(url, title_from_slug(url, strip_html=True) or url, "pin", url, {"pinned": True})
            title = _title(row.get("renamed_title"))
            if title:
                _rename(entry, title)
            state.entries.append(entry)
            present.add(url)
            added += 1
    if removed or added or refused:
        logger.info(f"[tradecraft] job {state.request.job_id} curation code= blocked={removed} pinned={added} "
                    f"refused={refused}")
    return state


def _pin_ok(state: "IngestState", url: str) -> bool:
    """A pin an entry may hold (http(s), no user name or password in it, at most 2,048 bytes, no
    fragment); on a resource with a login, on its own host only."""
    url = url.strip()
    if not fetch.entry_url_ok(url) or "#" in url:
        return False
    if fetch.has_login(state.request.secrets):
        return net.carries_same_host_headers(state.url, url)
    return True

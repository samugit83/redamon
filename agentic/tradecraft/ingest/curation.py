"""Stage ``curation`` (T6.6, §6.10, R-167, R-168, AC-14, AC-39, AC-40): the person's map curation applied
to the map this refresh built, so pins, blocks and renames survive every refresh.

The resource's ``tradecraft_curations`` rows (read through the store, keyed by the owner) are read
by the URL an entry is stored under (``fetch.page_url``: canonical, a PDF page's ``#page=N`` kept), so
a URL the person typed in another form and the entry's own name the same page. Several rows for one
page merge whatever their order: a block wins over a pin, a pin over nothing, and a rename on the
entry's own URL over one on another form of it.

- **blocked**: the entry leaves the map for good, before anything is stored, tagged or written; the
  read path refuses its URL from any source. A page blocked while the job runs is caught after the
  write (``block_late``): its sections and stored text leave the job's generation whatever the Map
  view's block already emptied (it reached only the rows that existed when it was made).
- **pinned** (a URL the person typed, or a dropped page restored, which the Map view also pins):
  kept whatever the focus decides (``extra["pinned"]``, which ``focus`` never drops), and added with
  source ``pin`` when the refresh did not find it, under its canonical URL (a fragment is not a
  page). On a resource with a login only on the resource's own host (§5: no page outside its map,
  and no login sent elsewhere), which the Map view checks too; never on a PDF or a CVE archive. A
  page pinned or restored while the job runs, which the job's focus dropped, is kept in the
  generation the job made live (``restore_late``). ``restored_from_drop`` alone is no pin: a block
  clears the pin, and an unblock does not bring it back.
- **renamed**: the entry takes the person's title (``title_source = "renamed"``); the page's own
  title is never stored over it, and clearing the rename brings the page's back at the next refresh.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping

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


@dataclass
class Curated:
    """The curation of one page, from every row that names it."""

    blocked: bool = False
    pinned: bool = False
    renamed: str = ""
    typed: list[str] = field(default_factory=list)

    @property
    def keeps(self) -> bool:
        return self.pinned and not self.blocked


def _title(value: Any) -> str:
    return " ".join(str(value or "").split())[:RENAME_MAX]


def merged(rows: Iterable[Mapping[str, Any]]) -> dict[str, Curated]:
    """{entry URL: curation} of the rows, the same whatever order they come in."""
    out: dict[str, Curated] = {}
    for row in sorted(rows, key=lambda r: str(r.get("url") or "")):
        raw = str(row.get("url") or "").strip()
        if not raw:
            continue
        key = fetch.page_url(raw)
        cur = out.setdefault(key, Curated())
        cur.blocked = cur.blocked or bool(row.get("blocked"))
        cur.pinned = cur.pinned or bool(row.get("pinned"))
        title = _title(row.get("renamed_title"))
        if title and (not cur.renamed or raw == key):
            cur.renamed = title
        cur.typed.append(raw)
    return out


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


def _pin_url(state: "IngestState", typed: Iterable[str]) -> str:
    """The URL a pin joins the map under, or "": a URL an entry may hold (http(s), no user name
    or password in it, at most 2,048 bytes; its fragment dropped); on a resource with a login, on
    its own host only."""
    for raw in typed:
        base = raw.split("#", 1)[0].strip()
        if not fetch.entry_url_ok(base):
            continue
        if fetch.has_login(state.request.secrets) and not net.carries_same_host_headers(state.url, base):
            continue
        return fetch.canonical_url(base)
    return ""


async def apply(state: "IngestState") -> "IngestState":
    """The map with the curation applied: blocked entries out, pinned ones kept or added, renamed
    ones retitled."""
    rows = await state.store.curation_rows(state.owner_id, state.resource_id)
    state.curations = list(rows)
    if not rows:
        return state
    curated = merged(rows)
    before = len(state.entries)
    state.entries = [e for e in state.entries if not (e.url in curated and curated[e.url].blocked)]
    removed = before - len(state.entries)
    present = {e.url for e in state.entries}
    for entry in state.entries:
        cur = curated.get(entry.url)
        if cur is None:
            continue
        if cur.keeps:
            _restore(entry)
        if cur.renamed:
            _rename(entry, cur.renamed)
    added = refused = 0
    if state.site_type not in _NO_PINS:
        for key, cur in curated.items():
            if key in present or not cur.keeps:
                continue
            url = _pin_url(state, cur.typed)
            if not url:
                refused += 1
                continue
            if url in present or (url in curated and curated[url].blocked):
                continue
            entry = Candidate(url, title_from_slug(url, strip_html=True) or url, "pin", url, {"pinned": True})
            if cur.renamed:
                _rename(entry, cur.renamed)
            state.entries.append(entry)
            present.add(url)
            added += 1
    if removed or added or refused:
        logger.info(f"[tradecraft] job {state.request.job_id} curation code= blocked={removed} pinned={added} "
                    f"refused={refused}")
    return state


async def block_late(state: "IngestState") -> None:
    """After the job's write: the pages blocked since ``apply`` lose their sections and stored text
    in the job's generation, leave the job's map, and stop counting as stored."""
    rows = await state.store.curation_rows(state.owner_id, state.resource_id)
    blocked = sorted(url for url, cur in merged(rows).items() if cur.blocked)
    if not blocked:
        return
    hit = set(await state.store.clear_blocked(state.owner_id, state.resource_id, state.generation, blocked))
    if not hit:
        return
    for card in state.cards:
        if card["url"] not in hit or card.get("status", "kept") != "kept":
            continue
        stored = state.texts.get(card["url"])
        size = stored.bytes if stored is not None else None
        if size is None and card.get("_carried"):
            entry = next((e for e in state.entries if e.url == card["url"]), None)
            size = int(((entry.extra.get("reuse") if entry else None) or {}).get("stored_bytes") or 0)
        if size is not None:
            state.stored_counts["pages"] = max(0, state.stored_counts["pages"] - 1)
            state.stored_counts["bytes"] = max(0, state.stored_counts["bytes"] - size)
    state.entries = [e for e in state.entries if e.url not in hit]
    state.cards = [c for c in state.cards if c["url"] not in hit]
    logger.info(f"[tradecraft] job {state.request.job_id} curation code=blocked_during_job pages={len(hit)}")


async def restore_late(state: "IngestState") -> None:
    """After the swap: a page pinned or restored while the job ran, which its focus dropped, is kept
    in the generation the job made live. A failure here leaves the job's result as it is."""
    try:
        rows = await state.store.curation_rows(state.owner_id, state.resource_id)
        pinned = sorted(url for url, cur in merged(rows).items() if cur.keeps)
        kept = await state.store.restore_pinned(state.owner_id, state.resource_id, state.generation, pinned)
    except Exception as exc:  # the store's errors only; the swap already happened
        logger.warning(f"[tradecraft] job {state.request.job_id} curation code=restore_failed cause={type(exc).__name__}")
        return
    if kept:
        logger.info(f"[tradecraft] job {state.request.job_id} curation code=restored_during_job pages={len(kept)}")

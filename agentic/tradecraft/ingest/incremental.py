"""Stage ``incremental`` (T6.2, §4.5 "Incremental refresh", R-342): which pages a refresh downloads again.

With ``storage.incremental`` on (the default) and text to store, each kept entry that has a stored
copy in the live generation is marked with what that copy was (``extra["reuse"]``: its fingerprint,
ETag, Last-Modified, date and the columns derived from its text, never the text). ``storage``
then decides per page, and a page it finds unchanged is not stored again: it is copied forward
into the new generation with its sections (``store.copy_forward``) and the stages that rebuild
from text (sections, the model tagging, the content check) skip it.

A page is unchanged on the site's own word or on identical text, never on a guess:

- the conditional request (``If-None-Match`` with its ETag, ``If-Modified-Since`` with its
  Last-Modified) answers 304;
- or the text this refresh downloaded, or the crawl's or the archive's copy of it, has the same
  fingerprint (the SHA-256 of the stored text) as the copy.

The sitemap's ``lastmod`` is not read: the sitemap reader every builder shares keeps page URLs
only, and a date the site writes in its sitemap is a weaker word than its own answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from tradecraft.ingest.storage import REUSE, UNCHANGED, stores_text

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState


def applies(state: "IngestState") -> bool:
    return stores_text(state.site_type, state.storage_mode) and state.settings.bool("storage.incremental")


def previous_generation(state: "IngestState") -> Optional[int]:
    return state.previous.get("generation") if state.previous else None


def unchanged(entry: Any) -> bool:
    return bool(entry.extra.get(UNCHANGED))


async def plan(state: "IngestState") -> "IngestState":
    """The kept entries with a stored copy, each marked with that copy (``extra["reuse"]``)."""
    if not applies(state):
        return state
    basis = await state.store.refresh_basis(state.owner_id, state.resource_id)
    if not basis:
        return state
    rows = {row["url"]: row for row in basis}
    state.previous = {"generation": int(basis[0]["generation"]), "pages": len(rows)}
    for entry in state.entries:
        if entry.extra.get("status", "kept") != "kept":
            continue
        row = rows.get(entry.url)
        if row is not None:
            entry.extra[REUSE] = row
    return state

"""Stage ``store``: the cleaned text of the kept pages of a Stored resource (§4.5).

A Live resource stores nothing; a PDF is always stored, a CVE archive never (R-082). Pages are
stored in map order until one of the limits says stop, and every page past it is counted in
the report and read live later:

- ``storage.maxPages`` pages and ``storage.maxResourceMb`` per resource (``notStoredSize``);
- ``storage.maxPageKb`` per page: a longer page is cut;
- the owner's quota, ``storage.userQuotaMb`` under ``constants.userStoredBytesCeiling``, and
  the install's ceiling ``constants.instanceStoredBytesCeiling`` (OQ-26), read once per job
  (``notStoredQuota``). The resource's own live generation does not count: the refresh
  replaces it.

A page the crawl already downloaded is not downloaded again; a PDF page's text comes from the
document. A page that cannot be read is not stored and its error code is counted.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from tradecraft import clock
from tradecraft.ingest import fetch
from tradecraft.settings import constant

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState

MB = 1024 * 1024


@dataclass
class StoredPage:
    text: str
    bytes: int
    text_hash: str
    fetched_at: datetime
    truncated: bool = False
    etag: str = ""
    last_modified: str = ""


def cut_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    """``text`` cut to at most ``max_bytes`` of UTF-8, on a character boundary."""
    data = text.encode("utf-8")
    if len(data) <= max_bytes:
        return text, False
    return data[:max_bytes].decode("utf-8", errors="ignore"), True


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stores_text(site_type: str, storage_mode: str) -> bool:
    if site_type == "cve-poc-db":
        return False
    return site_type == "pdf" or storage_mode == "stored"


async def _page_text(state: "IngestState", entry) -> tuple[str, str, dict]:
    """(Markdown text, error code, response headers) of one kept entry."""
    if "text" in entry.extra:  # a PDF page
        return entry.extra["text"] or "", "", {}
    if "html" in entry.extra:  # the crawl's own download
        return await state.clean(entry.extra["html"]), "", {}
    page = await fetch.smart_fetch(entry.url, state.settings, github_token=state.github_token,
                                   allow_browser=True, cleaner=state.clean)
    state.visited += 1
    state.store_downloads += 1
    if page.error or not (200 <= page.status < 300):
        state.store_download_failures += 1
        return "", page.error or "http_error", {}
    return page.text, "", page.headers


async def store(state: "IngestState") -> "IngestState":
    if not stores_text(state.site_type, state.storage_mode):
        return state
    s, st = state.settings, state.store
    max_pages = s.int("storage.maxPages")
    max_page_bytes = s.int("storage.maxPageKb") * 1024
    max_resource = s.int("storage.maxResourceMb") * MB
    quota = min(s.int("storage.userQuotaMb") * MB, int(constant("userStoredBytesCeiling")))
    used_by_others = await st.user_stored_bytes(state.owner_id, state.resource_id)
    own_live = await st.user_stored_bytes(state.owner_id) - used_by_others
    install_used = await st.instance_stored_bytes() - own_live
    room = min(quota - used_by_others, int(constant("instanceStoredBytesCeiling")) - install_used)

    kept = [e for e in state.entries if e.extra.get("status", "kept") == "kept"]
    total, stored = 0, 0
    for i, entry in enumerate(kept):
        await state.check_cancelled()
        if stored >= max_pages or total >= max_resource:
            state.stored_counts["notStoredSize"] += 1
            continue
        if total >= room:
            state.stored_counts["notStoredQuota"] += 1
            continue
        text, error, headers = await _page_text(state, entry)
        if error:
            state.count_error(error)
            continue
        if not text.strip():
            continue
        text, truncated = cut_utf8(text, max_page_bytes)
        size = len(text.encode("utf-8"))
        if total + size > max_resource:
            state.stored_counts["notStoredSize"] += 1
            continue
        if total + size > room:
            state.stored_counts["notStoredQuota"] += 1
            continue
        total += size
        stored += 1
        state.texts[entry.url] = StoredPage(text=text, bytes=size, text_hash=text_hash(text),
                                            fetched_at=clock.now(), truncated=truncated,
                                            etag=_header(headers, "etag"),
                                            last_modified=_header(headers, "last-modified"))
        await state.progress("store", i + 1, len(kept), "pages")
    state.stored_counts["pages"] = stored
    state.stored_counts["bytes"] = total
    return state


def failure_code(state: "IngestState") -> str:
    """``fetch_failed`` when more than half of the pages this refresh downloaded to store could
    not be read: the site is down or limiting us, and swapping in a generation without their
    text would delete the copies a Stored resource exists to keep (R-194, AC-16). Pages left
    unstored by the quota or a size limit are not failures; a crawl's or a PDF's text needs no
    download."""
    if state.store_downloads and state.store_download_failures * 2 > state.store_downloads:
        return "fetch_failed"
    return ""


def _header(headers: dict, name: str) -> str:
    value: Optional[str] = next((v for k, v in (headers or {}).items() if k.lower() == name), None)
    return (value or "")[:200]

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

Incremental refresh (T6.2): a page ``incremental.plan`` marked with its stored copy
(``extra["reuse"]``) is asked for with that copy's validators, and is unchanged when the site
answers 304 or its text has the copy's fingerprint. An unchanged page is counted as stored but
not kept here: the write copies it forward from the live generation (``extra["unchanged"]``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from logging_config import get_logger
from tradecraft import clock
from tradecraft.ingest import fetch, github_archive, titles
from tradecraft.settings import constant

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

MB = 1024 * 1024
# entry.extra keys of an incremental refresh: the live copy incremental.plan found, and the
# decision that the page did not change.
REUSE = "reuse"
UNCHANGED = "unchanged"


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


def conditional_headers(row: dict) -> dict[str, str]:
    """The stored copy's validators for a conditional request; {} when it has none. A value with
    a line break never travels (it was written by a site, and would add a header line)."""
    headers = {}
    for name, column in (("If-None-Match", "etag"), ("If-Modified-Since", "last_modified")):
        value = str(row.get(column) or "").strip()
        if value and not any(c in value for c in "\r\n\x00"):
            headers[name] = value
    return headers


def stores_text(site_type: str, storage_mode: str) -> bool:
    if site_type == "cve-poc-db":
        return False
    return site_type == "pdf" or storage_mode == "stored"


async def _page_text(state: "IngestState", entry) -> tuple[str, str, dict, bool]:
    """(Markdown text, error code, response headers, not modified) of one kept entry."""
    if "text" in entry.extra:  # a PDF page
        return entry.extra["text"] or "", "", {}, False
    if "html" in entry.extra:  # the crawl's own download
        return await state.clean(entry.extra["html"]), "", {}, False
    reuse = entry.extra.get(REUSE)
    # §5: a resource with a login never uses the browser, "always use the browser" included.
    page = await fetch.smart_fetch(entry.url, state.settings, github_token=state.github_token,
                                   allow_browser=not fetch.has_login(state.request.secrets), cleaner=state.clean,
                                   headers=conditional_headers(reuse) if reuse and reuse.get("conditional") else None)
    state.visited += 1
    if page.status == 304 and reuse:
        return "", "", page.headers, True
    state.store_downloads += 1
    if page.error or not (200 <= page.status < 300):
        state.store_download_failures += 1
        return "", page.error or "http_error", {}, False
    if page.truncated:
        state.count_error(fetch.PAGE_TOO_LARGE)
    titles.collect(state, entry, html=page.html, text=page.text, content_type=page.content_type)
    return page.text, "", page.headers, False


def _carry(state: "IngestState", entry, headers: dict) -> None:
    """The page did not change: the write copies it forward. Its new validators, when the site
    sent some, replace the copy's; a real title it had stays (no download gave a new one)."""
    entry.extra[UNCHANGED] = True
    entry.extra["validators"] = {"etag": _header(headers, "etag"), "last_modified": _header(headers, "last-modified")}
    row = entry.extra[REUSE]
    if titles.wants_stored(state, entry) and row.get("title_source") == "real" and row.get("title"):
        entry.title = row["title"]
        entry.extra["title_source"] = "real"


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
    # A Stored repository's files from one archive download (T6.3); what it misses is downloaded below.
    from_archive = await github_archive.prefetch(state, kept)
    total, stored, unchanged = 0, 0, 0
    for i, entry in enumerate(kept):
        await state.check_cancelled()
        if stored >= max_pages or total >= max_resource:
            state.stored_counts["notStoredSize"] += 1
            continue
        if total >= room:
            state.stored_counts["notStoredQuota"] += 1
            continue
        reuse = entry.extra.get(REUSE)
        not_modified = False
        if entry.url in from_archive:
            text, cut = from_archive.pop(entry.url)
            error, headers = "", {}
            if cut:
                state.count_error(fetch.PAGE_TOO_LARGE)
            titles.collect(state, entry, text=text, content_type="text/markdown")
        else:
            text, error, headers, not_modified = await _page_text(state, entry)
        if error:
            state.count_error(error)
            continue
        if not_modified:
            size = int(reuse.get("stored_bytes") or 0)
        else:
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
        digest = "" if not_modified else text_hash(text)
        if not_modified or (reuse and digest == reuse.get("text_hash")):
            _carry(state, entry, headers)
            unchanged += 1
        else:
            state.texts[entry.url] = StoredPage(text=text, bytes=size, text_hash=digest,
                                                fetched_at=clock.now(), truncated=truncated,
                                                etag=_header(headers, "etag"),
                                                last_modified=_header(headers, "last-modified"))
        await state.progress("store", i + 1, len(kept), "pages")
    state.stored_counts["pages"] = stored
    state.stored_counts["bytes"] = total
    titles.finish(state)
    if state.previous:
        logger.info(f"[tradecraft] job {state.request.job_id} incremental code= unchanged={unchanged} "
                    f"stored={stored - unchanged}")
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

"""Read now (T6.6, §6.10, R-166, R-229, AC-38): one page of a resource downloaded for the person,
the way the agent's tool reads it, and kept nowhere.

The webapp's Map view sends the URL of an entry of the live map (never one from the request body)
and the resource's secrets; the agent checks everything again against the store, not the request:

1. the resource is gone for this owner                     -> ``resource_deleted``, no request
2. the page is blocked                                     -> ``page_blocked``, no request
3. the resource has a login (the store's flag) and the URL is neither a kept entry of its live
   map nor a pin on its own host                            -> ``outside_map``, no request
4. otherwise the page is downloaded through the reader's live read (``reader.live_page``: the
   same settings, the same cleaning, plain HTTP only with a login, the login only on the
   resource's own host) and its text is answered; a PDF page is read from the document.

Nothing is written: no row, no file. The router ends the call at the contract's deadline
(``contract.DEADLINES_SEC["read_now"]``, 45 s) with ``timeout``. Log lines carry codes only.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

from logging_config import get_logger
from tradecraft import clock, net
from tradecraft.contract import ReadNowRequest, ReadNowResult
from tradecraft.ingest import fetch
from tradecraft.library import reader
from tradecraft.settings import EffectiveSettings

logger = get_logger(__name__)

# net's refusals as the contract's error codes.
_REFUSED = {"unsafe_address": "blocked_private_address", "userinfo_refused": "userinfo_refused", "bad_url": "bad_url"}
_PDF_PAGE = re.compile(r"#page=(\d+)$")


def default_store() -> Any:
    from tradecraft.store import Store
    return Store()


def _answer(code: str) -> ReadNowResult:
    logger.info(f"[tradecraft] read_now code={code}")
    return ReadNowResult(error_code=code)


async def _may_read(store: Any, owner: str, rid: str, url: str, row: dict, curation: Optional[dict]) -> bool:
    """A resource with a login reads only its map (§5): a kept entry of the live generation, or a
    pin the person added on the resource's own host that no refresh has listed yet."""
    if await store.in_map(owner, rid, url):
        return True
    pinned = bool(curation and (curation.get("pinned") or curation.get("restored_from_drop")))
    return pinned and net.carries_same_host_headers(row.get("url") or "", url)


async def _pdf_page(url: str, number: int, settings: EffectiveSettings, token: Optional[str]) -> tuple[str, str]:
    resp = await fetch.fetch_raw(url.split("#", 1)[0], settings, github_token=token)
    if resp.error:
        return "", _REFUSED.get(resp.error, "timeout" if resp.error == "timeout" else "fetch_failed")
    if not (resp.ok and resp.body[:5] == b"%PDF-"):
        return "", "fetch_failed"
    try:
        text = await asyncio.get_running_loop().run_in_executor(None, reader._pdf_page_text, resp.body, number)
    except Exception:
        text = ""
    return text, "" if text else "fetch_failed"


async def read_now(request: ReadNowRequest, *, store: Any = None) -> ReadNowResult:
    store = store if store is not None else default_store()
    url = request.url.strip()
    problem = net.url_problem(url.split("#", 1)[0])
    if problem:
        return _answer(_REFUSED.get(problem, "bad_url"))
    owner, rid = request.user_id, request.resource_id
    row = await store.legacy_sitemap(owner, rid)
    if row is None:
        return _answer("resource_deleted")
    canonical = fetch.page_url(url)
    curation = await store.curation(owner, rid, canonical)
    if curation and curation.get("blocked"):
        return _answer("page_blocked")
    has_login = bool(row.get("has_login"))
    if has_login and not await _may_read(store, owner, rid, canonical, row, curation):
        return _answer("outside_map")
    # The login travels only for a resource the store says has one, and only to its own host.
    credentials = request.secrets.credentials if has_login else None
    token = fetch.repo_token(url.split("#", 1)[0], request.secrets.github_token, row.get("url") or "")
    settings = EffectiveSettings(request.read_settings or {})
    truncated = False
    with fetch.use_login(row.get("url") or url, credentials):
        pdf = _PDF_PAGE.search(canonical)
        if pdf:
            text, code = await _pdf_page(url, int(pdf.group(1)), settings, token)
        else:
            page = await reader.live_page(url, settings, github_token=token, has_login=has_login)
            text, truncated = page.text, page.truncated
            if page.error:
                code = _REFUSED.get(page.error) or ("timeout" if page.error == "timeout" else "fetch_failed")
            elif not (200 <= page.status < 300) or not text:
                code = "fetch_failed"
            else:
                code = ""
    if code:
        return _answer(code)
    source = "live"
    if row.get("storage_mode") == "stored":
        copy = await store.entry_by_url(owner, rid, canonical)
        source = "live" if copy and copy.get("stored_text") else "live_not_stored"
    logger.info(f"[tradecraft] read_now code= source={source} chars={len(text)}")
    return ReadNowResult(text=text, source=source, fetched_at=clock.now().isoformat(), truncated=truncated)

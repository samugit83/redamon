"""The read path of ``tradecraft_lookup`` in a 2.0 run (Q1.1-Q1.3).

    the tool picked page P of resource R, for the run's owner
    1. R no longer exists?                      -> say it was deleted, no request
    2. P blocked, or R has a login and P is not in its map?  -> refused, no request
    3. R is Stored and P has a stored copy?     -> return it ("stored copy from <date>")
    4. otherwise                                -> download P, return it ("live", or
                                                   "live (not stored)" on a Stored resource);
                                                   nothing is kept
    5. the site cannot be reached               -> an error that says whether a copy exists

Every read is keyed by the catalog's owner and the resource's id, and reads the resource's
live generation at this call, so a refresh that swaps during a run is seen at the next call.
The catalog, its token and its logins come only from ``runtime.bound_catalog()``; outside a
run's task nothing is bound and nothing is requested. Reading never writes (R-306).

Reading by page and section (Q8, T2.5): ``page`` (an ID from search, a hint or the librarian)
names the page, ``section`` one of its headings and ``part`` a part of a long section. A read
returns one section, the one asked for or the best match for ``query``, at most
``reading.charsPerRead`` characters with code blocks whole (``split``), and its header names
the page ID, the section, "part N of M" and the page's other sections. A Live page is split
at read time and nothing is kept. Every page returned is recorded as seen in the run.

With ``resource_id`` and ``query`` (the 1.x arguments), the free first pass of search picks
the page of a resource that has cards (``map_version`` 2 and up), and the read is one section of
it. When the first pass finds nothing, today's title match over the resource's 1.x map, which
every 2.0 ingestion keeps current (TD-18, R-217), picks the page with no model (the section
picker is not used on such a resource), and the read is still one section. An unconverted
resource, a forced ``section_path`` and a run without a search index keep today's title match
and today's whole-page answer; the page they return is recorded as seen too when it is an
entry of the store (page IDs name entries). A CVE archive is read live, a CVE at a time; a PDF
page from the store.
"""

from __future__ import annotations

import asyncio
import io
import re
from datetime import datetime
from typing import Any, Optional

from logging_config import get_logger
from tradecraft import net, run_state, runtime
from tradecraft.ingest import fetch
from tradecraft.library import cve, legacy_match, page_ids, search, split
from tradecraft.library.types import READ_PAGE, READ_SOURCE, format_read_section, format_source, wrap_untrusted
from tradecraft.settings import EffectiveSettings, constant

logger = get_logger(__name__)

NOT_AVAILABLE = "Error: tradecraft_lookup is not available in this run (no Tradecraft library is bound to it)."
DELETED = "Error: resource '{slug}' was deleted from the library; it can no longer be read."
NOT_CONFIGURED = "Error: resource '{slug}' not configured. Available: {available}."
BLOCKED = "Error: refusing to read {url}: this page is blocked in resource '{slug}'."
OUTSIDE_MAP = ("Error: refusing to read {url}: resource '{slug}' has a site login, and only the pages of its "
               "map are read with it.")
BAD_URL = "Error: refusing to read {url}: {code}."
UNREACHABLE_LIVE = ("Error: could not read {url} ({code}). Resource '{slug}' is Live: no copy of its pages is "
                    "kept, so nothing can be returned until the site answers.")
UNREACHABLE_NOT_STORED = ("Error: could not read {url} ({code}). Resource '{slug}' is Stored, but this page has no "
                          "stored copy.")
NOT_REFRESHED = "the site could not be reached ({code}); this is the stored copy, not a fresh read"
SKIPPED_COPY = "read from the site at your request; the stored copy from {date} was not used"
# The address guard's refusals: not an unreachable site, and no copy is offered instead.
_REFUSED = ("unsafe_address", "userinfo_refused", "bad_url")
PAGE_GONE = ("Error: page {page_id} is no longer in resource '{slug}' (a refresh removed it); "
             "search again with tradecraft_search.")
NO_SECTION = "Error: page {page_id} has no section {section!r}. Its sections: {sections}."
NO_PART = "Error: section {section!r} of page {page_id} has {parts} part(s); ask for part 1 to {parts}."
CVE_BY_ID = "Error: resource '{slug}' is a cve-poc-db: read it with cve_id='CVE-YYYY-NNNNN', not by page."
NO_PAGE = ("Error: no page of resource '{slug}' matches {query!r}. Search it with tradecraft_search(query=..., "
           'resource="{slug}"), or browse it with tradecraft_search(resource="{slug}", path="").')
# The other sections a read header lists: the rest are counted.
OTHER_SECTIONS_LISTED = 30


def _date(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, str) and value:
        return value[:10]
    return "unknown date"


def code_blocks(text: str, max_blocks: Optional[int] = None) -> str:
    """The page's fenced code blocks, as 1.x lists them after the text."""
    limit = constant("codeBlocksPerRead") if max_blocks is None else max_blocks
    parts = []
    for lang, body in re.findall(r"```(\w*)\n(.*?)```", text or "", re.DOTALL)[:limit]:
        body = (body or "").strip()
        if body:
            parts.append(f"- {lang or 'text'}:\n    " + body.replace("\n", "\n    "))
    return "\n".join(parts)


def _one_line(value: Any) -> str:
    # A title or URL from the map is one header line: it cannot forge a second one.
    return " ".join(str(value).split())


def render(slug: str, url: str, section_title: str, source: str, text: str, note: str = "") -> str:
    """The result in Q1.2's shape, inside the untrusted envelope whatever the source."""
    lines = [f"resource: {_one_line(slug)}", f"url: {_one_line(url)}",
             f"section_title: {_one_line(section_title)}", f"source: {_one_line(source)}"]
    if note:
        lines.append(f"note: {_one_line(note)}")
    lines += ["---", text or ""]
    blocks = code_blocks(text)
    if blocks:
        lines += ["", "Code blocks:", blocks]
    return wrap_untrusted(lines)


class _Read:
    """One lookup's context: the catalog resource, its row, its settings."""

    def __init__(self, catalog: Any, resource: Any, row: dict, store: Any):
        self.catalog, self.resource, self.row, self.store = catalog, resource, row, store
        self.owner = catalog.owner_id
        self.settings = EffectiveSettings(resource.read_settings or {})
        self.token = resource.github_token
        self.sitemap = row.get("sitemap") or {}
        self.mode = row.get("storage_mode") or resource.storage_mode
        self.slug = resource.slug

    @property
    def has_login(self) -> bool:
        return bool(self.resource.has_login or self.row.get("has_login"))

    def login(self):
        """The resource's login, bound for this read (T6.4): sent to its own host only, and no
        browser. The catalog carries it only in its owner's own runs."""
        return fetch.use_login(self.row.get("url") or self.resource.url, self.resource.credentials)

    @property
    def converted(self) -> bool:
        """A 2.0 resource: it has cards, entries and page IDs."""
        return int(self.row.get("map_version") or 1) >= 2

    def record_seen(self, entry: Optional[dict]) -> None:
        """A page returned is seen in the run (R-366), when it is an entry: page IDs name entries."""
        if not entry or entry.get("page_id") is None:
            return
        try:
            run_state.record_seen([page_ids.format(self.slug, int(entry["page_id"]))])
        except LookupError:
            pass  # a read outside an executor node (a test, the librarian's own check) counts nowhere


async def lookup(*, resource_id: str = "", query: str = "", cve_id: Optional[str] = None,
                 section_path: Optional[str] = None, force_refresh: bool = False, page: Optional[str] = None,
                 section: Optional[str] = None, part: Optional[int] = None) -> str:
    catalog = runtime.bound_catalog()
    if catalog is None:
        return NOT_AVAILABLE
    if page:
        return await _by_page_id(catalog, page, section=section, part=part, query=query, force_refresh=force_refresh)
    resource = next((r for r in catalog.resources if r.slug == (resource_id or "")), None)
    if resource is None:
        available = ", ".join(sorted(r.slug for r in catalog.resources)) or "(none)"
        return NOT_CONFIGURED.format(slug=resource_id, available=available)
    store = runtime.run_store()
    row = await store.legacy_sitemap(catalog.owner_id, resource.id)
    if row is None:
        return DELETED.format(slug=resource.slug)
    read = _Read(catalog, resource, row, store)
    logger.info(f"[tradecraft] lookup resource={read.slug} section={'forced' if section_path else 'auto'}")
    with read.login():
        if resource.type == "cve-poc-db" or row.get("resource_type") == "cve-poc-db":
            return await _cve(read, cve_id)
        index = runtime.run_index()
        if index is not None and not section_path and read.converted:
            picked = await _first_pass_pick(read, query, index) or await _title_pick(read, query)
            if picked is None:
                return NO_PAGE.format(slug=read.slug, query=query)
            return await _read_section(read, *picked, section=section, part=part, query=query,
                                       force_refresh=force_refresh)
        if isinstance(read.sitemap.get("pages"), list) and read.sitemap.get("pages"):
            return await _pdf(read, query, section_path, force_refresh)
        return await _page(read, query, section_path, force_refresh)


# --------------------------------------------------------------------------------------
# A page of a site
# --------------------------------------------------------------------------------------

async def _pick_url(read: _Read, query: str, section_path: Optional[str], *,
                    use_picker: bool = True) -> tuple[str, str]:
    rtype = read.row.get("resource_type") or read.resource.type
    base = read.row.get("url") or read.resource.url
    if section_path:
        return legacy_match.resolve_path(rtype, base, read.sitemap, section_path), section_path
    entries = legacy_match.sitemap_entries(read.sitemap)
    picker = runtime.section_picker() if use_picker and len(entries) > legacy_match.SMALL_MAP else None
    picked = await legacy_match.pick(query, entries, picker=picker, resource_name=read.resource.name or read.slug)
    if picked is None:
        return base, "(homepage)"
    path = picked.get("path") or ""
    return legacy_match.resolve_path(rtype, base, read.sitemap, path), picked.get("title") or path


async def _refusal(read: _Read, url: str) -> str:
    """Why ``url`` must not be requested at all, or ""."""
    problem = net.url_problem(url)
    if problem:
        return BAD_URL.format(url=url, code=problem)
    # The entry's own URL: a PDF page keeps its "#page=N", which names a page of its own.
    canonical = fetch.page_url(url)
    curation = await read.store.curation(read.owner, read.resource.id, canonical)
    if curation and curation.get("blocked"):
        return BLOCKED.format(url=url, slug=read.slug)
    if read.has_login and not await read.store.in_map(read.owner, read.resource.id, canonical):
        return OUTSIDE_MAP.format(url=url, slug=read.slug)
    return ""


async def _stored_copy(read: _Read, url: str) -> Optional[dict]:
    if read.mode != "stored":
        return None
    entry = await read.store.entry_by_url(read.owner, read.resource.id, url)
    return entry if entry and entry.get("stored_text") else None


async def live_page(url: str, settings: EffectiveSettings, *, github_token: Optional[str],
                    has_login: bool) -> fetch.FetchedPage:
    """A page as the tool reads it from the site: the resource's fetching and content settings
    (the same cleaning as storing it), plain HTTP only with a login (§5). Read now (T6.6) reads
    through here, so the Map view shows what the agent would get."""
    return await fetch.smart_fetch(url, settings, github_token=github_token, allow_browser=not has_login)


async def _text_of(read: _Read, target: str, copy: Optional[dict], force_refresh: bool) -> tuple:
    """(text, source label, note, error): the stored copy, else the site, else the copy with a
    note, else the error that says whether a copy exists."""
    if copy is not None and not force_refresh:
        return copy["stored_text"], format_source("stored", _date(copy.get("fetched_at"))), "", ""
    # Bound here too, not only by lookup: the librarian's reads come straight to this function.
    with read.login():
        page = await live_page(target, read.settings, github_token=read.token, has_login=read.has_login)
    if page.error in _REFUSED:
        return None, "", "", BAD_URL.format(url=target, code=page.error)
    ok = not page.error and 200 <= page.status < 300 and bool(page.text)
    if not ok:
        code = page.error or (f"http_{page.status}" if page.status else "unreachable")
        if copy is not None:
            return (copy["stored_text"], format_source("stored", _date(copy.get("fetched_at"))),
                    NOT_REFRESHED.format(code=code), "")
        template = UNREACHABLE_NOT_STORED if read.mode == "stored" else UNREACHABLE_LIVE
        return None, "", "", template.format(url=target, code=code, slug=read.slug)
    if copy is not None:
        return page.text, format_source("live"), SKIPPED_COPY.format(date=_date(copy.get("fetched_at"))), ""
    return page.text, format_source("live_not_stored" if read.mode == "stored" else "live"), "", ""


async def _page(read: _Read, query: str, section_path: Optional[str], force_refresh: bool) -> str:
    target, title = await _pick_url(read, query, section_path)
    refused = await _refusal(read, target)
    if refused:
        return refused
    copy = await _stored_copy(read, fetch.canonical_url(target))
    text, source, note, error = await _text_of(read, target, copy, force_refresh)
    if error:
        return error
    if read.converted:
        read.record_seen(copy or await read.store.entry_by_url(read.owner, read.resource.id,
                                                               fetch.canonical_url(target)))
    return render(read.slug, target, title, source, text, note=note)


# --------------------------------------------------------------------------------------
# By page ID and section (Q8)
# --------------------------------------------------------------------------------------

async def _first_pass_pick(read: _Read, query: str, index: Any) -> Optional[tuple[str, str]]:
    """(page ID, URL) of the resource's page the free first pass ranks first, or None."""
    if not (query or "").strip():
        return None
    settings = EffectiveSettings(read.catalog.search or {}, scope="search")
    try:
        first = await search.free_first_pass(read.owner, read.catalog, query, resource=read.slug,
                                             settings=settings, index=index)
    except search.SearchError:
        return None
    _verdict, ranked = search.verdict_of(first.candidates, settings.str("search.strictness"))
    if not ranked:
        return None
    best = ranked[0].row
    return page_ids.format(read.slug, int(best["page_id"])), best["url"]


def _pdf_entries(read: _Read) -> list[dict]:
    """A PDF's pages as title-match entries: its first line, ``page=N``."""
    return [{"title": str(p.get("firstLine", "")), "path": f"page={p.get('page')}"}
            for p in read.sitemap.get("pages") or [] if isinstance(p, dict)]


async def _title_pick(read: _Read, query: str) -> Optional[tuple[str, str]]:
    """(page ID, URL) of the page today's title match picks with no model: a PDF's best page,
    else a site's best page or its start page; None when that page is not an entry."""
    if isinstance(read.sitemap.get("pages"), list) and read.sitemap.get("pages"):
        picked = await legacy_match.pick(query, _pdf_entries(read))
        number = re.search(r"page=(\d+)", picked["path"]) if picked else None
        if number is None:
            return None
        url = f"{fetch.canonical_url(read.row.get('url') or read.resource.url)}#page={number.group(1)}"
    else:
        target, _title = await _pick_url(read, query, None, use_picker=False)
        url = fetch.canonical_url(target)
    entry = await read.store.entry_by_url(read.owner, read.resource.id, url)
    if entry is None or entry.get("page_id") is None:
        return None
    return page_ids.format(read.slug, int(entry["page_id"])), url


async def _by_page_id(catalog: Any, text: str, *, section: Optional[str], part: Optional[int], query: str,
                      force_refresh: bool) -> str:
    store = runtime.run_store()
    resolved = await page_ids.resolve(store, catalog.owner_id, catalog, text)
    if isinstance(resolved, page_ids.Refused):
        return f"Error: {resolved.message}"
    row = await store.legacy_sitemap(catalog.owner_id, resolved.resource.id)
    if row is None:
        return DELETED.format(slug=resolved.resource.slug)
    read = _Read(catalog, resolved.resource, row, store)
    if resolved.resource.type == "cve-poc-db" or row.get("resource_type") == "cve-poc-db":
        return CVE_BY_ID.format(slug=read.slug)
    logger.info(f"[tradecraft] lookup resource={read.slug} section=page")
    with read.login():
        return await _read_section(read, resolved.page_id, resolved.url, section=section, part=part, query=query,
                                   force_refresh=force_refresh)


async def _pdf_page_live(read: _Read, url: str, entry: dict, force_refresh: bool) -> tuple:
    """A PDF page's text: the stored copy, else the document read again (as ``_pdf`` does)."""
    base = url.split("#", 1)[0]
    number = int(re.search(r"#page=(\d+)$", url).group(1))
    if entry.get("stored_text") and not force_refresh:
        return entry["stored_text"], format_source("stored", _date(entry.get("fetched_at"))), "", ""
    with read.login():
        resp = await fetch.fetch_raw(base, read.settings, github_token=read.token)
    text = ""
    if resp.ok and resp.body[:5] == b"%PDF-":
        try:
            text = await asyncio.get_running_loop().run_in_executor(None, _pdf_page_text, resp.body, number)
        except Exception:
            text = ""
    if text:
        note = SKIPPED_COPY.format(date=_date(entry.get("fetched_at"))) if entry.get("stored_text") else ""
        return text, format_source("live" if note else "live_not_stored"), note, ""
    code = resp.error or (f"http_{resp.status}" if resp.status else "unreachable")
    if entry.get("stored_text"):
        return (entry["stored_text"], format_source("stored", _date(entry.get("fetched_at"))),
                NOT_REFRESHED.format(code=code), "")
    return None, "", "", UNREACHABLE_NOT_STORED.format(url=url, code=code, slug=read.slug)


def render_section(page_id: str, crumbs: list[str], chosen: split.Section, sections: list[split.Section], part: int,
                   parts: int, source: str, text: str, note: str = "") -> str:
    """A read in Q8's shape, inside the untrusted envelope."""
    others = [split.section_name(s) for s in sections if s is not chosen]
    if len(others) > OTHER_SECTIONS_LISTED:
        others = others[:OTHER_SECTIONS_LISTED] + [f"… {len(others) - OTHER_SECTIONS_LISTED} more"]
    lines = [READ_PAGE.format(page_id=page_id, breadcrumb=_one_line(" › ".join(c for c in crumbs if c))),
             format_read_section(split.section_name(chosen), part, parts, others),
             READ_SOURCE.format(source=_one_line(source))]
    if note:
        lines.append(f"note: {_one_line(note)}")
    if part < parts:
        heading = split.hint_value(split.section_name(chosen))
        lines.append(f'next: tradecraft_lookup(page="{page_id}", section="{heading}", part={part + 1})')
    lines += ["---", text or ""]
    return wrap_untrusted(lines)


async def _read_section(read: _Read, page_id: str, url: str, *, section: Optional[str], part: Optional[int],
                        query: str, force_refresh: bool) -> str:
    refused = await _refusal(read, url)
    if refused:
        return refused
    # Page IDs and the first pass name an entry's own URL (canonical; a PDF page keeps "#page=N").
    entry = await read.store.entry_by_url(read.owner, read.resource.id, url)
    if entry is None:
        return PAGE_GONE.format(page_id=page_id, slug=read.slug)
    if "#page=" in url:
        text, source, note, error = await _pdf_page_live(read, url, entry, force_refresh)
    else:
        copy = entry if (read.mode == "stored" and entry.get("stored_text")) else None
        text, source, note, error = await _text_of(read, url, copy, force_refresh)
    if error:
        return error
    sections = split.split_markdown(text) or [split.Section(0, "", 0, "", "")]
    chosen = split.pick_section(sections, section, query)
    if chosen is None:
        names = ", ".join(split.section_name(s) for s in sections[:OTHER_SECTIONS_LISTED])
        return NO_SECTION.format(page_id=page_id, section=section, sections=names)
    chars = EffectiveSettings(read.catalog.search or {}, scope="search").int("reading.charsPerRead")
    pieces = split.parts(chosen.text, chars)
    number = 1 if part in (None, "") else int(part)
    if number < 1 or number > len(pieces):
        return NO_PART.format(section=split.section_name(chosen), page_id=page_id, parts=len(pieces))
    try:
        run_state.record_seen([page_id])
    except LookupError:
        pass  # a read outside an executor node (a test, the librarian's own check) counts nowhere
    crumbs = [read.resource.name or read.slug, *(entry.get("breadcrumb") or []), entry.get("title") or ""]
    return render_section(page_id, crumbs, chosen, sections, number, len(pieces), source, pieces[number - 1], note)


# --------------------------------------------------------------------------------------
# A CVE archive, and a PDF
# --------------------------------------------------------------------------------------

async def _cve(read: _Read, cve_id: Optional[str]) -> str:
    if not cve_id or not cve.CVE_ID_RE.match(cve_id):
        return (f"Error: resource '{read.slug}' is a cve-poc-db; "
                f"you must pass cve_id='CVE-YYYY-NNNNN'.")
    cve_norm = cve_id.upper()
    content, src, api_error = await cve.lookup(cve_norm, read.sitemap, read.settings, github_token=read.token)
    title = cve_norm
    if not content and api_error:
        return (f"Error: could not look up {cve_norm} in resource '{read.slug}' ({api_error}). This is NOT a "
                f"'PoC not found' answer; retry later or add a GitHub token in Global Settings -> API Keys.")
    if not content:
        text, url = await cve.readme(read.sitemap, read.settings, github_token=read.token)
        if text and cve_norm in text.upper():
            content, src = text, url
            title = f"{cve_norm} (repository README; no {cve_norm.split('-')[1]}/{cve_norm} entry)"
    if not content:
        return (f"PoC not found for {cve_norm} in resource '{read.slug}' "
                f"(no archive entry, and the repository README does not mention it).")
    return render(read.slug, src, title, format_source("live"), content)


def _pdf_page_text(body: bytes, page: int) -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(body))
    if page < 1 or page > len(reader.pages):
        return ""
    return reader.pages[page - 1].extract_text() or ""


async def _pdf(read: _Read, query: str, section_path: Optional[str], force_refresh: bool) -> str:
    pages = [p for p in read.sitemap.get("pages") or [] if isinstance(p, dict)]
    base = read.row.get("url") or read.resource.url
    if section_path:
        m = re.search(r"page\s*=\s*(\d+)", section_path) or re.fullmatch(r"\s*(\d+)\s*", section_path)
        if not m:
            return "Error: section_path for PDF must be 'page=N' or just an integer."
        number = int(m.group(1))
    else:
        entries = _pdf_entries(read)
        picker = runtime.section_picker() if len(entries) > legacy_match.SMALL_MAP else None
        picked = await legacy_match.pick(query, entries, picker=picker, resource_name=read.resource.name or read.slug)
        if picked is None:
            return f"PDF '{read.slug}': no page matched query={query!r}."
        number = int(re.search(r"page=(\d+)", picked["path"]).group(1))
    # The map holds the pages the person chose (a range, a skip list): those numbers, not
    # 1..len, are the readable ones, and an excluded page is never fetched live instead.
    numbers = sorted({p["page"] for p in pages if isinstance(p.get("page"), int)})
    if number not in numbers:
        span = f"{numbers[0]}..{numbers[-1]}" if numbers else "none"
        return f"PDF '{read.slug}': page {number} is not in this resource's map (pages {span})."
    url = f"{fetch.canonical_url(base)}#page={number}"
    refused = await _refusal(read, url)
    if refused:
        return refused
    entry = await read.store.entry_by_url(read.owner, read.resource.id, url)
    if entry and entry.get("stored_text") and not force_refresh:
        read.record_seen(entry)
        return render(read.slug, url, f"page {number}", format_source("stored", _date(entry.get("fetched_at"))),
                      entry["stored_text"])
    resp = await fetch.fetch_raw(base, read.settings, github_token=read.token)
    text = ""
    if resp.ok and resp.body[:5] == b"%PDF-":
        try:
            text = await asyncio.get_running_loop().run_in_executor(None, _pdf_page_text, resp.body, number)
        except Exception:
            text = ""
    if not text:
        code = resp.error or (f"http_{resp.status}" if resp.status else "unreachable")
        if entry and entry.get("stored_text"):
            read.record_seen(entry)
            return render(read.slug, url, f"page {number}", format_source("stored", _date(entry.get("fetched_at"))),
                          entry["stored_text"], note=NOT_REFRESHED.format(code=code))
        return UNREACHABLE_NOT_STORED.format(url=url, code=code, slug=read.slug)
    read.record_seen(entry)
    if entry and entry.get("stored_text"):
        return render(read.slug, url, f"page {number}", format_source("live"), text,
                      note=SKIPPED_COPY.format(date=_date(entry.get("fetched_at"))))
    source = "live_not_stored" if read.row.get("map_version", 1) >= 2 else "live"
    return render(read.slug, url, f"page {number}", format_source(source), text)

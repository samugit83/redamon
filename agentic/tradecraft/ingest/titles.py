"""Stage ``titles`` (T6.1): real page titles for the known types (§4.3 "Use real page titles").

With ``knownTypes.realTitles`` on (the account's or the resource's), the kept entries of a wiki,
a docs site, a GitBook or a GitHub repository get their page's own title instead of the one
guessed from a sitemap slug, a menu or a file name: an HTML page's first ``<h1>``, else its
``<title>``; a repository file's first Markdown heading. Cleaned to one line; a suffix the site
adds to most of its ``<title>``s (" - Site name") is removed, and a title most pages share is no
page's title (the guess stays). ``title_source`` becomes ``real``.

At most ``knownTypes.maxTitleFetches`` pages are downloaded, with the resource's fetch settings
and plain HTTP only (a title never needs the browser). No page is downloaded twice:

- a Stored resource's pages take their title from the download that stores them (``storage``
  calls ``collect`` and then ``finish``), with no request here;
- a Live wiki, GitBook or docs site's first ``cards.CARD_PASS_MAX_PAGES`` kept pages are read by
  the card pass, which sets their real title itself.

A page the person renamed (curation, T6.6) keeps the person's title.
"""

from __future__ import annotations

import asyncio
import collections
import html as html_lib
import re
from typing import TYPE_CHECKING, Any, Optional

from logging_config import get_logger
from orchestrator_helpers.web_sources import BeautifulSoup, rewrite_github_url
from tradecraft.ingest import cards, fetch, sections

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

# The spec's appliesTo of knownTypes.realTitles (wiki, docs, gitbook, github), as site types.
TYPES = ("mkdocs-wiki", "sphinx-docs", "gitbook", "github-repo")
# A title sits in the page's head or near the top of its body.
TITLE_MAX_BYTES = 512 * 1024
CONCURRENCY = 4
CHUNK = 20
MAX_CHARS = cards.MAX_TITLE_CHARS
# The separators a site puts between a page's title and its own name.
_SEPARATORS = (" | ", " - ", " — ", " – ", " · ", " :: ", " » ", " : ")
# A suffix (or a whole title) found on at least this share of the titles, and on at least
# SHARED_MIN of them, is the site's, not the page's.
SHARED_SHARE = 0.6
SHARED_MIN = 2
_ATX = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_UNDERLINE = re.compile(r"^\s{0,3}([=\-~^*+#])\1{2,}\s*$")


def applies(state: "IngestState") -> bool:
    return state.site_type in TYPES and state.settings.bool("knownTypes.realTitles")


def one_line(text: Any) -> str:
    return " ".join(html_lib.unescape(str(text or "")).split())[:MAX_CHARS]


def html_title(html: str) -> tuple[str, bool]:
    """(the page's title, whether it is its ``<title>``): the first ``<h1>``, else ``<title>``."""
    if not html or BeautifulSoup is None:
        return "", False
    soup = BeautifulSoup(html, "html.parser")
    for el in soup.select("script, style, nav, footer, aside"):
        el.decompose()
    h1 = soup.find("h1")
    text = sections.clean_heading(h1.get_text(" ", strip=True)) if h1 is not None else ""
    if text:
        return one_line(text), False
    if soup.title is not None:
        return one_line(soup.title.get_text(" ", strip=True)), True
    return "", False


def markdown_title(text: str) -> str:
    """A text file's title: its first level-1 heading (``# X`` or a line underlined with
    ``===``), else its first heading of any level; "" when it has none. Code blocks are skipped."""
    first_any = ""
    fence = False
    previous = ""
    for line in (text or "").splitlines()[:400]:
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            fence = not fence
            previous = ""
            continue
        if fence:
            continue
        m = _ATX.match(line)
        if m:
            title = one_line(sections.clean_heading(m.group(2)))
            if title and len(m.group(1)) == 1:
                return title
            first_any = first_any or title
        elif previous and _UNDERLINE.match(line) and not _UNDERLINE.match(previous):
            title = one_line(sections.clean_heading(previous))
            if title and line.strip()[0] == "=":
                return title
            first_any = first_any or title
        previous = stripped
    return first_any


def title_of(html: str, text: str, content_type: str) -> tuple[str, bool]:
    """(title, from a ``<title>`` tag) of one download: HTML, or a text file."""
    if "html" in (content_type or "") or (html and "<html" in html[:2000].lower()):
        return html_title(html)
    return markdown_title(text or html), False


def _split_suffix(title: str) -> tuple[str, str]:
    for sep in _SEPARATORS:
        head, found, tail = title.rpartition(sep)
        if found and head.strip() and tail.strip():
            return head.strip(), tail.strip().lower()
    return title, ""


def cleaned(found: dict[str, tuple[str, bool]]) -> dict[str, str]:
    """{url: title} for the titles worth taking. A ``<title>`` suffix most pages share is removed;
    a title most pages share (an app shell's) is dropped, and the guess stays."""
    if not found:
        return {}
    total = len(found)
    shared_at = max(SHARED_MIN, int(SHARED_SHARE * total + 0.999))
    whole = collections.Counter(t.lower() for t, _tag in found.values() if t)
    suffixes = collections.Counter(_split_suffix(t)[1] for t, tag in found.values() if tag)
    site = {s for s, n in suffixes.items() if s and n >= shared_at}
    out: dict[str, str] = {}
    for url, (title, tag) in found.items():
        if not title or (total >= SHARED_MIN and whole[title.lower()] >= shared_at):
            continue
        if tag:
            head, suffix = _split_suffix(title)
            if suffix in site:
                title = head
        out[url] = title
    return out


def _renamed(entry: Any) -> bool:
    return entry.extra.get("title_source") == "renamed"


def _set(entry: Any, title: str) -> None:
    entry.title = title
    entry.extra["title_source"] = "real"


# --------------------------------------------------------------------------------------
# A Stored resource: the download that stores the page gives its title
# --------------------------------------------------------------------------------------

def _stored(state: "IngestState") -> bool:
    # storage.stores_text for these types (storage imports this module).
    return state.storage_mode == "stored"


def wants_stored(state: "IngestState", entry: Any) -> bool:
    return applies(state) and _stored(state) and not _renamed(entry)


def collect(state: "IngestState", entry: Any, *, html: str = "", text: str = "", content_type: str = "") -> None:
    """Keeps the title of a page ``storage`` just downloaded or took from an archive (no request)."""
    if not wants_stored(state, entry):
        return
    title, tag = title_of(html, text, content_type)
    if title:
        entry.extra["_real_title"] = (title, tag)


def finish(state: "IngestState") -> None:
    """Sets the titles ``collect`` kept, cleaned together (a site's suffix shows across pages)."""
    found = {e.url: e.extra.pop("_real_title") for e in state.entries if "_real_title" in e.extra}
    titles = cleaned(found)
    for entry in state.entries:
        if entry.url in titles:
            _set(entry, titles[entry.url])


# --------------------------------------------------------------------------------------
# The stage: a Live resource's pages, one download each
# --------------------------------------------------------------------------------------

def _to_fetch(state: "IngestState") -> list[Any]:
    kept = [e for e in state.entries if e.extra.get("status", "kept") == "kept"]
    if cards.card_pass_applies(state):
        # The card pass reads these pages for their headings and takes their real title then.
        kept = kept[cards.CARD_PASS_MAX_PAGES:]
    todo = [e for e in kept if not _renamed(e) and fetch.entry_url_ok(e.url) and e.source != "pdf"]
    return todo[:state.settings.int("knownTypes.maxTitleFetches")]


async def _title(state: "IngestState", url: str) -> Optional[tuple[str, bool]]:
    resp = await fetch.fetch_raw(rewrite_github_url(url), state.settings, github_token=state.github_token,
                                 max_bytes=TITLE_MAX_BYTES)
    state.visited += 1
    if not resp.ok:
        return None
    body = resp.text
    title = await state.blocking(title_of, body, body, resp.content_type)
    return title if title[0] else None


async def apply(state: "IngestState") -> "IngestState":
    """The kept entries with their real titles (Live resources); a Stored one's come with its
    downloads (``collect``/``finish``)."""
    if not applies(state) or _stored(state):
        return state
    todo = _to_fetch(state)
    if not todo:
        return state
    gate = asyncio.Semaphore(CONCURRENCY)
    found: dict[str, tuple[str, bool]] = {}
    unreadable = 0

    async def one(entry: Any) -> None:
        nonlocal unreadable
        async with gate:
            got = await _title(state, entry.url)
        if got is None:
            unreadable += 1
            state.count_error("title_unreadable")
        else:
            found[entry.url] = got

    for i in range(0, len(todo), CHUNK):
        await state.check_cancelled()
        await asyncio.gather(*(one(e) for e in todo[i:i + CHUNK]))
        await state.progress("titles", min(i + CHUNK, len(todo)), len(todo), "pages")
    titles = cleaned(found)
    for entry in todo:
        if entry.url in titles:
            _set(entry, titles[entry.url])
    if unreadable:
        logger.info(f"[tradecraft] job {state.request.job_id} titles code=title_unreadable count={unreadable}")
    return state

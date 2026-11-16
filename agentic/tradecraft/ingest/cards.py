"""Stage ``cards`` (T2.3): one page card per map entry (Q4 item 2, R-331).

A card is the entry row the store writes: the title and its source, the breadcrumb (the page's
place in the tree: its GitHub folders, else its URL path under the resource's own), the
headings of levels 1-3, a one-line description and its source, and the entry's source. Tags
(T2.2, T5.1) and entities (T2.2) are added by later stages. The page ID is the store's (keyed
by URL, so it survives refreshes); size and download date come with a stored copy.

Where the facts come from, without a second download:

- a stored copy (a Stored resource, a PDF): its headings, and its first paragraph as the
  description (``first_paragraph``);
- the crawl's own download of a page (a website): its headings and its meta description;
- the card pass, for Live wikis, GitBooks and docs sites, which list pages from their index
  without opening them: each page is downloaded once and only its title, headings and meta
  description are kept, never its text, not even a first paragraph (R-010, R-339, OQ-12). At
  most ``constants.cardPassMaxPages`` pages per resource; the rest keep a title-only card.
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from logging_config import get_logger
from orchestrator_helpers.web_sources import BeautifulSoup
from tradecraft.ingest import fetch, sections
from tradecraft.settings import constant

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

CARD_PASS_TYPES = ("mkdocs-wiki", "gitbook", "sphinx-docs")
CARD_PASS_MAX_PAGES = int(constant("cardPassMaxPages"))
# The card pass reads a page's head and headings: a larger body is cut, never needed.
CARD_PASS_MAX_BYTES = 2 * 1024 * 1024
CARD_PASS_CONCURRENCY = 4
CARD_PASS_CHUNK = 20
MAX_HEADINGS = 50
MAX_DESCRIPTION_CHARS = 300
MAX_TITLE_CHARS = 300
MAX_BREADCRUMB = 8
_EXTENSION = re.compile(r"\.(html?|md|markdown|rst|txt|php|aspx?)$", re.IGNORECASE)


@dataclass
class PageFacts:
    title: str = ""
    headings: list[dict] = field(default_factory=list)
    description: str = ""


def _one_line(text: Any, limit: int) -> str:
    return " ".join(str(text or "").split())[:limit]


def page_facts(html: str) -> PageFacts:
    """A page's own title (its first ``h1``, else ``<title>``), headings of levels 1-3 and meta
    description, from its HTML. Nothing of its body text."""
    if not html or BeautifulSoup is None:
        return PageFacts()
    soup = BeautifulSoup(html, "html.parser")
    for el in soup.select("script, style, nav, footer, aside"):
        el.decompose()
    headings = []
    for h in soup.find_all(["h1", "h2", "h3"]):
        text = sections.clean_heading(h.get_text(" ", strip=True))
        if text:
            headings.append({"level": int(h.name[1]), "text": text})
        if len(headings) >= MAX_HEADINGS:
            break
    meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.IGNORECASE)})
    title = headings[0]["text"] if headings and headings[0]["level"] == 1 else ""
    if not title and soup.title is not None:
        title = soup.title.get_text(" ", strip=True)
    return PageFacts(title=_one_line(title, MAX_TITLE_CHARS), headings=headings,
                     description=_one_line(meta.get("content") if meta else "", MAX_DESCRIPTION_CHARS))


_MD_NOISE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)|[*_`>#|]+")


def first_paragraph(markdown: str) -> str:
    """The first paragraph of prose of a stored page: no heading, list, table or code."""
    for block in sections.split_markdown(markdown):
        fence = False
        para: list[str] = []
        for line in block.text.splitlines() + [""]:
            stripped = line.strip()
            if stripped.startswith(("```", "~~~")):
                fence = not fence
                continue
            if fence:
                continue
            if not stripped:
                if para:
                    text = _one_line(_MD_NOISE.sub(lambda m: m.group(1) or " ", " ".join(para)), MAX_DESCRIPTION_CHARS)
                    if len(text) >= 20:
                        return text
                para = []
                continue
            if stripped[0] in "-*+|" or re.match(r"^\d+[.)]\s", stripped):
                para = []
                continue
            para.append(stripped)
    return ""


def _segment(text: str) -> str:
    text = urllib.parse.unquote(text)
    return " ".join(re.sub(r"[-_/]+", " ", _EXTENSION.sub("", text)).split())


def breadcrumb_for(url: str, path: str, source: str, site_type: str, base_url: str) -> list[str]:
    """The page's folders: a GitHub file's repository folders; a PDF page none; anything else
    its URL path's folders under the resource's own path."""
    if site_type == "pdf" or source == "pdf":
        return []
    if source == "tree" and path and not path.startswith(("http://", "https://")):
        return [p for p in path.split("/")[:-1] if p][:MAX_BREADCRUMB]
    page_path = urllib.parse.urlsplit(url).path
    base_path = urllib.parse.urlsplit(base_url).path.rstrip("/")
    if base_path and (page_path == base_path or page_path.startswith(base_path + "/")):
        page_path = page_path[len(base_path):]
    parts = [p for p in page_path.split("/") if p]
    folders = [_segment(p) for p in parts[:-1]]
    return [f for f in folders if f][:MAX_BREADCRUMB]


def _base_card(entry: Any) -> dict:
    return {
        "url": entry.url,
        "title": entry.title,
        "title_source": "real" if entry.source == "crawl" else "guessed",
        "source": entry.source,
        "status": entry.extra.get("status", "kept"),
        "drop_reason": entry.extra.get("drop_reason", ""),
    }


def _apply_facts(card: dict, facts: PageFacts, *, title: bool) -> None:
    if title and facts.title and card.get("title_source") != "renamed":
        card["title"], card["title_source"] = facts.title, "real"
    if facts.headings:
        card["headings"] = facts.headings
    if facts.description:
        card["description"], card["description_source"] = facts.description, "meta"


async def build(state: "IngestState") -> "IngestState":
    """``state.cards``: one card per entry, in map order."""
    cards = []
    for entry in state.entries:
        card = _base_card(entry)
        card["breadcrumb"] = breadcrumb_for(entry.url, entry.path, entry.source, state.site_type, state.url)
        html = entry.extra.get("html")
        if html:
            _apply_facts(card, await state.blocking(page_facts, html), title=False)
        stored = state.texts.get(entry.url)
        if stored is not None:
            card["headings"] = await state.blocking(sections.headings_of, stored.text, MAX_HEADINGS)
            if not card.get("description"):
                para = await state.blocking(first_paragraph, stored.text)
                if para:
                    card["description"], card["description_source"] = para, "first_paragraph"
        cards.append(card)
    state.cards = cards
    await card_pass(state)
    return state


def card_pass_applies(state: "IngestState") -> bool:
    return state.storage_mode == "live" and state.site_type in CARD_PASS_TYPES


async def card_pass(state: "IngestState") -> None:
    if not card_pass_applies(state):
        return
    todo = [c for c in state.cards if c.get("status", "kept") == "kept"][:CARD_PASS_MAX_PAGES]
    gate = asyncio.Semaphore(CARD_PASS_CONCURRENCY)
    unreadable = 0

    async def one(card: dict) -> None:
        nonlocal unreadable
        async with gate:
            resp = await fetch.fetch_raw(card["url"], state.settings, github_token=state.github_token,
                                         max_bytes=CARD_PASS_MAX_BYTES)
        state.visited += 1
        if not resp.ok or "html" not in (resp.content_type or ""):
            unreadable += 1
            state.count_error("card_pass_unreadable")
            return
        _apply_facts(card, await state.blocking(page_facts, resp.text), title=True)

    for i in range(0, len(todo), CARD_PASS_CHUNK):
        await state.check_cancelled()
        await asyncio.gather(*(one(c) for c in todo[i:i + CARD_PASS_CHUNK]))
        await state.progress("cards", min(i + CARD_PASS_CHUNK, len(todo)), len(todo), "pages")
    if unreadable:
        logger.info(f"[tradecraft] job {state.request.job_id} card_pass code=card_pass_unreadable count={unreadable}")

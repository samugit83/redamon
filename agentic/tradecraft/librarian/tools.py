"""The librarian's own tools (Q9.4): search, browse, outline, read and grep, over the run's library
only.

Every read is keyed by the catalog's owner and limited to the catalog's resources (narrowed to
the agent's ``scope`` when it named some): no web search, no shell, no graph, nothing that
touches the target. A page is read the way ``tradecraft_lookup`` reads it (``library.reader``):
its ID resolved against the catalog, a blocked page or a page outside a login resource's map
refused, a Stored copy from the store, a Live page from its own site through the address guard.
A page read once is kept in memory for this one question and dropped with it (nothing is
saved). Nothing here records a page as seen: only the pages the answer returns are (T7.4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from tradecraft import runtime
from tradecraft.library import page_ids, reader, search, split
from tradecraft.library.types import BrowseLevel, Card
from tradecraft.settings import EffectiveSettings, constant

SECTION_CHARS = int(constant("librarianSectionChars"))
CANDIDATES = int(constant("mergedCandidates"))
GREP_LINES = 20
GREP_LINE_CHARS = 300


@dataclass
class Page:
    page_id: str
    # The resource's name, the page's folders and its title: the answer's breadcrumb.
    crumbs: tuple[str, ...]
    sections: list
    stored: bool
    text: str


@dataclass(frozen=True)
class Found:
    """One search: the verdict of the free first pass, and its cards, related ones first."""

    verdict: str
    cards: tuple[Card, ...]


def narrowed(catalog: Any, scope: Sequence[str]) -> tuple[Any, bool]:
    """(the catalog limited to the slugs of ``scope``, whether the scope matched any): an empty or
    unmatched scope leaves the whole catalog, which the agent may read anyway."""
    wanted = {s for s in scope or () if isinstance(s, str)}
    chosen = [r for r in catalog.resources if r.slug in wanted]
    if not chosen:
        return catalog, False
    return catalog.model_copy(update={"resources": chosen}), True


class LibraryTools:
    def __init__(self, owner_id: str, catalog: Any, *, session: Optional[search.Session] = None,
                 settings: Optional[EffectiveSettings] = None, index: Any = None, store: Any = None) -> None:
        self.owner_id = owner_id
        self.catalog = catalog
        self.session = session
        self.settings = settings or EffectiveSettings(catalog.search or {}, scope="search")
        self.index = index if index is not None else runtime.run_index()
        self.store = store if store is not None else runtime.run_store()
        self._pages: dict[str, Optional[Page]] = {}
        self.by_id = {r.id: r for r in catalog.resources}

    # --- search and browse -------------------------------------------------------------

    async def search(self, query: str) -> Found:
        """The free first pass of ``query`` (Q7.2) over the catalog: its verdict, and up to
        ``constants.mergedCandidates`` cards, the related ones in their order, then the rest."""
        if self.index is None:
            return Found("NOT FOUND", ())
        first = await search.free_first_pass(self.owner_id, self.catalog, query, session=self.session,
                                             settings=self.settings, index=self.index)
        verdict, related = search.verdict_of(first.candidates, self.settings.str("search.strictness"))
        seen = {c.row["id"] for c in related}
        ranked = list(related) + [c for c in first.candidates if c.row["id"] not in seen]
        cards = tuple(search.card_of(c.row, self.by_id[c.row["resource_id"]]) for c in ranked[:CANDIDATES]
                      if c.row["resource_id"] in self.by_id)
        return Found(verdict, cards)

    async def browse(self, slug: str, path: str = "") -> Optional[BrowseLevel]:
        if self.index is None:
            return None
        try:
            return await search.browse(self.owner_id, self.catalog, slug, path, index=self.index)
        except search.SearchError:
            return None

    # --- a page: outline, read, grep ---------------------------------------------------

    async def page(self, page_id: str) -> Optional[Page]:
        """The page's text and sections, read once for this question; None when it cannot be
        read here (an ID outside the catalog, a blocked page, a page a refresh removed, a site
        that does not answer)."""
        if page_id not in self._pages:
            self._pages[page_id] = await self._read_page(page_id)
        return self._pages[page_id]

    async def _read_page(self, page_id: str) -> Optional[Page]:
        resolved = await page_ids.resolve(self.store, self.owner_id, self.catalog, page_id)
        if isinstance(resolved, page_ids.Refused) or resolved.resource.type == "cve-poc-db":
            return None
        row = await self.store.legacy_sitemap(self.owner_id, resolved.resource.id)
        if row is None:
            return None
        read = reader._Read(self.catalog, resolved.resource, row, self.store)
        if await reader._refusal(read, resolved.url):
            return None
        entry = await self.store.entry_by_url(self.owner_id, resolved.resource.id, resolved.url)
        if entry is None:
            return None
        stored = read.mode == "stored" and bool(entry.get("stored_text"))
        if "#page=" in resolved.url:
            text, _src, _note, error = await reader._pdf_page_live(read, resolved.url, entry, False)
        else:
            text, _src, _note, error = await reader._text_of(read, resolved.url, entry if stored else None, False)
        if error or not text:
            return None
        crumbs = (read.resource.name or read.slug, *(entry.get("breadcrumb") or ()), entry.get("title") or "")
        sections = split.split_markdown(text) or [split.Section(0, "", 0, "", text)]
        return Page(page_id, tuple(c for c in crumbs if c), sections, stored or "#page=" in resolved.url, text)

    async def outline(self, page_id: str) -> Optional[list[tuple[str, int]]]:
        """(section name, characters) of each section of the page."""
        got = await self.page(page_id)
        return None if got is None else [(split.section_name(s), s.chars) for s in got.sections]

    async def read(self, page_id: str, section: str) -> Optional[str]:
        """One section's text, at most ``constants.librarianSectionChars`` characters."""
        got = await self.page(page_id)
        if got is None:
            return None
        chosen = split.pick_section(got.sections, section)
        return None if chosen is None else chosen.text[:SECTION_CHARS]

    async def grep(self, page_id: str, needle: str) -> list[str]:
        """The lines of a stored copy that contain ``needle`` (any case); nothing for a page with
        no stored copy (Q9.4: stored text only)."""
        got = await self.page(page_id)
        if got is None or not got.stored or not needle.strip():
            return []
        key = needle.lower()
        lines = [ln.strip()[:GREP_LINE_CHARS] for ln in got.text.splitlines() if key in ln.lower()]
        return lines[:GREP_LINES]


_TOKEN = re.compile(r"[A-Za-z0-9_().]+")


def exact_terms(need: str) -> list[str]:
    """The terms of the need worth finding word for word in a stored copy: code-like ones
    (``pg_sleep``, ``SLEEP()``, ``generate_series``) and upper-case keywords (``SLEEP``, ``WAF``)."""
    out: list[str] = []
    for raw in _TOKEN.findall(need or ""):
        term = raw.split("(", 1)[0].strip(".")
        code = "_" in term or "(" in raw
        caps = term.isalpha() and term.isupper()
        if len(term) >= 3 and (code or caps) and term not in out:
            out.append(term)
    return out[:5]

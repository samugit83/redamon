"""Page IDs: ``<slug>:<n>``, where ``n`` is a ``tradecraft_page_ids`` row keyed by (resource, URL).

The number is global and never reused (an autoincrement), so an ID survives a refresh,
and a resource deleted and added again with the same slug gets new numbers: an old ID can
never answer for the new resource's pages (TD-4, R-138). Resolving checks the number
against the owner's rows and the slug against the run's catalog, so an ID of another
user, of another resource, or of a resource added again is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Protocol

from tradecraft.contract import SLUG_PATTERN

_PAGE_ID = re.compile(rf"^(?P<slug>{SLUG_PATTERN}):(?P<n>[1-9][0-9]{{0,17}})$")

NOT_A_PAGE_ID = "not a page ID: use one from tradecraft_search, a hint or the librarian, such as patt:412"
UNKNOWN_RESOURCE = "no resource {slug} in this run's library"
PAGE_NOT_FOUND = "page not found: {page_id}"
PAGE_READDED = "page not found: the resource was added again, so {page_id} no longer exists; search again"


def format(slug: str, page_number: int) -> str:  # noqa: A001 - the contract names it format
    if not re.fullmatch(SLUG_PATTERN, slug) or page_number < 1:
        raise ValueError(f"cannot make a page ID from {slug!r} and {page_number!r}")
    return f"{slug}:{page_number}"


def parse(text: str) -> Optional[tuple[str, int]]:
    m = _PAGE_ID.match(text.strip()) if isinstance(text, str) else None
    return (m["slug"], int(m["n"])) if m else None


@dataclass(frozen=True)
class PageIdRow:
    resource_id: str
    url: str


class PageIdStore(Protocol):
    """What resolving needs from the page store (T1.4 implements it). Both reads are keyed
    by the owner: a page ID of another user's resource is not found."""

    async def lookup_page_id(self, owner_id: str, page_number: int) -> Optional[PageIdRow]:
        """The row ``page_number`` of a resource of ``owner_id``, or None."""

    async def min_page_id(self, owner_id: str, resource_id: str) -> Optional[int]:
        """The lowest page number of that resource of ``owner_id``, or None when it has none."""


@dataclass(frozen=True)
class Resolved:
    page_id: str
    page_number: int
    resource: Any
    url: str


@dataclass(frozen=True)
class Refused:
    message: str


def _resources(catalog: Any) -> Iterable[Any]:
    return getattr(catalog, "resources", catalog) or ()


async def resolve(store: PageIdStore, owner_id: str, catalog: Any, text: str) -> Resolved | Refused:
    """The page an ID names in this run, or why not. ``catalog`` is the run's V2 catalog (or
    its list of resources); the resource is found by slug among the ones this run may read."""
    parsed = parse(text)
    if parsed is None:
        return Refused(NOT_A_PAGE_ID)
    slug, number = parsed
    page_id = f"{slug}:{number}"
    resource = next((r for r in _resources(catalog) if getattr(r, "slug", None) == slug), None)
    if resource is None:
        return Refused(UNKNOWN_RESOURCE.format(slug=slug))
    row = await store.lookup_page_id(owner_id, number)
    if row is not None and row.resource_id == resource.id:
        return Resolved(page_id=page_id, page_number=number, resource=resource, url=row.url)
    if row is None:
        # Numbers only grow: one below the resource's first was issued before this copy of
        # the resource existed, to the copy that was deleted.
        first = await store.min_page_id(owner_id, resource.id)
        if first is not None and number < first:
            return Refused(PAGE_READDED.format(page_id=page_id))
    return Refused(PAGE_NOT_FOUND.format(page_id=page_id))

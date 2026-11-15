"""Citation ids and links for AI Navigator's docs answers (plan §8.7).

Each successful `wiki_read` allocates `S1`, `S2`, ... per run, keyed by (page, anchor); reading
the same section twice reuses its id. Links are built from the index, never from the model:

- `url`: the page's `public_url` (read from its canonical banner, which the docs site adds to the
  pages it publishes) plus `#<anchor>`; a page without the banner is not published yet, so it is
  cited on the GitHub wiki only, never as a redamon.org 404;
- `mirror_url`: the GitHub wiki page, the source every copy is pulled from.

The synthesizer writes only `[S#]` markers; `finalize` drops every marker this run did not
allocate and lists the ids actually used, in order of first use.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from navigator.limits import MAX_CITATIONS

PUBLIC_RE = re.compile(r"^https://www\.redamon\.org/docs(/[a-z0-9-]+)?(#[a-z0-9\-_]+)?$")
MIRROR_RE = re.compile(r"^https://github\.com/samugit83/redamon/wiki(/[A-Za-z0-9-]+)?(#[a-z0-9\-_]+)?$")
GITHUB_WIKI = "https://github.com/samugit83/redamon/wiki"
PUBLIC_HOME = "https://www.redamon.org/docs"

MARKER_RE = re.compile(r"\[(S\d{1,3})\]")


def url_allowed(url: str) -> bool:
    return bool(PUBLIC_RE.match(url) or MIRROR_RE.match(url))


def _with_anchor(base: str, anchor: Optional[str], pattern: re.Pattern) -> Optional[str]:
    for candidate in ((f"{base}#{anchor}" if anchor else base), base):
        if pattern.match(candidate):
            return candidate
    return None


def build_links(page: str, anchor: Optional[str], public_url: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(url, mirror_url) for a section; an anchor outside the allowlist falls back to the page."""
    mirror_base = GITHUB_WIKI if page == "Home" else f"{GITHUB_WIKI}/{page}"
    mirror = _with_anchor(mirror_base, anchor, MIRROR_RE)
    public = None
    if page == "Home":
        public = _with_anchor(PUBLIC_HOME, anchor, PUBLIC_RE)
    elif public_url and PUBLIC_RE.match(public_url) and "#" not in public_url:
        public = _with_anchor(public_url, anchor, PUBLIC_RE)
    return (public or mirror), mirror


@dataclass
class Citation:
    id: str
    page: str
    anchor: str
    title: str
    heading: str
    url: str
    mirror_url: str

    def event(self) -> dict:
        return {"id": self.id, "title": self.title[:200], "heading": self.heading[:200],
                "url": self.url, "mirror_url": self.mirror_url}


class CitationRegistry:
    """The sections one run actually read."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], Citation] = {}
        self._by_id: dict[str, Citation] = {}

    def allocate(self, page: str, anchor: str, title: str, heading: str, public_url: Optional[str]) -> Optional[Citation]:
        key = (page, anchor or "")
        if key in self._by_key:
            return self._by_key[key]
        if len(self._by_id) >= 999:
            return None
        url, mirror = build_links(page, anchor or None, public_url)
        if not url or not mirror:
            return None
        cid = f"S{len(self._by_id) + 1}"
        cit = Citation(cid, page, anchor or "", title, heading, url, mirror)
        self._by_key[key] = cit
        self._by_id[cid] = cit
        return cit

    def get(self, cid: str) -> Optional[Citation]:
        return self._by_id.get(cid)

    def __len__(self) -> int:
        return len(self._by_id)

    def finalize(self, text: str) -> tuple[str, list[Citation]]:
        """The text with unknown markers removed, and the citations it uses in order of first use."""
        used: list[Citation] = []
        seen: set[str] = set()

        def keep(m: re.Match) -> str:
            cit = self._by_id.get(m.group(1))
            if not cit:
                return ""
            if cit.id not in seen and len(used) < MAX_CITATIONS:
                seen.add(cit.id)
                used.append(cit)
            return m.group(0)

        return MARKER_RE.sub(keep, text), used

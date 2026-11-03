"""
Pure web helpers shared by Tradecraft Lookup and the workspace URL importer.

Nothing here opens a connection: callers fetch through the pinned egress guard
(`fetch_guard.pinned_async_transport`) and hand the bytes in.
"""
from __future__ import annotations

import urllib.parse
from typing import Optional

_NON_NAVIGABLE_SCHEMES = ("mailto:", "javascript:", "tel:", "data:")


def document_base_href(soup) -> Optional[str]:
    """The first `<base href>` of a parsed document, or None."""
    if soup is None:
        return None
    tag = soup.find("base", href=True)
    if tag is None:
        return None
    href = (tag.get("href") or "").strip()
    return href or None


def resolve_link(page_url: str, href: str, base_href: Optional[str] = None) -> Optional[str]:
    """Resolve `href` the way a browser does, or None when it is not a web link.

    The base is the page's FINAL URL (after redirects), or its `<base href>`
    resolved against that URL. Joining against `page_url + "/"` instead puts a
    sibling of `/a/page.html` under `/a/page.html/`, which does not exist.
    """
    href = (href or "").strip()
    if not href or href.lower().startswith(_NON_NAVIGABLE_SCHEMES):
        return None
    try:
        base = urllib.parse.urljoin(page_url, base_href) if base_href else page_url
        absolute, _fragment = urllib.parse.urldefrag(urllib.parse.urljoin(base, href))
        scheme = urllib.parse.urlsplit(absolute).scheme.lower()
    except ValueError:
        return None
    if scheme not in ("http", "https"):
        return None
    return absolute

"""Where a mirrored URL is saved, and which URLs a page or stylesheet names.

Every path comes from a third-party site, so each segment is decoded and then
neutralized: a site can never reach outside the mirror folder, collide a file
with a folder (`/a` and `/a/b`), or overwrite the mirror's own `.import.json`
and `_manifest.jsonl`.

HTML is parsed with the stdlib "html.parser" only, as every Tradecraft parse
of third-party HTML is: never lxml (master plan T23).
"""
from __future__ import annotations

import hashlib
import posixpath
import re
import unicodedata
import urllib.parse
from typing import Iterable, List, Optional, Tuple, Union

from bs4 import BeautifulSoup

from orchestrator_helpers.web_sources import document_base_href, resolve_link
from workspace_import.extract import RESERVED_NAMES

SEGMENT_MAX_BYTES = 150
PATH_MAX_BYTES = 1000
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})

_ASSET_RELS = frozenset({"stylesheet", "icon", "preload", "modulepreload", "manifest", "apple-touch-icon"})
_CSS_URL_RE = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)'"\s]*))\s*\)""", re.IGNORECASE)
_CSS_IMPORT_RE = re.compile(r"""@import\s+(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)


def media_type(content_type: Optional[str]) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def is_html(content_type: Optional[str]) -> bool:
    return media_type(content_type) in HTML_TYPES


def is_css(content_type: Optional[str]) -> bool:
    return media_type(content_type) == "text/css"


def is_pdf(content_type: Optional[str]) -> bool:
    return media_type(content_type) == "application/pdf"


def canonical_url(url: str) -> str:
    """The identity of a URL for deduplication: scheme and host lowercased, the
    default port and the fragment dropped, query parameters sorted."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = host if port is None or (scheme, port) in (("http", 80), ("https", 443)) else f"{host}:{port}"
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True)))
    return urllib.parse.urlunsplit((scheme, netloc, parts.path or "/", query, ""))


def _segment(raw: str) -> str:
    text = "".join(
        "_" if ch in "/\\" or unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch
        for ch in urllib.parse.unquote(raw)
    )
    if text in ("", ".", ".."):
        return "_"
    if len(text.encode("utf-8")) > SEGMENT_MAX_BYTES:
        stem, ext = _split_ext(text)
        room = SEGMENT_MAX_BYTES - len(ext.encode("utf-8"))
        text = (stem.encode("utf-8")[:room].decode("utf-8", "ignore") or "_") + ext
    return text


def _split_ext(name: str) -> Tuple[str, str]:
    stem, ext = posixpath.splitext(name)
    if not stem or len(ext) > 12:
        return name, ""
    return stem, ext


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _host_dir(parts: urllib.parse.SplitResult) -> str:
    host = (parts.hostname or "_").lower()
    return _segment(f"{host}_{parts.port}" if parts.port else host)


def url_to_relpath(url: str, content_type: Optional[str], *, mode: str,
                   scope_host: Union[str, Iterable[str]]) -> str:
    """The path, relative to the mirror folder, that `url` is saved at.

    `scope_host` is the host (or hosts, when a redirect only added or dropped
    `www.`) whose files map to the folder's root; any other host goes under
    `_external/<host>/`.
    """
    parts = urllib.parse.urlsplit(url)
    hosts = {scope_host} if isinstance(scope_host, str) else set(scope_host)
    readable = mode == "readable"
    html = is_html(content_type)
    index = "index.md" if readable else "index.html"

    path = parts.path or "/"
    raw_segments = path.split("/")[1:]
    if path.endswith("/"):
        raw_segments = raw_segments[:-1]
    segments = [_segment(s) for s in raw_segments]
    if path.endswith("/") or not segments:
        segments.append(index)
    else:
        _stem, ext = _split_ext(segments[-1])
        if html and not ext:
            segments.append(index)

    stem, ext = _split_ext(segments[-1])
    if readable and html:
        ext = ".md"
    elif readable and is_pdf(content_type):
        ext = ".txt"
    if parts.query:
        query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True)))
        stem = f"{stem}__q{_sha1(query)[:8]}"
    segments[-1] = stem + ext

    if (parts.hostname or "").lower() not in hosts:
        segments = ["_external", _host_dir(parts)] + segments

    if segments[-1] in RESERVED_NAMES:
        return f"_reserved/{_sha1(canonical_url(url))}"
    rel = "/".join(segments)
    if len(rel.encode("utf-8")) > PATH_MAX_BYTES:
        safe_ext = ext if re.fullmatch(r"\.[A-Za-z0-9]{1,10}", ext or "") else ""
        return f"_long/{_sha1(canonical_url(url))}{safe_ext}"
    return rel


def _srcset_urls(value: str) -> List[str]:
    """The URLs of a srcset, parsed as the HTML spec does: a URL ends at
    whitespace, so a data: URL's comma does not split it."""
    out: List[str] = []
    i, n = 0, len(value)
    while i < n:
        while i < n and (value[i].isspace() or value[i] == ","):
            i += 1
        if i >= n:
            break
        j = i
        while j < n and not value[j].isspace():
            j += 1
        url, i = value[i:j], j
        if url.endswith(","):
            url = url.rstrip(",")
        else:
            depth = 0
            while i < n:
                ch = value[i]
                i += 1
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth = max(0, depth - 1)
                elif ch == "," and depth == 0:
                    break
        if url:
            out.append(url)
    return out


def _css_refs(css_text: str) -> List[str]:
    refs = []
    for m in _CSS_URL_RE.finditer(css_text or ""):
        refs.append(next(g for g in m.groups() if g is not None))
    for m in _CSS_IMPORT_RE.finditer(css_text or ""):
        refs.append(m.group(1) if m.group(1) is not None else m.group(2))
    return refs


def _resolve(base_url: str, ref, base_href: Optional[str] = None) -> Optional[str]:
    # A fragment-only reference names the document itself, never a new URL.
    if not isinstance(ref, str) or ref.strip().startswith("#"):
        return None
    return resolve_link(base_url, ref, base_href)


def _dedupe(urls: Iterable[Optional[str]]) -> List[str]:
    seen, out = set(), []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_css_urls(css_text: str, css_url: str) -> List[str]:
    """`url(...)` and `@import` targets of a stylesheet, resolved against it."""
    return _dedupe(_resolve(css_url, ref) for ref in _css_refs(css_text))


def extract_links(html: str, final_url: str) -> Tuple[List[str], List[str]]:
    """(pages, assets) a page links to, resolved against its final URL and its
    `<base href>`, without fragments, http(s) only, each list deduplicated."""
    soup = BeautifulSoup(html or "", "html.parser")
    base = document_base_href(soup)

    def resolve(ref) -> Optional[str]:
        return _resolve(final_url, ref, base)

    pages = []
    for tag, attr in (("a", "href"), ("area", "href"), ("iframe", "src"), ("frame", "src")):
        pages.extend(resolve(el.get(attr)) for el in soup.find_all(tag, attrs={attr: True}))

    assets = []
    for el in soup.find_all("link", href=True):
        rels = el.get("rel") or []
        rels = rels.split() if isinstance(rels, str) else rels
        if _ASSET_RELS.intersection(r.lower() for r in rels):
            assets.append(resolve(el.get("href")))
    for tag, attr in (("script", "src"), ("img", "src"), ("source", "src"), ("video", "src"),
                      ("video", "poster"), ("audio", "src"), ("track", "src"), ("object", "data"),
                      ("embed", "src")):
        assets.extend(resolve(el.get(attr)) for el in soup.find_all(tag, attrs={attr: True}))
    for tag in ("img", "source"):
        for el in soup.find_all(tag, srcset=True):
            assets.extend(resolve(u) for u in _srcset_urls(el.get("srcset") or ""))
    for el in soup.find_all("style"):
        assets.extend(resolve(ref) for ref in _css_refs(el.get_text()))
    for el in soup.find_all(style=True):
        assets.extend(resolve(ref) for ref in _css_refs(el.get("style") or ""))
    return _dedupe(pages), _dedupe(assets)

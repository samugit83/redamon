"""Today's title match over a resource's 1.x map (R-217), and its path resolution.

A port of 1.x's lexical matcher (Jaccard plus substring) and ``_resolve_path_for_resource``.
An unconverted resource (``mapVersion`` 1) is read this way until the conversion (T9.1) reaches
it, and a converted one when the free first pass finds nothing, from the 1.x map every 2.0
ingestion keeps current (TD-18). The section picker model that 1.x could ask among the top
matches left with the cut-over (R-401): the best lexical match is the answer.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Optional

from orchestrator_helpers.web_sources import split_github_url

_KNOWN_EXTENSIONS = (".html", ".htm", ".md", ".txt", ".rst", ".pdf", ".json", ".yaml", ".yml", ".xml")
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokens(s: str) -> set:
    return set(_TOKEN_RE.findall((s or "").lower()))


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def substring_score(query_tokens: set, entry_tokens: set) -> float:
    """The share of query words (4+ letters) found inside an entry word or holding one:
    "kerberoasting" meets "kerberoast"."""
    if not query_tokens or not entry_tokens:
        return 0.0
    hits = 0
    for q in query_tokens:
        if len(q) < 4:
            continue
        if any(q in t or (len(t) >= 4 and t in q) for t in entry_tokens):
            hits += 1
    return hits / len(query_tokens)


def rank_score(query_tokens: set, entry: dict) -> float:
    et = tokens((entry.get("title") or "") + " " + (entry.get("path") or ""))
    return jaccard(query_tokens, et) + 0.5 * substring_score(query_tokens, et)


def sitemap_entries(sitemap: Any) -> list[dict]:
    """The 1.x map's entries as [{title, path}] (``nav``, ``tree`` or ``links``)."""
    if not isinstance(sitemap, dict):
        return []
    for key in ("nav", "tree", "links"):
        if isinstance(sitemap.get(key), list):
            return [{"title": str(e.get("title", "")), "path": str(e.get("path", ""))}
                    for e in sitemap[key] if isinstance(e, dict)]
    return []


def pick(query: str, entries: list[dict]) -> Optional[dict]:
    """The entry that best answers ``query`` by words alone (no model: the section picker left
    with 1.x, R-401), or None when no entry shares a word with it."""
    if not entries:
        return None
    qt = tokens(query)
    best = max(entries, key=lambda e: rank_score(qt, e))
    return best if rank_score(qt, best) > 0 else None


def find_in_sitemap(entries: list[dict], needle_text: str) -> Optional[dict]:
    """An entry by exact title, by a path ending in ``<needle><ext>``, then by path substring."""
    needle = needle_text.strip().lower()
    if not needle or not entries:
        return None
    for e in entries:
        if (e.get("title") or "").strip().lower() == needle:
            return e
    for e in entries:
        p = (e.get("path") or "").lower()
        if any(p.endswith(f"/{needle}{ext}") or p.endswith(f"{needle}{ext}") for ext in _KNOWN_EXTENSIONS):
            return e
    for e in entries:
        if needle in (e.get("path") or "").lower():
            return e
    return None


def _encode(path: str) -> str:
    return "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))


def resolve_path(resource_type: str, base_url: str, sitemap: Any, path: str) -> str:
    """A map path (or a title, or a path the agent typed) as the URL to read, as 1.x resolves it.
    The result is not checked against the map: a forced read checks it (``reader._in_resource``)."""
    if not path:
        return base_url
    if path.startswith(("http://", "https://")):
        return path
    path = path.lstrip("/")
    matched = find_in_sitemap(sitemap_entries(sitemap), path)
    return entry_url(resource_type, base_url, sitemap, (matched.get("path") or "") if matched else path)


def entry_url(resource_type: str, base_url: str, sitemap: Any, path: str) -> str:
    """The URL a path of the 1.x map is read at, with no lookup in the map: linear over a map,
    where ``resolve_path`` looks each path up again."""
    if path.startswith(("http://", "https://")):
        return path
    path = path.lstrip("/")
    if resource_type == "github-repo":
        if not path.lower().endswith(_KNOWN_EXTENSIONS):
            path = path.rstrip("/") + "/README.md"
        parsed = split_github_url(base_url)
        if parsed:
            owner, repo = parsed
            branch = (sitemap or {}).get("branch") or "main"
            return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{_encode(path)}"
    if resource_type == "sphinx-docs" and not path.lower().endswith(_KNOWN_EXTENSIONS):
        path = path + ".html"
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", _encode(path))

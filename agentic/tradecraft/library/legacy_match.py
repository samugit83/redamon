"""Today's title match over a resource's 1.x map (R-217), and its path resolution.

A port of 1.x's lexical matcher (Jaccard plus substring, top 30), the optional section picker
model, and ``_resolve_path_for_resource``. Phase 1 reads every resource this way: an
unconverted one (``mapVersion`` 1) from the map 1.x wrote, a 2.0 one from the 1.x map its
ingestion also writes (TD-18). Search (phase 2) replaces it for 2.0 resources.

The page titles are shown to the picker model as untrusted content: they come from the site.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Optional

from agent_in_the_loop.purpose import llm_purpose
from logging_config import get_logger
from orchestrator_helpers.json_utils import normalize_content
from orchestrator_helpers.web_sources import split_github_url
from prompt_safety import UNTRUSTED_OUTPUT_GUIDANCE, wrap_untrusted

logger = get_logger(__name__)

TOP_CANDIDATES = 30
CLEAR_WINNER = 0.6
SMALL_MAP = 5
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


async def pick(query: str, entries: list[dict], *, picker: Any = None, resource_name: str = "") -> Optional[dict]:
    """The entry that best answers ``query``: the top lexical match, or the picker model's
    choice among the top 30 when the map is large and no entry clearly wins."""
    if not entries:
        return None
    qt = tokens(query)
    scored = sorted(((rank_score(qt, e), e) for e in entries), key=lambda x: x[0], reverse=True)
    top = scored[:TOP_CANDIDATES]
    if picker is None:
        return top[0][1] if top[0][0] > 0 else None
    if len(entries) <= SMALL_MAP or top[0][0] >= CLEAR_WINNER:
        return top[0][1]
    lines = [f"  {i}. {(e.get('title') or e.get('path') or '')[:80]}  ->  {(e.get('path') or '')[:80]}"
             for i, (_s, e) in enumerate(top, 1)]
    prompt = "\n".join([
        "You pick the single most relevant page for a tradecraft query.",
        f"Reply with ONLY the number (1-{len(top)}). No prose.",
        "",
        UNTRUSTED_OUTPUT_GUIDANCE,
        "",
        f'Query: "{query}"',
        f"Pages from {resource_name}:",
        wrap_untrusted("\n".join(lines), "WEB_CONTENT"),
        "Answer with just the number.",
    ])
    try:
        with llm_purpose("tradecraft_librarian", step="section_picker"):
            resp = await picker.ainvoke(prompt)
        m = re.search(r"\d+", normalize_content(getattr(resp, "content", str(resp))).strip())
        if m and 0 <= int(m.group(0)) - 1 < len(top):
            return top[int(m.group(0)) - 1][1]
    except Exception as exc:
        # No retry (TD-20): the lexical winner stands.
        logger.warning(f"[tradecraft] section picker error={type(exc).__name__}")
    return top[0][1]


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
    """A map path (or a title, or a path the agent typed) as the URL to read, as 1.x resolves it."""
    if not path:
        return base_url
    if path.startswith(("http://", "https://")):
        return path
    path = path.lstrip("/")
    matched = find_in_sitemap(sitemap_entries(sitemap), path)
    if matched:
        mp = matched.get("path") or ""
        if mp.startswith(("http://", "https://")):
            return mp
        path = mp.lstrip("/")
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

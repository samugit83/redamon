"""wiki_toc, wiki_search, wiki_outline, wiki_read: the docs specialist's tools (plan §8.6).

Every lookup is by page name and anchor against the index; nothing here opens a path the model
named. `wiki_read` allocates the citation id the answer may cite.
"""
from __future__ import annotations

import html

from navigator.citations import CitationRegistry
from navigator.limits import WIKI_QUERY_MAX_CHARS, WIKI_READ_MAX_CHARS, WIKI_SEARCH_MAX_K
from navigator.tooling import NavTool, ToolOutcome, as_json, refused
from navigator.wiki_index import WikiIndex, snippet

ROUTE = "docs"


def toc_text(index: WikiIndex) -> str:
    """The sidebar, then one line per page: name, title and its first-paragraph summary."""
    lines = ["Sidebar:", index.sidebar.strip(), "", "Pages (name: title - summary):"]
    for name in sorted(index.pages):
        page = index.pages[name]
        lines.append(f"- {name}: {page.title}" + (f" - {page.summary}" if page.summary else ""))
    return "\n".join(lines)


def _page_or_error(index: WikiIndex, name):
    page = index.resolve_page(name) if isinstance(name, str) else None
    if page is None:
        close = index.close_names(name if isinstance(name, str) else "")
        return None, refused("unknown_page", "No such page." + (f" Close names: {', '.join(close)}" if close else ""),
                             "Looked for a docs page that does not exist")
    return page, None


def make_wiki_tools(index: WikiIndex, citations: CitationRegistry) -> list[NavTool]:
    async def wiki_toc(_args: dict) -> ToolOutcome:
        return ToolOutcome(toc_text(index), True, "Read the docs table of contents")

    async def wiki_search(args: dict) -> ToolOutcome:
        # Some models HTML-escape their tool arguments ("&amp;"); the wiki is plain text.
        query = html.unescape(str(args.get("query") or ""))[:WIKI_QUERY_MAX_CHARS].strip()
        try:
            k = int(args.get("k") or 5)
        except (TypeError, ValueError):
            k = 5
        k = max(1, min(WIKI_SEARCH_MAX_K, k))
        if not query:
            return refused("invalid_args", "query is required", "Searched the docs")
        hits = [{"page": s.page, "heading_path": s.heading_path, "anchor": s.anchor,
                 "snippet": snippet(s.text, query), "score": round(sc, 2)} for s, sc in index.search(query, k)]
        return ToolOutcome(as_json(hits), True, f"Searched the docs for “{query[:80]}”")

    async def wiki_outline(args: dict) -> ToolOutcome:
        page, err = _page_or_error(index, args.get("page"))
        if err:
            return err
        outline = [{"level": s.level, "heading": s.heading, "anchor": s.anchor, "chars": len(s.full_text)}
                   for s in page.sections]
        return ToolOutcome(as_json({"page": page.name, "title": page.title, "sections": outline}), True,
                           f"Read the outline of '{page.title}'")

    async def wiki_read(args: dict) -> ToolOutcome:
        page, err = _page_or_error(index, args.get("page"))
        if err:
            return err
        anchor = args.get("anchor")
        sec = index.section(page, anchor if isinstance(anchor, str) else None)
        if sec is None:
            anchors = ", ".join(s.anchor for s in page.sections[:40])
            return refused("unknown_anchor", f"No such section on {page.name}. Anchors: {anchors}",
                           f"Looked for a section of '{page.title}' that does not exist")
        try:
            offset = max(0, int(args.get("offset") or 0))
        except (TypeError, ValueError):
            offset = 0
        text = sec.full_text[offset:offset + WIKI_READ_MAX_CHARS]
        nxt = offset + WIKI_READ_MAX_CHARS if offset + WIKI_READ_MAX_CHARS < len(sec.full_text) else None
        cit = citations.allocate(page.name, sec.anchor, page.title, sec.heading, page.public_url)
        out = {"cite": cit.id if cit else None, "page": page.name, "heading_path": sec.heading_path,
               "anchor": sec.anchor, "text": text, "next_offset": nxt}
        where = page.title if sec.heading == page.title else f"{page.title} → {sec.heading}"
        return ToolOutcome(as_json(out), True, f"Read '{where}'")

    page_arg = {"type": "string", "description": "The page name exactly as the table of contents lists it, e.g. Scan-Timeline."}
    return [
        NavTool("wiki_toc", "The RedAmon documentation's table of contents: the sidebar and every page with a one-line summary.",
                {"type": "object", "properties": {}, "additionalProperties": False}, ROUTE, wiki_toc),
        NavTool("wiki_search", "Full-text search over every section of the RedAmon documentation. Returns page, heading path, anchor and a snippet.",
                {"type": "object", "properties": {
                    "query": {"type": "string", "description": "Keywords, at most 200 characters."},
                    "k": {"type": "integer", "minimum": 1, "maximum": WIKI_SEARCH_MAX_K, "description": "How many hits (default 5)."}},
                 "required": ["query"], "additionalProperties": False}, ROUTE, wiki_search),
        NavTool("wiki_outline", "The heading tree of one documentation page, with each section's anchor and size.",
                {"type": "object", "properties": {"page": page_arg}, "required": ["page"], "additionalProperties": False},
                ROUTE, wiki_outline),
        NavTool("wiki_read", "Read one section of a documentation page (and its sub-sections). Returns `cite`, the id to cite it with as [S#]. "
                "Without an anchor, reads the page from its top. Long sections return next_offset to continue.",
                {"type": "object", "properties": {
                    "page": page_arg,
                    "anchor": {"type": "string", "description": "The section anchor from wiki_search or wiki_outline."},
                    "offset": {"type": "integer", "minimum": 0}},
                 "required": ["page"], "additionalProperties": False}, ROUTE, wiki_read),
    ]

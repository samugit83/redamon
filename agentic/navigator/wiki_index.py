"""The wiki index AI Navigator's docs route reads at answer time (plan §8.6).

Pure Python, no new dependency. Built lazily on first use from the top-level `*.md` files of the
wiki checkout (`/app/wiki`, a read-only mount of `redamon.wiki`), and rebuilt when the newest
modification time changes, checked at most every WIKI_RECHECK_S seconds. A rebuild swaps the
index in one assignment.

Every lookup is by page name and anchor against the index: the model never supplies a path, so
there is no traversal surface. Sub-directories (hacklab/, xbench_sessions/, xbow-patches/,
docs/, images/) are never read, `_Footer.md` is skipped and `_Sidebar.md` is used only as the
table of contents.

Anchors follow github-slugger, which GitHub and the docs site (rehype-slug) both use, so a
citation's `#anchor` lands on the same heading in both copies.
"""
from __future__ import annotations

import difflib
import logging
import math
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from navigator.limits import (WIKI_DIR, WIKI_RECHECK_S, WIKI_SNIPPET_CHARS,
                              WIKI_SUMMARY_CHARS)

logger = logging.getLogger(__name__)

#: Appendix B: the only public docs URL a page's canonical banner may give.
PUBLIC_DOCS_RE = re.compile(r"^https://www\.redamon\.org/docs(/[a-z0-9-]+)?(#[a-z0-9\-_]+)?$")

_BANNER_BLOCK_RE = re.compile(r"<!--\s*canonical-banner\s*-->(.*?)<!--\s*canonical-banner\s*-->", re.S)
_BANNER_URL_RE = re.compile(r"\((https://[^)\s]+)\)")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_BADGE_LINE_RE = re.compile(r"^\s*(<a\b[^>]*>\s*)?<img\b[^>]*>(\s*</a>)?\s*$", re.I)
_HEADING_RE = re.compile(r"^(#{1,4})\s+(.+?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_WIKI_LINK_RE = re.compile(r"\]\(([A-Za-z0-9][A-Za-z0-9-]*)(#[^)\s]*)?\)")
_PAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,120}$")
_TOKEN_RE = re.compile(r"[a-z0-9]+")

_STOP_WORDS = frozenset(
    "a an and are as at be by can do does for from how i in is it its me my of on or the this to "
    "what when where which who why will with you your".split()
)


def strip_inline_markdown(text: str) -> str:
    """The text a heading renders to: links, code ticks, emphasis and HTML tags removed."""
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("`", "")
    text = re.sub(r"(\*\*|__)(.+?)\1", r"\2", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"\1", text)
    text = re.sub(r"(?<![\w_])_(?!\s)(.+?)(?<!\s)_(?![\w_])", r"\1", text)
    return text.strip()


def _slug_char_kept(ch: str) -> bool:
    if ch in " -_":
        return True
    cat = unicodedata.category(ch)
    return cat[0] in ("L", "N", "M") or cat == "Pc"


def github_slug(heading_text: str) -> str:
    """github-slugger's slug of an already rendered heading text (no duplicate suffix)."""
    lowered = heading_text.lower()
    return "".join(c for c in lowered if _slug_char_kept(c)).replace(" ", "-")


class Slugger:
    """github-slugger with its per-page duplicate counter: `x`, `x-1`, `x-2`, ..."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def slug(self, heading_text: str) -> str:
        base = github_slug(heading_text)
        slug = base
        while slug in self._seen:
            self._seen[base] += 1
            slug = f"{base}-{self._seen[base]}"
        self._seen[slug] = 0
        return slug


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP_WORDS]


@dataclass
class Section:
    page: str
    page_title: str
    heading: str
    level: int
    anchor: str
    path: list[str]
    text: str
    #: The section and every sub-section under it, the text `wiki_read` returns.
    full_text: str = ""
    links: list[str] = field(default_factory=list)

    @property
    def heading_path(self) -> str:
        return " › ".join(self.path)


@dataclass
class Page:
    name: str
    title: str
    summary: str
    public_url: Optional[str]
    sections: list[Section]


@dataclass
class _Posting:
    section: Section
    tf: dict[str, float]
    length: float


class WikiIndex:
    """One immutable build of the wiki. `present` is false for an empty or missing checkout."""

    K1 = 1.4
    B = 0.75

    def __init__(self, pages: dict[str, Page], sidebar: str, built_at: float, mtime: float):
        self.pages = pages
        self.sidebar = sidebar
        self.built_at = built_at
        self.mtime = mtime
        self._lower = {name.lower(): name for name in pages}
        self._postings: list[_Posting] = []
        self._df: dict[str, int] = {}
        for page in pages.values():
            for sec in page.sections:
                tf: dict[str, float] = {}
                for tok in tokenize(sec.text):
                    tf[tok] = tf.get(tok, 0.0) + 1.0
                for tok in tokenize(" ".join(sec.path)):
                    tf[tok] = tf.get(tok, 0.0) + 2.0
                for tok in tokenize(page.title):
                    tf[tok] = tf.get(tok, 0.0) + 3.0
                for tok in tf:
                    self._df[tok] = self._df.get(tok, 0) + 1
                self._postings.append(_Posting(sec, tf, sum(tf.values())))
        self._avg = (sum(p.length for p in self._postings) / len(self._postings)) if self._postings else 1.0

    @property
    def present(self) -> bool:
        return bool(self.pages)

    @property
    def section_count(self) -> int:
        return len(self._postings)

    def resolve_page(self, name: str) -> Optional[Page]:
        """A page by its name, case-insensitively; spaces read as dashes. Nothing path-like resolves."""
        if not isinstance(name, str):
            return None
        candidate = name.strip().replace(" ", "-")
        if candidate.endswith(".md"):
            candidate = candidate[:-3]
        if not _PAGE_NAME_RE.match(candidate):
            return None
        real = self._lower.get(candidate.lower())
        return self.pages.get(real) if real else None

    def close_names(self, name: str, n: int = 5) -> list[str]:
        if not isinstance(name, str):
            return []
        return difflib.get_close_matches(name.strip().replace(" ", "-"), list(self.pages), n=n, cutoff=0.4)

    def section(self, page: Page, anchor: Optional[str]) -> Optional[Section]:
        if not anchor:
            return page.sections[0] if page.sections else None
        anchor = anchor.lstrip("#").strip().lower()
        for sec in page.sections:
            if sec.anchor == anchor:
                return sec
        return None

    def search(self, query: str, k: int) -> list[tuple[Section, float]]:
        terms = tokenize(query)
        if not terms or not self._postings:
            return []
        n = len(self._postings)
        scored: list[tuple[Section, float]] = []
        for post in self._postings:
            score = 0.0
            for term in terms:
                tf = post.tf.get(term)
                if not tf:
                    continue
                df = self._df.get(term, 0)
                idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
                score += idf * tf * (self.K1 + 1) / (tf + self.K1 * (1 - self.B + self.B * post.length / self._avg))
            if score > 0:
                scored.append((post.section, score))
        scored.sort(key=lambda x: -x[1])
        return scored[:k]


def snippet(text: str, query: str, size: int = WIKI_SNIPPET_CHARS) -> str:
    flat = re.sub(r"\s+", " ", text).strip()
    terms = tokenize(query)
    low = flat.lower()
    pos = min((low.find(t) for t in terms if low.find(t) >= 0), default=0)
    start = max(0, pos - size // 3)
    cut = flat[start:start + size]
    return ("…" if start else "") + cut + ("…" if start + size < len(flat) else "")


def _clean_lines(raw: str) -> tuple[list[str], Optional[str]]:
    """The page's lines with the banner, comments and badge lines removed, and its public URL."""
    public_url = None
    banner = _BANNER_BLOCK_RE.search(raw)
    if banner:
        for url in _BANNER_URL_RE.findall(banner.group(1)):
            if PUBLIC_DOCS_RE.match(url):
                public_url = url
                break
    text = _BANNER_BLOCK_RE.sub("", raw)
    text = _HTML_COMMENT_RE.sub("", text)
    return [ln for ln in text.splitlines() if not _BADGE_LINE_RE.match(ln)], public_url


def _summary(lines: list[str]) -> str:
    para: list[str] = []
    in_fence = False
    for ln in lines:
        if _FENCE_RE.match(ln):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        s = ln.strip()
        if not s:
            if para:
                break
            continue
        if s.startswith(("#", ">", "|", "<", "!", "---", "- ", "* ")) or re.match(r"^\d+\.", s):
            if para:
                break
            continue
        para.append(s)
    text = strip_inline_markdown(" ".join(para))
    return text[:WIKI_SUMMARY_CHARS - 1] + "…" if len(text) > WIKI_SUMMARY_CHARS else text


def parse_page(name: str, raw: str) -> Page:
    lines, public_url = _clean_lines(raw)
    slugger = Slugger()
    sections: list[Section] = []
    stack: list[tuple[int, str]] = []
    title = name.replace("-", " ")
    current: Optional[dict] = None
    in_fence = False
    order: list[tuple[dict, int]] = []

    def close(cur: Optional[dict]):
        if cur is not None:
            order.append((cur, len(order)))

    preamble: list[str] = []
    for ln in lines:
        if _FENCE_RE.match(ln):
            in_fence = not in_fence
        m = None if in_fence else _HEADING_RE.match(ln)
        if m:
            close(current)
            level = len(m.group(1))
            heading = strip_inline_markdown(m.group(2))
            if level == 1 and not sections and not order:
                title = heading or title
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, heading))
            current = {"heading": heading, "level": level, "anchor": slugger.slug(heading),
                       "path": [h for _, h in stack], "lines": []}
            continue
        if current is None:
            preamble.append(ln)
        else:
            current["lines"].append(ln)
    close(current)

    if not order and preamble:
        order.append(({"heading": title, "level": 1, "anchor": "", "path": [title], "lines": preamble}, 0))
    elif preamble and order and order[0][0]["level"] > 1:
        order.insert(0, ({"heading": title, "level": 1, "anchor": "", "path": [title], "lines": preamble}, -1))

    for cur, _ in order:
        body = "\n".join(cur["lines"]).strip()
        sections.append(Section(
            page=name, page_title=title, heading=cur["heading"], level=cur["level"],
            anchor=cur["anchor"], path=cur["path"], text=f"{cur['heading']}\n{body}".strip(),
            links=sorted({m.group(1) for m in _WIKI_LINK_RE.finditer(body)}),
        ))
    # A section's full text runs to the next heading at its level or above.
    for i, sec in enumerate(sections):
        parts = [("#" * sec.level) + " " + sec.text]
        for nxt in sections[i + 1:]:
            if nxt.level <= sec.level:
                break
            parts.append(("#" * nxt.level) + " " + nxt.text)
        sec.full_text = "\n\n".join(parts)
    summary_src = [ln for ln in lines if not _HEADING_RE.match(ln)]
    return Page(name=name, title=title, summary=_summary(summary_src), public_url=public_url, sections=sections)


def _sidebar_text(raw: str) -> str:
    """The sidebar as plain lines, `Text (Page[#anchor])`, without the markdown noise."""
    out = []
    for ln in raw.splitlines():
        s = ln.rstrip()
        if not s.strip() or s.strip() == "---":
            continue
        s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", s)
        s = s.replace("**", "")
        out.append(s)
    return "\n".join(out)


def _md_files(root: str) -> list[str]:
    try:
        names = os.listdir(root)
    except OSError:
        return []
    return sorted(n for n in names if n.endswith(".md") and os.path.isfile(os.path.join(root, n)))


def _newest_mtime(root: str, files: list[str]) -> float:
    newest = 0.0
    for n in files:
        try:
            newest = max(newest, os.stat(os.path.join(root, n)).st_mtime)
        except OSError:
            continue
    return newest


def build_index(root: str) -> WikiIndex:
    files = _md_files(root)
    pages: dict[str, Page] = {}
    sidebar = ""
    for fname in files:
        name = fname[:-3]
        try:
            with open(os.path.join(root, fname), encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        if name == "_Footer":
            continue
        if name == "_Sidebar":
            sidebar = _sidebar_text(raw)
            continue
        if not _PAGE_NAME_RE.match(name):
            continue
        pages[name] = parse_page(name, raw)
    return WikiIndex(pages, sidebar, time.time(), _newest_mtime(root, files))


class WikiIndexHolder:
    """The index in force for one wiki directory: built lazily, refreshed on change."""

    def __init__(self, root: str = WIKI_DIR):
        self.root = root
        self._index: Optional[WikiIndex] = None
        self._checked = 0.0
        self._lock = threading.Lock()
        self._warned = False

    def get(self) -> WikiIndex:
        now = time.monotonic()
        idx = self._index
        if idx is not None and now - self._checked < WIKI_RECHECK_S:
            return idx
        with self._lock:
            idx = self._index
            if idx is not None and now - self._checked < WIKI_RECHECK_S:
                return idx
            self._checked = now
            files = _md_files(self.root)
            mtime = _newest_mtime(self.root, files)
            if idx is None or mtime != idx.mtime or len(files) != len(idx.pages) + _special_count(files):
                idx = build_index(self.root)
                self._index = idx
                if not idx.present and not self._warned:
                    self._warned = True
                    logger.warning("[navigator] wiki not installed at %s", self.root)
            return idx

    def force_stale(self) -> None:
        """Tests: the next get() checks the files again."""
        self._checked = 0.0


def _special_count(files: list[str]) -> int:
    return sum(1 for f in files if f in ("_Footer.md", "_Sidebar.md") or not _PAGE_NAME_RE.match(f[:-3]))


_HOLDER: Optional[WikiIndexHolder] = None
_HOLDER_LOCK = threading.Lock()


def wiki_index() -> WikiIndex:
    global _HOLDER
    with _HOLDER_LOCK:
        if _HOLDER is None:
            _HOLDER = WikiIndexHolder(WIKI_DIR)
    return _HOLDER.get()

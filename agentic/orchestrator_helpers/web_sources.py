"""
Pure web helpers shared by Tradecraft Lookup and the workspace URL importer.

Nothing here opens a connection: callers fetch through the pinned egress guard
(`fetch_guard.pinned_async_transport`) and hand the bytes in.
"""
from __future__ import annotations

import io
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None

try:
    from markdownify import markdownify as _md  # type: ignore
except Exception:
    _md = None

try:
    from pypdf import PdfReader  # type: ignore
except Exception:
    PdfReader = None

_NON_NAVIGABLE_SCHEMES = ("mailto:", "javascript:", "tel:", "data:")

# The user's GitHub token goes to these exact hosts only. Never match on a
# substring: github-docs.attacker.example contains "github" too.
GITHUB_TOKEN_HOSTS = frozenset({"github.com", "api.github.com", "raw.githubusercontent.com"})

PDF_MAX_PAGES = 200

# A sitemap is a list of URLs; one bigger than this is not worth parsing.
SITEMAP_MAX_BYTES = 10 * 1024 * 1024


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


# =========================================================================
# GitHub URLs
# =========================================================================

def url_host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def is_github_token_url(url: str) -> bool:
    """True only for https URLs on a GitHub host, the one place the token belongs."""
    return url.lower().startswith("https://") and url_host(url) in GITHUB_TOKEN_HOSTS


def rewrite_github_url(url: str) -> str:
    """github.com/{owner}/{repo}/blob/{branch}/{path} -> raw.githubusercontent.com/.../{branch}/{path}"""
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$", url)
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return url


def split_github_url(url: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:/|$)", url)
    if not m:
        return None
    owner, repo = m.groups()
    # NB: use removesuffix, NOT rstrip(".git") — rstrip strips any trailing
    # chars in the set {'.','g','i','t'}, mangling repos like "streamlit" ->
    # "streaml" or "nuclei" -> "nucle" and 404ing the GitHub API (issue #153).
    return owner, repo.removesuffix(".git")


# =========================================================================
# Sitemaps
# =========================================================================

_LANG_RE = re.compile(r"^/([a-z]{2}(?:-[A-Z]{2})?)/")


def prefer_english(urls: List[str]) -> List[str]:
    """If sitemap entries cluster under language codes /<lang>/..., keep only /en/.

    Many translated wikis (HackTricks across 20+ languages) inflate sitemaps with
    near-duplicate entries. We detect this when >40% of paths begin with a 2-letter
    language segment AND `/en/` is present, then filter to English only.
    """
    if not urls:
        return urls
    parsed = []
    has_lang = 0
    has_en = False
    for u in urls:
        try:
            path = urllib.parse.urlsplit(u).path or "/"
        except Exception:
            continue
        m = _LANG_RE.match(path)
        if m:
            has_lang += 1
            if m.group(1) == "en":
                has_en = True
        parsed.append((u, path, m))
    if has_en and has_lang > 0.4 * len(parsed):
        return [u for (u, p, m) in parsed if m and m.group(1) == "en"]
    return urls


def sitemap_xml_refused(text: str) -> bool:
    """True for a third-party sitemap that must not reach the XML parser: too
    big, or declaring a DTD or entities (billion laughs, external entities)."""
    if len(text) > SITEMAP_MAX_BYTES or len(text.encode("utf-8", "ignore")) > SITEMAP_MAX_BYTES:
        return True
    lowered = text.lower()
    return "<!doctype" in lowered or "<!entity" in lowered


def parse_sitemap_xml(text: str) -> Tuple[Optional[str], List[str]]:
    """("index", sitemap locs) | ("urlset", page locs) | (None, []).

    Handles both shapes:
      <urlset><url><loc>...</loc></url>...</urlset>
      <sitemapindex><sitemap><loc>...</loc></sitemap>...</sitemapindex>
    """
    if not text or BeautifulSoup is None or sitemap_xml_refused(text):
        return None, []
    if "<sitemapindex" in text:
        soup = BeautifulSoup(text, "xml")
        locs = []
        for sm in soup.find_all("sitemap"):
            loc = sm.find("loc")
            if loc and loc.get_text(strip=True):
                locs.append(loc.get_text(strip=True))
        return "index", locs
    if "<urlset" in text:
        soup = BeautifulSoup(text, "xml")
        return "urlset", [loc.get_text(strip=True) for loc in soup.find_all("loc") if loc.get_text(strip=True)]
    return None, []


# =========================================================================
# Page and PDF text
# =========================================================================

def html_to_markdown(html: str) -> str:
    """Strip nav/footer, keep article body, convert to markdown."""
    if not html:
        return ""
    if BeautifulSoup is None:
        # Conservative fallback: strip tags with regex.
        return re.sub(r"<[^>]+>", " ", html)
    soup = BeautifulSoup(html, "html.parser")
    # Drop noisy elements.
    for sel in ["nav", "footer", "header", "aside", "script", "style", "form", "iframe"]:
        for el in soup.select(sel):
            el.decompose()
    # Prefer the main article container.
    body_html = None
    for sel in ["article", "main", ".md-content", "[role='main']", ".post-content", ".content"]:
        el = soup.select_one(sel)
        if el and len(el.get_text(strip=True)) > 200:
            body_html = str(el)
            break
    if body_html is None:
        body_html = str(soup.body or soup)
    if _md is not None:
        try:
            return _md(body_html, heading_style="ATX")
        except Exception:
            pass
    # Fallback: just strip tags.
    return re.sub(r"<[^>]+>", " ", body_html)


def extract_pdf_pages(raw_bytes: bytes) -> Tuple[List[Dict[str, Any]], List[str], str]:
    """Returns (pages_meta, page_texts, last_error).

    pages_meta: [{"page": 1, "firstLine": "..."}]
    page_texts: full text per page, aligned with pages_meta
    """
    if PdfReader is None:
        return [], [], "pypdf not installed"
    if not raw_bytes:
        return [], [], "empty pdf body"
    try:
        reader = PdfReader(io.BytesIO(raw_bytes))
    except Exception as e:
        return [], [], f"pdf parse error: {e}"
    pages_meta: List[Dict[str, Any]] = []
    page_texts: List[str] = []
    total = len(reader.pages)
    truncated = total > PDF_MAX_PAGES
    n = min(total, PDF_MAX_PAGES)
    for i in range(n):
        try:
            text = reader.pages[i].extract_text() or ""
        except Exception:
            text = ""
        first_line = ""
        for line in (text or "").splitlines():
            line = line.strip()
            if line:
                first_line = line[:80]
                break
        pages_meta.append({"page": i + 1, "firstLine": first_line})
        page_texts.append(text)
    err = f"PDF truncated at {PDF_MAX_PAGES} pages (real total: {total})" if truncated else ""
    return pages_meta, page_texts, err

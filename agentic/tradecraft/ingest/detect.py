"""The site type of a resource from its start page (port of 1.x ``detect_type``; ``detect_type``
below keeps 1.x's signature for the workspace importer).

The same rules in the same order: a CVE archive, a GitHub repository, MkDocs or mdBook,
Sphinx or Docusaurus, GitBook, else a website for the crawl. The archive threshold is
``detection.cveArchiveThreshold`` (20, as 1.x) and a person can turn a detector off
(``detection.enabledDetectors``); with the defaults the answer equals 1.x's. A PDF is told
by its content, not here (``fetch.FetchedPage.is_pdf``).
"""

from __future__ import annotations

import re
import urllib.parse

from tradecraft.settings import EffectiveSettings

WEBSITE = "agentic-crawl"
_CVE_ID_ANYWHERE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_GITHUB_REPO_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)")

_MKDOCS_MARKERS = (
    'name="generator" content="mkdocs', 'name="generator" content="material',
    "<!-- book generated using mdbook -->", 'class="mdbook"', "mdbook.js",
)
_SPHINX_MARKERS = (
    'name="generator" content="docutils', "_static/searchindex.js", "searchindex.js",
    'name="generator" content="docusaurus', "docusaurus.config",
)
_GITBOOK_MARKERS = (
    'application-name" content="gitbook"', 'name="generator" content="gitbook',
    "static-2v.gitbook.com", "static.gitbook.com", "data-rsc-router",
)


def detect(url: str, raw_html: str, status: int, settings: EffectiveSettings) -> str:
    """One of ``cve-poc-db``, ``github-repo``, ``mkdocs-wiki``, ``sphinx-docs``, ``gitbook`` or
    ``agentic-crawl``. ``raw_html`` is the page before cleaning: the markers live in meta tags
    and comments that the Markdown drops."""
    enabled = set(settings.list("detection.enabledDetectors"))
    threshold = settings.int("detection.cveArchiveThreshold")
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return WEBSITE
    body = raw_html or ""
    body_lc = body.lower()

    # An archive of many CVEs laid out as {year}/{CVE}.md; a repository about one or two CVEs
    # is a plain repository (its README may repeat their ids many times).
    if "cve" in enabled and "github.com" in host:
        m = _GITHUB_REPO_RE.match(url)
        if m and re.search(r"cve", m.group(2), re.IGNORECASE) and not _CVE_ID_ANYWHERE_RE.search(m.group(2)):
            return "cve-poc-db"
        distinct = {c.upper() for c in _CVE_ID_ANYWHERE_RE.findall(body)}
        if len(distinct) > threshold:
            return "cve-poc-db"
    if "github" in enabled and host in ("github.com", "raw.githubusercontent.com"):
        return "github-repo"
    if "mkdocs" in enabled and any(m in body_lc for m in _MKDOCS_MARKERS):
        return "mkdocs-wiki"
    # ReadTheDocs always serves Sphinx: the host alone decides.
    if "sphinx" in enabled and (host.endswith(".readthedocs.io") or any(m in body_lc for m in _SPHINX_MARKERS)):
        return "sphinx-docs"
    if "gitbook" in enabled and ("gitbook.io" in host or any(m in body_lc for m in _GITBOOK_MARKERS)):
        return "gitbook"
    return WEBSITE


def detect_type(url: str, body: str, status: int = 200) -> str:
    """``detect`` with the default settings: 1.x's signature and answer, for the workspace
    importer, which tells a docs site from a website by it (``workspace_import/detect.py``)."""
    return detect(url, body, status, EffectiveSettings({}))

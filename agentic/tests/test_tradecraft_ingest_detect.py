"""Site-type detection (T1.6): with the default settings, the same answer 1.x's ``detect_type``
gave on every fixture site (the expected types below, which 1.x answered until the cut-over
deleted it); ``detect_type`` keeps its signature for the workspace importer (T9.2); the archive
threshold and the detectors are settings.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.ingest.detect import detect, detect_type, generators  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher, run  # noqa: E402

SITES = {
    "https://wiki.tc-fixture.test/": "mkdocs-wiki",
    "https://docs.tc-fixture.test/": "sphinx-docs",
    "https://book.tc-fixture.test/": "gitbook",
    "https://github.com/tc-fixture/payloads": "github-repo",
    "https://github.com/tc-fixture/cve": "cve-poc-db",
    "https://blog.tc-fixture.test/": "agentic-crawl",
}


@pytest.mark.parametrize("url,expected", sorted(SITES.items()))
def test_same_type_as_1x(url, expected):
    fetcher = FixtureFetcher()
    with net.use_fetcher(fetcher):
        resp = run(fetcher.get(url))
    assert resp.status == 200
    html = resp.text
    assert detect_type(url, html, resp.status) == expected
    assert detect(url, html, resp.status, EffectiveSettings()) == expected


def _cve_body(n):
    return " ".join(f"CVE-2023-{1000 + i}" for i in range(n))


def test_cve_archive_threshold_is_a_setting():
    url = "https://github.com/tc-fixture/notes"
    assert detect(url, _cve_body(21), 200, EffectiveSettings()) == "cve-poc-db"
    assert detect_type(url, _cve_body(21), 200) == "cve-poc-db"
    assert detect(url, _cve_body(20), 200, EffectiveSettings()) == "github-repo"
    assert detect(url, _cve_body(21), 200, EffectiveSettings({"detection.cveArchiveThreshold": 50})) == "github-repo"


def test_a_repository_named_for_one_cve_is_a_repository():
    for url in ("https://github.com/tc-fixture/CVE-2024-1234-poc", "https://github.com/tc-fixture/cve-2021-0001"):
        assert detect(url, "", 200, EffectiveSettings()) == detect_type(url, "", 200) == "github-repo"


def test_a_detector_turned_off_is_skipped():
    html = '<meta name="generator" content="mkdocs-1.6.0">'
    off = EffectiveSettings({"detection.enabledDetectors": ["sphinx", "gitbook", "github", "cve"]})
    assert detect("https://wiki.tc-fixture.test/", html, 200, EffectiveSettings()) == "mkdocs-wiki"
    assert detect("https://wiki.tc-fixture.test/", html, 200, off) == "agentic-crawl"
    no_github = EffectiveSettings({"detection.enabledDetectors": ["mkdocs"]})
    assert detect("https://github.com/tc-fixture/cve", "", 200, no_github) == "agentic-crawl"


def test_readthedocs_host_alone_is_sphinx():
    assert detect("https://tool.readthedocs.io/en/latest/", "", 200, EffectiveSettings()) == "sphinx-docs"


# A Hugo site whose search script is also named searchindex.js (an elasticlunr bundle, not
# Sphinx's index): the shape of the page that made a Hugo docs preset a homepage-only map.
HUGO_HOME = ('<!doctype html><html><head><meta charset="utf-8"><meta name="generator" content="Hugo 0.139.3">'
             '<title>Lab proxy docs</title><script src="/stable/searchindex.js" defer></script></head>'
             "<body><main><h1>Lab proxy</h1><p>Synthetic docs page.</p></main></body></html>")


def test_a_page_of_another_generator_that_loads_searchindex_js_is_not_sphinx():
    url = "https://hugo-docs.tc-fixture.test/stable/"
    assert detect(url, HUGO_HOME, 200, EffectiveSettings()) == "agentic-crawl"
    assert detect_type(url, HUGO_HOME, 200) == "agentic-crawl"
    # The generator meta written the other way round, with single quotes, still names Hugo,
    # and it outweighs even the path Sphinx itself would use.
    reversed_meta = ("<html><head><meta content='Hugo 0.139.3' name='generator'>"
                     '<script src="_static/searchindex.js"></script></head><body></body></html>')
    assert detect(url, reversed_meta, 200, EffectiveSettings()) == "agentic-crawl"
    # No generator at all: a file of that name alone says nothing about Sphinx.
    bare = '<html><head><script src="/searchindex.js"></script></head><body><p>docs</p></body></html>'
    assert detect(url, bare, 200, EffectiveSettings()) == "agentic-crawl"


def test_sphinx_markers_still_detect_sphinx():
    url = "https://sphinx2.tc-fixture.test/"
    sphinx = {
        "docutils generator": '<meta name="generator" content="Docutils 0.20.1: https://docutils.sourceforge.io/" />',
        "Sphinx's own index path": '<script src="_static/searchindex.js"></script>',
        "the search page": ('<script src="_static/documentation_options.js"></script>'
                            '<script src="_static/searchtools.js"></script><script src="searchindex.js" defer></script>'),
        "an inline index": '<script src="searchindex.js"></script><script>Search.setIndex({"docnames": []})</script>',
        "a sphinx generator": ('<meta name="generator" content="sphinx-7.2.6, furo 2024.01.29">'
                               '<script src="searchindex.js"></script>'),
        "doctools beside it": '<script src="_static/doctools.js"></script><script src="searchindex.js"></script>',
    }
    for why, head in sphinx.items():
        page = f"<html><head>{head}</head><body><p>docs</p></body></html>"
        assert detect(url, page, 200, EffectiveSettings()) == "sphinx-docs", why
        assert detect_type(url, page, 200) == "sphinx-docs", why
    # Docusaurus keeps its place in the same detector.
    docusaurus = '<html><head><meta name="generator" content="Docusaurus v3.5.2"></head><body></body></html>'
    assert detect(url, docusaurus, 200, EffectiveSettings()) == "sphinx-docs"
    # The detector turned off still turns every one of them off.
    off = EffectiveSettings({"detection.enabledDetectors": ["mkdocs", "gitbook", "github", "cve"]})
    assert detect(url, f"<html><head>{sphinx['the search page']}</head></html>", 200, off) == "agentic-crawl"


def test_generator_metas_are_read_in_one_bounded_pass():
    """Detection runs on the job's event loop, and a page is the site's to shape: a pattern over
    the whole page is quadratic on unclosed <meta tags. Each tag is read up to 2,000 characters,
    and only the first 1,000 tags."""
    hostile = "<html><head>" + "<meta " * 20_000 + '<script src="searchindex.js"></script></head></html>'
    assert generators(hostile) == []
    assert detect("https://x.tc-fixture.test/", hostile, 200, EffectiveSettings()) == "agentic-crawl"
    page = ('<meta charset="utf-8"><meta content="Hugo 0.139.3" name="generator">'
            "<META NAME=Generator CONTENT=Sphinx-7.2>")
    assert generators(page) == ["hugo 0.139.3", "sphinx-7.2"]
    late = '<meta name="viewport" content="width=device-width">' * 1000 + '<meta name="generator" content="Hugo">'
    assert generators(late) == []
    assert generators('<meta name="generator" content="' + "x" * 3000 + '">') == []


def test_markers_live_in_the_raw_html_not_the_markdown():
    # The mdBook marker is a comment: cleaning drops it, so detection reads the raw page.
    html = "<!-- Book generated using mdBook --><html><body><p>hi</p></body></html>"
    assert detect("https://book2.tc-fixture.test/", html, 200, EffectiveSettings()) == "mkdocs-wiki"
    # A URL that does not parse is a website, never an exception.
    assert detect("http://[::1/", html, 200, EffectiveSettings()) == "agentic-crawl"

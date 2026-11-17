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
from tradecraft.ingest.detect import detect, detect_type  # noqa: E402
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


def test_markers_live_in_the_raw_html_not_the_markdown():
    # The mdBook marker is a comment: cleaning drops it, so detection reads the raw page.
    html = "<!-- Book generated using mdBook --><html><body><p>hi</p></body></html>"
    assert detect("https://book2.tc-fixture.test/", html, 200, EffectiveSettings()) == "mkdocs-wiki"
    # A URL that does not parse is a website, never an exception.
    assert detect("http://[::1/", html, 200, EffectiveSettings()) == "agentic-crawl"

"""Real page titles (T6.1, §4.3, R-073): off by default, at most ``knownTypes.maxTitleFetches``
downloads, no second request for a page that is downloaded anyway, and cleaned titles."""

from __future__ import annotations

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.ingest import titles  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402
from tradecraft_job_harness import JobHarness  # noqa: E402

REPO = "https://github.com/tc-fixture/payloads"
WIKI = "https://wiki.tc-fixture.test/"
RAW = "https://raw.githubusercontent.com/tc-fixture/payloads/main/"


def _raw_requests(h):
    return [u for u in h.requested() if u.startswith(RAW)]


def _twice(h, start):
    """The URLs requested more than once, but the start page (fetch_home reads it before the map)."""
    counts = collections.Counter(h.requested())
    return [u for u, n in counts.items() if n > 1 and u != start]


def test_off_by_default(tmp_path):
    h = JobHarness(tmp_path, REPO)
    assert h.run().status == "succeeded"
    by_url = h.live_by_url()
    union = by_url[RAW + "sqli/union.md"]
    assert union["title"] == "sqli > union" and union["title_source"] == "guessed"
    # A Live repository reads no file to map it: with the setting off, nothing is downloaded for titles.
    assert _raw_requests(h) == []
    assert "titles" in h.stages


def test_on_takes_the_files_own_heading(tmp_path):
    h = JobHarness(tmp_path, REPO, settings={"knownTypes.realTitles": True})
    h.run()
    by_url = h.live_by_url()
    assert by_url[RAW + "sqli/union.md"]["title"] == "Union-based"
    assert by_url[RAW + "sqli/union.md"]["title_source"] == "real"
    assert by_url[RAW + "xss/polyglots.md"]["title"] == "Polyglots"
    report = h.row["ingestion_report"]
    assert report["readiness"]["realTitlesPct"] == 100


def test_limit(tmp_path):
    h = JobHarness(tmp_path, REPO, settings={"knownTypes.realTitles": True, "knownTypes.maxTitleFetches": 2})
    h.run()
    assert len(_raw_requests(h)) == 2
    sources = collections.Counter(e["title_source"] for e in h.live())
    assert sources["real"] == 2 and sources["guessed"] == len(h.live()) - 2


def test_stored_no_second_request(tmp_path):
    h = JobHarness(tmp_path, REPO, mode="stored", settings={"knownTypes.realTitles": True})
    h.run()
    assert _twice(h, REPO) == []
    union = h.live_by_url()[RAW + "sqli/union.md"]
    assert union["title"] == "Union-based" and union["title_source"] == "real"
    assert union["stored_text"].startswith("# Union-based")


def test_stored_wiki_takes_the_title_from_the_stored_download(tmp_path):
    h = JobHarness(tmp_path, WIKI, mode="stored", settings={"knownTypes.realTitles": True})
    h.run()
    assert _twice(h, WIKI) == []
    page = h.live_by_url()[WIKI + "sqli/union-based/"]
    assert page["title"] == "SQL injection: Union based" and page["title_source"] == "real"


def test_live_wiki_card_pass_pages_are_not_fetched_twice(tmp_path):
    h = JobHarness(tmp_path, WIKI, settings={"knownTypes.realTitles": True})
    h.run()
    assert _twice(h, WIKI) == []
    assert h.live_by_url()[WIKI + "sqli/union-based/"]["title_source"] == "real"


def test_a_website_is_never_retitled(tmp_path):
    blog = "https://blog.tc-fixture.test/"
    h = JobHarness(tmp_path, blog, settings={"knownTypes.realTitles": True, "crawl.strategy": "rules",
                                             "crawl.maxPages": 5})
    h.run()
    # The crawl read every page it kept and took its title then: nothing is downloaded again.
    assert _twice(h, blog) == []
    assert h.live() and all(e["title_source"] == "real" for e in h.live())


def test_renamed_page_keeps_the_persons_title(tmp_path):
    class Renaming(JobHarness):
        pass

    h = Renaming(tmp_path, REPO, settings={"knownTypes.realTitles": True})
    from tradecraft.ingest import curation

    async def rename(state):
        for e in state.entries:
            if e.url == RAW + "sqli/union.md":
                e.title = "My union notes"
                e.extra["title_source"] = "renamed"
        return state

    original = curation.apply
    curation.apply = rename
    try:
        h.run()
    finally:
        curation.apply = original
    union = h.live_by_url()[RAW + "sqli/union.md"]
    assert union["title"] == "My union notes" and union["title_source"] == "renamed"
    assert RAW + "sqli/union.md" not in _raw_requests(h)


# --------------------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------------------

def _page(title="", h1="", body=""):
    head = f"<title>{title}</title>" if title else ""
    h = f"<h1>{h1}</h1>" if h1 else ""
    return f"<html><head>{head}</head><body><nav><h1>Menu</h1></nav>{h}{body}</body></html>"


def test_title_cleaning():
    # The first h1 of the article (a menu's is not the page's), else the <title>; one line, entities read.
    assert titles.html_title(_page("T - Site", "Kerberoasting  &amp;\n  AS-REP")) == ("Kerberoasting & AS-REP", False)
    assert titles.html_title(_page("Kerberoasting &mdash; Site")) == ("Kerberoasting — Site", True)
    assert titles.html_title("") == ("", False)
    assert len(titles.html_title(_page("x" * 1000))[0]) == titles.MAX_CHARS

    # A suffix most <title>s share is the site's name: removed; a title's own separator stays.
    found = {
        "a": ("Union based - TC Wiki", True),
        "b": ("Error based - TC Wiki", True),
        "c": ("Blind - time based - TC Wiki", True),
        "d": ("Out of band | Other", True),
        "e": ("Heading from h1 - part two", False),
    }
    assert titles.cleaned(found) == {"a": "Union based", "b": "Error based", "c": "Blind - time based",
                                     "d": "Out of band | Other", "e": "Heading from h1 - part two"}
    # One page alone cannot tell its suffix from its title.
    assert titles.cleaned({"a": ("Union - based", True)}) == {"a": "Union - based"}
    # A title most pages share (an app shell's) is no page's title: the guess stays.
    shell = {u: ("Docs portal", True) for u in "abcd"}
    shell["e"] = ("Kerberos", True)
    assert titles.cleaned(shell) == {"e": "Kerberos"}


def test_markdown_title():
    assert titles.markdown_title("intro\n\n## Sub\n\n# Main **title**\n") == "Main title"
    assert titles.markdown_title("```\n# not a title\n```\n## Only [sub](x)\n") == "Only sub"
    assert titles.markdown_title("Setext title\n============\n\ntext") == "Setext title"
    assert titles.markdown_title("plain text, no heading") == ""


def test_collect_needs_the_setting_and_a_stored_resource():
    class S:
        site_type, storage_mode = "github-repo", "stored"

        class settings:
            @staticmethod
            def bool(key):
                return key == "knownTypes.realTitles"

    entry = Candidate(RAW + "a.md", "a", "tree", "a.md")
    titles.collect(S, entry, text="# Real", content_type="text/markdown")
    assert entry.extra["_real_title"] == ("Real", False)
    S.storage_mode = "live"
    other = Candidate(RAW + "b.md", "b", "tree", "b.md")
    titles.collect(S, other, text="# Real", content_type="text/markdown")
    assert "_real_title" not in other.extra

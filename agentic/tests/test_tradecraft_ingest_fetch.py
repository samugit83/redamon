"""Ingestion fetching (T1.6): the two tiers, the GitHub token's hosts, the address guard,
the start page's pre-flight, and the Markdown cleaning shared with the reader.

Every request goes to the fixture sites through ``FixtureFetcher``; no socket is opened.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers.web_sources import html_to_markdown  # noqa: E402
from tradecraft import net  # noqa: E402
from tradecraft.ingest import fetch  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE, FixtureFetcher, run  # noqa: E402

TOKEN = "ghp_fake_token_for_tests"
WIKI = "https://wiki.tc-fixture.test/"


def settings(**values):
    return EffectiveSettings(values)


@pytest.fixture
def fixture_fetcher():
    f = FixtureFetcher()
    with net.use_fetcher(f):
        yield f


def sent_headers(fetcher, url_part):
    return [h for u, h in fetcher.requests if url_part in u]


def test_tier1_page_is_cleaned_to_markdown(fixture_fetcher):
    # The fixture pages are short: a threshold of 0 keeps them on tier 1.
    page = run(fetch.smart_fetch(WIKI + "sqli/union-based/", settings(**{"fetching.browserBelowChars": 0})))
    assert page.error == "" and page.status == 200 and page.tier == 1
    assert "mkdocs" in page.html.lower()            # the raw page, for detection
    assert "<" not in page.text and page.text.strip()
    assert fixture_fetcher.browser.renders == []


def test_thin_page_goes_to_the_browser(fixture_fetcher):
    url = "https://blog.tc-fixture.test/posts/42-js-only/"
    tier1 = run(fixture_fetcher.get(url))
    assert tier1.status == 200
    page = run(fetch.smart_fetch(url, settings()))
    assert page.tier == 2 and fixture_fetcher.browser.renders == [url]
    assert len(page.text) > len(html_to_markdown(tier1.text))


def test_browser_off_keeps_tier_one(fixture_fetcher):
    url = "https://blog.tc-fixture.test/posts/42-js-only/"
    page = run(fetch.smart_fetch(url, settings(**{"fetching.browserEnabled": False})))
    assert page.tier == 1 and fixture_fetcher.browser.renders == []
    page = run(fetch.smart_fetch(url, settings(), allow_browser=False))
    assert page.tier == 1 and fixture_fetcher.browser.renders == []


def test_always_browser_skips_tier_one(fixture_fetcher):
    page = run(fetch.smart_fetch(WIKI, settings(**{"fetching.alwaysBrowser": True})))
    assert page.tier == 2 and fixture_fetcher.requests == [] and fixture_fetcher.browser.renders == [WIKI]


def test_threshold_comes_from_settings(fixture_fetcher):
    url = WIKI + "sqli/union-based/"
    run(fetch.smart_fetch(url, settings(**{"fetching.browserBelowChars": 20_000})))
    assert fixture_fetcher.browser.renders == [url]


def test_github_token_hosts(fixture_fetcher):
    """R-114: the token reaches github.com, api.github.com and raw.githubusercontent.com over
    https, never another host, plain http, or a hop to another host."""
    s = settings()
    run(fetch.smart_fetch("https://github.com/tc-fixture/payloads", s, github_token=TOKEN))
    run(fetch.fetch_raw("https://api.github.com/repos/tc-fixture/payloads", s, github_token=TOKEN))
    run(fetch.smart_fetch("https://github.com/tc-fixture/payloads/blob/main/sqli/union.md", s, github_token=TOKEN))
    for host in ("//github.com/", "//api.github.com/", "//raw.githubusercontent.com/"):
        hops = sent_headers(fixture_fetcher, host)
        assert hops and all(h.get("authorization") == f"token {TOKEN}" for h in hops), host

    before = len(fixture_fetcher.requests)
    run(fetch.smart_fetch(WIKI, s, github_token=TOKEN))
    run(fetch.smart_fetch("http://github.com/tc-fixture/payloads", s, github_token=TOKEN))
    for _url, headers in fixture_fetcher.requests[before:]:
        assert "authorization" not in headers

    # github.com redirects the archive to codeload: that hop gets no token.
    before = len(fixture_fetcher.requests)
    run(fetch.fetch_raw("https://github.com/tc-fixture/payloads/archive/refs/heads/main.tar.gz", s, github_token=TOKEN))
    first, second = fixture_fetcher.requests[before:]
    assert first[1].get("authorization") == f"token {TOKEN}"
    assert "codeload.github.com" in second[0] and "authorization" not in second[1]


def test_a_look_alike_host_never_gets_the_token():
    assert fetch.github_headers("https://github.com.tc-fixture.test/x", TOKEN) == {}
    assert fetch.github_headers("https://raw.githubusercontent.com.evil.test/x", TOKEN) == {}
    assert fetch.github_headers("https://api.github.com/x", None) == {}


def test_private_address_refused(fixture_fetcher):
    s = settings()
    page = run(fetch.smart_fetch("http://169.254.169.254/latest/meta-data/", s))
    assert page.error == "unsafe_address" and fetch.homepage_problem(page, s) == "blocked_private_address"
    # A redirect into internal space stops before the second hop and before the browser.
    page = run(fetch.smart_fetch("https://contract.tc-fixture.test/to-private", s))
    assert page.error == "unsafe_address"
    assert [u for u, _ in fixture_fetcher.requests] == ["https://contract.tc-fixture.test/to-private"]
    assert fixture_fetcher.browser.renders == []


def test_login_in_url_refused(fixture_fetcher):
    s = settings()
    page = run(fetch.smart_fetch("https://user:pw@wiki.tc-fixture.test/", s))
    assert fetch.homepage_problem(page, s) == "userinfo_refused"
    assert fixture_fetcher.requests == [] and fixture_fetcher.browser.renders == []


def test_thin_homepage(fixture_fetcher):
    s = settings(**{"fetching.browserEnabled": False})
    page = run(fetch.smart_fetch("https://files.tc-fixture.test/", s))
    assert page.status == 200 and fetch.homepage_problem(page, s) == "thin_homepage"
    lenient = settings(**{"fetching.browserEnabled": False, "detection.thinHomepageChars": 0})
    assert fetch.homepage_problem(page, lenient) == ""


def test_homepage_errors(fixture_fetcher):
    s = settings(**{"fetching.browserEnabled": False})
    missing = run(fetch.smart_fetch("https://contract.tc-fixture.test/missing.html", s))
    assert fetch.homepage_problem(missing, s) == "homepage_http_error"
    down = run(fetch.smart_fetch("https://down.tc-fixture.test/", s))
    assert fetch.homepage_problem(down, s) == "fetch_failed"


def test_pdf_is_not_sent_to_the_browser(fixture_fetcher):
    page = run(fetch.smart_fetch("https://files.tc-fixture.test/guide.pdf", settings()))
    assert page.is_pdf and page.body[:5] == b"%PDF-" and page.tier == 1
    assert fixture_fetcher.browser.renders == []
    assert fetch.homepage_problem(page, settings()) == ""


def test_request_headers_from_settings(fixture_fetcher):
    s = settings(**{"fetching.userAgent": "TC-Test-Agent/9", "fetching.acceptLanguage": "it"})
    run(fetch.fetch_raw(WIKI, s))
    headers = fixture_fetcher.requests[-1][1]
    assert headers["user-agent"] == "TC-Test-Agent/9" and headers["accept-language"] == "it"
    run(fetch.fetch_raw(WIKI, settings()))
    assert fixture_fetcher.requests[-1][1]["user-agent"] == "RedAmon-Tradecraft/1.0"
    assert "accept-language" not in fixture_fetcher.requests[-1][1]


def test_clean_page_is_1x_without_options():
    html = (Path(__file__).resolve().parent / "fixtures" / "tradecraft_sites" / "blog.tc-fixture.test" /
            "posts" / "17-misc-note-17" / "index.html").read_text()
    assert fetch.clean_page(html) == html_to_markdown(html)


def test_clean_page_body_selector_and_removals():
    html = ("<html><body><nav>menu</nav><div class='ad'>buy now</div>"
            "<div id='doc'><h1>Title</h1><p>short body</p><div class='ad'>more ads</div></div>"
            f"<footer>{FAKE_COOKIE}</footer></body></html>")
    text = fetch.clean_page(html, body_selector="#doc", remove=(".ad",))
    assert "Title" in text and "short body" in text
    assert "buy now" not in text and "more ads" not in text and "menu" not in text
    # A selector that does not parse is skipped, not raised.
    assert "Title" in fetch.clean_page(html, body_selector="#doc", remove=("[[[",))


def test_canonical_url():
    assert fetch.canonical_url("HTTPS://Wiki.TC-Fixture.test:443/A/b?x=1#frag") == "https://wiki.tc-fixture.test/A/b?x=1"
    assert fetch.canonical_url("http://wiki.tc-fixture.test") == "http://wiki.tc-fixture.test/"
    assert fetch.canonical_url("http://wiki.tc-fixture.test:8080/x") == "http://wiki.tc-fixture.test:8080/x"
    assert fetch.canonical_url("http://[::1]:8080/x") == "http://[::1]:8080/x"
    assert not fetch.entry_url_ok("https://wiki.tc-fixture.test/" + "a" * 2100)
    assert not fetch.entry_url_ok("javascript:alert(1)")

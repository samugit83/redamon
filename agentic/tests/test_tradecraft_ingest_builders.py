"""Map builders (T1.6): on every fixture site, at least as many distinct entries as the 1.x
builder found on the same fixture, with every cap read from the settings.

The 1.x builders left with the cut-over (T9.2); what they found on these fixture sites, read
through the same ``FixtureFetcher``, is frozen in ``fixtures/tradecraft_legacy/oracle_1x.json``
(recorded by S13 from the 1.x code just before it was deleted), so the comparison stands.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.ingest import builders, fetch  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher, run  # noqa: E402

TOKEN = "ghp_fake_token_for_tests"
# What 1.x's builders found on each fixture site (URLs resolved as 1.x reads them).
ORACLE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_legacy" / "oracle_1x.json")
                    .read_text())["builders"]


@pytest.fixture
def fixtures():
    fetcher = FixtureFetcher()
    with net.use_fetcher(fetcher):
        yield fetcher


def s(**values):
    return EffectiveSettings(values)


# --------------------------------------------------------------------------------------
# At least as many entries as 1.x, per type
# --------------------------------------------------------------------------------------

def test_wiki_matches_1x(fixtures):
    url = "https://wiki.tc-fixture.test/"
    new = run(builders.build_wiki(url, s()))
    assert new.type == "mkdocs-wiki" and new.index_kind == "sitemap"
    old_urls = set(ORACLE["wiki"]["urls"])
    assert old_urls and len(new.entries) >= len(old_urls)
    assert old_urls <= {e.url for e in new.entries}
    assert all(e.source == "sitemap" and e.title for e in new.entries)


def test_docs_matches_1x(fixtures):
    url = "https://docs.tc-fixture.test/"
    new = run(builders.build_docs(url, s()))
    old_urls = set(ORACLE["docs"]["urls"])
    assert old_urls and {e.url for e in new.entries} >= old_urls
    assert new.meta["indexUrl"] == ORACLE["docs"]["indexUrl"] and new.index_kind == "searchindex"
    titles = {e.title for e in new.entries}
    assert set(ORACLE["docs"]["titles"]) <= titles


def test_docs_index_with_entries_is_used_as_before(fixtures):
    """An index that lists pages builds the map as it always did, names itself in the report,
    and no sitemap is read."""
    new = run(builders.build_docs("https://docs.tc-fixture.test/", s()))
    assert new.index_kind == "searchindex" and len(new.entries) == len(ORACLE["docs"]["urls"]) == 8
    assert all(e.source == "searchindex" for e in new.entries) and not new.crawl_fallback
    assert new.report_stop == "docs: searchindex (8 pages)"
    assert not [u for u, _ in fixtures.requests if u.endswith(("/sitemap.xml", "/robots.txt"))]


# A Hugo docs site: its searchindex.js is a JavaScript bundle of another search library, and its
# sitemap lists its pages, another version's and another host's.
HUGO = "hugo-docs.tc-fixture.test"
HUGO_URL = f"https://{HUGO}/stable/"
HUGO_PAGES = [HUGO_URL] + [f"{HUGO_URL}{p}/" for p in ("overview", "concepts/filters", "howto/transparent", "api")]
ELASTICLUNR_BUNDLE = ("window.docsSearch = (function(){\n    /** elasticlunr - synthetic bundle */\n"
                      '    var lunr = function (config) { return config; };\n    var data = {"version": "0.9.5"};\n'
                      "    return lunr(data);\n})();\n")


def _urlset(urls):
    return ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{u}</loc></url>" for u in urls) + "</urlset>")


def _hugo_files(**extra):
    files = {
        "stable/index.html": '<html><head><meta name="generator" content="Hugo 0.139.3"><title>Lab proxy</title></head></html>',
        "stable/searchindex.js": ELASTICLUNR_BUNDLE,
        "stable/sitemap.xml": _urlset(HUGO_PAGES + [f"https://{HUGO}/v9/overview/", "https://other-docs.tc-fixture.test/stable/x/"]),
    }
    files.update(extra)
    return files


def test_docs_without_a_sphinx_index_maps_its_sitemap(tmp_path):
    with net.use_fetcher(_site(tmp_path, HUGO, _hugo_files())):
        new = run(builders.build_docs(HUGO_URL, s()))
    assert new.type == "sphinx-docs" and new.index_kind == "sitemap" and not new.crawl_fallback
    # Only the resource's own pages: not another version's folder, not another host.
    assert [e.url for e in new.entries] == HUGO_PAGES
    assert all(e.source == "sitemap" and e.title for e in new.entries)
    assert new.index_url == f"{HUGO_URL}sitemap.xml" and new.meta == {"indexUrl": ""}
    assert new.report_stop == "docs: no search index, sitemap.xml (5 pages)"
    assert new.note == "docs_index_unusable" and not new.error


def test_docs_sitemap_named_by_robots_and_the_map_limit(tmp_path):
    pages = [HUGO_URL] + [f"{HUGO_URL}page-{i}/" for i in range(101)]
    files = _hugo_files(**{"robots.txt": f"User-agent: *\nSitemap: https://{HUGO}/maps/docs.xml\n",
                           "maps/docs.xml": _urlset(pages)})
    with net.use_fetcher(_site(tmp_path, HUGO, files)):
        robots_first = run(builders.build_docs(HUGO_URL, s()))
        capped = run(builders.build_docs(HUGO_URL, s(**{"knownTypes.maxMapEntries.docs": 100})))
    assert [e.url for e in robots_first.entries] == pages and not robots_first.truncated
    assert robots_first.report_stop == "docs: no search index, robots (102 pages)"
    assert robots_first.index_url == f"https://{HUGO}/maps/docs.xml"
    assert [e.url for e in capped.entries] == pages[:100] and capped.truncated
    assert capped.report_stop == "docs: no search index, robots (100 pages, map limit)"


def test_docs_with_no_index_and_no_usable_sitemap_asks_for_the_crawl(tmp_path):
    """Read the Docs' root sitemap lists only version roots: inside the resource's folder that is
    the start page alone, which is no map; nothing at all is no map either."""
    host = "rtd-like.tc-fixture.test"
    roots = _urlset([f"https://{host}/en/latest/", f"https://{host}/en/stable/", f"https://{host}/fr/latest/"])
    files = {"en/latest/index.html": "<html><body>docs</body></html>", "robots.txt": f"Sitemap: https://{host}/sitemap.xml\n",
             "sitemap.xml": roots, "en/latest/searchindex.js": "Search.setIndex(not json)"}
    with net.use_fetcher(_site(tmp_path, host, files)):
        only_home = run(builders.build_docs(f"https://{host}/en/latest/", s()))
    assert only_home.entries == [] and only_home.crawl_fallback and only_home.index_kind == "none"
    assert only_home.note == "docs_index_unusable" and not only_home.error
    with net.use_fetcher(_site(tmp_path, "bare-docs.tc-fixture.test", {"index.html": "<html></html>"})):
        nothing = run(builders.build_docs("https://bare-docs.tc-fixture.test/", s()))
    assert nothing.entries == [] and nothing.crawl_fallback


def test_gitbook_matches_1x(fixtures):
    url = "https://book.tc-fixture.test/"
    new = run(builders.build_gitbook(url, s()))
    old_urls = set(ORACLE["gitbook"]["urls"])
    assert old_urls and {e.url for e in new.entries} >= old_urls


def test_github_matches_1x(fixtures):
    url = "https://github.com/tc-fixture/payloads"
    old = ORACLE["github"]
    new = run(builders.build_github(url, s(), github_token=TOKEN))
    assert not new.error and new.meta == {"owner": "tc-fixture", "repo": "payloads", "branch": old["branch"]}
    assert set(old["paths"]) == {e.path for e in new.entries}
    assert set(old["titles"]) == {e.title for e in new.entries}
    # The entry URL is what a read fetches: the raw file.
    assert all(e.url.startswith("https://raw.githubusercontent.com/tc-fixture/payloads/main/") for e in new.entries)
    # The token went only to GitHub's API host.
    api = [h for u, h in fixtures.requests if "api.github.com" in u]
    assert api and all(h.get("authorization") == f"token {TOKEN}" for h in api)


def test_cve_matches_1x(fixtures):
    url = "https://github.com/tc-fixture/cve"
    new = run(builders.build_known("cve-poc-db", url, s()))
    assert new.type == "cve-poc-db" and not new.retype and new.entries == []
    assert new.meta == ORACLE["cve"]


def test_cve_without_year_folders_is_retyped(fixtures):
    url = "https://github.com/tc-fixture/payloads"
    # 1.x saw the same thing: the repository has no year folders.
    assert ORACLE["cve_on_a_repo_without_year_folders"] == {"no_year_dirs": True}
    new = run(builders.build_known("cve-poc-db", url, s()))
    assert new.retype == "github-repo" and new.type == "github-repo" and new.entries


def test_pdf_pages(fixtures):
    url = "https://files.tc-fixture.test/guide.pdf"
    body = run(fixtures.get(url)).body
    old = ORACLE["pdf"]
    texts = old["texts"]
    result = run(builders.build_pdf(url, body, s()))
    assert not old["error"] and not result.error
    assert len(result.entries) == old["pages"] == 3
    assert [e.extra["page"] for e in result.entries] == [1, 2, 3]
    assert [e.extra["text"] for e in result.entries] == texts
    assert result.entries[0].url == url + "#page=1" and result.entries[0].source == "pdf"
    assert result.meta["totalPages"] == 3


def test_pdf_page_range_settings(fixtures):
    url = "https://files.tc-fixture.test/guide.pdf"
    body = run(fixtures.get(url)).body
    only_second = run(builders.build_pdf(url, body, s(**{"type.pdf.firstPage": 2, "type.pdf.lastPage": 2})))
    assert [e.extra["page"] for e in only_second.entries] == [2]
    skipped = run(builders.build_pdf(url, body, s(**{"type.pdf.skipPages": "1, 3"})))
    assert [e.extra["page"] for e in skipped.entries] == [2]
    capped = run(builders.build_pdf(url, body, s(**{"knownTypes.pdfMaxPages": 2})))
    assert [e.extra["page"] for e in capped.entries] == [1, 2] and capped.truncated
    assert run(builders.build_pdf(url, b"not a pdf", s())).error == "fetch_failed"


# --------------------------------------------------------------------------------------
# Settings act on the builders
# --------------------------------------------------------------------------------------

def test_github_file_types_and_folders(fixtures):
    url = "https://github.com/tc-fixture/payloads"
    yml = run(builders.build_github(url, s(**{"knownTypes.githubFileTypes": [".yml", ".yar"]})))
    assert {e.path for e in yml.entries} == {"recon/subdomains.yml", "xss/filters.yml", "rules/webshell.yar"}
    only_sqli = run(builders.build_github(url, s(**{"type.github.includeFolders": ["sqli"]})))
    assert {e.path for e in only_sqli.entries} == {"sqli/README.md", "sqli/blind.md", "sqli/union.md"}
    no_sqli = run(builders.build_github(url, s(**{"type.github.excludeFolders": ["sqli/"]})))
    assert not any(e.path.startswith("sqli/") for e in no_sqli.entries) and no_sqli.entries


def test_github_branch_setting_skips_the_metadata_call(fixtures):
    run(builders.build_github("https://github.com/tc-fixture/payloads", s(**{"type.github.branch": "main"})))
    assert [u for u, _ in fixtures.requests if "api.github.com" in u] == [
        "https://api.github.com/repos/tc-fixture/payloads/git/trees/main?recursive=1"]


def test_github_failure_is_a_code(fixtures):
    result = run(builders.build_github("https://github.com/tc-fixture/missing-repo", s()))
    assert result.error == "fetch_failed" and result.note == "github_not_found" and result.entries == []
    assert run(builders.build_github("https://wiki.tc-fixture.test/x", s())).error == "bad_url"


def test_language_filter():
    urls = [f"https://w.tc-fixture.test/{lang}/page{i}" for lang in ("en", "fr", "de") for i in range(3)]
    assert builders.language_filter(urls, s()) == urls[:3]
    assert builders.language_filter(urls, s(**{"knownTypes.language": "all"})) == urls
    fr = s(**{"knownTypes.language": "preferred", "knownTypes.preferredLanguage": "fr"})
    assert builders.language_filter(urls, fr) == urls[3:6]
    untagged = ["https://w.tc-fixture.test/a", "https://w.tc-fixture.test/b"]
    assert builders.language_filter(untagged, fr) == untagged


def test_caps_and_duplicates():
    entries = [builders.Candidate(f"https://w.tc-fixture.test/p{i % 150}", "t", "nav") for i in range(300)]
    kept, cut = builders._dedupe(entries, 100)
    assert len(kept) == 100 and cut
    kept, cut = builders._dedupe(entries[:150], 200)
    assert len(kept) == 150 and not cut
    bad = [builders.Candidate("javascript:x", "t", "nav"), builders.Candidate("https://u:p@w.tc-fixture.test/", "t", "nav")]
    assert builders._dedupe(bad, 10) == ([], False)


def test_menu_selector_setting(fixtures, tmp_path):
    url = "https://wiki.tc-fixture.test/"
    page = run(fixtures.get(url))
    default = run(builders.build_wiki(url, s(**{"type.wiki.sitemapUrls": ["/no-such-sitemap.xml"]}),
                                      home_html=page.text, home_final_url=url))
    assert default.index_kind == "nav" and default.entries
    narrow = run(builders.build_wiki(url, s(**{"type.wiki.sitemapUrls": ["/no-such-sitemap.xml"],
                                               "type.wiki.menuSelector": "a[href*='kerberos']"}),
                                     home_html=page.text, home_final_url=url))
    assert narrow.entries and all("kerberos" in e.url for e in narrow.entries)
    assert len(narrow.entries) < len(default.entries)


def _site(tmp_path, host, files):
    for rel, text in files.items():
        p = tmp_path / host / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return FixtureFetcher(root=tmp_path)


def test_sitemap_index_limits(tmp_path):
    host = "maps.tc-fixture.test"
    children = "".join(f"<sitemap><loc>https://{host}/s{i}.xml</loc></sitemap>" for i in range(25))
    files = {"sitemap.xml": f'<?xml version="1.0"?><sitemapindex>{children}</sitemapindex>'}
    for i in range(25):
        files[f"s{i}.xml"] = f'<?xml version="1.0"?><urlset><url><loc>https://{host}/p{i}</loc></url></urlset>'
    with net.use_fetcher(_site(tmp_path, host, files)):
        urls = run(builders.sitemap_urls(f"https://{host}/sitemap.xml", s()))
    # At most 20 children of an index are read (constants.sitemapMaxChildren).
    assert len(urls) == 20


def test_sitemap_with_entities_or_too_big_is_refused(tmp_path, monkeypatch):
    host = "maps2.tc-fixture.test"
    files = {
        "evil.xml": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><urlset><url><loc>https://x/&a;</loc></url></urlset>',
        "big.xml": '<?xml version="1.0"?><urlset>' + "<url><loc>https://maps2.tc-fixture.test/p</loc></url>" * 100 + "</urlset>",
    }
    with net.use_fetcher(_site(tmp_path, host, files)):
        assert run(builders.sitemap_urls(f"https://{host}/evil.xml", s())) == []
        assert len(run(builders.sitemap_urls(f"https://{host}/big.xml", s()))) == 100
        real = builders.constant
        monkeypatch.setattr(builders, "constant", lambda name: 1000 if name == "sitemapMaxBytes" else real(name))
        assert run(builders.sitemap_urls(f"https://{host}/big.xml", s())) == []


def test_parsing_goes_through_blocking(fixtures):
    calls = []

    async def recording(fn, *args):
        calls.append(fn.__name__)
        return fn(*args)

    run(builders.build_wiki("https://wiki.tc-fixture.test/", s(), blocking=recording))
    body = run(fixtures.get("https://files.tc-fixture.test/guide.pdf")).body
    run(builders.build_pdf("https://files.tc-fixture.test/guide.pdf", body, s(), blocking=recording))
    assert "parse_sitemap_xml" in calls and "pdf_pages" in calls


# --------------------------------------------------------------------------------------
# A sitemap index of per-language copies, read within the byte budget
# --------------------------------------------------------------------------------------

POLY = "polyglot.tc-fixture.test"
POLY_MAPS = "polyglot-maps.tc-fixture.test"
LANGS = ("af", "de", "el", "en", "fr")


def _poly_files(child_url):
    """robots.txt names an index on another host listing one child per language, alphabetically,
    as a translated wiki publishes them: English comes fourth."""
    children = {lang: child_url(lang) for lang in LANGS}
    index = ('<?xml version="1.0"?><sitemapindex>'
             + "".join(f"<sitemap><loc>{u}</loc></sitemap>" for u in children.values()) + "</sitemapindex>")
    files = {POLY: {"robots.txt": f"Sitemap: https://{POLY_MAPS}/sitemap.xml\n", "index.html": "<html></html>"},
             POLY_MAPS: {"sitemap.xml": index}}
    for lang, url in children.items():
        pages = [f"https://{POLY}/{lang}/topic-{i}/" for i in range(6)]
        files[POLY_MAPS][url.split(POLY_MAPS + "/", 1)[1]] = _urlset(pages)
    return files, index, len(files[POLY_MAPS][children["af"].split(POLY_MAPS + "/", 1)[1]])


def _poly_site(tmp_path, child_url):
    files, index, child = _poly_files(child_url)
    for host, host_files in files.items():
        fetcher = _site(tmp_path, host, host_files)
    return fetcher, len(index), child


def _budget(monkeypatch, nbytes):
    real = builders.constant
    monkeypatch.setattr(builders, "constant", lambda name: nbytes if name == "sitemapMaxBytes" else real(name))


def _langs(entries):
    return sorted({e.url.split("/")[3] for e in entries})


def test_a_per_language_index_is_read_in_the_preferred_language_first(tmp_path, monkeypatch):
    """The budget holds the index and two children: read in the listed order, it was spent on
    af and de before English, and the language filter then had no English to keep."""
    index_url = f"https://{POLY_MAPS}/sitemap.xml"
    for n, shape in enumerate((lambda lang: f"https://{POLY_MAPS}/{lang}/sitemap.xml",
                               lambda lang: f"https://{POLY_MAPS}/sitemap-{lang}.xml")):

        def build(url, **values):
            fetcher, index, child = _poly_site(tmp_path / f"shape{n}", shape)
            _budget(monkeypatch, index + 2 * child + child // 2)
            with net.use_fetcher(fetcher):
                result = run(builders.build_wiki(url, s(**values)))
            return result, [u for u, _ in fetcher.requests if u.startswith(f"https://{POLY_MAPS}/") and u != index_url]

        auto, read = build(f"https://{POLY}/")
        assert _langs(auto.entries) == ["en"] and len(auto.entries) == 6 and auto.index_kind == "sitemap"
        assert read == [shape("en")]
        french, _ = build(f"https://{POLY}/", **{"knownTypes.language": "preferred", "knownTypes.preferredLanguage": "fr"})
        assert _langs(french.entries) == ["fr"]
        german_folder, _ = build(f"https://{POLY}/de/")
        assert _langs(german_folder.entries) == ["de"]
        # A two-letter folder that names no language of the index leaves English first.
        other_folder, read = build(f"https://{POLY}/go/")
        assert _langs(other_folder.entries) == ["en"] and read == [shape("en")]
        # "all" keeps the listed order, and the budget still stops it after two children.
        every, read = build(f"https://{POLY}/", **{"knownTypes.language": "all"})
        assert _langs(every.entries) == ["af", "de"] and read == [shape(lang) for lang in ("af", "de", "el")]


def test_the_preferred_language_never_lifts_the_budget(tmp_path, monkeypatch):
    fetcher, index, child = _poly_site(tmp_path, lambda lang: f"https://{POLY_MAPS}/{lang}/sitemap.xml")
    # Room for the index and half a child: the English child is cut, so nothing is read, and no
    # other language is read after it.
    _budget(monkeypatch, index + child // 2)
    with net.use_fetcher(fetcher):
        budget = builders.SitemapBudget()
        urls = run(builders.sitemap_urls(f"https://{POLY_MAPS}/sitemap.xml", s(), budget=budget, languages=["en"]))
    assert urls == [] and budget.stopped == "sitemap_limit"
    children = [u for u, _ in fetcher.requests if u.startswith(f"https://{POLY_MAPS}/") and u != f"https://{POLY_MAPS}/sitemap.xml"]
    assert children == [f"https://{POLY_MAPS}/en/sitemap.xml"]


def test_the_other_languages_are_read_when_the_preferred_child_lists_nothing(tmp_path):
    fetcher, _index, _child = _poly_site(tmp_path, lambda lang: f"https://{POLY_MAPS}/{lang}/sitemap.xml")
    (tmp_path / POLY_MAPS / "en" / "sitemap.xml").unlink()
    with net.use_fetcher(fetcher):
        urls = run(builders.sitemap_urls(f"https://{POLY_MAPS}/sitemap.xml", s(), languages=["en"]))
    assert sorted({u.split("/")[3] for u in urls}) == ["af", "de", "el", "fr"]


def test_language_children():
    maps = [f"https://m.tc-fixture.test/{lang}/sitemap.xml" for lang in ("af", "de", "en", "en-us")]
    assert builders.language_children(maps, ["en"]) == (maps[2:], maps[:2])
    assert builders.language_children(maps, []) == (maps, [])
    assert builders.language_children(maps, ["pt"]) == (maps, [])
    # The first language the index has wins: a folder's language, else English.
    assert builders.language_children(maps, ["de", "en"]) == ([maps[1]], [maps[0]] + maps[2:])
    assert builders.language_children(maps, ["go", "en"]) == (maps[2:], maps[:2])
    # Not per-language: one tag only, or few children tagged; the order is kept.
    one = [f"https://m.tc-fixture.test/wp/sitemap-{k}.xml" for k in ("posts", "pages")]
    assert builders.language_children(one, ["en"]) == (one, [])
    few = ["https://m.tc-fixture.test/sitemap-en.xml", "https://m.tc-fixture.test/sitemap-de.xml"] + [
        f"https://m.tc-fixture.test/posts-{i}.xml" for i in range(4)]
    assert builders.language_children(few, ["en"]) == (few, [])
    # Untagged children of a per-language index are read with the preferred ones.
    mixed = ["https://m.tc-fixture.test/sitemap_fr.xml", "https://m.tc-fixture.test/sitemap_en.xml",
             "https://m.tc-fixture.test/images.xml"]
    assert builders.language_children(mixed, ["en"]) == (mixed[1:], mixed[:1])
    assert builders.preferred_languages("https://w.tc-fixture.test/", s()) == ["en"]
    assert builders.preferred_languages("https://w.tc-fixture.test/en/", s()) == ["en"]
    assert builders.preferred_languages("https://w.tc-fixture.test/fr/guide/", s()) == ["fr", "en"]
    assert builders.preferred_languages("https://w.tc-fixture.test/fr/", s(**{"knownTypes.language": "all"})) == []
    assert builders.preferred_languages("https://w.tc-fixture.test/", s(**{
        "knownTypes.language": "preferred", "knownTypes.preferredLanguage": "DE"})) == ["de"]


# --------------------------------------------------------------------------------------
# Titles guessed from a URL
# --------------------------------------------------------------------------------------

def test_slug_titles_are_decoded_once_into_one_clean_line():
    def t(path, strip_html=True):
        return builders.title_from_slug(f"https://w.tc-fixture.test/{path}", strip_html=strip_html)

    assert t("payloads/Server%20Side%20Request%20Forgery") == "Server Side Request Forgery"
    assert t("payloads/Xss%20Injection/") == "Xss Injection"
    assert t("Cross-Site%20Request%20Forgery") == "Cross Site Request Forgery"
    assert t("r%C3%A9sum%C3%A9.html") == "Résumé" and t("r%C3%A9sum%C3%A9.html", strip_html=False) == "Résumé.Html"
    # Decoded once: an encoded percent sign stays one; a plus in a path is a plus.
    assert t("100%2520coverage") == "100%20Coverage"
    assert t("C%2B%2B-tricks") == "C++ Tricks" and t("a+b") == "A+B"
    # What decoding could bring in never breaks the line: controls, separators, slashes.
    assert t("bad%0Aline%00x%2Fy%5Cz%E2%80%A8w%09v") == "Bad Line X Y Z W V"
    assert t("--a--b--") == "A B"
    # Bytes that are not UTF-8 stay as the site wrote them.
    assert t("caf%E9") == "Caf%E9"
    # A segment with nothing left after cleaning, or no segment at all, is named by its URL.
    assert t("%0A%0D") == "Https://W.Tc Fixture.Test/%0A%0D"
    assert builders.title_from_slug("https://w.tc-fixture.test/", strip_html=True) == "Https://W.Tc Fixture.Test/"
    for title in (t("bad%0Aline%00x"), t("%0A%0D"), t("caf%E9")):
        assert title and title.isprintable() and title == title.strip()


def test_the_website_sitemap_titles_are_decoded(tmp_path):
    """The website crawl's Auto reading names its entries the same way."""
    from tradecraft.ingest import crawl, robots

    host = "payloads.tc-fixture.test"
    pages = [f"https://{host}/payloads/{p}/" for p in ("Server%20Side%20Request%20Forgery", "Xss%20Injection",
                                                       "Cross-Site%20Request%20Forgery")]
    fetcher = _site(tmp_path, host, {"sitemap.xml": _urlset(pages), "index.html": "<html></html>"})
    base = f"https://{host}/"
    with net.use_fetcher(fetcher):
        rules = crawl.FollowRules(s(), [base])
        found = run(crawl.sitemap_entries(base, s(), rules=rules, robots_cache=robots.RobotsCache(s())))
    assert [e.title for e in found.entries] == ["Server Side Request Forgery", "Xss Injection",
                                                "Cross Site Request Forgery"]
    assert [e.url for e in found.entries] == pages

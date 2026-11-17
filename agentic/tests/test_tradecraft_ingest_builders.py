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

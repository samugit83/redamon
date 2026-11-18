"""Page cards and the card pass (T2.3): R-331 (card fields and description sources), R-010 and
R-339 (a card pass for Live wikis, GitBooks and docs sites: title, headings and meta description
only, within its own limit).

The pipeline runs on the fixture sites (``FixtureFetcher``) with ``MemoryStore``, through the
harness of ``test_tradecraft_ingest_pipeline.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tradecraft_ingest_pipeline import RID, Harness  # noqa: E402
from tradecraft.ingest import cards  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
KERBEROAST = WIKI + "kerberos/kerberoasting/"
PARAGRAPH = "TC-PARAGRAPH-NEVER-KEPT synthetic first paragraph of a live page"


def _card(h, url):
    return next(e for e in h.store.live_entries(RID) if e["url"] == url)


def test_breadcrumbs():
    assert cards.breadcrumb_for(KERBEROAST, KERBEROAST, "sitemap", "mkdocs-wiki", WIKI) == ["kerberos"]
    assert cards.breadcrumb_for("https://docs.tc-fixture.test/guide/install.html", "", "nav", "sphinx-docs",
                                "https://docs.tc-fixture.test/") == ["guide"]
    assert cards.breadcrumb_for("https://h.test/base/active-directory/adcs/esc1/", "", "crawl", "agentic-crawl",
                                "https://h.test/base/") == ["active directory", "adcs"]
    raw = "https://raw.githubusercontent.com/o/r/main/SQL%20Injection/PostgreSQL.md"
    assert cards.breadcrumb_for(raw, "SQL Injection/MySQL/PostgreSQL.md", "tree", "github-repo",
                                "https://github.com/o/r") == ["SQL Injection", "MySQL"]
    assert cards.breadcrumb_for("https://f.test/g.pdf#page=2", "2", "pdf", "pdf", "https://f.test/g.pdf") == []
    assert cards.breadcrumb_for(WIKI + "about/", "", "sitemap", "mkdocs-wiki", WIKI) == []


def test_page_facts_keep_no_body_text():
    html = ("<html><head><title>T - Site</title><meta name='Description' content='The  meta\nline'></head>"
            f"<body><nav><h2>Menu</h2></nav><h1>Real <em>title</em></h1><p>{PARAGRAPH}</p><h2>Part [A](#a)</h2>"
            "<h3>Sub</h3><h4>Deep</h4><script>var h1</script></body></html>")
    facts = cards.page_facts(html)
    assert facts.title == "Real title" and facts.description == "The meta line"
    assert facts.headings == [{"level": 1, "text": "Real title"}, {"level": 2, "text": "Part A"},
                              {"level": 3, "text": "Sub"}]
    assert PARAGRAPH not in repr(facts)


def test_first_paragraph():
    md = "# Title\n\n- a list item that is long enough\n\n```\ncode block line here\n```\n\nThe first real paragraph [with a link](x) and *emphasis*.\n\nSecond."
    assert cards.first_paragraph(md) == "The first real paragraph with a link and emphasis ."
    assert cards.first_paragraph("# Only a heading") == ""


def test_card_fields(tmp_path):
    """A Stored wiki: breadcrumb from the URL path, headings and the first paragraph from the
    stored copy, the page ID and the size with it."""
    h = Harness(tmp_path, WIKI, mode="stored", settings={"fetching.browserEnabled": False})
    assert h.run().status == "succeeded"
    card = _card(h, KERBEROAST)
    assert card["title"] and card["breadcrumb"] == ["kerberos"]
    assert {"level": 1, "text": "Kerberos: Kerberoasting"} in card["headings"]
    assert {"level": 2, "text": "How it works"} in card["headings"]
    assert card["description"] == "Synthetic notes on kerberos: kerberoasting."
    assert card["description_source"] == "first_paragraph"
    assert card["page_id"] > 0 and card["size_chars"] == len(card["stored_text"]) and card["fetched_at"]
    assert "active_directory" in card["topics"]


def test_crawled_page_card_uses_the_crawl_download(tmp_path):
    from tradecraft_memory_store import PipelineModel
    h = Harness(tmp_path, "https://blog.tc-fixture.test/", model=PipelineModel(follow=3),
                settings={"crawl.minTextChars": 0})
    assert h.run().status == "succeeded"
    crawled = [e for e in h.store.live_entries(RID) if e["source"] == "crawl" and e["headings"]]
    assert crawled and all(e["stored_text"] is None for e in crawled)
    assert all(e["description_source"] in ("", "meta") for e in h.store.live_entries(RID))


def _live_site(tmp_path, *, meta=True):
    root = padded_sites(tmp_path)
    page = root / "wiki.tc-fixture.test" / "kerberos" / "kerberoasting" / "index.html"
    text = page.read_text().replace("<p>Synthetic notes on kerberos: kerberoasting.</p>", f"<p>{PARAGRAPH}</p>", 1)
    if not meta:
        text = text.replace('<meta name="description" content="Synthetic notes on kerberos: kerberoasting.">', "")
    page.write_text(text)
    return root


def test_card_pass_live_wiki(tmp_path):
    h = Harness(tmp_path, WIKI, root=_live_site(tmp_path))
    outcome = h.run()
    assert outcome.status == "succeeded" and outcome.report.stored.pages == 0
    card = _card(h, KERBEROAST)
    assert card["title"] == "Kerberos: Kerberoasting" and card["title_source"] == "real"
    assert [x["text"] for x in card["headings"]] == ["Kerberos: Kerberoasting", "How it works", "Examples"]
    assert card["description"] == "Synthetic notes on kerberos: kerberoasting." and card["description_source"] == "meta"
    # No text is kept on a Live resource, not even the first paragraph.
    assert all(e["stored_text"] is None for e in h.store.live_entries(RID))
    assert PARAGRAPH not in repr(h.store.entries) + repr(h.store.sections) + repr(h.store.tree)
    assert h.store.sections == []
    assert "cards" in [n for n, _ in h.stages if _ is not None]  # its progress is reported


def test_card_pass_page_without_meta_gets_no_description(tmp_path):
    h = Harness(tmp_path, WIKI, root=_live_site(tmp_path, meta=False))
    h.run()
    card = _card(h, KERBEROAST)
    assert card["description"] == "" and card["headings"]


def test_card_pass_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(cards, "CARD_PASS_MAX_PAGES", 3)
    h = Harness(tmp_path, WIKI)
    h.run()
    entries = h.store.live_entries(RID)
    passed = [e for e in entries if e["title_source"] == "real"]
    assert len(passed) == 3 and len(entries) > 3
    # Beyond the limit a page keeps a title-only card.
    assert all(e["headings"] == [] and e["description"] == "" and e["title"] for e in entries if e not in passed)


@pytest.mark.parametrize("url,mode", [(WIKI, "stored"), ("https://github.com/tc-fixture/payloads", "live"),
                                      ("https://blog.tc-fixture.test/", "live")])
def test_no_card_pass_outside_live_wikis_gitbooks_and_docs(tmp_path, url, mode):
    h = Harness(tmp_path, url, mode=mode, settings={"fetching.browserEnabled": False})
    h.run()
    names = h.stage_names()
    cards_at = h.requests_at["cards"]
    after = h.requests_at[names[names.index("cards") + 1]]
    assert after == cards_at  # the cards stage made no request


def test_card_pass_unreadable_page_keeps_title_only(tmp_path):
    root = padded_sites(tmp_path)
    (root / "wiki.tc-fixture.test" / "_status.json").write_text('{"/kerberos/kerberoasting/": 500}')
    h = Harness(tmp_path, WIKI, root=root)
    outcome = h.run()
    assert outcome.status == "succeeded"
    card = _card(h, KERBEROAST)
    assert card["title_source"] == "guessed" and card["headings"] == []
    assert {"code": "card_pass_unreadable", "count": 1} in h.resource["ingestion_report"]["errors"]

"""Detection, known-type, summary and storage settings reach ingestion (T3.3, §4.2, §4.3, §4.5,
§4.6; R-072, R-073, R-083, R-095).

Each test runs whole jobs: the settings travel in the job request as the webapp sends them, are
clamped again by the agent (``EffectiveSettings``, as the job runner builds them), and change
what the pipeline does. The per-stage behaviour is in the T1.6/T1.8 files; here a value set by
a person must reach the stage that reads it. Sites are the fixture tree or a temporary one
(``FixtureFetcher``), the store ``MemoryStore``, the model scripted.
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.contract import IngestionReport, JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import pipeline  # noqa: E402
from tradecraft.settings import EffectiveSettings, constant  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore, PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER, RID, JID = "u1", "r1", "job-1"
MB = 1024 * 1024
TEXT = "Synthetic technique text about payloads and bypasses. " * 20


class Job:
    """One ingestion job of resource ``r1`` with the request's ``settings``."""

    def __init__(self, root, url, settings=None, *, mode="live", store=None, model=None, forced_type="",
                 credentials=None, fetcher=None):
        self.store = store or MemoryStore()
        self.fetcher = fetcher or FixtureFetcher(root)
        self.model = model or PipelineModel()
        spec = json.loads(json.dumps(FIXTURE))
        spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID, settings=dict(settings or {}))
        spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model", forced_type=forced_type)
        spec["secrets"] = {"github_token": None, "credentials": credentials}
        self.request = JobStartRequest.model_validate(spec)
        self.store.add_resource(OWNER, RID, url=url, storage_mode=mode, generation=0)
        self.store.add_job(OWNER, RID, JID, status="running")
        self.store.jobs[JID]["target_generation"] = 1
        self.state = None

    def run(self, is_cancelled=None):
        async def build_llm(owner, model):
            return self.model

        async def no(*_a, **_k):
            return False

        async def stage(name, progress=None):
            pass

        # As the job runner does (jobs.py): the request's values, clamped by the agent's spec.
        ctx = JobContext(request=self.request, settings=EffectiveSettings(self.request.settings), target_generation=1,
                         is_cancelled=is_cancelled or no, set_stage=stage)
        seen = {}
        original = pipeline.detect_type

        async def keep_state(state):
            await original(state)
            seen["state"] = state

        # The job's state, kept from the stage after which a failed job still has one.
        pipeline.detect_type = keep_state
        try:
            with net.use_fetcher(self.fetcher):
                outcome = asyncio.run(pipeline.run(ctx, store=self.store, build_llm=build_llm))
        finally:
            pipeline.detect_type = original
        self.state = seen.get("state")
        return outcome

    @property
    def resource(self):
        return self.store.resources[RID]

    @property
    def report(self):
        return IngestionReport.model_validate(self.resource["ingestion_report"])

    def urls(self):
        return [e["url"] for e in self.store.live_entries(RID)]


def site(root: Path, host: str, files: dict) -> Path:
    for path, text in files.items():
        target = root / host / path.lstrip("/")
        if path.endswith("/"):
            target = target / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def mkdocs_home(body=TEXT):
    return (f'<html><head><title>Lab wiki</title><meta name="generator" content="mkdocs-1.5"></head>'
            f"<body><main><article><p>{body}</p></article></main></body></html>")


def urlset(urls):
    return ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{u}</loc></url>" for u in urls) + "</urlset>")


# --------------------------------------------------------------------------------------

def test_detection_settings(tmp_path):
    padded = padded_sites(tmp_path)
    wiki = "https://wiki.tc-fixture.test/"
    raw = Job(FixtureFetcher().site.root, wiki)  # the generated start page is under 500 characters of text
    raw.run()
    assert raw.state.home_problem == "thin_homepage" and raw.state.site_type == "agentic-crawl"
    any_size = Job(FixtureFetcher().site.root, wiki, {"detection.thinHomepageChars": 0})
    assert any_size.run().status == "succeeded"
    assert any_size.state.site_type == "mkdocs-wiki" and any_size.resource["resource_type"] == "mkdocs-wiki"
    detected = Job(padded, wiki)
    detected.run()
    assert detected.state.site_type == "mkdocs-wiki" and 500 <= len(detected.state.home.text) < 5000
    # The agent clamps again: a value above the ceiling (5,000) still runs, at the ceiling.
    clamped = Job(padded, wiki, {"detection.thinHomepageChars": 10 ** 9})
    clamped.run()
    assert clamped.state.settings.int("detection.thinHomepageChars") == 5000
    assert clamped.state.home_problem == "thin_homepage" and clamped.state.site_type == "agentic-crawl"

    # A detector turned off: that site is crawled as a normal website.
    off = Job(padded, wiki, {"detection.enabledDetectors": ["sphinx", "gitbook", "github", "cve"]})
    off.run()
    assert off.state.home_problem == "" and off.state.site_type == "agentic-crawl"

    # The CVE archive threshold: a GitHub page naming 8 distinct CVE ids.
    readme = ("<html><body><article><p>" + " ".join(f"CVE-2024-{1000 + i}" for i in range(8))
              + "</p><p>" + TEXT + "</p></article></body></html>")
    root = site(tmp_path / "gh", "github.com", {"/tc-fixture/notes/": readme})
    for threshold, expected in ((20, "github-repo"), (5, "cve-poc-db")):
        job = Job(root, "https://github.com/tc-fixture/notes", {"detection.cveArchiveThreshold": threshold})
        job.run()
        assert job.state.site_type == expected, threshold


def test_known_type_settings(tmp_path):
    # Max map entries, per type: a wiki of 150 pages at a cap of 100; the docs cap does not apply.
    host = "kb.tc-fixture.test"
    pages = [f"https://{host}/notes/n{i}/" for i in range(150)]
    root = site(tmp_path / "kb", host, {"/": mkdocs_home(), "/sitemap.xml": urlset(pages)})
    capped = Job(root, f"https://{host}/", {"knownTypes.maxMapEntries.wiki": 100, "knownTypes.maxMapEntries.docs": 20000})
    capped.run()
    assert capped.resource["resource_type"] == "mkdocs-wiki" and len(capped.urls()) == 100
    whole = Job(root, f"https://{host}/", {"knownTypes.maxMapEntries.docs": 100})
    whole.run()
    assert len(whole.urls()) == 150

    # Language: a site where every page has a language copy.
    host = "lang.tc-fixture.test"
    langs = [f"https://{host}/{lang}/topic-{i}/" for i in range(10) for lang in ("en", "fr", "de")]
    root = site(tmp_path / "lang", host, {"/": mkdocs_home(), "/sitemap.xml": urlset(langs)})

    def language(**values):
        job = Job(root, f"https://{host}/", values)
        job.run()
        return sorted({u.split("/")[3] for u in job.urls()})

    assert language() == ["en"]
    assert language(**{"knownTypes.language": "all"}) == ["de", "en", "fr"]
    assert language(**{"knownTypes.language": "preferred", "knownTypes.preferredLanguage": "fr"}) == ["fr"]

    # GitHub file types: the fixture repository holds .md, .yml and .yar files.
    gh = padded_sites(tmp_path / "padded")
    md = Job(gh, "https://github.com/tc-fixture/payloads")
    md.run()
    yml = Job(gh, "https://github.com/tc-fixture/payloads", {"knownTypes.githubFileTypes": [".md", ".yml"]})
    yml.run()
    assert md.urls() and all(u.endswith((".md", ".txt", ".rst")) for u in md.urls())
    assert any(u.endswith(".yml") for u in yml.urls()) and not any(u.endswith(".yar") for u in yml.urls())

    # PDF max pages: the fixture guide has three pages.
    pdf = Job(gh, "https://files.tc-fixture.test/guide.pdf", {"knownTypes.pdfMaxPages": 2})
    pdf.run()
    assert [u.rsplit("#", 1)[1] for u in pdf.urls()] == ["page=1", "page=2"]


def _is_summary(messages) -> bool:
    first = messages[0] if messages else {}
    content = first.get("content", "") if isinstance(first, dict) else getattr(first, "content", "")
    return "summarizing a security-knowledge website" in str(content)


def test_summary_settings(tmp_path):
    root = padded_sites(tmp_path)
    model = PipelineModel()
    settings = {"summary.targetTokens": 600, "summary.homepageChars": 1000, "summary.titles": 3,
                "summary.extraInstructions": "Always list the vulnerability classes covered as keywords."}
    job = Job(root, "https://wiki.tc-fixture.test/", settings, model=model)
    assert job.run().status == "succeeded"
    calls = [m for m in model.summary_prompts if _is_summary(m)]
    assert len(calls) == 1
    system, user = calls[0][0]["content"], calls[0][1]["content"]
    assert "Output 550-650 tokens." in system
    # The person's instructions sit in the system prompt, never next to the page text.
    assert "Always list the vulnerability classes covered as keywords." in system
    assert "vulnerability classes covered" not in user
    assert "first 1000 chars" in user and "first 3)" in user
    titles = user.split("Sample page titles from sitemap (first 3):", 1)[1]
    assert titles.count("  - ") == 3
    assert job.resource["summary"] == model.summary

    defaults = PipelineModel()
    Job(root, "https://wiki.tc-fixture.test/", model=defaults).run()
    system = [m for m in defaults.summary_prompts if _is_summary(m)][0]
    assert "Output 250-350 tokens." in system[0]["content"] and "Instructions from the person" not in system[0]["content"]


def test_storage_limits_from_settings(tmp_path):
    host = "store.tc-fixture.test"
    pages = [f"https://{host}/notes/n{i}/" for i in range(7)]
    files = {"/": mkdocs_home(), "/sitemap.xml": urlset(pages)}
    for i, url in enumerate(pages):  # about 160 KB of text each
        files[url.split(host, 1)[1]] = f"<html><body><main><article><p>{'x' * (160 * 1024)} n{i}</p></article></main></body></html>"
    root = site(tmp_path / "store", host, files)
    url = f"https://{host}/"

    def stored(job):
        return [e for e in job.store.live_entries(RID) if e.get("stored_text")]

    default = Job(root, url, mode="stored")
    default.run()
    assert default.report.stored.pages == 7 and default.report.stored.notStoredSize == 0

    few = Job(root, url, {"storage.maxPages": 2}, mode="stored")
    few.run()
    assert few.report.stored.pages == 2 and few.report.stored.notStoredSize == 5

    cut = Job(root, url, {"storage.maxPageKb": 10}, mode="stored")
    cut.run()
    assert len(stored(cut)) == 7 and all(e["stored_bytes"] <= 10 * 1024 for e in stored(cut))

    # 1 MB per resource: six pages of 160 KB fit, the seventh would not.
    small = Job(root, url, {"storage.maxResourceMb": 1}, mode="stored")
    small.run()
    assert small.report.stored.pages == 6 and small.report.stored.notStoredSize == 1
    assert small.report.stored.bytes <= MB

    # The owner's quota counts the other resources' stored pages: 1 MB with 0.95 MB used elsewhere
    # leaves room for five pages cut at 10 KB.
    store = MemoryStore()
    store.add_resource(OWNER, "other", url="https://other.tc-fixture.test/", storage_mode="stored")
    store.page_ids[("other", "https://other.tc-fixture.test/a")] = 900
    store.entries.append({"id": 900, "user_id": OWNER, "resource_id": "other", "generation": 0, "page_id": 900,
                          "url": "https://other.tc-fixture.test/a", "stored_bytes": int(0.95 * MB)})
    quota = Job(root, url, {"storage.userQuotaMb": 1, "storage.maxPageKb": 10}, mode="stored", store=store)
    quota.run()
    assert quota.report.stored.pages == 5 and quota.report.stored.notStoredQuota == 2

    # A quota above the ceiling is clamped to it (10 GB, the constant); it never lifts the ceiling.
    high = Job(root, url, {"storage.userQuotaMb": 10 ** 7}, mode="stored")
    high.run()
    assert high.state.settings.int("storage.userQuotaMb") * MB == constant("userStoredBytesCeiling")
    assert high.report.stored.pages == 7

    # Live stores nothing, whatever the limits say.
    live = Job(root, url, {"storage.maxPages": 20000}, mode="live")
    live.run()
    assert live.report.stored.pages == 0 and stored(live) == []


# --------------------------------------------------------------------------------------
# A docs site whose search index lists nothing (detection §4.2, the docs map §4.3)
# --------------------------------------------------------------------------------------

# A Hugo docs site: its searchindex.js is another search library's JavaScript bundle, not
# Sphinx's index; its sitemap lists its pages. Every page links to the others.
HUGO = "hugo-docs.tc-fixture.test"
HUGO_URL = f"https://{HUGO}/stable/"
HUGO_PAGES = [f"{HUGO_URL}{p}/" for p in ("overview", "concepts", "howto", "api")]
ELASTICLUNR_BUNDLE = ("window.docsSearch = (function(){\n    /** elasticlunr - synthetic bundle */\n"
                      '    var lunr = function (config) { return config; };\n    var data = {"version": "0.9.5"};\n'
                      "    return lunr(data);\n})();\n")
FAKE_LOGIN = {"cookie": "cookie=fake-session", "headers": [], "basic_auth": None}


def docs_page(title, links=(), head=""):
    menu = "".join(f'<li><a href="{u}">{u.rstrip("/").rsplit("/", 1)[-1].title()}</a></li>' for u in links)
    return (f"<html><head><title>{title}</title>{head}</head><body><main><article><h1>{title}</h1>"
            f"<p>{TEXT}</p><ul>{menu}</ul></article></main></body></html>")


def hugo_site(root, **extra):
    head = '<meta name="generator" content="Hugo 0.139.3"><script src="/stable/searchindex.js" defer></script>'
    files = {"/stable/": docs_page("Lab proxy docs", HUGO_PAGES, head),
             "/stable/searchindex.js": ELASTICLUNR_BUNDLE,
             "/stable/sitemap.xml": urlset([HUGO_URL] + HUGO_PAGES)}
    files.update({u.split(HUGO, 1)[1]: docs_page(u.rstrip("/").rsplit("/", 1)[-1].title(), HUGO_PAGES) for u in HUGO_PAGES})
    files.update(extra)
    return site(root, HUGO, files)


def error_codes(job):
    return {e.code for e in job.report.errors}


def test_a_hugo_docs_site_is_crawled_not_kept_as_its_homepage(tmp_path):
    """Detection: a page that loads another tool's searchindex.js is a website, so the crawl maps
    it; it was typed a Sphinx site, and a map holding its homepage alone succeeded."""
    job = Job(hugo_site(tmp_path), HUGO_URL, model=PipelineModel(follow=len(HUGO_PAGES)))
    assert job.run().status == "succeeded"
    assert job.state.site_type == "agentic-crawl" and job.resource["resource_type"] == "agentic-crawl"
    assert set(HUGO_PAGES) <= set(job.urls())
    assert "map_empty_homepage_only" not in error_codes(job)


def test_a_docs_type_without_a_sphinx_index_is_mapped_from_its_sitemap(tmp_path):
    """The docs map: a search index that lists nothing falls back to the site's sitemap, and the
    report names the source; no crawl runs."""
    job = Job(hugo_site(tmp_path), HUGO_URL, forced_type="sphinx-docs")
    assert job.run().status == "succeeded"
    assert job.resource["resource_type"] == "sphinx-docs"
    assert sorted(job.urls()) == sorted([HUGO_URL] + HUGO_PAGES) and job.report.kept == 5
    assert job.report.stopReason == "docs: no search index, sitemap.xml (5 pages)"
    assert "map_empty_homepage_only" not in error_codes(job)
    assert job.state.crawl is None and job.resource["crawl_stats"] == {}
    # The 1.x columns: a docs map, with no index URL.
    assert job.resource["sitemap"]["indexUrl"] == "" and len(job.resource["sitemap"]["nav"]) == 5


def test_the_docs_sitemap_fallback_keeps_the_guards(tmp_path):
    """robots.txt names a sitemap at an internal address and one on another host: the first is
    refused before any request, and the resource's login never reaches the other host."""
    maps = "maps.tc-fixture.test"
    root = hugo_site(tmp_path, **{"/robots.txt": f"Sitemap: http://127.0.0.1/sitemap.xml\nSitemap: https://{maps}/docs.xml\n"})
    site(root, maps, {"/docs.xml": urlset([HUGO_URL] + HUGO_PAGES)})
    job = Job(root, HUGO_URL, forced_type="sphinx-docs", credentials=FAKE_LOGIN)
    assert job.run().status == "succeeded"
    assert sorted(job.urls()) == sorted([HUGO_URL] + HUGO_PAGES)
    assert job.report.stopReason == "docs: no search index, robots (5 pages)"
    requests = job.fetcher.requests
    assert not [u for u, _ in requests if "127.0.0.1" in u]
    off_host = [h for u, h in requests if f"//{maps}/" in u]
    own_host = [h for u, h in requests if f"//{HUGO}/" in u]
    assert off_host and not any("cookie" in h for h in off_host)
    assert own_host and all(h.get("cookie") == "cookie=fake-session" for h in own_host)


def test_a_sphinx_site_whose_index_lists_nothing_is_crawled(tmp_path):
    """A real Sphinx page whose index does not parse and with no sitemap: the crawl a website
    would get maps it, and the report says so."""
    host = "sphinx-broken.tc-fixture.test"
    url = f"https://{host}/"
    pages = [f"{url}{p}.html" for p in ("install", "usage", "options")]
    head = '<meta name="generator" content="Docutils 0.20.1: https://docutils.sourceforge.io/" />'
    files = {"/": docs_page("Lab tool documentation", pages, head), "/searchindex.js": "Search.setIndex({broken"}
    files.update({p.split(host, 1)[1]: docs_page(p.rsplit("/", 1)[-1], pages) for p in pages})
    job = Job(site(tmp_path, host, files), url, model=PipelineModel(follow=len(pages)))
    assert job.run().status == "succeeded"
    assert job.state.site_type == "sphinx-docs" and job.resource["resource_type"] == "sphinx-docs"
    assert set(pages) <= set(job.urls())
    assert job.report.stopReason.startswith("docs: no search index or sitemap, crawl (")
    assert job.resource["crawl_stats"]["strategy"] == "llm" and job.report.llmCalls >= 1
    assert "map_empty_homepage_only" not in error_codes(job)


def test_a_docs_index_that_lists_pages_is_used_as_before(tmp_path):
    job = Job(padded_sites(tmp_path), "https://docs.tc-fixture.test/")
    assert job.run().status == "succeeded"
    assert job.resource["resource_type"] == "sphinx-docs" and len(job.urls()) == 8
    assert job.report.stopReason == "docs: searchindex (8 pages)"
    assert job.resource["sitemap"]["indexUrl"] == "https://docs.tc-fixture.test/searchindex.js"
    assert job.resource["crawl_stats"] == {}
    assert not [u for u, _ in job.fetcher.requests if u.endswith(("/sitemap.xml", "/robots.txt"))]


def test_a_translated_wiki_keeps_its_english_pages_within_the_sitemap_budget(tmp_path, monkeypatch):
    """A translated wiki: robots.txt names an index on another host with one child per language
    (``/<lang>/sitemap.xml``, alphabetical, English fourth). The byte budget holds two children:
    the English one is read first, so the map is English, not the first two languages."""
    from tradecraft.ingest import builders

    host, maps = "polyglot.tc-fixture.test", "polyglot-maps.tc-fixture.test"
    langs = ("af", "de", "el", "en", "fr")
    children = {lang: urlset([f"https://{host}/{lang}/topic-{i}/" for i in range(6)]) for lang in langs}
    index = ('<?xml version="1.0"?><sitemapindex>'
             + "".join(f"<sitemap><loc>https://{maps}/{lang}/sitemap.xml</loc></sitemap>" for lang in langs)
             + "</sitemapindex>")
    root = site(tmp_path, host, {"/": mkdocs_home(), "/robots.txt": f"Sitemap: https://{maps}/sitemap.xml\n"})
    site(root, maps, {"/sitemap.xml": index, **{f"/{lang}/sitemap.xml": text for lang, text in children.items()}})
    real = builders.constant
    room = len(index) + 2 * len(children["af"]) + len(children["af"]) // 2
    monkeypatch.setattr(builders, "constant", lambda name: room if name == "sitemapMaxBytes" else real(name))

    def languages(**values):
        job = Job(root, f"https://{host}/", values)
        assert job.run().status == "succeeded"
        assert job.resource["resource_type"] == "mkdocs-wiki"
        return sorted({u.split("/")[3] for u in job.urls()})

    assert languages() == ["en"]
    assert languages(**{"knownTypes.language": "preferred", "knownTypes.preferredLanguage": "fr"}) == ["fr"]
    assert languages(**{"knownTypes.language": "all"}) == ["af", "de"]


def test_the_map_keeps_decoded_titles(tmp_path):
    """A website read with Auto: the titles guessed from its sitemap's percent-encoded paths are
    stored decoded, as search ranks them and the agent reads them."""
    host = "payloads.tc-fixture.test"
    slugs = ("Server%20Side%20Request%20Forgery", "Xss%20Injection", "Cross-Site%20Request%20Forgery")
    pages = [f"https://{host}/payloads/{s}/" for s in slugs]
    files = {"/": f"<html><head><title>Payloads</title></head><body><main><p>{TEXT}</p></main></body></html>",
             "/sitemap.xml": urlset(pages)}
    for url in pages:
        files[urllib.parse.unquote(url.split(host, 1)[1])] = docs_page("Payload page")
    job = Job(site(tmp_path, host, files), f"https://{host}/", {"crawl.strategy": "auto"})
    assert job.run().status == "succeeded"
    titles = {e["url"]: e["title"] for e in job.store.live_entries(RID)}
    assert [titles[u] for u in pages] == ["Server Side Request Forgery", "Xss Injection", "Cross Site Request Forgery"]


# --------------------------------------------------------------------------------------
# The docs map's fallback chain reads each source once, within its limits
# --------------------------------------------------------------------------------------

def versioned_docs(root, maps):
    """A Sphinx site whose index does not parse, in /docs/ beside an older version in /v9/. Its
    robots.txt names ``maps`` (each listing only /v9/ pages, outside the resource's folder)."""
    host = "versioned-docs.tc-fixture.test"
    url = f"https://{host}/docs/"
    inside = [f"{url}{p}.html" for p in ("install", "usage")]
    outside = [f"https://{host}/v9/{p}.html" for p in ("install", "usage")]
    head = '<meta name="generator" content="Docutils 0.20.1: https://docutils.sourceforge.io/" />'
    files = {"/docs/": docs_page("Lab docs", inside + outside[:1], head), "/docs/searchindex.js": "Search.setIndex({broken",
             "/robots.txt": "".join(f"Sitemap: https://{host}{m}\n" for m in maps)}
    files.update({m: urlset(outside) for m in maps})
    files.update({u.split(host, 1)[1]: docs_page(u.rsplit("/", 1)[-1], inside) for u in inside + outside})
    return site(root, host, files), host, url, inside


def test_the_docs_crawl_hand_off_reads_no_sitemap_again_and_stays_in_the_folder(tmp_path):
    """With Auto, the hand-off's crawl started with the sitemaps again, on a fresh budget and outside
    the folder the docs reading had just kept to; it is the model-guided crawl, in the folder."""
    root, host, url, inside = versioned_docs(tmp_path, ["/maps/all.xml"])
    job = Job(root, url, {"crawl.strategy": "auto"}, model=PipelineModel(follow=3))
    assert job.run().status == "succeeded"
    assert [u for u, _ in job.fetcher.requests if u.endswith("/maps/all.xml")] == [f"https://{host}/maps/all.xml"]
    assert set(inside) <= set(job.urls()) and all(u.startswith(url) for u in job.urls())
    assert job.report.stopReason.startswith("docs: no search index or sitemap, crawl (")
    assert job.resource["crawl_stats"]["strategy"] == "llm"


class _Signals(FixtureFetcher):
    """Runs ``on_first`` once, right after the first sitemap download."""

    def __init__(self, root, on_first):
        super().__init__(root)
        self.on_first = on_first

    async def get(self, url, **kwargs):
        resp = await super().get(url, **kwargs)
        if "/maps/" in url and self.on_first is not None:
            self.on_first, signal = None, self.on_first
            signal()
        return resp


def test_the_docs_sitemap_reading_stops_on_cancel_and_on_the_time_budget(tmp_path):
    from tradecraft import clock
    from tradecraft_doubles import FakeClock

    maps = ["/maps/a.xml", "/maps/b.xml"]
    cancelled = {"now": False}
    root, host, url, _inside = versioned_docs(tmp_path / "cancel", maps)
    fetcher = _Signals(root, lambda: cancelled.update(now=True))

    async def is_cancelled():
        return cancelled["now"]

    job = Job(root, url, fetcher=fetcher)
    assert job.run(is_cancelled=is_cancelled).status == "cancelled"
    assert not [u for u, _ in fetcher.requests if u.endswith("/maps/b.xml")]

    # The crawl's time budget (180 s) bounds the reading too: the clock passes it after one file.
    fake = FakeClock()
    root, host, url, inside = versioned_docs(tmp_path / "time", maps)
    fetcher = _Signals(root, lambda: fake.advance(200))
    job = Job(root, url, fetcher=fetcher, model=PipelineModel(follow=3))
    with clock.use_clock(fake):
        assert job.run().status == "succeeded"
    assert not [u for u, _ in fetcher.requests if u.endswith("/maps/b.xml")]
    assert set(inside) <= set(job.urls())


def test_the_docs_crawl_hand_off_keeps_the_docs_map_limit(tmp_path):
    """The crawl a docs site is handed to stops at the docs map's limit (here its minimum, 100),
    not at the website's (2,000) or the crawl's page limit (200)."""
    host = "big-docs.tc-fixture.test"
    url = f"https://{host}/"
    pages = [f"{url}page-{i}.html" for i in range(120)]
    head = '<meta name="generator" content="Docutils 0.20.1: https://docutils.sourceforge.io/" />'
    files = {"/": docs_page("Big docs", pages, head), "/searchindex.js": "Search.setIndex({broken"}
    files.update({p.split(host, 1)[1]: docs_page(p.rsplit("/", 1)[-1], pages) for p in pages})
    job = Job(site(tmp_path, host, files), url, {"crawl.strategy": "rules", "knownTypes.maxMapEntries.docs": 100})
    assert job.run().status == "succeeded"
    assert job.resource["resource_type"] == "sphinx-docs" and len(job.urls()) == 100
    assert job.report.stopReason == "docs: no search index or sitemap, crawl (max_map_entries)"

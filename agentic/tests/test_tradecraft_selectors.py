"""Content selectors (T4.3, §6.8, R-163): the body selector and the elements to remove shape the
text a Stored resource keeps and the text the agent reads live, with the same function, so a
page reads the same either way.

A Stored job runs through the pipeline (``MemoryStore``, ``FixtureFetcher``, a scripted model);
the live read goes through the reader with the catalog's ``read_settings``, as a run does.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net, runtime  # noqa: E402
from tradecraft.contract import JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import fetch, pipeline  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore, PipelineModel  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER = "u1"
HOST = "sel.tc-fixture.test"
SITE = f"https://{HOST}"
INTRO = "An index of synthetic posts about injection payloads. " * 20
SELECTORS = {"content.bodySelector": "#post", "content.removeSelectors": [".ads", "#comments"]}


def post(n: int) -> str:
    return (f"<html><head><title>Post {n}</title></head><body><nav><a href='/'>Home</a></nav>"
            f"<div id='banner'>Subscribe to the newsletter</div>"
            f"<div id='post'><h1>Post {n}</h1><p>Payload notes number {n}: use a UNION SELECT probe.</p>"
            f"<div class='ads'>Buy our scanner</div><pre><code>' UNION SELECT {n}--</code></pre></div>"
            f"<section id='comments'>Great post!</section><aside class='related'>Related posts</aside></body></html>")


def site(tmp_path: Path) -> Path:
    files = {"/": f"<html><head><title>Notes</title></head><body><main><p>{INTRO}</p>"
                  f"<a href='/posts/1/'>Post 1</a><a href='/posts/2/'>Post 2</a></main></body></html>",
             "/sitemap.xml": '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                             f"<url><loc>{SITE}/posts/1/</loc></url><url><loc>{SITE}/posts/2/</loc></url></urlset>",
             "/posts/1/": post(1), "/posts/2/": post(2)}
    for path, text in files.items():
        target = tmp_path / HOST / path.lstrip("/")
        if path.endswith("/"):
            target = target / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return tmp_path


def stored_job(root: Path, settings: dict) -> MemoryStore:
    """A Stored refresh of the site with ``settings``; returns the store with its pages."""
    store = MemoryStore()
    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id="j1", user_id=OWNER, actor_user_id=OWNER, resource_id="r1", settings=settings)
    spec["resource"].update(url=SITE + "/", storage_mode="stored", model="openai/fake-small-model")
    spec["secrets"] = {"github_token": None, "credentials": None}
    req = JobStartRequest.model_validate(spec)
    store.add_resource(OWNER, "r1", url=SITE + "/", storage_mode="stored", generation=0)
    store.add_job(OWNER, "r1", "j1", status="running")
    store.jobs["j1"]["target_generation"] = 1

    async def build_llm(owner, model):
        return PipelineModel(follow=2)

    async def no(*_a):
        return False

    ctx = JobContext(request=req, settings=EffectiveSettings(req.settings), target_generation=1, is_cancelled=no,
                     set_stage=no)
    with net.use_fetcher(FixtureFetcher(root)):
        outcome = asyncio.run(pipeline.run(ctx, store=store, build_llm=build_llm))
    assert outcome.status == "succeeded", outcome
    return store


def live_read(root: Path, store: MemoryStore, read_settings: dict, title: str) -> str:
    """The agent's read of a Live copy of the same resource, as a run does it."""
    catalog = {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": {},
               "resources": [{"id": "r2", "slug": "notes", "name": "notes", "url": SITE + "/", "type": "agentic-crawl",
                              "storage_mode": "live", "summary": "s", "has_login": False, "priority": "normal",
                              "map_version": 3, "read_settings": read_settings, "github_token": None,
                              "credentials": None}]}
    store.add_resource(OWNER, "r2", url=SITE + "/", slug="notes", storage_mode="live", map_version=3,
                       sitemap={"nav": [{"title": "Post 1", "path": f"{SITE}/posts/1/"},
                                        {"title": "Post 2", "path": f"{SITE}/posts/2/"}]})

    async def go():
        with net.use_fetcher(FixtureFetcher(root)), runtime.use_store(store):
            assert runtime.bind_run_catalog(catalog)
            return await reader.lookup(resource_id="notes", query=title)

    return contextvars.Context().run(asyncio.run, go())


def stored_text(store: MemoryStore, url: str) -> str:
    return next(e["stored_text"] for e in store.live_entries("r1") if e["url"] == url)


# --------------------------------------------------------------------------------------

def test_selectors_shape_the_stored_text(tmp_path):
    root = site(tmp_path)
    for strategy in ("llm", "auto"):  # pages the crawl downloaded, and pages storage downloads
        store = stored_job(root, {"crawl.strategy": strategy, "crawl.minTextChars": 0, **SELECTORS})
        text = stored_text(store, f"{SITE}/posts/1/")
        assert "Payload notes number 1" in text and "UNION SELECT 1--" in text
        for gone in ("Buy our scanner", "Great post!", "Related posts", "Subscribe to the newsletter", "Home"):
            assert gone not in text, (strategy, gone)
    # Without them, the 1.x cleaning keeps what is not a page landmark.
    plain = stored_text(stored_job(root, {"crawl.strategy": "auto"}), f"{SITE}/posts/1/")
    assert "Buy our scanner" in plain


def test_same_text_live_and_stored(tmp_path):
    root = site(tmp_path)
    for strategy in ("llm", "auto"):
        store = stored_job(root, {"crawl.strategy": strategy, "crawl.minTextChars": 0, **SELECTORS})
        for n in (1, 2):
            kept = stored_text(store, f"{SITE}/posts/{n}/")
            read = live_read(root, store, {**SELECTORS, "fetching.browserEnabled": False}, f"Post {n}")
            assert "source: live" in read
            assert read.split("\n---\n", 1)[1].startswith(kept), (strategy, n)
    # The same function, called the same way by both: storage (through the job's thread pool)
    # and the read (the default cleaner of smart_fetch).
    html = post(1)
    options = fetch.content_options(EffectiveSettings(SELECTORS))
    assert fetch.clean_page_args(html, options["body_selector"], options["remove"]) == fetch.clean_page(html, **options)


def test_an_invalid_selector_is_skipped(tmp_path):
    root = site(tmp_path)
    store = stored_job(root, {"crawl.strategy": "auto", "content.bodySelector": "#post[",
                              "content.removeSelectors": ["::bad::", ".ads"]})
    text = stored_text(store, f"{SITE}/posts/1/")
    assert "Payload notes number 1" in text and "Buy our scanner" not in text

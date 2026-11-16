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

    def __init__(self, root, url, settings=None, *, mode="live", store=None, model=None, forced_type=""):
        self.store = store or MemoryStore()
        self.fetcher = FixtureFetcher(root)
        self.model = model or PipelineModel()
        spec = json.loads(json.dumps(FIXTURE))
        spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID, settings=dict(settings or {}))
        spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model", forced_type=forced_type)
        spec["secrets"] = {"github_token": None, "credentials": None}
        self.request = JobStartRequest.model_validate(spec)
        self.store.add_resource(OWNER, RID, url=url, storage_mode=mode, generation=0)
        self.store.add_job(OWNER, RID, JID, status="running")
        self.store.jobs[JID]["target_generation"] = 1
        self.state = None

    def run(self):
        async def build_llm(owner, model):
            return self.model

        async def no(*_a, **_k):
            return False

        async def stage(name, progress=None):
            pass

        # As the job runner does (jobs.py): the request's values, clamped by the agent's spec.
        ctx = JobContext(request=self.request, settings=EffectiveSettings(self.request.settings), target_generation=1,
                         is_cancelled=no, set_stage=stage)
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

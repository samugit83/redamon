"""The 100-question measurement of library search (T2.7, Q15, R-430, AC-60): about 1,800
synthetic pages across a wiki, a repository, a docs site and a website, ingested into the
disposable database through the real pipeline (the fixture fetcher, a scripted model), then
about 100 questions, each with its correct page, asked of today's matcher and of search.

It writes a report (first-result rate, top-5 rate, tokens per find, misses, wasted calls) and
fails only on errors, never on scores: a measurement, not a gate. The report goes to
``TRADECRAFT_EVAL_REPORT_DIR`` when set, else to ``fixtures/tradecraft_eval/reports/`` (ignored
by git).

Today's matcher gets the benefit of the doubt: it is asked within the correct resource (the
agent has picked the right ``resource_id``), and it has no section picker. Search is asked
across the whole library, except the browse questions, which name their resource.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; the measurement skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
EVAL = HERE / "fixtures" / "tradecraft_eval"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(EVAL))

import make_corpus  # noqa: E402
from test_tradecraft_ingest_pipeline_integration import pg  # noqa: E402,F401

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
needs_pg = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

RESOURCES = [  # name, URL, storage mode, type
    ("wiki", make_corpus.WIKI, "live", "mkdocs-wiki"),
    ("repo", make_corpus.REPO, "stored", "github-repo"),
    ("docs", make_corpus.DOCS, "live", "sphinx-docs"),
    ("blog", make_corpus.BLOG, "stored", "agentic-crawl"),
]
SETTINGS = {"fetching.browserEnabled": False, "crawl.minTextChars": 0, "crawl.linksPerPage": 40,
            "crawl.maxPages": 300}
GLOBAL_CAP = 40_000  # the agent's limit per tool result, which caps a 1.x read


def load_questions() -> list[dict]:
    return [json.loads(line) for line in (EVAL / "questions.jsonl").read_text().splitlines() if line.strip()]


def test_questions_file_is_current(tmp_path):
    """The committed questions are the generator's, and every one names a page of the corpus."""
    pages = make_corpus.build(tmp_path)
    assert load_questions() == make_corpus.questions(pages)
    assert len(pages) >= 1500 and len(load_questions()) >= 90
    assert {q["kind"] for q in load_questions()} == {"precise", "vague", "cve", "browse"}
    assert {q["mode"] for q in load_questions()} == {"live", "stored"}
    # Synthetic only: reserved .test hosts, the made-up owner, CVE ids of the year 2098.
    for url in pages:
        host = url.split("/")[2]
        assert host.endswith(".tc-eval.test") or "tc-eval" in url, url
    assert all(not re.search(r"CVE-(?!2098)\d{4}-", p["markdown"]) for p in pages.values())


class EvalModel:
    """The scripted ingestion model: the crawl follows every link, folders get a plain line,
    every summary is the same."""

    def __init__(self):
        self.calls = 0

    async def ainvoke(self, messages, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        self.calls += 1
        if isinstance(messages, str) and "You describe the folders" in messages:
            paths = re.findall(r'^\s*"([^"\n]+/)": \[', messages, re.M)
            return AIMessage(content=json.dumps({p: f"Pages under {p}" for p in paths}))
        if isinstance(messages, str) and "Reply ONLY with JSON" in messages:
            n = len(re.findall(r'^\s+\d+\. "', messages, re.M))
            answer = {"action": "follow", "indices": list(range(1, n + 1)), "reason": "all"} if n else \
                {"action": "stop", "reason": "done"}
            return AIMessage(content=json.dumps(answer))
        return AIMessage(content="A synthetic library of lab techniques.")


async def ingest(pg, root, uid, name, url, mode, site_type):
    from test_tradecraft_ingest_pipeline_integration import FIXTURE
    from tradecraft import jobs, net  # noqa: F401
    from tradecraft.contract import JobStartBatch
    from tradecraft.ingest import pipeline
    from tradecraft.store import Store
    from tradecraft_doubles import FixtureFetcher

    rid = await pg.resource(uid, url, mode)
    jid = await pg.job(uid, rid)
    model = EvalModel()

    async def build_llm(owner, model_id):
        return model

    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid, settings=dict(SETTINGS))
    spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model", forced_type=site_type)
    store = Store()
    runner = jobs.JobRunner(store, instance=f"eval-{uuid.uuid4().hex[:6]}", fetcher_factory=lambda: FixtureFetcher(root))
    runner._entry = functools.partial(pipeline.run, store=store, run_blocking=runner.run_blocking, build_llm=build_llm)
    answer = await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
    assert answer.accepted == [jid], answer
    await asyncio.wait_for(runner._running[jid].task, timeout=600)
    await runner.close()
    job = await pg.row("tradecraft_ingestion_jobs", jid)
    assert job["status"] == "succeeded", (name, job["error_code"])
    return rid


def legacy_ranked(sitemap: dict, rtype: str, base: str, query: str) -> list[str]:
    """Today's matcher (1.x's ``_pick_section`` without a picker, ported as ``legacy_match``):
    its ranked URLs."""
    from tradecraft.ingest import fetch
    from tradecraft.library import legacy_match

    qt = legacy_match.tokens(query)
    scored = sorted(((legacy_match.rank_score(qt, e), e) for e in legacy_match.sitemap_entries(sitemap)),
                    key=lambda x: x[0], reverse=True)
    return [fetch.canonical_url(legacy_match.resolve_path(rtype, base, sitemap, e["path"]))
            for score, e in scored[:5] if score > 0]


def rate(n, d):
    return f"{100.0 * n / d:.0f}%" if d else "n/a"


@needs_pg
async def test_measurement(pg, tmp_path):
    from tradecraft import clock
    from tradecraft.agent_tools import render_search
    from tradecraft.contract import V2Catalog
    from tradecraft.ingest import fetch
    from tradecraft.library import search, split

    root = tmp_path / "sites"
    pages = make_corpus.build(root)
    canonical = {fetch.canonical_url(u): p for u, p in pages.items()}
    questions = load_questions()
    uid = await pg.user()
    started = datetime.now(timezone.utc)
    resources = {}
    for name, url, mode, site_type in RESOURCES:
        rid = await ingest(pg, root, uid, name, url, mode, site_type)
        resources[name] = (await pg.sql("SELECT * FROM user_tradecraft_resources WHERE id = %s", rid))[0]
    ingest_s = (datetime.now(timezone.utc) - started).total_seconds()
    counts = {n: (await pg.sql("SELECT count(*) AS n FROM tradecraft_entries e JOIN user_tradecraft_resources r ON "
                               "r.id = e.resource_id AND e.generation = r.generation WHERE e.resource_id = %s",
                               r["id"]))[0]["n"] for n, r in resources.items()}
    catalog = V2Catalog.model_validate({
        "v2": True, "owner_id": uid, "person_id": uid, "actor_id": None, "search": {},
        "resources": [{"id": r["id"], "slug": r["slug"], "name": n, "url": r["url"], "type": t,
                       "storage_mode": r["storage_mode"], "summary": r["summary"] or "", "map_version": 3}
                      for (n, _u, _m, t), r in ((spec, resources[spec[0]]) for spec in RESOURCES)]})
    slug_of = {n: r["slug"] for n, r in resources.items()}
    names = {r["slug"]: n for n, r in resources.items()}

    rows = []
    for q in questions:
        target = fetch.canonical_url(q["url"])
        res = resources[canonical[target]["resource"]]
        old = legacy_ranked(res["sitemap"] or {}, res["resource_type"], res["url"], q["query"])
        old_tokens = min(canonical[target]["chars"], GLOBAL_CAP) // 4 if old else 0
        answer = await search.search(uid, catalog, q["query"], resource=slug_of.get(q.get("resource")))
        urls = [fetch.canonical_url(h.card.url) for h in answer.hits]
        within = await search.search(uid, catalog, q["query"], resource=res["slug"])
        within_urls = [fetch.canonical_url(h.card.url) for h in within.hits]
        text = render_search(q["query"], answer, names, [])
        new_tokens = len(text) // 4
        if urls:
            page = canonical.get(urls[0])
            if page is not None:
                sections = split.split_markdown(page["markdown"])
                chosen = split.pick_section(sections, answer.hits[0].section, q["query"]) or sections[0]
                new_tokens += min(len(chosen.text), 12_000) // 4
        rows.append({"id": q["id"], "kind": q["kind"], "mode": q["mode"], "query": q["query"],
                     "old_first": bool(old) and old[0] == target, "old_top5": target in old[:5], "old_miss": not old,
                     "old_tokens": old_tokens, "new_first": bool(urls) and urls[0] == target,
                     "new_top5": target in urls[:5], "new_miss": answer.verdict == "NOT FOUND",
                     "in_first": bool(within_urls) and within_urls[0] == target, "in_top5": target in within_urls[:5],
                     "verdict": answer.verdict, "new_tokens": new_tokens})

    lines = [f"# Tradecraft search measurement — {clock.now().date().isoformat()}", "",
             f"Corpus: {len(pages)} generated pages; entries in the live generations: "
             + ", ".join(f"{n} {c}" for n, c in counts.items()) + f"; ingestion {ingest_s:.0f} s.",
             f"Questions: {len(rows)} (" + ", ".join(f"{k} {sum(1 for r in rows if r['kind'] == k)}"
                                                    for k in ("precise", "vague", "cve", "browse")) + ").",
             "", "Today's matcher is asked within the correct resource; \"search\" across the whole library (the "
             "browse questions name their resource); \"search, same resource\" within the correct resource, as "
             "today's matcher is.", "",
             "| Questions | n | today first | today top 5 | search first | search top 5 | search, same resource: "
             "first | top 5 | today misses | search NOT FOUND | today tokens/find | search tokens/find |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    groups = [("all", rows)] + [(k, [r for r in rows if r["kind"] == k]) for k in ("precise", "vague", "cve", "browse")] \
        + [(f"{m} pages", [r for r in rows if r["mode"] == m]) for m in ("live", "stored")]
    for label, group in groups:
        n = len(group)
        of = sum(r["old_first"] for r in group)
        nf = sum(r["new_first"] for r in group)
        lines.append(
            f"| {label} | {n} | {rate(of, n)} | {rate(sum(r['old_top5'] for r in group), n)} | {rate(nf, n)} | "
            f"{rate(sum(r['new_top5'] for r in group), n)} | {rate(sum(r['in_first'] for r in group), n)} | "
            f"{rate(sum(r['in_top5'] for r in group), n)} | {sum(r['old_miss'] for r in group)} | "
            f"{sum(r['new_miss'] for r in group)} | {sum(r['old_tokens'] for r in group) // max(of, 1)} | "
            f"{sum(r['new_tokens'] for r in group) // max(nf, 1)} |")
    lines += ["", "Tokens per find: the tokens of every answer of the group (today: the whole page read, up to "
              f"{GLOBAL_CAP:,} characters; search: its answer plus the section read) over the questions whose "
              "first result was the right page. Tool calls per find: today 1 (lookup), search 2 (search, lookup).",
              "The synthetic pages are short (median "
              f"{sorted(p['chars'] for p in pages.values())[len(pages) // 2]} characters), so a whole-page read is "
              "cheap here; a real page of up to 40,000 characters is not, and search reads one section of it.",
              "Wasted calls (librarian asks answered NOT FOUND): n/a until the librarian (T7.3).", "",
              "## Search misses (first result wrong)", ""]
    lines += [f"- {r['id']} ({r['kind']}, {r['verdict']}): {r['query']}" for r in rows if not r["new_first"]] or ["- none"]
    report_dir = Path(os.environ.get("TRADECRAFT_EVAL_REPORT_DIR") or EVAL / "reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report = report_dir / f"{clock.now().date().isoformat()}.md"
    report.write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:18]))
    assert report.exists() and len(rows) == len(questions)
    assert all(counts[n] > 0 for n in counts)

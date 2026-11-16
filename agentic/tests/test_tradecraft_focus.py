"""The ingestion focus in the pipeline (T5.1, §6.14): the keyword pre-sort, the title triage's
decisions on the map, the rules before the focus, dropped entries kept with their reason, pins
never dropped, a model error that drops nothing, and the report's focus counts.

The site is the fixture tree (``FixtureFetcher``), the store ``MemoryStore``, the model scripted.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.contract import IngestionReport, JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import focus, pipeline  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore, padded_sites  # noqa: E402

ENTRY_LINE = re.compile(r"^(\d+)\. (.*) — (.*)$")
BLOCK = re.compile(r"<<<UNTRUSTED_WEB_CONTENT id=(\w+)>>>\n(.*?)\n<<<END_UNTRUSTED_WEB_CONTENT id=\1>>>", re.DOTALL)


def entries_in(prompt: str) -> list[tuple[int, str, str]]:
    """(n, title, path) of every entry line inside a triage prompt's untrusted block."""
    m = BLOCK.search(prompt)
    assert m, "the entries must sit in an untrusted block"
    return [(int(g.group(1)), g.group(2), g.group(3)) for g in map(ENTRY_LINE.match, m.group(2).splitlines()) if g]


FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER, RID, JID = "u1", "r1", "job-1"
WIKI = "https://wiki.tc-fixture.test/"
REPO = "https://github.com/tc-fixture/payloads"
SQLI = {"mode": "focused", "topics": ["sql_injection"], "kinds": ["payloads"], "keep": "SQL injection payloads",
        "skip": "", "strictness": "balanced"}


class FocusModel:
    """The pipeline's model: triage prompts answered by ``decide(title, path)``, every other JSON
    prompt (crawl, folder descriptions) with an empty answer, the summary with a line."""

    def __init__(self, decide=None, triage_errors=()):
        self.decide = decide or (lambda title, path: ("keep", "fits", [], []))
        self.triage_errors = list(triage_errors)
        self.triage_prompts: list[str] = []
        self.tag_prompts: list[str] = []

    async def ainvoke(self, messages, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        text = messages if isinstance(messages, str) else ""
        if "The owner's focus:" in text:
            self.triage_prompts.append(text)
            if self.triage_errors:
                raise self.triage_errors.pop(0)
            out = []
            for n, title, path in entries_in(text):
                decision, reason, topics, kinds = self.decide(title, path)
                out.append({"n": n, "decision": decision, "reason": reason, "topics": topics, "kinds": kinds})
            return AIMessage(content=json.dumps({"entries": out}))
        if "You tag the pages" in text:
            self.tag_prompts.append(text)
            return AIMessage(content=json.dumps({"entries": []}))
        if "Reply ONLY with JSON" in text:
            return AIMessage(content='{"action": "stop", "reason": "enough"}' if '"action"' in text else "{}")
        return AIMessage(content="A synthetic library.")

    def judged_paths(self) -> list[str]:
        return [p for prompt in self.triage_prompts for _n, _t, p in entries_in(prompt)]


class Harness:
    def __init__(self, tmp_path, url, *, focus_value=None, settings=None, model=None):
        self.store = MemoryStore()
        self.fetcher = FixtureFetcher(padded_sites(tmp_path))
        self.model = model or FocusModel()
        spec = json.loads(json.dumps(FIXTURE))
        spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID, settings=dict(settings or {}))
        spec["resource"].update(url=url, storage_mode="live", model="openai/fake-small-model",
                                focus=focus_value if focus_value is not None else {"mode": "everything"})
        spec["secrets"] = {"github_token": None, "credentials": None}
        self.request = JobStartRequest.model_validate(spec)
        self.store.add_resource(OWNER, RID, url=url, storage_mode="live", generation=2)
        self.store.add_job(OWNER, RID, JID, status="running")
        self.store.jobs[JID]["target_generation"] = 3

    def run(self):
        async def build_llm(owner, model):
            return self.model

        async def is_cancelled():
            return False

        async def set_stage(stage, progress=None):
            await self.store.set_job_stage(OWNER, JID, stage, progress.model_dump() if progress else {})

        ctx = JobContext(request=self.request, settings=EffectiveSettings(self.request.settings), target_generation=3,
                         is_cancelled=is_cancelled, set_stage=set_stage)
        with net.use_fetcher(self.fetcher):
            return asyncio.run(pipeline.run(ctx, store=self.store, build_llm=build_llm))

    @property
    def resource(self):
        return self.store.resources[RID]

    def entries(self):
        return self.store.live_entries(RID)

    def report(self):
        return IngestionReport.model_validate(self.resource["ingestion_report"])


def _kept_paths(h):
    return sorted(e["url"].replace(WIKI, "/") for e in h.entries() if e["status"] == "kept")


def test_presort_strict_drops_unrelated(tmp_path):
    """Step 1: with Strict, an entry with no keyword of the focus is dropped before any call."""
    h = Harness(tmp_path, WIKI, focus_value=dict(SQLI, strictness="strict"))
    outcome = h.run()
    assert outcome.status == "succeeded"
    judged = h.model.judged_paths()
    assert judged and all("/sqli/" in p for p in judged)
    dropped = [e for e in h.entries() if e["status"] == "dropped"]
    assert dropped and all(e["drop_reason"] == focus.PRESORT_DROP_REASON for e in dropped)
    assert {e["url"] for e in dropped} >= {WIKI + "kerberos/golden-ticket/", WIKI + "xss/reflected/"}
    assert all("/sqli/" in p for p in _kept_paths(h))


def test_balanced_sends_every_entry_to_the_triage(tmp_path):
    h = Harness(tmp_path, WIKI, focus_value=SQLI)
    h.run()
    judged = h.model.judged_paths()
    assert any("/kerberos/" in p for p in judged) and any("/sqli/" in p for p in judged)
    # The pre-sort ranks: the pages naming the focus's keywords are judged first.
    first_unrelated = next(i for i, p in enumerate(judged) if "sqli" not in p)
    assert all("sqli" not in p for p in judged[first_unrelated:])


def test_rules_before_focus(tmp_path):
    """The rules are certain, the focus a judgement: a folder the rules exclude never reaches
    the triage, and is not a dropped entry either."""
    h = Harness(tmp_path, REPO, focus_value=dict(SQLI, strictness="loose"),
                settings={"type.github.excludeFolders": ["xss"]})
    outcome = h.run()
    assert outcome.status == "succeeded"
    judged = h.model.judged_paths()
    assert judged and not any("/xss/" in p for p in judged) and any("/sqli/" in p for p in judged)
    assert not any("/xss/" in e["url"] for e in h.entries())


def test_dropped_kept_with_reason(tmp_path):
    def decide(title, path):
        if "/sqli/" in path:
            return "keep", "SQL injection payloads", ["sql_injection"], ["payloads"]
        if "/xss/" in path:
            return "maybe", "", [], []
        return "drop", "not SQL injection", [], []

    h = Harness(tmp_path, WIKI, focus_value=SQLI, model=FocusModel(decide))
    outcome = h.run()
    assert outcome.status == "succeeded"
    by_url = {e["url"]: e for e in h.entries()}
    kerberos = by_url[WIKI + "kerberos/kerberoasting/"]
    assert kerberos["status"] == "dropped" and kerberos["drop_reason"] == "not SQL injection"
    assert by_url[WIKI + "xss/reflected/"]["status"] == "kept"  # maybe is kept (T6.9 checks it again)
    union = by_url[WIKI + "sqli/union-based/"]
    assert union["status"] == "kept" and "sql_injection" in union["topics"] and "payloads" in union["kinds"]
    report = h.report()
    dropped = sum(1 for e in h.entries() if e["status"] == "dropped")
    assert report.skipped.outsideFocus == dropped == report.focus["dropped"] > 0
    assert report.kept == report.focus["kept"] == len(h.entries()) - dropped
    assert report.focus["mode"] == "focused" and report.focus["maybe"] > 0
    # Dropped pages stay out of the 1.x map, the tree and the store.
    legacy = {i["path"] for i in h.resource["sitemap"]["nav"]}
    assert not any("kerberos" in p for p in legacy) and any("sqli" in p for p in legacy)
    assert not any(n["label"].lower().startswith("kerberos") for n in h.store.tree)


def test_model_error_keeps_maybe(tmp_path):
    """TD-20: a model error drops nothing and is not retried; the report counts model_error."""
    from llm_budget import LlmBudgetExhausted

    h = Harness(tmp_path, WIKI, focus_value=SQLI,
                model=FocusModel(triage_errors=[LlmBudgetExhausted("u1", 1, "yours")]))
    outcome = h.run()
    assert outcome.status == "succeeded"
    assert len(h.model.triage_prompts) == 1
    assert all(e["status"] == "kept" for e in h.entries())
    errors = {e.code: e.count for e in h.report().errors}
    assert errors.get("model_error") == 1


def test_everything_and_tag_only_change_nothing(tmp_path):
    for value in ({"mode": "everything"}, {}, {"mode": "tag_only", "topics": ["sql_injection"]},
                  {"mode": "focused"}):
        h = Harness(tmp_path / str(len(str(value))) / value.get("mode", "none"), WIKI, focus_value=value)
        h.run()
        assert h.model.triage_prompts == []
        assert all(e["status"] == "kept" for e in h.entries())
        assert h.report().skipped.outsideFocus == 0


def test_a_focus_that_drops_every_page_is_not_a_failure(tmp_path):
    h = Harness(tmp_path, WIKI, focus_value=SQLI, model=FocusModel(lambda t, p: ("drop", "no", [], [])))
    outcome = h.run()
    assert outcome.status == "succeeded" and outcome.swapped
    assert h.entries() and all(e["status"] == "dropped" for e in h.entries())
    assert h.report().kept == 0 and h.resource["last_error"] == ""


# --------------------------------------------------------------------------------------
# The stage alone
# --------------------------------------------------------------------------------------

class _Model:
    def __init__(self, decide):
        self.decide = decide
        self.calls = 0

    async def ainvoke(self, prompt, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        self.calls += 1
        return AIMessage(content=json.dumps({"entries": [
            {"n": n, "decision": self.decide(t), "reason": "r"} for n, t, _p in entries_in(prompt)]}))


def _state(entries, focus_value, model):
    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID)
    spec["resource"].update(focus=focus_value)
    request = JobStartRequest.model_validate(spec)

    async def no():
        return False

    async def stage(name, progress=None):
        return None

    ctx = JobContext(request=request, settings=EffectiveSettings({}), target_generation=3, is_cancelled=no,
                     set_stage=stage)

    async def build_llm(owner, model_id):
        return model

    state = pipeline.IngestState(ctx=ctx, store=None, blocking=pipeline._inline, build_llm=build_llm)
    state.entries = entries
    return state


def test_pinned_never_dropped():
    entries = [Candidate("https://w.test/a/", "Kerberos notes", "nav", "a", {"pinned": True}),
               Candidate("https://w.test/b/", "Kerberos notes", "pin", "b"),
               Candidate("https://w.test/c/", "Kerberos notes", "nav", "c")]
    model = _Model(lambda title: "drop")
    state = asyncio.run(focus.select(_state(entries, dict(SQLI, strictness="strict"), model)))
    statuses = [e.extra.get("status", "kept") for e in state.entries]
    # Strict's pre-sort dropped the unpinned one without a call; the pinned ones were judged,
    # and the model's drop does not apply to them.
    assert statuses == ["kept", "kept", "dropped"] and model.calls == 1
    assert state.entries[2].extra["drop_reason"] == focus.PRESORT_DROP_REASON


def test_an_entry_the_crawl_judged_is_not_judged_again():
    entries = [Candidate("https://w.test/a/", "SQLi notes", "crawl", "a", {"focus_decision": "keep"}),
               Candidate("https://w.test/b/", "SQLi union", "crawl", "b")]
    model = _Model(lambda title: "keep")
    state = asyncio.run(focus.select(_state(entries, SQLI, model)))
    assert model.calls == 1 and state.llm_calls == 1
    assert state.entries[0].extra["focus_decision"] == "keep"


def test_no_model_keeps_everything():
    entries = [Candidate("https://w.test/a/", "Kerberos", "nav", "a")]
    state = asyncio.run(focus.select(_state(entries, SQLI, None)))
    assert state.entries[0].extra.get("status", "kept") == "kept" and state.llm_calls == 0
    assert state.entries[0].extra["focus_decision"] == "maybe"

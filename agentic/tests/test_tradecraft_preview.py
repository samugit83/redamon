"""The focus preview (T5.3, §6.14): counts and every entry's decision and reason for up to 100
entries, with no write (AC-13), the loop model refused before any call, and the contract's deadline
answered with the entries not judged as maybe.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_context import current_llm_purpose  # noqa: E402
from tradecraft import contract, preview  # noqa: E402
from tradecraft.contract import PreviewRequest, PreviewResult  # noqa: E402

ENTRY = re.compile(r"^(\d+)\. (.*) — (.*)$", re.M)
FOCUS = {"mode": "focused", "topics": ["sql_injection"], "kinds": ["payloads"], "keep": "SQL injection payloads",
         "strictness": "balanced"}


class Model:
    def __init__(self, hang=False, error=None):
        self.hang, self.error = hang, error
        self.prompts, self.purposes = [], []

    async def ainvoke(self, prompt, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        self.prompts.append(prompt)
        self.purposes.append(dict(current_llm_purpose.get()))
        if self.error is not None:
            raise self.error
        if self.hang:
            await asyncio.Event().wait()
        block = prompt.split("Entries (number. title — path):", 1)[1]
        out = []
        for n, title, path in ENTRY.findall(block):
            hit = "sql" in (title + path).lower()
            out.append({"n": int(n), "decision": "keep" if hit else ("maybe" if "notes" in title.lower() else "drop"),
                        "reason": "SQL injection payloads" if hit else "not SQL injection",
                        "topics": ["sql_injection"] if hit else [], "kinds": ["payloads"] if hit else []})
        return AIMessage(content=json.dumps({"entries": out}))


def request(n=4, focus=None, model="openai/fake-small-model"):
    titles = ["SQL injection on PostgreSQL", "Site news", "SQLi WAF bypass", "Lab notes"]
    entries = [{"url": f"https://wiki.tc-fixture.test/p{i}/", "title": titles[i % 4]} for i in range(n)]
    return PreviewRequest.model_validate({"user_id": "u1", "model": model, "focus": focus or FOCUS, "entries": entries})


def run_preview(req, model):
    async def build(owner, model_id):
        assert owner == "u1" and model_id == req.model
        return model
    return asyncio.run(preview.preview_focus(req, build_llm=build))


def test_counts_and_examples():
    model = Model()
    answer = run_preview(request(), model)
    assert (answer.kept, answer.maybe, answer.dropped) == (2, 1, 1) and answer.llm_calls == 1
    assert [e.decision for e in answer.examples] == ["keep", "drop", "keep", "maybe"]
    assert answer.examples[0].reason == "SQL injection payloads" and answer.examples[0].topics == ["sql_injection"]
    assert answer.examples[1].reason == "not SQL injection" and answer.error_code == ""
    assert model.purposes == [{"purpose": "tradecraft_ingest", "step": "preview"}]
    PreviewResult.model_validate(answer.model_dump())


def test_strict_presort_drops_without_a_call():
    model = Model()
    answer = run_preview(request(focus=dict(FOCUS, strictness="strict")), model)
    news = answer.examples[1]
    assert news.decision == "drop" and news.reason == "no link to the focus"
    sent = [t for _n, t, _p in ENTRY.findall(model.prompts[0].split("Entries (number. title — path):", 1)[1])]
    assert sent == ["SQL injection on PostgreSQL", "SQLi WAF bypass"]


def test_any_mode_previews_as_focused():
    for mode in ("everything", "tag_only"):
        answer = run_preview(request(focus=dict(FOCUS, mode=mode)), Model())
        assert answer.dropped == 1 and answer.llm_calls == 1


def test_a_focus_with_nothing_to_judge_keeps_everything():
    model = Model()
    answer = run_preview(request(focus={"mode": "focused"}), model)
    assert model.prompts == [] and answer.kept == 4 and answer.llm_calls == 0


def test_caps_at_100():
    with pytest.raises(ValidationError):
        request(n=101)
    model = Model()
    answer = run_preview(request(n=100), model)
    assert model.prompts and len(model.prompts) == 1 and len(answer.examples) == 100
    assert contract.PREVIEW_MAX_ENTRIES == 100


def test_no_write():
    """AC-13: nothing is written. The module reaches neither the page store nor a database, and a
    store or a connection opened during a preview would fail this test."""
    source = Path(preview.__file__).read_text()
    for name in ("tradecraft.store", "tradecraft.db", "psycopg", "runtime.run_store", "Store("):
        assert name not in source, name
    import tradecraft.db as db
    import tradecraft.store as store

    def refuse(*a, **k):
        raise AssertionError("the preview opened the page store")

    original_store, original_conn = store.Store, db.connection
    store.Store, db.connection = refuse, refuse
    try:
        answer = run_preview(request(), Model())
    finally:
        store.Store, db.connection = original_store, original_conn
    assert answer.kept == 2


def test_loop_model_refused():
    """The real builder refuses a loop model before it reads a provider or calls anything."""
    answer = asyncio.run(preview.preview_focus(request(model="loop/mcp")))
    assert answer.error_code == "loop_model_not_supported_here" and answer.llm_calls == 0
    assert answer.maybe == 4 and [e.decision for e in answer.examples] == ["maybe"] * 4


def test_model_error_keeps_maybe():
    from llm_budget import LlmBudgetExhausted

    model = Model(error=LlmBudgetExhausted("u1", 3, "yours"))
    answer = run_preview(request(), model)
    assert len(model.prompts) == 1 and answer.error_code == "llm_budget_exhausted" and answer.maybe == 4


def test_deadline_keeps_maybe(monkeypatch):
    """The preview stops before the router's deadline, so its answer carries the entries: the ones
    not judged are maybe, with ``timeout``."""
    from tradecraft import api

    monkeypatch.setitem(contract.DEADLINES_SEC, "preview_focus", 0.3)
    monkeypatch.setattr(preview, "DEADLINE_MARGIN_SEC", 0.25)
    model = Model(hang=True)

    async def build(owner, model_id):
        return model

    monkeypatch.setattr("tradecraft.models.build_ingest_llm", build)
    answer = asyncio.run(api.preview_focus(request()))
    assert answer["error_code"] == "timeout" and answer["maybe"] == 4 and len(answer["examples"]) == 4
    assert answer["llm_calls"] == 1

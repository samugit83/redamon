"""The focused summary (T5.2, §6.14 step 5): with a Focused focus the summary's one call describes
the subset the focus kept, from the kept pages' titles; without one the prompt is as before.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.contract import JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import focus, pipeline, summary  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402
from tradecraft.ingest.fetch import FetchedPage  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
SQLI = {"mode": "focused", "topics": ["sql_injection"], "kinds": ["payloads", "bypasses"],
        "keep": "SQL injection payloads and filter bypasses", "strictness": "balanced"}


class Model:
    def __init__(self):
        self.messages = []

    async def ainvoke(self, messages, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        self.messages.append(messages)
        return AIMessage(content="SQL injection subset of the wiki: payloads and filter bypasses.")


def state_for(focus_value, model):
    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id="j1", user_id="u1", actor_user_id="u1", resource_id="r1")
    spec["resource"].update(focus=focus_value, summary="", summary_source="generated", summary_locked=False)
    request = JobStartRequest.model_validate(spec)

    async def no():
        return False

    async def stage(name, progress=None):
        return None

    async def build_llm(owner, model_id):
        return model

    ctx = JobContext(request=request, settings=EffectiveSettings({}), target_generation=2, is_cancelled=no,
                     set_stage=stage)
    st = pipeline.IngestState(ctx=ctx, store=None, blocking=pipeline._inline, build_llm=build_llm)
    st.url = "https://wiki.tc-fixture.test/"
    st.site_type = "mkdocs-wiki"
    st.home = FetchedPage(url=st.url, final_url=st.url, status=200, html="", text="A wiki of web attacks.")
    st.entries = [Candidate("https://wiki.tc-fixture.test/sqli/union/", "SQLi union payloads", "nav"),
                  Candidate("https://wiki.tc-fixture.test/xss/", "XSS basics", "nav",
                            extra={"status": "dropped", "dropped_by": "focus"})]
    return st


def run(coro):
    return asyncio.run(coro)


def test_focused_summary_mentions_subset():
    model = Model()
    st = run(summary.summarize(state_for(SQLI, model)))
    system, user = model.messages[0][0]["content"], model.messages[0][1]["content"]
    assert "keeps only part of the site (1 pages)" in system
    assert "SQL injection" in system and "Payloads & cheat sheets" in system and "Bypasses & evasion" in system
    assert "SQL injection payloads and filter bypasses" in system
    assert "subset" in system and "not the whole site" in system
    # The titles sent are the kept pages' only.
    assert "SQLi union payloads" in user and "XSS basics" not in user
    assert st.summary.startswith("SQL injection subset") and st.llm_calls == 1


def test_unfocused_summary_unchanged():
    for value in ({"mode": "everything"}, {}, {"mode": "focused"}, {"mode": "tag_only", "topics": ["xss"]}):
        model = Model()
        run(summary.summarize(state_for(value, model)))
        system = model.messages[0][0]["content"]
        assert system == summary.system_prompt(300, "")
        assert "subset" not in system


def test_the_focus_comes_before_the_persons_extra_instructions():
    line = summary.focus_instruction(focus.Focus("focused", ("xss",)), 3)
    prompt = summary.system_prompt(300, "Always list the payload families.", line)
    assert prompt.index("keeps only part of the site (3 pages)") < prompt.index("Always list the payload families.")

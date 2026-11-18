"""The think decision when the model's answer holds a complete JSON object and more after it
(FIX-ITER2: a run ended after three answers that each failed with "Invalid JSON: Extra data").

The first complete object is the decision, whatever follows it, and only the length of what
follows is logged: it is model text. A first object that is not valid JSON, or not a valid
decision, still fails as before. The real think node is run with the model call replaced, for
the content shapes the provider adapters return (a string; Anthropic and Bedrock Converse text
blocks; a list of strings) and for Agent in the Loop, which answers through the same parser:
the run goes on with one model call, no second one asked for.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import json
import logging
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from orchestrator_helpers.parsing import try_parse_llm_decision  # noqa: E402
from test_tradecraft_hints import catalog, library, state, todo  # noqa: E402
from test_tradecraft_library_now_prompt import CONFIG, DECISION, ChatAnthropic, Loop, Plain, _Resp, settings  # noqa: E402
from tradecraft import runtime  # noqa: E402

TRAILING = '\n\n{"note": "a second object the model added", "action": "complete"}'


def test_the_first_object_is_the_decision_and_only_the_trailing_length_is_logged(caplog):
    answer = json.dumps(DECISION) + TRAILING
    with caplog.at_level(logging.WARNING):
        decision, error = try_parse_llm_decision(answer)
    assert error is None and decision.action == "use_tool" and decision.thought == DECISION["thought"]
    messages = [r.getMessage() for r in caplog.records]
    assert f"Used the first JSON object of the LLM response; ignored {len(TRAILING)} trailing character(s)" in messages
    assert not any("second object" in m for m in messages)
    # Prose with a brace after the object, and a fenced answer with a note after the fence.
    for tail in (" Then I will check the {admin} page.", "\n```\nNote: {done}"):
        decision, error = try_parse_llm_decision(json.dumps(DECISION, indent=2) + tail)
        assert error is None and decision.tool_args == {"page": "patt:401"}, tail


def test_an_invalid_first_object_still_fails():
    broken = '{"thought": "x", "action": "use_tool",} ' + json.dumps(DECISION)
    decision, error = try_parse_llm_decision(broken)
    assert decision is None and error.startswith("Invalid JSON: ")
    # A first object that parses but is no decision is not replaced by the one after it: required
    # fields missing, or a field of the wrong type.
    for first in ('{"note": "not a decision"}', '{"thought": ["a", "list"], "reasoning": "r", "action": "use_tool"}'):
        decision, error = try_parse_llm_decision(first + " " + json.dumps(DECISION))
        assert decision is None and error.startswith("Validation error: "), first
    # Decisions in a list, or one after another with commas: an element of a list is no decision,
    # and the answer fails as it did before.
    one = {"thought": "a", "reasoning": "b"}
    for listed in (json.dumps([one, DECISION]), json.dumps(one) + ", " + json.dumps(DECISION)):
        decision, error = try_parse_llm_decision(listed)
        assert decision is None and error.startswith("Invalid JSON: Extra data"), listed[:30]


def test_the_log_line_holds_the_length_only_whatever_the_trailing_text(caplog):
    tail = '\n{"note": "token=ghp_FAKE0000000000 password=fake-hunter2 cookie=fake-session"}'
    with caplog.at_level(logging.DEBUG):
        decision, error = try_parse_llm_decision(json.dumps(DECISION) + tail)
    assert error is None and decision.action == "use_tool"
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert f"ignored {len(tail)} trailing character(s)" in text
    assert not any(secret in text for secret in ("ghp_FAKE", "fake-hunter2", "fake-session", "token="))


def _think(content, llm):
    """One real think whose model answers ``content``; (the node's updates, the model calls)."""
    tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
    calls = []

    async def call(_llm, messages, **_kw):
        calls.append(list(messages))
        return _Resp(content)

    async def go():
        ps._settings_ctx.set(settings())
        with runtime.use_store(object()), runtime.use_index(library()):
            runtime.bind_run_catalog(catalog())
            with patch.object(tn, "retry_llm_call", new=call), \
                 patch("orchestrator_helpers.skill_loader.list_skills", return_value=[]):
                st = state(todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])
                return await tn.think_node(st, CONFIG, llm=llm, guidance_queues={},
                                           neo4j_creds=("bolt://tc-fixture.invalid", "u", "p"))

    return contextvars.Context().run(asyncio.run, go()), calls


def test_every_adapter_and_the_loop_go_on_with_one_model_call():
    text = json.dumps(DECISION) + TRAILING
    shapes = {
        "string": (text, Plain()),
        "anthropic and bedrock text blocks": ([{"type": "text", "text": text}], ChatAnthropic()),
        "list of strings": ([text], Plain()),
        "agent in the loop": (text, Loop()),
    }
    for shape, (content, llm) in shapes.items():
        updates, calls = _think(content, llm)
        assert updates["_decision"]["action"] == "use_tool", shape
        assert updates["_decision"]["tool_args"] == {"page": "patt:401"}, shape
        assert len(calls) == 1, shape

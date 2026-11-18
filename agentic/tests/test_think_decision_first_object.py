"""The think decision when the model's answer holds a complete JSON object and more after it
(FIX-ITER2: a run ended after three answers that each failed with "Invalid JSON: Extra data").

A first object complete for its own action (a tool for use_tool, a plan for plan_tools, ...) is
the decision, whatever follows it, and only the length of what follows is logged: it is model
text. A first object that is only part of a decision, its tool or plan in the next object, would
end the run in generate_response: it fails with "Extra data" as before, and the think node asks
again. A first object that is not valid JSON, or not a valid decision, still fails too.

The real think node is run with ``retry_llm_call`` replaced by a fake answer. Its "adapters" are
stub classes: ``Plain`` and ``ChatAnthropic`` (the class name the cached tiers split for) with the
content shapes their providers return (a string; text blocks, the one shape Anthropic and Bedrock
Converse share; a list of strings), and ``Loop``, which marks Agent in the Loop, whose driver's
answer reaches the same parser. No provider library is called.
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
    # A first object that parses but is no decision is not replaced by the one after it: it lacks
    # what its action needs (the default action, use_tool, needs a tool), or it has all of that and
    # a field of the wrong type.
    decision, error = try_parse_llm_decision('{"note": "not a decision"} ' + json.dumps(DECISION))
    assert decision is None and error.startswith("Invalid JSON: Extra data")
    wrong_type = {"thought": ["a", "list"], "reasoning": "r", "action": "use_tool", "tool_name": "execute_curl"}
    decision, error = try_parse_llm_decision(json.dumps(wrong_type) + " " + json.dumps(DECISION))
    assert decision is None and error.startswith("Validation error: ")
    # Decisions in a list, or one after another with commas: an element of a list is no decision,
    # and the answer fails as it did before.
    one = {"thought": "a", "reasoning": "b"}
    for listed in (json.dumps([one, DECISION]), json.dumps(one) + ", " + json.dumps(DECISION)):
        decision, error = try_parse_llm_decision(listed)
        assert decision is None and error.startswith("Invalid JSON: Extra data"), listed[:30]


WHY = {"thought": "The probe goes next.", "reasoning": "It answers the open question."}
CURL = {"tool_name": "execute_curl", "tool_args": {"url": "http://lab.example.invalid/"}}
STEPS = {"steps": [{"tool_name": "execute_curl", "tool_args": {"url": "http://lab.example.invalid/"}}]}
QUESTION = {"question": "Which host?", "context": "Two hosts answer."}
MEMBERS = {"members": [{"name": "web", "task": "Probe the login form"}], "plan_rationale": "One front."}
SPLIT = {
    "the tool after the thought": (WHY, {"action": "use_tool", **CURL}),
    "the tool after the action": ({**WHY, "action": "use_tool"}, CURL),
    "the plan after the action": ({**WHY, "action": "plan_tools"}, {"tool_plan": STEPS}),
    "a plan with no step": ({**WHY, "action": "plan_tools", "tool_plan": {"steps": []}}, {"tool_plan": STEPS}),
    "a step with no tool": ({**WHY, "action": "plan_tools", "tool_plan": {"steps": [{"tool_args": {}}]}},
                            {"tool_plan": STEPS}),
    "the question after the action": ({**WHY, "action": "ask_user"}, {"user_question": QUESTION}),
    "a member with no task": ({**WHY, "action": "deploy_fireteam", "fireteam_plan": {"members": [{"name": "web"}]}},
                              {"fireteam_plan": MEMBERS}),
    "the phase after the action": ({**WHY, "action": "transition_phase"},
                                   {"phase_transition": {"to_phase": "exploitation"}}),
    "the skill after the action": ({**WHY, "action": "switch_skill"}, {"skill_switch": {"to_skill": "xss"}}),
}


def test_a_first_object_that_is_only_part_of_the_decision_fails_as_before():
    """Review finding (FIX-ITER2 review 2): a first object without what its own action needs would
    route to generate_response and end the run; it fails with "Extra data", so the think node asks
    again, as it did before. The two objects are never merged."""
    for case, (first, rest) in SPLIT.items():
        decision, error = try_parse_llm_decision(json.dumps(first) + "\n" + json.dumps(rest))
        assert decision is None and error.startswith("Invalid JSON: Extra data"), case


def test_a_first_object_complete_for_its_action_is_the_decision():
    for action, needs in (("use_tool", CURL), ("plan_tools", {"tool_plan": STEPS}),
                          ("ask_user", {"user_question": QUESTION}), ("complete", {"completion_reason": "Done."}),
                          ("deploy_fireteam", {"fireteam_plan": MEMBERS}),
                          ("transition_phase", {"phase_transition": {"to_phase": "exploitation"}}),
                          ("switch_skill", {"skill_switch": {"to_skill": "xss"}})):
        decision, error = try_parse_llm_decision(json.dumps({**WHY, "action": action, **needs}) + TRAILING)
        assert error is None and decision.action == action, action


def test_the_log_line_holds_the_length_only_whatever_the_trailing_text(caplog):
    tail = '\n{"note": "token=ghp_FAKE0000000000 password=fake-hunter2 cookie=fake-session"}'
    with caplog.at_level(logging.DEBUG):
        decision, error = try_parse_llm_decision(json.dumps(DECISION) + tail)
    assert error is None and decision.action == "use_tool"
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert f"ignored {len(tail)} trailing character(s)" in text
    assert not any(secret in text for secret in ("ghp_FAKE", "fake-hunter2", "fake-session", "token="))


def _think(content, llm, then=None):
    """One real think whose model answers ``content``, and ``then`` when it is asked again; (the
    node's updates, the model calls)."""
    tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
    calls = []

    async def call(_llm, messages, **_kw):
        calls.append(list(messages))
        return _Resp(content if len(calls) == 1 or then is None else then)

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


def test_a_split_decision_is_asked_again_through_every_adapter_and_the_loop():
    """The review's scenario through the real think node: the model's first answer holds the
    thought in one object and the tool in the next; the node asks again (as before the first-object
    rule) and goes on with the second answer, instead of a use_tool with no tool."""
    split = json.dumps(WHY) + "\n" + json.dumps({"action": "use_tool", **CURL})
    for shape, (content, llm) in {"string": (split, Plain()),
                                  "anthropic and bedrock text blocks": ([{"type": "text", "text": split}],
                                                                        ChatAnthropic()),
                                  "agent in the loop": (split, Loop())}.items():
        updates, calls = _think(content, llm, then=json.dumps(DECISION))
        assert len(calls) == 2 and "Extra data" in str(calls[1][-1].content), shape
        assert updates["_decision"]["tool_name"] == "tradecraft_lookup", shape

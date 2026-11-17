"""Library now in the real think node's prompt (owner decision 2026-11-17).

The think call's messages as the real ``think_node`` and prompt builders make them (the model call
is the only thing replaced, to capture them):

- with a built-in skill, a user skill and no skill, the skill's block is unchanged, the main
  instructions hold the one general rule, and the Library now block ends the system message;
- the library's line for the chosen skill sits just before the skill's block;
- every provider adapter still sends one system message (OpenAI and OpenAI-compatible strict chat
  templates, Anthropic, Gemini, Bedrock Converse, the Agent in the Loop renderer), and the
  thought's "Library: ..." sentence parses, through a provider and through the loop;
- the cached prefix stays the same from think to think while the block changes;
- a run with no active resource (none, or all turned off) sees no Tradecraft text anywhere,
  stealth mode included, and a run with one sees the rule, the tools, the block and the stealth
  section; the Fireteam member prompt follows the same rule.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import inspect
import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
from test_tradecraft_hints import FOOTER, catalog, library, state, todo  # noqa: E402
from tradecraft import runtime  # noqa: E402
from tradecraft.library import hints  # noqa: E402

CONFIG = {"configurable": {"user_id": "owner-1", "project_id": "p-libnow", "session_id": "s-1"}}
USER_SKILL = {"id": "abc", "name": "JWT none algorithm", "description": "Forge tokens signed with alg none.",
              "content": "## My JWT playbook\n\n1. Decode the token.\n2. Set alg to none and drop the signature."}
SKILLS = {"built-in": "sql_injection", "user": "user_skill:abc", "none": "web-unclassified"}
COVERAGE = {"pages": 12, "resources": [{"slug": "patt", "type": "github-repo", "pages": 12}],
            "topics": {"sql_injection": {"pages": 12, "kinds": {"payloads": 8}, "technologies": {"postgresql": 3}}}}
SKILL_LINE = "Library for SQL injection: 12 pages · payloads 8 · PostgreSQL"
DECISION = {"thought": "Library: read patt:401. Its time based payloads fit the next probe.",
            "reasoning": "The skill says confirm with a delay; the page has the PostgreSQL one.",
            "action": "use_tool", "tool_name": "tradecraft_lookup", "tool_args": {"page": "patt:401"},
            "updated_todo_list": [{"description": "Confirm time based blind SQL injection", "status": "in_progress",
                                   "priority": "high"}]}
TRADECRAFT_TEXT = re.compile(r"tradecraft|Library now|Your library|Library for ", re.IGNORECASE)


def settings(**extra):
    out = dict(ps.DEFAULT_AGENT_SETTINGS)
    config = json.loads(json.dumps(out["ATTACK_SKILL_CONFIG"]))
    config["user"] = {"abc": True}
    out.update({"ATTACK_SKILL_CONFIG": config, "USER_ATTACK_SKILLS": [USER_SKILL], "TRADECRAFT_V2": True,
                "TRADECRAFT_ASK": True, "PERSISTENT_CHECKPOINTER": False})
    out.update(extra)
    return out


class _Resp:
    def __init__(self, content):
        self.content = content
        self.usage_metadata = {"input_tokens": 10, "output_tokens": 5}


class ChatAnthropic:
    """The class name ``build_system_message_content`` splits the cache tiers for."""


class Plain:
    pass


class Loop:
    is_agent_in_the_loop = True


def run(states, *, cat="default", llm=None, run_settings=None, coverage=None, answer=None, before=None):
    """Real thinks in one run, its catalog bound once as at a run's start: ``states`` is the first
    state, then functions that make the next state from the one the previous think left. Returns
    [(the messages sent to the model, the node's updates)] and what ``before`` built in the run."""
    tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
    captured = []

    async def call(_llm, messages, **_kw):
        captured.append(list(messages))
        return _Resp(answer if answer is not None else json.dumps(DECISION))

    async def go():
        ps._settings_ctx.set(run_settings if run_settings is not None else settings())
        with runtime.use_store(object()), runtime.use_index(library()):
            runtime.bind_run_catalog(catalog() if cat == "default" else cat)
            if coverage is not None:
                runtime._coverage.set(coverage)
            extra = before() if before else None
            out, st = [], None
            with patch.object(tn, "retry_llm_call", new=call), \
                 patch("orchestrator_helpers.skill_loader.list_skills", return_value=[]):
                for step in states:
                    st = step({**st, **out[-1][1]}) if callable(step) else step
                    updates = await tn.think_node(st, CONFIG, llm=llm if llm is not None else Plain(),
                                                  guidance_queues={}, neo4j_creds=("bolt://tc-fixture.invalid", "u", "p"))
                    out.append((captured[-1], updates))
        return out, extra

    return contextvars.Context().run(asyncio.run, go())


def think(st, **kw):
    """One real think: (the messages sent to the model, the node's updates, what ``before`` built
    in the same run context)."""
    out, extra = run([st], **kw)
    return out[0][0], out[0][1], extra


def system_text(messages):
    content = messages[0].content
    return content if isinstance(content, str) else "\n\n".join(b["text"] for b in content)


def all_text(messages):
    return "\n\n".join(system_text([m]) if m.type == "system" else str(m.content) for m in messages)


def rules_section(text):
    return text[text.index("### Important Rules:"):text.index("### When to Ask User")]


def skill_block(skill):
    """The skill's own block as the prompt builders render it in this run."""
    import prompts

    allowed = ps.get_allowed_tools_for_phase("exploitation")
    if skill == "sql_injection":
        return prompts.build_builtin_skill_workflow(skill, allowed, False, [])
    if skill.startswith("user_skill:"):
        return [f"## User Attack Skill: {USER_SKILL['name']}\n\n{USER_SKILL['content']}"]
    return [prompts.UNCLASSIFIED_EXPLOIT_TOOLS]


# --------------------------------------------------------------------------------------
# The rule, the block and the skill's block, for every kind of skill
# --------------------------------------------------------------------------------------

def test_every_kind_of_skill_keeps_its_block_and_gets_the_rule_and_the_block():
    for kind, skill in SKILLS.items():
        st = state(attack_path_type=skill, todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])
        messages, _, block = think(st, before=lambda s=skill: skill_block(s))
        text = system_text(messages)
        assert block and all(part in text for part in block), kind
        # The one general rule, in the main instructions' rules, the same for every skill.
        assert text.count(hints.RULE) == 1 and hints.RULE in rules_section(text), kind
        assert "as you go\n6. **Your library.**" in text, kind
        # The block ends the system message, after everything else.
        tail = text[text.rindex("Library now (for your current goal: "):]
        assert tail.splitlines()[0] == 'Library now (for your current goal: "Confirm time based blind SQL injection"):'
        assert text.endswith(FOOTER) and "patt:401" in tail, kind
        assert text.index(block[-1]) < text.index(hints.RULE) < text.rindex("Library now (for your current goal")


def test_the_skill_line_sits_just_before_the_skills_block():
    st = state(todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])
    messages, _, block = think(st, coverage=COVERAGE, before=lambda: skill_block("sql_injection"))
    text = system_text(messages)
    assert text.count(SKILL_LINE) == 1
    line_end = text.index(SKILL_LINE) + len(SKILL_LINE)
    assert line_end < text.index(block[0]) and text[line_end:text.index(block[0])].strip() == ""
    # The other skills have no line: a user skill and no skill have no library topic.
    for skill in ("user_skill:abc", "web-unclassified"):
        messages, _, _ = think(state(attack_path_type=skill), coverage=COVERAGE)
        assert "Library for " not in system_text(messages)


def test_without_a_library_the_rules_read_as_before():
    messages, _, _ = think(state(), cat=None)
    rules = rules_section(system_text(messages))
    assert rules.rstrip().endswith("5. **Add exploitation steps as TODO items** and mark them in_progress/completed as you go")
    assert "Your library" not in rules


# --------------------------------------------------------------------------------------
# Valid messages for every adapter; the thought's sentence parses
# --------------------------------------------------------------------------------------

def _alternates(roles):
    """The rule of the chat templates that allow one leading system message (Mistral, Gemma 3,
    Llama 2, as vLLM, LM Studio and llama.cpp render them): then user, assistant, user, ..."""
    rest = roles[1:] if roles and roles[0] == "system" else roles
    return all(role == ("user" if i % 2 == 0 else "assistant") for i, role in enumerate(rest))


def test_one_system_message_for_every_adapter():
    from agent_in_the_loop.prompt_doc import render as render_doc, to_parts
    from langchain_anthropic.chat_models import _format_messages
    from langchain_aws.chat_models.bedrock_converse import _messages_to_bedrock
    from langchain_google_genai.chat_models import _parse_chat_history
    from langchain_openai.chat_models.base import _convert_message_to_dict

    st = state(todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])
    for shape, llm in (("tiers", ChatAnthropic()), ("plain", Plain()), ("loop", Loop())):
        messages, updates, _ = think(st, llm=llm)
        assert updates["_decision"]["action"] == "use_tool", shape
        note = system_text(messages)[system_text(messages).rindex("Library now (for your current goal"):]
        roles = [_convert_message_to_dict(m)["role"] for m in messages]
        assert roles == ["system", "user"] and _alternates(roles), shape
        system, rest = _format_messages(messages, model="claude-x")
        assert len(rest) == 1 and rest[0]["role"] == "user", shape
        if shape == "plain":
            assert isinstance(system, str) and system.endswith(note)
        else:
            # The block is one more text block after the tiers, with no cache_control.
            assert system[-1] == {"type": "text", "text": note}, shape
            cached = [b for b in system if "cache_control" in b]
            assert len(cached) == (3 if shape == "tiers" else 0), shape
        instruction, history = _parse_chat_history(messages)
        assert instruction is not None and len(history) == 1 and history[0].role == "user", shape
        bedrock_messages, bedrock_system = _messages_to_bedrock(messages)
        assert [m["role"] for m in bedrock_messages] == ["user"] and note in bedrock_system[-1]["text"], shape
        parts = to_parts(messages)
        assert [m.role for m in parts] == ["system", "user"] and parts[0].parts[-1].text.endswith(FOOTER), shape
        document, _ = render_doc(parts, delivered=set(), full=False)
        assert document.count("Library now (for your current goal") == 1 and hints.RULE in document, shape


def test_the_thoughts_library_sentence_parses():
    from orchestrator_helpers.parsing import try_parse_llm_decision

    st = state(todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])
    for llm in (Plain(), Loop()):
        _, updates, _ = think(st, llm=llm)
        assert updates["_decision"]["thought"].startswith("Library: read patt:401. ")
        assert updates["_decision"]["tool_args"] == {"page": "patt:401"}
    nothing = {**DECISION, "thought": "Library: nothing fit. Probe the delay by hand."}
    for answer in (json.dumps(nothing), "Library: nothing fit.\n" + json.dumps(nothing),
                   "```json\n" + json.dumps(nothing, indent=2) + "\n```"):
        decision, error = try_parse_llm_decision(answer)
        assert error is None and decision.thought.startswith("Library: nothing fit."), answer[:40]
    # With stealth on, the thought still begins with its risk line and holds the library sentence.
    stealthy = {**DECISION, "thought": "STEALTH RISK: LOW — a library read. Library: read patt:401."}
    decision, error = try_parse_llm_decision(json.dumps(stealthy))
    assert error is None and "Library: read patt:401." in decision.thought


# --------------------------------------------------------------------------------------
# The cached prefix from think to think
# --------------------------------------------------------------------------------------

def test_the_cached_prefix_stays_while_the_block_changes():
    first_goal = state(todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])

    def second_goal(st):
        return {**st, "todo_list": [todo("Confirm time based blind SQL injection", "completed"),
                                    todo("Dump the users table with stacked queries", "in_progress")]}

    (one, _), (two, _) = run([first_goal, second_goal], llm=ChatAnthropic())[0]
    cached = [[b for b in m[0].content if "cache_control" in b] for m in (one, two)]
    assert len(cached[0]) == 3 and cached[0] == cached[1]
    assert one[0].content[-1] != two[0].content[-1]
    assert 'goal: "Dump the users table with stacked queries"' in two[0].content[-1]["text"]


# --------------------------------------------------------------------------------------
# No active resource: no Tradecraft at all; one: all of it
# --------------------------------------------------------------------------------------

def member_prompt():
    tn = importlib.import_module("orchestrator_helpers.nodes.fireteam_member_think_node")
    return tn._build_member_prompt({"current_phase": "exploitation", "task": "check the login form",
                                    "attack_path_type": "xss", "tools": [], "max_iterations": 5})


def test_no_active_resource_no_tradecraft_text():
    """The owner has no resource, or the project turned them all off (the webapp's catalog is 2.0
    with no resource then): not a word of Tradecraft reaches the model, stealth mode included."""
    for cat in (None, catalog(resources=[])):
        for skill in ("xss", "web-unclassified"):
            messages, updates, member = think(state(attack_path_type=skill), cat=cat,
                                              run_settings=settings(STEALTH_MODE=True), before=member_prompt)
            found = TRADECRAFT_TEXT.findall(all_text(messages))
            assert not found, (cat and "empty catalog", skill, found[:3])
            assert "STEALTH MODE" in system_text(messages)
            assert not TRADECRAFT_TEXT.findall(member), member[:200]
            assert not any(k.startswith("tradecraft_") and v for k, v in updates.items() if k != "tradecraft_run_key")


def test_one_active_resource_shows_the_rule_the_tools_the_block_and_the_stealth_section():
    st = state(todo_list=[todo("Confirm time based blind SQL injection", "in_progress")])
    messages, _, member = think(st, run_settings=settings(STEALTH_MODE=True), before=member_prompt)
    text = system_text(messages)
    assert hints.RULE in text and text.endswith(FOOTER)
    for tool in ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask"):
        assert f"| **{tool}** |" in text, tool
    assert "### tradecraft_search, tradecraft_lookup, tradecraft_ask — NO RESTRICTIONS" in text
    assert "  - tradecraft_search, tradecraft_lookup, query_graph, web_search" in text
    assert '    tradecraft_lookup  -> {"page": "slug:N", "section": "..."}' in text
    assert '    tradecraft_lookup  -> {"page": "slug:N", "section": "..."}' in member
    # Search only: the librarian is named nowhere.
    search_only, _, _ = think(st, cat=catalog(**{"librarian.use": "search_only"}),
                              run_settings=settings(STEALTH_MODE=True, TRADECRAFT_ASK=False))
    assert "tradecraft_ask" not in all_text(search_only)
    # Hints off: the tools stay, with no rule and no block.
    off, _, _ = think(st, cat=catalog(**{"hints.enabled": False}))
    assert "| **tradecraft_lookup** |" in system_text(off)
    assert hints.RULE not in system_text(off) and "Library now (for your" not in system_text(off)


# --------------------------------------------------------------------------------------
# Where the hook sits
# --------------------------------------------------------------------------------------

def test_the_block_is_the_main_think_nodes_only():
    tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
    src = inspect.getsource(tn.think_node)
    content = src.index("system_message_content = build_system_message_content(")
    hook = src.index("_tc_note, _tc_hint_updates = await library_now(state, bound_catalog())")
    built = src.index("messages = think_messages(system_message_content, _tc_note)")
    assert content < hook < built < src.index("for attempt in range(max_retries):")
    assert src.index("    updates = {\n") < src.index("updates.update(_tc_hint_updates)") < src.index("return updates")
    assert "SystemMessage(content=_tc_note)" not in inspect.getsource(tn)
    member = importlib.import_module("orchestrator_helpers.nodes.fireteam_member_think_node")
    assert "library_now" not in inspect.getsource(member) and "library_rule" not in inspect.getsource(member)

"""Every executor path tells its tools which chat they run for.

Drift-map #89: the single-tool node passed the chat session id to
`set_tenant_context`, but the plan wave (also every fireteam member's wave), the
fireteam deploy node and the member think node did not, so the context held ""
while their tools ran. The signed X-Redamon-Ctx tag then carried
`session_id: null`: the replay and browser send budgets fell back to one bucket
per project, shared by every chat, the tag/credential same-run check was
skipped, and captured flows were tied to no chat.

A source test pins every `set_tenant_context(` call under the executor nodes to a
session id; behaviour tests drive the plan wave and a fireteam member's wave and
read the context var the executor sees; a unit test pins the tag's own fallback
to the per-turn log session id, the one its two siblings in tools.py use.
"""
from __future__ import annotations

import ast
import contextlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import pytest

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import project_settings  # noqa: E402
from agent_context import (  # noqa: E402
    current_log_session_id, current_project_id, current_session_id, current_user_id,
)
from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node  # noqa: E402

_NODES_DIR = _AGENTIC_DIR / "orchestrator_helpers" / "nodes"


def _set_tenant_calls(path: Path) -> list[ast.Call]:
    calls = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name == "set_tenant_context":
                calls.append(node)
    return calls


def _session_arg(call: ast.Call):
    if len(call.args) >= 3:
        return call.args[2]
    return next((kw.value for kw in call.keywords if kw.arg == "session_id"), None)


_CALLER_FILES = sorted(
    p.relative_to(_NODES_DIR).as_posix()
    for p in _NODES_DIR.rglob("*.py") if _set_tenant_calls(p)
)

# think_node runs no tool itself, but it sets the context its tools would read; the
# fix there is the same one-argument change and belongs to the file's own owner.
# strict: the day it passes a session id this XPASSes and the mark must go.
_KNOWN_MISSING: dict = {}


def test_the_walker_sees_every_executor_node():
    """Guard the guard: a walker that finds no call would pass vacuously."""
    expected = {"execute_tool_node.py", "execute_plan_node.py",
                "fireteam_deploy_node.py", "fireteam_member_think_node.py"}
    assert expected <= set(_CALLER_FILES), _CALLER_FILES


@pytest.mark.parametrize("rel", [
    pytest.param(rel, marks=pytest.mark.xfail(strict=True, reason=_KNOWN_MISSING[rel]))
    if rel in _KNOWN_MISSING else rel
    for rel in _CALLER_FILES
])
def test_every_set_tenant_context_call_passes_a_session_id(rel):
    missing = []
    for call in _set_tenant_calls(_NODES_DIR / rel):
        arg = _session_arg(call)
        # A literal ("" or a fixed id) names no chat; only a value read from the run does.
        if arg is None or isinstance(arg, ast.Constant):
            missing.append(call.lineno)
    assert not missing, (
        f"{rel}:{missing} calls set_tenant_context without the chat session id, so the "
        "tools it runs sign a capture tag with session_id null (drift-map #89)"
    )


_CONFIG = {"configurable": {"user_id": "u1", "project_id": "p1", "session_id": "chat-1"}}


@contextlib.contextmanager
def _settings(**overrides):
    base = dict(project_settings.DEFAULT_AGENT_SETTINGS)
    base.update(ROE_ENABLED=False, **overrides)
    with mock.patch.object(project_settings, "_settings", base):
        yield


def _recording_executor(seen: list):
    ok = {"success": True, "output": "ran", "error": None}

    async def _execute(*_a, **_k):
        seen.append(current_session_id.get())
        return ok

    ex = MagicMock()
    ex.execute = AsyncMock(side_effect=_execute)
    ex.execute_with_progress = AsyncMock(side_effect=_execute)
    return ex


class TheWaveToolsSeeTheChat(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Start blank, as a node after another's set_tenant_context(user, project) would.
        current_session_id.set("")

    async def test_a_plan_wave_sets_the_chat_session_id(self):
        seen: list = []
        state = {
            "messages": [], "current_iteration": 1, "current_phase": "exploitation",
            "_current_plan": {"steps": [{"tool_name": "execute_curl", "tool_args": {}},
                                        {"tool_name": "kali_shell", "tool_args": {}}]},
        }
        with _settings():
            await execute_plan_node(state, _CONFIG, tool_executor=_recording_executor(seen),
                                    streaming_callbacks={}, session_manager_base="http://x")
        self.assertEqual(seen, ["chat-1", "chat-1"])

    async def test_a_fireteam_members_wave_uses_the_session_id_its_state_carries(self):
        """A member graph runs without the parent's session id in its config; the
        member state (_build_member_state copies the parent's) supplies it."""
        from orchestrator_helpers.fireteam_member_graph import build_fireteam_member_graph

        seen: list = []
        graph = build_fireteam_member_graph(
            llm_getter=lambda: None, tool_executor=_recording_executor(seen),
            streaming_callbacks={}, session_manager_base="http://x", neo4j_creds=None,
        )
        state = {
            "messages": [], "current_iteration": 1, "max_iterations": 5,
            "current_phase": "exploitation", "user_id": "u1", "project_id": "p1",
            "session_id": "chat-1", "member_id": "m-1", "member_name": "Member",
            "fireteam_id": "ft-1", "tools": ["execute_curl"], "task": "t",
            "_decision": {"action": "plan_tools"},
            "_current_plan": {"steps": [{"tool_name": "execute_curl", "tool_args": {}}]},
        }
        with _settings():
            await graph.ainvoke(state, {"configurable": {"user_id": "u1", "project_id": "p1"}})
        self.assertEqual(seen, ["chat-1"])


class TheCaptureTagNamesTheChat(unittest.TestCase):
    KEY = "k" * 32

    def _tag_session(self, session_id: str, log_session_id: str):
        import redamon_ctx
        import tools

        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        tokens = [current_user_id.set("u1"), current_project_id.set("p1"),
                  current_session_id.set(session_id), current_log_session_id.set(log_session_id)]
        try:
            with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": self.KEY}):
                tag = executor._build_redamon_ctx("execute_curl")
        finally:
            for var, token in zip((current_user_id, current_project_id, current_session_id,
                                   current_log_session_id), tokens):
                var.reset(token)
        payload = redamon_ctx.verify_tag(tag, {"agent": self.KEY})
        self.assertIsNotNone(payload, "the tag did not verify")
        return payload.get("session_id")

    def test_a_blanked_session_id_falls_back_to_the_turns_log_session_id(self):
        self.assertEqual(self._tag_session("", "chat-1"), "chat-1")

    def test_the_tool_contexts_session_id_wins_when_set(self):
        self.assertEqual(self._tag_session("chat-2", "chat-1"), "chat-2")

    def test_no_session_at_all_signs_none(self):
        self.assertIsNone(self._tag_session("", ""))


if __name__ == "__main__":
    unittest.main()

"""
Decisions a project's settings take in the person's place still need the person's permission
(step 5.4 review, finding 1; OQ-R6's planned Fireteam gate).

With REQUIRE_APPROVAL_FOR_EXPLOITATION / REQUIRE_APPROVAL_FOR_POST_EXPLOITATION off nobody is asked
to approve a phase transition, and with REQUIRE_TOOL_CONFIRMATION off nobody confirms a dangerous
tool, so neither the ticket's `cap` nor the decision-time check was ever consulted: a collaborator
holding Use AI agent but not Exploitation & shells moved the run into exploitation (an attack-skill
switch flips the phase by itself) and ran kali_shell / metasploit_console unasked. Starting a
Fireteam wave asked nobody either, so `agent:fireteam` was never enforced.

Now the socket's task that runs the graph binds the run's actor (its ticket: the person, the
tenant, `act`, `cap`), and each such decision requires what the prompt would have checked:
`agent:approve_phase` for a transition, `agent:approve_dangerous` for a dangerous call (on every
executor path, Fireteam members included), `agent:fireteam` for a wave. The ticket's `cap` first;
then, for anyone but the project's owner signed in as themself, the webapp's fresh check. Refused
or unanswered: the transition, the tool or the wave does not happen, the `[rbac]` line is logged
and the chat says why. The owner keeps today's behaviour (their `cap` holds everything, and no
webapp call is made for them); a run no socket started has no person to check.

Run: ./agentic/run_tests.sh tests/test_unasked_decisions.py
"""
import ast
import asyncio
import contextlib
import importlib
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("WEBAPP_API_URL", "http://fake-webapp")

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import decision_check  # noqa: E402
from decision_check import DecisionCheck, RunActor, authorize_unasked, run_actor_holds  # noqa: E402
from writer_check import WriterCheck  # noqa: E402

try:
    import project_settings as ps  # noqa: E402
    from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node  # noqa: E402
    from orchestrator_helpers.nodes.execute_tool_node import execute_tool_node  # noqa: E402
    import websocket_api  # noqa: E402
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

ALL = frozenset(("agent:approve_phase", "agent:approve_dangerous", "agent:fireteam", "agent:kali_exec"))
ALLOWED = DecisionCheck(allowed=True)
REFUSED_LEVEL = DecisionCheck(False, "permission_required", "agent:approve_dangerous", "project_level")
UNAVAILABLE = DecisionCheck(False, "decision_check_unavailable")

OWNER = RunActor(user_id="owner-A", tenant_id="owner-A", project_id="p1", session_id="s1", cap=ALL)
COLLAB_NONE = RunActor(user_id="collab-B", tenant_id="owner-A", project_id="p1", session_id="s1",
                       cap=frozenset())
COLLAB_ALL = RunActor(user_id="collab-B", tenant_id="owner-A", project_id="p1", session_id="s1", cap=ALL)


@contextlib.contextmanager
def _as(actor):
    """The run's actor, as the socket's task binds it."""
    token = decision_check.current_run_actor.set(actor)
    try:
        yield
    finally:
        decision_check.current_run_actor.reset(token)


@contextlib.contextmanager
def _fresh(answer=ALLOWED):
    check = AsyncMock(return_value=answer)
    with mock.patch.object(decision_check, "authorize_decision", check):
        yield check


def _unasked(kind, *perms):
    return asyncio.run(authorize_unasked(kind, *perms))


class AuthorizeUnasked(unittest.TestCase):
    """The rule itself: cap first, then the webapp for anyone but the owner as themself."""

    def test_a_run_no_socket_started_is_today_s_behaviour(self):
        with _fresh() as check:
            self.assertEqual(_unasked("tool_confirmation", "agent:approve_dangerous"), ALLOWED)
        check.assert_not_awaited()
        self.assertTrue(run_actor_holds("agent:fireteam"))

    def test_the_owner_as_themself_is_allowed_without_asking_the_webapp(self):
        for cap in (ALL, None):
            with self.subTest(cap=cap), _as(RunActor("owner-A", "owner-A", "p1", "s1", cap=cap)), _fresh() as check:
                self.assertEqual(_unasked("approval", "agent:approve_phase"), ALLOWED)
                check.assert_not_awaited()

    def test_a_cap_without_the_permission_refuses_without_asking(self):
        with _as(COLLAB_NONE), _fresh() as check, self.assertLogs("decision_check", "WARNING") as logs:
            got = _unasked("approval", "agent:approve_phase")
        self.assertEqual(got, DecisionCheck(False, "permission_required", "agent:approve_phase", "capability"))
        check.assert_not_awaited()
        self.assertIn("[rbac] unasked decision refused kind=approval permission=agent:approve_phase", logs.output[0])

    def test_an_owner_whose_permissions_lack_it_is_refused_too(self):
        """A member owner with a narrowed set: their own cap says so (the OQ-R6 gate)."""
        restricted = RunActor("owner-A", "owner-A", "p1", "s1", cap=ALL - {"agent:fireteam"})
        with _as(restricted), _fresh() as check:
            got = _unasked("fireteam_deploy", "agent:fireteam")
        self.assertFalse(got.allowed)
        self.assertEqual(got.permission, "agent:fireteam")
        check.assert_not_awaited()
        with _as(restricted):
            self.assertFalse(run_actor_holds("agent:fireteam"))

    def test_a_collaborator_holding_it_is_asked_again_now(self):
        for answer in (ALLOWED, REFUSED_LEVEL, UNAVAILABLE):
            with self.subTest(answer=answer), _as(COLLAB_ALL), _fresh(answer) as check:
                self.assertEqual(_unasked("tool_confirmation", "agent:approve_dangerous"), answer)
                check.assert_awaited_once_with(
                    kind="tool_confirmation", user_id="collab-B", project_id="p1", session_id="s1",
                    actor_id=None, permissions=("agent:approve_dangerous",))

    def test_an_admin_acting_as_the_owner_is_asked_with_the_admin(self):
        acting = RunActor("owner-A", "owner-A", "p1", "s1", actor_id="admin-1", cap=ALL)
        with _as(acting), _fresh() as check:
            _unasked("approval", "agent:approve_phase")
        self.assertEqual(check.await_args.kwargs["actor_id"], "admin-1")
        self.assertEqual(check.await_args.kwargs["user_id"], "owner-A")

    def test_the_refusal_text_names_the_permission_or_the_outage(self):
        text = decision_check.unasked_refusal_text(
            DecisionCheck(False, "permission_required", "agent:approve_phase", "capability"),
            "move to the exploitation phase")
        self.assertIn("did not move to the exploitation phase", text)
        self.assertIn("agent:approve_phase", text)
        self.assertIn("could not check", decision_check.unasked_refusal_text(UNAVAILABLE, "start a Fireteam"))


# --- dangerous calls: every executor path -------------------------------------------------------

_CONFIG = {"configurable": {"user_id": "collab-B", "project_id": "p1", "session_id": "s1"}}


@contextlib.contextmanager
def _settings(**overrides):
    base = dict(ps.DEFAULT_AGENT_SETTINGS)
    base.update(overrides)
    with mock.patch.object(ps, "_settings", base):
        yield


def _executor():
    ok = {"success": True, "output": "ran", "error": None}
    ex = MagicMock()
    ex.execute = AsyncMock(return_value=ok)
    ex.execute_with_progress = AsyncMock(return_value=ok)
    return ex


def _dispatched(ex) -> bool:
    return ex.execute.await_count + ex.execute_with_progress.await_count > 0


async def _run_single(ex, tool_name, tool_args=None):
    state = {"messages": [], "current_iteration": 1, "current_phase": "exploitation",
             "_current_step": {"tool_name": tool_name, "tool_args": tool_args or {}}}
    out = await execute_tool_node(state, _CONFIG, tool_executor=ex, streaming_callbacks={},
                                  session_manager_base="http://x")
    return [out["_current_step"]]


async def _run_plan(ex, tool_name, tool_args=None):
    state = {"messages": [], "current_iteration": 1, "current_phase": "exploitation",
             "_current_plan": {"steps": [{"tool_name": tool_name, "tool_args": tool_args or {}}]}}
    out = await execute_plan_node(state, _CONFIG, tool_executor=ex, streaming_callbacks={},
                                  session_manager_base="http://x")
    return out["_current_plan"]["steps"]


async def _run_member(ex, action, tool_name, tool_args=None):
    from orchestrator_helpers.fireteam_member_graph import build_fireteam_member_graph

    graph = build_fireteam_member_graph(llm_getter=lambda: None, tool_executor=ex, streaming_callbacks={},
                                        session_manager_base="http://x", neo4j_creds=None)
    state = {"messages": [], "current_iteration": 1, "max_iterations": 5, "current_phase": "exploitation",
             "user_id": "collab-B", "project_id": "p1", "session_id": "s1", "member_id": "m-1",
             "member_name": "Member", "fireteam_id": "ft-1", "tools": [tool_name], "task": "t",
             "_decision": {"action": action}}
    step = {"tool_name": tool_name, "tool_args": tool_args or {}}
    if action == "use_tool":
        state["_current_step"] = step
    else:
        state["_current_plan"] = {"steps": [step]}
    final = await graph.ainvoke(state, _CONFIG)
    return [final["_current_step"]] if action == "use_tool" else final["_current_plan"]["steps"]


PATHS = (
    ("single tool", lambda ex, t, a=None: _run_single(ex, t, a)),
    ("plan wave", lambda ex, t, a=None: _run_plan(ex, t, a)),
    ("Fireteam member, single tool", lambda ex, t, a=None: _run_member(ex, "use_tool", t, a)),
    ("Fireteam member, plan wave", lambda ex, t, a=None: _run_member(ex, "plan_tools", t, a)),
)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class DangerousCallsUnasked(unittest.IsolatedAsyncioTestCase):
    """REQUIRE_TOOL_CONFIRMATION off: a dangerous call still needs agent:approve_dangerous."""

    async def _run(self, run, actor, answer=ALLOWED, tool="kali_shell", args=None, **settings):
        ex = _executor()
        settings.setdefault("REQUIRE_TOOL_CONFIRMATION", False)
        with _settings(**settings), _as(actor), _fresh(answer) as check:
            steps = await run(ex, tool, args)
        return ex, steps, check

    async def test_refused_without_the_permission_on_every_path_and_never_dispatched(self):
        for name, run in PATHS:
            with self.subTest(path=name):
                with self.assertLogs("decision_check", "WARNING") as logs:
                    ex, steps, check = await self._run(run, COLLAB_NONE)
                self.assertFalse(_dispatched(ex), "a refused dangerous call reached the executor")
                check.assert_not_awaited()
                for step in steps:
                    self.assertFalse(step["success"])
                    self.assertIn("REFUSED", step["tool_output"])
                    self.assertIn("agent:approve_dangerous", step["tool_output"])
                self.assertIn("[rbac] unasked decision refused kind=tool_confirmation", "\n".join(logs.output))

    async def test_a_background_job_of_a_dangerous_tool_is_refused_too(self):
        ex, steps, _ = await self._run(PATHS[0][1], COLLAB_NONE, tool="job_spawn",
                                       args={"tool_name": "metasploit_console", "tool_args": {}})
        self.assertFalse(_dispatched(ex))
        self.assertIn("REFUSED", steps[0]["tool_output"])

    async def test_the_webapp_refusing_or_not_answering_refuses_on_every_path(self):
        for answer, words in ((REFUSED_LEVEL, "agent:approve_dangerous"), (UNAVAILABLE, "could not check")):
            for name, run in PATHS:
                with self.subTest(path=name, code=answer.code):
                    ex, steps, check = await self._run(run, COLLAB_ALL, answer)
                    check.assert_awaited()
                    self.assertFalse(_dispatched(ex))
                    self.assertIn(words, steps[0]["tool_output"])

    async def test_allowed_with_it_the_call_runs_as_before(self):
        for name, run in PATHS:
            with self.subTest(path=name):
                ex, steps, check = await self._run(run, COLLAB_ALL)
                self.assertTrue(_dispatched(ex))
                check.assert_awaited_once()
                self.assertEqual(check.await_args.kwargs["kind"], "tool_confirmation")

    async def test_the_owner_runs_as_today_without_a_webapp_call(self):
        for name, run in PATHS:
            with self.subTest(path=name):
                ex, _, check = await self._run(run, OWNER)
                self.assertTrue(_dispatched(ex))
                check.assert_not_awaited()

    async def test_with_confirmations_on_the_person_who_confirmed_was_checked_then(self):
        for name, run in PATHS:
            with self.subTest(path=name):
                ex, _, check = await self._run(run, COLLAB_NONE, REQUIRE_TOOL_CONFIRMATION=True)
                self.assertTrue(_dispatched(ex))
                check.assert_not_awaited()

    async def test_a_tool_that_is_not_dangerous_asks_nothing(self):
        ex, _, check = await self._run(PATHS[0][1], COLLAB_NONE, tool="query_graph",
                                       args={"question": "hosts"})
        self.assertTrue(_dispatched(ex))
        check.assert_not_awaited()


# --- phase transitions and the Fireteam wave: the think node ------------------------------------

class _Recorder:
    """A streaming callback that records what reached the drawer."""

    def __init__(self):
        self.errors = []
        self._emitted_thinking_ids = set()

    async def on_error(self, message, recoverable=True, code="", **details):
        self.errors.append({"message": message, "recoverable": recoverable, "code": code, **details})

    def __getattr__(self, name):
        if not name.startswith("on_"):
            raise AttributeError(name)

        async def record(*a, **k):
            return None
        return record


def _state(phase="informational", **extra):
    from state import create_initial_state
    st = create_initial_state("collab-B", "p1", "s1", "recover the flag", 100)
    st["current_phase"] = phase
    st["_just_transitioned_to"] = None
    st.update(extra)
    return st


def _think(state, decision, *, settings=(), callback=None):
    tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
    resp = SimpleNamespace(content=json.dumps(decision), usage_metadata={"input_tokens": 10, "output_tokens": 5})
    base = dict(ps.DEFAULT_AGENT_SETTINGS)
    base.update(dict(settings))

    async def main():
        ps._settings_ctx.set(base)
        return await tn.think_node(
            state, {"configurable": {"user_id": "collab-B", "project_id": "p1", "session_id": "s1"}},
            llm=AsyncMock(), guidance_queues={}, neo4j_creds=("bolt://x", "u", "p"),
            streaming_callbacks={"s1": callback} if callback else None)

    with mock.patch.object(tn, "retry_llm_call", new=AsyncMock(return_value=resp)), \
            mock.patch.object(tn.chain_graph, "fire_update_chain_attack_path", MagicMock()):
        return asyncio.run(main())


def _route(state, updates):
    from orchestrator import AgentOrchestrator
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    return orch._route_after_think({**state, **updates})


TRANSITION = {"thought": "recon done", "reasoning": "exploit now", "action": "transition_phase",
              "phase_transition": {"to_phase": "exploitation", "reason": "map done", "planned_actions": ["x"]}}
NO_APPROVAL = (("REQUIRE_APPROVAL_FOR_EXPLOITATION", False),)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class PhaseTransitionsUnasked(unittest.TestCase):

    def test_refused_without_approve_phase_the_phase_stays_and_the_chat_says_why(self):
        cb = _Recorder()
        st = _state()
        with _as(COLLAB_NONE), _fresh() as check:
            updates = _think(st, TRANSITION, settings=NO_APPROVAL, callback=cb)
        check.assert_not_awaited()
        self.assertNotEqual(updates.get("current_phase"), "exploitation")
        self.assertIsNone(updates.get("_just_transitioned_to"))
        self.assertFalse(updates.get("awaiting_user_approval"))
        last = updates["execution_trace"][-1]
        self.assertEqual((last["tool_name"], last["success"]), ("phase_transition", False))
        self.assertIn("REFUSED", last["tool_output"])
        self.assertIn("agent:approve_phase", last["tool_output"])
        self.assertIn("Do NOT request transition_phase to exploitation", last["output_analysis"])
        (err,) = cb.errors
        self.assertEqual((err["code"], err["permission"], err["recoverable"]),
                         ("permission_required", "agent:approve_phase", True))
        self.assertNotIn("answer", err, "no card to put back: nobody was asked")
        self.assertEqual(_route(st, updates), "think")

    def test_a_tool_named_with_the_refused_transition_does_not_run(self):
        decision = {**TRANSITION, "tool_name": "kali_shell", "tool_args": {"command": "id"}}
        st = _state()
        with _as(COLLAB_NONE):
            updates = _think(st, decision, settings=NO_APPROVAL)
        self.assertEqual(_route(st, updates), "think")

    def test_the_webapp_not_answering_refuses_the_collaborator(self):
        cb = _Recorder()
        with _as(COLLAB_ALL), _fresh(UNAVAILABLE) as check:
            updates = _think(_state(), TRANSITION, settings=NO_APPROVAL, callback=cb)
        check.assert_awaited_once()
        self.assertEqual(check.await_args.kwargs["kind"], "approval")
        self.assertNotEqual(updates.get("current_phase"), "exploitation")
        self.assertEqual(cb.errors[0]["code"], "decision_check_unavailable")

    def test_a_third_refused_request_ends_the_run(self):
        refused = {"tool_name": "phase_transition", "tool_args": {"to_phase": "exploitation", "refused": True},
                   "success": False}
        st = _state(execution_trace=[dict(refused, iteration=i) for i in (1, 2)])
        with _as(COLLAB_NONE):
            updates = _think(st, TRANSITION, settings=NO_APPROVAL)
        self.assertTrue(updates.get("task_complete"))
        self.assertIn("agent:approve_phase", updates.get("completion_reason", ""))

    def test_allowed_the_transition_happens_as_before(self):
        for actor in (OWNER, COLLAB_ALL, None):
            with self.subTest(actor=actor and actor.user_id), _fresh() as check:
                with (_as(actor) if actor else contextlib.nullcontext()):
                    updates = _think(_state(), TRANSITION, settings=NO_APPROVAL)
                self.assertEqual(updates.get("current_phase"), "exploitation")
                self.assertEqual(updates.get("_just_transitioned_to"), "exploitation")
                self.assertEqual(check.await_count, 1 if actor is COLLAB_ALL else 0)

    def test_post_exploitation_unasked_needs_approve_phase_too(self):
        decision = {**TRANSITION, "phase_transition": {"to_phase": "post_exploitation", "reason": "r"}}
        with _as(COLLAB_NONE):
            updates = _think(_state("exploitation"), decision,
                             settings=(("REQUIRE_APPROVAL_FOR_POST_EXPLOITATION", False),))
        self.assertNotEqual(updates.get("current_phase"), "post_exploitation")

    def test_with_approvals_on_the_prompt_is_raised_and_nothing_is_asked_now(self):
        with _as(COLLAB_NONE), _fresh() as check:
            updates = _think(_state(), TRANSITION)
        self.assertTrue(updates.get("awaiting_user_approval"))
        check.assert_not_awaited()

    def test_an_attack_skill_switch_no_longer_flips_the_phase_by_itself(self):
        decision = {"thought": "sqli", "reasoning": "param", "action": "switch_skill",
                    "skill_switch": {"to_skill": "sql_injection", "reason": "error-based param"}}
        settings = NO_APPROVAL + (("AUTO_TRANSITION_ON_ATTACK_SKILL", True),
                                  ("ATTACK_SKILL_CONFIG", {"builtIn": {"sql_injection": True}, "user": {}}))
        cb = _Recorder()
        with _as(COLLAB_NONE):
            refused = _think(_state(), decision, settings=settings, callback=cb)
        self.assertEqual(refused.get("attack_path_type"), "sql_injection", "the skill itself switches")
        self.assertNotEqual(refused.get("current_phase"), "exploitation")
        self.assertIn("agent:approve_phase", refused["messages"][0].content)
        self.assertEqual(cb.errors[0]["permission"], "agent:approve_phase")
        with _as(OWNER):
            allowed = _think(_state(), decision, settings=settings)
        self.assertEqual(allowed.get("current_phase"), "exploitation")


FIRETEAM = {
    "thought": "fan out", "reasoning": "independent hosts", "action": "deploy_fireteam",
    "fireteam_plan": {"plan_rationale": "two hosts", "members": [
        {"name": "A", "task": "scan a", "tools": ["execute_curl"]},
        {"name": "B", "task": "scan b", "tools": ["execute_curl"]},
    ]},
}
FIRETEAM_ON = (("FIRETEAM_ENABLED", True), ("PERSISTENT_CHECKPOINTER", True),
               ("FIRETEAM_ALLOWED_PHASES", ["informational"]))


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class FireteamWaveStart(unittest.TestCase):

    def test_refused_without_agent_fireteam_no_wave_starts_and_the_chat_says_why(self):
        cb = _Recorder()
        with _as(RunActor("collab-B", "owner-A", "p1", "s1", cap=ALL - {"agent:fireteam"})), _fresh() as check:
            updates = _think(_state(), FIRETEAM, settings=FIRETEAM_ON, callback=cb)
        check.assert_not_awaited()
        self.assertIsNone(updates.get("_current_fireteam_plan"))
        self.assertNotEqual(updates["_decision"]["action"], "deploy_fireteam")
        self.assertIn("agent:fireteam", updates["messages"][0].content)
        self.assertEqual((cb.errors[0]["code"], cb.errors[0]["permission"]),
                         ("permission_required", "agent:fireteam"))

    def test_a_collaborator_holding_it_is_asked_again_with_the_fireteam_kind(self):
        with _as(COLLAB_ALL), _fresh(UNAVAILABLE) as check:
            updates = _think(_state(), FIRETEAM, settings=FIRETEAM_ON)
        self.assertEqual(check.await_args.kwargs["kind"], "fireteam_deploy")
        self.assertEqual(check.await_args.kwargs["permissions"], ("agent:fireteam",))
        self.assertIsNone(updates.get("_current_fireteam_plan"))

    def test_allowed_the_wave_starts_as_before(self):
        for actor in (OWNER, COLLAB_ALL, None):
            with self.subTest(actor=actor and actor.user_id), _fresh():
                with (_as(actor) if actor else contextlib.nullcontext()):
                    updates = _think(_state(), FIRETEAM, settings=FIRETEAM_ON)
                self.assertIsNotNone(updates.get("_current_fireteam_plan"))
                self.assertEqual(updates["_decision"]["action"], "deploy_fireteam")

    def test_the_prompt_offers_no_wave_to_a_person_without_it(self):
        tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
        for actor, offered in ((RunActor("collab-B", "owner-A", "p1", "s1", cap=frozenset()), False),
                               (OWNER, True)):
            with self.subTest(offered=offered):
                spy = MagicMock(wraps=tn.build_fireteam_prompt_fragments)
                with mock.patch.object(tn, "build_fireteam_prompt_fragments", spy), _as(actor):
                    _think(_state(), {"thought": "t", "reasoning": "r", "action": "complete",
                                      "completion_reason": "done"}, settings=FIRETEAM_ON)
                self.assertEqual(bool(spy.call_args.kwargs["enabled"]), offered)


# --- the socket binds the run's actor -----------------------------------------------------------

def _handler_methods():
    tree = ast.parse((_AGENTIC_DIR / "websocket_api.py").read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "WebSocketHandler")
    return {n.name: n for n in cls.body if isinstance(n, ast.AsyncFunctionDef)}


def _calls(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            yield sub, (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")), f


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class EveryRunBindsItsActor(unittest.TestCase):

    def test_every_method_that_runs_the_graph_binds_the_actor_first(self):
        methods = _handler_methods()
        runners = {}
        for name, method in methods.items():
            for call, attr, f in _calls(method):
                if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute)
                        and f.value.attr == "orchestrator" and attr.endswith("_with_streaming")):
                    runners.setdefault(name, []).append(call.lineno)
        self.assertGreaterEqual(len(runners), 5, f"found only {sorted(runners)}")
        for name, lines in runners.items():
            with self.subTest(method=name):
                binds = [c.lineno for c, attr, _ in _calls(methods[name]) if attr == "bind_run_actor"]
                self.assertTrue(binds, f"{name} runs the graph without binding the run's actor")
                self.assertLess(min(binds), min(lines))

    def test_a_query_runs_with_the_ticket_s_people_and_cap(self):
        seen = {}

        class Orch:
            async def invoke_with_streaming(self, **_kw):
                seen["actor"] = decision_check.current_run_actor.get()

        class WS:
            client = "t"

            async def send_json(self, _m):
                pass

        async def main():
            mgr = websocket_api.WebSocketManager()
            handler = websocket_api.WebSocketHandler(orchestrator=Orch(), ws_manager=mgr)
            conn = websocket_api.WebSocketConnection(WS())
            conn.cap = frozenset({"agent:approve_phase"})
            conn.actor_id = "admin-1"
            await mgr.authenticate(conn, "collab-B", "p1", "s1", verified=True)
            conn.tenant_id = "owner-A"
            await handler.handle_query(conn, {"question": "q"})
            await asyncio.wait_for(conn._active_task, 5)
            return decision_check.current_run_actor.get()

        # The per-run writer check (step 5.11 follow-up) is test_run_writer_check.py's; here it allows.
        with mock.patch.object(websocket_api, "update_conversation", AsyncMock()), \
                mock.patch.object(websocket_api, "second_writer_check", AsyncMock(return_value=WriterCheck(allowed=True))), \
                mock.patch.object(websocket_api, "save_chat_message", AsyncMock(return_value=None)):
            outside = asyncio.run(main())
        self.assertEqual(seen["actor"], RunActor(user_id="collab-B", tenant_id="owner-A", project_id="p1",
                                                 session_id="s1", actor_id="admin-1",
                                                 cap=frozenset({"agent:approve_phase"})))
        self.assertIsNone(outside, "the binding stays in the run's own task")

    def test_a_connection_without_a_tenant_names_its_person(self):
        conn = websocket_api.WebSocketConnection(SimpleNamespace())
        conn.user_id, conn.project_id, conn.session_id = "owner-A", "p1", "s1"
        self.assertTrue(conn.run_actor().is_owner)


if __name__ == "__main__":
    unittest.main()

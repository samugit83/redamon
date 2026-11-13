"""
Tickets carry the tenant and the actor; the agent splits them (RBAC step 5.3; SH-33, SH-34, SH-38).

A shared project's graph nodes carry its OWNER's user id (T9: the Neo4j key never changes),
while the person running the agent may be a collaborator. The webapp's ticket names both:
`ten`, the project's owner, and `sub`, the person (`act` stays the admin behind an act-as).
In the agent the tenant reaches every graph read and write (the attack chain of each label,
Fireteam members included), the REDAMON_CTX tag, the run credentials, the terminal's shell
and the triage run's graph; the person keeps the session key, the thread id, the chat, the
run registry, the Agent in the Loop scope, revocation and the triage run's `actorUserId`.

A ticket without `ten` was minted by a webapp from before this step, which minted tickets
only for a project's owner: its `sub` is the tenant, as before. A malformed `ten` never
verifies, so nothing falls back over it.

Run: ./agentic/run_tests.sh tests/test_ticket_tenant_actor.py
"""
import ast
import asyncio
import base64
import hashlib
import hmac
import importlib
import json
import os
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from ws_ticket import ticket_tenant, verify_ws_ticket  # noqa: E402

try:
    import websocket_api  # noqa: F401
    from fastapi.testclient import TestClient  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

# Outside the guard: a name missing from the agent is a failure, never a skip.
if _HAVE:
    from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402

    import machine_credential as mc  # noqa: E402
    import orchestrator as orchestrator_mod  # noqa: E402
    import orchestrator_helpers.chain_graph_writer as cg  # noqa: E402
    from agent_context import current_llm, current_project_id, current_user_id  # noqa: E402
    from orchestrator_helpers.config import create_config, get_tenant_id  # noqa: E402
    from websocket_api import (  # noqa: E402
        PROXIED_SOCKETS, ProxiedSocketRegistry, WebSocketConnection, WebSocketHandler,
        WebSocketManager, close_sockets,
    )

SECRET = "t" * 64
MASTER = "master-key-for-tenant-actor-tests"
OWNER, COLLAB, ADMIN = "owner-1", "collab-1", "admin-1"
PID, SID = "p-shared", "s-1"
NEO4J = ("bolt://unused", "neo4j", "pw")
NODES = Path(_AGENTIC_DIR) / "orchestrator_helpers" / "nodes"

COMPLETE = json.dumps({
    "thought": "t", "reasoning": "r", "action": "complete", "completion_reason": "done",
    "output_analysis": {
        "interpretation": "one recon step",
        "extracted_info": {"primary_target": "", "ports": [], "services": [], "technologies": [],
                           "vulnerabilities": [], "credentials": [], "sessions": []},
        "actionable_findings": [], "recommended_next_steps": [],
        "exploit_succeeded": False, "exploit_details": None, "chain_findings": [],
    },
})


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ticket(aud="agent", **claims) -> str:
    payload = {"sub": COLLAB, "pid": PID, "sid": SID, "aud": aud,
               "iat": int(time.time()), "exp": int(time.time()) + 60, **claims}
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


def _config(user=COLLAB, tenant=OWNER):
    return create_config(user, PID, SID, tenant)


class TicketClaims(unittest.TestCase):
    def test_ten_names_the_tenant_and_sub_stays_the_person(self):
        claims = verify_ws_ticket(_ticket(ten=OWNER, act=ADMIN), SECRET, expected_aud="agent")
        self.assertIsNotNone(claims)
        self.assertEqual((claims["sub"], ticket_tenant(claims), claims["act"]), (COLLAB, OWNER, ADMIN))

    def test_a_ticket_without_ten_behaves_as_today(self):
        # Minted by a webapp from before step 5.3, which minted only for the owner.
        claims = verify_ws_ticket(_ticket(sub=OWNER), SECRET, expected_aud="agent")
        self.assertIsNotNone(claims)
        self.assertNotIn("ten", claims)
        self.assertEqual(ticket_tenant(claims), OWNER)

    def test_a_malformed_ten_never_verifies(self):
        for bad in ("", None, 7, [OWNER], {"id": OWNER}, True):
            with self.subTest(ten=bad), self.assertLogs("ws_ticket", "WARNING") as logs:
                self.assertIsNone(verify_ws_ticket(_ticket(ten=bad), SECRET, expected_aud="agent"))
            self.assertIn("[rbac] ticket refused: malformed tenant", logs.output[0])

    def test_every_socket_reads_ten_the_same_way(self):
        for aud in ("agent", "kali-terminal", "cypherfix-triage", "cypherfix-codefix"):
            with self.subTest(aud=aud):
                claims = verify_ws_ticket(_ticket(aud=aud, ten=OWNER), SECRET, expected_aud=aud)
                self.assertEqual(ticket_tenant(claims), OWNER)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheConfigCarriesBoth(unittest.TestCase):
    def test_the_tenant_rides_beside_the_person_and_the_thread_stays_the_person_s(self):
        configurable = _config()["configurable"]
        self.assertEqual((configurable["user_id"], configurable["tenant_user_id"]), (COLLAB, OWNER))
        self.assertEqual(configurable["thread_id"], f"{COLLAB}:{PID}:{SID}")

    def test_without_a_tenant_the_person_is_the_tenant(self):
        for tenant in (None, ""):
            with self.subTest(tenant=tenant):
                self.assertEqual(create_config(OWNER, PID, SID, tenant)["configurable"]["tenant_user_id"], OWNER)
        self.assertEqual(create_config(OWNER, PID, SID)["configurable"]["tenant_user_id"], OWNER)

    def test_get_tenant_id_reads_the_config_then_the_state_then_the_person(self):
        self.assertEqual(get_tenant_id({"tenant_user_id": "stale"}, _config()), OWNER)
        bare = {"configurable": {"user_id": COLLAB, "project_id": PID, "session_id": SID}}
        self.assertEqual(get_tenant_id({"tenant_user_id": OWNER}, bare), OWNER)
        self.assertEqual(get_tenant_id({}, bare), COLLAB)
        self.assertEqual(get_tenant_id({"user_id": OWNER}, None), OWNER)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheNodesWriteUnderTheOwner(unittest.IsolatedAsyncioTestCase):
    """Each chain label, written by the root agent and by a Fireteam member."""

    def setUp(self):
        self.calls = []

        def record(name):
            def _record(*args, **kwargs):
                self.calls.append((name, args, kwargs))
                return True
            return _record

        names = ("fire_create_attack_chain", "fire_record_step", "sync_record_step", "fire_record_failure",
                 "fire_record_finding", "fire_record_exploit_success", "fire_resolve_step_bridges",
                 "fire_record_decision", "fire_update_chain_status", "fire_update_chain_attack_path")
        for name in names:
            patcher = mock.patch.object(cg, name, side_effect=record(name))
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(cg, "query_prior_chains", side_effect=lambda *a: self.calls.append(
            ("query_prior_chains", a, {})) or [])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tokens = [(var, var.set("")) for var in (current_user_id, current_project_id)]

    def tearDown(self):
        for var, token in reversed(self.tokens):
            var.reset(token)

    def written(self, name):
        return [kw for n, _a, kw in self.calls if n == name]

    async def test_the_attack_chain_is_created_under_the_owner_and_the_state_keeps_both(self):
        init_mod = importlib.import_module("orchestrator_helpers.nodes.initialize_node")
        classify = mock.AsyncMock(return_value=("sql_injection-unclassified", "informational", None, None, []))
        with mock.patch.object(init_mod, "classify_attack_path", classify):
            new = await init_mod._initialize({"messages": [HumanMessage(content="find the sqli")]}, _config(),
                                             llm=None, neo4j_creds=NEO4J)
        [chain] = self.written("fire_create_attack_chain")
        self.assertEqual((chain["user_id"], chain["project_id"], chain["chain_id"]), (OWNER, PID, SID))
        self.assertEqual((new["user_id"], new["tenant_user_id"]), (COLLAB, OWNER))

        self.calls.clear()
        state = {"messages": [HumanMessage(content="find the sqli")],
                 "conversation_objectives": [{"content": "find the sqli"}], "current_objective_index": 0}
        cont = await init_mod._initialize(state, _config(), llm=None, neo4j_creds=NEO4J)
        [chain] = self.written("fire_create_attack_chain")
        self.assertEqual(chain["user_id"], OWNER)
        [(_n, prior_args, _kw)] = [c for c in self.calls if c[0] == "query_prior_chains"]
        self.assertEqual(prior_args[3:6], (OWNER, PID, SID), "prior chains are read from the owner's graph")
        self.assertEqual((cont["user_id"], cont["tenant_user_id"]), (COLLAB, OWNER))

        resumed = await init_mod._initialize({"user_approval_response": "approve",
                                              "phase_transition_pending": {"to_phase": "exploitation"}},
                                             _config(), llm=None, neo4j_creds=NEO4J)
        self.assertEqual(resumed, {"user_id": COLLAB, "tenant_user_id": OWNER, "project_id": PID, "session_id": SID})

    async def test_the_scope_gate_reads_the_scanned_names_from_the_owner_graph(self):
        init_mod = importlib.import_module("orchestrator_helpers.nodes.initialize_node")
        bind = mock.AsyncMock()
        settings = {"ROE_ENABLED": False}
        with mock.patch.object(init_mod, "get_setting", side_effect=lambda k, d=None: settings.get(k, d)), \
                mock.patch.object(init_mod, "_bind_scanned_hostnames", bind), \
                mock.patch.object(init_mod, "_run_scope_checks", mock.AsyncMock(return_value=None)), \
                mock.patch("project_settings.scope_signature", return_value="sig"), \
                mock.patch.object(init_mod, "_initialize", mock.AsyncMock(return_value={})):
            await init_mod.initialize_node({}, _config(), llm=None, neo4j_creds=NEO4J)
        bind.assert_awaited_once_with(NEO4J, OWNER, PID, SID)

    async def test_a_phase_decision_is_recorded_under_the_owner(self):
        approval_mod = importlib.import_module("orchestrator_helpers.nodes.approval_nodes")
        for answer in ("approve", "abort"):
            self.calls.clear()
            state = {"user_approval_response": answer, "current_phase": "informational",
                     "phase_transition_pending": {"from_phase": "informational", "to_phase": "exploitation"},
                     "conversation_objectives": [{"content": "x"}], "current_objective_index": 0}
            await approval_mod.process_approval_node(state, _config(), neo4j_creds=NEO4J)
            [decision] = self.written("fire_record_decision")
            self.assertEqual((answer, decision["user_id"], decision["project_id"]), (answer, OWNER, PID))

    async def test_the_report_closes_the_owner_s_chain(self):
        report_mod = importlib.import_module("orchestrator_helpers.nodes.generate_response_node")
        llm = mock.MagicMock()
        llm.ainvoke = mock.AsyncMock(return_value=AIMessage(content="# Summary"))
        state = {"execution_trace": [{"success": True, "phase": "informational"}],
                 "original_objective": "list the assets", "completion_reason": "done"}
        await report_mod.generate_response_node(state, _config(), llm=llm, streaming_callbacks={},
                                                neo4j_creds=NEO4J)
        [status] = self.written("fire_update_chain_status")
        self.assertEqual((status["chain_id"], status["user_id"], status["project_id"]), (SID, OWNER, PID))

    async def test_a_fireteam_member_writes_and_reads_the_owner_s_graph(self):
        deploy_mod = importlib.import_module("orchestrator_helpers.nodes.fireteam_deploy_node")
        member_mod = importlib.import_module("orchestrator_helpers.nodes.fireteam_member_think_node")
        parent = {"user_id": COLLAB, "project_id": PID, "session_id": SID, "current_phase": "informational",
                  "attack_path_type": "cve_exploit", "target_info": {}}
        spec = {"name": "Web Tester", "tools": ["query_graph"], "task": "summarise the target"}
        state = deploy_mod._build_member_state(parent, spec, "member-0-abc", "fteam-1", tenant_user_id=OWNER)
        self.assertEqual((state["user_id"], state["tenant_user_id"]), (COLLAB, OWNER))
        # Without the deploy node's tenant, the parent state's (initialize_node keeps it there).
        inherited = deploy_mod._build_member_state({**parent, "tenant_user_id": OWNER}, spec, "m-1", "fteam-1")
        self.assertEqual(inherited["tenant_user_id"], OWNER)

        state.update({
            "messages": [], "_pending_confirmation": None, "tokens_used": 0, "_decision": None,
            "_last_chain_step_id": None, "_guardrail_blocked": False,
            "_current_step": {"tool_name": "execute_httpx", "tool_args": {}, "tool_output": "nginx",
                              "success": False, "error_message": "timeout", "iteration": 1},
        })
        llm = mock.MagicMock()
        llm.ainvoke = mock.AsyncMock(return_value=mock.MagicMock(content=COMPLETE))
        token = current_llm.set(llm)
        try:
            await member_mod.fireteam_member_think_node(state, None, llm=llm, neo4j_creds=NEO4J,
                                                         streaming_callbacks=None)
        finally:
            current_llm.reset(token)
        writes = [kw for n, _a, kw in self.calls if n != "query_prior_chains"]
        self.assertTrue({"fire_record_step", "fire_record_failure"} <= {n for n, _a, _kw in self.calls})
        self.assertEqual({kw["user_id"] for kw in writes}, {OWNER})
        # Its tools read the owner's graph: the node set the context they read.
        self.assertEqual((current_user_id.get(), current_project_id.get()), (OWNER, PID))

    async def test_the_ctx_tag_and_the_run_credential_carry_the_tenant(self):
        import redamon_ctx
        import tools
        current_user_id.set(OWNER)
        current_project_id.set(PID)
        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}):
            tag = executor._build_redamon_ctx("execute_curl")
            credential = executor._build_run_credential("traffic")
            self.assertEqual(redamon_ctx.verify_tag(tag, {"agent": MASTER})["user_id"], OWNER)
            self.assertEqual(mc.verify_run_credential(credential, "traffic")["ten"], OWNER)


def _calls(path: Path):
    return [n for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.Call)]


_PERSON_READERS = ("get_identifiers", "get_config_values")


def _is_person(node) -> bool:
    """The person, never the tenant: `user_id`, `state.get("user_id", ...)`, `state["user_id"]`,
    `config["configurable"]["user_id"]`, `get_identifiers(...)[0]`, `get_config_values(...)[0]`."""
    if isinstance(node, ast.Name):
        return node.id == "user_id"
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        if node.slice.value == "user_id":
            return True
        call = node.value
        if node.slice.value == 0 and isinstance(call, ast.Call):
            name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", None)
            return name in _PERSON_READERS
        return False
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
            and bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value == "user_id")


class TheScanKnowsEveryWayToNameThePerson(unittest.TestCase):
    def test_each_person_shape_is_caught_and_the_tenant_is_not(self):
        def expr(src):
            return ast.parse(src, mode="eval").body
        for src in ('user_id', 'state.get("user_id")', 'state.get("user_id", "")', 'state["user_id"]',
                    'config["configurable"]["user_id"]', 'get_identifiers(state, config)[0]',
                    'config_mod.get_identifiers(state, config)[0]', 'get_config_values(config)[0]'):
            with self.subTest(person=src):
                self.assertTrue(_is_person(expr(src)))
        for src in ('tenant_id', 'get_tenant_id(state, config)', 'state["tenant_user_id"]',
                    'state.get("tenant_user_id")', 'get_identifiers(state, config)[1]', 'ids[0]'):
            with self.subTest(not_person=src):
                self.assertFalse(_is_person(expr(src)))


class EveryNodeCallSiteHandsTheTenant(unittest.TestCase):
    """The behaviour tests above cover each label; this finds the next call site that forgets."""

    def test_no_chain_write_and_no_tool_context_takes_the_person(self):
        chain_calls, tenant_contexts, offenders = 0, 0, []
        for path in sorted(NODES.glob("*.py")):
            for call in _calls(path):
                func = call.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                        and func.value.id == "chain_graph":
                    chain_calls += 1
                    for kw in call.keywords:
                        if kw.arg == "user_id" and _is_person(kw.value):
                            offenders.append(f"{path.name}:{call.lineno} chain_graph.{func.attr}(user_id=<person>)")
                    if func.attr in ("fire_update_chain_status", "fire_update_chain_attack_path"):
                        named = {kw.arg for kw in call.keywords}
                        if not {"user_id", "project_id"} <= named:
                            offenders.append(f"{path.name}:{call.lineno} chain_graph.{func.attr} without its tenant")
                if any(isinstance(a, ast.Attribute) and a.attr == "query_prior_chains" for a in call.args):
                    chain_calls += 1
                    if len(call.args) > 4 and _is_person(call.args[4]):
                        offenders.append(f"{path.name}:{call.lineno} query_prior_chains(<person>)")
                if isinstance(func, ast.Name) and func.id == "set_tenant_context":
                    tenant_contexts += 1
                    if call.args and _is_person(call.args[0]):
                        offenders.append(f"{path.name}:{call.lineno} set_tenant_context(<person>)")
        self.assertGreaterEqual(chain_calls, 25, "the scan must see the chain writes it guards")
        self.assertGreaterEqual(tenant_contexts, 5, "think, execute_tool, execute_plan, both Fireteam nodes")
        self.assertEqual(offenders, [], "a shared project's chain or graph read would split onto the person")


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"
        self.closed = None

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


class _Orchestrator:
    """Records every run and resume the handler starts; admits each resume."""

    def __init__(self):
        self.calls = []

    async def _record(self, **kw):
        self.calls.append(kw)
        if "on_admitted" in kw:
            kw["on_admitted"]()

    invoke_with_streaming = _record
    resume_after_approval_with_streaming = _record
    resume_after_answer_with_streaming = _record
    resume_after_tool_confirmation_with_streaming = _record
    resume_execution_with_streaming = _record


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheAgentSocketSplitsThem(unittest.TestCase):
    def setUp(self):
        self.saved = mock.AsyncMock(return_value=None)
        from decision_check import DecisionCheck
        from writer_check import WriterCheck
        # The decision-time check (step 5.4) is test_decision_check.py's; here it allows.
        for patcher in (mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET}),
                        mock.patch.object(websocket_api, "authorize_decision", mock.AsyncMock(return_value=DecisionCheck(allowed=True))),
                        # The per-run writer check (step 5.11 follow-up) is test_run_writer_check.py's; here it allows.
                        mock.patch.object(websocket_api, "second_writer_check", mock.AsyncMock(return_value=WriterCheck(allowed=True))),
                        mock.patch.object(websocket_api, "save_chat_message", self.saved),
                        mock.patch.object(websocket_api, "post_agent_decision", mock.AsyncMock(return_value=True)),
                        mock.patch.object(websocket_api, "update_conversation", mock.AsyncMock())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _session(self, ticket, *frames):
        orch = _Orchestrator()

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            await handler.handle_init(conn, {"user_id": "x", "project_id": "x", "session_id": "x", "ticket": ticket})
            for method, payload in frames:
                await getattr(handler, method)(conn, dict(payload))
                if conn._active_task is not None:
                    await asyncio.wait_for(conn._active_task, 5)
            for _ in range(10):
                await asyncio.sleep(0)
            return conn

        return asyncio.run(main()), orch

    def test_init_keeps_the_tenant_beside_the_person(self):
        conn, _ = self._session(_ticket(ten=OWNER))
        self.assertTrue(conn.authenticated)
        self.assertEqual((conn.user_id, conn.tenant_id), (COLLAB, OWNER))
        self.assertEqual(conn.get_key(), f"{COLLAB}:{PID}:{SID}", "the session is the person's")

    def test_a_ticket_without_ten_names_the_person_as_tenant(self):
        conn, _ = self._session(_ticket(sub=OWNER))
        self.assertEqual((conn.user_id, conn.tenant_id), (OWNER, OWNER))

    def test_a_malformed_ten_is_refused_at_init(self):
        conn, _ = self._session(_ticket(ten=""))
        self.assertFalse(conn.authenticated)
        [err] = [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]
        self.assertEqual(err["code"], "ws_ticket_invalid")

    def test_a_run_reads_the_owner_s_graph_and_persists_under_the_collaborator(self):
        conn, orch = self._session(_ticket(ten=OWNER), ("handle_query", {"question": "list the hosts"}))
        [run] = orch.calls
        self.assertEqual((run["user_id"], run["tenant_user_id"], run["project_id"]), (COLLAB, OWNER, PID))
        saved = [c.kwargs for c in self.saved.await_args_list]
        self.assertTrue(saved, "the question is saved")
        self.assertEqual({(s["user_id"], s["session_id"]) for s in saved}, {(COLLAB, SID)})

    def test_every_resume_carries_both(self):
        _conn, orch = self._session(
            _ticket(ten=OWNER),
            ("handle_approval", {"decision": "approve"}),
            ("handle_answer", {"answer": "443"}),
            ("handle_tool_confirmation", {"decision": "approve"}),
        )
        self.assertEqual(len(orch.calls), 3)
        self.assertEqual({(c["user_id"], c["tenant_user_id"]) for c in orch.calls}, {(COLLAB, OWNER)})


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheOrchestratorSplitsThem(unittest.IsolatedAsyncioTestCase):
    async def test_the_graph_is_the_owner_s_the_thread_and_loop_scope_the_collaborator_s(self):
        seen = {}

        class Graph:
            async def astream(self, _input, config, stream_mode="values"):
                seen["configurable"] = dict(config["configurable"])
                yield {"messages": [AIMessage(content="done")], "task_complete": True}

        @asynccontextmanager
        async def lease(user):
            seen["lease"] = user
            yield

        @asynccontextmanager
        async def run_scope(user_id, project_id, session_id, *_a, **_kw):
            seen["scope"] = (user_id, project_id, session_id)
            yield mock.MagicMock()

        orch = orchestrator_mod.AgentOrchestrator()
        orch._initialized = True
        orch.graph = Graph()
        orch._apply_project_settings = lambda _pid: None
        orch._mcp_toolset_lease = lease
        broker = mock.MagicMock()
        broker.run_scope = run_scope
        callback = mock.AsyncMock()
        token = current_llm.set(mock.MagicMock())
        try:
            with mock.patch.object(orchestrator_mod, "get_broker", return_value=broker), \
                    mock.patch.object(orchestrator_mod, "emit_streaming_events", mock.AsyncMock()):
                await orch.invoke_with_streaming(question="list the hosts", user_id=COLLAB, project_id=PID,
                                                 session_id=SID, streaming_callback=callback,
                                                 tenant_user_id=OWNER)
        finally:
            current_llm.reset(token)
        self.assertEqual(seen["configurable"]["tenant_user_id"], OWNER)
        self.assertEqual(seen["configurable"]["user_id"], COLLAB)
        self.assertEqual(seen["configurable"]["thread_id"], f"{COLLAB}:{PID}:{SID}")
        self.assertEqual(seen["scope"], (COLLAB, PID, SID), "a loop model answers in the collaborator's scope")
        self.assertEqual(seen["lease"], OWNER, "the MCP toolset is the owner's USER_MCP_SERVERS: leased by tenant")
        callback.on_error.assert_not_awaited()

    async def test_a_plain_invoke_leases_the_toolset_by_tenant(self):
        seen = {}

        class Graph:
            async def ainvoke(self, _input, config):
                seen["configurable"] = dict(config["configurable"])
                return {"messages": [AIMessage(content="done")], "task_complete": True}

        @asynccontextmanager
        async def lease(tenant):
            seen["lease"] = tenant
            yield

        orch = orchestrator_mod.AgentOrchestrator()
        orch._initialized = True
        orch.graph = Graph()
        orch.llm = mock.MagicMock()
        orch._apply_project_settings = lambda _pid: None
        orch._mcp_toolset_lease = lease
        await orch.invoke(question="list the hosts", user_id=COLLAB, project_id=PID, session_id=SID,
                          tenant_user_id=OWNER)
        self.assertEqual(seen["lease"], OWNER)
        self.assertEqual(seen["configurable"]["user_id"], COLLAB)
        seen.clear()
        await orch.invoke(question="list the hosts", user_id=OWNER, project_id=PID, session_id=SID)
        self.assertEqual(seen["lease"], OWNER, "a config without a tenant is its person's, as before")


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class ClosingByPerson(unittest.IsolatedAsyncioTestCase):
    """A collaborator's revocation reaches their sockets and runs on the shared project, never the owner's."""

    async def asyncSetUp(self):
        self.tasks = []
        self.mgr = WebSocketManager()
        self.reg = ProxiedSocketRegistry()
        self.conns = {}
        for person in (OWNER, COLLAB):
            task = asyncio.ensure_future(asyncio.sleep(3600))
            self.tasks.append(task)
            key = f"{person}:{PID}:{person}-session"
            self.mgr.register_task(key, task)
            conn = WebSocketConnection(_WS())
            conn.tenant_id = OWNER
            conn._active_task = task
            await self.mgr.authenticate(conn, person, PID, f"{person}-session", verified=True)
            self.conns[person] = (conn, task)
        self.terms = {person: _WS() for person in (OWNER, COLLAB)}
        for person, ws in self.terms.items():
            self.reg.add(ws, "kali-terminal", {"sub": person, "ten": OWNER, "pid": PID, "sid": "t"}, run=f"run-{person}")

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()

    async def test_ws_close_for_the_collaborator_leaves_the_owner_s_sockets_open(self):
        result = await close_sockets(self.mgr, self.reg, kinds=["agent", "kali-terminal"],
                                     user_id=COLLAB, project_id=PID)
        self.assertEqual((result["closed"], result["stopped_runs"]), (2, 1))
        await asyncio.sleep(0)
        self.assertTrue(self.conns[COLLAB][1].cancelled())
        self.assertIsNotNone(self.conns[COLLAB][0].websocket.closed)
        self.assertIsNotNone(self.terms[COLLAB].closed)
        self.assertFalse(self.conns[OWNER][1].done(), "the owner's run on the project keeps going")
        self.assertIsNone(self.conns[OWNER][0].websocket.closed)
        self.assertIsNone(self.terms[OWNER].closed)
        self.assertTrue(self.reg.holds_run(f"run-{OWNER}", OWNER, PID))

    async def test_stop_for_the_collaborator_stops_their_run_only(self):
        self.assertEqual(await self.mgr.stop_for_user(COLLAB, [PID]), 1)
        await asyncio.sleep(0)
        self.assertTrue(self.conns[COLLAB][1].cancelled())
        self.assertFalse(self.conns[OWNER][1].done())

    async def test_a_terminal_credential_lives_under_the_tenant_not_the_person(self):
        self.assertTrue(self.reg.holds_run(f"run-{COLLAB}", OWNER, PID))
        self.assertFalse(self.reg.holds_run(f"run-{COLLAB}", COLLAB, PID))
        [entry] = self.reg.matching(kinds=["kali-terminal"], user_id=COLLAB, project_id=PID)
        self.assertEqual((entry.sub, entry.ten), (COLLAB, OWNER))

    async def test_a_stop_by_project_and_session_finds_the_run_whoever_s(self):
        other = asyncio.ensure_future(asyncio.sleep(3600))
        self.tasks.append(other)
        self.mgr.register_task(f"{COLLAB}:p-other:{COLLAB}-session", other)
        self.assertTrue(await self.mgr.stop_project_session(PID, f"{COLLAB}-session"))
        await asyncio.sleep(0)
        self.assertTrue(self.conns[COLLAB][1].cancelled())
        self.assertFalse(other.done(), "another project's session of the same id is not touched")
        self.assertFalse(self.conns[OWNER][1].done())
        self.assertFalse(await self.mgr.stop_project_session(PID, ""))


class _EchoKali:
    def __init__(self):
        self.queue = asyncio.Queue()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, message):
        await self.queue.put(message)

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self.queue.get()


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheAgentApi(unittest.TestCase):
    """The terminal proxy, the session stop, the triage and CodeFix sockets, through the app."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with mock.patch("api.lifespan", fake_lifespan):
            import api as api_module
        cls.api = api_module
        cls.client = TestClient(api_module.app)

    def setUp(self):
        self._e = mock.patch.dict(os.environ, {
            "INTERNAL_API_KEY": MASTER, "AGENT_WS_TICKET_SECRET": SECRET, "MCP_AUTH_TOKEN": "mcp-token-for-test",
        })
        self._e.start()
        self.addCleanup(self._e.stop)

    # --- the Kali terminal ------------------------------------------------------------

    def _open_terminal(self, **claims):
        connect = mock.MagicMock(side_effect=lambda *a, **k: _EchoKali())
        held = {}
        with mock.patch.object(self.api.websockets, "connect", connect):
            with self.client.websocket_connect(f"/ws/kali-terminal?ticket={_ticket('kali-terminal', **claims)}") as ws:
                ws.send_text("hello")
                self.assertEqual(ws.receive_text(), "hello")
                [entry] = PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id=claims.get("sub", COLLAB))
                held["entry"] = (entry.sub, entry.ten)
                token = connect.call_args.kwargs["additional_headers"]["X-Redamon-Run"]
                run = mc.verify_run_credential(token, "graph")["run"]
                held["tenant_holds"] = PROXIED_SOCKETS.holds_run(run, OWNER, PID)
                held["person_holds"] = PROXIED_SOCKETS.holds_run(run, COLLAB, PID)
        return connect.call_args, held

    def test_the_terminal_s_shell_and_redagraph_credential_name_the_owner(self):
        call, held = self._open_terminal(ten=OWNER)
        query = parse_qs(urlparse(call.args[0]).query)
        self.assertEqual(query["user_id"], [OWNER], "the shell's REDAMON_USER_ID is the project's tenant")
        claims = mc.verify_run_credential(call.kwargs["additional_headers"]["X-Redamon-Run"], "graph")
        self.assertEqual((claims["ten"], claims["pid"]), (OWNER, PID))
        self.assertEqual(held["entry"], (COLLAB, OWNER), "revocation still finds the socket by its person")
        self.assertEqual((held["tenant_holds"], held["person_holds"]), (True, False))

    def test_a_terminal_ticket_without_ten_names_its_person_as_before(self):
        call, held = self._open_terminal(sub=OWNER)
        self.assertEqual(parse_qs(urlparse(call.args[0]).query)["user_id"], [OWNER])
        self.assertEqual(held["entry"], (OWNER, OWNER))

    # --- the session stop ---------------------------------------------------------------

    def test_a_session_stop_without_a_user_stops_by_project_and_session(self):
        mgr = mock.MagicMock()
        mgr.stop_project_session = mock.AsyncMock(return_value=True)
        mgr.stop_session = mock.AsyncMock(return_value=True)
        headers = {"X-Internal-Key": MASTER}
        with mock.patch.object(self.api, "ws_manager", mgr):
            res = self.client.post("/agent-session/stop", json={"project_id": PID, "session_id": SID}, headers=headers)
            self.assertEqual((res.status_code, res.json()), (200, {"stopped": True}))
            mgr.stop_project_session.assert_awaited_once_with(PID, SID)
            mgr.stop_session.assert_not_awaited()
            # With the person (a conversation delete names its author), their session key.
            res = self.client.post("/agent-session/stop", json={"user_id": COLLAB, "project_id": PID, "session_id": SID},
                                   headers=headers)
            self.assertEqual(res.status_code, 200)
            mgr.stop_session.assert_awaited_once_with(f"{COLLAB}:{PID}:{SID}")
            self.assertEqual(self.client.post("/agent-session/stop", json={"project_id": PID, "session_id": SID}
                                              ).status_code, 401)

    # --- CypherFix triage -----------------------------------------------------------------

    def _fake_triage(self):
        from cypherfix_triage import websocket_handler as wh
        built = []

        class FakeOrchestrator:
            def __init__(self, **kwargs):
                built.append(kwargs)
                self.callback = kwargs["callback"]

            async def run(self, state):
                built.append({"state_user_id": state["user_id"]})
                await self.callback.on_authorized("run-1")

            async def cleanup(self):
                pass

        wh._RUNS.clear()
        self.addCleanup(wh._RUNS.clear)
        patcher = mock.patch.object(wh, "TriageOrchestrator", FakeOrchestrator)
        patcher.start()
        self.addCleanup(patcher.stop)
        return wh, built

    def test_the_triage_socket_runs_on_the_owner_s_graph_for_the_collaborator(self):
        wh, built = self._fake_triage()
        with self.client.websocket_connect(f"/ws/cypherfix-triage?ticket={_ticket('cypherfix-triage', ten=OWNER, act=ADMIN)}") as ws:
            ws.send_text(json.dumps({"type": "init"}))
            self.assertEqual(ws.receive_json()["type"], "connected")
            ws.send_text(json.dumps({"type": "start_triage"}))
            for _ in range(20):
                if len(built) >= 2:
                    break
                time.sleep(0.05)
        kwargs = built[0]
        self.assertEqual((kwargs["user_id"], kwargs["project_id"]), (OWNER, PID), "the owner's graph")
        self.assertEqual((kwargs["actor_user_id"], kwargs["real_actor_user_id"]), (COLLAB, ADMIN))
        self.assertEqual(built[1], {"state_user_id": OWNER})
        run = wh._RUNS.get(PID)
        if run is not None and run.task is not None:
            for _ in range(20):
                if run.task.done():
                    break
                time.sleep(0.05)

    def test_the_master_key_start_takes_the_actor(self):
        from cypherfix_triage import websocket_handler as wh
        seen = {}

        def start(user_id, project_id, **kwargs):
            seen.update(user_id=user_id, project_id=project_id, **kwargs)
            return mock.MagicMock(run_id="run-1", trigger="mcp"), True, None

        headers = {"X-Internal-Key": MASTER}
        with mock.patch.object(wh, "start_detached_run", side_effect=start):
            res = self.client.post("/triage/runs", headers=headers, json={
                "user_id": OWNER, "project_id": PID, "actor_user_id": COLLAB, "trigger": "mcp"})
            self.assertEqual(res.status_code, 202, res.text)
            self.assertEqual((seen["user_id"], seen["actor_user_id"]), (OWNER, COLLAB))
            seen.clear()
            # Without one, the tenant is the actor, as before.
            res = self.client.post("/triage/runs", headers=headers, json={"user_id": OWNER, "project_id": PID})
            self.assertEqual(res.status_code, 202, res.text)
            self.assertIsNone(seen["actor_user_id"])
            res = self.client.post("/triage/runs", headers=headers, json={
                "user_id": OWNER, "project_id": PID, "actor_user_id": "bad id!"})
            self.assertEqual((res.status_code, res.json()), (400, {"error": "invalid actor id"}))

    # --- CypherFix CodeFix ------------------------------------------------------------------

    def test_the_codefix_socket_works_on_the_owner_s_project(self):
        from cypherfix_codefix import websocket_handler as ch
        seen = {}

        class FakeCodeFix:
            def __init__(self, state, callback):
                seen["user_id"] = state.user_id
                self.approval_future = None

            async def run(self, _remediation_id):
                seen["ran"] = True

            async def cleanup(self):
                pass

        with mock.patch.object(ch, "CodeFixOrchestrator", FakeCodeFix):
            with self.client.websocket_connect(f"/ws/cypherfix-codefix?ticket={_ticket('cypherfix-codefix', ten=OWNER)}") as ws:
                ws.send_text(json.dumps({"type": "init"}))
                self.assertEqual(ws.receive_json()["type"], "connected")
                ws.send_text(json.dumps({"type": "start_fix", "payload": {"remediation_id": "r1"}}))
                for _ in range(20):
                    if "ran" in seen:
                        break
                    time.sleep(0.05)
        self.assertEqual(seen["user_id"], OWNER)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class ATriageRunRecordsItsPerson(unittest.IsolatedAsyncioTestCase):
    async def test_a_collaborator_s_run_reads_the_owner_s_graph_and_records_the_collaborator(self):
        orch_mod = importlib.import_module("cypherfix_triage.orchestrator")
        from cypherfix_triage.run_client import TriageRunAborted
        clients = []

        class FakeClient:
            def __init__(self, project_id, actor_user_id, real_actor_user_id=None):
                clients.append((project_id, actor_user_id, real_actor_user_id))
                self.run_id = None
                self.finish = mock.AsyncMock()

            def set_progress(self, *_a):
                pass

            async def authorize(self, *_a, **_kw):
                raise TriageRunAborted("refused in the test", "refused")

        orch = orch_mod.TriageOrchestrator(OWNER, PID, mock.AsyncMock(), real_actor_user_id=ADMIN,
                                           actor_user_id=COLLAB)
        self.assertEqual((orch.user_id, orch.neo4j.user_id, orch.actor_user_id), (OWNER, OWNER, COLLAB))
        orch.neo4j.close = mock.AsyncMock()
        with mock.patch.object(orch_mod, "TriageRunClient", FakeClient), \
                mock.patch.object(orch_mod, "load_cypherfix_settings", mock.AsyncMock(return_value={})):
            await orch.run({"user_id": OWNER, "project_id": PID})
        self.assertEqual(clients, [(PID, COLLAB, ADMIN)])
        # An owner's run, started without an actor, records the owner as before.
        self.assertEqual(orch_mod.TriageOrchestrator(OWNER, PID, None).actor_user_id, OWNER)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheChainStatusWritesAreScoped(unittest.TestCase):
    """Two writers matched an AttackChain by chain id alone; they now match the tenant's chain."""

    def test_the_fire_functions_pass_the_tenant_and_write_nothing_without_it(self):
        with mock.patch.object(cg, "_fire_and_forget") as fire:
            cg.fire_update_chain_status(*NEO4J, chain_id=SID, user_id=OWNER, project_id=PID)
            cg.fire_update_chain_attack_path(*NEO4J, chain_id=SID, attack_path_type="xss",
                                             user_id=OWNER, project_id=PID)
            self.assertEqual([(c.kwargs["user_id"], c.kwargs["project_id"]) for c in fire.call_args_list],
                             [(OWNER, PID), (OWNER, PID)])
            fire.reset_mock()
            with self.assertLogs(cg.logger, "WARNING"):
                cg.fire_update_chain_status(*NEO4J, chain_id=SID)
                cg.fire_update_chain_attack_path(*NEO4J, chain_id=SID, attack_path_type="xss", user_id=OWNER)
            fire.assert_not_called()

    def test_the_cypher_matches_the_tenant_s_chain(self):
        ran = []
        session = mock.MagicMock()
        session.run.side_effect = lambda cypher, params: ran.append((cypher, params))
        session.__enter__ = mock.Mock(return_value=session)
        session.__exit__ = mock.Mock(return_value=False)
        with mock.patch.object(cg, "_get_driver"), mock.patch.object(cg, "_session", return_value=session):
            cg._write_chain_status(*NEO4J, chain_id=SID, user_id=OWNER, project_id=PID, status="completed",
                                   final_outcome="", total_steps=1, successful_steps=1, failed_steps=0,
                                   phases_reached=[])
            cg._write_chain_attack_path(*NEO4J, chain_id=SID, user_id=OWNER, project_id=PID, attack_path_type="xss")
        for cypher, params in ran:
            self.assertIn("MATCH (ac:AttackChain {chain_id: $chain_id, user_id: $user_id, project_id: $project_id})",
                          cypher)
            self.assertEqual((params["chain_id"], params["user_id"], params["project_id"]), (SID, OWNER, PID))
        self.assertEqual(len(ran), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

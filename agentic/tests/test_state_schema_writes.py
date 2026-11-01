"""A node's writes must reach the next node: LangGraph drops what the schema lacks.

LangGraph builds each node's input from the declared state channels. A key a
node returns that AgentState / FireteamMemberState does not declare is dropped
with no error and no log line, and a write into the node's own ``state``
argument never leaves the node. Three features were dead this way: the "prior
productivity claim was downgraded" prompt note, the RoE timing warnings, and
the task_complete event. This file pins each fix and scans the whole nodes/
package for the next undeclared key.

Run: ./agentic/run_tests.sh tests/test_state_schema_writes.py
"""
import ast
import asyncio
import importlib
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.graph import END, START, StateGraph  # noqa: E402

import websocket_api  # noqa: E402
from orchestrator_helpers.streaming import (  # noqa: E402
    clear_stale_streaming_state,
    emit_streaming_events,
)
from state import AgentState, FireteamMemberState  # noqa: E402
from websocket_api import StreamingCallback, WebSocketConnection  # noqa: E402

# The package re-exports the initialize_node function under the module's name.
init_mod = importlib.import_module("orchestrator_helpers.nodes.initialize_node")

AGENTIC = Path(__file__).resolve().parents[1]
NODES = AGENTIC / "orchestrator_helpers" / "nodes"
MEMBER_GRAPH = AGENTIC / "orchestrator_helpers" / "fireteam_member_graph.py"

# think_node sets these on its own copy of the state to hand them to lats_hook
# within the same call; they are turn-local and never meant to leave the node.
IN_PLACE_ALLOWED = {
    ("think_node.py", "deep_think_ran_this_turn"),
    ("think_node.py", "guidance_drained_this_turn"),
    ("think_node.py", "_last_productivity_score"),
    ("think_node.py", "_lats_deep_think_hints"),
}

CONFIG = {"configurable": {"user_id": "u", "project_id": "p", "session_id": "s"}}
NEO4J = ("bolt://unused", "u", "p")
ENDED = "Engagement has ended (2000-01-31). Testing may no longer be authorized."
ROE_ENDED = {"ROE_ENABLED": True, "ROE_ENGAGEMENT_END_DATE": "2000-01-31"}

# Another test file may stub langgraph into sys.modules; the gate runs each
# file in its own process, so this only skips in a shared-process run.
_LANGGRAPH_REAL = not isinstance(StateGraph, MagicMock)


def _declared(schema) -> set:
    return set(schema.__required_keys__) | set(schema.__optional_keys__)


def _str_key(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _functions(path: Path):
    return [n for n in ast.walk(ast.parse(path.read_text()))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _writes(path: Path) -> set:
    """(line, key) for every key a node module puts in a state update.

    Two shapes cover the package: ``update[s]["k"] = ...`` and a dict literal
    returned by a ``*_node`` function.
    """
    found = set()
    for fn in _functions(path):
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                            and target.value.id in ("update", "updates")
                            and (key := _str_key(target.slice))):
                        found.add((node.lineno, key))
            elif (fn.name.endswith("_node") and isinstance(node, ast.Return)
                  and isinstance(node.value, ast.Dict)):
                found |= {(node.lineno, k) for k in map(_str_key, node.value.keys) if k}
    return found


def _in_place_writes(path: Path) -> set:
    """(line, key) for every ``state["k"] = ...`` in a function taking ``state``."""
    found = set()
    for fn in _functions(path):
        params = {a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs}
        if "state" not in params:
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                            and target.value.id == "state" and (key := _str_key(target.slice))):
                        found.add((node.lineno, key))
    return found


def _member_graph_modules() -> set:
    """Node files the fireteam member graph imports, so run on FireteamMemberState."""
    prefix = "orchestrator_helpers.nodes."
    return {n.module[len(prefix):] + ".py" for n in ast.walk(ast.parse(MEMBER_GRAPH.read_text()))
            if isinstance(n, ast.ImportFrom) and (n.module or "").startswith(prefix)}


def _schemas_for(path: Path, member_modules: set) -> list:
    schemas = []
    if path.name in member_modules:
        schemas.append(FireteamMemberState)
    if not path.name.startswith("fireteam_member_"):
        schemas.append(AgentState)
    return schemas


def _settings(values: dict):
    return patch.object(init_mod, "get_setting",
                        side_effect=lambda key, default=None: values.get(key, default))


def _initialize_stubs():
    """Stub the scope gate and the objective logic, which need an LLM and Neo4j."""
    return (patch.object(init_mod, "_scope_gate", AsyncMock(return_value=(None, {}))),
            patch.object(init_mod, "_initialize", AsyncMock(return_value={"current_iteration": 0})))


class TestNodeWritesAreDeclared(unittest.TestCase):
    def test_the_scan_sees_the_writes_it_guards(self):
        """A scan that finds nothing would pass vacuously."""
        def keys(name):
            return {k for _, k in _writes(NODES / name)}
        self.assertIn("_last_productivity_discrepancy", keys("think_node.py"))
        self.assertIn("_last_productivity_discrepancy", keys("fireteam_member_think_node.py"))
        self.assertIn("_report_generated", keys("generate_response_node.py"))
        self.assertGreater(len(keys("think_node.py")), 10)
        self.assertTrue({"fireteam_member_think_node.py", "execute_tool_node.py"}
                        <= _member_graph_modules())

    def test_every_key_a_node_writes_is_declared_on_its_graph_schema(self):
        member_modules = _member_graph_modules()
        missing = sorted({
            f"{path.name}:{line} {key!r} is not declared on {schema.__name__}"
            for path in NODES.glob("*.py")
            for schema in _schemas_for(path, member_modules)
            for line, key in _writes(path)
            if key not in _declared(schema)
        })
        self.assertEqual(missing, [], "LangGraph drops an undeclared key without an error")

    def test_no_node_writes_into_its_input_state(self):
        offenders = sorted({
            f"{path.name}:{line} state[{key!r}]"
            for path in NODES.glob("*.py")
            for line, key in _in_place_writes(path)
            if (path.name, key) not in IN_PLACE_ALLOWED
        })
        self.assertEqual(offenders, [], "a node receives a copy of the state: return the key")


class TestRoeTimingWarnings(unittest.TestCase):
    WINDOW = {
        "ROE_TIME_WINDOW_ENABLED": True,
        "ROE_TIME_WINDOW_TIMEZONE": "Europe/Rome",
        "ROE_TIME_WINDOW_DAYS": ["monday", "tuesday", "wednesday", "thursday", "friday"],
        "ROE_TIME_WINDOW_START_TIME": "09:00",
        "ROE_TIME_WINDOW_END_TIME": "18:00",
    }
    MONDAY_0730_UTC = datetime(2026, 1, 12, 7, 30, tzinfo=timezone.utc)

    def test_an_ended_engagement_warns(self):
        with _settings(ROE_ENDED):
            self.assertEqual(init_mod._roe_timing_warnings(self.MONDAY_0730_UTC), [ENDED])

    def test_the_window_is_judged_in_its_own_timezone(self):
        """07:30 UTC is 08:30 in Rome in January: before a 09:00 start."""
        with _settings(self.WINDOW):
            self.assertEqual(init_mod._roe_timing_warnings(self.MONDAY_0730_UTC), [
                "Current time (08:30 Europe/Rome) is outside the allowed window (09:00-18:00).",
            ])

    def test_inside_the_window_no_warning(self):
        with _settings(self.WINDOW):
            self.assertEqual(init_mod._roe_timing_warnings(self.MONDAY_0730_UTC.replace(hour=9)), [])

    def test_initialize_returns_the_warnings_and_leaves_its_input_alone(self):
        state = {"messages": []}
        gate, objectives = _initialize_stubs()
        with _settings(ROE_ENDED), gate, objectives:
            result = asyncio.run(init_mod.initialize_node(state, CONFIG, llm=None, neo4j_creds=NEO4J))
        self.assertEqual(result["_roe_warnings"], [ENDED])
        self.assertEqual(result["current_iteration"], 0)
        self.assertNotIn("_roe_warnings", state)

    def test_a_later_turn_rechecks_the_engagement(self):
        """The warnings persist in the checkpoint, so each turn must refresh them."""
        gate, objectives = _initialize_stubs()
        with _settings(ROE_ENDED), gate, objectives:
            result = asyncio.run(init_mod.initialize_node(
                {"messages": [], "execution_trace": [{"step_id": "x"}]},
                CONFIG, llm=None, neo4j_creds=NEO4J))
        self.assertEqual(result["_roe_warnings"], [ENDED])

    def test_roe_off_clears_a_stale_warning(self):
        gate, objectives = _initialize_stubs()
        with _settings({"ROE_ENABLED": False}), gate, objectives:
            result = asyncio.run(init_mod.initialize_node(
                {"messages": [], "_roe_warnings": [ENDED]}, CONFIG, llm=None, neo4j_creds=NEO4J))
        self.assertEqual(result["_roe_warnings"], [])


def _round_trip(schema, update: dict) -> dict:
    """What the next node reads after a node returns ``update``."""
    seen = {}

    def write(state):
        return update

    def read(state):
        seen.update({key: state.get(key) for key in update})
        return {"current_iteration": 1}

    graph = StateGraph(schema)
    graph.add_node("write", write)
    graph.add_node("read", read)
    graph.add_edge(START, "write")
    graph.add_edge("write", "read")
    graph.add_edge("read", END)
    graph.compile().invoke({"messages": []})
    return seen


class _FakeWS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


@unittest.skipUnless(_LANGGRAPH_REAL, "langgraph stubbed in-process by another test; run standalone")
class TestWritesReachTheNextNode(unittest.TestCase):
    def test_an_undeclared_key_is_dropped(self):
        """The LangGraph behaviour this file guards against; if it changes, revisit the scan."""
        self.assertEqual(_round_trip(AgentState, {"_undeclared_probe": 1}),
                         {"_undeclared_probe": None})

    def test_the_parent_schema_carries_the_three_keys(self):
        update = {
            "_last_productivity_discrepancy": "empty output claimed as progress",
            "_roe_warnings": [ENDED],
            "_report_generated": True,
        }
        self.assertEqual(_round_trip(AgentState, update), update)

    def test_the_member_schema_carries_the_downgrade_note(self):
        update = {"_last_productivity_discrepancy": "duplicate output claimed as progress"}
        self.assertEqual(_round_trip(FireteamMemberState, update), update)

    def test_initialize_warnings_reach_the_next_node(self):
        seen = {}

        async def initialize(state, config):
            return await init_mod.initialize_node(state, config, llm=None, neo4j_creds=NEO4J)

        def think(state):
            seen["roe"] = state.get("_roe_warnings")
            return {"current_iteration": 1}

        graph = StateGraph(AgentState)
        graph.add_node("initialize", initialize)
        graph.add_node("think", think)
        graph.add_edge(START, "initialize")
        graph.add_edge("initialize", "think")
        graph.add_edge("think", END)
        gate, objectives = _initialize_stubs()
        with _settings(ROE_ENDED), gate, objectives:
            asyncio.run(graph.compile().ainvoke({"messages": []}, CONFIG))
        self.assertEqual(seen["roe"], [ENDED])

    def test_task_complete_is_sent_after_the_report_and_not_when_the_next_query_starts(self):
        def finish(state):
            return {"task_complete": True, "_report_generated": True}

        graph = StateGraph(AgentState)
        graph.add_node("finish", finish)
        graph.add_edge(START, "finish")
        graph.add_edge("finish", END)
        app = graph.compile(checkpointer=MemorySaver())
        config = {"configurable": {**CONFIG["configurable"], "thread_id": "schema-writes"}}

        async def events_that_sent_task_complete(input_data):
            """One query as the orchestrator streams it, with a fresh callback."""
            conn = WebSocketConnection(_FakeWS())
            conn.user_id, conn.project_id, conn.session_id = "u", "p", "s"
            conn.authenticated = True
            callback = StreamingCallback(conn)
            sent_at, index = [], 0
            async for event in app.astream(input_data, config, stream_mode="values"):
                before = sum(m["type"] == "task_complete" for m in conn.websocket.sent)
                await emit_streaming_events(event, callback)
                if sum(m["type"] == "task_complete" for m in conn.websocket.sent) > before:
                    sent_at.append(index)
                index += 1
            return sent_at

        with patch.object(websocket_api, "save_chat_message", AsyncMock(return_value=None)):
            first = asyncio.run(events_that_sent_task_complete({"messages": []}))
            # Event 0 is the checkpoint merged with the new input, which still
            # holds the first run's task_complete=True.
            second = asyncio.run(events_that_sent_task_complete(
                clear_stale_streaming_state({"messages": []})))
        self.assertEqual(first, [1])
        self.assertEqual(second, [1])


if __name__ == "__main__":
    unittest.main()

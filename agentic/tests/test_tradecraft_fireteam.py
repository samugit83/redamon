"""Fireteam members and the Tradecraft run state (T2.6, R-425, D-48): a member of a 2.0 run is
offered ``tradecraft_search``; it starts from the run's pages and counts; what it reads and asks
reaches the main run, and the members of one wave and the main agent count against one per-run
limit. The member graph is a fake that does what a member's executor node does.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_settings as ps  # noqa: E402
# The package re-exports the node function under the module's name: import the module itself.
deploy = importlib.import_module("orchestrator_helpers.nodes.fireteam_deploy_node")
from tradecraft import run_state  # noqa: E402


class MemberGraph:
    """Each member binds the run state from its own state (as its execute node does), records
    what ``work`` gives it, and finishes."""

    def __init__(self, work=None):
        self.work = work or (lambda index, member_state: None)
        self.seen_states: list[dict] = []
        self.allowed: list[list[str]] = []

    def astream(self, member_state, config=None):
        return self._run(member_state)

    async def _run(self, member_state):
        index = len(self.seen_states)
        self.seen_states.append(dict(member_state))
        self.allowed.append(ps.get_allowed_tools_for_phase(member_state["current_phase"]))
        run_state.bind(member_state)
        await asyncio.sleep(0)
        self.work(index, member_state)
        yield {"fireteam_complete": {"task_complete": True, "completion_reason": "complete", "current_iteration": 1,
                                     "tokens_used": 0, "execution_trace": [], "target_info": {},
                                     "chain_findings_memory": []}}


def parent_state(members=2, **tc):
    state = {"user_id": "u", "project_id": "p", "session_id": "s-1", "current_phase": "exploitation",
             "attack_path_type": "sql_injection", "target_info": {}, "current_iteration": 4,
             "current_objective_index": 0,
             "_current_fireteam_plan": {"plan_rationale": "r", "members": [
                 {"name": f"M{i}", "task": f"task {i}", "tools": [], "max_iterations": 5} for i in range(members)]}}
    state.update(tc)
    return state


def deploy_in_run(state, graph, *, v2=True):
    async def go():
        ps._settings_ctx.set({"TOOL_PHASE_MAP": {"tradecraft_lookup": ["exploitation", "post_exploitation"]},
                              "TRADECRAFT_V2": v2, "FIRETEAM_MAX_MEMBERS": 5, "FIRETEAM_MAX_CONCURRENT": 3,
                              "FIRETEAM_TIMEOUT_SEC": 60, "FIRETEAM_MEMBER_MAX_ITERATIONS": 5})
        with patch.object(deploy, "_persist_deploy", new=AsyncMock(return_value="id")), \
                patch.object(deploy, "_patch_member", new=AsyncMock()), \
                patch.object(deploy, "_patch_fireteam", new=AsyncMock()):
            return await deploy.fireteam_deploy_node(state, None, member_graph=graph, streaming_callbacks={},
                                                     neo4j_creds=None)

    return contextvars.Context().run(asyncio.run, go())


def test_member_gets_search_in_2x_run():
    graph = MemberGraph()
    deploy_in_run(parent_state(), graph)
    assert all("tradecraft_search" in allowed and "tradecraft_lookup" in allowed for allowed in graph.allowed)
    graph_1x = MemberGraph()
    deploy_in_run(parent_state(), graph_1x, v2=False)
    assert all("tradecraft_search" not in allowed for allowed in graph_1x.allowed)


def test_member_seen_pages_reach_parent():
    graph = MemberGraph(lambda i, s: run_state.record_seen([f"patt:{10 + i}", "patt:1"]))
    state = parent_state(tradecraft_seen_pages=["patt:1"], tradecraft_run_key="objective:0")
    result = deploy_in_run(state, graph)
    assert sorted(result["tradecraft_seen_pages"]) == ["patt:1", "patt:10", "patt:11"]
    assert result["tradecraft_run_key"] == "objective:0"
    # Each member started from the run's pages.
    assert all(s["tradecraft_seen_pages"] == ["patt:1"] for s in graph.seen_states)
    assert set(run_state.FIELDS) <= set(graph.seen_states[0])


def test_members_count_one_limit():
    """Two members of one wave and the main agent share the per-run counts."""
    graph = MemberGraph(lambda i, s: (run_state.incr("ask"), run_state.incr("hint")))
    state = parent_state(tradecraft_ask_count=1, tradecraft_hint_count=2, tradecraft_run_key="objective:0")
    result = deploy_in_run(state, graph)
    assert result["tradecraft_ask_count"] == 3 and result["tradecraft_hint_count"] == 4
    assert [s["tradecraft_ask_count"] for s in graph.seen_states] == [1, 1]


def test_a_new_message_starts_the_members_from_empty_values():
    graph = MemberGraph()
    state = parent_state(current_objective_index=1, tradecraft_seen_pages=["patt:1"], tradecraft_ask_count=4,
                         tradecraft_run_key="objective:0")
    result = deploy_in_run(state, graph)
    assert graph.seen_states[0]["tradecraft_seen_pages"] == [] and graph.seen_states[0]["tradecraft_ask_count"] == 0
    assert result["tradecraft_run_key"] == "objective:1" and result["tradecraft_seen_pages"] == []


def test_a_1x_run_keeps_the_defaults():
    result = deploy_in_run(parent_state(), MemberGraph(), v2=False)
    assert {k: result[k] for k in run_state.FIELDS} == run_state.fresh_values("objective:0")
    assert set(result) == {"_current_fireteam_plan", "_current_fireteam_results", "_fireteam_id", *run_state.FIELDS}

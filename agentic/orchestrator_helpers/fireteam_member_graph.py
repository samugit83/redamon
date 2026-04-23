"""Fireteam member graph.

A stripped 5-node ReAct subgraph compiled once at orchestrator init and
invoked once per member during a fireteam deployment. No checkpointer:
members are ephemeral; only the parent agent state is checkpointed.

Nodes:
    fireteam_think              -> the member's ReAct reasoning (forbidden-action stripped)
    fireteam_execute_tool       -> reuses existing execute_tool_node
    fireteam_execute_plan       -> reuses existing execute_plan_node
    fireteam_await_confirmation -> pauses the member on an asyncio.Event until
                                   the operator decides; resumes back into the
                                   loop (approve -> executor, reject -> think).
                                   Replaces the legacy escalate-and-terminate
                                   node (FIRETEAM.md §7.3 superseded).
    fireteam_complete           -> exits the member with status=success
"""

import logging
from langgraph.graph import StateGraph, START, END

from state import FireteamMemberState

logger = logging.getLogger(__name__)


def _route_after_member_think(state: FireteamMemberState) -> str:
    """Route the member after its think node, mirroring _route_after_think
    but restricted to the four actions members can emit."""
    decision = state.get("_decision") or {}
    action = decision.get("action")

    if state.get("_pending_confirmation"):
        return "fireteam_await_confirmation"

    if state.get("task_complete") or action == "complete":
        return "fireteam_complete"

    if action == "plan_tools":
        return "fireteam_execute_plan"

    # Default: use_tool (all forbidden actions have already been stripped
    # to "complete" by the think node itself before routing).
    return "fireteam_execute_tool"


def _route_after_member_await_confirmation(state: FireteamMemberState) -> str:
    """Route after the member wakes from operator confirmation.

    approve -> _decision + _current_plan/_current_step are still populated, so
               dispatch to the matching executor.
    reject  -> _decision was cleared and a rejection HumanMessage was added;
               loop back to think to produce a fresh decision.
    """
    decision = state.get("_decision") or {}
    action = decision.get("action")
    if action == "plan_tools" and state.get("_current_plan"):
        return "fireteam_execute_plan"
    if action == "use_tool" and state.get("_current_step"):
        return "fireteam_execute_tool"
    return "fireteam_think"


def build_fireteam_member_graph(
    *,
    llm_getter,
    tool_executor,
    streaming_callbacks,
    session_manager_base,
    neo4j_creds,
    graph_view_cyphers=None,
):
    """Compile the fireteam member StateGraph.

    ``llm_getter`` is a zero-arg callable returning the current LLM. We use a
    getter rather than a direct reference because the parent orchestrator sets
    ``self.llm`` lazily after project settings are loaded, which happens AFTER
    this graph is compiled. Reading ``llm_getter()`` inside the wrapper body
    delays resolution until a member actually runs.
    """
    from orchestrator_helpers.nodes.execute_tool_node import execute_tool_node
    from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node
    from orchestrator_helpers.nodes.fireteam_member_think_node import (
        fireteam_member_think_node,
        fireteam_await_confirmation_node,
        fireteam_complete_node,
    )

    builder = StateGraph(FireteamMemberState)

    async def _think(state, config=None):
        llm = llm_getter()
        if llm is None:
            logger.error("fireteam_member_think: LLM not yet initialized; exiting member")
            return {
                "task_complete": True,
                "completion_reason": "llm_not_initialized",
            }
        return await fireteam_member_think_node(
            state, config,
            llm=llm,
            neo4j_creds=neo4j_creds,
            streaming_callbacks=streaming_callbacks,
            graph_view_cyphers=graph_view_cyphers,
        )

    async def _execute_tool(state, config=None):
        return await execute_tool_node(
            state, config,
            tool_executor=tool_executor,
            streaming_callbacks=streaming_callbacks,
            session_manager_base=session_manager_base,
            graph_view_cyphers=graph_view_cyphers,
        )

    async def _execute_plan(state, config=None):
        return await execute_plan_node(
            state, config,
            tool_executor=tool_executor,
            streaming_callbacks=streaming_callbacks,
            session_manager_base=session_manager_base,
            graph_view_cyphers=graph_view_cyphers,
        )

    async def _await_confirmation(state, config=None):
        return await fireteam_await_confirmation_node(
            state, config,
            streaming_callbacks=streaming_callbacks,
        )

    async def _complete(state, config=None):
        return await fireteam_complete_node(state, config)

    builder.add_node("fireteam_think", _think)
    builder.add_node("fireteam_execute_tool", _execute_tool)
    builder.add_node("fireteam_execute_plan", _execute_plan)
    builder.add_node("fireteam_await_confirmation", _await_confirmation)
    builder.add_node("fireteam_complete", _complete)

    def _route_from_start(state: FireteamMemberState) -> str:
        """Entry routing.

        Normal path: fireteam_think first, produce a decision, then dispatch.

        Pre-seeded path (operator-approved redeploy from
        process_fireteam_confirmation_node): the member state already carries
        ``_decision`` + ``_current_plan`` / ``_current_step``. Skip the first
        LLM call and dispatch straight to the executor so the approved tool(s)
        run without going through another think+parse+decide round-trip.
        """
        decision = state.get("_decision") or {}
        action = decision.get("action")
        if action == "plan_tools" and state.get("_current_plan"):
            return "fireteam_execute_plan"
        if action == "use_tool" and state.get("_current_step"):
            return "fireteam_execute_tool"
        return "fireteam_think"

    builder.add_conditional_edges(
        START,
        _route_from_start,
        {
            "fireteam_think": "fireteam_think",
            "fireteam_execute_tool": "fireteam_execute_tool",
            "fireteam_execute_plan": "fireteam_execute_plan",
        },
    )
    builder.add_conditional_edges(
        "fireteam_think",
        _route_after_member_think,
        {
            "fireteam_execute_tool": "fireteam_execute_tool",
            "fireteam_execute_plan": "fireteam_execute_plan",
            "fireteam_await_confirmation": "fireteam_await_confirmation",
            "fireteam_complete": "fireteam_complete",
        },
    )
    # After the member wakes from operator confirmation, dispatch based on
    # approve vs reject (see _route_after_member_await_confirmation).
    builder.add_conditional_edges(
        "fireteam_await_confirmation",
        _route_after_member_await_confirmation,
        {
            "fireteam_execute_tool": "fireteam_execute_tool",
            "fireteam_execute_plan": "fireteam_execute_plan",
            "fireteam_think": "fireteam_think",
        },
    )
    builder.add_edge("fireteam_execute_tool", "fireteam_think")
    builder.add_edge("fireteam_execute_plan", "fireteam_think")
    builder.add_edge("fireteam_complete", END)

    # No checkpointer: members are ephemeral.
    return builder.compile(checkpointer=None)

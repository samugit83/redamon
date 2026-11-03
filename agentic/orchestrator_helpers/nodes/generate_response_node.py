"""Generate response node — produces final response adaptive to interaction complexity."""

import logging

from langchain_core.messages import AIMessage, HumanMessage

from state import (
    AgentState,
    format_execution_trace,
    format_todo_list,
)
import orchestrator_helpers.chain_graph_writer as chain_graph
from orchestrator_helpers.json_utils import json_dumps_safe, normalize_content
from orchestrator_helpers.config import get_identifiers
from agent_in_the_loop.errors import LoopError
from agent_in_the_loop.purpose import llm_purpose
from prompts import (
    FINAL_REPORT_PROMPT,
    CONVERSATIONAL_RESPONSE_PROMPT,
    SUMMARY_RESPONSE_PROMPT,
    determine_response_tier,
)

logger = logging.getLogger(__name__)

LOOP_REPORT_FALLBACK = (
    "**The external agent did not write the final report** ({reason}).\n\n"
    "The steps above are saved in this conversation: {total} step(s) ran, "
    "{successful} succeeded and {failed} failed."
)


async def generate_response_node(
    state: AgentState,
    config,
    *,
    llm,
    streaming_callbacks,
    neo4j_creds,
) -> dict:
    """
    Generate final response, adaptive to interaction complexity.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        llm: The LLM instance for generating the response.
        streaming_callbacks: Dict of session_id -> streaming callback objects.
        neo4j_creds: Tuple of (neo4j_uri, neo4j_user, neo4j_password).
    """
    user_id, project_id, session_id = get_identifiers(state, config)
    neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

    # If this was an aborted phase transition, just output the cancel message
    if state.get("_abort_transition"):
        logger.info(f"[{user_id}/{project_id}/{session_id}] Abort transition — skipping full report")
        return {
            "_abort_transition": False,
        }

    # If guardrail blocked the target, the AIMessage is already in state — nothing to generate
    if state.get("_guardrail_blocked"):
        logger.info(f"[{user_id}/{project_id}/{session_id}] Guardrail blocked — skipping report generation")
        return {}

    # Determine response tier based on state signals (no LLM call)
    tier = determine_response_tier(
        execution_trace=state.get("execution_trace", []),
        attack_path_type=state.get("attack_path_type", "cve_exploit"),
        target_info=state.get("target_info", {}),
        objective_history=state.get("objective_history", []),
    )

    logger.info(f"[{user_id}/{project_id}/{session_id}] Generating final response (tier: {tier})...")

    # Get current objective
    objectives = state.get("conversation_objectives", [])
    current_idx = state.get("current_objective_index", 0)
    current_objective = (
        objectives[current_idx].get("content", "")
        if current_idx < len(objectives)
        else state.get("original_objective", "")
    )

    # Emit a thinking event with tier-appropriate message
    streaming_cb = streaming_callbacks.get(session_id)
    if streaming_cb:
        thinking_messages = {
            "conversational": ("Preparing response...", "Formulating a direct answer."),
            "summary": ("Preparing summary...", "Compiling a brief summary of the session."),
            "full_report": ("Generating final summary report...", "Compiling all findings, tool outputs, and recommendations into a comprehensive report."),
        }
        thought, reasoning = thinking_messages.get(tier, thinking_messages["full_report"])
        try:
            await streaming_cb.on_thinking(
                state.get("current_iteration", 0),
                state.get("current_phase", "informational"),
                thought,
                reasoning,
            )
        except Exception as e:
            logger.error(f"Error emitting report thinking event: {e}")

    # Build common formatted strings
    exec_trace_formatted = format_execution_trace(
        state.get("execution_trace", []),
        objectives=state.get("conversation_objectives", []),
        objective_history=state.get("objective_history", []),
        current_objective_index=state.get("current_objective_index", 0),
    )
    target_info_str = json_dumps_safe(state.get("target_info", {}), indent=2)

    # Select prompt based on tier
    if tier == "conversational":
        report_prompt = CONVERSATIONAL_RESPONSE_PROMPT.format(
            objective=current_objective,
            completion_reason=state.get("completion_reason", "Session ended"),
            execution_trace=exec_trace_formatted,
            target_info=target_info_str,
        )
    elif tier == "summary":
        report_prompt = SUMMARY_RESPONSE_PROMPT.format(
            objective=current_objective,
            completion_reason=state.get("completion_reason", "Session ended"),
            attack_path_type=state.get("attack_path_type", "cve_exploit"),
            iteration_count=state.get("current_iteration", 0),
            final_phase=state.get("current_phase", "informational"),
            execution_trace=exec_trace_formatted,
            target_info=target_info_str,
        )
    else:  # full_report
        report_prompt = FINAL_REPORT_PROMPT.format(
            objective=current_objective,
            iteration_count=state.get("current_iteration", 0),
            final_phase=state.get("current_phase", "informational"),
            completion_reason=state.get("completion_reason", "Session ended"),
            execution_trace=exec_trace_formatted,
            target_info=target_info_str,
            todo_list=format_todo_list(state.get("todo_list", [])),
        )

    trace = state.get("execution_trace", [])
    total = len(trace)
    successful = sum(1 for s in trace if s.get("success", True))
    failed = total - successful
    phases = list({s.get("phase") for s in trace if s.get("phase")})

    try:
        with llm_purpose("report"):
            response = await llm.ainvoke([HumanMessage(content=report_prompt)])
        report_text = normalize_content(response.content)
    except LoopError as exc:
        # Only an Agent in the Loop step: the run's trace is saved, so end with
        # the deterministic counts rather than a crash at the last step.
        logger.warning(f"Report step not answered ({exc.code}); writing the fallback report")
        report_text = LOOP_REPORT_FALLBACK.format(
            reason=exc.code, total=total, successful=successful, failed=failed)

    # Fire-and-forget: update AttackChain status to completed

    chain_graph.fire_update_chain_status(
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=session_id,
        status="completed",
        final_outcome=state.get("completion_reason", ""),
        total_steps=total,
        successful_steps=successful,
        failed_steps=failed,
        phases_reached=phases,
    )

    return {
        "messages": [AIMessage(content=report_text)],
        "task_complete": True,
        "completion_reason": state.get("completion_reason") or "Task completed successfully",
        "_report_generated": True,
        "_response_tier": tier,
    }

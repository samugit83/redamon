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
from orchestrator_helpers.config import get_identifiers, get_tenant_id
from orchestrator_helpers.llm_retry import describe_llm_failure, retry_llm_call
from logging_config import redact_text
from agent_in_the_loop.broker import get_broker
from agent_in_the_loop.errors import LoopError, LoopNoDriver, LoopStepDeclined, LoopStepNotAnswered
from agent_in_the_loop.purpose import llm_purpose
from prompts import (
    FINAL_REPORT_PROMPT,
    CONVERSATIONAL_RESPONSE_PROMPT,
    SUMMARY_RESPONSE_PROMPT,
    determine_response_tier,
)

logger = logging.getLogger(__name__)

LOOP_REPORT_FALLBACK = (
    "**The external agent did not write the final report**: {why} ({reason}).\n\n"
    "The steps above are saved in this conversation: {total} step(s) ran, "
    "{successful} succeeded and {failed} failed."
)

LOOP_RESUME = (
    "**To continue:** start your agent so it calls RedAmon again, then type *continue* "
    "in this chat. The chat keeps its history."
)

PROVIDER_REPORT_FALLBACK = (
    "**The final summary could not be written**: {reason}.\n\n"
    "The steps above are saved in this conversation: {total} step(s) ran, "
    "{successful} succeeded and {failed} failed. Ask for the summary again "
    "once the provider accepts calls."
)

# A fallback lists what the run already recorded, so a failed last step does not
# leave the person with counts only. Capped: a long session can hold hundreds.
MAX_FALLBACK_FINDINGS = 20


def _one_line(value, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _duration_words(seconds: int) -> str:
    if seconds % 60:
        return f"{seconds} seconds"
    minutes = seconds // 60
    return f"{minutes} minute{'' if minutes == 1 else 's'}"


def _loop_failure_words(exc: LoopError) -> str:
    if isinstance(exc, LoopNoDriver):
        grace = _duration_words(get_broker().cfg.no_driver_grace_s)
        return f"no agent called RedAmon for {grace}, so RedAmon ended the run"
    if isinstance(exc, LoopStepNotAnswered):
        return "a step reached its deadline without an answer"
    if isinstance(exc, LoopStepDeclined):
        return "the external agent declined the step"
    return "the Agent in the Loop step failed"


def _saved_work(state) -> str:
    """The last Fireteam wave and the session's findings, from state alone, as
    Markdown sections each opened by a blank line ("" when there is neither)."""
    sections: list[list[str]] = []
    waves = state.get("chain_waves_memory") or []
    members = (waves[-1].get("members") or []) if waves and isinstance(waves[-1], dict) else []
    if members:
        lines = ["**Last fireteam wave**"]
        for m in members:
            status = m.get("status") or "unknown"
            if status not in ("success", "partial") and m.get("completion_reason"):
                status += f" ({_one_line(m['completion_reason'], 60)})"
            lines.append(f"- {_one_line(m.get('name') or 'unnamed', 80)}: {status}, "
                         f"{int(m.get('findings_count') or 0)} finding(s)")
        sections.append(lines)
    findings = [f for f in (state.get("chain_findings_memory") or []) if isinstance(f, dict)]
    if findings:
        lines = [f"**Findings recorded in this session ({len(findings)})**"]
        for f in findings[:MAX_FALLBACK_FINDINGS]:
            title = _one_line(f.get("title") or f.get("finding_type") or "untitled", 160)
            line = f"- [{_one_line(f.get('severity') or 'info', 20)}] {title}"
            if f.get("source_agent"):
                line += f" · {_one_line(f['source_agent'], 60)}"
            lines.append(line)
        if len(findings) > MAX_FALLBACK_FINDINGS:
            lines.append(f"- …and {len(findings) - MAX_FALLBACK_FINDINGS} more.")
        sections.append(lines)
    return "".join("\n\n" + "\n".join(lines) for lines in sections)


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
            response = await retry_llm_call(
                llm, [HumanMessage(content=report_prompt)],
                label=f"{user_id}/{project_id}/{session_id} report",
            )
        report_text = normalize_content(response.content)
    except LoopError as exc:
        # Only an Agent in the Loop step: the run's trace is saved, so end with
        # the deterministic counts rather than a crash at the last step.
        logger.warning(f"Report step not answered ({exc.code}); writing the fallback report")
        report_text = LOOP_REPORT_FALLBACK.format(
            why=_loop_failure_words(exc), reason=exc.code,
            total=total, successful=successful, failed=failed)
        report_text += _saved_work(state) + "\n\n" + LOOP_RESUME
    except Exception as exc:
        # The provider still refused after retry_llm_call's waits (a rate limit
        # that did not clear, an empty quota, a 5xx). The work is done and its
        # steps are saved: a failed summary must not turn the run into an error.
        logger.error(
            f"[{user_id}/{project_id}/{session_id}] Report call failed; writing the "
            f"fallback report: {type(exc).__name__}: {redact_text(str(exc))}")
        report_text = PROVIDER_REPORT_FALLBACK.format(
            reason=describe_llm_failure(exc), total=total, successful=successful, failed=failed)
        report_text += _saved_work(state)

    # Fire-and-forget: update AttackChain status to completed

    chain_graph.fire_update_chain_status(
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=session_id,
        user_id=get_tenant_id(state, config), project_id=project_id,
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

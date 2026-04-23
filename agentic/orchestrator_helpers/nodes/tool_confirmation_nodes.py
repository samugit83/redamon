"""Tool confirmation nodes — pause for user confirmation before executing dangerous tools."""

import logging

from langchain_core.messages import HumanMessage

from state import (
    AgentState,
    ExecutionStep,
    utc_now,
)
from orchestrator_helpers.config import get_identifiers

logger = logging.getLogger(__name__)


async def await_tool_confirmation_node(state: AgentState, config) -> dict:
    """Pause and request user confirmation for dangerous tool execution."""
    user_id, project_id, session_id = get_identifiers(state, config)

    pending = state.get("tool_confirmation_pending", {})
    tools = pending.get("tools", [])
    mode = pending.get("mode", "single")

    logger.info(
        f"[{user_id}/{project_id}/{session_id}] Awaiting tool confirmation "
        f"({mode}): {[t.get('tool_name') for t in tools]}"
    )

    return {
        "awaiting_tool_confirmation": True,
    }


async def process_tool_confirmation_node(state: AgentState, config) -> dict:
    """Process user's tool confirmation response."""
    user_id, project_id, session_id = get_identifiers(state, config)

    decision = state.get("tool_confirmation_response")
    modification = state.get("tool_confirmation_modification")
    pending = state.get("tool_confirmation_pending", {})
    tools = pending.get("tools", [])
    mode = pending.get("mode", "single")

    logger.info(
        f"[{user_id}/{project_id}/{session_id}] Processing tool confirmation: {decision}"
    )

    # Common fields to clear confirmation state
    # Also clear _decision to prevent duplicate THINKING emissions on resume
    # (the new StreamingCallback has empty dedup sets, so stale _decision would re-emit)
    clear_state = {
        "awaiting_tool_confirmation": False,
        "tool_confirmation_pending": None,
        "tool_confirmation_response": None,
        "tool_confirmation_modification": None,
        "_tool_confirmation_mode": mode,  # Preserve for router
        "_decision": None,  # Prevent duplicate thinking on resume
        "_completed_step": None,  # Prevent duplicate tool_complete on resume
    }

    if decision == "approve":
        tool_names = ", ".join(t.get("tool_name", "?") for t in tools)
        logger.info(
            f"[{user_id}/{project_id}/{session_id}] Tool execution approved: {tool_names}"
        )
        return {
            **clear_state,
            "_reject_tool": False,
        }

    elif decision == "modify":
        logger.info(
            f"[{user_id}/{project_id}/{session_id}] Tool args modified by user"
        )

        updates = {
            **clear_state,
            "_reject_tool": False,
        }

        if modification and isinstance(modification, dict):
            if mode == "single":
                # Patch _current_step tool_args
                current_step = dict(state.get("_current_step") or {})
                if current_step:
                    current_args = dict(current_step.get("tool_args") or {})
                    current_args.update(modification)
                    current_step["tool_args"] = current_args
                    updates["_current_step"] = current_step
            else:
                # Patch matching steps in _current_plan
                current_plan = dict(state.get("_current_plan") or {})
                if current_plan and current_plan.get("steps"):
                    patched_steps = []
                    for step in current_plan["steps"]:
                        step = dict(step)
                        tool_name = step.get("tool_name", "")
                        if tool_name in modification:
                            step_args = dict(step.get("tool_args") or {})
                            step_args.update(modification[tool_name])
                            step["tool_args"] = step_args
                        patched_steps.append(step)
                    current_plan["steps"] = patched_steps
                    updates["_current_plan"] = current_plan

        return updates

    else:  # reject
        tool_names = ", ".join(t.get("tool_name", "?") for t in tools)
        logger.info(
            f"[{user_id}/{project_id}/{session_id}] Tool execution rejected: {tool_names}"
        )

        # Add execution trace entry for the rejection
        rejection_step = ExecutionStep(
            iteration=state.get("current_iteration", 0),
            phase=pending.get("phase", state.get("current_phase", "informational")),
            thought=f"User rejected execution of: {tool_names}",
            reasoning="User chose to reject this tool execution. Agent must choose a different approach.",
            tool_name="tool_rejection",
            tool_args={"rejected_tools": [t.get("tool_name") for t in tools]},
            tool_output=f"TOOL REJECTED BY USER: {tool_names}. Do NOT retry the same tool without a different justification.",
            success=False,
            output_analysis=f"User rejected {tool_names}. Choose an alternative approach or ask the user for guidance.",
        )
        updated_trace = state.get("execution_trace", []) + [rejection_step.model_dump()]

        return {
            **clear_state,
            "_reject_tool": True,
            "_current_step": None,
            "_current_plan": None,
            "execution_trace": updated_trace,
            "messages": [
                HumanMessage(
                    content=f"I rejected the execution of: {tool_names}. "
                    f"Please choose a different approach or ask me what I'd prefer."
                ),
            ],
        }

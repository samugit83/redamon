"""Process-fireteam-confirmation node.

Per FIRETEAM.md §7.3: when the operator responds to a fireteam member's
escalated dangerous-tool confirmation, this node:

  - approve  -> redeploy a SINGLE-MEMBER fireteam containing only the
                approved tool(s). The re-spawned member produces findings
                the normal way (chain_graph writes with member attribution,
                rolled up by fireteam_collect). The parent is NOT allowed
                to execute the approved tool as if it were its own plan —
                that was the source of the wave-merging / stale-pending
                UX disaster.
  - reject   -> inject a rejection SystemMessage and route back to think.
  - modify   -> same as approve, but with operator-provided tool_args.

The output state signals the orchestrator to route to fireteam_deploy_node
(not execute_plan / execute_tool) via `_tool_confirmation_mode="fireteam_redeploy"`.
"""

import logging
from uuid import uuid4
from typing import Optional

from state import AgentState

logger = logging.getLogger(__name__)


def _apply_modification(tool_args: dict, modification: Optional[dict]) -> dict:
    """Merge operator modifications onto the original tool_args."""
    if not modification or not isinstance(modification, dict):
        return dict(tool_args or {})
    merged = dict(tool_args or {})
    merged.update(modification)
    return merged


def _build_redeploy_plan(
    pending: dict,
    member_name: str,
    original_task: str,
    modification: Optional[dict],
) -> dict:
    """Build a single-member FireteamPlan dict containing the approved tools.

    The member inherits the original escalating member's name + skills so
    the UI keeps the same panel identity across the approval hop.
    """
    mode = pending.get("mode") or "single"
    raw_tools = pending.get("tools") or []

    approved_tool_names = []
    approved_pre_plan = []  # list of ToolPlanStep-shaped dicts
    for t in raw_tools:
        tname = t.get("tool_name")
        targs = _apply_modification(t.get("tool_args") or {}, modification)
        approved_tool_names.append(tname)
        approved_pre_plan.append({
            "tool_name": tname,
            "tool_args": targs,
            "rationale": f"Operator-approved escalation of {tname}",
        })

    task_prefix = (
        "Operator approved the escalated tool(s). Execute this approved "
        "plan EXACTLY as listed — do NOT re-plan or substitute tools. "
        "After execution, analyze the output(s) and produce findings, "
        "then emit action=complete."
    )
    tools_spec = "\n".join(
        f"- {s['tool_name']}  args: {s['tool_args']}" for s in approved_pre_plan
    )
    member_task = (
        f"{task_prefix}\n\n"
        f"Approved plan ({mode}, {len(approved_pre_plan)} tool(s)):\n{tools_spec}\n\n"
        f"Original context: {original_task[:800]}"
    )

    member_spec = {
        "name": member_name or "Approved Member",
        "task": member_task,
        "skills": [],                 # tools already chosen — skills not needed
        "max_iterations": 5,          # just: run tools, analyze, complete
        # Seed the approved plan into the member's state so the member does
        # not need to re-LLM the choice. Consumed by fireteam_deploy_node.
        "_seed_plan": {
            "steps": approved_pre_plan,
            "plan_rationale": pending.get("reasoning") or "operator approved",
        } if mode == "plan" or len(approved_pre_plan) > 1 else None,
        "_seed_single_tool": approved_pre_plan[0] if (mode == "single" and len(approved_pre_plan) == 1) else None,
    }

    return {
        "members": [member_spec],
        "plan_rationale": (
            f"Redeploying approved escalation from member "
            f"{member_name or '(unknown)'}: "
            f"{', '.join(n for n in approved_tool_names if n) or 'approved tools'}"
        ),
        "_operator_approved": True,
    }


async def process_fireteam_confirmation_node(state: AgentState, config) -> dict:
    """Resume after a fireteam-escalated tool confirmation.

    Returns a state update that the router dispatches to fireteam_deploy_node
    (for approve/modify) or think (for reject).
    """
    decision = state.get("tool_confirmation_response")
    pending = state.get("_escalated_fireteam_confirmation") or state.get("tool_confirmation_pending") or {}
    member_id = state.get("_escalated_member_id") or "unknown"
    modification = state.get("tool_confirmation_modification")
    queue: list = list(state.get("_pending_escalations") or [])

    # Always clear the confirmation-related state so we don't loop.
    cleanup = {
        "awaiting_tool_confirmation": False,
        "tool_confirmation_pending": None,
        "tool_confirmation_response": None,
        "tool_confirmation_modification": None,
        "_tool_confirmation_mode": None,
        "_escalated_fireteam_confirmation": None,
        "_escalated_member_id": None,
    }

    if decision == "reject":
        note = (
            f"[fireteam] Operator rejected the tool request escalated by member {member_id}. "
            f"Tool NOT executed. Parent agent continues without it."
        )
        logger.info("[fireteam] rejection for member %s", member_id)
        # If there are more queued escalations from the same wave, surface the
        # next one so the operator can decide each in turn (FIRETEAM.md §20 Q3).
        if queue:
            next_pending = queue.pop(0)
            logger.info(
                "[fireteam] surfacing next queued escalation from member %s (%d more queued)",
                next_pending.get("agent_id"), len(queue),
            )
            return {
                **cleanup,
                "messages": [{"role": "system", "content": note}],
                "_pending_escalations": queue or None,
                "_escalated_fireteam_confirmation": next_pending,
                "_escalated_member_id": next_pending.get("agent_id"),
                "awaiting_tool_confirmation": True,
                "tool_confirmation_pending": next_pending,
                "_tool_confirmation_mode": "fireteam_escalation",
            }
        return {
            **cleanup,
            "_pending_escalations": None,
            "messages": [{"role": "system", "content": note}],
        }

    tools = pending.get("tools") or []
    if not tools:
        logger.warning("[fireteam] approve/modify but no tools in pending_confirmation")
        return {
            **cleanup,
            "messages": [{"role": "system", "content": "[fireteam] approval received but pending tools missing — skipping."}],
        }

    member_name = pending.get("agent_name") or member_id
    original_task = pending.get("task") or pending.get("reasoning") or ""
    plan = _build_redeploy_plan(pending, member_name, original_task, modification)

    note = (
        f"[fireteam] Operator approved escalation from member '{member_name}'. "
        f"Redeploying as a single-member fireteam with the approved tool(s)."
    )
    logger.info(
        "[fireteam] approve for member %s -> single-member fireteam redeploy (%d tools)",
        member_id, len(tools),
    )
    return {
        **cleanup,
        # Signals orchestrator routing to go to fireteam_deploy_node.
        "_tool_confirmation_mode": "fireteam_redeploy",
        "_current_fireteam_plan": plan,
        "messages": [{"role": "system", "content": note}],
    }

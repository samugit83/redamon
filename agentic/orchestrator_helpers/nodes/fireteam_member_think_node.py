"""Fireteam member think node (safety-critical).

Mirrors think_node for a FireteamMemberState but enforces strict restrictions:

 * Forbidden actions (deploy_fireteam, transition_phase, ask_user) are
   stripped to action=complete with a descriptive completion_reason.
 * Iteration and token budgets cause clean exit before any LLM call.
 * Dangerous-tool use_tool / plan_tools decisions route to
   fireteam_escalate_confirmation so the parent handles approval.

This file is safety-critical and must maintain 100% line coverage on the
forbidden-action stripping and escalation paths.
"""

import asyncio
import logging
from typing import Optional
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from state import LLMDecision, FireteamMemberState, TargetInfo
from orchestrator_helpers.parsing import try_parse_llm_decision
from orchestrator_helpers.json_utils import normalize_content, json_dumps_safe
import orchestrator_helpers.chain_graph_writer as chain_graph
from project_settings import get_setting, get_allowed_tools_for_phase, DANGEROUS_TOOLS
from tools import set_tenant_context, set_phase_context, set_graph_view_context

logger = logging.getLogger(__name__)


# ---------- Exit nodes ----------

async def fireteam_await_confirmation_node(
    state: FireteamMemberState,
    config,
    *,
    streaming_callbacks=None,
) -> dict:
    """Pause the member, emit a WS event, and block on operator decision.

    Replaces the legacy escalate-and-terminate behavior (FIRETEAM.md §7.3).
    Rather than terminating with ``status=needs_confirmation`` and letting
    the parent redeploy, the member stays alive — its task awaits an
    ``asyncio.Event`` from ``fireteam_confirmation_registry``. Multiple
    members can be pending simultaneously, each waiting on its own Event;
    they resume independently as the operator decides per-member.

    State transitions produced:
      * approve -> clear ``_pending_confirmation``; keep ``_decision`` /
        ``_current_plan`` / ``_current_step`` populated so the graph router
        (``_route_after_member_await_confirmation``) dispatches to the
        appropriate executor (fireteam_execute_tool / fireteam_execute_plan).
      * reject  -> clear ``_pending_confirmation``; clear ``_decision``;
        inject a HumanMessage so the next think sees the rejection and
        chooses a different approach.
      * timeout -> same as reject, with a distinct message.
    """
    from orchestrator_helpers.fireteam_confirmation_registry import (
        register as _register,
        drop as _drop,
    )

    pending = state.get("_pending_confirmation") or {}
    session_id = state.get("session_id") or ""
    # FireteamMemberState exposes the wave id as `fireteam_id` (populated by
    # fireteam_deploy_node._build_member_state). Do NOT read `_fireteam_id`
    # — that is a parent-state field and is absent on member states.
    wave_id = state.get("fireteam_id") or ""
    member_id = state.get("member_id") or ""
    member_name = state.get("member_name") or member_id

    if not pending or not session_id or not wave_id or not member_id:
        logger.error(
            "fireteam_await_confirmation: missing ids/pending (session=%s wave=%s member=%s pending=%s); "
            "treating as reject",
            session_id, wave_id, member_id, bool(pending),
        )
        return _reject_state_update(
            reason="pending_confirmation_missing",
            note="Internal error: dangerous-tool request reached confirmation node without pending details.",
        )

    entry = _register(session_id, wave_id, member_id, meta={"pending": pending})

    # Notify the UI: this member is now awaiting operator input.
    streaming_cb = None
    if streaming_callbacks is not None and session_id:
        streaming_cb = streaming_callbacks.get(session_id)
    if streaming_cb is not None and hasattr(streaming_cb, "on_fireteam_member_awaiting_confirmation"):
        try:
            await streaming_cb.on_fireteam_member_awaiting_confirmation({
                "wave_id": wave_id,
                "member_id": member_id,
                "member_name": member_name,
                "confirmation_id": pending.get("confirmation_id"),
                "mode": pending.get("mode"),
                "tools": pending.get("tools") or [],
                "reasoning": pending.get("reasoning"),
                "iteration": pending.get("iteration"),
            })
        except Exception:
            logger.exception("fireteam_await_confirmation: streaming emit failed")

    timeout_s = int(get_setting("FIRETEAM_CONFIRMATION_TIMEOUT_SEC", 600))
    logger.info(
        "[%s] member %s (%s) awaiting operator confirmation (timeout=%ds, tools=%s)",
        session_id, member_id, member_name, timeout_s,
        [t.get("tool_name") for t in (pending.get("tools") or [])],
    )

    try:
        await asyncio.wait_for(entry.event.wait(), timeout=timeout_s)
        decision = entry.decision or "reject"
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] member %s confirmation timeout after %ds; treating as reject",
            session_id, member_id, timeout_s,
        )
        decision = "reject"
    except asyncio.CancelledError:
        # Wave cancelled mid-wait: propagate so the member task cleans up.
        _drop(session_id, wave_id, member_id)
        raise
    finally:
        _drop(session_id, wave_id, member_id)

    if decision == "approve":
        logger.info("[%s] member %s: operator APPROVED — resuming ReAct loop", session_id, member_id)
        # Keep _decision + _current_plan / _current_step populated (think node
        # left them there before routing here). Just clear _pending_confirmation
        # and the router dispatches to the executor.
        return {
            "_pending_confirmation": None,
        }

    # Reject (explicit or timeout): inject a rejection HumanMessage and clear
    # the decision so the next think produces a fresh plan.
    tool_names = [t.get("tool_name") for t in (pending.get("tools") or []) if t.get("tool_name")]
    tool_list = ", ".join(tool_names) or "the requested tool(s)"
    note = (
        f"Operator REJECTED your request to run {tool_list}. "
        f"Do not retry the same tool call. Choose a different approach or "
        f"emit action=complete if no viable alternative exists."
    )
    logger.info("[%s] member %s: operator REJECTED tools=%s", session_id, member_id, tool_names)
    return _reject_state_update(reason="operator_rejected", note=note)


def _reject_state_update(reason: str, note: str) -> dict:
    """Shared state update for rejection / timeout / internal-error paths."""
    return {
        "_pending_confirmation": None,
        "_decision": None,
        "_current_plan": None,
        "_current_step": None,
        "messages": [HumanMessage(content=note)],
    }


async def fireteam_complete_node(state: FireteamMemberState, config) -> dict:
    """Member terminates with success. Parent harvests final state."""
    return {"task_complete": True}


# ---------- Decision stripping (safety-critical) ----------

_FORBIDDEN_MEMBER_ACTIONS = {
    "deploy_fireteam": "deploy_forbidden_in_member",
    "transition_phase": "requested_phase_escalation",
    "ask_user": "cannot_ask_in_member",
}


def _strip_forbidden_actions(decision: LLMDecision, member_id: str) -> LLMDecision:
    """Return a decision with forbidden member actions rewritten to complete."""
    if decision.action in _FORBIDDEN_MEMBER_ACTIONS:
        reason = _FORBIDDEN_MEMBER_ACTIONS[decision.action]
        logger.warning(
            "fireteam_member %s emitted forbidden action=%s; stripped to complete (reason=%s)",
            member_id, decision.action, reason,
        )
        return decision.model_copy(update={
            "action": "complete",
            "completion_reason": reason,
            "tool_name": None,
            "tool_args": None,
            "tool_plan": None,
            "fireteam_plan": None,
            "phase_transition": None,
            "user_question": None,
        })
    return decision


def _plan_has_dangerous_tool(decision: LLMDecision) -> bool:
    plan = decision.tool_plan
    if not plan or not plan.steps:
        return False
    return any((s.tool_name or "") in DANGEROUS_TOOLS for s in plan.steps)


def _build_pending_confirmation(decision: LLMDecision, state: FireteamMemberState) -> dict:
    """Build a ToolConfirmationRequest-compatible dict for escalation."""
    if decision.action == "use_tool":
        tools = [{"tool_name": decision.tool_name, "tool_args": decision.tool_args or {}}]
        mode = "single"
    else:  # plan_tools
        tools = [
            {"tool_name": s.tool_name, "tool_args": s.tool_args or {}}
            for s in (decision.tool_plan.steps if decision.tool_plan else [])
        ]
        mode = "plan"
    return {
        "confirmation_id": uuid4().hex[:8],
        "mode": mode,
        "tools": tools,
        "reasoning": decision.reasoning,
        "phase": state.get("current_phase", "informational"),
        "iteration": state.get("current_iteration", 0),
        "agent_id": state.get("member_id"),
        "agent_name": state.get("member_name"),
    }


# ---------- Prompt construction ----------

_MEMBER_SYSTEM_PROMPT = """You are a Fireteam member agent specializing in a focused pentesting subtask.

## Your mission
{task}

## Constraints (hard-locked)
- Current phase: {phase}  (IMMUTABLE; you cannot request transition)
- You CANNOT deploy sub-fireteams. Stay focused on your assigned task.
- You CANNOT ask the operator. Use your best judgment; return findings when done.
- Every dangerous tool call you issue will be escalated to the operator for approval.
- Iteration budget: {max_iterations} steps.

## Target context (inherited from parent, snapshot)
{target_info}

## Your execution trace so far
{trace_summary}

## Available tools (filtered by your skills and current phase)
{tool_list}

## Tool argument schemas
{tool_args_section}

## Response format (STRICT — Pydantic-validated)
Emit EXACTLY ONE JSON object matching LLMDecision. ALL of these fields are REQUIRED at the top level:
  - `thought`    : string — what you observed / decided (1-2 sentences)
  - `reasoning`  : string — why you chose this next step (1-3 sentences)
  - `action`     : one of "use_tool" | "plan_tools" | "complete"

Action-specific required fields:
  - action="use_tool"   -> `tool_name` (string) + `tool_args` (OBJECT, never a CLI string)
  - action="plan_tools" -> `tool_plan` = {{"steps": [{{"tool_name": "...", "tool_args": {{...}}, "rationale": "..."}}, ...], "plan_rationale": "..."}}
  - action="complete"   -> `completion_reason` (string)

CRITICAL: `tool_args` is ALWAYS a JSON object keyed by argument name — NEVER a raw flag string.
  WRONG: "tool_args": "-w wordlist.txt -u https://example.com"
  RIGHT: "tool_args": {{"wordlist": "wordlist.txt", "url": "https://example.com"}}

Example use_tool:
```json
{{
  "thought": "nmap showed port 22 open; I need to fingerprint SSH.",
  "reasoning": "Version banner reveals CVE-applicable versions quickly.",
  "action": "use_tool",
  "tool_name": "execute_nmap",
  "tool_args": {{"target": "10.0.0.1", "ports": "22", "flags": "-sV"}}
}}
```

Example plan_tools:
```json
{{
  "thought": "Three independent endpoints to probe.",
  "reasoning": "Fan out in one wave for speed.",
  "action": "plan_tools",
  "tool_plan": {{
    "steps": [
      {{"tool_name": "execute_ffuf", "tool_args": {{"url": "https://x/FUZZ", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt"}}, "rationale": "path fuzz"}},
      {{"tool_name": "execute_httpx", "tool_args": {{"targets": ["https://x"]}}, "rationale": "fingerprint"}}
    ],
    "plan_rationale": "parallel recon"
  }}
}}
```

When you have completed your task or can go no further, emit action="complete" with a `completion_reason`.
Keep thought/reasoning concise. Prefer plan_tools when you can fire several independent tools at once.
{pending_output_section}"""


# Analysis section injected when a tool just finished and its output is
# pending analysis. Mirrors the root agent's PENDING_OUTPUT_ANALYSIS_SECTION
# but tailored to members' scope (they don't signal phase transitions, etc).
_MEMBER_PENDING_OUTPUT_SECTION = """
## Previous Tool Output (MUST ANALYZE)

The following tool just completed. You MUST include an `output_analysis` object
in your JSON response so your findings are persisted to the chain graph in
real time with YOUR attribution.

**Tool**: {tool_name}
**Arguments**: {tool_args}
**Success**: {success}
**Output**:
```
{tool_output}
```

Include `output_analysis`:
```json
"output_analysis": {{
    "interpretation": "What this output reveals (1-3 sentences)",
    "extracted_info": {{
        "primary_target": "", "ports": [], "services": [],
        "technologies": [], "vulnerabilities": [], "credentials": [], "sessions": []
    }},
    "actionable_findings": ["concrete follow-up items"],
    "recommended_next_steps": ["what you plan to do next"],
    "exploit_succeeded": false,
    "exploit_details": null,
    "chain_findings": [
        {{
            "finding_type": "vulnerability_confirmed | service_identified | credential_found | exploit_success | information_disclosure | configuration_found | custom",
            "severity": "critical | high | medium | low | info",
            "title": "one-line summary",
            "evidence": "2-3 sentences grounded in the output above",
            "related_cves": [],
            "related_ips": [],
            "confidence": 80
        }}
    ]
}}
```

Emit chain_findings for EVERY notable signal in the output: new services,
confirmed vulns, credentials, exploit outcomes. One finding per distinct fact.
Do NOT hallucinate findings not in the output. Empty list is fine if the
output shows nothing security-relevant.

Set `exploit_succeeded = true` ONLY when output shows a Meterpreter session
opened, cracked credentials returned, or a command proved RCE (uid=0, file
read, etc.). When true, populate `exploit_details` with target_ip, cve_ids,
and evidence."""


_MEMBER_PENDING_PLAN_OUTPUTS_SECTION = """
## Plan Wave Outputs (MUST ANALYZE ALL)

The {n_tools} tools from your plan wave have completed. Analyze ALL outputs
together and include a SINGLE `output_analysis` in your JSON response covering
every tool holistically. Findings will be persisted to the chain graph in
real time with YOUR attribution, anchored to each ChainStep in the wave.

{tool_outputs_section}

`output_analysis` schema (same as single-tool):
```json
"output_analysis": {{
    "interpretation": "Combined analysis of all tool outputs (2-4 sentences)",
    "extracted_info": {{
        "primary_target": "IP/host",
        "ports": [], "services": [], "technologies": [],
        "vulnerabilities": [], "credentials": [], "sessions": []
    }},
    "actionable_findings": [],
    "recommended_next_steps": [],
    "exploit_succeeded": false,
    "exploit_details": null,
    "chain_findings": [
        {{"finding_type": "service_identified|vulnerability_confirmed|...",
          "severity": "info|low|medium|high|critical",
          "title": "one-line", "evidence": "from output above",
          "related_cves": [], "related_ips": [], "confidence": 80}}
    ]
}}
```

One finding per distinct fact across ALL tools. Do NOT hallucinate — ground
every finding in the raw output above."""


def _build_pending_output_section(state: FireteamMemberState) -> str:
    """Build the output-analysis section for either a single-tool step or a
    completed plan wave. Returns empty string if nothing pending."""
    # Prefer plan wave when there are unanalyzed plan outputs — a plan wave
    # always carries richer signal than a stale _current_step.
    pending_plan = state.get("_current_plan")
    has_pending_plan_outputs = bool(
        pending_plan
        and pending_plan.get("steps")
        and any(s.get("tool_output") is not None for s in pending_plan.get("steps", []))
        and not pending_plan.get("_analyzed")
    )
    if has_pending_plan_outputs:
        plan_steps = pending_plan.get("steps", [])
        max_chars = get_setting('TOOL_OUTPUT_MAX_CHARS', 20000)
        chars_per_tool = max(2000, max_chars // max(1, len(plan_steps)))
        parts = []
        for i, s in enumerate(plan_steps):
            output = (s.get("tool_output") or s.get("error_message") or "No output")[:chars_per_tool]
            status = "OK" if s.get("success") else "FAILED"
            parts.append(
                f"### Tool {i+1}: {s.get('tool_name', 'unknown')} ({status})\n"
                f"Args: {json_dumps_safe(s.get('tool_args', {}))}\n"
                f"Output:\n```\n{output}\n```"
            )
        return _MEMBER_PENDING_PLAN_OUTPUTS_SECTION.format(
            n_tools=len(plan_steps),
            tool_outputs_section="\n\n".join(parts),
        )

    prev_step = state.get("_current_step")
    has_pending_output = bool(
        prev_step and prev_step.get("tool_output") is not None
    )
    if has_pending_output:
        max_chars = get_setting('TOOL_OUTPUT_MAX_CHARS', 20000)
        return _MEMBER_PENDING_OUTPUT_SECTION.format(
            tool_name=prev_step.get("tool_name", ""),
            tool_args=str(prev_step.get("tool_args", {}))[:500],
            success=bool(prev_step.get("success", True)),
            tool_output=str(prev_step.get("tool_output", ""))[:max_chars],
        )

    return ""


def _build_member_prompt(state: FireteamMemberState) -> str:
    from prompts import get_phase_tools
    from prompts.base import build_tool_args_section

    phase = state.get("current_phase", "informational")

    # Tools filtered to the ones available in this phase. `get_phase_tools`
    # returns an already-formatted multi-section STRING (tool names, args,
    # phase guidance, stealth rules). Do NOT `", ".join` it — that splits
    # the string character-by-character and triples the prompt size.
    #
    # Pass `attack_path_type` through so the member prompt also picks up
    # active chat/user skills (e.g. "user_skill:<id>") and built-in skill
    # workflows (e.g. "brute_force_credential_guess"). The parent state's
    # attack_path_type is inherited at deploy time in _build_member_state,
    # so members and the root agent see the same skill content.
    phase_tools = get_phase_tools(
        phase,
        attack_path_type=state.get("attack_path_type", ""),
        execution_trace=state.get("execution_trace") or None,
    )
    skills = state.get("skills") or []
    if skills:
        # Skills currently filter implicitly via the prompt; we also surface the skills
        # so the LLM picks the right tools. We do NOT hard-restrict the tool list here
        # because execute_tool_node already enforces phase allowlists and RoE.
        tool_list = f"{phase_tools}\n\n(prioritize skills: {', '.join(skills)})"
    else:
        tool_list = phase_tools

    # Structured per-tool argument schemas so the LLM emits tool_args as an
    # object (not a raw CLI flag string). Uses the same builder the root
    # think_node uses.
    allowed_tools = get_allowed_tools_for_phase(phase)
    tool_args_section = build_tool_args_section(allowed_tools)

    trace = state.get("execution_trace") or []
    if trace:
        trace_summary = "\n".join(
            f"  {i+1}. {s.get('tool_name', '?')} -> {str(s.get('output_analysis') or s.get('output_summary') or '')[:200]}"
            for i, s in enumerate(trace[-10:])
        )
    else:
        trace_summary = "  (no steps yet)"

    # Prefer the live (merged) target_info over the parent snapshot once the
    # member has started accumulating its own discoveries. Falls back to parent
    # snapshot on the first turn when member target_info is still the snapshot.
    target_info = state.get("target_info") or state.get("parent_target_info") or {}
    target_lines = []
    for key in ("primary_target", "ports", "services", "technologies", "vulnerabilities"):
        v = target_info.get(key)
        if v:
            target_lines.append(f"  {key}: {v}")
    target_str = "\n".join(target_lines) if target_lines else "  (no target info)"

    pending_output_section = _build_pending_output_section(state)

    return _MEMBER_SYSTEM_PROMPT.format(
        task=state.get("task", "(no task specified)"),
        phase=phase,
        max_iterations=state.get("max_iterations", 15),
        target_info=target_str,
        trace_summary=trace_summary,
        tool_list=tool_list,
        tool_args_section=tool_args_section,
        pending_output_section=pending_output_section,
    )


def _merge_extracted_info_into_target(state: FireteamMemberState, analysis) -> dict:
    """Return the merged target_info dict from state + analysis.extracted_info."""
    current = TargetInfo(**(state.get("target_info") or {}))
    extracted = analysis.extracted_info if analysis is not None else None
    if extracted is None:
        return current.model_dump()
    new_target = TargetInfo(
        primary_target=extracted.primary_target,
        ports=extracted.ports, services=extracted.services,
        technologies=extracted.technologies,
        vulnerabilities=extracted.vulnerabilities,
        credentials=extracted.credentials, sessions=extracted.sessions,
    )
    return current.merge_from(new_target).model_dump()


# ---------- Main node ----------

async def fireteam_member_think_node(
    state: FireteamMemberState,
    config,
    *,
    llm,
    neo4j_creds=None,
    streaming_callbacks=None,
    graph_view_cyphers=None,
) -> dict:
    """Single ReAct step for a fireteam member."""
    member_id = state.get("member_id") or "unknown"
    member_name = state.get("member_name") or member_id
    session_id = state.get("session_id") or ""
    user_id = state.get("user_id") or ""
    project_id = state.get("project_id") or ""
    fireteam_id = state.get("fireteam_id") or None
    prev_step_id = state.get("_last_chain_step_id")

    # Detect pending single-tool output and pending plan wave (at most one of
    # these is true on any given turn — execute_tool_node populates
    # _current_step, execute_plan_node populates _current_plan.steps[*].tool_output).
    pending_plan = state.get("_current_plan")
    has_pending_plan_outputs = bool(
        pending_plan
        and pending_plan.get("steps")
        and any(s.get("tool_output") is not None for s in pending_plan.get("steps", []))
        and not pending_plan.get("_analyzed")
    )

    prev_step = state.get("_current_step")
    has_pending_single_output = bool(
        prev_step
        and prev_step.get("tool_output") is not None
        and not has_pending_plan_outputs  # plan wave wins
    )

    # Chain graph write of the PREVIOUS single-tool step. Members write the
    # step BEFORE the LLM so findings can anchor to it. Plan-wave steps are
    # written later (after the LLM produces combined analysis) so per-step
    # extracted_info bridging happens with the same data for every step.
    step_chain_update: dict = {}
    prev_chain_step_id: Optional[str] = None  # Anchor for inline finding/failure writes below.
    if has_pending_single_output and neo4j_creds:
        neo4j_uri, neo4j_user, neo4j_password = neo4j_creds
        chain_step_id = uuid4().hex
        try:
            chain_graph.fire_record_step(
                neo4j_uri, neo4j_user, neo4j_password,
                step_id=chain_step_id,
                chain_id=session_id,
                prev_step_id=prev_step_id,
                user_id=user_id,
                project_id=project_id,
                iteration=int(prev_step.get("iteration") or 0),
                phase=state.get("current_phase", "informational"),
                tool_name=prev_step.get("tool_name") or "",
                tool_args_summary=str(prev_step.get("tool_args") or {})[:500],
                thought=(prev_step.get("thought") or "")[:4000],
                reasoning=(prev_step.get("reasoning") or "")[:4000],
                output_summary=(prev_step.get("tool_output") or "")[:4000],
                success=bool(prev_step.get("success", True)),
                error_message=prev_step.get("error_message"),
                duration_ms=prev_step.get("duration_ms"),
                agent_id=member_id,
                agent_name=member_name,
                fireteam_id=fireteam_id,
            )
            step_chain_update["_last_chain_step_id"] = chain_step_id
            prev_chain_step_id = chain_step_id
            # Inline ChainFailure write when the tool errored. Matches root's
            # pattern in think_node.py — failures need to appear in the graph
            # live, not be squirreled away only in member state.
            if not bool(prev_step.get("success", True)):
                try:
                    chain_graph.fire_record_failure(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=chain_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        failure_type="tool_error",
                        tool_name=prev_step.get("tool_name", ""),
                        error_message=(prev_step.get("error_message") or "")[:2000],
                        iteration=int(prev_step.get("iteration") or 0),
                    )
                except Exception as e:
                    logger.warning("member chain_failure write failed: %s", e)
        except Exception as e:
            logger.warning("member chain_step write failed: %s", e)

    # Propagate tenant context so tools called downstream know who we are.
    set_tenant_context(state.get("user_id", ""), state.get("project_id", ""))
    set_phase_context(state.get("current_phase", "informational"))
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # ---- Budget enforcement (before any LLM call) ----
    current_iter = state.get("current_iteration", 0)
    max_iter = state.get("max_iterations", 15)
    if current_iter >= max_iter:
        logger.info("[%s] member %s iteration budget exhausted (%d/%d)", session_id, member_id, current_iter, max_iter)
        return {
            "task_complete": True,
            "completion_reason": "iteration_budget_exceeded",
        }

    # Iteration budget is the sole runtime cap; tokens_used is accumulated
    # below for passive observability only (metrics, report, UI).
    tokens_used = state.get("tokens_used", 0)

    # ---- LLM call with parse-retry loop (mirrors root think_node) ----
    #
    # Do NOT concatenate state["messages"] into llm_messages. The member's
    # history lives in `execution_trace` (baked into the system prompt by
    # _build_member_prompt) and in `messages` as an auxiliary audit trail.
    # Passing the raw AIMessages back into the LLM caused the conversation
    # to end on an assistant message across iterations, which Anthropic
    # rejects on models without prefill support:
    #   "This model does not support assistant message prefill. The
    #    conversation must end with a user message."
    # Root think_node has the same design (think_node.py:439-442): fresh
    # [System, Human] per think call; the growing history lives in the
    # prompt text, not the LangChain messages list.
    system_prompt = _build_member_prompt(state)
    llm_messages: list = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=(
            "Based on your execution trace and current target_info, decide "
            "your next action. Output EXACTLY ONE valid LLMDecision JSON. "
            "Do not simulate tool output; you will receive real tool results "
            "on the next turn."
        )),
    ]

    # ---- Observability: header + full prompt dump (mirrors root think_node) ----
    phase = state.get("current_phase", "informational")
    member_name = state.get("member_name", member_id)
    logger.info(f"\n{'#' * 80}")
    logger.info(
        f"# FIRETEAM MEMBER THINK - {member_name} ({member_id}) - "
        f"Iteration {current_iter + 1}/{max_iter} - Phase: {phase}"
    )
    logger.info(f"# Session: {session_id} | Wave: {state.get('fireteam_id', '')}")
    logger.info(f"# Task: {state.get('task', '')[:200]}")
    logger.info(f"\n--- FULL SYSTEM PROMPT ({len(system_prompt)} chars) ---")
    for i in range(0, len(system_prompt), 4000):
        chunk = system_prompt[i:i + 4000]
        logger.info(f"MEMBER PROMPT[{i}:{i + len(chunk)}]:\n{chunk}")
    logger.info(f"{'#' * 80}\n")

    max_retries = get_setting('LLM_PARSE_MAX_RETRIES', 3)
    decision = None
    parse_error: Optional[str] = None
    raw_content = ""
    input_tokens_this_turn = 0
    output_tokens_this_turn = 0

    for attempt in range(max_retries):
        if attempt > 0:
            logger.info(
                "[%s] member %s parse attempt %d/%d after error: %s",
                session_id, member_id, attempt + 1, max_retries, parse_error,
            )
            llm_messages.append(AIMessage(content=raw_content))
            llm_messages.append(HumanMessage(
                content=(
                    f"Your previous JSON failed validation:\n{parse_error}\n\n"
                    "Fix the error and emit ONE valid LLMDecision JSON. "
                    "Remember: top-level `thought`, `reasoning`, `action` are REQUIRED. "
                    "`tool_args` must be a JSON object, NEVER a CLI string."
                )
            ))

        try:
            response = await llm.ainvoke(llm_messages)
        except Exception as exc:
            logger.error("[%s] member %s LLM call failed: %s", session_id, member_id, exc)
            return {
                "task_complete": True,
                "completion_reason": f"llm_error: {exc}",
            }

        raw_content = normalize_content(response.content if hasattr(response, "content") else response)

        _usage = getattr(response, "usage_metadata", None) or {}
        input_tokens_this_turn += int(_usage.get("input_tokens", 0) or 0)
        output_tokens_this_turn += int(_usage.get("output_tokens", 0) or 0)

        decision, parse_error = try_parse_llm_decision(raw_content)
        if decision is not None:
            break

    if decision is None:
        logger.warning(
            "[%s] member %s unparseable after %d attempts (%s); exiting",
            session_id, member_id, max_retries, parse_error,
        )
        return {
            "task_complete": True,
            "completion_reason": f"parse_error: {parse_error}",
        }

    # ---- Safety-critical: strip forbidden actions ----
    decision = _strip_forbidden_actions(decision, member_id)

    # ---- Observability: decision summary (mirrors root think_node) ----
    logger.info(f"[{session_id}] member {member_id} ({member_name}) "
                f"Decision: action={decision.action}, tool={decision.tool_name}")
    logger.info(f"[{member_id}] THOUGHT: {decision.thought}")
    logger.info(f"[{member_id}] REASONING: {decision.reasoning}")
    logger.info(f"[{member_id}] ACTION: {decision.action}")
    if decision.action == "plan_tools" and decision.tool_plan:
        for i, step in enumerate(decision.tool_plan.steps, 1):
            logger.info(f"[{member_id}]   PLAN STEP {i}: {step.tool_name} "
                        f"args={json_dumps_safe(step.tool_args or {})[:300]}")
    elif decision.action == "use_tool":
        logger.info(f"[{member_id}]   TOOL: {decision.tool_name} "
                    f"args={json_dumps_safe(decision.tool_args or {})[:300]}")
    if decision.output_analysis and getattr(decision.output_analysis, "interpretation", None):
        logger.info(f"[{member_id}] ANALYSIS: {decision.output_analysis.interpretation[:500]}")
    if decision.completion_reason:
        logger.info(f"[{member_id}] COMPLETION_REASON: {decision.completion_reason}")
    logger.info("=" * 60)

    # ---- Dangerous-tool escalation ----
    tool_confirmation_enabled = get_setting("REQUIRE_TOOL_CONFIRMATION", True)
    is_dangerous = False
    if tool_confirmation_enabled:
        if decision.action == "use_tool" and (decision.tool_name or "") in DANGEROUS_TOOLS:
            is_dangerous = True
        elif decision.action == "plan_tools" and _plan_has_dangerous_tool(decision):
            is_dangerous = True

    # Token accounting: prefer provider-reported usage_metadata (accurate
    # per-call). Fall back to the tokenizer estimate, and finally to a crude
    # char/3.5 estimate, so we always emit SOMETHING for the UI even if the
    # provider skips usage reporting. Count THIS turn's delta only: cumulative
    # counting on history would produce O(N^2) growth.
    if input_tokens_this_turn == 0 and output_tokens_this_turn == 0:
        try:
            _est = int(llm.get_num_tokens_from_messages([
                SystemMessage(content=system_prompt),
                AIMessage(content=raw_content),
            ]))
        except Exception:
            _est = max(1, int((len(system_prompt) + len(raw_content)) / 3.5))
        # Rough split when provider didn't report: ~85% input / 15% output.
        input_tokens_this_turn = int(_est * 0.85)
        output_tokens_this_turn = max(1, _est - input_tokens_this_turn)

    tokens_this_turn = input_tokens_this_turn + output_tokens_this_turn
    prev_in = int(state.get("input_tokens_used", 0) or 0)
    prev_out = int(state.get("output_tokens_used", 0) or 0)

    update: dict = {
        "current_iteration": current_iter + 1,
        "tokens_used": tokens_used + tokens_this_turn,
        "input_tokens_used": prev_in + input_tokens_this_turn,
        "output_tokens_used": prev_out + output_tokens_this_turn,
        "_input_tokens_this_turn": input_tokens_this_turn,
        "_output_tokens_this_turn": output_tokens_this_turn,
        "_decision": decision.model_dump(),
        "messages": [AIMessage(content=raw_content)],
    }

    # Merge chain-step update from PREVIOUS tool (so follow-on steps link correctly).
    update.update(step_chain_update)

    # Resolve the previous-step analysis object early — it's read by the
    # is_dangerous escalation branch below (for _completed_step emission) AND
    # by the downstream single-tool / plan-wave analysis branches. Without
    # defining it here, the is_dangerous branch crashed with NameError.
    analysis = decision.output_analysis

    if is_dangerous:
        pending = _build_pending_confirmation(decision, state)
        update["_pending_confirmation"] = pending
        # Even though we're escalating the NEW decision, the PREVIOUS
        # single-tool step (if any) is now completed — its output was the
        # input to this think call. Signal it to the streaming layer so the
        # UI flips the prior tool card from `running` to `success/error`.
        # Without this, the frontend sees: tool_start → (never completes) →
        # pending-approval card, and the prior tool stays stuck visually.
        if has_pending_single_output and prev_step:
            completed_prev = dict(prev_step)
            if analysis is not None:
                completed_prev["output_analysis"] = (
                    analysis.interpretation
                    or (prev_step.get("tool_output") or "")
                )[:20000]
                completed_prev["actionable_findings"] = list(analysis.actionable_findings or [])
                completed_prev["recommended_next_steps"] = list(analysis.recommended_next_steps or [])
            else:
                completed_prev["output_analysis"] = (prev_step.get("tool_output") or "")[:20000]
                completed_prev["actionable_findings"] = []
                completed_prev["recommended_next_steps"] = []
            update["_completed_step"] = completed_prev
        logger.info(
            "[%s] member %s escalating dangerous tool for parent approval: %s",
            session_id, member_id,
            decision.tool_name or [s.tool_name for s in (decision.tool_plan.steps if decision.tool_plan else [])],
        )
        # Router will send us to fireteam_await_confirmation because
        # _pending_confirmation is set.
        return update

    # If action is complete, ensure task_complete is True so the router exits.
    if decision.action == "complete":
        update["task_complete"] = True
        update["completion_reason"] = decision.completion_reason or "complete"

    # For use_tool / plan_tools, _current_plan and tool_name/args are read by the
    # execute_* nodes. Mirror existing think_node conventions.
    if decision.action == "plan_tools" and decision.tool_plan:
        update["_current_plan"] = decision.tool_plan.model_dump()
    elif decision.action == "use_tool":
        update["_current_step"] = {
            "step_id": uuid4().hex,
            "iteration": current_iter + 1,
            "phase": state.get("current_phase"),
            "tool_name": decision.tool_name,
            "tool_args": decision.tool_args or {},
            "thought": decision.thought,
            "reasoning": decision.reasoning,
        }

    # `analysis` already resolved earlier (before the is_dangerous branch).
    current_phase = state.get("current_phase", "informational")

    # =========================================================================
    # SINGLE-TOOL PATH: analysis applies to the previous _current_step.
    # ChainStep was already written above (fire_record_step); findings/exploit/
    # bridges anchor to that step. Also merge extracted_info into target_info
    # and append the completed step to execution_trace so the next prompt and
    # FireteamMemberResult.execution_trace_summary reflect the work.
    # =========================================================================
    if has_pending_single_output and analysis is not None:
        if neo4j_creds and prev_chain_step_id:
            neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

            # Bridge (ChainStep)-[:STEP_TARGETED|STEP_EXPLOITED|STEP_IDENTIFIED|...]
            # edges to recon graph nodes. Root agent does this inline inside
            # sync_record_step by passing extracted_info; the member wrote its
            # step BEFORE the LLM returned the analysis, so we resolve bridges
            # here as a follow-up fire-and-forget.
            try:
                extracted_info = (
                    analysis.extracted_info.model_dump()
                    if analysis.extracted_info is not None
                    else {}
                )
                if extracted_info:
                    chain_graph.fire_resolve_step_bridges(
                        neo4j_uri, neo4j_user, neo4j_password,
                        step_id=prev_chain_step_id,
                        extracted_info=extracted_info,
                        user_id=user_id,
                        project_id=project_id,
                        tool_name=prev_step.get("tool_name") or "" if prev_step else "",
                    )
            except Exception as e:
                logger.warning("member bridge resolve failed: %s", e)

            # exploit_success: write first so the PRODUCED edge is distinct from
            # regular findings (mirrors root think_node's ordering).
            if analysis.exploit_succeeded and analysis.exploit_details and current_phase == "exploitation":
                details = analysis.exploit_details
                try:
                    chain_graph.fire_record_exploit_success(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=prev_chain_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        attack_type=details.get("attack_type", state.get("attack_path_type", "cve_exploit")),
                        target_ip=details.get("target_ip", ""),
                        target_port=details.get("target_port"),
                        cve_ids=details.get("cve_ids", []),
                        session_id=details.get("session_id"),
                        evidence=details.get("evidence", "")[:500],
                    )
                except Exception as e:
                    logger.warning("member exploit_success write failed: %s", e)

            # Regular chain findings, skipping exploit-overlapping ones if
            # exploit_success was already recorded (same dedup as root).
            _EXPLOIT_OVERLAP = {"exploit_success", "access_gained", "credential_found"}
            step_iter = int(prev_step.get("iteration") or 0) if prev_step else 0
            member_findings_memory = list(state.get("chain_findings_memory") or [])
            for cf in (analysis.chain_findings or []):
                if analysis.exploit_succeeded and cf.finding_type in _EXPLOIT_OVERLAP:
                    continue
                try:
                    chain_graph.fire_record_finding(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=prev_chain_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        finding_type=cf.finding_type,
                        severity=cf.severity,
                        title=cf.title,
                        evidence=cf.evidence,
                        confidence=cf.confidence,
                        phase=current_phase,
                        iteration=step_iter,
                        related_cves=cf.related_cves or [],
                        related_ips=cf.related_ips or [],
                        agent_id=member_id,
                        source_agent=member_name,
                        fireteam_id=fireteam_id,
                    )
                except Exception as e:
                    logger.warning("member chain_finding write failed: %s", e)
                # Tag with step_iteration so the parent's format_chain_context
                # shows "(step N)" instead of "(step ?)" after roll-up.
                finding_dict = cf.model_dump()
                finding_dict["step_iteration"] = step_iter
                member_findings_memory.append(finding_dict)
            if member_findings_memory != (state.get("chain_findings_memory") or []):
                update["chain_findings_memory"] = member_findings_memory

        # Target-info merge + execution-trace append happen regardless of
        # whether Neo4j creds are configured — these are in-memory structures
        # consumed by the parent agent and by FireteamMemberResult.
        update["target_info"] = _merge_extracted_info_into_target(state, analysis)

        completed_step = dict(prev_step or {})
        completed_step["output_analysis"] = (
            analysis.interpretation[:20000] if analysis.interpretation else ""
        )
        completed_step["actionable_findings"] = list(analysis.actionable_findings or [])
        completed_step["recommended_next_steps"] = list(analysis.recommended_next_steps or [])
        update["execution_trace"] = list(state.get("execution_trace") or []) + [completed_step]

        # Signal the streaming layer to emit `fireteam_tool_complete` for this
        # now-finished step. emit_streaming_events watches for `_completed_step`
        # on state (streaming.py:133) — without this, standalone member tools
        # stay in `running` status in the UI forever, because the WS complete
        # event only fires when `_completed_step` is populated by the NEXT
        # think turn. Root think_node does the same (think_node.py:790).
        update["_completed_step"] = completed_step

        # Clear _current_step so the next iteration doesn't re-analyze the
        # same output. CRITICAL: if the new decision IS use_tool, the
        # earlier branch (line ~787) already populated update["_current_step"]
        # with the fresh step — do NOT clobber it here. Otherwise the next
        # execute_tool_node call would see an empty step and log "No tool
        # name in step_data".
        if decision.action != "use_tool":
            update["_current_step"] = None

    elif has_pending_single_output and analysis is None:
        # Analysis missing — still record the step in execution_trace so the
        # member doesn't forget it ran. Root does the same via the "fallback"
        # branch at think_node.py:794.
        completed_step = dict(prev_step or {})
        completed_step["output_analysis"] = (prev_step.get("tool_output") or "")[:20000] if prev_step else ""
        completed_step["actionable_findings"] = []
        completed_step["recommended_next_steps"] = []
        update["execution_trace"] = list(state.get("execution_trace") or []) + [completed_step]
        update["_completed_step"] = completed_step  # emit tool_complete even without analysis
        if decision.action != "use_tool":
            update["_current_step"] = None

    # =========================================================================
    # PLAN WAVE PATH: one ChainStep per plan step with sequential linkage;
    # per-step bridges; one combined exploit_success write anchored to the
    # last step; combined chain findings anchored to the last step. Marks
    # the plan as _analyzed so subsequent turns don't re-process it.
    # =========================================================================
    if has_pending_plan_outputs:
        plan_steps = pending_plan.get("steps", [])
        plan_iteration = current_iter  # turn that just completed the wave
        merged_target = TargetInfo(**(state.get("target_info") or {}))
        member_findings_memory = list(state.get("chain_findings_memory") or [])
        new_trace_entries = []

        combined_extracted: dict = {}
        if analysis and analysis.extracted_info:
            combined_extracted = (
                analysis.extracted_info.model_dump()
                if hasattr(analysis.extracted_info, "model_dump")
                else {}
            )
            merged_target = merged_target.merge_from(TargetInfo(
                primary_target=analysis.extracted_info.primary_target,
                ports=analysis.extracted_info.ports,
                services=analysis.extracted_info.services,
                technologies=analysis.extracted_info.technologies,
                vulnerabilities=analysis.extracted_info.vulnerabilities,
                credentials=analysis.extracted_info.credentials,
                sessions=analysis.extracted_info.sessions,
            ))

        # Sequential Neo4j writes so each step links to the prior via prev_step_id.
        chain_prev = prev_step_id
        last_written_step_id: Optional[str] = None
        loop = asyncio.get_running_loop()

        for i, plan_step in enumerate(plan_steps):
            step_id = uuid4().hex
            step_thought = f"[Wave] {plan_step.get('rationale', '')}"
            step_reasoning = pending_plan.get("plan_rationale", "")
            step_output_analysis = (
                analysis.interpretation[:20000] if analysis and analysis.interpretation
                else (plan_step.get("tool_output") or "")[:20000]
            )

            exec_step = {
                "step_id": step_id,
                "iteration": plan_iteration,
                "phase": current_phase,
                "thought": step_thought,
                "reasoning": step_reasoning,
                "tool_name": plan_step.get("tool_name"),
                "tool_args": plan_step.get("tool_args"),
                "tool_output": plan_step.get("tool_output"),
                "success": plan_step.get("success", False),
                "error_message": plan_step.get("error_message"),
                "output_analysis": step_output_analysis,
                "actionable_findings": list(analysis.actionable_findings or []) if analysis else [],
                "recommended_next_steps": list(analysis.recommended_next_steps or []) if analysis else [],
            }
            new_trace_entries.append(exec_step)

            if neo4j_creds:
                neo4j_uri, neo4j_user, neo4j_password = neo4j_creds
                # Sync step write (so the next step's prev_step_id chain is
                # valid in Neo4j). Off the event loop via executor since this
                # opens a Bolt session.
                try:
                    await loop.run_in_executor(
                        None,
                        lambda _sid=step_id, _prev=chain_prev, _ps=plan_step,
                               _ei=combined_extracted, _thought=step_thought,
                               _reasoning=step_reasoning, _oa=step_output_analysis,
                               uri=neo4j_uri, usr=neo4j_user, pw=neo4j_password:
                            chain_graph.sync_record_step(
                                uri, usr, pw,
                                step_id=_sid,
                                chain_id=session_id,
                                prev_step_id=_prev,
                                user_id=user_id,
                                project_id=project_id,
                                iteration=plan_iteration,
                                phase=current_phase,
                                tool_name=_ps.get("tool_name", ""),
                                tool_args_summary=str(_ps.get("tool_args", {}))[:500],
                                thought=_thought[:4000],
                                reasoning=_reasoning[:4000],
                                output_summary=(_ps.get("tool_output") or "")[:4000],
                                output_analysis=_oa[:20000],
                                success=_ps.get("success", False),
                                error_message=_ps.get("error_message"),
                                extracted_info=_ei,
                                agent_id=member_id,
                                agent_name=member_name,
                                fireteam_id=fireteam_id,
                            ),
                    )
                    last_written_step_id = step_id
                except Exception as e:
                    logger.warning("member plan_step sync write failed: %s", e)

                # ChainFailure per failed tool
                if not plan_step.get("success"):
                    try:
                        chain_graph.fire_record_failure(
                            neo4j_uri, neo4j_user, neo4j_password,
                            chain_id=session_id,
                            step_id=step_id,
                            user_id=user_id,
                            project_id=project_id,
                            failure_type="tool_error",
                            tool_name=plan_step.get("tool_name", ""),
                            error_message=(plan_step.get("error_message") or "")[:2000],
                            iteration=plan_iteration,
                        )
                    except Exception as e:
                        logger.warning("member plan_failure write failed: %s", e)

            chain_prev = step_id

        # Combined findings / exploit_success anchored to the last step.
        if neo4j_creds and last_written_step_id and analysis is not None:
            neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

            if analysis.exploit_succeeded and analysis.exploit_details and current_phase == "exploitation":
                details = analysis.exploit_details
                try:
                    chain_graph.fire_record_exploit_success(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=last_written_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        attack_type=details.get("attack_type", state.get("attack_path_type", "cve_exploit")),
                        target_ip=details.get("target_ip", ""),
                        target_port=details.get("target_port"),
                        cve_ids=details.get("cve_ids", []),
                        session_id=details.get("session_id"),
                        evidence=details.get("evidence", "")[:500],
                    )
                except Exception as e:
                    logger.warning("member wave exploit_success write failed: %s", e)

            _EXPLOIT_OVERLAP = {"exploit_success", "access_gained", "credential_found"}
            for cf in (analysis.chain_findings or []):
                if analysis.exploit_succeeded and cf.finding_type in _EXPLOIT_OVERLAP:
                    continue
                try:
                    chain_graph.fire_record_finding(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=last_written_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        finding_type=cf.finding_type,
                        severity=cf.severity,
                        title=cf.title,
                        evidence=cf.evidence,
                        confidence=cf.confidence,
                        phase=current_phase,
                        iteration=plan_iteration,
                        related_cves=cf.related_cves or [],
                        related_ips=cf.related_ips or [],
                        agent_id=member_id,
                        source_agent=member_name,
                        fireteam_id=fireteam_id,
                    )
                except Exception as e:
                    logger.warning("member wave chain_finding write failed: %s", e)

        # In-memory state updates. These apply even without Neo4j creds because
        # they feed FireteamMemberResult and the member's own next-turn prompt.
        if analysis is not None:
            for cf in (analysis.chain_findings or []):
                finding_dict = cf.model_dump()
                finding_dict["step_iteration"] = plan_iteration
                member_findings_memory.append(finding_dict)
            if member_findings_memory != (state.get("chain_findings_memory") or []):
                update["chain_findings_memory"] = member_findings_memory

        update["execution_trace"] = list(state.get("execution_trace") or []) + new_trace_entries
        update["target_info"] = merged_target.model_dump()
        if last_written_step_id:
            update["_last_chain_step_id"] = last_written_step_id

        # Mark the plan as analyzed so the next think turn doesn't re-process
        # it. If the LLM emitted a NEW plan_tools decision, `update["_current_plan"]`
        # was already overwritten above to the new plan (no _analyzed flag)
        # and the next turn will execute it. Otherwise clear the stale plan.
        if decision.action == "plan_tools" and decision.tool_plan:
            pass  # update["_current_plan"] already set to the new plan above
        else:
            update["_current_plan"] = None

    return update

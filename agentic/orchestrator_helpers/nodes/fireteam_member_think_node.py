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

from state import LLMDecision, FireteamMemberState, TargetInfo, format_chain_context
from orchestrator_helpers.parsing import try_parse_llm_decision
from orchestrator_helpers.json_utils import normalize_content, json_dumps_safe
from orchestrator_helpers.llm_retry import retry_llm_call
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


# ---------- Soft skill allowlist helpers ----------

def _collect_called_tools(decision: LLMDecision) -> list[str]:
    """Return the tool names this decision intends to invoke.

    use_tool  -> [tool_name]
    plan_tools -> [step.tool_name for step in tool_plan.steps]
    other actions -> []
    """
    if decision.action == "use_tool":
        return [decision.tool_name] if decision.tool_name else []
    if decision.action == "plan_tools" and decision.tool_plan:
        return [s.tool_name for s in (decision.tool_plan.steps or []) if s.tool_name]
    return []


def _validate_tool_expansion(
    decision: LLMDecision,
    declared_tools: set,
) -> Optional[str]:
    """Return None when the decision is consistent with the soft-allowlist
    contract, or a one-paragraph correction message that should be re-injected
    into the LLM conversation.

    Contract: if any called tool is OUTSIDE `declared_tools` (after the
    query_graph anchor is added), the decision MUST carry a non-empty
    `tool_expansion_reason`. Members with no declared tools (tools=[]) bypass
    this check — they are operating without a soft allowlist, same as the
    root agent.
    """
    if not declared_tools:
        return None
    if decision.action not in ("use_tool", "plan_tools"):
        return None
    called = _collect_called_tools(decision)
    if not called:
        return None
    allowed = set(declared_tools) | {"query_graph"}
    expanded = [t for t in called if t not in allowed]
    if not expanded:
        return None
    reason = (decision.tool_expansion_reason or "").strip()
    if reason:
        return None
    return (
        f"[system] You are reaching for fallback tools: {expanded}. "
        f"Your declared primary tools are {sorted(allowed - {'query_graph'})}. "
        "You MUST add a `tool_expansion_reason` field at the top level of your "
        "decision JSON explaining (in one sentence) why your primary tools "
        "cannot accomplish this step. If your primary tools CAN do the job, "
        "switch to one. If they CAN'T because the task was mis-scoped, consider "
        "emitting `action=complete` with current findings so the root planner "
        "can re-deploy with the right tools. Re-emit your full LLMDecision JSON "
        "with the new field."
    )


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
{peer_block}
## Constraints (hard-locked)
- Current phase: {phase}  (IMMUTABLE; you cannot request transition)
- You CANNOT deploy sub-fireteams. Stay focused on your assigned task.
- You CANNOT ask the operator. Use your best judgment; return findings when done.
- Every dangerous tool call you issue will be escalated to the operator for approval.
- Iteration budget: {max_iterations} steps.

## Target context (inherited from parent, snapshot)
{target_info}

## Engagement state (from the root agent and prior fireteam members)
This is everything the engagement already knows at the moment you were dispatched.
Findings carry source attribution (`from <agent>`); do NOT re-discover what is listed here.
Tools, payloads, captured artifacts (tokens, credentials, endpoints) and prior failures
are all surfaced — read this first before planning your own actions.
{parent_chain_context}

## Your local progress in this run
{local_chain_context}

## Available tools (filtered by your declared tools and current phase)
{tool_list}

## Tool argument schemas
{tool_args_section}

## Response format (STRICT — Pydantic-validated)
Emit EXACTLY ONE JSON object matching LLMDecision. ALL of these fields are REQUIRED at the top level:
  - `thought`    : string — what you observed / decided (1-2 sentences)
  - `reasoning`  : string — why you chose this next step (1-3 sentences)
  - `action`     : one of "use_tool" | "plan_tools" | "complete"

Action-specific required fields:
  - action="use_tool"   -> `tool_name` (string) + `tool_args` (JSON object — shape depends on the tool, see below)
  - action="plan_tools" -> `tool_plan` = {{"steps": [{{"tool_name": "...", "tool_args": {{...}}, "rationale": "..."}}, ...], "plan_rationale": "..."}}
  - action="complete"   -> `completion_reason` (string)

CRITICAL: `tool_args` shape is per-tool. The `## Tool argument schemas` section above
(rendered from the live tool registry) is the source of truth — copy its keys exactly.
Tools fall into FOUR shape buckets — pick the right one per tool name:

  Shape A — `{{"args": "<full CLI flag string, binary name stripped>"}}`
  Tools: cve_intel, execute_nuclei, execute_curl, execute_httpx, execute_naabu, execute_jsluice, execute_katana, execute_subfinder, execute_gau, execute_nmap, execute_amass, execute_hydra, execute_wpscan, execute_arjun, execute_ffuf.
  Examples: `{{"args": "-sV -p 22 10.0.0.1"}}` (nmap), `{{"args": "-u http://x -d 3 -jc -silent"}}` (katana), `{{"args": "-u http://x -sc -title -td -j -silent"}}` (httpx).

  Shape B — `{{"command": "<full shell command>"}}`
  Tools: kali_shell, metasploit_console.

  Shape C — typed kwargs declared per tool (multi-key JSON object). Use the EXACT keys shown in `## Tool argument schemas`.
    query_graph        -> {{"question": "..."}}
    web_search         -> {{"query": "...", "include_sources": ["nvd"], "min_cvss": 9.0}}
    google_dork        -> {{"query": "..."}}
    shodan             -> {{"action": "host"|"search"|"dns_reverse"|"dns_domain"|"count", "query": "...", "ip": "...", "domain": "..."}}
    execute_code       -> {{"code": "...", "language": "python", "filename": "exploit"}}
    execute_playwright -> {{"url": "...", "selector": "...", "format": "text"|"html"}}  OR  {{"script": "..."}}
    tradecraft_lookup  -> {{"resource_id": "...", "query": "..."}}

  Shape D — no args: msf_restart -> {{}}

  WRONG (Pydantic rejects every one of these with "Unexpected keyword argument"):
    {{"url": "...", "depth": 3, "jc": true}} on execute_katana
    {{"target": "...", "ports": "22", "flags": "-sV"}} on execute_nmap
    {{"targets": ["..."]}} on execute_httpx
    {{"host": "...", "ports": "1-1000"}} on execute_naabu
    "-w wordlist -u https://x" (raw string) on ANY tool
  RIGHT: Shape A — `{{"args": "<CLI flag string>"}}`. Never invent kwargs like url/target/host/port/depth/flags on Shape A tools.

Example use_tool:
```json
{{
  "thought": "nmap showed port 22 open; I need to fingerprint SSH.",
  "reasoning": "Version banner reveals CVE-applicable versions quickly.",
  "action": "use_tool",
  "tool_name": "execute_nmap",
  "tool_args": {{"args": "-sV -p 22 10.0.0.1"}}
}}
```

Example plan_tools:
```json
{{
  "thought": "Three independent probes on the same host.",
  "reasoning": "Fan out in one wave for speed.",
  "action": "plan_tools",
  "tool_plan": {{
    "steps": [
      {{"tool_name": "execute_ffuf", "tool_args": {{"args": "-u https://x/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,403"}}, "rationale": "path fuzz"}},
      {{"tool_name": "execute_httpx", "tool_args": {{"args": "-u https://x -sc -title -server -td -fr -silent -j"}}, "rationale": "fingerprint"}},
      {{"tool_name": "query_graph", "tool_args": {{"question": "What endpoints are known on x?"}}, "rationale": "graph cross-check"}}
    ],
    "plan_rationale": "parallel recon"
  }}
}}
```

## Self-Check Before Each Decision (read this every iteration)

Before emitting your next tool call, look at "Your local progress in this run":

1. **Find-rate test.** Compare your findings count NOW vs ~3 iterations ago.
   If your tool count grew by 5 or more but findings count stayed flat — you
   are looping. Emit `action=complete` with what you have. Do NOT keep probing.

2. **Duplicate-target test.** Is your next planned tool call essentially the
   same as something already in your trace? Same URL + same method + same
   payload class (introspection / GET param fuzz / directory fuzz / known-path
   probe) counts as duplicate even if flags differ slightly. If yes — DO NOT
   re-run it. Pivot to a different surface or complete.

3. **Negative-result test.** Did a previous probe return a known-negative
   result (404 catch-all, identical baseline timing, generic 200 with no
   reflection / no error / no signal)? Do not retry the same probe with a
   minor flag tweak. Emit a `cleared_endpoint` finding so siblings know it's
   dead, then pivot or complete.

4. **Findings-emission rule.** When you complete, EVERY distinct discovery in
   your trace MUST appear as a `chain_findings` entry in `output_analysis`
   (e.g. one per service version, endpoint, technology, credential, cleared
   surface). Findings flow to siblings via chain context; `completion_reason`
   text is mostly discarded. A 0-finding completion is almost always wrong.

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
    from prompts.base import build_tool_args_section, build_compact_tool_list

    phase = state.get("current_phase", "informational")

    declared_tools = state.get("tools") or []
    phase_allowed = get_allowed_tools_for_phase(phase)

    if declared_tools:
        # Soft allowlist. The member CAN call any phase-allowed tool, but the
        # prompt presents "primary tools" (the declared tools, full descriptions
        # + flag examples) and "fallback toolbox" (everything else, compact
        # bullet list with name + purpose only). Reaching for fallback requires
        # a `tool_expansion_reason` field on the decision (enforced post-parse).
        #
        # query_graph is always in the primary set as a read-only anchor —
        # members commonly need it to cross-check sibling findings.
        primary_set = set(declared_tools) | {"query_graph"}
        fallback_tools = [t for t in phase_allowed if t not in primary_set]

        # Primary block: full phase-context rendering (kali rules, custom
        # instructions, attack-path skill workflow, etc.) but with the tool
        # registry filtered to the declared tools only.
        primary_phase_tools = get_phase_tools(
            phase,
            attack_path_type=state.get("attack_path_type", ""),
            execution_trace=state.get("execution_trace") or None,
            tool_filter=primary_set,
        )
        primary_block = (
            "## Primary tools (your assigned toolbox — use these by default)\n\n"
            f"{primary_phase_tools}"
        )

        # Fallback block: compact name+purpose only. The model knows these
        # tools exist; reaching for them requires explicit justification.
        fallback_block = ""
        if fallback_tools:
            fallback_block = (
                "\n## Fallback toolbox (use ONLY when your primary tools cannot make progress)\n\n"
                "If you reach for a fallback tool, you MUST include a `tool_expansion_reason` "
                "field in your decision JSON explaining why your primary tools were insufficient. "
                "Repeated reaches into the fallback toolbox signal that your task was mis-scoped — "
                "consider emitting `action=complete` with current findings so the root planner can "
                "re-deploy with the right tools.\n\n"
            )
            fallback_block += build_compact_tool_list(fallback_tools)

        tool_list = primary_block + fallback_block
    else:
        # No declared tools: legacy unrestricted rendering (root-agent-equivalent).
        tool_list = get_phase_tools(
            phase,
            attack_path_type=state.get("attack_path_type", ""),
            execution_trace=state.get("execution_trace") or None,
        )

    # Structured per-tool argument schemas. Always render schemas for the FULL
    # phase-allowed set (not just primary) so that if the model legitimately
    # reaches into the fallback toolbox with a justification, it still has the
    # correct args shape and doesn't hallucinate kwargs.
    tool_args_section = build_tool_args_section(phase_allowed)

    # Engagement-state snapshot from the parent at deploy time. Rendered with
    # the same format_chain_context() the root agent uses in its own system
    # prompt — gives the member every finding (with source_agent attribution),
    # failed attempt, decision, and recent tool output the engagement already
    # produced. Replaces the old 200-char-per-step trace summary which omitted
    # captured artifacts (JWTs, credentials, cleared endpoints) and forced
    # members to re-discover them.
    parent_chain_context = format_chain_context(
        state.get("_parent_chain_findings") or [],
        state.get("_parent_chain_failures") or [],
        state.get("_parent_chain_decisions") or [],
        state.get("_parent_execution_trace") or [],
        recent_iterations=20,
    )

    # Member-local progress in this run, rendered in the same format. Findings
    # and failures the member has produced so far in its own iterations,
    # surfaced separately so the LLM can distinguish "what the engagement
    # already knew" from "what I have done in this turn".
    local_chain_context = format_chain_context(
        state.get("chain_findings_memory") or [],
        state.get("chain_failures_memory") or [],
        [],  # members cannot make phase decisions
        state.get("execution_trace") or [],
        recent_iterations=10,
    )

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

    # Sibling-scope block: lists what each peer member is covering in this wave
    # so the LLM doesn't pivot into their surface when its own runs dry. Placed
    # right after the mission so it weights heavily in instruction-following.
    # Empty string when this is a single-member wave or peer list is missing.
    peers = state.get("_peer_tasks") or []
    if peers:
        peer_lines = [
            "",
            "## Sibling members in this wave (OUT OF SCOPE for you)",
            "Each surface below is owned by another member. Do NOT probe these — their findings",
            "will reach you via the engagement state on later iterations. If your own surface is",
            "exhausted, emit `action=complete` with current findings. Do NOT pivot into a sibling's",
            "scope; the root planner will deploy a focused follow-up wave if more work is needed.",
            "",
        ]
        for p in peers:
            name = p.get("name") or "(unnamed)"
            summary = (p.get("task_summary") or "").strip()
            peer_lines.append(f"- **{name}**: {summary}")
        peer_block = "\n".join(peer_lines) + "\n"
    else:
        peer_block = ""

    pending_output_section = _build_pending_output_section(state)

    # Soft tool-expansion budget (Change C). Surfaces a graduated warning when
    # the member has reached into the fallback toolbox without producing new
    # findings, nudging the LLM toward `action=complete` so the root planner
    # can re-deploy with better-matched tools. Empty string until thresholds
    # cross — costs zero tokens for productive members.
    fallback_uses = int(state.get("fallback_uses_this_run", 0) or 0)
    stall = int(state.get("iterations_since_new_finding", 0) or 0)
    declared_for_warning = (
        sorted((set(declared_tools) - {"query_graph"})) if declared_tools else []
    )
    budget_prefix = ""
    if fallback_uses >= 4 and stall >= 2:
        budget_prefix = (
            "## Recommendation: complete\n\n"
            f"You have used {fallback_uses} fallback tools and produced no new findings "
            f"in your last {stall} iterations. Strongly recommend emitting `action=complete` "
            "with your current findings so the root planner can re-deploy with better-matched "
            "tools. Continuing to reach into the fallback toolbox is unlikely to yield new "
            "results.\n\n"
        )
    elif fallback_uses >= 2:
        budget_prefix = (
            "## Tool expansion budget\n\n"
            f"You have used {fallback_uses} fallback tool(s) so far. Each fallback use is a "
            f"signal that your declared primary tools ({declared_for_warning}) may not match "
            "the task. Two more fallback calls without a new `chain_findings` entry and the "
            "orchestrator will recommend you complete and let the root re-deploy.\n\n"
        )

    rendered = _MEMBER_SYSTEM_PROMPT.format(
        task=state.get("task", "(no task specified)"),
        peer_block=peer_block,
        phase=phase,
        max_iterations=state.get("max_iterations", 15),
        target_info=target_str,
        parent_chain_context=parent_chain_context,
        local_chain_context=local_chain_context,
        tool_list=tool_list,
        tool_args_section=tool_args_section,
        pending_output_section=pending_output_section,
    )
    # Prepend the budget prefix (if any). Sits ABOVE the mission header so the
    # LLM reads it before anything else.
    return budget_prefix + rendered


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
    # Tracks WHICH kind of error fired in the previous attempt so the retry
    # prep can pick the right correction wrapper: "json" (JSON/Pydantic shape
    # error from try_parse_llm_decision) or "semantic" (skill-expansion gate
    # rejected an otherwise-valid decision). Without this, semantic errors
    # would be wrapped as "Your previous JSON failed validation" — confusing
    # the model into rewriting tool_name instead of adding tool_expansion_reason.
    last_error_kind: Optional[str] = None
    raw_content = ""
    input_tokens_this_turn = 0
    output_tokens_this_turn = 0
    declared_tools_set = set(state.get("tools") or [])

    for attempt in range(max_retries):
        if attempt > 0:
            logger.info(
                "[%s] member %s parse attempt %d/%d after %s error: %s",
                session_id, member_id, attempt + 1, max_retries,
                last_error_kind or "unknown", parse_error,
            )
            llm_messages.append(AIMessage(content=raw_content))
            if last_error_kind == "semantic":
                # Embedded message already explains the contract; do NOT wrap
                # in "JSON failed validation" — that would mislead the model
                # into rewriting tool_name or restructuring the JSON instead
                # of adding the missing tool_expansion_reason field.
                llm_messages.append(HumanMessage(content=parse_error))
            else:
                llm_messages.append(HumanMessage(
                    content=(
                        f"Your previous JSON failed validation:\n{parse_error}\n\n"
                        "Fix the error and emit ONE valid LLMDecision JSON. "
                        "Remember: top-level `thought`, `reasoning`, `action` are REQUIRED. "
                        "`tool_args` must be a JSON object, NEVER a CLI string."
                    )
                ))

        try:
            response = await retry_llm_call(
                llm, llm_messages, label=f"{session_id} member {member_id}",
            )
        except Exception as exc:
            logger.error(
                "[%s] member %s LLM call failed: %s", session_id, member_id, exc,
            )
            return {
                "task_complete": True,
                "completion_reason": f"llm_error: {exc}",
            }

        raw_content = normalize_content(response.content if hasattr(response, "content") else response)

        _usage = getattr(response, "usage_metadata", None) or {}
        input_tokens_this_turn += int(_usage.get("input_tokens", 0) or 0)
        output_tokens_this_turn += int(_usage.get("output_tokens", 0) or 0)

        decision, parse_error = try_parse_llm_decision(raw_content)
        if decision is None:
            # JSON / Pydantic shape error: loop and retry.
            last_error_kind = "json"
            continue

        # Semantic gate: reaching for a fallback tool requires a
        # `tool_expansion_reason` field. We give the LLM ONE retry to fix it;
        # after that we accept the decision (the friction is real even when
        # the field is missing — the request to add it has already cost a
        # round-trip). Only fires when the member has declared tools.
        sem_err = _validate_tool_expansion(decision, declared_tools_set)
        if sem_err and attempt < max_retries - 1:
            logger.info(
                "[%s] member %s tool-expansion gate triggered on attempt %d/%d",
                session_id, member_id, attempt + 1, max_retries,
            )
            parse_error = sem_err
            last_error_kind = "semantic"
            decision = None
            continue
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

    # ---- Soft tool-allowlist counters (Change C) ----
    # Count how many fallback tools this decision references. Increment the
    # per-run counter so the next iteration's prompt sees an accurate budget
    # number. Counts tools, not iterations: a 4-step plan with 2 fallback
    # tools adds 2.
    if declared_tools_set:
        called = _collect_called_tools(decision)
        primary_for_counter = declared_tools_set | {"query_graph"}
        expanded_now = [t for t in called if t and t not in primary_for_counter]
        if expanded_now:
            prev_fallback = int(state.get("fallback_uses_this_run", 0) or 0)
            update["fallback_uses_this_run"] = prev_fallback + len(expanded_now)
            logger.info(
                "[%s] member %s fallback expansion: tools=%s reason=%r total=%d",
                session_id, member_id, expanded_now,
                (decision.tool_expansion_reason or "")[:120],
                update["fallback_uses_this_run"],
            )

    # Stall detection: compare the engagement-visible findings count NOW vs the
    # snapshot from end-of-previous iteration. No new findings -> bump
    # iterations_since_new_finding; new findings -> reset to 0. Used by the
    # prompt's `budget_prefix` to escalate the "Recommendation: complete"
    # nudge once the member is burning fallback calls without yield.
    #
    # SKIP the stall update on the first think call: at that point no tool
    # has executed yet (execution_trace is empty and no step is pending), so
    # "no new findings this iteration" is a vacuous truth — counting it as a
    # stall would falsely push the budget warning ahead by one iteration.
    has_done_work = bool(
        state.get("execution_trace")
        or state.get("_completed_step")
        or state.get("_current_step")
        or state.get("_current_plan")
    )
    if has_done_work:
        current_findings = len(state.get("chain_findings_memory") or [])
        last_findings = int(state.get("last_findings_count", 0) or 0)
        if current_findings > last_findings:
            update["iterations_since_new_finding"] = 0
        else:
            prev_stall = int(state.get("iterations_since_new_finding", 0) or 0)
            update["iterations_since_new_finding"] = prev_stall + 1
        update["last_findings_count"] = current_findings

    # Merge chain-step update from PREVIOUS tool (so follow-on steps link correctly).
    update.update(step_chain_update)

    # Resolve the previous-step analysis object early — it's read by the
    # is_dangerous escalation branch below (for _completed_step emission) AND
    # by the downstream single-tool / plan-wave analysis branches. Without
    # defining it here, the is_dangerous branch crashed with NameError.
    analysis = decision.output_analysis

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
                        evidence=details.get("evidence", "")[:10000],
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
                        evidence=details.get("evidence", "")[:10000],
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

    # Dangerous-tool escalation runs AFTER analysis-write so the prior wave's
    # chain_findings, target_info merge, and Neo4j writes commit before we
    # pause for operator approval. `_pending_confirmation` is the router's
    # signal to fireteam_await_confirmation — its placement in this function
    # does not affect routing, only whether analysis-write fires first.
    if is_dangerous:
        pending = _build_pending_confirmation(decision, state)
        update["_pending_confirmation"] = pending
        # Populate _current_plan / _current_step so they survive the await
        # round-trip. Without this, the await node returns to the router
        # with these fields unset and the router falls back to fireteam_think
        # -> infinite plan/approve loop, no tool execution.
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

    return update

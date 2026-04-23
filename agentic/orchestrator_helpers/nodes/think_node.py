"""Think node — core ReAct reasoning with LLM decision, output analysis, and chain memory."""

import asyncio
import logging
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from state import (
    AgentState,
    DeepThinkResult,
    ExecutionStep,
    LLMDecision,
    PhaseHistoryEntry,
    PhaseTransitionRequest,
    TargetInfo,
    ToolConfirmationRequest,
    UserQuestionRequest,
    format_chain_context,
    format_todo_list,
    format_qa_history,
    format_objective_history,
    utc_now,
)
import orchestrator_helpers.chain_graph_writer as chain_graph
from orchestrator_helpers.agent_context import get_agent_context
from orchestrator_helpers.json_utils import json_dumps_safe, normalize_content
from orchestrator_helpers.parsing import try_parse_llm_decision
from orchestrator_helpers.config import get_identifiers, is_session_config_complete
from project_settings import get_setting, get_allowed_tools_for_phase, DANGEROUS_TOOLS

from prompts import (
    REACT_SYSTEM_PROMPT,
    PENDING_OUTPUT_ANALYSIS_SECTION,
    PENDING_PLAN_OUTPUTS_SECTION,
    DEEP_THINK_PROMPT,
    DEEP_THINK_SECTION,
    DEEP_THINK_SELF_REQUEST_INSTRUCTION,
    get_phase_tools,
    build_phase_definitions,
    build_informational_guidance,
    build_attack_path_behavior,
    build_tool_name_enum,
    build_tool_args_section,
)
from prompts.base import build_fireteam_prompt_fragments
from utils import get_session_config_prompt
from tools import set_tenant_context, set_phase_context, set_graph_view_context

logger = logging.getLogger(__name__)


async def think_node(state: AgentState, config, *, llm, guidance_queues, neo4j_creds, streaming_callbacks=None, graph_view_cyphers=None) -> dict:
    """
    Core ReAct reasoning node.

    Analyzes previous steps, updates todo list, and decides next action.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        llm: The LLM instance for reasoning.
        guidance_queues: Dict of session_id -> asyncio.Queue for user guidance messages.
        neo4j_creds: Tuple of (neo4j_uri, neo4j_user, neo4j_password).
    """
    user_id, project_id, session_id = get_identifiers(state, config)
    neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

    iteration = state.get("current_iteration", 0) + 1
    phase = state.get("current_phase", "informational")

    # Check if we just transitioned - log and clear the marker
    just_transitioned = state.get("_just_transitioned_to")
    if just_transitioned:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Just transitioned to {just_transitioned}, now in phase: {phase}")

    logger.info(f"[{user_id}/{project_id}/{session_id}] Think node - iteration {iteration}, phase: {phase}")

    # Set context for tools
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # Get current objective from conversation objectives
    objectives = state.get("conversation_objectives", [])
    current_idx = state.get("current_objective_index", 0)

    if current_idx < len(objectives):
        current_objective = objectives[current_idx].get("content", "No objective specified")
    else:
        # Fallback to original_objective for backward compatibility
        current_objective = state.get("original_objective", "No objective specified")

    # Build the prompt with current state
    chain_context_formatted = format_chain_context(
        chain_findings=state.get("chain_findings_memory", []),
        chain_failures=state.get("chain_failures_memory", []),
        chain_decisions=state.get("chain_decisions_memory", []),
        execution_trace=state.get("execution_trace", []),
    )
    todo_list_formatted = format_todo_list(state.get("todo_list", []))
    target_info_formatted = json_dumps_safe(state.get("target_info", {}), indent=2)
    qa_history_formatted = format_qa_history(state.get("qa_history", []))
    objective_history_formatted = format_objective_history(state.get("objective_history", []))

    # ─── Deep Think pre-step (conditional) ────────────────────────────────
    deep_think_result = state.get("deep_think_result")  # existing from prior iterations
    deep_think_triggered = False
    # Deep-think token deltas — initialized unconditionally so the main
    # think-loop can seed its tally from them whether deep-think ran or not.
    _dt_in = 0
    _dt_out = 0

    if get_setting('DEEP_THINK_ENABLED', False):
        trigger_reason = None

        # Condition 1: first iteration of session
        if iteration == 1:
            trigger_reason = "First iteration — establishing initial strategy"

        # Condition 2: phase transition just happened
        elif just_transitioned:
            trigger_reason = f"Phase transition to {just_transitioned} — re-evaluating strategy"

        # Condition 3: failure loop (3+ consecutive failures)
        _exec_trace = state.get("execution_trace", [])
        if not trigger_reason and len(_exec_trace) >= 3:
            _consecutive = 0
            for _step in reversed(_exec_trace[-6:]):
                _out = ((_step.get("tool_output") or "")[:500]).lower()
                _is_fail = (
                    not _step.get("success", True)
                    or "failed" in _out
                    or "error" in _out
                    or "exploit completed, but no session" in _out
                )
                if _is_fail:
                    _consecutive += 1
                else:
                    break
            if _consecutive >= 3:
                trigger_reason = f"Failure loop detected ({_consecutive} consecutive failures) — pivoting strategy"

        # Condition 4: LLM self-requested deep think on previous iteration
        if not trigger_reason and state.get("_need_deep_think", False):
            trigger_reason = "Agent self-assessed stagnation — strategic re-evaluation requested"

        if trigger_reason:
            try:
                # Build session config (tunnel/LHOST/LPORT) for deep think context
                _attack_path = state.get("attack_path_type", "")
                _is_statefull = get_setting('POST_EXPL_PHASE_TYPE', 'statefull') == 'statefull'
                _needs_session = (
                    (phase == "exploitation" and _is_statefull)
                    or _attack_path == "phishing_social_engineering"
                )
                _session_config = ""
                if _needs_session:
                    _sc = get_session_config_prompt()
                    if _sc:
                        _session_config = f"\n{_sc}\n"

                # Build RoE section if enabled
                _roe_section = ""
                if get_setting('ROE_ENABLED', False):
                    from prompts.base import build_roe_prompt_section
                    _roe = build_roe_prompt_section()
                    if _roe:
                        _roe_section = f"\n{_roe}\n"

                deep_think_prompt = DEEP_THINK_PROMPT.format(
                    current_phase=phase,
                    objective=current_objective,
                    attack_path_type=_attack_path,
                    attack_path_behavior=build_attack_path_behavior(_attack_path),
                    phase_definitions=build_phase_definitions(),
                    iteration=iteration,
                    max_iterations=state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
                    target_info=target_info_formatted,
                    chain_context=chain_context_formatted,
                    trigger_reason=trigger_reason,
                    todo_list=todo_list_formatted,
                    objective_history=objective_history_formatted,
                    session_config=_session_config,
                    roe_section=_roe_section,
                )

                dt_response = await llm.ainvoke([
                    SystemMessage(content=deep_think_prompt),
                    HumanMessage(content="Produce the deep think analysis JSON now."),
                ])
                dt_raw = normalize_content(dt_response.content).strip()
                _dt_usage = getattr(dt_response, "usage_metadata", None) or {}
                _dt_in += int(_dt_usage.get("input_tokens", 0) or 0)
                _dt_out += int(_dt_usage.get("output_tokens", 0) or 0)
                # Strip markdown code fences if present (LLMs often wrap JSON in ```json ... ```)
                if dt_raw.startswith("```"):
                    dt_raw = dt_raw.split("\n", 1)[1] if "\n" in dt_raw else dt_raw[3:]
                    if dt_raw.endswith("```"):
                        dt_raw = dt_raw[:-3].strip()
                dt_parsed = DeepThinkResult.model_validate_json(dt_raw)

                deep_think_result = (
                    f"**Situation:** {dt_parsed.situation_assessment}\n\n"
                    f"**Attack Vectors:** {', '.join(dt_parsed.attack_vectors_identified)}\n\n"
                    f"**Approach:** {dt_parsed.recommended_approach}\n\n"
                    f"**Priority:** {' → '.join(dt_parsed.priority_order)}\n\n"
                    f"**Risks:** {dt_parsed.risks_and_mitigations}"
                )
                deep_think_triggered = True
                logger.info(f"[{user_id}/{project_id}/{session_id}] Deep Think triggered: {trigger_reason}")

                # Stream to frontend
                if streaming_callbacks:
                    streaming_cb = streaming_callbacks.get(session_id)
                    if streaming_cb:
                        await streaming_cb.on_deep_think(
                            trigger_reason=trigger_reason,
                            analysis=deep_think_result,
                            iteration=iteration,
                            phase=phase,
                        )
            except Exception as e:
                logger.warning(f"[{user_id}/{project_id}/{session_id}] Deep Think failed (non-blocking): {e}")
    # ─── End Deep Think ──────────────────────────────────────────────────

    # Get phase tools with attack path type for dynamic routing
    attack_path_type = state.get("attack_path_type", "")
    available_tools = get_phase_tools(
        phase,
        get_setting('ACTIVATE_POST_EXPL_PHASE', True),
        get_setting('POST_EXPL_PHASE_TYPE', 'statefull'),
        attack_path_type,
        execution_trace=state.get("execution_trace", []),
    )

    allowed_tools = get_allowed_tools_for_phase(phase)

    # Conditionally render the deploy_fireteam action based on project gates.
    # When FIRETEAM_ENABLED=false OR current phase not in allowed phases, the
    # three fragments are empty strings so the LLM never sees the action —
    # saves ~500 tokens per call and avoids the LLM emitting a gated action.
    ft_action_enum, ft_plan_field, ft_example = build_fireteam_prompt_fragments(
        enabled=get_setting("FIRETEAM_ENABLED", False)
                and get_setting("PERSISTENT_CHECKPOINTER", False),
        phase=phase,
        allowed_phases=get_setting("FIRETEAM_ALLOWED_PHASES", ["informational"]),
        max_members=int(get_setting("FIRETEAM_MAX_MEMBERS", 5)),
        propensity=int(get_setting("FIRETEAM_PROPENSITY", 3)),
    )

    system_prompt = REACT_SYSTEM_PROMPT.format(
        current_phase=phase,
        phase_definitions=build_phase_definitions(),
        informational_guidance=build_informational_guidance(phase),
        attack_path_type=attack_path_type,
        attack_path_behavior=build_attack_path_behavior(attack_path_type),
        available_tools=available_tools,
        tool_name_enum=build_tool_name_enum(allowed_tools),
        tool_args_section=build_tool_args_section(allowed_tools),
        iteration=iteration,
        max_iterations=state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
        objective=current_objective,
        objective_history_summary=objective_history_formatted,
        prior_chain_history=state.get("_prior_chain_context") or "No prior sessions.",
        chain_context=chain_context_formatted,
        todo_list=todo_list_formatted,
        target_info=target_info_formatted,
        qa_history=qa_history_formatted,
        fireteam_action_enum=ft_action_enum,
        fireteam_plan_field=ft_plan_field,
        fireteam_example_section=ft_example,
    )

    # Inject Deep Think section if available (from state or just computed)
    if deep_think_result:
        system_prompt += DEEP_THINK_SECTION.format(deep_think_result=deep_think_result)

    # Inject Deep Think self-request instruction (only when enabled)
    if get_setting('DEEP_THINK_ENABLED', False):
        system_prompt += DEEP_THINK_SELF_REQUEST_INSTRUCTION

    # Inject stealth mode rules if enabled (prepended for maximum priority)
    if get_setting('STEALTH_MODE', False):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        system_prompt = STEALTH_MODE_RULES + "\n\n" + system_prompt
        logger.info(f"[{user_id}/{project_id}/{session_id}] STEALTH MODE active — injected stealth rules into prompt")

    # Scope guardrail: remind agent to stay within authorized targets
    # Always inject for hard-blocked domains (government/public); also inject when soft guardrail is enabled
    _inject_scope_guardrail = get_setting('AGENT_GUARDRAIL_ENABLED', True)
    if not _inject_scope_guardrail:
        from hard_guardrail import is_hard_blocked
        _target_domain = get_setting('TARGET_DOMAIN', '')
        _ip_mode = get_setting('IP_MODE', False)
        if not _ip_mode and _target_domain:
            _inject_scope_guardrail, _ = is_hard_blocked(_target_domain)

    if _inject_scope_guardrail:
        system_prompt += (
            "\n\n## SCOPE GUARDRAIL\n\n"
            "You must ONLY operate against the project's configured target domain/IPs. "
            "Never scan, exploit, probe, or interact with domains or IPs outside the authorized scope. "
            "If the user asks you to target something outside the project scope, refuse and explain why."
        )

    # Rules of Engagement injection
    if get_setting('ROE_ENABLED', False):
        from prompts.base import build_roe_prompt_section
        roe_section = build_roe_prompt_section()
        if roe_section:
            system_prompt += "\n\n" + roe_section
            logger.info(f"[{user_id}/{project_id}/{session_id}] RoE rules injected into prompt")

        # Inject engagement date/time warnings from initialize_node
        roe_warnings = state.get("_roe_warnings", [])
        if roe_warnings:
            warning_block = "\n".join(f"- WARNING: {w}" for w in roe_warnings)
            system_prompt += (
                "\n\n## RoE TIMING WARNINGS\n"
                f"{warning_block}\n"
                "IMPORTANT: Inform the user about these warnings before proceeding. "
                "If the engagement has ended, do NOT perform any active testing."
            )

    # Failure loop detection: if 3+ consecutive similar failures, inject warning
    exec_trace = state.get("execution_trace", [])
    if len(exec_trace) >= 3:
        consecutive_failures = 0
        last_pattern = None
        for step in reversed(exec_trace[-6:]):
            output_lower = ((step.get("tool_output") or "")[:500]).lower()
            is_failure = (
                not step.get("success", True)
                or "failed" in output_lower
                or "error" in output_lower
                or "exploit completed, but no session" in output_lower
            )
            if is_failure:
                pattern = f"{step.get('tool_name')}:{str(step.get('tool_args', {}))[:80]}"
                if last_pattern is None or pattern == last_pattern:
                    consecutive_failures += 1
                    last_pattern = pattern
                else:
                    break
            else:
                break

        if consecutive_failures >= 3:
            system_prompt += (
                "\n\n## FAILURE LOOP DETECTED\n\n"
                "You have failed 3+ times with a similar approach. You MUST try a completely "
                "different strategy: use `web_search` for alternative techniques, try a different "
                "tool or payload, or use action='ask_user' for guidance. Do NOT retry the same approach.\n"
            )

    # CHECK: Is there a pending tool output to analyze?
    pending_step = state.get("_current_step")
    has_pending_output = (
        pending_step and
        pending_step.get("tool_output") is not None and
        not pending_step.get("output_analysis")
    )

    if has_pending_output:
        tool_output_raw = pending_step.get("tool_output") or pending_step.get("error_message") or "No output"
        output_section = PENDING_OUTPUT_ANALYSIS_SECTION.format(
            tool_name=pending_step.get("tool_name", "unknown"),
            tool_args=json_dumps_safe(pending_step.get("tool_args") or {}),
            success=pending_step.get("success", False),
            tool_output=tool_output_raw[:get_setting('TOOL_OUTPUT_MAX_CHARS', 20000)],
        )
        system_prompt = system_prompt + "\n" + output_section
        logger.info(f"[{user_id}/{project_id}/{session_id}] Injected output analysis section for tool: {pending_step.get('tool_name')}")

    # CHECK: Is there a pending plan wave to analyze?
    pending_plan = state.get("_current_plan")
    has_pending_plan_outputs = (
        pending_plan
        and pending_plan.get("steps")
        and any(s.get("tool_output") is not None for s in pending_plan.get("steps", []))
        and not pending_plan.get("_analyzed")
    )

    if has_pending_plan_outputs:
        plan_steps = pending_plan.get("steps", [])
        max_chars = get_setting('TOOL_OUTPUT_MAX_CHARS', 20000)
        chars_per_tool = max(2000, max_chars // len(plan_steps))

        # Build per-tool output sections
        tool_outputs_parts = []
        for i, s in enumerate(plan_steps):
            output = (s.get("tool_output") or s.get("error_message") or "No output")[:chars_per_tool]
            status = "OK" if s.get("success") else "FAILED"
            tool_outputs_parts.append(
                f"### Tool {i+1}: {s.get('tool_name', 'unknown')} ({status})\n"
                f"Args: {json_dumps_safe(s.get('tool_args', {}))}\n"
                f"Output:\n```\n{output}\n```"
            )

        plan_section = PENDING_PLAN_OUTPUTS_SECTION.format(
            n_tools=len(plan_steps),
            tool_outputs_section="\n\n".join(tool_outputs_parts),
        )
        system_prompt = system_prompt + "\n" + plan_section
        logger.info(f"[{user_id}/{project_id}/{session_id}] Injected plan output analysis section for {len(plan_steps)} tools")

    # Drain pending guidance messages from user (per-session queue)
    guidance_messages = []
    guidance_queue = guidance_queues.get(session_id)
    if guidance_queue:
        while not guidance_queue.empty():
            try:
                guidance_messages.append(guidance_queue.get_nowait())
            except asyncio.QueueEmpty:
                break

    if guidance_messages:
        guidance_section = (
            "\n\n## USER GUIDANCE (IMPORTANT)\n\n"
            "The user sent these guidance messages while you were working. "
            "They refine your CURRENT objective — do NOT treat them as new tasks. "
            "Adjust your plan and next action accordingly:\n\n"
        )
        for i, msg in enumerate(guidance_messages, 1):
            guidance_section += f"{i}. {msg}\n"
        guidance_section += "\nAcknowledge this guidance in your thought.\n"
        system_prompt += guidance_section
        logger.info(f"[{user_id}/{project_id}/{session_id}] Injected {len(guidance_messages)} guidance messages into prompt")

    # Log the full prompt for debugging
    logger.info(f"\n{'#'*80}")
    logger.info(f"# THINK NODE PROMPT - Iteration {iteration} - Phase: {phase}")
    logger.info(f"{'#'*80}")
    logger.info(f"\n--- CHAIN CONTEXT ---\n{chain_context_formatted}")
    logger.info(f"\n--- TODO LIST ---\n{todo_list_formatted}")
    logger.info(f"\n--- TARGET INFO ---\n{target_info_formatted}")
    logger.info(f"\n--- Q&A HISTORY ---\n{qa_history_formatted}")
    logger.info(f"\n--- FULL SYSTEM PROMPT ({len(system_prompt)} chars) ---")
    chunk_size = 4000
    for i in range(0, len(system_prompt), chunk_size):
        chunk = system_prompt[i:i+chunk_size]
        logger.info(f"PROMPT[{i}:{i+len(chunk)}]:\n{chunk}")
    logger.info(f"{'#'*80}\n")

    # Get LLM decision with retry on parse failures
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content="Based on the current state, what is your next action? Output EXACTLY ONE valid JSON object and nothing else. Do NOT simulate tool execution - you will receive actual tool output after submitting your decision. Do NOT output multiple JSON objects or continue the conversation - just ONE decision JSON.")
    ]

    max_retries = get_setting('LLM_PARSE_MAX_RETRIES', 3)
    decision = None
    last_error = None
    response_text = ""
    input_tokens_this_turn = _dt_in
    output_tokens_this_turn = _dt_out

    for attempt in range(max_retries):
        if attempt > 0:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Parse attempt {attempt}/{max_retries} failed: {last_error}")
            messages.append(AIMessage(content=response_text))
            messages.append(HumanMessage(
                content=f"Your previous JSON response failed validation:\n{last_error}\n\n"
                        f"Fix the error and output EXACTLY ONE valid JSON object. No extra text."
            ))

        response = await llm.ainvoke(messages)
        response_text = normalize_content(response.content).strip()

        usage = getattr(response, "usage_metadata", None) or {}
        input_tokens_this_turn += int(usage.get("input_tokens", 0) or 0)
        output_tokens_this_turn += int(usage.get("output_tokens", 0) or 0)

        logger.info(f"\n{'='*60}")
        logger.info(f"LLM RAW RESPONSE - Iteration {iteration} (attempt {attempt+1}/{max_retries})")
        logger.info(f"{'='*60}")
        logger.info(f"{response_text}")
        logger.info(f"{'='*60}\n")

        decision, last_error = try_parse_llm_decision(response_text)
        if decision:
            break

    # If all retries failed, use the fallback
    if not decision:
        logger.error(f"[{user_id}/{project_id}/{session_id}] All {max_retries} parse attempts failed: {last_error}")
        decision = LLMDecision(
            thought=response_text,
            reasoning="Failed to parse structured response after retries",
            action="complete",
            completion_reason=f"Unable to continue: JSON parsing failed after {max_retries} attempts",
            updated_todo_list=[],
        )

    logger.info(f"[{user_id}/{project_id}/{session_id}] Decision: action={decision.action}, tool={decision.tool_name}")

    # Detailed logging for debugging
    logger.info(f"\n{'='*60}")
    logger.info(f"THINK NODE - Iteration {iteration} - Phase: {phase}")
    logger.info(f"{'='*60}")
    logger.info(f"THOUGHT: {decision.thought}")
    logger.info(f"REASONING: {decision.reasoning}")
    logger.info(f"ACTION: {decision.action}")
    if decision.tool_name:
        logger.info(f"TOOL: {decision.tool_name}")
        logger.info(f"TOOL_ARGS: {json_dumps_safe(decision.tool_args, indent=2) if decision.tool_args else 'None'}")
    if decision.phase_transition:
        logger.info(f"PHASE_TRANSITION: {decision.phase_transition.to_phase}")

    # Log todo list updates
    if decision.updated_todo_list:
        logger.info(f"TODO LIST ({len(decision.updated_todo_list)} items):")
        for todo in decision.updated_todo_list:
            status_icon = {
                "pending": "[ ]",
                "in_progress": "[~]",
                "completed": "[x]",
                "blocked": "[!]"
            }.get(todo.status, "[ ]")
            priority_marker = {"high": "!!!", "medium": "!!", "low": "!"}.get(todo.priority, "!!")
            logger.info(f"  {status_icon} {priority_marker} {todo.description}")
    else:
        logger.info(f"TODO LIST: (no updates)")

    # Log Q&A history if present
    qa_history = state.get("qa_history", [])
    if qa_history:
        logger.info(f"Q&A HISTORY ({len(qa_history)} entries):")
        for i, entry in enumerate(qa_history, 1):
            q = entry.get("question", {})
            a = entry.get("answer", {})
            logger.info(f"  Q{i}: {q.get('question', 'N/A')[:10000]}")
            logger.info(f"      Answer: {a.get('answer', 'N/A')[:10000] if a else '(unanswered)'}")
    else:
        logger.info(f"Q&A HISTORY: (none)")

    # Fireteam gate: enforce feature-flag + persistent-checkpointer + allowed-phases.
    # If the LLM emitted deploy_fireteam but any gate fails, rewrite the action
    # to use_tool without a tool (so _route_after_think routes safely). The
    # system note is injected after `updates` is constructed below.
    _fireteam_gate_note: str | None = None
    if decision.action == "deploy_fireteam":
        ft_enabled = get_setting("FIRETEAM_ENABLED", False)
        persistent = get_setting("PERSISTENT_CHECKPOINTER", False)
        allowed_phases = get_setting("FIRETEAM_ALLOWED_PHASES", ["informational"])
        if not ft_enabled:
            _fireteam_gate_note = "fireteam feature disabled for this project"
        elif not persistent:
            _fireteam_gate_note = "persistent checkpointer required (PERSISTENT_CHECKPOINTER=false); fireteam cannot run safely without it"
        elif phase not in allowed_phases:
            _fireteam_gate_note = f"phase '{phase}' not in allowed phases {allowed_phases}"
        if _fireteam_gate_note:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] deploy_fireteam rejected: {_fireteam_gate_note}")
            decision = decision.model_copy(update={
                "action": "use_tool",
                "tool_name": None,
                "tool_args": None,
                "fireteam_plan": None,
            })

    # Log user_question if action is ask_user
    if decision.action == "ask_user" and decision.user_question:
        logger.info(f"USER_QUESTION:")
        logger.info(f"  Question: {decision.user_question.question}")
        logger.info(f"  Context: {decision.user_question.context}")
        logger.info(f"  Format: {decision.user_question.format}")
        if decision.user_question.options:
            logger.info(f"  Options: {decision.user_question.options}")

    logger.info(f"{'='*60}\n")

    # Create execution step
    step = ExecutionStep(
        iteration=iteration,
        phase=phase,
        thought=decision.thought,
        reasoning=decision.reasoning,
        tool_name=decision.tool_name if decision.action == "use_tool" else None,
        tool_args=decision.tool_args if decision.action == "use_tool" else None,
    )

    # Convert todo list updates to dicts for state storage
    todo_list = [item.model_dump() for item in decision.updated_todo_list] if decision.updated_todo_list else state.get("todo_list", [])

    # Build state updates
    _prev_input_tokens = int(state.get("input_tokens_used", 0) or 0)
    _prev_output_tokens = int(state.get("output_tokens_used", 0) or 0)
    _new_input_tokens = _prev_input_tokens + input_tokens_this_turn
    _new_output_tokens = _prev_output_tokens + output_tokens_this_turn

    updates = {
        "current_iteration": iteration,
        "todo_list": todo_list,
        "_decision": decision.model_dump(),
        "_just_transitioned_to": None,  # Clear the marker
        "_reject_tool": False,  # Clear tool rejection marker from previous iteration
        "_tool_confirmation_mode": None,  # Clear mode from previous confirmation
        "_completed_step": None,  # Will be set if we process pending output
        "input_tokens_used": _new_input_tokens,
        "output_tokens_used": _new_output_tokens,
        "tokens_used": _new_input_tokens + _new_output_tokens,
        "_input_tokens_this_turn": input_tokens_this_turn,
        "_output_tokens_this_turn": output_tokens_this_turn,
    }

    logger.info(
        f"[{user_id}/{project_id}/{session_id}] Tokens this turn: "
        f"in={input_tokens_this_turn} out={output_tokens_this_turn} "
        f"(cumulative in={_new_input_tokens} out={_new_output_tokens})"
    )

    # Inject fireteam-gate rejection note so the LLM doesn't just re-emit
    # deploy_fireteam on the next iteration. Use HumanMessage to represent
    # operator/system feedback mid-conversation (AIMessage would model the
    # LLM's own past output, which is semantically wrong).
    if _fireteam_gate_note:
        updates["messages"] = [HumanMessage(
            content=f"[system] deploy_fireteam rejected: {_fireteam_gate_note}. Choose use_tool, plan_tools, transition_phase, or complete instead."
        )]

    # Persist deep think result in state (only when newly triggered)
    if deep_think_triggered:
        updates["deep_think_result"] = deep_think_result

    # Persist LLM self-request for deep think (triggers on next iteration)
    updates["_need_deep_think"] = decision.need_deep_think if get_setting('DEEP_THINK_ENABLED', False) else False

    # When action is plan_tools, set _current_plan instead of _current_step.
    # When action is deploy_fireteam, set _current_fireteam_plan.
    if decision.action == "plan_tools" and decision.tool_plan:
        updates["_current_step"] = None  # No single step — plan node handles streaming
        updates["_current_plan"] = decision.tool_plan.model_dump()
        updates["_current_fireteam_plan"] = None
    elif decision.action == "deploy_fireteam" and decision.fireteam_plan:
        updates["_current_step"] = None
        updates["_current_plan"] = None
        updates["_current_fireteam_plan"] = decision.fireteam_plan.model_dump()
    else:
        updates["_current_step"] = step.model_dump()
        updates["_current_plan"] = None  # Clear any stale plan
        updates["_current_fireteam_plan"] = None

    # Process output analysis if we had pending tool output
    if has_pending_output:
        step_iteration = pending_step.get("iteration", iteration)

        if decision.output_analysis:
            analysis = decision.output_analysis

            # Update step with analysis data
            pending_step["output_analysis"] = analysis.interpretation
            pending_step["actionable_findings"] = analysis.actionable_findings or []
            pending_step["recommended_next_steps"] = analysis.recommended_next_steps or []

            # Log analysis results
            logger.info(f"\n{'='*60}")
            logger.info(f"OUTPUT ANALYSIS (inline) - Iteration {iteration} - Phase: {phase}")
            logger.info(f"{'='*60}")
            logger.info(f"TOOL: {pending_step.get('tool_name')}")
            logger.info(f"INTERPRETATION: {analysis.interpretation[:2000]}")
            if analysis.actionable_findings:
                logger.info(f"ACTIONABLE FINDINGS: {analysis.actionable_findings}")
            if analysis.recommended_next_steps:
                logger.info(f"RECOMMENDED NEXT STEPS: {analysis.recommended_next_steps}")
            if analysis.exploit_succeeded:
                logger.info(f"EXPLOIT SUCCEEDED: {analysis.exploit_details}")
            logger.info(f"{'='*60}\n")

            # Merge target info
            current_target = TargetInfo(**state.get("target_info", {}))
            extracted = analysis.extracted_info
            new_target = TargetInfo(
                primary_target=extracted.primary_target,
                ports=extracted.ports,
                services=extracted.services,
                technologies=extracted.technologies,
                vulnerabilities=extracted.vulnerabilities,
                credentials=extracted.credentials,
                sessions=extracted.sessions,
            )
            merged_target = current_target.merge_from(new_target)

            # --- Chain Memory Population ---
            step_id = pending_step.get("step_id")

            # 1. Populate chain_findings_memory
            chain_findings_mem = list(state.get("chain_findings_memory", []))
            if analysis.chain_findings:
                for cf in analysis.chain_findings:
                    finding_dict = cf.model_dump() if hasattr(cf, 'model_dump') else (cf if isinstance(cf, dict) else {})
                    finding_dict["step_iteration"] = step_iteration
                    chain_findings_mem.append(finding_dict)
            elif analysis.actionable_findings:
                for af_text in analysis.actionable_findings:
                    chain_findings_mem.append({
                        "finding_type": "custom",
                        "severity": "info",
                        "title": af_text[:200],
                        "evidence": "",
                        "step_iteration": step_iteration,
                        "confidence": 60,
                    })
            # Exploit success also goes into findings memory
            if analysis.exploit_succeeded and analysis.exploit_details:
                details = analysis.exploit_details
                chain_findings_mem.append({
                    "finding_type": "exploit_success",
                    "severity": "critical",
                    "title": f"Exploit success: {details.get('evidence', '')[:100]}",
                    "evidence": details.get("evidence", ""),
                    "step_iteration": step_iteration,
                    "confidence": 95,
                    "related_cves": details.get("cve_ids", []),
                    "related_ips": [details.get("target_ip", "")] if details.get("target_ip") else [],
                })
            updates["chain_findings_memory"] = chain_findings_mem

            # 2. Populate chain_failures_memory if step failed
            if not pending_step.get("success"):
                chain_failures_mem = list(state.get("chain_failures_memory", []))
                chain_failures_mem.append({
                    "step_iteration": step_iteration,
                    "failure_type": "tool_error",
                    "tool_name": pending_step.get("tool_name", ""),
                    "error_message": pending_step.get("error_message", ""),
                    "lesson_learned": analysis.interpretation[:300] if analysis else "",
                })
                updates["chain_failures_memory"] = chain_failures_mem

            # 3. Write ChainStep to Neo4j (via executor to avoid blocking the event loop)
            prev_step_id = state.get("_last_chain_step_id")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: chain_graph.sync_record_step(
                    neo4j_uri, neo4j_user, neo4j_password,
                    step_id=step_id,
                    chain_id=session_id,
                    prev_step_id=prev_step_id,
                    user_id=user_id, project_id=project_id,
                    iteration=step_iteration, phase=phase,
                    tool_name=pending_step.get("tool_name"),
                    tool_args_summary=str(pending_step.get("tool_args", {}))[:500],
                    thought=pending_step.get("thought", "")[:20000],
                    reasoning=pending_step.get("reasoning", "")[:20000],
                    output_summary=(pending_step.get("tool_output") or "")[:20000],
                    output_analysis=analysis.interpretation[:20000] if analysis else "",
                    success=pending_step.get("success", True),
                    error_message=pending_step.get("error_message"),
                    extracted_info=analysis.extracted_info.model_dump() if analysis and analysis.extracted_info else {},
                    **get_agent_context(state),
                ),
            )
            updates["_last_chain_step_id"] = step_id

            # 4. Fire-and-forget: write exploit success (AFTER step so PRODUCED link works)
            if analysis.exploit_succeeded and analysis.exploit_details and phase == "exploitation":
                details = analysis.exploit_details
                try:
                    chain_graph.fire_record_exploit_success(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=step_id,
                        user_id=user_id,
                        project_id=project_id,
                        attack_type=details.get("attack_type", state.get("attack_path_type", "cve_exploit")),
                        target_ip=details.get("target_ip", merged_target.primary_target),
                        target_port=details.get("target_port"),
                        cve_ids=details.get("cve_ids", merged_target.vulnerabilities),
                        session_id=details.get("session_id"),
                        username=details.get("username"),
                        password_found=details.get("password"),
                        evidence=details.get("evidence", ""),
                        execution_trace=state.get("execution_trace", []),
                        iteration=step_iteration,
                    )
                    logger.info(f"[{user_id}/{project_id}/{session_id}] Exploit success detected - ChainFinding created")
                except Exception as e:
                    logger.error(f"[{user_id}/{project_id}/{session_id}] Failed to record exploit success: {e}")

            # 5. Fire-and-forget: write other ChainFindings (skip exploit-related if already recorded)
            _EXPLOIT_OVERLAP_TYPES = {"exploit_success", "access_gained", "credential_found"}
            for cf in (analysis.chain_findings or []):
                if analysis.exploit_succeeded and cf.finding_type in _EXPLOIT_OVERLAP_TYPES:
                    continue
                _ctx = get_agent_context(state)
                chain_graph.fire_record_finding(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=step_id,
                    user_id=user_id, project_id=project_id,
                    finding_type=cf.finding_type, severity=cf.severity,
                    title=cf.title, evidence=cf.evidence,
                    confidence=cf.confidence, phase=phase,
                    iteration=step_iteration,
                    related_cves=cf.related_cves, related_ips=cf.related_ips,
                    agent_id=_ctx["agent_id"],
                    source_agent=_ctx["agent_name"],
                    fireteam_id=_ctx["fireteam_id"],
                )

            # 6. Fire-and-forget: write ChainFailure if failed
            if not pending_step.get("success"):
                chain_graph.fire_record_failure(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=step_id,
                    user_id=user_id, project_id=project_id,
                    failure_type="tool_error",
                    tool_name=pending_step.get("tool_name", ""),
                    error_message=pending_step.get("error_message", ""),
                    lesson_learned=analysis.interpretation[:20000] if analysis else "",
                    phase=phase,
                    iteration=step_iteration,
                )

            # Append completed step to execution trace
            execution_trace = state.get("execution_trace", []) + [pending_step]
            updates["execution_trace"] = execution_trace
            updates["target_info"] = merged_target.model_dump()
            updates["_completed_step"] = pending_step
            updates["messages"] = [AIMessage(content=f"**Step {step_iteration}** [{phase}]\n\n{analysis.interpretation}")]

        else:
            # LLM didn't return analysis — use raw output as fallback
            logger.warning(f"[{user_id}/{project_id}/{session_id}] No output_analysis in LLM response, using fallback")
            pending_step["output_analysis"] = (pending_step.get("tool_output") or "")[:20000]
            pending_step["actionable_findings"] = []
            pending_step["recommended_next_steps"] = []
            execution_trace = state.get("execution_trace", []) + [pending_step]
            updates["execution_trace"] = execution_trace
            updates["_completed_step"] = pending_step

    # Process plan wave outputs — uses same output_analysis as single-tool path
    if has_pending_plan_outputs:
        plan_steps = pending_plan.get("steps", [])
        analysis = decision.output_analysis  # Same field as single-tool
        plan_iteration = iteration - 1

        merged_target = TargetInfo(**state.get("target_info", {}))
        chain_findings_mem = list(state.get("chain_findings_memory", []))
        chain_failures_mem = list(state.get("chain_failures_memory", []))
        new_trace_entries = []

        if analysis:
            logger.info(f"\n{'='*60}")
            logger.info(f"PLAN OUTPUT ANALYSIS (combined) - {len(plan_steps)} tools")
            logger.info(f"{'='*60}")
            logger.info(f"  INTERPRETATION: {analysis.interpretation[:200]}")

            # Single target info merge from combined extracted_info
            extracted = analysis.extracted_info
            new_target = TargetInfo(
                primary_target=extracted.primary_target,
                ports=extracted.ports, services=extracted.services,
                technologies=extracted.technologies,
                vulnerabilities=extracted.vulnerabilities,
                credentials=extracted.credentials, sessions=extracted.sessions,
            )
            merged_target = merged_target.merge_from(new_target)

            # Chain findings (once, from combined analysis)
            if analysis.chain_findings:
                for cf in analysis.chain_findings:
                    finding_dict = cf.model_dump() if hasattr(cf, 'model_dump') else (cf if isinstance(cf, dict) else {})
                    finding_dict["step_iteration"] = plan_iteration
                    chain_findings_mem.append(finding_dict)
            elif analysis.actionable_findings:
                # Fallback: promote actionable_findings to chain_findings_memory
                for af_text in analysis.actionable_findings:
                    chain_findings_mem.append({
                        "finding_type": "custom",
                        "severity": "info",
                        "title": af_text[:200],
                        "evidence": "",
                        "step_iteration": plan_iteration,
                        "confidence": 60,
                    })

            # Exploit success
            if analysis.exploit_succeeded and analysis.exploit_details:
                details = analysis.exploit_details
                chain_findings_mem.append({
                    "finding_type": "exploit_success", "severity": "critical",
                    "title": f"Exploit success: {details.get('evidence', '')[:100]}",
                    "evidence": details.get("evidence", ""),
                    "step_iteration": plan_iteration, "confidence": 95,
                    "related_cves": details.get("cve_ids", []),
                    "related_ips": [details.get("target_ip", "")] if details.get("target_ip") else [],
                })

            logger.info(f"{'='*60}\n")

            # Emit plan_analysis to frontend so PlanWaveCard shows Analysis/Findings/NextSteps
            wave_id = pending_plan.get("wave_id")
            if wave_id and streaming_callbacks:
                streaming_cb = streaming_callbacks.get(session_id)
                if streaming_cb:
                    try:
                        await streaming_cb.on_plan_analysis(
                            wave_id=wave_id,
                            interpretation=analysis.interpretation,
                            actionable_findings=analysis.actionable_findings or [],
                            recommended_next_steps=analysis.recommended_next_steps or [],
                        )
                    except Exception as e:
                        logger.warning(f"Error emitting plan_analysis: {e}")
        else:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] No output_analysis for wave, using fallback for {len(plan_steps)} tools")

        # Create one ExecutionStep per plan tool (for trace granularity)
        # Use sync writes so each step exists before the next links to it
        prev_chain_step_id = state.get("_last_chain_step_id")
        loop = asyncio.get_running_loop()

        # Combined extracted_info for all wave tools (same for each — wave has one analysis)
        combined_extracted = {}
        if analysis and analysis.extracted_info:
            combined_extracted = analysis.extracted_info.model_dump() if hasattr(analysis.extracted_info, 'model_dump') else {}

        for i, plan_step in enumerate(plan_steps):
            step_id = uuid4().hex[:8]
            step_thought = f"[Wave] {plan_step.get('rationale', '')}"
            step_reasoning = pending_plan.get("plan_rationale", "")
            step_output_analysis = analysis.interpretation if analysis else (plan_step.get("tool_output") or "")[:20000]

            exec_step = {
                "step_id": step_id,
                "iteration": plan_iteration,
                "timestamp": utc_now().isoformat(),
                "phase": phase,
                "thought": step_thought,
                "reasoning": step_reasoning,
                "tool_name": plan_step.get("tool_name"),
                "tool_args": plan_step.get("tool_args"),
                "tool_output": plan_step.get("tool_output"),
                "success": plan_step.get("success", False),
                "error_message": plan_step.get("error_message"),
                "output_analysis": step_output_analysis,
                "actionable_findings": (analysis.actionable_findings or []) if analysis else [],
                "recommended_next_steps": (analysis.recommended_next_steps or []) if analysis else [],
            }
            new_trace_entries.append(exec_step)

            # Chain failure per failed tool (memory + Neo4j)
            if not plan_step.get("success"):
                chain_failures_mem.append({
                    "step_iteration": plan_iteration,
                    "failure_type": "tool_error",
                    "tool_name": plan_step.get("tool_name", ""),
                    "error_message": plan_step.get("error_message", ""),
                    "lesson_learned": analysis.interpretation[:300] if analysis else "",
                })

            # Neo4j chain step (sync so prev_step_id linkage is sequential)
            # Capture all loop variables via default args to avoid closure issues
            _ctx = get_agent_context(state)
            await loop.run_in_executor(
                None,
                lambda _sid=step_id, _prev=prev_chain_step_id, _ps=plan_step,
                       _ei=combined_extracted, _thought=step_thought,
                       _reasoning=step_reasoning, _oa=step_output_analysis,
                       _c=_ctx: chain_graph.sync_record_step(
                    neo4j_uri, neo4j_user, neo4j_password,
                    step_id=_sid,
                    chain_id=session_id,
                    prev_step_id=_prev,
                    user_id=user_id, project_id=project_id,
                    iteration=plan_iteration, phase=phase,
                    tool_name=_ps.get("tool_name", ""),
                    tool_args_summary=str(_ps.get("tool_args", {}))[:500],
                    thought=_thought[:20000],
                    reasoning=_reasoning[:20000],
                    output_summary=(_ps.get("tool_output") or "")[:20000],
                    output_analysis=_oa[:20000],
                    success=_ps.get("success", False),
                    error_message=_ps.get("error_message"),
                    extracted_info=_ei,
                    agent_id=_c["agent_id"],
                    agent_name=_c["agent_name"],
                    fireteam_id=_c["fireteam_id"],
                ),
            )
            # Update prev for next tool in wave (sequential chain linkage)
            prev_chain_step_id = step_id

            # Neo4j ChainFailure node for failed tools (mirrors single-tool path)
            if not plan_step.get("success"):
                chain_graph.fire_record_failure(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=step_id,
                    user_id=user_id, project_id=project_id,
                    failure_type="tool_error",
                    tool_name=plan_step.get("tool_name", ""),
                    error_message=plan_step.get("error_message", ""),
                    lesson_learned=analysis.interpretation[:20000] if analysis else "",
                    phase=phase,
                    iteration=plan_iteration,
                )

        # Neo4j exploit success (mirrors single-tool path)
        if analysis and analysis.exploit_succeeded and analysis.exploit_details and phase == "exploitation":
            last_step_id = new_trace_entries[-1]["step_id"] if new_trace_entries else None
            if last_step_id:
                details = analysis.exploit_details
                try:
                    chain_graph.fire_record_exploit_success(
                        neo4j_uri, neo4j_user, neo4j_password,
                        chain_id=session_id,
                        step_id=last_step_id,
                        user_id=user_id,
                        project_id=project_id,
                        attack_type=details.get("attack_type", state.get("attack_path_type", "cve_exploit")),
                        target_ip=details.get("target_ip", merged_target.primary_target),
                        target_port=details.get("target_port"),
                        cve_ids=details.get("cve_ids", merged_target.vulnerabilities),
                        session_id=details.get("session_id"),
                        username=details.get("username"),
                        password_found=details.get("password"),
                        evidence=details.get("evidence", ""),
                        execution_trace=state.get("execution_trace", []) + new_trace_entries,
                        iteration=plan_iteration,
                    )
                    logger.info(f"[{user_id}/{project_id}/{session_id}] Wave exploit success detected - ChainFinding created")
                except Exception as e:
                    logger.error(f"[{user_id}/{project_id}/{session_id}] Failed to record wave exploit success: {e}")

        # Neo4j chain findings (linked to last step — step already exists from sync write)
        if analysis and new_trace_entries:
            last_step_id = new_trace_entries[-1]["step_id"]
            # Skip exploit-related findings if exploit success already recorded (mirrors single-tool)
            _EXPLOIT_OVERLAP_TYPES = {"exploit_success", "access_gained", "credential_found"}
            _ctx = get_agent_context(state)
            for cf in (analysis.chain_findings or []):
                if analysis.exploit_succeeded and cf.finding_type in _EXPLOIT_OVERLAP_TYPES:
                    continue
                chain_graph.fire_record_finding(
                    neo4j_uri, neo4j_user, neo4j_password,
                    chain_id=session_id, step_id=last_step_id,
                    user_id=user_id, project_id=project_id,
                    finding_type=cf.finding_type, severity=cf.severity,
                    title=cf.title, evidence=cf.evidence,
                    confidence=cf.confidence, phase=phase,
                    iteration=plan_iteration,
                    related_cves=cf.related_cves, related_ips=cf.related_ips,
                    agent_id=_ctx["agent_id"],
                    source_agent=_ctx["agent_name"],
                    fireteam_id=_ctx["fireteam_id"],
                )

        # Update state
        updates["execution_trace"] = state.get("execution_trace", []) + new_trace_entries
        updates["target_info"] = merged_target.model_dump()
        updates["chain_findings_memory"] = chain_findings_mem
        updates["chain_failures_memory"] = chain_failures_mem
        if not (decision.action == "plan_tools" and decision.tool_plan):
            updates["_current_plan"] = None
        if new_trace_entries:
            updates["_last_chain_step_id"] = new_trace_entries[-1]["step_id"]
        tool_summary = ", ".join(f"{s.get('tool_name')}({'OK' if s.get('success') else 'FAIL'})" for s in plan_steps)
        overall = analysis.interpretation if analysis else "Plan wave completed"
        updates["messages"] = [AIMessage(content=f"**Wave** [{phase}] {tool_summary}\n\n{overall}")]

    # Handle different actions
    if decision.action == "complete":
        updates["task_complete"] = True
        updates["completion_reason"] = decision.completion_reason or "Task completed"

    elif decision.action == "transition_phase":
        phase_transition = decision.phase_transition
        to_phase = phase_transition.to_phase if phase_transition else "exploitation"

        # Block post-exploitation if ACTIVATE_POST_EXPL_PHASE=False
        if to_phase == "post_exploitation" and not get_setting('ACTIVATE_POST_EXPL_PHASE', True):
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Blocking post_exploitation transition: ACTIVATE_POST_EXPL_PHASE=False")
            updates["task_complete"] = True
            updates["completion_reason"] = "Exploitation completed. Post-exploitation phase is disabled."
            updates["messages"] = [
                AIMessage(content="Exploitation completed successfully. "
                                 "Post-exploitation phase is not available because ACTIVATE_POST_EXPL_PHASE=False. "
                                 "If you need post-exploitation capabilities, enable it in the project settings.")
            ]
            return updates

        # Ignore transition to same phase - just continue
        if to_phase == phase:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Ignoring transition to same phase: {phase}")
            if decision.tool_name:
                updates["_decision"]["action"] = "use_tool"
            else:
                logger.info(f"[{user_id}/{project_id}/{session_id}] No tool specified, looping back to think")
            return updates

        # Also ignore if we JUST transitioned to this phase
        if just_transitioned and to_phase == just_transitioned:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] Ignoring re-request for recent transition to: {to_phase}")
            if decision.tool_name:
                updates["_decision"]["action"] = "use_tool"
            else:
                logger.info(f"[{user_id}/{project_id}/{session_id}] No tool specified, looping back to think")
            return updates

        # AUTO-APPROVE: Downgrade to informational (safe, no approval needed)
        if to_phase == "informational" and phase in ["exploitation", "post_exploitation"]:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Auto-approving safe downgrade: {phase} → informational")
            updates["current_phase"] = to_phase
            updates["phase_history"] = state.get("phase_history", []) + [
                PhaseHistoryEntry(phase=to_phase).model_dump()
            ]
            updates["_just_transitioned_to"] = to_phase
            updates["messages"] = [
                AIMessage(content=f"Automatically transitioned from {phase} to informational phase for new objective.")
            ]
            return updates

        # Check if approval is required
        needs_approval = (
            (to_phase == "exploitation" and get_setting('REQUIRE_APPROVAL_FOR_EXPLOITATION', True)) or
            (to_phase == "post_exploitation" and get_setting('REQUIRE_APPROVAL_FOR_POST_EXPLOITATION', True))
        )

        if needs_approval:
            updates["phase_transition_pending"] = PhaseTransitionRequest(
                from_phase=phase,
                to_phase=to_phase,
                reason=phase_transition.reason if phase_transition else "",
                planned_actions=phase_transition.planned_actions if phase_transition else [],
                risks=phase_transition.risks if phase_transition else [],
            ).model_dump()
            updates["awaiting_user_approval"] = True
        else:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Auto-approving phase transition (approval not required): {phase} → {to_phase}")
            updates["current_phase"] = to_phase
            updates["phase_history"] = state.get("phase_history", []) + [
                PhaseHistoryEntry(phase=to_phase).model_dump()
            ]
            updates["_just_transitioned_to"] = to_phase
            updates["messages"] = [
                AIMessage(content=f"Phase transition from {phase} to {to_phase} auto-approved (approval not required in settings). Now operating in {to_phase} phase. Proceed with the objective.")
            ]

    elif decision.action == "ask_user":
        user_q = decision.user_question
        if user_q:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Asking user: {user_q.question[:10000]}")
            updates["pending_question"] = UserQuestionRequest(
                question=user_q.question,
                context=user_q.context,
                format=user_q.format,
                options=user_q.options,
                default_value=user_q.default_value,
                phase=phase,
            ).model_dump()
            updates["awaiting_user_question"] = True
        else:
            logger.warning(f"[{user_id}/{project_id}/{session_id}] ask_user action but no user_question provided")

    # Pre-exploitation validation: Force ask_user when session params are missing
    if (get_setting('POST_EXPL_PHASE_TYPE', 'statefull') == "statefull" and
        state.get("attack_path_type") == "cve_exploit" and
        decision.action == "use_tool" and
        decision.tool_name == "metasploit_console" and
        not updates.get("awaiting_user_question")):

        config_complete, missing_params = is_session_config_complete()

        if not config_complete:
            qa_history = state.get("qa_history", [])
            answered_params = set()
            for qa in qa_history:
                answer = qa.get("answer", {})
                answer_text = answer.get("answer", "") if answer else ""
                question_obj = qa.get("question", {})
                question_text = question_obj.get("question", "") if question_obj else ""

                if answer_text:
                    if "LHOST" in question_text.upper():
                        answered_params.add("LHOST")
                    if "LPORT" in question_text.upper():
                        answered_params.add("LPORT")
                    if "BIND" in question_text.upper():
                        answered_params.add("LPORT or BIND_PORT_ON_TARGET")

            still_missing = [p for p in missing_params if p not in answered_params]

            if still_missing:
                logger.info(f"[{user_id}/{project_id}/{session_id}] Forcing ask_user: missing session params {still_missing}")
                updates["_decision"]["action"] = "ask_user"
                updates["pending_question"] = UserQuestionRequest(
                    question=f"Please provide the following required parameters for session-based exploitation: {', '.join(still_missing)}",
                    context="Session-based exploitation requires these parameters to be configured. "
                            "LHOST is your attacker IP address where the target will connect back. "
                            "LPORT is the port you will listen on. "
                            "For bind payloads, BIND_PORT is the port the target will open.",
                    format="text",
                    phase=phase,
                ).model_dump()
                updates["awaiting_user_question"] = True

    # Tool confirmation gate — only when setting enabled and no other gate active
    if (get_setting('REQUIRE_TOOL_CONFIRMATION', True)
            and not updates.get("awaiting_user_approval")
            and not updates.get("awaiting_user_question")):

        action = decision.action
        if action == "use_tool" and decision.tool_name in DANGEROUS_TOOLS:
            updates["awaiting_tool_confirmation"] = True
            updates["tool_confirmation_pending"] = ToolConfirmationRequest(
                mode="single",
                tools=[{
                    "tool_name": decision.tool_name,
                    "tool_args": decision.tool_args or {},
                    "rationale": decision.reasoning or "",
                }],
                reasoning=decision.reasoning or "",
                phase=phase,
                iteration=iteration,
            ).model_dump()

        elif action == "plan_tools" and decision.tool_plan:
            dangerous = [
                {
                    "tool_name": s.tool_name,
                    "tool_args": s.tool_args,
                    "rationale": s.rationale,
                }
                for s in decision.tool_plan.steps
                if s.tool_name in DANGEROUS_TOOLS
            ]
            if dangerous:
                updates["awaiting_tool_confirmation"] = True
                updates["tool_confirmation_pending"] = ToolConfirmationRequest(
                    mode="plan",
                    tools=dangerous,
                    reasoning=decision.tool_plan.plan_rationale,
                    phase=phase,
                    iteration=iteration,
                ).model_dump()

    # If tool confirmation is pending, suppress the step analysis message
    # (it would show as a premature "Step X" report in chat; analysis is already
    # communicated via tool_complete streaming event)
    if updates.get("awaiting_tool_confirmation"):
        updates.pop("messages", None)

    return updates

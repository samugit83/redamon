"""Initialize node — handles new vs continuing objectives and attack chain creation."""

import logging

from langchain_core.messages import AIMessage, HumanMessage

from state import (
    AgentState,
    ConversationObjective,
    ObjectiveOutcome,
    PhaseHistoryEntry,
    TargetInfo,
    format_prior_chains,
    utc_now,
)
import orchestrator_helpers.chain_graph_writer as chain_graph
from orchestrator_helpers.config import get_config_values
from orchestrator_helpers.phase import classify_attack_path, determine_phase_for_new_objective
from project_settings import get_setting

logger = logging.getLogger(__name__)


def _build_guardrail_block(user_id, project_id, session_id, target_desc, reason) -> dict:
    """Build state update that blocks the agent with a guardrail message."""
    return {
        "messages": [AIMessage(content=(
            f"**Scope Guardrail: Target Blocked**\n\n"
            f"The target `{target_desc}` has been blocked by the security guardrail.\n\n"
            f"**Reason:** {reason}\n\n"
            f"This guardrail prevents scanning well-known public services, government websites, "
            f"and major companies that you are unlikely authorized to test. "
            f"Please create a new project with a target you are authorized to scan."
        ))],
        "task_complete": True,
        "completion_reason": f"Guardrail blocked: {reason}",
        "_guardrail_blocked": True,
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
    }


def _build_guardrail_error(user_id, project_id, session_id, target_desc, error) -> dict:
    """Build state update when the guardrail check itself fails (LLM error)."""
    return {
        "messages": [AIMessage(content=(
            f"**Scope Guardrail: Check Failed**\n\n"
            f"The guardrail could not verify whether `{target_desc}` is authorized for scanning "
            f"because the LLM check encountered an error.\n\n"
            f"**Error:** {error}\n\n"
            f"**What to do:**\n"
            f"- Verify your LLM model is correctly configured (must be a chat model)\n"
            f"- Check that your API key is valid and the provider is reachable\n"
            f"- Check the agent logs for more details\n\n"
            f"The agent uses a fail-closed policy — it will not proceed until the guardrail "
            f"can successfully verify the target."
        ))],
        "task_complete": True,
        "completion_reason": f"Guardrail check failed: {error}",
        "_guardrail_blocked": True,
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
    }


async def _run_scope_guardrail(llm, user_id, project_id, session_id) -> dict | None:
    """Run LLM-based guardrail check on the project's target scope.

    FAIL CLOSED: if the LLM is unavailable or errors occur, the agent refuses
    to proceed. This is intentional — the agent must never blindly trust
    project settings, even if the creation-time guardrail was bypassed.

    Returns a state update dict if blocked, or None if allowed.
    """
    from guardrail import check_target_allowed

    target_domain = get_setting('TARGET_DOMAIN', '')
    ip_mode = get_setting('IP_MODE', False)
    target_ips = get_setting('TARGET_IPS', [])

    # Nothing to check (no target configured yet)
    if not target_domain and not target_ips:
        return None

    target_desc = target_domain if not ip_mode else ", ".join(target_ips[:5])

    try:
        result = await check_target_allowed(
            llm,
            target_domain='' if ip_mode else target_domain,
            target_ips=target_ips if ip_mode else [],
        )

        if not result.get("allowed", True):
            reason = result.get("reason", "Target not authorized")
            logger.warning(
                f"[{user_id}/{project_id}/{session_id}] GUARDRAIL BLOCKED: {reason}"
            )
            return _build_guardrail_block(user_id, project_id, session_id, target_desc, reason)

    except Exception as e:
        # FAIL CLOSED — agent must not proceed if it cannot verify the target
        logger.error(
            f"[{user_id}/{project_id}/{session_id}] Scope guardrail error (fail closed): {e}"
        )
        return _build_guardrail_error(
            user_id, project_id, session_id, target_desc, str(e)
        )

    return None


async def initialize_node(state: AgentState, config, *, llm, neo4j_creds) -> dict:
    """
    Initialize state for new conversation or update for continuation.

    Handles multi-objective support: detects when a new objective should be added
    based on task completion and new user messages.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        llm: The LLM instance for attack path classification.
        neo4j_creds: Tuple of (neo4j_uri, neo4j_user, neo4j_password).
    """
    user_id, project_id, session_id = get_config_values(config)
    neo4j_uri, neo4j_user, neo4j_password = neo4j_creds

    logger.info(f"[{user_id}/{project_id}/{session_id}] Initializing state...")

    # Migrate legacy state if needed (backward compatibility)
    from state import migrate_legacy_objective
    state = migrate_legacy_objective(state)

    # RoE engagement date and time window warnings (first invocation only)
    if not state.get("execution_trace") and get_setting('ROE_ENABLED', False):
        from datetime import datetime, timezone
        try:
            import zoneinfo
        except ImportError:
            from backports import zoneinfo

        now_utc = datetime.now(timezone.utc)
        warnings = []

        # Engagement date check
        start_date = get_setting('ROE_ENGAGEMENT_START_DATE', '')
        end_date = get_setting('ROE_ENGAGEMENT_END_DATE', '')
        if start_date:
            try:
                if now_utc.date() < datetime.strptime(start_date, '%Y-%m-%d').date():
                    warnings.append(f"Engagement has not started yet (starts {start_date}).")
            except ValueError:
                pass
        if end_date:
            try:
                if now_utc.date() > datetime.strptime(end_date, '%Y-%m-%d').date():
                    warnings.append(f"Engagement has ended ({end_date}). Testing may no longer be authorized.")
            except ValueError:
                pass

        # Time window check
        if get_setting('ROE_TIME_WINDOW_ENABLED', False):
            tz_name = get_setting('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
            try:
                tz = zoneinfo.ZoneInfo(tz_name)
                now_local = datetime.now(tz)
                day_name = now_local.strftime('%A').lower()
                allowed_days = get_setting('ROE_TIME_WINDOW_DAYS', [])
                start_time = get_setting('ROE_TIME_WINDOW_START_TIME', '09:00')
                end_time = get_setting('ROE_TIME_WINDOW_END_TIME', '18:00')

                if day_name not in allowed_days:
                    warnings.append(f"Current day ({day_name.capitalize()}) is outside the allowed testing window.")
                else:
                    current_time = now_local.strftime('%H:%M')
                    # Handle overnight windows (e.g. 22:00 - 06:00)
                    if start_time <= end_time:
                        outside = current_time < start_time or current_time > end_time
                    else:
                        outside = current_time < start_time and current_time > end_time
                    if outside:
                        warnings.append(f"Current time ({current_time} {tz_name}) is outside the allowed window ({start_time}-{end_time}).")
            except Exception:
                pass

        if warnings:
            warning_text = " | ".join(warnings)
            logger.warning(f"[{user_id}/{project_id}/{session_id}] RoE WARNING: {warning_text}")
            # Inject warning into state so it appears in the agent's prompt context
            state["_roe_warnings"] = warnings

    # Hard guardrail: deterministic, non-disableable — always blocks government/public domains
    # Runs unconditionally regardless of AGENT_GUARDRAIL_ENABLED setting
    if not state.get("execution_trace") and not state.get("_guardrail_blocked"):
        from hard_guardrail import is_hard_blocked
        target_domain = get_setting('TARGET_DOMAIN', '')
        ip_mode = get_setting('IP_MODE', False)
        if not ip_mode and target_domain:
            blocked, reason = is_hard_blocked(target_domain)
            if blocked:
                logger.warning(
                    f"[{user_id}/{project_id}/{session_id}] HARD GUARDRAIL BLOCKED: {reason}"
                )
                return _build_guardrail_block(user_id, project_id, session_id, target_domain, reason)

    # Soft guardrail (LLM-based): on first invocation, verify the project target is authorized
    # Skip if already blocked (avoid redundant LLM calls on retry in same session)
    if get_setting('AGENT_GUARDRAIL_ENABLED', True) and not state.get("execution_trace") and not state.get("_guardrail_blocked"):
        guardrail_block = await _run_scope_guardrail(llm, user_id, project_id, session_id)
        if guardrail_block is not None:
            return guardrail_block

    # If resuming after approval/answer, preserve state for routing
    if state.get("user_approval_response") and state.get("phase_transition_pending"):
        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with approval response: {state.get('user_approval_response')}")
        return {
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id,
        }

    if state.get("user_question_answer") and state.get("pending_question"):
        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with question answer")
        return {
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id,
        }

    # Extract latest user message
    messages = state.get("messages", [])
    latest_message = ""
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            latest_message = msg.content
            break

    # Get current objective list
    objectives = state.get("conversation_objectives", [])
    current_idx = state.get("current_objective_index", 0)

    # Check if this is a NEW message (not approval/answer)
    is_new_message = not (
        state.get("user_approval_response") or
        state.get("user_question_answer")
    )

    # If new message AND previous objective was completed, add as new objective
    if is_new_message and latest_message:
        task_was_complete = state.get("task_complete", False)

        # Also detect new objective by comparing message content with current objective
        current_objective_content = ""
        if current_idx < len(objectives):
            current_objective_content = objectives[current_idx].get("content", "")

        # New objective if: task was completed, OR index out of bounds, OR message differs from current objective
        is_different_message = latest_message.strip() != current_objective_content.strip()

        logger.debug(f"[{user_id}/{project_id}/{session_id}] New objective check: task_complete={task_was_complete}, "
                    f"idx={current_idx}, len={len(objectives)}, is_different={is_different_message}")

        if task_was_complete or current_idx >= len(objectives) or is_different_message:
            logger.info(f"[{user_id}/{project_id}/{session_id}] Detected new objective after task completion")

            # Archive completed objective
            if task_was_complete and current_idx < len(objectives):
                completed_obj = ConversationObjective(**objectives[current_idx])
                outcome = ObjectiveOutcome(
                    objective=completed_obj.model_copy(
                        update={
                            "completed_at": utc_now(),
                            "completion_reason": state.get("completion_reason")
                        }
                    ),
                    execution_steps=[s["step_id"] for s in state.get("execution_trace", [])],
                    findings=state.get("target_info", {}),
                    success=True
                )
                objective_history = state.get("objective_history", []) + [outcome.model_dump()]
                logger.info(f"[{user_id}/{project_id}/{session_id}] Archived objective: {completed_obj.content[:10000]}")
            else:
                objective_history = state.get("objective_history", [])

            # Classify attack path, required phase, and target hints using LLM
            attack_path, required_phase, target_host, target_port, target_cves = await classify_attack_path(llm, latest_message)
            logger.info(f"[{user_id}/{project_id}/{session_id}] Attack path classified: {attack_path}, required_phase: {required_phase}, target: {target_host}:{target_port}, cves: {target_cves}")

            # Create new objective from latest message
            new_objective = ConversationObjective(
                content=latest_message,
                required_phase=required_phase
            ).model_dump()

            objectives = objectives + [new_objective]
            current_idx = len(objectives) - 1

            logger.info(f"[{user_id}/{project_id}/{session_id}] New objective #{current_idx + 1}: {latest_message[:10000]}")

            # CRITICAL: Reset task_complete for new objective
            task_complete = False

            # Determine if phase should auto-transition
            new_phase = determine_phase_for_new_objective(
                required_phase,
                state.get("current_phase"),
            )

            # Fire-and-forget: create/update AttackChain node (MERGE = idempotent)
            chain_graph.fire_create_attack_chain(
                neo4j_uri, neo4j_user, neo4j_password,
                chain_id=session_id,
                user_id=user_id,
                project_id=project_id,
                title=latest_message[:200] if latest_message else "Untitled",
                objective=latest_message[:500],
                attack_path_type=attack_path,
                target_host=target_host,
                target_port=target_port,
                target_cves=target_cves,
            )

            # CRITICAL: Preserve ALL context (user preference)
            return {
                "conversation_objectives": objectives,
                "current_objective_index": current_idx,
                "objective_history": objective_history,
                "task_complete": task_complete,
                "current_phase": new_phase,
                "attack_path_type": attack_path,
                "completion_reason": None,
                # Preserve context except TODO list (new objective = fresh TODO list)
                "execution_trace": state.get("execution_trace", []),
                "target_info": state.get("target_info", {}),
                "todo_list": [],  # Clear TODO list for new objective
                "phase_history": state.get("phase_history", []),
                "user_id": user_id,
                "project_id": project_id,
                "session_id": session_id,
                "awaiting_user_approval": False,
                "phase_transition_pending": None,
                "_abort_transition": False,
                "original_objective": state.get("original_objective", latest_message),  # Backward compat
                # Chain memory (preserve across objectives)
                "chain_findings_memory": state.get("chain_findings_memory", []),
                "chain_failures_memory": state.get("chain_failures_memory", []),
                "chain_decisions_memory": state.get("chain_decisions_memory", []),
                "_last_chain_step_id": state.get("_last_chain_step_id"),
                "_prior_chain_context": state.get("_prior_chain_context"),
            }

    # Otherwise, continue with current objective
    logger.info(f"[{user_id}/{project_id}/{session_id}] Continuing with current objective")

    # Fire-and-forget: create/update AttackChain node (MERGE = idempotent)
    current_objective_content = ""
    if current_idx < len(objectives):
        current_objective_content = objectives[current_idx].get("content", "")
    chain_graph.fire_create_attack_chain(
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=session_id,
        user_id=user_id,
        project_id=project_id,
        title=latest_message[:200] if latest_message else "Untitled",
        objective=current_objective_content[:500],
        attack_path_type=state.get("attack_path_type", "cve_exploit"),
    )

    updates = {
        "current_iteration": state.get("current_iteration", 0),
        "max_iterations": state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)),
        "task_complete": False,
        "current_phase": state.get("current_phase", "informational"),
        "attack_path_type": state.get("attack_path_type", "cve_exploit"),
        "phase_history": state.get("phase_history", [
            PhaseHistoryEntry(phase="informational").model_dump()
        ]),
        "execution_trace": state.get("execution_trace", []),
        "todo_list": state.get("todo_list", []),
        "conversation_objectives": objectives,
        "current_objective_index": current_idx,
        "objective_history": state.get("objective_history", []),
        "original_objective": state.get("original_objective", latest_message),  # Backward compat
        "target_info": state.get("target_info", TargetInfo().model_dump()),
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
        "awaiting_user_approval": False,
        "phase_transition_pending": None,
        "_abort_transition": False,
        # Chain memory (preserve)
        "chain_findings_memory": state.get("chain_findings_memory", []),
        "chain_failures_memory": state.get("chain_failures_memory", []),
        "chain_decisions_memory": state.get("chain_decisions_memory", []),
        "_last_chain_step_id": state.get("_last_chain_step_id"),
        "_prior_chain_context": state.get("_prior_chain_context"),
    }

    # Load prior chain context on first invocation (empty trace)
    if not state.get("execution_trace"):
        try:
            prior_chains = chain_graph.query_prior_chains(
                neo4j_uri, neo4j_user, neo4j_password,
                user_id, project_id, session_id,
            )
            if prior_chains:
                updates["_prior_chain_context"] = format_prior_chains(prior_chains)
        except Exception as exc:
            logger.warning("Failed to load prior chain context: %s", exc)

    return updates

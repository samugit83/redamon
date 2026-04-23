"""Streaming event emission and file detection helpers."""

import os
import re
import logging

logger = logging.getLogger(__name__)


def detect_generated_file(step: dict) -> dict | None:
    """Detect if a tool execution created a downloadable file in /tmp/.

    Checks both tool_args (for explicit -o /tmp/... flags) and
    tool_output (for file listing output confirming creation).

    Returns:
        dict with file metadata or None if no file detected.
    """
    tool_args = step.get("tool_args", {})
    output = (step.get("tool_output") or "") + (step.get("output_analysis") or "")
    command = ""

    if isinstance(tool_args, dict):
        command = tool_args.get("command", "") or tool_args.get("code", "")
    elif isinstance(tool_args, str):
        command = tool_args

    # Pattern 1: msfvenom -o /tmp/filename
    m = re.search(r'-o\s+(/tmp/[^\s;"\']+)', command)
    if m:
        filepath = m.group(1)
        filename = os.path.basename(filepath)
        # Verify file mentioned in output (success indicator)
        if filename in output and "[ERROR]" not in output[:200]:
            return {
                "filepath": filepath,
                "filename": filename,
                "source": "msfvenom",
                "description": f"Generated payload: {filename}",
            }

    # Pattern 2: cp ... /tmp/filename (from fileformat module copy)
    m = re.search(r'cp\s+\S+\s+(/tmp/[^\s;"\']+)', command)
    if m:
        filepath = m.group(1)
        filename = os.path.basename(filepath)
        if filename in output and "[ERROR]" not in output[:200]:
            return {
                "filepath": filepath,
                "filename": filename,
                "source": "fileformat",
                "description": f"Generated document: {filename}",
            }

    # Pattern 3: Output mentions a file was saved to /tmp/
    m = re.search(r'[Ss]aved\s+(?:as\s+|to\s+)?(/tmp/[^\s"\']+)', output)
    if m:
        filepath = m.group(1)
        filename = os.path.basename(filepath)
        return {
            "filepath": filepath,
            "filename": filename,
            "source": "tool_output",
            "description": f"Generated file: {filename}",
        }

    return None


def _make_event_id(prefix: str, obj: dict, *extra_keys) -> str:
    """Build a content-based unique ID for deduplication.

    Uses ONLY content fields — not id(obj) — because LangGraph reconstructs
    state dicts between node yields, giving the same content a new id().
    Content-only dedup correctly prevents re-emission of stale _completed_step
    and _decision across node boundaries within the same astream session.
    """
    parts = [prefix]
    for k in extra_keys:
        parts.append(str(obj.get(k, ""))[:200])
    return "|".join(parts)


async def emit_streaming_events(state: dict, callback) -> None:
    """Emit appropriate streaming events based on state changes.

    Deduplication markers are tracked on the callback object (which persists
    across the entire astream session) rather than on the state dict (which
    is re-created from checkpoint on resume and loses in-memory markers).
    """
    try:
        # Phase update (includes attack_path_type for dynamic routing display)
        if "current_phase" in state:
            await callback.on_phase_update(
                state.get("current_phase", "informational"),
                state.get("current_iteration", 0),
                state.get("attack_path_type", "")
            )

        # Todo list update
        if "todo_list" in state and state.get("todo_list"):
            await callback.on_todo_update(state["todo_list"])

        # Approval request — dedup via callback, not state dict
        # Skip when user_approval_response is set (user already responded —
        # on resume the first yield still has stale checkpoint fields).
        if (state.get("awaiting_user_approval")
                and state.get("phase_transition_pending")
                and not state.get("user_approval_response")):
            pending = state["phase_transition_pending"]
            approval_key = f"{pending.get('from_phase', '')}_{pending.get('to_phase', '')}"
            if callback._emitted_approval_key != approval_key:
                await callback.on_approval_request(pending)
                callback._emitted_approval_key = approval_key

        # Question request — dedup via callback, not state dict
        # Skip when user_question_answer is set (user already responded).
        if (state.get("awaiting_user_question")
                and state.get("pending_question")
                and not state.get("user_question_answer")):
            pending = state["pending_question"]
            question_key = f"{pending.get('phase', '')}_{hash(pending.get('question', '')[:100])}"
            if callback._emitted_question_key != question_key:
                await callback.on_question_request(pending)
                callback._emitted_question_key = question_key

        # 1. Emit tool_complete for PREVIOUS completed step (if any)
        #    This MUST come before thinking AND tool confirmation, so the frontend
        #    sees: tool_complete → thinking → tool_confirmation/tool_start
        #    Without this order, a confirmation request for the next tool arrives
        #    while the previous tool card is still 'running', causing it to be
        #    overwritten by the confirmation handler's findIndex(tool_name + running).
        if "_completed_step" in state and state["_completed_step"]:
            cstep = state["_completed_step"]
            cstep_id = _make_event_id("tc", cstep, "tool_name", "output_analysis")
            tool_name = cstep.get("tool_name")
            # Diagnostic: log the exact gate evaluation so we can spot why
            # tool_complete isn't firing for fireteam member standalone tools.
            logger.info(
                "[diag] tool_complete gate: tool_name=%r success=%r analysis_len=%d id=%r already_emitted=%s cb=%s",
                tool_name, cstep.get("success"),
                len(cstep.get("output_analysis") or ""), cstep_id,
                cstep_id in callback._emitted_tool_complete_ids,
                type(callback).__name__,
            )
            if tool_name and tool_name != "tool_rejection" and cstep.get("success") is not None and cstep.get("output_analysis") and cstep_id not in callback._emitted_tool_complete_ids:
                await callback.on_tool_complete(
                    cstep.get("tool_name", "unknown"),
                    cstep["success"],
                    cstep.get("output_analysis", "")[:10000],
                    actionable_findings=cstep.get("actionable_findings", []),
                    recommended_next_steps=cstep.get("recommended_next_steps", []),
                    # Thread the wall-clock duration stamped by
                    # execute_tool_node so the UI card shows the real time
                    # taken. Without this the member-streaming proxy defaults
                    # duration_ms to 0 and completed cards render "0s".
                    duration_ms=cstep.get("duration_ms"),
                )
                callback._emitted_tool_complete_ids.add(cstep_id)

                # Also emit execution_step summary for the completed step
                await callback.on_execution_step({
                    "iteration": cstep.get("iteration", 0),
                    "phase": state.get("current_phase", "informational"),
                    "thought": cstep.get("thought", ""),
                    "tool_name": cstep.get("tool_name"),
                    "success": cstep.get("success", False),
                    "output_summary": cstep.get("output_analysis", "")[:10000],
                    "actionable_findings": cstep.get("actionable_findings", []),
                    "recommended_next_steps": cstep.get("recommended_next_steps", []),
                })

                # Detect file creation in tool output and notify frontend
                if cstep.get("tool_name") in ("kali_shell", "execute_code", "metasploit_console"):
                    file_info = detect_generated_file(cstep)
                    if file_info:
                        await callback.on_file_ready(file_info)

        # 2. Emit thinking (from _decision stored by _think_node).
        # Threads the decision's `action` through so the UI / restore layer
        # can distinguish thinks that spawn a fireteam (whose rationale is
        # already surfaced on the FireteamCard as plan_rationale) from thinks
        # that precede a regular tool call. Without this, root deploy_fireteam
        # thinks appeared twice on session restore — once as a standalone
        # ThinkingItem, once as the fireteam card's rationale.
        if "_decision" in state and state["_decision"]:
            decision = state["_decision"]
            think_id = _make_event_id("th", decision, "thought")
            if decision.get("thought") and think_id not in callback._emitted_thinking_ids:
                try:
                    await callback.on_thinking(
                        state.get("current_iteration", 0),
                        state.get("current_phase", "informational"),
                        decision.get("thought", ""),
                        decision.get("reasoning", ""),
                        action=decision.get("action"),
                        input_tokens=int(state.get("_input_tokens_this_turn", 0) or 0),
                        output_tokens=int(state.get("_output_tokens_this_turn", 0) or 0),
                    )
                    callback._emitted_thinking_ids.add(think_id)
                except Exception as e:
                    logger.error(f"Error emitting thinking event: {e}")

        # 3. Emit tool_start and output chunks for CURRENT step (new tool)
        #    Skip if tool confirmation is pending — tool hasn't actually started yet
        if "_current_step" in state and state["_current_step"] and not state.get("awaiting_tool_confirmation"):
            step = state["_current_step"]
            start_id = _make_event_id("ts", step, "tool_name", "tool_args")
            output_id = _make_event_id("to", step, "tool_name", "tool_output")

            # Emit tool start
            if step.get("tool_name") and start_id not in callback._emitted_tool_start_ids:
                await callback.on_tool_start(
                    step["tool_name"],
                    step.get("tool_args", {})
                )
                callback._emitted_tool_start_ids.add(start_id)

            # Emit tool output chunk (raw tool output)
            if step.get("tool_output") and output_id not in callback._emitted_tool_output_ids:
                await callback.on_tool_output_chunk(
                    step.get("tool_name", "unknown"),
                    step["tool_output"],
                    is_final=True
                )
                callback._emitted_tool_output_ids.add(output_id)

            # NOTE: tool_complete for current step will be emitted via _completed_step
            # in the NEXT think iteration

        # 4. Tool confirmation request — AFTER tool_complete and thinking
        #    Dedup via callback. Skip when tool_confirmation_response is already set
        #    (user already responded) — on resume the first yield still has the stale
        #    checkpoint fields but the response is merged in from update_data.
        if (state.get("awaiting_tool_confirmation")
                and state.get("tool_confirmation_pending")
                and not state.get("tool_confirmation_response")):
            pending = state["tool_confirmation_pending"]
            conf_key = pending.get("confirmation_id", "")
            if callback._emitted_tool_confirmation_key != conf_key:
                await callback.on_tool_confirmation_request(pending)
                callback._emitted_tool_confirmation_key = conf_key

        # Task complete - only emit AFTER generate_response_node has finished
        if state.get("task_complete") and state.get("_report_generated"):
            await callback.on_task_complete(
                state.get("completion_reason", "Task completed successfully"),
                state.get("current_phase", "informational"),
                state.get("current_iteration", 0)
            )

    except Exception as e:
        logger.error(f"Error emitting streaming events: {e}")
        # Don't fail the whole operation if streaming fails
        pass

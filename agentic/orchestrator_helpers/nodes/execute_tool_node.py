"""Execute tool node — runs the selected tool with progress streaming support."""

import asyncio
import os
import re
import logging

import httpx

from state import AgentState
from orchestrator_helpers import roe_gate
from orchestrator_helpers.json_utils import json_dumps_safe
from orchestrator_helpers.config import get_identifiers, get_tenant_id
from tools import set_tenant_context, set_phase_context, set_graph_view_context
from kali_auth import kali_auth_headers, note_kali_refusal

logger = logging.getLogger(__name__)


# Patterns that indicate an MCP-server-wrapped failure returned with success=True.
# Matched against the tool output body; the first hit's match group becomes the
# synthesized error_message. Keep specific — broad patterns like 'error' alone
# false-positive on benign text (e.g., a ffuf result row that mentions 'error').
_EMBEDDED_ERROR_PATTERNS = [
    re.compile(r"^\[ERROR\][^\n]*", re.MULTILINE),
    re.compile(r"Navigation failed:[^\n]*", re.IGNORECASE),
    re.compile(r"Page\.goto:\s*Timeout[^\n]*", re.IGNORECASE),
    re.compile(r"playwright\._impl\._errors\.[A-Za-z]+Error[^\n]*"),
    re.compile(r"ConnectionError:[^\n]*"),
    re.compile(r"TimeoutError:[^\n]*"),
    # MCP tool wrappers commonly prefix their error envelope with this.
    re.compile(r"Tool execution failed:[^\n]*", re.IGNORECASE),
]


def _detect_embedded_tool_error(tool_output: str) -> str | None:
    """Scan tool output for embedded error signals that the MCP wrapper missed.

    Returns the first matched error fragment (truncated to 500 chars) or None
    when the output looks clean. Called on success=True outputs so a tool
    that "succeeded" but actually carried a Playwright timeout / connection
    failure still flips to success=False and a ChainFailure gets written.
    """
    if not tool_output:
        return None
    # Quick-reject: common success markers mean no need to pattern-scan.
    # Playwright's HTML dumps routinely exceed 40k chars; running 7 regexes
    # against each is fine, but skip obvious non-error outputs.
    head = tool_output[:4000]
    for pat in _EMBEDDED_ERROR_PATTERNS:
        m = pat.search(head)
        if m:
            return m.group(0)[:500]
    return None


async def execute_tool_node(
    state: AgentState,
    config,
    *,
    tool_executor,
    streaming_callbacks,
    session_manager_base,
    graph_view_cyphers=None,
) -> dict:
    """
    Execute the selected tool.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        tool_executor: PhaseAwareToolExecutor instance.
        streaming_callbacks: Dict of session_id -> streaming callback objects.
        session_manager_base: Base URL for the kali-sandbox session manager.
    """
    user_id, project_id, session_id = get_identifiers(state, config)

    step_data = state.get("_current_step") or {}
    tool_name = step_data.get("tool_name")
    tool_args = step_data.get("tool_args") or {}
    phase = state.get("current_phase", "informational")
    iteration = state.get("current_iteration", 0)

    # Detailed logging - tool execution start
    logger.info(f"\n{'='*60}")
    logger.info(f"EXECUTE TOOL - Iteration {iteration} - Phase: {phase}")
    logger.info(f"{'='*60}")
    logger.info(f"TOOL_NAME: {tool_name}")
    logger.info(f"TOOL_ARGS:")
    if tool_args:
        for key, value in tool_args.items():
            val_str = str(value)
            if len(val_str) > 200:
                val_str = val_str[:10000]
            logger.info(f"  {key}: {val_str}")
    else:
        logger.info("  (no arguments)")

    # Handle missing tool name
    if not tool_name:
        logger.error(f"[{user_id}/{project_id}/{session_id}] No tool name in step_data")
        step_data["tool_output"] = "Error: No tool specified"
        step_data["success"] = False
        step_data["error_message"] = "No tool name provided"
        logger.info(f"TOOL_OUTPUT: Error - No tool specified")
        logger.info(f"{'='*60}\n")
        return {
            "_current_step": step_data,
            "_tool_result": {"success": False, "error": "No tool name provided"},
        }

    # Set context
    # The project's owner: the graph, the traffic tag and the run credential are theirs.
    set_tenant_context(get_tenant_id(state, config), project_id, session_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    from project_settings import get_setting
    refusal = roe_gate.check_tool_call(tool_name, tool_args, phase, iteration)
    if refusal:
        logger.warning(f"[{user_id}/{project_id}/{session_id}] refused '{tool_name}' at iter {iteration}: {refusal.error}")
        step_data["tool_output"] = refusal.message
        step_data["success"] = False
        step_data["error_message"] = refusal.error
        return {
            "_current_step": step_data,
            "_tool_result": {"success": False, "error": refusal.message},
        }

    extra_updates = {}

    # Check if this is a long-running command that needs progress streaming
    is_long_running_msf = (
        tool_name == "metasploit_console" and
        any(cmd in (tool_args.get("command", "") or "").lower() for cmd in ["run", "exploit"])
    )
    is_long_running_hydra = (tool_name == "execute_hydra")

    # Execute the tool (with progress streaming for long-running commands)
    from orchestrator_helpers.member_streaming import resolve_streaming_callback
    import time as _time
    streaming_cb = resolve_streaming_callback(streaming_callbacks, session_id)
    _tool_t0 = _time.monotonic()
    user_stopped = False
    if is_long_running_msf and streaming_cb:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for long-running MSF command")
        _tool_coro = tool_executor.execute_with_progress(
            tool_name,
            tool_args,
            phase,
            progress_callback=streaming_cb.on_tool_output_chunk
        )
    elif is_long_running_hydra and streaming_cb:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for Hydra brute force")
        _tool_coro = tool_executor.execute_with_progress(
            tool_name,
            tool_args,
            phase,
            progress_callback=streaming_cb.on_tool_output_chunk,
            progress_url=os.environ.get('MCP_HYDRA_PROGRESS_URL', 'http://kali-sandbox:8014/progress')
        )
    else:
        _tool_coro = tool_executor.execute(tool_name, tool_args, phase)

    # Wrap in a cancellable inner task so the per-tool Stop button can cancel
    # just this tool without tearing down the whole orchestrator run. If the
    # user clicks Stop, we recover the CancelledError here, mark the tool as
    # failed, and let the agent loop proceed to the next iteration normally.
    _tool_task = asyncio.ensure_future(_tool_coro)
    if streaming_cb and hasattr(streaming_cb, "register_tool_task"):
        try:
            streaming_cb.register_tool_task(tool_name, None, None, _tool_task)
        except Exception as e:
            logger.debug(f"register_tool_task failed: {e}")
    try:
        try:
            result = await _tool_task
        except asyncio.CancelledError:
            # See execute_plan_node for the rationale: use current_task().cancelling()
            # (not _tool_task.cancelled()) to tell a per-tool Stop apart from
            # an outer cancel. Python propagates an outer cancel down into
            # awaited tasks, so both scenarios leave _tool_task cancelled.
            _cur = asyncio.current_task()
            outer_being_cancelled = bool(_cur and _cur.cancelling())
            if outer_being_cancelled:
                if not _tool_task.done():
                    _tool_task.cancel()
                raise
            user_stopped = True
            result = {
                "success": False,
                "error": "Stopped by user",
                "output": "Stopped by user",
            }
    finally:
        if streaming_cb and hasattr(streaming_cb, "unregister_tool_task"):
            try:
                streaming_cb.unregister_tool_task(tool_name, None, None)
            except Exception:
                pass
    # Record wall-clock duration on the step so the UI can show "17.3s" on
    # the tool card. Without this, emit_streaming_events had nothing to
    # pass into on_tool_complete(duration_ms=...) and the frontend reducer
    # patched `duration: 0` on the completed ToolExecutionItem.
    step_data["duration_ms"] = int((_time.monotonic() - _tool_t0) * 1000)
    if user_stopped:
        step_data["stopped_by_user"] = True

    # Update step with output (handle None result)
    if result:
        step_data["tool_output"] = result.get("output") or ""
        step_data["success"] = result.get("success", False)
        step_data["error_message"] = result.get("error")
    else:
        step_data["tool_output"] = ""
        step_data["success"] = False
        step_data["error_message"] = "Tool execution returned no result"

    # Detect embedded errors in tool output: MCP servers often return success=True
    # with an error message inside the body (e.g. Playwright's
    # "[ERROR] Navigation failed: Page.goto: Timeout 30000ms exceeded"). Without
    # this, ChainFailure nodes never get written and the LLM's chain_failures_memory
    # stays empty — so it retries the same failing pattern instead of learning.
    embedded_err = _detect_embedded_tool_error(step_data.get("tool_output") or "")
    if step_data.get("success") and embedded_err:
        step_data["success"] = False
        step_data["error_message"] = step_data.get("error_message") or embedded_err
        step_data["error_embedded"] = True

    # Diagnostic classification: distinguishes a shell-quoting glitch from a
    # real 4xx from a 5xx-in-3ms parse-time crash. Surfaced in chain context
    # so the LLM can see WHICH kind of failure happened, not just THAT one did.
    from orchestrator_helpers.error_class import classify_error_class
    step_data["error_class"] = classify_error_class(
        success=step_data.get("success", False),
        tool_output=step_data.get("tool_output"),
        error_message=step_data.get("error_message"),
        duration_ms=step_data.get("duration_ms"),
        tool_name=tool_name,
    )

    # Detailed logging - tool output
    tool_output = step_data.get("tool_output", "")
    success = step_data.get("success", False)
    error_msg = step_data.get("error_message")
    duration_ms = step_data.get("duration_ms")

    logger.info(f"SUCCESS: {success} duration_ms={duration_ms}")
    if error_msg:
        logger.info(f"ERROR: {error_msg}")

    # Only a bounded head goes to the prose log; the full body is already on the
    # offload file + DB, so line-by-line dumping the whole thing was pure bloat.
    _cap = int(get_setting('LOG_TOOL_OUTPUT_MAX_CHARS', 4000))
    logger.info(f"TOOL_OUTPUT ({len(tool_output)} chars):")
    if tool_output:
        for line in tool_output[:_cap].split('\n'):
            logger.info(f"  | {line}")
        if len(tool_output) > _cap:
            logger.info(f"  | ... ({len(tool_output) - _cap} more chars; full body offloaded/DB)")
    else:
        logger.info("  (empty output)")

    # Flag capture: the north-star event for a CTF harness. Detect the moment a
    # flag appears in tool output instead of leaving it buried in the dump.
    try:
        from session_log import detect_flags, log_event
        _flags = detect_flags(tool_output)
        if _flags:
            logger.info(f"[{user_id}/{project_id}/{session_id}] FLAG_CAPTURED via {tool_name}: {_flags}")
            for _flag in _flags:
                log_event("flag_captured", session=session_id, iteration=iteration,
                          phase=phase, tool=tool_name, flag=_flag)
        log_event("tool_result", session=session_id, iteration=iteration, phase=phase,
                  tool=tool_name, success=success, duration_ms=duration_ms,
                  output_chars=len(tool_output), error=error_msg)
    except Exception:
        pass

    # Detect new Metasploit sessions and register chat mapping
    if tool_name == "metasploit_console" and tool_output:
        for match in re.finditer(r'session\s+(\d+)\s+opened', tool_output, re.IGNORECASE):
            msf_session_id = int(match.group(1))
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(
                        f"{session_manager_base}/session-chat-map",
                        json={"msf_session_id": msf_session_id, "chat_session_id": session_id},
                        headers=kali_auth_headers(),
                    )
                    note_kali_refusal(resp.status_code, "/session-chat-map")
            except Exception:
                pass  # Best effort, don't break execution

    # Register non-MSF listeners (netcat, socat) created via kali_shell
    if tool_name == "kali_shell" and tool_args:
        cmd = tool_args.get("command", "")
        if re.search(r'(nc|ncat)\s+.*-l', cmd) or 'socat' in cmd:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(
                        f"{session_manager_base}/non-msf-sessions",
                        json={"type": "listener", "tool": "netcat", "command": cmd,
                               "chat_session_id": session_id},
                        headers=kali_auth_headers(),
                    )
                    note_kali_refusal(resp.status_code, "/non-msf-sessions")
            except Exception:
                pass

    updates = {
        "_current_step": step_data,
        "_tool_result": result or {"success": False, "error": "No result"},
    }
    updates.update(extra_updates)
    return updates

"""Execute tool node — runs the selected tool with progress streaming support."""

import asyncio
import os
import re
import logging

import httpx

from state import AgentState
from orchestrator_helpers.json_utils import json_dumps_safe
from orchestrator_helpers.config import get_identifiers
from tools import set_tenant_context, set_phase_context, set_graph_view_context

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
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # RoE enforcement: tool restrictions are handled via agentToolPhaseMap
    # (is_tool_allowed_in_phase already blocks tools with empty/missing phases).
    # Here we only enforce the severity phase cap.
    from project_settings import get_setting
    if get_setting('ROE_ENABLED', False):
        # Severity phase cap
        PHASE_ORDER = {'informational': 0, 'exploitation': 1, 'post_exploitation': 2}
        max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
        if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(max_phase, 2):
            msg = f"RoE BLOCKED: Current phase '{phase}' exceeds maximum allowed phase '{max_phase}'."
            logger.warning(f"[{user_id}/{project_id}/{session_id}] {msg}")
            step_data["tool_output"] = msg
            step_data["success"] = False
            step_data["error_message"] = msg
            return {
                "_current_step": step_data,
                "_tool_result": {"success": False, "error": msg},
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

    # Detailed logging - tool output
    tool_output = step_data.get("tool_output", "")
    success = step_data.get("success", False)
    error_msg = step_data.get("error_message")

    logger.info(f"SUCCESS: {success}")
    if error_msg:
        logger.info(f"ERROR: {error_msg}")

    logger.info(f"TOOL_OUTPUT ({len(tool_output)} chars):")
    if tool_output:
        output_preview = tool_output[:100000]
        for line in output_preview.split('\n'):
            logger.info(f"  | {line}")
        if len(tool_output) > 100000:
            logger.info(f"  | ... ({len(tool_output) - 100000} more chars)")
    else:
        logger.info("  (empty output)")
    logger.info(f"{'='*60}\n")

    # Detect new Metasploit sessions and register chat mapping
    if tool_name == "metasploit_console" and tool_output:
        for match in re.finditer(r'session\s+(\d+)\s+opened', tool_output, re.IGNORECASE):
            msf_session_id = int(match.group(1))
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/session-chat-map",
                        json={"msf_session_id": msf_session_id, "chat_session_id": session_id}
                    )
            except Exception:
                pass  # Best effort, don't break execution

    # Register non-MSF listeners (netcat, socat) created via kali_shell
    if tool_name == "kali_shell" and tool_args:
        cmd = tool_args.get("command", "")
        if re.search(r'(nc|ncat)\s+.*-l', cmd) or 'socat' in cmd:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/non-msf-sessions",
                        json={"type": "listener", "tool": "netcat", "command": cmd,
                               "chat_session_id": session_id}
                    )
            except Exception:
                pass

    updates = {
        "_current_step": step_data,
        "_tool_result": result or {"success": False, "error": "No result"},
    }
    updates.update(extra_updates)
    return updates

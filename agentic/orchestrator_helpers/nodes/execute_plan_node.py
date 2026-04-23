"""Execute plan node — runs a wave of independent tools in parallel.

This node emits streaming events directly to the callback (not through
emit_streaming_events in streaming.py) because it manages multiple tool
lifecycles in a single node execution.
"""

import asyncio
import os
import re
import logging
from uuid import uuid4

import httpx

from state import AgentState
from orchestrator_helpers.config import get_identifiers
from tools import set_tenant_context, set_phase_context, set_graph_view_context

logger = logging.getLogger(__name__)


def _validate_plan_mutex_groups(steps: list) -> str | None:
    """Return None if OK, or a diagnostic string if two plan steps invoke the
    same singleton tool group (e.g. two steps both calling metasploit_console).

    Mirrors fireteam_deploy_node._validate_mutex_groups but scans tool_name
    directly rather than declared skills — plan_tools steps carry the concrete
    tool call, not a skill declaration.
    """
    from project_settings import TOOL_MUTEX_GROUPS

    for group, tools in TOOL_MUTEX_GROUPS.items():
        claimers = [s.get("tool_name") for s in steps if s.get("tool_name") in tools]
        if len(claimers) > 1:
            return f"Multiple plan steps claim mutex group '{group}': {claimers}"
    return None


def _check_roe_blocked(tool_name: str, phase: str) -> str | None:
    """Check if a tool is blocked by Rules of Engagement. Returns error message or None."""
    from project_settings import get_setting

    if not get_setting('ROE_ENABLED', False):
        return None

    CATEGORY_TOOL_MAP = {
        'brute_force': ['execute_hydra', 'execute_wpscan', 'execute_ffuf'],
        'dos': [],
        'social_engineering': [],
        'exploitation': ['metasploit_console', 'execute_hydra'],
    }
    forbidden = set(get_setting('ROE_FORBIDDEN_TOOLS', []))
    for cat in get_setting('ROE_FORBIDDEN_CATEGORIES', []):
        forbidden.update(CATEGORY_TOOL_MAP.get(cat, []))

    if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
        forbidden.add('execute_hydra')
    if not get_setting('ROE_ALLOW_DOS', False):
        forbidden.update(CATEGORY_TOOL_MAP.get('dos', []))

    if tool_name in forbidden:
        return f"RoE BLOCKED: Tool '{tool_name}' is forbidden by the Rules of Engagement."

    PHASE_ORDER = {'informational': 0, 'exploitation': 1, 'post_exploitation': 2}
    max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
    if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(max_phase, 2):
        return f"RoE BLOCKED: Current phase '{phase}' exceeds maximum allowed phase '{max_phase}'."

    return None


async def _execute_single_step(
    step: dict,
    step_index: int,
    total_steps: int,
    *,
    phase: str,
    wave_id: str,
    user_id: str,
    project_id: str,
    session_id: str,
    tool_executor,
    streaming_cb,
    session_manager_base: str,
) -> bool:
    """Execute a single tool step within a wave. Returns True if successful."""
    tool_name = step.get("tool_name")
    tool_args = step.get("tool_args") or {}

    logger.info(f"\n--- Plan Step {step_index+1}/{total_steps}: {tool_name} ---")

    if not tool_name:
        step["tool_output"] = "Error: No tool specified"
        step["success"] = False
        step["error_message"] = "No tool name provided"
        return False

    # RoE gate
    roe_msg = _check_roe_blocked(tool_name, phase)
    if roe_msg:
        logger.warning(f"[{user_id}/{project_id}/{session_id}] {roe_msg}")
        step["tool_output"] = roe_msg
        step["success"] = False
        step["error_message"] = roe_msg
        if streaming_cb:
            try:
                await streaming_cb.on_tool_start(tool_name, tool_args, wave_id=wave_id, step_index=step_index)
                await streaming_cb.on_tool_complete(
                    tool_name, False, roe_msg, wave_id=wave_id, step_index=step_index,
                    duration_ms=0,
                )
            except Exception as e:
                logger.warning(f"Error emitting RoE block events: {e}")
        return False

    # Emit tool_start
    if streaming_cb:
        try:
            await streaming_cb.on_tool_start(tool_name, tool_args, wave_id=wave_id, step_index=step_index)
        except Exception as e:
            logger.warning(f"Error emitting tool_start: {e}")

    # Execute the tool
    import time as _time
    _step_t0 = _time.monotonic()
    user_stopped = False
    try:
        is_long_running_msf = (
            tool_name == "metasploit_console" and
            any(cmd in (tool_args.get("command", "") or "").lower() for cmd in ["run", "exploit"])
        )
        is_long_running_hydra = (tool_name == "execute_hydra")

        # Create a wave-aware progress callback
        async def _wave_progress(tn, chunk, is_final=False, _wid=wave_id, _si=step_index):
            if streaming_cb:
                await streaming_cb.on_tool_output_chunk(tn, chunk, is_final=is_final, wave_id=_wid, step_index=_si)

        # Wrap tool execution in an inner task so the per-tool Stop button
        # (handle_tool_stop → cancel_tool_task) can cancel just this tool
        # without tearing down the surrounding wave. The inner task is
        # registered in the ws_manager's tool-task registry and cleared in
        # the finally block.
        if is_long_running_msf and streaming_cb:
            _tool_coro = tool_executor.execute_with_progress(
                tool_name, tool_args, phase,
                progress_callback=_wave_progress,
            )
        elif is_long_running_hydra and streaming_cb:
            _tool_coro = tool_executor.execute_with_progress(
                tool_name, tool_args, phase,
                progress_callback=_wave_progress,
                progress_url=os.environ.get('MCP_HYDRA_PROGRESS_URL', 'http://kali-sandbox:8014/progress'),
            )
        else:
            _tool_coro = tool_executor.execute(tool_name, tool_args, phase)

        _tool_task = asyncio.ensure_future(_tool_coro)
        if streaming_cb and hasattr(streaming_cb, "register_tool_task"):
            try:
                streaming_cb.register_tool_task(tool_name, wave_id, step_index, _tool_task)
            except Exception as e:
                logger.debug(f"register_tool_task failed: {e}")
        try:
            try:
                result = await _tool_task
            except asyncio.CancelledError:
                # Distinguish a per-tool Stop (user clicked Stop on just this
                # card) from a global cancel (orchestrator shutdown / global
                # Stop / wave-level cancel). Python's asyncio propagates an
                # outer cancel down into awaited tasks, so `_tool_task.cancelled()`
                # alone cannot tell the two apart — both end up True. Instead,
                # ask the CURRENT task whether it itself has pending cancel
                # requests. If it does, the cancel came from outside this
                # coroutine and must propagate; otherwise only the inner
                # task was cancelled (per-tool Stop).
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
                    streaming_cb.unregister_tool_task(tool_name, wave_id, step_index)
                except Exception:
                    pass
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.error(f"Tool execution error for {tool_name}: {e}")
        result = {"success": False, "error": str(e), "output": f"Error: {e}"}
    step["duration_ms"] = int((_time.monotonic() - _step_t0) * 1000)
    if user_stopped:
        step["stopped_by_user"] = True

    # Store result
    if result:
        step["tool_output"] = result.get("output") or ""
        step["success"] = result.get("success", False)
        step["error_message"] = result.get("error")
    else:
        step["tool_output"] = ""
        step["success"] = False
        step["error_message"] = "Tool execution returned no result"

    # Same embedded-error detection as execute_tool_node so plan-wave steps
    # that returned success=True with a Playwright timeout / connection error
    # in the body flip to success=False and produce a ChainFailure record.
    from orchestrator_helpers.nodes.execute_tool_node import _detect_embedded_tool_error
    embedded_err = _detect_embedded_tool_error(step.get("tool_output") or "")
    if step.get("success") and embedded_err:
        step["success"] = False
        step["error_message"] = step.get("error_message") or embedded_err
        step["error_embedded"] = True

    tool_output = step.get("tool_output", "")

    # Emit output as chunk for non-streaming tools so frontend shows Raw Output
    is_long_running = is_long_running_msf or is_long_running_hydra
    if not is_long_running and streaming_cb and tool_output:
        try:
            await streaming_cb.on_tool_output_chunk(
                tool_name, tool_output, is_final=True, wave_id=wave_id, step_index=step_index,
            )
        except Exception as e:
            logger.warning(f"Error emitting tool output chunk: {e}")

    logger.info(f"  SUCCESS: {step['success']}")
    if step.get("error_message"):
        logger.info(f"  ERROR: {step['error_message']}")
    logger.info(f"  OUTPUT ({len(tool_output)} chars)")

    # Emit tool_complete (no output_summary — raw output already sent as chunk)
    if streaming_cb:
        try:
            await streaming_cb.on_tool_complete(
                tool_name,
                step["success"],
                "",
                wave_id=wave_id,
                step_index=step_index,
                duration_ms=step.get("duration_ms"),
            )
        except Exception as e:
            logger.warning(f"Error emitting tool_complete: {e}")

    # Detect new Metasploit sessions
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
                pass

    # Register non-MSF listeners
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

    return step["success"]


async def execute_plan_node(
    state: AgentState,
    config,
    *,
    tool_executor,
    streaming_callbacks,
    session_manager_base,
    graph_view_cyphers=None,
) -> dict:
    """Execute a wave of independent tools in parallel using asyncio.gather."""
    user_id, project_id, session_id = get_identifiers(state, config)
    plan_data = state.get("_current_plan")

    if not plan_data or not plan_data.get("steps"):
        logger.error(f"[{user_id}/{project_id}/{session_id}] execute_plan_node called with no plan data")
        return {"_current_plan": None}

    steps = plan_data["steps"]
    phase = state.get("current_phase", "informational")
    iteration = state.get("current_iteration", 0)
    wave_id = f"wave-{iteration}-{uuid4().hex[:8]}"

    plan_data["wave_id"] = wave_id

    logger.info(f"\n{'='*60}")
    logger.info(f"EXECUTE PLAN (PARALLEL) - Iteration {iteration} - Phase: {phase}")
    logger.info(f"Wave ID: {wave_id} - {len(steps)} tools")
    logger.info(f"Tools: {[s.get('tool_name') for s in steps]}")
    logger.info(f"{'='*60}")

    # Set context (ContextVar — inherited by child tasks in asyncio)
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # Get streaming callback
    from orchestrator_helpers.member_streaming import resolve_streaming_callback
    streaming_cb = resolve_streaming_callback(streaming_callbacks, session_id)

    # Emit plan_start
    tool_names = [s.get("tool_name", "unknown") for s in steps]
    if streaming_cb:
        try:
            await streaming_cb.on_plan_start(
                wave_id=wave_id,
                plan_rationale=plan_data.get("plan_rationale", ""),
                tools=tool_names,
            )
        except Exception as e:
            logger.warning(f"Error emitting plan_start: {e}")

    # Mutex validation — reject plans that stack singleton tools (e.g.
    # metasploit_console) in parallel. Runs after plan_start so the UI renders
    # a proper plan card with a rejection reason rather than a silent no-op.
    mutex_error = _validate_plan_mutex_groups(steps)
    if mutex_error:
        logger.warning(
            f"[{user_id}/{project_id}/{session_id}] plan mutex conflict: {mutex_error}"
        )
        rejection = (
            f"Plan rejected: {mutex_error}. "
            f"Revise the plan so only one step invokes this singleton tool per wave "
            f"(serialize across iterations instead)."
        )
        for step in steps:
            step["tool_output"] = rejection
            step["success"] = False
            step["error_message"] = rejection
        if streaming_cb:
            try:
                await streaming_cb.on_plan_complete(
                    wave_id=wave_id,
                    total=len(steps),
                    successful=0,
                    failed=len(steps),
                )
            except Exception as e:
                logger.warning(f"Error emitting plan_complete after mutex reject: {e}")
        return {"_current_plan": plan_data}

    # Cap concurrent tools inside this wave via a per-wave semaphore. Both the
    # root agent and every fireteam member funnel through this node, so this
    # single knob applies uniformly. A 20-step plan with cap=10 runs the first
    # 10 immediately and parks the other 10 on the semaphore queue — no tool
    # is dropped, nothing is reordered. Default 10 (see project_settings.py).
    from project_settings import get_setting
    max_parallel = max(1, int(get_setting('PLAN_MAX_PARALLEL_TOOLS', 10) or 10))
    wave_semaphore = asyncio.Semaphore(max_parallel)
    if len(steps) > max_parallel:
        logger.info(
            f"Plan wave {wave_id} has {len(steps)} steps; "
            f"throttling concurrency to {max_parallel}"
        )

    async def _bounded_step(step, index):
        async with wave_semaphore:
            return await _execute_single_step(
                step,
                index,
                len(steps),
                phase=phase,
                wave_id=wave_id,
                user_id=user_id,
                project_id=project_id,
                session_id=session_id,
                tool_executor=tool_executor,
                streaming_cb=streaming_cb,
                session_manager_base=session_manager_base,
            )

    tasks = [_bounded_step(step, i) for i, step in enumerate(steps)]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Count successes/failures
    successful = 0
    failed = 0
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Unexpected exception in parallel step {i}: {result}")
            steps[i]["tool_output"] = steps[i].get("tool_output") or f"Error: {result}"
            steps[i]["success"] = False
            steps[i]["error_message"] = str(result)
            failed += 1
        elif result:
            successful += 1
        else:
            failed += 1

    # Emit plan_complete
    if streaming_cb:
        try:
            await streaming_cb.on_plan_complete(
                wave_id=wave_id,
                total=len(steps),
                successful=successful,
                failed=failed,
            )
        except Exception as e:
            logger.warning(f"Error emitting plan_complete: {e}")

    logger.info(f"\n{'='*60}")
    logger.info(f"PLAN COMPLETE (PARALLEL) - {successful} ok, {failed} failed out of {len(steps)}")
    logger.info(f"{'='*60}\n")

    return {"_current_plan": plan_data}

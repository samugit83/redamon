"""Fireteam deploy node.

Parent agent reaches this node when it emits action=deploy_fireteam. We:

  1. Validate the plan (member count cap, mutex-group conflicts).
  2. Write a Fireteam row + N FireteamMember rows to Postgres.
  3. Launch N asyncio tasks, each running the compiled fireteam_member_graph,
     bounded by asyncio.Semaphore(FIRETEAM_MAX_CONCURRENT).
  4. Wrap the gather in asyncio.wait_for(timeout=FIRETEAM_TIMEOUT_SEC).
  5. On timeout or operator cancel, cancel outstanding tasks and collect
     partial results.
  6. Return FireteamMemberResult dicts via state._current_fireteam_results
     for fireteam_collect_node to merge.
"""

import asyncio
import json as _json
import logging
import os
import time
from typing import Iterable, Optional
from uuid import uuid4

import httpx
from langchain_core.messages import SystemMessage

from state import AgentState, FireteamMemberResult
from orchestrator_helpers.config import get_identifiers
from project_settings import get_setting, TOOL_MUTEX_GROUPS
from tools import set_tenant_context, set_phase_context, set_graph_view_context


def _system_msg(content: str) -> SystemMessage:
    """Build a SystemMessage used for status/rejection notes injected into
    the parent's conversation after a fireteam action."""
    return SystemMessage(content=content)

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
_INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

# Shared client for all fireteam persistence writes. One connection pool is
# reused for POST /fireteams + N PATCH /members + PATCH /fireteams calls per
# wave; prevents per-request connection churn when members complete in bursts.
_http_client: Optional[httpx.AsyncClient] = None

def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=5.0,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _http_client


# ---------- Helpers ----------

def _mk_member_id(idx: int) -> str:
    return f"member-{idx}-{uuid4().hex[:8]}"


def _validate_mutex_groups(plan_members: list) -> Optional[str]:
    """Return None if OK, or a diagnostic string if two members claim the same
    singleton tool group (e.g. two members both using metasploit)."""
    for group, tools in TOOL_MUTEX_GROUPS.items():
        claimers = []
        for m in plan_members:
            # A member "claims" a group if any of its declared skills overlaps the
            # group name, or if the group's tools are referenced by its skills.
            skills = [s.lower() for s in (m.get("skills") or [])]
            tool_keywords = {t.split("_", 1)[-1] for t in tools}
            if group.lower() in skills or any(k in skills for k in tool_keywords):
                claimers.append(m.get("name") or "(unnamed)")
        if len(claimers) > 1:
            return f"Multiple members claim mutex group '{group}': {claimers}"
    return None


def _build_member_state(
    parent_state: AgentState,
    spec: dict,
    member_id: str,
    fireteam_id: str,
) -> dict:
    """Construct a fresh FireteamMemberState dict from parent state + spec.

    When ``spec["_seed_plan"]`` or ``spec["_seed_single_tool"]`` is set (used
    by the approved-escalation redeploy path in
    :mod:`process_fireteam_confirmation_node`), the member skips the first
    LLM call and directly executes the operator-approved tool(s). This keeps
    the wave bound to the member's panel (no hijack of the parent's wave)
    and matches FIRETEAM.md §7.3.
    """
    # Per-member iteration budget is set **exclusively** by the project-level
    # FIRETEAM_MEMBER_MAX_ITERATIONS setting. The LLM's `max_iterations` in
    # the fireteam_plan JSON is ignored, because operators repeatedly found
    # the model conservatively picks small values (e.g. 12) even when the
    # project allows 20 — making the operator-facing setting feel broken.
    # If you want the model to have discretion back, reintroduce the
    # min(spec.max_iterations, project_cap) clamp here.
    _resolved_max_iter = int(get_setting("FIRETEAM_MEMBER_MAX_ITERATIONS", 15))

    base: dict = {
        "messages": [],
        "current_iteration": 0,
        "max_iterations": _resolved_max_iter,
        "task_complete": False,
        "completion_reason": None,

        # Inherited from parent (read-only)
        "current_phase": parent_state.get("current_phase", "informational"),
        "attack_path_type": parent_state.get("attack_path_type", ""),
        "user_id": parent_state.get("user_id", ""),
        "project_id": parent_state.get("project_id", ""),
        "session_id": parent_state.get("session_id", ""),
        "parent_target_info": dict(parent_state.get("target_info") or {}),
        "member_name": spec.get("name") or member_id,
        "member_id": member_id,
        "fireteam_id": fireteam_id,
        "skills": list(spec.get("skills") or []),
        "task": spec.get("task") or "",

        # Member-local
        "execution_trace": [],
        "target_info": dict(parent_state.get("target_info") or {}),
        "chain_findings_memory": [],
        "chain_failures_memory": [],

        # Confirmation escalation
        "_pending_confirmation": None,

        # Plan wave support (reused by execute_plan_node)
        "_current_plan": None,

        # Passive observability accumulator — no cap, just tracked for metrics.
        "tokens_used": 0,
        "input_tokens_used": 0,
        "output_tokens_used": 0,
        "_input_tokens_this_turn": 0,
        "_output_tokens_this_turn": 0,

        # Internal
        "_decision": None,
        "_current_step": None,
        "_last_chain_step_id": None,
        "_guardrail_blocked": False,
    }

    # Seed approved-escalation redeploys so the member jumps straight to tool
    # execution on its first graph step without an LLM round-trip. Matches
    # the normal fireteam_member_graph entry contract: having _current_plan
    # (or _current_step) set + _decision pre-populated lets the router dispatch
    # straight to execute.
    seed_plan = spec.get("_seed_plan")
    seed_single = spec.get("_seed_single_tool")
    if seed_plan and seed_plan.get("steps"):
        base["_current_plan"] = {
            "steps": [dict(s) for s in seed_plan["steps"]],
            "plan_rationale": seed_plan.get("plan_rationale", ""),
        }
        base["_decision"] = {
            "thought": "Executing operator-approved escalated plan.",
            "reasoning": seed_plan.get("plan_rationale", "operator approved"),
            "action": "plan_tools",
        }
    elif seed_single and seed_single.get("tool_name"):
        from uuid import uuid4 as _uuid4
        base["_current_step"] = {
            "step_id": _uuid4().hex,
            "iteration": 1,
            "phase": base["current_phase"],
            "tool_name": seed_single["tool_name"],
            "tool_args": dict(seed_single.get("tool_args") or {}),
            "thought": "Executing operator-approved escalated tool.",
            "reasoning": seed_single.get("rationale", "operator approved"),
        }
        base["_decision"] = {
            "thought": "Executing operator-approved escalated tool.",
            "reasoning": seed_single.get("rationale", "operator approved"),
            "action": "use_tool",
            "tool_name": seed_single["tool_name"],
            "tool_args": dict(seed_single.get("tool_args") or {}),
        }

    return base


def _result_from_final_state(final_state: dict, spec: dict, member_id: str, wall_s: float) -> dict:
    """Build a FireteamMemberResult dict from a terminal member state."""
    status: str
    completion_reason = final_state.get("completion_reason") or "complete"

    if completion_reason == "needs_confirmation":
        status = "needs_confirmation"
    elif completion_reason == "iteration_budget_exceeded":
        status = "partial"
    elif completion_reason.startswith("llm_error") or completion_reason.startswith("parse_error"):
        status = "error"
    elif completion_reason in ("deploy_forbidden_in_member", "requested_phase_escalation", "cannot_ask_in_member"):
        # These shouldn't leak but handle gracefully if they do.
        status = "partial"
    else:
        status = "success"

    # target_info_delta: new keys in final vs parent snapshot
    parent_snapshot = final_state.get("parent_target_info") or {}
    final_ti = final_state.get("target_info") or {}
    delta = {}
    for k, v in final_ti.items():
        if parent_snapshot.get(k) != v:
            delta[k] = v

    # Findings: prefer chain_findings_memory (populated if the member did
    # output analysis), fall back to empty. The ground truth lives in Neo4j
    # (written via chain_graph_writer with fireteam_id attribution), and the
    # report pipeline joins there directly — this field is a best-effort
    # denormalization for the FireteamMember.resultBlob dump.
    findings = []
    try:
        from state import ChainFindingExtract
        for f in (final_state.get("chain_findings_memory") or []):
            if isinstance(f, dict):
                findings.append(ChainFindingExtract(
                    finding_type=f.get("finding_type", "custom"),
                    severity=f.get("severity", "info"),
                    title=f.get("title", ""),
                    evidence=f.get("evidence", ""),
                    related_cves=f.get("related_cves") or [],
                    related_ips=f.get("related_ips") or [],
                    confidence=f.get("confidence", 80),
                    step_iteration=int(f.get("step_iteration") or 0),
                ))
    except Exception as e:
        logger.debug("findings conversion skipped: %s", e)

    return FireteamMemberResult(
        member_id=member_id,
        name=spec.get("name") or member_id,
        status=status,
        completion_reason=completion_reason,
        iterations_used=int(final_state.get("current_iteration") or 0),
        tokens_used=int(final_state.get("tokens_used") or 0),
        input_tokens_used=int(final_state.get("input_tokens_used") or 0),
        output_tokens_used=int(final_state.get("output_tokens_used") or 0),
        wall_clock_seconds=round(wall_s, 3),
        findings=findings,
        target_info_delta=delta,
        execution_trace_summary=[
            {"iteration": s.get("iteration"), "tool": s.get("tool_name"),
             "summary": str(s.get("output_summary", ""))[:200]}
            for s in (final_state.get("execution_trace") or [])
        ],
        last_chain_step_id=final_state.get("_last_chain_step_id"),
        pending_confirmation=final_state.get("_pending_confirmation"),
        error_message=None if status != "error" else completion_reason,
    ).model_dump()


def _cancelled_result(spec: dict, member_id: str, wall_s: float) -> dict:
    return FireteamMemberResult(
        member_id=member_id,
        name=spec.get("name") or member_id,
        status="cancelled",
        completion_reason="wave_cancelled",
        iterations_used=0,
        tokens_used=0,
        wall_clock_seconds=round(wall_s, 3),
    ).model_dump()


def _timeout_result(spec: dict, member_id: str, wall_s: float) -> dict:
    return FireteamMemberResult(
        member_id=member_id,
        name=spec.get("name") or member_id,
        status="timeout",
        completion_reason="wave_timeout",
        iterations_used=0,
        tokens_used=0,
        wall_clock_seconds=round(wall_s, 3),
    ).model_dump()


def _error_result(spec: dict, member_id: str, exc: BaseException, wall_s: float) -> dict:
    return FireteamMemberResult(
        member_id=member_id,
        name=spec.get("name") or member_id,
        status="error",
        completion_reason="unhandled_exception",
        iterations_used=0,
        tokens_used=0,
        wall_clock_seconds=round(wall_s, 3),
        error_message=str(exc),
    ).model_dump()


def _count_statuses(results: Iterable[dict]) -> dict:
    counts: dict = {}
    for r in results:
        s = r.get("status") or "unknown"
        counts[s] = counts.get(s, 0) + 1
    return counts


# Optional dev-only metrics dump. When FIRETEAM_METRICS_LOG=1 in the env,
# each wave appends one JSON line with wave stats to the given path. Cheap
# fire-and-forget; failures are swallowed so they never affect the agent.
_METRICS_PATH = os.environ.get("FIRETEAM_METRICS_PATH", "/tmp/fireteam_metrics.jsonl")


def _emit_metrics(record: dict) -> None:
    if os.environ.get("FIRETEAM_METRICS_LOG") != "1":
        return
    try:
        with open(_METRICS_PATH, "a") as f:
            f.write(_json.dumps(record, default=str) + "\n")
    except Exception as e:
        logger.debug("metrics emit failed: %s", e)


# ---------- Persistence (fire-and-forget Postgres writes) ----------

async def _persist_deploy(session_id: str, body: dict) -> Optional[str]:
    """POST the new fireteam + member rows. Returns the Fireteam.id or None."""
    try:
        resp = await _get_http_client().post(
            f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}/fireteams",
            json=body,
            headers=_INTERNAL_HEADERS,
        )
        if resp.status_code in (200, 201):
            return (resp.json() or {}).get("id")
        logger.warning("Fireteam persist failed (%s): %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("Fireteam persist error: %s", e)
    return None


async def _patch_member(session_id: str, fireteam_id_key: str, member_id_key: str, body: dict) -> None:
    try:
        await _get_http_client().patch(
            f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}"
            f"/fireteams/{fireteam_id_key}/members/{member_id_key}",
            json=body,
            headers=_INTERNAL_HEADERS,
        )
    except Exception as e:
        logger.warning("Fireteam member patch error: %s", e)


async def _patch_fireteam(session_id: str, fireteam_id_key: str, body: dict) -> None:
    try:
        await _get_http_client().patch(
            f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}"
            f"/fireteams/{fireteam_id_key}",
            json=body,
            headers=_INTERNAL_HEADERS,
        )
    except Exception as e:
        logger.warning("Fireteam patch error: %s", e)


# ---------- Main node ----------

async def fireteam_deploy_node(
    state: AgentState,
    config,
    *,
    member_graph,
    streaming_callbacks,
    neo4j_creds=None,
    graph_view_cyphers=None,
) -> dict:
    """Fan out N fireteam members concurrently. Returns merged results."""
    user_id, project_id, session_id = get_identifiers(state, config)
    plan_data = state.get("_current_fireteam_plan")
    if not plan_data or not plan_data.get("members"):
        logger.error("[%s] fireteam_deploy_node called with empty plan", session_id)
        return {"_current_fireteam_plan": None, "_current_fireteam_results": []}

    members = plan_data["members"]

    # Enforce per-wave cap from settings (independent of Pydantic).
    max_members = get_setting("FIRETEAM_MAX_MEMBERS", 5)
    if len(members) > max_members:
        logger.warning("[%s] fireteam plan exceeds max members (%d > %d); truncating",
                       session_id, len(members), max_members)
        members = members[:max_members]

    # Mutex group validation: abort and let parent re-plan.
    mutex_error = _validate_mutex_groups(members)
    if mutex_error:
        logger.warning("[%s] fireteam mutex conflict: %s", session_id, mutex_error)
        return {
            "_current_fireteam_plan": None,
            "_current_fireteam_results": [],
            "messages": [_system_msg(f"fireteam plan rejected: {mutex_error}. Revise plan.")],
        }

    iteration = state.get("current_iteration", 0)
    fireteam_id_key = f"fteam-{iteration}-{uuid4().hex[:8]}"
    plan_data["fireteam_id"] = fireteam_id_key

    max_concurrent = get_setting("FIRETEAM_MAX_CONCURRENT", 3)
    timeout_s = get_setting("FIRETEAM_TIMEOUT_SEC", 1800)
    sem = asyncio.Semaphore(max_concurrent)

    # ---- Observability: wave deploy header ----
    logger.info(f"\n{'=' * 80}")
    logger.info(
        f"[{session_id}] FIRETEAM DEPLOY wave={fireteam_id_key} "
        f"iteration={iteration} members={len(members)} "
        f"max_concurrent={max_concurrent} timeout_s={timeout_s} "
        f"phase={state.get('current_phase', 'informational')}"
    )
    # Iteration budget is uniform across all members in a wave — set by the
    # operator via FIRETEAM_MEMBER_MAX_ITERATIONS (see _build_member_state).
    _member_max_iter = int(get_setting("FIRETEAM_MEMBER_MAX_ITERATIONS", 15))
    logger.info(f"[{session_id}] plan_rationale: {plan_data.get('plan_rationale', '')[:300]}")
    logger.info(f"[{session_id}] per-member iteration cap: {_member_max_iter}")
    for i, m in enumerate(members):
        logger.info(
            f"[{session_id}]   member[{i}]: name={m.get('name')!r} "
            f"skills={m.get('skills') or []} "
            f"task={(m.get('task') or '')[:200]}"
        )
    logger.info(f"{'=' * 80}")

    # Propagate ContextVars BEFORE create_task so children inherit them.
    set_tenant_context(user_id, project_id)
    set_phase_context(state.get("current_phase", "informational"))
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # Assign stable member IDs up front (used by UI, DB, Neo4j).
    member_ids = [_mk_member_id(i) for i in range(len(members))]

    streaming_cb = (streaming_callbacks or {}).get(session_id)
    if streaming_cb:
        try:
            await streaming_cb.on_fireteam_deployed(
                fireteam_id=fireteam_id_key,
                iteration=iteration,
                plan_rationale=plan_data.get("plan_rationale", ""),
                members=[
                    {"member_id": mid, "name": m.get("name"), "task": m.get("task"),
                     "skills": m.get("skills") or [], "max_iterations": _member_max_iter}
                    for mid, m in zip(member_ids, members)
                ],
            )
        except Exception as e:
            logger.warning("[%s] fireteam_deployed event error: %s", session_id, e)

    # Persist deploy to Postgres (best-effort; failure does not kill run).
    await _persist_deploy(
        session_id,
        {
            "fireteamIdKey": fireteam_id_key,
            "fireteamNumber": iteration,
            "iteration": iteration,
            "memberCount": len(members),
            "planRationale": plan_data.get("plan_rationale", ""),
            "userId": user_id,
            "projectId": project_id,
            "members": [
                {"memberIdKey": mid, "name": m.get("name") or mid, "task": m.get("task") or "",
                 "skills": m.get("skills") or []}
                for mid, m in zip(member_ids, members)
            ],
        },
    )

    # ---- Per-member runner ----
    # Import here to avoid circular imports at module load time.
    from orchestrator_helpers.member_streaming import scoped_member_streaming
    from orchestrator_helpers.streaming import emit_streaming_events

    async def _run_one(spec: dict, member_id: str) -> dict:
        async with sem:
            member_state = _build_member_state(state, spec, member_id, fireteam_id_key)
            t0 = time.monotonic()
            logger.info(
                "[%s] wave=%s member=%s (%s) STARTED skills=%s max_iter=%s",
                session_id, fireteam_id_key, member_id,
                spec.get("name") or member_id,
                spec.get("skills") or [],
                _member_max_iter,
            )
            if streaming_cb:
                try:
                    await streaming_cb.on_fireteam_member_started(
                        fireteam_id=fireteam_id_key,
                        member_id=member_id,
                        name=spec.get("name") or member_id,
                    )
                except Exception:
                    pass
            final_state = dict(member_state)
            try:
                # Activate the member-scoped streaming proxy. While this
                # context is active, resolve_streaming_callback returns the
                # proxy, so execute_tool_node/execute_plan_node lookups emit
                # FIRETEAM_TOOL_START/COMPLETE instead of TOOL_START/COMPLETE,
                # scoping all events to the correct member panel in the UI.
                with scoped_member_streaming(
                    streaming_cb,
                    fireteam_id=fireteam_id_key,
                    member_id=member_id,
                    member_name=spec.get("name") or member_id,
                ) as member_scoped_cb:
                    # Track merged state + emit streaming events per yield.
                    # We call emit_streaming_events with the member-scoped proxy
                    # so _current_step / _decision from inner think/execute
                    # nodes become FIRETEAM_* events at the WS layer.
                    async for event in member_graph.astream(member_state):
                        if isinstance(event, dict):
                            for _node, node_update in event.items():
                                if isinstance(node_update, dict):
                                    final_state.update(node_update)
                                    if member_scoped_cb is not None:
                                        try:
                                            await emit_streaming_events(
                                                final_state, member_scoped_cb,
                                            )
                                        except Exception as e:
                                            logger.debug("member emit error: %s", e)
                result = _result_from_final_state(final_state, spec, member_id, time.monotonic() - t0)
                logger.info(
                    "[%s] wave=%s member=%s (%s) FINISHED status=%s iter=%s tokens=%s "
                    "findings=%s wall_s=%.2f reason=%r",
                    session_id, fireteam_id_key, member_id, result.get("name"),
                    result.get("status"), result.get("iterations_used", 0),
                    result.get("tokens_used", 0), len(result.get("findings") or []),
                    result.get("wall_clock_seconds", 0.0), result.get("completion_reason"),
                )
            except asyncio.CancelledError:
                logger.info("[%s] wave=%s member=%s CANCELLED", session_id, fireteam_id_key, member_id)
                # Propagate cancellation to gather.
                raise
            except Exception as exc:
                logger.exception("[%s] wave=%s member=%s CRASHED", session_id, fireteam_id_key, member_id)
                result = _error_result(spec, member_id, exc, time.monotonic() - t0)

            # Persist member completion (best-effort).
            await _patch_member(session_id, fireteam_id_key, member_id, {
                "status": result["status"],
                "completionReason": result.get("completion_reason"),
                "iterationsUsed": result.get("iterations_used", 0),
                "tokensUsed": result.get("tokens_used", 0),
                "findingsCount": len(result.get("findings") or []),
                "wallClockSeconds": result.get("wall_clock_seconds", 0.0),
                "errorMessage": result.get("error_message"),
                "resultBlob": result,
            })

            if streaming_cb:
                try:
                    await streaming_cb.on_fireteam_member_completed(
                        fireteam_id=fireteam_id_key,
                        member_id=member_id,
                        name=result.get("name") or member_id,
                        status=result["status"],
                        iterations_used=result.get("iterations_used", 0),
                        tokens_used=result.get("tokens_used", 0),
                        input_tokens_used=result.get("input_tokens_used", 0),
                        output_tokens_used=result.get("output_tokens_used", 0),
                        findings_count=len(result.get("findings") or []),
                        wall_clock_seconds=result.get("wall_clock_seconds", 0.0),
                        error_message=result.get("error_message"),
                    )
                except Exception:
                    pass
            return result

    tasks = [
        asyncio.create_task(_run_one(m, mid), name=f"fireteam-{fireteam_id_key}-{mid}")
        for m, mid in zip(members, member_ids)
    ]

    wave_start = time.monotonic()
    results: list = []
    try:
        raw = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout_s,
        )
        results = [
            r if isinstance(r, dict) else _error_result(m, mid, r, time.monotonic() - wave_start)
            for r, m, mid in zip(raw, members, member_ids)
        ]
    except asyncio.TimeoutError:
        logger.warning("[%s] fireteam %s timed out after %ds", session_id, fireteam_id_key, timeout_s)
        # Wake any members currently parked on the confirmation registry so
        # t.cancel() below doesn't race a forever-blocked asyncio.wait().
        from orchestrator_helpers.fireteam_confirmation_registry import drop_wave as _drop_wave
        _drop_wave(session_id, fireteam_id_key, reason="wave_timeout")
        for t in tasks:
            if not t.done():
                t.cancel()
        # Drain cancelled tasks so their exceptions are consumed and finally
        # blocks run. Without this we get "exception was never retrieved"
        # warnings on task GC.
        await asyncio.gather(*tasks, return_exceptions=True)
        # Collect completed results; mark outstanding as timeout.
        for t, m, mid in zip(tasks, members, member_ids):
            try:
                if t.done() and not t.cancelled():
                    results.append(t.result() if isinstance(t.result(), dict)
                                   else _error_result(m, mid, t.result(), time.monotonic() - wave_start))
                else:
                    results.append(_timeout_result(m, mid, time.monotonic() - wave_start))
            except asyncio.CancelledError:
                results.append(_timeout_result(m, mid, time.monotonic() - wave_start))
            except Exception as e:
                results.append(_error_result(m, mid, e, time.monotonic() - wave_start))
    except asyncio.CancelledError:
        logger.info("[%s] fireteam %s cancelled by operator", session_id, fireteam_id_key)
        from orchestrator_helpers.fireteam_confirmation_registry import drop_wave as _drop_wave
        _drop_wave(session_id, fireteam_id_key, reason="wave_cancelled")
        for t in tasks:
            if not t.done():
                t.cancel()
        # Drain the cancelled tasks so their CancelledError / finally blocks
        # run cleanly. Without this, each pending task surfaces as an
        # "exception was never retrieved" warning on GC.
        await asyncio.gather(*tasks, return_exceptions=True)
        for m, mid in zip(members, member_ids):
            results.append(_cancelled_result(m, mid, time.monotonic() - wave_start))
        wall = time.monotonic() - wave_start
        # Persist per-member cancellation to Postgres BEFORE the wave-level
        # patch. Without this, on session restore (or switch-and-return) the
        # /fireteams API returns each member with its original `running`
        # status — so the UI rebuild shows specialists "still running" even
        # though their tasks died minutes ago. The live WS events flip the
        # UI on cancel, but the DB source-of-truth needs updating too.
        for r, m, mid in zip(results, members, member_ids):
            await _patch_member(session_id, fireteam_id_key, mid, {
                "status": r.get("status", "cancelled"),
                "completionReason": r.get("completion_reason") or "wave_cancelled",
                "iterationsUsed": r.get("iterations_used", 0),
                "tokensUsed": r.get("tokens_used", 0),
                "findingsCount": len(r.get("findings") or []),
                "wallClockSeconds": r.get("wall_clock_seconds", 0.0),
                "errorMessage": r.get("error_message"),
                "resultBlob": r,
            })
        await _patch_fireteam(session_id, fireteam_id_key, {
            "status": "cancelled",
            "statusCounts": _count_statuses(results),
            "wallClockSeconds": round(wall, 3),
        })
        # Notify the UI BEFORE re-raising. Without these emits the frontend
        # never learns the wave or its members are done; cards stay spinning
        # on `running` even though tasks are dead. Emit per-member cancelled
        # first, then the wave-level cancelled event. Suppress any emit
        # failures so we don't mask the CancelledError.
        if streaming_cb:
            for r, m, mid in zip(results, members, member_ids):
                try:
                    await streaming_cb.on_fireteam_member_completed(
                        fireteam_id=fireteam_id_key,
                        member_id=mid,
                        name=r.get("name") or m.get("name") or mid,
                        status=r.get("status", "cancelled"),
                        iterations_used=r.get("iterations_used", 0),
                        tokens_used=r.get("tokens_used", 0),
                        input_tokens_used=r.get("input_tokens_used", 0),
                        output_tokens_used=r.get("output_tokens_used", 0),
                        findings_count=len(r.get("findings") or []),
                        wall_clock_seconds=r.get("wall_clock_seconds", 0.0),
                        error_message=r.get("error_message"),
                    )
                except Exception:
                    logger.exception("cancel emit member_completed failed")
            try:
                await streaming_cb.on_fireteam_completed(
                    fireteam_id=fireteam_id_key,
                    total=len(results),
                    status_counts=_count_statuses(results),
                    wall_clock_seconds=round(wall, 3),
                )
            except Exception:
                logger.exception("cancel emit fireteam_completed failed")
        raise

    wall = time.monotonic() - wave_start
    status_counts = _count_statuses(results)

    # Overall fireteam status: timeout if any timeout, else completed.
    if status_counts.get("timeout", 0) > 0:
        overall_status = "timeout"
    else:
        overall_status = "completed"

    await _patch_fireteam(session_id, fireteam_id_key, {
        "status": overall_status,
        "statusCounts": status_counts,
        "wallClockSeconds": round(wall, 3),
    })

    if streaming_cb:
        try:
            await streaming_cb.on_fireteam_completed(
                fireteam_id=fireteam_id_key,
                total=len(results),
                status_counts=status_counts,
                wall_clock_seconds=round(wall, 3),
            )
        except Exception:
            pass

    logger.info("[%s] fireteam %s complete: %s in %.2fs",
                session_id, fireteam_id_key, status_counts, wall)

    # Dev-only metrics line (gated on FIRETEAM_METRICS_LOG env).
    _emit_metrics({
        "ts": time.time(),
        "fireteam_id": fireteam_id_key,
        "session_id": session_id,
        "user_id": user_id,
        "project_id": project_id,
        "iteration": iteration,
        "n_members": len(members),
        "wall_clock_seconds": round(wall, 3),
        "status_counts": status_counts,
        "members": [
            {
                "member_id": r.get("member_id"),
                "name": r.get("name"),
                "status": r.get("status"),
                "iterations_used": r.get("iterations_used"),
                "tokens_used": r.get("tokens_used"),
                "findings_count": len(r.get("findings") or []),
                "wall_s": r.get("wall_clock_seconds"),
            }
            for r in results
        ],
    })

    return {
        "_current_fireteam_plan": plan_data,
        "_current_fireteam_results": results,
        "_fireteam_id": fireteam_id_key,
    }

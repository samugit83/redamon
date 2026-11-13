"""WebSocket handler for the triage agent."""

import asyncio
import json
import logging
import uuid
from fastapi import WebSocket, WebSocketDisconnect

from cypherfix_errors import reject_websocket, safe_error
from .orchestrator import TriageOrchestrator
from .state import TriageState

logger = logging.getLogger(__name__)


class TriageStreamingCallback:
    """Streams triage events to the frontend via WebSocket."""

    def __init__(self, websocket: WebSocket):
        self.ws = websocket

    async def on_phase(self, phase: str, description: str, progress: int = 0):
        await self._send("triage_phase", {
            "phase": phase, "description": description, "progress": progress,
        })

    async def on_finding(self, finding: dict):
        await self._send("triage_finding", finding)

    async def on_thinking(self, thought: str):
        await self._send("thinking", {"thought": thought})

    async def on_thinking_chunk(self, chunk: str):
        await self._send("thinking_chunk", {"chunk": chunk})

    async def on_tool_start(self, tool_name: str, tool_args: dict):
        display_args = {
            k: v[:200] if isinstance(v, str) and len(v) > 200 else v
            for k, v in tool_args.items()
        }
        await self._send("tool_start", {"tool_name": tool_name, "tool_args": display_args})

    async def on_tool_complete(self, tool_name: str, success: bool, output_summary: str):
        await self._send("tool_complete", {
            "tool_name": tool_name, "success": success,
            "output_summary": output_summary[:500],
        })

    async def on_complete(self, total: int, by_severity: dict, by_type: dict, summary: str,
                          **notices):
        await self._send("triage_complete", {
            "total_remediations": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "summary": summary,
            **notices,
        })

    async def on_error(self, message: str, recoverable: bool = True, code: str = "",
                       **details):
        await self._send("error", {
            "message": message, "recoverable": recoverable, "code": code, **details,
        })

    async def _send(self, msg_type: str, payload: dict):
        try:
            await self.ws.send_json({"type": msg_type, "payload": payload})
        except Exception:
            pass


class TriageRun:
    """A triage run, whose lifetime is the RUN's, not the browser tab's.

    The run used to be owned by the websocket: closing the tab cancelled the
    task mid-flight, so navigating away from the Priority Board tab silently threw
    away a multi-minute, paid-for LLM run and left no verdicts behind.

    The task now lives here instead. Every tab open on the project ATTACHES its
    socket for progress and detaches when it goes away; only an explicit Stop
    cancels the work. Events go to all of them, because a second tab (the board
    and /cypherfix side by side) used to take the run over, and the first then
    never heard its end. They are also recorded as they happen so a tab that
    reconnects can be caught up on what it missed.

    Process-local, which matches the deployment: triage runs inside the one agent
    container. A multi-replica agent would need this in Postgres or Redis.
    """

    def __init__(self, project_id: str, trigger: str = "app", token_id: str | None = None):
        self.project_id = project_id
        self.task: asyncio.Task | None = None
        self.orchestrator: TriageOrchestrator | None = None
        self.sockets: list[WebSocket] = []
        #: running | completed | error | stopped
        self.status = "running"
        self.last_phase: dict | None = None
        self.findings: list = []
        self.terminal: tuple[str, dict] | None = None  # (msg_type, payload)
        #: Who started it, for the banner and the audit: `app` or `mcp`.
        self.trigger = trigger
        self.token_id = token_id
        #: Set once the webapp has authorised the run (or refused it), so a
        #: headless start can answer with the run id.
        self.authorized = asyncio.Event()
        self.run_id: str = ""
        self.start_error: str = ""

    @property
    def is_active(self) -> bool:
        return self.task is not None and not self.task.done()

    @property
    def is_publishing(self) -> bool:
        return bool(self.last_phase) and self.last_phase.get("phase") == "publishing"

    def attach(self, websocket: WebSocket) -> None:
        if not self.is_attached(websocket):
            self.sockets.append(websocket)

    def detach(self, websocket: WebSocket) -> None:
        """Drop this one socket without touching the task. Idempotent.

        By identity, so a stale socket closing never detaches another tab.
        """
        self.sockets = [s for s in self.sockets if s is not websocket]

    def is_attached(self, websocket: WebSocket) -> bool:
        return any(s is websocket for s in self.sockets)

    def record(self, msg_type: str, payload: dict) -> None:
        """Keep the state a reconnecting tab needs to catch up."""
        if msg_type == "triage_phase":
            self.last_phase = payload
        elif msg_type == "triage_finding":
            self.findings.append(payload)
        elif msg_type == "triage_complete":
            self.status = "completed"
            self.terminal = (msg_type, payload)
        elif msg_type == "error":
            self.status = "error"
            self.terminal = (msg_type, payload)
        elif msg_type == "stopped":
            self.status = "stopped"
            self.terminal = (msg_type, payload)

    async def send(self, msg_type: str, payload: dict) -> None:
        """Forward to every attached socket. Never raises.

        A detached run keeps working; its events simply have nowhere to go until
        a tab reconnects, which is the whole point. A socket that fails is
        dropped, and the others still get the event.
        """
        for socket in list(self.sockets):
            try:
                await socket.send_json({"type": msg_type, "payload": payload})
            except Exception:
                self.detach(socket)

    async def replay(self, websocket: WebSocket) -> None:
        """Catch a freshly attached tab up on a run already in progress."""
        try:
            for finding in self.findings:
                await websocket.send_json({"type": "triage_finding", "payload": finding})
            if self.last_phase:
                await websocket.send_json({"type": "triage_phase", "payload": self.last_phase})
            if self.terminal:
                msg_type, payload = self.terminal
                await websocket.send_json({"type": msg_type, "payload": payload})
        except Exception:
            pass


class TriageRunCallback:
    """Orchestrator callback bound to a RUN rather than a socket."""

    def __init__(self, run: TriageRun):
        self.run = run

    async def on_authorized(self, run_id: str):
        self.run.run_id = run_id
        self.run.authorized.set()

    async def on_start_refused(self, reason: str):
        self.run.start_error = str(reason or "")[:300]
        self.run.authorized.set()

    async def on_phase(self, phase: str, description: str, progress: int = 0):
        await self._send("triage_phase", {
            "phase": phase, "description": description, "progress": progress,
        })

    async def on_finding(self, finding: dict):
        await self._send("triage_finding", finding)

    async def on_thinking(self, thought: str):
        await self._send("thinking", {"thought": thought})

    async def on_thinking_chunk(self, chunk: str):
        await self._send("thinking_chunk", {"chunk": chunk})

    async def on_tool_start(self, tool_name: str, tool_args: dict):
        display_args = {
            k: v[:200] if isinstance(v, str) and len(v) > 200 else v
            for k, v in tool_args.items()
        }
        await self._send("tool_start", {"tool_name": tool_name, "tool_args": display_args})

    async def on_tool_complete(self, tool_name: str, success: bool, output_summary: str):
        await self._send("tool_complete", {
            "tool_name": tool_name, "success": success,
            "output_summary": output_summary[:500],
        })

    async def on_complete(self, total: int, by_severity: dict, by_type: dict, summary: str,
                          **notices):
        await self._send("triage_complete", {
            "total_remediations": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "summary": summary,
            **notices,
        })

    async def on_error(self, message: str, recoverable: bool = True, code: str = "",
                       **details):
        await self._send("error", {
            "message": message, "recoverable": recoverable, "code": code, **details,
        })

    async def on_stopped(self):
        await self._send("stopped", {})

    async def _send(self, msg_type: str, payload: dict):
        self.run.record(msg_type, payload)
        await self.run.send(msg_type, payload)


#: In-flight and just-finished runs, keyed by project. A finished run is kept so
#: a tab that reconnects after the fact still sees the outcome; it is evicted
#: once replayed or when the next run starts.
_RUNS: dict[str, TriageRun] = {}

#: Kept as the single-flight view over the registry so existing callers and
#: tests keep a stable name for "is this project busy".
_TRIAGE_IN_FLIGHT: set = set()


def _active_run(project_id: str) -> TriageRun | None:
    """The run still working for this project, or None."""
    run = _RUNS.get(project_id)
    return run if run is not None and run.is_active else None


def _claim_triage_slot(project_id: str) -> bool:
    """Take the run slot for a project. False when one is already running.

    No lock is needed around the check-and-add: asyncio does not preempt a
    coroutine between two statements, and every caller shares the event loop.
    """
    if project_id in _TRIAGE_IN_FLIGHT:
        return False
    _TRIAGE_IN_FLIGHT.add(project_id)
    return True


def _release_triage_slot(project_id: str) -> None:
    """Free the slot. Safe to call twice."""
    _TRIAGE_IN_FLIGHT.discard(project_id)


#: What a Stop answers while the run is writing its results.
PUBLISHING_REFUSAL = "the run is publishing and will finish in moments"

#: What a start answers while the previous run is still recording its outcome.
STILL_FINISHING = ("the previous triage run is still finishing; "
                   "retry in a minute")


def stop_project_run(project_id: str) -> dict:
    """Cancel the in-flight run for a project, from outside the socket.

    Called by `POST /triage/runs/stop` (an MCP stop) and by `/graph/triage` op
    `stop_run` when the webapp is about to delete the project (X12). Without it
    the run would keep working against a project that is being deleted, and
    only notice at its next heartbeat.

    REFUSED once the run is publishing: a cancel then would leave half the
    batches on the board and no fix list (B17). The publish takes moments.

    Cancelling is enough otherwise: the run's own `finally` releases the slot
    and reports the outcome, and its publish and heartbeat calls fail closed
    once the project row is gone.
    """
    run = _RUNS.get(project_id)
    if run is None or not run.is_active:
        return {"stopped": False, "reason": "no run in progress"}
    if run.is_publishing:
        return {"stopped": False, "reason": "publishing", "runId": run.run_id}
    refusal = _stop_refusal(run)
    if refusal is not None:
        return refusal
    run.status = "stopped"
    if run.task is not None:
        run.task.cancel()
    return {"stopped": True, "runId": run.run_id}


def _stop_refusal(run: TriageRun) -> dict | None:
    """A Stop for a run that is already ending: answered, never cancelled again.

    A second cancel lands in the run's `finally`, inside the `finish` call,
    and leaves the row `running` until its heartbeat expires.
    """
    if run.status == "stopped":
        return {"stopped": True, "runId": run.run_id}
    if run.status != "running":
        return {"stopped": False, "reason": "finishing", "runId": run.run_id}
    return None


def _new_state(user_id: str, project_id: str, session_id: str = "") -> TriageState:
    return {
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,
        "settings": {},
        "raw_data": {},
        "analysis_result": None,
        "status": "initializing",
        "current_phase": "",
        "error": None,
    }


def start_detached_run(user_id: str, project_id: str,
                       real_actor_user_id: str | None = None,
                       trigger: str = "app", token_id: str | None = None,
                       max_review_budget: int | None = None,
                       socket: WebSocket | None = None,
                       session_id: str = "",
                       actor_user_id: str | None = None) -> tuple:
    """Start a run whose lifetime is its own, or attach to the one going.

    The one start path, for the websocket (a person) and for
    `POST /triage/runs` (an MCP agent). Returns `(run, attached, refusal)`:
    `attached` when a run was already working for this project, `refusal` a
    reason and no run when the slot is still held by a run that is finishing.

    The slot is held until the old run has recorded its outcome, so a start
    right after a Stop gets a clear "still finishing" rather than the webapp's
    "a run is already in progress" (C19).

    `user_id` is the graph tenant, the project's owner: the run reads and
    publishes the owner's graph. `actor_user_id` is the person the run is for,
    recorded as its `actorUserId` (the tenant when absent, as before step 5.3);
    `real_actor_user_id` the admin behind an act-as.
    """
    running = _active_run(project_id)
    if running is not None:
        if socket is not None:
            running.attach(socket)
        return running, True, None

    if not _claim_triage_slot(project_id):
        return None, False, STILL_FINISHING

    run = TriageRun(project_id, trigger=trigger, token_id=token_id)
    if socket is not None:
        run.attach(socket)
    _RUNS[project_id] = run

    orchestrator = TriageOrchestrator(
        user_id=user_id, project_id=project_id,
        callback=TriageRunCallback(run),
        actor_user_id=actor_user_id,
        real_actor_user_id=real_actor_user_id,
        trigger=trigger, token_id=token_id,
        max_review_budget=max_review_budget,
    )
    run.orchestrator = orchestrator
    state = _new_state(user_id, project_id, session_id)

    async def run_triage():
        try:
            await orchestrator.run(state)
        except asyncio.CancelledError:
            run.status = "stopped"
            # Every tab attached to the run, not only one that pressed Stop: an
            # MCP stop has no socket of its own to answer.
            await TriageRunCallback(run).on_stopped()
            raise
        except Exception as exc:
            logger.exception("Triage failed")
            run.status = "error"
            # The class and the phase it died in tell one bug from another in a
            # screenshot; the message stays in the log (it can quote target data).
            await TriageRunCallback(run).on_error(
                safe_error("internal_error"),
                recoverable=False,
                code="internal_error",
                error_class=type(exc).__name__,
                phase=str((run.last_phase or {}).get("phase") or ""),
            )
        finally:
            # The run owns its own teardown now that it outlives the socket:
            # nothing else is guaranteed to still be around when it ends. The
            # slot is released only here, after `finish` has been recorded.
            run.authorized.set()
            _release_triage_slot(run.project_id)
            try:
                await orchestrator.cleanup()
            except Exception:
                logger.debug("Triage orchestrator cleanup failed", exc_info=True)

    run.task = asyncio.create_task(run_triage())
    # A task cancelled before its first step never runs its `finally`, so the
    # slot is also released when the task ends, however it ends.
    run.task.add_done_callback(lambda _task: _release_triage_slot(project_id))
    return run, False, None


async def handle_triage_websocket(websocket: WebSocket):
    """Main WebSocket handler for triage agent connections.

    STRIDE S4: same-origin + fail-closed ws-ticket gate BEFORE accept(). Identity
    is bound from the verified ticket claims, never the self-asserted init frame.
    """
    import sys as _sys
    from pathlib import Path as _Path
    _agentic = str(_Path(__file__).resolve().parents[1])
    if _agentic not in _sys.path:
        _sys.path.insert(0, _agentic)
    from ws_ticket import authorize_ws, cors_allowlist, ticket_tenant
    from websocket_api import PROXIED_SOCKETS

    _origin = websocket.headers.get("origin")
    _host = websocket.headers.get("host")
    _ticket = websocket.query_params.get("ticket")
    _ok, _claims, _reason = authorize_ws(_origin, _host, _ticket, cors_allowlist(), aud="cypherfix-triage")
    if not _ok:
        logger.warning("Rejected /ws/cypherfix-triage: %s (origin=%r)", _reason, _origin)
        await reject_websocket(websocket, _reason)
        return

    await websocket.accept()
    # Found again by POST /ws/close when the user's access ends.
    PROXIED_SOCKETS.add(websocket, "cypherfix-triage", _claims)
    callback = TriageStreamingCallback(websocket)

    state: TriageState | None = None
    orchestrator: TriageOrchestrator | None = None
    triage_task: asyncio.Task | None = None
    triage_project_id: str | None = None
    #: The run this socket is streaming, whether it started it or attached to
    #: one already going. Detached (not cancelled) when the socket closes.
    attached_run: TriageRun | None = None

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif msg_type == "init":
                # Identity is bound from the VERIFIED ticket claims (S4), not the
                # self-asserted init frame. The state's user is the graph tenant
                # (`ten`, the project's owner); the person is `sub`, recorded at start.
                state: TriageState = _new_state(
                    ticket_tenant(_claims), str(_claims["pid"]), str(_claims["sid"]))
                await websocket.send_json({
                    "type": "connected", "session_id": state["session_id"],
                })

                # Re-attach to a run this project already has going, so a tab
                # that was closed (or reloaded) mid-run picks the progress back
                # up instead of showing an idle screen over a live run.
                existing = _RUNS.get(state["project_id"])
                if existing is not None:
                    existing.attach(websocket)
                    attached_run = existing
                    await existing.replay(websocket)
                    if not existing.is_active:
                        # Terminal state has now been delivered; stop holding it.
                        _RUNS.pop(state["project_id"], None)

            elif msg_type == "start_triage":
                if not state:
                    await callback.on_error("Not initialized. Send init first.", recoverable=True)
                    continue

                # One triage run per project at a time. Two concurrent runs would
                # collect the same findings, classify them twice against a graph
                # that is still changing, race each other writing verdicts back,
                # and bill the operator for both.
                #
                # A second start ATTACHES to the run already going rather than
                # erroring: the caller wants the answer that run is already
                # computing, and after a reload the tab cannot know one exists.
                run, attached, refusal = start_detached_run(
                    state["user_id"], state["project_id"],
                    actor_user_id=str(_claims["sub"]),
                    # The person actually signed in, when an admin acts as
                    # the owner (B13). Absent from a ticket minted before
                    # the claim existed.
                    real_actor_user_id=(str(_claims["act"]) if _claims.get("act") else None),
                    trigger="app", socket=websocket, session_id=state["session_id"])
                if refusal:
                    await callback.on_error(refusal[:1].upper() + refusal[1:] + ".",
                                            recoverable=True)
                    continue
                attached_run = run
                triage_project_id = state["project_id"]
                orchestrator = run.orchestrator
                triage_task = run.task
                if attached:
                    await run.replay(websocket)

            elif msg_type == "stop":
                # Explicit operator intent is the ONLY thing that cancels a run.
                # Resolved through the registry so a reconnected tab can stop a
                # run it did not itself start.
                stopping = attached_run or _active_run(state["project_id"] if state else "")
                if stopping is not None and stopping.is_active:
                    if stopping.is_publishing:
                        # A cancel now would half-write the board (B17).
                        await callback.on_error(
                            PUBLISHING_REFUSAL[:1].upper() + PUBLISHING_REFUSAL[1:] + ".",
                            recoverable=True, code="publishing")
                        continue
                    if _stop_refusal(stopping) is not None:
                        continue
                    stopping.status = "stopped"
                    stopping.task.cancel()
                    # The slot stays held until the run's own `finally` has
                    # recorded the outcome; releasing it here let a new start
                    # race the old run's finish.
                    _RUNS.pop(stopping.project_id, None)
                    # An attached tab hears it from the run as it ends; a tab
                    # that stopped a run it was not attached to hears it here.
                    if not stopping.is_attached(websocket):
                        await websocket.send_json({"type": "stopped"})

    except WebSocketDisconnect:
        logger.info("Triage WebSocket disconnected")
    except Exception as e:
        logger.exception(f"Triage WebSocket error: {e}")
    finally:
        PROXIED_SOCKETS.remove(websocket)
        # DETACH, never cancel. Closing the tab used to kill the run mid-flight,
        # throwing away a multi-minute paid LLM run and leaving no verdicts. The
        # run keeps going with nowhere to stream to; the next tab re-attaches and
        # is replayed. Only an explicit Stop cancels.
        if attached_run is not None:
            attached_run.detach(websocket)
        # The slot and the orchestrator now belong to the run, and are released
        # by run_triage's own `finally`. Releasing them here would free the slot
        # under a run that is still going and let a second run start.
        if attached_run is None and triage_project_id:
            _release_triage_slot(triage_project_id)
        if attached_run is None and orchestrator:
            await orchestrator.cleanup()

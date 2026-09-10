"""WebSocket handler for the triage agent."""

import asyncio
import json
import logging
import uuid
from fastapi import WebSocket, WebSocketDisconnect

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

    async def on_complete(self, total: int, by_severity: dict, by_type: dict, summary: str):
        await self._send("triage_complete", {
            "total_remediations": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "summary": summary,
        })

    async def on_error(self, message: str, recoverable: bool = True):
        await self._send("error", {"message": message, "recoverable": recoverable})

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

    The task now lives here instead. A socket ATTACHES for progress and detaches
    when the tab goes away; only an explicit Stop cancels the work. Events are
    recorded as they happen so a tab that reconnects can be caught up on what it
    missed.

    Process-local, which matches the deployment: triage runs inside the one agent
    container. A multi-replica agent would need this in Postgres or Redis.
    """

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.task: asyncio.Task | None = None
        self.orchestrator: TriageOrchestrator | None = None
        self.socket: WebSocket | None = None
        #: running | completed | error | stopped
        self.status = "running"
        self.last_phase: dict | None = None
        self.findings: list = []
        self.terminal: tuple[str, dict] | None = None  # (msg_type, payload)

    @property
    def is_active(self) -> bool:
        return self.task is not None and not self.task.done()

    def attach(self, websocket: WebSocket) -> None:
        self.socket = websocket

    def detach(self, websocket: WebSocket) -> None:
        """Drop the socket without touching the task. Idempotent.

        Guarded on identity so a stale socket closing cannot detach the tab that
        has since reconnected.
        """
        if self.socket is websocket:
            self.socket = None

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

    async def send(self, msg_type: str, payload: dict) -> None:
        """Forward to the attached socket, if any. Never raises.

        A detached run keeps working; its events simply have nowhere to go until
        a tab reconnects, which is the whole point.
        """
        socket = self.socket
        if socket is None:
            return
        try:
            await socket.send_json({"type": msg_type, "payload": payload})
        except Exception:
            self.socket = None

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

    async def on_complete(self, total: int, by_severity: dict, by_type: dict, summary: str):
        await self._send("triage_complete", {
            "total_remediations": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "summary": summary,
        })

    async def on_error(self, message: str, recoverable: bool = True):
        await self._send("error", {"message": message, "recoverable": recoverable})

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
    from ws_ticket import authorize_ws, cors_allowlist

    _origin = websocket.headers.get("origin")
    _host = websocket.headers.get("host")
    _ticket = websocket.query_params.get("ticket")
    _ok, _claims, _reason = authorize_ws(_origin, _host, _ticket, cors_allowlist())
    if not _ok:
        logger.warning("Rejected /ws/cypherfix-triage: %s (origin=%r)", _reason, _origin)
        await websocket.close(code=1008)
        return

    await websocket.accept()
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
                # self-asserted init frame.
                state: TriageState = {
                    "user_id": str(_claims["sub"]),
                    "project_id": str(_claims["pid"]),
                    "session_id": str(_claims["sid"]),
                    "settings": {},
                    "raw_data": {},
                    "analysis_result": None,
                    "status": "initializing",
                    "current_phase": "",
                    "error": None,
                }
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
                # A second start now ATTACHES to the run already going rather
                # than erroring: the caller wants the answer that run is already
                # computing, and after a reload the tab cannot know one exists.
                running = _active_run(state["project_id"])
                if running is not None:
                    running.attach(websocket)
                    attached_run = running
                    await running.replay(websocket)
                    continue

                if not _claim_triage_slot(state["project_id"]):
                    await callback.on_error(
                        "A triage run is already in progress for this project. "
                        "Wait for it to finish, or stop it first.",
                        recoverable=True,
                    )
                    continue
                triage_project_id = state["project_id"]

                run = TriageRun(state["project_id"])
                run.attach(websocket)
                attached_run = run
                _RUNS[state["project_id"]] = run

                orchestrator = TriageOrchestrator(
                    user_id=state["user_id"],
                    project_id=state["project_id"],
                    callback=TriageRunCallback(run),
                )
                run.orchestrator = orchestrator

                async def run_triage(run=run, orchestrator=orchestrator, state=state):
                    try:
                        await orchestrator.run(state)
                    except asyncio.CancelledError:
                        run.status = "stopped"
                        raise
                    except Exception as e:
                        logger.exception("Triage failed")
                        run.status = "error"
                        await TriageRunCallback(run).on_error(str(e), recoverable=False)
                    finally:
                        # The run owns its own teardown now that it outlives the
                        # socket: nothing else is guaranteed to still be around
                        # when it ends.
                        _release_triage_slot(run.project_id)
                        try:
                            await orchestrator.cleanup()
                        except Exception:
                            logger.debug("Triage orchestrator cleanup failed", exc_info=True)

                run.task = asyncio.create_task(run_triage())
                triage_task = run.task

            elif msg_type == "stop":
                # Explicit operator intent is the ONLY thing that cancels a run.
                # Resolved through the registry so a reconnected tab can stop a
                # run it did not itself start.
                stopping = attached_run or _active_run(state["project_id"] if state else "")
                if stopping is not None and stopping.is_active:
                    stopping.status = "stopped"
                    stopping.task.cancel()
                    _RUNS.pop(stopping.project_id, None)
                    _release_triage_slot(stopping.project_id)
                    await websocket.send_json({"type": "stopped"})

    except WebSocketDisconnect:
        logger.info("Triage WebSocket disconnected")
    except Exception as e:
        logger.exception(f"Triage WebSocket error: {e}")
    finally:
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

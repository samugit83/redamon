"""Route Kali work to the sandbox of the person doing it (group 1, contract B.11).

Every unit of Kali work (a chat run, an MCP ``kali_exec`` job, a terminal, a triage
refresh, a Tradecraft fetch) runs in the sandbox of the PERSON doing it: the ticket's
``sub``, the MCP token's owner, who started a triage run. Never the tenant (the
project's owner): the tenant keys graph, traffic and credential reads, the person keys
the sandbox. An admin acting as a member works in the member's separate ``act_as``
view (TD-26).

The router asks the webapp gateway (``/api/internal/agent/sandbox/*``, master key) to
ensure that person's sandbox, holds a lease on it renewed in the background, and hands
out per-instance MCP clients, URLs and bearer headers. Each instance has its own
token, so one person's client never carries another's token.

There is no other sandbox to fall back to: an unreachable gateway, an outage or an
answer that is not exactly the person's own instance is ``SandboxUnavailable("error")``,
and a call without a person is ``SandboxUnavailable("no_user")``. A call is never sent
to another person's sandbox or another view of the same person.
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import logging
import os
import re
import uuid
import weakref
from collections import OrderedDict
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import httpx

import sandbox_contract as contract
from decision_check import current_run_actor
from kali_auth import kali_auth_headers_for

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

LEASE_RENEW_S = contract.LEASE_RENEW_S
RUN_KIND = "run"
#: A per-instance client connects to a sandbox that is already healthy, so it gets the
#: short budget of a reconnect (MCPToolsManager.reconnect), not the startup's 5 x 10 s.
CLIENT_CONNECT_RETRIES = 3
CLIENT_RETRY_DELAY_S = 2.0
JOBS_MAX = 4096
JOB_PHASES = ("starting", "running", "failed")

#: The orchestrator issues ``secrets.token_urlsafe(32)``; anything else is not a sandbox token.
_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,512}")
_JOB_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_CODE = re.compile(r"[a-z_]{1,64}")
#: A URL path: empty, or `/` and printable ASCII without space or backslash.
_PATH = re.compile(r"(?:/[!-\[\]-~]*)?")
_DETAIL_MAX = 300

#: Replaced by the tests with an httpx.MockTransport; None is httpx's own transport.
_transport: Optional[httpx.AsyncBaseTransport] = None

#: The person of a unit of work that is not a chat run (a /kali/exec job, the terminal
#: proxy, triage, Tradecraft jobs, session routes, the tunnel push). Set it with
#: ``for_person``; it wins over the run actor. None means unbound; "" is bound to no
#: person, which never falls back to the run actor.
current_sandbox_user: ContextVar[Optional[str]] = ContextVar("current_sandbox_user", default=None)
#: True when that unit of work is an admin acting as the person (a terminal ticket with
#: ``act``, a triage run with ``real_actor_user_id``).
current_sandbox_acting: ContextVar[bool] = ContextVar("current_sandbox_acting", default=False)
_current_scope: ContextVar[Optional["_RunScope"]] = ContextVar("sandbox_run_scope", default=None)


# =============================================================================
# Who and which view
# =============================================================================

def sandbox_user() -> str:
    """The person whose sandbox runs this work: ``current_sandbox_user``, else the chat
    run's person (the ticket's ``sub``), else "". Never the tenant."""
    user = current_sandbox_user.get()
    if user is not None:
        return user
    actor = current_run_actor.get()
    return actor.user_id if actor is not None and actor.user_id else ""


def sandbox_view() -> str:
    """``act_as`` when the work is an admin acting as the person, else ``own``.

    Either signal is enough: an entry point that names the person does not turn an act-as
    chat run back into the member's own view, which mounts the projects shared with the
    member that act-as access refuses (TD-26)."""
    if current_sandbox_acting.get():
        return contract.VIEW_ACT_AS
    actor = current_run_actor.get()
    if actor is not None and actor.actor_id:
        return contract.VIEW_ACT_AS
    return contract.VIEW_OWN


@contextmanager
def for_person(user_id: Optional[str], *, acting: bool = False):
    """Bind the person (and whether an admin acts as them) for the work inside, and
    unbind on exit. The binding stays in the current task and the tasks it creates.
    An empty or missing person binds "no person": the work is refused, never run as
    whoever the surrounding chat run belongs to."""
    user_token = current_sandbox_user.set(user_id if isinstance(user_id, str) else "")
    acting_token = current_sandbox_acting.set(bool(acting))
    try:
        yield
    finally:
        current_sandbox_acting.reset(acting_token)
        current_sandbox_user.reset(user_token)


# =============================================================================
# Errors and handles
# =============================================================================

def _clean(text) -> str:
    if not isinstance(text, str):
        return ""
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:_DETAIL_MAX]


class SandboxUnavailable(Exception):
    """The person's sandbox cannot serve this work.

    ``reason`` is one of the contract's ``UNAVAILABLE_REASONS``; ``limit`` the governor's
    refusal payload (ram, hard) or None; ``detail`` a short code or the governor's
    sentence, never a token."""

    def __init__(self, reason: str, *, limit: Optional[Mapping] = None, detail: str = ""):
        if reason not in contract.UNAVAILABLE_REASONS:
            raise ValueError(f"unknown sandbox unavailable reason {reason!r}")
        self.reason = reason
        self.limit = dict(limit) if limit else None
        self.detail = _clean(detail)
        super().__init__(f"sandbox unavailable ({reason})" + (f": {self.detail}" if self.detail else ""))


@dataclass(eq=False)
class SandboxHandle:
    """One person's view of one sandbox instance, as one unit of work holds it. The
    tokens never appear in ``repr``."""
    user_id: str
    view: str
    instance: str
    host: str
    token: str = field(repr=False)
    tunnel_token: str = field(repr=False)
    ports: Mapping[str, int]
    reverse_port: int
    project_id: Optional[str] = None
    kind: Optional[str] = None
    state: str = "running"
    fresh: bool = False
    stop_at: Optional[float] = None
    stop_reason: Optional[str] = None
    warn: bool = False
    stale: bool = False
    released: bool = False
    lease_id: Optional[str] = field(default=None, repr=False)
    scoped: bool = field(default=False, repr=False)
    _scope_ref: Optional[Callable[[], Optional["_RunScope"]]] = field(default=None, repr=False)
    _renew_task: Optional[asyncio.Task] = field(default=None, repr=False)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.user_id, self.view, self.instance)

    @property
    def usable(self) -> bool:
        return self.state == "running" and not self.stale and not self.released

    def _apply_lease(self, data: Mapping) -> None:
        stop_at = data.get("stop_at")
        if isinstance(stop_at, (int, float)) and not isinstance(stop_at, bool):
            self.stop_at = float(stop_at)
        self.warn = data.get("warn") is True


# =============================================================================
# Module state
# =============================================================================

_listeners: List[Callable] = []
#: Per-instance MCP clients, keyed by (person, view, instance).
_clients: Dict[Tuple[str, str, str], Any] = {}
_client_locks: Dict[Tuple[str, str, str], asyncio.Lock] = {}
#: The live per-user handles of each person (weak: a dropped handle disappears).
_live: Dict[str, "weakref.WeakSet[SandboxHandle]"] = {}
#: The instance each (person, view) was last answered with.
_current: Dict[Tuple[str, str], str] = {}
_renewals: set = set()


def _who(user_id: str, view: str) -> str:
    """A person in a log line: the view's sandbox key, never the raw user id."""
    try:
        return contract.sandbox_key(user_id, view)
    except ValueError:
        return "?"


# =============================================================================
# Status events
# =============================================================================

def add_status_listener(fn: Callable) -> Callable:
    """``fn({user_id, view, kind, project_id, session_id, state, reason, limit, detail})``
    on each ``starting``, ``ready`` and ``unavailable``; it may be a coroutine function.
    ``kind`` is the lease kind of the acquire or renewal (a job or Tradecraft lease taken
    inside a chat run's task is not the run's own), ``view`` the sandbox view."""
    if fn not in _listeners:
        _listeners.append(fn)
    return fn


def remove_status_listener(fn: Callable) -> None:
    if fn in _listeners:
        _listeners.remove(fn)


def _session_id() -> str:
    scope = _current_scope.get()
    if scope is not None and scope.session_id:
        return scope.session_id
    actor = current_run_actor.get()
    return actor.session_id if actor is not None and actor.session_id else ""


async def _emit(user_id: str, project_id: Optional[str], state: str, reason: Optional[str] = None,
                limit: Optional[Mapping] = None, detail: str = "",
                session_id: Optional[str] = None, *, view: str, kind: str) -> None:
    """``session_id`` None reads it from the current task (a renewal passes its own: it
    runs in a context of its own)."""
    event = {"user_id": user_id, "view": view, "kind": kind, "project_id": project_id,
             "session_id": _session_id() if session_id is None else session_id,
             "state": state, "reason": reason, "limit": dict(limit) if limit else None,
             "detail": detail or None}
    for fn in list(_listeners):
        try:
            result = fn(dict(event))
            if inspect.isawaitable(result):
                await asyncio.wait_for(result, timeout=contract.FANOUT_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001 - a listener never breaks the work
            logger.warning("[sandbox] status listener failed: %s", type(exc).__name__)


async def _refuse(user_id: str, project_id: Optional[str], reason: str, *, view: str, kind: str,
                  limit: Optional[Mapping] = None, detail: str = "") -> SandboxUnavailable:
    """The exception to raise, after its ``unavailable`` event (``no_user`` has none: it
    never reaches a browser)."""
    exc = SandboxUnavailable(reason, limit=limit, detail=detail)
    logger.warning("[sandbox] %s view=%s kind=%s unavailable reason=%s detail=%s",
                   _who(user_id, view) if user_id else "-", view, kind, reason, exc.detail)
    if reason != "no_user":
        await _emit(user_id, project_id, "unavailable", reason, exc.limit, exc.detail,
                    view=view, kind=kind)
    return exc


# =============================================================================
# The gateway client
# =============================================================================

class _Unreachable(Exception):
    """No answer is possible: no internal key, or the connection refused."""


class _GatewayError(Exception):
    """An outage behind a reachable gateway: no answer in time, or an answer that is not
    the contract's (a 5xx that is not the manager's own error, a 401, a 404 or any other
    4xx without a contract code). The webapp answers 503 ``orchestrator_unavailable``
    when it cannot ask the orchestrator."""


#: The manager's own 5xx codes: answers about this start, not an outage.
_PER_USER_5XX = (contract.ERR_IMAGE_MISSING, contract.ERR_START_FAILED, contract.ERR_START_TIMEOUT)
#: The 4xx codes the gateway's routes answer (B.9, B.10); any other 4xx is an outage.
_CONTRACT_4XX = (contract.ERR_RAM, contract.ERR_HARD, contract.ERR_USER_REFUSED,
                 contract.ERR_PROJECT_REFUSED, contract.ERR_INVALID_PROJECT_ID,
                 contract.ERR_INVALID_USER_ID, contract.ERR_INVALID_VIEW,
                 contract.ERR_UNKNOWN_INSTANCE, contract.ERR_NOT_RUNNING, contract.ERR_DRAINING)


def _http(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, transport=_transport)


def _refusal(data) -> Tuple[Optional[str], Mapping]:
    """The error code of an answer and the dict that holds it: the gateway's flat body,
    or FastAPI's ``{"detail": {...}}`` passed through."""
    if isinstance(data, dict):
        for src in (data, data.get("detail")):
            if isinstance(src, dict) and isinstance(src.get("code"), str):
                return src["code"], src
    return None, {}


async def _gateway(method: str, url: str, body: Optional[dict] = None,
                   timeout: float = contract.GATEWAY_TIMEOUT_S) -> Tuple[int, Any]:
    """One call to the webapp gateway. Each caller writes its whole URL out as an
    f-string on WEBAPP_API_URL, so the middleware's drift test reads the route and checks
    it is on the internal-key allowlist."""
    if not INTERNAL_HEADERS.get("X-Internal-Key"):
        raise _Unreachable("no_internal_key")
    try:
        async with _http(timeout) as client:
            resp = await client.request(method, url, json=body, headers=INTERNAL_HEADERS)
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        raise _Unreachable(type(exc).__name__) from None
    except Exception as exc:  # noqa: BLE001 - read timeouts, protocol errors
        raise _GatewayError(type(exc).__name__) from None
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        data = None
    code = _refusal(data)[0]
    if resp.status_code >= 500 and code not in _PER_USER_5XX:
        raise _GatewayError(_status_detail(resp.status_code, code))
    if 400 <= resp.status_code < 500 and code not in _CONTRACT_4XX:
        raise _GatewayError(_status_detail(resp.status_code, code))
    return resp.status_code, data


def _status_detail(status: int, code: Optional[str]) -> str:
    return f"status={status}" + (f" code={code}" if code and _CODE.fullmatch(code) else "")


# =============================================================================
# Handles from answers
# =============================================================================

def _valid_token(token) -> bool:
    return isinstance(token, str) and _TOKEN.fullmatch(token) is not None


def _running_handle(person: str, view: str, project_id: Optional[str], data: Mapping) -> Optional[SandboxHandle]:
    """The handle a 200 answer gives, or None when the answer is not exactly
    this person's view: another person, another view, a host that is not their
    container, no token, or the project the work needs not mounted."""
    instance = data.get("instance")
    if (data.get("user_id") != person or data.get("view") != view
            or not contract.valid_instance(instance)
            or data.get("host") != contract.container_name(person, view, instance)
            or data.get("state") != "running" or not _valid_token(data.get("token"))):
        return None
    projects = data.get("projects")
    if project_id is not None and (not isinstance(projects, list) or project_id not in projects):
        return None
    reverse = data.get("reverse_port")
    if not isinstance(reverse, int) or isinstance(reverse, bool) or not 1 <= reverse <= 65535:
        reverse = contract.DEFAULT_REVERSE_PORT
    tunnel = data.get("tunnel_token")
    stop_at = data.get("stop_at")
    stop_reason = data.get("stop_reason")
    return SandboxHandle(
        user_id=person, view=view, instance=instance, host=data["host"],
        token=data["token"], tunnel_token=tunnel if _valid_token(tunnel) else "",
        # The ports are the contract's: an answer cannot move a call to another port.
        ports=contract.PORTS, reverse_port=reverse,
        project_id=project_id, fresh=data.get("fresh") is True,
        stop_at=float(stop_at) if isinstance(stop_at, (int, float)) and not isinstance(stop_at, bool) else None,
        stop_reason=stop_reason if isinstance(stop_reason, str) and stop_reason in contract.STOP_REASONS else None,
        warn=data.get("warn") is True)


def _starting_handle(person: str, view: str, project_id: Optional[str], data: Mapping) -> SandboxHandle:
    instance = data["instance"]
    return SandboxHandle(
        user_id=person, view=view, instance=instance,
        host=contract.container_name(person, view, instance), token="", tunnel_token="",
        ports=contract.PORTS, reverse_port=contract.DEFAULT_REVERSE_PORT,
        project_id=project_id, state="starting", fresh=data.get("fresh") is True)


async def _ensure(person: str, view: str, project_id: Optional[str], wait: bool, kind: str):
    """One gateway ``ensure``: ("running", handle) or ("starting", handle). Raises
    SandboxUnavailable for every refusal, error and outage."""
    body: Dict[str, Any] = {"userId": person, "wait": bool(wait)}
    if project_id is not None:
        body["projectId"] = project_id
    if view == contract.VIEW_ACT_AS:
        body["actingAs"] = True
    try:
        status, data = await _gateway("POST", f"{WEBAPP_API_URL}/api/internal/agent/sandbox/ensure", body,
                                      timeout=contract.GATEWAY_ENSURE_TIMEOUT_S)
    except (_Unreachable, _GatewayError) as exc:
        what = "gateway_unreachable" if isinstance(exc, _Unreachable) else "gateway_error"
        raise await _refuse(person, project_id, "error", view=view, kind=kind,
                            detail=f"{what} {exc}") from None

    code, src = _refusal(data)
    if status == 200 and isinstance(data, dict):
        handle = _running_handle(person, view, project_id, data)
        if handle is not None:
            return "running", handle
        logger.error("[sandbox] %s view=%s: the gateway's answer is not this person's sandbox",
                     _who(person, view), view)
        raise await _refuse(person, project_id, "error", view=view, kind=kind,
                            detail="gateway_answer_mismatch")
    if (status == 202 and isinstance(data, dict) and data.get("state") == "starting"
            and contract.valid_instance(data.get("instance"))):
        return "starting", _starting_handle(person, view, project_id, data)
    if status == 409 and code in (contract.ERR_RAM, contract.ERR_HARD):
        limit = {k: src[k] for k in contract.LIMIT_PAYLOAD_KEYS if k in src}
        reason = "ram" if code == contract.ERR_RAM else "hard"
        raise await _refuse(person, project_id, reason, view=view, kind=kind, limit=limit or None,
                            detail=src.get("detail") if isinstance(src.get("detail"), str) else code)
    if status == 403 and code in (contract.ERR_USER_REFUSED, contract.ERR_PROJECT_REFUSED):
        raise await _refuse(person, project_id, "refused", view=view, kind=kind, detail=code)
    raise await _refuse(person, project_id, "error", view=view, kind=kind,
                        detail=_status_detail(status, code))


# =============================================================================
# Leases
# =============================================================================

async def _lease_call(person: str, instance: str, lease_id: str, kind: str) -> Tuple[str, Optional[Mapping]]:
    """Take or renew (one idempotent upsert): "ok", "gone" (the instance stopped),
    "draining" (this id is unknown to a draining instance), "refused" (the person may no
    longer use a sandbox) or "transient"."""
    body = {"userId": person, "instance": instance, "leaseId": lease_id, "kind": kind}
    try:
        status, data = await _gateway("POST", f"{WEBAPP_API_URL}/api/internal/agent/sandbox/lease", body)
    except (_Unreachable, _GatewayError) as exc:
        logger.info("[sandbox] lease call failed (%s); retried at the next renewal", exc)
        return "transient", None
    code, _src = _refusal(data)
    if status == 200 and isinstance(data, dict):
        return "ok", data
    if (status == 409 and code == contract.ERR_NOT_RUNNING) or (status == 404 and code == contract.ERR_UNKNOWN_INSTANCE):
        return "gone", None
    if status == 409 and code == contract.ERR_DRAINING:
        return "draining", None
    if status == 403 and code in (contract.ERR_USER_REFUSED, contract.ERR_PROJECT_REFUSED):
        return "refused", None
    logger.info("[sandbox] lease call answered %s; retried at the next renewal", _status_detail(status, code))
    return "transient", None


def _cancel_quietly(task: Optional[asyncio.Task]) -> None:
    if task is None or task.done():
        return
    try:
        task.cancel()
    except Exception:  # noqa: BLE001 - its loop may be closed (a finalizer at exit)
        pass


def _cancel_from_finalizer(loop: asyncio.AbstractEventLoop, task: asyncio.Task) -> None:
    """A dropped handle's finalizer: the garbage collector may run it on any thread, and a
    task may only be cancelled from its own loop's thread."""
    if task.done():
        return
    try:
        loop.call_soon_threadsafe(_cancel_quietly, task)
    except RuntimeError:  # the loop is closed (interpreter exit): nothing left to renew
        pass


def _start_renewal(handle: SandboxHandle, session_id: str) -> None:
    """One renew task per handle. It holds only a weak reference to the handle and runs
    in an empty context: the acquirer's context holds its run scope, which holds the
    handle, so inheriting it would keep the handle alive and renew it forever. A handle
    dropped without ``release`` therefore stops its renewals (its lease then expires)."""
    loop = asyncio.get_running_loop()
    task = loop.create_task(
        _renew_loop(weakref.ref(handle), handle.user_id, handle.view, handle.instance,
                    handle.lease_id, handle.kind, handle.project_id, session_id),
        context=contextvars.Context())
    handle._renew_task = task
    _renewals.add(task)
    task.add_done_callback(_renewals.discard)
    weakref.finalize(handle, _cancel_from_finalizer, loop, task)


async def _renew_loop(ref, person, view, instance, lease_id, kind, project_id, session_id) -> None:
    while True:
        try:
            if not await _renew_once(ref, person, view, instance, lease_id, kind, project_id, session_id):
                return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a bug here must not end the renewals quietly
            logger.warning("[sandbox] lease renewal failed: %s", type(exc).__name__)


async def _renew_once(ref, person, view, instance, lease_id, kind, project_id, session_id) -> bool:
    await asyncio.sleep(LEASE_RENEW_S)
    alive = ref()
    if alive is None or not alive.usable:
        return False
    del alive
    outcome, data = await _lease_call(person, instance, lease_id, kind)
    handle = ref()
    if handle is None or not handle.usable:
        return False
    if outcome == "ok":
        handle._apply_lease(data)
        return True
    if outcome == "transient":
        return True
    # A stopped instance (or a person who lost access) takes every handle on it along;
    # an id a draining instance no longer knows is this handle's alone.
    _retire(handle, whole_instance=outcome != "draining")
    await _emit(person, project_id, "unavailable", "refused" if outcome == "refused" else "stopped",
                session_id=session_id, view=view, kind=kind)
    return False


def _in_use(key: Tuple[str, str, str]) -> bool:
    return any(h.usable and h.key == key for h in list(_live.get(key[0], ())))


def _drop_client(key: Tuple[str, str, str]) -> None:
    _clients.pop(key, None)
    _client_locks.pop(key, None)


def _retire(handle: SandboxHandle, *, whole_instance: bool) -> None:
    """Mark stale (the next ``acquire`` re-ensures) and drop the instance's client."""
    targets = [handle]
    if whole_instance:
        targets += [h for h in list(_live.get(handle.user_id, ())) if h.key == handle.key]
    current = asyncio.current_task()
    for h in targets:
        h.stale = True
        if h._renew_task is not current:
            _cancel_quietly(h._renew_task)
    if whole_instance or not _in_use(handle.key):
        _drop_client(handle.key)


def _register(handle: SandboxHandle) -> None:
    _live.setdefault(handle.user_id, weakref.WeakSet()).add(handle)


def _note_current(handle: SandboxHandle) -> None:
    """Remember the view's current instance and drop idle clients of its older ones."""
    _current[(handle.user_id, handle.view)] = handle.instance
    for key in [k for k in _clients if k[:2] == (handle.user_id, handle.view) and k[2] != handle.instance]:
        if not _in_use(key):
            _drop_client(key)


async def _release_now(handle: SandboxHandle) -> None:
    """Stop renewing and release the lease, once. Never raises."""
    if handle.released:
        return
    try:
        handle.released = True
        task, handle._renew_task = handle._renew_task, None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            await asyncio.wait([task], timeout=contract.GATEWAY_TIMEOUT_S)
        if handle.lease_id and not handle.stale:
            try:
                await _gateway("POST", f"{WEBAPP_API_URL}/api/internal/agent/sandbox/release",
                               {"userId": handle.user_id, "leaseId": handle.lease_id})
            except (_Unreachable, _GatewayError) as exc:
                logger.info("[sandbox] lease release not sent (%s); it expires by itself", exc)
        live = _live.get(handle.user_id)
        if live is not None:
            live.discard(handle)
        if _current.get((handle.user_id, handle.view)) != handle.instance and not _in_use(handle.key):
            _drop_client(handle.key)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("[sandbox] release failed: %s", type(exc).__name__)


# =============================================================================
# acquire / release / using / run_scope
# =============================================================================

async def _acquire(user_id: str, view: str, project_id: Optional[str], kind: str, wait: bool) -> SandboxHandle:
    person = user_id if contract.valid_user_id(user_id) else ""
    if not person:
        if user_id:
            logger.warning("[sandbox] a malformed person id was refused")
        raise await _refuse("", project_id, "no_user", view=view, kind=kind)
    if project_id is not None and not contract.valid_project_id(project_id):
        raise await _refuse(person, None, "error", view=view, kind=kind,
                            detail=contract.ERR_INVALID_PROJECT_ID)

    for _attempt in range(2):
        started = False
        outcome, handle = await _ensure(person, view, project_id, wait=False, kind=kind)
        if outcome == "starting":
            started = True
            await _emit(person, project_id, "starting", view=view, kind=kind)
            if not wait:
                _register(handle)
                return handle
            first_fresh = handle.fresh
            outcome, handle = await _ensure(person, view, project_id, wait=True, kind=kind)
            if outcome == "starting":
                raise await _refuse(person, project_id, "error", view=view, kind=kind,
                                    detail=contract.ERR_START_TIMEOUT)
            handle.fresh = handle.fresh or first_fresh

        handle.kind = kind
        handle.lease_id = str(uuid.uuid4())
        _register(handle)
        _note_current(handle)
        taken, data = await _lease_call(person, handle.instance, handle.lease_id, kind)
        if taken in ("gone", "draining", "refused"):
            # The instance went away between the answer and the lease: ask again once.
            _retire(handle, whole_instance=taken != "draining")
            continue
        if taken == "ok":
            handle._apply_lease(data)
        _start_renewal(handle, _session_id())
        if started:
            await _emit(person, project_id, "ready", view=view, kind=kind)
        return handle
    raise await _refuse(person, project_id, "error", view=view, kind=kind, detail="lease_refused")


async def acquire(user_id: str, *, project_id: Optional[str], kind: str, wait: bool = True,
                  view: Optional[str] = None) -> SandboxHandle:
    """The person's sandbox for one unit of work, with a lease renewed every
    ``LEASE_RENEW_S`` until ``release``. ``view=None`` is ``sandbox_view()``; a named view
    must be that one: who does the work decides the view, an argument never does.

    Inside ``run_scope`` a ``run`` acquire shares the scope's handle (one lease for the
    whole run, its Fireteam members included). With ``wait=False`` a cold start returns
    at once a ``starting`` handle with no lease and no token; acquire again to use it.
    Raises SandboxUnavailable."""
    if kind not in contract.LEASE_KINDS:
        raise ValueError("invalid_lease_kind")
    user_id = user_id if isinstance(user_id, str) else ""
    work_view = sandbox_view()
    if view is None:
        view = work_view
    elif contract.check_view(view) != work_view:
        # Act-as work never reaches the person's own view, which mounts the projects shared
        # with them that act-as access refuses; the person's own work never reaches the
        # act_as view, where an admin's act-as runs and their run credentials live (TD-26).
        raise await _refuse(user_id if contract.valid_user_id(user_id) else "", project_id,
                            "refused", view=work_view, kind=kind, detail="view_not_the_works")
    scope = _current_scope.get()
    if kind == RUN_KIND and scope is not None and not scope.closed:
        return await scope.handle_for(user_id, view, project_id, wait)
    return await _acquire(user_id, view, project_id, kind, wait)


async def release(handle: Optional[SandboxHandle]) -> None:
    """Stop renewing and release the lease (idempotent, never raises). A handle an open
    run scope holds is released when the scope ends."""
    if handle is None or handle.released:
        return
    if handle.scoped:
        scope = handle._scope_ref() if handle._scope_ref is not None else None
        if scope is not None and not scope.closed:
            return
    await _release_now(handle)


@asynccontextmanager
async def using(user_id: str, *, project_id: Optional[str], kind: str, view: Optional[str] = None):
    handle = await acquire(user_id, project_id=project_id, kind=kind, view=view)
    try:
        yield handle
    finally:
        await release(handle)


class _RunScope:
    """One chat run: its ``run`` handles, acquired on the first routed call (a run that
    uses no Kali tool starts no sandbox) and released when the run ends. Fireteam
    members inherit the scope from the run's task and share its handles; the lock makes
    concurrent first calls wait for one start."""

    def __init__(self, session_id: str):
        self.session_id = session_id if isinstance(session_id, str) else ""
        self.handles: Dict[Tuple[str, str, Optional[str]], SandboxHandle] = {}
        self.closed = False
        self._lock = asyncio.Lock()

    async def handle_for(self, user_id: str, view: str, project_id: Optional[str], wait: bool) -> SandboxHandle:
        async with self._lock:
            if not self.closed:
                key = (user_id, view, project_id)
                held = self.handles.get(key)
                if held is not None and held.usable:
                    return held
                if held is not None:
                    del self.handles[key]
                    await _release_now(held)
                handle = await _acquire(user_id, view, project_id, RUN_KIND, wait)
                # A scope that closed while the acquire waited released only what it
                # held then: this handle stays unscoped, and the caller's release() ends it.
                if handle.usable and not self.closed:
                    handle.scoped = True
                    handle._scope_ref = weakref.ref(self)
                    self.handles[key] = handle
                return handle
        return await _acquire(user_id, view, project_id, RUN_KIND, wait)

    async def close(self) -> None:
        # Not under the lock: an acquire in flight holds it for up to a cold start, and
        # re-checks `closed` when it returns.
        self.closed = True
        handles = list(self.handles.values())
        self.handles.clear()
        for handle in handles:
            _cancel_quietly(handle._renew_task)
        for handle in handles:
            await _release_now(handle)


@asynccontextmanager
async def run_scope(session_id: str = ""):
    """Wrap one chat run: its first ``run`` acquire takes the lease, the end releases it,
    also when the run is cancelled."""
    scope = _RunScope(session_id)
    token = _current_scope.set(scope)
    try:
        yield scope
    finally:
        try:
            _current_scope.reset(token)
        except ValueError:
            pass
        await scope.close()


def current_handle(project_id: Optional[str] = None) -> Optional[SandboxHandle]:
    """The run scope's usable handle of this work's person and view (and ``project_id``,
    when named), or None: no scope, no Kali call yet, ended, or held for someone else.
    A scope may hold several persons' handles; the run's last one is never handed out."""
    scope = _current_scope.get()
    person = sandbox_user()
    if scope is None or scope.closed or not person:
        return None
    view = sandbox_view()
    for (user, held_view, held_project), handle in list(scope.handles.items()):
        if (user == person and held_view == view and handle.usable
                and (project_id is None or held_project == project_id)):
            return handle
    return None


def run_scope_open() -> bool:
    """Whether this work runs inside an open chat run scope (a ``run`` acquire shares the
    run's lease there)."""
    scope = _current_scope.get()
    return scope is not None and not scope.closed


@contextmanager
def detach_run_scope():
    """Work inside does not belong to the surrounding chat run: a background job the run
    spawned outlives it, so it takes its own lease instead of the run's handle, which
    the run's end releases."""
    token = _current_scope.set(None)
    try:
        yield
    finally:
        _current_scope.reset(token)


def retire(handle: Optional[SandboxHandle]) -> None:
    """A call found this handle's sandbox gone (its client could not reconnect): every
    handle on that instance turns stale and its client is dropped, so the next
    ``acquire`` ensures again instead of handing the same dead instance back."""
    if handle is not None:
        _retire(handle, whole_instance=True)


async def is_running(user_id: str, view: Optional[str] = None) -> bool:
    """Whether the person's view has a running instance. Advisory: False on any failure,
    and the ``acquire`` that follows says why."""
    view = sandbox_view() if view is None else contract.check_view(view)
    try:
        status, data = await _gateway("GET", f"{WEBAPP_API_URL}/api/internal/agent/sandbox/list")
    except (_Unreachable, _GatewayError):
        return False
    if status != 200 or not isinstance(data, dict):
        return False
    return any(h.user_id == user_id and h.view == view and h.state == "running"
               for h in _listed_handles(data))


def _listed_handles(data: Mapping) -> List[SandboxHandle]:
    """The live instances of a list answer; an entry that is not exactly its person's
    container (host, ids, token) is skipped."""
    handles = []
    entries = data.get("sandboxes")
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        person, view, instance = entry.get("user_id"), entry.get("view"), entry.get("instance")
        if (not contract.valid_user_id(person) or view not in contract.VIEWS
                or not contract.valid_instance(instance)
                or entry.get("host") != contract.container_name(person, view, instance)
                or not _valid_token(entry.get("token"))
                or entry.get("state") not in ("running", "draining")):
            continue
        handles.append(SandboxHandle(
            user_id=person, view=view, instance=instance, host=entry["host"],
            token=entry["token"], tunnel_token="", ports=contract.PORTS,
            reverse_port=contract.DEFAULT_REVERSE_PORT,
            state="running" if entry["state"] == "running" else "draining"))
    return handles


async def running_sandboxes() -> List[SandboxHandle]:
    """Every live instance (running or draining), as lease-less handles, from the
    gateway's list. Raises SandboxUnavailable when the list cannot be read."""
    try:
        status, data = await _gateway("GET", f"{WEBAPP_API_URL}/api/internal/agent/sandbox/list")
    except (_Unreachable, _GatewayError) as exc:
        raise SandboxUnavailable("error", detail=f"gateway_outage {exc}") from None
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("sandboxes"), list):
        raise SandboxUnavailable("error", detail=_status_detail(status, _refusal(data)[0]))
    handles = _listed_handles(data)
    for handle in handles:
        _register(handle)
    return handles


async def lease_listed(handle: SandboxHandle, kind: str) -> Optional[SandboxHandle]:
    """A short lease of ``kind`` on exactly this listed instance (from
    ``running_sandboxes``), with no ``ensure``: a drive of a listed sandbox never starts
    or moves one. None when the instance takes no new lease (draining, gone, refused)
    or the gateway does not answer; the caller then goes on without one. Not renewed;
    end it with ``release``."""
    if kind not in contract.LEASE_KINDS:
        raise ValueError("invalid_lease_kind")
    leased = SandboxHandle(
        user_id=handle.user_id, view=handle.view, instance=handle.instance, host=handle.host,
        token=handle.token, tunnel_token=handle.tunnel_token, ports=handle.ports,
        reverse_port=handle.reverse_port, kind=kind, state=handle.state,
        lease_id=str(uuid.uuid4()))
    outcome, data = await _lease_call(handle.user_id, handle.instance, leased.lease_id, kind)
    if outcome != "ok":
        return None
    leased._apply_lease(data)
    _register(leased)
    return leased


# =============================================================================
# Per-instance clients, URLs, headers
# =============================================================================

def server_configs_for(handle: SandboxHandle) -> Dict[str, Dict[str, Any]]:
    """The five system servers' MultiServerMCPClient configs for this handle: on the
    instance's host, with its own static bearer."""
    from mcp_registry import to_mcp_servers_dict
    from tools import _build_system_mcp_servers

    config, _warnings = to_mcp_servers_dict(_build_system_mcp_servers(handle.host, handle.token))
    return config


async def client_for(handle: SandboxHandle):
    """The handle's MCPToolsManager for the five system servers, connected and cached per
    instance; reconnect through its own ``reconnect()``. Raises SandboxUnavailable
    ("stopped" for a stale or released handle)."""
    _check_serves(handle)
    if handle.state != "running":
        raise SandboxUnavailable("error", detail="sandbox_not_ready")
    key = handle.key
    client = _clients.get(key)
    if client is not None:
        return client
    lock = _client_locks.setdefault(key, asyncio.Lock())
    async with lock:
        client = _clients.get(key)
        if client is not None:
            return client
        from tools import MCPToolsManager

        client = MCPToolsManager(server_configs_for(handle))
        tools = await client.get_tools(max_retries=CLIENT_CONNECT_RETRIES, retry_delay=CLIENT_RETRY_DELAY_S)
        if not tools:
            raise SandboxUnavailable("error", detail="mcp_connect_failed")
        _check_serves(handle)
        _clients[key] = client
        return client


def _check_serves(handle: SandboxHandle) -> None:
    if handle.stale or handle.released:
        raise SandboxUnavailable("stopped", detail="sandbox_stopped")


async def tool_for(tool_name: str, handle: SandboxHandle):
    """The system tool ``tool_name`` from the handle's client, or None when it has none."""
    client = await client_for(handle)
    for tool in client.list_tools():
        if getattr(tool, "name", None) == tool_name:
            return tool
    return None


def url_for(handle: SandboxHandle, port_name: str, path: str = "") -> str:
    """The address of one of the sandbox's ports (``ws://`` for the terminal), plus ``path``."""
    if port_name not in contract.PORTS:
        raise ValueError("unknown_port")
    if not isinstance(path, str) or not _PATH.fullmatch(path):
        raise ValueError("invalid_path")
    scheme = "ws" if port_name == "terminal" else "http"
    return f"{scheme}://{handle.host}:{contract.PORTS[port_name]}{path}"


def headers_for(handle: SandboxHandle, port_name: Optional[str] = None) -> dict:
    """The bearer for the handle's instance: its tunnel token for the tunnel manager, none
    for ngrok's API (which checks nothing), its MCP token for every other port."""
    if port_name == "ngrok_api":
        return {}
    return kali_auth_headers_for(handle.tunnel_token if port_name == "tunnel" else handle.token)


async def drop(user_id: str) -> None:
    """Forget every client and handle of the person, both views (their sandboxes were
    stopped): in-flight handles turn stale, so the next ``acquire`` ensures again."""
    renewals = []
    for handle in list(_live.pop(user_id, ())):
        handle.stale = True
        if handle._renew_task is not None and not handle._renew_task.done():
            _cancel_quietly(handle._renew_task)
            renewals.append(handle._renew_task)
    for key in [k for k in list(_clients) + list(_client_locks) if k[0] == user_id]:
        _drop_client(key)
    for view in contract.VIEWS:
        _current.pop((user_id, view), None)
    current = asyncio.current_task()
    renewals = [t for t in renewals if t is not current]
    if renewals:
        await asyncio.wait(renewals, timeout=contract.GATEWAY_TIMEOUT_S)


# =============================================================================
# Messages
# =============================================================================

_MODEL_TEXT = {
    "ram": contract.SANDBOX_UNAVAILABLE_RAM,
    "hard": contract.SANDBOX_UNAVAILABLE_HARD,
    "error": contract.SANDBOX_UNAVAILABLE_ERROR,
    "no_user": contract.SANDBOX_UNAVAILABLE_ERROR,
    "refused": contract.SANDBOX_REFUSED,
    "stopped": contract.SANDBOX_STOPPED,
}


def unavailable_message(exc: SandboxUnavailable) -> str:
    """The tool result the model reads for a refusal (B.13)."""
    return _MODEL_TEXT[exc.reason]


# =============================================================================
# The job map (TD-9) and the job phase overlay (TD-10)
# =============================================================================

_ERROR_CODE = {
    "ram": "ram", "hard": "hard", "error": "sandbox_error", "no_user": "sandbox_error",
    "refused": "sandbox_refused", "stopped": "sandbox_stopped",
}


@dataclass(frozen=True)
class JobPhase:
    """The overlay a background job's view shows while it waits for or loses its sandbox;
    the job registry's own statuses are unchanged."""
    phase: str
    error_code: Optional[str] = None
    message: Optional[str] = None


@dataclass
class _Job:
    user_id: str
    view: str = ""
    phase: Optional[JobPhase] = None


_jobs: "OrderedDict[str, _Job]" = OrderedDict()


def _valid_job_id(job_id) -> bool:
    return isinstance(job_id, str) and _JOB_ID.fullmatch(job_id) is not None


def _job_entry(job_id: str) -> _Job:
    entry = _jobs.get(job_id)
    if entry is None:
        entry = _jobs[job_id] = _Job(user_id="")
        while len(_jobs) > JOBS_MAX:
            _jobs.popitem(last=False)
    return entry


def note_job(job_id: str, user_id: str, view: Optional[str] = None) -> bool:
    """Record whose sandbox, and which view of it, runs a background job (``view`` None:
    this work's ``sandbox_view()``). False, nothing recorded, without a valid job id,
    person and view."""
    if view is None:
        view = sandbox_view()
    if not _valid_job_id(job_id) or not contract.valid_user_id(user_id) or view not in contract.VIEWS:
        return False
    entry = _job_entry(job_id)
    entry.user_id, entry.view = user_id, view
    return True


def job_sandbox_user(job_id: str) -> str:
    return job_sandbox(job_id)[0]


def job_sandbox(job_id: str) -> Tuple[str, str]:
    """(person, view) of a background job's sandbox; ("", "") when none is recorded."""
    entry = _jobs.get(job_id) if _valid_job_id(job_id) else None
    return (entry.user_id, entry.view) if entry is not None and entry.user_id else ("", "")


def jobs_by_sandbox_user() -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for job_id, entry in _jobs.items():
        if entry.user_id:
            mapping.setdefault(entry.user_id, []).append(job_id)
    return mapping


def set_job_phase(job_id: str, phase: str) -> None:
    """``starting`` while the job waits for the sandbox, ``running`` once it has it."""
    if phase not in ("starting", "running") or not _valid_job_id(job_id):
        raise ValueError("invalid_job_phase")
    _job_entry(job_id).phase = JobPhase(phase)


def job_failed(job_id: str, exc: SandboxUnavailable) -> None:
    """The job failed for its sandbox: ``error_code`` per B.13, and the governor's
    sentence (ram, hard) or the contract's text as the message."""
    if not _valid_job_id(job_id):
        raise ValueError("invalid_job_phase")
    if exc.reason in ("ram", "hard") and exc.detail:
        message = exc.detail
    else:
        message = unavailable_message(exc)
    _job_entry(job_id).phase = JobPhase("failed", _ERROR_CODE[exc.reason], message)


def job_phase(job_id: str) -> Optional[JobPhase]:
    entry = _jobs.get(job_id) if _valid_job_id(job_id) else None
    return entry.phase if entry is not None else None


def forget_job(job_id: str) -> None:
    _jobs.pop(job_id, None)


# =============================================================================
# Tests
# =============================================================================

def _reset() -> None:
    """Forget everything."""
    for task in list(_renewals):
        _cancel_quietly(task)
    _listeners.clear()
    _clients.clear()
    _client_locks.clear()
    _live.clear()
    _current.clear()
    _jobs.clear()


async def shutdown() -> None:
    """Cancel every lease renewal and wait for it to end (the agent's shutdown). The
    leases are not released: they expire by themselves within LEASE_TTL_S."""
    tasks = [t for t in list(_renewals) if not t.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.wait(tasks, timeout=contract.GATEWAY_TIMEOUT_S)


_shutdown = shutdown

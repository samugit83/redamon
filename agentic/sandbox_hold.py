"""The hold watcher: live sessions and an active tunnel keep their Kali sandbox (group 1:
D24, contract B.8 `hold`, OD-G1-f).

A per-user sandbox stops after its idle minutes without a lease. A Metasploit session, a job
(a listener), a non-MSF session or a tunnel lives in the sandbox with no unit of work holding
it, so this watcher holds such an instance with one `hold` lease. A hold is not use: the
orchestrator still stops a sandbox held only by it after HOLD_MAX_NO_USE_S without use.

Every HOLD_WATCH_S it lists the live instances (`running_sandboxes()`) and reads every
one at once, each read bounded by
READ_TIMEOUT_S so a hung sandbox never delays another's hold, and by sandbox_http's size and
encoding rules, since whoever is root in a sandbox writes its answers: the session manager with the
instance's MCP token, and the tunnel manager with the instance's tunnel token once the tunnel
push has handed it over (`note_tunnel`), else with the MCP token, which the tunnel manager
accepts for its status (the gateway's list carries no tunnel token, and a restarted agent
holds none). An
instance holding anything has its hold taken at once; one holding nothing has it released.

Renewals run on their own every HOLD_RENEW_S (a third of the lease), so one failed or slow
read never lets a hold lapse. A failed read justifies nothing: it takes nothing, and a hold
is renewed only while its last good read is at most HOLD_JUSTIFIED_S old; after that it is
left to expire.

The lease is taken directly on the gateway's lease route, never through
`sandbox_router.acquire`: an `ensure` marks the sandbox used, which would make the no-use cap
unreachable, and could start a sandbox. Its id is fixed per instance (derived from the person,
view and instance), so a restarted agent renews the same lease, which a draining instance
still accepts. Nothing logged carries a token, a user id or a session's content: a sandbox is
named by its view's key and its instance.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

import sandbox_contract as contract
import sandbox_router
from kali_auth import kali_auth_headers_for
from sandbox_http import read_answer

logger = logging.getLogger(__name__)

HOLD_WATCH_S = contract.HOLD_WATCH_S
HOLD_RENEW_S = contract.LEASE_TTL_S / 3
HOLD_JUSTIFIED_S = contract.LEASE_TTL_S
READ_TIMEOUT_S = contract.FANOUT_TIMEOUT_S
SESSIONS_PATH = "/sessions"
TUNNEL_STATUS_PATH = "/tunnel/status"
_SESSION_LISTS = ("sessions", "jobs", "non_msf_sessions")
_TUNNELS = ("ngrok", "chisel")
_LEASE_NAMESPACE = uuid.UUID("5d0b7a1e-6c43-4f0e-9a51-3c1f8e2b7d64")

#: Replaced by the tests with an httpx.MockTransport; None is httpx's own transport.
_transport: Optional[httpx.AsyncBaseTransport] = None

Key = Tuple[str, str, str]


def hold_lease_id(handle: sandbox_router.SandboxHandle) -> str:
    """The one hold lease id of an instance (the gateway takes a UUID)."""
    return str(uuid.uuid5(_LEASE_NAMESPACE, "\n".join(handle.key)))


def _name(key: Key) -> str:
    """A sandbox in a log line: its view's key and its instance, never the user id."""
    person, view, instance = key
    try:
        return f"{contract.sandbox_key(person, view)}/{instance}"
    except ValueError:
        return f"?/{instance}"


def _code(data: Any) -> Optional[str]:
    """The error code of a gateway answer: flat, or FastAPI's `{"detail": {...}}`."""
    if isinstance(data, dict):
        for src in (data, data.get("detail")):
            if isinstance(src, dict) and isinstance(src.get("code"), str):
                return src["code"]
    return None


@dataclass
class _Hold:
    handle: sandbox_router.SandboxHandle
    lease_id: str
    #: Monotonic time of the last good read that found something to hold; None after one
    #: that found nothing.
    justified_at: Optional[float] = None
    #: The last take or renewal was accepted (a release is due when nothing is left).
    held: bool = False
    #: The instance takes no lease from us any more (draining, gone, or its person lost
    #: access): never asked again.
    refused: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class HoldWatcher:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._holds: Dict[Key, _Hold] = {}
        self._tunnel_tokens: Dict[Key, str] = {}
        self._tasks: List[asyncio.Task] = []

    # --- the tunnel token -------------------------------------------------------------

    def note_tunnel(self, handle: Optional[sandbox_router.SandboxHandle]) -> None:
        """Remember the instance's tunnel token, from a handle an `ensure` answered (the tunnel
        push holds one), so the watcher can read its tunnel manager."""
        if handle is None or not kali_auth_headers_for(handle.tunnel_token):
            return
        self._tunnel_tokens[handle.key] = handle.tunnel_token

    # --- one read round ---------------------------------------------------------------

    async def watch_once(self) -> None:
        try:
            handles = await sandbox_router.running_sandboxes()
        except sandbox_router.SandboxUnavailable as exc:
            logger.info("[sandbox-hold] the sandbox list could not be read (%s); "
                        "holds are renewed only while their last read is fresh", exc.reason)
            return
        live = {h.key: h for h in handles}
        # A listed instance is gone once it is not listed: its leases went with it.
        for key in [k for k in self._holds if k not in live]:
            del self._holds[key]
        for key in [k for k in self._tunnel_tokens if k not in live]:
            del self._tunnel_tokens[key]
        if live:
            await asyncio.gather(*(self._watch(h) for h in live.values()))

    async def _watch(self, handle: sandbox_router.SandboxHandle) -> None:
        hold = self._holds.get(handle.key)
        if hold is None:
            hold = self._holds[handle.key] = _Hold(handle=handle, lease_id=hold_lease_id(handle))
        hold.handle = handle
        verdict = await self._read(handle)
        async with hold.lock:
            if self._holds.get(handle.key) is not hold or verdict is None:
                return
            if verdict:
                hold.justified_at = self._clock()
                if not hold.refused:
                    await self._take(hold)
            else:
                hold.justified_at = None
                if hold.held:
                    await self._release(hold)

    async def _read(self, handle: sandbox_router.SandboxHandle) -> Optional[bool]:
        """True when the instance holds a session, a job or an active tunnel; False when it
        holds none; None when that cannot be told (a read failed or timed out)."""
        token = self._tunnel_tokens.get(handle.key)
        # The tunnel manager also answers its status to the instance's own MCP token, which
        # every listed handle carries: an agent restarted since the tunnel was pushed has no
        # tunnel token, and a live tunnel must keep holding its sandbox all the same.
        tunnel_headers = kali_auth_headers_for(token) if token else sandbox_router.headers_for(handle)
        async with httpx.AsyncClient(timeout=READ_TIMEOUT_S, transport=_transport) as client:
            sessions, tunnel = await asyncio.gather(
                self._bounded(self._sessions_live(client, handle)),
                self._bounded(self._tunnel_active(client, handle, tunnel_headers)))
        if sessions is True or tunnel is True:
            return True
        if sessions is None or tunnel is None:
            return None
        return False

    @staticmethod
    async def _bounded(read) -> Optional[bool]:
        try:
            return await asyncio.wait_for(read, timeout=READ_TIMEOUT_S)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a timeout, a refused connection, a bad answer
            return None

    @staticmethod
    async def _sessions_live(client: httpx.AsyncClient, handle) -> Optional[bool]:
        answer = await read_answer(client, "GET", sandbox_router.url_for(handle, "sessions", SESSIONS_PATH),
                                   headers=sandbox_router.headers_for(handle), deadline_s=READ_TIMEOUT_S)
        if answer.status != 200:
            return None
        data = answer.json()
        if not isinstance(data, dict):
            return None
        lists = [data.get(name) for name in _SESSION_LISTS]
        if not all(isinstance(items, list) for items in lists):
            return None
        return any(lists)

    @staticmethod
    async def _tunnel_active(client: httpx.AsyncClient, handle, headers: dict) -> Optional[bool]:
        answer = await read_answer(client, "GET", sandbox_router.url_for(handle, "tunnel", TUNNEL_STATUS_PATH),
                                   headers=headers, deadline_s=READ_TIMEOUT_S)
        if answer.status != 200:
            return None
        data = answer.json()
        if not isinstance(data, dict):
            return None
        return any(isinstance(data.get(name), dict) and data[name].get("active") is True
                   for name in _TUNNELS)

    # --- one renewal round ------------------------------------------------------------

    async def renew_once(self) -> None:
        due = [h for h in list(self._holds.values()) if self._justified(h)]
        if due:
            await asyncio.gather(*(self._renew(h) for h in due))

    def _justified(self, hold: _Hold) -> bool:
        return (not hold.refused and hold.justified_at is not None
                and self._clock() - hold.justified_at <= HOLD_JUSTIFIED_S)

    async def _renew(self, hold: _Hold) -> None:
        async with hold.lock:
            if self._holds.get(hold.handle.key) is hold and self._justified(hold):
                await self._take(hold)

    # --- the gateway's lease routes ---------------------------------------------------

    async def _take(self, hold: _Hold) -> None:
        status, code = await _gateway_post(contract.INTERNAL_ROUTE_LEASE, {
            "userId": hold.handle.user_id, "instance": hold.handle.instance,
            "leaseId": hold.lease_id, "kind": contract.HOLD_LEASE_KIND})
        if status == 200:
            if not hold.held:
                logger.info("[sandbox-hold] %s held", _name(hold.handle.key))
            hold.held = True
            return
        if ((status == 409 and code in (contract.ERR_NOT_RUNNING, contract.ERR_DRAINING))
                or (status == 404 and code == contract.ERR_UNKNOWN_INSTANCE)
                or (status == 403 and code in (contract.ERR_USER_REFUSED, contract.ERR_PROJECT_REFUSED))):
            hold.refused, hold.held = True, False
            logger.info("[sandbox-hold] %s takes no hold (%s)", _name(hold.handle.key), code)
            return
        logger.info("[sandbox-hold] %s hold not taken (status=%s); retried at the next renewal",
                    _name(hold.handle.key), status)

    async def _release(self, hold: _Hold) -> None:
        await _gateway_post(contract.INTERNAL_ROUTE_RELEASE,
                            {"userId": hold.handle.user_id, "leaseId": hold.lease_id})
        hold.held = False
        logger.info("[sandbox-hold] %s released: nothing left to hold", _name(hold.handle.key))

    # --- the loops ----------------------------------------------------------------------

    async def _read_loop(self) -> None:
        while True:
            try:
                await self.watch_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a bug must not end the watcher
                logger.warning("[sandbox-hold] read round failed: %s", type(exc).__name__)
            await asyncio.sleep(HOLD_WATCH_S)

    async def _renew_loop(self) -> None:
        while True:
            await asyncio.sleep(HOLD_RENEW_S)
            try:
                await self.renew_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("[sandbox-hold] renewal round failed: %s", type(exc).__name__)

    def start(self) -> bool:
        """Start both loops on the running loop; False when they already run (or no loop
        runs). They run in a context of their own: no request's or run's person leaks in."""
        if any(not t.done() for t in self._tasks):
            return False
        loop = asyncio.get_running_loop()
        self._tasks = [
            loop.create_task(self._read_loop(), name="sandbox-hold-read", context=contextvars.Context()),
            loop.create_task(self._renew_loop(), name="sandbox-hold-renew", context=contextvars.Context()),
        ]
        return True

    async def stop(self) -> None:
        """Cancel both loops. A hold left behind expires by itself (a restarted agent renews
        it under the same id)."""
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        pending = [t for t in tasks if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=contract.GATEWAY_TIMEOUT_S)


async def _gateway_post(path: str, body: dict) -> Tuple[int, Optional[str]]:
    """POST one of the gateway's internal lease routes: (status, error code); (0, None) when
    no answer came (no internal key, a connection or timeout error)."""
    if not sandbox_router.INTERNAL_HEADERS.get("X-Internal-Key"):
        return 0, None
    url = f"{sandbox_router.WEBAPP_API_URL.rstrip('/')}{path}"
    try:
        async with httpx.AsyncClient(timeout=contract.GATEWAY_TIMEOUT_S, transport=_transport) as client:
            resp = await client.post(url, json=body, headers=sandbox_router.INTERNAL_HEADERS)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.info("[sandbox-hold] gateway call failed: %s", type(exc).__name__)
        return 0, None
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001 - a 204 has no body
        data = None
    return resp.status_code, _code(data)


# =============================================================================
# The agent's one watcher (started and stopped by the API's lifespan)
# =============================================================================

_watcher: Optional[HoldWatcher] = None


def watcher() -> HoldWatcher:
    global _watcher
    if _watcher is None:
        _watcher = HoldWatcher()
    return _watcher


def start() -> bool:
    """Start the agent's watcher. Idempotent; never raises (it calls no gateway here)."""
    try:
        return watcher().start()
    except Exception as exc:  # noqa: BLE001 - no running loop, or a bug: start-up goes on
        logger.warning("[sandbox-hold] not started: %s", type(exc).__name__)
        return False


async def stop() -> None:
    """Stop the agent's watcher. Idempotent; never raises."""
    try:
        await watcher().stop()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[sandbox-hold] not stopped cleanly: %s", type(exc).__name__)


def note_tunnel(handle: Optional[sandbox_router.SandboxHandle]) -> None:
    """For the tunnel push (`POST /sandboxes/{user_id}/tunnel`): hand over the handle it
    acquired, so the watcher can see the tunnel it started and hold the sandbox for it."""
    watcher().note_tunnel(handle)

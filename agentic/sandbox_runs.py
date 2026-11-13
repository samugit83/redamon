"""
The agent's half of ending a stopped run's processes in the Kali sandbox
(GHSA-8whg-rvcr-r88r; the sandbox's half is mcp/servers/_run_registry.py).

Cancelling a chat run's tool tasks only stops the agent waiting: the MCP client
does not tell the server, and the sandbox ran the command on in its own thread
until its timeout. So every call to a run-tagged sandbox server carries the chat
session id in RUN_ARG, which the sandbox writes into the environment of each
process it starts, and stopping a session asks the sandbox to kill them.

The tag goes only to a tool that advertises RUN_ARG in its schema, on a system
server: a sandbox started before this change never sees an argument it would
reject, and no user MCP server learns a session id.
"""
import asyncio
import logging
import os
import re
from typing import Iterable, Optional, Set

from agent_context import current_log_session_id, current_session_id
from kali_auth import kali_auth_headers, note_kali_refusal

logger = logging.getLogger(__name__)

RUN_ARG = "_redamon_run_key"
RUN_TAGGED_SERVERS = frozenset({"network_recon", "nmap", "nuclei", "playwright"})
STOP_PATH = "/redamon/runs/stop"
STOP_TIMEOUT_S = 10.0

_RUN_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# Stop requests in flight; held so the event loop does not drop them mid-request.
_pending: Set[asyncio.Task] = set()


def current_run_key() -> str:
    """The chat session the current task belongs to, or "" outside a chat run.

    current_session_id is blanked mid-run by node-level set_tenant_context;
    current_log_session_id holds the same id for the whole run.
    """
    key = current_session_id.get() or current_log_session_id.get() or ""
    return key if _RUN_KEY_RE.match(key) else ""


def advertises_run_arg(tool) -> bool:
    schema = getattr(tool, "args_schema", None)
    return isinstance(schema, dict) and RUN_ARG in (schema.get("properties") or {})


class RunTagInterceptor:
    """A langchain-mcp-adapters tool interceptor that names the run on each call."""

    def __init__(self) -> None:
        self._advertised: frozenset = frozenset()

    def learn(self, tools: Iterable) -> None:
        """Remember which loaded tools take RUN_ARG (their server strips it)."""
        self._advertised = frozenset(t.name for t in tools if advertises_run_arg(t))

    async def __call__(self, request, handler):
        args = dict(request.args or {})
        # Whatever the model put there is never the run's name.
        args.pop(RUN_ARG, None)
        key = current_run_key()
        if key and request.server_name in RUN_TAGGED_SERVERS and request.name in self._advertised:
            args[RUN_ARG] = key
        return await handler(request.override(args=args))


def stop_url() -> str:
    base = os.environ.get("MCP_NETWORK_RECON_URL", "http://host.docker.internal:8000/sse")
    base = base[:-len("/sse")] if base.endswith("/sse") else base.rstrip("/")
    return base + STOP_PATH


async def stop_sandbox_run(run_key: str) -> Optional[int]:
    """Ask the sandbox to kill run `run_key`'s processes; how many it signalled.

    Never raises: a stop must finish in the agent whatever the sandbox answers.
    """
    if not _RUN_KEY_RE.match(run_key or ""):
        return None
    import httpx

    try:
        async with httpx.AsyncClient(timeout=STOP_TIMEOUT_S) as client:
            resp = await client.post(stop_url(), json={"run": run_key}, headers=kali_auth_headers())
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[stop] sandbox processes of run {run_key} not stopped: {type(exc).__name__}")
        return None
    if resp.status_code != 200:
        note_kali_refusal(resp.status_code, "the run stop")
        logger.warning(f"[stop] sandbox refused the stop of run {run_key}: HTTP {resp.status_code}")
        return None
    try:
        signalled = int(resp.json().get("signalled", 0))
    except Exception:  # noqa: BLE001
        signalled = 0
    if signalled:
        logger.info(f"[stop] sandbox signalled {signalled} process(es) of run {run_key}")
    return signalled


def schedule_sandbox_stop(run_key: str) -> Optional[asyncio.Task]:
    """Start `stop_sandbox_run` without making the caller wait for the sandbox."""
    if not _RUN_KEY_RE.match(run_key or ""):
        return None
    task = asyncio.get_running_loop().create_task(stop_sandbox_run(run_key))
    _pending.add(task)
    task.add_done_callback(_pending.discard)
    return task

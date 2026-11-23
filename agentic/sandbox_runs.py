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

A run's calls go to its person's sandbox (group 1), so the executor notes each
sandbox a run used (`note_run_sandbox`) and stopping the run asks those, each with its
own bearer; a run key is never sent to another person's sandbox, and a run that used
none asks nothing.
"""
import asyncio
import logging
import re
import weakref
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Set, Tuple

import sandbox_contract as contract
import sandbox_router
from agent_context import current_log_session_id, current_session_id
from kali_auth import note_kali_refusal

logger = logging.getLogger(__name__)

RUN_ARG = "_redamon_run_key"
RUN_TAGGED_SERVERS = frozenset({"network_recon", "nmap", "nuclei", "playwright"})
STOP_PATH = "/redamon/runs/stop"
STOP_TIMEOUT_S = 10.0
#: Each sandbox the emergency stop asks gets this long; one that does not answer is named.
FANOUT_TIMEOUT_S = contract.FANOUT_TIMEOUT_S
RUNS_MAX = 4096

_RUN_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# Stop requests in flight; held so the event loop does not drop them mid-request.
_pending: Set[asyncio.Task] = set()

#: run key -> the per-user handles its calls used (weak: a released, dropped handle goes).
_run_sandboxes: "OrderedDict[str, weakref.WeakSet]" = OrderedDict()


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


def note_run_sandbox(run_key: str, handle) -> None:
    """Record that run `run_key` called the sandbox of `handle` (the executor calls it on
    every routed call)."""
    if not _RUN_KEY_RE.match(run_key or "") or handle is None:
        return
    held = _run_sandboxes.get(run_key)
    if held is None:
        held = _run_sandboxes[run_key] = weakref.WeakSet()
        while len(_run_sandboxes) > RUNS_MAX:
            _run_sandboxes.popitem(last=False)
    held.add(handle)


def _run_handles(run_key: str) -> list:
    """The run's handles, one per sandbox instance."""
    by_instance = {}
    for handle in list(_run_sandboxes.get(run_key, ())):
        by_instance.setdefault(handle.key, handle)
    if not by_instance:
        _run_sandboxes.pop(run_key, None)
    return list(by_instance.values())


Target = Tuple[str, str, dict]   # (what, url, headers)


def _stop_targets(run_key: str) -> List[Target]:
    """Where to send the stop of `run_key`: each sandbox the run used, with its own
    bearer; nowhere when the run called no sandbox."""
    targets = []
    for handle in _run_handles(run_key):
        try:
            targets.append((handle.instance, sandbox_router.url_for(handle, "network_recon", STOP_PATH),
                            sandbox_router.headers_for(handle)))
        except Exception as exc:  # noqa: BLE001 - one bad handle never stops the others
            logger.warning(f"[stop] no stop address for a sandbox of run {run_key}: {type(exc).__name__}")
    return targets


#: The stop's answer is `{"signalled": n}`; anything larger is not the sandbox's server.
STOP_ANSWER_MAX_BYTES = 64 * 1024


async def _post_stop(url: str, headers: dict, run_key: str, timeout: float) -> Optional[int]:
    """One stop request; how many processes the sandbox signalled, None on any failure.
    Never raises. The answer is read under a cap and the deadline, compression refused:
    the sandbox's root decides what it answers, and the stop runs in the shared agent."""
    import httpx
    from sandbox_http import read_answer

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await read_answer(client, "POST", url, headers=headers, json={"run": run_key},
                                     max_bytes=STOP_ANSWER_MAX_BYTES, deadline_s=timeout)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[stop] sandbox processes of run {run_key} not stopped: {type(exc).__name__}")
        return None
    if resp.status != 200:
        note_kali_refusal(resp.status, "the run stop")
        logger.warning(f"[stop] sandbox refused the stop of run {run_key}: HTTP {resp.status}")
        return None
    try:
        signalled = int(resp.json().get("signalled", 0))
    except Exception:  # noqa: BLE001
        signalled = 0
    if signalled:
        logger.info(f"[stop] sandbox signalled {signalled} process(es) of run {run_key}")
    return signalled


async def _stop_at(targets: List[Target], run_key: str) -> Optional[int]:
    if not targets:
        return None
    answers = await asyncio.gather(*(_post_stop(url, headers, run_key, STOP_TIMEOUT_S)
                                     for _what, url, headers in targets))
    counted = [a for a in answers if a is not None]
    return sum(counted) if counted else None


async def stop_sandbox_run(run_key: str) -> Optional[int]:
    """Ask the sandbox (each sandbox the run used) to kill run `run_key`'s processes;
    how many were signalled, None when none answered or there was none to ask.

    Never raises: a stop must finish in the agent whatever the sandbox answers.
    """
    if not _RUN_KEY_RE.match(run_key or ""):
        return None
    return await _stop_at(_stop_targets(run_key), run_key)


def schedule_sandbox_stop(run_key: str) -> Optional[asyncio.Task]:
    """Start `stop_sandbox_run` without making the caller wait for the sandbox. The
    sandboxes are read now: the caller is cancelling the run, whose handles go when its
    scope closes."""
    if not _RUN_KEY_RE.match(run_key or ""):
        return None
    targets = _stop_targets(run_key)
    task = asyncio.get_running_loop().create_task(_stop_at(targets, run_key))
    _pending.add(task)
    task.add_done_callback(_pending.discard)
    return task


async def stop_all_runs() -> Dict[str, object]:
    """The emergency stop's half in the sandboxes: every running sandbox is asked at
    once to kill the agent's runs known to use it, each sandbox bounded by
    FANOUT_TIMEOUT_S, so a hung one never holds the stop (the webapp stops the
    containers themselves). Call it before cancelling the runs: a run's handles go when
    its scope closes.

    Answers ``{"sandboxes", "asked", "answered", "unavailable": [instance]}``."""
    result: Dict[str, object] = {"sandboxes": 0, "asked": 0, "answered": 0, "unavailable": []}
    try:
        running = await sandbox_router.running_sandboxes()
    except sandbox_router.SandboxUnavailable as exc:
        logger.warning(f"[stop] the sandbox list could not be read: {exc.reason}")
        result["error"] = "sandbox_list_unavailable"
        return result
    runs_by_instance: Dict[tuple, List[str]] = {}
    for run_key in list(_run_sandboxes):
        for handle in _run_handles(run_key):
            runs_by_instance.setdefault(handle.key, []).append(run_key)
    result["sandboxes"] = len(running)

    async def ask(handle, run_keys) -> bool:
        url = sandbox_router.url_for(handle, "network_recon", STOP_PATH)
        headers = sandbox_router.headers_for(handle)
        try:
            answers = await asyncio.wait_for(
                asyncio.gather(*(_post_stop(url, headers, key, FANOUT_TIMEOUT_S) for key in run_keys)),
                timeout=FANOUT_TIMEOUT_S)
        except asyncio.TimeoutError:
            return False
        return all(a is not None for a in answers)

    asked = [(h, runs_by_instance[h.key]) for h in running if runs_by_instance.get(h.key)]
    outcomes = await asyncio.gather(*(ask(h, keys) for h, keys in asked), return_exceptions=True)
    result["asked"] = len(asked)
    result["answered"] = sum(1 for o in outcomes if o is True)
    result["unavailable"] = [h.instance for (h, _keys), o in zip(asked, outcomes) if o is not True]
    if result["unavailable"]:
        logger.warning(f"[stop] {len(result['unavailable'])} sandbox(es) did not answer the stop")
    return result


def _reset() -> None:
    """Tests: forget every run's sandboxes."""
    _run_sandboxes.clear()

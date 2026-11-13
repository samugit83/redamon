"""
Which agent run started each process in the sandbox, and how a stopped run's
processes end (GHSA-8whg-rvcr-r88r).

The agent's emergency stop cancels its own asyncio tasks. The MCP client does not
tell the server about a cancelled call, and these tools run their commands in a
thread, so a `kali_shell`, hydra or nuclei process kept running against the target
for up to its own timeout (300 s, 1800 s for hydra) after a person pressed stop.

So the agent names the run on every call it makes to a run-tagged server, in the
hidden argument RUN_ARG (the chat session id). This module's middleware takes it
off the arguments before the tool sees them, and safe_env() writes it into every
child as RUN_ENV, which the child's own children inherit. When a run stops, the
agent posts to STOP_PATH and every process carrying that run's tag, and every
descendant of one (a child that cleared its environment still has a tagged
parent), gets SIGTERM, then SIGKILL after a grace period.

Metasploit is not a run-tagged server: its msfconsole is one process every chat
shares, started inside whichever call came first, and must not die with that run.
A process that clears its own environment AND detaches from its tagged parent
before the stop escapes; that residual is stated in README.SECURITY_POSTURE.md.
"""
import contextvars
import logging
import os
import re
import signal
import time
from collections import defaultdict
from typing import Callable, Dict, Optional, Set, Tuple

logger = logging.getLogger("mcp-run-registry")

RUN_ARG = "_redamon_run_key"
RUN_ENV = "REDAMON_RUN"
STOP_PATH = "/redamon/runs/stop"
#: The servers whose tools spawn per-call processes. The agent tags a call only when
#: the tool advertises RUN_ARG, which only these servers' middleware adds.
RUN_TAGGED_SERVERS = frozenset({"network_recon", "nmap", "nuclei", "playwright"})
#: The server that answers STOP_PATH. One is enough: the scan below covers every
#: process in the container's PID namespace, whichever server started it.
STOP_SERVER = "network_recon"
STOP_GRACE_S = 2.0

#: A chat session id; anything else is not a run key and tags nothing.
_RUN_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

current_run: contextvars.ContextVar[str] = contextvars.ContextVar("redamon_run", default="")


def valid_run_key(value) -> bool:
    return isinstance(value, str) and bool(_RUN_KEY_RE.match(value))


def take_run_arg(arguments: Optional[dict]) -> str:
    """Remove RUN_ARG from a tool call's arguments; the run key it named, or ""."""
    if not isinstance(arguments, dict):
        return ""
    value = arguments.pop(RUN_ARG, "")
    return value if valid_run_key(value) else ""


def run_tag() -> Dict[str, str]:
    """The variable safe_env() adds to a child started inside a tagged call."""
    key = current_run.get()
    return {RUN_ENV: key} if key else {}


# ---------------------------------------------------------------------------
# Finding and ending a run's processes
# ---------------------------------------------------------------------------

def _proc_table(proc_root: str = "/proc") -> Dict[int, Tuple[int, Optional[str], str]]:
    """pid -> (ppid, run tag or None, state) for every process readable here."""
    table: Dict[int, Tuple[int, Optional[str], str]] = {}
    prefix = RUN_ENV.encode() + b"="
    for name in os.listdir(proc_root):
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, name, "stat"), "rb") as f:
                stat = f.read()
            # "pid (comm) state ppid ...": comm may hold spaces and parentheses.
            fields = stat[stat.rindex(b")") + 2:].split()
            state, ppid = fields[0].decode(), int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
        tag = None
        try:
            with open(os.path.join(proc_root, name, "environ"), "rb") as f:
                for entry in f.read().split(b"\0"):
                    if entry.startswith(prefix):
                        tag = entry[len(prefix):].decode("utf-8", "replace")
                        break
        except OSError:
            pass
        table[int(name)] = (ppid, tag, state)
    return table


def run_processes(key: str, table: Dict[int, Tuple[int, Optional[str], str]]) -> Set[int]:
    """The live pids tagged with `key`, and every descendant of one."""
    if not valid_run_key(key):
        return set()
    # The servers carry no tag, so these never match. Refused anyway, and never
    # walked through: a stray variable in pid 1's environment must not make every
    # process in the container its descendant.
    protected = {0, 1, os.getpid(), os.getppid()}
    children: Dict[int, list] = defaultdict(list)
    for pid, (ppid, _, _) in table.items():
        children[ppid].append(pid)
    found: Set[int] = set()
    stack = [pid for pid, (_, tag, _) in table.items() if tag == key]
    while stack:
        pid = stack.pop()
        if pid not in found and pid not in protected:
            found.add(pid)
            stack.extend(children.get(pid, ()))
    return {pid for pid in found if table[pid][2] != "Z"}


def kill_run(key: str, grace: float = STOP_GRACE_S, proc_root: str = "/proc",
             kill: Callable[[int, int], None] = os.kill,
             sleep: Callable[[float], None] = time.sleep) -> int:
    """SIGTERM every process of run `key`, SIGKILL what is left after `grace`.

    Answers how many processes were signalled. Runs in a worker thread: it reads
    /proc and waits.
    """
    signalled = run_processes(key, _proc_table(proc_root))
    for pid in signalled:
        _signal(kill, pid, signal.SIGTERM)
    alive = set(signalled)
    deadline = time.monotonic() + grace
    while alive and time.monotonic() < deadline:
        sleep(0.1)
        # A rescan, so a child forked after the SIGTERM is caught too.
        alive = run_processes(key, _proc_table(proc_root))
    for pid in alive:
        _signal(kill, pid, signal.SIGKILL)
    return len(signalled | alive)


def _signal(kill, pid: int, sig: int) -> None:
    try:
        kill(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


# ---------------------------------------------------------------------------
# Wiring into a FastMCP server
# ---------------------------------------------------------------------------

def _advertise(tool):
    params = dict(tool.parameters or {})
    props = dict(params.get("properties") or {})
    props[RUN_ARG] = {"type": "string", "default": "",
                      "description": "Set by RedAmon; never by the model."}
    params["properties"] = props
    return tool.model_copy(update={"parameters": params})


def _middleware():
    from fastmcp.server.middleware import Middleware

    class RunTagMiddleware(Middleware):
        """Advertise RUN_ARG on every tool, and turn it into `current_run` per call."""

        async def on_list_tools(self, context, call_next):
            return [_advertise(tool) for tool in await call_next(context)]

        async def on_call_tool(self, context, call_next):
            token = current_run.set(take_run_arg(context.message.arguments))
            try:
                return await call_next(context)
            finally:
                current_run.reset(token)

    return RunTagMiddleware()


async def _stop_route(request):
    import anyio
    from starlette.responses import JSONResponse

    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = None
    key = body.get("run") if isinstance(body, dict) else None
    if not valid_run_key(key):
        return JSONResponse({"error": "`run` must be a run key"}, status_code=400)
    killed = await anyio.to_thread.run_sync(kill_run, key)
    logger.info("run stop: run=%s signalled=%d", key, killed)
    return JSONResponse({"run": key, "signalled": killed})


def install(mcp, server_name: str) -> None:
    """Tag the calls of a run-tagged server; serve STOP_PATH on STOP_SERVER.

    The route sits inside the bearer-auth wrapper like every other path of the
    server. Not wrapped in try/except: a server that strips no RUN_ARG would reject
    every call the agent tags, so a failure here must be loud.
    """
    if server_name not in RUN_TAGGED_SERVERS:
        return
    mcp.add_middleware(_middleware())
    if server_name == STOP_SERVER:
        mcp.custom_route(STOP_PATH, methods=["POST"])(_stop_route)

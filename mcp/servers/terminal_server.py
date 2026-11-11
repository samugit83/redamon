"""
RedAmon Terminal Server — WebSocket PTY for Kali Sandbox

Provides a WebSocket endpoint that spawns an interactive bash shell
with full PTY support. Used by the RedAmon Terminal tab in the webapp.

Runs on port 8016 inside the kali-sandbox container.

Only the agent's /ws/kali-terminal proxy may connect (NF-04). The port is on the
Docker networks every lab container shares, and it hands out a root shell, so the
upgrade must carry the bearer MCP_AUTH_TOKEN (which only the agent holds; unset
refuses everyone), checked before any PTY is forked. The proxy has verified the
browser's ticket and names the user and project in the upgrade's query; the
browser's own init frame is read and dropped, its ids ignored. The proxy also
sends the connection's graph credential (X-Redamon-Run), which the shell gets as
REDAMON_RUN_CREDENTIAL for redagraph. The shell gets no service secret: its
environment is built by safe_env().
"""

import asyncio
import fcntl
import hmac
import os
import sys
import pty
import signal
import struct
import termios
import json
import logging
import re
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from _auth_middleware import configured_token
from _safe_env import safe_env

logging.basicConfig(level=logging.INFO, format="%(asctime)s [terminal] %(message)s")
logger = logging.getLogger("terminal-server")

PORT = int(os.getenv("TERMINAL_WS_PORT", "8016"))
MAX_SESSIONS = int(os.getenv("TERMINAL_MAX_SESSIONS") or "5")

_active_sessions = 0
_session_lock = asyncio.Lock()
_warned_no_token = False


def _effective_max_sessions() -> int:
    """MAX_SESSIONS, further reduced under memory pressure by the resource
    governor when available. Byte-budget on the measured terminal-session
    envelope. Fail-open to MAX_SESSIONS (governor absent/disabled)."""
    try:
        from graph_db import resource_governor as rg
    except Exception:
        try:
            # Functional fallback: graph_db lives beside mcp_servers (…/graph_db).
            _gd = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "graph_db")
            if _gd not in sys.path:
                sys.path.insert(0, _gd)
            import resource_governor as rg
        except Exception:
            return MAX_SESSIONS
    try:
        if not rg.governor_enabled():
            return MAX_SESSIONS
        env = rg.envelope("mcp_terminal_session_envelope_bytes")
        frac = rg._env_float("AGENT_MEM_BUDGET_FRACTION", 0.5)
        return max(1, min(MAX_SESSIONS, rg.scaled_cap(MAX_SESSIONS, env, frac, 1)))
    except Exception:
        return MAX_SESSIONS


def _bearer(headers) -> str:
    value = headers.get("Authorization", "") or ""
    return value[7:].strip() if value[:7].lower() == "bearer " else ""


def _tenant_env(path: str):
    """The shell's identity from the proxy's query, or None when it lacks one."""
    query = parse_qs(urlsplit(path or "").query)
    user_id = (query.get("user_id") or [""])[0].strip()
    project_id = (query.get("project_id") or [""])[0].strip()
    if not user_id or not project_id:
        return None
    return {"REDAMON_USER_ID": user_id, "REDAMON_PROJECT_ID": project_id}


# b64url(claims).b64url(hmac): the only shape the agent mints. Anything else never
# reaches the shell's environment.
_RUN_CREDENTIAL = re.compile(r"[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,128}")


def _shell_env(request):
    """_tenant_env plus the run credential the proxy sent, or None without an identity."""
    env = _tenant_env(request.path)
    if env is None:
        return None
    credential = (request.headers.get("X-Redamon-Run", "") or "").strip()
    if _RUN_CREDENTIAL.fullmatch(credential):
        env["REDAMON_RUN_CREDENTIAL"] = credential
    elif credential:
        logger.warning("Dropped a malformed run credential from the terminal upgrade")
    return env


def _process_request(connection, request):
    """Refuse the upgrade, before the handler runs, unless the agent's proxy sent it."""
    global _warned_no_token
    expected = configured_token()
    if not expected:
        if not _warned_no_token:
            logger.warning("MCP_AUTH_TOKEN is not set - refusing every terminal connection (fail-closed)")
            _warned_no_token = True
        return connection.respond(HTTPStatus.UNAUTHORIZED, "Unauthorized\n")
    presented = _bearer(request.headers)
    if not presented or not hmac.compare_digest(presented.encode(), expected.encode()):
        logger.warning("Refused a terminal upgrade without the agent's bearer")
        return connection.respond(HTTPStatus.UNAUTHORIZED, "Unauthorized\n")
    if _tenant_env(request.path) is None:
        logger.warning("Refused a terminal upgrade that names no user or project")
        return connection.respond(HTTPStatus.BAD_REQUEST, "Missing identity\n")
    return None


async def _pty_session(ws):
    """Handle a single WebSocket connection with a PTY bash shell."""
    global _active_sessions

    tenant_env = _shell_env(ws.request)
    if tenant_env is None:
        await ws.close(1008, "Missing identity")
        return

    async with _session_lock:
        eff_max = _effective_max_sessions()
        if _active_sessions >= eff_max:
            logger.warning("Max sessions (%d) reached, rejecting connection", eff_max)
            await ws.close(1013, "Max terminal sessions reached")
            return
        _active_sessions += 1

    logger.info("Terminal session started (active: %d)", _active_sessions)

    try:
        await _run_pty_session(ws, tenant_env)
    finally:
        async with _session_lock:
            _active_sessions -= 1
        logger.info("Terminal session ended (active: %d)", _active_sessions)


async def _read_init_frame(ws, timeout: float = 0.5) -> bytes:
    """
    Read the browser's optional first `init` frame before forking, so it is not
    typed into the shell. Its ids are ignored: the identity is the proxy's.

    Returns the first frame's raw bytes when it was NOT an init frame, so the PTY
    loop can replay it (clients that send no init keep working), else b"".
    """
    try:
        first = await asyncio.wait_for(ws.recv(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        return b""

    if isinstance(first, str):
        try:
            msg = json.loads(first)
            if isinstance(msg, dict) and msg.get("type") == "init":
                return b""
        except (json.JSONDecodeError, TypeError):
            pass
        return first.encode("utf-8")
    if isinstance(first, (bytes, bytearray)):
        return bytes(first)
    return b""


async def _run_pty_session(ws, tenant_env=None):
    """Run the actual PTY session for a WebSocket connection, as `tenant_env`."""
    replay_bytes = await _read_init_frame(ws)

    master_fd, slave_fd = pty.openpty()
    pid = os.fork()

    if pid == 0:
        # Child process — become the shell
        os.setsid()
        os.close(master_fd)

        # Set slave as controlling terminal
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)

        env = safe_env({
            "TERM": "xterm-256color",
            "SHELL": "/bin/bash",
            "PS1": r"\[\033[1;31m\]redamon\[\033[0m\]@\[\033[1;36m\]kali\[\033[0m\]:\[\033[1;33m\]\w\[\033[0m\]$ ",
            **(tenant_env or {}),
        })

        os.execvpe("/bin/bash", ["/bin/bash", "--login"], env)
        # Never reached
        os._exit(1)

    # Parent process — bridge WebSocket ↔ PTY
    os.close(slave_fd)

    # Set initial terminal size
    _set_pty_size(master_fd, 24, 80)

    # If the first frame was not an init message, replay it to the shell so
    # non-webapp clients (e.g. wscat) keep working.
    if replay_bytes:
        try:
            os.write(master_fd, replay_bytes)
        except OSError as e:
            logger.debug("Replay write failed: %s", e)

    close_event = asyncio.Event()

    async def read_pty():
        """Read from PTY master and forward to WebSocket using async I/O."""
        loop = asyncio.get_event_loop()
        queue = asyncio.Queue()

        def on_readable():
            try:
                data = os.read(master_fd, 4096)
                if data:
                    queue.put_nowait(data)
                else:
                    queue.put_nowait(None)
            except OSError as e:
                logger.debug("PTY read error: %s", e)
                queue.put_nowait(None)

        loop.add_reader(master_fd, on_readable)
        try:
            while not close_event.is_set():
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if data is None:
                    break
                try:
                    await ws.send(data)
                except Exception as e:
                    logger.debug("WebSocket send error: %s", e)
                    break
        finally:
            try:
                loop.remove_reader(master_fd)
            except Exception:
                pass

    async def write_pty():
        """Read from WebSocket and forward to PTY master."""
        from websockets.exceptions import ConnectionClosed

        try:
            async for message in ws:
                if close_event.is_set():
                    break

                if isinstance(message, bytes):
                    os.write(master_fd, message)
                elif isinstance(message, str):
                    control = _control_frame(message)
                    if control is None:
                        os.write(master_fd, message.encode("utf-8"))
                    elif control["type"] == "resize":
                        _set_pty_size(
                            master_fd, control.get("rows", 24), control.get("cols", 80)
                        )
        except (ConnectionClosed, OSError) as e:
            # The browser went away, or EIO once the shell has exited.
            logger.debug("PTY write loop ended: %s", e)
        except Exception as e:
            # Anything else ends a live session for a bug, so it must reach the log.
            logger.warning("PTY write loop failed: %r", e)
        finally:
            close_event.set()

    try:
        reader_task = asyncio.create_task(read_pty())
        writer_task = asyncio.create_task(write_pty())
        await asyncio.wait(
            [reader_task, writer_task], return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        close_event.set()
        # Kill entire process group (child calls os.setsid())
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        # Wait briefly for child to exit, then force-kill if still alive
        for _ in range(10):
            try:
                result = os.waitpid(pid, os.WNOHANG)
                if result[0] != 0:
                    break
            except ChildProcessError:
                break
            await asyncio.sleep(0.1)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError, PermissionError):
                pass


_CONTROL_TYPES = ("resize", "ping")


def _control_frame(message: str):
    """The control message a text frame carries, or None when it is keystrokes.

    Keystrokes and control messages share text frames, so a frame is control only
    when it is a JSON object naming a known type. Input that merely parses as JSON
    (a digit, `true`, `null`, a quoted word, a pasted array) is keystrokes; reading
    it as a message raises in the write loop and ends the session with close 1000.
    """
    try:
        msg = json.loads(message)
    except (ValueError, RecursionError):
        return None
    # A tuple, not a set: membership by ==, so an unhashable "type" cannot raise.
    if isinstance(msg, dict) and msg.get("type") in _CONTROL_TYPES:
        return msg
    return None


def _set_pty_size(fd: int, rows: int, cols: int):
    """Set the PTY window size, clamping to safe bounds."""
    try:
        rows = max(1, min(500, int(rows)))
        cols = max(1, min(500, int(cols)))
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except (OSError, ValueError, TypeError, OverflowError):
        pass


def serve(host: str, port: int):
    """The terminal's WebSocket server: every upgrade passes _process_request first."""
    import websockets

    return websockets.serve(
        _pty_session,
        host,
        port,
        process_request=_process_request,
        ping_interval=30,
        ping_timeout=60,
        max_size=2**20,
    )


def main():
    """Start the WebSocket terminal server."""
    logger.info(f"Starting terminal WebSocket server on port {PORT}")
    if not configured_token():
        logger.warning("MCP_AUTH_TOKEN is not set - every terminal connection will be refused")

    async def _run():
        async with serve("0.0.0.0", PORT):
            logger.info(f"Terminal server listening on ws://0.0.0.0:{PORT}")
            await asyncio.Future()  # Run forever

    asyncio.run(_run())


if __name__ == "__main__":
    main()

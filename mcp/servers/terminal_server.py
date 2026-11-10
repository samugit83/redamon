"""
RedAmon Terminal Server — WebSocket PTY for Kali Sandbox

Provides a WebSocket endpoint that spawns an interactive bash shell
with full PTY support. Used by the RedAmon Terminal tab in the webapp.

Runs on port 8016 inside the kali-sandbox container.
"""

import asyncio
import fcntl
import os
import sys
import pty
import signal
import struct
import termios
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [terminal] %(message)s")
logger = logging.getLogger("terminal-server")

PORT = int(os.getenv("TERMINAL_WS_PORT", "8016"))
MAX_SESSIONS = int(os.getenv("TERMINAL_MAX_SESSIONS") or "5")

_active_sessions = 0
_session_lock = asyncio.Lock()


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


async def _pty_session(ws):
    """Handle a single WebSocket connection with a PTY bash shell."""
    global _active_sessions

    async with _session_lock:
        eff_max = _effective_max_sessions()
        if _active_sessions >= eff_max:
            logger.warning("Max sessions (%d) reached, rejecting connection", eff_max)
            await ws.close(1013, "Max terminal sessions reached")
            return
        _active_sessions += 1

    logger.info("Terminal session started (active: %d)", _active_sessions)

    try:
        await _run_pty_session(ws)
    finally:
        async with _session_lock:
            _active_sessions -= 1
        logger.info("Terminal session ended (active: %d)", _active_sessions)


async def _read_init_frame(ws, timeout: float = 0.5):
    """
    Try to read an optional `init` JSON frame from the browser before forking.

    Expected shape: {"type": "init", "user_id": "...", "project_id": "..."}.
    Returns (tenant_env, replay_bytes):
      - tenant_env: dict of env vars to inject into the shell (may be empty)
      - replay_bytes: the first frame's raw bytes if it was NOT an init frame,
        so the PTY loop can replay it (preserves backward compat with clients
        that don't send init).
    """
    tenant_env: dict = {}
    replay: bytes = b""
    try:
        first = await asyncio.wait_for(ws.recv(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        return tenant_env, replay

    if isinstance(first, str):
        try:
            msg = json.loads(first)
            if isinstance(msg, dict) and msg.get("type") == "init":
                user_id = str(msg.get("user_id", "")).strip()
                project_id = str(msg.get("project_id", "")).strip()
                if user_id:
                    tenant_env["REDAMON_USER_ID"] = user_id
                if project_id:
                    tenant_env["REDAMON_PROJECT_ID"] = project_id
                logger.info(
                    "Init frame received (user=%s project=%s)",
                    user_id or "<none>", project_id or "<none>",
                )
                return tenant_env, replay
        except (json.JSONDecodeError, TypeError):
            pass
        replay = first.encode("utf-8")
    elif isinstance(first, (bytes, bytearray)):
        replay = bytes(first)

    return tenant_env, replay


async def _run_pty_session(ws):
    """Run the actual PTY session for a WebSocket connection."""
    tenant_env, replay_bytes = await _read_init_frame(ws)

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

        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["SHELL"] = "/bin/bash"
        env["PS1"] = r"\[\033[1;31m\]redamon\[\033[0m\]@\[\033[1;36m\]kali\[\033[0m\]:\[\033[1;33m\]\w\[\033[0m\]$ "
        env.update(tenant_env)

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


def main():
    """Start the WebSocket terminal server."""
    import websockets

    logger.info(f"Starting terminal WebSocket server on port {PORT}")

    async def _run():
        async with websockets.serve(
            _pty_session,
            "0.0.0.0",
            PORT,
            ping_interval=30,
            ping_timeout=60,
            max_size=2**20,
        ):
            logger.info(f"Terminal server listening on ws://0.0.0.0:{PORT}")
            await asyncio.Future()  # Run forever

    asyncio.run(_run())


if __name__ == "__main__":
    main()

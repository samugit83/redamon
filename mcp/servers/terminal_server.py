"""
RedAmon Terminal Server — WebSocket PTY for Kali Sandbox

Provides a WebSocket endpoint that spawns an interactive bash shell
with full PTY support. Used by the RedAmon Terminal tab in the webapp.

Runs on port 8016 inside the kali-sandbox container.
"""

import asyncio
import fcntl
import os
import pty
import signal
import struct
import termios
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [terminal] %(message)s")
logger = logging.getLogger("terminal-server")

PORT = int(os.getenv("TERMINAL_WS_PORT", "8016"))
MAX_SESSIONS = int(os.getenv("TERMINAL_MAX_SESSIONS", "5"))

_active_sessions = 0
_session_lock = asyncio.Lock()


async def _pty_session(ws):
    """Handle a single WebSocket connection with a PTY bash shell."""
    global _active_sessions

    async with _session_lock:
        if _active_sessions >= MAX_SESSIONS:
            logger.warning("Max sessions (%d) reached, rejecting connection", MAX_SESSIONS)
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


async def _run_pty_session(ws):
    """Run the actual PTY session for a WebSocket connection."""
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

        os.execvpe("/bin/bash", ["/bin/bash", "--login"], env)
        # Never reached
        os._exit(1)

    # Parent process — bridge WebSocket ↔ PTY
    os.close(slave_fd)

    # Set initial terminal size
    _set_pty_size(master_fd, 24, 80)

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
        try:
            async for message in ws:
                if close_event.is_set():
                    break

                if isinstance(message, bytes):
                    os.write(master_fd, message)
                elif isinstance(message, str):
                    # Handle JSON control messages
                    try:
                        msg = json.loads(message)
                        msg_type = msg.get("type")
                        if msg_type == "resize":
                            rows = msg.get("rows", 24)
                            cols = msg.get("cols", 80)
                            _set_pty_size(master_fd, rows, cols)
                            continue
                        if msg_type == "ping":
                            continue
                    except (json.JSONDecodeError, TypeError):
                        pass
                    os.write(master_fd, message.encode("utf-8"))
        except Exception as e:
            logger.debug("PTY write loop ended: %s", e)
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

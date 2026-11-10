"""
Unit tests for terminal_server.py

Tests the PTY terminal WebSocket server logic.
Run with: python -m pytest tests/test_terminal_server.py -v
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp', 'servers'))

import pytest


class TestSetPtySize:
    """Test the _set_pty_size helper function."""

    def test_set_pty_size_valid(self):
        """Should pack rows/cols into a TIOCSWINSZ struct without error."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 24, 80)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 24
            assert cols == 80
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_different_dimensions(self):
        """Should correctly set arbitrary dimensions."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 50, 200)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 50
            assert cols == 200
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_invalid_fd(self):
        """Should not raise on invalid file descriptor (graceful failure)."""
        from terminal_server import _set_pty_size
        _set_pty_size(-1, 24, 80)  # Should not raise

    def test_set_pty_size_clamps_large_rows(self):
        """Should clamp rows > 500 to 500."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 99999, 80)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 500
            assert cols == 80
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_clamps_large_cols(self):
        """Should clamp cols > 500 to 500."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 24, 99999)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 24
            assert cols == 500
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_clamps_zero_to_one(self):
        """Should clamp 0 to 1."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 0, 0)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 1
            assert cols == 1
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_clamps_negative(self):
        """Should clamp negative values to 1."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, -10, -20)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 1
            assert cols == 1
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_handles_non_integer(self):
        """Should not raise on non-integer inputs."""
        from terminal_server import _set_pty_size
        # These should all be handled gracefully without raising
        _set_pty_size(-1, "abc", "xyz")
        _set_pty_size(-1, None, None)
        _set_pty_size(-1, 3.7, 4.2)


class TestPortConfig:
    """Test port configuration from environment."""

    def test_default_port(self):
        """Should default to 8016 when TERMINAL_WS_PORT is not set."""
        env_backup = os.environ.pop("TERMINAL_WS_PORT", None)
        try:
            # Re-import to get fresh PORT value
            import importlib
            import terminal_server
            importlib.reload(terminal_server)
            assert terminal_server.PORT == 8016
        finally:
            if env_backup is not None:
                os.environ["TERMINAL_WS_PORT"] = env_backup

    def test_custom_port(self):
        """Should use TERMINAL_WS_PORT environment variable."""
        os.environ["TERMINAL_WS_PORT"] = "9999"
        try:
            import importlib
            import terminal_server
            importlib.reload(terminal_server)
            assert terminal_server.PORT == 9999
        finally:
            os.environ["TERMINAL_WS_PORT"] = "8016"


class TestConnectionLimits:
    """Test session limit configuration."""

    def test_default_max_sessions(self):
        """Should default to 5 max sessions."""
        env_backup = os.environ.pop("TERMINAL_MAX_SESSIONS", None)
        try:
            import importlib
            import terminal_server
            importlib.reload(terminal_server)
            assert terminal_server.MAX_SESSIONS == 5
        finally:
            if env_backup is not None:
                os.environ["TERMINAL_MAX_SESSIONS"] = env_backup

    def test_custom_max_sessions(self):
        """Should use TERMINAL_MAX_SESSIONS environment variable."""
        os.environ["TERMINAL_MAX_SESSIONS"] = "10"
        try:
            import importlib
            import terminal_server
            importlib.reload(terminal_server)
            assert terminal_server.MAX_SESSIONS == 10
        finally:
            os.environ.pop("TERMINAL_MAX_SESSIONS", None)


class TestControlFrame:
    """_control_frame decides whether a text frame is a control message or keystrokes."""

    def test_resize_is_control(self):
        from terminal_server import _control_frame
        msg = _control_frame(json.dumps({"type": "resize", "rows": 30, "cols": 120}))
        assert msg == {"type": "resize", "rows": 30, "cols": 120}

    def test_ping_is_control(self):
        from terminal_server import _control_frame
        assert _control_frame(json.dumps({"type": "ping"})) == {"type": "ping"}

    @pytest.mark.parametrize("frame", ["ls -la", "echo hello", "a", "-", "\r", "\x1b[A", ""])
    def test_plain_input_is_keystrokes(self, frame):
        from terminal_server import _control_frame
        assert _control_frame(frame) is None

    # Each of these parses as JSON but is not an object: typing any digit used to
    # close the terminal session.
    @pytest.mark.parametrize("frame", ["5", "0", "42", "-1", "1e5", "true", "false", "null", '"x"', "[1]", "[]"])
    def test_json_scalars_and_arrays_are_keystrokes(self, frame):
        from terminal_server import _control_frame
        assert _control_frame(frame) is None

    @pytest.mark.parametrize("frame", [
        json.dumps({"type": "init"}),
        json.dumps({"type": "exec"}),
        json.dumps({"rows": 1, "cols": 1}),
        json.dumps({"type": []}),
        json.dumps({"type": {"a": 1}}),
    ])
    def test_objects_without_a_known_type_are_keystrokes(self, frame):
        from terminal_server import _control_frame
        assert _control_frame(frame) is None

    def test_deeply_nested_paste_does_not_raise(self):
        from terminal_server import _control_frame
        assert _control_frame("[" * 200_000) is None


class TestWriteLoopSurvivesJsonInput:
    """End to end over a real PTY: JSON-looking keystrokes reach the shell and the session stays up."""

    def test_json_looking_keystrokes_reach_the_shell(self):
        import asyncio
        import terminal_server

        # Typed one key per frame, as xterm sends them. The PTY echoes the input
        # line back, so assert on "X42Y true null": only the shell's own output
        # has the arithmetic evaluated.
        frames = ["echo X$((", "4", "0", "+", "2", "))Y ", "true", " ", "null",
                  json.dumps({"type": "resize", "rows": 40, "cols": 100}),
                  json.dumps({"type": "ping"}), "\r"]
        expected = b"X42Y true null"

        class FakeWs:
            def __init__(self):
                self.sent = []
                self._frames = list(frames)

            async def recv(self):
                return json.dumps({"type": "init", "user_id": "u", "project_id": "p"})

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._frames:
                    return self._frames.pop(0)
                # Hold the socket open until the shell has printed the result.
                for _ in range(200):
                    if expected in b"".join(self.sent):
                        break
                    await asyncio.sleep(0.05)
                raise StopAsyncIteration

            async def send(self, data):
                self.sent.append(data)

        ws = FakeWs()
        asyncio.run(asyncio.wait_for(terminal_server._run_pty_session(ws), timeout=20))
        output = b"".join(ws.sent)
        assert expected in output, output[-500:]
        assert b"resize" not in output and b"ping" not in output

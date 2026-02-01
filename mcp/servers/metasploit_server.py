"""
Metasploit MCP Server - Stateful Exploitation Framework

Exposes Metasploit Framework as a single MCP tool with PERSISTENT state.
Uses a persistent msfconsole process that maintains state between calls.

Architecture:
    - Single persistent msfconsole process per server instance
    - Module context persists between calls
    - Meterpreter/shell sessions persist until explicitly closed
    - Timing-based output detection (universal, no regex parsing)

Tools:
    - metasploit_console: Execute any msfconsole command (stateful)
"""

from fastmcp import FastMCP
import subprocess
import threading
import queue
import time
import os
import re
import json
import atexit
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Set, List

# Server configuration
SERVER_NAME = "metasploit"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("METASPLOIT_PORT", "8003"))
DEBUG = os.getenv("MSF_DEBUG", "false").lower() == "true"

# Timing configuration (set by run_servers.py or use defaults)
# Brute force (run command): 30 min timeout, 2 min quiet (with VERBOSE=true, output comes frequently)
MSF_RUN_TIMEOUT = int(os.getenv("MSF_RUN_TIMEOUT", "1800"))
MSF_RUN_QUIET_PERIOD = float(os.getenv("MSF_RUN_QUIET_PERIOD", "120"))
# CVE exploits (exploit command): 10 min timeout, 3 min quiet
MSF_EXPLOIT_TIMEOUT = int(os.getenv("MSF_EXPLOIT_TIMEOUT", "600"))
MSF_EXPLOIT_QUIET_PERIOD = float(os.getenv("MSF_EXPLOIT_QUIET_PERIOD", "180"))
# Other commands: 2 min timeout, 3s quiet
MSF_DEFAULT_TIMEOUT = int(os.getenv("MSF_DEFAULT_TIMEOUT", "120"))
MSF_DEFAULT_QUIET_PERIOD = float(os.getenv("MSF_DEFAULT_QUIET_PERIOD", "3"))

mcp = FastMCP(SERVER_NAME)


class PersistentMsfConsole:
    """
    Manages a persistent msfconsole process with bidirectional I/O.

    Uses timing-based output detection - waits for output to settle
    rather than parsing specific prompts. This is universal and works
    with any msfconsole output format.
    """

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.output_queue: queue.Queue = queue.Queue()
        self.reader_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.session_ids: Set[int] = set()
        self._initialized = False

        # Progress tracking for live updates
        self._current_output: List[str] = []
        self._execution_active: bool = False
        self._current_command: str = ""
        self._execution_start_time: float = 0
        self._progress_lock = threading.Lock()

    def start(self) -> bool:
        """Start the persistent msfconsole process."""
        if self.process and self.process.poll() is None:
            return True  # Already running

        try:
            print("[MSF] Starting msfconsole process...")
            self.process = subprocess.Popen(
                ["msfconsole", "-q", "-x", ""],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            print(f"[MSF] Process started with PID: {self.process.pid}")

            # Start background thread to read output
            self.reader_thread = threading.Thread(
                target=self._read_output,
                daemon=True
            )
            self.reader_thread.start()

            # Wait for msfconsole to be ready (can take 60-120s on first start)
            self._wait_for_output(timeout=120, quiet_period=5.0)
            self._initialized = True
            print(f"[MSF] Persistent msfconsole ready (PID: {self.process.pid})")
            return True

        except Exception as e:
            print(f"[MSF] Failed to start msfconsole: {e}")
            return False

    def _read_output(self):
        """Background thread to continuously read msfconsole output."""
        if DEBUG:
            print("[MSF] Reader thread started")
        try:
            while self.process and self.process.poll() is None:
                line = self.process.stdout.readline()
                if line:
                    self.output_queue.put(line)
                    if DEBUG:
                        print(f"[MSF] OUTPUT: {line.rstrip()[:200]}")
                    self._detect_session_events(line)
        except Exception as e:
            print(f"[MSF] Reader thread error: {e}")
        if DEBUG:
            print("[MSF] Reader thread exited")

    def _detect_session_events(self, line: str):
        """Simple session event detection - just tracks session IDs."""
        line_lower = line.lower()

        # Detect "session X opened"
        if 'session' in line_lower and 'opened' in line_lower:
            try:
                idx = line_lower.index('session')
                rest = line_lower[idx + 7:].strip()
                parts = rest.split()
                if parts and parts[0].isdigit():
                    session_id = int(parts[0])
                    self.session_ids.add(session_id)
                    print(f"[MSF] Session {session_id} opened")
            except (ValueError, IndexError):
                pass

        # Detect "session X closed"
        elif 'session' in line_lower and 'closed' in line_lower:
            try:
                idx = line_lower.index('session')
                rest = line_lower[idx + 7:].strip()
                parts = rest.split()
                if parts and parts[0].isdigit():
                    session_id = int(parts[0])
                    self.session_ids.discard(session_id)
                    print(f"[MSF] Session {session_id} closed")
            except (ValueError, IndexError):
                pass

    def _is_meaningful_output(self, line: str) -> bool:
        """
        Check if a line is meaningful output (not just prompt/cursor noise).

        Prompt redraws and cursor movements shouldn't reset the quiet period timer.
        """
        # Strip ANSI escape codes for checking
        clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line).strip()

        # Empty after stripping = noise
        if not clean:
            return False

        # Just the msf prompt = noise (variations: "msf >", "msf6 >", "msf exploit(...) >")
        if re.match(r'^msf\d?\s*([\w\(\)/]+\s*)?>?\s*$', clean, re.IGNORECASE):
            return False

        # Just cursor positioning or escape sequences = noise
        if clean in ['>', '']:
            return False

        return True

    def _wait_for_output(self, timeout: float, quiet_period: float) -> str:
        """
        Wait for msfconsole output using timing-based detection.
        Waits until no new output arrives for 'quiet_period' seconds.
        Also tracks progress for live updates via HTTP endpoint.

        Note: Prompt redraws and cursor movements are ignored for quiet period calculation.
        """
        # Initialize progress tracking
        with self._progress_lock:
            self._current_output = []
            self._execution_active = True
            self._execution_start_time = time.time()

        output_lines = []
        end_time = time.time() + timeout
        start_time = time.time()
        last_output_time = time.time()

        min_wait = min(3.0, timeout / 2)

        while time.time() < end_time:
            try:
                line = self.output_queue.get(timeout=0.1)
                stripped = line.rstrip()
                output_lines.append(stripped)

                # Only reset quiet period timer for meaningful output
                # (not prompt redraws or cursor movements)
                if self._is_meaningful_output(stripped):
                    last_output_time = time.time()

                # Track progress for HTTP endpoint (include all lines for display)
                with self._progress_lock:
                    self._current_output.append(stripped)

            except queue.Empty:
                elapsed = time.time() - start_time
                time_since_last = time.time() - last_output_time

                if output_lines and time_since_last >= quiet_period:
                    if DEBUG:
                        print(f"[MSF] Output complete ({quiet_period}s quiet)")
                    break

                if not output_lines and elapsed < min_wait:
                    continue

        # Mark execution complete
        with self._progress_lock:
            self._execution_active = False

        return '\n'.join(output_lines)

    def execute(self, command: str, timeout: float = 120, quiet_period: float = 2.0) -> str:
        """Execute a command in the persistent msfconsole."""
        with self.lock:
            if not self.process or self.process.poll() is not None:
                if not self.start():
                    return "[ERROR] Failed to start msfconsole"

            # Track current command for progress endpoint
            with self._progress_lock:
                self._current_command = command

            # Clear any pending output
            while not self.output_queue.empty():
                try:
                    self.output_queue.get_nowait()
                except queue.Empty:
                    break

            # Send command(s) - split by semicolons to support chaining
            # msfconsole doesn't parse semicolons in stdin, so we convert them to newlines
            try:
                if ';' in command:
                    # Split by semicolons and send each as separate line
                    commands = [cmd.strip() for cmd in command.split(';') if cmd.strip()]
                    for cmd in commands:
                        self.process.stdin.write(cmd + "\n")
                    self.process.stdin.flush()
                else:
                    self.process.stdin.write(command + "\n")
                    self.process.stdin.flush()
            except Exception as e:
                return f"[ERROR] Failed to send command: {e}"

            # Collect output
            output = self._wait_for_output(timeout=timeout, quiet_period=quiet_period)
            return output if output else "(no output)"

    def stop(self, force: bool = False):
        """Stop the msfconsole process."""
        if self.process and self.process.poll() is None:
            if force:
                print("[MSF] Force killing msfconsole process...")
                try:
                    self.process.kill()
                    self.process.wait(timeout=5)
                except:
                    pass
            else:
                try:
                    self.process.stdin.write("exit -y\n")
                    self.process.stdin.flush()
                    self.process.wait(timeout=5)
                except:
                    self.process.kill()
            print("[MSF] msfconsole stopped")
        self.process = None
        self._initialized = False
        self.session_ids.clear()

    def restart(self):
        """Restart msfconsole for a completely clean state."""
        print("[MSF] Restarting msfconsole...")
        self.stop(force=True)
        # Clear progress tracking state
        with self._progress_lock:
            self._current_output = []
            self._execution_active = False
            self._current_command = ""
            self._execution_start_time = 0
        # Clear output queue
        while not self.output_queue.empty():
            try:
                self.output_queue.get_nowait()
            except queue.Empty:
                break
        print("[MSF] Old process terminated, ready for fresh start")

    def get_progress(self) -> dict:
        """Get current execution progress (thread-safe) for HTTP endpoint."""
        with self._progress_lock:
            # Join last 100 lines and clean ANSI codes for display
            raw_output = '\n'.join(self._current_output[-100:])
            clean_output = _clean_ansi_for_progress(raw_output)
            return {
                "active": self._execution_active,
                "command": self._current_command[:100] if self._current_command else "",
                "elapsed_seconds": round(time.time() - self._execution_start_time, 1) if self._execution_active else 0,
                "line_count": len(self._current_output),
                "output": clean_output
            }


# Global singleton instance
_msf_console: Optional[PersistentMsfConsole] = None
_msf_lock = threading.Lock()


def get_msf_console() -> PersistentMsfConsole:
    """Get or create the persistent msfconsole instance."""
    global _msf_console
    with _msf_lock:
        if _msf_console is None:
            _msf_console = PersistentMsfConsole()
            _msf_console.start()
            atexit.register(_msf_console.stop)
        elif not _msf_console._initialized:
            _msf_console.start()
    return _msf_console


def _get_timing_for_command(command: str) -> tuple[float, float]:
    """Determine timeout and quiet_period based on command type.

    Different timing for different command types:
    - run (brute force): 5 min quiet period, 20 min total timeout
    - exploit (CVE): 3 min quiet period, 10 min total timeout

    Timing is configurable via environment variables (set in run_servers.py).
    """
    cmd_lower = command.lower()

    if 'run' in cmd_lower:
        # Brute force modules (ssh_login, ftp_login, etc.) use 'run' command
        # Long pauses between SSH login attempts possible
        return (MSF_RUN_TIMEOUT, MSF_RUN_QUIET_PERIOD)
    elif 'exploit' in cmd_lower:
        # CVE exploits - may have staged payloads with delays
        return (MSF_EXPLOIT_TIMEOUT, MSF_EXPLOIT_QUIET_PERIOD)
    elif 'search' in cmd_lower:
        return (60, MSF_DEFAULT_QUIET_PERIOD)
    elif 'sessions' in cmd_lower:
        return (60, 5.0)
    elif any(x in cmd_lower for x in ['info', 'show']):
        return (60, MSF_DEFAULT_QUIET_PERIOD)
    else:
        return (MSF_DEFAULT_TIMEOUT, MSF_DEFAULT_QUIET_PERIOD)


def _clean_ansi_output(text: str) -> str:
    """Remove ANSI escape codes and control characters from msfconsole output."""
    # Remove ANSI escape sequences
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    text = re.sub(r'\x1b[()][AB012]', '', text)

    cleaned_lines = []
    for line in text.split('\n'):
        # Handle carriage returns
        if '\r' in line:
            parts = line.split('\r')
            non_empty_parts = [p for p in parts if p.strip()]
            if non_empty_parts:
                line = non_empty_parts[-1]
            else:
                line = ''

        # Handle backspaces
        while '\x08' in line:
            pos = line.find('\x08')
            if pos > 0:
                line = line[:pos-1] + line[pos+1:]
            else:
                line = line[1:]

        # Remove control characters
        line = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', line)
        line = line.rstrip()

        if line or (cleaned_lines and cleaned_lines[-1]):
            cleaned_lines.append(line)

    # Remove trailing empty lines
    while cleaned_lines and not cleaned_lines[-1]:
        cleaned_lines.pop()

    # Remove garbled echo lines
    final_lines = []
    for line in cleaned_lines:
        if line.startswith('<'):
            continue
        if re.match(r'^msf\s+\S+>\S', line):
            continue
        if len(line) < 5 and not line.startswith('[') and '=>' not in line:
            continue
        final_lines.append(line)

    return '\n'.join(final_lines)


def _clean_ansi_for_progress(text: str) -> str:
    """
    Light ANSI cleaning for progress output.

    Less aggressive than _clean_ansi_output - keeps more content
    but removes escape codes for clean display.
    """
    # Remove ANSI escape sequences (colors, formatting)
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    text = re.sub(r'\x1b[()][AB012]', '', text)
    # Remove other control characters except newlines
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


# =============================================================================
# MCP TOOL - Single tool for all Metasploit operations
# =============================================================================

@mcp.tool()
def metasploit_console(command: str) -> str:
    """
    Execute Metasploit Framework console commands with PERSISTENT state.

    This is the ONLY tool you need for all Metasploit operations.
    The msfconsole process runs continuously - state persists between calls.

    ## Context Detection (IMPORTANT for post-exploitation!)

    Check the OUTPUT to know where you are:

    | Output ends with      | You are in              | What to do                      |
    |-----------------------|-------------------------|----------------------------------|
    | `msf6 >` or `msf >`   | Main Metasploit console | Configure modules, run exploits  |
    | `meterpreter >`       | Inside Meterpreter      | Run meterpreter commands         |
    | `shell >` or `$ ` `#` | Inside system shell     | Run OS commands (whoami, ls)     |

    ## Exploitation Workflow

    1. Search: "search CVE-2021-41773"
    2. Use module: "use exploit/multi/http/apache_normalize_path_rce"
    3. Configure: "set RHOSTS x.x.x.x" (one option per call)
    4. Exploit: "exploit"
    5. Check output for session or meterpreter prompt

    ## Post-Exploitation Workflow (after session established)

    If output shows `meterpreter >`:
    - You're IN the session, run commands directly: "sysinfo", "getuid", "shell"

    If output shows `msf6 >`:
    - Enter session: "sessions -i 1"
    - Then run meterpreter commands

    To drop to OS shell from meterpreter:
    - Run: "shell"
    - Now you can run: "whoami", "id", "cat /etc/passwd"
    - Exit shell back to meterpreter: "exit"

    To background session (return to msf console):
    - Run: "background"

    ## Common Commands

    Exploitation:
    - "search <term>" - Find modules
    - "use <module>" - Load module
    - "show options" - See required options
    - "set <OPTION> <value>" - Set option
    - "exploit" - Run the exploit

    Session Management:
    - "sessions -l" - List all sessions
    - "sessions -i <id>" - Interact with session
    - "background" - Background current session
    - "sessions -k <id>" - Kill session

    Meterpreter (when in session):
    - "sysinfo" - System information
    - "getuid" - Current user
    - "shell" - Drop to OS shell
    - "download <file>" - Download file
    - "upload <file>" - Upload file

    Args:
        command: The msfconsole command to execute

    Returns:
        The output from msfconsole (check prompt to know your context)
    """
    if DEBUG:
        print(f"[MSF] Executing: {command[:100]}...")

    msf = get_msf_console()
    timeout, quiet_period = _get_timing_for_command(command)

    if DEBUG:
        print(f"[MSF] timeout={timeout}s, quiet_period={quiet_period}s")

    result = msf.execute(command, timeout=timeout, quiet_period=quiet_period)
    result = _clean_ansi_output(result)

    if DEBUG:
        print(f"[MSF] Result ({len(result)} chars)")

    return result


@mcp.tool()
def msf_restart() -> str:
    """
    Restart msfconsole completely for a clean state.

    This tool:
    - Kills all active sessions
    - Terminates the msfconsole process
    - Starts a fresh msfconsole instance
    - Resets all module configurations

    Use this when:
    - Starting a new penetration test session
    - Clearing stuck/hung sessions
    - Resetting after errors
    - Ensuring a clean slate for new attacks

    Returns:
        Confirmation message with restart status
    """
    print("[MSF] Restarting msfconsole (full reset)...")

    msf = get_msf_console()
    msf.restart()

    # Start fresh process
    if msf.start():
        return "Metasploit console restarted successfully. All sessions cleared, all module settings reset. Ready for new commands."
    else:
        return "[ERROR] Failed to restart msfconsole. Check container logs."


# =============================================================================
# HTTP PROGRESS SERVER - For live progress updates during execution
# =============================================================================

PROGRESS_PORT = int(os.getenv("MSF_PROGRESS_PORT", "8013"))


class ProgressHandler(BaseHTTPRequestHandler):
    """HTTP handler for progress endpoint."""

    def do_GET(self):
        if self.path == '/progress':
            try:
                msf = get_msf_console()
                progress = msf.get_progress()

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(progress).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress request logging."""
        pass


def start_progress_server(port: int = PROGRESS_PORT):
    """Start HTTP server for progress endpoint in a background thread."""
    server = HTTPServer(('0.0.0.0', port), ProgressHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[MSF] Progress server started on port {port}")
    return server


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        # Start progress HTTP server alongside MCP
        start_progress_server(PROGRESS_PORT)
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")

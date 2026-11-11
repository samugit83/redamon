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
from typing import Optional, Set, List, Dict, Tuple

from _safe_env import safe_env

# Server configuration
SERVER_NAME = "metasploit"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("METASPLOIT_PORT", "8003"))
DEBUG = os.getenv("MSF_DEBUG", "false").lower() == "true"

# Timing configuration (set by run_servers.py or use defaults)
# Brute force (run command): 30 min timeout, 20s quiet (with VERBOSE=true, output comes frequently)
MSF_RUN_TIMEOUT = int(os.getenv("MSF_RUN_TIMEOUT", "1800"))
MSF_RUN_QUIET_PERIOD = float(os.getenv("MSF_RUN_QUIET_PERIOD", "20"))
# CVE exploits (exploit command): 10 min timeout, 20sec quiet
MSF_EXPLOIT_TIMEOUT = int(os.getenv("MSF_EXPLOIT_TIMEOUT", "600"))
MSF_EXPLOIT_QUIET_PERIOD = float(os.getenv("MSF_EXPLOIT_QUIET_PERIOD", "20"))
# Other commands: 2 min timeout, 3s quiet
MSF_DEFAULT_TIMEOUT = int(os.getenv("MSF_DEFAULT_TIMEOUT", "120"))
MSF_DEFAULT_QUIET_PERIOD = float(os.getenv("MSF_DEFAULT_QUIET_PERIOD", "3"))

# msfconsole reads stdin line by line and runs any line it does not recognise
# as a LOCAL shell command (AllowCommandPassthru defaults on; this container is
# root). A newline in a session command would end the `sessions -c` line and run
# the rest here, not on the target; other control bytes (^C, ^Z, ESC) can drive
# the console itself. Tab is the one control byte a command legitimately carries.
_SESSION_CMD_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

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

        # Session management — cached detail info refreshed by background thread
        self._session_details: List[dict] = []
        self._job_details: List[dict] = []
        self._detail_cache_time: float = 0
        self._detail_lock = threading.Lock()
        self._chat_session_map: Dict[int, str] = {}
        self._non_msf_sessions: Dict[str, dict] = {}
        self._detail_thread_started = False

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
                env=safe_env(),
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

            # Start session detail refresh thread (once)
            if not self._detail_thread_started:
                self._detail_thread = threading.Thread(
                    target=self._refresh_details_loop, daemon=True
                )
                self._detail_thread.start()
                self._detail_thread_started = True
                print("[MSF] Session detail refresh thread started")

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
        # Includes private mode sequences like \x1b[?25h (show cursor) / \x1b[?25l (hide cursor)
        clean = re.sub(r'\x1b\[[\?]?[0-9;]*[a-zA-Z]', '', line)
        # Also strip OSC sequences and other escape types
        clean = re.sub(r'\x1b\][^\x07]*\x07', '', clean)
        clean = re.sub(r'\x1b[()][AB012]', '', clean)
        clean = clean.strip()

        # Empty after stripping = noise
        if not clean:
            return False

        # Just the msf prompt = noise (variations: "msf >", "msf6 >", "msf exploit(...) >")
        if re.match(r'^msf\d?\s*([\w\(\)/]+\s*)?>?\s*$', clean, re.IGNORECASE):
            return False

        # Shell prompt noise ($ or # alone, possibly with hostname)
        if re.match(r'^[\$#>]\s*$', clean):
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

    # =========================================================================
    # SESSION MANAGEMENT — quick execute, detail refresh, interaction
    # =========================================================================

    def _quick_execute(self, command: str, timeout: float = 15, quiet_period: float = 3.0) -> str:
        """
        Execute a quick command without acquiring self.lock.
        Caller MUST hold self.lock before calling this method.
        Does not update progress tracking (used for internal session queries).
        """
        if not self.process or self.process.poll() is not None:
            return "[ERROR] msfconsole not running"

        # Clear pending output
        while not self.output_queue.empty():
            try:
                self.output_queue.get_nowait()
            except queue.Empty:
                break

        # Send command
        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
        except Exception as e:
            return f"[ERROR] Failed to send command: {e}"

        # Collect output using timing-based detection (same logic as _wait_for_output)
        output_lines = []
        end_time = time.time() + timeout
        start_time = time.time()
        last_output_time = time.time()
        min_wait = min(2.0, timeout / 2)

        while time.time() < end_time:
            try:
                line = self.output_queue.get(timeout=0.1)
                stripped = line.rstrip()
                output_lines.append(stripped)
                if self._is_meaningful_output(stripped):
                    last_output_time = time.time()
            except queue.Empty:
                elapsed = time.time() - start_time
                time_since_last = time.time() - last_output_time
                if output_lines and time_since_last >= quiet_period:
                    break
                if not output_lines and elapsed < min_wait:
                    continue

        return '\n'.join(output_lines)

    def _ensure_msf_prompt(self):
        """Ensure msfconsole is at the msf> prompt, not inside a session.

        If the console is inside a meterpreter or shell session (left behind
        after an agent exploit), send 'background' to return to msf>.
        Caller MUST hold self.lock.
        """
        # Drain any pending output from previous commands
        while not self.output_queue.empty():
            try:
                self.output_queue.get_nowait()
            except queue.Empty:
                break
        # Send a blank line to trigger a prompt redraw
        self.process.stdin.write("\n")
        self.process.stdin.flush()
        # Wait for prompt to appear (up to 1s, stop as soon as we get output)
        prompt_lines = []
        start = time.time()
        while time.time() - start < 1.0:
            try:
                prompt_lines.append(self.output_queue.get(timeout=0.15))
            except queue.Empty:
                if prompt_lines:
                    break
        prompt_text = ' '.join(prompt_lines).lower().strip()
        if not prompt_text:
            return  # No prompt detected, assume msf> (safe default)
        # Check if we're inside a meterpreter session
        if 'meterpreter' in prompt_text:
            print("[MSF] Console stuck in meterpreter session — sending 'background'")
            self._quick_execute("background", timeout=5, quiet_period=1.0)
        # Check if we're at the msf> prompt (safe — do nothing)
        elif 'msf' in prompt_text:
            return
        # Check if we're inside a raw shell ($ or # prompt).
        # This should only happen if the agent left msfconsole inside a session
        # (e.g., after an exploit). The UI's interact_session never enters shell
        # sessions interactively (uses `sessions -c` instead), so this is a
        # recovery path for agent-created stuck states only.
        # Send `exit` to leave — this may kill the shell session, but it's
        # the only reliable way to recover msfconsole through a subprocess pipe
        # (Ctrl+Z doesn't work reliably through pipes).
        elif re.search(r'[\$#]\s*$', prompt_text):
            print(f"[MSF] Console stuck in raw shell (prompt: {prompt_text!r}) — sending 'exit' to recover msf>")
            self._quick_execute("exit", timeout=5, quiet_period=1.0)
            # After exiting the OS shell, we might be at meterpreter > — check and background
            while not self.output_queue.empty():
                try:
                    self.output_queue.get_nowait()
                except queue.Empty:
                    break
            self.process.stdin.write("\n")
            self.process.stdin.flush()
            post_lines = []
            t0 = time.time()
            while time.time() - t0 < 1.0:
                try:
                    post_lines.append(self.output_queue.get(timeout=0.15))
                except queue.Empty:
                    if post_lines:
                        break
            post_text = ' '.join(post_lines).lower().strip()
            if 'meterpreter' in post_text:
                print("[MSF] Now at meterpreter prompt — sending 'background'")
                self._quick_execute("background", timeout=5, quiet_period=1.0)
            elif 'msf' in post_text or not post_text:
                return  # Already at msf> or no prompt (safe default)
        # Any other non-msf prompt with > (e.g., irb, pry)
        elif '>' in prompt_text:
            print(f"[MSF] Console in unknown interactive mode (prompt: {prompt_text!r}) — sending 'exit'")
            self._quick_execute("exit", timeout=5, quiet_period=1.0)

    def _refresh_details_loop(self):
        """Background thread that periodically refreshes session & job details."""
        while True:
            time.sleep(3)
            if not self._initialized:
                continue
            # Try to acquire lock briefly — don't block if agent is busy
            acquired = self.lock.acquire(timeout=0.5)
            if not acquired:
                continue
            try:
                # Ensure we're at msf> prompt, not inside a session
                self._ensure_msf_prompt()
                raw_sessions = self._quick_execute("sessions -l", timeout=10, quiet_period=1.0)
                raw_jobs = self._quick_execute("jobs -l", timeout=10, quiet_period=1.0)
                parsed_sessions = self._parse_sessions_output(raw_sessions)
                parsed_jobs = self._parse_jobs_output(raw_jobs)
                with self._detail_lock:
                    self._session_details = parsed_sessions
                    self._job_details = parsed_jobs
                    self._detail_cache_time = time.time()
            except Exception as e:
                print(f"[MSF] Session detail refresh error: {e}")
            finally:
                self.lock.release()

    def _parse_sessions_output(self, raw: str) -> List[dict]:
        """Parse 'sessions -l' output into structured dicts.

        sessions -l uses fixed-width columns separated by 2+ spaces:
            Id  Name  Type                     Information          Connection
            --  ----  ----                     -----------          ----------
            1         meterpreter x86/linux    uid=0                172.28.0.5:4444 -> ...

        When Name is empty (most common), splitting by 2+ spaces yields:
            [Id, Type, Info, Connection] — 3 or 4 parts
        When Name is present:
            [Id, Name, Type, Info, Connection] — 4 or 5 parts
        """
        sessions = []
        if not raw or 'No active sessions' in raw:
            return sessions

        lines = raw.strip().split('\n')
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('--') or stripped.startswith('Id'):
                continue
            if stripped.startswith('Active') or stripped.startswith('==='):
                continue

            # Split by 2+ consecutive spaces (column separator)
            parts = [p for p in re.split(r'\s{2,}', stripped) if p]
            if not parts or not parts[0].isdigit():
                continue

            sid = int(parts[0])

            # Determine fields based on part count
            # 3 parts: Id, Type, Connection (no Info)
            # 4 parts: Id, Type, Info, Connection  OR  Id, Name, Type, Connection
            # 5 parts: Id, Name, Type, Info, Connection
            if len(parts) >= 5:
                # Has Name
                stype_raw = parts[2].lower()
                info = parts[3]
                connection = parts[4]
            elif len(parts) == 4:
                # Could be (Id, Type, Info, Connection) or (Id, Name, Type, Connection)
                # Heuristic: if parts[1] contains "meterpreter" or "shell", it's the Type
                if 'meterpreter' in parts[1].lower() or 'shell' in parts[1].lower():
                    stype_raw = parts[1].lower()
                    info = parts[2]
                    connection = parts[3]
                else:
                    # parts[1] is Name, parts[2] is Type
                    stype_raw = parts[2].lower()
                    info = ""
                    connection = parts[3]
            elif len(parts) == 3:
                # Id, Type, Connection (no Info)
                stype_raw = parts[1].lower()
                info = ""
                connection = parts[2]
            else:
                # Fallback for 2 or fewer parts
                sessions.append({
                    "id": sid,
                    "type": "unknown",
                    "info": stripped,
                    "connection": "",
                    "target_ip": "",
                    "chat_session_id": self._chat_session_map.get(sid),
                })
                continue

            stype = 'meterpreter' if 'meterpreter' in stype_raw else 'shell'

            # Extract target IP from connection string like "1.2.3.4:4444 -> 5.6.7.8:12345"
            target_ip = ""
            conn_match = re.search(r'->\s*([\d.]+)', connection)
            if conn_match:
                target_ip = conn_match.group(1)

            session = {
                "id": sid,
                "type": stype,
                "info": info,
                "connection": connection,
                "target_ip": target_ip,
                "chat_session_id": self._chat_session_map.get(sid),
            }
            sessions.append(session)

        return sessions

    def _parse_jobs_output(self, raw: str) -> List[dict]:
        """Parse 'jobs -l' output into structured dicts."""
        jobs = []
        if not raw or 'No active jobs' in raw:
            return jobs

        # jobs -l format:
        #   Id  Name                    Payload                          Payload opts
        #   --  ----                    -------                          ------------
        #   0   Exploit: multi/handler  linux/x64/meterpreter/reverse_tcp  tcp://0.0.0.0:4444
        lines = raw.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('--') or line.startswith('Id'):
                continue
            match = re.match(
                r'^\s*(\d+)\s+'    # Id
                r'(.+?)\s{2,}'     # Name
                r'(\S+)\s*'        # Payload
                r'(.*)?$',         # Payload opts
                line
            )
            if match:
                jid = int(match.group(1))
                name = match.group(2).strip()
                payload = match.group(3).strip()
                opts = match.group(4).strip() if match.group(4) else ""
                # Try to extract port from opts like "tcp://0.0.0.0:4444"
                port = 0
                port_match = re.search(r':(\d+)', opts)
                if port_match:
                    port = int(port_match.group(1))
                jobs.append({
                    "id": jid,
                    "name": name,
                    "payload": payload,
                    "port": port,
                })

        return jobs

    def get_sessions_data(self) -> dict:
        """Get cached session data for the HTTP endpoint (no lock needed)."""
        with self._detail_lock:
            return {
                "sessions": list(self._session_details),
                "jobs": list(self._job_details),
                "non_msf_sessions": list(self._non_msf_sessions.values()),
                "cache_age_seconds": round(time.time() - self._detail_cache_time, 1) if self._detail_cache_time > 0 else -1,
                "agent_busy": self._execution_active,
            }

    def interact_session(self, session_id: int, command: str) -> dict:
        """Send a command to a specific session. Uses try-with-timeout on lock.

        Shell sessions use `sessions -c` to execute commands without entering
        the session interactively. This avoids the enter/exit problem entirely:
        - `exit` inside a shell session DESTROYS it
        - Ctrl+Z (\x1a) doesn't work reliably through subprocess pipes
        - `sessions -c "cmd" -i <id>` runs the command from the msf> prompt
          and never leaves it, keeping the session alive.

        Meterpreter sessions still use interactive mode (sessions -i) because
        meterpreter commands (sysinfo, upload, migrate, etc.) require the
        meterpreter prompt context. `background` works reliably for meterpreter.
        """
        if _SESSION_CMD_CONTROL_RE.search(command):
            return {"busy": False,
                    "output": "[ERROR] Command must be a single line without control characters"}

        acquired = self.lock.acquire(timeout=8)
        if not acquired:
            return {"busy": True, "message": "Agent is executing a command, try again shortly"}
        try:
            # Determine session type from cache
            session_type = None
            with self._detail_lock:
                for s in self._session_details:
                    if s.get("id") == session_id:
                        session_type = s.get("type")
                        break

            # Cache miss — force an inline lookup
            if session_type is None:
                raw = self._quick_execute("sessions -l", timeout=10, quiet_period=2.0)
                parsed = self._parse_sessions_output(raw)
                with self._detail_lock:
                    self._session_details = parsed
                    self._detail_cache_time = time.time()
                for s in parsed:
                    if s.get("id") == session_id:
                        session_type = s.get("type")
                        break

            # Default to "shell" — the non-interactive path is safe for both
            if session_type is None:
                session_type = "shell"

            # ─── SHELL SESSIONS: non-interactive via `sessions -c` ───
            if session_type != "meterpreter":
                # msfconsole splits the line with Shellwords rules, where a
                # backslash inside double quotes escapes the next character: an
                # unescaped trailing backslash would swallow the closing quote.
                escaped_cmd = command.replace('\\', '\\\\').replace('"', '\\"')

                # Clear pending output
                while not self.output_queue.empty():
                    try:
                        self.output_queue.get_nowait()
                    except queue.Empty:
                        break

                # Send command
                try:
                    self.process.stdin.write(
                        f'sessions -c "{escaped_cmd}" -i {session_id}\n'
                    )
                    self.process.stdin.flush()
                except Exception as e:
                    return {"busy": False, "output": f"[ERROR] Failed to send command: {e}"}

                # Prompt-detection: read lines until msf prompt reappears.
                # sessions -c output flow:
                #   1. command echo (contains "sessions -c")
                #   2. [*] Running '...' on shell session N (...)
                #   3. <actual command output>       ← we want this
                #   4. msf prompt                    ← signals done
                _ansi_re = re.compile(r'\x1b\[[\?]?[0-9;]*[a-zA-Z]')
                _osc_re = re.compile(r'\x1b\][^\x07]*\x07')
                _charset_re = re.compile(r'\x1b[()][AB012]')
                _msf_prompt_re = re.compile(r'^msf\d?\s|^msf6')

                output_lines = []
                end_time = time.time() + 30
                saw_echo = False

                while time.time() < end_time:
                    try:
                        line = self.output_queue.get(timeout=0.2)
                        clean = _ansi_re.sub('', line.rstrip())
                        clean = _osc_re.sub('', clean)
                        clean = _charset_re.sub('', clean).strip()

                        if not clean:
                            continue

                        # Command echo — marks the start
                        if 'sessions -c' in clean:
                            saw_echo = True
                            continue

                        # msf prompt after echo — command is done
                        if saw_echo and _msf_prompt_re.match(clean):
                            break

                        # After echo: collect output, skip [*] noise lines
                        if saw_echo:
                            if clean.startswith('[*] Running '):
                                continue
                            if clean.startswith('[*] Command output'):
                                continue
                            output_lines.append(clean)

                    except queue.Empty:
                        continue

                output = '\n'.join(output_lines).strip()
                if not output:
                    output = "(no output)"
                return {"busy": False, "output": _clean_ansi_output(output)}

            # ─── METERPRETER SESSIONS: interactive mode ───
            # Detect command type for meterpreter sessions
            _SHELL_COMMANDS = {"shell", "irb", "python", "pry"}
            cmd_parts = command.strip().lower().split()
            cmd_lower = cmd_parts[0] if cmd_parts else ""
            has_inline_flag = len(cmd_parts) > 1 and cmd_parts[1] == "-c"
            opens_subshell = cmd_lower in _SHELL_COMMANDS and not has_inline_flag
            is_inline_shell = cmd_lower == "shell" and has_inline_flag

            # Enter meterpreter session
            enter_output = self._quick_execute(f"sessions -i {session_id}", timeout=10, quiet_period=1.0)
            if "Invalid session" in enter_output or "not found" in enter_output.lower():
                return {"busy": False, "output": f"[ERROR] Session {session_id} is no longer active"}

            if is_inline_shell:
                # "shell -c 'cmd'": open shell → run → exit shell → background meterpreter
                inner_cmd = re.sub(
                    r'^shell\s+-c\s+', '', command, flags=re.IGNORECASE
                ).strip()
                if (len(inner_cmd) >= 2
                        and inner_cmd[0] in ('"', "'")
                        and inner_cmd[-1] == inner_cmd[0]):
                    inner_cmd = inner_cmd[1:-1]
                self._quick_execute("shell", timeout=10, quiet_period=1.5)
                output = self._quick_execute(inner_cmd, timeout=30, quiet_period=1.5)
                self._quick_execute("exit", timeout=5, quiet_period=0.5)
                self._quick_execute("background", timeout=5, quiet_period=0.5)
            else:
                output = self._quick_execute(command, timeout=30, quiet_period=1.5)
                if opens_subshell:
                    self._quick_execute("exit", timeout=5, quiet_period=0.5)
                    self._quick_execute("background", timeout=5, quiet_period=0.5)
                else:
                    self._quick_execute("background", timeout=5, quiet_period=0.5)

            return {"busy": False, "output": _clean_ansi_output(output)}
        except Exception as e:
            return {"busy": False, "output": f"[ERROR] {str(e)}"}
        finally:
            self.lock.release()

    def kill_session(self, session_id: int) -> dict:
        """Kill a specific session."""
        acquired = self.lock.acquire(timeout=5)
        if not acquired:
            return {"busy": True, "message": "Agent is busy"}
        try:
            output = self._quick_execute(f"sessions -k {session_id}")
            self.session_ids.discard(session_id)
            return {"busy": False, "output": _clean_ansi_output(output)}
        finally:
            self.lock.release()

    def kill_job(self, job_id: int) -> dict:
        """Kill a background job."""
        acquired = self.lock.acquire(timeout=5)
        if not acquired:
            return {"busy": True, "message": "Agent is busy"}
        try:
            output = self._quick_execute(f"jobs -k {job_id}")
            return {"busy": False, "output": _clean_ansi_output(output)}
        finally:
            self.lock.release()


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
    # Remove ANSI escape sequences (including private mode like \x1b[?25h cursor show/hide)
    text = re.sub(r'\x1b\[[\?]?[0-9;]*[a-zA-Z]', '', text)
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


class SessionProgressHandler(BaseHTTPRequestHandler):
    """HTTP handler for progress + session management endpoints."""

    def _parse_route(self) -> Tuple[str, Optional[int], Optional[str]]:
        """Parse URL path into (resource, id, action).

        Examples:
            /progress         -> ('progress', None, None)
            /sessions         -> ('sessions', None, None)
            /sessions/1/interact -> ('sessions', 1, 'interact')
            /session-chat-map -> ('session-chat-map', None, None)
            /non-msf-sessions -> ('non-msf-sessions', None, None)
        """
        parts = [p for p in self.path.strip('/').split('/') if p]
        # Handle query params (strip anything after ?)
        if parts:
            parts[-1] = parts[-1].split('?')[0]

        resource = parts[0] if parts else ''
        res_id = None
        action = None
        if len(parts) >= 2:
            try:
                res_id = int(parts[1])
            except ValueError:
                pass
        if len(parts) >= 3:
            action = parts[2]
        return resource, res_id, action

    def _read_json_body(self) -> dict:
        """Read and parse JSON request body."""
        content_length = self.headers.get('Content-Length')
        if not content_length:
            return {}
        try:
            body = self.rfile.read(int(content_length))
            return json.loads(body) if body else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    def _send_json(self, status: int, data):
        """Send a JSON response.

        A client that polls this progress/session endpoint and hangs up mid-response
        (normal for a browser tab closing or the UI reconnecting) leaves the socket
        half-closed. Serialise BEFORE touching the socket, then swallow the resulting
        BrokenPipe/ConnectionReset instead of letting it bubble up: otherwise do_GET's
        own error handler tries to write a 500 to the same dead socket, faults again,
        and socketserver logs a noisy double traceback (issue #159)."""
        payload = json.dumps(data).encode()
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            # No CORS header (I9): served only server-side by the agent container;
            # leaks live session/exploitation data if readable cross-origin.
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # Client disconnected before we finished writing; nothing to recover.
            pass

    def _send_status(self, status: int):
        """Send a body-less status response (404/204/…), swallowing the same
        client-disconnect errors as _send_json so a poller that hangs up on these
        paths can't spam the log with an unhandled BrokenPipe traceback either."""
        try:
            self.send_response(status)
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        resource, res_id, action = self._parse_route()

        if resource == 'progress':
            try:
                msf = get_msf_console()
                progress = msf.get_progress()
                self._send_json(200, progress)
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif resource == 'sessions':
            try:
                msf = get_msf_console()
                data = msf.get_sessions_data()
                self._send_json(200, data)
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif resource == 'health':
            self._send_json(200, {"status": "ok"})

        else:
            self._send_status(404)

    def do_POST(self):
        resource, res_id, action = self._parse_route()
        body = self._read_json_body()

        try:
            msf = get_msf_console()

            if resource == 'sessions' and res_id is not None and action == 'interact':
                command = body.get("command", "")
                if not command or not isinstance(command, str):
                    self._send_json(400, {"error": "Missing 'command' in request body"})
                    return
                result = msf.interact_session(res_id, command)
                self._send_json(200, result)

            elif resource == 'sessions' and res_id is not None and action == 'kill':
                result = msf.kill_session(res_id)
                self._send_json(200, result)

            elif resource == 'jobs' and res_id is not None and action == 'kill':
                result = msf.kill_job(res_id)
                self._send_json(200, result)

            elif resource == 'session-chat-map':
                msf_sid = body.get("msf_session_id")
                chat_sid = body.get("chat_session_id")
                if msf_sid is not None and chat_sid:
                    msf._chat_session_map[int(msf_sid)] = str(chat_sid)
                    self._send_json(200, {"ok": True})
                else:
                    self._send_json(400, {"error": "Missing msf_session_id or chat_session_id"})

            elif resource == 'non-msf-sessions':
                sid = f"raw-{int(time.time()*1000)}"
                body["id"] = sid
                msf._non_msf_sessions[sid] = body
                self._send_json(200, {"ok": True, "id": sid})

            else:
                self._send_status(404)

        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def do_DELETE(self):
        resource, res_id, action = self._parse_route()

        if resource == 'non-msf-sessions' and res_id is not None:
            msf = get_msf_console()
            sid = f"raw-{res_id}"
            msf._non_msf_sessions.pop(sid, None)
            self._send_json(200, {"ok": True})
        else:
            self._send_status(404)

    def do_OPTIONS(self):
        """Preflight: no CORS allowance (I9). Cross-origin browser reads of this
        server-side-only endpoint are intentionally rejected."""
        self._send_status(204)

    def log_message(self, format, *args):
        """Suppress request logging."""
        pass


def start_progress_server(port: int = PROGRESS_PORT):
    """Start HTTP server for progress + session management in a background thread."""
    server = HTTPServer(('0.0.0.0', port), SessionProgressHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[MSF] Progress & session server started on port {port}")
    return server


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        # Start progress HTTP server alongside MCP
        start_progress_server(PROGRESS_PORT)
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")

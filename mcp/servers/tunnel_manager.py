"""
Lightweight HTTP server for managing ngrok/chisel tunnel processes.

Runs on port 8015 inside each person's Kali sandbox. The agent pushes the
person's tunnel configuration to it.

Endpoints:
  POST /tunnel/configure  — start/restart/stop tunnels
  GET  /tunnel/status     — current tunnel process status
  GET  /health            — simple health check
"""

import hmac
import json
import os
import re
import signal
import subprocess
import threading
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from _safe_env import safe_env

PORT = 8015

# Track tunnel processes
_lock = threading.Lock()
_ngrok_proc: subprocess.Popen | None = None
_chisel_proc: subprocess.Popen | None = None
# The chisel server's host, for the status: chisel itself reports no public endpoint.
_chisel_host: str | None = None

NGROK_API_PORT = 4040
_NGROK_API_READ_S = 2.0
_NGROK_API_MAX_BYTES = 64 * 1024

# Each client's log is the only place it says whether its tunnel forwards: a refused
# remote port (another client holds R:4444 on the same chisel server), a wrong
# credential or an unreachable server leave the process alive and retrying, so a
# running process is no proof. Each status names one of "on" (it forwards),
# "connecting", "error: <reason>" and "off" (not running).
CHISEL_LOG = "/var/log/chisel.log"
NGROK_LOG = "/var/log/ngrok.log"
_LOG_TAIL_BYTES = 64 * 1024
_REASON_MAX = 200
_CHISEL_ATTEMPT = re.compile(r"\s*\(Attempt: [^)]*\)\s*$")
_CHISEL_REMOTE_REFUSED = re.compile(r"Server cannot listen on R:(?:[^:=>\s]*:)?(\d+)")
_URL_USERINFO = re.compile(r"(//)[^/@\s]*@")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# An authtoken or credential a client may echo back (ngrok quotes the token it was
# given in its authentication error).
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_-]{24,}")
_NGROK_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_NGROK_CODE = re.compile(r"ERR_NGROK_\d+")

# STRIDE I19/S14: inbound bearer token the webapp presents on config pushes.
# Fail CLOSED when unset (STRIDE S5): every /tunnel/* request gets a 401, with a
# one-time warning, mirroring the MCP servers' MCP_AUTH_TOKEN convention.
_warned_failopen = False


def _configured_token() -> str:
    return os.environ.get("TUNNEL_AUTH_TOKEN", "") or ""


def _instance_mcp_token() -> str:
    return os.environ.get("MCP_AUTH_TOKEN", "") or ""


def ngrok_config(authtoken: str) -> str:
    """ngrok's config. Its local API (4040) checks no credential, so it stays on the
    sandbox's loopback: anything else on the sandbox's network could drive the
    tunnel. The agent reads the endpoint through this manager instead."""
    return f'version: "3"\nagent:\n  authtoken: {authtoken}\n  web_addr: 127.0.0.1:{NGROK_API_PORT}\n'


def _kill_process(proc: subprocess.Popen | None, name: str) -> None:
    if proc is None:
        return
    try:
        if proc.poll() is None:  # still running
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            print(f"[tunnel_manager] Stopped {name} (pid {proc.pid})")
    except Exception as e:
        print(f"[tunnel_manager] Error stopping {name}: {e}")


def _start_ngrok(authtoken: str) -> subprocess.Popen | None:
    if not authtoken:
        return None

    # Write ngrok config
    os.makedirs("/root/.config/ngrok", exist_ok=True)
    with open("/root/.config/ngrok/ngrok.yml", "w") as f:
        f.write(ngrok_config(authtoken))

    print("[tunnel_manager] Starting ngrok TCP tunnel on port 4444...")
    proc = subprocess.Popen(
        ["ngrok", "tcp", "4444", "--config", "/root/.config/ngrok/ngrok.yml",
         "--log=stdout", "--log-level=info"],
        stdout=open(NGROK_LOG, "w"),
        stderr=subprocess.STDOUT,
        env=safe_env(),
    )
    print(f"[tunnel_manager] ngrok started (pid {proc.pid})")
    return proc


def _start_chisel(server_url: str, auth: str) -> subprocess.Popen | None:
    if not server_url:
        return None

    # STRIDE I19: only expose the reverse-shell handler port (4444). The former
    # web-delivery reverse mapping on port 8080 published an internal HTTP
    # listener to the internet with no reverse-shell justification and is dropped.
    cmd = ["chisel", "client", server_url, "R:4444:localhost:4444"]

    print(f"[tunnel_manager] Starting chisel reverse tunnel to {server_url}...")
    proc = subprocess.Popen(
        cmd,
        stdout=open(CHISEL_LOG, "w"),
        stderr=subprocess.STDOUT,
        # chisel reads AUTH when --auth is absent: the credential stays off the
        # command line, which `ps` shows to every process here and on the host.
        env=safe_env({"AUTH": auth} if auth else None),
    )
    print(f"[tunnel_manager] chisel started (pid {proc.pid}, tunneling port 4444)")
    return proc


def _starts_a_tunnel(config: dict) -> bool:
    return bool(config.get("ngrokAuthtoken") or config.get("chiselServerUrl"))


def configure_tunnels(config: dict) -> dict:
    global _ngrok_proc, _chisel_proc, _chisel_host

    ngrok_token = config.get("ngrokAuthtoken", "")
    chisel_url = config.get("chiselServerUrl", "")
    chisel_auth = config.get("chiselAuth", "")

    with _lock:
        # Stop existing tunnels
        _kill_process(_ngrok_proc, "ngrok")
        _kill_process(_chisel_proc, "chisel")
        _ngrok_proc = None
        _chisel_proc = None

        # Start new tunnels
        _ngrok_proc = _start_ngrok(ngrok_token)
        _chisel_proc = _start_chisel(chisel_url, chisel_auth)
        _chisel_host = _url_host(chisel_url) if _chisel_proc is not None else None

    return {
        "status": "ok",
        "ngrok": _ngrok_proc is not None,
        "chisel": _chisel_proc is not None,
    }


def _url_host(url: str) -> str | None:
    try:
        return urlparse(url).hostname or None
    except ValueError:
        return None


def _ngrok_public_endpoint() -> tuple[str, int] | None:
    """(host, port) of ngrok's TCP tunnel from its local API on this container's
    loopback, or None. Bounded: the status call waits on it."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{NGROK_API_PORT}/api/tunnels",
                                    timeout=_NGROK_API_READ_S) as resp:
            data = json.loads(resp.read(_NGROK_API_MAX_BYTES + 1)[:_NGROK_API_MAX_BYTES])
        for tunnel in data.get("tunnels", []):
            if tunnel.get("proto") == "tcp":
                host, port = str(tunnel["public_url"]).replace("tcp://", "").rsplit(":", 1)
                return host, int(port)
    except Exception:
        return None
    return None


def _reason(text: str) -> str:
    text = _URL_USERINFO.sub(r"\1", _CONTROL.sub(" ", text))
    return _LONG_TOKEN.sub("***", text).strip()[:_REASON_MAX] or "unknown"


def _chisel_error(message: str) -> str:
    raw = _CHISEL_ATTEMPT.sub("", message)
    refused = _CHISEL_REMOTE_REFUSED.search(raw)
    if refused:
        return (f"remote port {refused.group(1)} in use on the chisel server (another client holds it; "
                f"each person needs their own chisel server)")
    if "unable to authenticate" in raw:
        return "authentication failed on the chisel server"
    return _reason(raw)


def chisel_log_status(log: str) -> tuple:
    """(status, reason) from the chisel client's log, read in order: "on" after
    "Connected" (its server took the reverse port), "error" with the last error while
    it keeps failing (a retry does not clear it), else "connecting"."""
    status, reason = "connecting", None
    for line in log.splitlines():
        _, sep, message = line.partition("client: ")
        if not sep:
            continue
        if message.startswith("Connected"):
            status, reason = "on", None
        elif message.startswith("Connection error: "):
            status, reason = "error", _chisel_error(message[len("Connection error: "):])
        elif message.startswith("Authentication failed"):
            status, reason = "error", "authentication failed on the chisel server"
        elif message.startswith("Disconnected"):
            status, reason = "connecting", None
    return status, reason


def _ngrok_value(raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        raw = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return raw


def ngrok_log_error(log: str):
    """The reason of ngrok's last failure while no tunnel has started since (its
    logfmt log at info level), or None. A failure is an error line with an `err`: in a
    sandbox ngrok logs `lvl=eror msg="no usable hardware address found"` at every start,
    failing or not. Only the error's first line is kept, with ngrok's error code: its
    authentication error goes on to quote the authtoken."""
    reason = None
    for line in log.splitlines():
        fields = {k: _ngrok_value(v) for k, v in _NGROK_FIELD.findall(line)}
        if fields.get("msg") == "started tunnel":
            reason = None
        elif fields.get("lvl") in ("eror", "crit") and fields.get("err") not in (None, "", "<nil>"):
            text = fields["err"]
            code = _NGROK_CODE.search(text)
            first = re.split(r"\\n|\\r|\n|\r", text, maxsplit=1)[0]
            reason = _reason(first) + (f" ({code.group(0)})" if code and code.group(0) not in first else "")
    return reason


def _log_tail(path: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        size = os.fstat(fd).st_size
        os.lseek(fd, max(0, size - _LOG_TAIL_BYTES), os.SEEK_SET)
        return os.read(fd, _LOG_TAIL_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return ""
    finally:
        os.close(fd)


def _proc_status(proc) -> dict:
    """``active``: the process runs (the webapp reads it so). Whether the tunnel
    forwards is ``status``."""
    if proc is None:
        return {"active": False, "status": "off"}
    return {"active": proc.poll() is None, "pid": proc.pid}


def _chisel_status(proc) -> dict:
    entry = _proc_status(proc)
    if proc is None:
        return entry
    status, reason = chisel_log_status(_log_tail(CHISEL_LOG))
    if not entry["active"]:
        status = "error" if status == "error" else "off"
    entry["status"] = f"error: {reason}" if status == "error" else status
    return entry


def _ngrok_status(proc) -> dict:
    """"on" once ngrok's API names the public endpoint; else its last error, else
    "connecting"; "off" once it exited without one."""
    entry = _proc_status(proc)
    if proc is None:
        return entry
    endpoint = _ngrok_public_endpoint() if entry["active"] else None
    if endpoint:
        entry["host"], entry["port"] = endpoint
        entry["status"] = "on"
        return entry
    reason = ngrok_log_error(_log_tail(NGROK_LOG))
    entry["status"] = f"error: {reason}" if reason else ("connecting" if entry["active"] else "off")
    return entry


def get_status() -> dict:
    with _lock:
        ngrok_proc, chisel_proc, chisel_host = _ngrok_proc, _chisel_proc, _chisel_host
    # Outside the lock: ngrok's API may be slow to answer, a log slow to read.
    status = {"ngrok": _ngrok_status(ngrok_proc), "chisel": _chisel_status(chisel_proc)}
    if status["chisel"]["active"] and chisel_host:
        status["chisel"]["host"] = chisel_host
    return status


class TunnelHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default access logs
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        """Validate the inbound bearer token (constant-time). Fail-CLOSED when
        TUNNEL_AUTH_TOKEN is unset (STRIDE S5): an absent token means REFUSE,
        never accept-everyone. redamon.sh ensure_auth_secrets always sets it."""
        global _warned_failopen
        expected = _configured_token()
        if not expected:
            if not _warned_failopen:
                print("[tunnel_manager] TUNNEL_AUTH_TOKEN not set - REJECTING "
                      "tunnel config requests (fail-closed). Set the token to "
                      "enable the tunnel control plane.")
                _warned_failopen = True
            return False
        return self._presents(expected)

    def _presents(self, expected: str) -> bool:
        header = self.headers.get("Authorization", "") or ""
        presented = header[7:].strip() if header[:7].lower() == "bearer " else ""
        return bool(presented and expected) and hmac.compare_digest(presented, expected)

    def _authorized_to_read_or_stop(self) -> bool:
        """The tunnel token, or the instance's MCP token to read the status or to stop
        the tunnels. The agent holds every listed sandbox's MCP token but not its tunnel
        token, and that token already gives a root shell here, so it widens nothing;
        starting a tunnel still takes the tunnel token."""
        if self._authorized():
            return True
        return self._presents(_instance_mcp_token())

    def do_GET(self):
        if self.path == "/health":
            # Unauthenticated on purpose: the container healthcheck curls this.
            self._send_json({"status": "ok"})
        elif self.path == "/tunnel/status":
            if not self._authorized_to_read_or_stop():
                self._send_json({"error": "unauthorized"}, 401)
                return
            self._send_json(get_status())
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/tunnel/configure":
            if not self._authorized_to_read_or_stop():
                self._send_json({"error": "unauthorized"}, 401)
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                config = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON"}, 400)
                return
            if not isinstance(config, dict):
                self._send_json({"error": "invalid config"}, 400)
                return
            if _starts_a_tunnel(config) and not self._authorized():
                self._send_json({"error": "unauthorized"}, 401)
                return
            result = configure_tunnels(config)
            self._send_json(result)
        else:
            self._send_json({"error": "not found"}, 404)


def main():
    server = HTTPServer(("0.0.0.0", PORT), TunnelHandler)
    print(f"[tunnel_manager] Listening on port {PORT}")

    # Graceful shutdown on SIGTERM/SIGINT
    def shutdown(sig, frame):
        print(f"[tunnel_manager] Shutting down (signal {sig})...")
        with _lock:
            _kill_process(_ngrok_proc, "ngrok")
            _kill_process(_chisel_proc, "chisel")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.serve_forever()


if __name__ == "__main__":
    main()

"""
Lightweight HTTP server for managing ngrok/chisel tunnel processes.

Runs on port 8015 inside kali-sandbox. Accepts configuration pushes
from the webapp (on settings change) and from the entrypoint script
(on container boot).

Endpoints:
  POST /tunnel/configure  — start/restart/stop tunnels
  GET  /tunnel/status     — current tunnel process status
  GET  /health            — simple health check
"""

import json
import os
import signal
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8015

# Track tunnel processes
_lock = threading.Lock()
_ngrok_proc: subprocess.Popen | None = None
_chisel_proc: subprocess.Popen | None = None


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
        f.write(f'version: "3"\nagent:\n  authtoken: {authtoken}\n  web_addr: 0.0.0.0:4040\n')

    print("[tunnel_manager] Starting ngrok TCP tunnel on port 4444...")
    proc = subprocess.Popen(
        ["ngrok", "tcp", "4444", "--config", "/root/.config/ngrok/ngrok.yml",
         "--log=stdout", "--log-level=info"],
        stdout=open("/var/log/ngrok.log", "w"),
        stderr=subprocess.STDOUT,
    )
    print(f"[tunnel_manager] ngrok started (pid {proc.pid}, API at http://0.0.0.0:4040)")
    return proc


def _start_chisel(server_url: str, auth: str) -> subprocess.Popen | None:
    if not server_url:
        return None

    cmd = ["chisel", "client"]
    if auth:
        cmd += ["--auth", auth]
    cmd += [server_url, "R:4444:localhost:4444", "R:8080:localhost:8080"]

    print(f"[tunnel_manager] Starting chisel reverse tunnel to {server_url}...")
    proc = subprocess.Popen(
        cmd,
        stdout=open("/var/log/chisel.log", "w"),
        stderr=subprocess.STDOUT,
    )
    print(f"[tunnel_manager] chisel started (pid {proc.pid}, tunneling ports 4444 + 8080)")
    return proc


def configure_tunnels(config: dict) -> dict:
    global _ngrok_proc, _chisel_proc

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

    return {
        "status": "ok",
        "ngrok": _ngrok_proc is not None,
        "chisel": _chisel_proc is not None,
    }


def get_status() -> dict:
    with _lock:
        def proc_status(proc, name):
            if proc is None:
                return {"active": False}
            running = proc.poll() is None
            return {"active": running, "pid": proc.pid}

        return {
            "ngrok": proc_status(_ngrok_proc, "ngrok"),
            "chisel": proc_status(_chisel_proc, "chisel"),
        }


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

    def do_GET(self):
        if self.path == "/tunnel/status":
            self._send_json(get_status())
        elif self.path == "/health":
            self._send_json({"status": "ok"})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/tunnel/configure":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                config = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON"}, 400)
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

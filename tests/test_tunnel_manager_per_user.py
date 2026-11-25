"""The tunnel manager in a per-user Kali sandbox (group 1, S11; the 4040 class of both
S10 reviews).

ngrok's own API (4040) checks no credential, and a per-user sandbox sits on a network
it shares with the agent and the capture proxy. So in a per-user sandbox ngrok's API
listens on the sandbox's loopback only, and the agent reads the tunnel's public
endpoint through the tunnel manager (8015), which checks a bearer: the instance's
tunnel token for anything, or its MCP token to read the status or to stop the tunnels
(the agent holds that one for every listed instance; it is already a root shell there).
Every sandbox is one person's: the switch the shared container once read
(`REDAMON_SANDBOX_MODE`) changes none of this (FU-8).

Runs in the agent image (root-agent section): python -m pytest tests/test_tunnel_manager_per_user.py
"""
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp", "servers"))

import tunnel_manager  # noqa: E402

TUNNEL = "tunnel-token-0123456789"
MCP = "mcp-token-0123456789"


class TestNgrokApiAddress:
    def test_a_per_user_sandbox_binds_ngroks_api_to_its_loopback(self, monkeypatch):
        monkeypatch.setenv("REDAMON_SANDBOX_MODE", "per_user")
        assert "web_addr: 127.0.0.1:4040" in tunnel_manager.ngrok_config("tok")
        assert "0.0.0.0" not in tunnel_manager.ngrok_config("tok")

    @pytest.mark.parametrize("mode", [None, "shared", ""])
    def test_the_old_mode_switch_never_opens_it(self, monkeypatch, mode):
        if mode is None:
            monkeypatch.delenv("REDAMON_SANDBOX_MODE", raising=False)
        else:
            monkeypatch.setenv("REDAMON_SANDBOX_MODE", mode)
        assert "web_addr: 127.0.0.1:4040" in tunnel_manager.ngrok_config("tok")
        assert "0.0.0.0" not in tunnel_manager.ngrok_config("tok")

    def test_the_config_written_is_the_one_built(self, monkeypatch, tmp_path):
        monkeypatch.setenv("REDAMON_SANDBOX_MODE", "per_user")
        written = {}
        real_open = open

        def fake_open(path, mode="r", *a, **k):
            if str(path).endswith("ngrok.yml"):
                target = tmp_path / "ngrok.yml"
                written["path"] = target
                return real_open(target, mode, *a, **k)
            return real_open(os.devnull, mode, *a, **k)

        with mock.patch.object(tunnel_manager.os, "makedirs"), \
                mock.patch("builtins.open", fake_open), \
                mock.patch.object(tunnel_manager.subprocess, "Popen") as popen:
            tunnel_manager._start_ngrok("tok")
        assert "127.0.0.1:4040" in written["path"].read_text()
        assert popen.called


class TestStatusCarriesThePublicEndpoint:
    def setup_method(self):
        tunnel_manager._ngrok_proc = None
        tunnel_manager._chisel_proc = None
        tunnel_manager._chisel_host = None

    def teardown_method(self):
        for proc in (tunnel_manager._ngrok_proc, tunnel_manager._chisel_proc):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
        self.setup_method()

    def test_an_active_ngrok_tunnel_names_its_host_and_port(self):
        tunnel_manager._ngrok_proc = subprocess.Popen(["sleep", "30"])
        with mock.patch.object(tunnel_manager, "_ngrok_public_endpoint",
                               return_value=("0.tcp.ngrok.io", 14444)):
            status = tunnel_manager.get_status()
        assert status["ngrok"]["active"] is True and status["ngrok"]["status"] == "on"
        assert (status["ngrok"]["host"], status["ngrok"]["port"]) == ("0.tcp.ngrok.io", 14444)

    def test_an_active_chisel_tunnel_names_its_server_host(self, monkeypatch, tmp_path):
        # On once its server took the tunnel (the client's log says so, FU-5).
        log = tmp_path / "chisel.log"
        log.write_text("2026/11/23 10:00:00 client: Connected (Latency 1.2ms)\n")
        monkeypatch.setattr(tunnel_manager, "CHISEL_LOG", str(log))
        with mock.patch.object(tunnel_manager, "_start_chisel",
                               side_effect=lambda *a: subprocess.Popen(["sleep", "30"])):
            tunnel_manager.configure_tunnels({"chiselServerUrl": "https://vps.example:8443",
                                              "chiselAuth": "u:p"})
        status = tunnel_manager.get_status()
        assert status["chisel"]["active"] is True and status["chisel"]["status"] == "on"
        assert status["chisel"]["host"] == "vps.example"

    def test_no_tunnel_names_no_host(self):
        status = tunnel_manager.get_status()
        assert "host" not in status["ngrok"] and "host" not in status["chisel"]

    def test_ngrok_api_answers_are_read_from_loopback_only(self):
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append(req.full_url if hasattr(req, "full_url") else req)
            raise urllib.error.URLError("down")

        with mock.patch.object(tunnel_manager.urllib.request, "urlopen", fake_urlopen):
            assert tunnel_manager._ngrok_public_endpoint() is None
        assert seen == ["http://127.0.0.1:4040/api/tunnels"]


class TestTheBearers:
    @pytest.fixture(autouse=True)
    def server(self, monkeypatch):
        monkeypatch.setenv("TUNNEL_AUTH_TOKEN", TUNNEL)
        monkeypatch.setenv("MCP_AUTH_TOKEN", MCP)
        monkeypatch.setenv("REDAMON_SANDBOX_MODE", "per_user")
        tunnel_manager._ngrok_proc = None
        tunnel_manager._chisel_proc = None
        started = []
        # As the real ones: nothing starts without a token or a server.
        monkeypatch.setattr(tunnel_manager, "_start_ngrok",
                            lambda tok: started.append("ngrok") if tok else None)
        monkeypatch.setattr(tunnel_manager, "_start_chisel",
                            lambda url, auth: started.append("chisel") if url else None)
        self.started = started
        srv = HTTPServer(("127.0.0.1", 0), tunnel_manager.TunnelHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{srv.server_address[1]}"
        yield
        srv.shutdown()

    def _call(self, path, token, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"{self.base}{path}", data=data, headers=headers,
                                     method="POST" if body is not None else "GET")
        try:
            return urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_the_mcp_token_reads_the_status(self):
        assert self._call("/tunnel/status", MCP) == 200
        assert self._call("/tunnel/status", "wrong") == 401
        assert self._call("/tunnel/status", None) == 401

    def test_the_mcp_token_stops_the_tunnels(self):
        assert self._call("/tunnel/configure", MCP, {"ngrokAuthtoken": "", "chiselServerUrl": ""}) == 200
        assert self._call("/tunnel/configure", MCP, {}) == 200
        assert self.started == []

    def test_only_the_tunnel_token_starts_a_tunnel(self):
        assert self._call("/tunnel/configure", MCP, {"ngrokAuthtoken": "2abc"}) == 401
        assert self._call("/tunnel/configure", MCP, {"chiselServerUrl": "https://vps.example"}) == 401
        assert self.started == []
        assert self._call("/tunnel/configure", TUNNEL, {"ngrokAuthtoken": "2abc"}) == 200
        assert self.started == ["ngrok"]

    @pytest.mark.parametrize("mode", [None, "shared"])
    def test_the_old_mode_switch_changes_no_bearer(self, monkeypatch, mode):
        if mode is None:
            monkeypatch.delenv("REDAMON_SANDBOX_MODE", raising=False)
        else:
            monkeypatch.setenv("REDAMON_SANDBOX_MODE", mode)
        assert self._call("/tunnel/status", MCP) == 200
        assert self._call("/tunnel/configure", MCP, {}) == 200
        assert self._call("/tunnel/configure", MCP, {"ngrokAuthtoken": "2abc"}) == 401
        assert self._call("/tunnel/status", TUNNEL) == 200
        assert not hasattr(tunnel_manager, "_per_user_sandbox")

    def test_without_an_mcp_token_only_the_tunnel_token_works(self, monkeypatch):
        monkeypatch.delenv("MCP_AUTH_TOKEN")
        assert self._call("/tunnel/status", "") == 401
        assert self._call("/tunnel/configure", "", {}) == 401
        assert self._call("/tunnel/status", TUNNEL) == 200

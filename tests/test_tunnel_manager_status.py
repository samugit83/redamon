"""A tunnel's status says whether it forwards, not whether its process runs (FU-5).

Every person's chisel client asks its server for the same remote port, R:4444. On a server
where another client already holds it, the server refuses; with a wrong credential or an
unreachable server the client never connects. In each case the process stays alive and
retries for ever, so the old status ("active" because the process ran) told the agent a
dead tunnel was up. ngrok is alike until its API names a public endpoint.

Each tunnel now carries `status`: "on" when it forwards (chisel: its log says "Connected";
ngrok: its API names the public endpoint), "error: <reason>" when the client failed or
was refused, "connecting" while it tries, "off" when it does not run. The agent treats only
"on" as up and "error..." as failed. `active` keeps its old meaning (the process runs): the
webapp reads it to decide whether a changed tunnel setting is pushed.

The chisel lines are chisel 1.11.4's own, captured from the Kali image (client: logger).
The ngrok lines follow ngrok v3's logfmt log (`--log=stdout --log-level=info`); NGROK_REAL
is a real start in a sandbox-image container without a network.

Runs in the agent image (root-agent section): python -m pytest tests/test_tunnel_manager_status.py
"""
import os
import subprocess
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp", "servers"))

import tunnel_manager  # noqa: E402

T = "2026/11/23 17:09:45 "
CONNECTED = [T + "client: Connecting to ws://vps.example:8080", T + "client: Connected (Latency 1.230385ms)"]
REFUSED = [T + "client: Connecting to ws://vps.example:8080",
           T + "client: Connection error: server: Server cannot listen on R:4444=>localhost:4444",
           T + "client: Retrying in 100ms...",
           T + "client: Connection error: server: Server cannot listen on R:4444=>localhost:4444 "
               "(Attempt: 1/unlimited)",
           T + "client: Retrying in 200ms..."]
UNREACHABLE = [T + "client: Connecting to ws://203.0.113.7:8080",
               T + "client: Connection error: dial tcp 203.0.113.7:8080: connect: connection refused",
               T + "client: Retrying in 100ms..."]
BAD_AUTH = [T + "client: Connecting to ws://vps.example:8080",
            T + "client: Authentication failed",
            T + "client: Connection error: ssh: handshake failed: ssh: unable to authenticate, attempted "
                "methods [none password], no supported methods remain"]
REFUSED_REASON = ("remote port 4444 in use on the chisel server (another client holds it; "
                  "each person needs their own chisel server)")

N = "t=2026-11-23T17:09:45+0000 "
TOKEN = "2abcDEFghiJKLmnoPQRstuVWXyz0123456789_abcdefgh"
NGROK_STARTING = [N + 'lvl=info msg="starting web service" obj=web addr=127.0.0.1:4040']
NGROK_AUTH_FAILED = NGROK_STARTING + [
    N + 'lvl=eror msg="failed to reconnect session" obj=tunnels.session '
        'err="authentication failed: The authtoken you specified does not look like a proper ngrok '
        f'tunnel authtoken.\\nYour authtoken: {TOKEN}\\nInstructions: https://dashboard.ngrok.com\\r\\n'
        '\\r\\nERR_NGROK_105\\r\\n"']
NGROK_UNREACHABLE = NGROK_STARTING + [
    N + 'lvl=eror msg="failed to reconnect session" obj=tunnels.session '
        'err="failed to dial ngrok server with address \\"connect.ngrok-agent.com:443\\": dial tcp: '
        'lookup connect.ngrok-agent.com: no such host"']
NGROK_STARTED_AFTER_ERROR = NGROK_UNREACHABLE + [
    N + 'lvl=info msg="started tunnel" obj=tunnels name=command_line addr=//localhost:4444 '
        'url=tcp://0.tcp.ngrok.io:14444']


NGROK_REAL = [
    't=2026-11-23T17:45:03+0000 lvl=info msg="open config file" path=/w/ngrok.yml err=<nil>',
    't=2026-11-23T17:45:03+0000 lvl=info msg="FIPS 140 mode" enabled=false',
    't=2026-11-23T17:45:03+0000 lvl=eror msg="no usable hardware address found" obj=tunnels.session',
    't=2026-11-23T17:45:03+0000 lvl=info msg="starting web service" obj=web addr=127.0.0.1:4040 allow_hosts=[]',
    't=2026-11-23T17:45:03+0000 lvl=eror msg="failed to reconnect session" obj=tunnels.session '
    'err="failed to dial ngrok server with address \\"connect.ngrok-agent.com:443\\": dial tcp: lookup '
    'connect.ngrok-agent.com on 8.8.4.4:53: dial udp 8.8.4.4:53: connect: network is unreachable"',
    't=2026-11-23T17:45:03+0000 lvl=warn msg="failed to check for update" obj=updater err="Post '
    '\\"https://update.ngrok-agent.com/check\\": dial tcp: lookup update.ngrok-agent.com on 8.8.4.4:53"',
]


def chisel(lines):
    return tunnel_manager.chisel_log_status("\n".join(lines) + "\n")


def ngrok(lines):
    return tunnel_manager.ngrok_log_error("\n".join(lines) + "\n")


class TestTheLogsDecide:
    def test_chisel_connected_is_on(self):
        assert chisel(CONNECTED) == ("on", None)

    def test_chisel_refused_remote_port_is_an_error_that_a_retry_never_clears(self):
        assert chisel(REFUSED) == ("error", REFUSED_REASON)

    def test_chisel_unreachable_and_bad_credential_are_errors(self):
        assert chisel(UNREACHABLE) == ("error", "dial tcp 203.0.113.7:8080: connect: connection refused")
        assert chisel(BAD_AUTH) == ("error", "authentication failed on the chisel server")
        assert chisel(BAD_AUTH[:2]) == ("error", "authentication failed on the chisel server")

    def test_chisel_reconnect_is_on_and_a_drop_is_connecting(self):
        assert chisel([]) == ("connecting", None)
        assert chisel(CONNECTED[:1]) == ("connecting", None)
        assert chisel(REFUSED + CONNECTED[1:]) == ("on", None)
        assert chisel(CONNECTED + [T + "client: Disconnected"]) == ("connecting", None)

    def test_a_reason_carries_no_credential_or_control_bytes(self):
        _, reason = chisel([T + "client: Connection error: websocket: bad handshake "
                                "(ws://admin:hunter2@vps.example:8080)\x1b[31m"])
        assert "hunter2" not in reason and "admin" not in reason and "\x1b" not in reason
        assert len(chisel([T + "client: Connection error: " + "x y " * 5000])[1]) == 200

    def test_ngrok_errors_keep_the_first_line_and_code_never_the_token(self):
        reason = ngrok(NGROK_AUTH_FAILED)
        assert reason.startswith("authentication failed: The authtoken you specified does not look")
        assert reason.endswith("(ERR_NGROK_105)")
        assert TOKEN not in reason and "Your authtoken" not in reason
        assert ngrok(NGROK_UNREACHABLE).startswith(
            'failed to dial ngrok server with address "connect.ngrok-agent.com:443"')

    def test_ngrok_s_routine_hardware_address_error_is_no_failure(self):
        # Logged at every start in a sandbox, failing or not: it must not read as FAILED.
        assert ngrok(NGROK_REAL[:4]) is None
        assert ngrok(NGROK_REAL).startswith(
            'failed to dial ngrok server with address "connect.ngrok-agent.com:443": dial tcp: lookup')
        assert ngrok(NGROK_REAL[:4] + [
            't=x lvl=info msg="session closing" obj=tunnels.session err=<nil>']) is None

    def test_ngrok_a_started_tunnel_clears_an_error(self):
        assert ngrok(NGROK_STARTING) is None
        assert ngrok(NGROK_STARTED_AFTER_ERROR) is None


class TestTheStatusAnswer:
    @pytest.fixture(autouse=True)
    def logs(self, monkeypatch, tmp_path):
        self.chisel_log = tmp_path / "chisel.log"
        self.ngrok_log = tmp_path / "ngrok.log"
        monkeypatch.setattr(tunnel_manager, "CHISEL_LOG", str(self.chisel_log))
        monkeypatch.setattr(tunnel_manager, "NGROK_LOG", str(self.ngrok_log))
        tunnel_manager._ngrok_proc = None
        tunnel_manager._chisel_proc = None
        tunnel_manager._chisel_host = "vps.example"
        yield
        for proc in (tunnel_manager._ngrok_proc, tunnel_manager._chisel_proc):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
        tunnel_manager._ngrok_proc = None
        tunnel_manager._chisel_proc = None
        tunnel_manager._chisel_host = None

    @staticmethod
    def alive():
        return subprocess.Popen(["sleep", "30"])

    @staticmethod
    def dead(code=0):
        proc = subprocess.Popen(["sh", "-c", f"exit {code}"])
        proc.wait()
        return proc

    def status(self, endpoint=None):
        with mock.patch.object(tunnel_manager, "_ngrok_public_endpoint", return_value=endpoint):
            return tunnel_manager.get_status()

    # chisel

    def test_chisel_refused_remote_port_is_error(self):
        self.chisel_log.write_text("\n".join(REFUSED) + "\n")
        tunnel_manager._chisel_proc = self.alive()
        entry = self.status()["chisel"]
        assert entry["status"] == f"error: {REFUSED_REASON}"
        assert entry["status"].startswith("error")

    def test_chisel_connected_is_on(self):
        self.chisel_log.write_text("\n".join(CONNECTED) + "\n")
        tunnel_manager._chisel_proc = self.alive()
        entry = self.status()["chisel"]
        assert (entry["status"], entry["active"], entry["host"]) == ("on", True, "vps.example")

    def test_chisel_still_connecting(self):
        self.chisel_log.write_text("\n".join(CONNECTED[:1]) + "\n")
        tunnel_manager._chisel_proc = self.alive()
        assert self.status()["chisel"]["status"] == "connecting"

    def test_chisel_process_dead_is_off(self):
        self.chisel_log.write_text("\n".join(CONNECTED) + "\n")
        tunnel_manager._chisel_proc = self.dead()
        entry = self.status()["chisel"]
        assert (entry["status"], entry["active"]) == ("off", False)

    def test_chisel_dead_after_an_error_says_the_error(self):
        self.chisel_log.write_text("\n".join(UNREACHABLE + [T + "client: Give up"]) + "\n")
        tunnel_manager._chisel_proc = self.dead(1)
        assert self.status()["chisel"]["status"] == \
            "error: dial tcp 203.0.113.7:8080: connect: connection refused"

    def test_chisel_not_configured_is_off(self):
        assert self.status()["chisel"] == {"active": False, "status": "off"}

    def test_a_linked_log_is_never_read(self, tmp_path):
        secret = tmp_path / "secret"
        secret.write_text(T + "client: Connected (Latency 1ms)\n")
        os.symlink(str(secret), str(self.chisel_log))
        tunnel_manager._chisel_proc = self.alive()
        assert self.status()["chisel"]["status"] == "connecting"

    # ngrok

    def test_ngrok_with_a_public_endpoint_is_on(self):
        self.ngrok_log.write_text("\n".join(NGROK_STARTED_AFTER_ERROR) + "\n")
        tunnel_manager._ngrok_proc = self.alive()
        entry = self.status(("0.tcp.ngrok.io", 14444))["ngrok"]
        assert (entry["status"], entry["active"], entry["host"], entry["port"]) == \
            ("on", True, "0.tcp.ngrok.io", 14444)

    def test_ngrok_failing_is_error_without_the_token(self):
        self.ngrok_log.write_text("\n".join(NGROK_AUTH_FAILED) + "\n")
        tunnel_manager._ngrok_proc = self.alive()
        entry = self.status()["ngrok"]
        assert entry["status"].startswith("error: authentication failed")
        assert TOKEN not in entry["status"] and "host" not in entry

    def test_ngrok_without_an_endpoint_yet_is_connecting(self):
        self.ngrok_log.write_text("\n".join(NGROK_REAL[:4]) + "\n")
        tunnel_manager._ngrok_proc = self.alive()
        assert self.status()["ngrok"]["status"] == "connecting"

    def test_ngrok_process_dead_is_off(self):
        self.ngrok_log.write_text("\n".join(NGROK_STARTING) + "\n")
        tunnel_manager._ngrok_proc = self.dead()
        entry = self.status(("0.tcp.ngrok.io", 14444))["ngrok"]
        assert (entry["status"], entry["active"]) == ("off", False) and "host" not in entry

    def test_ngrok_not_configured_is_off(self):
        assert self.status()["ngrok"] == {"active": False, "status": "off"}

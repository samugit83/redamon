"""
Unit tests for the payload-settings prompt (utils.get_session_config_prompt).

Regression cover for issue #180 ("LHOST IP prompts/confirms from AI Agent"):
when no payload direction is configured the agent must be told that LHOST is the
HOST machine's address a target reaches (a deployed server's public IP) and that
it must NOT auto-detect an IP from inside the kali-sandbox container (that
container's own `172.x` address is unreachable by the target), and how the pool
port is opened locally and on a deployed server. The reverse/bind branches must
keep working unchanged.

Run (inside agent container):
    ./agentic/run_tests.sh tests/test_payload_settings.py
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

import utils  # noqa: E402


def _fake_settings(values: dict):
    """Return a get_setting stand-in backed by `values` with a default fallback."""
    def _get(key, default=None):
        return values.get(key, default)
    return _get


POOL_PORT = 45002


class _PoolSandbox(unittest.TestCase):
    """The run's own sandbox publishes a pool port (KALI_SANDBOX_PORT_POOL), the one case
    where a direct reverse shell to the host's address can work."""

    def setUp(self):
        import sandbox_router
        from one_sandbox import handle

        sandbox_router._reset()
        self.addCleanup(sandbox_router._reset)
        patcher = patch.object(sandbox_router, "current_handle",
                               lambda project_id=None: handle(reverse_port=POOL_PORT))
        patcher.start()
        self.addCleanup(patcher.stop)


class NoPublishedPortGuidanceTests(unittest.TestCase):
    """A run whose sandbox is not known yet, or one that publishes no port: never the
    host's LAN IP. Not knowing the sandbox is not "no port" (D-E): it asks nothing yet."""

    def setUp(self):
        import sandbox_router

        sandbox_router._reset()
        self.addCleanup(sandbox_router._reset)

    def _render(self, sandbox):
        import sandbox_router

        with patch.object(utils, "get_setting", _fake_settings({})), \
             patch.object(sandbox_router, "current_handle", lambda project_id=None: sandbox), \
             patch.dict(os.environ, {"HOST_LAN_IP": "192.168.1.50"}, clear=False):
            return utils.get_session_config_prompt()

    def test_a_sandbox_not_known_yet_is_said_so(self):
        out = self._render(None)
        self.assertIn("Your Kali sandbox: not known yet.", out)
        self.assertNotIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertNotIn("NO DIRECT REVERSE SHELL", out)
        self.assertNotIn("192.168.1.50", out)

    def test_a_sandbox_without_a_port_offers_no_direct_reverse_shell(self):
        from one_sandbox import handle

        out = self._render(handle())
        self.assertIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertIn("NO DIRECT REVERSE SHELL", out)
        self.assertNotIn("192.168.1.50", out)
        self.assertNotIn("host machine's LAN IP", out)


class AskBranchGuidanceTests(_PoolSandbox):
    """All-empty settings -> ASK branch must steer the agent to the host's address and
    the sandbox's published pool port.

    HOST_LAN_IP is cleared so these assert the no-detection fallback deterministically
    regardless of the ambient environment; the suggestion path is covered separately.
    """

    def _render(self, values):
        with patch.object(utils, "get_setting", _fake_settings(values)), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HOST_LAN_IP", None)
            return utils.get_session_config_prompt()

    def test_ask_branch_triggers_when_nothing_configured(self):
        out = self._render({})
        self.assertIn("PAYLOAD DIRECTION NOT CONFIGURED", out)

    def test_ask_branch_names_the_hosts_address_as_lhost(self):
        out = self._render({})
        self.assertIn("as LHOST the host's address the target can reach", out)

    def test_ask_branch_forbids_container_ip_autodetection(self):
        out = self._render({})
        # The exact failure from issue #180: the agent ran `ip`/`ifconfig` inside
        # the container and got the unreachable Docker address.
        self.assertIn("DO NOT GUESS OR AUTO-DETECT", out)
        self.assertIn("Docker IP the target CANNOT reach", out)
        for cmd in ("ip addr", "ifconfig", "hostname -I"):
            self.assertIn(cmd, out)
        self.assertIn("ASK THE USER", out)

    def test_ask_branch_names_the_published_pool_port(self):
        out = self._render({})
        self.assertIn(f"use LPORT `{POOL_PORT}`", out)
        self.assertNotIn("host-LAN-IP:LPORT", out)

    def test_ask_branch_says_how_the_pool_port_is_opened_locally_and_when_deployed(self):
        # A deployed server refuses a pool bound off loopback: revshell-open's forwarders
        # are its only way in, so a bind address cannot be the one condition named.
        flat = " ".join(self._render({}).split())
        self.assertIn("on a local install by giving `KALI_SANDBOX_PORT_POOL` a bind address", flat)
        self.assertIn("on a deployed server, where the pool stays on loopback, by running "
                      "`deploy.sh revshell-open`, which forwards it from the server's public IP", flat)
        self.assertNotIn("only if the operator published the pool on that address", flat)


class DetectedHostIpSuggestionTests(_PoolSandbox):
    """HOST_LAN_IP (issue #180): the ask-branch suggests the host's LAN IP, but
    only when no tunnel is configured."""

    def _render(self, values, env):
        with patch.object(utils, "get_setting", _fake_settings(values)), \
             patch.dict(os.environ, env, clear=False):
            return utils.get_session_config_prompt()

    def test_detected_ip_is_suggested_when_set_and_no_tunnel(self):
        out = self._render({}, {"HOST_LAN_IP": "192.168.1.50"})
        flat = " ".join(out.split())
        self.assertIn("RedAmon's address for this host is `192.168.1.50`", flat)
        # The value is a deployed server's public IP, or else the default route's LAN IP.
        self.assertIn("the public IP a deployed server was given, else the LAN IP of the default route", flat)
        self.assertIn("suggest it as LHOST and confirm with the user", flat)
        # Still forbids self-detection from inside the sandbox.
        self.assertIn("DO NOT GUESS OR AUTO-DETECT", out)
        # And no longer the bare "ASK THE USER" fallback line.
        self.assertNotIn("ASK THE USER for it", out)

    def test_no_suggestion_when_env_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HOST_LAN_IP", None)
            with patch.object(utils, "get_setting", _fake_settings({})):
                out = utils.get_session_config_prompt()
        self.assertIn("ASK THE USER for it", out)

    def _tunnels_off(self):
        import time
        from one_sandbox import handle

        utils._forget_all_tunnel_status()
        self.addCleanup(utils._forget_all_tunnel_status)
        utils._tunnel_status[handle(reverse_port=POOL_PORT).key] = (
            time.monotonic(), {"ngrok": {"active": False}, "chisel": {"active": False}})

    def test_suggested_when_an_enabled_ngrok_tunnel_is_off(self):
        # The pool port reaches the sandbox without the tunnel, so its LHOST is still the
        # host's address; the banner says the tunnel is off, not that a token is wrong.
        self._tunnels_off()
        out = self._render({"NGROK_TUNNEL_ENABLED": True},
                           {"HOST_LAN_IP": "192.168.1.50"})
        self.assertIn("192.168.1.50", out)
        self.assertIn("ngrok Tunnel: OFF", out)

    def test_suggested_when_an_enabled_chisel_tunnel_is_off(self):
        self._tunnels_off()
        out = self._render({"CHISEL_TUNNEL_ENABLED": True},
                           {"HOST_LAN_IP": "192.168.1.50"})
        self.assertIn("192.168.1.50", out)
        self.assertIn("Chisel Tunnel: OFF", out)


class ModeRegressionTests(_PoolSandbox):
    """Configured reverse/bind modes are unaffected by the new guidance."""

    def _render(self, values):
        with patch.object(utils, "get_setting", _fake_settings(values)):
            return utils.get_session_config_prompt()

    def test_reverse_mode_still_selected_and_prints_lhost(self):
        out = self._render({"LHOST": "203.0.113.9", "LPORT": 4444})
        self.assertIn("Mode: REVERSE", out)
        self.assertIn("203.0.113.9", out)
        # The ask-branch-only guidance must NOT leak into a fully configured run.
        self.assertNotIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertNotIn("DO NOT GUESS OR AUTO-DETECT", out)

    def test_bind_mode_still_selected(self):
        out = self._render({"BIND_PORT_ON_TARGET": 4444})
        self.assertIn("Mode: BIND", out)
        self.assertNotIn("DO NOT GUESS OR AUTO-DETECT", out)

    def test_lhost_without_lport_is_reverse_on_the_pool_port(self):
        # The sandbox's pool port is LPORT (D-F): an empty project LPORT is not missing.
        out = self._render({"LHOST": "203.0.113.9"})
        self.assertIn("Mode: REVERSE", out)
        self.assertIn(f"set LPORT {POOL_PORT}", out)
        self.assertNotIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertNotIn("LPORT is missing", out)


if __name__ == "__main__":
    unittest.main()

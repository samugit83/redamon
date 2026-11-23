"""
Unit tests for the payload-settings prompt (utils.get_session_config_prompt).

Regression cover for issue #180 ("LHOST IP prompts/confirms from AI Agent"):
when no payload direction is configured the agent must be told that LHOST is the
HOST machine's LAN IP and that it must NOT auto-detect an IP from inside the
kali-sandbox container (that container's own `172.x` address is unreachable by
the target). The reverse/bind branches must keep working unchanged.

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
    """A run with no sandbox yet, or one that publishes no port: the ASK branch never
    steers the agent to the host's LAN IP."""

    def test_the_default_offers_no_direct_reverse_shell(self):
        import sandbox_router

        sandbox_router._reset()
        self.addCleanup(sandbox_router._reset)
        with patch.object(utils, "get_setting", _fake_settings({})), \
             patch.dict(os.environ, {"HOST_LAN_IP": "192.168.1.50"}, clear=False):
            out = utils.get_session_config_prompt()
        self.assertIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertIn("YOUR KALI SANDBOX PUBLISHES NO PORT", out)
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


class DetectedHostIpSuggestionTests(_PoolSandbox):
    """HOST_LAN_IP (issue #180): the ask-branch suggests the host's LAN IP, but
    only when no tunnel is configured."""

    def _render(self, values, env):
        with patch.object(utils, "get_setting", _fake_settings(values)), \
             patch.dict(os.environ, env, clear=False):
            return utils.get_session_config_prompt()

    def test_detected_ip_is_suggested_when_set_and_no_tunnel(self):
        out = self._render({}, {"HOST_LAN_IP": "192.168.1.50"})
        self.assertIn("192.168.1.50", out)
        self.assertIn("detected LAN IP", out)
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

    def test_suppressed_when_ngrok_tunnel_enabled(self):
        # Tunnel enabled -> the ask-branch is a broken-tunnel state; a LAN-IP
        # suggestion would contradict the "fix your tunnel" guidance.
        out = self._render({"NGROK_TUNNEL_ENABLED": True},
                           {"HOST_LAN_IP": "192.168.1.50"})
        self.assertNotIn("192.168.1.50", out)
        self.assertIn("ASK THE USER for it", out)

    def test_suppressed_when_chisel_tunnel_enabled(self):
        out = self._render({"CHISEL_TUNNEL_ENABLED": True},
                           {"HOST_LAN_IP": "192.168.1.50"})
        self.assertNotIn("192.168.1.50", out)


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

    def test_lhost_without_lport_falls_to_ask_with_guidance(self):
        # Discordant config (LHOST set, LPORT missing) -> ASK, and the host-IP
        # guidance still shows so the user knows which value to complete.
        out = self._render({"LHOST": "203.0.113.9"})
        self.assertIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertIn("LPORT is missing", out)
        self.assertIn("as LHOST the host's address the target can reach", out)


if __name__ == "__main__":
    unittest.main()

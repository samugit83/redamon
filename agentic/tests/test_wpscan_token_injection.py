"""
The user's WPScan token reaches wpscan off its command line.

The executor used to prepend `--api-token <token>` to the args it sent the sandbox,
so the token sat in wpscan's argv for the whole scan, which `ps` shows to every
process in the shared container and on the host. It now travels as the MCP tool's
own `api_token` argument, which the sandbox hands to that one wpscan child as
WPSCAN_API_TOKEN (wpscan reads it; an --api-token on the command line wins).

Run: ./agentic/run_tests.sh tests/test_wpscan_token_injection.py
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)


class WpscanToken(unittest.TestCase):
    def _executor(self, token="rbac-wpscan-token"):
        from tools import PhaseAwareToolExecutor
        ex = PhaseAwareToolExecutor(mcp_manager=mock.MagicMock(), graph_tool=None)
        tool = mock.AsyncMock()
        tool.name = "execute_wpscan"
        tool.ainvoke.return_value = "ok"
        ex._all_tools["execute_wpscan"] = tool
        if token:
            ex.set_wpscan_api_token(token)
        return ex, tool

    def _run(self, ex, args):
        with mock.patch("tools.is_tool_allowed_in_phase", return_value=True):
            return asyncio.new_event_loop().run_until_complete(
                ex.execute("execute_wpscan", args, phase="informational"))

    def test_the_token_travels_as_its_own_argument_not_in_the_command_line(self):
        ex, tool = self._executor()
        original = {"args": "--url https://wp.rbac.invalid --format json"}
        self._run(ex, original)
        sent = tool.ainvoke.call_args.args[0]
        self.assertEqual(sent["api_token"], "rbac-wpscan-token")
        self.assertEqual(sent["args"], "--url https://wp.rbac.invalid --format json")
        self.assertNotIn("rbac-wpscan-token", sent["args"])
        self.assertEqual(original, {"args": "--url https://wp.rbac.invalid --format json"})

    def test_a_token_the_args_already_carry_is_left_alone(self):
        ex, tool = self._executor()
        self._run(ex, {"args": "--url https://wp.rbac.invalid --api-token typed-by-hand"})
        sent = tool.ainvoke.call_args.args[0]
        self.assertNotIn("api_token", sent)
        self.assertEqual(sent["args"], "--url https://wp.rbac.invalid --api-token typed-by-hand")

    def test_no_token_configured_sends_none(self):
        ex, tool = self._executor(token="")
        self._run(ex, {"args": "--url https://wp.rbac.invalid"})
        self.assertNotIn("api_token", tool.ainvoke.call_args.args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

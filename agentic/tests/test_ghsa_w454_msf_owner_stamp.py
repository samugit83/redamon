"""
GHSA-w454-6hwp-fm58: every Metasploit call carries the run's own project, stamped by
the executor.

The sandbox's one msfconsole now serves one project at a time and admits a call only
for the project that holds it (tests/test_ghsa_w454_msf_project_lease.py). That rule
is only as good as the project the call names, so the executor writes
`_redamon_owner` from the run's context over whatever the model put in the args: a
prompt that makes the model claim another project's id gets the run's own project
instead. A call with no project in context never leaves the agent.

Run: ./agentic/run_tests.sh tests/test_ghsa_w454_msf_owner_stamp.py
"""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)


class MsfOwnerStamp(unittest.TestCase):
    def setUp(self):
        import agent_context
        self.ctx = agent_context
        self.tokens = [
            (agent_context.current_user_id, agent_context.current_user_id.set("tenant-bob")),
            (agent_context.current_project_id, agent_context.current_project_id.set("project-bob")),
            (agent_context.current_session_id, agent_context.current_session_id.set("chat-bob")),
            (agent_context.current_log_session_id, agent_context.current_log_session_id.set("chat-bob")),
        ]

    def tearDown(self):
        for var, token in reversed(self.tokens):
            var.reset(token)

    def _executor(self, *names):
        from tools import PhaseAwareToolExecutor
        ex = PhaseAwareToolExecutor(mcp_manager=mock.MagicMock(), graph_tool=None)
        tools = {}
        for name in names:
            tool = mock.AsyncMock()
            tool.name = name
            tool.ainvoke.return_value = "msf6 >"
            ex._all_tools[name] = tool
            tools[name] = tool
        return ex, tools

    def _run(self, ex, name, args):
        with mock.patch("tools.is_tool_allowed_in_phase", return_value=True):
            return asyncio.new_event_loop().run_until_complete(
                ex.execute(name, args, phase="exploitation"))

    def _sent_owner(self, tool):
        return json.loads(tool.ainvoke.call_args.args[0]["_redamon_owner"])

    def test_metasploit_console_names_the_runs_project_and_chat(self):
        ex, tools = self._executor("metasploit_console")
        result = self._run(ex, "metasploit_console", {"command": "sessions -l"})
        self.assertTrue(result["success"], result)
        sent = tools["metasploit_console"].ainvoke.call_args.args[0]
        self.assertEqual(sent["command"], "sessions -l")
        self.assertEqual(self._sent_owner(tools["metasploit_console"]),
                         {"project_id": "project-bob", "user_id": "tenant-bob", "chat_session_id": "chat-bob"})

    def test_a_project_the_model_writes_is_overwritten(self):
        ex, tools = self._executor("metasploit_console")
        forged = json.dumps({"project_id": "project-alice", "chat_session_id": "chat-alice"})
        self._run(ex, "metasploit_console", {"command": "sessions -i 1", "_redamon_owner": forged})
        self.assertEqual(self._sent_owner(tools["metasploit_console"])["project_id"], "project-bob")

    def test_msf_restart_is_stamped_too(self):
        ex, tools = self._executor("msf_restart")
        self._run(ex, "msf_restart", {})
        self.assertEqual(self._sent_owner(tools["msf_restart"])["project_id"], "project-bob")

    def test_a_plan_wave_without_a_session_id_still_names_the_chat(self):
        # execute_plan_node calls set_tenant_context(user, project): current_session_id is "".
        self.ctx.current_session_id.set("")
        ex, tools = self._executor("metasploit_console")
        self._run(ex, "metasploit_console", {"command": "sessions -l"})
        self.assertEqual(self._sent_owner(tools["metasploit_console"])["chat_session_id"], "chat-bob")

    def test_no_project_in_context_never_reaches_the_sandbox(self):
        self.ctx.current_project_id.set("")
        ex, tools = self._executor("metasploit_console", "msf_restart")
        for name, args in (("metasploit_console", {"command": "sessions -l"}), ("msf_restart", {})):
            with self.subTest(tool=name):
                result = self._run(ex, name, args)
                self.assertFalse(result["success"])
                self.assertIn("no project", result["error"])
                tools[name].ainvoke.assert_not_called()

    def test_other_tools_carry_no_owner(self):
        ex, tools = self._executor("kali_shell")
        self._run(ex, "kali_shell", {"command": "id"})
        self.assertNotIn("_redamon_owner", tools["kali_shell"].ainvoke.call_args.args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

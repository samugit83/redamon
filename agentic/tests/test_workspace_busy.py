"""Busy targets: the drawer and the agent's fs_* tools cannot change a folder a
running import is about to replace."""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

import workspace_fs  # noqa: E402
from workspace_import import busy  # noqa: E402
from workspace_import.errors import ImportFailure  # noqa: E402

JOB = "a" * 32


class BusyTable(unittest.TestCase):
    def tearDown(self):
        busy.clear()

    def assertBusy(self, path, pid="p1"):
        with self.assertRaises(ImportFailure) as ctx:
            busy.check_mutation(pid, path)
        self.assertEqual(ctx.exception.code, "busy")
        self.assertEqual(ctx.exception.detail, JOB)

    def test_target_and_inside_refused_ancestor_of_destination_refused(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        for path in ("uploads/repo", "uploads/repo/", "./uploads/repo/a/b.txt", "/uploads/repo/x"):
            self.assertBusy(path)
        for path in ("uploads", "uploads/", ".", ""):
            self.assertBusy(path)

    def test_unrelated_paths_allowed(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        for path in ("uploads/repo-2", "uploads/other.txt", "notes/a.md", "uploadsx"):
            busy.check_mutation("p1", path)
        busy.check_mutation("p2", "uploads/repo")  # another project

    def test_inside_destination_without_target_is_allowed(self):
        busy.register("p1", JOB, dest_dir="uploads")  # keep_both upload: no target
        busy.check_mutation("p1", "uploads/anything.txt")
        self.assertBusy("uploads")

    def test_unregister_frees(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        busy.unregister(JOB)
        busy.check_mutation("p1", "uploads/repo/x")
        busy.unregister(JOB)  # idempotent


class WorkspaceBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-busy-"))
        self._root = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp)
        self._root.start()
        self.root = workspace_fs.resolve_for_project("p1", ".")
        (self.root / "uploads/repo/sub").mkdir(parents=True)
        (self.root / "uploads/repo/a.txt").write_text("a")
        (self.root / "notes/n.md").write_text("n")

    def tearDown(self):
        busy.clear()
        self._root.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)


class DrawerRoutes(WorkspaceBase):
    def test_drawer_rename_and_delete_answer_busy(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        for call in (lambda: workspace_fs.rename_for_project("p1", "uploads/repo/a.txt", "b.txt"),
                     lambda: workspace_fs.delete_for_project("p1", "uploads/repo", recursive=True),
                     lambda: workspace_fs.rename_for_project("p1", "uploads/repo", "x")):
            with self.assertRaises(ImportFailure) as ctx:
                call()
            self.assertEqual(ctx.exception.code, "busy")
        self.assertTrue((self.root / "uploads/repo/a.txt").exists())
        workspace_fs.rename_for_project("p1", "notes/n.md", "m.md")  # unrelated still works

    def test_symlink_into_a_busy_target_is_refused(self):
        os.symlink(self.root / "uploads/repo", self.root / "notes/link")
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        with self.assertRaises(ImportFailure):
            workspace_fs.check_not_busy("p1", "notes/link/a.txt")

    def test_a_failing_check_refuses(self):
        with mock.patch.object(busy, "check_mutation", side_effect=RuntimeError("table broken")):
            with self.assertRaises(ImportFailure) as ctx:
                workspace_fs.check_not_busy("p1", "notes/n.md")
        self.assertEqual(ctx.exception.code, "busy")

    def test_http_routes_answer_409_with_the_job(self):
        from fastapi.testclient import TestClient
        import api
        from llm_guard import require_configured_master_auth

        api.app.dependency_overrides[require_configured_master_auth] = lambda: None
        try:
            client = TestClient(api.app)
            busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
            r = client.post("/workspace/rename", json={"projectId": "p1", "path": "uploads/repo",
                                                       "newName": "x"})
            self.assertEqual(r.status_code, 409)
            self.assertEqual(r.json()["code"], "busy")
            self.assertEqual(r.json()["jobId"], JOB)
            r = client.delete("/workspace", params={"projectId": "p1", "path": "uploads/repo/a.txt"})
            self.assertEqual(r.status_code, 409)
            self.assertEqual(r.json()["code"], "busy")
            busy.unregister(JOB)
            r = client.delete("/workspace", params={"projectId": "p1", "path": "uploads/repo/a.txt"})
            self.assertEqual(r.status_code, 200)
        finally:
            api.app.dependency_overrides.pop(require_configured_master_auth, None)


class Classification(unittest.TestCase):
    def test_every_dispatch_tool_is_classified(self):
        writes = set(workspace_fs.FS_TOOL_WRITE_ARGS)
        reads = set(workspace_fs.FS_TOOL_READ_ONLY)
        self.assertEqual(writes & reads, set())
        self.assertEqual(set(workspace_fs.DISPATCH) - writes - reads, set())
        self.assertEqual((writes | reads) - set(workspace_fs.DISPATCH), set())

    def test_write_args_are_real_parameters(self):
        import inspect
        for tool, names in workspace_fs.FS_TOOL_WRITE_ARGS.items():
            params = inspect.signature(workspace_fs.DISPATCH[tool]).parameters
            for name in names:
                self.assertIn(name, params, f"{tool}.{name}")


def _executor():
    import tools as tools_module
    return tools_module.PhaseAwareToolExecutor(mcp_manager=MagicMock(), graph_tool=None)


# One call per write argument, each aimed inside the busy target.
INSIDE = "uploads/repo/sub/x.txt"
FS_CALLS = {
    "fs_write": {"path": INSIDE, "content": "x"},
    "fs_edit": {"path": "uploads/repo/a.txt", "old_string": "a", "new_string": "b"},
    "fs_multi_edit": {"path": "uploads/repo/a.txt", "edits": [{"old_string": "a", "new_string": "b"}]},
    "fs_undo_edit": {"path": "uploads/repo/a.txt"},
    "fs_chmod": {"path": "uploads/repo/a.txt", "mode_str": "600"},
    "fs_delete": {"path": "uploads/repo/a.txt"},
    "fs_move": [{"src": "uploads/repo/a.txt", "dst": "notes/a.txt"},
                {"src": "notes/n.md", "dst": INSIDE}],
    "fs_copy": {"src": "notes/n.md", "dst": INSIDE},
    "fs_mkdir": {"path": "uploads/repo/newdir"},
    "fs_symlink_create": {"target": "notes/n.md", "linkname": INSIDE},
    "fs_extract": {"archive_path": "notes/n.md", "dest": "uploads/repo/out"},
    "fs_archive": {"paths": ["notes/n.md"], "dest": "uploads/repo/n.tar.gz"},
}


class FsToolsThroughTheChokepoint(WorkspaceBase, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        import agent_context
        self._pid_token = agent_context.current_project_id.set("p1")
        self.executor = _executor()

    def tearDown(self):
        import agent_context
        agent_context.current_project_id.reset(self._pid_token)
        super().tearDown()

    async def test_each_mutating_fs_tool_refuses_inside_target(self):
        self.assertEqual(set(FS_CALLS), set(workspace_fs.FS_TOOL_WRITE_ARGS))
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        for tool, calls in FS_CALLS.items():
            for args in calls if isinstance(calls, list) else [calls]:
                with self.subTest(tool=tool, args=args):
                    res = await self.executor._dispatch_fs_tool(tool, dict(args))
                    self.assertFalse(res["success"])
                    self.assertIn("is being replaced by a running import", res["error"])
                    self.assertIn(JOB, res["error"])
        self.assertEqual((self.root / "uploads/repo/a.txt").read_text(), "a")
        self.assertFalse((self.root / INSIDE).exists())

    async def test_execute_path_reaches_the_gate(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        res = await self.executor.execute("fs_write", {"path": INSIDE, "content": "x"}, "informational")
        self.assertFalse(res["success"])
        self.assertIn("running import", res["error"])

    async def test_plan_wave_path_hits_the_busy_gate(self):
        # The parallel plan path runs each step through the same executor.
        import importlib
        # The package re-exports the node FUNCTION under the module's name.
        execute_plan_node = importlib.import_module("orchestrator_helpers.nodes.execute_plan_node")

        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        step = {"tool_name": "fs_write", "tool_args": {"path": INSIDE, "content": "x"}}
        with mock.patch.object(execute_plan_node.roe_gate, "check_tool_call", return_value=None):
            ok = await execute_plan_node._execute_single_step(
                step, 0, 1, phase="informational", iteration=1, wave_id="w1", user_id="u",
                project_id="p1", session_id="s", tool_executor=self.executor, streaming_cb=None,
                session_manager_base="",
            )
        self.assertFalse(ok)
        self.assertIn("is being replaced by a running import", step["error_message"])
        self.assertFalse((self.root / INSIDE).exists())

    async def test_fs_tools_unchanged_without_registration(self):
        res = await self.executor._dispatch_fs_tool("fs_write", {"path": INSIDE, "content": "x"})
        self.assertTrue(res["success"], res)
        self.assertEqual((self.root / INSIDE).read_text(), "x")

    async def test_read_only_fs_tools_never_refused(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        for tool, args in (("fs_read", {"path": "uploads/repo/a.txt"}), ("fs_list", {"path": "uploads/repo"}),
                           ("fs_stat", {"path": "uploads/repo"}), ("fs_tree", {"path": "uploads"}),
                           ("fs_hash", {"path": "uploads/repo/a.txt"})):
            res = await self.executor._dispatch_fs_tool(tool, args)
            self.assertTrue(res["success"], (tool, res))

    async def test_writes_outside_the_busy_paths_still_work(self):
        busy.register("p1", JOB, target="uploads/repo", dest_dir="uploads")
        res = await self.executor._dispatch_fs_tool("fs_write", {"path": "uploads/other.txt", "content": "o"})
        self.assertTrue(res["success"], res)
        abs_inside = str(self.root / INSIDE)  # absolute paths are normalized too
        res = await self.executor._dispatch_fs_tool("fs_write", {"path": abs_inside, "content": "x"})
        self.assertFalse(res["success"])


if __name__ == "__main__":
    unittest.main()

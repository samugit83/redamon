"""
Whole-implementation deep review (Phases 1-6).

Tests for bugs that only surface at the seams between phases:
  - Project ID injection (HTTP-attacker-controlled value can have ../)
  - Symlink TOCTOU race
  - Memory limits for read snapshots and edit history
  - Contract drift between backend response shape + frontend Entry type
  - ContextVar isolation across concurrent asyncio tasks (fireteam)
  - End-to-end tool visibility: 29 new tools reach the rendered LLM prompt

Run with: python3 -m unittest tests.test_whole_impl_review -v
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from contextvars import copy_context
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import agent_context  # noqa: E402
import job_runner  # noqa: E402
import workspace_fs  # noqa: E402
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402
from prompts.base import build_informational_tool_descriptions  # noqa: E402


# =============================================================================
# (1) PROJECT-ID INJECTION
# =============================================================================

class TestProjectIdInjection(unittest.TestCase):
    """projectId comes from the HTTP query string (after auth). If it
    contains '..' or '/', resolve_for_project would compute a root OUTSIDE
    the intended workspace, and every subsequent path check would treat
    that escaped root as "the workspace" - leaking host filesystem access.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-inject-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_traversal_in_project_id_rejected(self):
        for bad in ("../escape", "../../etc", "..\\escape", "valid/../bad"):
            with self.assertRaises(ValueError,
                                   msg=f"projectId {bad!r} should be rejected"):
                workspace_fs.resolve_for_project(bad, ".")

    def test_absolute_project_id_rejected(self):
        for bad in ("/etc", "/tmp/escape"):
            with self.assertRaises(ValueError, msg=f"projectId {bad!r} should be rejected"):
                workspace_fs.resolve_for_project(bad, ".")

    def test_null_byte_in_project_id_rejected(self):
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project("proj\x00escape", ".")

    def test_slash_in_project_id_rejected(self):
        # Even without .. - a slash means "nested path", which lets an
        # attacker silently land in a different project they shouldn't see.
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project("foo/bar", ".")

    def test_valid_project_ids_accepted(self):
        # UUIDs, plain identifiers, hex
        for ok in ("550e8400-e29b-41d4-a716-446655440000", "my-project-1",
                   "abc123", "PROJ_X"):
            p = workspace_fs.resolve_for_project(ok, ".")
            self.assertTrue(p.is_dir(), f"projectId {ok!r} should be valid")


# =============================================================================
# (2) Symlink race / TOCTOU
# =============================================================================

class TestSymlinkTocTou(unittest.TestCase):
    """If a file is validated, then atomically replaced with a symlink to
    /etc/passwd before the actual read, does the workspace_fs still leak?

    Real exploitation is hard (requires concurrent attacker write to a
    workspace-writable dir). Mitigation is that .resolve() follows
    symlinks BOTH at validate AND read time - and Linux file ops are
    open(O_RDONLY) which is atomic post-open. The realistic attack would
    need to swap an intermediate directory component, which Path.resolve()
    sees through.

    This test just locks in the current behavior: a symlink pointing
    OUTSIDE the workspace planted between calls is rejected on each call.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-toctou-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        agent_context.current_project_id.set("toctou")

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)
        agent_context.current_project_id.set("")

    def test_each_call_revalidates(self):
        # Plant a real file, then mid-test replace with a symlink-to-outside.
        async def scenario():
            await workspace_fs.fs_write("safe.txt", "v1")
            full = Path(self.tmp) / "toctou" / "safe.txt"
            full.unlink()
            outside = Path(self.tmp) / "outside.txt"
            outside.write_text("SECRET")
            os.symlink(str(outside), str(full))
            # Now fs_read on the same path. The symlink resolves OUTSIDE
            # the workspace - must be rejected, not return SECRET.
            out = await workspace_fs.fs_read("safe.txt")
            self.assertNotIn("SECRET", out)
            self.assertIn("Error", out)
        asyncio.run(scenario())


# =============================================================================
# (3) Bounded caches
# =============================================================================

class TestBoundedCaches(unittest.TestCase):
    """Read snapshots evict least recently used entries at their limits."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-leak-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        workspace_fs._last_read_contents.clear()
        workspace_fs._last_read_hashes.clear()
        agent_context.current_project_id.set("leak")

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)
        agent_context.current_project_id.set("")
        workspace_fs._last_read_contents.clear()
        workspace_fs._last_read_hashes.clear()

    def test_read_snapshots_evict_least_recently_used(self):
        with patch.object(workspace_fs, "_SNAPSHOT_MAX_HASHES", 2), \
             patch.object(workspace_fs, "_SNAPSHOT_MAX_TOTAL", 2):
            first, second, third = ("project", "first"), ("project", "second"), ("project", "third")
            workspace_fs._remember_read(first, "a", b"a")
            workspace_fs._remember_read(second, "b", b"b")
            workspace_fs._remember_read(first, "a", b"a")
            workspace_fs._remember_read(third, "c", b"c")
            self.assertEqual(list(workspace_fs._last_read_hashes), [first, third])
            self.assertEqual(list(workspace_fs._last_read_contents), [first, third])
            self.assertEqual(sum(map(len, workspace_fs._last_read_contents.values())), 2)

    def test_edit_stack_capped_at_20_per_file(self):
        # This is the existing per-file cap; lock it in.
        async def scenario():
            await workspace_fs.fs_write("c.txt", "0")
            for i in range(1, 30):  # 29 edits > cap 20
                await workspace_fs.fs_edit("c.txt", str(i - 1), str(i))
        asyncio.run(scenario())
        full = Path(self.tmp) / "leak" / "c.txt"
        stack = workspace_fs._edit_stack[str(full.resolve())]
        self.assertEqual(len(stack), 20,
                         "fs_edit undo stack cap regressed from 20")


# =============================================================================
# (4) Contract drift: backend Entry shape <-> frontend Entry interface
# =============================================================================

class TestEntryShapeContract(unittest.TestCase):
    """The frontend FileSystemDrawer Entry interface declares:
        name, path, isDir, isSymlink, size, mtime.
    The backend list_dir_for_project must produce exactly these keys.
    """

    EXPECTED_KEYS = {"name", "path", "isDir", "isSymlink", "size", "mtime"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-contract-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_dir_entry_keys_match_frontend(self):
        # Plant one of each entry type: file, dir, symlink (in supported envs)
        root = workspace_fs.resolve_for_project("ct", ".")
        (root / "notes" / "f.txt").write_text("v")
        (root / "notes" / "sub").mkdir()
        try:
            os.symlink(str(root / "notes" / "f.txt"), str(root / "notes" / "link"))
        except OSError:
            pass  # skip symlink on systems that don't support it (Windows)

        entries = workspace_fs.list_dir_for_project("ct", "notes")
        self.assertTrue(entries)
        for e in entries:
            self.assertEqual(
                set(e.keys()), self.EXPECTED_KEYS,
                f"Entry key drift! frontend Entry expects "
                f"{sorted(self.EXPECTED_KEYS)}, backend produced {sorted(e.keys())}"
            )

    def test_drawer_typescript_interface_matches(self):
        # Lock the FE interface in source. If someone renames a field on
        # either side, one of these two tests fires.
        ts_file = (Path(_AGENTIC_DIR).parent / "webapp" / "src" / "app" / "graph"
                   / "components" / "FileSystemDrawer" / "FileSystemDrawer.tsx")
        src = ts_file.read_text()
        # Find the Entry interface definition
        for key in self.EXPECTED_KEYS:
            self.assertIn(
                f"{key}:", src,
                f"Frontend Entry interface is missing '{key}'. Backend "
                f"list_dir_for_project still emits it - silent contract drift."
            )


# =============================================================================
# (5) ContextVar isolation across concurrent asyncio tasks (fireteam)
# =============================================================================

class TestFireteamContextIsolation(unittest.IsolatedAsyncioTestCase):
    """Fireteam runs multiple agent members concurrently. Each should
    see its own project_id. If ContextVar.set() leaks across tasks,
    one member's fs_write could land in another's workspace.

    Python's asyncio runs each task in a copy of the parent's context
    by default (per PEP 567 / asyncio.Task semantics). Setting a
    ContextVar inside one task doesn't affect the other task's view.
    This test locks that in for project_id specifically.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-fireteam-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        agent_context.current_project_id.set("")

    async def asyncTearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        agent_context.current_project_id.set("")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tearDown(self):
        pass

    async def test_concurrent_tasks_see_isolated_project_id(self):
        results: dict[str, str] = {}

        async def member(pid: str):
            # Set in this task's context - should not leak to siblings
            agent_context.current_project_id.set(pid)
            await asyncio.sleep(0.01)  # yield to siblings mid-set
            await workspace_fs.fs_write("marker.txt", f"member-{pid}")
            await asyncio.sleep(0.01)
            # Read back what this task set
            results[pid] = agent_context.current_project_id.get()

        # Run two tasks concurrently. Each must end its turn with its own pid.
        # NOTE: each task needs its own Context to be truly isolated.
        async def run_in_ctx(pid):
            ctx = copy_context()
            await ctx.run(asyncio.create_task, member(pid))

        # Simpler: just create tasks. asyncio.create_task copies context
        # at task creation; but if we await both, they share the OUTER
        # context's pid which is "". We need to set pid INSIDE the task.
        # That's already what member() does, so the design is correct.
        await asyncio.gather(member("A"), member("B"))

        self.assertEqual(results.get("A"), "A",
                         "Task A's pid leaked or got overwritten")
        self.assertEqual(results.get("B"), "B",
                         "Task B's pid leaked or got overwritten")

        # And each task's fs_write landed in the right project
        self.assertTrue((Path(self.tmp) / "A" / "marker.txt").exists())
        self.assertTrue((Path(self.tmp) / "B" / "marker.txt").exists())
        self.assertEqual(
            (Path(self.tmp) / "A" / "marker.txt").read_text(), "member-A")
        self.assertEqual(
            (Path(self.tmp) / "B" / "marker.txt").read_text(), "member-B")


# =============================================================================
# (6) End-to-end tool visibility: 29 new tools reach the LLM prompt
# =============================================================================

class TestToolsReachLLMPrompt(unittest.TestCase):
    """Tool registry has the entries, dispatch works, but is the LLM
    actually told about them? Verifies the full chain registry ->
    build_informational_tool_descriptions -> output string.

    Picks a representative cross-section so a future filter dropping
    fs_/job_ tools from the prompt would fire here.
    """

    SAMPLED_TOOLS = [
        "fs_read", "fs_write", "fs_edit", "fs_grep", "fs_extract",
        "fs_hash", "fs_diff", "fs_symbols",
        "job_spawn", "job_status", "job_wait", "job_cancel", "job_list",
    ]

    def test_each_sampled_tool_rendered_in_descriptions(self):
        # Pass ALL Phase-3 tools to the renderer; verify each appears.
        all_new = [n for n in TOOL_REGISTRY if n.startswith(("fs_", "job_"))]
        out = build_informational_tool_descriptions(all_new)
        for tool in self.SAMPLED_TOOLS:
            self.assertIn(
                f"**{tool}**", out,
                f"{tool} description missing from LLM prompt. Phase-3 "
                f"entries are in the registry but the renderer skipped them."
            )

    def test_purpose_appears_in_output_for_each_tool(self):
        all_new = [n for n in TOOL_REGISTRY if n.startswith(("fs_", "job_"))]
        out = build_informational_tool_descriptions(all_new)
        # Sample: fs_read's description should mention reading files
        self.assertIn("Cat-n style", out)  # from fs_read description
        # And job_spawn's purpose should mention background
        self.assertIn("background", out.lower())


if __name__ == "__main__":
    unittest.main()

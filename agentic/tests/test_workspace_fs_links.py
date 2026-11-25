"""The workspace file tools under a sandbox that plants links, pipes and giants.

Every Kali sandbox that mounts a project writes its folder as root, so any name
in it can be a link out of the project, a pipe, or a sparse giant, and can become
one between the path check and the open. The agent's tools must never read or
write through such a link (STRIDE T4/I6), never block on a pipe and never read a
giant whole (D15): the agent serves every tenant on one event loop.

`outside/` stands in for the agent container's own files and its canary for a
secret; nothing real is read.
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import io
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_context  # noqa: E402
import workspace_fs  # noqa: E402

PID = "proj-links"
CANARY = "INTERNAL_API_KEY=planted-canary-0451"
GUARD_SEC = 5.0
GIANT = 64 << 20          # over the 32 MiB read cap; sparse, so it costs no disk
PEAK_LIMIT = 8 << 20


def _unblock(fifo):
    # A blocked reader waits for a writer and a blocked writer for a reader.
    for flags in (os.O_WRONLY | os.O_NONBLOCK, os.O_RDONLY | os.O_NONBLOCK):
        try:
            os.close(os.open(fifo, flags))
        except OSError:
            pass


def guarded(test, coro_fn, fifos=()):
    """Run an async tool in a thread; still blocked after GUARD_SEC (the old open()
    of a pipe) it is unblocked, then the test FAILS, so a hang is a failure and
    never a stuck run."""
    box, ctx = {}, contextvars.copy_context()

    def target():
        try:
            box["value"] = ctx.run(asyncio.run, coro_fn())
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(GUARD_SEC)
    hung = t.is_alive()
    deadline = time.monotonic() + 10
    while t.is_alive() and time.monotonic() < deadline:
        for fifo in fifos:
            _unblock(fifo)
        t.join(0.05)
    if hung:
        test.fail(f"blocked on a planted pipe for {GUARD_SEC}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="redamon-wslinks-"))
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.secret = self.outside / "environ"
        self.secret.write_text(CANARY + "\n")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = self.tmp / "workspace"
        workspace_fs._edit_stack.clear()
        workspace_fs._last_read_contents.clear()
        workspace_fs._last_read_hashes.clear()
        agent_context.current_project_id.set(PID)
        self.root = self.tmp / "workspace" / PID
        self.root.mkdir(parents=True)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        agent_context.current_project_id.set("")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def no_canary(self, value):
        self.assertNotIn("planted-canary", str(value))

    def link_folder(self, name="esc"):
        """A folder of the project replaced by a link to outside/."""
        (self.root / name).symlink_to(self.outside)
        return self.root / name


class ReadsAreBoundedAndNeverBlock(_Base):
    async def test_fs_read_of_a_pipe_does_not_hang(self):
        fifo = self.root / "notes.txt"
        os.mkfifo(fifo)
        out = guarded(self, lambda: workspace_fs.fs_read("notes.txt"), [fifo])
        self.assertTrue(out.startswith("Error:"), out)

    async def test_fs_read_of_a_sparse_giant_is_refused_without_reading_it(self):
        with open(self.root / "big.log", "wb") as fh:
            fh.truncate(GIANT)
        tracemalloc.start()
        try:
            out = await workspace_fs.fs_read("big.log")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertTrue(out.startswith("Error:"), out[:200])
        self.assertIn("fs_grep", out)
        self.assertLess(peak, PEAK_LIMIT)

    async def test_fs_read_many_reads_only_what_it_can_show(self):
        with open(self.root / "big.log", "wb") as fh:
            fh.truncate(GIANT)
        os.mkfifo(self.root / "pipe")
        tracemalloc.start()
        try:
            out = guarded(self, lambda: workspace_fs.fs_read_many(["big.log", "pipe"]),
                          [self.root / "pipe"])
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertIn("=== pipe ===\nError:", out)
        self.assertLess(peak, PEAK_LIMIT)

    async def test_fs_edit_of_a_pipe_does_not_hang(self):
        fifo = self.root / "conf.txt"
        os.mkfifo(fifo)
        out = guarded(self, lambda: workspace_fs.fs_edit("conf.txt", "a", "b"), [fifo])
        self.assertTrue(out.startswith("Error:"), out)

    async def test_fs_write_append_to_a_pipe_does_not_hang(self):
        fifo = self.root / "out.log"
        os.mkfifo(fifo)
        try:
            out = guarded(self, lambda: workspace_fs.fs_write("out.log", "x", mode="append"), [fifo])
        except BrokenPipeError:
            self.fail("the append opened the pipe")
        self.assertTrue(out.startswith("Error:"), out)

    async def test_fs_extract_of_a_pipe_does_not_hang(self):
        fifo = self.root / "a.tar"
        os.mkfifo(fifo)
        out = guarded(self, lambda: workspace_fs.fs_extract("a.tar", "dest"), [fifo])
        self.assertTrue(out.startswith("Error:"), out)

    async def test_fs_extract_over_a_planted_pipe_does_not_hang(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("member.txt")
            info.size = 5
            tf.addfile(info, io.BytesIO(b"hello"))
        (self.root / "a.tar").write_bytes(buf.getvalue())
        (self.root / "dest").mkdir()
        fifo = self.root / "dest" / "member.txt"
        os.mkfifo(fifo)
        out = guarded(self, lambda: workspace_fs.fs_extract("a.tar", "dest"), [fifo])
        self.assertTrue(out.startswith("Error:"), out)

    async def test_fs_archive_onto_a_planted_pipe_does_not_hang(self):
        (self.root / "a.txt").write_text("a")
        fifo = self.root / "bundle.tar.gz"
        os.mkfifo(fifo)
        out = guarded(self, lambda: workspace_fs.fs_archive(["a.txt"], "bundle.tar.gz"), [fifo])
        self.assertTrue(out.startswith("Archived"), out)
        with tarfile.open(self.root / "bundle.tar.gz") as tf:
            self.assertEqual(tf.getnames(), ["a.txt"])

    async def test_fs_hash_of_a_sparse_giant_stays_within_its_cap(self):
        with open(self.root / "big.bin", "wb") as fh:
            fh.truncate(GIANT)
        with mock.patch.dict(os.environ, {"FS_HASH_MAX_BYTES": str(1 << 20)}):
            out = await workspace_fs.fs_hash("big.bin")
        self.assertTrue(out.startswith("Error:"), out)


class NoLinkOutIsFollowed(_Base):
    async def test_a_folder_swapped_for_a_link_after_the_check_is_not_read(self):
        """The race: _resolve_safe approves notes/x.txt, then the sandbox swaps
        notes for a link to outside before the open."""
        (self.root / "notes").mkdir()
        (self.root / "notes" / "environ").write_text("in-project text\n")
        real_resolve = workspace_fs._resolve_safe

        def resolve_then_swap(user_path, follow_symlinks=True):
            checked = real_resolve(user_path, follow_symlinks)
            (self.root / "notes").rename(self.root / "notes.real")
            (self.root / "notes").symlink_to(self.outside)
            return checked

        with mock.patch.object(workspace_fs, "_resolve_safe", resolve_then_swap):
            out = await workspace_fs.fs_read("notes/environ")
        self.no_canary(out)
        self.assertTrue(out.startswith("Error:"), out)

    async def test_fs_stat_never_measures_or_hashes_through_a_link(self):
        self.link_folder()
        out = await workspace_fs.fs_stat("esc/environ", include_hash=True)
        self.assertNotIn(hashlib.sha256(self.secret.read_bytes()).hexdigest(), out)
        self.assertNotIn(f"size: {self.secret.stat().st_size}", out)
        (self.root / "lnk").symlink_to(self.secret)
        out = await workspace_fs.fs_stat("lnk", include_hash=True)
        self.assertNotIn(hashlib.sha256(self.secret.read_bytes()).hexdigest(), out)
        self.assertIn("type: symlink", out)

    async def test_fs_symlink_read_never_reads_a_link_outside(self):
        self.link_folder()
        (self.outside / "agent-link").symlink_to("/agent/only/path")
        out = await workspace_fs.fs_symlink_read("esc/agent-link")
        self.assertNotIn("/agent/only/path", out)

    async def test_listings_never_show_what_is_behind_a_link(self):
        (self.outside / "agent-secret-name.txt").write_text("x")
        self.link_folder()
        for out in (await workspace_fs.fs_tree("."),
                    await workspace_fs.fs_glob("esc/*"),
                    workspace_fs.tree_for_project(PID, ".")):
            self.assertNotIn("agent-secret-name", out)
        rows, _ = workspace_fs.list_dir_page(PID, ".")
        self.assertIs({r["name"]: r["isDir"] for r in rows}["esc"], False)

    async def test_properties_never_hash_through_a_link(self):
        (self.root / "lnk").symlink_to(self.secret)
        props = workspace_fs.properties_for_project(PID, "lnk")
        self.assertNotIn("sha256", props)
        self.assertNotEqual(props["size"], self.secret.stat().st_size)
        self.link_folder()
        with self.assertRaises(ValueError):
            workspace_fs.properties_for_project(PID, "esc/environ")

    async def test_a_recursive_copy_keeps_a_link_a_link(self):
        (self.root / "src").mkdir()
        (self.root / "src" / "x").symlink_to(self.secret)
        await workspace_fs.fs_copy("src", "dst", recursive=True)
        self.assertTrue((self.root / "dst" / "x").is_symlink(), "the link's target was copied in")
        self.no_canary(await workspace_fs.fs_read("dst/x"))

    async def test_a_grep_pattern_is_never_an_rg_option(self):
        if shutil.which("rg") is None:
            self.skipTest("ripgrep is not installed in this image")
        (self.root / "a.txt").write_text("plain text\n")
        out = await workspace_fs.fs_grep("--version")
        self.assertNotIn("ripgrep", out)


class WritesNeverFollowAPlantedTempName(_Base):
    """T4: the writers used a predictable sibling (`<file>.tmp`, `.upload-tmp`)
    opened with write_text, which writes through a link planted at that name."""

    def victim(self):
        v = self.outside / "agent_module.py"
        v.write_text("original\n")
        return v

    async def test_fs_write(self):
        v = self.victim()
        (self.root / "report.md.tmp").symlink_to(v)
        await workspace_fs.fs_write("report.md", "attacker-chosen")
        self.assertEqual(v.read_text(), "original\n")
        self.assertEqual((self.root / "report.md").read_text(), "attacker-chosen")
        self.assertFalse((self.root / "report.md").is_symlink())

    async def test_fs_edit_and_fs_multi_edit(self):
        v = self.victim()
        (self.root / "a.py").write_text("x = 1\n")
        (self.root / "a.py.tmp").symlink_to(v)
        await workspace_fs.fs_edit("a.py", "x = 1", "x = 2")
        await workspace_fs.fs_multi_edit("a.py", [{"old_string": "x = 2", "new_string": "x = 3"}])
        self.assertEqual(v.read_text(), "original\n")
        self.assertEqual((self.root / "a.py").read_text(), "x = 3\n")

    async def test_upload(self):
        v = self.victim()
        (self.root / "uploads").mkdir()
        (self.root / "uploads" / "f.bin.upload-tmp").symlink_to(v)
        workspace_fs.upload_for_project(PID, "uploads", b"uploaded", "f.bin")
        self.assertEqual(v.read_text(), "original\n")
        self.assertEqual((self.root / "uploads" / "f.bin").read_bytes(), b"uploaded")

    async def test_an_append_never_writes_through_a_link_planted_after_the_check(self):
        v = self.victim()
        real_resolve = workspace_fs._resolve_safe

        def resolve_then_plant(user_path, follow_symlinks=True):
            checked = real_resolve(user_path, follow_symlinks)
            (self.root / "late.txt").symlink_to(v)
            return checked

        with mock.patch.object(workspace_fs, "_resolve_safe", resolve_then_plant):
            await workspace_fs.fs_write("late.txt", "content", mode="append")
        self.assertEqual(v.read_text(), "original\n")

    async def test_a_recursive_copy_never_chmods_through_a_link(self):
        v = self.victim()
        os.chmod(v, 0o600)
        (self.root / "src").mkdir()
        (self.root / "src" / "x").symlink_to(v)
        await workspace_fs.fs_copy("src", "dst", recursive=True)
        self.assertEqual(v.stat().st_mode & 0o777, 0o600)


class LegitimateUseStillWorks(_Base):
    """Regression guards: these pass before and after the fix."""

    async def test_read_write_edit_undo_append(self):
        await workspace_fs.fs_write("notes/a.txt", "one\ntwo\n")
        self.assertIn("1\tone", await workspace_fs.fs_read("notes/a.txt"))
        await workspace_fs.fs_edit("notes/a.txt", "two", "three")
        await workspace_fs.fs_write("notes/a.txt", "four\n", mode="append")
        self.assertEqual((self.root / "notes" / "a.txt").read_text(), "one\nthree\nfour\n")
        await workspace_fs.fs_undo_edit("notes/a.txt")
        self.assertEqual((self.root / "notes" / "a.txt").read_text(), "one\ntwo\n")
        self.assertIn("already exists", await workspace_fs.fs_write("notes/a.txt", "x", mode="create_only"))

    async def test_an_in_project_link_still_reads_and_hashes(self):
        (self.root / "real.txt").write_text("real content\n")
        (self.root / "alias.txt").symlink_to(self.root / "real.txt")
        self.assertIn("real content", await workspace_fs.fs_read("alias.txt"))
        out = await workspace_fs.fs_stat("alias.txt", include_hash=True)
        self.assertIn(hashlib.sha256(b"real content\n").hexdigest(), out)

    async def test_copy_move_chmod_delete(self):
        await workspace_fs.fs_write("a.txt", "data")
        await workspace_fs.fs_copy("a.txt", "b.txt")
        await workspace_fs.fs_move("b.txt", "c.txt")
        await workspace_fs.fs_chmod("c.txt", "600")
        self.assertEqual((self.root / "c.txt").stat().st_mode & 0o777, 0o600)
        await workspace_fs.fs_delete("c.txt")
        self.assertEqual(sorted(p.name for p in self.root.iterdir() if p.is_file()), ["a.txt"])

    async def test_a_large_but_allowed_file_reads(self):
        (self.root / "out.txt").write_text("".join(f"line {i}\n" for i in range(100_000)))
        out = await workspace_fs.fs_read("out.txt", offset=99_990, limit=5)
        self.assertIn("99990\tline 99989", out)


if __name__ == "__main__":
    unittest.main()

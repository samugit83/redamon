"""FU-29 rev 5: ways the rev-4 rewrite let one person tie up the shared agent.

Built on the reviewer's rev-4 repros (FU/rvP5/rv4 test_rvp5_rev4*.py). A call that
could hang on the old code runs in a child interpreter with a timeout, so a hang
is a failure and never a stuck run. Nothing real is read.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_context  # noqa: E402
import job_runner  # noqa: E402
import workspace_fs  # noqa: E402
from workspace_import.errors import ImportFailure  # noqa: E402

PID = "proj-rv5"
AGENTIC = str(Path(__file__).resolve().parent.parent)


def run_child(code: str, timeout: float):
    """(seconds, output, hung) of `code` in a fresh interpreter."""
    t = time.time()
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout)
        return time.time() - t, r.stdout + r.stderr[-1500:], False
    except subprocess.TimeoutExpired:
        return time.time() - t, "", True


def grep_children() -> list[int]:
    """The live grep children of THIS process: the gate runs test files side by
    side in one container, and another file's searches must not be counted."""
    pids, me = [], os.getpid()
    for pid in os.listdir("/proc"):
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                fields = fh.read().rsplit(b")", 1)[1].split()
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                argv = fh.read().split(b"\0")
        except (OSError, IndexError):
            continue
        state, ppid = fields[0], int(fields[1])
        if ppid == me and state != b"Z" and b"-I" in argv and b"-S" in argv and b"-c" in argv:
            pids.append(int(pid))
    return pids


async def poll(condition, seconds: float) -> bool:
    """True as soon as condition() holds, False if it never did within `seconds`."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.05)
    return condition()


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-rev5-"))
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = self.tmp / "workspace"
        agent_context.current_project_id.set(PID)
        self.root = self.tmp / "workspace" / PID
        self.root.mkdir(parents=True)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        agent_context.current_project_id.set("")
        subprocess.run(["rm", "-rf", str(self.tmp)])

    def prelude(self) -> str:
        return (f"import asyncio, sys, time\nsys.path.insert(0, {AGENTIC!r})\n"
                f"import agent_context, workspace_fs\nfrom pathlib import Path\n"
                f"workspace_fs.WORKSPACE_ROOT = Path({str(self.tmp / 'workspace')!r})\n"
                f"agent_context.current_project_id.set({PID!r})\n")

    def redos_file(self):
        (self.root / "notes").mkdir(exist_ok=True)
        (self.root / "notes" / "a.txt").write_text("a" * 40 + "b\n")


# 1. ---------------------------------------------------------------- the grep child
class GrepChildIsBounded(_Base):
    async def test_a_backtracking_pattern_is_stopped_mid_match(self):
        self.redos_file()
        t = time.time()
        out = await workspace_fs.fs_grep("(a+)+$", path="notes")
        took = time.time() - t
        self.assertLess(took, 5, f"one fs_grep burnt a CPU for {took:.1f}s")
        self.assertTrue(out.startswith("Error:"), out)

    async def test_at_most_two_children_run_at_once(self):
        self.redos_file()
        tasks = [asyncio.create_task(workspace_fs.fs_grep("(a+)+$", path="notes")) for _ in range(6)]
        most = 0
        while not all(t.done() for t in tasks):
            most = max(most, len(grep_children()))
            await asyncio.sleep(0.05)
        await asyncio.gather(*tasks, return_exceptions=True)
        self.assertGreater(most, 0, "no search child was ever seen")
        self.assertLessEqual(most, 2, f"{most} grep children ran at once")

    async def test_a_cancelled_search_takes_its_child_with_it(self):
        self.redos_file()
        task = asyncio.create_task(workspace_fs.fs_grep("(a+)+$", path="notes"))
        # Cancel only once the child really runs (under load it can start late).
        self.assertTrue(await poll(lambda: grep_children() or task.done(), 15), "the child never started")
        self.assertFalse(task.done(), "the search ended before it could be cancelled")
        task.cancel()  # the chat's per-tool Stop
        try:
            await task
        except asyncio.CancelledError:
            pass
        gone = await poll(lambda: not grep_children(), 15)
        orphans = grep_children()
        for p in orphans:
            os.kill(p, 9)
        self.assertTrue(gone, f"a cancelled fs_grep left its child running: {orphans}")

    async def test_multiline_reads_a_bounded_part_of_each_file(self):
        p = self.root / "big.log"
        with open(p, "wb") as fh:
            fh.write(b"hello world\n" * 700)
            fh.truncate(256 << 20)
        out = await workspace_fs.fs_grep("zzz", path="big.log", multiline=True)
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        self.assertEqual(out, "No matches found.")
        self.assertLess(peak // 1024, 256, f"one multiline grep child peaked at {peak // 1024} MB")

    async def test_brace_globs_and_hostile_arguments(self):
        (self.root / "notes").mkdir()
        (self.root / "notes" / "a.py").write_text("y = 1\n")
        (self.root / "notes" / "b.txt").write_text("y = 2\n")
        (self.root / "notes" / "c.md").write_text("y = 3\n")
        out = await workspace_fs.fs_grep("y", path="notes", glob="*.{py,txt}")
        self.assertEqual(sorted(out.splitlines()), ["notes/a.py", "notes/b.txt"])
        self.assertTrue((await workspace_fs.fs_grep("y", path="notes", context="5; rm -rf /")).startswith("Error:"))
        self.assertTrue((await workspace_fs.fs_grep("(?P<x", path="notes")).startswith("Error:"))


# 2. --------------------------------------------------------------------- fs_glob
class GlobMatcherIsLinear(_Base):
    def test_many_double_stars_on_a_deep_tree(self):
        deep = self.root
        for _ in range(30):
            deep = deep / "a"
        deep.mkdir(parents=True)
        code = self.prelude() + (f"t = time.time(); out = asyncio.run(workspace_fs.fs_glob({('**/' * 12 + 'zz')!r}))\n"
                                 "print('RETURNED', round(time.time() - t, 2), out[:80])\n")
        took, out, hung = run_child(code, 30)
        self.assertFalse(hung, "fs_glob held a worker past 30 s")
        self.assertIn("No files matching", out)
        seconds = float(out.split("RETURNED", 1)[1].split()[0])
        self.assertLess(seconds, 2, f"one fs_glob held a worker {seconds}s on a 30-folder tree")

    def test_hundreds_of_double_stars_are_refused_cleanly(self):
        (self.root / "a" / "b" / "c" / "d").mkdir(parents=True)
        code = self.prelude() + (f"out = asyncio.run(workspace_fs.fs_glob({('**/' * 400 + 'zz')!r}))\n"
                                 "print('RETURNED', out[:120])\n")
        took, out, hung = run_child(code, 30)
        self.assertFalse(hung)
        self.assertIn("RETURNED", out)
        self.assertNotIn("RecursionError", out)
        code = self.prelude() + (f"out = asyncio.run(workspace_fs.fs_glob({('a*/' * 70 + 'zz')!r}))\n"
                                 "print('RETURNED', out[:120])\n")
        took, out, hung = run_child(code, 30)
        self.assertIn("RETURNED Error:", out)

    async def test_legitimate_patterns_and_braces(self):
        (self.root / "d" / "e").mkdir(parents=True)
        for name in ("a.json", "d/b.txt", "d/e/c.json", "d/e/x.md"):
            (self.root / name).write_text("x")
        self.assertEqual(sorted((await workspace_fs.fs_glob("**/*.{json,txt}")).splitlines()),
                         ["a.json", "d/b.txt", "d/e/c.json"])
        self.assertEqual(await workspace_fs.fs_glob("d/*/x.md"), "d/e/x.md")
        self.assertEqual(sorted((await workspace_fs.fs_glob("**/**/*.json")).splitlines()),
                         ["a.json", "d/e/c.json"])


# 3. -------------------------------------------------------------- sparse giants
class SparseGiantsAreCheap(_Base):
    async def test_three_lines_of_a_sparse_giant_with_a_text_head(self):
        # What proves the bound is how much is DECODED (the costly part, every line
        # to the 4 GiB scan cap on the old code), not the time a loaded host takes.
        p = self.root / "giant.log"
        with open(p, "wb") as fh:
            fh.write(b"line\n" * 2000)
            fh.truncate((1 << 30) - 1)
        decoded = [0]
        real = workspace_fs.codecs.getincrementaldecoder

        def counting(encoding):
            base = real(encoding)

            class Counting(base):
                def decode(self, data, final=False):
                    decoded[0] += len(data)
                    return super().decode(data, final)

            return Counting

        with mock.patch.object(workspace_fs.codecs, "getincrementaldecoder", counting):
            out = await workspace_fs.fs_read("giant.log", limit=3)
        self.assertIn("1\tline", out)
        self.assertLess(decoded[0], 16 << 20, f"three lines decoded {decoded[0]} bytes of the file")

    async def test_fs_archive_of_a_4_gib_sparse_file_is_refused(self):
        (self.root / "d").mkdir()
        with open(self.root / "d" / "sparse.bin", "wb") as fh:
            fh.truncate(4 << 30)
        t = time.time()
        out = await workspace_fs.fs_archive(["d"], "d.tar.gz")
        self.assertLess(time.time() - t, 5)
        self.assertTrue(out.startswith("Error:"), out)
        self.assertFalse((self.root / "d.tar.gz").exists())

    def test_a_drawer_download_over_the_budget_is_too_large(self):
        (self.root / "d").mkdir()
        with open(self.root / "d" / "sparse.bin", "wb") as fh:
            fh.truncate(4 << 30)
        with self.assertRaises(ImportFailure) as ctx:
            workspace_fs.write_dir_archive(io.BytesIO(), self.root / "d", "d", "zip")
        self.assertEqual(ctx.exception.code, "too_large")

    async def test_paging_and_diff_still_work(self):
        (self.root / "big.log").write_bytes(b"".join(b"line %d\n" % i for i in range(3_000_000)))
        out = await workspace_fs.fs_read("big.log", offset=2_999_990, limit=3)
        self.assertIn("line 2999989", out)
        self.assertIn("of 3000000]", out)
        await workspace_fs.fs_read("big.log", limit=1)
        self.assertEqual(await workspace_fs.fs_diff("big.log", vs_last_read=True),
                         "(no changes since last fs_read)")
        await workspace_fs.fs_write("big.log", "new\n", mode="append")
        self.assertIn("changed since the last fs_read", await workspace_fs.fs_diff("big.log", vs_last_read=True))


# 4. --------------------------------------------------------------- faked job ids
class PlantedOwnLookingIds(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-rev5j-"))
        self.root = self.tmp / "workspace"
        self.jobs = self.root / "p1" / "jobs"
        self.jobs.mkdir(parents=True)
        self._orig = job_runner.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = self.root

    def tearDown(self):
        job_runner.WORKSPACE_ROOT = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_newer_32_hex_names_do_not_push_out_the_agents_job(self):
        real = "f" * 32
        (self.jobs / f"{real}.meta.json").write_text(json.dumps({"job_id": real, "status": "done",
                                                                 "started_at": "2026"}))
        os.utime(self.jobs / f"{real}.meta.json", (1, 1))
        reg = job_runner.JobRegistry()
        reg.recover_on_boot()
        future = time.time() + 10 ** 6
        for i in range(600):
            path = self.jobs / f"{i:032x}.meta.json"
            path.write_text(json.dumps({"job_id": f"{i:032x}", "status": "done", "started_at": "2099"}))
            os.utime(path, (future, future))
        rows = reg.list("p1")
        self.assertIn(real, [r.get("job_id") for r in rows], "planted 32-hex names pushed the real job out")

    def test_a_flood_of_32_hex_names_keeps_the_listing_fast(self):
        for i in range(100_000):
            os.close(os.open(self.jobs / f"{i:032x}.meta.json", os.O_WRONLY | os.O_CREAT, 0o644))
        t = time.time()
        job_runner.JobRegistry().list("p1")
        self.assertLess(time.time() - t, 0.5)


# 5. ----------------------------------------------------------------- deep trees
class DeepTrees(_Base):
    async def test_a_70_deep_tree_copies_whole(self):
        deep = self.root / "t"
        for i in range(70):
            deep = deep / f"d{i}"
        deep.mkdir(parents=True)
        (deep / "leaf.txt").write_text("leaf\n")
        out = await workspace_fs.fs_copy("t", "t2", recursive=True)
        self.assertEqual(out, "Copied t -> t2.")
        self.assertTrue(list((self.root / "t2").rglob("leaf.txt")))
        await workspace_fs.fs_archive(["t"], "t.zip", format="zip")
        with zipfile.ZipFile(self.root / "t.zip") as zf:
            self.assertTrue(any(n.endswith("leaf.txt") for n in zf.namelist()))

    async def test_past_the_walk_depth_the_cut_is_reported(self):
        deep = self.root / "t"
        for _ in range(workspace_fs._WALK_MAX_DEPTH + 5):
            deep = deep / "d"
        os.makedirs(deep)
        (deep / "leaf.txt").write_text("leaf\n")
        out = await workspace_fs.fs_copy("t", "t2", recursive=True)
        self.assertIn("without 1 folder(s) nested deeper", out)
        out = await workspace_fs.fs_archive(["t"], "t.zip", format="zip")
        self.assertIn("without 1 folder(s) nested deeper", out)
        with self.assertRaises(ImportFailure) as ctx:
            workspace_fs.write_dir_archive(io.BytesIO(), self.root / "t", "t", "zip")
        self.assertEqual(ctx.exception.code, "too_deep")

    async def test_a_1500_deep_member_is_refused_and_a_deep_tree_still_resets(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("x/" + "a/" * 1500 + "leaf.txt", b"leaf")
        (self.root / "deep.zip").write_bytes(buf.getvalue())
        out = await workspace_fs.fs_extract("deep.zip", "dest")
        self.assertTrue(out.startswith("Error:") and "levels deep" in out, out)
        # A sandbox can nest folders that deep itself: the reset must still remove them.
        fd = os.open(self.root, os.O_RDONLY)
        try:
            os.mkdir("sandbox-made", dir_fd=fd)
            cur = os.open("sandbox-made", os.O_RDONLY, dir_fd=fd)
            for _ in range(1500):
                os.mkdir("a", dir_fd=cur)
                nxt = os.open("a", os.O_RDONLY, dir_fd=cur)
                os.close(cur)
                cur = nxt
            os.close(cur)
        finally:
            os.close(fd)
        workspace_fs.reset_for_project(PID)
        self.assertFalse((self.root / "sandbox-made").exists())


if __name__ == "__main__":
    unittest.main()

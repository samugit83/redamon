"""place(): Keep both / Replace / Fail, atomic and cancel-safe."""
from __future__ import annotations

import asyncio
import os
import shutil
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import workspace_fs
from workspace_import import executor, place, staging
from workspace_import.errors import ImportFailure


class PlaceBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-place-"))
        self._root = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp)
        self._root.start()
        self._pool = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2)
        place._locks.clear()
        self.root = workspace_fs.resolve_for_project("p1", ".")

    def tearDown(self):
        executor.IMPORT_EXECUTOR.shutdown(wait=True)
        executor.IMPORT_EXECUTOR = self._pool
        self._root.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def staged_dir(self, files=None):
        op = staging.new_op_dir("p1", "test")
        out = op / "out"
        out.mkdir()
        for rel, data in (files or {"README": "new"}).items():
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            (out / rel).write_text(data)
        return out

    def staged_file(self, data="pdf"):
        op = staging.new_op_dir("p1", "test")
        f = op / "data.part"
        f.write_text(data)
        return f

    async def assertCode(self, code, coro):
        with self.assertRaises(ImportFailure) as ctx:
            await coro
        self.assertEqual(ctx.exception.code, code)


class Policies(PlaceBase):
    async def test_keep_both_dir_and_file_suffixes(self):
        (self.root / "uploads/site").mkdir()
        (self.root / "uploads/report.pdf").write_text("old")
        (self.root / "uploads/pack.tar.gz").write_text("old")
        self.assertEqual(await place.place("p1", self.staged_dir(), "uploads", "site", "keep_both"),
                         "uploads/site-2")
        self.assertEqual(await place.place("p1", self.staged_file(), "uploads", "report.pdf", "keep_both"),
                         "uploads/report-2.pdf")
        self.assertEqual(await place.place("p1", self.staged_file(), "uploads", "pack.tar.gz", "keep_both"),
                         "uploads/pack-2.tar.gz")
        self.assertEqual(await place.place("p1", self.staged_dir(), "uploads", "site", "keep_both"),
                         "uploads/site-3")
        self.assertEqual((self.root / "uploads/report.pdf").read_text(), "old")

    async def test_first_placement_keeps_the_name(self):
        rel = await place.place("p1", self.staged_dir(), "uploads", "repo", "keep_both")
        self.assertEqual(rel, "uploads/repo")
        self.assertEqual((self.root / "uploads/repo/README").read_text(), "new")

    async def test_replace_swaps_and_removes_old(self):
        (self.root / "uploads/repo").mkdir()
        (self.root / "uploads/repo/old.txt").write_text("old")
        rel = await place.place("p1", self.staged_dir(), "uploads", "repo", "replace")
        self.assertEqual(rel, "uploads/repo")
        self.assertEqual(sorted(os.listdir(self.root / "uploads/repo")), ["README"])
        trash = list((self.tmp / ".staging/p1").glob("trash-*"))
        self.assertEqual(trash, [])

    async def test_replace_refuses_protected_and_type_mismatch(self):
        await self.assertCode("protected_path", place.place("p1", self.staged_dir(), ".", "uploads", "replace"))
        (self.root / "uploads/thing").write_text("a file")
        await self.assertCode("conflict_type", place.place("p1", self.staged_dir(), "uploads", "thing", "replace"))
        self.assertEqual((self.root / "uploads/thing").read_text(), "a file")

    async def test_fail_policy_raises_exists(self):
        (self.root / "uploads/repo").mkdir()
        await self.assertCode("exists", place.place("p1", self.staged_dir(), "uploads", "repo", "fail"))

    async def test_name_exhausted_after_999(self):
        (self.root / "uploads/r").mkdir()
        for i in range(2, 1000):
            (self.root / f"uploads/r-{i}").mkdir()
        await self.assertCode("name_exhausted", place.place("p1", self.staged_dir(), "uploads", "r", "keep_both"))

    async def test_destination_removed_before_place_is_destination_missing(self):
        (self.root / "uploads/sub").mkdir()
        staged = self.staged_dir()
        shutil.rmtree(self.root / "uploads/sub")
        await self.assertCode("destination_missing", place.place("p1", staged, "uploads/sub", "repo", "keep_both"))
        self.assertTrue(staged.exists())  # the caller removes staging

    async def test_two_concurrent_places_get_distinct_names(self):
        results = await asyncio.gather(*[
            place.place("p1", self.staged_dir({"f": str(i)}), "uploads", "dup", "keep_both") for i in range(5)
        ])
        self.assertEqual(sorted(results), ["uploads/dup", "uploads/dup-2", "uploads/dup-3",
                                           "uploads/dup-4", "uploads/dup-5"])

    async def test_modes_normalized(self):
        staged = self.staged_dir({"a/b.txt": "x"})
        os.chmod(staged / "a/b.txt", 0o600)
        os.chmod(staged / "a", 0o700)
        await place.place("p1", staged, "uploads", "m", "keep_both")
        self.assertEqual(stat.S_IMODE((self.root / "uploads/m/a").stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE((self.root / "uploads/m/a/b.txt").stat().st_mode), 0o666)
        f = self.staged_file()
        os.chmod(f, 0o600)
        await place.place("p1", f, "uploads", "f.bin", "keep_both")
        self.assertEqual(stat.S_IMODE((self.root / "uploads/f.bin").stat().st_mode), 0o666)

    async def test_unknown_policy_refused(self):
        await self.assertCode("invalid_request", place.place("p1", self.staged_dir(), "uploads", "x", "merge"))


class _Crash(BaseException):
    """Stands in for the process dying (asyncio re-raises a real SystemExit
    out of the event loop instead of through the awaiting task)."""


class CancelAndCrash(PlaceBase):
    async def test_cancel_cannot_split_the_swap(self):
        # Cancel the place() task after every possible number of event-loop
        # steps: the target is always whole, old or new, never missing.
        for steps in range(0, 12):
            target = self.root / "uploads/repo"
            if target.exists():
                shutil.rmtree(target)
            target.mkdir()
            (target / "old.txt").write_text("old")
            task = asyncio.ensure_future(place.place("p1", self.staged_dir(), "uploads", "repo", "replace"))
            for _ in range(steps):
                await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            names = sorted(os.listdir(target))
            self.assertIn(names, (["old.txt"], ["README"]), f"after {steps} steps: {names}")
        await asyncio.sleep(0.2)  # let a scheduled trash removal finish
        self.assertEqual(list((self.tmp / ".staging/p1").glob("trash-*")), [])

    async def test_crash_after_first_rename_is_recovered_at_boot(self):
        target = self.root / "uploads/repo"
        target.mkdir()
        (target / "old.txt").write_text("old")
        real_rename = os.rename
        calls = []

        def dead_after_first(src, dst):
            # The process dies after the first rename: nothing else runs,
            # not even the in-process rollback.
            calls.append(src)
            if len(calls) >= 2:
                raise _Crash()
            return real_rename(src, dst)

        with mock.patch("workspace_import.place.os.rename", dead_after_first):
            with self.assertRaises(_Crash):
                await place.place("p1", self.staged_dir(), "uploads", "repo", "replace")
        self.assertFalse(target.exists())  # the state a crash leaves
        self.assertEqual(staging.recover_swaps(), 1)  # the next boot
        self.assertEqual(sorted(os.listdir(target)), ["old.txt"])

    async def test_failed_second_rename_rolls_back(self):
        target = self.root / "uploads/repo"
        target.mkdir()
        (target / "old.txt").write_text("old")
        real_rename = os.rename
        calls = []

        def fail_second(src, dst):
            calls.append(src)
            if len(calls) == 2:
                raise OSError(28, "No space left on device")
            return real_rename(src, dst)

        with mock.patch("workspace_import.place.os.rename", fail_second):
            with self.assertRaises(OSError):
                await place.place("p1", self.staged_dir(), "uploads", "repo", "replace")
        self.assertEqual(sorted(os.listdir(target)), ["old.txt"])


if __name__ == "__main__":
    unittest.main()

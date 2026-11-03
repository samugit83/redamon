"""Staging area, disk-reservation ledger, sweeps and crash-safe swap recovery."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import workspace_fs
from workspace_import import staging
from workspace_import.errors import ImportFailure

GIB = 1024 ** 3


class StagingBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-staging-"))
        self._root = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp)
        self._root.start()
        staging.reset_ledger()
        self.env = mock.patch.dict(os.environ, {"JOB_QUEUE_MIN_FREE_DISK": "0",
                                                "WORKSPACE_IMPORT_MIN_FREE_BYTES": str(GIB)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self._root.stop()
        staging.reset_ledger()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def free(self, nbytes):
        return mock.patch.object(staging, "disk_usage", lambda _p: SimpleNamespace(free=nbytes))


class OpDirs(StagingBase):
    def test_op_dirs_live_outside_every_project_root(self):
        workspace_fs.resolve_for_project("p1", ".")
        op = staging.new_op_dir("p1", "up")
        self.assertEqual(op.parent, self.tmp / ".staging" / "p1")
        self.assertTrue(op.name.startswith("up-") and len(op.name) == 35)
        self.assertNotIn(self.tmp / "p1", op.parents)
        self.assertEqual(os.stat(op).st_mode & 0o777, 0o777)
        # .staging is never a project: the drawer and the fs tools refuse it.
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project(".staging", ".")

    def test_invalid_project_id_refused(self):
        for bad in ("", "../x", ".staging", "a/b", "a\x00"):
            with self.assertRaises(ValueError, msg=bad):
                staging.new_op_dir(bad, "up")

    def test_sweep_all_and_sweep_project(self):
        a1 = staging.new_op_dir("pa", "up")
        b1 = staging.new_op_dir("pb", "imp")
        staging.sweep_project("pa")
        self.assertFalse(a1.exists())
        self.assertTrue(b1.exists())
        staging.sweep_all()
        self.assertFalse(b1.exists())
        self.assertTrue((self.tmp / ".staging").is_dir())


class Reservations(StagingBase):
    def test_check_space_refuses_below_reserve(self):
        with self.free(3 * GIB):
            staging.check_space(2 * GIB)
            with self.assertRaises(ImportFailure) as ctx:
                staging.check_space(2 * GIB + 1)
        self.assertEqual(ctx.exception.code, "insufficient_storage")

    def test_disk_usage_error_refuses(self):
        def boom(_p):
            raise OSError("statvfs failed")
        with mock.patch.object(staging, "disk_usage", boom):
            with self.assertRaises(ImportFailure) as ctx:
                staging.reserve("op", 1)
        self.assertEqual(ctx.exception.code, "insufficient_storage")

    def test_concurrent_reservations_cannot_overrun_free_space(self):
        results = []
        barrier = threading.Barrier(10)

        def worker(i):
            barrier.wait()
            try:
                staging.reserve(f"op{i}", GIB)
                results.append("ok")
            except ImportFailure:
                results.append("refused")

        with self.free(5 * GIB):
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(results.count("ok"), 4)
        self.assertEqual(staging.reserved_total(), 4 * GIB)

    def test_grow_checks_again_and_release_is_idempotent(self):
        with self.free(4 * GIB):
            r = staging.reserve("op", GIB)
            r.grow(GIB)
            self.assertEqual(r.nbytes, 2 * GIB)
            with self.assertRaises(ImportFailure):
                r.grow(GIB + 1)
            self.assertEqual(r.nbytes, 2 * GIB)
        r.release()
        r.release()
        self.assertEqual(staging.reserved_total(), 0)

    def test_grow_after_release_brings_nothing_back(self):
        # An extraction thread can outlive its job by a few chunks.
        with self.free(4 * GIB):
            r = staging.reserve("op", GIB)
            r.release()
            r.grow(GIB)
        self.assertEqual((r.nbytes, staging.reserved_total()), (0, 0))

    def test_sweep_releases_reservations(self):
        with self.free(10 * GIB):
            staging.reserve("a-op", GIB, project_id="pa")
            staging.reserve("b-op", GIB, project_id="pb")
        staging.sweep_project("pa")
        self.assertEqual(staging.reserved_total(), GIB)
        staging.sweep_all()
        self.assertEqual(staging.reserved_total(), 0)


class SwapRecovery(StagingBase):
    def _interrupted_swap(self, target_present: bool):
        root = workspace_fs.resolve_for_project("p1", ".")
        trash = staging.new_op_dir("p1", "trash")
        staging.write_swap_record(trash, "uploads/repo")
        old = trash / staging.SWAP_ENTRY
        old.mkdir()
        (old / "old.txt").write_text("old copy")
        if target_present:
            (root / "uploads" / "repo").mkdir()
            (root / "uploads" / "repo" / "new.txt").write_text("new copy")
        return root, trash

    def test_crash_between_renames_restores_old_folder_at_boot(self):
        root, trash = self._interrupted_swap(target_present=False)
        self.assertEqual(staging.recover_swaps(), 1)
        self.assertEqual((root / "uploads/repo/old.txt").read_text(), "old copy")
        self.assertFalse(trash.exists())
        staging.sweep_all()
        self.assertEqual((root / "uploads/repo/old.txt").read_text(), "old copy")

    def test_recover_swaps_deletes_trash_when_target_present(self):
        root, trash = self._interrupted_swap(target_present=True)
        self.assertEqual(staging.recover_swaps(), 0)
        self.assertEqual(sorted(os.listdir(root / "uploads/repo")), ["new.txt"])
        self.assertFalse(trash.exists())

    def test_swap_record_cannot_point_outside_the_project(self):
        workspace_fs.resolve_for_project("p1", ".")
        trash = staging.new_op_dir("p1", "trash")
        (trash / staging.SWAP_RECORD).write_text(json.dumps({"target_rel": "../../escaped"}))
        (trash / staging.SWAP_ENTRY).mkdir()
        staging.recover_swaps()
        self.assertFalse((self.tmp / "escaped").exists())
        self.assertFalse(trash.exists())


if __name__ == "__main__":
    unittest.main()

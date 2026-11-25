"""The boot-time swap record read is bounded (group 1, S12, WI-S12-4; D16, TD-18).

At boot `recover_swaps()` reads every `/workspace/.staging/<project>/trash-*/swap.json` to put
back a folder an interrupted replace was swapping. Until the per-user sandboxes, the shared Kali
container mounted the whole workspace, `.staging` included, so a shell there could plant a
record: a sparse gigabyte, a link to something huge, or a directory. The agent read it whole at
its next start.

Now a record that is not a regular file is skipped (never followed), and one larger than
SWAP_RECORD_MAX_BYTES is removed with its trash and never read: no read API is called on it.
A legitimate record (a few dozen bytes) is restored as before.

Run: ./agentic/run_tests.sh tests/test_staging_swap_record_bounded.py
"""
from __future__ import annotations

import builtins
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import workspace_fs
from workspace_import import staging

GIB = 1024 ** 3


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-swap-bound-"))
        self._root = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp)
        self._root.start()
        staging.reset_ledger()
        workspace_fs.resolve_for_project("p1", ".")
        (self.tmp / "p1" / "uploads").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._root.stop()
        staging.reset_ledger()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def trash_with_entry(self):
        """An interrupted replace: the old folder sits in the trash as `entry`, the target is gone."""
        trash = staging.new_op_dir("p1", "trash")
        (trash / staging.SWAP_ENTRY).mkdir()
        (trash / staging.SWAP_ENTRY / "old.txt").write_text("old copy")
        return trash

    def no_reads(self):
        """Every way Python could read the record's bytes is recorded in `self.reads` and
        refused. Recorded, not only raised: recover_swaps() logs and swallows any error."""
        self.reads = []

        def refuse(path, *_a, **_k):
            self.reads.append(("read", str(path)))
            raise AssertionError("the swap record was read")

        real_open = builtins.open

        def guarded_open(file, *args, **kwargs):
            if str(file).endswith(staging.SWAP_RECORD):
                self.reads.append(("open", str(file)))
                raise AssertionError("the swap record was opened")
            return real_open(file, *args, **kwargs)

        real_os_open = os.open

        def guarded_os_open(path, *args, **kwargs):
            if str(path).endswith(staging.SWAP_RECORD):
                self.reads.append(("os.open", str(path)))
                raise AssertionError("the swap record was opened")
            return real_os_open(path, *args, **kwargs)

        return [
            mock.patch.object(Path, "read_text", refuse),
            mock.patch.object(Path, "read_bytes", refuse),
            mock.patch.object(builtins, "open", guarded_open),
            mock.patch.object(os, "open", guarded_os_open),
        ]


class OversizedRecord(_Base):
    def test_sparse_gigabyte_record_is_removed_and_never_read(self):
        trash = self.trash_with_entry()
        rec = trash / staging.SWAP_RECORD
        rec.touch()
        os.truncate(rec, GIB)  # sparse: a gigabyte on paper, nothing on disk
        self.assertGreater(rec.stat().st_size, staging.SWAP_RECORD_MAX_BYTES)

        patches = self.no_reads()
        for p in patches:
            p.start()
        try:
            with self.assertLogs(staging.logger, level="WARNING") as logs:
                restored = staging.recover_swaps()
        finally:
            for p in reversed(patches):
                p.stop()

        self.assertEqual(self.reads, [], "the oversized record must never be read")
        self.assertEqual(restored, 0)
        self.assertFalse(trash.exists(), "the oversized record's trash must be removed")
        self.assertFalse((self.tmp / "p1" / "uploads" / "repo").exists())
        self.assertEqual(len(logs.records), 1, "one warning, not one per byte or per retry")
        self.assertNotIn(str(GIB), logs.output[0])

    def test_one_byte_over_the_bound_is_refused(self):
        trash = self.trash_with_entry()
        rec = trash / staging.SWAP_RECORD
        body = json.dumps({"target_rel": "uploads/repo"})
        rec.write_text(body + " " * (staging.SWAP_RECORD_MAX_BYTES + 1 - len(body)))
        self.assertEqual(rec.stat().st_size, staging.SWAP_RECORD_MAX_BYTES + 1)
        self.assertEqual(staging.recover_swaps(), 0)
        self.assertFalse(trash.exists())
        self.assertFalse((self.tmp / "p1" / "uploads" / "repo").exists())

    def test_a_record_at_the_bound_is_still_read(self):
        trash = self.trash_with_entry()
        rec = trash / staging.SWAP_RECORD
        body = json.dumps({"target_rel": "uploads/repo"})
        rec.write_text(body + " " * (staging.SWAP_RECORD_MAX_BYTES - len(body)))
        self.assertEqual(rec.stat().st_size, staging.SWAP_RECORD_MAX_BYTES)
        self.assertEqual(staging.recover_swaps(), 1)
        self.assertEqual((self.tmp / "p1" / "uploads" / "repo" / "old.txt").read_text(), "old copy")


class NotARegularFile(_Base):
    def test_symlinked_record_is_skipped_never_followed(self):
        """A link to a huge file (here: to a sparse gigabyte outside the trash) is not read."""
        target = self.tmp / "elsewhere.json"
        target.touch()
        os.truncate(target, GIB)
        trash = self.trash_with_entry()
        (trash / staging.SWAP_RECORD).symlink_to(target)

        patches = self.no_reads()
        for p in patches:
            p.start()
        try:
            restored = staging.recover_swaps()
        finally:
            for p in reversed(patches):
                p.stop()

        self.assertEqual(self.reads, [], "a symlinked record must never be followed or read")
        self.assertEqual(restored, 0)
        self.assertFalse((self.tmp / "p1" / "uploads" / "repo").exists())
        self.assertTrue(target.exists(), "the link's target is never touched")

    def test_symlink_to_a_valid_record_is_not_followed_either(self):
        """Even a link to a well-formed record: only a regular file in the trash counts."""
        real = self.tmp / "real-swap.json"
        real.write_text(json.dumps({"target_rel": "uploads/repo"}))
        trash = self.trash_with_entry()
        (trash / staging.SWAP_RECORD).symlink_to(real)
        self.assertEqual(staging.recover_swaps(), 0)
        self.assertFalse((self.tmp / "p1" / "uploads" / "repo").exists())

    def test_directory_named_like_the_record_is_skipped(self):
        trash = self.trash_with_entry()
        (trash / staging.SWAP_RECORD).mkdir()
        (trash / staging.SWAP_RECORD / "big").write_bytes(b"x" * 1024)
        self.assertEqual(staging.recover_swaps(), 0)
        self.assertFalse((self.tmp / "p1" / "uploads" / "repo").exists())

    def test_fifo_record_is_skipped_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs on this platform")
        trash = self.trash_with_entry()
        os.mkfifo(trash / staging.SWAP_RECORD)
        # Opening a FIFO for reading blocks until a writer comes: the skip must come first.
        self.assertEqual(staging.recover_swaps(), 0)


class LegitimateRecord(_Base):
    def test_a_normal_record_still_restores_the_folder(self):
        trash = self.trash_with_entry()
        staging.write_swap_record(trash, "uploads/repo")
        self.assertLess((trash / staging.SWAP_RECORD).stat().st_size, 200)
        self.assertEqual(staging.recover_swaps(), 1)
        self.assertEqual((self.tmp / "p1" / "uploads" / "repo" / "old.txt").read_text(), "old copy")
        self.assertFalse(trash.exists())


if __name__ == "__main__":
    unittest.main()

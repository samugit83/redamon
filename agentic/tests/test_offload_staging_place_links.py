"""Three more writers into a project folder a sandbox writes (FU rev 3).

- output_offload writes tool output to tool-outputs/ under a name anyone can
  predict (the job id, or the second it ran): a link planted there made root
  write the output anywhere in the agent (STRIDE T4, no race needed).
- staging.recover_swaps puts an interrupted Replace back by a path checked only
  as text: a link above the target carried the old copy into another project.
- place() moves an upload or import in by path after resolve_for_project
  checked the folder, then chmods the new name by path: a folder swapped for a
  link in between moved it into another project, and a name swapped for a link
  after the move had its target's mode loosened.

`outside/` stands in for the agent's own files; `p2` for another tenant.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import output_offload
import workspace_fs
from workspace_import import executor, place, staging
from workspace_import.errors import ImportFailure

JOB = "a" * 32
OUTPUT = "scan line\n" * 3000  # over the offload threshold


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-rev3-"))
        self.ws = self.tmp / "workspace"
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.victim = self.outside / "agent_module.py"
        self.victim.write_text("original\n")
        os.chmod(self.victim, 0o600)
        self._patches = [mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.ws),
                         mock.patch.object(output_offload, "WORKSPACE_ROOT", self.ws)]
        for p in self._patches:
            p.start()
        self._pool = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2)
        place._locks.clear()
        self.root = workspace_fs.resolve_for_project("p1", ".")
        self.other = workspace_fs.resolve_for_project("p2", ".")

    def tearDown(self):
        executor.IMPORT_EXECUTOR.shutdown(wait=True)
        executor.IMPORT_EXECUTOR = self._pool
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assert_victim_untouched(self):
        self.assertEqual(self.victim.read_text(), "original\n")
        self.assertEqual(stat.S_IMODE(self.victim.stat().st_mode), 0o600)

    def staged_dir(self):
        out = staging.new_op_dir("p1", "test") / "out"
        out.mkdir()
        (out / "README").write_text("new")
        return out

    def staged_file(self):
        f = staging.new_op_dir("p1", "test") / "data.part"
        f.write_text("uploaded")
        return f


class OffloadNeverWritesThroughALink(_Base):
    async def test_a_link_at_the_predictable_name_is_not_written_through(self):
        (self.root / "tool-outputs" / f"{JOB}-execute_nmap.log").symlink_to(self.victim)
        stub = output_offload.maybe_offload("p1", "execute_nmap", OUTPUT, override="file", job_id=JOB)
        self.assert_victim_untouched()
        written = stub.split("tool-outputs/", 1)[1].split("]", 1)[0]
        self.assertNotEqual(written, f"{JOB}-execute_nmap.log")
        self.assertEqual((self.root / "tool-outputs" / written).read_text(), OUTPUT)

    async def test_a_tool_outputs_folder_that_is_a_link_is_refused(self):
        shutil.rmtree(self.root / "tool-outputs")
        (self.root / "tool-outputs").symlink_to(self.outside)
        out = output_offload.maybe_offload("p1", "execute_nmap", OUTPUT, override="file", job_id=JOB)
        self.assertEqual(out, OUTPUT, "refused: the output stays inline")
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["agent_module.py"])

    async def test_a_traversing_project_id_writes_nothing_outside(self):
        out = output_offload.maybe_offload("../outside", "execute_nmap", OUTPUT, override="file", job_id=JOB)
        self.assertEqual(out, OUTPUT)
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["agent_module.py"])

    async def test_an_output_with_a_lone_surrogate_stays_inline(self):
        # json.loads lets "\ud800" through; the encode fails, and the output must
        # fall back inline as it did at 40c11197, not be lost.
        text = "\udcff" + "x" * 30000
        self.assertEqual(output_offload.maybe_offload("p1", "execute_nmap", text, override="file"), text)

    async def test_legitimate_offload_still_writes_its_file(self):
        stub = output_offload.maybe_offload("p1", "execute_nmap", OUTPUT, override="file", job_id=JOB)
        self.assertIn(f"tool-outputs/{JOB}-execute_nmap.log", stub)
        self.assertEqual((self.root / "tool-outputs" / f"{JOB}-execute_nmap.log").read_text(), OUTPUT)


class RecoveryNeverRestoresIntoAnotherProject(_Base):
    def interrupted_swap(self):
        trash = staging.new_op_dir("p1", "trash")
        staging.write_swap_record(trash, "uploads/repo")
        (trash / staging.SWAP_ENTRY).mkdir()
        (trash / staging.SWAP_ENTRY / "old.txt").write_text("old copy")
        return trash

    async def test_a_link_above_the_target_is_not_followed(self):
        self.interrupted_swap()
        shutil.rmtree(self.root / "uploads")
        (self.root / "uploads").symlink_to(self.other / "uploads")
        self.assertEqual(staging.recover_swaps(), 0)
        self.assertEqual(list((self.other / "uploads").iterdir()), [], "planted in another project")

    async def test_a_legitimate_interrupted_replace_is_still_restored(self):
        self.interrupted_swap()
        self.assertEqual(staging.recover_swaps(), 1)
        self.assertEqual((self.root / "uploads/repo/old.txt").read_text(), "old copy")


class PlaceNeverLeavesTheProject(_Base):
    def swap_after_check(self, folder: Path, to: Path):
        """resolve_for_project approves `folder`, then a sandbox swaps it for a link."""
        real = workspace_fs.resolve_for_project

        def resolve_then_swap(project_id, user_path, follow_symlinks=True):
            checked = real(project_id, user_path, follow_symlinks)
            if project_id == "p1" and user_path == "uploads":
                folder.rename(folder.with_name(folder.name + ".real"))
                folder.symlink_to(to)
            return checked

        return mock.patch.object(workspace_fs, "resolve_for_project", resolve_then_swap)

    async def test_a_folder_swapped_for_a_link_receives_nothing(self):
        for staged in (self.staged_file(), self.staged_dir()):
            with self.subTest(kind="file" if staged.is_file() else "dir"):
                if (self.root / "uploads").is_symlink():
                    (self.root / "uploads").unlink()
                    (self.root / "uploads.real").rename(self.root / "uploads")
                with self.swap_after_check(self.root / "uploads", self.other / "uploads"):
                    with self.assertRaises(ImportFailure) as ctx:
                        await place.place("p1", staged, "uploads", "drop", "keep_both")
                self.assertEqual(ctx.exception.code, "destination_missing")
                self.assertEqual(list((self.other / "uploads").iterdir()), [])

    async def test_a_name_swapped_for_a_link_after_the_move_keeps_its_target_mode(self):
        staged = self.staged_file()
        target = self.root / "uploads" / "f.bin"
        real_unlink = os.unlink

        def unlink_then_swap(path, *a, **kw):
            real_unlink(path, *a, **kw)
            if Path(path) == staged:
                # Right after the move: the sandbox replaces the new name.
                real_unlink(target)
                target.symlink_to(self.victim)

        with mock.patch("workspace_import.place.os.unlink", unlink_then_swap):
            await place.place("p1", staged, "uploads", "f.bin", "keep_both")
        self.assert_victim_untouched()

    async def test_the_name_choice_is_no_oracle_of_paths_outside(self):
        """A folder swapped right after the check: the error must not tell whether a
        name exists in the folder the link points at (here another project's)."""
        (self.other / "uploads" / "exists.bin").write_text("another tenant's file")
        codes = {}
        for name in ("exists.bin", "absent.bin"):
            if (self.root / "uploads").is_symlink():
                (self.root / "uploads").unlink()
                (self.root / "uploads.real").rename(self.root / "uploads")
            with self.swap_after_check(self.root / "uploads", self.other / "uploads"):
                with self.assertRaises(ImportFailure) as ctx:
                    await place.place("p1", self.staged_file(), "uploads", name, "fail")
            codes[name] = ctx.exception.code
        self.assertEqual(codes, {"exists.bin": "destination_missing", "absent.bin": "destination_missing"})

    async def test_the_swap_record_names_the_folder_that_was_checked(self):
        # The name is chosen in uploads/, then uploads/ is swapped for a link to
        # notes/: the move must not land in notes/, nor the record name it.
        (self.root / "notes" / "repo").mkdir()
        (self.root / "notes" / "repo" / "keep.txt").write_text("keep me")
        with self.swap_after_check(self.root / "uploads", self.root / "notes"):
            with self.assertRaises(ImportFailure):
                await place.place("p1", self.staged_dir(), "uploads", "repo", "replace")
        self.assertEqual(sorted(os.listdir(self.root / "notes" / "repo")), ["keep.txt"])

    async def test_legitimate_placements_still_work_with_their_modes(self):
        staged = self.staged_dir()
        os.chmod(staged / "README", 0o600)
        self.assertEqual(await place.place("p1", staged, "uploads", "repo", "keep_both"), "uploads/repo")
        self.assertEqual(stat.S_IMODE((self.root / "uploads/repo").stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE((self.root / "uploads/repo/README").stat().st_mode), 0o666)
        self.assertEqual(await place.place("p1", self.staged_dir(), "uploads", "repo", "replace"),
                         "uploads/repo")
        self.assertEqual((self.root / "uploads/repo/README").read_text(), "new")
        self.assertEqual(await place.place("p1", self.staged_file(), "uploads", "f.bin", "keep_both"),
                         "uploads/f.bin")
        self.assertEqual(stat.S_IMODE((self.root / "uploads/f.bin").stat().st_mode), 0o666)


if __name__ == "__main__":
    unittest.main()

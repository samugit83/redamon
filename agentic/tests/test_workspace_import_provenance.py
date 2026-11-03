"""Signed provenance: only a record this server signed, for this project, counts."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from workspace_import import provenance
from workspace_import.errors import ImportFailure

RECORD = {"source": {"url": "https://github.com/o/r", "kind": "github-repo", "host": "github.com"},
          "options": {}, "fetchedAt": "2026-11-03T10:00:00+00:00",
          "stats": {"files": 3, "bytes": 30, "skipped": 0}, "resyncable": True}


class ProvenanceBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-prov-"))
        self.env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "a-strong-test-master-key"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def folder(self, rel="uploads/r"):
        d = self.tmp / rel
        d.mkdir(parents=True, exist_ok=True)
        return d


class ReadWrite(ProvenanceBase):
    def test_round_trip(self):
        d = self.folder()
        stored = provenance.write(d, RECORD, project_id="p1")
        self.assertEqual((stored["version"], stored["projectId"]), (1, "p1"))
        self.assertRegex(stored["importId"], r"^[0-9a-f]{32}$")
        got = provenance.read(d, project_id="p1")
        self.assertEqual(got, stored)
        self.assertNotIn("sig", got)
        self.assertEqual(os.stat(d / ".import.json").st_mode & 0o777, 0o666)

    def test_signature_covers_every_field(self):
        d = self.folder()
        provenance.write(d, RECORD, project_id="p1")
        original = json.loads((d / ".import.json").read_text())
        for key in [k for k in original if k != "sig"]:
            with self.subTest(key=key):
                data = dict(original)
                data[key] = "tampered" if not isinstance(data[key], str) else data[key] + "x"
                (d / ".import.json").write_text(json.dumps(data))
                self.assertIsNone(provenance.read(d, project_id="p1"))

    def test_signature_bound_to_project(self):
        d = self.folder()
        provenance.write(d, RECORD, project_id="p1")
        self.assertIsNone(provenance.read(d, project_id="p2"))

    def test_forged_and_unsigned_files_ignored(self):
        d = self.folder()
        (d / ".import.json").write_text(json.dumps(dict(RECORD, version=1, projectId="p1")))
        self.assertIsNone(provenance.read(d, project_id="p1"))
        (d / ".import.json").write_text(json.dumps(dict(RECORD, version=1, projectId="p1", sig="0" * 64)))
        self.assertIsNone(provenance.read(d, project_id="p1"))

    def test_unknown_version_and_keys(self):
        d = self.folder()
        provenance.write(d, dict(RECORD, futureField={"x": 1}), project_id="p1")
        got = provenance.read(d, project_id="p1")
        self.assertNotIn("futureField", got)  # kept in the signed bytes, dropped from the answer
        data = json.loads((d / ".import.json").read_text())
        data["version"] = 2
        (d / ".import.json").write_text(json.dumps(data))
        self.assertIsNone(provenance.read(d, project_id="p1"))

    def test_oversized_or_invalid_ignored(self):
        d = self.folder()
        (d / ".import.json").write_text("{" + " " * (70 * 1024) + "}")
        self.assertIsNone(provenance.read(d, project_id="p1"))
        (d / ".import.json").write_text("not json")
        self.assertIsNone(provenance.read(d, project_id="p1"))
        (d / ".import.json").unlink()
        os.symlink("/etc/hostname", d / ".import.json")
        self.assertIsNone(provenance.read(d, project_id="p1"))

    def test_weak_master_key_reads_nothing(self):
        d = self.folder()
        provenance.write(d, RECORD, project_id="p1")
        for weak in ("", "changeme"):
            with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": weak}):
                self.assertIsNone(provenance.read(d, project_id="p1"))
                with self.assertRaises(ImportFailure):
                    provenance.write(self.folder("uploads/other"), RECORD, project_id="p1")

    def test_rotated_key_turns_imports_into_plain_folders(self):
        d = self.folder()
        provenance.write(d, RECORD, project_id="p1")
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "a-new-master-key"}):
            self.assertIsNone(provenance.read(d, project_id="p1"))

    def test_renamed_folder_keeps_provenance(self):
        d = self.folder()
        provenance.write(d, RECORD, project_id="p1")
        moved = self.tmp / "notes" / "renamed"
        moved.parent.mkdir()
        d.rename(moved)
        self.assertIsNotNone(provenance.read(moved, project_id="p1"))


class FindImports(ProvenanceBase):
    def test_find_imports_bounded_depth_and_dirs(self):
        provenance.write(self.folder("uploads/a"), RECORD, project_id="p1")
        provenance.write(self.folder("notes/x/y/z/deep"), RECORD, project_id="p1")  # depth 5
        found = provenance.find_imports(self.tmp, project_id="p1")
        self.assertEqual([rel for rel, _ in found], ["uploads/a"])
        for i in range(400):
            (self.tmp / "bulk" / f"d{i:03d}").mkdir(parents=True)
        with mock.patch.object(provenance, "read", wraps=provenance.read) as spy:
            provenance.find_imports(self.tmp, project_id="p1", max_dirs=50)
        self.assertLessEqual(spy.call_count, 50)

    def test_nested_import_json_not_listed(self):
        top = self.folder("uploads/outer")
        provenance.write(top, RECORD, project_id="p1")
        provenance.write(self.folder("uploads/outer/inner"), RECORD, project_id="p1")
        self.assertEqual([rel for rel, _ in provenance.find_imports(self.tmp, project_id="p1")], ["uploads/outer"])

    def test_skips_jobs_and_tool_outputs(self):
        provenance.write(self.folder("jobs/fake"), RECORD, project_id="p1")
        provenance.write(self.folder("tool-outputs/fake"), RECORD, project_id="p1")
        self.assertEqual(provenance.find_imports(self.tmp, project_id="p1"), [])

    def test_symlinked_folder_not_followed(self):
        real = self.folder("elsewhere/r")
        provenance.write(real, RECORD, project_id="p1")
        os.symlink(self.tmp / "elsewhere", self.folder("uploads") / "link")
        rels = [rel for rel, _ in provenance.find_imports(self.tmp, project_id="p1", skip=("elsewhere",))]
        self.assertEqual(rels, [])


if __name__ == "__main__":
    unittest.main()

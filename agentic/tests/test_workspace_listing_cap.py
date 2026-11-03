"""list_dir_page: capped, dirs first, and only the page is stat'ed."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import workspace_fs


class ListingCap(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-list-"))
        self._root = mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp)
        self._root.start()
        self.root = workspace_fs.resolve_for_project("p1", ".")
        self.big = self.root / "uploads" / "big"
        self.big.mkdir()
        for i in range(30):
            (self.big / f"f{i:02d}.txt").write_text("x" * i)
        for name in ("Zdir", "adir"):
            (self.big / name).mkdir()

    def tearDown(self):
        self._root.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_limit_total_truncated(self):
        rows, total = workspace_fs.list_dir_page("p1", "uploads/big", 10)
        self.assertEqual(total, 32)
        self.assertEqual(len(rows), 10)
        rows, total = workspace_fs.list_dir_page("p1", "uploads/big", 1000)
        self.assertEqual((len(rows), total), (32, 32))

    def test_dirs_first_order_kept(self):
        rows, _ = workspace_fs.list_dir_page("p1", "uploads/big", 5)
        self.assertEqual([r["name"] for r in rows], ["adir", "Zdir", "f00.txt", "f01.txt", "f02.txt"])
        self.assertEqual(rows[0]["path"], "uploads/big/adir")
        self.assertTrue(rows[0]["isDir"])
        # Same rows as the uncapped helper the rest of the code still uses, plus
        # the page's `imported` flag.
        self.assertEqual([{k: v for k, v in r.items() if k != "imported"} for r in rows],
                         workspace_fs.list_dir_for_project("p1", "uploads/big")[:5])
        self.assertEqual({r["imported"] for r in rows}, {False})

    def test_only_the_page_is_statted(self):
        real_stat = os.stat
        statted = []

        def counting(path, *a, **kw):
            # Direct children only: each listed folder is also probed for its
            # .import.json, which is a stat one level down.
            if os.path.dirname(str(path)) == str(self.big):
                statted.append(os.path.basename(str(path)))
            return real_stat(path, *a, **kw)

        with mock.patch("workspace_fs.os.stat", counting):
            workspace_fs.list_dir_page("p1", "uploads/big", 4)
        self.assertEqual(sorted(statted), sorted(["adir", "Zdir", "f00.txt", "f01.txt"]))

    def test_not_a_directory_and_escape_refused(self):
        with self.assertRaises(ValueError):
            workspace_fs.list_dir_page("p1", "uploads/big/f01.txt", 10)
        with self.assertRaises(ValueError):
            workspace_fs.list_dir_page("p1", "../..", 10)


if __name__ == "__main__":
    unittest.main()

"""safe_extract: formats, path safety, skips, caps and cancellation.

Every archive is built inside the test with tarfile / zipfile / gzip.
"""
from __future__ import annotations

import ast
import gzip
import io
import os
import shutil
import stat
import tarfile
import tempfile
import threading
import unittest
import unittest.mock
import zipfile
from pathlib import Path

from workspace_import import errors
from workspace_import.errors import ImportFailure
from workspace_import.extract import detect_archive_format, safe_extract, single_top_dir

BIG = 1 << 30


def _tar(path, entries, mode="w"):
    """entries: list of (name, bytes | None for dir | ('sym', target) | ('lnk', target) | 'fifo' | 'chr')."""
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as tf:
        for name, data in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime = 1_700_000_000
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif isinstance(data, tuple):
                ti.type = tarfile.SYMTYPE if data[0] == "sym" else tarfile.LNKTYPE
                ti.linkname = data[1]
                tf.addfile(ti)
            elif data == "fifo":
                ti.type = tarfile.FIFOTYPE
                tf.addfile(ti)
            elif data == "chr":
                ti.type = tarfile.CHRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return path


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries:
            if isinstance(data, zipfile.ZipInfo):
                zf.writestr(data, b"/etc/passwd")
            elif data is None:
                zf.writestr(name.rstrip("/") + "/", b"")
            else:
                zf.writestr(name, data)
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-extract-"))
        self.dest = self.tmp / "out"
        self.dest.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def extract(self, archive, **kw):
        kw.setdefault("max_bytes", BIG)
        kw.setdefault("max_entries", 50_000)
        return safe_extract(archive, self.dest, **kw)

    def assertCode(self, code, fn, *a, **kw):
        with self.assertRaises(ImportFailure) as ctx:
            fn(*a, **kw)
        self.assertEqual(ctx.exception.code, code)

    def tree(self):
        return sorted(str(p.relative_to(self.dest)) for p in self.dest.rglob("*"))


class Formats(Base):
    ENTRIES = [("top/", None), ("top/a.txt", b"alpha"), ("top/sub/b.bin", b"\x00" * 3000)]

    def _check(self, report):
        self.assertEqual(self.tree(), ["top", "top/a.txt", "top/sub", "top/sub/b.bin"])
        self.assertEqual((self.dest / "top/a.txt").read_bytes(), b"alpha")
        self.assertEqual(report.files, 2)
        self.assertEqual(report.bytes, 3005)
        self.assertEqual(stat.S_IMODE((self.dest / "top/a.txt").stat().st_mode), 0o666)
        self.assertEqual(stat.S_IMODE((self.dest / "top/sub").stat().st_mode), 0o777)
        self.assertEqual(report.top_level, ["top"])

    def test_tar(self):
        self._check(self.extract(_tar(self.tmp / "a.tar", self.ENTRIES)))

    def test_tar_gz(self):
        self._check(self.extract(_tar(self.tmp / "a.tgz", self.ENTRIES, "w:gz")))

    def test_tar_bz2(self):
        self._check(self.extract(_tar(self.tmp / "a.tbz2", self.ENTRIES, "w:bz2")))

    def test_tar_xz(self):
        self._check(self.extract(_tar(self.tmp / "a.txz", self.ENTRIES, "w:xz")))

    def test_zip(self):
        self._check(self.extract(_zip(self.tmp / "a.zip", self.ENTRIES)))

    def test_single_gz_becomes_one_file(self):
        p = self.tmp / "notes.txt.gz"
        p.write_bytes(gzip.compress(b"plain text, not a tar"))
        self.assertEqual(detect_archive_format(p), "gz")
        report = self.extract(p)
        self.assertEqual(self.tree(), ["notes.txt"])
        self.assertEqual((self.dest / "notes.txt").read_bytes(), b"plain text, not a tar")
        self.assertEqual(report.files, 1)

    def test_single_gz_takes_the_callers_name(self):
        p = self.tmp / "data.part"
        p.write_bytes(gzip.compress(b"x"))
        self.extract(p, single_name="report.txt")
        self.assertEqual(self.tree(), ["report.txt"])

    def test_mtime_kept(self):
        self.extract(_tar(self.tmp / "a.tar", self.ENTRIES))
        self.assertEqual(int((self.dest / "top/a.txt").stat().st_mtime), 1_700_000_000)

    def test_format_is_detected_by_content_not_name(self):
        p = _zip(self.tmp / "x.tar.gz", [("a.txt", b"a")])
        self.assertEqual(detect_archive_format(p), "zip")
        self.extract(p)
        self.assertEqual(self.tree(), ["a.txt"])

    def test_unknown_bytes_are_unsupported(self):
        p = self.tmp / "x.zip"
        p.write_bytes(b"this is not an archive at all" * 40)
        self.assertIsNone(detect_archive_format(p))
        self.assertCode("unsupported_archive", self.extract, p)

    def test_truncated_archive_is_corrupt(self):
        full = _tar(self.tmp / "a.tgz", [("a.bin", os.urandom(200_000))], "w:gz").read_bytes()
        cut = self.tmp / "cut.tgz"
        cut.write_bytes(full[: len(full) // 2])
        self.assertCode("corrupt_archive", self.extract, cut)

    def test_dest_must_be_empty(self):
        (self.dest / "x").write_text("x")
        with self.assertRaises(ValueError):
            self.extract(_tar(self.tmp / "a.tar", self.ENTRIES))


class PathSafety(Base):
    def test_traversal_names_abort(self):
        for name in ("../e", "/abs", "a/../../b", "..\\e", "C:/win"):
            with self.subTest(name=name):
                shutil.rmtree(self.dest)
                self.dest.mkdir()
                p = _tar(self.tmp / "t.tar", [("inside.txt", b"i"), (name, b"evil")])
                self.assertCode("unsafe_path", self.extract, p)
                self.assertFalse((self.tmp / "e").exists())
                self.assertFalse(Path("/abs").exists())
                self.assertFalse((self.tmp / "b").exists())

    def test_nul_in_name_aborts(self):
        from workspace_import.extract import _normalize
        self.assertCode("unsafe_path", _normalize, "a/\x00b")

    def test_zip_traversal_aborts(self):
        p = _zip(self.tmp / "t.zip", [("../evil.txt", b"x")])
        self.assertCode("unsafe_path", self.extract, p)
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_links_devices_fifos_are_skipped_and_reported(self):
        p = _tar(self.tmp / "t.tar", [
            ("ok.txt", b"ok"), ("s", ("sym", "/etc/passwd")), ("h", ("lnk", "ok.txt")),
            ("f", "fifo"), ("c", "chr"),
        ])
        report = self.extract(p)
        self.assertEqual(self.tree(), ["ok.txt"])
        self.assertEqual(sorted(report.skipped), [
            ("c", "special_file"), ("f", "special_file"), ("h", "link"), ("s", "link"),
        ])

    def test_symlink_then_file_through_it_stays_inside(self):
        p = _tar(self.tmp / "t.tar", [("l", ("sym", "/tmp")), ("l/x", b"inside")])
        self.extract(p)
        self.assertEqual(self.tree(), ["l", "l/x"])
        self.assertTrue((self.dest / "l").is_dir())
        self.assertFalse((self.dest / "l").is_symlink())
        self.assertFalse(Path("/tmp/x").exists() and Path("/tmp/x").read_bytes() == b"inside")

    def test_planted_symlink_component_is_not_followed(self):
        # kali-sandbox can write into staging: swap a folder the extractor already
        # created for a symlink between two entries, and the next write must not
        # follow it.
        outside = self.tmp / "outside"
        outside.mkdir()
        p = _tar(self.tmp / "t.tar", [("d/a", b"a"), ("d/b", b"b")])

        def plant(files, _nbytes):
            if files == 1 and not (self.dest / "d").is_symlink():
                shutil.rmtree(self.dest / "d")
                os.symlink(outside, self.dest / "d")

        clock = iter(range(10_000))
        with self.assertRaises(OSError):
            self.extract(p, progress=plant, now=lambda: next(clock))
        self.assertEqual(list(outside.iterdir()), [])

    def test_zip_unix_symlink_entry_is_skipped(self):
        zi = zipfile.ZipInfo("link")
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        p = _zip(self.tmp / "t.zip", [("ok.txt", b"ok"), ("link", zi)])
        report = self.extract(p)
        self.assertEqual(self.tree(), ["ok.txt"])
        self.assertIn(("link", "link"), report.skipped)


class Caps(Base):
    def test_real_bytes_cap_aborts_mid_stream(self):
        p = _tar(self.tmp / "t.tar", [("big.bin", b"\x01" * (2 << 20))])
        self.assertCode("too_large", self.extract, p, max_bytes=1 << 20)

    def test_lying_declared_size_still_capped_on_real_bytes(self):
        p = _zip(self.tmp / "t.zip", [("big.bin", b"\x01" * (2 << 20))])
        from workspace_import import extract as ex
        orig = ex._Budget.declare
        with unittest.mock.patch.object(ex._Budget, "declare", lambda self, size: orig(self, 0)):
            self.assertCode("too_large", self.extract, p, max_bytes=1 << 20)

    def test_declared_sizes_pre_checked(self):
        p = _zip(self.tmp / "t.zip", [("a.bin", b"\x01" * 600_000), ("b.bin", b"\x01" * 600_000)])
        self.assertCode("too_large", self.extract, p, max_bytes=1_000_000)
        # b.bin was refused on its declared size, before any of it was written
        self.assertFalse((self.dest / "b.bin").exists())

    def test_entry_cap(self):
        p = _tar(self.tmp / "t.tar", [(f"f{i}", b"x") for i in range(11)])
        self.assertCode("too_many_entries", self.extract, p, max_entries=10)

    def test_depth_cap(self):
        deep = "/".join(["d"] * 65) + "/f"
        p = _tar(self.tmp / "t.tar", [(deep, b"x")])
        self.assertCode("too_deep", self.extract, p)

    def test_name_length_cap(self):
        p = _tar(self.tmp / "t.tar", [("n" * 256, b"x")])
        self.assertCode("name_too_long", self.extract, p)
        shutil.rmtree(self.dest)
        self.dest.mkdir()
        long_path = "/".join(["s" * 200] * 21)
        p2 = _tar(self.tmp / "t2.tar", [(long_path, b"x")])
        self.assertCode("name_too_long", self.extract, p2)


class Skips(Base):
    def test_duplicate_is_skipped(self):
        p = _tar(self.tmp / "t.tar", [("a.txt", b"first"), ("a.txt", b"second")])
        report = self.extract(p)
        self.assertEqual((self.dest / "a.txt").read_bytes(), b"first")
        self.assertIn(("a.txt", "duplicate"), report.skipped)

    def test_file_dir_conflict_aborts(self):
        p = _tar(self.tmp / "t.tar", [("a", b"file"), ("a/b", b"under")])
        self.assertCode("conflicting_entries", self.extract, p)
        shutil.rmtree(self.dest)
        self.dest.mkdir()
        p2 = _tar(self.tmp / "t2.tar", [("a/", None), ("a", b"file")])
        self.assertCode("conflicting_entries", self.extract, p2)

    def test_macos_metadata_skipped(self):
        p = _zip(self.tmp / "t.zip", [("__MACOSX/._a", b"m"), ("top/.DS_Store", b"m"), ("top/a", b"a")])
        report = self.extract(p)
        self.assertEqual(self.tree(), ["top", "top/a"])
        self.assertEqual(report.skipped_count, 2)

    def test_archive_import_json_is_dropped(self):
        p = _tar(self.tmp / "t.tar", [
            ("r/.import.json", b'{"version":1}'), ("r/x/_manifest.jsonl", b"{}"),
            ("r/.import.json/inner", b"x"), ("r/keep.txt", b"k"),
        ])
        report = self.extract(p)
        self.assertEqual(self.tree(), ["r", "r/keep.txt"])
        reasons = {name: reason for name, reason in report.skipped}
        self.assertEqual(reasons["r/.import.json"], "reserved_name")
        self.assertEqual(reasons["r/x/_manifest.jsonl"], "reserved_name")
        self.assertEqual(reasons["r/.import.json/inner"], "reserved_name")

    def test_encrypted_zip_entry_skipped(self):
        p = _zip(self.tmp / "t.zip", [("a.txt", b"a"), ("secret.txt", b"s")])
        raw = bytearray(p.read_bytes())
        # Set the encryption bit (general purpose flag bit 0) on secret.txt's
        # local header and central directory record.
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            start = 0
            while True:
                i = raw.find(sig, start)
                if i < 0:
                    break
                name_off = i + (30 if sig == b"PK\x03\x04" else 46)
                flag_off = i + (6 if sig == b"PK\x03\x04" else 8)
                if raw[name_off:name_off + 10] == b"secret.txt":
                    raw[flag_off] |= 0x1
                start = i + 4
        p.write_bytes(bytes(raw))
        report = self.extract(p)
        self.assertEqual(self.tree(), ["a.txt"])
        self.assertIn(("secret.txt", "encrypted"), report.skipped)

    def test_skipped_list_capped_at_200(self):
        p = _tar(self.tmp / "t.tar", [("ok", b"o")] + [(f"l{i}", ("sym", "x")) for i in range(250)])
        report = self.extract(p)
        self.assertEqual(len(report.skipped), 200)
        self.assertEqual(report.skipped_count, 250)


class Behaviour(Base):
    def test_member_filter_keeps_subtree_and_strips_prefix(self):
        p = _tar(self.tmp / "t.tgz", [
            ("o-r-abc1234/", None), ("o-r-abc1234/README", b"r"),
            ("o-r-abc1234/docs/a.md", b"a"), ("o-r-abc1234/docs/sub/b.md", b"b"),
        ], "w:gz")
        prefix = "o-r-abc1234/docs/"

        def keep(name):
            return name[len(prefix):] if name.startswith(prefix) else None

        report = self.extract(p, member_filter=keep)
        self.assertEqual(self.tree(), ["a.md", "sub", "sub/b.md"])
        self.assertEqual(report.files, 2)

    def test_member_filter_result_is_validated(self):
        p = _tar(self.tmp / "t.tar", [("a", b"x")])
        self.assertCode("unsafe_path", self.extract, p, member_filter=lambda n: "../" + n)

    def test_single_top_dir(self):
        self.extract(_tar(self.tmp / "t.tar", [("only/a", b"a")]))
        self.assertEqual(single_top_dir(self.dest), self.dest / "only")
        (self.dest / "second").write_text("x")
        self.assertIsNone(single_top_dir(self.dest))

    def test_cancel_event_stops(self):
        p = _tar(self.tmp / "t.tar", [("a", b"a"), ("b", b"b")])
        ev = threading.Event()
        ev.set()
        self.assertCode("cancelled", self.extract, p, cancel_event=ev)

    def test_cancel_between_chunks(self):
        p = _tar(self.tmp / "t.tar", [("big", b"\x02" * (3 << 20))])
        ev = threading.Event()
        calls = []

        def progress(files, nbytes):
            calls.append(nbytes)
            if nbytes:
                ev.set()

        self.assertCode("cancelled", self.extract, p, cancel_event=ev, progress=progress,
                        now=iter(range(0, 10_000)).__next__)

    def test_progress_throttled(self):
        p = _tar(self.tmp / "t.tar", [(f"f{i}", b"x") for i in range(20)])
        calls = []
        clock = iter([0.0] * 1000)
        self.extract(p, progress=lambda f, b: calls.append(f), now=lambda: next(clock))
        # the first chunk ticks, nothing more until 250 ms pass, then the forced final call
        self.assertEqual(calls, [0, 20])

    def test_empty_archive(self):
        p = _tar(self.tmp / "t.tar", [])
        self.assertCode("empty_archive", self.extract, p)
        p2 = _tar(self.tmp / "t2.tar", [("l", ("sym", "x"))])
        self.assertCode("empty_archive", self.extract, p2)

    def test_folder_only_archive_is_kept(self):
        report = self.extract(_tar(self.tmp / "t.tar", [("a/", None), ("a/b/", None)]))
        self.assertEqual(self.tree(), ["a", "a/b"])
        self.assertEqual(report.dirs, 2)

    def test_long_unicode_pax_names(self):
        name = "dossier/" + "é" * 120 + ".txt"
        self.extract(_tar(self.tmp / "t.tar", [(name, b"u")]))
        self.assertEqual((self.dest / name).read_bytes(), b"u")


class Catalogue(unittest.TestCase):
    def test_every_raised_code_is_in_catalogue(self):
        pkg = Path(errors.__file__).parent
        raised = set()
        for py in pkg.glob("*.py"):
            for node in ast.walk(ast.parse(py.read_text())):
                if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ImportFailure"
                        and node.args and isinstance(node.args[0], ast.Constant)):
                    raised.add(node.args[0].value)
        self.assertTrue(raised)
        self.assertEqual(raised - set(errors.CODES), set())

    def test_unknown_code_is_refused(self):
        with self.assertRaises(ValueError):
            ImportFailure("no_such_code")

    def test_error_body_is_the_fixed_sentence(self):
        body = errors.error_body("unsafe_path")
        self.assertEqual(body["code"], "unsafe_path")
        self.assertEqual(body["error"], errors.CODES["unsafe_path"][1])


if __name__ == "__main__":
    unittest.main()


class ExtractedBytesHook(Base):
    def test_on_bytes_sees_the_running_total_before_each_write(self):
        archive = self.tmp / "a.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\0" * (3 * 1024 * 1024))
        seen = []
        report = self.extract(archive, on_bytes=seen.append)
        self.assertEqual(seen, sorted(seen))
        self.assertEqual(seen[-1], report.bytes)
        self.assertGreater(len(seen), 1)

    def test_on_bytes_refusal_stops_the_extraction(self):
        archive = self.tmp / "a.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\0" * (8 * 1024 * 1024))

        def refuse(total):
            if total > 1024 * 1024:
                raise ImportFailure("insufficient_storage")
        self.assertCode("insufficient_storage", self.extract, archive, on_bytes=refuse)
        written = sum(p.stat().st_size for p in self.dest.rglob("*") if p.is_file())
        self.assertLessEqual(written, 2 * 1024 * 1024)

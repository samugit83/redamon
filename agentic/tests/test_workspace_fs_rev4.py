"""FU-29 rev 4: the workspace tools that handed a checked path to a library that
reopens it by path (round 2 of rev 2's review).

Built on the reviewer's repros (FU/rvP5 test_rvp5_repros*.py), real races
included: a separate process (the sandbox) swaps entries with
renameat2(RENAME_EXCHANGE) or plants a link the moment a file appears. Sizes and
tries are trimmed for the unit gate. `outside/` stands in for the agent's own
files and its canary for a secret; nothing real is read.
"""
from __future__ import annotations

import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_context  # noqa: E402
import workspace_fs  # noqa: E402

PID = "proj-rv4"
CANARY = "INTERNAL_API_KEY=planted-canary-0451"
AGENTIC = str(Path(__file__).resolve().parent.parent)

SWAPPER = r'''
import ctypes, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
dur = float(sys.argv[1]); ready = sys.argv[2]
pairs = [tuple(p.encode() for p in a.split("|")) for a in sys.argv[3:]]
open(ready, "w").close()
end = time.time() + dur
while time.time() < end:
    for a, b in pairs:
        libc.renameat2(-100, a, -100, b, 2)
'''

PLANTER = r'''
import os, sys, time
watch, link, target = sys.argv[1:4]
end = time.time() + 60
while not os.path.exists(watch):
    if time.time() > end:
        sys.exit(2)
os.symlink(target, link)
'''


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-rev4-"))
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
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.kill()
            p.wait()
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        agent_context.current_project_id.set("")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def swapper(self, pairs, dur=30.0):
        ready = self.tmp / "swapper.ready"
        p = subprocess.Popen([sys.executable, "-I", "-c", SWAPPER, str(dur), str(ready),
                              *[f"{a}|{b}" for a, b in pairs]])
        self.procs.append(p)
        while not ready.exists():
            time.sleep(0.01)

    def planter(self, watch, link, target):
        self.procs.append(subprocess.Popen([sys.executable, "-I", "-c", PLANTER,
                                            str(watch), str(link), str(target)]))
        time.sleep(0.3)

    def swap_after_resolve(self, folder: Path, to: Path, only=None):
        """_resolve_safe approves a path, then the sandbox swaps `folder` for a link."""
        real = workspace_fs._resolve_safe

        def resolve_then_swap(user_path, follow_symlinks=True):
            checked = real(user_path, follow_symlinks)
            if (only is None or user_path == only) and not folder.is_symlink():
                folder.rename(folder.with_name(folder.name + ".real"))
                folder.symlink_to(to)
            return checked

        return mock.patch.object(workspace_fs, "_resolve_safe", resolve_then_swap)


# 1. ----------------------------------------------------------------- archives
class ArchivesNeverReadThroughASwappedEntry(_Base):
    def plant(self, size=None):
        dl = self.root / "dl"
        dl.mkdir()
        decoy = b"d" * (size if size is not None else 5)
        pairs = []
        for i in range(64):
            f, g = dl / f"f{i:03d}", dl / f"g{i:03d}"
            f.write_bytes(decoy)
            g.symlink_to(self.secret)
            pairs.append((f, g))
        self.swapper(pairs)
        return dl

    def leaks(self, blob, fmt):
        bio = io.BytesIO(blob)
        if fmt == "zip":
            with zipfile.ZipFile(bio) as zf:
                return sum(b"planted-canary" in zf.read(n) for n in zf.namelist())
        with tarfile.open(fileobj=bio, mode="r:gz") as tf:
            return sum(m.isfile() and b"planted-canary" in tf.extractfile(m).read() for m in tf.getmembers())

    def race(self, build, fmt, tries=20):
        for i in range(tries):
            try:
                blob = build()
            except Exception:
                continue
            if self.leaks(blob, fmt):
                return i + 1
        return None

    def test_drawer_zip_download(self):
        dl = self.plant()

        def build():
            buf = io.BytesIO()
            workspace_fs.write_dir_archive(buf, dl, "dl", "zip")
            return buf.getvalue()

        self.assertIsNone(self.race(build, "zip"), "the zip download carried an outside file")

    def test_drawer_targz_download(self):
        dl = self.plant(size=len(self.secret.read_bytes()))

        def build():
            buf = io.BytesIO()
            workspace_fs.write_dir_archive(buf, dl, "dl", "tar.gz")
            return buf.getvalue()

        self.assertIsNone(self.race(build, "tar.gz"), "the tar.gz download carried an outside file")

    def test_drawer_bulk_zip_download(self):
        dl = self.plant()

        def build():
            buf = io.BytesIO()
            workspace_fs.write_bulk_archive(buf, [dl], "zip")
            return buf.getvalue()

        self.assertIsNone(self.race(build, "zip"), "the bulk download carried an outside file")

    async def test_fs_archive_zip(self):
        self.plant()
        hit = None
        for i in range(20):
            await workspace_fs.fs_archive(["dl"], "out.zip", format="zip")
            if self.leaks((self.root / "out.zip").read_bytes(), "zip"):
                hit = i + 1
                break
        self.assertIsNone(hit, "fs_archive put an outside file's content in the project")


# 2. ----------------------------------------------------------------- extract
class ExtractNeverWritesThroughALinkPlantedDuringExtraction(_Base):
    async def test_zip_real_race(self):
        victim = self.outside / "sitecustomize.py"  # created through the link, if followed
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"\0" * (48 << 20))
            zf.writestr("evil.txt", b"import os  # attacker code, run as root at next start\n")
        (self.root / "a.zip").write_bytes(buf.getvalue())
        self.planter(self.root / "dest" / "big.bin", self.root / "dest" / "evil.txt", victim)
        await workspace_fs.fs_extract("a.zip", "dest")
        self.assertFalse(victim.exists(), "zip extraction wrote outside the project")

    async def test_tar_link_planted_after_the_checks(self):
        victim = self.outside / "agent_module.py"
        victim.write_text("original\n")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            data = b"attacker content\n"
            info = tarfile.TarInfo("evil.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        (self.root / "a.tar").write_bytes(buf.getvalue())
        planted = []

        def plant():
            if not planted:
                os.symlink(victim, self.root / "dest" / "evil.txt")
                planted.append(1)

        real_one, real_extractfile = tarfile.TarFile._extract_one, tarfile.TarFile.extractfile

        def plant_then_extract_one(tf, tarinfo, *a, **kw):  # the path extractall takes
            plant()
            return real_one(tf, tarinfo, *a, **kw)

        def plant_then_extractfile(tf, member):  # the path a per-member writer takes
            plant()
            return real_extractfile(tf, member)

        with mock.patch.object(tarfile.TarFile, "_extract_one", plant_then_extract_one), \
                mock.patch.object(tarfile.TarFile, "extractfile", plant_then_extractfile):
            await workspace_fs.fs_extract("a.tar", "dest")
        self.assertTrue(planted, "the sandbox never got its moment")
        self.assertEqual(victim.read_text(), "original\n", "tar extraction wrote through a link")

    async def test_legitimate_extract_and_archive_roundtrip(self):
        (self.root / "t").mkdir()
        (self.root / "t" / "a.txt").write_text("A\n")
        (self.root / "t" / "sub").mkdir()
        (self.root / "t" / "sub" / "b.txt").write_text("B\n")
        for fmt, name in (("tar.gz", "t.tar.gz"), ("zip", "t.zip")):
            self.assertTrue((await workspace_fs.fs_archive(["t"], name, format=fmt)).startswith("Archived"))
            self.assertTrue((await workspace_fs.fs_extract(name, f"x-{fmt}")).startswith("Extracted"))
            base = self.root / f"x-{fmt}" / "t"
            self.assertEqual((base / "a.txt").read_text(), "A\n")
            self.assertEqual((base / "sub" / "b.txt").read_text(), "B\n")
        (self.root / "one.txt.gz").write_bytes(gzip.compress(b"gz body\n"))
        await workspace_fs.fs_extract("one.txt.gz", "gzout")
        self.assertEqual((self.root / "gzout" / "one.txt").read_text(), "gz body\n")


# 3 and 6. ------------------------------------------------------------- copy
class CopyNeverLeavesTheProject(_Base):
    async def test_a_link_planted_in_dst_during_the_copy_is_not_written_through(self):
        victim = self.outside / "sitecustomize.py"
        src = self.root / "src"
        src.mkdir()
        (src / "big.bin").write_bytes(b"\1" * (24 << 20))
        # A name copied after big.bin both in scandir order (shutil.copytree) and
        # in sorted order (the descriptor walk).
        for i in range(200):
            name = f"zz-evil{i}.txt"
            (src / name).write_text("import os  # attacker code\n")
            order = [e.name for e in os.scandir(src)]
            if order.index(name) > order.index("big.bin"):
                break
            (src / name).unlink()
        self.planter(self.root / "dst" / "big.bin", self.root / "dst" / name, victim)
        await workspace_fs.fs_copy("src", "dst", recursive=True)
        self.assertFalse(victim.exists(), "the recursive copy wrote outside the project")

    async def test_a_source_swapped_after_the_check_is_not_read(self):
        (self.root / "src").mkdir()
        (self.root / "src" / "a.txt").write_text("in-project\n")
        with self.swap_after_resolve(self.root / "src", self.outside, only="src"):
            await workspace_fs.fs_copy("src", "dst", recursive=True)
        copied = self.root / "dst" / "environ"
        self.assertFalse(copied.exists() and "planted-canary" in copied.read_text())

    def test_a_planted_char_device_is_not_read(self):
        """No race: a sandbox root can `mknod c 1 5` in its own project folder."""
        src = self.root / "src"
        src.mkdir()
        os.mknod(src / "zero", 0o666 | 0o020000, os.makedev(1, 5))
        code = f'''
import asyncio, resource, signal, sys
sys.path.insert(0, {AGENTIC!r})
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
import agent_context, workspace_fs
from pathlib import Path
workspace_fs.WORKSPACE_ROOT = Path({str(self.tmp / "workspace")!r})
agent_context.current_project_id.set({PID!r})
try:
    print(asyncio.run(workspace_fs.fs_copy("src", "dst", recursive=True)))
except Exception as e:
    print("raised", type(e).__name__)
'''
        subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
        dst = self.root / "dst"
        written = max((f.lstat().st_size for f in dst.rglob("*")), default=0) if dst.exists() else 0
        self.assertLess(written, 1 << 20, f"fs_copy read {written} bytes from a device node")

    async def test_a_sparse_file_is_copied_sparse(self):
        with open(self.root / "sparse.bin", "wb") as fh:
            fh.truncate(256 << 20)
        await workspace_fs.fs_copy("sparse.bin", "copy.bin")
        st = (self.root / "copy.bin").stat()
        self.assertEqual(st.st_size, 256 << 20)
        self.assertLess(st.st_blocks * 512, 64 << 20, "the sparse file was written out dense")

    async def test_the_copy_is_bounded(self):
        (self.root / "data.bin").write_bytes(b"x" * (2 << 20))
        with mock.patch.dict(os.environ, {"FS_COPY_MAX_BYTES": str(1 << 20)}):
            out = await workspace_fs.fs_copy("data.bin", "copy.bin")
        self.assertTrue(out.startswith("Error:"), out)
        self.assertFalse((self.root / "copy.bin").exists())

    async def test_legitimate_copies_keep_links_and_modes(self):
        (self.root / "t").mkdir()
        (self.root / "t" / "a.txt").write_text("A\n")
        (self.root / "t" / "rel").symlink_to("a.txt")
        await workspace_fs.fs_copy("t", "t2", recursive=True)
        self.assertTrue((self.root / "t2" / "rel").is_symlink())
        self.assertEqual((self.root / "t2" / "rel").read_text(), "A\n")
        self.assertEqual((self.root / "t2").stat().st_mode & 0o777, 0o777)
        self.assertEqual((self.root / "t2" / "a.txt").stat().st_mode & 0o777, 0o666)
        (self.root / "into").mkdir()
        await workspace_fs.fs_copy("t/a.txt", "into")
        self.assertEqual((self.root / "into" / "a.txt").read_text(), "A\n")


# 4. -------------------------------------------------------------------- grep
class GrepNeverSearchesOutside(_Base):
    async def test_a_folder_swapped_after_the_check(self):
        (self.root / "notes").mkdir()
        with self.swap_after_resolve(self.root / "notes", self.outside):
            out = await workspace_fs.fs_grep("planted-canary", path="notes", output_mode="content")
        self.assertNotIn("planted-canary", out)

    async def test_a_real_race_on_the_folder(self):
        (self.root / "notes").mkdir()
        (self.root / "notes" / "hello.txt").write_text("hello\n")
        (self.root / "notes_x").symlink_to(self.outside)
        self.swapper([(self.root / "notes", self.root / "notes_x")])
        for _ in range(40):
            try:
                out = await workspace_fs.fs_grep("planted-canary", path="notes", output_mode="content")
            except OSError:
                continue
            self.assertNotIn("planted-canary", out)

    async def test_no_argument_becomes_an_option(self):
        marker = self.outside / "ran"
        script = self.outside / "pre.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\ncat \"$1\"\n")
        script.chmod(0o755)
        (self.root / "a.txt").write_text("needle\n")
        for kw in ({"glob": f"--pre={script}"}, {"glob": "--pre"}, {"pattern": f"--pre={script}"},
                   {"pattern": "-f/etc/passwd"}, {"glob": "-e"}):
            await workspace_fs.fs_grep(**{"pattern": "needle", **kw})
        self.assertFalse(marker.exists())

    async def test_the_search_has_a_minimal_environment(self):
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "planted-canary-env"}):
            (self.root / "probe.txt").write_text("x\n")
            calls = []
            real = workspace_fs.asyncio.create_subprocess_exec

            async def spy(*a, **kw):
                calls.append(kw.get("env"))
                return await real(*a, **kw)

            with mock.patch.object(workspace_fs.asyncio, "create_subprocess_exec", spy):
                await workspace_fs.fs_grep("x")
        self.assertTrue(calls)
        self.assertNotIn("planted-canary-env", str(calls))

    async def test_legitimate_searches(self):
        (self.root / "a.txt").write_text("one\nneedle here\nthree\n")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.py").write_text("needle = 1\n")
        (self.root / "c.txt").write_text("haystack\n")
        files = await workspace_fs.fs_grep("needle")
        self.assertEqual(sorted(files.splitlines()), ["a.txt", "sub/b.py"])
        content = await workspace_fs.fs_grep("needle", output_mode="content", type="py")
        self.assertEqual(content, "sub/b.py:1:needle = 1")
        self.assertEqual(await workspace_fs.fs_grep("needle", path="a.txt", output_mode="count"), "1")
        self.assertIn("2:needle here", await workspace_fs.fs_grep("needle", path="a.txt", output_mode="content"))
        self.assertEqual(await workspace_fs.fs_grep("NEEDLE", glob="*.txt", case_insensitive=True), "a.txt")
        self.assertEqual(await workspace_fs.fs_grep("nothing-here"), "No matches found.")


# 5 and 8. ------------------------------------------------------------- fs_read
class FsReadStreams(_Base):
    def test_peak_memory_of_a_32_mib_file(self):
        path = self.root / "lines.txt"
        n = (32 << 20) - 64
        path.write_bytes((b"ab\n" * (n // 3 + 1))[:n])
        code = f'''
import asyncio, resource, sys
sys.path.insert(0, {AGENTIC!r})
import agent_context, workspace_fs
from pathlib import Path
workspace_fs.WORKSPACE_ROOT = Path({str(self.tmp / "workspace")!r})
agent_context.current_project_id.set({PID!r})
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
asyncio.run(workspace_fs.fs_read("lines.txt", offset=1, limit=10))
print("PEAK_DELTA_MB", (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) // 1024)
'''
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300)
        delta = int(r.stdout.split("PEAK_DELTA_MB")[1].split()[0])
        self.assertLess(delta, 256, f"one fs_read of a 32 MiB file peaked +{delta} MB")

    async def test_snapshots_are_bounded(self):
        for i in range(6):
            (self.root / f"f{i}.txt").write_bytes(b"x" * (8 << 20))
            await workspace_fs.fs_read(f"f{i}.txt", limit=1)
        self.assertLess(sum(map(len, workspace_fs._last_read_contents.values())), 32 << 20)

    async def test_a_file_over_the_whole_read_cap_pages(self):
        (self.root / "big.txt").write_bytes(b"".join(b"line %d\n" % i for i in range(3_000_000)))
        self.assertGreater((self.root / "big.txt").stat().st_size, 32 << 20)
        out = await workspace_fs.fs_read("big.txt", offset=2_999_990, limit=3)
        self.assertIn("line 2999989", out)
        self.assertIn("of 3000000]", out)

    async def test_a_big_file_still_diffs_by_hash(self):
        (self.root / "big.txt").write_bytes(b"a\n" * (2 << 20))
        await workspace_fs.fs_read("big.txt", limit=1)
        self.assertEqual(await workspace_fs.fs_diff("big.txt", vs_last_read=True),
                         "(no changes since last fs_read)")
        with open(self.root / "big.txt", "ab") as fh:
            fh.write(b"b\n")
        self.assertIn("changed since the last fs_read", await workspace_fs.fs_diff("big.txt", vs_last_read=True))

    async def test_lines_match_splitlines(self):
        text = "a\r\nb\rc\nd\x0be f\n\n" + "x" * 10000 + "\nlast"
        (self.root / "mixed.txt").write_text(text, newline="")
        out = await workspace_fs.fs_read("mixed.txt")
        shown = [line.split("\t", 1)[1] for line in out.splitlines() if "\t" in line]
        expected = [ln if len(ln) <= 2000 else ln[:2000] + " [LINE TRUNCATED]" for ln in text.splitlines()]
        self.assertEqual(shown, expected)

    async def test_the_edit_stack_is_bounded(self):
        for i in range(12):
            await workspace_fs.fs_write(f"e{i}.txt", "x" * (7 << 20) + "MARK")
            self.assertIn("Replaced", await workspace_fs.fs_edit(f"e{i}.txt", "MARK", "MARX"))
        held = sum(len(s) for st in workspace_fs._edit_stack.values() for s in st)
        self.assertLessEqual(held, 64 << 20)
        self.assertIn("Reverted", await workspace_fs.fs_undo_edit("e11.txt"))


# 7. -------------------------------------------------------------------- glob
class GlobNeverWalksOutside(_Base):
    async def test_a_link_to_a_big_tree(self):
        (self.root / "esc").symlink_to("/usr")
        t = time.time()
        out = await workspace_fs.fs_glob("esc/**/*")
        self.assertLess(time.time() - t, 1.0, "fs_glob walked an outside tree")
        self.assertTrue(out.startswith("No files matching pattern"), out[:200])

    async def test_legitimate_patterns(self):
        (self.root / "a.md").write_text("x")
        (self.root / "d" / "e").mkdir(parents=True)
        (self.root / "d" / "e" / "b.md").write_text("x")
        self.assertEqual(await workspace_fs.fs_glob("*.md"), "a.md")
        self.assertEqual(sorted((await workspace_fs.fs_glob("**/*.md")).splitlines()), ["a.md", "d/e/b.md"])
        self.assertEqual(await workspace_fs.fs_glob("*.md", path="d/e"), "d/e/b.md")


# 9. ---------------------------------------------------------------- listings
class ListingsOfASwappedFolder(_Base):
    async def test_fs_list_fs_tree_fs_find_and_the_drawer(self):
        (self.outside / "OTHER-TENANT-PROJECT-ID").mkdir()
        (self.root / "notes").mkdir()
        outs = []
        for call in (lambda: workspace_fs.fs_list("notes"), lambda: workspace_fs.fs_tree("notes"),
                     lambda: workspace_fs.fs_find(path="notes")):
            with self.swap_after_resolve(self.root / "notes", self.outside):
                outs.append(await call())
            (self.root / "notes").unlink()
            (self.root / "notes.real").rename(self.root / "notes")
        real = workspace_fs.resolve_for_project

        def r2(pid, p, follow_symlinks=True):
            out = real(pid, p, follow_symlinks)
            if p == "notes" and not (self.root / "notes").is_symlink():
                (self.root / "notes").rename(self.root / "notes.real")
                (self.root / "notes").symlink_to(self.outside)
            return out

        with mock.patch.object(workspace_fs, "resolve_for_project", r2):
            try:
                outs.append(str(workspace_fs.list_dir_page(PID, "notes")))
            except ValueError as e:
                outs.append(str(e))
        for out in outs:
            self.assertNotIn("OTHER-TENANT-PROJECT-ID", out)


# 10. ------------------------------------------------------------------ mkdir
class NoFolderCreatedOrChmodedOutside(_Base):
    async def test_fs_write_parents(self):
        (self.root / "a").mkdir()
        with self.swap_after_resolve(self.root / "a", self.outside):
            await workspace_fs.fs_write("a/newdir/x.txt", "x")
        self.assertFalse((self.outside / "newdir").exists())

    async def test_fs_mkdir_fs_move_fs_copy_and_fs_archive_parents(self):
        (self.root / "a").mkdir()
        (self.root / "f.txt").write_text("x")
        for call in (lambda: workspace_fs.fs_mkdir("a/m1/m2"),
                     lambda: workspace_fs.fs_copy("f.txt", "a/c1/f.txt"),
                     lambda: workspace_fs.fs_archive(["f.txt"], "a/z1/out.zip", format="zip")):
            with self.swap_after_resolve(self.root / "a", self.outside):
                await call()
            (self.root / "a").unlink()
            (self.root / "a.real").rename(self.root / "a")
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["environ"])

    def test_mkdir_for_project_never_chmods_through_a_link(self):
        victim = self.outside / "agent_secret.key"
        victim.write_text("k")
        os.chmod(victim, 0o600)
        real_mkdir = Path.mkdir
        target = self.root / "newdir"

        def mkdir_then_swap(p, *a, **kw):
            real_mkdir(p, *a, **kw)
            if p == target:
                p.rmdir()
                p.symlink_to(victim)

        real_osmkdir = os.mkdir

        def osmkdir_then_swap(path, mode=0o777, *, dir_fd=None):
            real_osmkdir(path, mode, dir_fd=dir_fd)
            if path == "newdir" and dir_fd is not None:
                os.rmdir(path, dir_fd=dir_fd)
                os.symlink(victim, path, dir_fd=dir_fd)

        with mock.patch.object(Path, "mkdir", mkdir_then_swap), \
                mock.patch.object(workspace_fs.os, "mkdir", osmkdir_then_swap):
            try:
                workspace_fs.mkdir_for_project(PID, "newdir")
            except (OSError, ValueError):
                pass
        self.assertEqual(victim.stat().st_mode & 0o777, 0o600, "chmod 0777 followed a link outside")

    def test_mkdir_for_project_makes_a_0777_folder(self):
        workspace_fs.mkdir_for_project(PID, "made/deep")
        self.assertEqual((self.root / "made" / "deep").stat().st_mode & 0o777, 0o777)


# 11. ---------------------------------------------------------------- hashing
class HashingIsBounded(_Base):
    async def test_properties_and_fs_hash_of_a_2_gib_file(self):
        with open(self.root / "sparse.bin", "wb") as fh:
            fh.truncate((2 << 30) - 1)
        t = time.time()
        props = workspace_fs.properties_for_project(PID, "sparse.bin")
        self.assertLess(time.time() - t, 0.5, "one Properties click hashed 2 GiB")
        self.assertNotIn("sha256", props)
        self.assertTrue((await workspace_fs.fs_hash("sparse.bin")).startswith("Error:"))

    async def test_a_small_file_still_hashes(self):
        (self.root / "s.txt").write_text("abc")
        out = await workspace_fs.fs_hash("s.txt")
        self.assertEqual(out, "sha256(s.txt) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main()

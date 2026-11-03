"""Safe archive extraction for workspace uploads and URL imports.

Every entry is written here, by hand, instead of through `extractall`:
  - names are normalized and refused when absolute, '..', NUL, too deep or too long;
  - links, devices, FIFOs and encrypted zip entries are skipped, never created;
  - REAL bytes are counted against the cap while copying (a declared size can lie);
  - each path component is opened with O_NOFOLLOW relative to its parent's fd.
    Staging lives in /workspace, which kali-sandbox mounts read-write, so a
    component could be swapped for a symlink between two entries.

Callers run safe_extract on the import pool (executor.run_blocking), never on
the event loop or the default pool.
"""
from __future__ import annotations

import gzip
import lzma
import bz2
import os
import re
import tarfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from workspace_import.errors import ImportFailure

_CHUNK = 1024 * 1024
MAX_DEPTH = 64
MAX_SEGMENT_BYTES = 255
MAX_PATH_BYTES = 4096
MAX_REPORTED_SKIPS = 200
_PROGRESS_INTERVAL_SEC = 0.25

# The importer writes these itself after extraction; a copy inside the source
# must never collide with or shadow them.
RESERVED_NAMES = frozenset({".import.json", "_manifest.jsonl"})
_METADATA_NAMES = frozenset({".DS_Store"})
_ZERO_BLOCK = b"\0" * 512
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


@dataclass
class ExtractReport:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    skipped: list = field(default_factory=list)  # (name, reason), capped
    skipped_count: int = 0
    top_level: list = field(default_factory=list)

    def skip(self, name: str, reason: str) -> None:
        self.skipped_count += 1
        if len(self.skipped) < MAX_REPORTED_SKIPS:
            self.skipped.append((name, reason))


def _looks_like_tar(head: bytes) -> bool:
    return len(head) >= 512 and (head[257:262] == b"ustar" or head[:512] == _ZERO_BLOCK)


def _decompressed_head(path: Path, opener) -> bytes:
    try:
        with opener(path, "rb") as f:
            return f.read(512)
    except (OSError, EOFError, zlib.error, lzma.LZMAError):
        return b""


def _tar_has_member(path: Path) -> bool:
    try:
        with tarfile.open(path, "r:*") as tf:
            return tf.next() is not None
    except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError):
        return False


def detect_archive_format(path) -> Optional[str]:
    """'zip', 'tar' or 'gz' (a gzip that is not a tar), by content, never by name."""
    path = Path(path)
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError:
        return None
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        if _looks_like_tar(_decompressed_head(path, gzip.open)) or _tar_has_member(path):
            return "tar"
        return "gz"
    if head[:3] == b"BZh":
        inner = _decompressed_head(path, bz2.open)
        return "tar" if _looks_like_tar(inner) or _tar_has_member(path) else None
    if head[:6] == b"\xfd7zXZ\x00":
        inner = _decompressed_head(path, lzma.open)
        return "tar" if _looks_like_tar(inner) or _tar_has_member(path) else None
    if _looks_like_tar(head):
        return "tar"
    return None


def _normalize(name: str) -> list[str]:
    """Split an archive name into safe segments, or abort the extraction."""
    n = (name or "").replace("\\", "/")
    if "\x00" in n or n.startswith("/") or _DRIVE_RE.match(n):
        raise ImportFailure("unsafe_path")
    while n.startswith("./"):
        n = n[2:]
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ImportFailure("unsafe_path")
    return parts


def _check_lengths(parts: list[str]) -> None:
    if len(parts) > MAX_DEPTH:
        raise ImportFailure("too_deep")
    if any(len(p.encode("utf-8", "surrogateescape")) > MAX_SEGMENT_BYTES for p in parts):
        raise ImportFailure("name_too_long")
    if len("/".join(parts).encode("utf-8", "surrogateescape")) > MAX_PATH_BYTES:
        raise ImportFailure("name_too_long")


class _Writer:
    """Creates entries under `dest` one path component at a time."""

    def __init__(self, dest: Path):
        self.dest_fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.kinds: dict[tuple, str] = {}  # path tuple -> "dir" | "file"

    def close(self) -> None:
        os.close(self.dest_fd)

    def _claim(self, parts: tuple, kind: str) -> bool:
        """False when this exact entry already exists (a later duplicate)."""
        for i in range(1, len(parts)):
            if self.kinds.get(parts[:i]) == "file":
                raise ImportFailure("conflicting_entries")
        existing = self.kinds.get(parts)
        if existing is not None and existing != kind:
            raise ImportFailure("conflicting_entries")
        return existing is None

    def _open_dir(self, parts: tuple) -> int:
        """An fd for dest/<parts>, creating each missing folder 0777."""
        fd = os.dup(self.dest_fd)
        try:
            for i, seg in enumerate(parts):
                try:
                    os.mkdir(seg, 0o777, dir_fd=fd)
                    created = True
                except FileExistsError:
                    created = False
                nxt = os.open(seg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
                if created:
                    os.fchmod(fd, 0o777)
                self.kinds.setdefault(parts[: i + 1], "dir")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def mkdir(self, parts: tuple) -> bool:
        if not self._claim(parts, "dir"):
            return False
        os.close(self._open_dir(parts))
        return True

    def open_file(self, parts: tuple) -> Optional[int]:
        if not self._claim(parts, "file"):
            return None
        parent = self._open_dir(parts[:-1])
        try:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o666, dir_fd=parent)
        finally:
            os.close(parent)
        os.fchmod(fd, 0o666)
        self.kinds[parts] = "file"
        return fd


class _Budget:
    def __init__(self, max_bytes, max_entries, report, progress, cancel_event, now, on_bytes=None):
        self.max_bytes = max_bytes
        self.on_bytes = on_bytes
        self.max_entries = max_entries
        self.report = report
        self.progress = progress
        self.cancel_event = cancel_event
        self.now = now
        self.entries = 0
        self.declared = 0
        self._last_progress = None

    def check_cancel(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ImportFailure("cancelled")

    def count_entry(self) -> None:
        self.entries += 1
        if self.entries > self.max_entries:
            raise ImportFailure("too_many_entries")

    def declare(self, size: int) -> None:
        self.declared += max(0, int(size or 0))
        if self.declared > self.max_bytes:
            raise ImportFailure("too_large")

    def tick(self, force: bool = False) -> None:
        if self.progress is None:
            return
        t = self.now()
        if force or self._last_progress is None or t - self._last_progress >= _PROGRESS_INTERVAL_SEC:
            self._last_progress = t
            self.progress(self.report.files, self.report.bytes)


def _copy(src, fd: int, budget: _Budget, mtime: Optional[float]) -> None:
    try:
        while True:
            budget.check_cancel()
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            budget.report.bytes += len(chunk)
            if budget.report.bytes > budget.max_bytes:
                raise ImportFailure("too_large")
            if budget.on_bytes is not None:
                budget.on_bytes(budget.report.bytes)
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            budget.tick()
        if mtime is not None:
            try:
                os.utime(fd, (mtime, mtime))
            except (OSError, OverflowError, ValueError):
                pass
    finally:
        os.close(fd)


def _target_parts(raw_name: str, member_filter) -> Optional[list[str]]:
    parts = _normalize(raw_name)
    if member_filter is not None and parts:
        renamed = member_filter("/".join(parts))
        if renamed is None:
            return None
        parts = _normalize(renamed)
    if not parts:
        return None
    _check_lengths(parts)
    return parts


def _skip_reason(parts: list[str]) -> Optional[str]:
    if parts[0] == "__MACOSX" or parts[-1] in _METADATA_NAMES:
        return "metadata"
    if any(p in RESERVED_NAMES for p in parts):
        return "reserved_name"
    return None


def _extract_tar(path, writer, budget, member_filter):
    report = budget.report
    with tarfile.open(path, "r:*") as tf:
        for m in tf:
            budget.check_cancel()
            budget.count_entry()
            parts = _target_parts(m.name, member_filter)
            if parts is None:
                continue
            name = "/".join(parts)
            if m.issym() or m.islnk():
                report.skip(name, "link")
                continue
            if m.ischr() or m.isblk() or m.isfifo():
                report.skip(name, "special_file")
                continue
            if not (m.isdir() or m.isfile()):
                report.skip(name, "unsupported_type")
                continue
            reason = _skip_reason(parts)
            if reason:
                report.skip(name, reason)
                continue
            if m.isdir():
                writer.mkdir(tuple(parts))
                continue
            budget.declare(m.size)
            fd = writer.open_file(tuple(parts))
            if fd is None:
                report.skip(name, "duplicate")
                continue
            src = tf.extractfile(m)
            if src is None:
                os.close(fd)
                continue
            with src:
                _copy(src, fd, budget, m.mtime)
            report.files += 1
            budget.tick()


_ZIP_SYMLINK = 0o120000


def _extract_zip(path, writer, budget, member_filter):
    report = budget.report
    with zipfile.ZipFile(path) as zf:
        for zi in zf.infolist():
            budget.check_cancel()
            budget.count_entry()
            parts = _target_parts(zi.filename, member_filter)
            if parts is None:
                continue
            name = "/".join(parts)
            unix_mode = zi.external_attr >> 16
            if unix_mode and (unix_mode & 0o170000) == _ZIP_SYMLINK:
                report.skip(name, "link")
                continue
            if zi.flag_bits & 0x1:
                report.skip(name, "encrypted")
                continue
            reason = _skip_reason(parts)
            if reason:
                report.skip(name, reason)
                continue
            if zi.is_dir():
                writer.mkdir(tuple(parts))
                continue
            budget.declare(zi.file_size)
            fd = writer.open_file(tuple(parts))
            if fd is None:
                report.skip(name, "duplicate")
                continue
            mtime = None
            try:
                mtime = time.mktime(zi.date_time + (0, 0, -1))
            except (OverflowError, ValueError):
                pass
            with zf.open(zi) as src:
                _copy(src, fd, budget, mtime)
            report.files += 1
            budget.tick()


def _extract_single_gz(path, writer, budget, single_name):
    parts = _target_parts(single_name, None)
    if parts is None or len(parts) != 1:
        raise ImportFailure("unsafe_path")
    budget.count_entry()
    fd = writer.open_file(tuple(parts))
    with gzip.open(path, "rb") as src:
        _copy(src, fd, budget, None)
    budget.report.files += 1


def safe_extract(
    archive,
    dest,
    *,
    max_bytes: int,
    max_entries: int,
    member_filter: Optional[Callable[[str], Optional[str]]] = None,
    progress: Optional[Callable[[int, int], None]] = None,
    cancel_event=None,
    single_name: Optional[str] = None,
    now: Callable[[], float] = time.monotonic,
    on_bytes: Optional[Callable[[int], None]] = None,
) -> ExtractReport:
    """Extract `archive` into `dest`, an empty directory inside staging.

    `member_filter(name) -> new_name | None` keeps a subtree and strips a
    prefix. A gzip that is not a tar becomes one file named `single_name`
    (default: the archive's name minus `.gz`). On any ImportFailure the
    caller removes `dest`.

    `on_bytes(total)` sees the bytes extracted so far before each write, and
    may raise (a refused disk reservation): an archive can hold far more than
    its own size.
    """
    archive, dest = Path(archive), Path(dest)
    if not dest.is_dir() or dest.is_symlink() or any(dest.iterdir()):
        raise ValueError("safe_extract needs an empty, real directory")
    fmt = detect_archive_format(archive)
    if fmt is None:
        raise ImportFailure("unsupported_archive")
    report = ExtractReport()
    budget = _Budget(max_bytes, max_entries, report, progress, cancel_event, now, on_bytes)
    writer = _Writer(dest)
    try:
        if fmt == "zip":
            _extract_zip(archive, writer, budget, member_filter)
        elif fmt == "tar":
            _extract_tar(archive, writer, budget, member_filter)
        else:
            stem = archive.name[:-3] if archive.name.lower().endswith(".gz") else archive.name
            _extract_single_gz(archive, writer, budget, single_name or stem or "download")
    except ImportFailure:
        raise
    except (tarfile.TarError, zipfile.BadZipFile, gzip.BadGzipFile, EOFError, zlib.error,
            lzma.LZMAError) as e:
        raise ImportFailure("corrupt_archive", detail=type(e).__name__) from None
    finally:
        writer.close()
    report.dirs = sum(1 for kind in writer.kinds.values() if kind == "dir")
    if report.files == 0 and report.dirs == 0:
        raise ImportFailure("empty_archive")
    report.top_level = sorted({parts[0] for parts in writer.kinds})
    budget.tick(force=True)
    return report


def single_top_dir(dest) -> Optional[Path]:
    """The only entry of `dest` when it is a real folder, else None."""
    try:
        entries = list(Path(dest).iterdir())
    except OSError:
        return None
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return None

"""A Stored GitHub repository read from one archive download (T6.3, §4.5, §5, EX-4).

Instead of one request per file, a Stored repository whose size (the repository API's ``size``,
in KB) is under ``constants.githubArchiveMaxBytes`` is read from its ``.tar.gz``, which GitHub
serves from ``github.com/<owner>/<repo>/archive/refs/heads/<branch>.tar.gz`` behind one redirect to
``codeload.github.com``. The API's size counts the git history, so it overestimates the archive:
it is only the pre-check, and the bytes counted while streaming are the measure.

- The download goes through ``fetch.stream_raw``: every hop judged by the address guard, the
  GitHub token only on the GitHub host it was sent to (codeload gets none; a private repository's
  redirect carries its own short-lived token in the URL).
- The body is unpacked as it arrives: a worker thread reads the tar stream, pulling each chunk
  from the event loop, and keeps only the files of the map (the chosen file types and folders,
  already applied by the builder), each at most ``storage.maxPageKb`` (a longer file is cut and
  its rest skipped unread), within ``storage.maxPages`` and ``storage.maxResourceMb``.
- Two ceilings stop it: the archive's bytes (``Content-Length`` before reading, then the running
  count) and the unpacked bytes (``UNPACKED_MAX_BYTES``, against an archive that unpacks to far more
  than it weighs).

Anything that goes wrong leaves the files it could not read to the file-by-file path
(``storage``'s downloads), so a failed archive costs one request and never the refresh. A bigger
repository is read file by file from the start. Log lines carry codes and counts only.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import tarfile
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

from logging_config import get_logger
from tradecraft.ingest import fetch
from tradecraft.settings import EffectiveSettings, constant

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

ARCHIVE_MAX_BYTES = int(constant("githubArchiveMaxBytes"))
# A text repository unpacks to a few times its archive; ten times the ceiling is far past that.
UNPACKED_MAX_BYTES = 10 * ARCHIVE_MAX_BYTES
CHUNK_BYTES = 64 * 1024
# Chunks downloaded ahead of the unpacking thread.
QUEUE_CHUNKS = 16
MB = 1024 * 1024


class _TooLarge(Exception):
    pass


class _Stalled(Exception):
    pass


@dataclass
class ArchiveTexts:
    """The files read from the archive: {repository path: text}; ``cut`` the paths whose text
    stops at the per-file limit. ``error`` is "" or a code (``archive_*``, a net code)."""

    texts: dict[str, str] = field(default_factory=dict)
    cut: set[str] = field(default_factory=set)
    error: str = ""
    archive_bytes: int = 0


def archive_url(owner: str, repo: str, branch: str) -> str:
    quoted = "/".join(urllib.parse.quote(seg, safe="") for seg in branch.split("/"))
    return f"https://github.com/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}" \
           f"/archive/refs/heads/{quoted}.tar.gz"


def eligible(size_kb: Any) -> bool:
    """The repository API's size says the archive may fit under the ceiling."""
    return isinstance(size_kb, int) and not isinstance(size_kb, bool) and 0 <= size_kb * 1024 <= ARCHIVE_MAX_BYTES


def repo_path(member_name: str) -> str:
    """A member's path in the repository: GitHub prefixes every member with ``<repo>-<ref>/``."""
    parts = member_name.split("/", 1)
    return parts[1] if len(parts) == 2 else ""


class _Source(io.RawIOBase):
    """The archive as a file the tar reader pulls in a worker thread: each read waits for the
    next downloaded chunk on the event loop and unpacks the gzip layer, counting what it unpacks."""

    def __init__(self, pull: Callable[[], bytes], unpacked_max: int) -> None:
        self._pull = pull
        self._gz = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._buf = b""
        self._pending = b""
        self._eof = False
        self._max = unpacked_max
        self.unpacked = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        while not self._buf and not self._eof:
            if self._gz.eof:
                self._eof = True
                break
            data = self._pending or self._pull()
            if not data:
                self._buf = self._gz.flush()
                self._eof = True
            else:
                self._buf = self._gz.decompress(data, CHUNK_BYTES)
                self._pending = self._gz.unconsumed_tail
            self.unpacked += len(self._buf)
            if self.unpacked > self._max:
                raise _TooLarge()
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


def _decode(data: bytes, cut: bool) -> str:
    text = data.decode("utf-8", errors="replace")
    # A cut can split a character: its replacement mark is not the file's.
    return text.rstrip("�") if cut else text


def unpack(source: io.RawIOBase, wanted: set[str], *, max_file_bytes: int, max_total_bytes: int,
           max_files: int) -> ArchiveTexts:
    """Reads the tar stream (blocking: a worker thread), keeping the wanted files. Members are
    never written anywhere, so a member's name only selects; links and folders are skipped."""
    out = ArchiveTexts()
    total = 0
    try:
        with tarfile.open(fileobj=io.BufferedReader(source, CHUNK_BYTES), mode="r|") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                path = repo_path(member.name)
                if path not in wanted or path in out.texts:
                    continue
                if len(out.texts) >= max_files or total >= max_total_bytes:
                    break  # storage keeps no more: the rest of the download is not needed
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                data = handle.read(max_file_bytes)
                cut = member.size > max_file_bytes
                out.texts[path] = _decode(data, cut)
                if cut:
                    out.cut.add(path)
                total += len(data)
                if len(out.texts) == len(wanted):
                    break
    except _TooLarge:
        out.error = "archive_too_large"
    except _Stalled:
        out.error = "archive_stalled"
    except (tarfile.TarError, zlib.error, EOFError, OSError, ValueError):
        out.error = "archive_unreadable"
    return out


async def read(owner: str, repo: str, branch: str, settings: EffectiveSettings, *, github_token: Optional[str],
               wanted: set[str], max_file_bytes: int, max_total_bytes: int, max_files: int,
               should_stop: Optional[Callable[[], Awaitable[bool]]] = None) -> ArchiveTexts:
    """The wanted files of one archive download. Never raises; ``error`` says what stopped it."""
    loop = asyncio.get_running_loop()
    wait = float(settings.int("fetching.requestTimeoutSec")) + 5.0
    async with fetch.stream_raw(archive_url(owner, repo, branch), settings, github_token=github_token,
                                max_bytes=ARCHIVE_MAX_BYTES + 1) as resp:
        if not resp.ok:
            return ArchiveTexts(error=resp.error or f"archive_http_{resp.status}")
        length = resp.headers.get("content-length") or ""
        if length.isdigit() and int(length) > ARCHIVE_MAX_BYTES:
            return ArchiveTexts(error="archive_too_large")
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_CHUNKS)
        stopped = False

        async def produce() -> None:
            nonlocal stopped
            async for chunk in resp.chunks():
                if should_stop is not None and await should_stop():
                    stopped = True
                    break
                await queue.put(chunk)
            await queue.put(b"")  # the end: the thread reads it as the end of the archive

        def pull() -> bytes:
            try:
                return asyncio.run_coroutine_threadsafe(queue.get(), loop).result(timeout=wait)
            except Exception as exc:  # a stall, or the loop closing under a job that ended
                raise _Stalled() from exc

        producer = asyncio.create_task(produce())
        try:
            got = await loop.run_in_executor(None, lambda: unpack(
                _Source(pull, UNPACKED_MAX_BYTES), wanted, max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes, max_files=max_files))
        finally:
            producer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await producer
        got.archive_bytes = resp.received
        if stopped:
            got.error = "cancelled"
        elif resp.truncated:
            got.error = "archive_too_large"
        elif resp.error:
            got.error = resp.error
        return got


async def repo_size_kb(owner: str, repo: str, settings: EffectiveSettings,
                       github_token: Optional[str]) -> Optional[int]:
    resp = await fetch.fetch_raw(f"https://api.github.com/repos/{owner}/{repo}", settings,
                                 github_token=github_token, max_bytes=256 * 1024)
    if resp.status != 200:
        return None
    try:
        size = json.loads(resp.text).get("size")
    except (ValueError, AttributeError):
        return None
    return size if isinstance(size, int) and not isinstance(size, bool) else None


async def prefetch(state: "IngestState", entries: list) -> dict[str, tuple[str, bool]]:
    """{entry URL: (text, cut)} for the files of a Stored repository's kept entries that its archive
    holds; {} for any other resource, a repository over the ceiling, or an archive that failed."""
    if state.site_type != "github-repo" or state.storage_mode != "stored":
        return {}
    meta = state.meta
    owner, repo, branch = meta.get("owner"), meta.get("repo"), meta.get("branch")
    wanted = {e.path: e.url for e in entries if e.source == "tree" and e.path}
    if not (owner and repo and branch and wanted):
        return {}
    size = state.repo_size_kb
    if size is None:
        size = await repo_size_kb(owner, repo, state.settings, state.github_token)
        state.visited += 1
    job = state.request.job_id
    if not eligible(size):
        logger.info(f"[tradecraft] job {job} github_archive code=archive_over_ceiling")
        return {}
    s = state.settings
    got = await read(owner, repo, branch, s, github_token=state.github_token, wanted=set(wanted),
                     max_file_bytes=s.int("storage.maxPageKb") * 1024, max_total_bytes=s.int("storage.maxResourceMb") * MB,
                     max_files=s.int("storage.maxPages"), should_stop=state.ctx.is_cancelled)
    state.visited += 1
    if got.error == "cancelled":
        await state.check_cancelled()
    if got.error:
        state.count_error(got.error if got.error.startswith("archive_") else "archive_unavailable")
    logger.info(f"[tradecraft] job {job} github_archive code={got.error} files={len(got.texts)} "
                f"bytes={got.archive_bytes}")
    return {wanted[p]: (text, p in got.cut) for p, text in got.texts.items()}

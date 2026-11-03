"""Streaming responses for workspace downloads and archive builds.

Nothing is buffered in memory: an imported file can be gigabytes and the agent
has a 3 GB limit. Every download is an `attachment` with `nosniff`, because a
mirrored website puts attacker HTML and SVG in the workspace.
"""
from __future__ import annotations

import logging
import os
import threading
import urllib.parse
from typing import Callable, Iterator

from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

import workspace_fs
from workspace_import import executor, staging
from workspace_import.errors import ImportFailure, error_body, map_os_error

logger = logging.getLogger(__name__)

_CHUNK = 1024 * 1024
ARCHIVE_MIME = {"tar.gz": "application/gzip", "zip": "application/zip"}


def attachment_headers(filename: str, size: int) -> dict:
    ascii_name = "".join(c if 0x20 <= ord(c) < 0x7F and c not in '"\\;%' else "_" for c in filename)
    return {
        "Content-Disposition": (f'attachment; filename="{ascii_name}"; '
                                f"filename*=UTF-8''{urllib.parse.quote(filename, safe='')}"),
        "X-Content-Type-Options": "nosniff",
        "Content-Length": str(size),
    }


class _OwnedFd:
    """A descriptor closed exactly once, by whichever comes first: the stream's
    end or the response's background task."""

    def __init__(self, fd: int):
        self.fd = fd
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            fd, self.fd = self.fd, -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _iter_fd(owned: _OwnedFd) -> Iterator[bytes]:
    # pread at our own offset: a read still in flight after the background
    # close can never move the offset of a descriptor that reused the number.
    offset = 0
    try:
        while owned.fd >= 0:
            chunk = os.pread(owned.fd, _CHUNK, offset)
            if not chunk:
                break
            offset += len(chunk)
            yield chunk
    finally:
        owned.close()


def stream_fd(fd: int, size: int, mime: str, filename: str) -> StreamingResponse:
    """Stream an already-opened, already-checked descriptor and close it. A
    client that leaves before the first byte (during an archive build) means
    the stream never starts; the background task closes the descriptor then,
    or an unlinked archive would hold its disk space until the agent restarts."""
    owned = _OwnedFd(fd)
    return StreamingResponse(_iter_fd(owned), media_type=mime, headers=attachment_headers(filename, size),
                             background=BackgroundTask(owned.close))


def _open_built(path) -> tuple[int, int]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    return fd, os.fstat(fd).st_size


async def archive_response(
    project_id: str,
    sources: list,
    write: Callable[[object], None],
    filename: str,
    format: str,
):
    """Build an archive of `sources` in staging, on the import pool, then stream it.

    The build first reserves as many bytes as the sources hold. The finished
    file is opened, unlinked and its op dir removed before the first byte, so
    nothing is left on disk however the download ends; the open descriptor
    holds the space until it is closed.
    """
    op = staging.new_op_dir(project_id, "dl")
    reservation = None
    try:
        nbytes = await executor.run_blocking(workspace_fs.tree_bytes, sources)
        reservation = staging.reserve(op.name, nbytes, project_id=project_id)
        out = op / "archive"

        def build():
            with open(out, "xb") as f:
                write(f)
            return _open_built(out)

        fd, size = await executor.run_blocking(build)
    except ImportFailure as e:
        return JSONResponse(content=error_body(e.code), status_code=e.status)
    except OSError as e:
        failure = map_os_error(e)
        if failure is None:
            logger.error(f"[workspace-import] archive build failed project={project_id}: {type(e).__name__}")
            return JSONResponse(content=error_body("internal_error"), status_code=500)
        return JSONResponse(content=error_body(failure.code), status_code=failure.status)
    finally:
        if reservation is not None:
            reservation.release()
        staging.remove_tree(op)
    return stream_fd(fd, size, ARCHIVE_MIME.get(format, "application/octet-stream"), filename)

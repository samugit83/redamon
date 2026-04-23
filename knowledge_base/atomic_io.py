import errno
import fcntl
import json
import logging
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Union

logger = logging.getLogger(__name__)


# =============================================================================
# Atomic file writes
# =============================================================================

def atomic_write_bytes(path: Union[str, Path], data: bytes) -> None:
    """
    Atomically write bytes to `path`.

    Writes to a sibling tempfile in the same directory and renames it into
    place. On POSIX, os.replace() is atomic when src and dst are on the same
    filesystem. A crash before the rename leaves the original file untouched
    and the tempfile orphaned (cleaned up on retry).

    Args:
        path: Destination file path.
        data: Bytes to write.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    # mkstemp returns an OS-level fd; close it after writing.
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
    except Exception:
        # Best-effort cleanup of orphaned tempfile.
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_text(path: Union[str, Path], text: str, encoding: str = "utf-8") -> None:
    """Atomically write a text string to `path`."""
    atomic_write_bytes(path, text.encode(encoding))


def atomic_write_json(path: Union[str, Path], data: Any, indent: int = None) -> None:
    """Atomically write a JSON-serializable object to `path`."""
    payload = json.dumps(data, indent=indent)
    atomic_write_text(path, payload)


# =============================================================================
# Process-level ingest lock
# =============================================================================

class IngestLockError(RuntimeError):
    """Raised when another ingest is already running."""


@contextmanager
def ingest_lock(data_dir: Union[str, Path], wait: bool = False) -> Iterator[Path]:
    """
    Acquire an exclusive process lock on the KB data directory.

    Uses fcntl.flock on a `.ingest.lock` file inside `data_dir`. The lock
    is released automatically when the context exits, even on exceptions.

    Args:
        data_dir: KB data directory (e.g. /app/knowledge_base/data).
        wait: If True, block until the lock is available.
              If False (default), raise IngestLockError immediately if another
              ingest is running.

    Yields:
        The lock file path.

    Raises:
        IngestLockError: if wait=False and another ingest holds the lock.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    lock_path = data_dir / ".ingest.lock"

    # Open in append mode so the file gets created if missing but we don't
    # truncate someone else's PID record on contention.
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        flags = fcntl.LOCK_EX
        if not wait:
            flags |= fcntl.LOCK_NB
        try:
            fcntl.flock(fd, flags)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                # Read the existing PID for the error message
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    held_by = os.read(fd, 64).decode("utf-8", "replace").strip()
                except OSError:
                    held_by = "unknown pid"
                raise IngestLockError(
                    f"Another KB ingest is already running (pid={held_by}). "
                    f"Lock file: {lock_path}. "
                    f"Pass wait=True to wait for it, or kill the holding process."
                ) from None
            raise

        # Record our PID inside the lock file for debugging.
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
        except OSError:
            pass

        logger.debug(f"Acquired ingest lock: {lock_path} (pid={os.getpid()})")
        try:
            yield lock_path
        finally:
            logger.debug(f"Releasing ingest lock: {lock_path}")
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)

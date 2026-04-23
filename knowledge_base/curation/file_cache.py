import hashlib
import json
import logging
import os
import tarfile
import yaml
from pathlib import Path
from typing import Iterator, Optional

from knowledge_base.atomic_io import atomic_write_json

logger = logging.getLogger(__name__)

# =============================================================================
# Tarball safety
# =============================================================================
MAX_TAR_MEMBER_BYTES = 10 * 1024 * 1024        # 10 MB per file
MAX_TAR_DECOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB total across the archive


class TarballTooLargeError(ValueError):
    """Raised by ``bounded_tar_iter`` when a size cap is exceeded."""


def bounded_tar_iter(
    tar: tarfile.TarFile,
    label: str = "tarball",
    *,
    max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
    max_total_bytes: int = MAX_TAR_DECOMPRESSED_BYTES,
) -> Iterator[tarfile.TarInfo]:
    """
    Iterate regular-file members of ``tar`` with size caps enforced.

    Raises ``TarballTooLargeError`` if either cap is exceeded. Non-file
    members (dirs, symlinks, hardlinks, devices, fifos) are skipped
    silently — KB clients never want those.

    The caller is still responsible for calling ``safe_relative_path``
    on each member's name before using it as a filesystem destination.
    """
    total = 0
    for member in tar:
        if not member.isfile():
            continue
        if member.size > max_member_bytes:
            raise TarballTooLargeError(
                f"{label}: member {member.name!r} is {member.size} bytes "
                f"(> per-member cap {max_member_bytes})"
            )
        total += member.size
        if total > max_total_bytes:
            raise TarballTooLargeError(
                f"{label}: cumulative decompressed size {total} bytes "
                f"exceeds cap {max_total_bytes}"
            )
        yield member


# =============================================================================
# YAML parser safety
# =============================================================================
MAX_YAML_BYTES = 1 * 1024 * 1024  # 1 MB per document
MAX_YAML_INDENT_CHARS = 256       # ≈ 64 levels at 4-space indent
MAX_YAML_FLOW_DEPTH = 64          # max open { [ at any one time
MAX_YAML_ANCHORS = 100            # anchors (&name) across the doc
MAX_YAML_ALIASES = 1000           # alias references (*name) across the doc


class YAMLTooComplexError(ValueError):
    """Raised when a YAML document exceeds size / depth / alias limits."""


def _scan_yaml_complexity(content: str) -> tuple[int, int, int, int]:
    """
    Cheap single-pass scan for ``(max_indent, max_flow_depth, anchors, aliases)``.

    Approximate by design — we want to reject obviously hostile inputs
    before yaml.safe_load touches them, not replicate the parser. False
    negatives (something pathological we miss) are handled by
    yaml.safe_load's own defences; false positives (a legit file
    rejected) require raising the constants above.

    The scan is line-based but ignores comments (``# …``) and naive
    about single/double quoted strings: a ``{`` inside a quoted string
    still counts toward nesting depth. This is intentional — the
    overcount is bounded and always safe.
    """
    max_indent = 0
    flow_depth = 0
    max_flow_depth = 0
    anchors = 0
    aliases = 0
    for line in content.splitlines():
        # Indentation depth via leading spaces on non-blank lines.
        lstripped = line.lstrip(" ")
        if lstripped and not lstripped.startswith("#"):
            indent = len(line) - len(lstripped)
            if indent > max_indent:
                max_indent = indent
        # Flow-style nesting and anchor/alias counts.
        for ch in line:
            if ch in "{[":
                flow_depth += 1
                if flow_depth > max_flow_depth:
                    max_flow_depth = flow_depth
            elif ch in "}]":
                if flow_depth > 0:
                    flow_depth -= 1
            elif ch == "&":
                anchors += 1
            elif ch == "*":
                aliases += 1
    return max_indent, max_flow_depth, anchors, aliases


def bounded_yaml_load(
    content: str,
    label: str = "yaml",
    *,
    max_bytes: int = MAX_YAML_BYTES,
    max_indent_chars: int = MAX_YAML_INDENT_CHARS,
    max_flow_depth: int = MAX_YAML_FLOW_DEPTH,
    max_anchors: int = MAX_YAML_ANCHORS,
    max_aliases: int = MAX_YAML_ALIASES,
):
    """
    Parse ``content`` with ``yaml.safe_load`` after pre-scan guards.

    Raises ``YAMLTooComplexError`` if any guard trips; the caller
    should catch it and skip the document (or log + continue). No
    exceptions propagate out of this function except the guard error
    and whatever ``yaml.safe_load`` itself raises (YAMLError).
    """

    size = len(content.encode("utf-8", errors="replace"))
    if size > max_bytes:
        raise YAMLTooComplexError(
            f"{label}: YAML size {size} bytes exceeds cap {max_bytes}"
        )

    indent, flow_depth, anchors, aliases = _scan_yaml_complexity(content)
    if indent > max_indent_chars:
        raise YAMLTooComplexError(
            f"{label}: max indentation {indent} chars exceeds cap {max_indent_chars}"
        )
    if flow_depth > max_flow_depth:
        raise YAMLTooComplexError(
            f"{label}: flow-style nesting depth {flow_depth} exceeds cap {max_flow_depth}"
        )
    if anchors > max_anchors:
        raise YAMLTooComplexError(
            f"{label}: {anchors} YAML anchors exceeds cap {max_anchors}"
        )
    if aliases > max_aliases:
        raise YAMLTooComplexError(
            f"{label}: {aliases} YAML aliases exceeds cap {max_aliases} "
            f"(billion-laughs defense)"
        )

    return yaml.safe_load(content)


# =============================================================================
# Symlink-safe file writes (Sec #7)
# =============================================================================

def safe_write_text(
    path: Path, content: str, encoding: str = "utf-8", mode: int = 0o644
) -> None:
    """
    Create-or-overwrite ``path`` with ``content``, refusing to follow symlinks.

    Defends against the TOCTOU race where a concurrent process
    creates a symlink at ``path`` between the time ``safe_relative_path``
    validated it and the time we actually open the file. ``O_NOFOLLOW``
    on the final path component makes ``open()`` through a symlink fail
    with ``ELOOP`` rather than silently writing to the symlink target.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(str(path), flags, mode)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
        fd = -1  # fdopen took ownership of the fd
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass


def file_hash(content: str) -> str:
    """SHA256 hash of file content (first 16 hex chars)."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def load_file_hashes(cache_dir: Path) -> dict:
    """Load {relative_path: content_hash} from .file_hashes.json."""
    path = cache_dir / ".file_hashes.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_file_hashes(cache_dir: Path, hashes: dict) -> None:
    """
    Save {relative_path: content_hash} to .file_hashes.json.

    Writes are atomic (tempfile + os.replace) so a crash mid-write
    doesn't leave a half-written hash file.
    """
    path = cache_dir / ".file_hashes.json"
    atomic_write_json(path, hashes, indent=2)


def safe_relative_path(rel_path: str, base: Path) -> Optional[Path]:
    """
    Resolve a relative path against `base` and reject any escape attempts.

    Defends against path traversal in tarballs:
        - Rejects absolute paths
        - Rejects paths containing '..' segments
        - Rejects paths whose resolved location escapes `base`
        - Rejects empty paths and paths with NUL bytes

    Args:
        rel_path: Relative path string from an untrusted source (tar member name,
                  cache key, etc.).
        base: The trusted base directory the path must stay inside.

    Returns:
        The safe absolute Path inside base, or None if the path is unsafe.
    """
    if not rel_path or "\x00" in rel_path:
        return None

    # Reject absolute paths outright
    p = Path(rel_path)
    if p.is_absolute():
        return None

    # Reject any '..' segment — even if filesystem resolution would be a no-op
    if any(part == ".." for part in p.parts):
        return None

    # Reject paths that look absolute on Windows (drive letters, UNC)
    if p.drive or p.root:
        return None

    # Build the candidate path and verify it stays inside base after resolution
    base_resolved = base.resolve()
    try:
        candidate = (base_resolved / p).resolve()
    except (OSError, RuntimeError):
        return None

    # Check the resolved candidate is base or a descendant of base
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        return None

    return candidate


def diff_files(
    new_files: dict[str, str],
    old_hashes: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Compare new file contents against cached hashes.

    Args:
        new_files: {relative_path: content} from the latest download.
        old_hashes: {relative_path: content_hash} from .file_hashes.json.

    Returns:
        (changed_files, updated_hashes)
        changed_files: {relative_path: content} — only new/modified files.
        updated_hashes: full hash map (old + updated entries).
    """
    changed = {}
    updated_hashes = dict(old_hashes)

    for rel_path, content in new_files.items():
        h = file_hash(content)
        if old_hashes.get(rel_path) == h:
            continue  # unchanged
        changed[rel_path] = content
        updated_hashes[rel_path] = h

    return changed, updated_hashes

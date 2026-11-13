"""
Workspace filesystem primitives.

24 fs_* tools that operate inside /workspace/<projectId>/. Every user-supplied
path goes through _resolve_safe() which rejects .. traversal and symlink
escapes. project_id is pulled from the current_project_id contextvar (set by
the agent runtime) - tools refuse to run without it.

All functions are async coroutines that return a single string for direct LLM
consumption. The DISPATCH map at the bottom is what tools.py wires into the
in-process executor.
"""
from __future__ import annotations

import base64
import difflib
import fnmatch
import gzip
import hashlib
import logging
import mimetypes
import os
import posixpath
import re
import shutil
import stat as statlib
import subprocess
import tarfile
import time
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from workspace_import import busy as _busy
from workspace_import import provenance as _provenance

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    """Read a positive-int env var; fall back to default on unset/invalid so a
    typo can never disable a safety cap (D10)."""
    try:
        v = int(str(os.environ.get(name, "")).strip())
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))

# In-memory undo stack: absolute path -> list of pre-edit byte snapshots.
# Cap depth at 20 (oldest evicted). Lost on agent restart - undo is a
# session-scoped affordance, not durable state.
_edit_stack: dict[str, list[bytes]] = {}
_EDIT_STACK_DEPTH = 20

# (project_id, rel_path) -> last fs_read content + sha256. Used by
# fs_diff(vs_last_read=True) to detect concurrent writes.
_last_read_contents: dict[tuple[str, str], bytes] = {}
_last_read_hashes: dict[tuple[str, str], str] = {}

# Hard cap on fs_read_many total payload (bytes).
_DEFAULT_READ_MANY_CAP = 200_000

# Subdirs auto-created on first project access. These are also "protected"
# by the HTTP layer: the drawer cannot rename or delete them via
# rename_for_project / delete_for_project. The LLM-facing fs_delete /
# fs_move tools are NOT gated so the agent can still recreate them after
# accidental damage (next call to _workspace_root_for auto-creates).
_DEFAULT_SUBDIRS = ("notes", "tool-outputs", "jobs", "uploads")
PROTECTED_SUBDIRS = frozenset(_DEFAULT_SUBDIRS)


def is_protected_path(rel_path: str) -> bool:
    """True if rel_path is the project root or a default subdir.

    Used by HTTP delete/rename to refuse destructive operations on the
    layout the workspace assumes exists.

    SECURITY (bug #17 regression): normalize the path before checking,
    otherwise variants like ./notes, notes/, notes//, ./ bypass the
    gate via the naive .split('/') check. os.path.normpath collapses
    these, and we treat the result of '.' as the project root.
    """
    if rel_path is None:
        return True
    # Normalize: collapse ./ and //, strip trailing /. normpath('') -> '.'
    norm = os.path.normpath(rel_path.strip()) if rel_path.strip() else "."
    # Treat normalized root or '.' as the protected project root
    if norm in (".", "/", ""):
        return True
    # If normalization produces a '..' component, it's escape - protect
    # conservatively (also rejected by resolve_for_project later)
    if norm.startswith(".."):
        return True
    norm = norm.lstrip("/")
    parts = norm.split("/")
    return len(parts) == 1 and parts[0] in PROTECTED_SUBDIRS

# Dirs skipped by fs_tree.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


# =============================================================================
# Internals
# =============================================================================

def _validate_project_id(pid: str) -> None:
    """Reject project_ids that could escape the workspace root.

    SECURITY: this is the only thing protecting the workspace boundary
    when project_id is HTTP-attacker-controlled (it's a query-string
    parameter on /workspace/* endpoints). Without it, projectId="../foo"
    causes (WORKSPACE_ROOT / "../foo").resolve() to land OUTSIDE the
    workspace, and every subsequent path check accepts that escaped
    location as "the workspace root" - leaking host filesystem access.
    """
    if not pid:
        raise ValueError("project_id required")
    if "/" in pid or "\\" in pid or "\x00" in pid:
        raise ValueError(f"invalid project_id (contains separator): {pid!r}")
    if pid in (".", "..") or pid.startswith("."):
        raise ValueError(f"invalid project_id (dot path): {pid!r}")
    # Reject absolute-looking values
    if pid.startswith("/"):
        raise ValueError(f"invalid project_id (absolute): {pid!r}")


def _project_id() -> str:
    from agent_context import current_project_id
    pid = current_project_id.get()
    if not pid:
        raise ValueError("fs_* tool called without project_id in context")
    _validate_project_id(pid)
    return pid


def _workspace_root_for(project_id: str) -> Path:
    root = WORKSPACE_ROOT / project_id
    root.mkdir(parents=True, exist_ok=True)
    for sub in _DEFAULT_SUBDIRS:
        (root / sub).mkdir(exist_ok=True)
    return root


def _workspace_root() -> Path:
    return _workspace_root_for(_project_id())


def _resolve_safe(user_path: Optional[str], follow_symlinks: bool = True) -> Path:
    """Resolve user_path against project workspace. Reject any escape.

    follow_symlinks=False is for tools that need to *inspect* a symlink itself
    (fs_symlink_read, fs_stat) rather than its target. Even with following off,
    the path is still normalised (`..` collapsed) and confined to the workspace.
    """
    root = _workspace_root().resolve()
    if user_path in (None, "", ".", "/"):
        return root
    p = Path(user_path)
    if p.is_absolute():
        if follow_symlinks:
            try:
                resolved = p.resolve()
            except Exception:
                raise ValueError(f"absolute path not allowed: {user_path}")
        else:
            resolved = Path(os.path.normpath(str(p)))
        if resolved == root or root in resolved.parents:
            return resolved
        raise ValueError(f"absolute path not allowed: {user_path}")
    if follow_symlinks:
        candidate = (root / user_path).resolve()
    else:
        candidate = Path(os.path.normpath(str(root / user_path)))
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"path escapes workspace: {user_path}")
    return candidate


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(_workspace_root().resolve()))
    except ValueError:
        return str(path)


def _fmt_size(n: int) -> str:
    f = float(n)
    for u in ("B", "K", "M", "G"):
        if f < 1024:
            return f"{f:.0f}{u}"
        f /= 1024
    return f"{f:.0f}T"


def _fmt_mtime(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return "?"


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _push_undo(abs_path: str, snapshot: bytes) -> None:
    stack = _edit_stack.setdefault(abs_path, [])
    stack.append(snapshot)
    if len(stack) > _EDIT_STACK_DEPTH:
        stack.pop(0)


def _parse_duration(spec: str) -> Optional[float]:
    """Parse '24h', '7d', etc. -> seconds. Leading <,>,= is ignored here."""
    if not spec:
        return None
    s = spec.strip().lstrip("<>=")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if not s or s[-1] not in units:
        return None
    try:
        return float(s[:-1]) * units[s[-1]]
    except ValueError:
        return None


def _parse_size(spec: str) -> Optional[int]:
    if not spec:
        return None
    s = spec.strip().lstrip("<>=")
    units = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if not s:
        return None
    if s[-1].upper() in units:
        try:
            return int(float(s[:-1]) * units[s[-1].upper()])
        except ValueError:
            return None
    try:
        return int(s)
    except ValueError:
        return None


# =============================================================================
# READ (3)
# =============================================================================

async def fs_read(path: str, offset: Optional[int] = None, limit: Optional[int] = None) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: file not found: {path}. Use fs_glob to find the correct path."
    if full.is_dir():
        return f"Error: {path} is a directory. Use fs_list or fs_tree."

    raw = full.read_bytes()
    key = (_project_id(), _rel(full))
    _last_read_contents[key] = raw
    _last_read_hashes[key] = hashlib.sha256(raw).hexdigest()

    if _is_binary(raw):
        mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
        b64 = base64.b64encode(raw).decode("ascii")
        return (
            f"[binary file: {path} ({len(raw)} bytes, {mime})]\n"
            f"--- base64 ---\n{b64}"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"Error: {path} could not be decoded as UTF-8."

    lines = text.splitlines()
    total = len(lines)
    start = (offset - 1) if offset and offset > 0 else 0
    end = start + (limit if limit else 2000)
    selected = lines[start:end]
    width = max(1, len(str(start + len(selected))))
    formatted = []
    for i, line in enumerate(selected, start=start + 1):
        if len(line) > 2000:
            line = line[:2000] + " [LINE TRUNCATED]"
        formatted.append(f"{i:>{width}}\t{line}")
    out = "\n".join(formatted)
    if total > len(selected):
        out = f"[{path}: lines {start + 1}-{start + len(selected)} of {total}]\n{out}"
    return out


async def fs_read_many(paths: list, max_total_bytes: int = _DEFAULT_READ_MANY_CAP) -> str:
    if not isinstance(paths, list) or not paths:
        return "Error: `paths` must be a non-empty list of file paths."
    out_parts = []
    used = 0
    for p in paths:
        try:
            full = _resolve_safe(p)
        except ValueError as e:
            out_parts.append(f"=== {p} ===\nError: {e}")
            continue
        if not full.exists():
            out_parts.append(f"=== {p} ===\nError: not found")
            continue
        if full.is_dir():
            out_parts.append(f"=== {p} ===\nError: is a directory")
            continue
        try:
            data = full.read_bytes()
        except Exception as e:
            out_parts.append(f"=== {p} ===\nError: {e}")
            continue
        remaining = max_total_bytes - used
        if remaining <= 0:
            out_parts.append(f"=== {p} ===\n[skipped - total cap {max_total_bytes} reached]")
            continue
        if _is_binary(data):
            out_parts.append(f"=== {p} ===\n[binary file: {len(data)} bytes - use fs_read for base64]")
            used += 80
            continue
        text = data.decode("utf-8", errors="replace")
        if len(text) > remaining:
            text = text[:remaining] + f"\n[truncated at {remaining} bytes]"
        used += len(text)
        out_parts.append(f"=== {p} ===\n{text}")
    return "\n\n".join(out_parts)


async def fs_stat(path: str, include_hash: bool = False) -> str:
    try:
        # follow_symlinks=False so a symlink reports as type=symlink instead
        # of being resolved to its target.
        full = _resolve_safe(path, follow_symlinks=False)
    except ValueError as e:
        return f"Error: {e}"
    if not (full.exists() or full.is_symlink()):
        return f"Error: not found: {path}"
    st = full.stat() if full.exists() else full.lstat()
    if full.is_symlink():
        kind = "symlink"
    elif full.is_dir():
        kind = "dir"
    else:
        kind = "file"
    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"path: {path}",
        f"type: {kind}",
        f"size: {st.st_size}",
        f"mode: {statlib.filemode(st.st_mode)} ({oct(st.st_mode & 0o7777)})",
        f"mtime: {mtime}",
    ]
    if include_hash and full.is_file():
        h = hashlib.sha256()
        with full.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        lines.append(f"sha256: {h.hexdigest()}")
    return "\n".join(lines)


# =============================================================================
# WRITE & MUTATE (10)
# =============================================================================

async def fs_write(path: str, content: str, mode: str = "overwrite") -> str:
    if mode not in ("overwrite", "create_only", "append"):
        return f"Error: invalid mode '{mode}'. Use overwrite|create_only|append."
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    full.parent.mkdir(parents=True, exist_ok=True)
    if mode == "create_only" and full.exists():
        return f"Error: file already exists: {path}. Use mode='overwrite' or 'append'."
    if mode == "append":
        with full.open("a", encoding="utf-8") as f:
            f.write(content)
        return f"Appended {len(content)} chars to {path}."
    tmp = full.with_suffix(full.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, full)
    line_count = content.count("\n") + (0 if content.endswith("\n") else 1) if content else 0
    return f"Wrote {path} ({len(content)} chars, {line_count} lines, mode={mode})."


async def fs_edit(path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    content = full.read_text(encoding="utf-8")
    if old_string not in content:
        return f"Error: old_string not found in {path}."
    if old_string == new_string:
        return "Error: new_string is identical to old_string."
    occurrences = content.count(old_string)
    if occurrences > 1 and not replace_all:
        return (
            f"Error: old_string found {occurrences} times in {path}. "
            "Provide more surrounding context, or set replace_all=True."
        )
    _push_undo(str(full), full.read_bytes())
    new_content = content.replace(old_string, new_string, -1 if replace_all else 1)
    tmp = full.with_suffix(full.suffix + ".tmp")
    tmp.write_text(new_content, encoding="utf-8")
    os.replace(tmp, full)
    n = occurrences if replace_all else 1
    return f"Replaced {n} occurrence(s) in {path}."


async def fs_multi_edit(path: str, edits: list) -> str:
    if not isinstance(edits, list) or not edits:
        return "Error: `edits` must be a non-empty list of {old_string,new_string,replace_all?}."
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    snapshot = full.read_bytes()
    new_content = snapshot.decode("utf-8", errors="strict")
    applied = []
    for i, edit in enumerate(edits, start=1):
        old_s = edit.get("old_string")
        new_s = edit.get("new_string")
        replace_all = bool(edit.get("replace_all", False))
        if old_s is None or new_s is None:
            return f"Error: edit #{i} missing old_string or new_string. No changes applied."
        if old_s == new_s:
            return f"Error: edit #{i} identical old/new. No changes applied."
        if old_s not in new_content:
            return f"Error: edit #{i} old_string not found (after prior edits). No changes applied."
        occurrences = new_content.count(old_s)
        if occurrences > 1 and not replace_all:
            return (
                f"Error: edit #{i} matches {occurrences} times. "
                "Provide more context or set replace_all=True. No changes applied."
            )
        new_content = new_content.replace(old_s, new_s, -1 if replace_all else 1)
        applied.append(occurrences if replace_all else 1)
    _push_undo(str(full), snapshot)
    tmp = full.with_suffix(full.suffix + ".tmp")
    tmp.write_text(new_content, encoding="utf-8")
    os.replace(tmp, full)
    return f"Applied {len(edits)} edits to {path} ({sum(applied)} replacements total)."


async def fs_undo_edit(path: str) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    stack = _edit_stack.get(str(full)) or []
    if not stack:
        return f"No undo history for {path}."
    snapshot = stack.pop()
    full.write_bytes(snapshot)
    return f"Reverted {path} ({len(stack)} undo step(s) remaining)."


async def fs_delete(path: str, recursive: bool = False) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    if full.is_dir():
        if not recursive:
            return f"Error: {path} is a directory. Pass recursive=True to delete it and its contents."
        shutil.rmtree(full)
        return f"Removed directory {path} (recursive)."
    full.unlink()
    return f"Deleted file {path}."


async def fs_move(src: str, dst: str) -> str:
    try:
        src_p = _resolve_safe(src)
        dst_p = _resolve_safe(dst)
    except ValueError as e:
        return f"Error: {e}"
    if not src_p.exists():
        return f"Error: source not found: {src}"
    dst_p.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src_p), str(dst_p))
    return f"Moved {src} -> {dst}."


async def fs_copy(src: str, dst: str, recursive: bool = False) -> str:
    try:
        src_p = _resolve_safe(src)
        dst_p = _resolve_safe(dst)
    except ValueError as e:
        return f"Error: {e}"
    if not src_p.exists():
        return f"Error: source not found: {src}"
    dst_p.parent.mkdir(parents=True, exist_ok=True)
    if src_p.is_dir():
        if not recursive:
            return f"Error: {src} is a directory. Pass recursive=True."
        shutil.copytree(src_p, dst_p)
        # shutil.copytree preserves source modes; normalize so host stays
        # able to edit/delete workspace files (Phase-6 bug #15).
        _normalize_workspace_tree(dst_p)
    else:
        shutil.copy2(src_p, dst_p)
        try:
            os.chmod(dst_p, 0o666)
        except OSError:
            pass
    return f"Copied {src} -> {dst}."


def _normalize_workspace_tree(root: Path) -> None:
    """Walk a copied tree and set dirs to 0o777, files to 0o666 so the host
    user can edit/delete despite root ownership of the agent process."""
    try:
        os.chmod(root, 0o777)
    except OSError:
        pass
    for p, dirs, files in os.walk(root):
        for d in dirs:
            try:
                os.chmod(Path(p) / d, 0o777)
            except OSError:
                pass
        for f in files:
            try:
                os.chmod(Path(p) / f, 0o666)
            except OSError:
                pass


async def fs_mkdir(path: str, parents: bool = True) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if full.exists():
        if not full.is_dir():
            return f"Error: {path} exists and is not a directory."
        try:
            entry_count = sum(1 for _ in full.iterdir())
        except OSError:
            entry_count = -1
        if entry_count < 0:
            return f"Directory {path} already exists (no change)."
        return f"Directory {path} already exists (no change, {entry_count} entries inside)."
    try:
        full.mkdir(parents=parents, exist_ok=False)
    except FileNotFoundError:
        return (
            f"Error: parent of {path} does not exist. "
            f"Pass parents=True to auto-create intermediate directories."
        )
    except OSError as e:
        return f"Error: failed to create {path}: {e}"
    return f"Created directory {path}."


async def fs_chmod(path: str, mode_str: str) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    s = (mode_str or "").strip()
    if not s:
        return "Error: mode_str required (e.g. '755', '+x')."
    try:
        if s[0] in ("+", "-"):
            cur = full.stat().st_mode
            op = s[0]
            flags = 0
            for ch in s[1:]:
                if ch == "x":
                    flags |= 0o111
                elif ch == "w":
                    flags |= 0o222
                elif ch == "r":
                    flags |= 0o444
                else:
                    return f"Error: unsupported chmod symbol '{ch}'. Use '+x'/'-x'/'+w' or octal '755'."
            new = (cur | flags) if op == "+" else (cur & ~flags)
            full.chmod(new)
        else:
            full.chmod(int(s, 8))
    except ValueError:
        return f"Error: bad mode '{mode_str}'. Use octal '755' or '+x'/'-x'/'+w'."
    return f"chmod {mode_str} {path}."


async def fs_symlink_create(target: str, linkname: str, type: str = "soft") -> str:
    if type not in ("soft", "hard"):
        return "Error: type must be 'soft' or 'hard'."
    try:
        link = _resolve_safe(linkname)
        target_p = _resolve_safe(target)
    except ValueError as e:
        return f"Error: {e}"
    if link.exists() or link.is_symlink():
        return f"Error: {linkname} already exists."
    link.parent.mkdir(parents=True, exist_ok=True)
    if type == "hard":
        os.link(target_p, link)
    else:
        link.symlink_to(target_p)
    return f"Created {type} link {linkname} -> {target}."


# =============================================================================
# SEARCH & NAVIGATE (7)
# =============================================================================

async def fs_grep(
    pattern: str,
    path: str = ".",
    glob: Optional[str] = None,
    type: Optional[str] = None,
    output_mode: str = "files_with_matches",
    context: int = 0,
    case_insensitive: bool = False,
    multiline: bool = False,
    head_limit: int = 50,
) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    cmd = ["rg", pattern]
    if output_mode == "files_with_matches":
        cmd.append("-l")
    elif output_mode == "count":
        cmd.append("-c")
    if glob:
        cmd.extend(["--glob", glob])
    if type:
        cmd.extend(["--type", type])
    if context > 0 and output_mode == "content":
        cmd.extend(["-C", str(context)])
    if case_insensitive:
        cmd.append("-i")
    if multiline:
        cmd.extend(["-U", "--multiline-dotall"])
    if output_mode == "content":
        cmd.append("-n")
    cmd.extend(["--max-count", "1000"])
    cmd.append(str(full))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "Error: search timed out after 30s."
    except FileNotFoundError:
        return "Error: ripgrep (rg) not installed in agent container."
    if result.returncode == 1:
        return "No matches found."
    if result.returncode > 1:
        return f"Error: ripgrep failed: {result.stderr.strip()}"
    lines = result.stdout.strip().split("\n")
    truncated = len(lines) > head_limit
    if truncated:
        lines = lines[:head_limit]
    root_prefix = str(_workspace_root().resolve()) + "/"
    out = "\n".join(line.replace(root_prefix, "") for line in lines)
    if truncated:
        out += f"\n[Results truncated - showing first {head_limit}]"
    return out or "No matches found."


async def fs_glob(pattern: str, path: Optional[str] = None) -> str:
    try:
        base = _resolve_safe(path or ".")
    except ValueError as e:
        return f"Error: {e}"
    if not base.exists():
        return f"Error: directory not found: {path}"
    matches = sorted(
        base.glob(pattern),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    if not matches:
        return f"No files matching pattern: {pattern}"
    rows = [_rel(m) for m in matches[:500]]
    out = "\n".join(rows)
    if len(matches) > 500:
        out += f"\n\n[Showing first 500 of {len(matches)} matches]"
    return out


async def fs_find(
    path: Optional[str] = None,
    name: Optional[str] = None,
    mtime: Optional[str] = None,
    size: Optional[str] = None,
    type: Optional[str] = None,
    max_results: int = 200,
) -> str:
    try:
        base = _resolve_safe(path or ".")
    except ValueError as e:
        return f"Error: {e}"
    if not base.exists():
        return f"Error: directory not found: {path}"
    max_results = min(max(1, max_results), 5000)

    mtime_sec = _parse_duration(mtime) if mtime else None
    mtime_op = (mtime[0] if (mtime and mtime[0] in ("<", ">")) else ">") if mtime else None
    size_bytes = _parse_size(size) if size else None
    size_op = (size[0] if (size and size[0] in ("<", ">")) else ">") if size else None

    now = time.time()
    deadline = now + 30
    results: list[str] = []

    def _match(p: Path) -> bool:
        if name and not fnmatch.fnmatch(p.name, name):
            return False
        if type:
            if type == "file" and not p.is_file():
                return False
            if type == "dir" and not p.is_dir():
                return False
            if type == "symlink" and not p.is_symlink():
                return False
        try:
            st = p.stat()
        except Exception:
            return False
        if mtime_sec is not None:
            age = now - st.st_mtime
            if mtime_op == "<" and age >= mtime_sec:
                return False
            if mtime_op == ">" and age <= mtime_sec:
                return False
        if size_bytes is not None:
            if size_op == "<" and st.st_size >= size_bytes:
                return False
            if size_op == ">" and st.st_size <= size_bytes:
                return False
        return True

    try:
        for root, dirs, files in os.walk(base):
            if time.time() > deadline:
                results.append("[walk timeout after 30s]")
                break
            for n in files + dirs:
                p = Path(root) / n
                if _match(p):
                    results.append(_rel(p))
                    if len(results) >= max_results:
                        results.append(f"[truncated at {max_results}]")
                        return "\n".join(results)
    except Exception as e:
        return f"Error during walk: {e}"
    return "\n".join(results) if results else "No matches found."


async def fs_list(path: str = ".") -> str:
    try:
        target = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not target.is_dir():
        return f"Error: not a directory: {path}"
    entries = sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    rows = []
    for e in entries[:200]:
        if e.is_dir():
            kind = "dir"
        elif e.is_symlink():
            kind = "lnk"
        else:
            kind = "   "
        try:
            sz = _fmt_size(e.stat().st_size) if e.is_file() else "-"
            mt = _fmt_mtime(e)
        except Exception:
            sz, mt = "?", "?"
        rows.append(f"{kind}  {sz:>6}  {mt}  {e.name}")
    out = "\n".join(rows)
    total = sum(1 for _ in target.iterdir())
    if total > 200:
        out += f"\n\n[Showing first 200 of {total} entries]"
    return out or "(empty directory)"


async def fs_tree(path: str = ".", max_depth: int = 3, max_entries: int = 500) -> str:
    try:
        base = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not base.is_dir():
        return f"Error: not a directory: {path}"

    rows = [(_rel(base) or ".") + "/"]
    count = [1]

    def _walk(p: Path, depth: int, prefix: str):
        if depth > max_depth or count[0] >= max_entries:
            return
        try:
            children = sorted(
                [c for c in p.iterdir() if not c.name.startswith(".") and c.name not in _SKIP_DIRS],
                key=lambda c: (not c.is_dir(), c.name.lower()),
            )
        except Exception:
            return
        for i, c in enumerate(children):
            if count[0] >= max_entries:
                rows.append(f"{prefix}└── [truncated at {max_entries} entries]")
                return
            last = i == len(children) - 1
            branch = "└── " if last else "├── "
            suffix = "/" if c.is_dir() else ""
            rows.append(f"{prefix}{branch}{c.name}{suffix}")
            count[0] += 1
            if c.is_dir():
                _walk(c, depth + 1, prefix + ("    " if last else "│   "))

    _walk(base, 1, "")
    return "\n".join(rows)


# Ext -> tree-sitter language name
_EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".jsx": "javascript", ".java": "java", ".go": "go", ".rs": "rust",
    ".rb": "ruby", ".php": "php", ".c": "c", ".cpp": "cpp", ".cs": "c_sharp",
    ".kt": "kotlin", ".swift": "swift", ".scala": "scala",
}
_DEFINITION_TYPES = {
    "python": ["function_definition", "class_definition", "decorated_definition"],
    "javascript": ["function_declaration", "class_declaration", "method_definition", "arrow_function", "variable_declarator"],
    "typescript": ["function_declaration", "class_declaration", "method_definition", "arrow_function", "variable_declarator", "interface_declaration", "type_alias_declaration"],
    "java": ["class_declaration", "method_declaration", "interface_declaration"],
    "go": ["function_declaration", "method_declaration", "type_declaration"],
    "rust": ["function_item", "impl_item", "struct_item", "enum_item", "trait_item"],
    "ruby": ["method", "class", "module", "singleton_method"],
    "php": ["function_definition", "class_declaration", "method_declaration"],
    "c": ["function_definition", "struct_specifier"],
    "cpp": ["function_definition", "class_specifier", "struct_specifier"],
    "c_sharp": ["class_declaration", "method_declaration", "interface_declaration"],
}


_MARKDOWN_EXTS = (".md", ".markdown", ".mdown", ".mkd")


def _markdown_symbols(full: Path, rel_path: str) -> str:
    try:
        text = full.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"Error parsing {rel_path}: {e}"
    headers: list[tuple[int, str, int, int]] = []
    lines = text.splitlines()
    in_fence = False
    fence_marker: str | None = None
    atx_re = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
    setext_re = re.compile(r"^(=+|-+)\s*$")
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif fence_marker and stripped.startswith(fence_marker):
                in_fence, fence_marker = False, None
            continue
        if in_fence:
            continue
        m = atx_re.match(line)
        if m:
            headers.append((len(m.group(1)), m.group(2).strip(), idx + 1, idx + 1))
            continue
        if idx > 0 and setext_re.match(line):
            prev = lines[idx - 1].strip()
            if prev and not prev.startswith("#") and not atx_re.match(lines[idx - 1]):
                level = 1 if line.lstrip().startswith("=") else 2
                headers.append((level, prev, idx, idx + 1))
    if not headers:
        return f"No definitions found in {rel_path}."
    out = [f"Symbols in {rel_path} ({len(headers)} defs):"]
    for level, name, start, end in headers[:500]:
        indent = "  " * (level - 1)
        out.append(f"{indent}h{level} {name}  [{start}-{end}]")
    return "\n".join(out)


async def fs_symbols(file_path: str) -> str:
    try:
        full = _resolve_safe(file_path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: file not found: {file_path}"
    if full.suffix.lower() in _MARKDOWN_EXTS:
        return _markdown_symbols(full, file_path)
    lang = _EXT_TO_LANG.get(full.suffix)
    if not lang:
        supported = ", ".join(list(_EXT_TO_LANG) + list(_MARKDOWN_EXTS))
        return f"Error: unsupported language for {full.suffix}. Supported: {supported}"
    try:
        from tree_sitter_languages import get_parser
        parser = get_parser(lang)
    except Exception as e:
        return f"Error: tree-sitter parser unavailable for {lang}: {e}"

    def _extract_name(node):
        for child in node.children:
            if child.type in ("identifier", "name", "property_identifier", "type_identifier"):
                return child.text.decode("utf-8")
        return None

    def _walk(node, depth=0, parent_name=None):
        defs = []
        types = _DEFINITION_TYPES.get(lang, [])
        for c in node.children:
            if c.type in types:
                nm = _extract_name(c)
                if nm:
                    kind = c.type.replace("_definition", "").replace("_declaration", "").replace("_item", "")
                    scope = f"{parent_name} > " if parent_name else ""
                    defs.append({
                        "name": nm, "kind": kind, "scope": scope, "depth": depth,
                        "start_line": c.start_point[0] + 1, "end_line": c.end_point[0] + 1,
                    })
                    defs.extend(_walk(c, depth + 1, nm))
            else:
                defs.extend(_walk(c, depth, parent_name))
        return defs

    try:
        tree = parser.parse(full.read_bytes())
        defs = _walk(tree.root_node)
    except Exception as e:
        return f"Error parsing {file_path}: {e}"
    if not defs:
        return f"No definitions found in {file_path}."
    lines = [f"Symbols in {file_path} ({len(defs)} defs):"]
    for d in defs[:500]:
        lines.append(
            f"{'  ' * d['depth']}{d['kind']} {d['scope']}{d['name']}  "
            f"[{d['start_line']}-{d['end_line']}]"
        )
    return "\n".join(lines)


async def fs_symlink_read(path: str) -> str:
    try:
        full = _resolve_safe(path, follow_symlinks=False)
    except ValueError as e:
        return f"Error: {e}"
    if not full.is_symlink():
        return f"Error: {path} is not a symlink."
    return f"{path} -> {os.readlink(full)}"


# =============================================================================
# INTEGRITY & ARCHIVE (4)
# =============================================================================

async def fs_hash(path: str, algo: str = "sha256") -> str:
    if algo not in ("sha256", "md5"):
        return "Error: algo must be sha256 or md5."
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.is_file():
        return f"Error: not a file: {path}"
    h = hashlib.new(algo)
    with full.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"{algo}({path}) = {h.hexdigest()}"


async def fs_diff(
    path_a: str,
    path_b: Optional[str] = None,
    vs_last_read: bool = False,
) -> str:
    if vs_last_read:
        try:
            full = _resolve_safe(path_a)
        except ValueError as e:
            return f"Error: {e}"
        key = (_project_id(), _rel(full))
        prior = _last_read_contents.get(key)
        if prior is None:
            return f"Error: no fs_read snapshot for {path_a}. Call fs_read first."
        cur = full.read_bytes() if full.exists() else b""
        if hashlib.sha256(cur).hexdigest() == _last_read_hashes.get(key):
            return "(no changes since last fs_read)"
        a_text = prior.decode("utf-8", errors="replace")
        b_text = cur.decode("utf-8", errors="replace")
        diff = difflib.unified_diff(
            a_text.splitlines(keepends=True), b_text.splitlines(keepends=True),
            fromfile=f"a/{path_a} (last fs_read)", tofile=f"b/{path_a} (current)",
        )
        out = "".join(diff)
        return out or "(no changes since last fs_read)"

    if not path_b:
        return "Error: provide path_b (or set vs_last_read=True)."
    try:
        fa = _resolve_safe(path_a)
        fb = _resolve_safe(path_b)
    except ValueError as e:
        return f"Error: {e}"
    if not fa.exists() or not fb.exists():
        return "Error: one or both files not found."
    a_text = fa.read_text(encoding="utf-8", errors="replace")
    b_text = fb.read_text(encoding="utf-8", errors="replace")
    diff = difflib.unified_diff(
        a_text.splitlines(keepends=True), b_text.splitlines(keepends=True),
        fromfile=f"a/{path_a}", tofile=f"b/{path_b}",
    )
    out = "".join(diff)
    return out or "(files identical)"


async def fs_extract(archive_path: str, dest: str, format: str = "auto") -> str:
    try:
        archive = _resolve_safe(archive_path)
        dest_p = _resolve_safe(dest)
    except ValueError as e:
        return f"Error: {e}"
    if not archive.exists():
        return f"Error: archive not found: {archive_path}"
    dest_p.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_p.resolve()

    fmt = format
    if fmt == "auto":
        n = archive.name.lower()
        if n.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar")):
            fmt = "tar"
        elif n.endswith(".zip"):
            fmt = "zip"
        elif n.endswith(".gz"):
            fmt = "gz"
        else:
            return f"Error: cannot auto-detect format for {archive_path}. Pass format='tar'|'zip'|'gz'."

    def _safe(member_name: str) -> bool:
        candidate = (dest_p / member_name).resolve()
        return candidate == dest_resolved or dest_resolved in candidate.parents

    def _safe_link(member) -> bool:
        # A tar entry may be a symlink/hardlink whose *target* escapes dest even
        # when its name does not (e.g. a link named "ok" pointing at
        # "../../etc/passwd"). extractall(filter="data") guards this on 3.12+,
        # but we validate explicitly so the check holds on every runtime.
        link = getattr(member, "linkname", "") or ""
        if not link:
            return True
        if os.path.isabs(link):
            return False
        if member.issym():
            base = dest_p / os.path.dirname(member.name)
        else:  # hardlink target is relative to the archive root
            base = dest_p
        candidate = (base / link).resolve()
        return candidate == dest_resolved or dest_resolved in candidate.parents

    # D10: zip/tar-bomb defense. Cap entry count and total DECLARED uncompressed
    # size before extracting, and stream the gz path with a byte ceiling, so a
    # small crafted archive cannot inflate to tens of GB and OOM the agent. Env-
    # overridable with generous defaults.
    max_entries = _int_env("FS_EXTRACT_MAX_ENTRIES", 5000)
    max_total = _int_env("FS_EXTRACT_MAX_TOTAL_BYTES", 500 * 1024 * 1024)

    if fmt == "tar":
        with tarfile.open(archive, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > max_entries:
                return f"Error: archive has too many entries ({len(members)}; max {max_entries}). Aborted."
            total = sum(max(0, m.size) for m in members)
            if total > max_total:
                return f"Error: archive decompresses too large ({total} bytes; max {max_total}). Aborted."
            for m in members:
                if not _safe(m.name):
                    return f"Error: tar-slip attempt detected for entry '{m.name}'. Aborted."
                if (m.issym() or m.islnk()) and not _safe_link(m):
                    return f"Error: unsafe link target in entry '{m.name}' -> '{m.linkname}'. Aborted."
            try:
                # filter="data" (Python 3.12+) also strips setuid/dev nodes and
                # re-validates link targets; fall back cleanly on older runtimes
                # where our explicit name+link checks above already apply.
                tf.extractall(dest_p, filter="data")
            except TypeError:
                tf.extractall(dest_p)
            except Exception as e:
                return f"Error: tar extraction blocked by safety filter: {e}. Aborted."
            return f"Extracted {len(members)} entries from {archive_path} -> {dest}."
    if fmt == "zip":
        with zipfile.ZipFile(archive, "r") as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                return f"Error: archive has too many entries ({len(infos)}; max {max_entries}). Aborted."
            total = sum(max(0, i.file_size) for i in infos)
            if total > max_total:
                return f"Error: archive decompresses too large ({total} bytes; max {max_total}). Aborted."
            for i in infos:
                if not _safe(i.filename):
                    return f"Error: zip-slip attempt detected for entry '{i.filename}'. Aborted."
            zf.extractall(dest_p)
            return f"Extracted {len(infos)} entries from {archive_path} -> {dest}."
    if fmt == "gz":
        out_name = archive.stem  # strips trailing .gz
        out_path = (dest_p / out_name).resolve()
        if out_path != dest_resolved and dest_resolved not in out_path.parents:
            return "Error: extraction would escape dest."
        # gz carries no reliable declared size; stream with a hard byte ceiling.
        written = 0
        with gzip.open(archive, "rb") as gz, out_path.open("wb") as out:
            while True:
                chunk = gz.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_total:
                    out.close()
                    try:
                        out_path.unlink()
                    except Exception:
                        pass
                    return f"Error: gz stream exceeds max size ({max_total} bytes). Aborted."
                out.write(chunk)
        return f"Extracted 1 file from {archive_path} -> {dest}/{out_name}."
    return f"Error: unsupported format '{format}'."


async def fs_archive(paths: list, dest: str, format: str = "tar.gz") -> str:
    if not isinstance(paths, list) or not paths:
        return "Error: paths must be a non-empty list."
    if format not in ("tar.gz", "zip"):
        return "Error: format must be tar.gz or zip."
    try:
        dest_p = _resolve_safe(dest)
        resolved_inputs = [_resolve_safe(p) for p in paths]
    except ValueError as e:
        return f"Error: {e}"
    for p in resolved_inputs:
        if not p.exists():
            return f"Error: not found: {_rel(p)}"
    dest_p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    if format == "tar.gz":
        def _skip_symlinks(tarinfo):
            if tarinfo.issym() or tarinfo.islnk():
                return None
            return tarinfo
        with tarfile.open(dest_p, "w:gz") as tf:
            for p in resolved_inputs:
                if p.is_symlink():
                    continue
                tf.add(p, arcname=p.name, filter=_skip_symlinks)
                n += 1
    else:
        with zipfile.ZipFile(dest_p, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in resolved_inputs:
                if p.is_symlink():
                    continue
                if p.is_dir():
                    for sub in p.rglob("*"):
                        if sub.is_symlink() or not sub.is_file():
                            continue
                        zf.write(sub, arcname=f"{p.name}/{sub.relative_to(p)}")
                else:
                    zf.write(p, arcname=p.name)
                n += 1
    return f"Archived {n} entries -> {dest} ({format})."


# =============================================================================
# Dispatch (name -> coroutine). Wired into PhaseAwareToolExecutor._invoke().
# =============================================================================

# =============================================================================
# Public helpers for HTTP endpoints (project-explicit, no contextvar dependency)
# =============================================================================
# These are used by api.py /workspace/* routes. They take project_id as an
# argument instead of reading the contextvar so the HTTP layer doesn't have
# to fiddle with contextvar state per request.

#: Where the agent and kali-sandbox mount every project's workspace (compose). A
#: file the agent writes for the person is named `/workspace/<projectId>/...`,
#: the only absolute form the webapp's download route accepts. Fixed, unlike
#: WORKSPACE_ROOT (the agent's own mount, which tests move).
SANDBOX_WORKSPACE_ROOT = "/workspace"


def sandbox_workspace_relative(project_id: str, path: Optional[str]) -> Optional[str]:
    """`path` relative to project `project_id`'s workspace, or None when it points
    anywhere else.

    `path` is absolute under `/workspace/<projectId>/` (as the sandbox and a chat
    download card name it) or already workspace-relative. An empty, `.` or `..`
    segment, a backslash or a NUL is refused, so nothing climbs out before
    resolve_for_project's own confinement, which also refuses a symlink escape.
    """
    try:
        _validate_project_id(project_id)
    except ValueError:
        return None
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return None
    if path.startswith("/"):
        prefix = f"{SANDBOX_WORKSPACE_ROOT}/{project_id}/"
        if not path.startswith(prefix):
            return None
        path = path[len(prefix):]
    if any(part in ("", ".", "..") for part in path.split("/")):
        return None
    return path


def resolve_for_project(project_id: str, user_path: Optional[str], follow_symlinks: bool = True) -> Path:
    """Public variant of _resolve_safe that takes project_id explicitly."""
    _validate_project_id(project_id)
    root = (WORKSPACE_ROOT / project_id).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for sub in _DEFAULT_SUBDIRS:
        (root / sub).mkdir(exist_ok=True)
    if user_path in (None, "", ".", "/"):
        return root
    p = Path(user_path)
    if p.is_absolute():
        if follow_symlinks:
            try:
                resolved = p.resolve()
            except Exception:
                raise ValueError(f"absolute path not allowed: {user_path}")
        else:
            resolved = Path(os.path.normpath(str(p)))
        if resolved == root or root in resolved.parents:
            return resolved
        raise ValueError(f"absolute path not allowed: {user_path}")
    if follow_symlinks:
        candidate = (root / user_path).resolve()
    else:
        candidate = Path(os.path.normpath(str(root / user_path)))
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"path escapes workspace: {user_path}")
    return candidate


def list_dir_for_project(project_id: str, path: str = ".") -> list[dict]:
    """Directory entries as structured dicts for the frontend drawer."""
    target = resolve_for_project(project_id, path)
    if not target.is_dir():
        raise ValueError(f"not a directory: {path}")
    rows = []
    root = (WORKSPACE_ROOT / project_id).resolve()
    for entry in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        try:
            st = entry.stat()
            rel = str(entry.relative_to(root))
            rows.append({
                "name": entry.name,
                "path": rel,
                "isDir": entry.is_dir(),
                "isSymlink": entry.is_symlink(),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
            })
        except Exception as e:
            logger.warning(f"list_dir: skipped {entry}: {e}")
    return rows


def list_dir_page(project_id: str, path: str = ".", limit: int = 2000) -> tuple[list[dict], int]:
    """The first `limit` entries of a directory, dirs first then by name, and
    the total count. Only the page is stat'ed: the drawer polls this every few
    seconds, and an imported tree can hold tens of thousands of entries."""
    target = resolve_for_project(project_id, path)
    if not target.is_dir():
        raise ValueError(f"not a directory: {path}")
    root = (WORKSPACE_ROOT / project_id).resolve()
    with os.scandir(target) as it:
        entries = list(it)

    def _is_dir(e: os.DirEntry) -> bool:
        try:
            return e.is_dir()
        except OSError:
            return False

    entries.sort(key=lambda e: (not _is_dir(e), e.name.lower()))
    rows = []
    for entry in entries[:max(0, limit)]:
        try:
            st = os.stat(entry.path)
            is_dir = _is_dir(entry)
            # A signed record of this project, not just a file of that name.
            record = _provenance.read(entry.path, project_id=project_id) \
                if is_dir and not entry.is_symlink() and os.path.isfile(os.path.join(entry.path, _provenance.FILENAME)) \
                else None
            row = {
                "name": entry.name,
                "path": str(Path(entry.path).relative_to(root)),
                "isDir": is_dir,
                "isSymlink": entry.is_symlink(),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
                "imported": record is not None,
            }
            if record is not None:
                facts = import_facts(record)
                row["importKind"] = facts["kind"]
                row["resyncable"] = facts["resyncable"]
            rows.append(row)
        except Exception as e:
            logger.warning(f"list_dir: skipped {entry.path}: {e}")
    return rows, len(entries)


def tree_for_project(project_id: str, path: str = ".", max_depth: int = 3, max_entries: int = 500) -> str:
    """ASCII tree as a single string (for the drawer's tree view)."""
    base = resolve_for_project(project_id, path)
    if not base.is_dir():
        raise ValueError(f"not a directory: {path}")
    root = (WORKSPACE_ROOT / project_id).resolve()

    rows = [(str(base.relative_to(root)) if base != root else ".") + "/"]
    count = [1]

    def _walk(p: Path, depth: int, prefix: str):
        if depth > max_depth or count[0] >= max_entries:
            return
        try:
            children = sorted(
                [c for c in p.iterdir() if not c.name.startswith(".") and c.name not in _SKIP_DIRS],
                key=lambda c: (not c.is_dir(), c.name.lower()),
            )
        except Exception:
            return
        for i, c in enumerate(children):
            if count[0] >= max_entries:
                rows.append(f"{prefix}└── [truncated at {max_entries} entries]")
                return
            last = i == len(children) - 1
            branch = "└── " if last else "├── "
            suffix = "/" if c.is_dir() else ""
            rows.append(f"{prefix}{branch}{c.name}{suffix}")
            count[0] += 1
            if c.is_dir():
                _walk(c, depth + 1, prefix + ("    " if last else "│   "))

    _walk(base, 1, "")
    return "\n".join(rows)


def download_for_project(project_id: str, path: str) -> tuple[bytes, str]:
    """Returns (content_bytes, mime_type). Raises ValueError on bad path."""
    full = resolve_for_project(project_id, path)
    if not full.is_file():
        raise ValueError(f"not a file: {path}")
    mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
    return full.read_bytes(), mime


def project_relative(project_id: str, user_path: Optional[str], follow_symlinks: bool = False) -> str:
    """`user_path` (relative or absolute) as a normalized project-relative path,
    '.' for the root. Raises ValueError when it escapes the project."""
    full = resolve_for_project(project_id, user_path, follow_symlinks=follow_symlinks)
    root = (WORKSPACE_ROOT / project_id).resolve()
    return "." if full == root else str(full.relative_to(root))


def check_not_busy(project_id: str, user_path: Optional[str]) -> None:
    """Refuse a mutation a running import would undo (workspace_import.busy).
    Both the path as written and where its symlinks lead are checked; any error
    in the check refuses."""
    try:
        for follow in (False, True):
            try:
                rel = project_relative(project_id, user_path, follow_symlinks=follow)
            except ValueError:
                continue
            _busy.check_mutation(project_id, rel)
    except Exception as e:
        if getattr(e, "code", None) == "busy":
            raise
        raise _busy.ImportFailure("busy", detail="unknown") from None


def open_download_for_project(project_id: str, path: str) -> tuple[int, int, str, str]:
    """Open a workspace file for streaming: (fd, size, mime, filename).

    The descriptor checked is the descriptor streamed. The workspace is writable
    by the agent, kali-sandbox and the host, so a component swapped for a
    symlink between a check and a later open-by-path would escape: the last
    component is opened with O_NOFOLLOW, and the opened file's real path is
    checked against the project root. O_NONBLOCK keeps a FIFO from hanging the
    open; fstat then refuses anything that is not a regular file.
    """
    full = resolve_for_project(project_id, path)
    root = str((WORKSPACE_ROOT / project_id).resolve())
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError(f"not a file: {path}") from None
    try:
        st = os.fstat(fd)
        if not statlib.S_ISREG(st.st_mode):
            raise ValueError(f"not a file: {path}")
        real = os.readlink(f"/proc/self/fd/{fd}")
        if real != root and not real.startswith(root + os.sep):
            raise ValueError(f"path escapes workspace: {path}")
    except OSError:
        os.close(fd)
        raise ValueError(f"not a file: {path}") from None
    except BaseException:
        os.close(fd)
        raise
    mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
    return fd, st.st_size, mime, os.path.basename(str(full)) or "download"


def rename_for_project(project_id: str, path: str, new_name: str) -> str:
    """Rename a single entry within its parent dir. Returns new relative path."""
    if is_protected_path(path):
        raise ValueError(f"cannot rename protected path: {path}")
    if (not new_name or not new_name.strip() or "/" in new_name
            or "\x00" in new_name or new_name in ("..", ".")):
        raise ValueError(f"invalid new_name: {new_name!r}")
    full = resolve_for_project(project_id, path)
    if not (full.exists() or full.is_symlink()):
        raise ValueError(f"not found: {path}")
    new_full = full.parent / new_name
    # Re-validate the new path to be sure it stays in-workspace
    new_rel = str(new_full.relative_to((WORKSPACE_ROOT / project_id).resolve()))
    resolve_for_project(project_id, new_rel)
    check_not_busy(project_id, path)
    check_not_busy(project_id, new_rel)
    if new_full.exists() or new_full.is_symlink():
        raise ValueError(f"destination already exists: {new_name}")
    full.rename(new_full)
    root = (WORKSPACE_ROOT / project_id).resolve()
    return str(new_full.relative_to(root))


def delete_for_project(project_id: str, path: str, recursive: bool = False) -> None:
    if is_protected_path(path):
        raise ValueError(f"cannot delete protected path: {path}")
    full = resolve_for_project(project_id, path)
    if not (full.exists() or full.is_symlink()):
        raise ValueError(f"not found: {path}")
    check_not_busy(project_id, path)
    if full.is_dir() and not full.is_symlink():
        if not recursive:
            raise ValueError(f"{path} is a directory (pass recursive=True)")
        shutil.rmtree(full)
    else:
        full.unlink()


def reset_for_project(project_id: str) -> dict:
    """Wipe the entire workspace back to its initial state.

    Removes every entry under the project root, then re-creates the four
    PROTECTED_SUBDIRS empty. Returns a small summary so the caller can
    confirm what was removed.
    """
    root = _workspace_root_for(project_id).resolve()
    removed_entries = 0
    removed_protected_children = 0
    for child in list(root.iterdir()):
        name = child.name
        if name in PROTECTED_SUBDIRS and child.is_dir() and not child.is_symlink():
            for sub in list(child.iterdir()):
                if sub.is_dir() and not sub.is_symlink():
                    shutil.rmtree(sub)
                else:
                    sub.unlink()
                removed_protected_children += 1
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
        removed_entries += 1
    for sub in _DEFAULT_SUBDIRS:
        (root / sub).mkdir(exist_ok=True)
    return {
        "removed_top_level": removed_entries,
        "removed_protected_children": removed_protected_children,
        "default_subdirs": list(_DEFAULT_SUBDIRS),
    }


# =============================================================================
# Stage A additions: upload, mkdir, archive-download, preview, properties
# =============================================================================


def upload_for_project(
    project_id: str,
    dest_dir: str,
    file_bytes: bytes,
    filename: str,
    overwrite: bool = False,
) -> str:
    """Save uploaded file bytes into dest_dir under the given filename.

    Returns the new file's relative path.
    Raises ValueError on bad path/filename, FileExistsError if collision
    and overwrite=False.
    """
    if (not filename or "/" in filename or "\\" in filename
            or "\x00" in filename or filename in (".", "..")):
        raise ValueError(f"invalid filename: {filename!r}")
    full_dir = resolve_for_project(project_id, dest_dir)
    if not full_dir.is_dir():
        raise ValueError(f"not a directory: {dest_dir}")
    target = full_dir / filename
    # Inside a folder a Re-sync is replacing, the swap would delete this file.
    check_not_busy(project_id, posixpath.join(dest_dir or ".", filename))
    if (target.exists() or target.is_symlink()) and not overwrite:
        raise FileExistsError(f"{filename} already exists in {dest_dir}")
    # Atomic write (consistent with fs_write)
    tmp = target.with_suffix(target.suffix + ".upload-tmp")
    tmp.write_bytes(file_bytes)
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o666)
    except OSError:
        pass
    root = (WORKSPACE_ROOT / project_id).resolve()
    return str(target.relative_to(root))


def mkdir_for_project(project_id: str, path: str) -> str:
    """Create a new directory. Returns relative path.

    Raises ValueError if the path already exists.
    """
    if not path or path in (".", ".."):
        raise ValueError(f"invalid path: {path!r}")
    full = resolve_for_project(project_id, path)
    if full.exists() or full.is_symlink():
        raise ValueError(f"already exists: {path}")
    check_not_busy(project_id, path)
    full.mkdir(parents=True)
    try:
        os.chmod(full, 0o777)
    except OSError:
        pass
    root = (WORKSPACE_ROOT / project_id).resolve()
    return str(full.relative_to(root))


def bulk_archive_for_project(
    project_id: str,
    paths: list,
    format: str = "tar.gz",
    archive_name: str = "bundle",
) -> tuple:
    """Bundle multiple workspace entries (files or dirs) into ONE archive.

    Returns (bytes, suggested_filename). Used by the drawer's multi-select
    "Download N as zip" action. Skips symlinks for the same reason as
    archive_dir_for_project (bug #18 - tarball/zip exfiltration of target
    content). Tar entries map each path to its top-level arcname; dir
    contents are nested under that.
    """
    import io as _io
    resolved, filename = prepare_bulk_archive(project_id, paths, format, archive_name)
    buf = _io.BytesIO()
    write_bulk_archive(buf, resolved, format)
    return buf.getvalue(), filename


def prepare_bulk_archive(project_id: str, paths: list, format: str, archive_name: str) -> tuple[list, str]:
    """Validate a bulk download: (resolved paths, suggested filename)."""
    if format not in ("tar.gz", "zip"):
        raise ValueError(f"format must be tar.gz or zip, got {format!r}")
    if not isinstance(paths, list) or not paths:
        raise ValueError("paths must be a non-empty list")
    resolved = []
    for p in paths:
        full = resolve_for_project(project_id, p)
        if not (full.exists() or full.is_symlink()):
            raise ValueError(f"not found: {p}")
        resolved.append(full)
    return resolved, f"{archive_name}.{format}"


def _skip_symlinks(tarinfo):
    if tarinfo.issym() or tarinfo.islnk():
        return None
    return tarinfo


def write_bulk_archive(fileobj, resolved: list, format: str) -> None:
    if format == "tar.gz":
        with tarfile.open(fileobj=fileobj, mode="w:gz") as tf:
            for p in resolved:
                if p.is_symlink():
                    continue
                tf.add(p, arcname=p.name, filter=_skip_symlinks)
    else:
        with zipfile.ZipFile(fileobj, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in resolved:
                if p.is_symlink():
                    continue
                if p.is_dir():
                    for sub in p.rglob("*"):
                        if sub.is_symlink():
                            continue
                        if sub.is_file():
                            zf.write(sub, arcname=f"{p.name}/{sub.relative_to(p)}")
                else:
                    zf.write(p, arcname=p.name)


def archive_dir_for_project(
    project_id: str,
    path: str,
    format: str = "tar.gz",
) -> tuple:
    """Build an in-memory archive of a directory tree.

    Returns (bytes, suggested_filename).

    SECURITY (bug #18 regression): skip symlinks entirely. Without this,
    zipfile.write() follows symlinks - reading the TARGET's content and
    storing it under the symlink's name. A symlink inside the workspace
    pointing at /etc/passwd would otherwise leak through the archive
    download endpoint to anyone with project access.

    Tar's add() stores symlinks as link entries by default (no content
    leak), but we apply the same skip filter to both formats for
    consistency and defense in depth.
    """
    import io as _io
    src, name, filename = prepare_dir_archive(project_id, path, format)
    buf = _io.BytesIO()
    write_dir_archive(buf, src, name, format)
    return buf.getvalue(), filename


def prepare_dir_archive(project_id: str, path: str, format: str) -> tuple[Path, str, str]:
    """Validate a folder download: (source dir, top-level name, suggested filename)."""
    if format not in ("tar.gz", "zip"):
        raise ValueError(f"format must be tar.gz or zip, got {format!r}")
    src = resolve_for_project(project_id, path)
    if not src.is_dir():
        raise ValueError(f"not a directory: {path}")
    name = src.name or project_id
    return src, name, f"{name}.{format}"


def write_dir_archive(fileobj, src: Path, name: str, format: str) -> None:
    if format == "tar.gz":
        with tarfile.open(fileobj=fileobj, mode="w:gz") as tf:
            tf.add(src, arcname=name, filter=_skip_symlinks)
    else:
        with zipfile.ZipFile(fileobj, "w", zipfile.ZIP_DEFLATED) as zf:
            for sub in src.rglob("*"):
                # Skip symlinks: zf.write would follow and leak target content
                if sub.is_symlink():
                    continue
                if sub.is_file():
                    zf.write(sub, arcname=str(sub.relative_to(src.parent)))


_ARCHIVE_ENTRY_OVERHEAD = 1024  # a tar header block plus padding, per entry


def tree_bytes(paths: list) -> int:
    """An upper bound for an archive of `paths` (symlinks not followed): the
    regular files' bytes plus a header's worth per entry. Sizes the disk
    reservation of an archive build."""
    total = 0
    for p in paths:
        p = Path(p)
        if p.is_symlink():
            continue
        if p.is_file():
            total += p.stat().st_size + _ARCHIVE_ENTRY_OVERHEAD
            continue
        for dirpath, dirs, files in os.walk(p):
            total += _ARCHIVE_ENTRY_OVERHEAD * (1 + len(dirs))
            for f in files:
                try:
                    st = os.lstat(os.path.join(dirpath, f))
                except OSError:
                    continue
                if statlib.S_ISREG(st.st_mode):
                    total += st.st_size + _ARCHIVE_ENTRY_OVERHEAD
    return total


PREVIEW_MAX_BYTES = 1024 * 1024  # 1 MiB - default preview cap


def preview_for_project(
    project_id: str,
    path: str,
    max_bytes: int = PREVIEW_MAX_BYTES,
) -> dict:
    """Return file content suitable for inline rendering.

    Shape: {content, isBinary, truncated, mime, size, lines?}
    - text: content is the UTF-8 decoded string, truncated at max_bytes
    - binary: content is base64 of the first max_bytes
    """
    full = resolve_for_project(project_id, path)
    if not full.is_file():
        raise ValueError(f"not a file: {path}")
    size = full.stat().st_size
    truncated = size > max_bytes
    with full.open("rb") as f:
        raw = f.read(max_bytes)
    mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
    is_bin = _is_binary(raw)
    if is_bin:
        content = base64.b64encode(raw).decode("ascii")
    else:
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="replace")
    return {
        "path": path,
        "content": content,
        "isBinary": is_bin,
        "truncated": truncated,
        "mime": mime,
        "size": size,
    }


def properties_for_project(project_id: str, path: str) -> dict:
    """Return rich metadata for a path - used by the properties popover.

    Shape: {path, type, size, mtime, mode, sha256?, target?}
    """
    full = resolve_for_project(project_id, path, follow_symlinks=False)
    if not (full.exists() or full.is_symlink()):
        raise ValueError(f"not found: {path}")
    st = full.stat() if full.exists() else full.lstat()
    if full.is_symlink():
        kind = "symlink"
    elif full.is_dir():
        kind = "dir"
    else:
        kind = "file"
    props = {
        "path": path,
        "type": kind,
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        "mode": oct(st.st_mode & 0o7777),
    }
    if full.is_file():
        h = hashlib.sha256()
        with full.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        props["sha256"] = h.hexdigest()
    if full.is_symlink():
        props["target"] = os.readlink(full)
    if kind == "dir":
        record = _provenance.read(full, project_id=project_id)
        if record is not None:
            props["import"] = import_facts(record)
    return props


def import_facts(record: dict) -> dict:
    """What the Properties popover shows about an import, every field sanitized."""
    source = record.get("source") if isinstance(record.get("source"), dict) else {}

    def text(value, limit=200):
        value = "" if value is None else str(value)
        return "".join(ch if ch.isprintable() else "?" for ch in value)[:limit]

    try:
        source_path = urllib.parse.urlsplit(str(source.get("url") or "")).path
    except ValueError:
        source_path = ""
    commit = text(source.get("commit"), 64)
    return {
        "kind": text(source.get("kind"), 40),
        "host": text(source.get("host"), 255),
        "sourcePath": text(source_path, 500),
        "ref": text(source.get("ref"), 255),
        "commit7": commit[:7],
        "fetchedAt": text(record.get("fetchedAt"), 40),
        "resyncable": bool(record.get("resyncable")),
    }


DISPATCH = {
    # Read
    "fs_read": fs_read,
    "fs_read_many": fs_read_many,
    "fs_stat": fs_stat,
    # Write & Mutate
    "fs_write": fs_write,
    "fs_edit": fs_edit,
    "fs_multi_edit": fs_multi_edit,
    "fs_undo_edit": fs_undo_edit,
    "fs_delete": fs_delete,
    "fs_move": fs_move,
    "fs_copy": fs_copy,
    "fs_mkdir": fs_mkdir,
    "fs_chmod": fs_chmod,
    "fs_symlink_create": fs_symlink_create,
    # Search & Navigate
    "fs_grep": fs_grep,
    "fs_glob": fs_glob,
    "fs_find": fs_find,
    "fs_list": fs_list,
    "fs_tree": fs_tree,
    "fs_symbols": fs_symbols,
    "fs_symlink_read": fs_symlink_read,
    # Integrity & Archive
    "fs_hash": fs_hash,
    "fs_diff": fs_diff,
    "fs_extract": fs_extract,
    "fs_archive": fs_archive,
}

FS_TOOL_NAMES = frozenset(DISPATCH.keys())

# For each mutating fs_* tool, the arguments that name a path it writes,
# deletes or moves. The executor's single fs chokepoint refuses those paths
# while a running import is replacing them (workspace_import.busy). Every
# DISPATCH key is in exactly one of these two tables; a test enforces it, so a
# new tool cannot skip the check silently.
FS_TOOL_WRITE_ARGS: dict[str, tuple[str, ...]] = {
    "fs_write": ("path",),
    "fs_edit": ("path",),
    "fs_multi_edit": ("path",),
    "fs_undo_edit": ("path",),
    "fs_chmod": ("path",),
    "fs_delete": ("path",),
    "fs_move": ("src", "dst"),
    "fs_copy": ("dst",),
    "fs_mkdir": ("path",),
    "fs_symlink_create": ("linkname",),
    "fs_extract": ("dest",),
    "fs_archive": ("dest",),
}
FS_TOOL_READ_ONLY = frozenset({
    "fs_read", "fs_read_many", "fs_stat", "fs_grep", "fs_glob", "fs_find", "fs_list",
    "fs_tree", "fs_symbols", "fs_symlink_read", "fs_hash", "fs_diff",
})

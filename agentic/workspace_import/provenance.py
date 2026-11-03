""".import.json: the signed record of where an imported folder came from.

It decides the "imported" badge, the URL a Re-sync fetches and the facts the
agent's prompt shows. Users, the agent's fs_* tools, kali-sandbox shell
commands and the host can all write files in the workspace, so refusing the
name in some writers could never make the file trustworthy: it is signed with
a key derived from INTERNAL_API_KEY, which kali-sandbox does not hold, and bound
to its project. Every reader ignores a record that does not verify; a renamed
or moved folder keeps its record, a copy in another project does not.

Stdlib only: the prompt builder imports this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import uuid
from collections import deque
from pathlib import Path
from typing import Optional

from workspace_import.errors import ImportFailure

FILENAME = ".import.json"
VERSION = 1
MAX_BYTES = 64 * 1024
IMPORTER = "redamon-workspace-import/1"
KNOWN_KEYS = ("version", "source", "options", "fetchedAt", "stats", "resyncable", "importer",
              "projectId", "importId")
# The compose fallback for INTERNAL_API_KEY (llm_guard._CHANGEME): a key
# everybody knows signs nothing.
_WEAK_KEYS = ("", "changeme")
_KEY_LABEL = b"redamon-workspace-provenance-v1"


def _key() -> Optional[bytes]:
    master = os.environ.get("INTERNAL_API_KEY", "")
    if master in _WEAK_KEYS:
        return None
    return hmac.new(master.encode(), _KEY_LABEL, hashlib.sha256).digest()


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(key: bytes, record: dict) -> str:
    return hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()


def write(folder, record: dict, *, project_id: str) -> dict:
    """Sign `record` for `project_id` and write it into `folder`. Returns the
    record as stored (with projectId, importId and version)."""
    key = _key()
    if key is None:
        raise ImportFailure("internal_error", detail="weak INTERNAL_API_KEY")
    stored = dict(record, version=VERSION, projectId=project_id, importId=uuid.uuid4().hex)
    stored.setdefault("importer", IMPORTER)
    payload = dict(stored, sig=_sign(key, stored))
    folder = Path(folder)
    tmp = folder / (FILENAME + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
    os.fchmod(fd, 0o666)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2))
    os.replace(tmp, folder / FILENAME)
    return stored


def read(folder, *, project_id: str) -> Optional[dict]:
    """The verified record of `folder`, or None for anything that does not verify."""
    key = _key()
    if key is None:
        return None
    path = Path(folder) / FILENAME
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_BYTES:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("version") != VERSION:
        return None
    sig = data.pop("sig", None)
    if not isinstance(sig, str) or not hmac.compare_digest(sig, _sign(key, data)):
        return None
    if data.get("projectId") != project_id:
        return None
    return {k: data[k] for k in KNOWN_KEYS if k in data}


def is_imported_dir(path, *, project_id: str) -> bool:
    return (Path(path) / FILENAME).is_file() and read(path, project_id=project_id) is not None


def find_imports(root, *, project_id: str, max_depth: int = 3, max_dirs: int = 300,
                 skip: tuple = ("jobs", "tool-outputs")) -> list[tuple[str, dict]]:
    """(relative path, record) for every imported folder under `root`, found by
    a bounded walk that follows no symlink and never descends into an import."""
    root = Path(root)
    found: list[tuple[str, dict]] = []
    queue = deque([(root, 0)])
    visited = 0
    while queue and visited < max_dirs:
        folder, depth = queue.popleft()
        visited += 1
        if folder != root:
            record = read(folder, project_id=project_id) if (folder / FILENAME).is_file() else None
            if record is not None:
                found.append((str(folder.relative_to(root)), record))
                continue
        if depth >= max_depth:
            continue
        try:
            children = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            continue
        for entry in children:
            if folder == root and entry.name in skip:
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    queue.append((Path(entry.path), depth + 1))
            except OSError:
                continue
    return found

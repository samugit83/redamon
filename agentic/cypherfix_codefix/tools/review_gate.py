"""The one gate every CodeFix file change goes through (GHSA-vhjw-gfmx-j3fx).

For each file, the pull request carries the repository's own version (HEAD) plus
the changes that passed this gate: accepted by a person when the project
requires approval, or as the edit tools made them when it does not. That content
lives in `state.committable`, and `_finalize` commits it, never the worktree as
it happens to be. The build sandbox mounts the worktree read-write, so a build,
a test or a dependency's install script can change any file there. None of that
reaches the PR, not even in a file a person already approved.

github_edit and github_write both call `propose_change`. The approval check used
to live in each tool, and github_write never had it: its changes reached the PR
unreviewed.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .repo_paths import RepoPathError, resolve_in_repo

logger = logging.getLogger(__name__)

_LANGUAGES = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
    '.tsx': 'typescript', '.jsx': 'javascript', '.java': 'java',
    '.go': 'go', '.rs': 'rust', '.rb': 'ruby', '.php': 'php',
    '.c': 'c', '.cpp': 'cpp', '.cs': 'csharp', '.sql': 'sql',
}


class ReviewError(Exception):
    """A file CodeFix cannot change or commit safely. The message names the file."""


@dataclass(frozen=True)
class ProposedChange:
    """A change written to disk and waiting for a person's decision."""

    path: str
    #: The reviewed content it replaces; None when the file did not exist.
    before: Optional[str]
    after: str


def language_for(path: str) -> str:
    return _LANGUAGES.get(Path(path).suffix, 'text')


def _head_content(repo_path: Path, rel: str) -> Optional[str]:
    """HEAD's version of `rel` as git checks it out, or None when HEAD has none.

    `--filters` applies line-ending conversion, so an untouched file compares
    equal to the worktree copy.
    """
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
             "cat-file", "--filters", f"HEAD:{rel}"],
            cwd=repo_path, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReviewError(f"Could not read the repository's version of {rel}.") from exc
    if result.returncode != 0:
        return None
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewError(f"{rel} is a binary file and cannot be edited.") from exc


def _disk_text(full_path: Path) -> Optional[str]:
    try:
        return full_path.read_text(encoding="utf-8") if full_path.is_file() else None
    except (OSError, UnicodeDecodeError):
        return None


def reviewed_content(state, rel: str, full_path: Path) -> Optional[str]:
    """The content a change to `rel` builds on, or None when there is no such file.

    That is its committable content once a change passed the gate, and before
    then HEAD's version, never the worktree's, which a build may have changed.
    A directory with no git history has nothing else to compare with, so there
    the content on disk is the reference.
    """
    if rel in state.committable:
        return state.committable[rel]
    if (Path(state.repo_path) / ".git").exists():
        return _head_content(Path(state.repo_path), rel)
    if not full_path.is_file():
        return None
    try:
        return full_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewError(f"{rel} is a binary file and cannot be edited.") from exc


def restore_if_drifted(full_path: Path, reviewed: str) -> bool:
    """Put back the reviewed content if something else changed the file. True if it had."""
    if _disk_text(full_path) == reviewed:
        return False
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(reviewed, encoding="utf-8")
    return True


async def propose_change(state, rel: str, full_path: Path, before: Optional[str],
                         after: str, block) -> None:
    """Write `after`, show `block`, and hold the change for review when approval is on."""
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(after, encoding="utf-8")
    state.files_modified.add(rel)
    state.diff_blocks.append(block)
    if state.settings.require_approval:
        state.block_backups[block.block_id] = ProposedChange(rel, before, after)
        state.pending_approval = True
        state.pending_block_id = block.block_id
    else:
        state.committable[rel] = after
    if state.streaming_callback:
        await state.streaming_callback.on_diff_block(block)


def _set_status(state, block_id: str, status: str) -> None:
    for block in state.diff_blocks:
        if block.block_id == block_id:
            block.status = status


def accept_change(state, block_id: Optional[str]) -> None:
    """A person accepted the block: its content is what the PR will carry."""
    change = state.block_backups.pop(block_id, None)
    if change is None:
        return
    state.committable[change.path] = change.after
    _set_status(state, block_id, "accepted")


def reject_change(state, block_id: Optional[str]) -> None:
    """A person rejected the block (or nobody answered): undo it on disk.

    The commit does not depend on this write succeeding: `prepare_commit` stages
    committable content only, and a rejected change never became committable.
    """
    change = state.block_backups.pop(block_id, None)
    if change is None:
        return
    if change.path not in state.committable:
        state.files_modified.discard(change.path)
    _set_status(state, block_id, "rejected")
    try:
        full_path = resolve_in_repo(state.repo_path, change.path, allow_root=False)
        if change.before is None:
            full_path.unlink(missing_ok=True)
        else:
            full_path.write_text(change.before, encoding="utf-8")
    except (OSError, RepoPathError) as exc:
        logger.error(f"Could not undo rejected block {block_id} on disk: {exc}")


def prepare_commit(state) -> tuple[list[str], list[str]]:
    """Write each committable file's reviewed content back; return (to stage, restored).

    `restored` names the files something outside the edit tools had changed
    since review. Raises ReviewError for a file that is now reached through a
    symbolic link or is no longer a file, rather than commit what it points at.
    """
    base = Path(state.repo_path).resolve()
    staged, restored = [], []
    for rel in sorted(state.committable):
        try:
            full_path = resolve_in_repo(state.repo_path, rel, allow_root=False)
        except (RepoPathError, OSError, RuntimeError) as exc:
            raise ReviewError(f"{rel} can no longer be committed safely: {exc}") from exc
        if full_path != base / rel:
            raise ReviewError(f"{rel} is now reached through a symbolic link; refusing to commit it.")
        if full_path.exists() and not full_path.is_file():
            raise ReviewError(f"{rel} is no longer a file; refusing to commit it.")
        if restore_if_drifted(full_path, state.committable[rel]):
            restored.append(rel)
        staged.append(rel)
    return staged, restored

"""Edit tool: exact string replacement with diff block generation."""

from uuid import uuid4
from ..state import DiffBlock
from .repo_paths import RepoPathError, repo_relative, resolve_in_repo
from .review_gate import (
    ReviewError, language_for, propose_change, restore_if_drifted, reviewed_content,
)

_DRIFT_NOTE = (
    "Note: {path} had changes made outside github_edit/github_write (for example "
    "by a github_bash command). They were never reviewed, so they were removed: "
    "the file holds its reviewed content{suffix}."
)


async def github_edit(state, file_path: str, old_string: str,
                      new_string: str, replace_all: bool = False) -> str:
    """Exact string replacement in a file. Mirrors Claude Code's Edit tool."""
    try:
        full_path = resolve_in_repo(state.repo_path, file_path, allow_root=False)
    except RepoPathError as exc:
        return f"Error: {exc}"
    rel = repo_relative(state.repo_path, full_path)

    # The edit applies to the reviewed content, not to the worktree, which the
    # build sandbox can change (review_gate).
    try:
        content = reviewed_content(state, rel, full_path)
    except ReviewError as exc:
        return f"Error: {exc}"
    if content is None:
        if full_path.is_file():
            return (
                f"Error: {file_path} is not part of the repository (a build may have "
                "generated it). Only tracked files and files created with github_write "
                "can be edited."
            )
        return f"Error: File not found: {file_path}. Use github_glob to find the correct path."

    if rel not in state.files_read:
        return (
            f"Error: You must read {file_path} before editing it. "
            "Use github_read first to see the current content."
        )

    drifted = restore_if_drifted(full_path, content)

    if old_string not in content:
        if drifted:
            return "Error: " + _DRIFT_NOTE.format(path=rel, suffix="") + (
                " Use github_read to see it, then retry with the exact text from the file."
            )
        return (
            f"Error: old_string not found in {file_path}. "
            "The file content may have changed. Use github_read to see the current content, "
            "then retry with the exact text from the file."
        )

    if old_string == new_string:
        return "Error: new_string is identical to old_string. No changes made."

    occurrences = content.count(old_string)
    if occurrences > 1 and not replace_all:
        return (
            f"Error: old_string found {occurrences} times in {file_path}. "
            "Provide more surrounding context to make it unique, "
            "or set replace_all=True to replace all occurrences."
        )

    new_content = content.replace(old_string, new_string, -1 if replace_all else 1)
    diff_block = _generate_diff_block(
        rel, old_string, new_string, content, new_content, state,
    )
    await propose_change(state, rel, full_path, content, new_content, diff_block)

    replaced = occurrences if replace_all else 1
    message = (
        f"Successfully replaced {replaced} occurrence(s) in {file_path}. "
        f"Diff block {diff_block.block_id} streamed to user for review."
    )
    if drifted:
        message += "\n" + _DRIFT_NOTE.format(path=rel, suffix=" plus this edit")
    return message


def _generate_diff_block(file_path, old_string, new_string,
                         old_content, new_content, state):
    """Generate a structured diff block with context lines."""
    old_lines = old_content.splitlines(keepends=True)

    # Find the start line of old_string
    char_pos = old_content.index(old_string)
    start_line = old_content[:char_pos].count('\n') + 1
    end_line = start_line + old_string.count('\n')

    # Extract context (3 lines before and after)
    context_lines = 3
    ctx_start = max(0, start_line - 1 - context_lines)
    ctx_end = min(len(old_lines), end_line + context_lines)

    context_before = ''.join(old_lines[ctx_start:start_line - 1])
    context_after = ''.join(old_lines[end_line:ctx_end])

    return DiffBlock(
        block_id=f"block-{uuid4().hex[:8]}",
        file_path=file_path,
        language=language_for(file_path),
        old_code=old_string,
        new_code=new_string,
        context_before=context_before,
        context_after=context_after,
        start_line=start_line,
        end_line=end_line,
        description="",
        status="pending",
    )

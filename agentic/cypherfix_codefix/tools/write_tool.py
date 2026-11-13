"""Write tool: create or overwrite a whole file, held for review like an edit."""

from uuid import uuid4
from ..state import DiffBlock
from .repo_paths import RepoPathError, repo_relative, resolve_in_repo
from .review_gate import ReviewError, language_for, propose_change, reviewed_content


async def github_write(state, file_path: str, content: str) -> str:
    """Create or overwrite a file. The whole file is shown for review."""
    try:
        full_path = resolve_in_repo(state.repo_path, file_path, allow_root=False)
    except RepoPathError as exc:
        return f"Error: {exc}"
    rel = repo_relative(state.repo_path, full_path)

    if full_path.is_dir():
        return f"Error: {file_path} is a directory."
    try:
        before = reviewed_content(state, rel, full_path)
    except ReviewError as exc:
        return f"Error: {exc}"
    if before == content:
        return f"Error: {file_path} already has this content. No changes made."

    block = _whole_file_block(rel, before, content)
    await propose_change(state, rel, full_path, before, content, block)
    line_count = content.count('\n') + 1
    return (
        f"Successfully wrote {file_path} ({line_count} lines). "
        f"Diff block {block.block_id} streamed to user for review."
    )


def _whole_file_block(rel: str, before, after: str) -> DiffBlock:
    old = before or ""
    return DiffBlock(
        block_id=f"block-{uuid4().hex[:8]}",
        file_path=rel,
        language=language_for(rel),
        old_code=old,
        new_code=after,
        context_before="",
        context_after="",
        start_line=1,
        end_line=max(1, len(old.splitlines())),
        description="New file" if before is None else "Replaces the whole file",
        status="pending",
    )

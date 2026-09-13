"""Edit tool: exact string replacement with diff block generation."""

from pathlib import Path
from uuid import uuid4
from ..state import DiffBlock
from .repo_paths import RepoPathError, resolve_in_repo


async def github_edit(state, file_path: str, old_string: str,
                      new_string: str, replace_all: bool = False) -> str:
    """Exact string replacement in a file. Mirrors Claude Code's Edit tool."""
    try:
        full_path = resolve_in_repo(state.repo_path, file_path, allow_root=False)
    except RepoPathError as exc:
        return f"Error: {exc}"

    if not full_path.exists() or not full_path.is_file():
        return f"Error: File not found: {file_path}. Use github_glob to find the correct path."

    if file_path not in state.files_read:
        return (
            f"Error: You must read {file_path} before editing it. "
            "Use github_read first to see the current content."
        )

    content = full_path.read_text(encoding='utf-8')

    if old_string not in content:
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

    # Perform replacement
    new_content = content.replace(old_string, new_string, -1 if replace_all else 1)
    full_path.write_text(new_content, encoding='utf-8')
    was_modified = file_path in state.files_modified
    state.files_modified.add(file_path)

    # Generate diff block
    diff_block = _generate_diff_block(
        file_path, old_string, new_string, content, new_content, state,
    )
    state.diff_blocks.append(diff_block)
    state.block_backups[diff_block.block_id] = (file_path, content, was_modified)

    # Stream diff block to frontend
    if state.streaming_callback:
        await state.streaming_callback.on_diff_block(diff_block)

    # If approval required, mark as pending
    if state.settings.require_approval:
        state.pending_approval = True
        state.pending_block_id = diff_block.block_id

    replaced = occurrences if replace_all else 1
    return (
        f"Successfully replaced {replaced} occurrence(s) in {file_path}. "
        f"Diff block {diff_block.block_id} streamed to user for review."
    )


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

    # Detect language from file extension
    ext_to_lang = {
        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
        '.tsx': 'typescript', '.jsx': 'javascript', '.java': 'java',
        '.go': 'go', '.rs': 'rust', '.rb': 'ruby', '.php': 'php',
        '.c': 'c', '.cpp': 'cpp', '.cs': 'csharp', '.sql': 'sql',
    }
    ext = Path(file_path).suffix
    language = ext_to_lang.get(ext, 'text')

    return DiffBlock(
        block_id=f"block-{uuid4().hex[:8]}",
        file_path=file_path,
        language=language,
        old_code=old_string,
        new_code=new_string,
        context_before=context_before,
        context_after=context_after,
        start_line=start_line,
        end_line=end_line,
        description="",
        status="pending",
    )

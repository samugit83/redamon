"""Write tool: create or overwrite files."""

from .repo_paths import RepoPathError, resolve_in_repo


async def github_write(state, file_path: str, content: str) -> str:
    """Create or overwrite a file."""
    try:
        full_path = resolve_in_repo(state.repo_path, file_path, allow_root=False)
    except RepoPathError as exc:
        return f"Error: {exc}"

    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(content, encoding='utf-8')
    state.files_modified.add(file_path)
    line_count = content.count('\n') + 1
    return f"Successfully wrote {file_path} ({line_count} lines)."

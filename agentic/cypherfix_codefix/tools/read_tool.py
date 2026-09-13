"""Read tool: file reading with line numbers."""

from .repo_paths import RepoPathError, resolve_in_repo


async def github_read(state, file_path: str, offset: int = None, limit: int = None) -> str:
    """Read a file with line numbers (cat -n format)."""
    try:
        full_path = resolve_in_repo(state.repo_path, file_path, allow_root=False)
    except RepoPathError as exc:
        return f"Error: {exc}"

    if not full_path.exists() or not full_path.is_file():
        return f"Error: File not found: {file_path}. Use github_glob to find the correct path."

    try:
        content = full_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        return f"Error: {file_path} appears to be a binary file."

    lines = content.splitlines()
    total_lines = len(lines)

    start = (offset - 1) if offset and offset > 0 else 0
    end = start + (limit if limit else 2000)
    selected = lines[start:end]

    max_line_num = start + len(selected)
    width = len(str(max_line_num))
    formatted = []
    for i, line in enumerate(selected, start=start + 1):
        if len(line) > 2000:
            line = line[:2000] + " [LINE TRUNCATED]"
        formatted.append(f"{i:>{width}}\t{line}")

    output = '\n'.join(formatted)

    # Track that this file has been read (for edit pre-check)
    state.files_read.add(file_path)

    if total_lines > len(selected):
        output = (
            f"[{file_path}: showing lines {start + 1}-{start + len(selected)} "
            f"of {total_lines} total]\n{output}"
        )

    return output

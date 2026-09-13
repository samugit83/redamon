"""List directory tool."""

from .repo_paths import RepoPathError, resolve_in_repo


async def github_list_dir(state, path: str = ".") -> str:
    """List directory contents with type indicators."""
    try:
        target = resolve_in_repo(state.repo_path, path)
    except RepoPathError as exc:
        return f"Error: {exc}"

    if not target.is_dir():
        return f"Error: Not a directory: {path}"

    entries = sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name))
    results = []
    for entry in entries[:200]:
        try:
            rel = entry.relative_to(state.repo_path)
            prefix = "dir  " if entry.is_dir() else "     "
            results.append(f"{prefix}{rel}")
        except ValueError:
            results.append(str(entry))

    output = '\n'.join(results)
    total = len(list(target.iterdir()))
    if total > 200:
        output += f"\n\n[Showing first 200 of {total} entries]"
    return output

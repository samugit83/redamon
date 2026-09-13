"""Glob tool: find files by pattern."""

from .repo_paths import RepoPathError, resolve_in_repo


async def github_glob(state, pattern: str, path: str = None) -> str:
    """Find files matching a glob pattern. Sorted by modification time."""
    try:
        base = resolve_in_repo(state.repo_path, path)
    except RepoPathError as exc:
        return f"Error: {exc}"

    if not base.exists():
        return f"Error: Directory not found: {path or '.'}"

    matches = sorted(
        base.glob(pattern),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    if not matches:
        return f"No files matching pattern: {pattern}"

    results = []
    for m in matches[:500]:
        try:
            rel = m.relative_to(state.repo_path)
            results.append(str(rel))
        except ValueError:
            results.append(str(m))

    output = '\n'.join(results)
    if len(matches) > 500:
        output += f"\n\n[Showing first 500 of {len(matches)} matches]"
    return output

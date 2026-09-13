"""Grep tool: ripgrep-based content search."""

import subprocess

from .repo_paths import RepoPathError, resolve_in_repo


async def github_grep(state, pattern: str, path: str = ".", glob: str = None,
                      type: str = None, output_mode: str = "files_with_matches",
                      context: int = 0, case_insensitive: bool = False,
                      multiline: bool = False, head_limit: int = 50) -> str:
    """Search file contents using ripgrep."""
    try:
        target = resolve_in_repo(state.repo_path, path)
    except RepoPathError as exc:
        return f"Error: {exc}"

    repo_path = target.parent if target.is_file() else target
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
    cmd.append(str(target))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=str(repo_path),
        )
    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 30 seconds."

    if result.returncode == 1:
        return "No matches found."
    if result.returncode > 1:
        return f"Error: ripgrep failed: {result.stderr.strip()}"

    lines = result.stdout.strip().split('\n')
    if len(lines) > head_limit:
        lines = lines[:head_limit]
        lines.append(f"\n[Results truncated — showing first {head_limit}]")

    repo_prefix = str(repo_path) + '/'
    output = '\n'.join(line.replace(repo_prefix, '') for line in lines)
    return output or "No matches found."

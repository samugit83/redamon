from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()


def load_document(source_path: str, project_root: Path | str = None) -> str:
    """
    Load the full source document for a chunk.

    Args:
        source_path: Project-relative POSIX path stored on the chunk's
            `source_path` property.
        project_root: Override the default project root (the redamon/
            directory). Useful for tests and alternate deployments.

    Returns:
        The full file contents as a string (UTF-8, decoding errors
        replaced rather than raised).

    Raises:
        ValueError: source_path is empty/None or escapes project_root via
            traversal (`..` or absolute paths that resolve outside).
        FileNotFoundError: the resolved file doesn't exist on disk.
    """
    if not source_path:
        raise ValueError("source_path is empty or None")

    root = Path(project_root).resolve() if project_root else _PROJECT_ROOT

    # Resolve and verify the result is still under root. This catches both
    # raw `..` segments and absolute paths that point outside the project.
    candidate = (root / source_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ValueError(
            f"source_path {source_path!r} escapes project root {root}"
        )

    if not candidate.is_file():
        raise FileNotFoundError(
            f"Document not found at {candidate} (source_path={source_path!r})"
        )

    return candidate.read_text(encoding="utf-8", errors="replace")


def to_source_path(absolute_path, project_root: Path | str = None) -> str:
    """
    Convert an absolute filesystem path to a project-relative source_path.

    Used by curation clients that read source files via absolute paths
    (tool_docs reads from `agentic/skills/...`, etc.) to compute the
    string they store on each chunk's `source_path` property.

    Args:
        absolute_path: Absolute path to the source file. Can be a Path
            or a string. Need not currently exist.
        project_root: Override the default project root. Same semantics
            as `load_document`.

    Returns:
        POSIX-style project-relative path string. Empty string if the
        path is not under project_root (caller decides whether to log).
    """
    root = Path(project_root).resolve() if project_root else _PROJECT_ROOT
    try:
        rel = Path(absolute_path).resolve().relative_to(root)
    except (ValueError, OSError):
        return ""
    return rel.as_posix()

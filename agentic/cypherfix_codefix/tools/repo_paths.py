"""Confine every model-supplied path to the checked-out repository.

The codefix agent is steered by remediation text that ultimately comes from
scanner output, so `file_path` is untrusted input. `repo_path / file_path`
alone is not a boundary: an absolute path replaces the base entirely, and
`../` walks out of it into the agent container, where the environment holds
NEO4J_PASSWORD, INTERNAL_API_KEY and DATABASE_URL.

Every tool that turns a model string into a filesystem path goes through
`resolve_in_repo`. Symlinks are resolved before the containment check, so a
link committed inside the repo cannot be used as the escape hatch.
"""

from __future__ import annotations

from pathlib import Path


class RepoPathError(ValueError):
    """A model-supplied path pointed outside the repository."""


def resolve_in_repo(repo_path, relative: str | None, *, allow_root: bool = True) -> Path:
    """Resolve `relative` under `repo_path` and refuse anything outside it.

    Raises:
        RepoPathError: the path escapes the repo, or it is empty when the repo
            root itself is not an acceptable answer.
    """
    if repo_path is None:
        raise RepoPathError("No repository is checked out.")

    base = Path(repo_path).resolve()
    text = (relative or "").strip()

    if not text:
        if allow_root:
            return base
        raise RepoPathError("A file path is required.")

    candidate = Path(text)
    if candidate.is_absolute():
        raise RepoPathError(
            f"Path '{text}' is absolute. Use a path relative to the repository root."
        )

    resolved = (base / candidate).resolve()
    if resolved != base and base not in resolved.parents:
        raise RepoPathError(
            f"Path '{text}' resolves outside the repository and was refused."
        )
    return resolved


def repo_relative(repo_path, resolved: Path) -> str:
    """The repo-relative spelling of an already-confined path."""
    base = Path(repo_path).resolve()
    if resolved == base:
        return "."
    return str(resolved.relative_to(base))

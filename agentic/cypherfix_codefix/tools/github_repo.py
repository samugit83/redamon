"""GitHubRepoManager: clone, branch, commit, push, create PR.

Security (T6/E10/T7):
  * Clones into the shared CodeFix work dir (`<work>/<job>/repo`) so the build
    sandbox can mount the worktree; `.git` is mounted read-only into the sandbox.
  * The GitHub token is supplied via GIT_ASKPASS, NEVER embedded in the clone/push
    URL, so it never lands in `.git/config` (which the sandbox can read).
  * All git invocations disable hooks (`core.hooksPath=/dev/null`) so a malicious
    build cannot plant a hook that runs when the agent commits/pushes.
  * `.git/config` must stay as the clone wrote it: commit and push refuse to run
    once it changed, every git call overrides the config keys that run a command
    or answer for the token, and the push names the GitHub URL instead of trusting
    `origin` (GHSA-vhjw-gfmx-j3fx). CodeFix tools cannot reach `.git` at all.
  * Commits stage ONLY the LLM's approved files, not `git add -A`, so build
    artifacts or files a malicious build slipped into the worktree never reach the PR.
  * Pushes are refused to the default branch / main / master.
"""

import hashlib
import logging
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Per-job worktrees live under the shared cypherfix-work volume so the orchestrator
# can bind them into the build sandbox. Falls back to the legacy path off-volume.
WORK_BASE = Path(os.environ.get("CODEFIX_WORK_BASE", "/app/codefix-work"))

#: git's stderr, reduced to a fixed cause a person may see. git exits 128 for a
#: bad token, a missing repository and a missing branch alike, and the stderr
#: itself names the remote URL, so neither can be shown as it is.
_GIT_CAUSES = (
    ("authentication failed", "auth_failed"),
    ("could not read username", "auth_failed"),
    ("invalid username or password", "auth_failed"),
    ("permission to", "permission_denied"),
    ("the requested url returned error: 403", "permission_denied"),
    ("repository not found", "repo_not_found"),
    ("not found in upstream", "branch_not_found"),
    ("could not resolve host", "network_error"),
    ("protected branch", "protected_branch"),
)


def git_failure_cause(stderr: str) -> str:
    """The fixed cause of a git failure, or "" when none is recognised."""
    lowered = (stderr or "").lower()
    for marker, cause in _GIT_CAUSES:
        if marker in lowered:
            return cause
    return ""


#: Config that no repository may override for the agent's own git commands.
#: fsmonitor: git runs a non-boolean value as a shell command when it refreshes
#: the index. An empty credential.helper resets the list, so only GIT_ASKPASS
#: answers for the token.
_FIXED_GIT_CONFIG = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "credential.helper=",
)


class GitConfigChanged(RuntimeError):
    """`.git/config` differs from what the clone wrote; git must not run with it."""


class GitCommandError(RuntimeError):
    """A git command that exited non-zero. The message keeps the (token-free)
    stderr for the log; `returncode` and `cause` are the parts safe to show."""

    def __init__(self, message: str, returncode: int, cause: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.cause = cause


class GitHubRepoManager:
    def __init__(self, token: str, repo: str, default_branch: str = "main",
                 job_id: str = "", branch_prefix: str = "cypherfix/"):
        self.token = token
        self.repo = repo  # owner/repo
        self.default_branch = default_branch
        self.branch_prefix = branch_prefix
        # Deterministic, sandbox-mountable location: <work>/<job>/repo
        self.work_dir = WORK_BASE / (job_id or repo.replace("/", "_"))
        self.repo_path: Optional[Path] = None
        self._askpass_path: Optional[str] = None
        self._config_sha: Optional[str] = None

    def _remote_url(self) -> str:
        # Username only in the URL (no secret); password comes from GIT_ASKPASS.
        return f"https://x-access-token@github.com/{self.repo}.git"

    def _config_digest(self) -> Optional[str]:
        try:
            return hashlib.sha256((self.repo_path / ".git" / "config").read_bytes()).hexdigest()
        except (OSError, TypeError):
            return None

    def _assert_config_untouched(self) -> None:
        if self._config_digest() != self._config_sha:
            raise GitConfigChanged(
                "The repository's .git/config changed during the run; refusing to run git with it."
            )

    # -- token handling -----------------------------------------------------

    def _ensure_askpass(self) -> str:
        """Write a GIT_ASKPASS helper (off the shared volume) that echoes the
        token from the environment. The token literal is never written to disk."""
        if self._askpass_path:
            return self._askpass_path
        fd, path = tempfile.mkstemp(prefix="cypherfix-askpass-", suffix=".sh")
        with os.fdopen(fd, "w") as f:
            f.write('#!/bin/sh\nexec echo "$GIT_PASS"\n')
        os.chmod(path, stat.S_IRWXU)  # 0700, agent-only
        self._askpass_path = path
        return path

    def _git_env(self) -> dict:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if self.token:
            env["GIT_ASKPASS"] = self._ensure_askpass()
            env["GIT_PASS"] = self.token
        return env

    def _run_git(self, args: list[str], **kwargs):
        """Run git with hooks disabled and the askpass-based credential env."""
        cmd = ["git", *_FIXED_GIT_CONFIG, *args]
        kwargs.setdefault("env", self._git_env())
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        return subprocess.run(cmd, **kwargs)

    def _sanitize(self, text: str) -> str:
        if self.token and text:
            return text.replace(self.token, "***")
        return text or ""

    # -- lifecycle ----------------------------------------------------------

    def clone(self, branch: str = None) -> Path:
        """Clone the repository into <work>/repo and make the worktree writable
        by the sandbox's non-root user."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        repo_dir = self.work_dir / "repo"

        clone_url = self._remote_url()
        args = ["clone", "--depth", "50"]
        if branch:
            args.extend(["-b", branch])
        args.extend([clone_url, str(repo_dir)])

        result = self._run_git(args, timeout=120)
        if result.returncode != 0:
            raise GitCommandError(f"Clone failed: {self._sanitize(result.stderr)}",
                                  result.returncode, git_failure_cause(result.stderr))

        # The sandbox runs as a non-root user (uid 1001) and bind-mounts this
        # worktree read-write; make it group/other-writable so installs succeed.
        # `.git` is mounted read-only into the sandbox regardless, so this does
        # not let a build tamper with history.
        try:
            subprocess.run(["chmod", "-R", "a+rwX", str(repo_dir)],
                           capture_output=True, text=True, timeout=60)
        except Exception as e:
            logger.warning(f"Could not relax worktree permissions: {e}")

        self.repo_path = repo_dir
        self._config_sha = self._config_digest()
        return repo_dir

    def create_branch(self, branch_name: str):
        """Create and switch to a new branch."""
        result = self._run_git(["checkout", "-b", branch_name], cwd=self.repo_path)
        if result.returncode != 0:
            raise GitCommandError(f"Branch create failed: {self._sanitize(result.stderr)}",
                                  result.returncode, git_failure_cause(result.stderr))
        # Still before the sandbox or the model exist: nothing untrusted ran yet.
        self._config_sha = self._config_digest()

    def commit(self, message: str, files: Optional[list[str]] = None):
        """Stage ONLY the approved files and commit.

        `files` are repo-relative paths (the LLM's reviewed edits). Staging just
        these — never `git add -A` — keeps build artifacts and any files a
        malicious build wrote into the worktree out of the PR.
        """
        files = [f for f in (files or []) if f]
        if not files:
            raise RuntimeError("commit called with no approved files")
        self._assert_config_untouched()

        add_result = self._run_git(["add", "--", *files], cwd=self.repo_path)
        if add_result.returncode != 0:
            raise RuntimeError(f"git add failed: {self._sanitize(add_result.stderr)}")

        env = {
            **self._git_env(),
            "GIT_AUTHOR_NAME": "CypherFix",
            "GIT_AUTHOR_EMAIL": "cypherfix@redamon.io",
            "GIT_COMMITTER_NAME": "CypherFix",
            "GIT_COMMITTER_EMAIL": "cypherfix@redamon.io",
        }
        commit_result = self._run_git(["commit", "-m", message], cwd=self.repo_path, env=env)
        if commit_result.returncode != 0:
            raise RuntimeError(f"git commit failed: {self._sanitize(commit_result.stderr)}")

    def push(self, branch_name: str):
        """Push branch to remote (force-push to handle re-runs on same branch).

        Refuses to target the default branch / main / master, and requires the
        configured fix-branch prefix, so a prompt-injected branch name cannot
        rewrite a protected branch (T7).
        """
        forbidden = {self.default_branch, "main", "master"}
        if branch_name in forbidden or (self.branch_prefix and not branch_name.startswith(self.branch_prefix)):
            raise RuntimeError(
                f"Refusing to push to disallowed branch {branch_name!r} "
                f"(must start with {self.branch_prefix!r} and not be {sorted(forbidden)})"
            )
        self._assert_config_untouched()
        ref = f"refs/heads/{branch_name}"
        result = self._run_git(["push", "--force", self._remote_url(), f"{ref}:{ref}"],
                               cwd=self.repo_path)
        if result.returncode != 0:
            stderr = self._sanitize(result.stderr)
            logger.error(f"Git push failed (exit {result.returncode}): {stderr}")
            raise GitCommandError(f"Git push failed: {stderr}", result.returncode,
                                  git_failure_cause(result.stderr))

    def create_pr(self, title: str, body: str, branch: str, base: str = None) -> dict:
        """Create a pull request via GitHub API, or update the existing one."""
        from github import Github, GithubException
        g = Github(self.token)
        repo = g.get_repo(self.repo)
        try:
            pr = repo.create_pull(
                title=title, body=body,
                head=branch, base=base or self.default_branch,
            )
        except GithubException as e:
            # PR already exists for this branch — find and update it
            if e.status == 422:
                existing = repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch}")
                pr = None
                for p in existing:
                    pr = p
                    break
                if pr is None:
                    raise RuntimeError(f"PR already exists but could not be found for branch {branch}")
                pr.edit(title=title, body=body)
                logger.info(f"Updated existing PR #{pr.number} for branch {branch}")
            else:
                raise
        return {
            "pr_url": pr.html_url,
            "pr_number": pr.number,
            "branch": branch,
            "title": title,
            "files_changed": pr.changed_files,
            "additions": pr.additions,
            "deletions": pr.deletions,
        }

    def cleanup(self):
        """Remove the cloned worktree and the askpass helper."""
        if self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
        if self._askpass_path and os.path.exists(self._askpass_path):
            try:
                os.unlink(self._askpass_path)
            except OSError:
                pass
            self._askpass_path = None

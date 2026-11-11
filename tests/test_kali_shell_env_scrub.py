"""
No service credential in a process the sandbox hands to a person or the agent (HD-18, NF-12).

Every process the kali-sandbox started for a person (the terminal PTY) or for the
agent (kali_shell, execute_code, proxy_brain, msfconsole, the playwright child and
every fixed-argv wrapper, whose arguments the agent controls: `execute_curl -d
@/proc/self/environ`) inherited the servers' whole environment, SCANNER_API_KEY,
MCP_AUTH_TOKEN and TUNNEL_AUTH_TOKEN included (step 0.2, E3). They now get
`mcp/servers/_safe_env.py`'s `safe_env()`: the inherited environment minus those
names and any *_KEY, *_TOKEN, *_SECRET, *_PASSWORD, plus only what the wrapper
adds on purpose. The AST guard at the end keeps a new wrapper from bringing the
leak back. SCANNER_API_KEY also leaves the kali-sandbox service in compose.

Runs in the agent image (root-agent section): real child processes for the
shells, captured environments for the wrappers whose binaries live only in kali.
Run: python -m pytest tests/test_kali_shell_env_scrub.py
"""
import ast
import asyncio
import json
import os
import subprocess
import sys
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SERVERS = REPO / "mcp" / "servers"
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

# fastmcp only ships in the kali image: an identity @mcp.tool() is enough here.
if "fastmcp" not in sys.modules:
    _fm = types.ModuleType("fastmcp")

    class _StubMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda fn: fn

        def run(self, *a, **k):
            pass

    _fm.FastMCP = _StubMCP
    sys.modules["fastmcp"] = _fm

import _safe_env  # noqa: E402
import metasploit_server  # noqa: E402
import network_recon_server as nrs  # noqa: E402
import nmap_server  # noqa: E402
import nuclei_server  # noqa: E402
import playwright_server  # noqa: E402
import redamon as redamon_sdk  # noqa: E402
import terminal_server  # noqa: E402
import tunnel_manager  # noqa: E402

# Obvious fakes. The first three are what E3 measured in the sandbox; the rest
# prove the suffix rule (any case) and that a credential left in the server's own
# environment never reaches a child that was not handed one explicitly.
SECRETS = {
    "SCANNER_API_KEY": "rbac-fake-scanner-key",
    "MCP_AUTH_TOKEN": "rbac-fake-mcp-token",
    "TUNNEL_AUTH_TOKEN": "rbac-fake-tunnel-token",
    "INTERNAL_API_KEY": "rbac-fake-internal-key",
    "RBAC_SERVICE_SECRET": "rbac-fake-secret",
    "RBAC_DB_PASSWORD": "rbac-fake-password",
    "rbac_lower_api_key": "rbac-fake-lower",
    "REDAMON_RUN_CREDENTIAL": "rbac-fake-leftover-credential",
}
KEPT = {
    "REDAMON_AGENT_URL": "http://agent:8080",
    "CAPTURE_PROXY_URL": "http://rbac-capture.invalid:8080",
    "RBAC_PLAIN_SETTING": "kept",
}


def _server_env(**extra):
    """os.environ as the sandbox servers see it: the secrets plus ordinary settings."""
    return mock.patch.dict(os.environ, {**SECRETS, **KEPT, **extra})


def _names(text):
    return {line.split("=", 1)[0].strip() for line in text.splitlines() if "=" in line}


class SafeEnvHelper(unittest.TestCase):
    def test_drops_the_service_tokens_and_every_secret_suffix(self):
        with _server_env():
            env = _safe_env.safe_env()
        for name in SECRETS:
            self.assertNotIn(name, env)
        for name, value in KEPT.items():
            self.assertEqual(env[name], value)
        self.assertIn("PATH", env)

    def test_what_the_wrapper_adds_on_purpose_is_kept(self):
        with _server_env():
            env = _safe_env.safe_env({"REDAMON_CTX": "tag", "REDAMON_RUN_CREDENTIAL": "mine", "PDCP_API_KEY": "own"})
        self.assertEqual((env["REDAMON_CTX"], env["REDAMON_RUN_CREDENTIAL"], env["PDCP_API_KEY"]),
                         ("tag", "mine", "own"))
        self.assertNotIn("SCANNER_API_KEY", env)

    def test_never_changes_the_servers_own_environment(self):
        with _server_env():
            _safe_env.safe_env({"RBAC_ADDED": "1"})
            self.assertEqual(os.environ["MCP_AUTH_TOKEN"], SECRETS["MCP_AUTH_TOKEN"])
            self.assertNotIn("RBAC_ADDED", os.environ)

    def test_secret_name_rule(self):
        for name in ("MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN", "SCANNER_API_KEY", "A_SECRET", "x_password",
                     "Github_Token", "REDAMON_RUN_CREDENTIAL"):
            self.assertTrue(_safe_env.is_secret_name(name), name)
        for name in ("PATH", "HOME", "KEYBOARD", "TOKENIZER", "REDAMON_CTX", "MSF_DATABASE_CONFIG",
                     "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"):
            self.assertFalse(_safe_env.is_secret_name(name), name)


class ShellsGivenToTheAgent(unittest.TestCase):
    """Real child processes: what the agent's own commands can read."""

    def test_kali_shell_child_has_none_of_the_keys(self):
        with _server_env():
            out = nrs.kali_shell("env")
        names = _names(out)
        self.assertIn("RBAC_PLAIN_SETTING", names, out[-500:])
        self.assertEqual(sorted(set(SECRETS) & names), [])
        for value in SECRETS.values():
            self.assertNotIn(value, out)

    def test_kali_shell_cannot_read_a_key_through_its_own_proc_entry(self):
        with _server_env():
            # Not `tr ... < /proc/self/environ`: bash opens that entry and then execs
            # tr over itself, and the entry of a replaced image reads empty.
            out = nrs.kali_shell("cat /proc/self/environ | tr '\\0' '\\n'")
        # The read happened: an ordinary setting of the same environment came back.
        self.assertIn("RBAC_PLAIN_SETTING=kept", out, out[-500:])
        for value in SECRETS.values():
            self.assertNotIn(value, out)

    def test_execute_code_child_has_none(self):
        code = "import os\nprint('\\n'.join(f'{k}={v}' for k, v in sorted(os.environ.items())))"
        with _server_env():
            out = nrs.execute_code(code, "python", f"rbac_env_{uuid.uuid4().hex}")
        self.assertIn("RBAC_PLAIN_SETTING=kept", out)
        self.assertEqual(sorted(set(SECRETS) & _names(out)), [])

    def test_execute_code_bash_child_has_none(self):
        with _server_env():
            out = nrs.execute_code("env", "bash", f"rbac_env_{uuid.uuid4().hex}")
        self.assertIn("RBAC_PLAIN_SETTING=kept", out)
        self.assertEqual(sorted(set(SECRETS) & _names(out)), [])

    def test_proxy_brain_keeps_redamon_ctx_and_its_run_credential_and_nothing_secret(self):
        # The child imports the SDK from the servers directory (the kali image has
        # it on PYTHONPATH; so does the test container, made explicit here).
        pythonpath = os.pathsep.join(p for p in (str(SERVERS), os.environ.get("PYTHONPATH", "")) if p)
        code = "import os, json\nprint('ENVJSON' + json.dumps(dict(os.environ)))"
        with _server_env(PYTHONPATH=pythonpath):
            out = nrs.proxy_brain(code, _redamon_ctx="rbac-ctx-tag", _redamon_run="rbac-run-credential")
        line = next((ln for ln in out.splitlines() if ln.startswith("ENVJSON")), None)
        self.assertIsNotNone(line, out[-800:])
        env = json.loads(line[len("ENVJSON"):])
        self.assertEqual(env.get("REDAMON_CTX"), "rbac-ctx-tag")
        self.assertEqual(env.get("REDAMON_RUN_CREDENTIAL"), "rbac-run-credential")
        self.assertEqual(sorted((set(SECRETS) - {"REDAMON_RUN_CREDENTIAL"}) & set(env)), [])
        self.assertEqual(env.get("REDAMON_AGENT_URL"), KEPT["REDAMON_AGENT_URL"])


class TheTerminalShell(unittest.TestCase):
    """A real PTY, as the person sees it: only the proxy's identity and credential."""

    def test_terminal_pty_has_none(self):
        start, end = b"ENV2START", b"ENV2END"
        # $((1+1)) so the markers are printed only by the shell, never by the PTY's echo.
        frames = ["echo ENV$((1+1))START; env; echo CRED=$REDAMON_RUN_CREDENTIAL:; echo ENV$((1+1))END\r"]

        class FakeWs:
            def __init__(self):
                self.sent = []
                self._frames = list(frames)

            async def recv(self):
                return json.dumps({"type": "init"})

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._frames:
                    return self._frames.pop(0)
                for _ in range(200):
                    if end in b"".join(self.sent):
                        break
                    await asyncio.sleep(0.05)
                raise StopAsyncIteration

            async def send(self, data):
                self.sent.append(data)

        ws = FakeWs()
        shell_env = {"REDAMON_USER_ID": "proxy-user", "REDAMON_PROJECT_ID": "proxy-project",
                     "REDAMON_RUN_CREDENTIAL": "rbac-terminal-credential"}
        with _server_env():
            asyncio.run(asyncio.wait_for(terminal_server._run_pty_session(ws, shell_env), timeout=20))
        output = b"".join(ws.sent)
        self.assertIn(end, output, output[-500:])
        printed = output.split(start, 1)[-1].split(end, 1)[0].decode("utf-8", "replace").replace("\r", "")
        names = _names(printed)
        self.assertIn("REDAMON_USER_ID", names, printed[-500:])
        self.assertIn("RBAC_PLAIN_SETTING", names)
        self.assertEqual(sorted((set(SECRETS) - {"REDAMON_RUN_CREDENTIAL"}) & names), [])
        self.assertIn("CRED=rbac-terminal-credential:", printed)
        self.assertNotIn(SECRETS["REDAMON_RUN_CREDENTIAL"], printed)


class _Captured:
    """subprocess.run / Popen stand-in that records the environment it was given."""

    def __init__(self):
        self.envs = []

    def run(self, *args, **kwargs):
        self.envs.append(kwargs.get("env", "INHERITED"))
        return subprocess.CompletedProcess(args[0] if args else [], 0, "", "")

    def popen(self, *args, **kwargs):
        self.envs.append(kwargs.get("env", "INHERITED"))
        proc = mock.MagicMock()
        proc.stdout = iter(["rbac\n"])
        proc.returncode = 0
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        proc.pid = 4242
        return proc

    def assert_clean(self, test, label):
        test.assertTrue(self.envs, f"{label}: no child process was started")
        for env in self.envs:
            test.assertIsInstance(env, dict, f"{label}: the child inherits the server's environment")
            leaked = sorted(set(SECRETS) & set(env))
            test.assertEqual(leaked, [], f"{label}: {leaked} reach the child")
            test.assertEqual(env.get("RBAC_PLAIN_SETTING"), "kept", label)


class FixedArgvWrappers(unittest.TestCase):
    """The agent picks these wrappers' arguments, so their children are scrubbed too."""

    def _capture(self, module, call):
        cap = _Captured()
        with _server_env(), \
                mock.patch.object(module.subprocess, "run", side_effect=cap.run), \
                mock.patch.object(module.subprocess, "Popen", side_effect=cap.popen):
            call()
        return cap

    def test_network_recon_wrappers(self):
        calls = {
            "execute_curl": lambda: nrs.execute_curl("-s http://rbac.invalid/"),
            "execute_naabu": lambda: nrs.execute_naabu("-host rbac.invalid"),
            "execute_httpx": lambda: nrs.execute_httpx("-u rbac.invalid"),
            "execute_subfinder": lambda: nrs.execute_subfinder("-d rbac.invalid"),
            "execute_gau": lambda: nrs.execute_gau("rbac.invalid"),
            "execute_hydra": lambda: nrs.execute_hydra("-l a -p b ssh://rbac.invalid"),
            "execute_jsluice": lambda: nrs.execute_jsluice("urls /tmp/rbac.js"),
            "execute_masscan": lambda: nrs.execute_masscan("-p80 192.0.2.1"),
            "execute_wpscan": lambda: nrs.execute_wpscan("--url http://rbac.invalid"),
            "execute_amass": lambda: nrs.execute_amass("enum -d rbac.invalid"),
            "execute_katana": lambda: nrs.execute_katana("-u http://rbac.invalid"),
            "execute_arjun": lambda: nrs.execute_arjun("-u http://rbac.invalid"),
            "execute_ffuf": lambda: nrs.execute_ffuf("-u http://rbac.invalid/FUZZ -w /tmp/rbac.txt"),
            "cve_intel": lambda: nrs.cve_intel("id CVE-2024-0001 --json"),
            "execute_osv_scanner": lambda: nrs.execute_osv_scanner("pkg:npm/lodash@4.17.21"),
        }
        for label, call in calls.items():
            with self.subTest(wrapper=label):
                self._capture(nrs, call).assert_clean(self, label)

    def test_cve_intel_hands_vulnx_only_the_pdcp_key_it_was_given(self):
        cap = self._capture(nrs, lambda: nrs.cve_intel("id CVE-2024-0001 --json", api_key="rbac-own-pdcp"))
        [env] = cap.envs
        self.assertEqual(env["PDCP_API_KEY"], "rbac-own-pdcp")
        self.assertEqual(sorted(set(SECRETS) & set(env)), [])

    def test_nmap_and_nuclei(self):
        self._capture(nmap_server, lambda: nmap_server.execute_nmap("-sV 192.0.2.1")).assert_clean(self, "nmap")
        self._capture(nuclei_server, lambda: nuclei_server.execute_nuclei("-u http://rbac.invalid")
                      ).assert_clean(self, "nuclei")

    def test_playwright_and_msfconsole_children_have_none(self):
        self._capture(playwright_server, lambda: playwright_server._run_playwright_script("print(1)")
                      ).assert_clean(self, "playwright")

        cap = _Captured()

        def refuse_after_capture(*args, **kwargs):
            cap.popen(*args, **kwargs)
            raise FileNotFoundError("msfconsole is not in the test image")

        with _server_env(), mock.patch.object(metasploit_server.subprocess, "Popen", side_effect=refuse_after_capture):
            self.assertFalse(metasploit_server.PersistentMsfConsole().start())
        cap.assert_clean(self, "msfconsole")

    def test_the_sdk_replay_curl(self):
        self._capture(redamon_sdk, lambda: redamon_sdk._run("-s http://rbac.invalid/", "")
                      ).assert_clean(self, "redamon._run")

    def test_tunnel_clients(self):
        with mock.patch("builtins.open", mock.mock_open()), mock.patch.object(tunnel_manager.os, "makedirs"):
            self._capture(tunnel_manager, lambda: tunnel_manager._start_ngrok("rbac-fake-ngrok")
                          ).assert_clean(self, "ngrok")
            self._capture(tunnel_manager, lambda: tunnel_manager._start_chisel("http://rbac.invalid", "")
                          ).assert_clean(self, "chisel")


class SecretsOffCommandLinesAndSharedFiles(unittest.TestCase):
    """A user's tool key reaches only the child that needs it: not its command line, which
    `ps` shows every process in the container and on the host, nor a file left in the
    shared home directory."""

    def _run(self, module, call, home):
        calls = []

        def run(argv, **kwargs):
            config = None
            if "--config" in argv and Path(argv[argv.index("--config") + 1]).exists():
                path = Path(argv[argv.index("--config") + 1])
                config = (path, path.read_text(encoding="utf-8"), path.stat().st_mode & 0o777)
            calls.append({"argv": list(argv), "env": kwargs.get("env"), "config": config})
            return subprocess.CompletedProcess(argv, 0, "", "")

        with _server_env(HOME=home), mock.patch.object(module.subprocess, "run", side_effect=run):
            call()
        return calls

    def test_gau_reads_the_urlscan_key_from_a_private_file_removed_after_the_call(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            [c] = self._run(nrs, lambda: nrs.execute_gau("--subs rbac.invalid", urlscan_api_key="rbac-urlscan-key"),
                            home)
            self.assertFalse((Path(home) / ".gau.toml").exists())
        path, text, mode = c["config"]
        self.assertIn('apikey = "rbac-urlscan-key"', text)
        self.assertEqual(mode, 0o600)
        self.assertFalse(path.exists(), "the per-call config outlives the call")
        self.assertEqual(c["argv"][0], "gau")
        self.assertEqual(c["argv"][-2:], ["--subs", "rbac.invalid"])
        self.assertNotIn("rbac-urlscan-key", " ".join(c["argv"]))
        self.assertNotIn("rbac-urlscan-key", json.dumps(c["env"]))

    def test_gau_without_a_key_or_with_its_own_config_is_unchanged(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            [plain] = self._run(nrs, lambda: nrs.execute_gau("rbac.invalid"), home)
            [own] = self._run(nrs, lambda: nrs.execute_gau("--config /tmp/mine.toml rbac.invalid",
                                                           urlscan_api_key="rbac-urlscan-key"), home)
            self.assertFalse((Path(home) / ".gau.toml").exists())
        self.assertEqual(plain["argv"], ["gau", "rbac.invalid"])
        self.assertEqual(own["argv"], ["gau", "--config", "/tmp/mine.toml", "rbac.invalid"])

    def test_gau_removes_the_file_when_the_tool_fails(self):
        import tempfile
        seen = []

        def boom(argv, **kwargs):
            seen.append(Path(argv[argv.index("--config") + 1]))
            raise subprocess.TimeoutExpired(argv, 300)

        with tempfile.TemporaryDirectory() as home, _server_env(HOME=home), \
                mock.patch.object(nrs.subprocess, "run", side_effect=boom):
            out = nrs.execute_gau("rbac.invalid", urlscan_api_key="rbac-urlscan-key")
        self.assertIn("timed out", out)
        self.assertFalse(seen[0].exists())

    def test_wpscan_token_reaches_wpscan_in_its_environment_not_its_argv(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            [c] = self._run(nrs, lambda: nrs.execute_wpscan("--url http://rbac.invalid", api_token="rbac-wpscan"),
                            home)
            [none] = self._run(nrs, lambda: nrs.execute_wpscan("--url http://rbac.invalid"), home)
        self.assertEqual(c["env"]["WPSCAN_API_TOKEN"], "rbac-wpscan")
        self.assertNotIn("rbac-wpscan", " ".join(c["argv"]))
        self.assertNotIn("--api-token", c["argv"])
        self.assertEqual(sorted(set(SECRETS) & set(c["env"])), [])
        self.assertNotIn("WPSCAN_API_TOKEN", none["env"])

    def test_chisel_auth_reaches_chisel_in_its_environment_not_its_argv(self):
        cap = _Captured()
        argvs = []

        def popen(argv, **kwargs):
            argvs.append(list(argv))
            return cap.popen(argv, **kwargs)

        with _server_env(), mock.patch("builtins.open", mock.mock_open()), \
                mock.patch.object(tunnel_manager.subprocess, "Popen", side_effect=popen):
            tunnel_manager._start_chisel("http://rbac.invalid:8080", "rbac-user:rbac-pass")
            tunnel_manager._start_chisel("http://rbac.invalid:8080", "")
        with_auth, without = cap.envs
        self.assertEqual(argvs[0], ["chisel", "client", "http://rbac.invalid:8080", "R:4444:localhost:4444"])
        self.assertEqual(with_auth["AUTH"], "rbac-user:rbac-pass")
        self.assertEqual(argvs[1], argvs[0])
        self.assertNotIn("AUTH", without)
        cap.assert_clean(self, "chisel")


# --- the guard: every spawn in mcp/servers/*.py passes env built by safe_env ---

_SPAWN_MODULES = ("subprocess", "os", "asyncio", "pty")
_SUBPROCESS_SPAWNS = {"run", "Popen", "call", "check_call", "check_output"}
# subprocess helpers that take no env= at all: they always inherit.
_SUBPROCESS_INHERITING = {"getoutput", "getstatusoutput"}
# os.* spawns that take an environment, and where it sits when passed positionally.
_OS_ENV_POSITION = {"execve": 2, "execvpe": 2, "spawnve": 3, "spawnvpe": 3, "posix_spawn": 2, "posix_spawnp": 2}
# os.* spawns that cannot take one: they always inherit, so they are never allowed.
_OS_INHERITING = {"execv", "execvp", "execl", "execlp", "execle", "execlpe", "spawnv", "spawnvp",
                  "spawnl", "spawnlp", "spawnle", "spawnlpe", "system", "popen"}


def _is_safe_env_call(node):
    return (isinstance(node, ast.Call)
            and (getattr(node.func, "id", None) == "safe_env" or getattr(node.func, "attr", None) == "safe_env"))


def _env_built_by_safe_env(expr, scope):
    if _is_safe_env_call(expr):
        return True
    if not isinstance(expr, ast.Name):
        return False
    assigned, clean = [], True
    for node in ast.walk(scope):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == expr.id:
                    assigned.append(node.value)
                if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                        and target.value.id == expr.id):
                    clean = False  # env[...] = ... after safe_env re-adds what it removed
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == expr.id
                and node.func.attr in ("update", "setdefault", "__setitem__")):
            clean = False
    return clean and bool(assigned) and all(_is_safe_env_call(v) for v in assigned)


def spawn_violations(source, filename="<src>"):
    """Every child-process start in `source` whose environment is not built by safe_env()."""
    return [problem for _where, problem in _inspect_spawns(source, filename) if problem]


def spawn_sites(source, filename="<src>"):
    return [where for where, _problem in _inspect_spawns(source, filename)]


def _inspect_spawns(source, filename):
    """(where, problem-or-None) for every child-process start in `source`."""
    tree = ast.parse(source, filename)
    modules = {m: m for m in _SPAWN_MODULES}  # local name -> module, for `import subprocess as sp`
    aliases = {}  # local name -> (module, function) for `from subprocess import run`
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in _SPAWN_MODULES:
                    modules[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module in _SPAWN_MODULES:
            for a in node.names:
                aliases[a.asname or a.name] = (node.module, a.name)

    scopes = {}
    for scope in ast.walk(tree):
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(scope):
                scopes.setdefault(id(child), scope)

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in modules:
            module, name = modules[func.value.id], func.attr
        elif isinstance(func, ast.Name) and func.id in aliases:
            module, name = aliases[func.id]
        else:
            continue
        where = f"{filename}:{node.lineno} {module}.{name}"
        if (module == "os" and name in _OS_INHERITING or module == "pty" and name == "spawn"
                or module == "subprocess" and name in _SUBPROCESS_INHERITING):
            out.append((where, f"{where} always inherits the environment"))
            continue
        if module == "subprocess" and name in _SUBPROCESS_SPAWNS or \
                module == "asyncio" and name in ("create_subprocess_exec", "create_subprocess_shell"):
            env = next((k.value for k in node.keywords if k.arg == "env"), None)
        elif module == "os" and name in _OS_ENV_POSITION:
            pos = _OS_ENV_POSITION[name]
            env = node.args[pos] if len(node.args) > pos else next(
                (k.value for k in node.keywords if k.arg == "env"), None)
        else:
            continue
        if env is None:
            out.append((where, f"{where} passes no env= (inherits the server's secrets)"))
        elif not _env_built_by_safe_env(env, scopes.get(id(node), tree)):
            out.append((where, f"{where} passes an env not built by safe_env()"))
        else:
            out.append((where, None))
    return out


def _server_sources():
    return sorted(p for p in SERVERS.glob("*.py")
                  if not p.name.startswith("test_") and p.name != "_safe_env.py")


class EverySpawnIsScrubbed(unittest.TestCase):
    def test_every_subprocess_call_in_the_servers_passes_env_built_by_safe_env(self):
        found = []
        for path in _server_sources():
            found += spawn_violations(path.read_text(encoding="utf-8"), path.name)
        self.assertEqual(found, [])

    def test_the_guard_sees_the_known_spawn_sites(self):
        # A guard that finds nothing guards nothing: E3 counted 28 spawn sites.
        sites = []
        for path in _server_sources():
            sites += spawn_sites(path.read_text(encoding="utf-8"), path.name)
        self.assertGreaterEqual(len(sites), 28, sites)
        for expected in ("network_recon_server.py", "terminal_server.py", "tunnel_manager.py",
                         "metasploit_server.py", "playwright_server.py", "nmap_server.py",
                         "nuclei_server.py", "redamon.py"):
            self.assertTrue(any(s.startswith(expected + ":") for s in sites), expected)

    def test_the_guard_refuses_each_leaky_shape(self):
        leaky = {
            "no env": "import subprocess\ndef f():\n    subprocess.run(['curl'])\n",
            "copied env": "import os, subprocess\ndef f():\n    env = os.environ.copy()\n    subprocess.run(['x'], env=env)\n",
            "dict(os.environ)": "import os, subprocess\ndef f():\n    subprocess.Popen(['x'], env=dict(os.environ))\n",
            "re-added key": ("import subprocess\nfrom _safe_env import safe_env\ndef f(k):\n"
                             "    env = safe_env()\n    env['SCANNER_API_KEY'] = k\n    subprocess.run(['x'], env=env)\n"),
            "updated": ("import subprocess\nfrom _safe_env import safe_env\ndef f(o):\n"
                        "    env = safe_env()\n    env.update(o)\n    subprocess.run(['x'], env=env)\n"),
            "execvpe": "import os\ndef f():\n    os.execvpe('/bin/bash', ['bash'], os.environ.copy())\n",
            "execv": "import os\ndef f():\n    os.execv('/bin/bash', ['bash'])\n",
            "os.system": "import os\ndef f(c):\n    os.system(c)\n",
            "from-import": "from subprocess import run\ndef f():\n    run(['x'])\n",
            "asyncio": ("import asyncio\nasync def f():\n"
                        "    await asyncio.create_subprocess_exec('x')\n"),
            "aliased subprocess": "import subprocess as sp\ndef f():\n    sp.run(['x'])\n",
            "aliased subprocess, copied env": ("import os\nimport subprocess as sp\ndef f():\n"
                                               "    sp.Popen(['x'], env=os.environ.copy())\n"),
            "aliased os": "import os as o\ndef f(c):\n    o.system(c)\n",
            "aliased os execvpe": "import os as o\ndef f():\n    o.execvpe('/bin/bash', ['bash'], o.environ)\n",
            "aliased asyncio": ("import asyncio as aio\nasync def f():\n"
                                "    await aio.create_subprocess_shell('x')\n"),
            "getoutput": "import subprocess\ndef f(c):\n    subprocess.getoutput(c)\n",
            "getstatusoutput": "import subprocess\ndef f(c):\n    subprocess.getstatusoutput(c)\n",
            "from-import getstatusoutput as": "from subprocess import getstatusoutput as g\ndef f(c):\n    g(c)\n",
        }
        for label, src in leaky.items():
            with self.subTest(shape=label):
                self.assertTrue(spawn_violations(src), label)

    def test_the_guard_accepts_the_scrubbed_shapes(self):
        clean = ("import os, subprocess\nfrom _safe_env import safe_env\n"
                 "def f(c):\n    subprocess.run(['x'], env=safe_env())\n"
                 "    env = safe_env({'REDAMON_CTX': c})\n    subprocess.Popen(['y'], env=env)\n"
                 "    os.execvpe('/bin/bash', ['bash'], safe_env({'TERM': 'xterm'}))\n")
        self.assertEqual(spawn_violations(clean), [])
        aliased = ("import subprocess as sp\nfrom _safe_env import safe_env\n"
                   "def f():\n    sp.run(['x'], env=safe_env())\n")
        self.assertEqual(spawn_violations(aliased), [])
        self.assertEqual(len(spawn_sites(aliased)), 1)

    def test_a_probe_file_with_an_aliased_spawn_is_caught(self):
        # A probe module on disk, read the way the guard reads mcp/servers/*.py
        # (the run that mounts one into that directory is in the step's evidence).
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe_aliased_spawn.py"
            probe.write_text("import subprocess as sp\n\ndef leak(cmd):\n"
                             "    return sp.check_output(cmd, shell=True)\n", encoding="utf-8")
            found = spawn_violations(probe.read_text(encoding="utf-8"), probe.name)
        self.assertEqual(len(found), 1, found)
        self.assertIn("probe_aliased_spawn.py:4 subprocess.check_output", found[0])


class TheSandboxHoldsNoScannerKey(unittest.TestCase):
    def test_compose_gives_the_kali_sandbox_no_scanner_or_master_key(self):
        import yaml

        compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
        env = compose["services"]["kali-sandbox"]["environment"]
        names = set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}
        self.assertNotIn("SCANNER_API_KEY", names)
        self.assertNotIn("INTERNAL_API_KEY", names)
        # The two inbound tokens stay: the servers in that container validate them.
        self.assertTrue({"MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN"} <= names)

    def test_no_sandbox_client_reads_the_scanner_key(self):
        for name in ("redamon.py", "redagraph.py"):
            self.assertNotIn("SCANNER_API_KEY", (SERVERS / name).read_text(encoding="utf-8"), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""The hardened git clone: the command built, the pin, the env, and the watchdog."""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from workspace_import import executor, git_clone
from workspace_import.errors import ImportFailure

PUBLIC = "93.184.216.34"
HARDENING = [
    "protocol.allow=never", "protocol.https.allow=always", "http.followRedirects=false",
    "core.symlinks=false", "core.hooksPath=/dev/null", "transfer.fsckObjects=true",
    "fetch.fsckObjects=true", "submodule.recurse=false", "credential.helper=",
    "core.askPass=/bin/false", "http.version=HTTP/1.1",
]


class Command(unittest.TestCase):
    def test_command_has_every_hardening_flag_once_and_double_dash_before_url(self):
        cmd = git_clone.build_git_command("https://git.example.test/r.git", "git.example.test", 443, PUBLIC,
                                          "/staging/out", ref="main")
        for flag in HARDENING:
            self.assertEqual(sum(1 for i, a in enumerate(cmd) if a == flag and cmd[i - 1] == "-c"), 1, flag)
        self.assertIn(f"http.curloptResolve=git.example.test:443:{PUBLIC}", cmd)
        for opt in ("--depth", "--single-branch", "--no-tags", "--no-recurse-submodules"):
            self.assertEqual(cmd.count(opt), 1, opt)
        self.assertEqual(cmd[cmd.index("--depth") + 1], "1")
        self.assertEqual(cmd[cmd.index("--branch") + 1], "main")
        dd = cmd.index("--")
        self.assertEqual(cmd[dd + 1:], ["https://git.example.test/r.git", "/staging/out"])
        self.assertLess(cmd.index("clone"), dd)

    def test_ipv6_pin_bracketed(self):
        cmd = git_clone.build_git_command("https://h.test/r.git", "h.test", 443, "2606:2800::1", "/o")
        self.assertIn("http.curloptResolve=h.test:443:[2606:2800::1]", cmd)

    def test_refuses_http_userinfo_query_leading_dash(self):
        for url, code in (("http://git.example.test/r.git", "unsupported_scheme"),
                          ("https://u:p@git.example.test/r.git", "credentials_in_url"),
                          ("https://git.example.test/r.git?x=1", "invalid_url"),
                          ("https://git.example.test/r.git#frag", "invalid_url"),
                          ("-uhttps://git.example.test/r.git", "invalid_url"),
                          ("ssh://git.example.test/r.git", "unsupported_scheme")):
            with self.subTest(url=url):
                with self.assertRaises(ImportFailure) as ctx:
                    git_clone.check_clone_url(url)
                self.assertEqual(ctx.exception.code, code)

    def test_refuses_private_resolution(self):
        for answers in (["10.0.0.1"], [PUBLIC, "127.0.0.1"], ["::ffff:192.168.0.1"], ["169.254.169.254"]):
            with self.assertRaises(ImportFailure) as ctx:
                git_clone.pin_address("git.example.test", resolver=lambda _h, a=answers: a)
            self.assertEqual(ctx.exception.code, "blocked_address")
        with self.assertRaises(ImportFailure) as ctx:
            git_clone.pin_address("metadata.google.internal", resolver=lambda _h: [PUBLIC])
        self.assertEqual(ctx.exception.code, "blocked_address")
        with self.assertRaises(ImportFailure) as ctx:
            git_clone.pin_address("gone.example.test", resolver=lambda _h: [])
        self.assertEqual(ctx.exception.code, "dns_failed")
        self.assertEqual(git_clone.pin_address("git.example.test", resolver=lambda _h: [PUBLIC, "93.184.216.35"]),
                         PUBLIC)

    def test_env_is_allowlisted(self):
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "SENTINEL-SECRET", "DATABASE_URL": "postgres://x",
                                          "GIT_SSH_COMMAND": "evil", "PATH": "/usr/bin"}):
            env = git_clone.build_git_env("/tmp/home")
        self.assertNotIn("SENTINEL-SECRET", " ".join(env.values()))
        self.assertEqual(set(env), {"PATH", "HOME", "LC_ALL", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM",
                                    "GIT_CONFIG_GLOBAL", "GIT_LFS_SKIP_SMUDGE", "GIT_ASKPASS", "SSH_ASKPASS"})
        self.assertEqual((env["GIT_CONFIG_NOSYSTEM"], env["GIT_TERMINAL_PROMPT"]), ("1", "0"))


class _Stream:
    def __init__(self, data=b""):
        self.data = data

    async def read(self, n):
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk


class _FakeClone:
    """Stands in for `git clone`: writes files into its dest over time."""

    def __init__(self, dest: Path, *, chunks=3, size=1000, rc=0, stderr=b"", forever=False):
        self.dest, self.chunks, self.size, self.rc, self.forever = dest, chunks, size, rc, forever
        self.stderr = _Stream(stderr)
        self.returncode = None
        self.killed = False
        self._done = asyncio.Event()
        self._task = asyncio.ensure_future(self._work())

    async def _work(self):
        try:
            i = 0
            while self.forever or i < self.chunks:
                (self.dest / f"f{i}.bin").write_bytes(b"x" * self.size)
                i += 1
                await asyncio.sleep(0.02)
                if self.killed:
                    return
            (self.dest / ".git").mkdir(exist_ok=True)
            (self.dest / ".git" / "HEAD").write_text("ref")
            if not os.path.lexists(self.dest / "evil-link"):
                os.symlink("/etc/passwd", self.dest / "evil-link")
            self.returncode = self.rc
        finally:
            self._done.set()

    async def wait(self):
        await self._done.wait()
        return self.returncode

    def send_signal(self, _sig):
        self.killed = True
        self.returncode = -9
        self._done.set()


class _FakeRevParse:
    returncode = 0

    async def communicate(self):
        return b"7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n", b""


class Clone(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-git-"))
        self.out = self.tmp / "out"
        self.out.mkdir()
        self._pool = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2)
        self.commands = []
        self.envs = []

    def tearDown(self):
        executor.IMPORT_EXECUTOR.shutdown(wait=True)
        executor.IMPORT_EXECUTOR = self._pool
        shutil.rmtree(self.tmp, ignore_errors=True)

    def spawner(self, **clone_kw):
        procs = []

        async def spawn(*cmd, env=None, cwd=None, **_kw):
            self.commands.append(list(cmd))
            self.envs.append(env)
            if "clone" in cmd:
                p = _FakeClone(self.out, **clone_kw)
                procs.append(p)
                return p
            return _FakeRevParse()
        return spawn, procs

    async def clone(self, spawn, **kw):
        kw.setdefault("watch_interval", 0.01)
        return await git_clone.clone_into("https://git.example.test/team/tool.git", self.out, spawn=spawn,
                                          resolver=lambda _h: [PUBLIC], **kw)

    async def test_git_dir_and_symlinks_removed_after_clone(self):
        spawn, _ = self.spawner()
        got = await self.clone(spawn)
        self.assertEqual(got["commit"], "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")
        self.assertEqual((got["files"], got["skipped"]), (3, 1))
        self.assertFalse((self.out / ".git").exists())
        self.assertFalse(os.path.lexists(self.out / "evil-link"))
        self.assertIn(f"http.curloptResolve=git.example.test:443:{PUBLIC}", self.commands[0])
        self.assertEqual(self.commands[1][-2:], ["rev-parse", "HEAD"])
        self.assertTrue(all(e["GIT_CONFIG_NOSYSTEM"] == "1" for e in self.envs))

    async def test_watchdog_kills_on_size(self):
        spawn, procs = self.spawner(forever=True, size=10_000)
        with self.assertRaises(ImportFailure) as ctx:
            await self.clone(spawn, max_bytes=25_000)
        self.assertEqual(ctx.exception.code, "too_large")
        self.assertTrue(procs[0].killed)

    async def test_refused_reservation_growth_kills(self):
        class Res:
            nbytes = 0

            def grow(self, _n):
                raise ImportFailure("insufficient_storage")

        spawn, procs = self.spawner(forever=True)
        with self.assertRaises(ImportFailure) as ctx:
            await self.clone(spawn, reservation=Res())
        self.assertEqual(ctx.exception.code, "insufficient_storage")
        self.assertTrue(procs[0].killed)

    async def test_cancel_kills_process(self):
        spawn, procs = self.spawner(forever=True)
        task = asyncio.ensure_future(self.clone(spawn))
        await asyncio.sleep(0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(procs[0].killed)
        ev = threading.Event()
        ev.set()
        spawn2, procs2 = self.spawner(forever=True)
        with self.assertRaises(ImportFailure) as ctx:
            await self.clone(spawn2, cancel=ev)
        self.assertEqual(ctx.exception.code, "cancelled")
        self.assertTrue(procs2[0].killed)

    async def test_timeout_kills(self):
        spawn, procs = self.spawner(forever=True)
        with self.assertRaises(ImportFailure) as ctx:
            await self.clone(spawn, timeout=0.05)
        self.assertEqual(ctx.exception.code, "timeout")
        self.assertTrue(procs[0].killed)

    async def test_stderr_never_in_job_error(self):
        secret = b"fatal: repository 'https://user:SENTINEL@git.example.test/x?token=SENTINEL' not found\n"
        spawn, _ = self.spawner(chunks=0, rc=128, stderr=secret)
        with self.assertLogs("workspace_import.git_clone", "WARNING") as logs:
            with self.assertRaises(ImportFailure) as ctx:
                await self.clone(spawn)
        self.assertEqual(ctx.exception.code, "not_found")
        self.assertNotIn("SENTINEL", str(ctx.exception))
        self.assertNotIn("SENTINEL", ctx.exception.detail)
        self.assertNotIn("SENTINEL", "\n".join(logs.output))
        spawn, _ = self.spawner(chunks=0, rc=128, stderr=b"fatal: unable to update url base from redirection\n")
        with self.assertRaises(ImportFailure) as ctx:
            await self.clone(spawn)
        self.assertEqual(ctx.exception.code, "redirect_refused")


if __name__ == "__main__":
    unittest.main()

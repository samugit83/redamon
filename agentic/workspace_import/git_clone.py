"""A hardened, shallow `git clone` for any public https repository.

git resolves hosts itself, outside the pinned httpx transport, so the address
is judged here and git is pinned to it with http.curloptResolve; redirects,
every protocol but https, hooks, symlinks, submodules, credential helpers and
the system/global config are all off. `.git` is removed after the clone: no
history in this version.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import sys
import urllib.parse
from pathlib import Path
from typing import Callable, Optional

from orchestrator_helpers.fetch_guard import _BLOCKED_HOSTNAMES, _is_disallowed_ip
from orchestrator_helpers.llm_url_guard import _resolve_ips
from workspace_import import executor, limits
from workspace_import.errors import ImportFailure
from workspace_import.redact import redact_text

logger = logging.getLogger(__name__)

CLONE_TIMEOUT_SEC = 900
WATCH_INTERVAL_SEC = 2.0
STDERR_KEEP = 2048
_ENV_ALLOWED = ("PATH",)


def check_clone_url(url: str) -> tuple[str, int]:
    """(host, port) of a cloneable URL: https only, no userinfo, query or fragment."""
    if url.startswith("-"):
        raise ImportFailure("invalid_url")
    try:
        u = urllib.parse.urlsplit(url)
        host, port = (u.hostname or "").lower(), u.port or 443
    except ValueError:
        raise ImportFailure("invalid_url") from None
    if u.scheme.lower() != "https":
        raise ImportFailure("unsupported_scheme")
    if "@" in u.netloc:
        raise ImportFailure("credentials_in_url")
    if u.query or u.fragment or not host:
        raise ImportFailure("invalid_url")
    return host, port


def pin_address(host: str, resolver: Callable[[str], list] = _resolve_ips) -> str:
    """The address git will dial: refuse the host if ANY answer is non-public."""
    if host.rstrip(".") in _BLOCKED_HOSTNAMES:
        raise ImportFailure("blocked_address")
    ips = list(dict.fromkeys(resolver(host)))
    if not ips:
        raise ImportFailure("dns_failed")
    if any(_is_disallowed_ip(ip) for ip in ips):
        raise ImportFailure("blocked_address")
    return ips[0]


def build_git_command(url: str, host: str, port: int, ip: str, dest, ref: Optional[str] = None) -> list[str]:
    pinned = f"[{ip}]" if ":" in ip else ip
    cmd = [
        "git",
        "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false", "-c", f"http.curloptResolve={host}:{port}:{pinned}",
        "-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null",
        "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true",
        "-c", "submodule.recurse=false", "-c", "credential.helper=", "-c", "core.askPass=/bin/false",
        # GIT_CONFIG_NOSYSTEM drops the image's system-wide HTTP/1.1 setting,
        # which GitHub needs (it answers git's HTTP/2 upload-pack POST with 401).
        "-c", "http.version=HTTP/1.1",
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
    ]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, str(dest)]
    return cmd


def build_git_env(home) -> dict:
    """A minimal environment from an allowlist: nothing else is inherited, so no
    secret of the agent's environment can reach git or a helper it runs."""
    env = {k: os.environ[k] for k in _ENV_ALLOWED if k in os.environ}
    env.update({
        "HOME": str(home), "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false",
    })
    return env


def _tree_bytes(path: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return total


def _stderr_code(stderr: str) -> str:
    low = stderr.lower()
    if "not found" in low or "repository not found" in low or "404" in low:
        return "not_found"
    if "redirect" in low:
        return "redirect_refused"
    return "git_failed"


def _finish_tree(out: Path) -> tuple[int, int, int]:
    """Remove .git and any symlink; (files, bytes, symlinks removed)."""
    shutil.rmtree(out / ".git", ignore_errors=True)
    files = nbytes = links = 0
    for dirpath, dirs, names in os.walk(out):
        for n in list(dirs) + names:
            p = os.path.join(dirpath, n)
            if os.path.islink(p):
                os.unlink(p)
                links += 1
                if n in dirs:
                    dirs.remove(n)
            elif n in names:
                files += 1
                nbytes += os.lstat(p).st_size
    return files, nbytes, links


async def _drain(stream, keep: int) -> bytes:
    """Read a pipe to its end, keeping the first `keep` bytes, so a chatty git
    never blocks on a full pipe."""
    if stream is None:
        return b""
    kept = b""
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return kept
        if len(kept) < keep:
            kept += chunk[: keep - len(kept)]


async def _kill(proc) -> None:
    try:
        proc.send_signal(signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    try:
        await asyncio.wait_for(proc.wait(), 10)
    except Exception:
        pass


async def _run(cmd, env, cwd, spawn) -> tuple[int, str, str]:
    proc = await spawn(*cmd, env=env, cwd=str(cwd), stdout=asyncio.subprocess.PIPE,
                       stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    return proc.returncode, (out or b"").decode("utf-8", "replace"), (err or b"").decode("utf-8", "replace")


async def clone_into(url: str, out, *, reservation=None, progress=None, cancel=None,
                     spawn=asyncio.create_subprocess_exec, resolver: Callable[[str], list] = _resolve_ips,
                     timeout: float = CLONE_TIMEOUT_SEC, max_bytes: Optional[int] = None,
                     watch_interval: float = WATCH_INTERVAL_SEC) -> dict:
    out = Path(out)
    host, port = check_clone_url(url)
    ip = await asyncio.to_thread(pin_address, host, resolver)
    home = out.parent / "git-home"
    home.mkdir(mode=0o700, exist_ok=True)
    env = build_git_env(home)
    cap = max_bytes if max_bytes is not None else limits.max_bytes()
    if progress is not None:
        progress.update(phase="downloading", bytes=0)
    proc = await spawn(*build_git_command(url, host, port, ip, out), env=env, cwd=str(out.parent),
                       stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    stderr_task = asyncio.ensure_future(_drain(proc.stderr, STDERR_KEEP))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
        while True:
            try:
                await asyncio.wait_for(asyncio.shield(proc.wait()), watch_interval)
                break
            except asyncio.TimeoutError:
                pass
            size = await executor.run_blocking(_tree_bytes, out)
            if progress is not None:
                progress.update(phase="downloading", bytes=size)
            if size > cap:
                await _kill(proc)
                raise ImportFailure("too_large")
            if reservation is not None:
                try:
                    while size > reservation.nbytes:
                        reservation.grow(64 * 1024 * 1024)
                except ImportFailure:
                    await _kill(proc)
                    raise
            if cancel is not None and cancel.is_set():
                await _kill(proc)
                raise ImportFailure("cancelled")
            if loop.time() > deadline:
                await _kill(proc)
                raise ImportFailure("timeout")
    except BaseException:
        stderr_task.cancel()
        if isinstance(sys.exc_info()[1], asyncio.CancelledError):
            await _kill(proc)
        raise
    stderr = (await stderr_task).decode("utf-8", "replace")
    if proc.returncode != 0:
        code = _stderr_code(stderr)
        # stderr can quote the URL and the server's words: server log only, redacted.
        logger.warning(f"[workspace-import] git clone failed code={code} rc={proc.returncode} "
                       f"stderr={redact_text(stderr)!r}")
        raise ImportFailure(code)
    rc, sha, _err = await _run(["git", "-c", "safe.directory=*", "rev-parse", "HEAD"], env, out, spawn)
    commit = sha.strip() if rc == 0 else ""
    files, nbytes, links = await executor.run_blocking(_finish_tree, out)
    shutil.rmtree(home, ignore_errors=True)
    return {"files": files, "bytes": nbytes, "commit": commit, "skipped": links}

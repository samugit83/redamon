"""B09: GAU's URL verification gets the configured threads, timeout and rate,
and a timeout never marks unverified URLs as verified.

Both callers passed (timeout, rate_limit, threads) into a function declared
(threads, timeout, rate_limit), so httpx ran with 5 threads, a 100 s timeout and
50 requests/s; and when the 300 s subprocess timed out the function returned
every input URL as verified.
"""
from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.resource_enum import gau_helpers  # noqa: E402

CALLERS = [
    PROJECT_ROOT / "recon" / "main_recon_modules" / "resource_enum.py",
    PROJECT_ROOT / "recon" / "partial_recon_modules" / "web_crawling.py",
]
EXPECTED = {"threads": "GAU_VERIFY_THREADS", "timeout": "GAU_VERIFY_TIMEOUT",
            "rate_limit": "GAU_VERIFY_RATE_LIMIT", "docker_image": "GAU_VERIFY_DOCKER_IMAGE",
            "accept_status": "GAU_VERIFY_ACCEPT_STATUS"}


def _verify_calls(path: Path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "verify_gau_urls":
            yield node


@pytest.mark.parametrize("path", CALLERS, ids=lambda p: p.name)
def test_b09_each_setting_reaches_its_parameter(path):
    sig = inspect.signature(gau_helpers.verify_gau_urls)
    calls = list(_verify_calls(path))
    assert calls, f"no verify_gau_urls call in {path.name}"
    for call in calls:
        placeholders = [f"<arg{i}>" for i in range(len(call.args))]
        names = {f"<arg{i}>": ast.unparse(a) for i, a in enumerate(call.args)}
        bound = sig.bind(*placeholders, **{k.arg: k.arg for k in call.keywords})
        kw_values = {k.arg: ast.unparse(k.value) for k in call.keywords}
        for param, setting in EXPECTED.items():
            got = bound.arguments[param]
            got = names.get(got, kw_values.get(got, got))
            assert got == setting, f"{path.name}: {param} receives {got}, not {setting}"


def _run_verify(side_effect):
    with patch.object(gau_helpers.subprocess, "run", side_effect=side_effect) as run:
        out = gau_helpers.verify_gau_urls(
            ["https://a.example.test/x", "https://a.example.test/y"],
            docker_image="httpx:test", threads=7, timeout=9, rate_limit=11,
            accept_status=[200])
    return out, run


def _data_dir(cmd) -> Path:
    mount = cmd[cmd.index("-v") + 1]
    return Path(mount.split(":", 1)[0])


def test_b09_command_carries_the_configured_values():
    def fake(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, "", "")
    _out, run = _run_verify(fake)
    cmd = run.call_args[0][0]
    assert cmd[cmd.index("-t") + 1] == "7"
    assert cmd[cmd.index("-timeout") + 1] == "9"
    assert cmd[cmd.index("-rl") + 1] == "11"


def test_b09_timeout_keeps_only_the_urls_verified_so_far():
    def fake(cmd, **_kw):
        out = _data_dir(cmd) / "verified.json"
        out.write_text(json.dumps({"url": "https://a.example.test/x", "status_code": 200}) + "\n")
        raise subprocess.TimeoutExpired(cmd, 300)
    out, _run = _run_verify(fake)
    assert out == {"https://a.example.test/x"}


def test_b09_timeout_with_nothing_written_verifies_nothing():
    def fake(cmd, **_kw):
        raise subprocess.TimeoutExpired(cmd, 300)
    out, _run = _run_verify(fake)
    assert out == set()


def test_b09_launch_error_verifies_nothing():
    out, _run = _run_verify(OSError("docker missing"))
    assert out == set()

"""Regression: WCVS ran over the RoE ceiling (R-8, B-R8c).

The FP lab run with a 2 rps ceiling logged 3 WCVS requests a second. WCVS got
``-rr 2`` (WEB_CACHE_POISON_MAX_RPS_PER_HOST, capped to the ceiling) next to
``-t 10``. Its ``-rr`` is one golang.org/x/time/rate limiter with a burst of 1,
shared by every thread and every URL (Web-Cache-Vulnerability-Scanner v2.0.0,
pkg/flags.go), not a per-host rate. But a thread can take its token and then
sleep before it sends: on a target whose cache answers with an Age header,
the cache-buster checks wait 2 s between the token and the request
(pkg/recon.go), so with ten threads the late sends land among the next
tokens' and bunch past the rate.

One thread does not cure it: the delayed request still leaves together with
the next token's. Measured on a loopback copy of the FP lab cache (X-Cache and
Age, 4 URLs, 120 s), -t 10 -rr 2 and -t 1 -rr 2 both put 3 requests in one
second; -t 1 -rr 1 never more than 2. So under a ceiling C WCVS runs one thread
at ``wcvs_ceiling_rate(C)``: C - 1 from 2 up (a pair plus the next tokens fit
in the second), 1 / (2 + 1/C) below (no pair: the next token comes 1/C after
the delayed send), or the project's lower rate. With no ceiling its argv is
byte-identical.

Only Docker is replaced: run_wcvs builds and "runs" its real command.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.cache_scan import wcvs_runner  # noqa: E402

NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
    {"ROE_ENABLED": True},
]
NO_CEILING_IDS = ["no-roe", "roe-off", "rps-0", "rps-unset"]
URLS = ["https://shop.example.com/", "https://shop.example.com/promo", "http://www.example.com/"]


class _Ran:
    timed_out = False


@pytest.fixture
def docker(monkeypatch):
    """The argv of every WCVS container run_wcvs starts."""
    from recon.helpers import docker_helpers
    sent = []

    def run_tool_container(cmd, **kwargs):
        sent.append((list(cmd), kwargs))
        return _Ran()

    monkeypatch.setattr(docker_helpers, "run_tool_container", run_tool_container)
    return sent


def _argv(docker, tmp_path, settings) -> list:
    docker.clear()
    wcvs_runner.run_wcvs(URLS, dict(settings), work_dir=str(tmp_path / "wcvs"))
    assert len(docker) == 1
    cmd, kwargs = docker[0]
    assert kwargs["tool"] == "wcvs"
    # The per-run directory is random; everything else must match exactly.
    return [re.sub(r"^.*/wcvs/[0-9a-f]+", "<run>", a) for a in cmd]


def _flag(cmd, name):
    return cmd[cmd.index(name) + 1]


def _ceiling(rps, **extra) -> dict:
    return {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps, **extra}


def test_under_a_ceiling_wcvs_runs_one_thread_under_it(docker, tmp_path, capsys):
    project = {"WEB_CACHE_POISON_CONCURRENCY": 10, "WEB_CACHE_POISON_MAX_RPS_PER_HOST": 2}
    plain = _argv(docker, tmp_path, project)
    paced = _argv(docker, tmp_path, _ceiling(2, **project))

    assert _flag(plain, "-t") == "10" and _flag(plain, "-rr") == "2.0"
    # Only the two values differ.
    swapped = {plain.index("-t") + 1: "1", plain.index("-rr") + 1: "1.0"}
    assert paced == [swapped.get(i, a) for i, a in enumerate(plain)]
    assert "[*][CachePoison] WCVS paced to the 2 rps RoE ceiling: one thread, -rr 1\n" \
        in capsys.readouterr().out


@pytest.mark.parametrize("ceiling, configured, rr", [
    (0.5, 0.5, "0.25"),
    (1, 1, "0.333"),
    (2, 2, "1.0"),
    (5, 5, "4.0"),
    (2, 0, "1.0"),       # 0 (unlimited) when the capper did not run
    (5, 1, "1.0"),       # a lower project rate stays
    (5, 3.5, "3.5"),
])
def test_the_rate_never_exceeds_the_ceiling(docker, tmp_path, ceiling, configured, rr):
    cmd = _argv(docker, tmp_path, _ceiling(ceiling, WEB_CACHE_POISON_CONCURRENCY=10,
                                           WEB_CACHE_POISON_MAX_RPS_PER_HOST=configured))
    assert _flag(cmd, "-t") == "1"
    assert _flag(cmd, "-rr") == rr
    assert cmd.count("-t") == cmd.count("-rr") == 1


@pytest.mark.parametrize("rate", [0, 3])
@pytest.mark.parametrize("roe", NO_CEILING, ids=NO_CEILING_IDS)
def test_no_ceiling_leaves_the_wcvs_command_byte_identical(docker, tmp_path, capsys, roe, rate):
    project = {"WEB_CACHE_POISON_CONCURRENCY": 10, "WEB_CACHE_POISON_MAX_RPS_PER_HOST": rate}
    plain = _argv(docker, tmp_path, project)

    assert _argv(docker, tmp_path, {**project, **roe}) == plain
    assert _flag(plain, "-t") == "10"
    assert ("-rr" in plain) == bool(rate)
    assert "paced to the" not in capsys.readouterr().out


@pytest.mark.parametrize("ceiling", [0.5, 1, 2, 5])
def test_the_rate_holds_the_ceiling_through_wcvs_delayed_sends(ceiling):
    """WCVS's single thread modelled: a burst-1 token bucket at -rr; a plain
    request is sent when its token is granted, a delayed one 2 s after (the
    Age-header cache-buster checks). Every mix of the two, eight long: no
    one-second window holds more than the ceiling, and below 1 rps no two
    requests are closer than 1/C."""
    import itertools

    rate = wcvs_runner.wcvs_ceiling_rate(ceiling)
    for ops in itertools.product(("plain", "delayed"), repeat=8):
        now, last, sends = 0.0, None, []
        for op in ops:
            grant = now if last is None else max(now, last + 1 / rate)
            last = grant
            now = grant + (2.0 if op == "delayed" else 0.0)
            sends.append(now)
        sends.sort()
        if ceiling >= 1:
            for t in sends:
                assert sum(1 for s in sends if t <= s < t + 1 - 1e-9) <= ceiling, (ops, sends)
        else:
            assert all(b - a >= 1 / ceiling - 1e-9 for a, b in zip(sends, sends[1:])), (ops, sends)

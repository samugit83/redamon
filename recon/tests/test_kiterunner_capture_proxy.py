"""Kiterunner under traffic capture still runs, direct and untagged (S-26).

With capture on, run_kiterunner_discovery added `--proxy <capture url>` and the
`X-Redamon-Ctx` tag to `kr scan`. kr v1.0.2, the release RedAmon downloads, has
`--proxy` only on `kr kb replay`: run on the real binary, `kr scan ... --proxy
http://...` exits 1 with "Error: unknown flag: --proxy" and an empty stdout, so
every capture-on run found no endpoints. Nor can kr be pointed at the proxy
another way: `scan` sends through a fasthttp.HostClient with no Dial set
(pkg/http/client.go), and on the real binary with HTTP_PROXY / HTTPS_PROXY /
http_proxy / https_proxy all set, every request went to the target and none to
the proxy.

So kr runs direct under capture (the proxy's fail-open rule: capture never
costs the scan its coverage), and with no tag, since the tag rides only with
the proxy (the tag-leak guard in recon/helpers/proxy_routing.py).

kr itself is not run here (run_with_heartbeat mocked); the binary and wordlist
are empty temp files.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.helpers.resource_enum import kiterunner_helpers as kh  # noqa: E402
from recon.helpers.resource_enum import tool_health as th  # noqa: E402

CAPTURE_ON = ("http://127.0.0.1:8888", "signed-ctx-tag")
CAPTURE_OFF = (None, None)
TARGETS = ["https://app.example.test", "https://api.example.test"]
USER_HEADER = "Authorization: Bearer synthetic-token"

#: Every flag `kr scan --help` lists on the real v1.0.2 binary (scan's own flags
#: plus the root's persistent --config/--output/--quiet/--verbose). cobra exits 1
#: on any other flag before kr sends a request.
KR_V102_SCAN_FLAGS = frozenset({
    "-A", "--assetnote-wordlist", "--blacklist-domain", "--delay", "--disable-precheck",
    "--fail-status-codes", "--filter-api", "--force-method", "-H", "--header",
    "-h", "--help", "--ignore-length", "--kitebuilder-full-scan", "-w", "--kitebuilder-list",
    "-x", "--max-connection-per-host", "-j", "--max-parallel-hosts", "--max-redirects",
    "-d", "--preflight-depth", "--profile-name", "--progress", "--quarantine-threshold",
    "--success-status-codes", "-t", "--timeout", "--user-agent", "--wildcard-detection",
    "--config", "-o", "--output", "-q", "--quiet", "-v", "--verbose",
})

#: What the real kr v1.0.2 printed for the old capture-on command.
KR_UNKNOWN_FLAG_STDERR = ("Error: unknown flag: --proxy\nUsage:\n"
                          "  kite scan INPUT [ -w wordlist.kite ] [flags]\n")

KR_HIT = json.dumps({"method": "GET", "target": "https://api.example.test", "path": "/api/users",
                     "responses": [{"uri": "", "sc": 200, "len": 1234}],
                     "time": "2026-11-11T10:00:00Z"})


@pytest.fixture(autouse=True)
def _clean_state():
    request_pacer.reset()
    th.drain()
    yield
    request_pacer.reset()
    th.drain()


@pytest.fixture
def kr_files(tmp_path):
    binary = tmp_path / "kr"
    binary.write_text("")
    wordlist = tmp_path / "routes.kite"
    wordlist.write_text("")
    return str(binary), str(wordlist)


def _discover(kr_files, routing, *, stdout="", returncode=0, stderr=""):
    launched = []

    def fake_run(cmd, **_kw):
        launched.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    binary, wordlist = kr_files
    with mock.patch.object(kh, "run_with_heartbeat", side_effect=fake_run), \
         mock.patch("helpers.proxy_routing.get_capture_routing", return_value=routing):
        found = kh.run_kiterunner_discovery(
            TARGETS, binary, wordlist, "routes",
            rate_limit=10, connections=100, timeout=10, scan_timeout=60, threads=50,
            ignore_status=[404], match_status=[200, 401], min_content_length=100,
            headers=[USER_HEADER])
    return found, launched


def _kiterunner_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "kiterunner"]


def test_under_capture_kr_gets_only_flags_its_scan_command_has(kr_files):
    _, launched = _discover(kr_files, CAPTURE_ON)

    (cmd,) = launched
    assert cmd[1] == "scan"
    unknown = [tok for tok in cmd[3:] if tok.startswith("-") and tok not in KR_V102_SCAN_FLAGS]
    assert unknown == [], f"kr v1.0.2 `scan` exits on {unknown}: {cmd}"


def test_under_capture_the_tag_never_reaches_the_target(kr_files):
    _, launched = _discover(kr_files, CAPTURE_ON)

    (cmd,) = launched
    assert not any("X-Redamon-Ctx" in tok or "signed-ctx-tag" in tok for tok in cmd), cmd
    assert not any("127.0.0.1:8888" in tok for tok in cmd), cmd
    assert cmd[cmd.index("-H") + 1] == USER_HEADER


def test_capture_does_not_change_the_kr_command(kr_files):
    _, (captured,) = _discover(kr_files, CAPTURE_ON)
    _, (direct,) = _discover(kr_files, CAPTURE_OFF)

    # argv[2] is the per-run targets file under a fresh temp dir.
    assert captured[:2] + captured[3:] == direct[:2] + direct[3:]


def test_under_capture_kr_results_still_parse(kr_files):
    found, _ = _discover(kr_files, CAPTURE_ON, stdout=KR_HIT + "\n")

    assert found == [{"method": "GET", "status": 200, "url": "https://api.example.test/api/users",
                      "path": "/api/users", "content_length": 1234}]
    assert th.drain() == [] and _kiterunner_gaps() == []


def test_the_operator_is_told_kr_traffic_is_not_captured(kr_files, capsys):
    _discover(kr_files, CAPTURE_ON)
    assert "not captured" in capsys.readouterr().out

    _discover(kr_files, CAPTURE_OFF)
    assert "not captured" not in capsys.readouterr().out


def test_kr_rejecting_its_command_line_is_a_coverage_gap_not_no_endpoints(kr_files):
    found, _ = _discover(kr_files, CAPTURE_OFF, returncode=1, stderr=KR_UNKNOWN_FLAG_STDERR)

    assert found == []
    results = th.drain()
    assert [(r.tool, r.verdict, r.return_code, r.seeds) for r in results] == [
        ("kiterunner", th.FAILURE, 1, 2)]
    th.note_gaps(results)
    (gap,) = _kiterunner_gaps()
    assert gap["module"] == "resource_enum" and gap["skipped"] == 1

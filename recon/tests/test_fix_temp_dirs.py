"""
Per-run temp files for the Docker-backed recon tools.

/tmp/redamon is ONE host directory, bind-mounted read-write into every recon
container and every sibling tool container, and several scans may run at once
(different projects, or up to 12 partial recons of one project). A fixed name
there let two runs scan each other's targets.txt (outside the authorised scope),
parse each other's output into the wrong project's graph, or delete each other's
live files, because each run's cleanup emptied the shared directory.

Each test below interleaves two runs the way two containers do: run B starts
and finishes while run A's tool is still "running", then A's own files must
still be there and A must parse only its own targets. Docker and the network
are mocked; only files under /tmp/redamon inside the test container are touched.

Run (inside the redamon-recon image):
    python /repo/tooling/scripts/pytest_isolated.py unit tests/test_fix_temp_dirs.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from unittest import mock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.main_recon_modules import domain_recon as dr  # noqa: E402
from recon.main_recon_modules import http_probe as hp  # noqa: E402
from recon.main_recon_modules import port_scan as ps  # noqa: E402
from recon.helpers.resource_enum import jsluice_helpers as jh  # noqa: E402

SHARED = Path("/tmp/redamon")

HOST_A = "a.example.test"
HOST_B = "b.example.test"
IPS = {HOST_A: "192.0.2.10", HOST_B: "192.0.2.20"}


def _mounts(cmd):
    """{container path: host path} for every `-v` of a docker command."""
    out = {}
    for i, tok in enumerate(cmd):
        if tok == "-v":
            host, container = cmd[i + 1].split(":")[:2]
            out[container] = host
    return out


def _recon(host, port_scan=None):
    data = {
        "domain": host,
        "dns": {"domain": {"ips": {"ipv4": [IPS[host]], "ipv6": []}, "has_records": True},
                "subdomains": {}},
    }
    if port_scan is not None:
        data["port_scan"] = port_scan
    return data


def _foreign_files(prefix):
    """Files another run owns: one in the legacy fixed dir, one in a per-run dir."""
    dirs = [SHARED / prefix, SHARED / f"{prefix}_{uuid.uuid4().hex[:12]}"]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        (d / "targets.txt").write_text("other-run.example.test\n")
    return dirs


def _assert_foreign_files_survive(dirs):
    try:
        for d in dirs:
            f = d / "targets.txt"
            assert f.is_file(), f"another run's {f} was deleted"
            assert f.read_text() == "other-run.example.test\n", f"another run's {f} was overwritten"
    finally:
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Naabu (port_scan.run_port_scan)
# ---------------------------------------------------------------------------

class _FakeNaabu:
    """Popen stand-in that behaves like naabu: reads the mounted targets file,
    writes one open port per target into the mounted output file."""

    def __init__(self, during_first_scan=None):
        self.calls = []
        self._hook = during_first_scan

    def __call__(self, cmd, **_kw):
        self.calls.append(list(cmd))
        if self._hook:
            hook, self._hook = self._hook, None
            hook()
        mounts = _mounts(cmd)
        targets = Path(mounts["/targets"]) / Path(cmd[cmd.index("-list") + 1]).name
        output = Path(mounts["/output"]) / Path(cmd[cmd.index("-o") + 1]).name
        proc = mock.MagicMock()
        proc.communicate.return_value = ("", "")
        if targets.is_file():
            # A target is a hostname or, as run_port_scan also queues it, a bare IP.
            lines = [
                json.dumps({"host": t, "ip": IPS.get(t, t), "port": 443})
                for t in targets.read_text().split()
            ]
            output.write_text("\n".join(lines) + "\n")
            proc.returncode = 0
        else:
            proc.returncode = 1
        return proc


# CONNECT scan: a SYN scan that "fails" would retry and muddle the call count.
_NAABU_SETTINGS = {"NAABU_SCAN_TYPE": "c"}


def _naabu_env(fake):
    return [
        mock.patch.object(ps, "is_docker_installed", return_value=True),
        mock.patch.object(ps, "is_docker_running", return_value=True),
        mock.patch.object(ps, "pull_naabu_docker_image", return_value=True),
        mock.patch.object(ps.subprocess, "Popen", side_effect=fake),
    ]


def _run_naabu(recon, fake):
    patches = _naabu_env(fake)
    for p in patches:
        p.start()
    try:
        return ps.run_port_scan(recon, output_file=None, settings=dict(_NAABU_SETTINGS))
    finally:
        for p in reversed(patches):
            p.stop()


class TestNaabuTempDir:
    def test_interleaved_runs_each_scan_and_parse_only_their_own_targets(self):
        results = {}
        fake = _FakeNaabu(during_first_scan=lambda: results.__setitem__(
            "b", ps.run_port_scan(_recon(HOST_B), output_file=None,
                                  settings=dict(_NAABU_SETTINGS))))
        results["a"] = _run_naabu(_recon(HOST_A), fake)

        a_hosts = set(results["a"].get("port_scan", {}).get("by_host", {}))
        b_hosts = set(results["b"].get("port_scan", {}).get("by_host", {}))
        assert a_hosts == {HOST_A, IPS[HOST_A]}, f"run A parsed {a_hosts or 'nothing'}"
        assert b_hosts == {HOST_B, IPS[HOST_B]}, f"run B parsed {b_hosts or 'nothing'}"

    def test_each_run_gets_its_own_dir_and_mounts_exactly_that_dir(self):
        fake = _FakeNaabu(during_first_scan=lambda: ps.run_port_scan(
            _recon(HOST_B), output_file=None, settings=dict(_NAABU_SETTINGS)))
        _run_naabu(_recon(HOST_A), fake)

        assert len(fake.calls) == 2
        dirs = []
        for cmd in fake.calls:
            m = _mounts(cmd)
            # targets and output live in the same per-run dir, mounted by its
            # host path, which for /tmp/redamon is the container path itself.
            assert m["/targets"] == m["/output"]
            assert m["/targets"].startswith("/tmp/redamon/.naabu_temp_")
            dirs.append(m["/targets"])
        assert dirs[0] != dirs[1], "two concurrent runs shared one temp dir"
        for d in dirs:
            assert not Path(d).exists(), f"{d} was not cleaned up by its own run"

    def test_cleanup_leaves_other_runs_files_alone(self):
        foreign = _foreign_files(".naabu_temp")
        _run_naabu(_recon(HOST_A), _FakeNaabu())
        _assert_foreign_files_survive(foreign)

    def test_single_run_command_is_unchanged_apart_from_the_dir(self):
        fake = _FakeNaabu()
        _run_naabu(_recon(HOST_A), fake)
        cmd = fake.calls[0]
        d = _mounts(cmd)["/targets"]
        expected = ps.build_naabu_command(f"{d}/targets.txt", f"{d}/naabu_output.json",
                                          dict(_NAABU_SETTINGS))
        # The name a timeout kills the container by (R-9) differs per run.
        i = cmd.index("--name")
        assert cmd[i + 1].startswith("naabu-")
        del cmd[i:i + 2]
        assert cmd == expected


# ---------------------------------------------------------------------------
# httpx (http_probe.run_http_probe)
# ---------------------------------------------------------------------------

class _StopProbe(RuntimeError):
    """Raised from the fake Popen; run_http_probe catches it and cleans up."""


def _https_port_scan(host):
    return {"by_host": {host: {"host": host, "port_details": [{"port": 443, "service": "https"}]}}}


def _run_httpx(recon, popen):
    with mock.patch.object(hp, "is_docker_installed", return_value=True), \
         mock.patch.object(hp, "is_docker_running", return_value=True), \
         mock.patch.object(hp, "pull_httpx_docker_image", return_value=True), \
         mock.patch.object(hp.subprocess, "Popen", side_effect=popen):
        return hp.run_http_probe(recon, output_file=None, settings={})


def _targets_of(cmd):
    m = _mounts(cmd)
    f = Path(m["/targets"]) / Path(cmd[cmd.index("-l") + 1]).name
    return f.read_text().split() if f.is_file() else None


class TestHttpxTempDir:
    def test_interleaved_runs_keep_their_own_targets_file(self):
        calls, seen = [], {}

        def fake_popen(cmd, **_kw):
            calls.append(list(cmd))
            if len(calls) == 1:
                seen["a_before"] = _targets_of(cmd)
                _run_httpx(_recon(HOST_B, _https_port_scan(HOST_B)), fake_popen)
                # A's httpx reads targets.txt only now, after B came and went.
                seen["a_after"] = _targets_of(cmd)
            else:
                seen["b"] = _targets_of(cmd)
            raise _StopProbe()

        _run_httpx(_recon(HOST_A, _https_port_scan(HOST_A)), fake_popen)

        assert seen["a_before"] == [f"https://{HOST_A}"]
        assert seen["b"] == [f"https://{HOST_B}"]
        assert seen["a_after"] == [f"https://{HOST_A}"], (
            f"run A's targets became {seen['a_after']} after run B")

        dirs = [_mounts(c)["/targets"] for c in calls]
        for c in calls:
            m = _mounts(c)
            assert m["/targets"] == m["/output"]
            assert m["/targets"].startswith("/tmp/redamon/.httpx_temp_")
        assert dirs[0] != dirs[1], "two concurrent runs shared one temp dir"
        for d in dirs:
            assert not Path(d).exists(), f"{d} was not cleaned up by its own run"

    def test_cleanup_leaves_other_runs_files_alone(self):
        foreign = _foreign_files(".httpx_temp")

        def fake_popen(cmd, **_kw):
            raise _StopProbe()

        _run_httpx(_recon(HOST_A, _https_port_scan(HOST_A)), fake_popen)
        _assert_foreign_files_survive(foreign)


# ---------------------------------------------------------------------------
# Amass (domain_recon.run_amass)
# ---------------------------------------------------------------------------

_AMASS_SETTINGS = {"AMASS_ENABLED": True}


def _run_amass(domain, fake_run):
    with mock.patch.object(dr, "_source_skipped", return_value=False), \
         mock.patch.object(dr, "_source_record"), \
         mock.patch.object(dr.subprocess, "run", side_effect=fake_run):
        return dr.run_amass(domain, settings=dict(_AMASS_SETTINGS))


class TestAmassTempDir:
    def test_interleaved_runs_keep_their_own_config_dir(self):
        calls, seen = [], {}

        def fake_run(cmd, **_kw):
            calls.append(list(cmd))
            config = Path(_mounts(cmd)["/root/.config/amass"])
            (config / "amass.sqlite").write_text(cmd[cmd.index("-d") + 1])
            if len(calls) == 1:
                _run_amass(HOST_B, fake_run)
                f = config / "amass.sqlite"
                seen["a_after"] = f.read_text() if f.is_file() else None
            return mock.MagicMock(returncode=0, stdout="", stderr="")

        _run_amass(HOST_A, fake_run)

        assert seen["a_after"] == HOST_A, "run B removed or reused run A's Amass config dir"
        dirs = [_mounts(c)["/root/.config/amass"] for c in calls]
        assert all(d.startswith("/tmp/redamon/.amass_temp_") for d in dirs)
        assert dirs[0] != dirs[1]
        for d in dirs:
            assert not Path(d).exists(), f"{d} was not cleaned up by its own run"

    def test_cleanup_leaves_other_runs_files_alone(self):
        foreign = _foreign_files(".amass_temp")
        _run_amass(HOST_A, lambda cmd, **_kw: mock.MagicMock(returncode=0, stdout="", stderr=""))
        _assert_foreign_files_survive(foreign)


# ---------------------------------------------------------------------------
# puredns (domain_recon.run_puredns_resolve)
# ---------------------------------------------------------------------------

_PUREDNS_DOMAIN = "example.test"
_SUBS_A = ["keep-a.example.test", "drop-a.example.test"]
_SUBS_B = ["keep-b.example.test", "drop-b.example.test"]


def _ensure_shared_resolvers():
    SHARED.mkdir(parents=True, exist_ok=True)
    shared = SHARED / "resolvers.txt"
    if not shared.exists():
        shared.write_text("192.0.2.53\n")


def _puredns_files(cmd):
    data = Path(_mounts(cmd)["/data"])
    return (data / Path(cmd[cmd.index("resolve") + 1]).name,
            data / Path(cmd[cmd.index("--write") + 1]).name)


def _fake_puredns(cmd):
    """Keep every name starting with 'keep', like puredns dropping wildcards."""
    inp, out = _puredns_files(cmd)
    if inp.is_file():
        kept = [n for n in inp.read_text().split() if n.startswith("keep")]
        out.write_text("\n".join(kept) + "\n")
    return mock.MagicMock(returncode=0, stderr="")


def _run_puredns(subs, fake_run):
    with mock.patch.object(dr, "_source_skipped", return_value=False), \
         mock.patch.object(dr, "_source_record"), \
         mock.patch.object(dr.subprocess, "run", side_effect=fake_run):
        names, _status = dr.run_puredns_resolve(list(subs), _PUREDNS_DOMAIN, {"PUREDNS_ENABLED": True})
        return names


class TestPurednsTempFiles:
    def test_interleaved_runs_on_the_same_domain_filter_only_their_own_list(self):
        _ensure_shared_resolvers()
        calls, results = [], {}

        def fake_run(cmd, **_kw):
            calls.append(list(cmd))
            if len(calls) == 1:
                results["b"] = _run_puredns(_SUBS_B, fake_run)
            return _fake_puredns(cmd)

        results["a"] = _run_puredns(_SUBS_A, fake_run)

        assert results["b"] == ["keep-b.example.test"]
        assert results["a"] == ["keep-a.example.test"], (
            f"run A returned {results['a']} after run B used the same domain")

        files = [_puredns_files(c) for c in calls]
        assert files[0][0] != files[1][0] and files[0][1] != files[1][1]
        for inp, out in files:
            assert inp.name.startswith(f"puredns_input_{_PUREDNS_DOMAIN}")
            assert out.name.startswith(f"puredns_output_{_PUREDNS_DOMAIN}")
            assert not inp.exists() and not out.exists(), "temp files were not cleaned up"

    def test_command_shape_is_unchanged_apart_from_the_file_names(self):
        _ensure_shared_resolvers()
        calls = []

        def fake_run(cmd, **_kw):
            calls.append(list(cmd))
            return _fake_puredns(cmd)

        _run_puredns(_SUBS_A, fake_run)
        cmd = calls[0]
        inp, out = _puredns_files(cmd)
        # The name a timeout kills the container by (R-9) differs per run.
        i = cmd.index("--name")
        assert cmd[i + 1].startswith("puredns-")
        del cmd[i:i + 2]
        assert cmd == [
            "docker", "run", "--rm",
            "-v", "/tmp/redamon:/data",
            "frost19k/puredns:latest",
            "resolve", f"/data/{inp.name}",
            "-r", "/data/resolvers.txt",
            "--write", f"/data/{out.name}",
            "-q",
        ]

    def test_stale_shared_resolver_list_is_refreshed_from_the_newer_source(self):
        src = Path("/app/recon/data/resolvers.txt")
        if not src.is_file():
            pytest.skip("this image has no /app/recon/data/resolvers.txt")
        SHARED.mkdir(parents=True, exist_ok=True)
        shared = SHARED / "resolvers.txt"
        shared.write_text("192.0.2.53\n")
        old = src.stat().st_mtime - 3600
        os.utime(shared, (old, old))

        _run_puredns(_SUBS_A, lambda cmd, **_kw: _fake_puredns(cmd))

        assert shared.is_file(), "the shared resolver list must never be deleted"
        assert shared.read_bytes() == src.read_bytes(), "stale shared resolver list was kept"


class TestRefreshSharedResolvers:
    def _src(self, tmp_path, text="192.0.2.1\n192.0.2.2\n"):
        src = tmp_path / "src" / "resolvers.txt"
        src.parent.mkdir()
        src.write_text(text)
        return src

    def test_copies_when_missing_world_readable_with_the_source_mtime(self, tmp_path):
        src = self._src(tmp_path)
        shared = tmp_path / "shared" / "resolvers.txt"
        shared.parent.mkdir()
        dr._refresh_shared_resolvers(src, shared)
        assert shared.read_text() == src.read_text()
        assert shared.stat().st_mode & 0o777 == 0o644
        # The copy carries the source's mtime, so the next run sees it as current.
        assert shared.stat().st_mtime == src.stat().st_mtime

    def test_replaces_an_older_copy(self, tmp_path):
        src = self._src(tmp_path, "192.0.2.7\n")
        shared = tmp_path / "resolvers.txt"
        shared.write_text("stale\n")
        old = src.stat().st_mtime - 60
        os.utime(shared, (old, old))
        dr._refresh_shared_resolvers(src, shared)
        assert shared.read_text() == "192.0.2.7\n"

    def test_leaves_an_up_to_date_copy_alone(self, tmp_path):
        src = self._src(tmp_path)
        shared = tmp_path / "resolvers.txt"
        dr._refresh_shared_resolvers(src, shared)
        with mock.patch.object(dr.shutil, "copy2") as copy2:
            dr._refresh_shared_resolvers(src, shared)
        copy2.assert_not_called()

    def test_missing_source_keeps_the_shared_copy(self, tmp_path):
        shared = tmp_path / "resolvers.txt"
        shared.write_text("192.0.2.9\n")
        dr._refresh_shared_resolvers(tmp_path / "nope.txt", shared)
        assert shared.read_text() == "192.0.2.9\n"

    def test_a_failed_copy_never_exposes_a_partial_file(self, tmp_path, capsys):
        src = self._src(tmp_path)
        shared = tmp_path / "resolvers.txt"
        shared.write_text("old\n")
        old = time.time() - 3600
        os.utime(shared, (old, old))

        def half_copy(_src, dst):
            Path(dst).write_text("192.0.")
            raise OSError("disk full")

        with mock.patch.object(dr.shutil, "copy2", side_effect=half_copy):
            dr._refresh_shared_resolvers(src, shared)

        assert shared.read_text() == "old\n"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["resolvers.txt", "src"]
        assert "Could not refresh" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# jsluice (jsluice_helpers.run_jsluice_analysis)
# ---------------------------------------------------------------------------

_JS_A = f"https://{HOST_A}/app.js"
_JS_B = f"https://{HOST_B}/app.js"


def _run_jsluice(js_url):
    return jh.run_jsluice_analysis(
        discovered_urls=[js_url], max_files=10, timeout=30,
        extract_urls=True, extract_secrets=False, concurrency=1, parallelism=1,
        allowed_hosts={HOST_A, HOST_B},
    )


class TestJsluiceWorkDir:
    def test_interleaved_runs_never_share_or_delete_each_others_work_dir(self):
        seen, after = [], {}

        def fake_download(js_urls, work_dir, parallelism=5, errors=None):
            work_dir = Path(work_dir)
            seen.append(work_dir)
            (work_dir / "js_0.js").write_text(js_urls[0])
            if len(seen) == 1:
                _run_jsluice(_JS_B)
                f = work_dir / "js_0.js"
                after["a"] = f.read_text() if f.is_file() else None
            return {}

        with mock.patch.object(jh.shutil, "which", return_value="/usr/local/bin/jsluice"), \
             mock.patch.object(jh, "_download_js_files", side_effect=fake_download):
            _run_jsluice(_JS_A)

        assert after["a"] == _JS_A, "run B removed or overwrote run A's downloaded JS"
        assert seen[0] != seen[1]
        assert all(str(d).startswith("/tmp/redamon/jsluice_") for d in seen)
        for d in seen:
            assert not d.exists(), f"{d} was not cleaned up by its own run"

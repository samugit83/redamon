"""nmap scans as many IPs at once as the project default says when the
settings it is handed omit NMAP_PARALLELISM.

The default is 5 in DEFAULT_SETTINGS, the Prisma column and the registry; the
module's own fallback was 2, so a caller that passed partial settings ran nmap
at less than half the shipped parallelism.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import nmap_scan  # noqa: E402
from recon.project_settings import DEFAULT_SETTINGS  # noqa: E402

IPS = [f"192.0.2.{i}" for i in range(10, 18)]


class _FakeNmap:
    def __init__(self):
        self.cmds: list = []

    def __call__(self, cmd, **_kw):
        self.cmds.append(cmd)
        target = cmd[-1]
        Path(cmd[cmd.index("-oX") + 1]).write_text(
            '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93">'
            '<host><status state="up" reason="syn-ack"/>'
            f'<address addr="{target}" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
            '<service name="https" product="nginx" version="1.25.0"/></port></ports>'
            '</host></nmaprun>')

        class _Proc:
            returncode = 0

            def communicate(self, timeout=None):
                return "", ""

        return _Proc()


def _pool_sizes(monkeypatch, settings):
    pools: list = []
    real_pool = nmap_scan.ThreadPoolExecutor

    def pool(*args, **kwargs):
        pools.append(kwargs.get("max_workers", args[0] if args else None))
        return real_pool(*args, **kwargs)

    nmap = _FakeNmap()
    monkeypatch.setattr(nmap_scan, "ThreadPoolExecutor", pool)
    monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
    monkeypatch.setattr(nmap_scan.subprocess, "Popen", nmap)
    recon = {"port_scan": {"by_ip": {ip: {"ip": ip, "hostnames": [], "ports": [443]} for ip in IPS},
                           "by_host": {}, "ip_to_hostnames": {}}}
    out = nmap_scan.run_nmap_scan(recon, settings=settings)
    assert sorted(e["ip"] for e in out["nmap_scan"]["by_host"].values()) == IPS
    assert sorted(cmd[-1] for cmd in nmap.cmds) == IPS
    return pools


def test_missing_parallelism_falls_back_to_the_project_default(monkeypatch):
    assert DEFAULT_SETTINGS["NMAP_PARALLELISM"] == 5
    assert _pool_sizes(monkeypatch, {"ROE_ENABLED": False}) == [DEFAULT_SETTINGS["NMAP_PARALLELISM"]]


def test_an_explicit_parallelism_still_wins(monkeypatch):
    assert _pool_sizes(monkeypatch, {"NMAP_PARALLELISM": 3}) == [3]

"""A partial Masscan run that masscan never completed ends failed, not "completed successfully".

run_masscan_scan returns the recon dict unchanged, with no masscan_scan
section, when masscan exits with an error before writing output (here the
"could not determine default interface" a container without a usable route
gives), when it is not installed, or when it times out. The partial run used to
write that empty result back and print "Masscan port scanning completed
successfully". Now nothing is written, the addresses it was handed are noted
not scanned (so the coverage record says so and no prune reads their old
ports as gone), and the run report names the failure, exit 1.

The masscan process, the graph and the settings are fakes. Documentation
addresses (RFC 5737) only.

Run: ./redamon.sh test unit (recon section), or one file in the recon image
(06_testing.md §1.2 of the IP-mode plan).
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.partial_recon_modules import helpers  # noqa: E402

PID = "cmpartialmasscanfail000001"
ROOT = f"ip-targets.{PID}"
T1, T2 = "203.0.113.1", "203.0.113.2"
SETTINGS = {"IP_MODE": True, "TARGET_IPS": [T1, T2], "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [],
            "DOMAIN_BATCH_MODE": False, "TARGET_DOMAIN": "", "MASSCAN_ENABLED": True,
            "MASSCAN_TOP_PORTS": "100", "MASSCAN_RATE": 100}
STDERR = "FAIL: could not determine default interface\nFAIL:... try \"--interface ethX\"\n"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    helpers.set_run_ip_targets({})
    yield
    helpers.set_run_ip_targets({})
    circuit_breaker.reset_registry()


class _FailingMasscan:
    """subprocess.Popen as masscan behaves without a default interface."""
    calls: list = []

    def __init__(self, cmd, *_a, **_k):
        _FailingMasscan.calls.append(cmd)
        self.returncode = 1

    def communicate(self, timeout=None):
        return "", STDERR


class _NoWrite:
    def __init__(self, *_a, **_k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return True

    def update_graph_from_port_scan(self, *_a, **_k):
        pytest.fail("a failed masscan run wrote its empty result to the graph")

    def create_user_input_node(self, *_a, **_k):
        pytest.fail("a failed masscan run created a UserInput node")


@pytest.fixture
def failing_masscan(monkeypatch):
    from recon.main_recon_modules import masscan_scan
    _FailingMasscan.calls = []
    monkeypatch.setattr(masscan_scan, "is_masscan_installed", lambda: True)
    monkeypatch.setattr(masscan_scan.subprocess, "Popen", _FailingMasscan)
    monkeypatch.setattr("graph_db.Neo4jClient", _NoWrite)
    monkeypatch.setattr("graph_db.neo4j_client.Neo4jClient", _NoWrite)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    return _FailingMasscan


def _run(capsys):
    import recon.partial_recon as pr
    cfg = {"tool_id": "Masscan", "domains": [ROOT], "include_graph_targets": False,
           "user_targets": {"ips": [T1, T2]}}
    refused = pr._prepare_scope(cfg, dict(SETTINGS), PID)
    statuses, completed = pr._run_tool("Masscan", cfg)
    pr.print_run_report("Masscan", statuses, refused)
    return statuses, completed, capsys.readouterr().out


def test_a_masscan_that_never_ran_fails_the_run(failing_masscan, capsys):
    statuses, completed, out = _run(capsys)
    assert failing_masscan.calls, "masscan was never started"
    assert statuses == {ROOT: "failed: Masscan produced no result"}
    assert completed is True
    import recon.partial_recon as pr
    assert pr.run_exit_code(statuses) == 1
    assert "completed successfully" not in out
    assert "Roots scanned (0): none" in out
    assert f"{ROOT}: failed: Masscan produced no result" in out
    assert "could not determine default interface" in out      # masscan's own line stays in the log


def test_the_addresses_it_never_scanned_are_noted(failing_masscan, capsys):
    _run(capsys)
    report = circuit_breaker.coverage_report()
    assert report.degraded
    assert {T1, T2} <= set(report.skipped_hosts)
    # Cut for masscan only: the other tools still reached these hosts.
    assert set(dict(report.source_hosts).get("masscan") or ()) == {T1, T2}


def test_a_masscan_that_ran_still_writes_and_completes(monkeypatch, capsys):
    from recon.main_recon_modules import masscan_scan
    from recon.partial_recon_modules import port_scanning
    written = []

    class _Writes(_NoWrite):
        def update_graph_from_port_scan(self, recon_data, **_k):
            written.append(recon_data)
            return {}

    monkeypatch.setattr("graph_db.Neo4jClient", _Writes)
    monkeypatch.setattr(masscan_scan, "run_masscan_scan",
                        lambda recon_data, **_k: dict(recon_data, masscan_scan={
                            "by_ip": {T1: {"ports": [443]}}, "by_host": {}, "all_ports": [443],
                            "ip_to_hostnames": {}, "summary": {}, "scan_metadata": {}}))
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    helpers.set_run_ip_targets(SETTINGS)
    monkeypatch.setattr(port_scanning, "_build_recon_data_from_graph", lambda *_a, **_k: helpers.ip_mode_recon({
        "domain": ROOT, "domains": [ROOT],
        "dns": {"domain": {"ips": {"ipv4": [T1], "ipv6": []}, "has_records": True}, "subdomains": {}}}))
    cfg = {"tool_id": "Masscan", "domains": [ROOT], "include_graph_targets": True, "_settings": dict(SETTINGS)}
    assert port_scanning.run_masscan(cfg) is None
    assert written and written[0]["port_scan"]["all_ports"] == [443]
    assert "Masscan port scanning completed successfully" in capsys.readouterr().out


def test_the_addresses_of_a_domain_run_come_from_its_dns_block():
    from recon.partial_recon_modules.port_scanning import _scanned_addresses
    data = {"dns": {"domain": {"ips": {"ipv4": [T1], "ipv6": []}},
                    "subdomains": {"www.example.com": {"ips": {"ipv4": [T2, ""], "ipv6": ["2001:db8::1"]}},
                                   "bad.example.com": None}}}
    assert _scanned_addresses(data) == ["2001:db8::1", T1, T2]
    assert _scanned_addresses({"metadata": {"ip_mode": True, "expanded_ips": [T2, T1, None]}}) == [T1, T2]

"""Partial tlsx handshakes the IP the operator typed, never another one.

The operator types IPs and, optionally, the Subdomain they belong to
(``ip_attach_to``). run_tlsx put that name in the typed IP's port-scan row,
and _build_tlsx_targets sends a row's name instead of its address so tlsx
presents SNI. tlsx resolves a name itself, so the handshake went to whatever
the name resolves to, and its certificate was written onto the typed IP.

tlsx takes SNI only as one global ``-sni`` for the whole run (v1.2.2), and the
command is built in tls_scan.py, so the partial module keeps the name on a
typed IP only when tlsx resolving it lands on that IP: the name's one address
is the typed IP. Otherwise the typed IP is handshaken as a bare address.

The target lines asserted are the real _build_tlsx_targets output on the dict
run_tlsx hands run_tlsx_enrichment; DNS is a fake socket.getaddrinfo.
Reserved names and documentation ranges only; no Docker, no network.
"""
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402
from recon.partial_recon_modules import tlsx_scanning  # noqa: E402

ROOTS = ["example.com"]
NAME = "app.example.com"
TYPED = "192.0.2.10"


class FakeDns:
    def __init__(self, table=None):
        self.table = dict(table or {})
        self.asked = []

    def __call__(self, host, port=None, *args, **kwargs):
        self.asked.append(host)
        answers = self.table.get(str(host).rstrip(".").lower())
        if not answers:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (a, 0, 0, 0) if ":" in a else (a, 0)) for a in answers]


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    fake = FakeDns()
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


@pytest.fixture(autouse=True)
def _domain_run():
    partial_helpers.set_run_ip_targets({})
    yield
    partial_helpers.set_run_ip_targets({})


def _run_tlsx(user_targets, settings=None, include_graph=False):
    """run_tlsx on typed input; returns (lines, meta) of the target file."""
    from recon.main_recon_modules import tls_scan
    client = MagicMock()
    client.verify_connection.return_value = True
    client.update_graph_from_tlsx.return_value = {}
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    fake_graph_db = MagicMock()
    fake_graph_db.Neo4jClient.return_value = client
    built = []

    def enrichment(recon_data, settings=None):
        built.append(tls_scan._build_tlsx_targets(recon_data, settings))
        return recon_data

    config = {"_settings": dict(settings or {}), "domains": list(ROOTS), "domain": ROOTS[0],
              "include_graph_targets": include_graph, "user_targets": user_targets}
    with patch.dict(sys.modules, {"graph_db": fake_graph_db}), \
         patch("recon.main_recon_modules.tls_scan.run_tlsx_enrichment", side_effect=enrichment), \
         patch("recon.main_recon_modules.ip_filter.is_non_routable_ip", return_value=False):
        tlsx_scanning.run_tlsx(config)
    assert len(built) == 1
    return built[0]


def test_an_attach_name_resolving_elsewhere_never_steers_the_handshake(dns):
    dns.table = {NAME: ["198.51.100.50"]}
    lines, meta = _run_tlsx({"ips": [TYPED], "ports": [993], "ip_attach_to": NAME})
    assert lines == [f"{TYPED}:993"]
    assert meta == {f"{TYPED}:993": TYPED}


def test_an_attach_name_whose_one_address_is_the_typed_ip_is_sent_for_sni(dns):
    # tlsx resolving the name lands on the typed IP, so the name only adds SNI.
    dns.table = {NAME: [TYPED]}
    lines, meta = _run_tlsx({"ips": [TYPED], "ports": [993], "ip_attach_to": NAME})
    assert lines == [f"{NAME}:993"]
    assert meta == {f"{NAME}:993": TYPED}


def test_an_attach_name_with_a_second_address_is_not_sent(dns):
    # tlsx could pick either address, so the line would not reach the typed IP.
    dns.table = {NAME: [TYPED, "192.0.2.77"]}
    lines, _ = _run_tlsx({"ips": [TYPED], "ports": [993], "ip_attach_to": NAME})
    assert lines == [f"{TYPED}:993"]


def test_an_attach_name_with_no_address_is_not_sent(dns):
    lines, _ = _run_tlsx({"ips": [TYPED], "ports": [993], "ip_attach_to": NAME})
    assert lines == [f"{TYPED}:993"]
    assert dns.asked == [NAME]


def test_a_typed_cidr_gives_the_name_only_to_the_address_it_resolves_to(dns):
    dns.table = {NAME: ["192.0.2.9"]}
    lines, meta = _run_tlsx({"ips": ["192.0.2.8/30"], "ports": [993], "ip_attach_to": NAME})
    assert sorted(lines) == sorted([f"{NAME}:993", "192.0.2.10:993"])
    assert meta[f"{NAME}:993"] == "192.0.2.9" and meta["192.0.2.10:993"] == "192.0.2.10"
    assert dns.asked == [NAME]


def test_the_name_still_marks_the_typed_ips_as_attached(dns):
    # The attach decides the graph link (no generic UserInput), whatever tlsx is sent.
    dns.table = {NAME: ["198.51.100.50"]}
    client = MagicMock()
    client.verify_connection.return_value = True
    client.update_graph_from_tlsx.return_value = {}
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    fake_graph_db = MagicMock()
    fake_graph_db.Neo4jClient.return_value = client
    with patch.dict(sys.modules, {"graph_db": fake_graph_db}), \
         patch("recon.main_recon_modules.tls_scan.run_tlsx_enrichment",
               side_effect=lambda rd, settings=None: rd):
        tlsx_scanning.run_tlsx({"_settings": {}, "domains": ROOTS, "domain": ROOTS[0],
                                "include_graph_targets": False,
                                "user_targets": {"ips": [TYPED], "ports": [993], "ip_attach_to": NAME}})
    client.create_user_input_node.assert_not_called()


def test_the_tlsx_command_is_unchanged():
    from recon.main_recon_modules.tls_scan import build_tlsx_command
    cmd = build_tlsx_command("/tmp/t/targets.txt", "/tmp/t", {})
    assert "-sni" not in cmd
    assert cmd[cmd.index("-l") + 1] == "/tmp/t/targets.txt"


def test_ip_mode_keeps_its_label_rule_and_resolves_nothing(dns):
    settings = {"IP_MODE": True, "TARGET_IPS": [TYPED]}
    partial_helpers.set_run_ip_targets(settings)
    lines, meta = _run_tlsx({"ips": [TYPED], "ports": [993], "ip_attach_to": "192-0-2-10"},
                            settings=settings)
    assert lines == [f"{TYPED}:993"]
    assert dns.asked == []

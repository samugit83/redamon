"""A certificate SAN never mints a Subdomain the scan did not admit (D2, R-2).

A certificate names whatever its owner put on it, and the target chooses that
list. In the full pipeline merge_discovered_hostnames decides which SAN names
join the scan (group scope, RoE, syntax, cap, non-routable address, wildcard
DNS), and the late-name DNS step writes the admitted ones as Subdomains under
their Domain. update_graph_from_tlsx then MERGEd a Subdomain for every SAN under
a scan root regardless of that verdict: an RoE-excluded name became a Subdomain
with only a COVERS_HOST edge and no BELONGS_TO, which partial Naabu, httpx and
Nuclei read back as a target. Partial tlsx, which admits no SAN at all, did the
same.

The writer now only links a certificate to a Subdomain already in the tenant's
graph, as the Uncover writer links a URL; the certificate's san list still
records every name. The real parser, merge and writer run; DNS and Neo4j are
the fakes (an empty graph). Only example.com names and RFC 5737 addresses.
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.recon.tlsx_mixin import TlsxMixin  # noqa: E402
from recon.helpers.target_helpers import merge_discovered_hostnames  # noqa: E402
from recon.main_recon_modules.tls_scan import _discovered_hostnames, _parse_tlsx_output  # noqa: E402

ROOT = "example.com"
KEPT = "api.example.com"
EXCLUDED = "shop.example.com"
SIBLING = "www.example.com"
FOREIGN = "cdn.example.net"
IP = "192.0.2.10"
PORT = 8443
ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED]}
PID = "proj-tlsx-san"


class _Session:
    """Records every statement and answers no rows: an empty graph."""

    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda _s: iter([])
        return result


def _writer():
    session = _Session()
    writer = TlsxMixin()
    writer.driver = MagicMock()
    writer.driver.session.return_value = session
    return writer, session


def _minted(session) -> set:
    """Every name a statement may create a Subdomain node for."""
    return {params.get("name") for cypher, params in session.calls
            if "MERGE (s:Subdomain" in cypher or "CREATE (s:Subdomain" in cypher}


def _covers_lookups(session) -> list:
    return [params for cypher, params in session.calls if "COVERS_HOST" in cypher]


def _cert_sans(session) -> list:
    for cypher, params in session.calls:
        if "MERGE (c:Certificate" in cypher:
            return list(params["props"].get("san") or [])
    return []


def _tlsx_payload() -> dict:
    """What run_tlsx_enrichment stores, built by the real parser."""
    line = json.dumps({
        "host": KEPT, "ip": IP, "port": str(PORT), "probe_status": True,
        "tls_version": "tls13", "subject_cn": KEPT, "subject_dn": f"CN={KEPT}",
        "subject_an": [KEPT, EXCLUDED, SIBLING, FOREIGN],
        "issuer_cn": "Example CA", "issuer_dn": "CN=Example CA",
        "serial": "01", "fingerprint_hash": {"sha256": "ab" * 32},
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
    })
    by_target = _parse_tlsx_output(line, {f"{KEPT}:{PORT}": IP})
    return {"by_target": by_target, "discovered_hostnames": _discovered_hostnames(by_target),
            "wildcard_dropped": [], "cdn_by_ip": {}}


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    """The merge resolves each name and probes its zone for wildcard DNS."""
    from recon.helpers import circuit_breaker, wildcard_control

    def getaddrinfo(host, *_a, **_k):
        raise socket.gaierror(socket.EAI_NONAME, "unknown name")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(wildcard_control, "_query", lambda name, rtype: ("nx", []))
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _group_recon(mode: str, exact_hosts=()) -> dict:
    """What run_domain_recon holds for one scope group at GROUP 3.6."""
    return {"domain": ROOT, "dns": {"domain": {}, "subdomains": {}},
            "metadata": {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": mode,
                         "include_root_domain": False, "subdomain_filter": list(exact_hosts)},
            "tlsx": _tlsx_payload()}


def _full_run(combined: dict, settings: dict, inject: bool = True):
    """GROUP 3.6 in main.py: the merge (when injection is on), then the writer."""
    if inject:
        merge_discovered_hostnames(
            combined, combined["tlsx"]["discovered_hostnames"], source="tlsx",
            root_domain=ROOT, settings=settings, max_injected=200)
    writer, session = _writer()
    stats = writer.update_graph_from_tlsx(combined, "u1", PID)
    return session, stats


# --------------------------------------------------------------------------- #
# Full pipeline
# --------------------------------------------------------------------------- #
def test_an_roe_excluded_san_never_becomes_a_subdomain():
    combined = _group_recon("enumerate")
    session, stats = _full_run(combined, ROE)

    subs = combined["dns"]["subdomains"]
    assert EXCLUDED not in subs and KEPT in subs
    assert EXCLUDED not in _minted(session)
    assert stats["errors"] == []


def test_the_writer_mints_no_subdomain_at_all():
    # The names the merge admitted are written by the late-name DNS step,
    # under their Domain; the certificate only links to them.
    session, _stats = _full_run(_group_recon("enumerate"), ROE)

    assert _minted(session) == set()


def test_the_certificate_still_records_every_name():
    session, _stats = _full_run(_group_recon("enumerate"), ROE)

    assert {KEPT, EXCLUDED, SIBLING, FOREIGN} <= set(_cert_sans(session))


def test_links_are_tenant_scoped_lookups_and_skip_foreign_names():
    session, _stats = _full_run(_group_recon("enumerate"), ROE)

    lookups = _covers_lookups(session)
    assert sorted(p["name"] for p in lookups) == sorted([KEPT, EXCLUDED, SIBLING])
    assert all(p["uid"] == "u1" and p["pid"] == PID for p in lookups)
    for cypher, _params in session.calls:
        if "COVERS_HOST" in cypher:
            assert "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})" in cypher


def test_an_exact_group_mints_no_unlisted_san():
    # An EXACT group scans the listed hosts only; the merge admits no SAN.
    combined = _group_recon("exact", exact_hosts=[KEPT])
    session, _stats = _full_run(combined, {})

    assert combined["dns"]["subdomains"] == {}
    assert _minted(session) == set()


def test_with_injection_off_no_san_becomes_a_subdomain():
    # TLSX_INJECT_HOSTNAMES off: "no name from a certificate is added as a
    # target", and partial scans read every Subdomain back as one.
    session, _stats = _full_run(_group_recon("enumerate"), {}, inject=False)

    assert _minted(session) == set()


# --------------------------------------------------------------------------- #
# Partial tlsx (admits no SAN: it runs no merge)
# --------------------------------------------------------------------------- #
def test_partial_tlsx_mints_no_subdomain_for_an_excluded_san(monkeypatch):
    from recon.partial_recon_modules import tlsx_scanning

    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)

    def graph_recon(domains, *_a, **_kw):
        return {
            "domain": domains[0], "domains": list(domains),
            "port_scan": {"by_ip": {IP: {"ip": IP, "hostnames": [KEPT], "ports": [PORT],
                                         "port_details": []}},
                          "by_host": {}, "ip_to_hostnames": {}, "all_ports": [PORT],
                          "scan_metadata": {}, "summary": {}},
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                    "subdomains": {}},
            "metadata": {"include_root_domain": False},
        }

    def grab(recon_data, settings=None):
        recon_data["tlsx"] = _tlsx_payload()
        return recon_data

    writer, session = _writer()
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_tlsx.side_effect = writer.update_graph_from_tlsx
    fake_graph_db = MagicMock()
    fake_graph_db.Neo4jClient.return_value = client
    monkeypatch.setattr(tlsx_scanning, "_build_port_scan_data_from_graph", graph_recon)

    with patch.dict(sys.modules, {"graph_db": fake_graph_db}), \
         patch("recon.main_recon_modules.tls_scan.run_tlsx_enrichment", side_effect=grab):
        tlsx_scanning.run_tlsx({"_settings": dict(ROE), "domains": [ROOT], "domain": ROOT})

    assert client.update_graph_from_tlsx.called
    assert EXCLUDED not in _minted(session)
    assert _minted(session) == set()
    assert EXCLUDED in _cert_sans(session)

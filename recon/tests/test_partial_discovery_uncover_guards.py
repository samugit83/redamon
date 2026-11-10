"""Partial discovery and partial Uncover apply the full pipeline's name guards (R-12).

Partial Naabu, httpx and Nuclei read their targets back from the graph, so a
name a partial run writes is a name a later partial run scans.

- Discovery: merge_group_hosts drops a DISCOVERED name that resolves to a
  never-scannable address (loopback, link-local such as 169.254.169.254,
  multicast, unspecified). Partial discovery wrote such names. The operator's
  own hosts and the scan root stay: scanning them is the operator's decision,
  and private addresses stay (internal estates are scanned on purpose).
- Uncover: the full pipeline passes the search-engine payload through
  merge_uncover_into_pipeline before update_graph_from_uncover. An EXACT group
  then writes no discovered host, IP or port (a URL on a listed host stays),
  and an ENUMERATE group's names pass RoE, syntax and the non-routable check.
  Partial Uncover wrote the raw payload.

The real modules run, with the real _prepare_scope building the run's scope
groups; discovery, DNS, the Uncover container and Neo4j are the fakes. Only
example.com names and RFC 5737 addresses are used, plus the special-purpose
addresses the guard is about.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import helpers, osint_enrichment, subdomain_discovery  # noqa: E402

ROOT = "example.com"
PID = "proj-r12"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    monkeypatch.delenv("WEBAPP_API_URL", raising=False)


@pytest.fixture
def graph(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    for writer in ("update_graph_from_partial_discovery", "update_graph_from_uncover",
                   "create_user_input_node", "update_user_input_status"):
        getattr(client, writer).return_value = {}
    monkeypatch.setattr("graph_db.Neo4jClient", MagicMock(return_value=client))
    return client


def _settings(mode: str, exact_hosts=(), include_root=False, **extra) -> dict:
    return {"TARGET_DOMAIN": ROOT, "IP_MODE": False, "DOMAIN_BATCH_MODE": False,
            "VERIFY_DOMAIN_OWNERSHIP": False, "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [],
            "SCOPE_GROUPS": [{"scanRoot": ROOT, "orgDomain": ROOT, "mode": mode,
                              "includeRoot": include_root, "exactHosts": list(exact_hosts)}],
            **extra}


def _prepared(tool_id: str, settings: dict, **config) -> dict:
    """The config a module receives: the real _prepare_scope."""
    import recon.partial_recon as pr
    cfg = {"tool_id": tool_id, "domains": [ROOT], "include_graph_targets": True, **config}
    refused = pr._prepare_scope(cfg, settings, PID)
    assert refused == {}
    return cfg


# --------------------------------------------------------------------------- #
# Partial discovery: the never-scannable-address guard
# --------------------------------------------------------------------------- #
ADDRESSES = {
    "www.example.com": ["203.0.113.10"],
    "intranet.example.com": ["10.0.0.5"],
    "meta.example.com": ["169.254.169.254"],
    "localhost.example.com": ["127.0.0.1"],
    "mcast.example.com": ["224.0.0.251"],
    "dual.example.com": ["203.0.113.11", "fe80::1"],
    "dev.example.com": ["127.0.0.1"],
    "lab.example.com": ["127.0.0.1"],
}
NEVER_SCANNABLE = {"meta.example.com", "localhost.example.com", "mcast.example.com",
                   "dual.example.com"}


def _dns_entry(addresses):
    return {"ips": {"ipv4": [a for a in addresses if ":" not in a],
                    "ipv6": [a for a in addresses if ":" in a]},
            "has_records": True}


def _dns(names):
    return {"domain": {}, "subdomains": {n: _dns_entry(ADDRESSES[n]) for n in names}}


DISCOVERED = ["www.example.com", "intranet.example.com", "meta.example.com",
              "localhost.example.com", "mcast.example.com", "dual.example.com"]


def _discovery_result(extra=()):
    names = DISCOVERED + list(extra)
    return {"domain": ROOT, "subdomains": names, "subdomain_count": len(names),
            "dns": _dns(names), "external_domains": [],
            "subdomain_status_map": {n: "resolved" for n in names}}


def _discover(cfg, extra=()):
    with patch("recon.main_recon_modules.domain_recon.discover_subdomains",
               return_value=_discovery_result(extra)), \
         patch("recon.main_recon_modules.domain_recon.run_puredns_resolve",
               side_effect=lambda subs, domain, s: (list(subs), "filtered")), \
         patch("recon.main_recon_modules.domain_recon.resolve_all_dns",
               side_effect=lambda domain, subs, **kw: _dns(subs)):
        return subdomain_discovery.run_subdomain_discovery(cfg)


def _written_discovery(graph):
    return graph.update_graph_from_partial_discovery.call_args.kwargs["recon_data"]


def test_discovered_names_on_never_scannable_addresses_are_not_written(graph, capsys):
    statuses = _discover(_prepared("SubdomainDiscovery", _settings("enumerate")))

    written = _written_discovery(graph)
    kept = ["www.example.com", "intranet.example.com"]
    assert written["subdomains"] == kept
    assert written["subdomain_count"] == 2
    assert set(written["dns"]["subdomains"]) == set(kept)
    assert set(written["subdomain_status_map"]) == set(kept)
    assert statuses[ROOT] == "ok"
    out = capsys.readouterr().out
    assert "Dropped discovered host meta.example.com" in out


def test_a_host_the_operator_typed_is_kept_whatever_it_resolves_to(graph):
    _discover(_prepared("SubdomainDiscovery", _settings("enumerate"),
                        user_inputs=["dev.example.com"]))

    written = _written_discovery(graph)
    assert "dev.example.com" in written["subdomains"]
    assert written["dns"]["subdomains"]["dev.example.com"]["ips"]["ipv4"] == ["127.0.0.1"]
    assert not NEVER_SCANNABLE & set(written["subdomains"])
    assert not NEVER_SCANNABLE & set(written["dns"]["subdomains"])


def test_a_host_the_group_lists_is_kept_when_discovery_also_finds_it(graph):
    _discover(_prepared("SubdomainDiscovery", _settings("enumerate", exact_hosts=["lab.example.com"])),
              extra=["lab.example.com"])

    written = _written_discovery(graph)
    assert "lab.example.com" in written["subdomains"]
    assert "lab.example.com" in written["dns"]["subdomains"]
    assert not NEVER_SCANNABLE & set(written["subdomains"])


# --------------------------------------------------------------------------- #
# Partial Uncover: merge_uncover_into_pipeline before the write
# --------------------------------------------------------------------------- #
def _uncover_payload():
    return {
        "hosts": ["api.example.com", "shop.example.com", "meta.example.com"],
        "ips": ["203.0.113.5"],
        "ip_ports": {"203.0.113.5": [443, 6333]},
        "urls": ["https://api.example.com/login", "https://shop.example.com/cart"],
        "sources": ["shodan"], "source_counts": {"shodan": 5},
        "total_raw": 5, "total_deduped": 5,
    }


def _fake_getaddrinfo(host, *_a, **_k):
    if host == "meta.example.com":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
    raise socket.gaierror(socket.EAI_NONAME, "unknown name")


def _uncover(cfg):
    with patch("recon.main_recon_modules.uncover_enrich.run_uncover_expansion",
               side_effect=lambda combined, settings: _uncover_payload()), \
         patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        return osint_enrichment.run_uncover(cfg)


def _written_uncover(graph):
    return graph.update_graph_from_uncover.call_args.kwargs["recon_data"]["uncover"]


def test_an_exact_group_writes_no_search_engine_host_ip_or_port(graph):
    statuses = _uncover(_prepared("Uncover", _settings("exact", exact_hosts=["api.example.com"])))

    written = _written_uncover(graph)
    assert written["hosts"] == []
    assert written["ips"] == []
    assert written["ip_ports"] == {}
    assert written["urls"] == ["https://api.example.com/login"]
    assert statuses[ROOT] == "ok"


def test_an_enumerate_group_writes_only_names_that_pass_the_gates(graph):
    settings = _settings("enumerate", DNS_ENABLED=False, ROE_ENABLED=True,
                         ROE_EXCLUDED_HOSTS=["shop.example.com"])
    _uncover(_prepared("Uncover", settings))

    written = _written_uncover(graph)
    # shop: RoE-excluded; meta: resolves to a link-local address.
    assert written["hosts"] == ["api.example.com"]
    assert written["ips"] == ["203.0.113.5"]
    assert written["ip_ports"] == {"203.0.113.5": [443, 6333]}

"""Partial AI Surface sends its vector-DB reads only to ports an active scan found
on addresses the run may touch (R-13).

The partial module read every (IP)-[:HAS_PORT]->(Port) of the project and
handed them to the full module's _confirm_vector_dbs, which sends a read to
each vector-DB port. A Port a passive source wrote (Shodan, Uncover...) is a
third party's crawl, often of an address outside the engagement, and an
RoE-excluded address must never be sent a request. The full pipeline reads
port_scan.by_host, which holds only what its own active scan found.

The real partial module runs, with the real _prepare_scope (RoE) and the real
PortMixin.active_open_ports; the fake graph answers that query the way its
Cypher predicate reads (an active writer's passive_only = false, or a Port
from before the mark that no passive provider created). The captured recon
dict is then fed to the real _confirm_vector_dbs to list the requests it
builds. Only example.com names and RFC 5737 addresses are used.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.recon.port_mixin import PASSIVE_PORT_SOURCES, PortMixin  # noqa: E402
from recon.main_recon_modules import ai_surface_recon as full  # noqa: E402
from recon.partial_recon_modules import ai_surface_recon as partial  # noqa: E402

ROOT = "example.com"
PID = "proj-r13"
EXCLUDED_NET = "192.0.2.0/24"

# (ip, port, passive_only, source): the graph's Port nodes. 6333 is Qdrant and
# 19530 Milvus in the AI port catalogue.
PORTS = [
    ("203.0.113.20", 6333, False, None),          # naabu found it
    ("203.0.113.21", 19530, None, None),          # an active Port from before the mark
    ("198.51.100.30", 6333, True, "shodan"),      # Shodan's crawl, outside the roots
    ("203.0.113.22", 6333, None, "uncover"),      # an Uncover search result
    ("192.0.2.40", 6333, False, None),            # active, but the RoE excludes the address
]
PROBED = {"203.0.113.20": [6333], "203.0.113.21": [19530]}


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def close(self):
        pass

    def run(self, cypher, **params):
        self.queries.append(" ".join(cypher.split()))
        if "ai_interface_type IS NOT NULL" in cypher:
            return [{"base_url": "https://api.example.com", "path": "/v1/chat/completions",
                     "method": "POST", "iface": "llm-chat", "ai_fw": False,
                     "declared_only": False}]
        if "HAS_PORT" not in cypher:
            return []
        rows = [r for r in PORTS if "ips" not in params or r[0] in params["ips"]]
        if "p.passive_only = false" in cypher:
            rows = [r for r in rows if r[2] is False
                    or (r[2] is None and (r[3] or "") not in PASSIVE_PORT_SOURCES)]
        if "collect(DISTINCT p.number) AS ports" in cypher:
            by_ip = {}
            for ip, port, *_ in rows:
                by_ip.setdefault(ip, []).append(port)
            return [{"ip": ip, "ports": ports} for ip, ports in by_ip.items()]
        return [{"ip": ip, "port": port} for ip, port, *_ in rows]


class _Client(PortMixin):
    queries: list = []

    def __init__(self, *_a, **_k):
        self.driver = self

    def session(self, **_k):
        return _Session(_Client.queries)

    def close(self):
        pass

    def update_graph_from_ai_surface_recon(self, *_a, **_k):
        return {}


def _settings(**extra) -> dict:
    return {"TARGET_DOMAIN": ROOT, "IP_MODE": False, "DOMAIN_BATCH_MODE": False,
            "VERIFY_DOMAIN_OWNERSHIP": False, "ROE_ENABLED": True,
            "ROE_EXCLUDED_HOSTS": [EXCLUDED_NET],
            "SCOPE_GROUPS": [{"scanRoot": ROOT, "orgDomain": ROOT, "mode": "enumerate",
                              "includeRoot": True, "exactHosts": []}],
            **extra}


def _run(settings: dict) -> dict:
    import recon.partial_recon as pr
    cfg = {"tool_id": "AiSurfaceRecon", "domains": [ROOT], "include_graph_targets": True}
    assert pr._prepare_scope(cfg, settings, PID) == {}
    _Client.queries = []
    seen = {}
    with mock.patch("graph_db.neo4j_client.Neo4jClient", _Client), \
         mock.patch.object(full, "run_ai_surface_recon",
                           side_effect=lambda data, *a, **k: seen.update(data) or data), \
         mock.patch.dict("os.environ", {"USER_ID": "u1", "PROJECT_ID": PID}):
        partial.run_ai_surface_recon(cfg)
    return seen


class _Requests:
    def __init__(self):
        self.urls = []

    def get(self, url, *_a, **_k):
        self.urls.append(url)
        return mock.Mock(status_code=404, text="")


def test_only_active_ports_on_admitted_addresses_reach_the_vector_db_reads():
    seen = _run(_settings())

    by_host = seen["port_scan"]["by_host"]
    assert {host: sorted(rec["ports"]) for host, rec in by_host.items()} == PROBED
    assert all(rec["ip"] == host for host, rec in by_host.items())

    requests = _Requests()
    full._confirm_vector_dbs(seen, requests, 1)
    assert requests.urls
    assert {urlparse(u).hostname for u in requests.urls} == set(PROBED)


def test_without_an_roe_exclusion_the_active_port_on_that_address_is_read():
    seen = _run(_settings(ROE_ENABLED=False))

    by_host = seen["port_scan"]["by_host"]
    assert {host: sorted(rec["ports"]) for host, rec in by_host.items()} == {
        **PROBED, "192.0.2.40": [6333]}


def test_the_port_read_is_parameterised():
    _run(_settings())

    port_reads = [q for q in _Client.queries if "HAS_PORT" in q]
    assert port_reads
    assert all("$" in q and "203.0.113" not in q for q in port_reads)

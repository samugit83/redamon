"""Partial recon's DNS view ignores Shodan's reverse-DNS edges (plan 11.6).

A partial run reads "which IPs do these names resolve to" from the graph's
Subdomain -[:RESOLVES_TO]-> IP edges. Shodan's PTR and domain-DNS answers write
the same edge, so between full runs a partial run took them for current DNS:
the OSINT enrichers re-queried those IPs, IP attribution counted them as DNS
names, vhost/SNI called them DNS-known. Every builder now skips an edge whose
`source` starts with 'shodan_'; an edge with no source (DNS, or written before
plan 11) still counts.

A fake Neo4j records the Cypher each builder sends; no graph.
"""
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import graph_builders as gb  # noqa: E402

FORWARD = "r.source IS NULL"


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.queries.append(" ".join(query.split()))
        result = mock.MagicMock()
        result.__iter__ = lambda s: iter([])
        result.single.return_value = None
        return result


def _fake_graph_db(queries):
    client = mock.MagicMock()
    client.verify_connection.return_value = True
    client.driver.session.side_effect = lambda: _Session(queries)
    cls = mock.MagicMock()
    cls.return_value.__enter__ = mock.MagicMock(return_value=client)
    cls.return_value.__exit__ = mock.MagicMock(return_value=False)
    return mock.MagicMock(Neo4jClient=cls)


BUILDERS = ["_build_recon_data_from_graph", "_build_port_scan_data_from_graph",
            "_build_http_probe_data_from_graph", "_build_vuln_scan_data_from_graph"]


@pytest.mark.parametrize("builder", BUILDERS)
def test_every_resolves_to_read_skips_a_shodan_edge(builder):
    queries: list = []
    with mock.patch.dict("sys.modules", {"graph_db": _fake_graph_db(queries)}):
        getattr(gb, builder)(["example.com"], "u1", "p1", include_root_domain=True)
    reads = [q for q in queries if "RESOLVES_TO" in q]
    assert reads, "the builder reads no DNS edge"
    for q in reads:
        assert re.search(r"-\[r:RESOLVES_TO\]-", q), q
        assert FORWARD in q, q


def test_partial_origin_discovery_reads_forward_dns_only():
    """The fronted-host loader decides "this host sits behind a CDN" from the
    IPs its name resolves to, and its IP becomes the host's edge address, which
    a candidate is dropped against as "the edge". A Shodan PTR edge points at an
    address whose PTR names the host, often a former origin: read as current
    DNS, the very origin sought is discarded. Every RESOLVES_TO it reads carries
    the forward-DNS filter."""
    from recon.partial_recon_modules import origin_enrichment as oe

    queries: list = []
    with mock.patch.dict("sys.modules", {"graph_db": _fake_graph_db(queries)}):
        oe._inject_graph_fronted_hosts({}, ["example.com"], "u1", "p1")
    reads = [q for q in queries if "RESOLVES_TO" in q]
    assert reads, "the loader reads no DNS edge"
    for q in reads:
        edges = re.findall(r"\[(\w*):RESOLVES_TO\]", q)
        assert edges and all(edges), f"an unnamed RESOLVES_TO cannot be filtered: {q}"
        assert q.count(FORWARD) >= len(edges), q

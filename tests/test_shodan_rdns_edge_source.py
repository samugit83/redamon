"""Shodan's reverse DNS is not forward DNS (plan 11.6).

Shodan's PTR answers and its domain-DNS records created Subdomain -[:RESOLVES_TO]->
IP edges that read exactly like a resolver's, so a partial run treated them as
current DNS. The Shodan writer now stamps the edges it creates (ON CREATE) with
source 'shodan_rdns' or 'shodan_dns'; an edge DNS wrote first keeps no source,
and a later DNS confirmation clears a Shodan stamp. Readers that mean "resolves
now" ignore a shodan_* edge; an edge with no source still counts.

Session doubles record every statement; no Neo4j. Addresses are RFC 5737.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402

IP = "192.0.2.40"


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Client(OsintMixin, DomainMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def edges(self):
        return [q for q, _p in self.session.calls if "MERGE (s)-[r:RESOLVES_TO]->(i)" in q]


def _shodan(reverse_dns=None, domain_dns=None):
    return {
        "domain": "example.com", "domains": ["example.com"],
        "metadata": {"root_domain": "example.com"},
        "shodan": {"hosts": [], "cves": [],
                   "reverse_dns": reverse_dns or {}, "domain_dns": domain_dns or {}},
    }


class TestTheShodanWriterStampsItsEdges(unittest.TestCase):
    def test_a_reverse_dns_edge_is_shodan_rdns(self):
        client = _Client()
        client.update_graph_from_shodan(_shodan(reverse_dns={IP: ["mail.example.com"]}), "u1", "p1")
        (edge,) = client.edges()
        self.assertIn("ON CREATE SET r.timestamp = datetime(), r.source = 'shodan_rdns'", edge)

    def test_a_domain_dns_record_edge_is_shodan_dns(self):
        client = _Client()
        client.update_graph_from_shodan(_shodan(domain_dns={
            "domain": "example.com", "subdomains": ["mail"],
            "records": [{"type": "A", "value": IP, "subdomain": "mail"}]}), "u1", "p1")
        (edge,) = client.edges()
        self.assertIn("ON CREATE SET r.timestamp = datetime(), r.source = 'shodan_dns'", edge)

    def test_the_stamp_is_on_create_only(self):
        # An edge DNS already wrote is matched, never relabelled as Shodan's.
        client = _Client()
        client.update_graph_from_shodan(_shodan(reverse_dns={IP: ["mail.example.com"]}), "u1", "p1")
        (edge,) = client.edges()
        set_clause = edge.split("ON CREATE SET", 1)[1]
        self.assertNotIn("SET r.source", set_clause.split("r.source = 'shodan_rdns'", 1)[1])


class TestDnsConfirmationClearsTheStamp(unittest.TestCase):
    def test_the_domain_discovery_edge_drops_a_shodan_source(self):
        import inspect
        body = " ".join(inspect.getsource(DomainMixin).split())
        merges = [i for i in range(len(body)) if body.startswith("MERGE (s)-[r:RESOLVES_TO]->(i)", i)]
        self.assertTrue(merges)
        for i in merges:
            self.assertIn("REMOVE r.source", body[i:i + 300])


class TestReadersIgnoreAShodanEdge(unittest.TestCase):
    def test_gone_hosts_needs_a_forward_dns_edge(self):
        sys.path.insert(0, os.path.join(_REPO, "agentic"))
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES
        query = " ".join(next(q for q in PROJECT_FACT_QUERIES if q["name"] == "gone_hosts")["query"].split())
        # Forward DNS is an edge with no source: every passive writer, Shodan's
        # included, stamps one when it creates the edge.
        self.assertIn("MATCH (n)-[r:RESOLVES_TO]->(:IP) WHERE r.source IS NULL", query)
        self.assertIn("MATCH (n)<-[r:RESOLVES_TO]-(:Subdomain) WHERE r.source IS NULL", query)


if __name__ == "__main__":
    unittest.main()

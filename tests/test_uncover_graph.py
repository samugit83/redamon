"""Tests for graph_db update_graph_from_uncover method."""
import os
import sys
import unittest
from unittest.mock import MagicMock, call

# Stub neo4j + dotenv before any graph_db import
_neo4j_mock = MagicMock()
_neo4j_mock.GraphDatabase.driver = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_mock)
sys.modules.setdefault("dotenv", MagicMock())

import importlib.util

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, relpath):
    path = os.path.join(_REPO, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load in dependency order (same pattern as test_graph_db_refactor.py)
_cpe = _load("graph_db.cpe_resolver", "graph_db/cpe_resolver.py")
_schema = _load("graph_db.schema", "graph_db/schema.py")
sys.modules.setdefault("graph_db", MagicMock())
sys.modules["graph_db.schema"] = _schema
sys.modules["graph_db.cpe_resolver"] = _cpe
_base = _load("graph_db.mixins.base_mixin", "graph_db/mixins/base_mixin.py")
_osint = _load("graph_db.mixins.osint_mixin", "graph_db/mixins/osint_mixin.py")


def _make_client():
    """Create an OsintMixin instance with a mocked Neo4j driver/session."""
    client = _osint.OsintMixin()
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
    client.driver = mock_driver
    return client, mock_session


def _recon_data(hosts=None, ips=None, ip_ports=None, sources=None,
                source_counts=None, total_raw=0, total_deduped=0):
    return {
        "domain": "example.com",
        "uncover": {
            "hosts": hosts or [],
            "ips": ips or [],
            "ip_ports": ip_ports or {},
            "sources": sources or [],
            "source_counts": source_counts or {},
            "total_raw": total_raw,
            "total_deduped": total_deduped,
        },
    }


class TestUpdateGraphFromUncover(unittest.TestCase):

    def test_empty_uncover_data_returns_zero_stats(self):
        client, session = _make_client()
        recon = {"domain": "example.com", "uncover": {"hosts": [], "ips": []}}
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["subdomains_created"], 0)
        self.assertEqual(stats["ips_created"], 0)
        self.assertEqual(stats["relationships_created"], 0)
        session.run.assert_not_called()

    def test_creates_subdomain_nodes(self):
        client, session = _make_client()
        recon = _recon_data(
            hosts=["sub1.example.com", "sub2.example.com"],
            sources=["shodan", "censys"],
            total_raw=10,
            total_deduped=5,
        )
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["subdomains_created"], 2)
        # Each subdomain: 1 MERGE subdomain + 1 MERGE relationships (BELONGS_TO + HAS_SUBDOMAIN)
        self.assertEqual(stats["relationships_created"], 4)

    def test_creates_ip_nodes(self):
        client, session = _make_client()
        recon = _recon_data(
            ips=["1.2.3.4", "5.6.7.8"],
            sources=["shodan"],
            source_counts={"shodan": 2},
            total_raw=5,
            total_deduped=2,
        )
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["ips_created"], 2)

    def test_creates_port_nodes_for_ips(self):
        client, session = _make_client()
        recon = _recon_data(
            ips=["1.2.3.4"],
            ip_ports={"1.2.3.4": [80, 443]},
        )
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["ips_created"], 1)
        self.assertEqual(stats["relationships_created"], 3)  # 1 HAS_IP + 2 HAS_PORT

    def test_skips_empty_hostname(self):
        client, session = _make_client()
        recon = _recon_data(hosts=["", "valid.example.com"])
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["subdomains_created"], 1)

    def test_skips_empty_ip(self):
        client, session = _make_client()
        recon = _recon_data(ips=["", "1.2.3.4"])
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["ips_created"], 1)

    def test_skips_invalid_ports(self):
        client, session = _make_client()
        recon = _recon_data(
            ips=["1.2.3.4"],
            ip_ports={"1.2.3.4": [0, -1, 80]},
        )
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["relationships_created"], 2)  # 1 HAS_IP + 1 HAS_PORT (port 80)

    def test_sources_metadata_passed_to_cypher(self):
        client, session = _make_client()
        recon = _recon_data(
            ips=["1.2.3.4"],
            sources=["shodan", "censys"],
            source_counts={"shodan": 3, "censys": 2},
            total_raw=10,
            total_deduped=5,
        )
        client.update_graph_from_uncover(recon, "user1", "proj1")
        # Verify session.run was called with sources parameter
        ip_calls = [c for c in session.run.call_args_list
                     if 'uncover_sources' in str(c)]
        self.assertTrue(len(ip_calls) > 0,
                        "Expected session.run calls with uncover_sources parameter")

    def test_missing_uncover_key_returns_zero(self):
        client, session = _make_client()
        stats = client.update_graph_from_uncover(
            {"domain": "example.com"}, "user1", "proj1"
        )
        self.assertEqual(stats["subdomains_created"], 0)
        self.assertEqual(stats["ips_created"], 0)

    def test_exception_in_subdomain_recorded(self):
        client, session = _make_client()
        session.run.side_effect = Exception("Neo4j error")
        recon = _recon_data(hosts=["fail.example.com"])
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertTrue(len(stats["errors"]) > 0)

    def test_exception_in_ip_recorded(self):
        client, session = _make_client()
        session.run.side_effect = Exception("Neo4j error")
        recon = _recon_data(ips=["1.2.3.4"])
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertTrue(len(stats["errors"]) > 0)

    def test_no_domain_skips_relationships(self):
        client, session = _make_client()
        recon = {
            "domain": "",
            "uncover": {
                "hosts": ["orphan.example.com"],
                "ips": [],
                "ip_ports": {},
                "sources": [],
                "source_counts": {},
                "total_raw": 0,
                "total_deduped": 0,
            },
        }
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["subdomains_created"], 1)
        self.assertEqual(stats["relationships_created"], 0)


    def test_creates_endpoint_nodes_from_urls(self):
        client, session = _make_client()
        recon = {
            "domain": "example.com",
            "uncover": {
                "hosts": [], "ips": [],
                "ip_ports": {},
                "urls": ["https://www.example.com/page", "https://api.example.com/v1"],
                "sources": [], "source_counts": {},
                "total_raw": 0, "total_deduped": 0,
            },
        }
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["urls_created"], 2)

    def test_skips_empty_url(self):
        client, session = _make_client()
        recon = {
            "domain": "example.com",
            "uncover": {
                "hosts": [], "ips": [],
                "ip_ports": {},
                "urls": ["", "https://www.example.com/page"],
                "sources": [], "source_counts": {},
                "total_raw": 0, "total_deduped": 0,
            },
        }
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["urls_created"], 1)

    def test_url_exception_recorded(self):
        client, session = _make_client()
        session.run.side_effect = Exception("Neo4j error")
        recon = {
            "domain": "example.com",
            "uncover": {
                "hosts": [], "ips": [],
                "ip_ports": {},
                "urls": ["https://fail.example.com/x"],
                "sources": [], "source_counts": {},
                "total_raw": 0, "total_deduped": 0,
            },
        }
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertTrue(len(stats["errors"]) > 0)

    def test_urls_only_triggers_processing(self):
        """Verify that having only urls (no hosts/ips) still processes."""
        client, session = _make_client()
        recon = {
            "domain": "example.com",
            "uncover": {
                "hosts": [], "ips": [],
                "ip_ports": {},
                "urls": ["https://www.example.com/"],
                "sources": ["publicwww"], "source_counts": {"publicwww": 1},
                "total_raw": 1, "total_deduped": 1,
            },
        }
        stats = client.update_graph_from_uncover(recon, "user1", "proj1")
        self.assertEqual(stats["urls_created"], 1)
        self.assertEqual(stats["subdomains_created"], 0)
        self.assertEqual(stats["ips_created"], 0)


if __name__ == '__main__':
    unittest.main()

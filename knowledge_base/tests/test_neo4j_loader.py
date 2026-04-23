import os
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

from knowledge_base.neo4j_loader import Neo4jLoader, SOURCE_SCHEMAS


# =============================================================================
# Unit tests (mock driver — no Neo4j required)
# =============================================================================

class TestNeo4jLoaderUnit:
    """Unit tests with mocked Neo4j driver."""

    @pytest.fixture
    def mock_driver(self):
        driver = MagicMock()
        session = MagicMock()
        driver.session.return_value.__enter__ = MagicMock(return_value=session)
        driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return driver

    @pytest.fixture
    def loader(self, mock_driver):
        return Neo4jLoader(mock_driver)

    def test_ensure_schema_creates_constraint_and_indexes(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        loader.ensure_schema()

        calls = session.run.call_args_list
        statements = [c.args[0] for c in calls]

        # Base constraint
        assert any("kb_chunk_id" in s for s in statements)
        # Per-source indexes
        assert any("nvd_cve_id" in s for s in statements)
        assert any("gtfo_binary" in s for s in statements)
        assert any("lolbas_binary" in s for s in statements)
        assert any("owasp_test_id" in s for s in statements)
        assert any("nuclei_template" in s for s in statements)
        assert any("tooldoc_tool" in s for s in statements)
        assert any("edb_id" in s for s in statements)

    def test_ensure_schema_uses_if_not_exists(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        loader.ensure_schema()

        calls = session.run.call_args_list
        for c in calls:
            assert "IF NOT EXISTS" in c.args[0]

    def test_upsert_chunks_calls_merge(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value

        chunks = [
            {"chunk_id": "abc123", "content": "test content", "title": "test", "source": "nvd", "cve_id": "CVE-2021-44228"},
        ]
        count = loader.upsert_chunks(chunks, "NVDChunk")

        assert count == 1
        cypher = session.run.call_args_list[0].args[0]
        assert "MERGE" in cypher
        assert "KBChunk" in cypher
        assert "NVDChunk" in cypher

    def test_upsert_chunks_skips_without_chunk_id(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value

        chunks = [
            {"content": "no id", "title": "test", "source": "nvd"},
        ]
        count = loader.upsert_chunks(chunks, "NVDChunk")
        assert count == 0

    def test_upsert_chunks_empty_list(self, loader):
        count = loader.upsert_chunks([], "NVDChunk")
        assert count == 0

    def test_upsert_chunks_sets_ingested_at(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value

        chunks = [
            {"chunk_id": "abc", "content": "test", "title": "t", "source": "nvd"},
        ]
        loader.upsert_chunks(chunks, "NVDChunk")

        props = session.run.call_args_list[0].kwargs["props"]
        assert "ingested_at" in props

    def test_upsert_chunks_excludes_none_values(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value

        chunks = [
            {"chunk_id": "abc", "content": "test", "title": "t", "source": "nvd", "cvss_score": None},
        ]
        loader.upsert_chunks(chunks, "NVDChunk")

        props = session.run.call_args_list[0].kwargs["props"]
        assert "cvss_score" not in props

    def test_filter_chunks_builds_correct_cypher(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        loader.filter_chunks(["id1", "id2"], sources=["nvd", "owasp"])

        cypher = session.run.call_args.args[0]
        assert "chunk_id IN $chunk_ids" in cypher
        assert "source IN $sources" in cypher
        # No tenant filter
        assert "user_id" not in cypher
        assert "project_id" not in cypher

    def test_filter_chunks_with_cvss(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        loader.filter_chunks(["id1"], min_cvss=7.0)

        cypher = session.run.call_args.args[0]
        assert "cvss_score >= $min_cvss" in cypher

    def test_filter_chunks_with_severity(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        loader.filter_chunks(["id1"], severity="critical")

        cypher = session.run.call_args.args[0]
        assert "severity = $severity" in cypher

    def test_filter_chunks_no_filters(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        loader.filter_chunks(["id1", "id2"])

        cypher = session.run.call_args.args[0]
        assert "chunk_id IN $chunk_ids" in cypher
        assert "source IN" not in cypher

    def test_filter_chunks_empty_ids(self, loader):
        result = loader.filter_chunks([])
        assert result == []

    def test_filter_chunks_no_tenant_fields(self, loader, mock_driver):
        """Verify KB queries never include tenant filtering."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        loader.filter_chunks(["id1"], sources=["nvd"], min_cvss=5.0, severity="high")

        cypher = session.run.call_args.args[0]
        assert "user_id" not in cypher
        assert "project_id" not in cypher
        assert "tenant" not in cypher.lower()

    def test_get_stats(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = [
            {"source": "nvd", "cnt": 100},
            {"source": "gtfobins", "cnt": 50},
        ]

        stats = loader.get_stats()
        assert stats == {"nvd": 100, "gtfobins": 50}

    def test_drop_source(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        # Simulate one batch of 5 deletions, then 0 (done)
        mock_result_1 = MagicMock()
        mock_result_1.single.return_value = {"deleted": 5}
        mock_result_2 = MagicMock()
        mock_result_2.single.return_value = {"deleted": 0}
        session.run.side_effect = [mock_result_1, mock_result_2]

        count = loader.drop_source("nvd")
        assert count == 5

        cypher = session.run.call_args_list[0].args[0]
        assert "source: $source" in cypher
        assert "DELETE" in cypher

    def test_source_schemas_completeness(self):
        """All expected source labels are defined."""
        expected = {"NVDChunk", "ExploitDBChunk", "GTFOBinsChunk", "LOLBASChunk",
                    "OWASPChunk", "NucleiChunk", "ToolDocChunk"}
        assert set(SOURCE_SCHEMAS.keys()) == expected

    def test_upsert_rejects_unknown_label(self, loader):
        """Sec #5: unknown node_label must raise ValueError, not warn-and-proceed."""
        with pytest.raises(ValueError, match="Unknown node label"):
            loader.upsert_chunks(
                [{"chunk_id": "x", "content": "t", "title": "t", "source": "unknown"}],
                "UnknownChunk",
            )

    def test_upsert_rejects_cypher_injection_in_label(self, loader):
        """Sec #5: an attacker-shaped label must be rejected at the identifier check."""
        with pytest.raises(ValueError, match="Cypher identifier"):
            loader.upsert_chunks(
                [{"chunk_id": "x", "content": "t", "title": "t", "source": "x"}],
                "Foo SET c.owned = true //",
            )

    def test_upsert_rejects_label_with_spaces(self, loader):
        with pytest.raises(ValueError, match="Cypher identifier"):
            loader.upsert_chunks(
                [{"chunk_id": "x", "content": "t", "title": "t", "source": "x"}],
                "My Label",
            )

    def test_upsert_rejects_label_starting_with_digit(self, loader):
        with pytest.raises(ValueError, match="Cypher identifier"):
            loader.upsert_chunks(
                [{"chunk_id": "x", "content": "t", "title": "t", "source": "x"}],
                "1NVDChunk",
            )

    def test_filter_chunks_rejects_cypher_injection_in_filter_key(self, loader, mock_driver):
        """Sec #4: filter property keys must pass the Cypher identifier check."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []

        with pytest.raises(ValueError, match="Cypher identifier"):
            # Pass a malicious key via **filters
            loader.filter_chunks(["id1"], **{"chunk_id} RETURN c //": "x"})

    def test_filter_chunks_rejects_filter_key_with_dash(self, loader, mock_driver):
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []
        with pytest.raises(ValueError, match="Cypher identifier"):
            loader.filter_chunks(["id1"], **{"some-key": "x"})

    def test_filter_chunks_accepts_valid_filter_key(self, loader, mock_driver):
        """Sanity check that the validator doesn't reject valid identifiers."""
        session = mock_driver.session.return_value.__enter__.return_value
        session.run.return_value = []
        # Should not raise — `tag` is a valid identifier
        loader.filter_chunks(["id1"], tag="rce")

        # Verify the cypher was built with the valid key
        cypher = session.run.call_args.args[0]
        assert "c.tag = $filter_tag" in cypher


# =============================================================================
# Integration tests (require running Neo4j)
# =============================================================================

def neo4j_available():
    """Check if Neo4j is reachable."""
    try:
        from neo4j import GraphDatabase
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "changeme123")
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        driver.close()
        return True
    except Exception:
        return False


neo4j = pytest.mark.skipif(
    not neo4j_available(),
    reason="Neo4j not available at bolt://localhost:7687"
)


@neo4j
class TestNeo4jLoaderIntegration:
    """Integration tests against a real Neo4j instance."""

    @pytest.fixture(scope="class")
    def driver(self):
        from neo4j import GraphDatabase
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "changeme123")
        d = GraphDatabase.driver(uri, auth=(user, password))
        yield d
        d.close()

    @pytest.fixture(autouse=True)
    def cleanup(self, driver):
        """Clean up test KBChunk nodes before and after each test."""
        with driver.session() as session:
            session.run("MATCH (c:KBChunk) WHERE c.source STARTS WITH 'test_' DETACH DELETE c")
        yield
        with driver.session() as session:
            session.run("MATCH (c:KBChunk) WHERE c.source STARTS WITH 'test_' DETACH DELETE c")

    @pytest.fixture
    def loader(self, driver):
        ldr = Neo4jLoader(driver)
        ldr.ensure_schema()
        return ldr

    def test_upsert_and_filter_roundtrip(self, loader):
        chunks = [
            {"chunk_id": "test_001", "content": "Log4j RCE vuln", "title": "CVE-2021-44228",
             "source": "test_nvd", "cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "critical"},
            {"chunk_id": "test_002", "content": "Python SUID privesc", "title": "python suid",
             "source": "test_gtfobins", "binary_name": "python", "function_type": "suid"},
        ]
        loader.upsert_chunks(chunks[:1], "NVDChunk")
        loader.upsert_chunks(chunks[1:], "GTFOBinsChunk")

        results = loader.filter_chunks(["test_001", "test_002"])
        assert len(results) == 2

    def test_upsert_updates_existing(self, loader):
        chunk_v1 = [{"chunk_id": "test_upd", "content": "v1", "title": "t",
                      "source": "test_nvd", "cvss_score": 7.0}]
        chunk_v2 = [{"chunk_id": "test_upd", "content": "v2", "title": "t",
                      "source": "test_nvd", "cvss_score": 9.8}]

        loader.upsert_chunks(chunk_v1, "NVDChunk")
        loader.upsert_chunks(chunk_v2, "NVDChunk")

        results = loader.filter_chunks(["test_upd"])
        assert len(results) == 1
        assert results[0]["content"] == "v2"
        assert results[0]["cvss_score"] == 9.8

    def test_filter_by_source(self, loader):
        loader.upsert_chunks(
            [{"chunk_id": "test_s1", "content": "a", "title": "a", "source": "test_nvd"}],
            "NVDChunk",
        )
        loader.upsert_chunks(
            [{"chunk_id": "test_s2", "content": "b", "title": "b", "source": "test_gtfobins"}],
            "GTFOBinsChunk",
        )

        results = loader.filter_chunks(["test_s1", "test_s2"], sources=["test_nvd"])
        assert len(results) == 1
        assert results[0]["chunk_id"] == "test_s1"

    def test_filter_by_cvss(self, loader):
        loader.upsert_chunks([
            {"chunk_id": "test_c1", "content": "high", "title": "h", "source": "test_nvd", "cvss_score": 9.0},
            {"chunk_id": "test_c2", "content": "low", "title": "l", "source": "test_nvd", "cvss_score": 3.0},
        ], "NVDChunk")

        results = loader.filter_chunks(["test_c1", "test_c2"], min_cvss=7.0)
        assert len(results) == 1
        assert results[0]["chunk_id"] == "test_c1"

    def test_multi_label(self, loader, driver):
        loader.upsert_chunks(
            [{"chunk_id": "test_ml", "content": "test", "title": "t", "source": "test_nvd"}],
            "NVDChunk",
        )

        with driver.session() as session:
            # Has KBChunk label
            r1 = session.run("MATCH (c:KBChunk {chunk_id: 'test_ml'}) RETURN c").single()
            assert r1 is not None
            # Also has NVDChunk label
            r2 = session.run("MATCH (c:NVDChunk {chunk_id: 'test_ml'}) RETURN c").single()
            assert r2 is not None

    def test_drop_source(self, loader):
        loader.upsert_chunks([
            {"chunk_id": "test_d1", "content": "a", "title": "a", "source": "test_drop"},
            {"chunk_id": "test_d2", "content": "b", "title": "b", "source": "test_drop"},
            {"chunk_id": "test_d3", "content": "c", "title": "c", "source": "test_keep"},
        ], "ToolDocChunk")

        deleted = loader.drop_source("test_drop")
        assert deleted == 2

        remaining = loader.filter_chunks(["test_d1", "test_d2", "test_d3"])
        assert len(remaining) == 1
        assert remaining[0]["chunk_id"] == "test_d3"

    def test_get_stats(self, loader):
        loader.upsert_chunks([
            {"chunk_id": "test_st1", "content": "a", "title": "a", "source": "test_nvd"},
            {"chunk_id": "test_st2", "content": "b", "title": "b", "source": "test_nvd"},
            {"chunk_id": "test_st3", "content": "c", "title": "c", "source": "test_gtfobins"},
        ], "NVDChunk")

        stats = loader.get_stats()
        assert stats.get("test_nvd", 0) >= 2
        assert stats.get("test_gtfobins", 0) >= 1

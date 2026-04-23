import pytest
from unittest.mock import MagicMock, patch

from knowledge_base.kb_orchestrator import PentestKnowledgeBase


@pytest.fixture
def mock_embedder():
    embedder = MagicMock()
    embedder.embed_query.return_value = [0.1] * 1024
    embedder.dimensions = 1024
    return embedder


@pytest.fixture
def mock_faiss():
    faiss = MagicMock()
    faiss.count.return_value = 100
    faiss.load.return_value = True
    faiss.search.return_value = [
        ("chunk_a", 0.92),
        ("chunk_b", 0.85),
        ("chunk_c", 0.71),
        ("chunk_d", 0.60),
        ("chunk_e", 0.45),
        ("chunk_f", 0.30),
    ]
    return faiss


@pytest.fixture
def mock_neo4j():
    neo4j = MagicMock()
    neo4j.filter_chunks.return_value = [
        {"chunk_id": "chunk_a", "content": "Log4j RCE vuln", "title": "CVE-2021-44228", "source": "nvd"},
        {"chunk_id": "chunk_b", "content": "Python SUID privesc", "title": "python suid", "source": "gtfobins"},
        {"chunk_id": "chunk_c", "content": "sqlmap tamper scripts", "title": "sqlmap tamper", "source": "tool_docs"},
    ]
    return neo4j


@pytest.fixture
def kb(mock_faiss, mock_neo4j, mock_embedder):
    return PentestKnowledgeBase(mock_faiss, mock_neo4j, mock_embedder)


class TestQuery:

    def test_query_returns_results_with_scores(self, kb):
        results = kb.query("log4j exploit")
        assert len(results) > 0
        assert all("score" in r for r in results)
        assert all("content" in r for r in results)

    def test_query_calls_embedder_with_query(self, kb, mock_embedder):
        kb.query("test query")
        mock_embedder.embed_query.assert_called_once_with("test query")

    def test_query_calls_faiss_with_overfetch(self, kb, mock_faiss):
        kb.top_k = 5
        kb.query("test")
        mock_faiss.search.assert_called_once()
        _, kwargs = mock_faiss.search.call_args
        # Default overfetch_factor is 6, so 5 * 6 = 30
        assert kwargs["top_k"] == kb.top_k * kb.overfetch_factor

    def test_query_passes_sources_to_neo4j(self, kb, mock_neo4j):
        # Tests that include_sources at the orchestrator level translates
        # to `sources=` on the underlying Neo4j filter API. The Neo4j layer
        # still uses the legacy `sources` parameter name; only the
        # orchestrator's external API was renamed for clarity.
        kb.query("test", include_sources=["nvd", "owasp"])
        _, kwargs = mock_neo4j.filter_chunks.call_args
        assert kwargs["sources"] == ["nvd", "owasp"]

    def test_query_passes_cvss_to_neo4j(self, kb, mock_neo4j):
        kb.query("test", min_cvss=7.0)
        _, kwargs = mock_neo4j.filter_chunks.call_args
        assert kwargs["min_cvss"] == 7.0

    def test_query_passes_severity_to_neo4j(self, kb, mock_neo4j):
        kb.query("test", severity="critical")
        _, kwargs = mock_neo4j.filter_chunks.call_args
        assert kwargs["severity"] == "critical"

    def test_query_respects_top_k(self, kb):
        results = kb.query("test", top_k=2)
        assert len(results) <= 2

    def test_query_scores_sorted_descending(self, kb):
        """With MMR disabled, results should be sorted by score descending."""
        kb.mmr_enabled = False
        results = kb.query("test")
        scores = [r["score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_query_top_result_is_highest_scored(self, kb):
        """Top result should have the highest score regardless of MMR.
        MMR always selects the highest-scored item first."""
        results = kb.query("test")
        if results:
            top_score = results[0]["score"]
            for r in results[1:]:
                assert r["score"] <= top_score

    def test_query_merges_faiss_scores_with_neo4j_metadata(self, kb):
        # This test isolates the FAISS-result × Neo4j-metadata merge step
        # from every layer that would otherwise reorder the result list:
        #   - source_boosts: per-source multipliers would push tool_docs
        #     (chunk_c, 1.20×) above nvd (chunk_a, 0.90×) and break the
        #     "chunk_a is first" assertion based on FAISS rank alone.
        #   - rerank_enabled: the cross-encoder would re-score the merged
        #     pool against the literal query "test", which is semantically
        #     unrelated to the mock chunk content and gives noise ordering.
        #   - mmr_enabled: MMR diversification can reshuffle the top-k.
        #   - fulltext_enabled: with Lucene merged in, RRF wouldn't reflect
        #     FAISS rank 1:1 anymore (an unmocked fulltext_search would
        #     also raise on the MagicMock placeholder).
        # All four together collapse the pipeline to "FAISS → RRF → sort
        # by RRF → take top_k", which is the merge-step behavior the test
        # name actually describes.
        kb.source_boosts = {}
        kb.rerank_enabled = False
        kb.mmr_enabled = False
        kb.fulltext_enabled = False

        results = kb.query("test")
        top = results[0]

        # chunk_a has FAISS score 0.92, the highest in the mock, so after
        # RRF + sort it should land at top[0].
        assert top["chunk_id"] == "chunk_a"
        assert top["content"] == "Log4j RCE vuln"
        assert top["source"] == "nvd"
        # `score` is the RRF-fused score (post-merge composite), NOT the
        # raw FAISS score. RRF for rank-0 is 1/(rrf_k+1) ≈ 0.0164. The
        # raw FAISS score is preserved on `vector_score` for callers that
        # need it, so assert against that instead.
        assert top["vector_score"] == pytest.approx(0.92)

    def test_query_filters_out_chunks_not_in_neo4j(self, kb, mock_neo4j):
        """Chunks returned by FAISS but filtered out by Neo4j should not appear."""
        # Neo4j only returns chunk_a and chunk_b (not c through f)
        mock_neo4j.filter_chunks.return_value = [
            {"chunk_id": "chunk_a", "content": "a", "title": "a", "source": "nvd"},
            {"chunk_id": "chunk_b", "content": "b", "title": "b", "source": "gtfobins"},
        ]
        results = kb.query("test", top_k=5)
        result_ids = {r["chunk_id"] for r in results}
        assert "chunk_c" not in result_ids
        assert "chunk_d" not in result_ids


# RRF rank-N score is 1 / (rrf_k + 1 + N). With the default rrf_k=60,
# rank 0 = 1/61, rank 1 = 1/62. The TestSourceBoost tests below compute
# expected scores from this formula directly so they're decoupled from
# whatever the raw FAISS score happens to be.
_RRF_K = 60


def _rrf_score(rank: int) -> float:
    """RRF score for the chunk at the given (zero-indexed) FAISS rank,
    with the default rrf_k constant. Mirrors the orchestrator's RRF math
    so test assertions stay symbolic rather than hardcoded."""
    return 1.0 / (_RRF_K + 1 + rank)


def _isolate_score_pipeline(kb):
    """Disable every score-shaping layer downstream of the RRF merge.

    Used by unit tests that want to assert against the
    `score = rrf_score * boost` formula directly, without the cross-encoder
    reranker, MMR diversification, or Lucene fulltext fusion adding noise.
    The test for each individual layer (rerank, mmr, fulltext) is
    elsewhere in the suite — these unit tests are about boost arithmetic
    in isolation.
    """
    kb.rerank_enabled = False
    kb.fulltext_enabled = False
    # Caller decides whether to also disable MMR and source_boosts.


class TestSourceBoost:

    def test_source_boost_applied_to_score(self, mock_faiss, mock_embedder):
        """Per-source multiplier should multiply into the RRF score."""
        from unittest.mock import MagicMock
        from knowledge_base.kb_orchestrator import PentestKnowledgeBase

        neo4j = MagicMock()
        neo4j.filter_chunks.return_value = [
            {"chunk_id": "chunk_a", "content": "a", "title": "a", "source": "tool_docs"},
            {"chunk_id": "chunk_b", "content": "b", "title": "b", "source": "exploitdb"},
        ]
        kb = PentestKnowledgeBase(mock_faiss, neo4j, mock_embedder)
        # Isolate from rerank/fulltext so `score` reflects pure RRF*boost.
        # MMR disabled too — this test is about boost arithmetic, not selection.
        _isolate_score_pipeline(kb)
        kb.mmr_enabled = False
        kb.source_boosts = {"tool_docs": 2.0, "exploitdb": 0.5}

        results = kb.query("test", top_k=2)

        chunk_a = next(r for r in results if r["chunk_id"] == "chunk_a")
        chunk_b = next(r for r in results if r["chunk_id"] == "chunk_b")
        # The orchestrator stores `score = rrf_score * boost`, NOT
        # `faiss_score * boost`. Compute expected RRF for each chunk's
        # FAISS rank (chunk_a is rank 0, chunk_b is rank 1) and apply
        # the boost the same way the orchestrator does.
        assert chunk_a["score"] == pytest.approx(_rrf_score(0) * 2.0)
        assert chunk_b["score"] == pytest.approx(_rrf_score(1) * 0.5)
        # raw_score on the chunk preserves the underlying FAISS score
        # (set in step 3 of the merge loop, line ~214 of kb_orchestrator).
        assert chunk_a["raw_score"] == pytest.approx(0.92)
        assert chunk_b["raw_score"] == pytest.approx(0.85)
        # Cross-check: vector_score is also preserved as the raw FAISS hit.
        assert chunk_a["vector_score"] == pytest.approx(0.92)
        assert chunk_b["vector_score"] == pytest.approx(0.85)

    def test_source_boost_changes_ordering(self, mock_faiss, mock_embedder):
        """A heavy boost on a low-FAISS-score chunk can flip ordering."""
        from unittest.mock import MagicMock
        from knowledge_base.kb_orchestrator import PentestKnowledgeBase

        neo4j = MagicMock()
        neo4j.filter_chunks.return_value = [
            {"chunk_id": "chunk_a", "content": "a", "title": "a", "source": "exploitdb"},  # rank 0, faiss=0.92
            {"chunk_id": "chunk_b", "content": "b", "title": "b", "source": "lolbas"},      # rank 1, faiss=0.85
        ]
        kb = PentestKnowledgeBase(mock_faiss, neo4j, mock_embedder)
        # Isolate from rerank/fulltext so the test deterministically
        # exercises the boost-driven ordering flip.
        _isolate_score_pipeline(kb)
        kb.mmr_enabled = False
        kb.source_boosts = {"exploitdb": 0.5, "lolbas": 2.0}

        results = kb.query("test", top_k=2)
        # Effective scores after RRF * boost:
        #   chunk_a: rrf(0) * 0.5  = (1/61) * 0.5  ≈ 0.0082
        #   chunk_b: rrf(1) * 2.0  = (1/62) * 2.0  ≈ 0.0323
        # → chunk_b's 4x boost overcomes its rank-1 RRF disadvantage.
        assert results[0]["chunk_id"] == "chunk_b"

    def test_unknown_source_uses_default_boost(self, mock_faiss, mock_embedder):
        """Sources not in source_boosts dict should use boost of 1.0."""
        from unittest.mock import MagicMock
        from knowledge_base.kb_orchestrator import PentestKnowledgeBase

        neo4j = MagicMock()
        neo4j.filter_chunks.return_value = [
            {"chunk_id": "chunk_a", "content": "a", "title": "a", "source": "weird_source"},
        ]
        kb = PentestKnowledgeBase(mock_faiss, neo4j, mock_embedder)
        _isolate_score_pipeline(kb)
        kb.mmr_enabled = False
        kb.source_boosts = {}  # empty — nothing should be boosted

        results = kb.query("test", top_k=1)
        # With boost=1.0 (the default for unknown sources), score is
        # exactly the unmultiplied RRF score. The raw FAISS hit is on
        # `vector_score`, separately preserved.
        assert results[0]["score"] == pytest.approx(_rrf_score(0) * 1.0)
        assert results[0]["vector_score"] == pytest.approx(0.92)


class TestMMRDiversity:

    def test_mmr_picks_highest_first(self, mock_faiss, mock_embedder):
        """MMR always selects the highest-scored item first."""
        from unittest.mock import MagicMock
        from knowledge_base.kb_orchestrator import PentestKnowledgeBase

        # Chunk ids must match the mock_faiss fixture (chunk_a..chunk_f).
        # Otherwise the orchestrator's `if cid not in rrf_score_map` check
        # filters out every Neo4j chunk and results comes back empty.
        chunk_letters = ["chunk_a", "chunk_b", "chunk_c", "chunk_d", "chunk_e", "chunk_f"]
        neo4j = MagicMock()
        neo4j.filter_chunks.return_value = [
            {"chunk_id": cid, "content": "x", "title": f"title {i}", "source": f"src{i}"}
            for i, cid in enumerate(chunk_letters)
        ]
        kb = PentestKnowledgeBase(mock_faiss, neo4j, mock_embedder)
        # Disable rerank/fulltext so RRF order = FAISS order. MMR stays
        # ENABLED — that's what this test is actually about.
        _isolate_score_pipeline(kb)
        kb.source_boosts = {}  # disable boost so we test MMR in isolation

        results = kb.query("test", top_k=3)
        # chunk_a has the highest FAISS score (0.92), so RRF rank 0, so
        # MMR picks it first by definition (MMR's first pick is always
        # the highest-relevance item before diversity weighting kicks in).
        assert results[0]["chunk_id"] == "chunk_a"

    def test_mmr_disabled_returns_top_k_by_score(self, mock_faiss, mock_embedder):
        """With MMR disabled, results are pure score-sorted."""
        from unittest.mock import MagicMock
        from knowledge_base.kb_orchestrator import PentestKnowledgeBase

        # Chunk ids must match mock_faiss; see test_mmr_picks_highest_first.
        chunk_letters = ["chunk_a", "chunk_b", "chunk_c", "chunk_d", "chunk_e", "chunk_f"]
        neo4j = MagicMock()
        # All same source so no boost variance
        neo4j.filter_chunks.return_value = [
            {"chunk_id": cid, "content": "x", "title": f"t{i}", "source": "nvd"}
            for i, cid in enumerate(chunk_letters)
        ]
        kb = PentestKnowledgeBase(mock_faiss, neo4j, mock_embedder)
        # Disable rerank/fulltext as well so the cross-encoder's noise
        # doesn't shuffle the FAISS-rank order this test checks for.
        _isolate_score_pipeline(kb)
        kb.mmr_enabled = False

        results = kb.query("test", top_k=3)
        # All same source → boost is uniform → ordering follows FAISS
        # rank → RRF rank: chunk_a (0.92), chunk_b (0.85), chunk_c (0.71).
        assert [r["chunk_id"] for r in results] == ["chunk_a", "chunk_b", "chunk_c"]

    def test_mmr_prefers_diverse_sources(self, mock_faiss, mock_embedder):
        """MMR should prefer different sources when scores are close."""
        from unittest.mock import MagicMock
        from knowledge_base.kb_orchestrator import PentestKnowledgeBase

        # Make 6 candidates: first 3 from 'nvd', next 3 from different sources.
        # Chunk ids match mock_faiss so the orchestrator's
        # `if cid not in rrf_score_map` check passes for every chunk.
        neo4j = MagicMock()
        neo4j.filter_chunks.return_value = [
            {"chunk_id": "chunk_a", "content": "x", "title": "nvd one",   "source": "nvd"},
            {"chunk_id": "chunk_b", "content": "x", "title": "nvd two",   "source": "nvd"},
            {"chunk_id": "chunk_c", "content": "x", "title": "nvd three", "source": "nvd"},
            {"chunk_id": "chunk_d", "content": "x", "title": "owasp one", "source": "owasp"},
            {"chunk_id": "chunk_e", "content": "x", "title": "tool one",  "source": "tool_docs"},
            {"chunk_id": "chunk_f", "content": "x", "title": "gtfo one",  "source": "gtfobins"},
        ]
        kb = PentestKnowledgeBase(mock_faiss, neo4j, mock_embedder)
        # Disable rerank/fulltext so RRF order = FAISS order. MMR stays
        # ENABLED — diversification is what the test is verifying.
        _isolate_score_pipeline(kb)
        kb.source_boosts = {}  # disable boost
        kb.mmr_lambda = 0.5  # equal weight on relevance + diversity

        results = kb.query("test", top_k=3)
        sources = {r["source"] for r in results}
        # MMR with 50/50 should produce more than 1 source in the top 3
        assert len(sources) > 1

    def test_chunk_similarity_same_source(self, kb):
        a = {"source": "nvd", "title": "CVE-2021-1"}
        b = {"source": "nvd", "title": "CVE-2021-2"}
        sim = kb._chunk_similarity(a, b)
        # Same source contributes 0.4
        assert sim >= 0.4

    def test_chunk_similarity_different_sources(self, kb):
        a = {"source": "nvd", "title": "completely different"}
        b = {"source": "gtfobins", "title": "totally unrelated"}
        sim = kb._chunk_similarity(a, b)
        # Different source, no token overlap = 0.0
        assert sim == 0.0

    def test_chunk_similarity_title_overlap(self, kb):
        a = {"source": "nvd", "title": "apache struts rce vulnerability"}
        b = {"source": "exploitdb", "title": "apache struts rce exploit"}
        sim = kb._chunk_similarity(a, b)
        # Different sources but heavy title overlap (3/5 tokens)
        assert sim > 0.3


class TestNoOpState:

    def test_empty_faiss_returns_empty(self, mock_neo4j, mock_embedder):
        faiss = MagicMock()
        faiss.count.return_value = 0
        kb = PentestKnowledgeBase(faiss, mock_neo4j, mock_embedder)

        results = kb.query("test")
        assert results == []

    def test_faiss_search_returns_empty(self, mock_neo4j, mock_embedder):
        faiss = MagicMock()
        faiss.count.return_value = 100
        faiss.search.return_value = []
        kb = PentestKnowledgeBase(faiss, mock_neo4j, mock_embedder)

        results = kb.query("test")
        assert results == []

    def test_no_neo4j_returns_faiss_only(self, mock_faiss, mock_embedder):
        """Without Neo4j, results have chunk_ids and scores but no metadata."""
        kb = PentestKnowledgeBase(mock_faiss, None, mock_embedder)
        results = kb.query("test")
        assert len(results) > 0
        assert all("chunk_id" in r for r in results)
        assert all("score" in r for r in results)


class TestIsSufficient:

    def test_sufficient_when_top_score_above_threshold(self, kb):
        results = [{"score": 0.8}, {"score": 0.5}]
        assert kb.is_sufficient(results) is True

    def test_insufficient_when_top_score_below_threshold(self, kb):
        results = [{"score": 0.2}, {"score": 0.1}]
        assert kb.is_sufficient(results) is False

    def test_insufficient_when_empty(self, kb):
        assert kb.is_sufficient([]) is False

    def test_custom_threshold(self, kb):
        results = [{"score": 0.5}]
        assert kb.is_sufficient(results, threshold=0.4) is True
        assert kb.is_sufficient(results, threshold=0.6) is False

    def test_uses_instance_threshold(self):
        kb = PentestKnowledgeBase(MagicMock(), MagicMock(), MagicMock())
        kb.score_threshold = 0.7
        assert kb.is_sufficient([{"score": 0.75}]) is True
        assert kb.is_sufficient([{"score": 0.65}]) is False


class TestLoad:

    def test_load_calls_faiss_load(self, kb, mock_faiss):
        kb.load()
        mock_faiss.load.assert_called_once()

    def test_load_logs_warning_when_no_index(self, mock_neo4j, mock_embedder, caplog):
        import logging
        faiss = MagicMock()
        faiss.load.return_value = False
        kb = PentestKnowledgeBase(faiss, mock_neo4j, mock_embedder)

        with caplog.at_level(logging.WARNING):
            kb.load()
        assert "no-op" in caplog.text.lower() or "No FAISS" in caplog.text


class TestStats:

    def test_stats_includes_faiss_count(self, kb, mock_faiss):
        mock_faiss.count.return_value = 42
        stats = kb.stats()
        assert stats["faiss_vectors"] == 42

    def test_stats_includes_neo4j_when_available(self, kb, mock_neo4j):
        mock_neo4j.get_stats.return_value = {"nvd": 100, "gtfobins": 50}
        stats = kb.stats()
        assert stats["neo4j_available"] is True
        assert stats["neo4j_chunks_by_source"] == {"nvd": 100, "gtfobins": 50}

    def test_stats_handles_no_neo4j(self, mock_faiss, mock_embedder):
        kb = PentestKnowledgeBase(mock_faiss, None, mock_embedder)
        stats = kb.stats()
        assert stats["neo4j_available"] is False
        assert "neo4j_chunks_by_source" not in stats

    def test_stats_handles_neo4j_error(self, kb, mock_neo4j):
        mock_neo4j.get_stats.side_effect = Exception("connection refused")
        stats = kb.stats()
        assert "neo4j_error" in stats

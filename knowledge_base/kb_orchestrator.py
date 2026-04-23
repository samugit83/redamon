import logging
import math
from typing import Optional

from knowledge_base.kb_config import KBConfig, load_kb_config

logger = logging.getLogger(__name__)


def _sigmoid(x: float) -> float:
    """Numerically-stable sigmoid for cross-encoder logits."""
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    else:
        z = math.exp(x)
        return z / (1.0 + z)


class PentestKnowledgeBase:
    """Hybrid FAISS + Neo4j knowledge base for pentesting."""

    def __init__(
        self,
        faiss_indexer,
        neo4j_loader,
        embedder,
        reranker=None,
        config: Optional[KBConfig] = None,
    ):
        """
        Args:
            faiss_indexer: FAISSIndexer instance.
            neo4j_loader: Neo4jLoader instance (can be None if Neo4j unavailable).
            embedder: Embedder instance.
            reranker: Optional CrossEncoderReranker instance. If None and the
                      config has reranker.enabled = true, a default one is
                      lazy-instantiated on first query.
            config: Optional explicit KBConfig. If None, loads from
                    `kb_config.yaml` via load_kb_config().
        """
        self.faiss = faiss_indexer
        self.neo4j = neo4j_loader
        self.embedder = embedder
        self._reranker = reranker
        self.config = config or load_kb_config()

        # Hot fields copied from config so callers can mutate them at runtime
        # without touching the underlying immutable config object. The config
        # provides the *defaults*; runtime tweaks override per-instance.
        self.score_threshold = self.config.retrieval.score_threshold
        self.top_k = self.config.retrieval.top_k
        self.overfetch_factor = self.config.retrieval.overfetch_factor
        self.rrf_k = self.config.retrieval.rrf_k

        self.source_boosts = dict(self.config.source_boosts)

        self.mmr_enabled = self.config.mmr.enabled
        self.mmr_lambda = self.config.mmr.lambda_

        self.fulltext_enabled = self.config.fulltext.enabled
        self.rerank_enabled = self.config.reranker.enabled
        self.rerank_pool_size = self.config.reranker.pool_size

    def load(self) -> None:
        """Load FAISS index from disk. No-op if not found."""
        loaded = self.faiss.load()
        if not loaded:
            logger.warning(
                "No FAISS index found — KB is in no-op state. "
                "Run the ingestion pipeline to build the index."
            )

    def query(
        self,
        query: str,
        top_k: Optional[int] = None,
        include_sources: Optional[list[str]] = None,
        exclude_sources: Optional[list[str]] = None,
        min_cvss: Optional[float] = None,
        severity: Optional[str] = None,
        **filters,
    ) -> list[dict]:
        """
        Query the knowledge base.

        Args:
            query: Natural language query string.
            top_k: Number of results to return (default: self.top_k).
            include_sources: Optional allowlist of sources to restrict to
                (e.g. ['owasp', 'gtfobins']). When set, only chunks from
                these sources are returned. Renamed from `sources` for
                semantic clarity now that exclude_sources also exists.
            exclude_sources: Optional blacklist of sources to drop. Applied
                AFTER include_sources, so a source in both lists is excluded.
                Useful for "everything except the high-volume noise sources"
                queries — e.g. exclude_sources=['exploitdb'] for broad
                concept queries where ExploitDB's 46k chunks would dominate.
            min_cvss: Optional minimum CVSS score filter (NVD chunks only).
            severity: Optional severity filter.
            **filters: Additional Neo4j property filters.

        Returns:
            List of result dicts: [{content, title, source, score, ...metadata}]
            Returns [] if KB is in no-op state.
        """
        k = top_k or self.top_k

        if self.faiss.count() == 0:
            return []

        # Normalize exclude_sources to a set for O(1) membership testing
        # in the post-merge filter loop below.
        _exclude_set: set[str] = set(exclude_sources or ())

        # ─────────────────────────────────────────────────────────────────
        # 1. Hybrid candidate retrieval
        # ─────────────────────────────────────────────────────────────────
        candidate_pool_size = max(
            k * self.overfetch_factor,
            self.rerank_pool_size if self.rerank_enabled else 0,
        )
        # ─────────────────────────────────────────────────────────────────
        # 1a. Vector candidates from FAISS
        # ─────────────────────────────────────────────────────────────────
        query_vector = self.embedder.embed_query(query)
        vector_candidates = self.faiss.search(
            query_vector, top_k=candidate_pool_size
        )
        vector_score_map = {cid: score for cid, score in vector_candidates}
        # ─────────────────────────────────────────────────────────────────
        # 1b. Fulltext candidates from Neo4j Lucene index (if enabled)
        # ─────────────────────────────────────────────────────────────────
        fulltext_score_map: dict[str, float] = {}
        if self.fulltext_enabled and self.neo4j is not None:
            fulltext_results = self.neo4j.fulltext_search(
                query, top_k=candidate_pool_size, sources=include_sources
            )
            fulltext_score_map = {cid: score for cid, score in fulltext_results}

        if not vector_candidates and not fulltext_score_map:
            return []
        # ─────────────────────────────────────────────────────────────────
        # 1c. Reciprocal Rank Fusion to merge the two ranked lists
        # ─────────────────────────────────────────────────────────────────
        rrf_score_map = self._rrf_score_map(
            vector_candidates,
            list(fulltext_score_map.items()),
        )
        fused_chunk_ids = sorted(
            rrf_score_map, key=lambda c: rrf_score_map[c], reverse=True
        )

        # ─────────────────────────────────────────────────────────────────
        # 2. Fetch chunk metadata from Neo4j (with filters)
        # ─────────────────────────────────────────────────────────────────
        if self.neo4j is not None:
            filtered = self.neo4j.filter_chunks(
                fused_chunk_ids,
                sources=include_sources,
                min_cvss=min_cvss,
                severity=severity,
                **filters,
            )
        else:
            filtered = [{"chunk_id": cid} for cid in fused_chunk_ids]

        # ─────────────────────────────────────────────────────────────────
        # 3. Attach scores + apply per-source boost (multiplicative on RRF)
        # ─────────────────────────────────────────────────────────────────
        results = []
        for chunk_data in filtered:
            cid = chunk_data.get("chunk_id")
            if cid not in rrf_score_map:
                continue
            source = chunk_data.get("source", "")
            if source in _exclude_set:
                continue
            chunk_data["vector_score"] = vector_score_map.get(cid)
            chunk_data["fulltext_score"] = fulltext_score_map.get(cid)
            chunk_data["rrf_score"] = rrf_score_map[cid]
            boost = self.source_boosts.get(source, 1.0)
            chunk_data["score"] = rrf_score_map[cid] * boost
            chunk_data["raw_score"] = chunk_data.get("vector_score") or 0.0
            results.append(chunk_data)

        # ─────────────────────────────────────────────────────────────────
        # 4. Sort by boosted RRF score (gives reranker a sane starting order)
        # ─────────────────────────────────────────────────────────────────
        results.sort(key=lambda x: x.get("score", 0), reverse=True)

        # ─────────────────────────────────────────────────────────────────
        # 5. Cross-encoder rerank (optional, on by default)
        # ─────────────────────────────────────────────────────────────────
        if self.rerank_enabled and len(results) > 1:
            try:
                reranker = self._get_reranker()
                if reranker is not None:
                    pool = results[: self.rerank_pool_size]
                    reranked = reranker.rerank(
                        query=query, chunks=pool, top_k=None
                    )
                    # rerank() set rerank_score (a logit, often negative).
                    # Apply sigmoid to map [-inf, +inf] → (0, 1) before the
                    # source boost, so multiplicative boost has consistent
                    # semantics on negative logits. Without this, a curated
                    # source with rerank_score=-1.6 and boost=1.20 would end
                    # up with score=-1.92 (more negative, ranked LOWER instead
                    # of higher). Sigmoid+boost gives 0.168 * 1.20 = 0.201,
                    # which correctly preserves the boost direction.
                    for chunk in reranked:
                        boost = self.source_boosts.get(chunk.get("source", ""), 1.0)
                        rerank_logit = chunk.get("rerank_score", 0.0)
                        rerank_prob = _sigmoid(rerank_logit)
                        chunk["rerank_prob"] = rerank_prob
                        chunk["score"] = rerank_prob * boost
                    reranked.sort(key=lambda x: x.get("score", 0), reverse=True)
                    results = reranked + results[self.rerank_pool_size:]
            except Exception as e:
                logger.warning(f"Reranker failed, falling back to RRF order: {e}")

        # ─────────────────────────────────────────────────────────────────
        # 6. MMR diversity re-ranking (mixes sources, avoids duplicates)
        # ─────────────────────────────────────────────────────────────────
        if self.mmr_enabled and len(results) > k:
            results = self._mmr_rerank(results, top_k=k, lambda_=self.mmr_lambda)
        else:
            results = results[:k]

        return results

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    def _get_reranker(self):
        """Lazy-load the default reranker on first use."""
        if self._reranker is not None:
            return self._reranker
        if not self.rerank_enabled:
            return None
        try:
            from knowledge_base.reranker import CrossEncoderReranker
            self._reranker = CrossEncoderReranker(
                model_name=self.config.reranker.model,
                max_tokens_per_side=self.config.reranker.max_tokens_per_side,
            )
            return self._reranker
        except Exception as e:
            logger.warning(
                f"Could not initialize reranker — disabling for this session: {e}"
            )
            self.rerank_enabled = False
            return None

    def _rrf_score_map(
        self,
        ranked_lists: list[tuple[str, float]],
        *more_lists: list[tuple[str, float]],
    ) -> dict[str, float]:
        """
        Reciprocal Rank Fusion over multiple ranked lists.

        RRF_score(d) = Σ 1 / (k + rank_i(d))

        Robust to score-scale differences between vector and fulltext —
        uses ranks, not raw scores. The constant `k` (self.rrf_k) is the
        Cormack et al. 2009 standard value of 60 by default.
        """
        all_lists = [ranked_lists, *more_lists]
        rrf_scores: dict[str, float] = {}
        for ranked in all_lists:
            for rank, (chunk_id, _score) in enumerate(ranked):
                rrf_scores.setdefault(chunk_id, 0.0)
                rrf_scores[chunk_id] += 1.0 / (self.rrf_k + rank + 1)
        return rrf_scores

    def _mmr_rerank(
        self,
        results: list[dict],
        top_k: int,
        lambda_: float = 0.5,
    ) -> list[dict]:
        """
        Maximal Marginal Relevance re-ranking.

        Picks results that balance relevance to the query against diversity
        (avoiding redundancy with already-selected results). Uses source +
        title overlap as a cheap proxy for similarity since we don't keep
        chunk vectors after FAISS search.

        Args:
            results: Pre-ranked list of result dicts (already sorted by score desc).
            top_k: Final number of results to return.
            lambda_: 1.0 = pure relevance (no diversity), 0.0 = pure diversity.

        Returns:
            Re-ranked list of top_k results.
        """
        if not results:
            return []
        if len(results) <= top_k:
            return results

        selected: list[dict] = [results[0]]
        remaining = list(results[1:])

        while len(selected) < top_k and remaining:
            best_idx = 0
            best_mmr = -math.inf

            for i, candidate in enumerate(remaining):
                relevance = candidate.get("score", 0.0)
                max_sim = max(
                    self._chunk_similarity(candidate, sel) for sel in selected
                )
                mmr = lambda_ * relevance - (1 - lambda_) * max_sim
                if mmr > best_mmr:
                    best_mmr = mmr
                    best_idx = i

            selected.append(remaining.pop(best_idx))

        return selected

    @staticmethod
    def _chunk_similarity(a: dict, b: dict) -> float:
        """
        Cheap similarity proxy between two chunks.

        Combines:
        - Source equality (heavy weight — discourage same-source pile-ups)
        - Title token Jaccard overlap (catches near-duplicates within a source)

        Returns a value in [0, 1].
        """
        sim = 0.0
        if a.get("source") and a.get("source") == b.get("source"):
            sim += 0.4
        title_a = (a.get("title") or "").lower()
        title_b = (b.get("title") or "").lower()
        if title_a and title_b:
            tokens_a = set(title_a.split())
            tokens_b = set(title_b.split())
            if tokens_a or tokens_b:
                jaccard = len(tokens_a & tokens_b) / max(len(tokens_a | tokens_b), 1)
                sim += 0.6 * jaccard
        return min(sim, 1.0)

    def is_sufficient(
        self, results: list[dict], threshold: Optional[float] = None
    ) -> bool:
        """Check if KB results are good enough to skip Tavily."""
        if not results:
            return False
        t = threshold or self.score_threshold
        return results[0].get("score", 0) >= t

    def stats(self) -> dict:
        """Return KB statistics."""
        info = {
            "faiss_vectors": self.faiss.count(),
            "neo4j_available": self.neo4j is not None,
            "config_path": str(self.config.source_path) if self.config.source_path else None,
        }
        if self.neo4j is not None:
            try:
                info["neo4j_chunks_by_source"] = self.neo4j.get_stats()
            except Exception as e:
                info["neo4j_error"] = str(e)
        return info

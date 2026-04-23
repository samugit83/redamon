import logging
import os
import time
from typing import Optional
from sentence_transformers import CrossEncoder

from knowledge_base.kb_config import load_kb_config

logger = logging.getLogger(__name__)


# Last-resort fallbacks. These are only reached when load_kb_config()
# itself raises (missing pyyaml, unreadable YAML, etc.). In normal
# operation, the values come from kb_config.yaml's `reranker` block,
# either directly via load_kb_config() or (more commonly) via
# kb_orchestrator passing config.reranker.* as explicit kwargs.
#
# BGE-reranker-base handles security/technical content significantly
# better than the smaller MS-MARCO MiniLM models.
# Alternatives (override via KB_RERANKER_MODEL or kb_config.yaml):
#   cross-encoder/ms-marco-MiniLM-L-6-v2  (80 MB, ~3x faster, web-tuned)
#   BAAI/bge-reranker-large               (1.3 GB, slower on CPU)
#   BAAI/bge-reranker-v2-m3               (2.3 GB, 8192-token context)
DEFAULT_RERANKER_MODEL = "BAAI/bge-reranker-base"
DEFAULT_MAX_TOKENS_PER_SIDE = 480

# Heuristic: the chunker and token budget everywhere in this project
# estimate tokens as ``len(text) // 4``. We use the same ratio in
# reverse to convert a token budget into a character pre-truncation
# budget. This is approximate — prose ≈ 4 chars/token, code/CLI often
# fewer (3 chars/token) — so we apply the ratio then let the
# cross-encoder's own tokenizer do the final accurate truncation.
_CHARS_PER_TOKEN = 4


class CrossEncoderReranker:
    """
    Wraps sentence-transformers CrossEncoder for KB result reranking.

    Use:
        reranker = CrossEncoderReranker()
        reranked = reranker.rerank(
            query="certutil download payload windows",
            chunks=candidate_chunks,
            top_k=10,
        )
        # candidate_chunks now have a "rerank_score" key, sorted by it desc
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        max_tokens_per_side: Optional[int] = None,
    ):
        """
        Args:
            model_name: HuggingFace model id for a cross-encoder. If None,
                        reads from kb_config.yaml (`reranker.model`), then
                        KB_RERANKER_MODEL env var, then falls back to the
                        DEFAULT_RERANKER_MODEL constant.
            max_tokens_per_side: Token budget per side (query, doc) fed to
                        the cross-encoder. If None, reads from
                        kb_config.yaml (`reranker.max_tokens_per_side`),
                        then falls back to DEFAULT_MAX_TOKENS_PER_SIDE.
                        Clamped at runtime to the tokenizer's
                        model_max_length (with a warning if clamped).
        """
        # Load config once so both fields come from the same snapshot.
        cfg = None
        if model_name is None or max_tokens_per_side is None:
            try:
                cfg = load_kb_config().reranker
            except Exception:
                cfg = None

        if model_name is None:
            if cfg is not None:
                model_name = cfg.model
            else:
                model_name = (
                    os.getenv("KB_RERANKER_MODEL") or DEFAULT_RERANKER_MODEL
                )

        if max_tokens_per_side is None:
            if cfg is not None:
                max_tokens_per_side = cfg.max_tokens_per_side
            else:
                env_val = os.getenv("KB_RERANKER_MAX_TOKENS_PER_SIDE")
                if env_val:
                    try:
                        max_tokens_per_side = int(env_val)
                    except ValueError:
                        max_tokens_per_side = DEFAULT_MAX_TOKENS_PER_SIDE
                else:
                    max_tokens_per_side = DEFAULT_MAX_TOKENS_PER_SIDE

        self.model_name = model_name
        self.max_tokens_per_side = max_tokens_per_side
        # Effective limit computed once the model is loaded and its
        # tokenizer.model_max_length is known. Set in _load_model().
        self._effective_max_chars: Optional[int] = None
        self._model = None  # Lazy

    def _load_model(self) -> None:
        """Lazy-load the cross-encoder on first use and compute the
        effective character truncation budget from the configured
        token budget + the tokenizer's hard ceiling."""
        if self._model is not None:
            return

        logger.info(f"Loading cross-encoder reranker: {self.model_name}")
        t0 = time.time()
        self._model = CrossEncoder(self.model_name)

        # Interrogate the tokenizer for its actual max_length. This is
        # the hard ceiling — asking for more tokens than the model can
        # consume is a config error and gets clamped with a warning.
        # Sentence-transformers' CrossEncoder holds the HF tokenizer
        # on .tokenizer; fall back gracefully if that ever changes.
        tokenizer_max = None
        try:
            tokenizer = getattr(self._model, "tokenizer", None)
            if tokenizer is not None:
                tokenizer_max = getattr(tokenizer, "model_max_length", None)
                # HuggingFace uses a giant sentinel (1e30) when the model
                # has no real cap — treat that as "unknown, trust config".
                if tokenizer_max and tokenizer_max > 100_000:
                    tokenizer_max = None
        except Exception as e:
            logger.debug(f"Could not read tokenizer max_length: {e}")

        configured = self.max_tokens_per_side
        if tokenizer_max and configured > tokenizer_max:
            logger.warning(
                f"Reranker max_tokens_per_side={configured} exceeds "
                f"tokenizer model_max_length={tokenizer_max} for "
                f"{self.model_name}; clamping to {tokenizer_max}"
            )
            effective_tokens = tokenizer_max
        else:
            effective_tokens = configured

        # Convert to a character budget for pre-truncation. We pre-
        # truncate as a fast upper bound so very long chunk text (≫
        # the tokenizer capacity) doesn't waste tokenization cycles
        # just to have its tail chopped off. The cross-encoder's own
        # tokenizer then does the final, accurate truncation.
        self._effective_max_chars = effective_tokens * _CHARS_PER_TOKEN

        logger.info(
            f"Cross-encoder loaded: {self.model_name} "
            f"({time.time() - t0:.1f}s, "
            f"max_tokens_per_side={effective_tokens}, "
            f"pre_truncate_chars={self._effective_max_chars})"
        )

    def rerank(
        self,
        query: str,
        chunks: list[dict],
        top_k: Optional[int] = None,
        batch_size: int = 32,
    ) -> list[dict]:
        """
        Rerank a list of candidate chunks against the query.

        Mutates each chunk dict in-place to add `rerank_score` and updates
        `score` to the rerank score (so downstream code that sorts by
        `score` picks up the new ranking). The original `score` is preserved
        as `pre_rerank_score` for debugging.

        Args:
            query: User query string (no embedder prefix needed — cross-encoders
                   take raw text on both sides).
            chunks: List of dicts, each with at least `content` (or `title`
                    as a fallback). Order doesn't matter on input.
            top_k: Trim the output to this many chunks after reranking.
                   None = return all reranked.
            batch_size: Cross-encoder forward-pass batch size.

        Returns:
            New list of chunks sorted by rerank_score desc, length <= top_k.
        """
        if not chunks:
            return []
        if not query:
            return chunks[:top_k] if top_k else list(chunks)

        self._load_model()

        # Build (query, document) pairs. Use content if available, fall
        # back to title. Pre-truncate both sides at the character budget
        # derived from the configured token budget + tokenizer ceiling
        # (computed in _load_model). The cross-encoder's tokenizer will
        # then truncate the concatenated (query + [SEP] + doc) sequence
        # accurately to the model's hard token limit.
        max_chars = self._effective_max_chars or (_CHARS_PER_TOKEN * 128)
        truncated_query = query[:max_chars]
        pairs = []
        for c in chunks:
            doc = (c.get("content") or c.get("title") or "")[:max_chars]
            pairs.append((truncated_query, doc))

        t0 = time.time()
        scores = self._model.predict(
            pairs,
            batch_size=batch_size,
            show_progress_bar=False,
        )
        elapsed = time.time() - t0

        # Mutate in place: stash the pre-rerank score, then overwrite `score`
        # with the rerank score so downstream sorting/MMR uses it.
        for chunk, rerank_score in zip(chunks, scores):
            chunk["pre_rerank_score"] = chunk.get("score", 0.0)
            chunk["rerank_score"] = float(rerank_score)
            chunk["score"] = float(rerank_score)

        # Sort and trim
        chunks.sort(key=lambda c: c.get("rerank_score", 0.0), reverse=True)
        if top_k is not None:
            chunks = chunks[:top_k]

        rate = len(pairs) / elapsed if elapsed > 0 else 0.0
        logger.info(
            f"Reranked {len(pairs)} chunks in {elapsed * 1000:.0f}ms "
            f"({rate:.0f} pairs/sec, model={self.model_name})"
        )
        return chunks

    @property
    def is_loaded(self) -> bool:
        """True if the model has been pulled into memory."""
        return self._model is not None

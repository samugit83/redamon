import logging
import os
from typing import Optional

# Suppress noisy huggingface/transformers/sentence-transformers output
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")

import numpy as np

from knowledge_base.kb_config import load_kb_config

# Quiets library loggers
for _name in (
    "huggingface_hub",
    "huggingface_hub.utils._http",
    "transformers",
    "sentence_transformers",
    "sentence_transformers.SentenceTransformer",
):
    logging.getLogger(_name).setLevel(logging.ERROR)

logger = logging.getLogger(__name__)


# Per-model-family prefix rules. The first matching rule wins.
# Each rule is (substring_match, query_prefix, document_prefix).
# Empty strings = no prefix needed (symmetric model).
PREFIX_RULES = [
    # E5 family (intfloat) — asymmetric, query/passage prefixes required
    ("intfloat/e5",         "query: ",         "passage: "),
    ("e5-large",            "query: ",         "passage: "),
    ("e5-base",             "query: ",         "passage: "),
    ("e5-small",            "query: ",         "passage: "),

    # BGE family (BAAI) — asymmetric, query instruction only.
    # BGE only prefixes queries, not documents.
    ("BAAI/bge",            "Represent this sentence for searching relevant passages: ", ""),
    ("bge-large-en",        "Represent this sentence for searching relevant passages: ", ""),

    # MiniLM and other sentence-transformers defaults — symmetric
    ("sentence-transformers/", "", ""),
    ("all-MiniLM",             "", ""),
    ("all-mpnet",              "", ""),
    ("paraphrase-",            "", ""),
]


def _resolve_prefixes(model_name: str) -> tuple[str, str]:
    """
    Pick the right (query_prefix, document_prefix) for the given model.

    Falls back to empty prefixes if no rule matches (safe default — works
    for symmetric models, only suboptimal for asymmetric ones we don't know about).
    """
    name = model_name.lower()
    for substring, q_prefix, d_prefix in PREFIX_RULES:
        if substring.lower() in name:
            return q_prefix, d_prefix
    return "", ""  # safe default


class Embedder:
    """
    Wraps sentence-transformers with model-aware prefix handling.

    Default model is read from kb_config.yaml (`embedder.model`) on first
    instantiation when no explicit `model_name` is passed. Override per
    instance with the constructor arg, or globally via the YAML / env var.
    """

    def __init__(self, model_name: Optional[str] = None):
        if model_name is None:
            model_name = load_kb_config().embedder.model
        self.model_name = model_name
        self._model = None
        self._query_prefix, self._doc_prefix = _resolve_prefixes(model_name)

    def _load_model(self):
        """Lazy-load the SentenceTransformer model on first use."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name)

            prefix_info = (
                f"query='{self._query_prefix}' doc='{self._doc_prefix}'"
                if (self._query_prefix or self._doc_prefix)
                else "(no prefixes)"
            )
            logger.info(
                f"Embedding model loaded: {self.model_name} "
                f"(dim={self._model.get_sentence_embedding_dimension()}, {prefix_info})"
            )

    def embed_query(self, text: str) -> list[float]:
        """
        Embed a query string.

        Prepends the model-specific query prefix (if any) before encoding.
        Returns a normalized vector.
        """
        self._load_model()
        prefixed = f"{self._query_prefix}{text}"
        vector = self._model.encode(prefixed, normalize_embeddings=True)
        return vector.tolist()

    def embed_document(self, text: str) -> list[float]:
        """
        Embed a document string.

        Prepends the model-specific document prefix (if any) before encoding.
        Returns a normalized vector.
        """
        self._load_model()
        prefixed = f"{self._doc_prefix}{text}"
        vector = self._model.encode(prefixed, normalize_embeddings=True)
        return vector.tolist()

    def embed_documents_batch(
        self,
        texts: list[str],
        batch_size: Optional[int] = None,
    ) -> list[list[float]]:
        """
        Embed multiple document strings.

        Prepends the model-specific document prefix to each. SentenceTransformer
        handles batching internally for efficiency.

        Args:
            texts: List of document strings to embed.
            batch_size: SentenceTransformer encode batch size. If None, reads
                        the default from kb_config.yaml (`embedder.batch_size`,
                        default 64). 32 is safe for low-memory hosts; 64 is
                        ~30% faster on hosts with >8GB RAM headroom.

        Returns list of normalized vectors. Logs throughput so successive
        runs can be compared.
        """
        if not texts:
            return []
        if batch_size is None:
            from knowledge_base.kb_config import load_kb_config
            batch_size = load_kb_config().embedder.batch_size
        self._load_model()
        import time as _time

        prefixed = [f"{self._doc_prefix}{t}" for t in texts]
        t0 = _time.time()
        vectors = self._model.encode(
            prefixed,
            normalize_embeddings=True,
            batch_size=batch_size,
            show_progress_bar=False,
        )
        elapsed = _time.time() - t0
        rate = len(texts) / elapsed if elapsed > 0 else 0.0
        logger.info(
            f"Embedded {len(texts)} docs in {elapsed:.1f}s "
            f"({rate:.1f} docs/sec, batch_size={batch_size})"
        )
        return vectors.tolist()

    @property
    def dimensions(self) -> int:
        """Return embedding dimensions for the loaded model."""
        self._load_model()
        return self._model.get_sentence_embedding_dimension()


def create_embedder(model_name=None):
    """Factory: returns APIEmbedder if KB_EMBEDDING_USE_API=true, else local Embedder."""
    use_api = os.getenv("KB_EMBEDDING_USE_API", "false").lower() == "true"
    if use_api:
        from .api_embedder import APIEmbedder

        return APIEmbedder()
    return Embedder(model_name=model_name)

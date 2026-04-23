"""API-based embedder for the Knowledge Base.

Drop-in replacement for the local ``Embedder`` class that uses an external
embedding API instead of running sentence-transformers on CPU/GPU.
Uses the OpenAI SDK, which works with any OpenAI-compatible API
(OpenAI, Ollama, Together AI, Azure, vLLM, LiteLLM, etc.).

Controlled via environment variables:

    KB_EMBEDDING_USE_API=true
    KB_EMBEDDING_API_BASE_URL=https://api.openai.com/v1  (or any compatible endpoint)
    KB_EMBEDDING_API_KEY=sk-...
    KB_EMBEDDING_API_MODEL=text-embedding-3-small
"""

import logging
import os
import time

logger = logging.getLogger(__name__)

# Known dimensions per model so we can set up FAISS without a probe call.
_MODEL_DIMENSIONS: dict[str, int] = {
    # OpenAI
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "text-embedding-ada-002": 1536,
}


class APIEmbedder:
    """Embedding via external API.  Same interface as ``Embedder``."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        self.model = model or os.getenv("KB_EMBEDDING_API_MODEL", "text-embedding-3-small")
        self.api_key = api_key or os.getenv("KB_EMBEDDING_API_KEY")
        self.base_url = base_url or os.getenv("KB_EMBEDDING_API_BASE_URL") or None
        if not self.api_key:
            raise ValueError(
                "KB_EMBEDDING_API_KEY is required when KB_EMBEDDING_USE_API=true"
            )
        self._client = None
        self._dimensions: int | None = _MODEL_DIMENSIONS.get(self.model)
        logger.info(
            "APIEmbedder configured: base_url=%s model=%s dim=%s",
            self.base_url or "https://api.openai.com/v1 (default)",
            self.model,
            self._dimensions or "auto-detect",
        )

    # ------------------------------------------------------------------
    # Client
    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        return self._client

    # ------------------------------------------------------------------
    # Core embedding
    # ------------------------------------------------------------------

    def _embed(self, texts: list[str]) -> list[list[float]]:
        client = self._get_client()
        resp = client.embeddings.create(input=texts, model=self.model)
        return [item.embedding for item in resp.data]

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text])[0]

    def embed_document(self, text: str) -> list[float]:
        return self._embed([text])[0]

    def embed_documents_batch(
        self,
        texts: list[str],
        batch_size: int | None = None,
    ) -> list[list[float]]:
        batch_size = batch_size or 2048  # OpenAI supports up to 2048 per request
        all_vectors: list[list[float]] = []
        start = time.time()
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            all_vectors.extend(self._embed(batch))
        elapsed = time.time() - start
        rate = len(texts) / elapsed if elapsed > 0 else 0
        logger.info(
            "API-embedded %d docs in %.1fs (%.1f docs/sec)",
            len(texts),
            elapsed,
            rate,
        )
        return all_vectors

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def dimensions(self) -> int:
        if self._dimensions is not None:
            return self._dimensions
        # Fallback: embed a short text to discover dimensions
        vec = self.embed_query("dimension probe")
        self._dimensions = len(vec)
        logger.info("Auto-detected embedding dimensions: %d", self._dimensions)
        return self._dimensions

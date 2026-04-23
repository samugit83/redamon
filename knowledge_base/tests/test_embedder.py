import pytest
import numpy as np


class TestEmbedder:
    """
    Test suite for Embedder prefix handling and normalization.

    NOTE: These tests require the sentence-transformers package and will
    download the model on first run (~1.3GB). Mark with @pytest.mark.slow
    for CI environments that skip heavy tests.
    """

    @pytest.fixture(scope="class")
    def embedder(self):
        """Shared embedder instance (model loads once per test class)."""
        from knowledge_base.embedder import Embedder
        return Embedder(model_name="intfloat/e5-large-v2")

    def test_embed_query_returns_list(self, embedder):
        result = embedder.embed_query("test query")
        assert isinstance(result, list)
        assert all(isinstance(x, float) for x in result)

    def test_embed_document_returns_list(self, embedder):
        result = embedder.embed_document("test document")
        assert isinstance(result, list)
        assert all(isinstance(x, float) for x in result)

    def test_dimensions_match(self, embedder):
        vec = embedder.embed_query("test")
        assert len(vec) == embedder.dimensions
        assert embedder.dimensions == 1024

    def test_query_and_document_differ(self, embedder):
        """Same text with different prefixes should produce different vectors."""
        text = "metasploit reverse tcp payload"
        q_vec = embedder.embed_query(text)
        d_vec = embedder.embed_document(text)
        # Vectors should not be identical (different prefixes)
        assert q_vec != d_vec

    def test_normalized_vectors(self, embedder):
        """Vectors should be unit-length (L2 norm ≈ 1.0)."""
        vec = np.array(embedder.embed_query("test normalization"))
        norm = np.linalg.norm(vec)
        assert abs(norm - 1.0) < 1e-5, f"Expected unit vector, got norm={norm}"

    def test_batch_matches_individual(self, embedder):
        """Batch encoding should produce same results as individual encoding."""
        texts = ["apache struts rce", "sql injection bypass"]
        batch = embedder.embed_documents_batch(texts)
        individual = [embedder.embed_document(t) for t in texts]

        assert len(batch) == len(individual)
        for b, i in zip(batch, individual):
            np.testing.assert_allclose(b, i, atol=1e-5)

    def test_batch_empty_input(self, embedder):
        result = embedder.embed_documents_batch([])
        assert result == []

    def test_dimensions_property(self, embedder):
        assert isinstance(embedder.dimensions, int)
        assert embedder.dimensions > 0

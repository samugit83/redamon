"""Unit tests for api_embedder.py and the create_embedder factory."""

import os
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# APIEmbedder
# ---------------------------------------------------------------------------


class TestAPIEmbedder:
    """Tests for APIEmbedder class."""

    def test_init_requires_api_key(self):
        """APIEmbedder raises ValueError when no API key is provided."""
        from knowledge_base.api_embedder import APIEmbedder

        with pytest.raises(ValueError, match="KB_EMBEDDING_API_KEY is required"):
            APIEmbedder(model="text-embedding-3-small", api_key="")

    def test_init_requires_api_key_from_env(self, monkeypatch):
        """APIEmbedder raises when env var is also empty."""
        from knowledge_base.api_embedder import APIEmbedder

        monkeypatch.delenv("KB_EMBEDDING_API_KEY", raising=False)
        with pytest.raises(ValueError, match="KB_EMBEDDING_API_KEY is required"):
            APIEmbedder(model="text-embedding-3-small")

    def test_init_accepts_explicit_key(self):
        """APIEmbedder accepts an explicit API key."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test-key-123",
        )
        assert embedder.model == "text-embedding-3-small"
        assert embedder.api_key == "sk-test-key-123"

    def test_init_reads_env_vars(self, monkeypatch):
        """APIEmbedder reads config from environment variables."""
        from knowledge_base.api_embedder import APIEmbedder

        monkeypatch.setenv("KB_EMBEDDING_API_MODEL", "text-embedding-3-large")
        monkeypatch.setenv("KB_EMBEDDING_API_KEY", "sk-env-key")
        monkeypatch.setenv("KB_EMBEDDING_API_BASE_URL", "https://custom.api.com/v1")

        embedder = APIEmbedder()
        assert embedder.model == "text-embedding-3-large"
        assert embedder.api_key == "sk-env-key"
        assert embedder.base_url == "https://custom.api.com/v1"

    def test_base_url_defaults_to_none(self, monkeypatch):
        """Base URL defaults to None (OpenAI SDK default) when not set."""
        from knowledge_base.api_embedder import APIEmbedder

        monkeypatch.delenv("KB_EMBEDDING_API_BASE_URL", raising=False)
        embedder = APIEmbedder(api_key="sk-test")
        assert embedder.base_url is None

    def test_base_url_explicit(self):
        """Base URL can be set explicitly."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            api_key="sk-test",
            base_url="http://localhost:11434/v1",
        )
        assert embedder.base_url == "http://localhost:11434/v1"

    def test_known_dimensions(self):
        """Known models return their dimension without an API call."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test",
        )
        assert embedder.dimensions == 1536

    def test_known_dimensions_large(self):
        """text-embedding-3-large returns 3072 dimensions."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-large",
            api_key="sk-test",
        )
        assert embedder.dimensions == 3072

    def test_unknown_model_probes_dimensions(self):
        """Unknown model probes dimensions via a dummy embed call."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="custom-model-v1",
            api_key="sk-test",
        )
        # Mock the _embed call for probe
        fake_vector = [0.1] * 768
        embedder._embed = MagicMock(return_value=[fake_vector])
        assert embedder.dimensions == 768

    def test_embed_query_calls_api(self):
        """embed_query returns a single vector from the API."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test",
        )
        fake_vector = [0.1] * 1536
        embedder._embed = MagicMock(return_value=[fake_vector])

        result = embedder.embed_query("test query")
        assert result == fake_vector
        embedder._embed.assert_called_once_with(["test query"])

    def test_embed_document_calls_api(self):
        """embed_document returns a single vector from the API."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test",
        )
        fake_vector = [0.2] * 1536
        embedder._embed = MagicMock(return_value=[fake_vector])

        result = embedder.embed_document("test doc")
        assert result == fake_vector
        embedder._embed.assert_called_once_with(["test doc"])

    def test_embed_documents_batch_respects_batch_size(self):
        """Batch embedding splits into correct number of API calls."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test",
        )
        fake_vector = [0.1] * 1536
        embedder._embed = MagicMock(return_value=[fake_vector])

        texts = [f"doc {i}" for i in range(5)]
        result = embedder.embed_documents_batch(texts, batch_size=2)

        assert len(result) == 5
        # 5 docs with batch_size=2 = 3 API calls (2+2+1)
        assert embedder._embed.call_count == 3

    def test_embed_documents_batch_default_batch_size(self):
        """Default batch size is 2048 for API embedder."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test",
        )
        fake_vector = [0.1] * 1536
        # 100 docs with default batch_size=2048 = 1 API call
        embedder._embed = MagicMock(return_value=[fake_vector] * 100)

        texts = [f"doc {i}" for i in range(100)]
        result = embedder.embed_documents_batch(texts)

        assert len(result) == 100
        embedder._embed.assert_called_once()

    def test_client_lazy_init(self):
        """Client is not created until first embed call."""
        from knowledge_base.api_embedder import APIEmbedder

        embedder = APIEmbedder(
            model="text-embedding-3-small",
            api_key="sk-test",
        )
        assert embedder._client is None


# ---------------------------------------------------------------------------
# create_embedder factory
# ---------------------------------------------------------------------------


class TestCreateEmbedder:
    """Tests for the create_embedder factory function."""

    def test_default_returns_local_embedder(self, monkeypatch):
        """Without KB_EMBEDDING_USE_API, returns local Embedder."""
        monkeypatch.delenv("KB_EMBEDDING_USE_API", raising=False)
        from knowledge_base.embedder import Embedder, create_embedder

        result = create_embedder(model_name="intfloat/e5-large-v2")
        assert isinstance(result, Embedder)
        assert result.model_name == "intfloat/e5-large-v2"

    def test_use_api_false_returns_local(self, monkeypatch):
        """KB_EMBEDDING_USE_API=false returns local Embedder."""
        monkeypatch.setenv("KB_EMBEDDING_USE_API", "false")
        from knowledge_base.embedder import Embedder, create_embedder

        result = create_embedder()
        assert isinstance(result, Embedder)

    def test_use_api_true_returns_api_embedder(self, monkeypatch):
        """KB_EMBEDDING_USE_API=true returns APIEmbedder."""
        monkeypatch.setenv("KB_EMBEDDING_USE_API", "true")
        monkeypatch.setenv("KB_EMBEDDING_API_KEY", "sk-test-key")
        monkeypatch.setenv("KB_EMBEDDING_API_MODEL", "text-embedding-3-small")

        from knowledge_base.embedder import create_embedder
        from knowledge_base.api_embedder import APIEmbedder

        result = create_embedder()
        assert isinstance(result, APIEmbedder)
        assert result.api_key == "sk-test-key"

    def test_use_api_true_without_key_raises(self, monkeypatch):
        """KB_EMBEDDING_USE_API=true without API key raises ValueError."""
        monkeypatch.setenv("KB_EMBEDDING_USE_API", "true")
        monkeypatch.delenv("KB_EMBEDDING_API_KEY", raising=False)

        from knowledge_base.embedder import create_embedder

        with pytest.raises(ValueError, match="KB_EMBEDDING_API_KEY is required"):
            create_embedder()

    def test_use_api_case_insensitive(self, monkeypatch):
        """KB_EMBEDDING_USE_API is case-insensitive."""
        monkeypatch.setenv("KB_EMBEDDING_USE_API", "True")
        monkeypatch.setenv("KB_EMBEDDING_API_KEY", "sk-test")

        from knowledge_base.embedder import create_embedder
        from knowledge_base.api_embedder import APIEmbedder

        result = create_embedder()
        assert isinstance(result, APIEmbedder)

    def test_model_name_ignored_in_api_mode(self, monkeypatch):
        """model_name parameter is ignored when API mode is active."""
        monkeypatch.setenv("KB_EMBEDDING_USE_API", "true")
        monkeypatch.setenv("KB_EMBEDDING_API_KEY", "sk-test")
        monkeypatch.setenv("KB_EMBEDDING_API_MODEL", "text-embedding-3-small")

        from knowledge_base.embedder import create_embedder
        from knowledge_base.api_embedder import APIEmbedder

        # Pass a HuggingFace model name -- it should be ignored
        result = create_embedder(model_name="intfloat/e5-large-v2")
        assert isinstance(result, APIEmbedder)
        assert result.model == "text-embedding-3-small"

    def test_base_url_passed_through(self, monkeypatch):
        """Base URL from env is passed to APIEmbedder."""
        monkeypatch.setenv("KB_EMBEDDING_USE_API", "true")
        monkeypatch.setenv("KB_EMBEDDING_API_KEY", "sk-test")
        monkeypatch.setenv("KB_EMBEDDING_API_BASE_URL", "http://localhost:11434/v1")

        from knowledge_base.embedder import create_embedder

        result = create_embedder()
        assert result.base_url == "http://localhost:11434/v1"


# ---------------------------------------------------------------------------
# cpu-lite profile
# ---------------------------------------------------------------------------


class TestCpuLiteProfile:
    """Tests for the cpu-lite profile in config and ingestion."""

    def test_cpu_lite_in_fallback_profiles(self):
        """cpu-lite exists in the hardcoded fallback profiles."""
        from knowledge_base.curation.data_ingestion import _FALLBACK_PROFILE_SOURCES

        assert "cpu-lite" in _FALLBACK_PROFILE_SOURCES
        assert _FALLBACK_PROFILE_SOURCES["cpu-lite"] == [
            "tool_docs", "gtfobins", "lolbas"
        ]

    def test_cpu_lite_is_subset_of_lite(self):
        """cpu-lite sources are a strict subset of lite sources."""
        from knowledge_base.curation.data_ingestion import _FALLBACK_PROFILE_SOURCES

        cpu_lite = set(_FALLBACK_PROFILE_SOURCES["cpu-lite"])
        lite = set(_FALLBACK_PROFILE_SOURCES["lite"])
        assert cpu_lite < lite  # strict subset

    def test_cpu_lite_profile_from_config(self):
        """cpu-lite profile loads correctly from kb_config.yaml."""
        from knowledge_base.kb_config import load_kb_config, reset_cache

        reset_cache()
        config = load_kb_config(refresh=True)
        profiles = config.ingestion.profiles
        assert "cpu-lite" in profiles
        assert profiles["cpu-lite"] == ["tool_docs", "gtfobins", "lolbas"]

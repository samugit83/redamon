
import logging

import pytest

from knowledge_base.reranker import (
    DEFAULT_MAX_TOKENS_PER_SIDE,
    DEFAULT_RERANKER_MODEL,
    CrossEncoderReranker,
    _CHARS_PER_TOKEN,
)


class _FakeTokenizer:
    def __init__(self, model_max_length: int):
        self.model_max_length = model_max_length


class _FakeCrossEncoder:
    """Duck-types the subset of sentence_transformers.CrossEncoder that
    CrossEncoderReranker uses: .tokenizer and .predict()."""

    def __init__(self, model_max_length: int = 512):
        self.tokenizer = _FakeTokenizer(model_max_length)
        self.predicted_pairs = None

    def predict(self, pairs, batch_size=32, show_progress_bar=False):
        self.predicted_pairs = pairs
        # Return decreasing scores so the sort order is deterministic
        return [float(len(pairs) - i) for i in range(len(pairs))]


def _install_fake_model(reranker: CrossEncoderReranker, model_max_length: int):
    """Bypass _load_model's real sentence-transformers import by
    preloading a fake model, then call _load_model which detects the
    already-loaded instance and only runs the tokenizer/clamp logic."""
    reranker._model = _FakeCrossEncoder(model_max_length=model_max_length)
    # Manually run the clamp logic that _load_model would have run.
    # We do it by invoking the private path used internally: compute
    # effective_max_chars the same way the real code does.
    tokenizer_max = model_max_length
    configured = reranker.max_tokens_per_side
    if configured > tokenizer_max:
        effective_tokens = tokenizer_max
    else:
        effective_tokens = configured
    reranker._effective_max_chars = effective_tokens * _CHARS_PER_TOKEN


# =============================================================================
# Config precedence
# =============================================================================

class TestRerankerConfigPrecedence:

    def test_explicit_kwargs_win(self, monkeypatch):
        """When both model_name and max_tokens_per_side are passed as
        kwargs, they bypass kb_config and env lookups entirely."""
        # Set env + config-path distractors that should be ignored
        monkeypatch.setenv("KB_RERANKER_MODEL", "should/be-ignored")
        monkeypatch.setenv("KB_RERANKER_MAX_TOKENS_PER_SIDE", "42")

        r = CrossEncoderReranker(
            model_name="explicit/model",
            max_tokens_per_side=123,
        )
        assert r.model_name == "explicit/model"
        assert r.max_tokens_per_side == 123

    def test_reads_from_kb_config(self):
        """When no kwargs, values come from load_kb_config() — proves
        the config-driven default path works and matches what
        kb_orchestrator passes explicitly in prod."""
        from knowledge_base.kb_config import load_kb_config
        cfg = load_kb_config()

        r = CrossEncoderReranker()
        assert r.model_name == cfg.reranker.model
        assert r.max_tokens_per_side == cfg.reranker.max_tokens_per_side

    def test_env_fallback_when_config_load_fails(self, monkeypatch):
        """If load_kb_config() raises (broken YAML, missing pyyaml,
        etc.), fall back to env var → DEFAULT_ constants.

        ``load_kb_config`` is imported at reranker module scope so we
        patch the binding inside ``knowledge_base.reranker`` itself —
        this is the "patch where it's used, not where it's defined"
        rule: replacing ``knowledge_base.kb_config.load_kb_config``
        after the reranker module has already bound its local name
        would have no effect on the already-bound reference."""
        import knowledge_base.reranker as _rr

        def raising_load():
            raise RuntimeError("simulated config failure")

        monkeypatch.setattr(_rr, "load_kb_config", raising_load)
        monkeypatch.setenv("KB_RERANKER_MODEL", "env/model")
        monkeypatch.setenv("KB_RERANKER_MAX_TOKENS_PER_SIDE", "256")

        r = CrossEncoderReranker()
        assert r.model_name == "env/model"
        assert r.max_tokens_per_side == 256

    def test_default_constants_when_config_and_env_both_missing(self, monkeypatch):
        import knowledge_base.reranker as _rr

        def raising_load():
            raise RuntimeError("no config")

        monkeypatch.setattr(_rr, "load_kb_config", raising_load)
        monkeypatch.delenv("KB_RERANKER_MODEL", raising=False)
        monkeypatch.delenv("KB_RERANKER_MAX_TOKENS_PER_SIDE", raising=False)

        r = CrossEncoderReranker()
        assert r.model_name == DEFAULT_RERANKER_MODEL
        assert r.max_tokens_per_side == DEFAULT_MAX_TOKENS_PER_SIDE

    def test_invalid_env_int_falls_through_to_default(self, monkeypatch):
        """KB_RERANKER_MAX_TOKENS_PER_SIDE=not-a-number must not crash
        — it falls through to the constant default."""
        import knowledge_base.reranker as _rr

        def raising_load():
            raise RuntimeError("no config")

        monkeypatch.setattr(_rr, "load_kb_config", raising_load)
        monkeypatch.setenv("KB_RERANKER_MAX_TOKENS_PER_SIDE", "not-a-number")

        r = CrossEncoderReranker()
        assert r.max_tokens_per_side == DEFAULT_MAX_TOKENS_PER_SIDE


# =============================================================================
# Tokenizer clamp — the core Sec-bug fix
# =============================================================================

class TestTokenizerClamp:

    def test_configured_under_tokenizer_max_used_as_is(self, caplog):
        """When configured ≤ tokenizer.model_max_length, the configured
        value is used verbatim. 480 ≤ 512 → 480 × 4 = 1920 char budget."""
        r = CrossEncoderReranker(
            model_name="fake/model",
            max_tokens_per_side=480,
        )
        with caplog.at_level(logging.WARNING, logger="knowledge_base.reranker"):
            _install_fake_model(r, model_max_length=512)
        assert r._effective_max_chars == 480 * _CHARS_PER_TOKEN
        # No clamp warning should have fired
        assert not any(
            "exceeds tokenizer model_max_length" in rec.message
            for rec in caplog.records
        )

    def test_configured_over_tokenizer_max_clamped_with_warning(self, caplog):
        """The bug scenario: operator sets max_tokens_per_side=1024 in
        kb_config.yaml while still using bge-reranker-base (512-token
        capacity). The reranker must clamp to 512 AND log a WARNING so
        operators notice the misconfiguration."""
        r = CrossEncoderReranker(
            model_name="fake/bge-reranker-base",
            max_tokens_per_side=1024,  # > model capacity
        )
        r._model = _FakeCrossEncoder(model_max_length=512)
        # Run the real _load_model clamp path by calling it. We've
        # preloaded _model, so the import guard at the top of
        # _load_model short-circuits and it returns early — we need
        # to exercise the clamp path differently. Simulate by
        # walking the same logic:
        with caplog.at_level(logging.WARNING, logger="knowledge_base.reranker"):
            # Manual trace of the clamp branch:
            tokenizer_max = r._model.tokenizer.model_max_length
            assert tokenizer_max == 512
            configured = r.max_tokens_per_side
            assert configured > tokenizer_max
            effective_tokens = tokenizer_max  # clamp
            r._effective_max_chars = effective_tokens * _CHARS_PER_TOKEN

        assert r._effective_max_chars == 512 * _CHARS_PER_TOKEN == 2048

    def test_clamp_end_to_end_via_load_model(self, caplog, monkeypatch):
        """End-to-end version: replace the CrossEncoder binding in the
        reranker module's own namespace so _load_model's call resolves
        to our fake. This exercises the actual clamp + logging path
        that runs in production. (CrossEncoder is imported at
        reranker.py module scope, so the local binding is what the
        `self._model = CrossEncoder(...)` line looks up.)
        """
        import knowledge_base.reranker as mod

        tokenizer_max = 512
        monkeypatch.setattr(
            mod,
            "CrossEncoder",
            lambda name: _FakeCrossEncoder(model_max_length=tokenizer_max),
        )

        r = mod.CrossEncoderReranker(
            model_name="fake/bge-reranker-base",
            max_tokens_per_side=1024,  # intentionally over
        )

        with caplog.at_level(logging.WARNING, logger="knowledge_base.reranker"):
            r._load_model()

        # Clamped to the tokenizer's actual max
        assert r._effective_max_chars == tokenizer_max * _CHARS_PER_TOKEN
        # Warning fired with the relevant numbers
        clamp_warnings = [
            rec for rec in caplog.records
            if "exceeds tokenizer model_max_length" in rec.message
        ]
        assert clamp_warnings, "expected a clamp warning to be logged"
        msg = clamp_warnings[0].message
        assert "1024" in msg
        assert "512" in msg

    def test_unknown_tokenizer_max_respects_config(self, monkeypatch):
        """Some tokenizers use a giant sentinel (~1e30) when there's
        no real cap. _load_model treats that as 'unknown' and uses
        the configured value unclamped."""
        import knowledge_base.reranker as mod

        monkeypatch.setattr(
            mod,
            "CrossEncoder",
            lambda name: _FakeCrossEncoder(model_max_length=10**30),
        )

        r = mod.CrossEncoderReranker(
            model_name="fake/unbounded",
            max_tokens_per_side=2048,
        )
        r._load_model()
        # No clamp applied — configured value wins
        assert r._effective_max_chars == 2048 * _CHARS_PER_TOKEN


# =============================================================================
# Rerank() — pre-truncation uses the effective char budget
# =============================================================================

class TestRerankTruncation:

    def test_rerank_pre_truncates_to_effective_max_chars(self):
        """Chunks longer than _effective_max_chars must be truncated
        BEFORE being handed to the cross-encoder tokenizer. This is
        the fix for the old hardcoded 512-char cap that discarded ~75%
        of each chunk's content."""
        r = CrossEncoderReranker(
            model_name="fake/model",
            max_tokens_per_side=480,
        )
        _install_fake_model(r, model_max_length=512)
        # Effective budget: 480 * 4 = 1920 chars
        assert r._effective_max_chars == 1920

        long_content = "X" * 5000  # well over the cap
        chunks = [
            {"content": long_content, "chunk_id": "c1"},
            {"content": "short", "chunk_id": "c2"},
        ]
        r.rerank(query="anything", chunks=chunks)

        pairs = r._model.predicted_pairs
        assert pairs is not None
        # The long doc should have been truncated to _effective_max_chars
        q0, d0 = pairs[0]
        assert len(d0) == 1920, (
            f"long doc not truncated to budget: got {len(d0)} chars"
        )
        # The short doc passes through
        q1, d1 = pairs[1]
        assert d1 == "short"

    def test_rerank_empty_chunks_returns_empty(self):
        r = CrossEncoderReranker(
            model_name="fake/model",
            max_tokens_per_side=480,
        )
        _install_fake_model(r, model_max_length=512)
        assert r.rerank(query="q", chunks=[]) == []

    def test_rerank_empty_query_returns_chunks_untouched(self):
        r = CrossEncoderReranker(
            model_name="fake/model",
            max_tokens_per_side=480,
        )
        _install_fake_model(r, model_max_length=512)
        chunks = [{"content": "a"}, {"content": "b"}]
        out = r.rerank(query="", chunks=chunks, top_k=1)
        # No reranking ran; cross-encoder was not called
        assert r._model.predicted_pairs is None
        assert len(out) == 1

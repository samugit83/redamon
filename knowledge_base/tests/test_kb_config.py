import os
import textwrap
from pathlib import Path

import pytest

from knowledge_base import kb_config
from knowledge_base.kb_config import (
    DEFAULTS,
    KBConfig,
    _coerce_bool,
    _deep_merge,
    load_kb_config,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _clear_cache_and_env(monkeypatch):
    """Reset module-level cache and clear KB env vars before every test."""
    reset_cache()
    for var in (
        "KB_CONFIG_FILE",
        "KB_EMBEDDING_MODEL",
        "KB_RERANK_ENABLED",
        "KB_RERANKER_MODEL",
        "KB_FULLTEXT_ENABLED",
        "NVD_LOOKBACK_DAYS",
        "NVD_MIN_CVSS",
    ):
        monkeypatch.delenv(var, raising=False)
    yield
    reset_cache()


def _write_yaml(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "kb_config.yaml"
    path.write_text(textwrap.dedent(content))
    return path


class TestDefaults:
    def test_load_with_missing_file_returns_defaults(self, tmp_path):
        cfg = load_kb_config(path=tmp_path / "nonexistent.yaml")
        assert isinstance(cfg, KBConfig)
        assert cfg.runtime.mode == DEFAULTS["runtime"]["mode"]
        assert cfg.embedder.model == DEFAULTS["embedder"]["model"]
        assert cfg.reranker.enabled == DEFAULTS["reranker"]["enabled"]
        assert cfg.fulltext.enabled == DEFAULTS["fulltext"]["enabled"]
        assert cfg.retrieval.top_k == DEFAULTS["retrieval"]["top_k"]
        assert cfg.mmr.lambda_ == DEFAULTS["mmr"]["lambda"]
        assert cfg.source_boosts["nvd"] == DEFAULTS["source_boosts"]["nvd"]
        assert cfg.ingestion.nvd_lookback_days == DEFAULTS["ingestion"]["nvd_lookback_days"]
        assert cfg.source_path is None  # signals "no file used"

    def test_default_mode_is_local(self, tmp_path):
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert cfg.runtime.mode == "local"

    def test_default_nvd_days_is_90(self, tmp_path):
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert cfg.ingestion.nvd_lookback_days == 90

    def test_default_nvd_min_cvss_is_7(self, tmp_path):
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert cfg.ingestion.nvd_min_cvss == 7.0


class TestYamlLoading:
    def test_yaml_overrides_defaults(self, tmp_path):
        path = _write_yaml(tmp_path, """
            runtime:
              mode: docker
            embedder:
              model: intfloat/e5-base-v2
            reranker:
              enabled: false
            ingestion:
              nvd_lookback_days: 365
        """)
        cfg = load_kb_config(path=path)
        assert cfg.runtime.mode == "docker"
        assert cfg.embedder.model == "intfloat/e5-base-v2"
        assert cfg.reranker.enabled is False
        assert cfg.ingestion.nvd_lookback_days == 365
        assert cfg.source_path == path

    def test_yaml_partial_keeps_defaults_for_missing(self, tmp_path):
        # Only override one field; everything else should be default.
        path = _write_yaml(tmp_path, """
            mmr:
              lambda: 0.3
        """)
        cfg = load_kb_config(path=path)
        assert cfg.mmr.lambda_ == 0.3
        # Untouched defaults preserved
        assert cfg.embedder.model == DEFAULTS["embedder"]["model"]
        assert cfg.reranker.model == DEFAULTS["reranker"]["model"]

    def test_source_boosts_loaded(self, tmp_path):
        path = _write_yaml(tmp_path, """
            source_boosts:
              tool_docs: 1.5
              nvd: 0.5
              new_source: 1.25
        """)
        cfg = load_kb_config(path=path)
        assert cfg.source_boosts["tool_docs"] == 1.5
        assert cfg.source_boosts["nvd"] == 0.5
        assert cfg.source_boosts["new_source"] == 1.25

    def test_unknown_top_level_key_rejected(self, tmp_path):
        path = _write_yaml(tmp_path, """
            embedder:
              model: foo
            mistypped_key:
              foo: bar
        """)
        # Loader should log a warning and fall back to defaults rather than
        # crashing — but the warning should mention the unknown key.
        cfg = load_kb_config(path=path)
        # Defaults retained because validation rejected the file
        assert cfg.embedder.model == DEFAULTS["embedder"]["model"]

    def test_kb_enabled_top_level_key_allowed(self, tmp_path):
        """KB_ENABLED is a top-level feature gate that must pass validation.

        It's read by redamon.sh::is_kb_enabled via direct YAML parsing, not
        through the Python loader's typed dataclass. The only requirement on
        the Python side is that adding it to the YAML doesn't cause the
        validator to reject the whole file.
        """
        path = _write_yaml(tmp_path, """
            KB_ENABLED: true
            embedder:
              model: from-yaml
        """)
        cfg = load_kb_config(path=path)
        # Should load successfully (not fall back to defaults)
        assert cfg.embedder.model == "from-yaml"
        assert cfg.source_path == path

    def test_kb_enabled_false_at_top_level(self, tmp_path):
        """KB_ENABLED: false also passes validation."""
        path = _write_yaml(tmp_path, """
            KB_ENABLED: false
            reranker:
              enabled: false
        """)
        cfg = load_kb_config(path=path)
        assert cfg.reranker.enabled is False
        assert cfg.source_path == path


class TestEnvOverrides:
    def test_env_overrides_yaml(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            embedder:
              model: from-yaml
            reranker:
              enabled: true
        """)
        monkeypatch.setenv("KB_EMBEDDING_MODEL", "from-env")
        monkeypatch.setenv("KB_RERANK_ENABLED", "false")

        cfg = load_kb_config(path=path)
        assert cfg.embedder.model == "from-env"
        assert cfg.reranker.enabled is False

    def test_env_overrides_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KB_RERANKER_MODEL", "BAAI/bge-reranker-base")
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert cfg.reranker.model == "BAAI/bge-reranker-base"

    def test_nvd_lookback_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NVD_LOOKBACK_DAYS", "180")
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert cfg.ingestion.nvd_lookback_days == 180

    def test_nvd_lookback_env_invalid_falls_back(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NVD_LOOKBACK_DAYS", "not_a_number")
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        # Should fall back to default, not crash
        assert cfg.ingestion.nvd_lookback_days == DEFAULTS["ingestion"]["nvd_lookback_days"]

    def test_nvd_min_cvss_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NVD_MIN_CVSS", "9.0")
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert cfg.ingestion.nvd_min_cvss == 9.0

    def test_nvd_min_cvss_env_invalid_falls_back(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NVD_MIN_CVSS", "critical_only")
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        # Invalid float string → fall back to default, not crash
        assert cfg.ingestion.nvd_min_cvss == DEFAULTS["ingestion"]["nvd_min_cvss"]

    def test_nvd_min_cvss_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, """
            ingestion:
              nvd_min_cvss: 4.0
        """)
        cfg = load_kb_config(path=path)
        assert cfg.ingestion.nvd_min_cvss == 4.0

    def test_nvd_min_cvss_env_overrides_yaml(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            ingestion:
              nvd_min_cvss: 7.0
        """)
        monkeypatch.setenv("NVD_MIN_CVSS", "9.0")
        cfg = load_kb_config(path=path)
        assert cfg.ingestion.nvd_min_cvss == 9.0

    def test_kb_config_file_env_var(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            embedder:
              model: from-kb-config-file
        """)
        monkeypatch.setenv("KB_CONFIG_FILE", str(path))
        cfg = load_kb_config()  # No explicit path arg
        assert cfg.embedder.model == "from-kb-config-file"

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("true", True),
            ("false", False),
            ("True", True),
            ("FALSE", False),
            ("1", True),
            ("0", False),
            ("yes", True),
            ("no", False),
            ("", False),
            ("anything-else", True),
        ],
    )
    def test_coerce_bool(self, value, expected):
        assert _coerce_bool(value) is expected


class TestCaching:
    def test_load_caches_result(self, tmp_path):
        path = _write_yaml(tmp_path, """
            embedder:
              model: cached-model
        """)
        cfg1 = load_kb_config(path=path)
        cfg2 = load_kb_config()  # No path — should hit cache, not re-read
        assert cfg1 is cfg2

    def test_refresh_bypasses_cache(self, tmp_path):
        path = _write_yaml(tmp_path, """
            embedder:
              model: original
        """)
        load_kb_config(path=path)
        path.write_text("embedder:\n  model: updated\n")
        cfg = load_kb_config(path=path, refresh=True)
        assert cfg.embedder.model == "updated"

    def test_reset_cache(self, tmp_path):
        load_kb_config(path=tmp_path / "missing.yaml")
        assert kb_config._cached_config is not None
        reset_cache()
        assert kb_config._cached_config is None


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 20, "c": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 20, "c": 3}

    def test_nested_merge(self):
        base = {"section": {"a": 1, "b": 2}, "other": "x"}
        override = {"section": {"b": 20, "c": 3}}
        result = _deep_merge(base, override)
        assert result == {"section": {"a": 1, "b": 20, "c": 3}, "other": "x"}

    def test_override_wins_on_type_mismatch(self):
        base = {"key": {"nested": 1}}
        override = {"key": "now a string"}
        result = _deep_merge(base, override)
        assert result == {"key": "now a string"}


class TestProfileLoading:
    def test_default_profiles_loaded(self, tmp_path):
        cfg = load_kb_config(path=tmp_path / "missing.yaml")
        assert "lite" in cfg.ingestion.profiles
        assert "standard" in cfg.ingestion.profiles
        assert "full" in cfg.ingestion.profiles
        # Profile composition:
        #   - lite:     committed caches only (no NVD, no nuclei)
        #   - standard: lite + NVD (730-day window by Makefile override)
        #   - full:     standard + nuclei
        assert "nvd" not in cfg.ingestion.profiles["lite"]
        assert "nvd" in cfg.ingestion.profiles["standard"]
        assert "nvd" in cfg.ingestion.profiles["full"]
        assert "nuclei" not in cfg.ingestion.profiles["lite"]
        assert "nuclei" not in cfg.ingestion.profiles["standard"]
        assert "nuclei" in cfg.ingestion.profiles["full"]
        assert "exploitdb" in cfg.ingestion.profiles["lite"]
        assert "exploitdb" in cfg.ingestion.profiles["standard"]
        assert "exploitdb" in cfg.ingestion.profiles["full"]
        # The committed-cache sources are in every profile
        for p in ("lite", "standard", "full"):
            for src in ("tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb"):
                assert src in cfg.ingestion.profiles[p], f"{src} missing from {p}"

    def test_yaml_can_override_profiles(self, tmp_path):
        path = _write_yaml(tmp_path, """
            ingestion:
              profiles:
                custom: [tool_docs, gtfobins]
        """)
        cfg = load_kb_config(path=path)
        assert "custom" in cfg.ingestion.profiles
        assert cfg.ingestion.profiles["custom"] == ["tool_docs", "gtfobins"]

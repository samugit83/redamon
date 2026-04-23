import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# Code defaults — the absolute fallback if YAML is missing or corrupt
# =============================================================================
DEFAULTS: dict[str, Any] = {
    "runtime": {
        "mode": "local",
    },
    "embedder": {
        "model": "intfloat/e5-large-v2",
        "batch_size": 64,
    },
    "chunking": {
        # Hard upper bound per chunk before the splitter kicks in. Should be
        # set to (embedder max_seq_length - margin). For e5-large-v2 (cap=512)
        # we use 480, leaving 32 tokens of slop for the chars/4 estimator's
        # imprecision. Bump this when swapping to a longer-context embedder
        # (nomic-embed, OpenAI text-embedding-3, etc.).
        "max_tokens": 480,
        # Soft target for the paragraph-splitting fallback. Splits at the
        # first paragraph boundary that pushes past this number, capped at
        # max_tokens. Smaller = more, finer chunks; larger = fewer, denser.
        "preferred_tokens": 256,
    },
    "reranker": {
        "enabled": True,
        "model": "BAAI/bge-reranker-base",
        "pool_size": 30,
        # Token budget per side (query, doc) fed to the cross-encoder.
        # Defaults to the same value as chunking.max_tokens so one
        # ingested chunk can fit under the reranker without truncation.
        # Capped at runtime by the tokenizer's model_max_length.
        "max_tokens_per_side": 480,
    },
    "fulltext": {
        "enabled": True,
    },
    "retrieval": {
        "top_k": 5,
        "overfetch_factor": 6,
        "score_threshold": 0.35,
        "rrf_k": 60,
    },
    "mmr": {
        "enabled": True,
        "lambda": 0.5,
    },
    "source_boosts": {
        "tool_docs":  1.20,
        "gtfobins":   1.15,
        "lolbas":     1.15,
        "owasp":      1.05,
        "nuclei":     1.00,
        "nvd":        0.90,
        "exploitdb":  0.85,
    },
    "ingestion": {
        "default_profile": "lite",
        "nvd_lookback_days": 90,
        "nvd_min_cvss": 7.0,
        "profiles": {
            # lite = committed source caches only. No NVD — avoids the
            # multi-minute NVD API fetch on every bootstrap. Use standard
            # or full when CVE coverage is needed.
            "lite":     ["tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb"],
            "standard": ["tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb", "nvd"],
            "full":     ["tool_docs", "gtfobins", "lolbas", "owasp", "exploitdb", "nvd", "nuclei"],
        },
    },
}


# =============================================================================
# Typed config dataclasses
# =============================================================================

@dataclass
class RuntimeConfig:
    mode: str = "local"


@dataclass
class EmbedderConfig:
    model: str = "intfloat/e5-large-v2"
    batch_size: int = 64


@dataclass
class ChunkingConfig:
    """
    Token-budget settings for the markdown / text chunker.

    These values must be kept in sync with the embedder's max sequence
    length — see kb_config.yaml for the embedder ↔ chunker contract.
    """
    max_tokens: int = 480
    preferred_tokens: int = 256


@dataclass
class RerankerConfig:
    enabled: bool = True
    model: str = "BAAI/bge-reranker-base"
    pool_size: int = 30
    # Token budget per side fed to the cross-encoder. The old code
    # hard-coded a 512-CHAR pre-truncation (not token!) which threw
    # away ~75% of each chunk before the cross-encoder ever saw it.
    # 480 matches chunking.max_tokens so a full chunk survives.
    max_tokens_per_side: int = 480


@dataclass
class FulltextConfig:
    enabled: bool = True


@dataclass
class RetrievalConfig:
    top_k: int = 5
    overfetch_factor: int = 6
    score_threshold: float = 0.35
    rrf_k: int = 60


@dataclass
class MMRConfig:
    enabled: bool = True
    lambda_: float = 0.5  # `lambda` is reserved in Python; suffix with _


@dataclass
class IngestionConfig:
    default_profile: str = "lite"
    nvd_lookback_days: int = 90
    nvd_min_cvss: float = 7.0
    profiles: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class KBConfig:
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    embedder: EmbedderConfig = field(default_factory=EmbedderConfig)
    chunking: ChunkingConfig = field(default_factory=ChunkingConfig)
    reranker: RerankerConfig = field(default_factory=RerankerConfig)
    fulltext: FulltextConfig = field(default_factory=FulltextConfig)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    mmr: MMRConfig = field(default_factory=MMRConfig)
    source_boosts: dict[str, float] = field(default_factory=dict)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    # Origin path for debugging — set to the file the values came from, or
    # None if defaults were used.
    source_path: Optional[Path] = None


# =============================================================================
# Loader
# =============================================================================

# Top-level keys allowed in the YAML — anything else is rejected so typos
# fail loudly instead of silently being ignored.

_ALLOWED_TOP_LEVEL_KEYS = {
    "KB_ENABLED",
    "runtime", "embedder", "chunking", "reranker", "fulltext", "retrieval",
    "mmr", "source_boosts", "ingestion",
}


def _default_config_path() -> Path:
    """Path to the canonical kb_config.yaml shipped with the package."""
    return Path(__file__).parent / "kb_config.yaml"


def _coerce_bool(value: Any) -> bool:
    """Tolerant bool coercion for env vars (str → bool)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no", "off", "")
    return bool(value)


def _clamp_int(
    value: Any,
    *,
    lo: int,
    hi: int,
    field: str,
    default: int,
) -> int:
    """
    Coerce ``value`` to int and clamp to ``[lo, hi]``.

    The single chokepoint for numeric-config validation. Handles three
    failure modes, all with WARNING-level logging and a safe fallback:

    1. Not coercible to int (wrong type, nested dict, non-numeric string)
       → return ``default``
    2. Below ``lo`` → return ``lo``
    3. Above ``hi`` → return ``hi``

    Use this for any config field whose range is bounded by external
    constraints (embedder max sequence length, Neo4j property limits, etc.).
    Inline clamping is discouraged — reusing this helper keeps the warning
    message format consistent and makes all numeric-config validation
    auditable via a single grep.

    Args:
        value: The raw value from the merged config dict. May be anything.
        lo: Minimum acceptable value (inclusive).
        hi: Maximum acceptable value (inclusive).
        field: Human-readable field name for the log message (e.g.
            ``"chunking.max_tokens"``).
        default: Value to return if ``value`` is not coercible to int.

    Returns:
        An int in ``[lo, hi]``.
    """
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        logger.warning(
            f"{field}: expected int, got {type(value).__name__}={value!r}; "
            f"falling back to default {default}"
        )
        return default
    if coerced < lo:
        logger.warning(
            f"{field}: value {coerced} below minimum {lo}; clamping to {lo}"
        )
        return lo
    if coerced > hi:
        logger.warning(
            f"{field}: value {coerced} above maximum {hi}; clamping to {hi}"
        )
        return hi
    return coerced


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins on leaves."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _validate_top_level(yaml_data: dict, source: str) -> None:
    """Reject unknown top-level keys to catch typos in the YAML."""
    if not isinstance(yaml_data, dict):
        raise ValueError(
            f"KB config root must be a mapping, got {type(yaml_data).__name__} "
            f"({source})"
        )
    unknown = set(yaml_data) - _ALLOWED_TOP_LEVEL_KEYS
    if unknown:
        raise ValueError(
            f"Unknown top-level key(s) in {source}: {sorted(unknown)}. "
            f"Allowed: {sorted(_ALLOWED_TOP_LEVEL_KEYS)}"
        )


def _apply_env_overrides(merged: dict) -> dict:
    """
    Apply environment variable overrides for documented keys.

    Env vars are documented at the top of this file. Anything else is ignored.
    """
    env = os.environ

    def setdefault(section: str) -> dict:
        merged.setdefault(section, {})
        return merged[section]

    if "KB_EMBEDDING_MODEL" in env:
        setdefault("embedder")["model"] = env["KB_EMBEDDING_MODEL"]
    if "KB_RERANK_ENABLED" in env:
        setdefault("reranker")["enabled"] = _coerce_bool(env["KB_RERANK_ENABLED"])
    if "KB_RERANKER_MODEL" in env:
        setdefault("reranker")["model"] = env["KB_RERANKER_MODEL"]
    if "KB_RERANKER_MAX_TOKENS_PER_SIDE" in env:
        try:
            setdefault("reranker")["max_tokens_per_side"] = int(
                env["KB_RERANKER_MAX_TOKENS_PER_SIDE"]
            )
        except ValueError:
            logger.warning(
                f"Invalid KB_RERANKER_MAX_TOKENS_PER_SIDE env var: "
                f"{env['KB_RERANKER_MAX_TOKENS_PER_SIDE']!r}"
            )
    if "KB_FULLTEXT_ENABLED" in env:
        setdefault("fulltext")["enabled"] = _coerce_bool(env["KB_FULLTEXT_ENABLED"])
    if "NVD_LOOKBACK_DAYS" in env:
        try:
            setdefault("ingestion")["nvd_lookback_days"] = int(env["NVD_LOOKBACK_DAYS"])
        except ValueError:
            logger.warning(
                f"Invalid NVD_LOOKBACK_DAYS env var: {env['NVD_LOOKBACK_DAYS']!r}"
            )
    if "NVD_MIN_CVSS" in env:
        try:
            setdefault("ingestion")["nvd_min_cvss"] = float(env["NVD_MIN_CVSS"])
        except ValueError:
            logger.warning(
                f"Invalid NVD_MIN_CVSS env var: {env['NVD_MIN_CVSS']!r}"
            )

    return merged


def _build_typed(merged: dict, source_path: Optional[Path]) -> KBConfig:
    """Convert a merged dict into the typed KBConfig dataclass."""
    rt = merged.get("runtime", {})
    em = merged.get("embedder", {})
    ch = merged.get("chunking", {})
    rr = merged.get("reranker", {})
    ft = merged.get("fulltext", {})
    rv = merged.get("retrieval", {})
    mm = merged.get("mmr", {})
    boosts = merged.get("source_boosts", {})
    ing = merged.get("ingestion", {})

    # Chunking: clamp both values to a safe range and enforce the
    # preferred < max invariant. The bounds encode what the chunker can
    # actually drive:
    #   - max_tokens floor: 64 — below this, chunks are too small to
    #     carry meaningful semantic content; retrieval degenerates.
    #   - max_tokens ceiling: 8192 — covers the longest-context embedders
    #     on the market today (nomic-embed, Snowflake arctic, text-
    #     embedding-3). Anything larger is a typo or attack.
    #   - preferred_tokens floor: 32, ceiling: 4096 — half the max
    #     bounds, so the soft target always has headroom under the cap.
    chunking_max = _clamp_int(
        ch.get("max_tokens", DEFAULTS["chunking"]["max_tokens"]),
        lo=64, hi=8192,
        field="chunking.max_tokens",
        default=DEFAULTS["chunking"]["max_tokens"],
    )
    chunking_preferred = _clamp_int(
        ch.get("preferred_tokens", DEFAULTS["chunking"]["preferred_tokens"]),
        lo=32, hi=4096,
        field="chunking.preferred_tokens",
        default=DEFAULTS["chunking"]["preferred_tokens"],
    )
    # Cross-field sanity: preferred must be strictly below max. If a
    # user writes { max: 300, preferred: 500 } (typo), fall back to
    # max // 2 rather than letting the chunker misbehave at runtime.
    if chunking_preferred >= chunking_max:
        fallback = max(32, chunking_max // 2)
        logger.warning(
            f"chunking.preferred_tokens ({chunking_preferred}) >= "
            f"chunking.max_tokens ({chunking_max}); "
            f"setting preferred_tokens to {fallback}"
        )
        chunking_preferred = fallback

    return KBConfig(
        runtime=RuntimeConfig(mode=str(rt.get("mode", "local"))),
        embedder=EmbedderConfig(
            model=str(em.get("model", DEFAULTS["embedder"]["model"])),
            batch_size=int(em.get("batch_size", DEFAULTS["embedder"]["batch_size"])),
        ),
        chunking=ChunkingConfig(
            max_tokens=chunking_max,
            preferred_tokens=chunking_preferred,
        ),
        reranker=RerankerConfig(
            enabled=bool(rr.get("enabled", DEFAULTS["reranker"]["enabled"])),
            model=str(rr.get("model", DEFAULTS["reranker"]["model"])),
            pool_size=int(rr.get("pool_size", DEFAULTS["reranker"]["pool_size"])),
            max_tokens_per_side=int(rr.get(
                "max_tokens_per_side",
                DEFAULTS["reranker"]["max_tokens_per_side"],
            )),
        ),
        fulltext=FulltextConfig(
            enabled=bool(ft.get("enabled", DEFAULTS["fulltext"]["enabled"])),
        ),
        retrieval=RetrievalConfig(
            top_k=int(rv.get("top_k", DEFAULTS["retrieval"]["top_k"])),
            overfetch_factor=int(rv.get("overfetch_factor", DEFAULTS["retrieval"]["overfetch_factor"])),
            score_threshold=float(rv.get("score_threshold", DEFAULTS["retrieval"]["score_threshold"])),
            rrf_k=int(rv.get("rrf_k", DEFAULTS["retrieval"]["rrf_k"])),
        ),
        mmr=MMRConfig(
            enabled=bool(mm.get("enabled", DEFAULTS["mmr"]["enabled"])),
            lambda_=float(mm.get("lambda", DEFAULTS["mmr"]["lambda"])),
        ),
        source_boosts={k: float(v) for k, v in boosts.items()} or dict(DEFAULTS["source_boosts"]),
        ingestion=IngestionConfig(
            default_profile=str(ing.get("default_profile", DEFAULTS["ingestion"]["default_profile"])),
            nvd_lookback_days=int(ing.get("nvd_lookback_days", DEFAULTS["ingestion"]["nvd_lookback_days"])),
            nvd_min_cvss=float(ing.get("nvd_min_cvss", DEFAULTS["ingestion"]["nvd_min_cvss"])),
            profiles={k: list(v) for k, v in ing.get("profiles", DEFAULTS["ingestion"]["profiles"]).items()},
        ),
        source_path=source_path,
    )


# Module-level cache so multiple importers share the same loaded config.
_cached_config: Optional[KBConfig] = None


def load_kb_config(path: Optional[Path] = None, refresh: bool = False) -> KBConfig:
    """Load and validate KB configuration.

    Args:
        path: Optional explicit YAML path. If None, uses KB_CONFIG_FILE env var,
              then falls back to the canonical path next to this module.
        refresh: If True, re-read from disk even if a cached version exists.

    Returns:
        Typed KBConfig with all sections populated.
    """
    global _cached_config
    if _cached_config is not None and not refresh:
        return _cached_config

    # Resolve path: explicit arg > env var > default location
    if path is None:
        env_path = os.environ.get("KB_CONFIG_FILE")
        path = Path(env_path) if env_path else _default_config_path()

    yaml_data: dict = {}
    source_path: Optional[Path] = None

    if path.exists():
        try:
            import yaml
            with open(path) as f:
                loaded = yaml.safe_load(f) or {}
            _validate_top_level(loaded, str(path))
            yaml_data = loaded
            source_path = path
            logger.info(f"KB config loaded from {path}")
        except Exception as e:
            logger.warning(
                f"Failed to load KB config from {path}: {e}. "
                f"Falling back to code defaults."
            )
    else:
        logger.info(
            f"KB config file not found at {path}, using code defaults. "
            f"Set KB_CONFIG_FILE to override."
        )

    # Merge: defaults < yaml < env vars
    merged = _deep_merge(DEFAULTS, yaml_data)
    merged = _apply_env_overrides(merged)

    _cached_config = _build_typed(merged, source_path)
    return _cached_config


def reset_cache() -> None:
    """Clear the module-level cache. Used by tests."""
    global _cached_config
    _cached_config = None

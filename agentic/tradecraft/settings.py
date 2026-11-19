"""Tradecraft settings on the agent side: the spec, the second clamp, typed access.

``settings_spec.json`` is a byte-for-byte copy of ``webapp/src/lib/tradecraft/settingsSpec.json``
(``webapp/scripts/gen-tradecraft-spec.mjs --check`` keeps it so). The webapp merges the
user's values and the resource's overrides and sends the result with each job; the agent
clamps it again here, because a ceiling is a security limit (§5) and the webapp is not the
only writer of the JSON columns. Nothing here reads the environment: every limit is a spec
value or a spec constant (§2).
"""

from __future__ import annotations

import functools
import json
import math
from pathlib import Path
from typing import Any, Mapping

_SPEC_PATH = Path(__file__).with_name("settings_spec.json")

_MISSING = object()


@functools.lru_cache(maxsize=1)
def load_spec() -> dict[str, Any]:
    with _SPEC_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


@functools.lru_cache(maxsize=1)
def _by_key() -> dict[str, dict[str, Any]]:
    return {s["key"]: s for s in load_spec()["settings"]}


def setting(key: str) -> dict[str, Any]:
    """The spec entry of ``key``; KeyError for a key the spec does not have."""
    return _by_key()[key]


def keys(scope: str | None = None) -> list[str]:
    return [s["key"] for s in load_spec()["settings"] if scope is None or s["scope"] == scope]


def constants() -> dict[str, Any]:
    return load_spec()["constants"]


def constant(name: str) -> Any:
    return constants()[name]


def default(key: str) -> Any:
    value = setting(key)["default"]
    return list(value) if isinstance(value, list) else value


def site_type_key(type_name: str) -> str | None:
    """``mkdocs-wiki`` -> ``wiki``: the short name the spec's per-type keys use."""
    return load_spec()["siteTypes"].get(type_name)


def _clamp_one(spec: Mapping[str, Any], value: Any) -> Any:
    """``value`` brought inside the spec's limits, or ``_MISSING`` when it is not that type."""
    kind = spec["type"]
    if kind in ("int", "number"):
        # bool is an int in Python; a true/false is never a number here.
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return _MISSING
        number = int(round(value)) if kind == "int" else value
        return min(spec["ceiling"], max(spec["min"], number))
    if kind == "bool":
        return value if isinstance(value, bool) else _MISSING
    if kind == "enum":
        return value if isinstance(value, str) and value in spec["values"] else _MISSING
    if kind == "string":
        return value[: spec["maxLength"]] if isinstance(value, str) else _MISSING
    if kind == "list":
        if not isinstance(value, (list, tuple)):
            return _MISSING
        allowed = spec.get("values")
        out: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item:
                continue
            item = item[: spec["maxLength"]]
            if allowed is not None and item not in allowed:
                continue
            if item not in out:
                out.append(item)
            if len(out) >= spec["maxItems"]:
                break
        return out
    return _MISSING


def clamp(values: Mapping[str, Any]) -> dict[str, Any]:
    """Every numeric between its minimum and its ceiling, enums to their values, strings and
    lists to their limits; unknown keys and values of the wrong type are dropped."""
    by_key = _by_key()
    out: dict[str, Any] = {}
    for key, value in values.items():
        spec = by_key.get(key)
        if spec is None:
            continue
        clamped = _clamp_one(spec, value)
        if clamped is not _MISSING:
            out[key] = clamped
    return out


class EffectiveSettings:
    """The settings one job or one run works with: the spec's defaults for ``scope``, under
    the clamped values received. Accessors raise KeyError for a key the spec lacks, so a
    typo fails in the tests rather than reading a silent default."""

    def __init__(self, values: Mapping[str, Any] | None = None, scope: str = "ingestion"):
        self.scope = scope
        merged = {key: default(key) for key in keys(scope)}
        merged.update({k: v for k, v in clamp(values or {}).items() if setting(k)["scope"] == scope})
        self._values = merged

    @property
    def values(self) -> dict[str, Any]:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in self._values.items()}

    def get(self, key: str) -> Any:
        setting(key)
        if key not in self._values:
            raise KeyError(f"{key} is a {setting(key)['scope']} setting, not {self.scope}")
        value = self._values[key]
        return list(value) if isinstance(value, list) else value

    def int(self, key: str) -> int:
        self._expect(key, "int")
        return int(self.get(key))

    def number(self, key: str) -> float:
        self._expect(key, "int", "number")
        return float(self.get(key))

    def bool(self, key: str) -> bool:
        self._expect(key, "bool")
        return bool(self.get(key))

    def str(self, key: str) -> str:
        self._expect(key, "string", "enum")
        return str(self.get(key))

    def list(self, key: str) -> list[str]:
        self._expect(key, "list")
        return self.get(key)

    @staticmethod
    def _expect(key: str, *types: str) -> None:
        actual = setting(key)["type"]
        if actual not in types:
            raise TypeError(f"{key} is a {actual} setting")

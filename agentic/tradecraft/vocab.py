"""The Tradecraft vocabulary on the agent side.

``vocab.json`` is a byte-for-byte copy of ``webapp/src/lib/tradecraft/vocab.json``
(``webapp/scripts/gen-tradecraft-spec.mjs --check``): topics, content kinds, recipes, the
keywords that tag a page by rules, technology names, built-in synonyms and the kind each
phase prefers. A code constant, never a table (master plan TD-14).
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

_VOCAB_PATH = Path(__file__).with_name("vocab.json")


@dataclass(frozen=True)
class Vocab:
    topics: tuple[Mapping[str, Any], ...]
    kinds: tuple[Mapping[str, Any], ...]
    kind_aliases: Mapping[str, str]
    recipes: tuple[Mapping[str, Any], ...]
    keywords: Mapping[str, tuple[str, ...]]
    kind_keywords: Mapping[str, tuple[str, ...]]
    technologies: tuple[Mapping[str, Any], ...]
    synonyms: tuple[Mapping[str, Any], ...]
    kind_preference_by_phase: Mapping[str, tuple[str, ...]]

    @property
    def topic_ids(self) -> tuple[str, ...]:
        return tuple(t["id"] for t in self.topics)

    @property
    def skill_topic_ids(self) -> tuple[str, ...]:
        return tuple(t["id"] for t in self.topics if t["source"] == "skill")

    @property
    def kind_ids(self) -> tuple[str, ...]:
        return tuple(k["id"] for k in self.kinds)

    def resolve_kind(self, name: str) -> str | None:
        key = name.strip().lower()
        return key if key in self.kind_ids else self.kind_aliases.get(key)


def _frozen(items: list[dict[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    return tuple(MappingProxyType(dict(i)) for i in items)


def _tuples(mapping: dict[str, list[str]]) -> Mapping[str, tuple[str, ...]]:
    return MappingProxyType({k: tuple(v) for k, v in mapping.items()})


@functools.lru_cache(maxsize=1)
def load_vocab() -> Vocab:
    with _VOCAB_PATH.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    return Vocab(
        topics=_frozen(raw["topics"]),
        kinds=_frozen(raw["kinds"]),
        kind_aliases=MappingProxyType(dict(raw["kindAliases"])),
        recipes=_frozen(raw["recipes"]),
        keywords=_tuples(raw["keywords"]),
        kind_keywords=_tuples(raw["kindKeywords"]),
        technologies=_frozen(raw["technologies"]),
        synonyms=_frozen(raw["synonyms"]),
        kind_preference_by_phase=_tuples(raw["kindPreferenceByPhase"]),
    )

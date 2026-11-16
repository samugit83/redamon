"""Synonyms and acronyms for search (Q4 "The search index", TD-14): the list shipped with
RedAmon (``vocab.json``) plus the user's own pairs (Q11 "My synonyms", user only, at most
``constants.maxUserSynonyms``).

Expansion happens in Python before any query (TD-14): ``expand`` names the phrases a query's
words stand for, and search adds them as its second wording. Every entry works both ways:
"sqli" adds "sql injection", and "SQL injection" adds "sqli", so the three spellings of AC-62
reach the same pages; a user's "PATT = PayloadsAllTheThings" expands either name into the
other. Matching is by whole words, case-insensitive, one level deep.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Any, Iterable

from tradecraft.ingest.tags import normalize
from tradecraft.settings import constant
from tradecraft.vocab import load_vocab

MAX_USER_SYNONYMS = int(constant("maxUserSynonyms"))
MAX_TERM_CHARS = 100
MAX_EXPANSIONS = 5


@dataclass(frozen=True)
class Synonym:
    term: str
    expansions: tuple[str, ...]


@functools.lru_cache(maxsize=1)
def builtin() -> tuple[Synonym, ...]:
    return tuple(Synonym(normalize(s["term"]), tuple(normalize(e) for e in s["expansions"]))
                 for s in load_vocab().synonyms)


def _clip(text: Any) -> str:
    return normalize(text)[:MAX_TERM_CHARS] if isinstance(text, str) else ""


def parse_user(raw: Any) -> list[Synonym]:
    """The user's pairs from the run's search settings: a list of ``{term, expansions}`` or of
    ``"A = B"`` strings; anything else is skipped. At most ``maxUserSynonyms`` entries."""
    out: list[Synonym] = []
    for item in raw if isinstance(raw, (list, tuple)) else ():
        if len(out) >= MAX_USER_SYNONYMS:
            break
        if isinstance(item, str) and "=" in item:
            a, b = (_clip(p) for p in item.split("=", 1))
            if a and b and a != b:
                out += [Synonym(a, (b,)), Synonym(b, (a,))]
        elif isinstance(item, dict):
            term = _clip(item.get("term"))
            expansions = tuple(e for e in (_clip(x) for x in item.get("expansions") or ()) if e and e != term)
            if term and expansions:
                out.append(Synonym(term, expansions[:MAX_EXPANSIONS]))
    return out[:MAX_USER_SYNONYMS]


def contains(norm_query: str, phrase: str) -> bool:
    return bool(phrase) and re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", norm_query) is not None


def pairs(user_synonyms: Iterable[Synonym] = ()) -> list[tuple[str, tuple[str, ...]]]:
    """(phrase, what it also means): every entry forwards, then every expansion back to its term."""
    entries = (*builtin(), *user_synonyms)
    out = [(s.term, s.expansions) for s in entries if s.term]
    out += [(e, (s.term,)) for s in entries if s.term for e in s.expansions if e]
    return out


def expand(query: str, user_synonyms: Iterable[Synonym] = ()) -> list[str]:
    """The phrases the query's words stand for, in order, without the ones it already says."""
    norm = normalize(query)
    out: list[str] = []
    for phrase, alternatives in pairs(user_synonyms):
        if contains(norm, phrase):
            out += [a for a in alternatives if a and a not in out and not contains(norm, a)]
    return out

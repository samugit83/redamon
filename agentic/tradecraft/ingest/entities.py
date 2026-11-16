"""Stage ``entities`` (T2.2): CVE ids and technology, product and tool names on each card.

CVE ids are found by pattern and written upper case; names only from the technology list
shipped with RedAmon (``vocab.json``), as its lower-case ids. Never from a project's recon
results (Q4 item 4, R-333): a page is ingested for its owner's library, not for one target,
and what a target reports must not decide what the library says it holds. Search matches a
query's entities against these exactly (the free first pass's fifth wording).
"""

from __future__ import annotations

import functools
import re
from typing import TYPE_CHECKING, Iterable

from tradecraft.ingest.tags import PhraseMatcher, heading_texts, technology_words

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

# CVE-YYYY-NNNN with 4 to 7 digits (the CVE program's format; ids began in 1999).
CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-((?:19|20)\d{2})-(\d{4,7})(?![A-Za-z0-9])", re.IGNORECASE)
# A page that lists hundreds of CVEs (a changelog, an index) is not about each of them.
MAX_PER_CARD = 50


def cve_ids(text: str) -> list[str]:
    out: list[str] = []
    for m in CVE_RE.finditer(text or ""):
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        if cve not in out:
            out.append(cve)
    return out


@functools.lru_cache(maxsize=1)
def _names() -> PhraseMatcher:
    return PhraseMatcher(technology_words())


def find(texts: Iterable[str]) -> list[str]:
    """The CVE ids, then the vocabulary's technology ids, named in ``texts``; at most
    ``MAX_PER_CARD``."""
    texts = [str(t) for t in texts if t]
    out: list[str] = []
    for text in texts:
        out += [c for c in cve_ids(text) if c not in out]
    joined = " | ".join(texts)
    out += [n for n in _names().find(joined) if n not in out]
    return out[:MAX_PER_CARD]


async def extract(state: "IngestState") -> "IngestState":
    """Every card with the entities of its title, breadcrumb, headings, description and URL,
    added to any it already has."""
    for card in state.cards:
        texts = [card.get("title", ""), *(card.get("breadcrumb") or ()), *heading_texts(card.get("headings")),
                 card.get("description", ""), card.get("url", "")]
        existing = [e for e in card.get("entities") or () if isinstance(e, str) and e]
        card["entities"] = (existing + [e for e in find(texts) if e not in existing])[:MAX_PER_CARD]
    return state

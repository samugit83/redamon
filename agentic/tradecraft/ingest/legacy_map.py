"""Stage ``legacy_map``: the 1.x columns of the resource, written by every 2.0 ingestion (TD-18).

A person who turns the switch off, or an install rolled back to 7.8.0, reads ``sitemap``,
``resource_type``, ``crawl_stats`` and ``crawl_stopped_because`` exactly as 1.x wrote them:

- a wiki, a GitBook, a docs site or a website: ``{"nav": [{title, path}]}`` (a docs site adds
  ``indexUrl``);
- a GitHub repository: ``{"tree": [{title, path}], owner, repo, branch}``;
- a CVE archive: ``{owner, repo, branch}``;
- a PDF: ``{"pages": [{page, firstLine}]}`` with the type ``agentic-crawl``, as 1.x stored it.

``legacyMapHash`` is the hash of that map: a 1.x refresh made while the switch is off changes
the map, and the next switch-on sees it changed and converts the resource again.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState


def map_hash(sitemap: Any) -> str:
    """The first 16 hex characters of the SHA-256 of the map's canonical JSON."""
    canonical = json.dumps(sitemap, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def legacy_shape(site_type: str, entries: list, meta: dict) -> tuple[dict, str]:
    """(the 1.x ``sitemap``, the 1.x ``resource_type``) for the kept entries."""
    items = [{"title": e.title, "path": e.path or e.url} for e in entries]
    if site_type == "pdf":
        pages = [{"page": e.extra.get("page"), "firstLine": e.extra.get("first_line", "")} for e in entries]
        return {"pages": pages}, "agentic-crawl"
    if site_type == "github-repo":
        out = {"tree": items}
        out.update({k: meta[k] for k in ("owner", "repo", "branch") if k in meta})
        return out, site_type
    if site_type == "cve-poc-db":
        return {k: meta[k] for k in ("owner", "repo", "branch") if k in meta}, site_type
    out: dict = {"nav": items}
    if site_type == "sphinx-docs":
        out["indexUrl"] = meta.get("indexUrl", "")
    return out, site_type


async def build(state: "IngestState") -> "IngestState":
    kept = [e for e in state.entries if e.extra.get("status", "kept") == "kept"]
    state.legacy_sitemap, state.legacy_type = legacy_shape(state.site_type, kept, state.meta)
    state.legacy_hash = map_hash(state.legacy_sitemap)
    return state

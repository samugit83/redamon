"""
RedAmon - urlscan helpers for resource enumeration
==================================================
urlscan's addresses join `by_base_url` like the archive sources (GAU,
ParamSpider) do, so they get the labels every other module writes
(Endpoint.category, Parameter.category and type) and reach OpenAPI's seeds,
Route Exposure and the classifiers.

Only on bases that are live in this scan: copied as is, the merge would add
every scheme://host:port urlscan ever saw, and the graph writer would create
that BaseURL and nuclei would target it. No sample value or URL is copied: a
parameter's type was computed in the urlscan module before its value was
masked. A quarantined address never reaches this list.
"""
from typing import Dict, Iterable, List, Set, Tuple
from urllib.parse import urlparse

from .classification import classify_parameter, endpoint_category
from .gau_helpers import parse_gau_url_to_endpoint


def live_bases(recon_data: dict) -> Set[str]:
    """scheme://netloc of every http_probe.by_url entry that answered (its
    status_code is set), as http_mixin's is_live rule: a key can carry a path
    when extra probe paths are set."""
    out = set()
    for url, entry in ((recon_data or {}).get("http_probe") or {}).get("by_url", {}).items():
        if not isinstance(entry, dict) or entry.get("status_code") is None:
            continue
        parsed = urlparse(str(entry.get("url") or url))
        if parsed.scheme and parsed.netloc:
            out.add(f"{parsed.scheme}://{parsed.netloc}")
    return out


def merge_urlscan_into_by_base_url(rows: Iterable[dict], by_base_url: Dict, bases: Set[str],
                                   scope_hosts: Iterable[str] = ()) -> Tuple[Dict, Dict]:
    """Merge urlscan.urls_with_paths rows (masked, with param_types) into by_base_url."""
    stats = {"urlscan_total": 0, "urlscan_new": 0, "urlscan_overlap": 0,
             "urlscan_not_live": 0, "urlscan_out_of_scope": 0}
    hosts = {h.lower() for h in scope_hosts or ()}
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        stats["urlscan_total"] += 1
        parsed = parse_gau_url_to_endpoint(row.get("full_url") or "")
        if not parsed:
            continue
        base, path = parsed["base_url"], parsed["path"]
        host = (urlparse(base).hostname or "").lower()
        if hosts and host not in hosts:
            stats["urlscan_out_of_scope"] += 1
            continue
        if base not in bases:
            stats["urlscan_not_live"] += 1
            continue
        types = row.get("param_types") or {}
        names = parsed["parameters"].get("query", [])
        base_entry = by_base_url.setdefault(base, {
            "base_url": base, "endpoints": {},
            "summary": {"total_endpoints": 0, "total_parameters": 0, "methods": {}, "categories": {}},
        })
        endpoints = base_entry["endpoints"]
        if path in endpoints:
            ep = endpoints[path]
            sources = ep.get("sources") or ([ep["source"]] if ep.get("source") else [])
            if "urlscan" not in sources:
                sources.append("urlscan")
                stats["urlscan_overlap"] += 1
            ep["sources"] = sources
            query = ep.setdefault("parameters", {"query": [], "body": [], "path": []}).setdefault("query", [])
            known = {p.get("name") if isinstance(p, dict) else p: p for p in query}
            for name in names:
                if name not in known:
                    query.append({"name": name, "category": classify_parameter(name),
                                  "type": types.get(name, "string"), "source": "urlscan"})
                elif isinstance(known[name], dict) and known[name].get("type") in (None, "", "string") \
                        and types.get(name, "string") != "string":
                    known[name]["type"] = types[name]
            if ep.get("category") in (None, "", "other"):
                ep["category"] = endpoint_category(path, ep.get("methods") or ["GET"],
                                                   {"query": query}, row.get("title"))
            continue
        stats["urlscan_new"] += 1
        query = [{"name": n, "category": classify_parameter(n), "type": types.get(n, "string"),
                  "source": "urlscan"} for n in names]
        category = endpoint_category(path, ["GET"], {"query": query, "body": [], "path": []},
                                     row.get("title"))
        endpoints[path] = {
            "methods": ["GET"],
            "parameters": {"query": query, "body": [], "path": []},
            "sources": ["urlscan"],
            "category": category,
            "parameter_count": {"query": len(query), "body": 0, "path": 0, "total": len(query)},
        }
        base_entry["summary"]["total_endpoints"] += 1
        base_entry["summary"]["categories"][category] = base_entry["summary"]["categories"].get(category, 0) + 1
    return by_base_url, stats


def title_seed_urls(rows: Iterable[dict], by_url: Dict) -> List[str]:
    """Pages titled like an API description (Swagger UI, ReDoc), from urlscan's
    rows and httpx's live pages: OpenAPI seeds whatever their path."""
    from .classification import is_api_doc_title
    out = []
    for row in rows or ():
        if isinstance(row, dict) and is_api_doc_title(row.get("title")) and row.get("full_url"):
            out.append(str(row["full_url"]).split("?", 1)[0])
    for url, entry in (by_url or {}).items():
        if isinstance(entry, dict) and is_api_doc_title(entry.get("title")):
            out.append(str(entry.get("final_url") or entry.get("url") or url))
    return sorted(set(out))

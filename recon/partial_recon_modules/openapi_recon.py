"""Partial recon: OpenAPI import on its own, written through resource enumeration.

Mirrors Kiterunner's partial run (parameter_discovery.run_kiterunner): read the
BaseURLs from the graph, run the one source, merge its results into a fresh
``by_base_url`` and write them with ``update_graph_from_resource_enum``. The
same engine and the same merge as the full pipeline, so a document imported
here lands in the graph exactly as a full run would write it.
"""
import os
import uuid
from urllib.parse import urlparse


def _spec_like_graph_urls(roots, user_id, project_id, domain_groups):
    """Crawled endpoints whose path looks like API documentation (auto-discover seeds)."""
    from graph_db import Neo4jClient
    from recon.helpers.openapi.discovery import SPEC_LIKE_PATH
    from recon.partial_recon_modules.graph_builders import graph_url_scope, url_host

    urls = []
    with Neo4jClient() as client:
        if not client.verify_connection():
            return urls
        with client.driver.session() as session:
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups, apex_filter=False)
            rows = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL AND NOT coalesce(e.quarantined, false)
                RETURN DISTINCT b.url AS base, e.path AS path
                """,
                uid=user_id, pid=project_id,
            )
            for row in rows:
                base, path = row["base"], row["path"]
                if base and path and SPEC_LIKE_PATH.search(path) and keep(url_host(base)):
                    urls.append(base.rstrip("/") + path)
    return urls


def _redeclared(by_base_url):
    """``"<METHOD> <baseurl><path>"`` -> the spec URLs that declared it this run."""
    out = {}
    for base, bucket in by_base_url.items():
        for path, entry in (bucket.get("endpoints") or {}).items():
            for method, meta in (entry.get("openapi") or {}).items():
                out[f"{method} {base}{path}"] = list(meta.get("spec_urls") or [])
    return out


def _custom_endpoint_keys(payload):
    """(baseurl, concrete path, method) of every operation a custom document declared."""
    from recon.helpers.resource_enum.openapi_helpers import concrete_path

    keys = set()
    for op in payload.get("operations") or []:
        if not op.get("custom"):
            continue
        spec = op.get("operation") if isinstance(op.get("operation"), dict) else {}
        path_params = {p.get("name"): p for p in spec.get("parameters") or []
                       if isinstance(p, dict) and p.get("in") == "path"}
        keys.add((op["baseurl"], concrete_path(op["path"], path_params), str(op["method"]).upper()))
    return keys


def run_openapi_partial(config: dict):
    from graph_db.mixins.base_mixin import run_timestamp
    from recon.helpers.openapi.discovery import run_openapi_discovery
    from recon.helpers.openapi.fetch import public_url
    from recon.helpers.resource_enum import build_openapi_inventory, merge_openapi_into_by_base_url
    from recon.partial_recon_modules.helpers import (
        _is_valid_url, _should_include_root_domain, partial_settings, run_per_root,
        scope_roots, typed_host_ok,
    )
    from recon.partial_recon_modules.graph_builders import _build_http_probe_data_from_graph

    run_started_at = run_timestamp()
    roots = scope_roots(config)
    settings = dict(partial_settings(config))
    if settings.get("STEALTH_MODE", False):
        print("[-][OpenAPI] Partial recon skipped: stealth mode turns document fetching off")
        return None
    settings["OPENAPI_ENABLED"] = True
    user_id = os.environ.get("USER_ID") or config.get("user_id", "")
    project_id = os.environ.get("PROJECT_ID") or config.get("project_id", "")
    if not user_id or not project_id:
        raise ValueError("OpenAPI partial recon requires a user and project")

    # Custom URLs are documents the operator typed (D13): fetched as
    # specifications whatever Auto-discover says. In IP mode the scope check is
    # the engine's (target IPs and CIDRs); a domain run also keeps them under
    # its roots here.
    ip_mode = bool(settings.get("IP_MODE"))
    custom_urls = []
    for entry in (config.get("user_targets") or {}).get("urls", []) or []:
        entry = (entry or "").strip()
        if not entry:
            continue
        host = urlparse(entry).hostname or ""
        if _is_valid_url(entry) and (ip_mode or typed_host_ok(host, roots, config.get("domain_groups"))):
            custom_urls.append(entry)
        else:
            # The URL may carry a token in its query: log its location only.
            print(f"[!][OpenAPI] Skipping custom URL outside the project roots: {public_url(entry)}")
    if custom_urls:
        print(f"[+][OpenAPI] {len(custom_urls)} custom document URL(s)")

    include_graph = config.get("include_graph_targets", True)
    include_root = _should_include_root_domain(settings)

    def run_root(root):
        if include_graph:
            recon_data = _build_http_probe_data_from_graph(
                root, user_id, project_id, include_root_domain=include_root,
                domain_groups=config.get("domain_groups"))
        else:
            recon_data = {
                "domain": root, "domains": [root], "subdomains": [],
                "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False}, "subdomains": {}},
                "http_probe": {"by_url": {}},
                "metadata": {"include_root_domain": include_root},
            }
        seeds = list((recon_data.get("http_probe") or {}).get("by_url") or {})
        if include_graph and settings.get("OPENAPI_AUTO_DISCOVER"):
            seeds += _spec_like_graph_urls(root, user_id, project_id, config.get("domain_groups"))

        # As Kiterunner does: the hosts this run reached are in the writer's scope.
        hosts = set(recon_data.get("subdomains") or [])
        for url in seeds + custom_urls:
            host = urlparse(url).hostname
            if host:
                hosts.add(host)
        recon_data["subdomains"] = sorted(hosts)

        payload = run_openapi_discovery(recon_data, settings, seeds, documents=custom_urls)
        by_base_url, stats = merge_openapi_into_by_base_url(payload, {})
        result = dict(recon_data)
        result["resource_enum"] = {
            "by_base_url": by_base_url,
            "forms": [],
            "jsluice_secrets": [],
            "openapi": build_openapi_inventory(recon_data, payload, stats),
            "scan_metadata": {"openapi_enabled": True},
            "summary": {
                "total_endpoints": sum(len(b["endpoints"]) for b in by_base_url.values()),
                "total_base_urls": len(by_base_url),
            },
            "external_domains": [],
        }
        print(f"[+][OpenAPI] {stats['openapi_operations']} declaration(s) from "
              f"{len(payload['documents'])} document(s); {stats['openapi_new']} new endpoint(s)")

        if not settings.get("UPDATE_GRAPH_DB", True):
            return None
        from graph_db import Neo4jClient
        with Neo4jClient() as client:
            if not client.verify_connection():
                raise RuntimeError("Neo4j not reachable; OpenAPI declarations not written")
            graph_stats = client.update_graph_from_resource_enum(result, user_id, project_id)
            if graph_stats.get("errors"):
                raise RuntimeError("OpenAPI graph write incomplete")
            # D17: what a document read again no longer declares. Only documents
            # fetched and parsed this run count, so a failed fetch removes nothing.
            reread = [d["url"] for d in payload.get("documents") or [] if d.get("url")]
            if reread:
                pruned = client.prune_withdrawn_openapi_declarations(
                    user_id, project_id, reread, run_started_at, _redeclared(by_base_url))
                print(f"[+][OpenAPI] Withdrawn declarations: {pruned['deleted']} endpoint(s) deleted, "
                      f"{pruned['withdrawn']} updated")
            custom = _custom_endpoint_keys(payload)
            if custom:
                _link_user_input(client, roots, user_id, project_id, custom_urls, custom, graph_stats)
        return None

    return run_per_root(roots, run_root, "OpenAPI")


def _link_user_input(client, roots, user_id, project_id, custom_urls, keys, stats):
    """UserInput -[:PRODUCED]-> Endpoint for what the operator's documents declared (D13)."""
    from recon.helpers.openapi.fetch import public_url
    from recon.partial_recon_modules.helpers import root_orgs

    user_input_id = str(uuid.uuid4())
    client.create_user_input_node(
        domain=roots,
        # Locations only: a query string can carry a token.
        user_input_data={"id": user_input_id, "input_type": "urls",
                         "values": [public_url(u) for u in custom_urls], "tool_id": "OpenAPI"},
        user_id=user_id, project_id=project_id,
        root_orgs=root_orgs(roots),
    )
    rows = [{"baseurl": b, "path": p, "method": m} for b, p, m in sorted(keys)]
    with client.driver.session() as session:
        session.run(
            """
            MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
            UNWIND $rows AS row
            MATCH (e:Endpoint {path: row.path, method: row.method, baseurl: row.baseurl,
                               user_id: $uid, project_id: $pid})
            MERGE (ui)-[:PRODUCED]->(e)
            """,
            ui_id=user_input_id, rows=rows, uid=user_id, pid=project_id,
        ).consume()
    client.update_user_input_status(user_input_id, "completed", {
        "endpoints_created": stats.get("endpoints_created", 0),
        "parameters_created": stats.get("parameters_created", 0),
    })
    print(f"[+][OpenAPI] Linked {len(rows)} declared endpoint(s) to the custom documents via UserInput")

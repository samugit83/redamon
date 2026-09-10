"""Target-scoped OpenAPI declaration storage for the recon graph."""

from __future__ import annotations

import json
from collections import defaultdict
from ipaddress import ip_address
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from graph_db.mixins.recon.openapi_scope import (
    Scope,
    _normalize_host,
    _normalize_scope_host,
)


_HTTP_METHODS = frozenset({
    "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
})
_INVALID_PATH = re.compile(r"[\x00-\x20\x7f\\]")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sanitize_url(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = _normalize_scope_host(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    if port is not None and port != default_port:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))


def _summary_entries(values: Any, fields: tuple[str, ...]) -> list[dict]:
    if not isinstance(values, list):
        return []
    cleaned = []
    for item in values:
        if not isinstance(item, dict):
            continue
        entry = {field: item[field] for field in fields if field in item}
        if "url" in entry:
            entry["url"] = _sanitize_url(entry["url"])
        cleaned.append(entry)
    return cleaned


def _normalize_operation(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    baseurl = value.get("baseurl")
    path = value.get("path")
    method = value.get("method")
    source_url = value.get("source_url")
    operation = value.get("operation")
    if not all(isinstance(item, str) and item for item in (
        baseurl, path, method, source_url,
    )) or not isinstance(operation, dict):
        return None

    try:
        parsed = urlsplit(baseurl)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        host = _normalize_host(baseurl)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        not host
        or not path.startswith("/")
        or "?" in path
        or "#" in path
        or _INVALID_PATH.search(path)
    ):
        return None

    method = method.upper()
    if method not in _HTTP_METHODS:
        return None
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    host_for_url = f"[{host}]" if ":" in host else host
    normalized_baseurl = f"{parsed.scheme.lower()}://{host_for_url}"
    if port != (443 if parsed.scheme.lower() == "https" else 80):
        normalized_baseurl += f":{port}"

    source_url = _sanitize_url(source_url)
    if not source_url:
        return None
    declaration = {
        "source_url": source_url,
        "document_hash": value.get("document_hash"),
        "operation_ref": value.get("operation_ref"),
        "operation": operation,
    }
    source_id = value.get("source_id")
    if isinstance(source_id, str) and source_id:
        declaration["source_id"] = source_id
    try:
        _json(declaration)
    except (TypeError, ValueError):
        return None
    return {
        "baseurl": normalized_baseurl,
        "path": path,
        "method": method,
        "host": host,
        "scheme": parsed.scheme.lower(),
        "port": port,
        "declaration": declaration,
    }


def _load_declarations(value: Any) -> list[dict]:
    if not isinstance(value, str) or not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _same_source(left: dict, right: dict) -> bool:
    left_id = left.get("source_id")
    right_id = right.get("source_id")
    if left_id and right_id:
        same_document = left_id == right_id
    else:
        same_document = (
            bool(left.get("source_url"))
            and left.get("source_url") == right.get("source_url")
        )
    return same_document and left.get("operation_ref") == right.get("operation_ref")


def _merge_declarations(existing: Any, incoming: list[dict]) -> str:
    merged = _load_declarations(existing)
    for declaration in incoming:
        merged = [item for item in merged if not _same_source(item, declaration)]
        merged.append(declaration)
    merged.sort(key=lambda item: (
        str(item.get("source_id") or ""),
        str(item.get("source_url") or ""),
        str(item.get("operation_ref") or ""),
    ))
    return _json(merged)


def _record_value(record: Any, key: str):
    if record is None:
        return None
    if hasattr(record, "get"):
        return record.get(key)
    try:
        return record[key]
    except (KeyError, TypeError):
        return None


def _domain_name(recon_data: dict, scope: Scope, project_id: str) -> str:
    if scope.root:
        return scope.root
    metadata = recon_data.get("metadata") or {}
    for candidate in (metadata.get("root_domain"), recon_data.get("domain")):
        normalized = _normalize_host(candidate)
        if normalized:
            return normalized
    return f"ip-targets.{project_id}" if scope.ip_networks else ""


def _subdomain_name(recon_data: dict, host: str) -> str:
    try:
        ip_address(host)
    except ValueError:
        return host
    metadata = recon_data.get("metadata") or {}
    mapped = (metadata.get("ip_to_hostname") or {}).get(host)
    return _normalize_host(mapped) or host


def _persist_endpoint(tx, parameters: dict, meta: dict, declarations: list[dict]) -> None:
    record = tx.run(
        """
        MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                           user_id: $user_id, project_id: $project_id})
        ON CREATE SET e.source = 'openapi',
                      e.created_at = datetime()
        SET e._openapi_write_lock = randomUUID(),
            e.updated_at = datetime()
        RETURN e.openapi_declarations AS declarations
        """,
        **parameters,
    ).single()
    merged = _merge_declarations(_record_value(record, "declarations"), declarations)
    tx.run(
        """
        MERGE (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
        ON CREATE SET d.source = 'openapi',
                      d.created_at = datetime()
        SET d.updated_at = datetime()
        MERGE (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
        ON CREATE SET s.source = 'openapi',
                      s.discovered_at = datetime()
        SET s.updated_at = datetime()
        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
        MERGE (s)-[:BELONGS_TO]->(d)
        MERGE (b:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
        ON CREATE SET b.source = 'openapi',
                      b.scheme = $scheme,
                      b.host = $host,
                      b.port = $port,
                      b.created_at = datetime()
        SET b.updated_at = datetime()
        MERGE (s)-[:HAS_BASEURL]->(b)
        MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                           user_id: $user_id, project_id: $project_id})
        ON CREATE SET e.source = 'openapi',
                      e.created_at = datetime()
        SET e.openapi_declarations = $openapi_declarations,
            e.openapi_declared = true,
            e.url = coalesce(e.url, $full_url),
            e.updated_at = datetime()
        REMOVE e._openapi_write_lock
        MERGE (b)-[:HAS_ENDPOINT]->(e)
        """,
        **parameters,
        scheme=meta["scheme"],
        host=meta["host"],
        port=meta["port"],
        full_url=f'{parameters["baseurl"]}{parameters["path"]}',
        openapi_declarations=merged,
    )


class OpenApiMixin:
    """Persist parsed OpenAPI operations without making API requests."""

    def update_graph_from_openapi(
        self, recon_data: dict, user_id: str, project_id: str,
    ) -> dict:
        stats = {
            "operations_imported": 0,
            "endpoints_updated": 0,
            "skipped_out_of_scope": 0,
            "skipped_invalid": 0,
            "relationships_created": 0,
            "errors": [],
        }
        if not isinstance(recon_data, dict):
            stats["errors"].append("Invalid recon_data for OpenAPI graph ingestion")
            return stats
        openapi_data = recon_data.get("openapi", recon_data)
        if not isinstance(openapi_data, dict):
            stats["errors"].append("No OpenAPI data found in recon_data")
            return stats

        operations = openapi_data.get("operations")
        if not isinstance(operations, list):
            stats["errors"].append("OpenAPI operations must be a list")
            return stats
        scope = Scope.from_payload(openapi_data.get("scope"))

        grouped = defaultdict(list)
        endpoint_meta = {}
        for raw_operation in operations:
            normalized = _normalize_operation(raw_operation)
            if normalized is None:
                stats["skipped_invalid"] += 1
                continue
            if not scope.allows(normalized["baseurl"]):
                stats["skipped_out_of_scope"] += 1
                continue
            key = (
                normalized["baseurl"], normalized["path"], normalized["method"],
            )
            grouped[key].append(normalized["declaration"])
            endpoint_meta[key] = normalized

        if not scope.is_valid:
            return stats

        domain_name = _domain_name(recon_data, scope, project_id)
        if not domain_name:
            stats["errors"].append("OpenAPI scope has no graph domain anchor")
            return stats

        summary = {
            "documents": _summary_entries(
                openapi_data.get("documents"),
                ("url", "source_id", "sha256", "version", "operation_count"),
            ),
            "diagnostics": _summary_entries(
                openapi_data.get("diagnostics"), ("url", "code", "message"),
            ),
        }
        try:
            openapi_summary = _json(summary)
        except (TypeError, ValueError) as exc:
            stats["errors"].append(f"OpenAPI summary is not JSON serializable: {exc}")
            openapi_summary = _json({"documents": [], "diagnostics": []})

        with self.driver.session() as session:
            try:
                session.run(
                    """
                    MERGE (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                    ON CREATE SET d.source = 'openapi',
                                  d.created_at = datetime()
                    SET d.openapi_summary = $openapi_summary,
                        d.openapi_last_import_at = datetime(),
                        d.updated_at = datetime()
                    """,
                    domain=domain_name,
                    user_id=user_id,
                    project_id=project_id,
                    openapi_summary=openapi_summary,
                )
            except Exception as exc:
                stats["errors"].append(f"OpenAPI summary storage failed: {exc}")

            for key, declarations in grouped.items():
                baseurl, path, method = key
                meta = endpoint_meta[key]
                subdomain = _subdomain_name(recon_data, meta["host"])
                parameters = {
                    "domain": domain_name,
                    "subdomain": subdomain,
                    "baseurl": baseurl,
                    "path": path,
                    "method": method,
                    "user_id": user_id,
                    "project_id": project_id,
                }
                try:
                    session.execute_write(
                        _persist_endpoint, parameters, meta, declarations,
                    )
                    stats["operations_imported"] += len(declarations)
                    stats["endpoints_updated"] += 1
                    stats["relationships_created"] += 4
                except Exception as exc:
                    stats["errors"].append(
                        f"OpenAPI endpoint {method} {baseurl}{path} failed: {exc}"
                    )

        return stats

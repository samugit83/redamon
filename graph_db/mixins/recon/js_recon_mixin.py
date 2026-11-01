"""JS recon graph updates (JsReconFinding, Secret).

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.coverage_stamps import stamp_base_url_coverage
from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import build_host_scope, home_domain, host_in_scope, scan_root_for_host

# merge_discovered_hostnames (recon/helpers/target_helpers.py) tags each name it
# admits into dns.subdomains with one of these, after its apex allow-list, RoE,
# syntax and resolve checks. Untagged dns.subdomains entries are NOT vetted: the
# domain run copies that dict wholesale, RoE-excluded names included.
_VETTED_HOSTNAME_SOURCES = ("js_recon", "tlsx", "certificate_san")

# JS Recon's TruffleHog engine: an alternate name it adds to a key the regex
# engine also found.
_TRUFFLEHOG_ALT_PREFIX = "TruffleHog:"


def _keep_trufflehog_data(secret: dict, stored: dict) -> tuple:
    """`(alternate_names, validation)` for a key this run could not ask
    TruffleHog about: what TruffleHog said in an earlier run stays on it."""
    alternate = list(secret.get("alternate_names") or [])
    alternate += [a for a in stored.get("alternate_names") or []
                  if isinstance(a, str) and a.startswith(_TRUFFLEHOG_ALT_PREFIX) and a not in alternate]
    validation = dict(secret.get("validation") or {})
    if "trufflehog" not in validation:
        try:
            earlier = json.loads(stored.get("validation_info") or "{}") or {}
        except (TypeError, ValueError):
            earlier = {}
        if isinstance(earlier, dict) and isinstance(earlier.get("trufflehog"), dict):
            validation["trufflehog"] = earlier["trufflehog"]
    return alternate, validation


def _displayable_map_url(map_url: str) -> str:
    """An inline `data:` map is the whole map, megabytes of base64: keep a
    label, not the payload. Other URLs are capped too."""
    if map_url.startswith("data:"):
        return f"{map_url.split(',', 1)[0]},… (inline source map, {len(map_url)} chars)"
    return map_url[:2000]


def _finding_type_props(data_key: str, finding: dict) -> dict:
    """The fields one finding kind carries beyond the shared title/detail/
    evidence, flattened to scalars and string lists (a property cannot hold a
    map). A source map's first-party sources are analyzed as files of their
    own (source_url ``<map_url>#<source>``), so a key in them is a Secret node
    under that file; ``secrets_in_source`` counts those Secrets."""
    if data_key == "source_maps":
        map_url = _displayable_map_url(finding.get("map_url") or "")
        first_party = int(finding.get("first_party_files") or 0)
        files = int(finding.get("files_count") or 0)
        if finding.get("accessible"):
            detail = (
                f"Source map served at {map_url}: {files} source file(s), "
                f"{first_party} of them the target's own"
                + (", with their source text embedded" if finding.get("has_sources_content") else "")
                + (" (the script is served from a third-party host)" if finding.get("third_party") else "")
            )
        else:
            detail = (
                f"Script references {map_url}, which answered "
                f"{finding.get('fetch_result') or 'without a source map'}"
                + (" (the missing-key control check could not run, so the refusal is unconfirmed)"
                   if finding.get("control_check") == "failed" else "")
            )
        return {
            "map_url": map_url,
            "accessible": bool(finding.get("accessible")),
            "fetch_result": finding.get("fetch_result") or ("ok" if finding.get("accessible") else None),
            "control_check": finding.get("control_check"),
            "discovery_method": finding.get("discovery_method"),
            "files_count": files,
            "first_party_files": first_party,
            "has_sources_content": bool(finding.get("has_sources_content")),
            "source_files": [s for s in (finding.get("source_files") or []) if isinstance(s, str)][:100],
            "secrets_in_source": int(finding.get("secrets_in_source") or 0),
            "third_party": bool(finding.get("third_party")),
            "detail": detail,
            "evidence": map_url[:500],
        }
    if data_key == "dom_sinks":
        return {
            "line": finding.get("line"),
            "column": finding.get("column"),
            "user_source": finding.get("user_source"),
            "vendor": bool(finding.get("vendor")),
            "third_party": bool(finding.get("third_party")),
            "nominal_severity": finding.get("nominal_severity"),
        }
    return {}


def js_endpoint_scope(recon_data: dict) -> set:
    """Hosts a JS-extracted Endpoint may be stored under; empty set = no filter.

    build_host_scope is the set every recon mixin agrees on, but it only reads
    the top-level subdomain list. A subdomain JS recon itself found in the code
    reaches dns.subdomains alone, so it is added here, provided the containment
    in merge_discovered_hostnames admitted it. A filtered run (IP mode, or an
    explicit subdomain list) keeps exactly the targets the user gave.
    """
    scope = build_host_scope(recon_data)
    if not scope or (recon_data.get("metadata") or {}).get("filtered_mode"):
        return scope
    subs = (recon_data.get("dns") or {}).get("subdomains")
    if isinstance(subs, dict):
        scope |= {
            name.strip().lower()
            for name, entry in subs.items()
            if isinstance(name, str) and isinstance(entry, dict)
            and entry.get("source") in _VETTED_HOSTNAME_SOURCES
        }
    scope.discard("")
    return scope


def split_absolute_endpoint(path: str, source_js: str) -> tuple:
    """``(base_url, path)`` when an extracted ``path`` is really a whole URL, else ``('', path)``.

    Config, GraphQL, WebSocket and custom-keyword matches carry the full URL in
    ``path``. Stored as-is they became ``{baseurl: <host of the JS file>, path:
    'https://other.host/v1'}``, a foreign URL filed under the target. A WebSocket
    belongs to the HTTP origin that serves its upgrade handshake.
    """
    candidate = path.strip()
    if candidate.startswith('//'):
        scheme = urlparse(source_js).scheme if source_js else ''
        candidate = f"{scheme if scheme in ('http', 'https') else 'https'}:{candidate}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return '', path
    scheme = {'ws': 'http', 'wss': 'https'}.get(parsed.scheme, parsed.scheme)
    if scheme not in ('http', 'https') or not parsed.netloc:
        return '', path
    return f"{scheme}://{parsed.netloc}", parsed.path or '/'


class JsReconMixin:
    def update_graph_from_js_recon(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Ingest JS Recon Scanner results into the graph.

        Graph structure:
        - Domain/BaseURL -[:HAS_JS_FILE]-> JsReconFinding(finding_type='js_file')
        - JsReconFinding(js_file) -[:HAS_JS_FINDING]-> JsReconFinding (findings)
        - JsReconFinding(js_file) -[:HAS_SECRET]-> Secret
        - JsReconFinding(js_file) -[:HAS_ENDPOINT]-> Endpoint
        - BaseURL -[:HAS_ENDPOINT]-> Endpoint (network endpoints; not uploaded JS)

        Each analyzed JS file becomes a JsReconFinding node with finding_type='js_file'.
        All findings discovered in that file are linked to the file node, not directly
        to Domain/BaseURL. An Endpoint is written only for an in-scope host
        (js_endpoint_scope); third-party hosts are recorded as external domains
        by the JS recon module instead.
        """
        js_recon_data = recon_data.get("js_recon", {})
        if not js_recon_data:
            return {"status": "skipped", "reason": "no js_recon data"}

        stats = {
            "file_nodes_created": 0,
            "findings_created": 0,
            "secrets_created": 0,
            "endpoints_created": 0,
            "endpoints_out_of_scope": 0,
            "relationships_created": 0,
            "errors": [],
        }

        scan_ts = js_recon_data.get("scan_metadata", {}).get("scan_timestamp", "")
        # The org Domain of the scan root this run covered (a Domain node is the org).
        domain_name = home_domain(recon_data)

        def _is_uploaded(source_url: str) -> bool:
            return source_url.startswith('upload://')

        def _derive_base_url(source_url: str) -> str:
            if not source_url or _is_uploaded(source_url):
                return ''
            try:
                parsed = urlparse(source_url)
                if parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
            except Exception:
                pass
            return ''

        def _filename_from_url(url: str) -> str:
            if _is_uploaded(url):
                return url.replace('upload://', '')
            try:
                parsed = urlparse(url)
                name = parsed.path.split('/')[-1] or url
                # A source recovered from a source map: <map>#<source path>.
                return f"{name}#{parsed.fragment}" if parsed.fragment else name
            except Exception:
                return url

        def _linked(result) -> bool:
            record = result.single() if result is not None else None
            return bool(record) and int(record.get("linked", 0) or 0) > 0

        with self.driver.session() as session:
            # --- 0. Collect all unique source JS files and create file nodes ---
            all_source_urls = set()
            for data_key in ("dependencies", "source_maps", "dom_sinks", "dev_comments",
                             "emails", "ip_addresses", "object_references", "cloud_assets",
                             "dev_references"):
                for f in js_recon_data.get(data_key, []):
                    url = f.get("source_url", f.get("js_url", ""))
                    if url:
                        all_source_urls.add(url)
            for f in js_recon_data.get("frameworks", []):
                url = f.get("source_url", "")
                if url:
                    all_source_urls.add(url)
            for s in js_recon_data.get("secrets", []):
                url = s.get("source_url", "")
                if url:
                    all_source_urls.add(url)
            for ep in js_recon_data.get("endpoints", []):
                url = ep.get("source_js", "")
                if url:
                    all_source_urls.add(url)
            for f in js_recon_data.get("ai_sdk_findings", []):
                url = f.get("source_url", "")
                if url:
                    all_source_urls.add(url)

            # Map source_url -> file node id
            file_node_ids = {}
            for source_url in all_source_urls:
                try:
                    url_hash = hashlib.sha256(source_url.encode()).hexdigest()[:16]
                    file_node_id = f"jsrf-{user_id}-{project_id}-file-{url_hash}"
                    base_url = _derive_base_url(source_url)
                    filename = _filename_from_url(source_url)

                    props = {
                        "id": file_node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "js_file",
                        "severity": "info",
                        "confidence": "high",
                        "title": filename,
                        "detail": source_url,
                        "evidence": "",
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "is_uploaded": _is_uploaded(source_url),
                        "discovered_at": scan_ts,
                    }

                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=file_node_id, props=props
                    )
                    file_node_ids[source_url] = file_node_id
                    stats["file_nodes_created"] += 1

                    # Link file node to BaseURL (pipeline) or Domain (uploaded).
                    # Counted only when the parent existed and the link was made.
                    if base_url:
                        linked = _linked(session.run(
                            """
                            MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                            MATCH (jf:JsReconFinding {id: $fid, user_id: $uid, project_id: $pid})
                            MERGE (bu)-[r:HAS_JS_FILE]->(jf)
                            RETURN count(r) AS linked
                            """,
                            base_url=base_url, uid=user_id, pid=project_id, fid=file_node_id
                        ))
                        # No BaseURL: a host only the JS named, or a port http_probe
                        # never probed. Its in-scope Subdomain is the parent; a
                        # BaseURL is never created for a host nobody probed.
                        host = (urlparse(base_url).hostname or "").lower()
                        if not linked and host and scan_root_for_host(host, recon_data):
                            linked = _linked(session.run(
                                """
                                MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                                MATCH (jf:JsReconFinding {id: $fid, user_id: $uid, project_id: $pid})
                                MERGE (s)-[r:HAS_JS_FILE]->(jf)
                                RETURN count(r) AS linked
                                """,
                                host=host, uid=user_id, pid=project_id, fid=file_node_id
                            ))
                    else:
                        # Uploaded file or no base URL -- link to Domain
                        if domain_name:
                            linked = _linked(session.run(
                                """
                                MATCH (d:Domain {name: $dname, user_id: $uid, project_id: $pid})
                                MATCH (jf:JsReconFinding {id: $fid, user_id: $uid, project_id: $pid})
                                MERGE (d)-[r:HAS_JS_FILE]->(jf)
                                RETURN count(r) AS linked
                                """,
                                dname=domain_name, uid=user_id, pid=project_id, fid=file_node_id
                            ))
                        else:
                            linked = _linked(session.run(
                                """
                                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                                WITH d LIMIT 1
                                MATCH (jf:JsReconFinding {id: $fid, user_id: $uid, project_id: $pid})
                                MERGE (d)-[r:HAS_JS_FILE]->(jf)
                                RETURN count(r) AS linked
                                """,
                                uid=user_id, pid=project_id, fid=file_node_id
                            ))
                    if linked:
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS file node creation failed ({source_url}): {e}")

            def _link_to_file(session, node_id: str, node_label: str, rel_type: str, source_url: str) -> bool:
                """Link a finding/secret/endpoint to its parent JS file node."""
                file_node_id = file_node_ids.get(source_url)
                if not file_node_id:
                    return False
                if node_label not in ('JsReconFinding', 'Secret', 'Endpoint'):
                    return False
                if rel_type not in ('HAS_JS_FINDING', 'HAS_SECRET', 'HAS_ENDPOINT'):
                    return False
                result = session.run(
                    f"""
                    MATCH (file:JsReconFinding {{id: $fid, finding_type: 'js_file', user_id: $uid, project_id: $pid}})
                    MATCH (n:{node_label} {{id: $nid, user_id: $uid, project_id: $pid}})
                    MERGE (file)-[r:{rel_type}]->(n)
                    RETURN count(r) AS linked
                    """,
                    fid=file_node_id, nid=node_id, uid=user_id, pid=project_id
                )
                record = result.single()
                linked = record.get("linked", 0) if record else 0
                return int(linked) > 0

            def _link_endpoint_to_file(session, source_url: str, path: str, method: str, baseurl: str) -> bool:
                """Link a JS file to an Endpoint using the Endpoint canonical identity."""
                file_node_id = file_node_ids.get(source_url)
                if not file_node_id:
                    return False
                result = session.run(
                    """
                    MATCH (file:JsReconFinding {id: $fid, finding_type: 'js_file', user_id: $uid, project_id: $pid})
                    MATCH (n:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $uid, project_id: $pid})
                    MERGE (file)-[r:HAS_ENDPOINT]->(n)
                    RETURN count(r) AS linked
                    """,
                    fid=file_node_id, path=path, method=method, baseurl=baseurl,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                linked = record.get("linked", 0) if record else 0
                return int(linked) > 0

            # --- 1. JsReconFinding nodes (non-secret findings) ---
            finding_types = [
                ("dependencies", "dependency_confusion"),
                ("source_maps", "source_map_exposure"),
                ("dom_sinks", "dom_sink"),
                ("dev_comments", "dev_comment"),
            ]

            for data_key, finding_type in finding_types:
                for finding in js_recon_data.get(data_key, []):
                    try:
                        finding_id = finding.get("id")
                        if not finding_id:
                            continue

                        node_id = f"jsrf-{user_id}-{project_id}-{finding_id}"
                        source_url = finding.get("source_url", finding.get("js_url", ""))
                        base_url = _derive_base_url(source_url)

                        props = {
                            "id": node_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "finding_type": finding.get("finding_type", finding_type),
                            "severity": finding.get("severity", "info"),
                            "confidence": finding.get("confidence", "medium"),
                            # The finding's own type before the loop default:
                            # an unreachable map's row is source_map_reference,
                            # and titling it source_map_exposure made a 404
                            # read as a disclosure.
                            "title": finding.get("title", finding.get("type", finding.get("finding_type", finding_type))),
                            "detail": finding.get("detail", finding.get("content", finding.get("description", ""))),
                            "evidence": finding.get("evidence", finding.get("pattern", finding.get("content", "")))[:500],
                            # package_name / package_version, NOT name / version:
                            # `name` is what the graph viewer displays as the node
                            # label (format.ts falls back to `title` only when
                            # `name` is absent), so writing it there would silently
                            # relabel every framework node from "React 18.2.0" to
                            # "React". These fed the JS Dep Signals table's
                            # Package + Version columns, which read as empty on
                            # every row because nothing ever wrote them.
                            "package_name": finding.get("package_name"),
                            "package_version": finding.get("version"),
                            "source_url": source_url,
                            "base_url": base_url or 'upload',
                            "source": "js_recon",
                            "discovered_at": scan_ts,
                        }
                        props.update(_finding_type_props(data_key, finding))

                        session.run(
                            "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                            id=node_id, props=props
                        )
                        stats["findings_created"] += 1

                        if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"JsReconFinding creation failed: {e}")

            # Framework findings
            for fw in js_recon_data.get("frameworks", []):
                try:
                    fw_id = fw.get("id")
                    if not fw_id:
                        continue
                    node_id = f"jsrf-{user_id}-{project_id}-{fw_id}"
                    source_url = fw.get("source_url", "")
                    base_url = _derive_base_url(source_url)

                    version_str = f" {fw['version']}" if fw.get('version') else ""
                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "framework",
                        "severity": "info",
                        "confidence": fw.get("confidence", "medium"),
                        "title": f"{fw['name']}{version_str}",
                        "detail": f"Framework detected: {fw['name']}{version_str}",
                        "evidence": fw.get("name", ""),
                        # See the note in the generic finding block above: these
                        # are deliberately NOT `name`/`version`.
                        "package_name": fw.get("name"),
                        "package_version": fw.get("version"),
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Framework finding failed: {e}")

            # Email findings
            created_emails = set()
            for email in js_recon_data.get("emails", []):
                try:
                    email_addr = (email.get("email") or "").strip()
                    if not email_addr:
                        continue
                    source_url = email.get("source_url", "")
                    base_url = _derive_base_url(source_url)

                    id_hash = hashlib.sha256(f"{email_addr}:{source_url}".encode()).hexdigest()[:16]
                    node_id = f"jsrf-{user_id}-{project_id}-email-{id_hash}"
                    if node_id in created_emails:
                        continue
                    created_emails.add(node_id)

                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "email",
                        "severity": "info",
                        "confidence": "high",
                        "title": email_addr,
                        "detail": (email.get("context") or "")[:500],
                        "evidence": email_addr,
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Email finding failed: {e}")

            # Internal IP findings (RFC1918)
            created_ips = set()
            for ip_entry in js_recon_data.get("ip_addresses", []):
                try:
                    ip_addr = (ip_entry.get("ip") or "").strip()
                    if not ip_addr:
                        continue
                    source_url = ip_entry.get("source_url", "")
                    base_url = _derive_base_url(source_url)

                    id_hash = hashlib.sha256(f"{ip_addr}:{source_url}".encode()).hexdigest()[:16]
                    node_id = f"jsrf-{user_id}-{project_id}-ip-{id_hash}"
                    if node_id in created_ips:
                        continue
                    created_ips.add(node_id)

                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "internal_ip",
                        "severity": "low",
                        "confidence": "high",
                        "title": ip_addr,
                        "detail": (ip_entry.get("context") or "")[:500],
                        "evidence": ip_entry.get("type", "private"),
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Internal IP finding failed: {e}")

            # Developer references: localhost / internal-staging URLs and debug
            # flags. Recon leads, not credentials, so not Secret nodes.
            for ref in js_recon_data.get("dev_references", []):
                try:
                    value = (ref.get("value") or "").strip()
                    if not value:
                        continue
                    source_url = ref.get("source_url", "")
                    id_hash = hashlib.sha256(f"{ref.get('type')}:{value}:{source_url}".encode()).hexdigest()[:16]
                    node_id = f"jsrf-{user_id}-{project_id}-devref-{id_hash}"
                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "dev_reference",
                        "severity": "info",
                        "confidence": "medium",
                        "title": ref.get("type") or "dev_reference",
                        "detail": (ref.get("context") or "")[:500],
                        "evidence": value[:500],
                        "line": ref.get("line_number"),
                        "source_url": source_url,
                        "base_url": _derive_base_url(source_url) or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Developer reference finding failed: {e}")

            # Object reference (UUID / IDOR) findings
            created_refs = set()
            for ref in js_recon_data.get("object_references", []):
                try:
                    value = (ref.get("value") or "").strip()
                    if not value:
                        continue
                    source_url = ref.get("source_url", "")
                    base_url = _derive_base_url(source_url)

                    id_hash = hashlib.sha256(f"{value}:{source_url}".encode()).hexdigest()[:16]
                    node_id = f"jsrf-{user_id}-{project_id}-objref-{id_hash}"
                    if node_id in created_refs:
                        continue
                    created_refs.add(node_id)

                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "object_reference",
                        "severity": "info",
                        "confidence": "medium",
                        "title": value,
                        "detail": (ref.get("context") or "")[:500],
                        "evidence": ref.get("type", "uuid"),
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "potential_idor": bool(ref.get("potential_idor", False)),
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Object reference finding failed: {e}")

            # Cloud asset findings (S3 / GCP / Azure URLs)
            created_cloud = set()
            for ca in js_recon_data.get("cloud_assets", []):
                try:
                    url_val = (ca.get("url") or "").strip()
                    if not url_val:
                        continue
                    source_url = ca.get("source_url", "")
                    base_url = _derive_base_url(source_url)
                    provider = ca.get("provider", "unknown")
                    asset_type = ca.get("type", "cloud_asset")

                    id_hash = hashlib.sha256(f"{url_val}:{source_url}".encode()).hexdigest()[:16]
                    node_id = f"jsrf-{user_id}-{project_id}-cloud-{id_hash}"
                    if node_id in created_cloud:
                        continue
                    created_cloud.add(node_id)

                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "cloud_asset",
                        "severity": "medium",
                        "confidence": "high",
                        "title": url_val,
                        "detail": f"{provider} — {asset_type}",
                        "evidence": provider,
                        "cloud_provider": provider,
                        "cloud_asset_type": asset_type,
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Cloud asset finding failed: {e}")

            # External domain findings (3rd-party domains leaked in JS URLs)
            created_ext = set()
            for ext in js_recon_data.get("external_domains", []):
                try:
                    domain_val = (ext.get("domain") or "").strip().lower()
                    if not domain_val:
                        continue
                    times_seen = int(ext.get("times_seen", 1))
                    sample_urls = ext.get("urls", [])

                    id_hash = hashlib.sha256(domain_val.encode()).hexdigest()[:16]
                    node_id = f"jsrf-{user_id}-{project_id}-extdom-{id_hash}"
                    if node_id in created_ext:
                        continue
                    created_ext.add(node_id)

                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "external_domain",
                        "severity": "info",
                        "confidence": "high",
                        "title": domain_val,
                        "detail": f"Seen {times_seen}x — {', '.join(sample_urls[:3])}"[:500],
                        "evidence": domain_val,
                        "times_seen": times_seen,
                        "sample_urls": sample_urls[:3],
                        "source_url": "",
                        "base_url": "",
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    # External domains don't belong to a single file — link to Domain
                    if domain_name:
                        session.run(
                            """
                            MATCH (d:Domain {name: $dname, user_id: $uid, project_id: $pid})
                            MATCH (jf:JsReconFinding {id: $fid, user_id: $uid, project_id: $pid})
                            MERGE (d)-[:HAS_JS_FINDING]->(jf)
                            """,
                            dname=domain_name, uid=user_id, pid=project_id, fid=node_id
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"External domain finding failed: {e}")

            # --- 2. Secret nodes (source='js_recon') ---
            # A TruffleHog run that did not complete (failed, timed out, image
            # missing) found nothing this time, which is not "gone": its own
            # earlier findings of the files it was given stay alive, and keys
            # both engines found keep what TruffleHog said about them. Regex
            # findings prune as always.
            trufflehog = (js_recon_data.get("scan_metadata") or {}).get("trufflehog") or {}
            trufflehog_missed = bool(trufflehog) and trufflehog.get("status") != "ran"
            stored_trufflehog = {}
            if trufflehog_missed:
                try:
                    ids = [f"secret-{user_id}-{project_id}-{s.get('id')}"
                           for s in js_recon_data.get("secrets", []) if s.get("id")]
                    for record in session.run(
                            """
                            MATCH (s:Secret {user_id: $uid, project_id: $pid, source: 'js_recon'})
                            WHERE s.id IN $ids
                            RETURN s.id AS id, s.alternate_names AS alternate_names,
                                   s.validation_info AS validation_info
                            """,
                            uid=user_id, pid=project_id, ids=ids):
                        stored_trufflehog[record["id"]] = dict(record)
                except Exception as e:
                    stats["errors"].append(f"JS Recon TruffleHog data read failed: {e}")

            created_secrets = set()
            for secret in js_recon_data.get("secrets", []):
                try:
                    secret_id = secret.get("id")
                    if not secret_id:
                        continue

                    node_id = f"secret-{user_id}-{project_id}-{secret_id}"
                    if node_id in created_secrets:
                        continue

                    source_url = secret.get("source_url", "")
                    base_url = _derive_base_url(source_url)
                    validation = secret.get("validation", {})
                    alternate_names = [str(a) for a in secret.get("alternate_names") or []]
                    if node_id in stored_trufflehog:
                        alternate_names, validation = _keep_trufflehog_data(secret, stored_trufflehog[node_id])
                    line_number = secret.get("line_number")

                    session.run(
                        """
                        MERGE (s:Secret {id: $id, user_id: $user_id,
                                         project_id: $project_id})
                        SET s.user_id = $user_id,
                            s.project_id = $project_id,
                            s.secret_type = $secret_type,
                            s.severity = $severity,
                            s.source = 'js_recon',
                            s.source_url = $source_url,
                            s.base_url = $base_url,
                            s.sample = $sample,
                            s.confidence = $confidence,
                            s.detection_method = $detection_method,
                            s.key_type = $key_type,
                            s.validation_status = $validation_status,
                            s.matched_text = $matched_text,
                            s.validation_info = $validation_info,
                            s.context = $context,
                            s.public_client_key = $public_client_key,
                            s.line_number = $line_number,
                            s.alternate_names = $alternate_names,
                            s.discovered_at = $discovered_at,
                            s.updated_at = datetime()
                        """,
                        id=node_id, user_id=user_id, project_id=project_id,
                        public_client_key=bool(secret.get("public_client_key")),
                        line_number=line_number if isinstance(line_number, int) else None,
                        alternate_names=alternate_names,
                        # Already masked by the detector; the cap guards the node.
                        context=(secret.get("context") or "")[:400],
                        secret_type=secret.get("name", "unknown"),
                        severity=secret.get("severity", "info"),
                        source_url=source_url,
                        base_url=base_url or 'upload',
                        sample=secret.get("redacted_value", ""),
                        matched_text=secret.get("matched_text", ""),
                        confidence=secret.get("confidence", "medium"),
                        detection_method=secret.get("detection_method", "regex"),
                        key_type=secret.get("category", ""),
                        validation_status=validation.get("status", "unvalidated"),
                        validation_info=json.dumps(validation) if validation else "",
                        discovered_at=scan_ts,
                    )
                    created_secrets.add(node_id)
                    stats["secrets_created"] += 1

                    if _link_to_file(session, node_id, 'Secret', 'HAS_SECRET', source_url):
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS Recon Secret node failed: {e}")

            analyzed_urls = [u for u in trufflehog.get("analyzed_urls") or [] if isinstance(u, str)]
            if trufflehog_missed and analyzed_urls:
                try:
                    record = session.run(
                        """
                        MATCH (s:Secret {user_id: $uid, project_id: $pid, source: 'js_recon',
                                         detection_method: 'trufflehog'})
                        WHERE s.source_url IN $analyzed_urls
                        SET s.updated_at = datetime()
                        RETURN count(s) AS kept
                        """,
                        uid=user_id, pid=project_id, analyzed_urls=analyzed_urls).single()
                    stats["trufflehog_kept_alive"] = int((record or {}).get("kept", 0) or 0)
                except Exception as e:
                    stats["errors"].append(f"JS Recon TruffleHog keep-alive failed: {e}")

            # --- 3. Endpoint nodes (source='js_recon') ---
            created_endpoints = set()
            endpoint_scope = js_endpoint_scope(recon_data)
            for ep in js_recon_data.get("endpoints", []):
                try:
                    # Drop only endpoints a probe positively judged: dead
                    # ('not_hittable'), or answered exactly like a made-up path
                    # on a catch-all host ('catch_all', an SPA shell). 'hittable',
                    # 'unvalidated' (probing off, unresolved upload-relative URL,
                    # or unsupported scheme) and a missing status are all
                    # ingested, so disabling endpoint probing keeps the prior
                    # "ingest every extracted endpoint" behavior.
                    if ep.get("validation_status") in ("not_hittable", "catch_all"):
                        continue

                    path = ep.get("path", "")
                    method = ep.get("method", "GET")
                    source_js = ep.get("source_js", "")
                    base_url = ep.get("base_url", "")
                    is_upload = _is_uploaded(source_js)

                    absolute_base, absolute_path = split_absolute_endpoint(path, source_js)
                    if absolute_base:
                        base_url, path = absolute_base, absolute_path

                    if not base_url and source_js and not is_upload:
                        base_url = _derive_base_url(source_js)

                    if not path:
                        continue
                    if not base_url and not is_upload:
                        continue
                    # Only a relative path in uploaded JS has no host to judge;
                    # it stays under the 'upload' pseudo base.
                    if base_url and not host_in_scope(base_url, endpoint_scope):
                        stats["endpoints_out_of_scope"] += 1
                        continue

                    ep_key = f"{method}:{path}:{base_url or 'upload'}"
                    if ep_key in created_endpoints:
                        continue
                    created_endpoints.add(ep_key)

                    effective_baseurl = base_url or 'upload'
                    id_hash = hashlib.sha256(f"{effective_baseurl}:{method}:{path}".encode()).hexdigest()[:16]
                    node_id = f"endpoint-{user_id}-{project_id}-js-{id_hash}"

                    result = session.run(
                        """
                        MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $uid, project_id: $pid})
                        ON CREATE SET e.id = COALESCE(e.id, $id),
                            e.source = 'js_recon',
                            e.category = $category,
                            e.full_url = $full_url,
                            e.status_code = $status_code,
                            e.js_status_code = $status_code,
                            e.resolved_url = $resolved_url,
                            e.validation_status = $validation_status,
                            e.endpoint_type = $ep_type,
                            e.path_template = $path_template,
                            e._js_recon_created = true,
                            e.updated_at = datetime()
                        ON MATCH SET e.id = COALESCE(e.id, $id),
                            e.js_recon_source = true,
                            e.endpoint_type = COALESCE(e.endpoint_type, $ep_type),
                            e.path_template = COALESCE(e.path_template, $path_template),
                            e.full_url = COALESCE(e.full_url, $full_url),
                            // K2: `status_code` is what the score model reads
                            // liveness from, and the HTTP probe owns it. JS
                            // recon's own probe goes in its own property rather
                            // than overwriting a stronger measurement.
                            e.js_status_code = COALESCE($status_code, e.js_status_code),
                            e.status_code = COALESCE(e.status_code, $status_code),
                            e.resolved_url = CASE WHEN $resolved_url <> '' THEN $resolved_url ELSE e.resolved_url END,
                            e.validation_status = COALESCE($validation_status, e.validation_status),
                            e.updated_at = datetime()
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        WITH e, COALESCE(e._js_recon_created, false) AS created
                        REMOVE e._js_recon_created
                        RETURN created AS created
                        """,
                        path=path, method=method, baseurl=effective_baseurl,
                        uid=user_id, pid=project_id,
                        id=node_id,
                        category=ep.get("category", "endpoint"),
                        full_url=ep.get("full_url", ""),
                        status_code=ep.get("status_code"),
                        resolved_url=ep.get("resolved_url", ""),
                        validation_status=ep.get("validation_status"),
                        ep_type=ep.get("type", "rest"),
                        # `parameterized` is this property being set.
                        path_template=ep.get("path_template") if ep.get("parameterized") else None,
                    )
                    record = result.single()
                    if record and bool(record.get("created", False)):
                        stats["endpoints_created"] += 1

                    if _link_endpoint_to_file(session, source_js, path, method, effective_baseurl):
                        stats["relationships_created"] += 1

                    if base_url:
                        # Same ownership write as resource_enum. MERGE, not MATCH:
                        # an in-scope host that only the JS names (an unprobed
                        # port, a subdomain found in the code) has no BaseURL yet.
                        owner = session.run(
                            """
                            MERGE (bu:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
                            ON CREATE SET bu.source = 'js_recon',
                                          bu.updated_at = datetime()
                            WITH bu
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $uid, project_id: $pid})
                            MERGE (bu)-[r:HAS_ENDPOINT]->(e)
                            RETURN count(r) AS linked
                            """,
                            baseurl=base_url, path=path, method=method,
                            uid=user_id, pid=project_id,
                        ).single()
                        if owner and int(owner.get("linked", 0) or 0) > 0:
                            stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS Recon Endpoint node failed: {e}")

            # --- 4. AI SDK findings (source='js_recon', finding_type='ai-sdk-*') ---
            # Four channels: ai-sdk-client (imports), ai-sdk-key-literal (keys),
            # ai-sdk-browser-allowed (dangerouslyAllowBrowser), ai-frontend-detected
            # (product markers), and ai-provider-url (contextual URLs).
            # For ai-sdk-key-literal findings we ALSO enrich any matching Secret
            # node with `ai_provider`/`ai_finding_id` — value-prefixed reuse per
            # AI_SURFACE_RECON.md §7.2, so existing Secret-based queries pick up
            # AI context without a parallel taxonomy.
            stats["ai_sdk_findings_created"] = 0
            stats["ai_sdk_secrets_enriched"] = 0
            created_ai_sdk = set()
            for finding in js_recon_data.get("ai_sdk_findings", []):
                try:
                    fid = finding.get("id")
                    if not fid:
                        continue
                    node_id = f"jsrf-{user_id}-{project_id}-{fid}"
                    if node_id in created_ai_sdk:
                        continue
                    created_ai_sdk.add(node_id)

                    source_url = finding.get("source_url", "")
                    base_url = _derive_base_url(source_url)
                    category = finding.get("category", "ai-sdk-client")
                    sdk_name = finding.get("sdk_name", "unknown")

                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": category,
                        "severity": finding.get("severity", "info"),
                        "confidence": finding.get("confidence", "medium"),
                        "title": sdk_name,
                        "detail": finding.get("matched_text", "")[:500],
                        "evidence": finding.get("matched_text", "")[:500],
                        "sample": finding.get("sample", ""),
                        "sdk_name": sdk_name,
                        "ai_provider": sdk_name,
                        "byte_offset": int(finding.get("byte_offset", 0)),
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "detection_method": finding.get("detection_method", "ai_sdk_catalogue"),
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["ai_sdk_findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1

                    # Enrich any pre-existing Secret found in the same JS file
                    # whose stored value overlaps this AI key literal. Anchors:
                    #   1. Use the captured key value (no surrounding context),
                    #      not matched_text — matched_text can include the
                    #      whole "apiKey:'sk-...'" wrapper and risk symmetric
                    #      CONTAINS spuriously matching unrelated short secrets.
                    #   2. Require the Secret's matched_text to start with a
                    #      known AI-key prefix so we never enrich a Stripe /
                    #      Slack / AWS literal that happens to live in the
                    #      same byte range.
                    captured = finding.get("captured_value", "") or ""
                    if (category == "ai-sdk-key-literal" and source_url
                            and captured and len(captured) >= 12):
                        result = session.run(
                            """
                            MATCH (s:Secret {source_url: $source_url, user_id: $uid, project_id: $pid})
                            WHERE (s.matched_text STARTS WITH 'sk-'
                                OR s.matched_text STARTS WITH 'hf_'
                                OR s.matched_text STARTS WITH 'lsv2_'
                                OR s.matched_text STARTS WITH 'gsk_'
                                OR s.matched_text STARTS WITH 'r8_'
                                OR s.matched_text STARTS WITH 'pcsk_'
                                OR s.matched_text STARTS WITH 'pplx-'
                                OR s.matched_text STARTS WITH 'xai-'
                                OR s.matched_text STARTS WITH 'csk-'
                                OR s.matched_text STARTS WITH 'tgp_'
                                OR s.matched_text STARTS WITH 'pa-'
                                OR s.matched_text STARTS WITH 'AIzaSy'
                                OR s.matched_text STARTS WITH 'co_'
                                OR s.matched_text STARTS WITH 'rpa_'
                                OR s.matched_text STARTS WITH 'pk-lf-'
                                OR s.matched_text STARTS WITH 'fw_')
                              AND (s.matched_text CONTAINS $needle
                                   OR $needle CONTAINS s.matched_text)
                            SET s.ai_provider = $sdk_name,
                                s.ai_finding_id = $ai_finding_id,
                                s.updated_at = datetime()
                            RETURN count(s) AS enriched
                            """,
                            source_url=source_url, uid=user_id, pid=project_id,
                            needle=captured,
                            sdk_name=sdk_name, ai_finding_id=node_id,
                        ).single()
                        if result and result.get("enriched"):
                            stats["ai_sdk_secrets_enriched"] += int(result["enriched"])

                except Exception as e:
                    stats["errors"].append(f"AI SDK finding failed: {e}")

            coverage = (js_recon_data.get("scan_metadata") or {}).get("coverage")
            if coverage:
                scope = js_endpoint_scope(recon_data)
                try:
                    stats["coverage_stamped"] = stamp_base_url_coverage(
                        session, "js_recon", coverage, user_id, project_id,
                        in_scope=lambda host: host_in_scope(host, scope))
                except Exception as e:
                    stats["errors"].append(f"JS Recon coverage stamp failed: {e}")

        print(f"[+][graph-db] JS Recon: {stats['file_nodes_created']} files, "
              f"{stats['findings_created']} findings, {stats['secrets_created']} secrets, "
              f"{stats['endpoints_created']} endpoints, "
              f"{stats.get('ai_sdk_findings_created', 0)} AI SDK findings "
              f"({stats.get('ai_sdk_secrets_enriched', 0)} Secret nodes enriched), "
              f"{stats['relationships_created']} relationships")
        if stats["errors"]:
            print(f"[!][graph-db] JS Recon: {len(stats['errors'])} errors")

        return stats

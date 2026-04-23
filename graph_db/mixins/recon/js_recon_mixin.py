"""JS recon graph updates (JsReconFinding, Secret).

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address

class JsReconMixin:
    def update_graph_from_js_recon(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Ingest JS Recon Scanner results into the graph.

        Graph structure:
        - Domain/BaseURL -[:HAS_JS_FILE]-> JsReconFinding(finding_type='js_file')
        - JsReconFinding(js_file) -[:HAS_JS_FINDING]-> JsReconFinding (findings)
        - JsReconFinding(js_file) -[:HAS_SECRET]-> Secret
        - JsReconFinding(js_file) -[:HAS_ENDPOINT]-> Endpoint

        Each analyzed JS file becomes a JsReconFinding node with finding_type='js_file'.
        All findings discovered in that file are linked to the file node, not directly
        to Domain/BaseURL.
        """
        js_recon_data = recon_data.get("js_recon", {})
        if not js_recon_data:
            return {"status": "skipped", "reason": "no js_recon data"}

        stats = {
            "file_nodes_created": 0,
            "findings_created": 0,
            "secrets_created": 0,
            "endpoints_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        scan_ts = js_recon_data.get("scan_metadata", {}).get("scan_timestamp", "")
        domain_name = recon_data.get('domain', '')

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
                return urlparse(url).path.split('/')[-1] or url
            except Exception:
                return url

        with self.driver.session() as session:
            # --- 0. Collect all unique source JS files and create file nodes ---
            all_source_urls = set()
            for data_key in ("dependencies", "source_maps", "dom_sinks", "dev_comments",
                             "emails", "ip_addresses", "object_references", "cloud_assets"):
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
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
                        id=file_node_id, props=props
                    )
                    file_node_ids[source_url] = file_node_id
                    stats["file_nodes_created"] += 1

                    # Link file node to BaseURL (pipeline) or Domain (uploaded)
                    if base_url:
                        session.run(
                            """
                            MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                            MATCH (jf:JsReconFinding {id: $fid})
                            MERGE (bu)-[:HAS_JS_FILE]->(jf)
                            """,
                            base_url=base_url, uid=user_id, pid=project_id, fid=file_node_id
                        )
                    else:
                        # Uploaded file or no base URL -- link to Domain
                        if domain_name:
                            session.run(
                                """
                                MATCH (d:Domain {name: $dname, user_id: $uid, project_id: $pid})
                                MATCH (jf:JsReconFinding {id: $fid})
                                MERGE (d)-[:HAS_JS_FILE]->(jf)
                                """,
                                dname=domain_name, uid=user_id, pid=project_id, fid=file_node_id
                            )
                        else:
                            session.run(
                                """
                                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                                WITH d LIMIT 1
                                MATCH (jf:JsReconFinding {id: $fid})
                                MERGE (d)-[:HAS_JS_FILE]->(jf)
                                """,
                                uid=user_id, pid=project_id, fid=file_node_id
                            )
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
                session.run(
                    f"""
                    MATCH (file:JsReconFinding {{id: $fid, finding_type: 'js_file'}})
                    MATCH (n:{node_label} {{id: $nid}})
                    MERGE (file)-[:{rel_type}]->(n)
                    """,
                    fid=file_node_id, nid=node_id
                )
                return True

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
                            "title": finding.get("title", finding.get("type", finding_type)),
                            "detail": finding.get("detail", finding.get("content", finding.get("description", ""))),
                            "evidence": finding.get("evidence", finding.get("pattern", finding.get("content", "")))[:500],
                            "source_url": source_url,
                            "base_url": base_url or 'upload',
                            "source": "js_recon",
                            "discovered_at": scan_ts,
                        }

                        session.run(
                            "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
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
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
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
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
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
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Internal IP finding failed: {e}")

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
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
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
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
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
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    # External domains don't belong to a single file — link to Domain
                    if domain_name:
                        session.run(
                            """
                            MATCH (d:Domain {name: $dname, user_id: $uid, project_id: $pid})
                            MATCH (jf:JsReconFinding {id: $fid})
                            MERGE (d)-[:HAS_JS_FINDING]->(jf)
                            """,
                            dname=domain_name, uid=user_id, pid=project_id, fid=node_id
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"External domain finding failed: {e}")

            # --- 2. Secret nodes (source='js_recon') ---
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

                    session.run(
                        """
                        MERGE (s:Secret {id: $id})
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
                            s.discovered_at = $discovered_at,
                            s.updated_at = datetime()
                        """,
                        id=node_id, user_id=user_id, project_id=project_id,
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

            # --- 3. Endpoint nodes (source='js_recon') ---
            created_endpoints = set()
            for ep in js_recon_data.get("endpoints", []):
                try:
                    path = ep.get("path", "")
                    method = ep.get("method", "GET")
                    source_js = ep.get("source_js", "")
                    base_url = ep.get("base_url", "")
                    is_upload = _is_uploaded(source_js)

                    if not base_url and source_js and not is_upload:
                        base_url = _derive_base_url(source_js)

                    if not path:
                        continue
                    if not base_url and not is_upload:
                        continue

                    ep_key = f"{method}:{path}:{base_url or 'upload'}"
                    if ep_key in created_endpoints:
                        continue
                    created_endpoints.add(ep_key)

                    effective_baseurl = base_url or 'upload'

                    session.run(
                        """
                        MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $uid, project_id: $pid})
                        ON CREATE SET e.source = 'js_recon',
                            e.category = $category,
                            e.full_url = $full_url,
                            e.endpoint_type = $ep_type,
                            e.updated_at = datetime()
                        ON MATCH SET e.js_recon_source = true,
                            e.endpoint_type = COALESCE(e.endpoint_type, $ep_type),
                            e.full_url = COALESCE(e.full_url, $full_url),
                            e.updated_at = datetime()
                        """,
                        path=path, method=method, baseurl=effective_baseurl,
                        uid=user_id, pid=project_id,
                        category=ep.get("category", "endpoint"),
                        full_url=ep.get("full_url", ""),
                        ep_type=ep.get("type", "rest"),
                    )
                    stats["endpoints_created"] += 1

                    if _link_to_file(session, node_id, 'Endpoint', 'HAS_ENDPOINT', source_js):
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS Recon Endpoint node failed: {e}")

        print(f"[+][graph-db] JS Recon: {stats['file_nodes_created']} files, "
              f"{stats['findings_created']} findings, {stats['secrets_created']} secrets, "
              f"{stats['endpoints_created']} endpoints, {stats['relationships_created']} relationships")
        if stats["errors"]:
            print(f"[!][graph-db] JS Recon: {len(stats['errors'])} errors")

        return stats

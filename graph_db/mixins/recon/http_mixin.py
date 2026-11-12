"""HTTP probe graph updates (BaseURL, Endpoint, Technology, Header, Certificate).

Lap-1 Patch D refactor: each httpx output URL is split into

  - BaseURL  (one per scheme+host+port — the HTTP service identity)
  - Endpoint (one per probed path — carries status/headers/title/AI annotations)

linked by ``(BaseURL)-[:HAS_ENDPOINT]->(Endpoint)``.

Previously the mixin MERGEd ``BaseURL {url: <full URL with path>}`` which
conflated "service" and "path" — when httpxPaths probed multiple paths per
port the result was N BaseURL nodes per HTTP service, all sharing the same
scheme+host+port. The viewer label collapsed them to identical strings;
the schema semantics were violated. Patch D restores the intended shape:
ONE BaseURL per service, MANY Endpoints per BaseURL.
"""
import json
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import org_for_scan_root
from graph_db.cert_key import build_cert_key
from graph_db.schema import NON_RECON_SOURCES
from graph_db.technology_identity import (  # noqa: F401  re-exported for callers
    TECH_RELATIONSHIPS as _TECH_TWIN_RELATIONSHIPS,
    resolve_tech_name,
    resolve_tech_version,
    tech_name_key,
)
from graph_db.endpoint_paths import normalize_endpoint_path


#: A root page whose exact body this many distinct BaseURLs serve (200 or 403)
#: is one shared deny or parking page, not each host's own content.
SHARED_BODY_MIN_BASEURLS = 3

#: Appended to a Technology MERGE: adds `$detector` to the comma-joined
#: `detected_by` instead of overwriting it. clear_recon_data spares a Technology
#: only while `gvm` is listed, so an overwrite let the next full recon delete a
#: GVM-tagged node with its vulnerabilities. `gvm` stays last, as
#: absorb_technology keeps it, because clear_gvm_data deletes an exact 'gvm' and
#: strips only a ',gvm'.
_ADD_DETECTOR = """
    WITH t, [s IN split(coalesce(t.detected_by, '') + ',' + $detector, ',')
             WHERE trim(s) <> '' | trim(s)] AS parts
    WITH t, reduce(acc = [], s IN parts | CASE WHEN s IN acc THEN acc ELSE acc + s END) AS seen
    SET t.detected_by = reduce(out = '', s IN [d IN seen WHERE d <> 'gvm'] + [d IN seen WHERE d = 'gvm'] |
                               CASE WHEN out = '' THEN s ELSE out + ',' + s END)
"""


def _split_url(url: str) -> tuple[str, str]:
    """Return ``(base_url, path)`` where ``base_url = scheme://host:port``
    and ``path`` is the URL path (defaults to ``'/'``). Query string and
    fragment are dropped — Endpoint identity is ``(path, method, baseurl)``
    per the existing Redamon convention (matches js_recon + vuln_scan mixins)."""
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = normalize_endpoint_path(parsed.path or "/")
    return base_url, path


def _asn_label(value) -> str | None:
    """httpx -asn reports {"as_number": "AS13335", ...}. Stored as the "AS<n>"
    string Netlas and FOFA write: Neo4j rejects a map property, which would drop
    the whole Endpoint write."""
    if isinstance(value, dict):
        value = value.get("as_number")
    match = re.search(r"\d+", str(value or ""))
    return f"AS{match.group(0)}" if match else None


class HttpMixin:
    def update_graph_from_http_probe(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with HTTP probe data.

        Lap-1 model:
        - BaseURL nodes  — one per scheme+host+port (the HTTP service identity)
        - Endpoint nodes — one per probed path (carries response data + AI annotations)
        - Technology nodes for detected technologies (attached to Endpoint)
        - Header nodes for response headers (attached to Endpoint)
        - Certificate nodes (attached to Endpoint when TLS data is present)
        - Service nodes (if not existing) for the HTTP/HTTPS service

        Relationships:
        - Service  -[:SERVES_URL]->        BaseURL
        - BaseURL  -[:HAS_ENDPOINT]->      Endpoint
        - Endpoint -[:HAS_HEADER]->        Header
        - Endpoint -[:HAS_CERTIFICATE]->   Certificate
        - Endpoint -[:USES_TECHNOLOGY]->   Technology

        Args:
            recon_data: The recon JSON data containing http_probe results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "baseurls_created": 0,
            "certificates_created": 0,
            "services_created": 0,
            "technologies_created": 0,
            "headers_created": 0,
            "relationships_created": 0,
            "subdomains_updated": 0,
            "errors": []
        }

        http_probe_data = recon_data.get("http_probe", {})
        if not http_probe_data:
            stats["errors"].append("No http_probe data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = http_probe_data.get("scan_metadata", {})
            by_url = http_probe_data.get("by_url", {})
            wappalyzer = http_probe_data.get("wappalyzer", {})
            all_technologies = wappalyzer.get("all_technologies", {})

            # Process each URL
            for url, url_info in by_url.items():
                try:
                    # Extract URL components
                    host = url_info.get("host", "")
                    scheme = "https" if url.startswith("https://") else "http"

                    # Lap-1 Patch D: split URL into base_url (one per service) and
                    # path (one per Endpoint). MERGE BaseURL as a thin node keyed
                    # by base_url; MERGE Endpoint with all the response data.
                    base_url, path = _split_url(url)

                    # ---- BaseURL: thin "HTTP service" identity node ----------
                    baseurl_props = {
                        "url": base_url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "scheme": scheme,
                        "host": host,
                        "source": "http_probe",
                    }
                    baseurl_props = {k: v for k, v in baseurl_props.items() if v is not None}
                    session.run(
                        """
                        MERGE (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        SET u += $props,
                            u.updated_at = datetime()
                        """,
                        base_url=base_url, user_id=user_id, project_id=project_id, props=baseurl_props
                    )
                    stats["baseurls_created"] += 1

                    # ---- Endpoint: path-level data + AI annotations ----------
                    endpoint_props = {
                        "path": path,
                        "method": "GET",  # httpx default; the URL identity uses (path, method, baseurl)
                        "baseurl": base_url,
                        "url": url,                                       # convenience: full URL
                        "user_id": user_id,
                        "project_id": project_id,
                        "status_code": url_info.get("status_code"),
                        "content_length": url_info.get("content_length"),
                        "content_type": url_info.get("content_type"),
                        "title": url_info.get("title"),
                        "server": url_info.get("server"),
                        "response_time_ms": url_info.get("response_time_ms"),
                        "word_count": url_info.get("word_count"),
                        "line_count": url_info.get("line_count"),
                        "resolved_ip": url_info.get("ip"),
                        "cname": url_info.get("cname"),
                        "cdn": url_info.get("cdn"),
                        "is_cdn": url_info.get("is_cdn", False),
                        "asn": _asn_label(url_info.get("asn")),
                        "favicon_hash": url_info.get("favicon_hash"),
                        "is_live": url_info.get("status_code") is not None,
                        # status_code is the last hop's (httpx follows redirects).
                        "final_url": url_info.get("final_url"),
                        "first_status_code": url_info.get("first_status_code"),
                        "redirect_chain_codes": url_info.get("redirect_chain_codes"),
                        "redirected_off_host": url_info.get("redirected_off_host"),
                        "source": "http_probe",
                        # AI surface recon (lap-1 Patch D — moved from BaseURL to Endpoint)
                        "is_ai_framework_detected": url_info.get("is_ai_framework_detected"),
                        "ai_framework_name": url_info.get("ai_framework_name"),
                        "ai_frontend_product_guess": url_info.get("ai_frontend_product_guess"),
                        # Page type (TypeSafe Jev, the pre-filter where Jev gave no answer).
                        "page_class": url_info.get("page_class"),
                        "page_class_confidence": url_info.get("page_class_confidence"),
                        "page_class_source": url_info.get("page_class_source"),
                    }
                    # Only when httpx labelled the page: a null here would erase a
                    # category a crawler wrote in an earlier partial run.
                    if url_info.get("category"):
                        endpoint_props["category"] = url_info["category"]
                    body_hash = url_info.get("body_hash", {})
                    if body_hash:
                        endpoint_props["body_sha256"] = body_hash.get("body_sha256")
                        endpoint_props["header_sha256"] = body_hash.get("header_sha256")
                    tls_data = url_info.get("tls", {})
                    if tls_data:
                        endpoint_props["tls_cipher"] = tls_data.get("cipher")
                        endpoint_props["tls_version"] = tls_data.get("version")
                    endpoint_props = {k: v for k, v in endpoint_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                        SET e += $props,
                            e.updated_at = datetime()
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        """,
                        path=path, base_url=base_url, user_id=user_id, project_id=project_id, props=endpoint_props
                    )
                    stats.setdefault("endpoints_created", 0)
                    stats["endpoints_created"] += 1

                    self._tag_ip_from_httpx(session, url_info, user_id, project_id, stats)

                    # ---- BaseURL -[:HAS_ENDPOINT]-> Endpoint ------------------
                    session.run(
                        """
                        MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                        MERGE (u)-[:HAS_ENDPOINT]->(e)
                        """,
                        base_url=base_url, path=path,
                        user_id=user_id, project_id=project_id,
                    )
                    stats["relationships_created"] += 1

                    # Certificate from TLS data. Keyed on cert_key (not subject_cn),
                    # so empty-CN / SAN-only certs are stored and two scanners
                    # observing the same cert converge on one node.
                    if tls_data and tls_data.get("certificate"):
                        cert_data = tls_data.get("certificate", {})
                        subject_cn = cert_data.get("subject_cn") or ""
                        issuer_raw = cert_data.get("issuer")
                        issuer_str = ", ".join(issuer_raw) if isinstance(issuer_raw, list) else issuer_raw
                        not_before = cert_data.get("not_before")
                        not_after = cert_data.get("not_after")
                        fingerprint = cert_data.get("fingerprint_sha256") or cert_data.get("fingerprint")
                        cert_key = build_cert_key(
                            fingerprint_sha256=fingerprint, subject_cn=subject_cn,
                            issuer=issuer_str, not_before=not_before, not_after=not_after,
                        )

                        def _join(value):
                            if isinstance(value, list):
                                return ", ".join(str(v) for v in value if v)
                            return value

                        cert_props = {
                            "subject_cn": subject_cn or None,
                            "subject_dn": cert_data.get("subject_dn"),
                            "subject_org": _join(cert_data.get("subject_org")),
                            "issuer": issuer_str,
                            "issuer_cn": cert_data.get("issuer_cn"),
                            "issuer_dn": cert_data.get("issuer_dn"),
                            "issuer_org": _join(cert_data.get("issuer_org")),
                            "serial": cert_data.get("serial"),
                            "not_before": not_before,
                            "not_after": not_after,
                            "san": cert_data.get("san", []),  # full SAN list as presented
                            "cipher": tls_data.get("cipher"),
                            "tls_version": tls_data.get("version"),
                            # Phase 0.6: httpx already pays ~10 TLS handshakes for
                            # -jarm (default on) and writes it at the URL level,
                            # NOT inside tls.certificate -- so reading it from the
                            # cert dict found nothing and the fingerprint was
                            # thrown away every scan.
                            "jarm": (cert_data.get("jarm") or tls_data.get("jarm")
                                     or url_info.get("jarm")),
                            # Same verdicts the tlsx writer stores. None means the
                            # probe predates http_probe keeping them, and the
                            # filter below drops it, so an unknown never overwrites
                            # a verdict tlsx already wrote on the converged node.
                            "expired": cert_data.get("expired"),
                            "self_signed": cert_data.get("self_signed"),
                            "mismatched": cert_data.get("mismatched"),
                            "wildcard": cert_data.get("wildcard"),
                        }
                        if fingerprint:
                            cert_props["fingerprint_sha256"] = fingerprint
                        # Empty is "this scanner saw nothing", not "the cert has
                        # nothing". Since re-keying on cert_key makes sources
                        # converge on ONE node, a `SET c += {san: []}` here would
                        # erase a SAN list another source already stored.
                        cert_props = {k: v for k, v in cert_props.items()
                                      if v is not None and v != "" and v != []}

                        # source is first-writer provenance (ON CREATE); observed_by
                        # accumulates so a cross-source clear can tell sole vs shared.
                        session.run(
                            """
                            MERGE (c:Certificate {cert_key: $cert_key, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET c.source = 'http_probe'
                            SET c += $props,
                                c.observed_by = CASE WHEN 'http_probe' IN coalesce(c.observed_by, [])
                                                     THEN c.observed_by
                                                     ELSE coalesce(c.observed_by, []) + 'http_probe' END,
                                c.updated_at = datetime()
                            """,
                            cert_key=cert_key, user_id=user_id, project_id=project_id, props=cert_props
                        )
                        stats["certificates_created"] += 1

                        # Reconcile a pre-migration 'legacy:'-keyed duplicate of THIS
                        # cert. Scoped to recon-owned rows: matching on subject_cn
                        # alone deleted a GVM certificate that merely shared a
                        # common name, which is the cross-source data loss Phase
                        # 0.3 exists to prevent.
                        if subject_cn:
                            session.run(
                                """
                                MATCH (old:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                WHERE old.cert_key STARTS WITH 'legacy:'
                                  AND NOT coalesce(old.source, '') IN $non_recon
                                DETACH DELETE old
                                """,
                                subject_cn=subject_cn, user_id=user_id, project_id=project_id,
                                non_recon=list(NON_RECON_SOURCES)
                            )

                        # BaseURL -[:HAS_CERTIFICATE]-> Certificate: the documented
                        # anchor (a cert is presented per host:port, not per path).
                        session.run(
                            """
                            MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                            MATCH (c:Certificate {cert_key: $cert_key, user_id: $user_id, project_id: $project_id})
                            MERGE (u)-[:HAS_CERTIFICATE]->(c)
                            """,
                            base_url=base_url, cert_key=cert_key,
                            project_id=project_id, user_id=user_id
                        )
                        stats["relationships_created"] += 1

                    # Create relationship: Service -[:SERVES_URL]-> BaseURL
                    # BaseURLs are served by HTTP/HTTPS services running on ports
                    if host:
                        resolved_ip = url_info.get("ip")
                        # Extract actual port from URL (e.g., http://example.com:8080)
                        # Only use default ports (80/443) if no explicit port in URL
                        parsed_url = urlparse(url)
                        port_number = parsed_url.port or (443 if scheme == "https" else 80)
                        default_service_name = "https" if scheme == "https" else "http"

                        if resolved_ip:
                            # Check if a service already exists for this port/IP (from port scan)
                            # If so, reuse it instead of creating a duplicate with different name
                            existing_service = session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                RETURN svc.name as name LIMIT 1
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                user_id=user_id, project_id=project_id
                            ).single()

                            if existing_service:
                                # Use the existing service name (e.g., http-proxy from port scan)
                                service_name = existing_service["name"]
                            else:
                                # No existing service, create one with default name (http/https)
                                service_name = default_service_name
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                    SET svc.updated_at = datetime()
                                    """,
                                    service_name=service_name, port_number=port_number, ip_addr=resolved_ip,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["services_created"] += 1

                            # Create relationship: Service -[:SERVES_URL]-> BaseURL
                            # (Patch D: BaseURL is now host-level — one per Service)
                            session.run(
                                """
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                                MERGE (svc)-[:SERVES_URL]->(u)
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=resolved_ip, base_url=base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                            # Also ensure Port node exists and is connected to Service
                            session.run(
                                """
                                MERGE (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET p.state = 'open',
                                    p.updated_at = datetime()
                                WITH p
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                service_name=service_name,
                                user_id=user_id, project_id=project_id
                            )

                            # Also ensure IP -[:HAS_PORT]-> Port relationship exists
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=resolved_ip, port_number=port_number,
                                user_id=user_id, project_id=project_id
                            )

                    # Process technologies from both httpx and wappalyzer
                    # Track processed tech names to avoid duplicates
                    processed_techs = set()

                    # 1. Process technologies from httpx first
                    httpx_technologies = url_info.get("technologies", [])
                    for tech_str in httpx_technologies:
                        try:
                            # Parse technology string (e.g., "Nginx:1.19.0" or "Ubuntu")
                            if ":" in tech_str:
                                tech_name, tech_version = tech_str.split(":", 1)
                            else:
                                tech_name = tech_str
                                tech_version = None

                            # Get additional info from wappalyzer if available
                            wap_info = all_technologies.get(tech_name, {})
                            categories = wap_info.get("categories", [])
                            confidence = wap_info.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Land on the node another detector already wrote,
                            # whatever its spelling or version presence.
                            tech_name = resolve_tech_name(
                                session, tech_name, user_id, project_id)
                            tech_version = resolve_tech_version(
                                session, tech_name, tech_version, user_id, project_id)
                            tech_props["name"] = tech_name
                            tech_props["version"] = tech_version

                            # Create Technology node (unique by name + version + tenant)
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """ + _ADD_DETECTOR,
                                    name=tech_name, version=tech_version, props=tech_props,
                                    detector="httpx",
                                    user_id=user_id, project_id=project_id
                                )
                                processed_techs.add((tech_name_key(tech_name), tech_version))
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """ + _ADD_DETECTOR,
                                    name=tech_name, props=tech_props, detector="httpx",
                                    user_id=user_id, project_id=project_id
                                )
                                processed_techs.add((tech_name_key(tech_name), None))
                            stats["technologies_created"] += 1

                            # Create relationship: Endpoint -[:USES_TECHNOLOGY]-> Technology
                            # (Patch D: technologies are detected per-path-response → Endpoint)
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Technology {tech_str} failed: {e}")

                    # AI surface recon: MERGE Technology(category=ai-*) when the
                    # url_entry carries an AI framework / frontend annotation.
                    # (Patch D: edge now hangs off Endpoint, not BaseURL —
                    #  AI signals are observed at the response/path level.)
                    ai_name = url_info.get("ai_framework_name")
                    ai_category = url_info.get("ai_framework_category")
                    if ai_name and ai_category:
                        # Pick a precise detected_by based on which signal fired
                        if url_info.get("is_ai_framework_detected") and ai_name != url_info.get("ai_frontend_product_guess"):
                            ai_detected_by = "httpx-ai-header"
                        elif url_info.get("ai_frontend_product_guess") == ai_name:
                            # Favicon vs title — favicon wins when both fire. The
                            # parse_httpx_output annotator already prefers favicon,
                            # so distinguishing here requires inspecting the entry
                            # for an explicit favicon hit. We default to header
                            # for safety; favicon/title operators can refine in
                            # later phases when the favicon catalogue is filled.
                            ai_detected_by = "httpx-ai-favicon" if url_info.get("favicon_hash") else "httpx-ai-title"
                        else:
                            ai_detected_by = "httpx-ai-header"

                        try:
                            # MERGE on the version too: a MERGE without it creates
                            # a NULL-version node the uniqueness constraint ignores.
                            ai_tech = resolve_tech_name(session, ai_name, user_id, project_id)
                            ai_version = resolve_tech_version(
                                session, ai_tech, "", user_id, project_id)
                            session.run(
                                """
                                MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                SET t.category = $category,
                                    t.source = 'ai-surface-recon',
                                    t.updated_at = datetime()
                                """,
                                name=ai_tech, version=ai_version, category=ai_category,
                                user_id=user_id, project_id=project_id,
                            )
                            stats.setdefault("ai_technologies_created", 0)
                            stats["ai_technologies_created"] += 1

                            session.run(
                                """
                                MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                MERGE (e)-[r:USES_TECHNOLOGY]->(t)
                                SET r.detected_by = $detected_by,
                                    r.confidence = coalesce(r.confidence, 100)
                                """,
                                path=path, base_url=base_url, name=ai_tech, version=ai_version,
                                detected_by=ai_detected_by,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(
                                f"AI Technology {ai_name!r} on {url} failed: {e}"
                            )

                    # 2. Process wappalyzer technologies not found by httpx
                    # wappalyzer.by_url contains complete tech list per URL
                    # (plugins, analytics, security_tools, frameworks are just filtered subsets by category)
                    wappalyzer_by_url = wappalyzer.get("by_url", {})
                    wap_techs_for_url = wappalyzer_by_url.get(url, [])

                    for wap_tech in wap_techs_for_url:
                        try:
                            tech_name = wap_tech.get("name", "")
                            tech_version = wap_tech.get("version")  # Can be None

                            # Skip if already processed from httpx. Case-blind:
                            # the two spell some products differently.
                            if (tech_name_key(tech_name), tech_version) in processed_techs:
                                continue
                            # Also skip if httpx found it without version but wappalyzer has version
                            if (tech_name_key(tech_name), None) in processed_techs:
                                continue

                            categories = wap_tech.get("categories", [])
                            confidence = wap_tech.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Same twin-collapsing as the httpx path above: the two
                            # detectors disagree on version presence often (React
                            # 18.2.0 from httpx vs bare React from wappalyzer).
                            tech_name = resolve_tech_name(
                                session, tech_name, user_id, project_id)
                            tech_version = resolve_tech_version(
                                session, tech_name, tech_version, user_id, project_id)
                            tech_props["name"] = tech_name
                            tech_props["version"] = tech_version

                            # Create Technology node
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """ + _ADD_DETECTOR,
                                    name=tech_name, version=tech_version, props=tech_props,
                                    detector="wappalyzer",
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """ + _ADD_DETECTOR,
                                    name=tech_name, props=tech_props, detector="wappalyzer",
                                    user_id=user_id, project_id=project_id
                                )
                            stats["technologies_created"] += 1

                            # Create relationship: Endpoint -[:USES_TECHNOLOGY]-> Technology
                            # (Patch D: wappalyzer detects technologies from per-path responses → Endpoint)
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    path=path, base_url=base_url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Wappalyzer technology {tech_name} failed: {e}")

                    # Process headers
                    headers = url_info.get("headers", {})
                    security_headers = ["x-frame-options", "x-xss-protection", "content-security-policy",
                                        "strict-transport-security", "x-content-type-options"]
                    tech_revealing_headers = ["server", "x-powered-by", "x-aspnet-version"]

                    for header_name, header_value in headers.items():
                        try:
                            is_security = header_name.lower() in security_headers
                            reveals_tech = header_name.lower() in tech_revealing_headers

                            # (Patch D: Header keyed by full URL is fine — headers are
                            # response-specific. We MERGE per (name, value, full url)
                            # then link to the Endpoint that produced the response.)
                            session.run(
                                """
                                MERGE (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                SET h.user_id = $user_id,
                                    h.project_id = $project_id,
                                    h.is_security_header = $is_security,
                                    h.reveals_technology = $reveals_tech,
                                    h.updated_at = datetime()
                                """,
                                name=header_name, value=str(header_value), url=url,
                                user_id=user_id, project_id=project_id,
                                is_security=is_security, reveals_tech=reveals_tech
                            )
                            stats["headers_created"] += 1

                            # Create relationship: Endpoint -[:HAS_HEADER]-> Header
                            # (Patch D: headers come from a specific path response → Endpoint)
                            session.run(
                                """
                                MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url, user_id: $user_id, project_id: $project_id})
                                MATCH (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                MERGE (e)-[:HAS_HEADER]->(h)
                                """,
                                path=path, base_url=base_url, url=url,
                                name=header_name, value=str(header_value),
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Header {header_name} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"URL {url} processing failed: {e}")

            # Update Domain node with http probe metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            # The flat per-tool stamp goes on the org Domain (§4.11.3): a scan
            # root below its org has no Domain node of its own.
            if root_domain:
                root_domain = metadata.get("org_domain") or org_for_scan_root(root_domain, recon_data)
            summary = http_probe_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.http_probe_timestamp = $scan_timestamp,
                            d.http_probe_live_urls = $live_urls,
                            d.http_probe_technology_count = $tech_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        live_urls=summary.get("live_urls", 0),
                        tech_count=summary.get("technology_count", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            # --- Update Subdomain nodes with HTTP probe status ---
            by_host = http_probe_data.get("by_host", {})
            # IP mode probes the IP literal while the Subdomain node carries the
            # placeholder name minted for that IP ("21.40.250.84" -> "21-40-250-84").
            # A hostname the run scanned is keyed by its own name, which the map
            # never holds, so it keeps matching its own Subdomain.
            ip_to_hostname = (recon_data.get("metadata") or {}).get("ip_to_hostname") or {}
            for probed_host, host_info in by_host.items():
                hostname = ip_to_hostname.get(probed_host, probed_host)
                try:
                    status_codes = host_info.get("status_codes", [])  # already sorted int list
                    live_urls = host_info.get("live_urls", [])

                    # Determine status as the primary HTTP status code (string)
                    # Priority: lowest non-5xx code, then lowest overall
                    if status_codes:
                        non_error = [c for c in status_codes if c < 500]
                        primary = min(non_error) if non_error else min(status_codes)
                        http_status = str(primary)
                    else:
                        http_status = "no_http"

                    session.run(
                        """
                        MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                        SET s.status = $status,
                            s.status_codes = $status_codes,
                            s.http_live_url_count = $live_count,
                            s.http_probed_at = datetime(),
                            s.updated_at = datetime()
                        """,
                        hostname=hostname, user_id=user_id, project_id=project_id,
                        status=http_status, status_codes=status_codes,
                        live_count=len(live_urls)
                    )
                    stats["subdomains_updated"] += 1
                except Exception as e:
                    stats["errors"].append(f"Subdomain status update for {hostname}: {e}")

            # Mark resolved subdomains that got no HTTP response at all as "no_http".
            # Translated like the loop above, or every live IP-mode host is demoted.
            all_probed_hosts = set(by_host.keys())
            all_probed_hosts |= {ip_to_hostname[h] for h in all_probed_hosts if h in ip_to_hostname}
            all_target_subs = set(recon_data.get("subdomains", []))
            no_response_hosts = all_target_subs - all_probed_hosts
            if no_response_hosts:
                session.run(
                    """
                    UNWIND $hosts AS hostname
                    MATCH (s:Subdomain {name: hostname, user_id: $user_id, project_id: $project_id})
                    WHERE s.status = 'resolved'
                    SET s.status = 'no_http',
                        s.http_probed_at = datetime(),
                        s.updated_at = datetime()
                    """,
                    hosts=list(no_response_hosts), user_id=user_id, project_id=project_id
                )

            self._mark_shared_body_clusters(session, user_id, project_id, stats)

            print(f"[+][graph-db] Created {stats['baseurls_created']} BaseURL nodes")
            print(f"[+][graph-db] Created/Updated {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['technologies_created']} Technology nodes")
            print(f"[+][graph-db] Created {stats['headers_created']} Header nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Updated {stats['subdomains_updated']} Subdomain statuses")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    @staticmethod
    def _tag_ip_from_httpx(session, url_info: dict, user_id: str, project_id: str,
                           stats: dict) -> None:
        """Carry httpx's CDN and ASN to the resolved IP, which IP attribution reads.

        Only ever adds: is_cdn never goes from true to false, a cdn_name or asn
        another tool wrote first is kept, and cdn_source is 'httpx' only when no
        tool had tagged the address. Matches the tenant-scoped IP, never creates
        one. A failure costs this tag only, never the Endpoint.
        """
        ip = url_info.get("ip")
        is_cdn = bool(url_info.get("is_cdn"))
        asn = _asn_label(url_info.get("asn"))
        if not ip or not (is_cdn or asn):
            return
        try:
            session.run(
                """
                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                WITH i, coalesce(i.is_cdn, false) AS already_tagged
                SET i.cdn_source = CASE WHEN $is_cdn AND NOT already_tagged THEN 'httpx'
                                        ELSE i.cdn_source END,
                    i.is_cdn = CASE WHEN $is_cdn THEN true ELSE i.is_cdn END,
                    i.cdn_name = coalesce(i.cdn_name, $cdn_name),
                    i.asn = coalesce(i.asn, $asn)
                """,
                ip=ip, is_cdn=is_cdn, cdn_name=(url_info.get("cdn") or None) if is_cdn else None,
                asn=asn, user_id=user_id, project_id=project_id,
            )
        except Exception as e:
            stats["errors"].append(f"httpx IP tag {ip}: {e}")

    @staticmethod
    def _mark_shared_body_clusters(session, user_id: str, project_id: str, stats: dict) -> None:
        """Mark root Endpoints whose body many BaseURLs share (shared_body_cluster).

        Recomputed over the whole project on every http_probe write, full or
        partial, because a partial run does not recreate Endpoints: an Endpoint
        whose host now serves its own page loses the mark here. The mark tracks
        target state, so it moves no `updated_at`.
        """
        try:
            row = session.run(
                """
                MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})-[:HAS_ENDPOINT]->
                      (e:Endpoint {user_id: $user_id, project_id: $project_id, path: '/'})
                WHERE e.body_sha256 IS NOT NULL AND e.status_code IN $statuses
                WITH e.body_sha256 AS body, collect(DISTINCT bu.url) AS bases, collect(DISTINCT e) AS eps
                WHERE size(bases) >= $min_bases
                UNWIND eps AS e
                SET e.shared_body_cluster = size(bases)
                RETURN collect(elementId(e)) AS clustered
                """,
                user_id=user_id, project_id=project_id, statuses=[200, 403],
                min_bases=SHARED_BODY_MIN_BASEURLS,
            ).single()
            clustered = list((row or {}).get("clustered") or [])
            session.run(
                """
                MATCH (e:Endpoint {user_id: $user_id, project_id: $project_id})
                WHERE e.shared_body_cluster IS NOT NULL AND NOT elementId(e) IN $clustered
                REMOVE e.shared_body_cluster
                """,
                user_id=user_id, project_id=project_id, clustered=clustered,
            )
            stats["shared_body_endpoints"] = len(clustered)
            if clustered:
                print(f"[+][graph-db] {len(clustered)} root Endpoint(s) serve a page "
                      f"{SHARED_BODY_MIN_BASEURLS}+ BaseURLs share (shared_body_cluster)")
        except Exception as e:
            stats["errors"].append(f"shared body cluster pass failed: {e}")

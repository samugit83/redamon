"""tlsx TLS certificate grab graph updates.

Writes, all tenant-scoped on {natural_key, user_id, project_id}:
  - Certificate           MERGEd on cert_key (Phase 0.2 shared key)
  - (IP)-[:HAS_CERTIFICATE]->(Certificate)   the documented non-HTTP TLS anchor
  - (Certificate)-[:COVERS_HOST]->(Subdomain) per in-scope SAN entry, so SAN
        data is traversable instead of a dead list property
  - Service enrichment: advisory TLS props on the EXISTING Service node
        (never a rename -- name is part of the Service MERGE key, so writing a
        different one orphans the node)

Certificate properties: cert_key, subject_cn, subject_dn, subject_org, san,
issuer_cn, issuer_dn, issuer, issuer_org, serial, fingerprint_sha256,
not_before, not_after, expired, self_signed, mismatched, revoked, untrusted,
wildcard, jarm, ja3, ja3s. source is ON CREATE (first-writer); observed_by
appends 'tlsx'.

Service properties: tls, tls_version, tls_cipher, tls_key_exchange,
tls_connection, tls_service_hint, tls_versions_supported, tls_ciphers_weak,
tls_probe_failed, tls_probe_error.
"""

from __future__ import annotations

from datetime import datetime, timezone

from graph_db.cert_key import build_cert_key
from graph_db.schema import NON_RECON_SOURCES


def _join(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    return value


def _weak_cipher_names(cipher_enum) -> list:
    """Flatten tlsx's `-ce -ct weak` output to cipher names.

    H7: tlsx reports one envelope per TLS version -- `[{"version": "tls12",
    "ciphers": {...}}]` -- and Neo4j refuses a list of maps as a property
    ("Property values can only be of primitive types or arrays thereof"). The
    whole `SET svc += $props` was rejected, so enabling the "Enumerate weak
    ciphers" toggle silently wiped tls, tls_version, tls_cipher AND
    tls_service_hint off every Service, and the error went into a stats list
    nothing printed.

    Duplicated from recon/helpers/security_checks.py on purpose: graph_db must
    not import recon.
    """
    names = []
    for entry in cipher_enum or []:
        if isinstance(entry, str):
            names.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        ciphers = entry.get("ciphers")
        buckets = ciphers.values() if isinstance(ciphers, dict) else [ciphers]
        for bucket in buckets:
            if isinstance(bucket, list):
                names.extend(str(c) for c in bucket if c)
            elif bucket:
                names.append(str(bucket))
    seen = set()
    return [n for n in names if not (n in seen or seen.add(n))]


def _primitive_list(value) -> list:
    """Only arrays of primitives survive as Neo4j properties."""
    return [str(v) for v in (value or []) if v is not None and not isinstance(v, (dict, list))]


class TlsxMixin:
    def update_graph_from_tlsx(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "certificates_created": 0, "relationships_created": 0,
            "services_enriched": 0, "covers_host_edges": 0, "errors": [],
        }
        tlsx_data = recon_data.get("tlsx") or {}
        by_target = tlsx_data.get("by_target") or {}
        if not by_target:
            return stats

        domain = (
            recon_data.get("domain")
            or (recon_data.get("metadata") or {}).get("target", "")
            or ""
        ).strip().lower()

        def _in_scope(name: str) -> bool:
            # Fail closed without an apex (batch mode empties it): only link a
            # cert to a Subdomain that is genuinely in this group's scope.
            return bool(domain) and (name == domain or name.endswith("." + domain))

        with self.driver.session() as session:
            for key, entry in by_target.items():
                if not isinstance(entry, dict):
                    continue
                scanned_ip = entry.get("scanned_ip") or (key.rsplit(":", 1)[0] if ":" in key else key)
                port = entry.get("port")

                # --- Service enrichment (advisory; never a rename) -------------
                try:
                    if port is not None:
                        if entry.get("probe_status"):
                            svc_props = {
                                "tls": True,
                                "tls_version": entry.get("tls_version"),
                                "tls_cipher": entry.get("cipher"),
                                "tls_key_exchange": entry.get("key_exchange"),
                                "tls_connection": entry.get("tls_connection"),
                                "tls_service_hint": entry.get("tls_service_hint"),
                                "tls_versions_supported": _primitive_list(
                                    entry.get("version_enum")) or None,
                                "tls_ciphers_weak": _weak_cipher_names(
                                    entry.get("cipher_enum")) or None,
                                "tls_probe_failed": False,
                                "tls_updated_at": datetime.now(timezone.utc).isoformat(),
                            }
                        else:
                            svc_props = {
                                "tls_probe_failed": True,
                                "tls_probe_error": entry.get("error") or "no TLS",
                                "tls_updated_at": datetime.now(timezone.utc).isoformat(),
                            }
                        svc_props = {k: v for k, v in svc_props.items() if v is not None}
                        res = session.run(
                            """
                            MATCH (svc:Service {port_number: $port, ip_address: $ip,
                                                user_id: $uid, project_id: $pid})
                            SET svc += $props
                            RETURN count(svc) AS matched
                            """,
                            port=port, ip=scanned_ip, uid=user_id, pid=project_id, props=svc_props,
                        )
                        row = res.single()
                        if row and row["matched"]:
                            stats["services_enriched"] += 1
                except Exception as e:
                    stats["errors"].append(f"tlsx service {key}: {e}")

                # No usable certificate on this target: nothing more to write.
                if not (entry.get("fingerprint_sha256") or entry.get("subject_cn")):
                    continue

                # --- Certificate --------------------------------------------
                try:
                    subject_cn = entry.get("subject_cn") or ""
                    issuer_dn = entry.get("issuer_dn")
                    issuer_cn = entry.get("issuer_cn")
                    fingerprint = entry.get("fingerprint_sha256")
                    cert_key = build_cert_key(
                        fingerprint_sha256=fingerprint, subject_cn=subject_cn,
                        issuer=issuer_dn or issuer_cn,
                        not_before=entry.get("not_before"), not_after=entry.get("not_after"),
                    )
                    cert_props = {
                        "subject_cn": subject_cn or None,
                        "subject_dn": entry.get("subject_dn"),
                        "subject_org": _join(entry.get("subject_org")),
                        "san": entry.get("san") or [],
                        "issuer_cn": issuer_cn,
                        "issuer_dn": issuer_dn,
                        "issuer": issuer_dn or issuer_cn,
                        "issuer_org": _join(entry.get("issuer_org")),
                        "serial": entry.get("serial"),
                        "fingerprint_sha256": fingerprint,
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                        "expired": bool(entry.get("expired")),
                        "self_signed": bool(entry.get("self_signed")),
                        "mismatched": bool(entry.get("mismatched")),
                        "revoked": bool(entry.get("revoked")),
                        "untrusted": bool(entry.get("untrusted")),
                        "wildcard": bool(entry.get("wildcard")),
                        "jarm": entry.get("jarm"),
                        "ja3": entry.get("ja3"),
                        "ja3s": entry.get("ja3s"),
                    }
                    # Empty is "not observed", not "absent on the cert": dropping
                    # "" / [] keeps a SAN-less observation from erasing SANs another
                    # source stored on the same cert_key. `False` survives the
                    # filter, so the hygiene booleans above are still written.
                    cert_props = {k: v for k, v in cert_props.items()
                                  if v is not None and v != "" and v != []}

                    session.run(
                        """
                        MERGE (c:Certificate {cert_key: $cert_key, user_id: $uid, project_id: $pid})
                        ON CREATE SET c.source = 'tlsx'
                        SET c += $props,
                            c.observed_by = CASE WHEN 'tlsx' IN coalesce(c.observed_by, [])
                                                 THEN c.observed_by
                                                 ELSE coalesce(c.observed_by, []) + 'tlsx' END,
                            c.updated_at = datetime()
                        WITH c
                        MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                        MERGE (i)-[:HAS_CERTIFICATE]->(c)
                        """,
                        cert_key=cert_key, uid=user_id, pid=project_id,
                        props=cert_props, ip=scanned_ip,
                    )
                    stats["certificates_created"] += 1
                    stats["relationships_created"] += 1

                    # Reconcile a pre-migration legacy-keyed duplicate.
                    if subject_cn:
                        session.run(
                            """
                            MATCH (old:Certificate {subject_cn: $cn, user_id: $uid, project_id: $pid})
                            WHERE old.cert_key STARTS WITH 'legacy:'
                              AND NOT coalesce(old.source, '') IN $non_recon
                            DETACH DELETE old
                            """,
                            cn=subject_cn, uid=user_id, pid=project_id,
                            non_recon=list(NON_RECON_SOURCES),
                        )

                    # --- COVERS_HOST for each in-scope SAN --------------------
                    for san_name in entry.get("san") or []:
                        name = (san_name or "").strip().lower().lstrip("*.")
                        if not name or not _in_scope(name):
                            continue
                        try:
                            session.run(
                                """
                                MATCH (c:Certificate {cert_key: $cert_key, user_id: $uid, project_id: $pid})
                                MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                                  ON CREATE SET s.source = 'tlsx_san', s.updated_at = datetime()
                                MERGE (c)-[:COVERS_HOST]->(s)
                                """,
                                cert_key=cert_key, name=name, uid=user_id, pid=project_id,
                            )
                            stats["covers_host_edges"] += 1
                        except Exception as e:
                            stats["errors"].append(f"tlsx covers_host {name}: {e}")
                except Exception as e:
                    stats["errors"].append(f"tlsx cert {key}: {e}")

        print(f"[*][graph-db] tlsx: {stats['certificates_created']} cert(s), "
              f"{stats['services_enriched']} service(s), {stats['covers_host_edges']} COVERS_HOST edge(s)")
        # A swallowed write is how H7 stayed hidden: every Service enrichment
        # failed on a Neo4j type error while the counts above read as a clean
        # run. Surface the first few rather than burying them in the return.
        if stats["errors"]:
            print(f"[!][graph-db] tlsx: {len(stats['errors'])} graph write error(s); "
                  f"first: {stats['errors'][0]}")
        return stats

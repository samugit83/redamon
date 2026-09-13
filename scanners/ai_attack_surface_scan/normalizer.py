"""Shared spine piece 3 — the findings normalizer (§6.3, §7).

Every tool has its own native parser; all parsers emit the SAME Finding shape,
which this module maps onto the existing `Vulnerability` label using the fields
the schema reserves for this lap (ai_owasp_llm_id, ai_asr, ai_trials, ...).
Zero new node labels. Findings link to the attacked Endpoint via
HAS_VULNERABILITY. When the target is custom / off-graph (no Endpoint exists),
the normalizer materialises the target node chain (BaseURL -> Endpoint, anchored
to a Subdomain+Domain or IP) marked ``source='ai_attack_target'`` so the finding
is never a disconnected island -- the same approach partial recon uses for
user-typed inputs.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("ai-attack-surface")


@dataclass
class Finding:
    """The unified finding shape every tool adapter emits (§7)."""
    source: str                      # garak / pyrit / giskard / promptfoo / skeleton
    chip: str                        # prompt-injection / jailbreak / ...
    name: str
    baseurl: str
    path: str = "/"
    severity: str = "medium"
    description: str = ""
    ai_owasp_llm_id: str | None = None      # LLM01..LLM10
    ai_atlas_technique: str | None = None    # MITRE ATLAS AML.T*
    ai_asr: float = 0.0                       # attack success rate over trials
    ai_trials: int = 0
    ai_oracle_kind: str = "none"             # regex/contains/judge_llm/length/latency
    ai_payload_class: str = ""               # e.g. garak-promptinject
    ai_transcript_ref: str | None = None
    ai_probe_pack_version: str | None = None
    evidence: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def vuln_type(self) -> str:
        return f"ai_attack_{self.chip.replace('-', '_')}"


def finding_id(finding: Finding) -> str:
    """Deterministic id so dedup keys on OWASP-LLM id + target + payload class
    (§6.3): re-running the same tool against the same target updates rather than
    duplicates. Mirrors ai_surface_recon's aisr_<sha16> convention."""
    key = "|".join([
        finding.source,
        finding.ai_owasp_llm_id or finding.chip,
        finding.ai_payload_class or finding.chip,
        finding.baseurl or "",
        finding.path or "/",
    ])
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"aiatk_{digest}"


def _target_url(finding: Finding) -> str:
    base = (finding.baseurl or "").rstrip("/")
    path = finding.path or "/"
    if path and not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _props(finding: Finding, vid: str, user_id: str, project_id: str) -> dict:
    return {
        "id": vid,
        "user_id": user_id,
        "project_id": project_id,
        "source": finding.source,
        "type": finding.vuln_type,
        # The attacked URL, stored on the finding so custom (off-graph) targets
        # still display a target even when no Endpoint node exists to link to.
        "ai_target_url": _target_url(finding),
        "name": finding.name,
        "severity": (finding.severity or "medium").lower(),
        "description": finding.description or finding.name,
        "evidence": finding.evidence,
        "ai_owasp_llm_id": finding.ai_owasp_llm_id,
        "ai_atlas_technique": finding.ai_atlas_technique,
        "ai_asr": float(finding.ai_asr),
        "ai_trials": int(finding.ai_trials),
        "ai_oracle_kind": finding.ai_oracle_kind,
        "ai_payload_class": finding.ai_payload_class,
        "ai_transcript_ref": finding.ai_transcript_ref,
        "ai_probe_pack_version": finding.ai_probe_pack_version,
    }


def write_finding(session, finding: Finding, user_id: str, project_id: str,
                  target=None) -> str:
    """MERGE the Vulnerability and connect it into the graph. Never orphans.

    Linking strategy (a finding must ALWAYS end up connected, §6.3):
      1. If the attacked Endpoint already exists -> HAS_VULNERABILITY to it.
      2. Otherwise MATERIALISE the target: create the BaseURL -> Endpoint chain
         (marked ``source='ai_attack_target'``, ``ai_attack_synthetic=true``),
         anchor it to a host node (Subdomain+Domain for a hostname, IP for a raw
         IP), and link the finding to the new Endpoint. This mirrors how partial
         recon materialises user-typed inputs, so a custom (off-graph) target is
         never a disconnected island.

    ``target`` (a target_loader.Target, optional) supplies the request method and
    AI annotations (ai_interface_type / ai_model_ids) stamped on a created node.

    Returns "existing" (linked to a pre-existing Endpoint), "created" (target
    materialised), or "" only on an unexpected write failure.
    """
    vid = finding_id(finding)
    props = _props(finding, vid, user_id, project_id)

    session.run(
        """
        MERGE (v:Vulnerability {id: $id, user_id: $props.user_id,
                                project_id: $props.project_id})
        ON CREATE SET v.first_seen = datetime()
        SET v += $props, v.updated_at = datetime()
        """,
        id=vid, props=props,
    )

    base_url = finding.baseurl
    path = finding.path or "/"

    # Tier 1: link to an Endpoint that recon already discovered for this target.
    linked = session.run(
        """
        MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
        OPTIONAL MATCH (e:Endpoint {baseurl: $baseurl, user_id: $uid, project_id: $pid})
          WHERE e.path = $path
        // Prefer the AI-typed endpoint over a bare sibling on the same path.
        WITH v, e ORDER BY (CASE WHEN e.ai_interface_type IS NOT NULL THEN 0 ELSE 1 END) LIMIT 1
        FOREACH (_ IN CASE WHEN e IS NOT NULL THEN [1] ELSE [] END |
            MERGE (e)-[:HAS_VULNERABILITY]->(v))
        RETURN e IS NOT NULL AS linked
        """,
        id=vid, baseurl=base_url, path=path, uid=user_id, pid=project_id,
    ).single()

    if linked and linked.get("linked"):
        return "existing"

    # Tier 2: no Endpoint exists (custom / off-graph target, or recon lost it) ->
    # materialise the target node chain and link, so the finding is never orphaned.
    _ensure_target_node(session, finding, vid, user_id, project_id, target)
    return "created"


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    """Naive eTLD+1 (no PSL): keep the last two labels, else the host itself.
    Good enough to give a created Subdomain a Domain anchor to hang off."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else host


def _ensure_target_node(session, finding: Finding, vid: str,
                        user_id: str, project_id: str, target=None) -> None:
    """Create the attacked target's node chain and link the finding to it.

    Builds ``BaseURL -[:HAS_ENDPOINT]-> Endpoint -[:HAS_VULNERABILITY]-> Vuln``
    (always connected) and anchors the BaseURL to a host root so it joins the
    graph rather than floating: a hostname gets ``Domain -[:HAS_SUBDOMAIN]->
    Subdomain -[:HAS_BASE_URL]-> BaseURL``; a raw IP gets ``IP -[:HAS_VULNERABILITY]
    -> Vuln`` (the IP, Endpoint and BaseURL share the one Vulnerability node, so
    the whole thing is a single connected component). Created nodes carry
    ``source='ai_attack_target'`` + ``ai_attack_synthetic=true`` so they are
    distinguishable from recon-discovered nodes and never overwrite them.
    """
    base_url = finding.baseurl or ""
    path = finding.path or "/"
    method = (getattr(target, "method", None) or "POST")
    iface = getattr(target, "ai_interface_type", None)
    model_ids = getattr(target, "ai_model_ids", None)
    parsed = urlparse(base_url)
    host = parsed.hostname or ""

    # BaseURL + Endpoint + the finding edge.
    session.run(
        """
        MERGE (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
          ON CREATE SET b.source = 'ai_attack_target', b.ai_attack_synthetic = true,
                        b.scheme = $scheme, b.host = $host, b.created_at = datetime()
        SET b.updated_at = datetime()
        MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl,
                           user_id: $uid, project_id: $pid})
          ON CREATE SET e.source = 'ai_attack_target', e.ai_attack_synthetic = true,
                        e.created_at = datetime()
        SET e.ai_interface_type = COALESCE($iface, e.ai_interface_type),
            e.ai_model_ids      = COALESCE($models, e.ai_model_ids),
            e.updated_at = datetime()
        MERGE (b)-[:HAS_ENDPOINT]->(e)
        WITH e
        MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
        MERGE (e)-[:HAS_VULNERABILITY]->(v)
        """,
        baseurl=base_url, path=path, method=method, uid=user_id, pid=project_id,
        scheme=parsed.scheme or "http", host=host, iface=iface, models=model_ids, id=vid,
    )

    if not host:
        return

    if _is_ip(host):
        # No IP-[:HAS_BASE_URL] in the schema; anchor the IP to the shared
        # Vulnerability (vhost_sni precedent) so the component stays connected.
        session.run(
            """
            MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
            MERGE (ip:IP {address: $host, user_id: $uid, project_id: $pid})
              ON CREATE SET ip.source = 'ai_attack_target', ip.ai_attack_synthetic = true,
                            ip.created_at = datetime()
            SET ip.updated_at = datetime()
            MERGE (ip)-[:HAS_VULNERABILITY]->(v)
            """,
            id=vid, host=host, uid=user_id, pid=project_id,
        )
    else:
        session.run(
            """
            MATCH (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
            MERGE (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
              ON CREATE SET s.source = 'ai_attack_target', s.ai_attack_synthetic = true,
                            s.updated_at = datetime()
            MERGE (s)-[:HAS_BASE_URL]->(b)
            MERGE (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
              ON CREATE SET d.source = 'ai_attack_target', d.ai_attack_synthetic = true,
                            d.updated_at = datetime()
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """,
            baseurl=base_url, host=host, domain=_registrable(host),
            uid=user_id, pid=project_id,
        )


def make_dummy_finding(target, tool: str, run_id: str) -> Finding:
    """Step 2 skeleton: a hardcoded dummy finding per target, proving the
    graph-in / findings-out loop without any real attack tool."""
    return Finding(
        source=tool,
        chip="prompt-injection",
        name="AI Attack Surface skeleton dummy finding",
        baseurl=target.baseurl,
        path=target.path,
        severity="info",
        description=(
            "Placeholder finding emitted by the AI Attack Surface skeleton "
            "(no tool ran). Proves graph read -> normalize -> Vulnerability write."
        ),
        ai_owasp_llm_id="LLM01",
        ai_payload_class=f"{tool}-skeleton-dummy",
        ai_oracle_kind="none",
        ai_asr=0.0,
        ai_trials=0,
        ai_probe_pack_version=f"skeleton/{run_id or 'dev'}",
        evidence=f"interface={target.ai_interface_type} model={target.ai_model_family_guess}",
    )

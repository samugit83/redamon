"""Group findings by "what the fix is". Deterministic, no LLM.

A group is ONE PROBLEM, ONE FIX, ONE FUTURE REMEDIATION. The same CVE on three
hosts is one upgrade, not three tickets; eleven advisories on one package are one
version bump.

The key is a string stored on the node as `triage_group_key`, and it replaces
`triage_cluster_id`, which an LLM produced and the UI never read. Three reasons
the model does not do this any more:

- its output could not be verified in code, so a bad grouping was invisible;
- it cost a call per run for a job that is a lookup table;
- it was not stable, so the same graph grouped differently twice.

TWO RULES THAT ARE NOT OBVIOUS

1. **The affected hosts are members, not part of the key.** That is the whole
   point: if the host were in the key, the same CVE on three hosts would be
   three groups again.
2. **A key never contains a secret value**, only a hash of it. The key is stored
   on the node, returned to the browser and used as a Postgres unique key, so a
   raw value here would leak into all three.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

#: Postgres indexes this as a unique key and Neo4j stores it as a property, so
#: it is capped rather than left to whatever a scanner put in a title.
MAX_KEY_LENGTH = 200

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _slug(value, cap: int = 80) -> str:
    """A key-safe fragment: lowercase, no whitespace, no surprises.

    Colons survive on purpose: a purl IS `pkg:npm/lodash`, and stripping them
    turned every package key into `pkgnpm/lodash`. The key is only ever read by
    its prefix, so an inner colon is not ambiguous.
    """
    text = str(value or "").strip().lower()
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^a-z0-9._/@+:-]", "", text)
    return text[:cap]


def _hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8", "replace")).hexdigest()[:32]


def _lowest_cve(finding: dict) -> str:
    """The alphabetically lowest CVE id on this finding, or ''.

    Lowest rather than first: the order a writer stores CVE ids in is not
    stable, and an unstable key would split a group across two runs.
    """
    candidates = set()
    for value in (finding.get("cve_ids") or []):
        match = _CVE_RE.search(str(value))
        if match:
            candidates.add(match.group(0).upper())
    for field in ("name", "id", "description"):
        match = _CVE_RE.search(str(finding.get(field) or ""))
        if match:
            candidates.add(match.group(0).upper())
    return min(candidates) if candidates else ""


_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$",
                         re.I)


def _route_template(path: str) -> str:
    """`/api/v1/orders/42` -> `/api/v1/orders/:id`: numeric, UUID and long-hex
    segments are one route, so their exposures share one fix. `:id` survives
    `_slug`, which strips braces."""
    return "/".join(":id" if _ID_SEGMENT.match(seg) else seg for seg in (path or "/").split("/")) or "/"


def group_key(finding: dict) -> str:
    """The key for one finding. Always returns something; never raises."""
    finding = finding or {}
    source = str(finding.get("source") or "").strip().lower()
    label = str(finding.get("label") or "")
    finding_id = str(finding.get("id") or "")

    # A CVE is the strongest signal there is: one upgrade fixes every finding
    # that names it, whoever reported it. This also merges an ExploitGvm with
    # the vulnerability it exploits, which used to be scored twice (C9).
    cve = _lowest_cve(finding)
    if cve:
        return f"cve:{cve.lower()}"[:MAX_KEY_LENGTH]

    if source in ("osv", "retirejs", "guarddog") or label == "MalPackageFinding":
        if str(finding_id).upper().startswith("MAL-"):
            return f"malpkg:{_slug(finding_id)}"[:MAX_KEY_LENGTH]
        package = finding.get("package_purl") or finding.get("package_name")
        if package:
            # One upgrade fixes every advisory on that package, so the package
            # is the key and the advisories are the members. A purl already
            # starts with "pkg:", so it is not repeated.
            slug = _slug(package, 140)
            return (slug if slug.startswith("pkg:")
                    else f"pkg:{slug}")[:MAX_KEY_LENGTH]
        return f"advisory:{_slug(finding_id)}"[:MAX_KEY_LENGTH]

    if source == "nuclei":
        template = finding.get("template_id")
        if template:
            return f"nuclei:{_slug(template, 140)}"[:MAX_KEY_LENGTH]

    if source == "gvm" or label == "ExploitGvm":
        oid = finding.get("oid") or finding_id
        return f"gvm:{_slug(oid, 140)}"[:MAX_KEY_LENGTH]

    if source == "security_check":
        check = _slug(finding.get("type") or finding.get("name"))
        header = _slug(finding.get("missing_header") or "", 60)
        return (f"check:{check}:{header}" if header else f"check:{check}")[:MAX_KEY_LENGTH]

    # The four branches below read the properties their writers store. When a
    # node lacks them (an older or imported one), the finding falls through to
    # its own group: a key with empty parts would make every finding of that
    # source one fix item.
    if source == "takeover_scan":
        provider = _slug(finding.get("takeover_provider"))
        if provider:
            return f"takeover:{provider}:{_slug(finding.get('takeover_method'))}"[:MAX_KEY_LENGTH]

    if source == "cache_poisoning":
        # One fix per technique and unkeyed input (a header, a parameter, or a
        # deception URL shape); the hosts that share it are members.
        technique = _slug(finding.get("cache_technique"))
        vector = _slug(finding.get("cache_header") or finding.get("cache_param"))
        if technique or vector:
            return f"cache:{technique}:{vector}"[:MAX_KEY_LENGTH]

    if source in ("graphql_scan", "graphql_cop"):
        # The GraphQL writer stores no `name`, only `vulnerability_type`.
        kind = _slug(finding.get("vulnerability_type") or finding.get("name"))
        if kind:
            return f"graphql:{kind}"[:MAX_KEY_LENGTH]

    if source in ("ai_surface_recon", "ai_attack", "garak", "pyrit",
                  "promptfoo", "giskard"):
        owasp = _slug(finding.get("ai_owasp_llm_id"))
        payload = _slug(finding.get("ai_payload_class"))
        if owasp or payload:
            return f"ai:{owasp}:{payload}"[:MAX_KEY_LENGTH]

    if label in ("Secret", "GithubSecret", "MultiscannerFinding"):
        # Hash the VALUE when one is stored, so the same leaked key found in
        # three places is one rotation. The value never enters the key itself:
        # this string is stored on the node, sent to the browser and used as a
        # Postgres unique key.
        value = (finding.get("matched_text") or finding.get("raw_secret")
                 or finding.get("secret_value") or finding.get("sample"))
        if value:
            return f"secret:{_hash(str(value))}"[:MAX_KEY_LENGTH]
        detector = _slug(finding.get("detector_name") or finding.get("secret_type"))
        location = _slug(finding.get("triage_host") or finding.get("host"), 60)
        return f"secret:{detector}:{location}"[:MAX_KEY_LENGTH]

    if label == "GithubSensitiveFile":
        return (f"ghfile:{_slug(finding.get('triage_host') or finding.get('host'), 60)}:"
                f"{_slug(finding.get('path') or finding.get('name'), 100)}")[:MAX_KEY_LENGTH]

    if label == "JsReconFinding" or source in ("js_recon", "jsluice"):
        return (f"js:{_slug(finding.get('finding_type'))}:"
                f"{_slug(finding.get('name') or finding.get('package_name'), 100)}")[:MAX_KEY_LENGTH]

    if source == "route_exposure":
        # Only projected fields: type and matched_at (fact_queries.py).
        kind = _slug(finding.get("type"))
        try:
            parts = urlparse(str(finding.get("matched_at") or ""))
            host, path = parts.hostname or "", parts.path
        except ValueError:
            host, path = "", ""
        if kind in ("cors_credentialed_origin_reflection", "authenticated_content_cacheable"):
            # A header policy is set once per application: one fix covers the host.
            return f"route:{kind}:{_slug(host, 60)}"[:MAX_KEY_LENGTH]
        # The same exposed path on several hosts is one deployment fix.
        return f"route:{kind}:{_slug(_route_template(path), 100)}"[:MAX_KEY_LENGTH]

    # Nothing matched: the finding is its own group, so it still gets a
    # remediation rather than silently sharing one with an unrelated finding.
    return f"finding:{_slug(finding_id, 150)}"[:MAX_KEY_LENGTH]


def assign_groups(scored: list) -> dict:
    """Stamp `group_key` on every row and return the groups, best first.

    The group's risk is 1 - PROD(1 - r) over its OPEN members: the probability
    that at least one of them gets exploited. More affected hosts raise it with
    diminishing returns, and it never exceeds 1. The group's tier is its best
    member's.

    A member is read through its `group_view` when the run has combined the
    layers (else its own base values). A false positive decided by a person or
    by the built-in AI leaves the group; one an external agent's review called
    keeps its member, so a review over MCP can never silently delete a fix item
    (product decision P2). The orchestrator builds that view.
    """
    from . import score_model

    groups: dict = {}
    for row in scored:
        key = group_key(row.get("_row") or row)
        row["group_key"] = key
        groups.setdefault(key, []).append(row)

    result = {}
    for key, members in groups.items():
        views = [(m, m.get("group_view") or m) for m in members]
        live = [m for m, view in views if view.get("state") == score_model.STATE_OPEN]
        live_views = [view for _, view in views if view.get("state") == score_model.STATE_OPEN]
        risks = [float(view.get("risk") or 0.0) for view in live_views]
        tier = score_model.best_tier([view.get("tier", "T4") for view in live_views]) \
            if live_views else "T4"
        risk = score_model.group_risk(risks) if risks else 0.0
        result[key] = {
            "key": key,
            "members": members,
            "live_members": live,
            "risk": risk,
            "tier": tier,
            "score": score_model.score_for(tier, risk) if live else 0.0,
        }
    return result


def ordered_groups(groups: dict) -> list:
    """Groups in board order: score first, then the key as a stable tiebreak."""
    return sorted(groups.values(),
                  key=lambda g: (-float(g["score"]), str(g["key"])))

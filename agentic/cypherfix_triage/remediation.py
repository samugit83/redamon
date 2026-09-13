"""Turn groups into remediations. One group, one fix, one item.

WHAT CHANGED AND WHY
The remediations used to come from a second LLM run that read a 20,000-character
truncated dump of the graph — cut mid-JSON, in no particular order — invented its
own priority from a stale weight table, capped itself at 20 items, and returned
NOTHING at all if it hit its iteration limit. On a large project it never saw
most of the findings. Nothing linked a remediation back to the findings it was
for, so de-duplication relied on the model's wording.

Now the shape is fixed and the model only writes prose:

- WHICH groups get a remediation, and in WHAT ORDER: the score, computed in code.
- affectedAssets, cveIds, cvssScore, severity, priority, findingIds: computed in
  code from the group's members.
- targetRepo: the project's setting. NEVER model output — it decides where the
  CodeFix agent pushes.
- title, description, solution and the four enums: the model, in batches, with
  no tools bound, and a deterministic fallback when there is no model.

There is no item cap. T4 (Track) groups get no remediation, which is the only
thing that limits the list, and it is a rule rather than a number.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

#: Caps on what the model may write. Enforced after parsing, never asked for.
MAX_TITLE = 120
MAX_DESCRIPTION = 600
MAX_SOLUTION = 800

#: Enums. A value outside one falls back to the default rather than being stored,
#: because these reach the CodeFix agent's behaviour and the dashboard's filters.
REMEDIATION_TYPES = ("code_fix", "config_change", "dependency_upgrade",
                     "infrastructure", "manual_review")
FIX_COMPLEXITIES = ("trivial", "low", "medium", "high")
CATEGORIES = ("vulnerability", "dependency", "secret", "misconfiguration",
              "exposure", "hardening")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Tiers that earn a remediation. Track is what the board shows and nobody
#: schedules, so filling the fix list with it is how the fix list stops meaning
#: anything.
REMEDIATED_TIERS = ("T1", "T2", "T3")

#: At most this many assets are listed; the rest are counted.
MAX_LISTED_ASSETS = 5


def _worst_severity(values) -> str:
    for severity in SEVERITY_ORDER:
        if severity in values:
            return severity
    return "medium"


def _enum(value, allowed, default):
    text = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    return text if text in allowed else default


def group_display_name(group: dict) -> str:
    """A name for the group that does not need a model to produce.

    Used as the fallback title, and as the label the board shows on a collapsed
    group row.
    """
    key = str(group.get("key") or "")
    members = group.get("members") or []
    first_name = str((members[0] if members else {}).get("name") or "").strip()

    if key.startswith("cve:"):
        cve = key.split(":", 1)[1].upper()
        return f"{cve}{f' - {first_name}' if first_name else ''}"[:MAX_TITLE]
    if key.startswith("pkg:"):
        return f"Upgrade {key.split(':', 1)[1]}"[:MAX_TITLE]
    if key.startswith("malpkg:"):
        return f"Remove malicious package ({key.split(':', 1)[1]})"[:MAX_TITLE]
    if key.startswith("secret:"):
        return f"Rotate exposed secret{f': {first_name}' if first_name else ''}"[:MAX_TITLE]
    return (first_name or key)[:MAX_TITLE]


def deterministic_prose(group: dict) -> dict:
    """Title, description and solution with no model at all.

    This is what ships when the project has no provider key, when the model is
    unreachable, and when a batch fails. It is deliberately plain rather than
    empty: an operator can act on "upgrade this package", and an empty fix list
    tells them nothing.
    """
    members = group.get("members") or []
    best = members[0] if members else {}
    key = str(group.get("key") or "")
    row = best.get("_row") or {}

    solution = str(best.get("fix_lever") or "").strip()
    if not solution and key.startswith("pkg:"):
        package = key.split(":", 1)[1]
        fixed = row.get("fixed_version")
        solution = (f"Upgrade `{package}` to {fixed}." if fixed
                    else f"Upgrade `{package}` to a version without this advisory.")
    if not solution:
        solution = "Review this finding and apply the vendor's recommended fix."

    description = str(row.get("description") or best.get("name") or "").strip()
    if len(members) > 1:
        description = (f"{description}\n\nThe same fix resolves "
                       f"{len(members)} findings.").strip()

    return {
        "title": group_display_name(group),
        "description": description[:MAX_DESCRIPTION],
        "solution": solution[:MAX_SOLUTION],
        "remediationType": _default_type(key),
        "fixComplexity": "medium",
        "estimatedFiles": 0,
        "category": _default_category(key),
    }


def _default_type(key: str) -> str:
    if key.startswith(("pkg:", "malpkg:")):
        return "dependency_upgrade"
    if key.startswith("check:"):
        return "config_change"
    if key.startswith(("secret:", "ghfile:")):
        return "manual_review"
    return "code_fix"


def _default_category(key: str) -> str:
    if key.startswith(("pkg:", "malpkg:")):
        return "dependency"
    if key.startswith(("secret:", "ghfile:")):
        return "secret"
    if key.startswith("check:"):
        return "hardening"
    return "vulnerability"


def build_remediation(group: dict, rank: int, run_id: str, target_repo: str,
                      target_branch: str, prose: dict | None = None) -> dict:
    """One remediation row. Every field except the prose is computed here."""
    members = group.get("members") or []
    live = group.get("live_members") or []
    rows = [m.get("_row") or {} for m in members]

    hosts, seen = [], set()
    for member in members:
        host = str(member.get("host") or "").strip()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)

    cve_ids = sorted({c for row in rows for c in (row.get("cve_ids") or [])})
    cwe_ids = sorted({str(c) for row in rows for c in (row.get("cwe_ids") or []) if c})

    cvss_scores = [row.get("cvss_score") for row in rows]
    cvss_scores = [float(c) for c in cvss_scores
                   if isinstance(c, (int, float)) and c == c]

    kev = any(bool(row.get("cisa_kev")) for row in rows)
    exploit = kev or any(m.get("proven") for m in members) or any(
        "public PoC" in (m.get("signals") or []) for m in members)

    quote = ""
    for member in members:
        candidate = str(member.get("ai_quote") or "").strip()
        if candidate:
            quote = candidate
            break

    text = dict(deterministic_prose(group))
    if prose:
        text.update(prose)

    return {
        "groupKey": group["key"],
        "title": text["title"][:MAX_TITLE] or group_display_name(group),
        "description": text["description"][:MAX_DESCRIPTION],
        "solution": text["solution"][:MAX_SOLUTION],
        "remediationType": _enum(text.get("remediationType"), REMEDIATION_TYPES,
                                 _default_type(group["key"])),
        "fixComplexity": _enum(text.get("fixComplexity"), FIX_COMPLEXITIES, "medium"),
        "category": _enum(text.get("category"), CATEGORIES,
                          _default_category(group["key"])),
        "estimatedFiles": _clamp_int(text.get("estimatedFiles"), 0, 50),
        "severity": _worst_severity(
            {str(m.get("severity") or "").lower() for m in members}),
        "priority": rank,
        "priorityScore": round(float(group.get("score") or 0.0), 4),
        "affectedAssets": hosts[:MAX_LISTED_ASSETS],
        "affectedAssetCount": len(hosts),
        "cveIds": cve_ids,
        "cweIds": cwe_ids,
        "cvssScore": max(cvss_scores) if cvss_scores else None,
        "cisaKev": kev,
        "exploitAvailable": exploit,
        "evidence": quote[:2000],
        "findingIds": [str(m["id"]) for m in members],
        "liveMemberCount": len(live),
        "triageRunId": run_id,
        # From project settings, never from the model: this is where the CodeFix
        # agent clones and pushes.
        "targetRepo": target_repo,
        "targetBranch": target_branch or "main",
    }


def _clamp_int(value, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(float(value))))
    except (TypeError, ValueError):
        return low


def eligible_groups(ordered: list) -> list:
    """T1 to T3 groups that still have an open, non-false-positive member."""
    return [g for g in ordered
            if g.get("tier") in REMEDIATED_TIERS and g.get("live_members")]

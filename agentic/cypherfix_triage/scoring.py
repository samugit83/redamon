"""Deterministic finding prioritisation for the Priority Board.

The weight table below used to live as PROSE in `prompts/system.py`, evaluated by
an LLM for remediation ranking only. Findings in the Priority Board table were fed to
a *separate* LLM step that asked "real or noise?" and, given thin evidence,
answered "needs verification" for almost everything.

This module makes the ranking deterministic: score every finding from graph
signals (exploitation proof, KEV, exposure, injectability, CVSS, severity), with
no LLM guessing. Pure functions, no I/O. The collection query
(`prompts/cypher_queries.py`) supplies the per-finding signal dict; the LLM is
left to do only what it is good at (clustering + a one-line rationale on the top
findings).

The score is the single sort key: higher = more urgent. There is deliberately no
second inverted "priority number" field — the codebase already sorts the existing
`Remediation.priority` in opposite directions in two places, and a finding-side
inverse would extend that trap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ── Weights ─────────────────────────────────────────────────────────────────
# Presence of a signal RAISES priority. Mirrors the table in prompts/system.py,
# which now defers to this module as the single source of truth.
SIGNAL_WEIGHTS = {
    "chain_exploit_success": 1200,  # agent opened a session / RCE on this
    "confirmed_exploit":     1000,  # ExploitGvm executed a payload (qod=100)
    "chain_access_gained":    900,  # access_gained / privilege_escalation
    "cisa_kev":               800,  # CISA KEV flag, or a known public exploit
    "chain_credential":       700,  # credential_found
    "malicious_package":      600,  # OSV-confirmed malicious dependency (authoritative)
    "secret_exposed":         500,  # a leaked secret / sensitive file
    "host_compromised":       300,  # the agent popped THIS HOST (not proof of this vuln, but adjacency)
    "suspicious_package":     150,  # GuardDog heuristic lead, not confirmed
    "chain_reachability":     200,  # internet-facing / origin-exposed
    "dast_confirmed":         150,  # nuclei DAST match with a real response
    "injectable_param":       100,  # a fuzzed, injectable parameter
    "cert_expired":            80,
    "cert_weak":               40,
    "gvm_qod":                 30,  # GVM Quality of Detection >= 70
}

# The graph shows this is LESS urgent than its raw scanner severity claims.
DEMOTIONS = {
    "gvm_remediated":       -1000,  # a GVM re-scan confirmed it is patched
    "chain_exploit_failed":  -600,  # the agent attacked it and failed
    "secret_unvalidated":    -300,  # the credential was checked and is dead
    "cdn_fronted_only":      -100,  # behind a CDN, no origin found: less directly reachable
}

SEVERITY_WEIGHT = {"critical": 50, "high": 40, "medium": 20, "low": 10, "info": 0}

CVSS_MAX_POINTS = 100  # cvss * 10, capped

#: ChainFinding.finding_type values that count as agent-proven exploitation.
_PROVEN_ACCESS = frozenset({"access_gained", "privilege_escalation"})

#: Finding labels whose mere existence is a leaked-secret signal.
_SECRET_LABELS = frozenset({
    "Secret", "GithubSecret", "GithubSensitiveFile", "MultiscannerFinding",
})

# Tier bands off the raw score, for the UI colour only (not stored).
_TIER_BANDS = (
    (1000, "Critical"),
    (500, "High"),
    (150, "Medium"),
    (40, "Low"),
)


@dataclass
class FindingScore:
    """The deterministic verdict for one finding.

    `auto_verdict` is set ONLY when the graph is decisive (exploit-proven,
    validated-live, a deterministic fact, or proven-dead). Everything else is
    left None — a candidate for the reduced LLM rationale pass, never guessed
    here.
    """
    score: float
    signals: list = field(default_factory=list)
    proven: bool = False
    auto_verdict: Optional[str] = None       # 'confirmed' | 'likely_noise' | None
    auto_confidence: Optional[float] = None


def _as_float(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def score_finding(row: dict, label: str = "") -> FindingScore:
    """Score one finding from its graph-signal row. Never raises.

    `row` is the flattened record the collection query returns for this finding.
    Unknown or absent fields contribute nothing, so a thin row (a security_check
    with only name+severity) still scores sensibly rather than erroring.
    """
    row = row or {}
    score = 0.0
    fired: list = []
    proven = False

    def fire(name: str) -> None:
        fired.append(name)

    # Severity floor + CVSS: every finding has these, they are the baseline.
    severity = str(row.get("severity") or "").lower()
    sev_pts = SEVERITY_WEIGHT.get(severity, 0)
    score += sev_pts
    if sev_pts:
        fire(f"severity_{severity}")

    cvss = _as_float(row.get("cvss_score"))
    if cvss and cvss > 0:
        cvss_pts = min(cvss * 10, CVSS_MAX_POINTS)
        score += cvss_pts
        fire("cvss")

    # ── Exploitation proof (agent memory + confirmed scanner exploits) ────────
    chain_types = set(row.get("chain_proofs") or [])
    if "exploit_success" in chain_types:
        score += SIGNAL_WEIGHTS["chain_exploit_success"]
        fire("chain_exploit_success")
        proven = True
    if chain_types & _PROVEN_ACCESS:
        score += SIGNAL_WEIGHTS["chain_access_gained"]
        fire("chain_access_gained")
        proven = True
    if "credential_found" in chain_types:
        score += SIGNAL_WEIGHTS["chain_credential"]
        fire("chain_credential")
        proven = True
    if _as_int(row.get("confirmed_exploits")) > 0:
        score += SIGNAL_WEIGHTS["confirmed_exploit"]
        fire("confirmed_exploit")
        proven = True

    # The agent popped this HOST (an exploit-class chain finding on the same
    # host), but not necessarily via THIS finding. A real signal that findings
    # on the box matter more, but NOT proof of this one -- so no `proven`, no
    # auto-confirm. Precise proof is the CVE-matched chain signals above.
    if _as_int(row.get("host_compromised")) > 0:
        score += SIGNAL_WEIGHTS["host_compromised"]
        fire("host_compromised")

    # ── Known-exploited / high-signal flags ──────────────────────────────────
    if row.get("cisa_kev") or row.get("has_exploit"):
        score += SIGNAL_WEIGHTS["cisa_kev"]
        fire("cisa_kev")

    validation_status = str(row.get("validation_status") or "").lower()
    if label in _SECRET_LABELS or row.get("secret_type"):
        score += SIGNAL_WEIGHTS["secret_exposed"]
        fire("secret_exposed")
        if validation_status == "validated":
            proven = True

    # Malicious/suspicious packages (supply chain). A confirmed-malicious OSV
    # verdict is authoritative -> proven; a GuardDog "suspicious" is a weaker lead.
    mal_verdict = str(row.get("verdict") or "").lower()
    if mal_verdict == "malicious":
        score += SIGNAL_WEIGHTS["malicious_package"]
        fire("malicious_package")
        proven = True
    elif mal_verdict == "suspicious":
        score += SIGNAL_WEIGHTS["suspicious_package"]
        fire("suspicious_package")

    # ── Exposure / reachability ───────────────────────────────────────────────
    # Fire ONLY on positive exposure evidence: a confirmed-live BaseURL, or an
    # unmasked origin behind a CDN. The tempting `not is_cdn and host` clause was
    # removed after review: almost every finding has a host and is not CDN-
    # fronted, so it made a +200 signal fire for nearly everything -- a constant
    # offset, not a discriminator. Absence of exposure evidence earns nothing.
    is_cdn = bool(row.get("is_cdn"))
    is_origin = bool(row.get("is_origin"))
    if row.get("is_live") or is_origin:
        score += SIGNAL_WEIGHTS["chain_reachability"]
        fire("chain_reachability")

    if row.get("is_dast_finding") and row.get("matcher_status"):
        score += SIGNAL_WEIGHTS["dast_confirmed"]
        fire("dast_confirmed")

    if row.get("injectable"):
        score += SIGNAL_WEIGHTS["injectable_param"]
        fire("injectable_param")

    if _as_int(row.get("qod")) >= 70:
        score += SIGNAL_WEIGHTS["gvm_qod"]
        fire("gvm_qod")

    # ── Demotions ─────────────────────────────────────────────────────────────
    if row.get("remediated"):
        score += DEMOTIONS["gvm_remediated"]
        fire("gvm_remediated")
    if _as_int(row.get("exploit_failures")) > 0 and not proven:
        score += DEMOTIONS["chain_exploit_failed"]
        fire("chain_exploit_failed")
    if validation_status == "unvalidated":
        score += DEMOTIONS["secret_unvalidated"]
        fire("secret_unvalidated")
    if is_cdn and not is_origin:
        score += DEMOTIONS["cdn_fronted_only"]
        fire("cdn_fronted_only")

    # ── Deterministic verdict, only where the graph is decisive ───────────────
    source = str(row.get("source") or "").lower()
    auto_verdict: Optional[str] = None
    auto_confidence: Optional[float] = None
    if proven:
        auto_verdict, auto_confidence = "confirmed", 1.0
    elif mal_verdict == "suspicious":
        # A heuristic lead worth a human look, not a fact.
        auto_verdict = None
    elif source == "security_check":
        # A missing DMARC record / header is a FACT, not a guess. Confirmed-true,
        # but its low score keeps it at the bottom. Never sent to the LLM.
        auto_verdict, auto_confidence = "confirmed", 0.9
    elif row.get("remediated"):
        auto_verdict, auto_confidence = "likely_noise", 0.8
    elif _as_int(row.get("exploit_failures")) > 0:
        # The agent tried this and failed. Demote, and mark likely_noise so it
        # drops out of remediation -- but it is NOT deleted or muted, and a human
        # can still see and act on it.
        auto_verdict, auto_confidence = "likely_noise", 0.6

    return FindingScore(
        score=score,
        signals=fired,
        proven=proven,
        auto_verdict=auto_verdict,
        auto_confidence=auto_confidence,
    )


def tier_for_score(score: float) -> str:
    """Coarse band off the raw score, for a UI colour. Not stored on the node."""
    for threshold, tier in _TIER_BANDS:
        if score >= threshold:
            return tier
    return "Info"


def _severity_rank(severity: str) -> int:
    order = ("critical", "high", "medium", "low", "info")
    try:
        return order.index(str(severity or "").lower())
    except ValueError:
        return len(order)


def rank_findings(scored: list) -> list:
    """Order scored findings, worst first, and stamp a 1-based rank.

    `scored` is a list of dicts each carrying at least `score`, `severity`, `id`.
    Returns the same dicts (mutated) sorted by score DESC, then severity, then id
    as a stable final tiebreak so the order is deterministic across runs.
    """
    ordered = sorted(
        scored,
        key=lambda r: (
            -float(r.get("score") or 0.0),
            _severity_rank(r.get("severity")),
            str(r.get("id") or ""),
        ),
    )
    for index, row in enumerate(ordered, start=1):
        row["rank"] = index
    return ordered

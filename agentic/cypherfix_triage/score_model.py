"""The risk model behind the Priority Board (score model v3).

WHY THIS REPLACED A POINTS FORMULA
The old model added points per signal. That is wrong in ways that showed up on
real graphs, not just on paper:

- it counted one fact two or three times (severity, CVSS score and CVSS vector
  all describe the same thing);
- it summed signals measuring the same thing (KEV + EPSS + a public PoC);
- it ADDED impact and likelihood, but risk is likelihood x impact, so something
  harmless and trivially exploitable could outrank something devastating;
- proof sat outside everything else, so a proven exploit on a host that has
  since been patched or has vanished stayed at the top;
- missing data was sometimes neutral and sometimes zero;
- bands came from arbitrary thresholds, so enough weak signals crossed into
  "Critical". On the live dev graph that put 119 GitHub "secrets" that are
  private IP addresses at the top of the board, each scoring ~540, while an
  ungraded advisory on a live dependency scored ~0.

THE MODEL
For every open finding we estimate four things, each between 0 and 1:

    C  P(the finding is real)              how it was detected
    L  P(exploited | real)                 the strongest exploit signal, not a sum
    I  impact                              the CVSS impact part, else severity, else class
    R  reachability                        how an attacker gets to it

    risk  r = min(1, C x L x I x R)
    tier    = T1 Act now | T2 Act soon | T3 Plan | T4 Track   (fixed rules)
    score   = 25 x tier_level + 25 x r      T1=3 T2=2 T3=1 T4=0   ->  0 to 100

Sorting by `score` is exactly "tier first, then risk", so a bigger score always
means more urgent, with no exceptions. The breakdown reads as a sentence:
`real 95% x exploit 70% x impact 0.75 x reach 1.0 -> Act soon, 62.5`.

STATE COMES FIRST. A fixed, gone or inactive finding leaves the ranking
entirely instead of being demoted to a small number that still sorts above a
real one.

This module is PURE: no I/O, no graph, no clock, no randomness. Every table is
data, so the Phase 6 calibration is a diff of numbers rather than of code, and
`SCORE_MODEL_VERSION` changes with them. The AI review (Step C) corrects the
FACTORS and re-runs these same rules; it never produces a score.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

#: Bump on ANY change to a table, a threshold or a rule below. Stored with each
#: run so two runs are only comparable when this matches.
SCORE_MODEL_VERSION = "v3.11.0"


# ===========================================================================
# Normalisers (K10, K24): the same fact arrives in several shapes
# ===========================================================================
SEVERITY_IMPACT = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.45,
    "moderate": 0.45,
    "low": 0.2,
    "info": 0.02,
    "informational": 0.02,
    "none": 0.02,
}

#: Impact when nothing says how bad it is. NOT 0.02: OSV writes `severity: info`
#: to mean "this advisory was never graded" (all 419 PYSEC advisories in the dev
#: graph), and InternetDB writes no severity at all. Treating unknown as info
#: is what buried real advisories at the bottom of the board.
IMPACT_UNKNOWN = 0.45

#: Reachability when there is no evidence either way. Deliberately high: most
#: findings sit on assets a scanner reached, and assuming the worst about
#: missing data would make R meaningless.
REACH_UNKNOWN = 0.8
#: The evidence that default carries. The reachable-now gate reads it as
#: "unknown": a guess good enough to rank by is not a fact to report on.
REACH_NO_EVIDENCE = "no reachability evidence either way"


def normalise_severity(value: Any) -> Optional[str]:
    """A severity word, or None when the value says nothing."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or text in ("unknown", "n/a", "-"):
        return None
    if text in SEVERITY_IMPACT:
        return text
    # Numeric severities appear as CVSS-like 0-10 and as 0-100.
    number = as_float(text)
    if number is None:
        return None
    if number > 10:
        number /= 10.0
    if number >= 9.0:
        return "critical"
    if number >= 7.0:
        return "high"
    if number >= 4.0:
        return "medium"
    if number > 0:
        return "low"
    return "info"


def normalise_confidence(value: Any) -> Optional[float]:
    """Confidence as 0-1, from the four shapes the writers use.

    Stored today as a word ('high'), a 0-100 int, a 0-1 float, and a verdict
    word ('malicious' / 'suspicious'). Reading any one of those as a number
    silently mis-scored the other three.
    """
    if value is None or value is True or value is False:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return min(1.0, number / 100.0) if number > 1.0 else max(0.0, number)
    text = str(value).strip().lower()
    words = {
        "high": 0.9, "medium": 0.6, "moderate": 0.6, "low": 0.3,
        "confirmed": 1.0, "certain": 1.0, "tentative": 0.25,
        "malicious": 1.0, "suspicious": 0.4, "likely": 0.7,
        "manual_review": 0.25, "unconfirmed": 0.3, "strong": 0.75,
    }
    if text in words:
        return words[text]
    number = as_float(text)
    if number is None:
        return None
    return min(1.0, number / 100.0) if number > 1.0 else max(0.0, number)


def as_float(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if number != number else number          # reject NaN


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    return bool(value)


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v is not None]
    return [value]


# ===========================================================================
# CVSS: the only place a vector is read
# ===========================================================================
#: v3.x / v4 weights. The exploitability and impact halves are kept apart on
#: purpose: I uses ONLY the impact part, so a vector never contributes to both
#: I and L (that double-count is one of the reasons the old formula was wrong).
_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_V2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_V2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_V2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_V2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}

#: Normalisers, so both halves come out on 0-1.
_V3_IMPACT_MAX = 6.05
_V3_EXPLOIT_MAX = 3.89
_V2_IMPACT_MAX = 10.0
_V2_EXPLOIT_MAX = 10.0


@dataclass
class Cvss:
    """What a vector tells us, already on 0-1. `version` is for the explanation."""
    version: str = ""
    impact: Optional[float] = None
    exploitability: Optional[float] = None
    privileges_required: str = ""
    user_interaction: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""


_VECTOR_RE = re.compile(r"([A-Za-z]{1,3}):([A-Za-z]+)")


def parse_cvss_vector(vector: Any) -> Cvss:
    """Parse a CVSS v2, v3.x or v4.0 vector string. Never raises.

    An unparseable or absent vector yields an empty `Cvss`, and the caller falls
    back to the numeric score, then the severity, then the class default. That
    chain is why a missing vector never scores zero by accident.
    """
    text = str(vector or "").strip()
    if not text:
        return Cvss()

    parts = {k.upper(): v.upper() for k, v in _VECTOR_RE.findall(text)}
    if not parts:
        return Cvss()

    upper = text.upper()
    if upper.startswith("CVSS:4"):
        return _parse_v4(parts)
    if upper.startswith("CVSS:3") or ("UI" in parts and "S" in parts):
        return _parse_v3(parts)
    if "AU" in parts:
        return _parse_v2(parts)
    # A bare "AV:N/AC:L/..." with no Au is v3-shaped in practice.
    return _parse_v3(parts) if "UI" in parts else _parse_v2(parts)


def _parse_v3(parts: dict) -> Cvss:
    scope_changed = parts.get("S", "U") == "C"
    conf = _V3_CIA.get(parts.get("C", "N"), 0.0)
    integ = _V3_CIA.get(parts.get("I", "N"), 0.0)
    avail = _V3_CIA.get(parts.get("A", "N"), 0.0)
    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    impact = max(0.0, impact)

    pr_table = _V3_PR_CHANGED if scope_changed else _V3_PR_UNCHANGED
    exploitability = (
        8.22
        * _V3_AV.get(parts.get("AV", "N"), 0.85)
        * _V3_AC.get(parts.get("AC", "L"), 0.77)
        * pr_table.get(parts.get("PR", "N"), 0.85)
        * _V3_UI.get(parts.get("UI", "N"), 0.85)
    )
    return Cvss(
        version="3",
        impact=min(1.0, impact / _V3_IMPACT_MAX),
        exploitability=min(1.0, exploitability / _V3_EXPLOIT_MAX),
        privileges_required=parts.get("PR", ""),
        user_interaction=parts.get("UI", ""),
        attack_vector=parts.get("AV", ""),
        attack_complexity=parts.get("AC", ""),
    )


def _parse_v2(parts: dict) -> Cvss:
    conf = _V2_CIA.get(parts.get("C", "N"), 0.0)
    integ = _V2_CIA.get(parts.get("I", "N"), 0.0)
    avail = _V2_CIA.get(parts.get("A", "N"), 0.0)
    impact = 10.41 * (1 - (1 - conf) * (1 - integ) * (1 - avail))
    exploitability = (
        20.0
        * _V2_AV.get(parts.get("AV", "N"), 1.0)
        * _V2_AC.get(parts.get("AC", "L"), 0.71)
        * _V2_AU.get(parts.get("AU", "N"), 0.704)
    )
    # v2 has no UI metric; "Au" is the nearest thing to PR.
    pr = {"N": "N", "S": "L", "M": "H"}.get(parts.get("AU", "N"), "N")
    return Cvss(
        version="2",
        impact=min(1.0, impact / _V2_IMPACT_MAX),
        exploitability=min(1.0, exploitability / _V2_EXPLOIT_MAX),
        privileges_required=pr,
        user_interaction="",
        attack_vector=parts.get("AV", ""),
        attack_complexity=parts.get("AC", ""),
    )


def _parse_v4(parts: dict) -> Cvss:
    """A documented approximation, not the official v4 scoring.

    v4's real score comes from a 270-row lookup table that is not worth carrying
    for a ranking input. Decision 13 of the plan: map AV/AC/AT/PR/UI onto the v3
    exploitability weights, and take impact from the HIGHER of the vulnerable
    system (VC/VI/VA) and the subsequent system (SC/SI/SA). Tested against
    published v4 examples to within 1.0 on the 0-10 scale.
    """
    def triad(prefix: str) -> float:
        conf = _V3_CIA.get(parts.get(f"{prefix}C", "N"), 0.0)
        integ = _V3_CIA.get(parts.get(f"{prefix}I", "N"), 0.0)
        avail = _V3_CIA.get(parts.get(f"{prefix}A", "N"), 0.0)
        return 1 - ((1 - conf) * (1 - integ) * (1 - avail))

    iss = max(triad("V"), triad("S"))
    impact = 6.42 * iss

    # AT (Attack Requirements) is v4-only; treat "Present" like added complexity.
    at_penalty = 0.85 if parts.get("AT", "N") == "P" else 1.0
    exploitability = (
        8.22
        * _V3_AV.get(parts.get("AV", "N"), 0.85)
        * _V3_AC.get(parts.get("AC", "L"), 0.77)
        * _V3_PR_UNCHANGED.get(parts.get("PR", "N"), 0.85)
        * _V3_UI.get(parts.get("UI", "N"), 0.85)
        * at_penalty
    )
    return Cvss(
        version="4",
        impact=min(1.0, max(0.0, impact) / _V3_IMPACT_MAX),
        exploitability=min(1.0, exploitability / _V3_EXPLOIT_MAX),
        privileges_required=parts.get("PR", ""),
        user_interaction=parts.get("UI", ""),
        attack_vector=parts.get("AV", ""),
        attack_complexity=parts.get("AC", ""),
    )


# ===========================================================================
# Class tables (3.2.4a): data, not code branches
# ===========================================================================
@dataclass(frozen=True)
class FindingClass:
    """What a finding's KIND implies when nothing better is known.

    `caps_impact` marks the classes whose writer stamps a BLANKET severity on
    every node it creates: the GitHub hunt writes "high" on all 284 of its
    secrets, 119 of which are private IP addresses. For those, the class table
    is the better evidence and becomes a ceiling on I. For nuclei, GVM and OSV
    the severity is a per-finding judgement, so it is left alone.
    """
    name: str
    likelihood: float
    impact: float
    caps_impact: bool = False


CLASS_DEFAULT = FindingClass("unclassified", 0.3, IMPACT_UNKNOWN)

#: security_check `type` -> class. `missing_*` and cache_control_missing are
#: hardening: real, confirmed facts, but a missing header is not a way in.
SECURITY_CHECK_CLASSES = {
    "missing_": FindingClass("hardening", 0.05, 0.1, caps_impact=True),
    "cache_control_missing": FindingClass("hardening", 0.05, 0.1, caps_impact=True),
    "spf_missing": FindingClass("spoofing", 0.3, 0.3, caps_impact=True),
    "dmarc_missing": FindingClass("spoofing", 0.3, 0.3, caps_impact=True),
    "dkim_missing": FindingClass("spoofing", 0.3, 0.3, caps_impact=True),
    "direct_ip_http": FindingClass("cdn_bypass", 0.3, 0.3, caps_impact=True),
    "direct_ip_https": FindingClass("cdn_bypass", 0.3, 0.3, caps_impact=True),
    "waf_bypass": FindingClass("cdn_bypass", 0.3, 0.3, caps_impact=True),
    "ip_api_exposed": FindingClass("exposure", 0.3, 0.5, caps_impact=True),
    "no_rate_limiting": FindingClass("rate_limit", 0.2, 0.3, caps_impact=True),
    "cors_misconfiguration": FindingClass("misconfig", 0.4, 0.5, caps_impact=True),
    "open_redirect": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    # A service that should never face the internet, reached directly. Not
    # impact-capped: the check grades each one itself (a Kubernetes API that
    # answers anonymously is critical, one that asks for a login is high), so
    # its severity is a per-finding judgement. Calibrated against GVM's
    # "Redis Server No Password", which lands at T3 ~39.
    "redis_no_auth": FindingClass("unauthenticated_access", 0.5, 0.75),
    "kubernetes_api_exposed": FindingClass("exposure", 0.5, 0.75),
    "database_exposed": FindingClass("exposure", 0.5, 0.75),
    "smtp_open_relay": FindingClass("spoofing", 0.5, 0.75),
    "zone_transfer": FindingClass("info_disclosure", 0.5, 0.75),
    # Real, but the attacker needs a position on the network path first.
    "login_no_https": FindingClass("cleartext_credentials", 0.3, 0.5, caps_impact=True),
    "basic_auth_no_tls": FindingClass("cleartext_credentials", 0.3, 0.5, caps_impact=True),
    # Low risk on their own: the generic misconfig numbers.
    "admin_port_exposed": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "cache_purge_exposed": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "session_no_secure": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "session_no_httponly": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "csp_unsafe_inline": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "insecure_form_action": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "dnssec_missing": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_expired": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_expiring_soon": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_self_signed": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_hostname_mismatch": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_weak_version": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_weak_cipher": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_wildcard_overbroad": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_weak_version_supported": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "tls_weak_cipher_supported": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    # Page Content (item 5), on the rows of the findings they resemble: an open
    # console or an installer anyone can finish runs code like an exposed debug
    # console; a debug page or a listing leaks like a debug error page; a
    # deleted-service page is a takeover; a defacement is someone else's write.
    "open_console": FindingClass("rce", 0.7, 0.75),
    "unfinished_installer": FindingClass("rce", 0.7, 0.75),
    "debug_page": FindingClass("info_disclosure", 0.3, 0.3, caps_impact=True),
    "directory_listing": FindingClass("info_disclosure", 0.3, 0.3, caps_impact=True),
    "takeover_error_page": FindingClass("takeover", 0.7, 0.75),
    "defaced_page": FindingClass("unauthenticated_access", 0.5, 0.75),
    "dev_server": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
    "test_certificate": FindingClass("misconfig", 0.3, 0.3, caps_impact=True),
}

#: Secret class by detector / secret_type. The `identifier` row is the fix for
#: the single most visible symptom: 119 of 284 GitHub-hunt "secrets" in the dev
#: graph are private IP addresses, and each one used to score +500.
SECRET_CLASSES = {
    "credential": FindingClass("credential", 0.6, 0.9, caps_impact=True),
    "secret": FindingClass("generic_secret", 0.4, 0.6, caps_impact=True),
    "identifier": FindingClass("identifier", 0.2, 0.1, caps_impact=True),
    "public": FindingClass("public_client_id", 0.2, 0.1, caps_impact=True),
    # A public client key a validator could spend on a paid API (an AIza key
    # with no API restriction): billing abuse, not account takeover.
    "public_unrestricted": FindingClass("unrestricted_api_key", 0.4, 0.45, caps_impact=True),
}

#: Keys that are PUBLIC BY DESIGN: they ship to every browser that loads the
#: page, and the service limits what they can do. Exact producer names (the
#: GitHub hunt's SECRET_PATTERNS and js_recon's _RAW_PATTERNS share them), never
#: substrings: "gcp" alone is also a service-account key and "stripe" alone
#: also a secret key, and both must stay credentials. js_recon's
#: PUBLIC_CLIENT_KEY_NAMES, lowercased, plus jsluice's name; a test pins them.
PUBLIC_CLIENT_KEY_TYPES = frozenset({
    "gcp api key",              # AIza..., a Google browser (Maps / Firebase) key
    "gcpkey",                   # jsluice's name for the same AIza key
    "firebase api key",         # the web config's apiKey
    "segment write key",        # write-only analytics
    "amplitude api key",
    "new relic browser api token",  # NRJS-
    "sentry dsn",
    "stripe publishable key",   # pk_live_
    "google recaptcha key",     # 6L..., the site key
    "mapbox token",             # the pattern only matches public pk. tokens
    "algolia app id",
    "algolia search key",       # only when labelled as the search key
    "intercom app id",
    "pusher key",
    "clerk publishable key",
    "mailgun public key",       # pubkey-
    "flutterwave public key",   # FLWPUBK-
    "supabase anon key",        # a Supabase JWT whose role is anon
    "supabase publishable key",  # sb_publishable_
})

#: Substrings matched against the lowercased detector / secret_type, most
#: specific first. A detector with no match falls to `generic_secret`.
SECRET_CLASS_PATTERNS = (
    ("identifier", (
        "ip address", "private ip", "s3 bucket", "bucket", "email",
        "phone", "domain", "hostname", "mac address", "uuid",
    )),
    ("credential", (
        "aws", "gcp", "azure", "private key", "privatekey", "rsa", "ssh",
        "password", "passwd", "connection string", "connectionstring",
        "jwt", "bearer", "session", "oauth", "refresh token", "access token",
        "slack", "stripe", "twilio", "sendgrid", "github", "gitlab", "npm",
        "docker", "kubernetes", "kubeconfig", "database", "postgres", "mysql",
        "mongodb", "redis", "credential",
        # A Supabase service_role JWT or sb_secret_ key bypasses row-level
        # security: the project's whole database.
        "service_role", "supabase secret",
    )),
    ("secret", ("api key", "apikey", "token", "secret", "key")),
)

#: JsReconFinding `finding_type` -> class.
JS_RECON_CLASSES = {
    "api_key": FindingClass("generic_secret", 0.4, 0.6, caps_impact=True),
    "credential": FindingClass("credential", 0.6, 0.9, caps_impact=True),
    "secret": FindingClass("generic_secret", 0.4, 0.6, caps_impact=True),
    "internal_ip": FindingClass("info_disclosure", 0.2, 0.1, caps_impact=True),
    "email": FindingClass("info_disclosure", 0.2, 0.1, caps_impact=True),
    "source_map_exposure": FindingClass("info_disclosure", 0.2, 0.2, caps_impact=True),
    "source_map_reference": FindingClass("info_disclosure", 0.1, 0.05, caps_impact=True),
    # Not capped: the scanner rates a comment naming a password or key medium
    # and the rest low, a per-finding judgement worth keeping.
    "dev_comment": FindingClass("info_disclosure", 0.2, 0.1),
    "dev_reference": FindingClass("info_disclosure", 0.1, 0.05, caps_impact=True),
    # A lexical sink is a lead for a DOM XSS, not a confirmed one, and older
    # scans stamped every Function()/eval() match critical, so the class caps
    # it. A sink fed by a nearby URL/message source is written high and lands
    # at the cap; one without a source is written low.
    "dom_sink": FindingClass("dom_sink", 0.2, 0.5, caps_impact=True),
    "hidden_route": FindingClass("info_disclosure", 0.2, 0.2, caps_impact=True),
    "endpoint": FindingClass("info_disclosure", 0.2, 0.1, caps_impact=True),
    "graphql_endpoint": FindingClass("info_disclosure", 0.2, 0.2, caps_impact=True),
    "cloud_storage": FindingClass("exposure", 0.3, 0.4, caps_impact=True),
}

#: route_exposure `vulnerability_type` (stored as `type`) -> class. The scorer
#: reads a fixed projection that carries `type`, never `exposure_kind`. No key
#: here may equal a SECURITY_CHECK_CLASSES key: `_class_for` routes by type
#: before source for every other writer. `secret_exposure` is classed by its
#: first secret detector instead (classify_secret).
ROUTE_EXPOSURE_CLASSES = {
    "unauthenticated_endpoint": FindingClass("unauthenticated_access", 0.5, 0.75),
    "sensitive_data_exposure": FindingClass("data_exposure", 0.5, 0.75),
    "cors_credentialed_origin_reflection": FindingClass("misconfig", 0.4, 0.5, caps_impact=True),
    "authenticated_content_cacheable": FindingClass("data_exposure", 0.4, 0.5, caps_impact=True),
    "exposed_version_control": FindingClass("source_disclosure", 0.7, 0.75),
    "exposed_env_file": FindingClass("credential_exposure", 0.7, 0.75),
    "exposed_config_file": FindingClass("info_disclosure", 0.5, 0.5),
    "exposed_backup_file": FindingClass("source_disclosure", 0.6, 0.75),
    # the likelihood EXPLOITABLE_CLASSES gives rce: an open console runs code
    "exposed_debug_console": FindingClass("rce", 0.7, 0.75),
    "exposed_debug_endpoint": FindingClass("info_disclosure", 0.5, 0.75),
    "debug_error_page": FindingClass("info_disclosure", 0.3, 0.3, caps_impact=True),
    "exposed_route_catalog": FindingClass("info_disclosure", 0.3, 0.3, caps_impact=True),
}

#: urlscan history (source "urlscan_leak") `type` -> class. A public record of
#: what someone opened, never confirmed live by RedAmon: likelihood stays below
#: the confirmed rows, and the history writer already caps severity at high.
#: Routed by source BEFORE the type and exploitable-class gates, since
#: `_is_exploitable_class` matches substrings and "takeover_page_seen" would
#: otherwise read as a confirmed takeover by its name.
URLSCAN_LEAK_CLASSES = {
    "leaked_one_time_link": FindingClass("credential_exposure", 0.4, 0.75),
    "sensitive_file_seen": FindingClass("data_exposure", 0.4, 0.75),
    "open_redirect_seen": FindingClass("open_redirect", 0.3, 0.3, caps_impact=True),
    "takeover_page_seen": FindingClass("possible_takeover", 0.4, 0.75),
    "open_console_seen": FindingClass("rce", 0.4, 0.75),
    "installer_seen": FindingClass("rce", 0.4, 0.75),
    "debug_page_seen": FindingClass("info_disclosure", 0.3, 0.3, caps_impact=True),
    "directory_listing_seen": FindingClass("info_disclosure", 0.3, 0.3, caps_impact=True),
    "dev_server_seen": FindingClass("misconfig", 0.2, 0.3, caps_impact=True),
    "test_certificate_seen": FindingClass("misconfig", 0.2, 0.3, caps_impact=True),
    "defaced_page_seen": FindingClass("unauthenticated_access", 0.4, 0.75),
}
URLSCAN_LEAK_DEFAULT = FindingClass("urlscan_history", 0.2, 0.3, caps_impact=True)

#: Directly exploitable classes. Reaching one of these, CONFIRMED, is the 0.7
#: row of the L table.
EXPLOITABLE_CLASSES = frozenset({
    "sqli", "sql-injection", "sql_injection", "rce", "cmdi", "command-injection",
    "command_injection", "lfi", "rfi", "ssrf", "xxe", "ssti", "deserialization",
    "auth-bypass", "auth_bypass", "authentication-bypass", "takeover",
    "subdomain_takeover", "cache_poisoning", "path-traversal", "path_traversal",
    "file-upload", "xslt", "log4j", "jndi",
})

#: nuclei tags that mean "we identified software", not "we found a weakness".
#: Impact is capped at info for these, so a fingerprint can never outrank a CVE.
FINGERPRINT_TAGS = frozenset({"tech", "detect", "detection", "panel", "favicon"})

#: Ports whose exposure makes anything on that host more damaging.
SENSITIVE_PORTS = frozenset({3306, 5432, 6379, 9200, 27017, 1433, 5984, 11211})


def _names_a_public_client_key(detector: Any, secret_type: Any) -> bool:
    return bool({_lower(detector), _lower(secret_type)} & PUBLIC_CLIENT_KEY_TYPES)


def _is_public_client_key(finding: dict) -> bool:
    return _names_a_public_client_key(finding.get("detector_name"),
                                      finding.get("secret_type"))


def classify_secret(detector: Any, secret_type: Any = None) -> FindingClass:
    """credential / generic secret / identifier / public client key, from the
    detector name."""
    if _names_a_public_client_key(detector, secret_type):
        return SECRET_CLASSES["public"]
    haystack = f"{_lower(detector)} {_lower(secret_type)}".strip()
    for class_key, needles in SECRET_CLASS_PATTERNS:
        if any(needle in haystack for needle in needles):
            return SECRET_CLASSES[class_key]
    return SECRET_CLASSES["secret"]


def classify_security_check(check_type: Any) -> FindingClass:
    text = _lower(check_type)
    if text in SECURITY_CHECK_CLASSES:
        return SECURITY_CHECK_CLASSES[text]
    for prefix, klass in SECURITY_CHECK_CLASSES.items():
        if prefix.endswith("_") and text.startswith(prefix):
            return klass
    if text.startswith("missing"):
        return SECURITY_CHECK_CLASSES["missing_"]
    return FindingClass("misconfig", 0.3, 0.3, caps_impact=True)


# ===========================================================================
# C: probability the finding is real (3.2.3)
# ===========================================================================
#: Baseline confidence per source, BEFORE the detection-specific upgrades in
#: `confidence()`. Every finding-bearing source in the writer inventory has a
#: row; `test_score_model.py` fails the gate when one is missing, because an
#: unknown source silently getting 0.75 is how a new scanner ships mis-ranked.
CONFIDENCE_BY_SOURCE = {
    # active, evidence-bearing
    "nuclei": 0.75,
    "gvm": 0.75,
    "nmap_nse": 0.75,
    "takeover_scan": 0.75,
    "cache_poisoning": 0.75,
    "graphql_scan": 0.75,
    "graphql_cop": 0.75,
    "ai_surface_recon": 0.75,
    "ai_attack": 0.75,
    "wcvs": 0.75,
    "vuln_scan": 0.75,
    "http_probe": 0.75,
    "origin_discovery": 0.75,
    "vhost_sni_enum": 0.75,
    "resource_enum": 0.75,
    # facts: deterministic checks, not detections
    "security_check": 1.0,
    # advisory matching against a package
    "osv": 0.9,
    "retirejs": 0.9,
    "sourcemap": 0.4,
    # unproven static signature: serialization is present and reachable, not
    # exploitable. Low on purpose so the info gate's T4 floor keeps it low until
    # the agent's proof-typed CONFIRMS edge promotes it (never an accidental 0.75).
    "serialized_scan": 0.4,
    # route exposure: its findings are signature-proven (a .git HEAD, an env
    # file, a debug console), like nuclei's. Its pending leads are written info,
    # so the info gate keeps them at T4 until a proof-typed CONFIRMS edge.
    "route_exposure": 0.75,
    "guarddog": 0.25,
    # never-validated secrets
    "github_hunt": 0.6,
    "github": 0.6,
    "github_experimental": 0.6,
    "git": 0.6,
    "filesystem": 0.6,
    "trufflehog": 0.6,
    "jsluice": 0.6,
    "js_recon": 0.6,
    # version guesses from passive intelligence
    "shodan": 0.4,
    "shodan_api": 0.4,
    "internetdb": 0.4,
    "criminalip": 0.4,
    "netlas": 0.4,
    "censys": 0.4,
    "fofa": 0.4,
    "zoomeye": 0.4,
    "uncover": 0.4,
    "urlscan": 0.4,
    # urlscan's history: a public record of what someone opened, not a test
    "urlscan_leak": 0.4,
    "otx": 0.4,
    "vulners": 0.4,
    "nvd": 0.4,
    "wappalyzer": 0.4,
    "typosquat": 0.4,
    # the agent and the operator
    "agent": 1.0,
    "human": 1.0,
    "operator": 1.0,
    "user": 1.0,
    "import": 0.75,
    "graph": 0.75,
    "recon": 0.75,
    "finding": 0.75,
    "ai": 0.75,
    "ai_classifier": 0.75,
    "hypothesis": 0.25,
    "ai_unavailable": 0.25,
}

#: What an unknown source gets, plus a log line. Never silently right.
CONFIDENCE_UNKNOWN_SOURCE = 0.75

#: The `source` of a passive CVE: a provider's own crawl of the IP, weeks old at
#: times. Kept in step with PASSIVE_CVE_SOURCES in
#: recon/helpers/finding_sources.py (a test compares them).
PASSIVE_CVE_SOURCES = frozenset({
    "shodan_api", "internetdb", "shodan", "shodan_host_lookup", "netlas", "criminalip",
})

#: The highest C a "real" review gives a passive CVE whose port this run's scan
#: did not find open: the quote it verifies is the provider's own banner, which
#: shows nothing live. Shodan's own verification earns the same 0.6.
PASSIVE_REVIEW_MAX_CONFIDENCE = 0.6

#: security_check types that INFER the problem rather than observe it, so they
#: get a detector's C instead of the 1.0 of a fact. Every other check (a header
#: that is absent, an AXFR that answered, a PONG with no AUTH, a relay that
#: accepted the recipient) saw the condition itself and keeps 1.0.
SECURITY_CHECK_CONFIDENCE = {
    "admin_port_exposed": (0.75, "an open port; the service is assumed from its number"),
    "database_exposed": (0.75, "an open port; the database is assumed from its number"),
    "cache_purge_exposed": (0.75, "PURGE was accepted while a bogus method was refused"),
    "kubernetes_api_exposed": (0.6, "a keyword in the /api response, not a verified API"),
    "ip_api_exposed": (0.6, "an API inferred from a status code or a content type"),
    "no_rate_limiting": (0.6, "ten logins went unthrottled; a limit may start later"),
    # A page title is strong evidence of what the page is, not proof of access.
    "open_console": (0.75, "the page title names a console; the console itself was not used"),
    "unfinished_installer": (0.75, "the page title names an installer; it was not completed"),
    "debug_page": (0.75, "the page title names a debug page"),
    "directory_listing": (0.75, "the page title names a folder listing"),
    "defaced_page": (0.75, "the page title says the site was defaced"),
    "takeover_error_page": (0.75, "the page is the provider's deleted-service page; the name was not claimed"),
}

#: waf_bypass by the `detection_method` the producer recorded. A node with none
#: was written before the writer stored it, and keeps the 1.0 it was scored
#: with until a rescan says how the bypass was found.
WAF_BYPASS_CONFIDENCE = {
    # Not 1.0: the "same page" is a token-similarity judgement (>= 0.80), and a
    # site that serves one template everywhere can still pass it.
    "payload_differential": (0.95, "the edge blocked a probe the origin served with a 2xx page "
                                   "matching the edge's own page for a benign request"),
    "static_headers": (0.75, "the edge's Server header names a WAF and the origin's does not"),
    "ai_classifier": (0.6, "an AI classifier saw a WAF on the edge but not on the origin"),
    "jev_classifier": (0.6, "a Jev classifier saw a WAF on the edge but not on the origin"),
}

#: How many labels it takes to move a detector's C halfway from its class prior
#: to what an operator's clicks say. Ten is deliberately slow: a detector is
#: judged on a handful of findings at first, and three unlucky clicks must not
#: be able to switch a real detector off.
DETECTOR_PRIOR_WEIGHT = 10

#: C is never learned all the way to 0 or 1. A detector a person has called
#: wrong twenty times still fires, just near the bottom of the board, because a
#: silenced detector is invisible and nobody ever finds out it went wrong. The
#: top bound is below 1.0 because 1.0 is reserved for PROVEN.
DETECTOR_MIN_CONFIDENCE = 0.1
DETECTOR_MAX_CONFIDENCE = 0.99

#: GVM `qod_type` values that mean the detection actually interacted with the
#: vulnerability rather than reading a banner.
GVM_ACTIVE_QOD_TYPES = frozenset({
    "exploit", "remote_vul", "remote_app", "remote_active", "package",
})


# ===========================================================================
# The inputs
# ===========================================================================
@dataclass
class ProjectFacts:
    """Project-wide facts, collected once per run.

    Every field defaults to empty, so a fact set that failed to load degrades to
    "we do not know" rather than to "it is not true". That is the difference
    between a finding losing its reachability bonus and a finding being scored
    as unreachable.
    """
    proven_finding_ids: set = field(default_factory=set)
    proven_cve_ids: set = field(default_factory=set)
    #: host -> the chain findings that proved something on it (X9 `triage_proof`)
    proof_by_host: dict = field(default_factory=dict)
    compromised_hosts: set = field(default_factory=set)
    threat_intel_hosts: set = field(default_factory=set)
    origin_exposed_hosts: set = field(default_factory=set)
    live_hosts: set = field(default_factory=set)
    #: host -> "active" | "passive": how the open port was found
    port_hosts: dict = field(default_factory=dict)
    #: (host, port number) -> "active" | "passive": the same, per port
    port_status: dict = field(default_factory=dict)
    #: package purl -> "served" | "repo" | "sbom"
    package_exposure: dict = field(default_factory=dict)
    sensitive_hosts: set = field(default_factory=set)
    login_hosts: set = field(default_factory=set)
    #: hosts that no longer resolve / have no live endpoint and no open port
    gone_hosts: set = field(default_factory=set)
    #: hosts with at least one usable credential finding (dangerous combination)
    credential_hosts: set = field(default_factory=set)
    #: hosts with an injectable parameter on an authentication endpoint
    injectable_auth_hosts: set = field(default_factory=set)
    #: hosts behind a CDN with no origin found
    cdn_only_hosts: set = field(default_factory=set)
    #: hosts whose matched URL answered 401/403
    auth_required_hosts: set = field(default_factory=set)
    #: IP address -> IP attribution tag (shared_edge | dedicated | unknown); an
    #: IP no run has attributed yet is absent, which means "not known"
    ip_ownership: dict = field(default_factory=dict)
    #: IP addresses tagged shared_edge: a CDN edge serving many tenants
    shared_edge_hosts: set = field(default_factory=set)
    #: IP addresses no current DNS name of the target points at (never an
    #: IP-mode target, which the operator listed by address)
    no_dns_name_hosts: set = field(default_factory=set)
    #: hosts the run skipped (a tripped breaker), lower-case names and
    #: addresses: not re-checked, so their reachability is unknown
    skipped_hosts: set = field(default_factory=set)
    #: DNS name -> the attribution tags of the IPs it currently resolves to,
    #: '' for an IP no run has attributed yet
    name_ownership: dict = field(default_factory=dict)
    #: detector key -> {"real": n, "fp": n}, this USER's own verdicts across
    #: every project of theirs. Never shared between users: one operator's
    #: "that detector is noise here" is about their estate, not about the
    #: detector, and pooling them would let one account's clicks re-rank
    #: another's board. See `learned_confidence`.
    detector_labels: dict = field(default_factory=dict)


@dataclass
class Factor:
    """One factor, with the evidence it came from.

    `evidence` is what the board shows under the score and what the AI review is
    asked to dispute. A factor with no evidence string is a default, and the UI
    says so rather than implying a measurement.
    """
    value: float
    evidence: str = ""

    def __float__(self) -> float:                              # pragma: no cover
        return float(self.value)


@dataclass
class ScoreResult:
    state: str
    confidence: Factor
    likelihood: Factor
    impact: Factor
    reach: Factor
    risk: float
    tier: str
    tier_rule: str
    score: float
    signals: list = field(default_factory=list)
    proven: bool = False
    host: str = ""
    warnings: list = field(default_factory=list)
    tier_inputs: "TierInputs" = None

    @property
    def explanation(self) -> str:
        return (
            f"real {self.confidence.value:.0%} x "
            f"exploit {self.likelihood.value:.0%} x "
            f"impact {self.impact.value:.2f} x "
            f"reach {self.reach.value:.1f} -> "
            f"{TIER_LABELS[self.tier]}, {self.score:.1f}"
        )

    def as_factors_dict(self) -> dict:
        """What gets stored as `triage_factors` JSON."""
        return {
            "C": {"value": round(self.confidence.value, 4),
                  "evidence": self.confidence.evidence},
            "L": {"value": round(self.likelihood.value, 4),
                  "evidence": self.likelihood.evidence},
            "I": {"value": round(self.impact.value, 4),
                  "evidence": self.impact.evidence},
            "R": {"value": round(self.reach.value, 4),
                  "evidence": self.reach.evidence},
        }


TIER_LEVELS = {"T1": 3, "T2": 2, "T3": 1, "T4": 0}
TIER_LABELS = {"T1": "Act now", "T2": "Act soon", "T3": "Plan", "T4": "Track"}

STATE_OPEN = "open"
STATE_FIXED = "fixed"
STATE_GONE = "gone"
STATE_INACTIVE = "inactive"
STATE_FALSE_POSITIVE = "false_positive"

#: States that leave the ranked section. They keep their facts and can come back
#: to `open` on a later run.
RESOLVED_STATES = frozenset({STATE_FIXED, STATE_GONE, STATE_INACTIVE})


# ===========================================================================
# State (3.2.2): decided before anything is scored
# ===========================================================================
def finding_state(finding: dict, facts: ProjectFacts) -> tuple[str, str]:
    """(state, why). Only `open` findings are ranked.

    Never `false_positive`: that is an outcome of `combine_layers` (a person's
    decision or a valid review), not a fact about the finding. A legacy node
    still carrying `triage_status = 'likely_noise'` with `triage_source = 'ai'`
    is therefore read as open here, and its old verdict comes back, if at all,
    as an adopted built-in review.
    """
    if _truthy(finding.get("remediated")):
        return STATE_FIXED, "the scanner confirmed it is patched"

    if finding.get("stale_since"):
        # Ingest-then-prune (X7): a completed run of the owning scanner did not
        # see this finding again, but it is muted or human-owned so it was kept.
        return STATE_FIXED, "the last scan of this source no longer reports it"

    validation = _lower(finding.get("validation_status"))
    if validation == "rejected":
        # js_recon and TruffleHog both write it for the provider's own verdict.
        # 'unknown' (a timeout, a 429, a 403...) is no verdict and stays open.
        return STATE_INACTIVE, "a validator tested the credential and the service rejected it"
    if validation == "format_invalid":
        return STATE_INACTIVE, "the value is not a well-formed credential"
    if validation == "unvalidated" and finding.get("validated_at"):
        # A TruffleHog node written before 'rejected': checked and dead, as
        # opposed to never checked at all.
        return STATE_INACTIVE, "the credential was tested and does not work"
    if _validator_rejected_it(finding):
        return STATE_INACTIVE, "a validator tested the credential and the service rejected it"
    if _port_found_closed(finding):
        return STATE_INACTIVE, "the port scan found the port closed"

    host = finding.get("triage_host") or finding.get("host")
    if host and host in facts.gone_hosts:
        return STATE_GONE, "the host has no live endpoint and no open port"

    return STATE_OPEN, ""


def _port_found_closed(finding: dict) -> bool:
    """A passive CVE whose port this run's port scan looked at and did not
    find open. A missing `port_confirmed` is unknown, never closed."""
    verdict = finding.get("port_confirmed")
    return (_lower(finding.get("source")) in PASSIVE_CVE_SOURCES
            and (verdict is False or _lower(verdict) == "false"))


def _passive_unconfirmed(finding: dict) -> bool:
    """A passive CVE no port scan of this run confirmed open."""
    verdict = finding.get("port_confirmed")
    return (_lower(finding.get("source")) in PASSIVE_CVE_SOURCES
            and (_ip_left_the_run(finding)
                 or not (verdict is True or _lower(verdict) == "true")))


def _ip_left_the_run(finding: dict) -> bool:
    """A passive CVE whose IP has no node in the project's graph any more.

    A full run rebuilds the IP nodes from its own targets, and the
    positive-coverage prune keeps a passive CVE on an IP it did not re-check,
    so the CVE outlives its IP: nothing of this run says whether it is
    reachable, and its `port_confirmed` is the last run's that had the IP. A
    row without `target_ip_in_graph` (no `target_ip`, an older reader) is not
    one.
    """
    present = finding.get("target_ip_in_graph")
    return (_lower(finding.get("source")) in PASSIVE_CVE_SOURCES
            and (present is False or _lower(present) == "false"))


def _validator_rejected_it(finding: dict) -> bool:
    """A LEGACY js_recon node: a validator ran and the service rejected the
    credential itself.

    js_recon now writes 'rejected', 'unknown' and 'format_invalid' (read
    directly by `finding_state`). Nodes written before that hold 'invalid', a
    word it wrote for a rejection, for a call that never got an answer (a
    timeout, an open circuit breaker, no key found in the match) and for ANY
    non-2xx answer alike.
    `validation_info.error` tells the first apart; of the answers, only a 401
    says the credential is not accepted. A 403 is as often a live key without
    the scope (or the SSO grant) the probe needed, and a 404 a moved endpoint,
    so those stay open: hiding a live credential is the failure to avoid.
    'unvalidated' is never enough: js_recon means "no validator" by it.
    """
    if _lower(finding.get("validation_status")) != "invalid":
        return False
    info = finding.get("validation_info")
    if isinstance(info, str):
        try:
            info = json.loads(info) if info.strip() else None
        except ValueError:
            return False
    if not isinstance(info, dict):
        return False
    error = _lower(info.get("error"))
    if error == "format_invalid":
        return True
    if error:
        return False
    status = re.search(r"\bstatus=(\d{3})\b", str(info.get("info") or ""))
    return bool(status) and status.group(1) == "401"


# ===========================================================================
# C (3.2.3), and what an operator's clicks teach it (Phase 8a)
# ===========================================================================
def detector_key(finding: dict) -> str:
    """Which DETECTOR produced this, as a stable string.

    Not the same thing as `group_key`. A group is one problem with one fix, so
    it merges by CVE. A detector key is the rule that fired, so that clicking
    "false positive" on one of its findings says something about the next one:
    a nuclei template, a secret detector, a GVM test, a deterministic check.

    Deliberately NOT per advisory. "CVE-2021-23337 was a false positive here"
    says nothing about CVE-2022-0001, so OSV-style sources key on the source
    alone and learn how much this operator trusts advisory matching at all.
    """
    finding = finding or {}
    source = _lower(finding.get("source"))
    label = str(finding.get("label") or "")

    def part(*values, cap=100):
        for value in values:
            text = str(value or "").strip().lower()
            if text:
                # A tight charset on purpose: this string is written to the
                # graph and read back as a grouping key, so a template id
                # carrying separators must not be able to look like another
                # detector's key.
                return re.sub(r"[^a-z0-9._-]+", "-", text)[:cap]
        return ""

    if source == "nuclei":
        template = part(finding.get("template_id"))
        return f"nuclei:{template}" if template else "nuclei"

    if source == "gvm" or label == "ExploitGvm":
        # The OID identifies the NVT. It is the closest thing GVM has to a
        # rule id, and its families are far too broad to learn on.
        oid = part(finding.get("oid"), finding.get("nvt_oid"))
        return f"gvm:{oid}" if oid else "gvm"

    if source == "security_check":
        check = part(finding.get("type"), finding.get("name"))
        return f"check:{check}" if check else "security_check"

    if source == "urlscan_leak":
        # Per type AND kind: a "false positive" on a folder listing, or on a
        # config file, must not teach down leaked reset links or .env files.
        kind_type = part(finding.get("type"))
        kind = part(finding.get("finding_kind"))
        if kind:
            return f"urlscan_leak:{kind_type}:{kind}"
        return f"urlscan_leak:{kind_type}" if kind_type else "urlscan_leak"

    if label in ("Secret", "GithubSecret", "GithubSensitiveFile",
                 "MultiscannerFinding") or source in ("trufflehog", "github_hunt"):
        detector = part(finding.get("detector_name"), finding.get("secret_type"),
                        finding.get("key_type"))
        prefix = source or "secret"
        return f"{prefix}:{detector}" if detector else prefix

    if source in ("ai_surface_recon", "ai_attack"):
        owasp = part(finding.get("ai_owasp_llm_id"))
        return f"{source}:{owasp}" if owasp else source

    if source:
        return source
    return f"label:{part(label) or 'unknown'}"


def learned_confidence(base: float, real: int, false_positive: int) -> Optional[float]:
    """This user's verdicts on this detector, folded into its class prior.

    A Beta posterior with the class prior as its pseudo-counts:

        C = (W x base + real) / (W + real + fp)      W = DETECTOR_PRIOR_WEIGHT

    With no labels it returns None and the rule stands. With one label it barely
    moves. With twenty it is mostly what the operator said. Bounded on both
    sides so a detector is never learned into silence or into certainty.
    """
    real = max(0, as_int(real))
    false_positive = max(0, as_int(false_positive))
    if real + false_positive == 0:
        return None
    weight = DETECTOR_PRIOR_WEIGHT
    posterior = (weight * float(base) + real) / (weight + real + false_positive)
    return min(DETECTOR_MAX_CONFIDENCE, max(DETECTOR_MIN_CONFIDENCE, posterior))


def confidence(finding: dict, facts: ProjectFacts) -> Factor:
    """C: P(the finding is real), from how it was detected and how this
    operator's own verdicts on that detector have turned out.

    PROVEN is exempt. Something an exploit demonstrated is real whatever anyone
    clicked, and letting clicks talk it down is the same mistake the AI review
    is forbidden from making.
    """
    rule = _rule_confidence(finding, facts)
    if is_proven(finding, facts):
        return rule

    counts = (facts.detector_labels or {}).get(detector_key(finding))
    if not counts:
        return rule

    real = as_int(counts.get("real"))
    false_positive = as_int(counts.get("fp"))
    learned = learned_confidence(rule.value, real, false_positive)
    if learned is None:
        return rule

    verdicts = real + false_positive
    return Factor(
        learned,
        f"{rule.evidence}; you judged {real} of {verdicts} of these real",
    )


def _rule_confidence(finding: dict, facts: ProjectFacts) -> Factor:
    source = _lower(finding.get("source"))
    label = str(finding.get("label") or "")

    if is_proven(finding, facts):
        return Factor(1.0, "proven: an exploit or a validated credential")

    # Keyed on the type, not the source: origin discovery and the security
    # check MERGE the same waf_bypass node, and `source` is set on create only.
    if _lower(finding.get("type")) == "waf_bypass" and _truthy(finding.get("file_match")):
        return Factor(0.9, "the suspect served the site's own build file byte for byte")

    if source == "security_check":
        return _security_check_confidence(finding)

    if _lower(finding.get("validation_status")) == "validated" and \
            _is_public_client_key(finding):
        return Factor(0.95, "a validator called an API with the key and it worked")

    # ---- 0.95: the tool interacted with the finding and kept the proof ----
    if source == "nuclei":
        if _truthy(finding.get("matcher_status")) and _as_list(
                finding.get("extracted_results")):
            return Factor(0.95, "nuclei matched and extracted proof from the response")
        if _truthy(finding.get("is_dast_finding")) and _truthy(
                finding.get("matcher_status")):
            return Factor(0.95, "a nuclei DAST matcher hit")

    if source in ("gvm", "ExploitGvm") or label == "ExploitGvm":
        qod_type = _lower(finding.get("qod_type"))
        qod = as_int(finding.get("qod"), -1)
        if qod_type in GVM_ACTIVE_QOD_TYPES or qod >= 95:
            return Factor(0.95, f"GVM QoD {qod if qod >= 0 else qod_type}, active detection")
        if qod >= 70:
            return Factor(0.75, f"GVM QoD {qod}, banner or version detection")
        if qod >= 0:
            return Factor(0.4, f"GVM QoD {qod}, a weak detection")

    if source == "nmap_nse" and _lower(finding.get("state")) == "vulnerable":
        return Factor(0.95, "the NSE script reported VULNERABLE")

    if source == "takeover_scan":
        verdict = _lower(finding.get("verdict"))
        if verdict == "confirmed":
            return Factor(0.95, "the takeover was confirmed")
        if verdict == "likely":
            return Factor(0.75, "the takeover looks likely")
        if verdict == "manual_review":
            return Factor(0.25, "the tool asked for a manual review")

    if source == "cache_poisoning":
        tier = _lower(finding.get("confidence_tier"))
        if tier == "confirmed":
            return Factor(0.95, "the cache poisoning was confirmed")
        if tier == "strong":
            return Factor(0.75, "strong cache-poisoning evidence")
        if tier == "tentative":
            return Factor(0.25, "tentative cache-poisoning evidence")

    if source in ("ai_surface_recon", "ai_attack"):
        asr = as_float(finding.get("ai_asr"))
        oracle = _lower(finding.get("ai_oracle_kind"))
        if asr is not None and asr >= 0.5 and oracle in ("classifier", "judge_llm"):
            return Factor(0.95, f"attack success rate {asr:.0%}, judged by {oracle}")

    if source in ("graphql_scan", "graphql_cop") and _truthy(
            finding.get("introspection_enabled")):
        return Factor(0.95, "GraphQL introspection answered")

    # ---- 0.9: an advisory against a KNOWN version ----
    if source in ("osv", "retirejs"):
        if _lower(finding.get("verdict")) == "malicious" or \
                str(finding.get("id") or "").upper().startswith("MAL-"):
            return Factor(1.0, "OSV lists this package as malicious")
        if finding.get("package_version"):
            return Factor(0.9, "an advisory against the package's exact version")
        return Factor(0.4, "an advisory against a package with no known version")

    if source == "guarddog":
        if _truthy(finding.get("soft_error")):
            return Factor(0.1, "GuardDog could not analyse this package")
        return Factor(0.25, "a GuardDog heuristic, not a confirmation")

    if source in ("shodan", "shodan_api", "internetdb"):
        method = _lower(finding.get("detection_method"))
        if method == "passive_verified":
            # Credible, but Shodan's check is not ours and may be stale: below
            # the 0.75 that T1/T2 need, so it ranks first in T3 until proven.
            return Factor(0.6, "Shodan verified this CVE on the service")
        if method == "passive_version_match":
            return Factor(0.4, "a CVE matched to a service banner's product and version")
        # Rows written before the grading carry no method, and every one of
        # them was an IP-level catalog match.
        return Factor(0.25, "a CVE from the IP's catalog, with no service or version observed")

    if source == "origin_discovery":
        confidence_score = as_float(finding.get("confidence_score"))
        if confidence_score is not None and confidence_score >= 70:
            return Factor(0.75, f"origin confidence {confidence_score:.0f}")
        return Factor(0.4, "a weak origin match")

    if source in ("js_recon", "jsluice"):
        level = normalise_confidence(finding.get("confidence"))
        if level is not None:
            if level >= 0.85:
                return Factor(0.75, "the JS scanner is confident")
            if level >= 0.5:
                return Factor(0.6, "medium JS-scanner confidence")
            return Factor(0.25, "the JS scanner is unsure")

    # ---- the source baseline ----
    if source in CONFIDENCE_BY_SOURCE:
        return Factor(CONFIDENCE_BY_SOURCE[source], f"detected by {source}")

    if not source and label in ("GithubSecret", "GithubSensitiveFile"):
        # The GitHub-hunt writer stores no `source` on its nodes.
        return Factor(0.6, "a secret found in a repository, never validated")
    if not source and label == "MalPackageFinding":
        verdict = _lower(finding.get("verdict"))
        if verdict == "malicious":
            return Factor(1.0, "the package is listed as malicious")
        if verdict == "suspicious":
            return Factor(0.25, "a heuristic flagged this package")
        return Factor(0.6, "a supply-chain finding")

    return Factor(
        CONFIDENCE_UNKNOWN_SOURCE,
        f"unknown source {source or '(none)'}: using the default",
    )


def _security_check_confidence(finding: dict) -> Factor:
    check = _lower(finding.get("type") or finding.get("name"))
    if check == "waf_bypass":
        method = _lower(finding.get("detection_method"))
        if method:
            value, why = WAF_BYPASS_CONFIDENCE.get(
                method, (CONFIDENCE_UNKNOWN_SOURCE,
                         f"unknown detection method {method}: using the default"))
            return Factor(value, why)
    elif check in SECURITY_CHECK_CONFIDENCE:
        value, why = SECURITY_CHECK_CONFIDENCE[check]
        return Factor(value, why)
    return Factor(CONFIDENCE_BY_SOURCE["security_check"],
                  "a deterministic check, not a detection")


#: An agent's ChainFinding proves the finding it CONFIRMS only at this
#: confidence (0-100) or above: below it the agent itself called the
#: confirmation a guess. A missing value is the writer's default
#: (chain_graph_writer.fire_record_finding), so older proof keeps counting.
#: The proof fact query and triage_mixin._LIVE_PROOF apply the same numbers.
PROOF_MIN_AGENT_CONFIDENCE = 70
AGENT_CONFIDENCE_DEFAULT = 80


def agent_proof_counts(confidence: Any) -> bool:
    """Is a ChainFinding of this confidence proof? Mirrors Cypher's
    `coalesce(toInteger(cf.confidence), 80) >= 70`."""
    return as_int(confidence, AGENT_CONFIDENCE_DEFAULT) >= PROOF_MIN_AGENT_CONFIDENCE


def is_proven(finding: dict, facts: ProjectFacts) -> bool:
    """Did something actually demonstrate this finding, rather than infer it?"""
    finding_id = str(finding.get("id") or "")
    if finding_id and finding_id in facts.proven_finding_ids:
        return True
    if _lower(finding.get("label")) == "exploitgvm":
        return True
    if as_int(finding.get("confirmed_exploits")) > 0:
        return True
    # A public client key is meant to work, so a validator getting an answer
    # with one proves its normal state, not an exploit.
    if _lower(finding.get("validation_status")) == "validated" and \
            not _is_public_client_key(finding):
        return True
    if _lower(finding.get("verdict")) == "malicious":
        return True
    if str(finding_id).upper().startswith("MAL-"):
        return True
    cves = {str(c).upper() for c in _as_list(finding.get("cve_ids"))}
    return bool(cves & facts.proven_cve_ids)


# ===========================================================================
# L (3.2.4): the highest applicable signal, never a sum
# ===========================================================================
def likelihood(finding: dict, facts: ProjectFacts, intel: dict,
               cvss: Cvss, klass: FindingClass) -> Factor:
    candidates: list[tuple[float, str]] = []

    if is_proven(finding, facts):
        candidates.append((1.0, "proven by an exploit"))

    cves = [str(c).upper() for c in _as_list(finding.get("cve_ids"))]
    best_intel = _best_cve_intel(cves, intel)

    if _truthy(finding.get("cisa_kev")) or best_intel.get("kev"):
        candidates.append((0.9, "listed in CISA KEV"))

    epss = best_intel.get("epss_score")
    if epss is not None:
        if epss >= 0.5:
            candidates.append((0.8, f"EPSS {epss:.2f}"))
        elif epss >= 0.1:
            candidates.append((0.6, f"EPSS {epss:.2f}"))
        elif epss >= 0.01:
            candidates.append((0.4, f"EPSS {epss:.2f}"))

    if _is_exploitable_class(finding, klass) and _is_tool_confirmed(finding):
        candidates.append((0.7, f"a confirmed {klass.name} finding"))

    if klass.name == "credential" or _credential_in_response(finding):
        candidates.append((0.6, "a usable credential"))

    if best_intel.get("has_poc") or _truthy(finding.get("has_exploit")):
        candidates.append((0.5, "a public proof of concept"))

    if cvss.exploitability is not None:
        candidates.append((
            0.6 * cvss.exploitability,
            f"CVSS v{cvss.version} exploitability {cvss.exploitability:.2f}",
        ))

    candidates.append((klass.likelihood, f"the {klass.name} class prior"))

    value, evidence = max(candidates, key=lambda pair: pair[0])

    # ---- modifiers, applied AFTER the max ----
    modifier = 1.0
    notes = []
    if cvss.user_interaction == "R":
        modifier *= 0.7
        notes.append("a victim must act")
    if cvss.attack_complexity == "H":
        modifier *= 0.8
        notes.append("high attack complexity")

    host = finding.get("triage_host") or finding.get("host") or ""
    hot = 1.0
    if host and host in facts.compromised_hosts:
        hot *= 1.3
        notes.append("the agent compromised this host")
    if host and host in facts.threat_intel_hosts:
        hot *= 1.15
        notes.append("the host appears in threat intelligence")
    if _dangerous_combination(finding, facts, host):
        hot *= 1.2
        notes.append("a dangerous combination on this host")
    modifier *= min(hot, 1.5)

    if modifier != 1.0:
        value = value * modifier
        evidence = f"{evidence}; " + ", ".join(notes)

    return Factor(min(1.0, max(0.0, value)), evidence)


def _best_cve_intel(cve_ids: Iterable[str], intel: dict) -> dict:
    """The strongest intelligence across a finding's CVEs.

    A finding often carries several CVE ids; taking the maximum of each field
    keeps the answer stable no matter what order they arrive in.
    """
    best: dict = {}
    for cve in cve_ids:
        row = (intel or {}).get(cve) or {}
        if row.get("kev"):
            best["kev"] = True
        if row.get("has_poc"):
            best["has_poc"] = True
        if row.get("has_template"):
            best["has_template"] = True
        epss = as_float(row.get("epss_score"))
        if epss is not None and epss > (best.get("epss_score") or -1):
            best["epss_score"] = epss
    return best


def _is_exploitable_class(finding: dict, klass: FindingClass) -> bool:
    if _lower(finding.get("source")) == "urlscan_leak":
        # A historical record: its type names what was seen, not a weakness a
        # tool reached ("takeover_page_seen" is not a takeover).
        return klass.name in EXPLOITABLE_CLASSES
    if _lower(finding.get("type")) == "takeover_error_page":
        # A provider that now asks for a DNS verification record (Netlify,
        # Azure, Shopify, Fastly) leaves the name dangling, not claimable.
        return _lower(finding.get("outcome")) != "dangling_dns"
    haystack = " ".join([
        _lower(finding.get("category")),
        _lower(finding.get("type")),
        _lower(finding.get("takeover_method")),
        _lower(finding.get("cache_impact")),
        " ".join(_lower(t) for t in _as_list(finding.get("tags"))),
        _lower(finding.get("template_id")),
    ])
    if klass.name in EXPLOITABLE_CLASSES:
        return True
    return any(name in haystack for name in EXPLOITABLE_CLASSES)


def _is_tool_confirmed(finding: dict) -> bool:
    if _truthy(finding.get("matcher_status")):
        return True
    if _lower(finding.get("verdict")) == "confirmed":
        return True
    if _lower(finding.get("confidence_tier")) == "confirmed":
        return True
    return _lower(finding.get("state")) == "vulnerable"


#: Credential shapes worth finding inside a stored response body. Deliberately
#: a short, exact list: a loose regex over every response would fire constantly.
_CREDENTIAL_PATTERNS = (
    re.compile(r"\b(?:DB|DATABASE|MYSQL|POSTGRES|REDIS|MONGO)_PASSWORD\s*="),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:SECRET_KEY|API_SECRET|CLIENT_SECRET)\s*="),
)


def _credential_in_response(finding: dict) -> bool:
    body = " ".join(
        str(finding.get(key) or "")
        for key in ("raw_response", "evidence", "extracted_results", "detail")
    )
    return any(pattern.search(body) for pattern in _CREDENTIAL_PATTERNS)


def _dangerous_combination(finding: dict, facts: ProjectFacts, host: str) -> bool:
    """Fixed rules; BOTH halves must exist in the graph."""
    if not host:
        return False
    if host in facts.credential_hosts and host in facts.login_hosts:
        return True
    if host in facts.injectable_auth_hosts:
        return True
    if _truthy(finding.get("introspection_enabled")) and \
            _truthy(finding.get("graphql_get_mutations")):
        return True
    return False


# ===========================================================================
# I (3.2.5)
# ===========================================================================
def impact(finding: dict, facts: ProjectFacts, cvss: Cvss,
           klass: FindingClass) -> Factor:
    value: Optional[float] = None
    evidence = ""

    if cvss.impact is not None:
        value = cvss.impact
        evidence = f"CVSS v{cvss.version} impact {cvss.impact:.2f}"
    else:
        score = as_float(finding.get("cvss_score")) or as_float(finding.get("cve_cvss"))
        if score is not None and score > 0:
            value = min(1.0, score / 10.0)
            evidence = f"CVSS score {score}"
        else:
            severity = normalise_severity(finding.get("severity"))
            ungraded = _lower(finding.get("source")) in ("osv", "internetdb") and \
                severity in ("info", None)
            if severity and not ungraded:
                value = SEVERITY_IMPACT[severity]
                evidence = f"severity {severity}"
            elif ungraded:
                value = IMPACT_UNKNOWN
                evidence = "the advisory was never graded"
            else:
                value = klass.impact
                evidence = f"the {klass.name} class default"

    # A blanket severity cannot raise a class whose writer stamps the same word
    # on everything it creates. The GitHub hunt writes "high" on all 284 of its
    # secrets, 119 of which are private IP addresses; taking that at face value
    # is what put them at the top of the board.
    if klass.caps_impact and value > klass.impact:
        value = klass.impact
        evidence = f"the {klass.name} class caps this (the scanner's severity " \
                   f"is the same for every finding it writes)"

    # A fingerprint identifies software; it is not a weakness on its own.
    tags = {_lower(t) for t in _as_list(finding.get("tags"))}
    if tags & FINGERPRINT_TAGS:
        value = min(value, SEVERITY_IMPACT["info"])
        evidence = "a fingerprint, not a weakness"

    host = finding.get("triage_host") or finding.get("host") or ""
    if host and host in facts.sensitive_hosts:
        value *= 1.2
        evidence += "; on a sensitive asset"

    return Factor(min(1.2, max(0.0, value)), evidence)


# ===========================================================================
# R (3.2.6)
# ===========================================================================
#: Below the 0.7 the KEV and "Act soon" rules need: a finding on an address that
#: is not shown to be the target's own can still be planned for, never rushed.
SHARED_EDGE_MAX_REACH = 0.5
LEFT_TARGET_MAX_REACH = 0.5


def _host_address(host: str) -> str:
    """The address in a host spelled as a URL ("https://198.51.100.1:443"), else the host."""
    if "://" not in host:
        return host
    try:
        return urlparse(host).hostname or host
    except ValueError:
        return host


def reach(finding: dict, facts: ProjectFacts, cvss: Cvss) -> Factor:
    """R, capped when the IP attribution tag says the address may not be the
    target's, or when a passive CVE's IP is no longer in the graph.

    The cap reads the IP itself (or a URL on it), never a hostname: a site
    served through a CDN is still the target's application.
    """
    factor = _reach(finding, facts, cvss)
    if _ip_left_the_run(finding):
        # Said even when R is already lower: R's evidence is what the reviewer
        # reads about reach, and this run has no fact about the address at all.
        return Factor(min(factor.value, LEFT_TARGET_MAX_REACH),
                      f"the IP is no longer among this run's targets, so reach unknown "
                      f"({factor.evidence})")
    address = _host_address(finding.get("triage_host") or finding.get("host") or "")
    if address in facts.shared_edge_hosts and factor.value > SHARED_EDGE_MAX_REACH:
        return Factor(SHARED_EDGE_MAX_REACH,
                      f"a shared CDN edge serving many tenants, not the target's own server "
                      f"({factor.evidence})")
    if (address in facts.no_dns_name_hosts and factor.value > LEFT_TARGET_MAX_REACH
            and _lower(finding.get("source")) in PASSIVE_CVE_SOURCES):
        return Factor(LEFT_TARGET_MAX_REACH,
                      f"no current DNS name of the target points at this IP, which may have "
                      f"left the target ({factor.evidence})")
    return factor


def _reach(finding: dict, facts: ProjectFacts, cvss: Cvss) -> Factor:
    host = finding.get("triage_host") or finding.get("host") or ""

    if cvss.attack_vector == "L" or cvss.attack_vector == "P":
        return Factor(0.3, "the vector needs local or physical access")
    if cvss.attack_vector == "A":
        return Factor(0.5, "the vector needs adjacent network access")

    if host and host in facts.origin_exposed_hosts:
        return Factor(1.0, "behind a CDN, but the origin is exposed")

    package = finding.get("package_purl") or finding.get("package_name")
    if package:
        exposure = facts.package_exposure.get(str(package))
        if exposure == "served":
            return Factor(1.0, "the package is served by a live site")
        if exposure in ("repo", "sbom"):
            return Factor(0.7, f"the package is only in a {exposure}, "
                               f"deployment not confirmed")

    if host and host in facts.live_hosts:
        if host in facts.auth_required_hosts:
            return Factor(0.6, "the URL answered 401/403, so a login is needed")
        return Factor(1.0, "a live endpoint on this host")

    port = as_int(finding.get("target_port"), 0)
    if host and port > 0:
        how = facts.port_status.get((host, port))
        if how == "active":
            return Factor(1.0, f"port {port} was found open by an active scan")
        if how == "passive":
            return Factor(0.7, f"port {port} was only seen passively")
        if _lower(finding.get("source")) in PASSIVE_CVE_SOURCES:
            # Another port of the host being open says nothing about this one.
            return Factor(0.7, f"only a passive source reported port {port}; "
                               f"no scan found it open")

    port_source = facts.port_hosts.get(host) if host else None
    if port_source == "active":
        return Factor(1.0, "an open port found by an active scan")
    if port_source == "passive":
        return Factor(0.7, "the port was only seen passively")

    if _lower(finding.get("source")) in ("github_hunt", "github", "git",
                                         "trufflehog", "github_experimental"):
        if _truthy(finding.get("repository_public")):
            return Factor(1.0, "the repository is public")

    if cvss.privileges_required in ("L", "H"):
        return Factor(0.6, "the vector needs an account")

    if host and host in facts.cdn_only_hosts:
        return Factor(0.7, "behind a CDN with no origin found")

    return Factor(REACH_UNKNOWN, REACH_NO_EVIDENCE)


# ===========================================================================
# The four gates (plan 10.4): what a finding still lacks to be reported
# ===========================================================================
#: Asked of every finding, in this order, before it goes in a report. Each is
#: True, False or None (unknown). They name a candidate's blocker
#: (`disposition`); no tier and no score reads them.
GATES = ("reachable_now", "attributed", "controlled", "impactful")

#: R at or above this is reachable now: the bar the KEV and "Act soon" rules use.
REACHABLE_NOW_MIN_REACH = 0.7

#: A control that ran and showed the hit was not the target's doing: the cache
#: confirmation's verdicts (recon/cache_scan/confirm.py). That check drops such
#: a hit today, so only an older or another writer could store one.
_CONTROL_CONTRADICTED = frozenset({"canary_on_fresh_slot", "baseline_drift", "not_reproduced"})

#: IP attribution tags (plan 11) that pass the attributed gate. `unknown` is the
#: step finding no shared edge, which is all a cloud server or an IP-mode
#: target can show: it is not evidence against the target.
_ATTRIBUTED_TAGS = frozenset({"dedicated", "unknown"})


def _gate_name(host: str) -> str:
    """The host's name or address, lower-case, with no scheme, port or IPv6
    brackets: how the coverage record spells a skipped host
    (circuit_breaker.hostname_of) and how the IP and DNS facts are keyed."""
    text = str(host or "").strip()
    if "://" in text:
        try:
            text = urlparse(text).hostname or ""
        except ValueError:
            return ""
    elif text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.lower()


def _behind_a_login(facts: ProjectFacts, host: str) -> bool:
    """The matched URL answered, with 401/403: `_reach`'s login rule."""
    return bool(host) and host in facts.live_hosts and host in facts.auth_required_hosts


def _reachable_now(finding: dict, facts: ProjectFacts, cvss: Cvss, host: str,
                   name: str) -> Optional[bool]:
    if host and host in facts.gone_hosts:
        return False
    if name and name in facts.skipped_hosts:
        return None
    if _lower(finding.get("source")) in PASSIVE_CVE_SOURCES:
        # A banner is as current as the port scan that found its port again,
        # whatever else on the host answers.
        verdict = finding.get("port_confirmed")
        if verdict is False or _lower(verdict) == "false":
            return False
        # Only an "open" is discounted: a stale "closed" keeps the finding
        # resolved (finding_state), and this gate agrees with it.
        if _ip_left_the_run(finding):
            return None
        if verdict is True or _lower(verdict) == "true":
            return True
        return None
    if _behind_a_login(facts, host):
        # It answered: the login is the impact gate's business.
        return True
    # Before reach()'s caps: a shared edge is the attribution gate's business.
    raw = _reach(finding, facts, cvss)
    if raw.evidence == REACH_NO_EVIDENCE:
        return None
    return raw.value >= REACHABLE_NOW_MIN_REACH


def _attributed(facts: ProjectFacts, host: str, name: str) -> Optional[bool]:
    """Does the finding sit on the target's own server, as far as the IP
    attribution tag (plan 11) shows? False means a shared edge may be what
    answered, never "not the target's". Unknown until a run has tagged the IP."""
    if not name:
        return None
    tag = facts.ip_ownership.get(name)
    if name in facts.shared_edge_hosts or tag == "shared_edge":
        return False
    if tag is not None:
        return True if tag in _ATTRIBUTED_TAGS else None
    if name in facts.origin_exposed_hosts or host in facts.origin_exposed_hosts:
        return True
    if name in facts.cdn_only_hosts or host in facts.cdn_only_hosts:
        return False
    tags = facts.name_ownership.get(name)
    if tags == {"shared_edge"}:
        return False
    if tags and tags <= _ATTRIBUTED_TAGS:
        return True
    # Untagged, or some of its addresses a shared edge and some not.
    return None


def _evidence_field(value: Any, key: str) -> Any:
    if isinstance(value, str):
        try:
            value = json.loads(value) if value.strip() else None
        except ValueError:
            return None
    return value.get(key) if isinstance(value, dict) else None


def _controlled(finding: dict) -> Optional[bool]:
    """Did a made-up request get a different answer? Only a check that ran and
    read its control says either way: "failed" (the control got no answer) and
    a producer with no control both leave it unknown."""
    verdict = _lower(finding.get("control_check"))
    if not verdict and _lower(finding.get("source")) == "cache_poisoning":
        verdict = _lower(_evidence_field(finding.get("evidence"), "control_check"))
    if verdict == "passed":
        return True
    if verdict in _CONTROL_CONTRADICTED:
        return False
    return None


def _impactful(facts: ProjectFacts, host: str, proven: bool) -> Optional[bool]:
    if proven:
        return True
    if _behind_a_login(facts, host):
        # A 401 is the protection working.
        return False
    return None


def gate_facts(finding: dict, facts: ProjectFacts, proven: bool) -> dict:
    """{gate: True | False | None} for one finding. Pure."""
    finding = finding or {}
    host = str(finding.get("triage_host") or finding.get("host") or "")
    name = _gate_name(host)
    return {
        "reachable_now": _reachable_now(finding, facts, _cvss_of(finding), host, name),
        "attributed": _attributed(facts, host, name),
        "controlled": _controlled(finding),
        "impactful": _impactful(facts, host, proven),
    }


def _gate_value(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


# ===========================================================================
# Tiers (3.2.7): fixed rules, checked top to bottom
# ===========================================================================
@dataclass
class TierInputs:
    """What the tier rules read besides the four factors.

    Stored on the node as `triage_tier_inputs`, so a finding can be re-tiered
    after a verdict or a review without re-reading the graph. `validated` is not
    here: a validated credential already makes `is_proven` true.
    """
    proven: bool = False
    kev: bool = False
    #: A passive CVE no port scan confirmed open: a review's "real" raises its
    #: C to PASSIVE_REVIEW_MAX_CONFIDENCE at most. Stored only when set, so
    #: every other finding keeps its stored inputs as they were.
    passive_unconfirmed: bool = False
    #: A key that is public by design: its disposition is info whatever its
    #: tier. Stored only when set.
    public_client_key: bool = False
    #: {gate: True | False | None} for each of GATES. None as a whole on inputs
    #: stored before the gates were measured: unmeasured, which is not unknown.
    gates: Optional[dict] = None

    def as_dict(self) -> dict:
        out = {"proven": bool(self.proven), "kev": bool(self.kev)}
        if self.passive_unconfirmed:
            out["passive_unconfirmed"] = True
        if self.public_client_key:
            out["public_client_key"] = True
        if self.gates is not None:
            out["gates"] = {g: _gate_value(self.gates.get(g)) for g in GATES}
        return out

    @classmethod
    def from_dict(cls, value) -> "TierInputs":
        value = value if isinstance(value, dict) else {}
        gates = value.get("gates")
        return cls(proven=bool(value.get("proven")), kev=bool(value.get("kev")),
                   passive_unconfirmed=bool(value.get("passive_unconfirmed")),
                   public_client_key=bool(value.get("public_client_key")),
                   gates=({g: _gate_value(gates.get(g)) for g in GATES}
                          if isinstance(gates, dict) else None))


def tier_inputs(finding: dict, facts: ProjectFacts, intel: dict) -> TierInputs:
    finding = finding or {}
    cves = [str(x).upper() for x in _as_list(finding.get("cve_ids"))]
    kev = _truthy(finding.get("cisa_kev")) or _best_cve_intel(cves, intel or {}).get("kev")
    proven = is_proven(finding, facts)
    return TierInputs(proven=proven, kev=bool(kev),
                      passive_unconfirmed=_passive_unconfirmed(finding),
                      public_client_key=(_is_public_client_key(finding)
                                         or _truthy(finding.get("public_client_key"))),
                      gates=gate_facts(finding, facts, proven))


def tier_rule(inputs: TierInputs, c: float, l: float, i: float, r: float) -> tuple[str, str]:
    """The tier rules, from stored inputs rather than the graph."""
    if inputs.proven:
        return "T1", "proven"

    # Guarantee 2. Without this, a KEV-listed CVE whose own vector says
    # C:N/I:N/A:N - it does nothing - would be Act now purely for being famous.
    # Proof is the only thing that overrides "there is no impact here", and it
    # was handled above.
    if i <= SEVERITY_IMPACT["info"]:
        return "T4", "nothing here has any impact"

    if inputs.kev and c >= 0.75 and r >= 0.7:
        return "T1", "KEV-listed, confidently detected and reachable"

    if c >= 0.75 and l >= 0.6 and i >= 0.45 and r >= 0.7:
        return "T2", "likely real, likely exploited, real impact, reachable"

    if c >= 0.4 and i >= 0.2:
        return "T3", "credible, with impact worth planning for"

    return "T4", "no rule placed this higher"


def tier_for(finding: dict, facts: ProjectFacts, intel: dict,
             c: float, l: float, i: float, r: float) -> tuple[str, str]:
    return tier_rule(tier_inputs(finding, facts, intel), c, l, i, r)


def score_for(tier: str, risk: float) -> float:
    """25 x tier_level + 25 x risk, on 0-100.

    The tier is INSIDE the number, so one sort key gives "tier first, then
    risk" and the board never needs a secondary sort that could disagree.
    """
    return round(25.0 * TIER_LEVELS[tier] + 25.0 * risk, 4)


# ===========================================================================
# The entry point
# ===========================================================================
def score(finding: dict, facts: Optional[ProjectFacts] = None,
          intel: Optional[dict] = None) -> ScoreResult:
    """Score one finding. Pure, total, and never raises on a thin row."""
    finding = finding or {}
    facts = facts or ProjectFacts()
    intel = intel or {}

    klass = _class_for(finding)
    cvss = _cvss_of(finding)

    state, state_why = finding_state(finding, facts)

    c = confidence(finding, facts)
    i = impact(finding, facts, cvss, klass)
    r = reach(finding, facts, cvss)
    l = likelihood(finding, facts, intel, cvss, klass)

    warnings = []
    source = _lower(finding.get("source"))
    if source and source not in CONFIDENCE_BY_SOURCE:
        warnings.append(f"source {source!r} has no confidence row")

    inputs = tier_inputs(finding, facts, intel)

    if state != STATE_OPEN:
        # Not ranked, but the facts are kept so the finding can come back.
        return ScoreResult(
            state=state, confidence=c, likelihood=l, impact=i, reach=r,
            risk=0.0, tier="T4", tier_rule=state_why, score=0.0,
            signals=_signals(finding, facts, intel, c, l, i, r, cvss, klass),
            proven=inputs.proven,
            host=str(finding.get("triage_host") or finding.get("host") or ""),
            warnings=warnings,
            tier_inputs=inputs,
        )

    risk = min(1.0, c.value * l.value * i.value * r.value)
    tier, rule = tier_rule(inputs, c.value, l.value, i.value, r.value)

    return ScoreResult(
        state=state, confidence=c, likelihood=l, impact=i, reach=r,
        risk=round(risk, 6), tier=tier, tier_rule=rule,
        score=score_for(tier, risk),
        signals=_signals(finding, facts, intel, c, l, i, r, cvss, klass),
        proven=inputs.proven,
        host=str(finding.get("triage_host") or finding.get("host") or ""),
        warnings=warnings,
        tier_inputs=inputs,
    )


def _cvss_of(finding: dict) -> Cvss:
    return parse_cvss_vector(finding.get("cvss_vector") or finding.get("cvss_metrics")
                             or finding.get("cve_cvss_vector"))


def _class_for(finding: dict) -> FindingClass:
    source = _lower(finding.get("source"))
    label = str(finding.get("label") or "")

    # Before the type-first gate below: no other writer MERGEs a route_exposure
    # node, so the reason that gate exists does not apply to it.
    if source == "route_exposure":
        return _route_exposure_class(finding)
    # The same holds for urlscan's history, whose ids no other writer produces.
    if source == "urlscan_leak":
        return URLSCAN_LEAK_CLASSES.get(_lower(finding.get("type")), URLSCAN_LEAK_DEFAULT)

    # By type before source: origin_discovery MERGEs the same waf_bypass node as
    # security_check and `source` is set on create only, so routing by source
    # made the class depend on which writer got there first.
    if source == "security_check" or _lower(finding.get("type")) in SECURITY_CHECK_CLASSES:
        return classify_security_check(finding.get("type") or finding.get("name"))
    if label in ("Secret", "GithubSecret", "GithubSensitiveFile",
                 "MultiscannerFinding") or source in (
            "github_hunt", "github", "git", "trufflehog", "filesystem",
            "github_experimental"):
        return _secret_class(finding)
    if label == "JsReconFinding" or source in ("js_recon", "jsluice"):
        finding_type = _lower(finding.get("finding_type"))
        if finding_type in JS_RECON_CLASSES:
            return JS_RECON_CLASSES[finding_type]
        return _secret_class(finding)
    if source in ("osv", "retirejs", "guarddog") or label == "MalPackageFinding":
        # A dependency vulnerability with no vector and no intelligence.
        return FindingClass("dependency", 0.3, IMPACT_UNKNOWN)

    for name in EXPLOITABLE_CLASSES:
        if name in _lower(finding.get("category")) or \
                name in _lower(finding.get("type")):
            return FindingClass(name, 0.7, 0.75)

    tags = {_lower(t) for t in _as_list(finding.get("tags"))}
    if tags & {"exposure", "misconfig", "misconfiguration"}:
        return FindingClass("misconfig", 0.3, 0.3, caps_impact=True)

    return CLASS_DEFAULT


def _route_exposure_class(finding: dict) -> FindingClass:
    kind = _lower(finding.get("type"))
    if kind == "secret_exposure":
        detectors = _as_list(finding.get("secret_types"))
        return classify_secret(detectors[0] if detectors else None)
    return ROUTE_EXPOSURE_CLASSES.get(kind, CLASS_DEFAULT)


def _secret_class(finding: dict) -> FindingClass:
    klass = classify_secret(finding.get("detector_name"), finding.get("secret_type"))
    if klass is SECRET_CLASSES["public"] and \
            _lower(finding.get("validation_status")) == "validated":
        return SECRET_CLASSES["public_unrestricted"]
    return klass


def _signals(finding, facts, intel, c, l, i, r, cvss, klass) -> list:
    """The readable chips behind the factors, for `triage_signals`."""
    chips = []
    if is_proven(finding, facts):
        chips.append("proven")
    cves = [str(x).upper() for x in _as_list(finding.get("cve_ids"))]
    best = _best_cve_intel(cves, intel)
    if _truthy(finding.get("cisa_kev")) or best.get("kev"):
        chips.append("KEV")
    if best.get("epss_score") is not None:
        chips.append(f"EPSS {best['epss_score']:.2f}")
    if best.get("has_poc") or _truthy(finding.get("has_exploit")):
        chips.append("public PoC")
    host = finding.get("triage_host") or finding.get("host") or ""
    if host and host in facts.live_hosts:
        chips.append("live endpoint")
    if host and host in facts.compromised_hosts:
        chips.append("hot host")
    if host and host in facts.sensitive_hosts:
        chips.append("sensitive asset")
    if host and host in facts.origin_exposed_hosts:
        chips.append("origin exposed")
    if cvss.version:
        chips.append(f"CVSS v{cvss.version}")
    if klass.name != CLASS_DEFAULT.name:
        chips.append(klass.name)
    return chips


# ===========================================================================
# Groups (3.2.8)
# ===========================================================================
def group_risk(member_risks: Iterable[float]) -> float:
    """P(at least one member gets exploited) = 1 - PROD(1 - r).

    More affected hosts raise the group's risk with diminishing returns, and it
    can never exceed 1 or fall below its best member.
    """
    product = 1.0
    for risk in member_risks:
        product *= (1.0 - min(1.0, max(0.0, float(risk))))
    # 9 places, not 6: rounding a one-member group to 6 could land just BELOW
    # that member's own risk, breaking guarantee 8 by a rounding error.
    return round(1.0 - product, 9)


def best_tier(tiers: Iterable[str]) -> str:
    """The most urgent tier in a group."""
    levels = [TIER_LEVELS.get(t, 0) for t in tiers] or [0]
    top = max(levels)
    for tier, level in TIER_LEVELS.items():
        if level == top:
            return tier
    return "T4"                                            # pragma: no cover


# ===========================================================================
# The three layers, and the one function that combines them
# ===========================================================================
# A finding's final score is never written by anyone. Each layer is stored on
# the node on its own, and `combine_layers` is the only thing that turns them
# into the values the board sorts by:
#
#   BASE      the rules, from a run's facts          rewritten by every run
#   REVIEW    a machine read the evidence and        valid while its evidence
#             corrected factors (the built-in AI,    hash equals the current one
#             or an external agent over MCP)
#   DECISION  a person: Real or False positive       lasts until a person changes it
#
# The higher layer wins. A review is only ever a correction of factors with a
# quote behind it; the tier and the score come from the same rules as the base.

REVIEW_CHANNELS = ("builtin", "mcp")
REVIEW_VERDICTS = ("real", "doubtful", "false_positive", "unclear")
DECISION_STATUSES = ("confirmed", "likely_noise")

DECIDED_BY_RULES = "rules"
DECIDED_BY_REVIEW = "review"
DECIDED_BY_PERSON = "person"


@dataclass
class BaseLayer:
    """The rules-only result of a run, as stored in `triage_base_*`."""
    factors: dict
    tier: str
    tier_rule: str
    state: str
    inputs: TierInputs = field(default_factory=TierInputs)
    score: float = 0.0
    risk: float = 0.0

    @classmethod
    def from_result(cls, result: ScoreResult) -> "BaseLayer":
        return cls(
            factors=result.as_factors_dict(), tier=result.tier,
            tier_rule=result.tier_rule, state=result.state,
            inputs=result.tier_inputs or TierInputs(proven=result.proven),
            score=result.score, risk=result.risk,
        )


@dataclass
class ReviewLayer:
    """One review. Valid only while `evidence_hash` is the finding's current one."""
    verdict: str
    evidence_hash: str
    channel: str = "builtin"
    impact_multiplier: float = 1.0
    impact_quote: str = ""
    disputed_facts: list = field(default_factory=list)


@dataclass
class DecisionLayer:
    """A person's decision. `unreviewed` is the absence of one, not a decision."""
    status: str


@dataclass
class Final:
    score: float
    tier: str
    tier_rule: str
    risk: float
    factors: dict
    state: str
    decided_by: str
    #: One of DISPOSITIONS, and a candidate's blocker. None when the base was
    #: stored before the gates were measured: the readers compute it then.
    disposition: Optional[str] = None
    blocker: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "score": self.score, "tier": self.tier, "tier_rule": self.tier_rule,
            "risk": self.risk, "factors": self.factors, "state": self.state,
            "decided_by": self.decided_by, "disposition": self.disposition,
            "blocker": self.blocker,
        }


# ---------------------------------------------------------------------------
# Disposition (plan 10.5): can this go in a report?
# ---------------------------------------------------------------------------
# The same rules, in the same order and words, as the webapp's read-side
# disposition (webapp/src/lib/triage/disposition.ts), pinned by
# tests/test_disposition_parity.py over its vector files: a finding keeps its
# bucket when a run starts storing the answer.
DISPOSITIONS = ("reportable", "candidate", "info", "excluded")

#: tier_rule's own strings, as the webapp reads them.
TIER_RULE_PROVEN = "proven"
TIER_RULE_NO_IMPACT = "nothing here has any impact"

BLOCKER_NOT_TRIAGED = "not triaged yet"
BLOCKER_AI_FALSE_POSITIVE = "AI review: likely false positive"

#: gate -> (its blocker when it fails, its blocker when it is unknown).
GATE_BLOCKERS = {
    "reachable_now": ("not reachable now", "unknown: reachable now"),
    "attributed": ("shared edge", "unknown: attributed"),
    "controlled": ("failed its control check", "unknown: controlled"),
    "impactful": ("no impact shown", "unknown: impactful"),
}


def gate_blocker(gates: Optional[dict]) -> Optional[str]:
    """The first gate that fails, else the first unknown one. None for
    unmeasured gates, or when every gate passed."""
    if gates is None:
        return None
    for gate in GATES:
        if gates.get(gate) is False:
            return GATE_BLOCKERS[gate][0]
    for gate in GATES:
        if gates.get(gate) is None:
            return GATE_BLOCKERS[gate][1]
    return None


def disposition_of(state: str, tier_rule: str, person_status: Optional[str],
                   inputs: TierInputs) -> tuple[str, Optional[str]]:
    """(disposition, blocker) from a finding's final values. Pure.

    `person_status` is a person's decision only (`confirmed` | `likely_noise`).
    A review never decides here: its false positive is a candidate that says so,
    because the reviewer reads target-controlled text.
    """
    if state in RESOLVED_STATES or person_status == "likely_noise":
        return "excluded", None
    if tier_rule == TIER_RULE_PROVEN or person_status == "confirmed":
        return "reportable", None
    if tier_rule == TIER_RULE_NO_IMPACT or inputs.public_client_key:
        return "info", None
    if state == STATE_FALSE_POSITIVE:
        return "candidate", BLOCKER_AI_FALSE_POSITIVE
    return "candidate", gate_blocker(inputs.gates) or tier_rule or BLOCKER_NOT_TRIAGED


def factor_values(factors: dict) -> dict:
    """{C, L, I, R} as floats from a stored factors dict. Missing is 0."""
    out = {}
    for key in ("C", "L", "I", "R"):
        entry = (factors or {}).get(key)
        value = entry.get("value") if isinstance(entry, dict) else entry
        out[key] = as_float(value) or 0.0
    return out


def review_is_valid(review: Optional[ReviewLayer], evidence_hash: str) -> bool:
    """A review answers the evidence it read, and nothing newer."""
    return bool(review is not None and review.evidence_hash and evidence_hash
                and review.evidence_hash == evidence_hash
                and review.verdict in REVIEW_VERDICTS)


def apply_corrections(values: dict, review: ReviewLayer, proven: bool,
                      real_ceiling: float = 0.95) -> dict:
    """The factor corrections one review makes. Pure.

    A "real" verdict raises C to `real_ceiling`: 0.95, or less for a finding
    whose own record cannot show it is live (a passive CVE).

    On a PROVEN finding a review may only raise: a doubtful verdict, every
    dispute and a multiplier below 1 are ignored, because a sentence in a
    response body does not outweigh an exploit that ran.

    The multiplier needs its own verified `impact_quote`; without one it does
    nothing, so the one numeric correction cannot move a score unquoted.
    """
    c, l, i, r = values["C"], values["L"], values["I"], values["R"]

    if review.verdict == "real":
        c = max(c, real_ceiling)
    elif review.verdict == "doubtful" and not proven:
        c = min(c, 0.25)

    if not proven:
        seen = set()
        for dispute in review.disputed_facts or []:
            fact = dispute.get("fact") if isinstance(dispute, dict) else None
            if not fact or fact in seen:
                continue
            seen.add(fact)
            if fact == "reachable":
                # Only ever lowers: disputing a reach the rules never relied on
                # must not raise it to the unknown default.
                r = min(r, REACH_UNKNOWN)
            elif fact in ("tool_confirmed", "extracted_proof"):
                c = min(c, 0.75)
            elif fact in ("dast_confirmed", "exploitable_class", "public_poc",
                          "credential_in_response"):
                l = min(l, 0.3)
            elif fact == "sensitive_asset":
                i = i / 1.2

    multiplier = as_float(review.impact_multiplier)
    if multiplier is not None and str(review.impact_quote or "").strip():
        multiplier = min(1.5, max(0.5, multiplier))
        if proven:
            multiplier = max(1.0, multiplier)
        i = min(1.2, max(0.0, i * multiplier))

    return {"C": c, "L": l, "I": i, "R": r}


def _review_fp_rule(review: ReviewLayer) -> str:
    if review.channel == "mcp":
        return "an external agent's review found it a false positive"
    return "the AI review found it a false positive"


def combine_layers(base: BaseLayer, review: Optional[ReviewLayer],
                   decision: Optional[DecisionLayer], evidence_hash: str,
                   proven_now: bool = False) -> Final:
    """The final values, from the three layers. Pure, total, idempotent.

    `proven_now` is proof read live when the combine happens outside a run (a
    verdict or a review write), so a finding proven after the last run can
    still not be talked down.

    The disposition is decided last, from the other final values and the
    base's gates, so a review reaches it only through the false-positive state
    it can set, and a person's decision always wins.
    """
    final = _final_values(base, review, decision, evidence_hash, proven_now)
    inputs = replace(base.inputs, proven=bool(base.inputs.proven or proven_now))
    if inputs.gates is None:
        return final
    status = decision.status if decision is not None else None
    disposition, blocker = disposition_of(
        final.state, final.tier_rule, status if status in DECISION_STATUSES else None, inputs)
    return replace(final, disposition=disposition, blocker=blocker)


def _final_values(base: BaseLayer, review: Optional[ReviewLayer],
                  decision: Optional[DecisionLayer], evidence_hash: str,
                  proven_now: bool) -> Final:
    proven = bool(base.inputs.proven or proven_now)
    inputs = replace(base.inputs, proven=proven)
    real_ceiling = (PASSIVE_REVIEW_MAX_CONFIDENCE
                    if base.inputs.passive_unconfirmed and not proven else 0.95)
    evidence = {k: ((base.factors or {}).get(k) or {}).get("evidence", "")
                if isinstance((base.factors or {}).get(k), dict) else ""
                for k in ("C", "L", "I", "R")}
    base_values = factor_values(base.factors)

    def factors_of(values: dict) -> dict:
        return {k: {"value": round(values[k], 4), "evidence": evidence[k]}
                for k in ("C", "L", "I", "R")}

    # 0. A resolved finding leaves the ranking whatever anyone said about it.
    if base.state in RESOLVED_STATES:
        return Final(score=0.0, tier="T4", tier_rule=base.tier_rule, risk=0.0,
                     factors=factors_of(base_values), state=base.state,
                     decided_by=DECIDED_BY_RULES)

    status = decision.status if decision is not None else None
    if status not in DECISION_STATUSES:
        status = None

    # 1. A person's False positive.
    if status == "likely_noise":
        return Final(score=0.0, tier="T4", tier_rule="marked a false positive by you",
                     risk=0.0, factors=factors_of(base_values),
                     state=STATE_FALSE_POSITIVE, decided_by=DECIDED_BY_PERSON)

    # 2. A valid review.
    values = dict(base_values)
    moved_by_review = False
    if review_is_valid(review, evidence_hash):
        if review.verdict == "false_positive" and status != "confirmed" and not proven:
            return Final(score=0.0, tier="T4", tier_rule=_review_fp_rule(review),
                         risk=0.0, factors=factors_of(base_values),
                         state=STATE_FALSE_POSITIVE, decided_by=DECIDED_BY_REVIEW)
        values = apply_corrections(values, review, proven, real_ceiling)
        moved_by_review = any(abs(values[k] - base_values[k]) > 1e-9 for k in values)

    # 3. A person's Real.
    if status == "confirmed":
        values["C"] = 1.0

    decided_by = (DECIDED_BY_PERSON if status
                  else DECIDED_BY_REVIEW if moved_by_review else DECIDED_BY_RULES)

    unchanged = (all(abs(values[k] - base_values[k]) <= 1e-9 for k in values)
                 and inputs == base.inputs)
    if unchanged:
        # Identity: the base as stored, not re-derived from rounded factors.
        return Final(score=base.score, tier=base.tier, tier_rule=base.tier_rule,
                     risk=base.risk, factors=factors_of(base_values),
                     state=STATE_OPEN, decided_by=decided_by)

    # 4. The same rules as the base, on the corrected factors.
    c, l, i, r = values["C"], values["L"], values["I"], values["R"]
    risk = min(1.0, max(0.0, c * l * i * r))
    tier, rule = tier_rule(inputs, c, l, i, r)
    return Final(score=score_for(tier, risk), tier=tier, tier_rule=rule,
                 risk=round(risk, 6), factors=factors_of(values),
                 state=STATE_OPEN, decided_by=decided_by)

"""
RedAmon - Subdomain Takeover Helpers
====================================
Helpers for the layered subdomain takeover module.

Layers:
    1. Subjack  (DNS-first, primary, Apache-2.0 Go binary installed in container)
    2. Nuclei   (fingerprint-based, reuses projectdiscovery/nuclei:latest)
       with template flags -t http/takeovers/ -t dns/

Scoring rules: see score_finding().
"""

from __future__ import annotations

import hashlib
from typing import Iterable, List, Optional


# =============================================================================
# Provider fingerprints
# =============================================================================
# Maps lowercase signals (subjack `service`, nuclei `template-id`, or CNAME
# substrings) to a canonical provider slug. Used by _normalize_* helpers and by
# provider_from_cname(). Keep this list in sync with nuclei-templates/http/
# takeovers/ and subjack fingerprints.
PROVIDER_FROM_SIGNAL: dict[str, str] = {
    # Subjack service names (as emitted in Result.service)
    "github": "github-pages",
    "heroku": "heroku",
    "aws/s3": "aws-s3",
    "aws-s3": "aws-s3",
    "shopify": "shopify",
    "fastly": "fastly",
    "ghost": "ghost",
    "zendesk": "zendesk",
    "tumblr": "tumblr",
    "unbounce": "unbounce",
    "readthedocs": "readthedocs",
    "surge": "surge",
    "pantheon": "pantheon",
    "desk": "desk",
    "cargo": "cargo",
    "helpjuice": "helpjuice",
    "helpscout": "helpscout",
    "bitbucket": "bitbucket",
    "wordpress": "wordpress",
    "teamwork": "teamwork",
    "tictail": "tictail",
    "intercom": "intercom",
    "webflow": "webflow",
    "uservoice": "uservoice",
    "kajabi": "kajabi",
    "pingdom": "pingdom",
    "tilda": "tilda",
    "statuspage": "statuspage",
    "campaignmonitor": "campaignmonitor",
    # Subjack internal service strings (emitted in Result.service for non-CNAME checks)
    "ns delegation takeover": "ns-delegation",
    "ns takeover": "ns-delegation",
    "spf takeover": "spf-include",
    "mx takeover": "mx-takeover",
    "zone transfer": "zone-transfer",
    # Nuclei template-id substrings (template names follow -<service>-takeover pattern)
    "github-takeover": "github-pages",
    "heroku-takeover": "heroku",
    "aws-bucket-takeover": "aws-s3",
    "s3-takeover": "aws-s3",
    "fastly-takeover": "fastly",
    "shopify-takeover": "shopify",
    "ghost-takeover": "ghost",
    "zendesk-takeover": "zendesk",
    "readthedocs-takeover": "readthedocs",
    "webflow-takeover": "webflow",
    "unbounce-takeover": "unbounce",
    "statuspage-takeover": "statuspage",
    "elasticbeanstalk-takeover": "aws-elastic-beanstalk",
    "azure-takeover": "azure",
    "detect-dangling-cname": "dangling-cname",
    "dns-saas-service-detection": "dns-saas",
    # CNAME domain patterns (longest first -- processed in order)
    ".github.io": "github-pages",
    ".herokuapp.com": "heroku",
    ".herokussl.com": "heroku",
    ".s3.amazonaws.com": "aws-s3",
    ".s3-website": "aws-s3",
    ".cloudfront.net": "aws-cloudfront",
    ".elasticbeanstalk.com": "aws-elastic-beanstalk",
    ".azurewebsites.net": "azure-app-service",
    ".blob.core.windows.net": "azure-blob",
    ".trafficmanager.net": "azure-traffic-manager",
    ".cloudapp.net": "azure-cloud-services",
    ".myshopify.com": "shopify",
    ".ghost.io": "ghost",
    ".zendesk.com": "zendesk",
    ".fastly.net": "fastly",
    ".readthedocs.io": "readthedocs",
    ".unbouncepages.com": "unbounce",
    ".surge.sh": "surge",
    ".netlify.app": "netlify",
    ".netlify.com": "netlify",
    ".vercel.app": "vercel",
    ".pantheonsite.io": "pantheon",
    ".webflow.io": "webflow",
    ".tumblr.com": "tumblr",
    ".statuspage.io": "statuspage",
    ".desk.com": "desk",
    ".helpjuice.com": "helpjuice",
    ".helpscoutdocs.com": "helpscout",
    ".intercom.help": "intercom",
    ".bitbucket.io": "bitbucket",
}

# Providers where a claim is a single-step registration (name-based namespace,
# no verification challenge). A confirmed match on these is auto-exploitable
# and gets a confidence bump.
AUTO_EXPLOITABLE_PROVIDERS: frozenset[str] = frozenset({
    "github-pages",
    "heroku",
    "aws-s3",
    "shopify",
    "fastly",
    "ghost",
    "unbounce",
    "readthedocs",
    "surge",
    "webflow",
    "tumblr",
    "statuspage",
})


def provider_from_cname(cname: Optional[str]) -> Optional[str]:
    """Map a CNAME target hostname to a canonical provider slug, or None."""
    if not cname:
        return None
    lowered = cname.lower().rstrip(".")
    # Check longest CNAME patterns first
    best_match: tuple[int, Optional[str]] = (0, None)
    for signal, provider in PROVIDER_FROM_SIGNAL.items():
        if signal.startswith(".") and signal in ("." + lowered if not lowered.startswith(".") else lowered):
            if len(signal) > best_match[0]:
                best_match = (len(signal), provider)
    return best_match[1]


def provider_from_signal(signal: Optional[str]) -> Optional[str]:
    """
    Map any short signal (subjack `service` field, nuclei `template-id`) to a
    provider slug. CNAME patterns (inputs starting with `.`) are rejected up
    front -- those are reserved for `provider_from_cname()`.
    """
    if not signal:
        return None
    lowered = signal.lower().strip()
    # Reject CNAME-shaped inputs: they are tool-agnostic DNS patterns, not
    # service identifiers, so they must go through provider_from_cname().
    if lowered.startswith("."):
        return None
    # Exact match first
    if lowered in PROVIDER_FROM_SIGNAL:
        return PROVIDER_FROM_SIGNAL[lowered]
    # Substring match for template-ids (e.g. "github-pages-takeover-v2" → github-pages)
    for key, provider in PROVIDER_FROM_SIGNAL.items():
        if key.startswith("."):
            continue  # CNAME patterns only in provider_from_cname
        if key in lowered:
            return provider
    return None


# =============================================================================
# Subjack command builder
# =============================================================================
def build_subjack_command(
    targets_file: str,
    output_file: str,
    *,
    threads: int = 10,
    timeout: int = 30,
    ssl: bool = True,
    all_urls: bool = False,
    check_ns: bool = False,
    check_ar: bool = False,
    check_mail: bool = False,
    verbose: bool = False,
    resolver_list: Optional[str] = None,
) -> list[str]:
    """
    Build the subjack argv.

    Flags (verified against upstream README of haccer/subjack):
        -w <wordlist>  Path to subdomain list
        -t <int>       Concurrent threads (default 10)
        -timeout <sec> Connection timeout (default 10)
        -o <file>      Output file -- use .json extension for JSON output
        -ssl           Force HTTPS for probing (improves accuracy)
        -a             Test every URL, not just identified CNAMEs
        -m             Flag dead CNAMEs even when service says unclaimed
        -r <file>      DNS resolver list
        -ns            Check NS takeovers
        -ar            Check stale A records
        -mail          Check SPF includes + MX takeovers
        -v             Verbose

    Note: subjack has NO -c flag; fingerprints are compiled into the binary.
    """
    cmd: list[str] = [
        "subjack",
        "-w", targets_file,
        "-t", str(threads),
        "-timeout", str(timeout),
        "-o", output_file,
    ]
    if ssl:
        cmd.append("-ssl")
    if all_urls:
        cmd.append("-a")
    if check_ns:
        cmd.append("-ns")
    if check_ar:
        cmd.append("-ar")
    if check_mail:
        cmd.append("-mail")
    if verbose:
        cmd.append("-v")
    if resolver_list:
        cmd.extend(["-r", resolver_list])
    return cmd


# =============================================================================
# BadDNS command builder (Docker-in-Docker, isolated AGPL sidecar)
# =============================================================================
# Docker run pattern, mirrors how nuclei is invoked. Calls the BadDNS batch
# entrypoint (`/usr/local/bin/baddns-batch`) with a shared-volume targets
# file. Output is NDJSON on stdout (one Finding per line).
#
# AGPL isolation: RedAmon Python never imports baddns. The binary lives
# in its own image (`redamon-baddns:latest`) with its own filesystem.
# Process + filesystem boundary = not a derivative work. See
# THIRD-PARTY-LICENSES.md.
# =============================================================================
# BadDNS module registry -- lowercase per upstream convention.
#
# Upstream ships 11 modules but only 10 are addressable via CLI. MTA-STS is
# excluded here intentionally: baddns-2.1.0's validate_modules regex rejects
# hyphens and its substring-match against `module.name.upper()` fails for any
# underscore form (MTA_STS vs MTA-STS). Passing "mta_sts" or "mta-sts" to
# `baddns -m` makes the whole invocation exit with argparse error, yielding
# zero findings. The findings_dict may STILL arrive with `"module": "MTA-STS"`
# from other baddns entry points (e.g. bbot), so the normalizer keeps a
# mapping for it -- but it must not be offered as a user-selectable input.
BADDNS_MODULES: tuple[str, ...] = (
    "cname",
    "ns",
    "mx",
    "nsec",
    "references",
    "txt",
    "zonetransfer",
    "dmarc",
    "wildcard",
    "spf",
)

# Default subset -- the high-value takeover-relevant modules. Heavy modules
# like `nsec` (zone walking) and `zonetransfer` are opt-in because they
# can be slow on large targets.
BADDNS_DEFAULT_MODULES: tuple[str, ...] = ("cname", "ns", "mx", "txt", "spf")


def build_baddns_command(
    work_dir_host: str,
    *,
    targets_filename: str = "baddns_targets.txt",
    docker_image: str = "redamon-baddns:latest",
    modules: Iterable[str] = BADDNS_DEFAULT_MODULES,
    nameservers: Iterable[str] = (),
    extra_docker_args: Iterable[str] = (),
) -> list[str]:
    """
    Build the `docker run` argv for spawning the BadDNS sidecar.

    We mount the WORKING DIRECTORY (not a single file) because Docker's
    bind-mount semantics create the target as a directory if it doesn't
    pre-exist in the image filesystem. Mounting the parent directory
    matches the convention used by nuclei_helpers.py / the rest of
    RedAmon.

    `work_dir_host` must be a path visible to the Docker daemon (i.e. the
    HOST path when invoked from Docker-in-Docker). The directory must
    contain `targets_filename`, which becomes `/work/<targets_filename>`
    inside the sidecar.

    The sidecar's entrypoint positional arguments are:
        $1  targets_file  -- inside-container path
        $2  modules       -- comma-separated lowercase module list
        $3  nameservers   -- optional comma-separated resolver list

    Returns a list suitable for subprocess.run.
    """
    safe_modules = [m for m in modules if m in BADDNS_MODULES]
    if not safe_modules:
        safe_modules = list(BADDNS_DEFAULT_MODULES)
    modules_arg = ",".join(safe_modules)
    nameservers_arg = ",".join(n.strip() for n in nameservers if n and n.strip())

    cmd: list[str] = [
        "docker", "run", "--rm",
        "-v", f"{work_dir_host}:/work:ro",
    ]
    cmd.extend(extra_docker_args)
    cmd.extend([
        docker_image,
        f"/work/{targets_filename}",
        modules_arg,
        nameservers_arg,
    ])
    return cmd


# =============================================================================
# Finding normalization + deduplication
# =============================================================================
def normalize_subjack_result(raw: dict) -> Optional[dict]:
    """
    Normalize a single Subjack `Result` struct into our canonical finding shape.

    Subjack JSON output is an array of Result objects:
        {
          "subdomain":       "...",
          "vulnerable":      bool,
          "service":         "...",            # omitempty
          "nonexist_domain": "...",            # omitempty (set on NS checks)
        }

    Only `vulnerable == True` results are returned. Non-vulnerable rows are
    filtered out (they're exhaustive noise).
    """
    if not raw or not isinstance(raw, dict):
        return None
    if not raw.get("vulnerable"):
        return None

    hostname = (raw.get("subdomain") or "").strip().lower()
    if not hostname:
        return None

    service_raw = (raw.get("service") or "").strip()
    provider = provider_from_signal(service_raw)
    nonexist = (raw.get("nonexist_domain") or "").strip()

    # Method heuristic: if nonexist_domain is set, we observed an NS/CNAME
    # pointing to a dead zone. Otherwise assume CNAME match.
    method = "ns" if nonexist else "cname"

    return {
        "hostname": hostname,
        "cname_target": nonexist or None,
        "takeover_provider": provider or (service_raw.lower() or "unknown"),
        "takeover_method": method,
        "evidence": f"Subjack confirmed {service_raw or 'unknown service'} takeover",
        "source_tool": "subjack",
        "raw": raw,
    }


def normalize_nuclei_takeover(parsed: dict) -> Optional[dict]:
    """
    Normalize a standardized nuclei finding (output of parse_nuclei_finding) into
    our canonical shape. Only findings whose tags or template-id indicate a
    takeover are kept; other categories (cve, misconfig, etc.) are discarded.
    """
    if not parsed:
        return None

    tags = [t.lower() for t in (parsed.get("tags") or []) if t]
    template_id = (parsed.get("template_id") or "").lower()
    is_takeover = (
        "takeover" in tags
        or "takeover" in template_id
        or "dangling" in template_id
        or "detect-dangling-cname" in template_id
    )
    if not is_takeover:
        return None

    hostname = _hostname_from_url(parsed.get("matched_at") or parsed.get("target") or "")
    if not hostname:
        return None

    provider = provider_from_signal(template_id)
    if not provider:
        # Template-id first segment often names the provider (e.g. "heroku-takeover")
        provider = template_id.split("-")[0] if template_id else "unknown"

    # DNS templates live under dns/ path, http templates under http/takeovers/
    template_path = (parsed.get("template_path") or "").lower()
    method = "dns" if template_path.startswith("dns/") or "dns/" in template_path else "cname"

    extracted = parsed.get("extracted_results") or []
    cname_target = extracted[0] if extracted else None

    return {
        "hostname": hostname,
        "cname_target": cname_target,
        "takeover_provider": provider,
        "takeover_method": method,
        "evidence": (parsed.get("name") or template_id or "Nuclei takeover match"),
        "matcher_name": parsed.get("matcher_name") or "",
        "severity": (parsed.get("severity") or "high").lower(),
        "source_tool": "nuclei_takeover",
        "raw": parsed,
    }


def normalize_baddns_finding(raw: dict) -> Optional[dict]:
    """
    Normalize a single BadDNS finding into our canonical shape.

    BadDNS emits one JSON object per Finding (via `Finding.to_json()`):
        {
          "target":      "promo.example.com",
          "description": "...",
          "confidence":  "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN",
          "severity":    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
          "signature":   "...",        # upstream signature name
          "indicator":   "...",        # fingerprint match
          "trigger":     "..." | [...],
          "module":      "CNAME" | "NS" | "MX" | "TXT" | "SPF" | "..." ,
          "found_domains": [...]       # optional
        }

    Mapping to the canonical takeover finding shape:
        hostname         ← target (lowercased)
        cname_target     ← first element of found_domains when present
        takeover_provider ← provider slug inferred from signature/indicator
                             (falls back to BadDNS module lowercased)
        takeover_method  ← module-driven: cname|ns|mx|spf|txt|dns
        evidence         ← description (+ indicator snippet)
        severity         ← lowercase BadDNS severity (used by the scorer)
        source_tool      ← "baddns"
    """
    if not raw or not isinstance(raw, dict):
        return None

    hostname = (raw.get("target") or "").strip().lower()
    if not hostname:
        return None

    module_raw = (raw.get("module") or "").strip().lower()
    # Normalize BadDNS module name → takeover_method bucket
    method_map = {
        "cname": "cname",
        "ns": "ns",
        "mx": "mx",
        "spf": "spf",
        "txt": "txt",
        "dmarc": "txt",
        "mta_sts": "txt",
        "mta-sts": "txt",
        "references": "cname",
        "wildcard": "dns",
        "zonetransfer": "dns",
        "nsec": "dns",
    }
    method = method_map.get(module_raw, "dns")

    # Provider inference -- prefer signature then indicator then found_domains
    signature = (raw.get("signature") or "").strip()
    indicator = (raw.get("indicator") or "").strip()
    found_domains = raw.get("found_domains") or []
    if isinstance(found_domains, str):
        found_domains = [found_domains]

    cname_target: Optional[str] = None
    if found_domains and isinstance(found_domains, list):
        first = str(found_domains[0]).strip(".").lower()
        cname_target = first or None

    provider = (
        provider_from_signal(signature)
        or provider_from_signal(indicator)
        or (provider_from_cname(cname_target) if cname_target else None)
        or (module_raw if module_raw else "unknown")
    )

    description = (raw.get("description") or "").strip() or f"BadDNS {module_raw} match"
    indicator_trimmed = indicator[:200] if indicator else ""
    # `trigger` in upstream is the DNS record value that fired the match
    # (CNAME chain, NS target, etc). Stringified by baddns itself (lists are
    # joined with ", " in Finding.__init__). Prefer it for evidence when
    # present because it is the most actionable datum for a human triaging.
    trigger_raw = raw.get("trigger")
    if isinstance(trigger_raw, list):
        trigger_str = ", ".join(str(t) for t in trigger_raw if t)
    else:
        trigger_str = str(trigger_raw or "").strip()
    trigger_trimmed = trigger_str[:200]
    evidence_parts = [f"BadDNS: {description}"]
    if indicator_trimmed:
        evidence_parts.append(f"[{indicator_trimmed}]")
    if trigger_trimmed:
        evidence_parts.append(f"via {trigger_trimmed}")
    evidence = " ".join(evidence_parts)[:500]

    severity = (raw.get("severity") or "").strip().lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = ""

    return {
        "hostname": hostname,
        "cname_target": cname_target,
        "takeover_provider": provider,
        "takeover_method": method,
        "evidence": evidence,
        "severity": severity,  # passed through to scorer
        "source_tool": "baddns",
        "raw": raw,
    }


def _hostname_from_url(url: str) -> Optional[str]:
    """Extract the hostname from a URL or host:port string. Lowercase, no port."""
    if not url:
        return None
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    return s.lower() or None


def dedupe_findings(findings: Iterable[dict]) -> list[dict]:
    """
    Merge findings by (hostname, takeover_provider, takeover_method).

    Produces one finding per logical issue with:
        sources: ordered list of tool names that confirmed it
        confirmation_count: len(sources)
        raw_by_source: {tool_name: raw payload}
    """
    merged: dict[tuple[str, str, str], dict] = {}
    for f in findings:
        if not f:
            continue
        key = (
            f.get("hostname") or "",
            f.get("takeover_provider") or "unknown",
            f.get("takeover_method") or "cname",
        )
        if not key[0]:
            continue
        if key not in merged:
            base = dict(f)
            base["sources"] = [f["source_tool"]]
            base["raw_by_source"] = {f["source_tool"]: f.get("raw")}
            base.pop("source_tool", None)
            base.pop("raw", None)
            merged[key] = base
        else:
            existing = merged[key]
            tool = f["source_tool"]
            if tool not in existing["sources"]:
                existing["sources"].append(tool)
            existing["raw_by_source"][tool] = f.get("raw")
            # Keep the higher-precision evidence (subjack beats nuclei fingerprint)
            if tool == "subjack":
                existing["evidence"] = f.get("evidence") or existing.get("evidence")
                existing["cname_target"] = f.get("cname_target") or existing.get("cname_target")
    for v in merged.values():
        v["confirmation_count"] = len(v["sources"])
    return list(merged.values())


# =============================================================================
# Scoring
# =============================================================================
def score_finding(
    finding: dict,
    *,
    confidence_threshold: int = 60,
    manual_review_auto_publish: bool = False,
) -> dict:
    """
    Score a deduped finding. Adds keys: confidence (0-100 int), verdict, severity.

    Rules:
        +30  confirmed by 2+ tools
        +25  subjack confirmed vulnerable
        +20  provider in AUTO_EXPLOITABLE_PROVIDERS
        +15  nuclei template match (stronger than generic substring)
        +10  method = cname (most reliable)
        -15  method = stale_a or mx (probabilistic, needs human)
        -10  provider = unknown

    verdict:
        confirmed      if score >= threshold + 10
        likely         if score >= threshold
        manual_review  otherwise

    severity:
        - confirmed findings keep any nuclei-assigned severity, otherwise "high"
        - likely findings keep nuclei severity, otherwise "medium"
        - manual_review findings default to "info" so they don't pollute the main
          alert stream. When `manual_review_auto_publish=True`, they are promoted
          to "medium" so they surface alongside other findings.
    """
    score = 0
    sources = finding.get("sources") or []
    provider = (finding.get("takeover_provider") or "").lower()
    method = (finding.get("takeover_method") or "cname").lower()

    if len(sources) >= 2:
        score += 30
    if "subjack" in sources:
        score += 25
    if provider in AUTO_EXPLOITABLE_PROVIDERS:
        score += 20
    if "nuclei_takeover" in sources:
        score += 15
    if method == "cname":
        score += 10
    if method in ("stale_a", "mx"):
        score -= 15
    if provider == "unknown":
        score -= 10

    score = max(0, min(100, score))

    if score >= confidence_threshold + 10:
        verdict = "confirmed"
    elif score >= confidence_threshold:
        verdict = "likely"
    else:
        verdict = "manual_review"

    # Severity inherits from nuclei when available; otherwise map from verdict.
    severity = (finding.get("severity") or "").lower()
    if verdict == "manual_review":
        severity = "medium" if manual_review_auto_publish else "info"
    elif not severity:
        severity = "high" if verdict == "confirmed" else "medium"

    finding["confidence"] = score
    finding["verdict"] = verdict
    finding["severity"] = severity
    return finding


# =============================================================================
# Deterministic ID
# =============================================================================
def finding_id(hostname: str, provider: str, method: str) -> str:
    """
    Stable id for Neo4j MERGE -- independent of timestamps so re-scans update
    rather than duplicate.
    """
    key = f"{hostname.lower()}|{provider.lower()}|{method.lower()}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    return f"takeover_{digest}"

"""
RedAmon - Nuclei Helper Functions
==================================
Functions for building Nuclei commands, parsing output, and detecting false positives.
"""

import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Import volume constant from docker helpers
from .docker_helpers import NUCLEI_TEMPLATES_VOLUME


def get_host_path(container_path: str) -> str:
    """
    Convert container path to host path for Docker-in-Docker volume mounts.

    When running inside a container with mounted volumes, sibling containers
    need host paths, not container paths.

    /tmp/redamon is mounted to the same path inside and outside, so no translation needed.
    """
    # /tmp/redamon paths are the same inside and outside the container
    if container_path.startswith("/tmp/redamon"):
        return container_path

    host_output_path = os.environ.get("HOST_RECON_OUTPUT_PATH", "")
    container_output_path = "/app/recon/output"

    if host_output_path and container_path.startswith(container_output_path):
        return container_path.replace(container_output_path, host_output_path, 1)
    return container_path


# =============================================================================
# Nuclei Command Building
# =============================================================================

def build_nuclei_command(
    targets_file: str,
    output_file: str,
    docker_image: str,
    # Nuclei configuration
    severity: List[str] = None,
    templates: List[str] = None,
    exclude_templates: List[str] = None,
    custom_templates: List[str] = None,
    selected_custom_templates: List[str] = None,
    tags: List[str] = None,
    exclude_tags: List[str] = None,
    rate_limit: int = 0,
    bulk_size: int = 0,
    concurrency: int = 0,
    timeout: int = 0,
    retries: int = 0,
    dast_mode: bool = False,
    new_templates_only: bool = False,
    headless: bool = False,
    system_resolvers: bool = False,
    follow_redirects: bool = False,
    max_redirects: int = 0,
    interactsh: bool = True,
    force_dast_pass: bool = False,
    auth_headers: List[str] = None,
    container_name: str = None,
    max_host_error: int = 0,
    ip_mode: bool = False,
    roe_exclusions: bool = False,
) -> List[str]:
    """
    Build nuclei Docker command with all configured parameters.

    Args:
        targets_file: Path to file containing target URLs
        output_file: Path for JSON output
        docker_image: Nuclei Docker image to use
        force_dast_pass: When True, forces -dast and drops tag/template
            filters that would otherwise empty-intersect with the DAST set
            (built-in DAST templates carry tags like xss/sqli/ssti, not the
            detection-class tags users typically configure).
        ip_mode: the run's targets are addresses, so a redirect is followed
            only on the same host (B-07): a cross-host Location can name any
            address on the internet.
        roe_exclusions: the Rules of Engagement exclude hosts, so a redirect
            is followed only on the same host too: an admitted target's
            Location can name an excluded host, and nuclei follows it before
            any scope check (R-2).
        ... (configuration parameters)

    Returns:
        Command as list of arguments
    """
    if force_dast_pass:
        dast_mode = True
        templates = None
        exclude_templates = None
        custom_templates = None
        selected_custom_templates = None
        tags = None
        exclude_tags = None
        new_templates_only = False
    # Docker command with volume mounts
    # Convert container paths to host paths for sibling container volume mounts
    targets_host_path = get_host_path(str(Path(targets_file).parent))
    output_host_path = get_host_path(str(Path(output_file).parent))
    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name

    # --net=host is ALWAYS passed so Nuclei can reach loopback / local-lab
    # targets. See recon/helpers/resource_enum/katana_helpers.py for the long
    # comment on sibling-container network isolation. Nuclei sends HTTP probes
    # to the targets, so without --net=host every fetch against 127.0.0.1
    # silently fails with ECONNREFUSED.
    cmd = [
        "docker", "run", "--rm", "--net=host",
    ]
    # A name so the runtime-cap watchdog can `docker kill` this exact container.
    # vuln_scan's Nuclei and the takeover Nuclei start together in GROUP 6, and a
    # pid-based name repeats across scan containers, so the caller passes a uuid.
    if container_name:
        cmd.extend(["--name", container_name])
    cmd.extend([
        "-v", f"{targets_host_path}:/targets:ro",
        "-v", f"{output_host_path}:/output",
        "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
    ])

    # Mount custom templates if any are selected
    host_custom_templates = os.environ.get("HOST_CUSTOM_TEMPLATES_PATH", "")
    if selected_custom_templates and host_custom_templates:
        cmd.extend(["-v", f"{host_custom_templates}:/custom-templates:ro"])
    
    cmd.extend([
        docker_image,
        "-l", f"/targets/{targets_filename}",
        "-jsonl",
        "-o", f"/output/{output_filename}",
        "-silent",
        "-nc",
        "-duc",  # Disable automatic update check
        "-stats",
        "-stats-interval", "30",  # Progress heartbeat every 30s so long scans aren't silent
    ])
    
    # Severity filter
    if severity:
        cmd.extend(["-severity", ",".join(severity)])
    
    # Template selection
    if templates:
        for template in templates:
            cmd.extend(["-t", template])
    
    if exclude_templates:
        for template in exclude_templates:
            cmd.extend(["-exclude-templates", template])
    
    if custom_templates:
        for template in custom_templates:
            cmd.extend(["-t", template])

    # Built-in template pool + custom selection -- new semantics:
    #   tags is now the gate that decides whether the built-in pool is loaded.
    #     - tags non-empty: load /root/nuclei-templates/ (filtered by -tags below)
    #                       + any selected custom templates alongside.
    #     - tags empty:     load ONLY the selected custom templates (no built-in pool).
    #                       If no custom is selected either, the caller is expected
    #                       to have refused before reaching here -- omitting -t lets
    #                       nuclei fall back to its default directory.
    host_custom_templates = os.environ.get("HOST_CUSTOM_TEMPLATES_PATH", "")
    custom_selected = bool(selected_custom_templates) and bool(host_custom_templates)
    explicit_t_paths = bool(templates) or bool(custom_templates)

    if custom_selected:
        if tags and not explicit_t_paths:
            # Tags filter present -> include the built-in pool so it has something to match.
            cmd.extend(["-t", "/root/nuclei-templates/"])
        # When tags is empty here, we deliberately skip the built-in pool so the
        # scan runs ONLY the custom templates the user picked.
        for tpl_path in selected_custom_templates:
            # Nuclei v3+ only recognizes `.yaml` as a template extension; a `.yml`
            # path is interpreted as a path-list file (one template path per
            # line) and the scan fatals with "no templates provided for scan".
            # If the file on disk is .yml but a .yaml sibling exists, prefer
            # the .yaml. Otherwise pass-through and let nuclei's own error
            # surface (the upload handler normalizes new uploads to .yaml).
            normalized_path = tpl_path
            if tpl_path.lower().endswith(".yml"):
                yaml_sibling = tpl_path[:-4] + ".yaml"
                yaml_disk_path = os.path.join(host_custom_templates, yaml_sibling)
                if os.path.exists(yaml_disk_path):
                    normalized_path = yaml_sibling
                else:
                    print(
                        f"[!][Nuclei] Custom template '{tpl_path}' uses .yml extension. "
                        "Nuclei v3+ requires .yaml for templates (a .yml is read as "
                        "a path-list file). Rename to .yaml or re-upload via the UI."
                    )
            cmd.extend(["-t", f"/custom-templates/{normalized_path}"])
    elif tags and not explicit_t_paths:
        # Tags-only scan: point nuclei at the built-in pool explicitly.
        cmd.extend(["-t", "/root/nuclei-templates/"])

    # Tags
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    
    if exclude_tags:
        cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
    
    # Rate limiting
    if rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])
    
    if bulk_size > 0:
        cmd.extend(["-bulk-size", str(bulk_size)])
    
    if concurrency > 0:
        cmd.extend(["-concurrency", str(concurrency)])
    
    # Timeouts
    if timeout > 0:
        cmd.extend(["-timeout", str(timeout)])
    
    if retries > 0:
        cmd.extend(["-retries", str(retries)])

    # -mhe: stop probing a host after this many errors, so one dead host in a
    # big target list cannot soak the whole pass in timeouts.
    if max_host_error and max_host_error > 0:
        cmd.extend(["-mhe", str(max_host_error)])
    
    # DAST mode for active vulnerability fuzzing
    if dast_mode:
        cmd.append("-dast")
    
    # New templates only
    if new_templates_only:
        cmd.append("-nt")
    
    # Headless browser
    if headless:
        cmd.append("-headless")
    
    # System resolvers
    if system_resolvers:
        cmd.append("-system-resolvers")
    
    # Nuclei applies -H headers to EVERY request it makes, and two of its
    # features send requests to hosts that are not in the target list, so
    # merge_auth_headers' scope check never sees them. Carrying a session into
    # either one hands the operator's credentials to a third party.
    _has_auth = bool(auth_headers)

    # Follow redirects
    if follow_redirects:
        # A cross-host redirect (an SSO hop, an attacker-controlled Location)
        # re-sends the -H session to whatever host it names. -follow-host-redirects
        # keeps redirect coverage but confines it to the host we scope-checked.
        # The CLI flag also overrides a template's own `redirects: true`.
        cmd.extend(["-follow-host-redirects" if _has_auth or ip_mode or roe_exclusions
                    else "-follow-redirects"])
        if max_redirects > 0:
            cmd.extend(["-max-redirects", str(max_redirects)])

    # Interactsh (OOB testing)
    if not interactsh:
        cmd.append("-no-interactsh")
    elif _has_auth:
        # OAST callbacks go to a public third-party collector (interact.sh /
        # oast.fun and friends) that can never be in a project's scope, and the
        # session rides along on the polling requests. Losing blind-OOB coverage
        # beats disclosing the session, so OAST is dropped for authenticated runs.
        cmd.append("-no-interactsh")
        print("[!][Nuclei] OAST disabled: an authenticated session is attached and "
              "interactsh callbacks would carry it to a third-party host.")

    # Authenticated-session profile: real target headers on the tool's own header
    # path, kept entirely separate from the X-Redamon-Ctx branch below. Already
    # scope-checked and sanitized by the caller (merge_auth_headers).
    for header in (auth_headers or []):
        cmd.extend(["-H", header])

    # HTTP traffic capture (Phase 1): route through the capture proxy when
    # enabled + reachable; tag added ONLY in this branch (§20.2 no-leak).
    from helpers.proxy_routing import get_capture_routing
    _cap_url, _cap_token = get_capture_routing("nuclei")
    if _cap_url and _cap_token:
        cmd.extend(["-proxy", _cap_url, "-H", f"X-Redamon-Ctx: {_cap_token}"])

    return cmd


# =============================================================================
# False Positive Detection
# =============================================================================

# Per-scan AI classifier context for the WAF/block-page response filter.
# Initialized once at the top of run_vuln_scan() and consumed by
# is_false_positive(). A module-level dict keeps the call signature of
# is_false_positive() unchanged while still letting the AI cascade fall
# back deterministically when the flag is off.
_FP_AI_CTX: dict = {
    "enabled": False,
    "model": "",
    "user_id": "",
    "project_id": "",
    "cache": None,  # populated when enabled
}

# Confidence threshold required to override the static-negative verdict.
# Mirrors the WAF classifier threshold so behavior is consistent across
# the two cascades.
_FP_AI_BLOCKED_THRESHOLD = 70

# Status codes commonly returned by WAFs/rate-limiters. When a finding's
# response carries one of these AND the static keyword check missed, we
# call the AI to disambiguate. Pure 200 responses bypass the AI call --
# they're unlikely to be block pages and the cost would be wasted.
_FP_AI_SUSPICIOUS_STATUSES = ("403", "406", "418", "429", "503", "451")


def set_fp_ai_ctx(enabled: bool, model: str, user_id: str, project_id: str) -> None:
    """Initialize the per-scan AI cascade context. Called from run_vuln_scan()
    based on the NUCLEI_AI_RESPONSE_FILTER setting."""
    _FP_AI_CTX["enabled"] = bool(enabled and model)
    _FP_AI_CTX["model"] = model or ""
    _FP_AI_CTX["user_id"] = user_id or ""
    _FP_AI_CTX["project_id"] = project_id or ""
    _FP_AI_CTX["cache"] = {} if _FP_AI_CTX["enabled"] else None


def _classify_fp_ai(response_text: str, template_id: str, tags: list) -> Optional[dict]:
    """Lazy wrapper around the Nuclei FP AI classifier. Returns None if AI is
    not enabled or the classifier returns its safe fallback (so callers can
    keep the static behavior)."""
    if not _FP_AI_CTX["enabled"] or not response_text:
        return None
    try:
        from recon.helpers.ai_planner.nuclei_response_filter import classify_nuclei_response
    except Exception as exc:
        print(f"[!][Nuclei-FP-AI] Cannot import nuclei_response_filter: {exc}")
        return None
    result = classify_nuclei_response(
        response_text=response_text,
        template_id=template_id,
        tags=tags,
        model=_FP_AI_CTX["model"],
        cache=_FP_AI_CTX["cache"],
        user_id=_FP_AI_CTX["user_id"],
        project_id=_FP_AI_CTX["project_id"],
    )
    if result.get("source") == "ai_unavailable":
        return None
    return result


def _tag_list(tags) -> list:
    """Nuclei tags as a list; a template may carry them as one comma-separated string."""
    if not tags:
        return []
    if isinstance(tags, str):
        return [t.strip() for t in tags.split(",") if t.strip()]
    return [str(t) for t in tags if t is not None]


def _words(text: str) -> list:
    return [w for w in re.split(r"[^a-z0-9]+", text.lower()) if w]


_TIMING_TAGS = frozenset({"time-based", "blind", "time-based-sqli"})


def _is_timing_template(template_id: str, tags: list) -> bool:
    # Whole words of the id: "time" inside uptime-kuma-panel or iptime-router
    # is a product name, not a template that measures the server's delay.
    if any(t.lower() in _TIMING_TAGS for t in tags):
        return True
    words = _words(template_id)
    return "time" in words or "blind" in words


# Copy a throttling server writes on its 429/503 page. It counts only once the
# response head says the server throttled: on a served page these are ordinary
# words ("Loading, please wait..." above an exposed /.git/config).
_THROTTLE_PHRASES = (
    "too many requests",
    "rate limit",
    "too many attempts",
    "please wait",
    "try again later",
    "temporarily blocked",
    "request blocked",
)

_STATUS_LINE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)")
_MAX_HEAD_LINES = 100


def _response_head(response: str) -> tuple:
    """(status, lower-cased header names) of a raw HTTP response.

    Nuclei's JSONL has no status field; its `response` is the raw dump, status
    line first. A DNS, network or file template's response is no HTTP head:
    (None, set()).
    """
    lines = response.lstrip().splitlines()
    match = _STATUS_LINE.match(lines[0]) if lines else None
    if not match:
        return None, set()
    names = set()
    for line in lines[1:_MAX_HEAD_LINES]:
        if not line.strip():
            break
        name, sep, _ = line.partition(":")
        if sep:
            names.add(name.strip().lower())
    return int(match.group(1)), names


def _throttle_marker(response: str) -> Optional[str]:
    """What shows the server throttled this response, or None."""
    status, header_names = _response_head(response)
    if status == 429:
        return "HTTP 429"
    if status != 503 and "retry-after" not in header_names:
        return None
    lowered = response.lower()
    return next((p for p in _THROTTLE_PHRASES if p in lowered), None)


def is_false_positive(finding: dict) -> tuple:
    """
    Detect common false positive patterns in nuclei findings.

    False positive indicators:
    1. Rate limiting, for time-based and blind templates only: the server
       throttled the response (status 429, or status 503 / a Retry-After
       header with throttle wording), so the delay the template measured is
       the throttle's, not the payload's. Any other template keeps its match,
       and throttle wording on a page the server did not throttle is copy.
    2. WAF/firewall blocks - response doesn't reflect actual vulnerability

    When the AI cascade is enabled (per-scan via set_fp_ai_ctx), responses
    that the static keyword list missed but still LOOK like block pages
    (suspicious status code + small body) get a second pass through the
    LLM. Confidence >= _FP_AI_BLOCKED_THRESHOLD flips the verdict to
    "false positive" so rebranded WAF blocks no longer ship as findings.

    Args:
        finding: Raw nuclei JSON output line

    Returns:
        Tuple of (is_false_positive: bool, reason: str or None)
    """
    # Coerce None to empty string -- Nuclei sometimes emits {"response": null}
    # for findings that didn't capture a response (DNS templates, e.g.).
    # Without this, response.lower() below raises AttributeError and crashes
    # the JSONL parsing loop in _execute_nuclei_pass.
    response = finding.get("response") or ""
    template_id = finding.get("template-id") or ""
    info = finding.get("info") or {}
    tags = _tag_list(info.get("tags"))

    waf_block_indicators = [
        "403 Forbidden",
        "Access Denied",
        "Request Blocked",
        "Blocked by",
        "Web Application Firewall",
        "WAF",
        "ModSecurity",
        "Cloudflare",
        "AWS WAF",
    ]
    
    if _is_timing_template(template_id, tags):
        marker = _throttle_marker(response)
        if marker:
            return True, f"Rate limiting detected ('{marker}') - invalidates time-based attack detection"

    # Check for WAF blocks on injection attacks
    is_injection = any(t in ["sqli", "xss", "rce", "lfi", "ssti", "injection"] for t in tags)
    
    if is_injection:
        for indicator in waf_block_indicators:
            if indicator.lower() in response.lower():
                # 403 with WAF indicators likely means WAF blocked the payload, not a real vuln
                if "403" in response[:50]:
                    return True, f"WAF/Firewall block detected ('{indicator}') - payload was blocked, not executed"

    # AI cascade: when the keyword list missed but the response shape still
    # looks like a block page (suspicious status code, injection-class tag),
    # ask the LLM to disambiguate. Only runs when WAF rebranding likely
    # bypassed the static keyword match -- pure 200 responses skip the AI
    # call to keep cost bounded.
    if is_injection and _FP_AI_CTX["enabled"]:
        head = response[:50] if response else ""
        looks_suspicious = any(code in head for code in _FP_AI_SUSPICIOUS_STATUSES)
        if looks_suspicious:
            ai_result = _classify_fp_ai(response, template_id, tags)
            if ai_result and ai_result.get("is_blocked") and ai_result.get("confidence", 0) >= _FP_AI_BLOCKED_THRESHOLD:
                reason = ai_result.get("reason") or "WAF block fingerprint"
                return True, f"AI: {reason} (conf={ai_result.get('confidence')})"

    return False, None


# =============================================================================
# Nuclei Output Parsing
# =============================================================================

# Order matters: the first key a tag matches decides that tag's category.
_CATEGORY_BY_TAG = {
    "xss": "xss",
    "sqli": "sqli",
    "rce": "rce",
    "lfi": "lfi",
    "rfi": "rfi",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "ssti": "ssti",
    "cve": "cve",
    "exposure": "exposure",
    "misconfig": "misconfiguration",
    "misconfiguration": "misconfiguration",
    "default-login": "authentication",
    "auth-bypass": "authentication",
    "panel": "exposed_panel",
    "tech": "technology",
    "takeover": "takeover",
    "dos": "dos",
    "idor": "idor",
    "csrf": "csrf",
    "redirect": "open_redirect",
    "crlf": "crlf",
    "injection": "injection",
    "file-upload": "file_upload",
    "traversal": "path_traversal",
    "disclosure": "information_disclosure",
    "ssl": "ssl_tls",
    "tls": "ssl_tls",
    "cloud": "cloud",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
    "kubernetes": "cloud",
    "docker": "cloud",
}
_CATEGORY_KEY_WORDS = tuple((tuple(_words(key)), category)
                            for key, category in _CATEGORY_BY_TAG.items())


def _category_from_tags(tags: list) -> str:
    """Category of the first tag that names one, else "general".

    A key matches whole words of a tag only (time-based-sqli is sqli,
    open-redirect is open_redirect), never a substring: "source",
    "ecommerce" and "salesforce" contain "rce", "sqlite" contains "sqli",
    and the Priority Board ranks on this category.
    """
    for tag in tags:
        words = tuple(_words(tag))
        for key, category in _CATEGORY_KEY_WORDS:
            n = len(key)
            if any(words[i:i + n] == key for i in range(len(words) - n + 1)):
                return category
    return "general"


def parse_nuclei_finding(finding: dict) -> dict:
    """
    Parse a single nuclei finding into standardized format.
    
    Args:
        finding: Raw nuclei JSON output line
        
    Returns:
        Standardized finding dictionary
    """
    info = finding.get("info", {})
    
    # Extract CVE IDs from various locations
    cves = []
    
    # From classification. Nuclei v3 emits cve-id as a lowercase list
    # (["cve-2021-41773"]), so match case-insensitively and store the canonical
    # upper-case id; a case-sensitive "CVE-" test silently dropped every CVE.
    classification = info.get("classification", {})
    if classification.get("cve-id"):
        cve_ids = classification["cve-id"]
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        for cve_id in cve_ids:
            if cve_id and str(cve_id).upper().startswith("CVE-"):
                cves.append({
                    "id": str(cve_id).upper(),
                    "cvss": classification.get("cvss-score"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{str(cve_id).upper()}"
                })
    
    # From CVE details
    if classification.get("cve"):
        cve_detail = classification["cve"]
        if isinstance(cve_detail, list):
            for cve_id in cve_detail:
                cid = str(cve_id).upper() if cve_id else ""
                if cid.startswith("CVE-") and not any(c["id"] == cid for c in cves):
                    cves.append({
                        "id": cid,
                        "cvss": None,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
                    })
    
    tags = _tag_list(info.get("tags"))
    category = _category_from_tags(tags)

    # Build result
    result = {
        "template_id": finding.get("template-id", "unknown"),
        "template_path": finding.get("template", ""),
        "name": info.get("name", "Unknown"),
        "description": info.get("description", ""),
        "severity": info.get("severity", "unknown").lower(),
        "category": category,
        "tags": tags,
        "reference": info.get("reference", []),
        "cves": cves,
        "cvss_score": classification.get("cvss-score"),
        "cvss_metrics": classification.get("cvss-metrics", ""),
        "cwe_id": classification.get("cwe-id", []),
        "target": finding.get("host", ""),
        "matched_at": finding.get("matched-at", ""),
        "matcher_name": finding.get("matcher-name", ""),
        "extracted_results": finding.get("extracted-results", []),
        "curl_command": finding.get("curl-command", ""),
        "request": finding.get("request", ""),
        "response": finding.get("response", "")[:500] if finding.get("response") else "",
        "timestamp": finding.get("timestamp", datetime.now().isoformat()),
        "raw": finding  # Keep raw data for reference
    }
    
    return result


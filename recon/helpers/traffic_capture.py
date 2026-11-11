"""
HTTP Traffic Capture — recon side (mitmproxy integration, Phase 0).

Phase 0 recovers the full httpx response bodies that the probe otherwise discards
(`http_probe.py` pops "body" after fingerprinting) and persists each probed URL as
a `captured_http_transaction` row, so the /traffic UI and later the agent tools can
query real request/response data instead of only URLs + hashes.

There is no capture proxy yet in Phase 0. Recon POSTs the transactions straight to
the webapp ingest endpoint (`POST /api/traffic/{project_id}/ingest`) with the same
scanner key and job credential it reads project settings with (scan_auth.py). The
webapp is the sole Postgres writer and stamps the tenant (user_id/project_id) from
the project owner — recon never sends tenant fields it could forge.

Gated by `CAPTURE_PROXY_ENABLED` (per-project). Best-effort / fail-open: any error
here is logged and swallowed so it can never break a scan (§20.1).
"""

import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Keep inline bodies bounded before they leave recon; the ingest route caps again.
_MAX_BODY_BYTES = (int(os.environ.get("CAPTURE_PROXY_MAX_BODY_KB", "64") or "64")) * 1024
# Bound each POST payload so a large crawl streams in chunks.
_BATCH_SIZE = 500

# Cheap passive signal: security headers a response ought to carry.
_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def _normalize_headers(headers):
    """
    Canonicalize httpx response headers to a {dash-lowercase-name: value} dict.

    In production httpx serializes header names in UNDERSCORE form
    (`x_frame_options`, `set_cookie`) and occasionally as a single CRLF-joined
    STRING rather than a dict (see http_probe._annotate_ai_http_signals, which
    normalizes `_`->`-` for exactly this reason — a mismatch here silently made
    every passive signal wrong). Duplicate names (e.g. multiple Set-Cookie)
    collapse to a list so cookie-flag auditing sees them all.
    """
    out = {}

    def _add(name, value):
        key = str(name).strip().replace("_", "-").lower()
        if not key:
            return
        if key in out:
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        else:
            out[key] = value

    if isinstance(headers, dict):
        for k, v in headers.items():
            _add(k, v)
    elif isinstance(headers, str):
        for line in headers.replace("\r\n", "\n").split("\n"):
            if ":" in line:
                name, value = line.split(":", 1)
                _add(name, value.strip())
    return out


def _parse_int(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return None


def _parse_duration_ms(v):
    """httpx response-time is like '1.234567s' or '123ms' or a float of seconds."""
    if v is None:
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        # Heuristic: values < 1000 are almost certainly seconds from httpx.
        return int(v * 1000) if v < 1000 else int(v)
    s = str(v).strip().lower()
    try:
        if s.endswith("ms"):
            return int(float(s[:-2]))
        if s.endswith("s"):
            return int(float(s[:-1]) * 1000)
        # bare number: treat as seconds (httpx default)
        return int(float(s) * 1000)
    except (ValueError, TypeError):
        return None


def _truncate(body):
    if not body:
        return None, 0
    if not isinstance(body, str):
        body = str(body)
    raw = body.encode("utf-8", errors="replace")
    size = len(raw)
    if size <= _MAX_BODY_BYTES:
        return body, size
    return raw[:_MAX_BODY_BYTES].decode("utf-8", errors="replace"), size


def _cookie_flag_issues(set_cookie):
    """Flag Set-Cookie values missing HttpOnly / Secure / SameSite."""
    issues = []
    values = set_cookie if isinstance(set_cookie, list) else [set_cookie]
    for cookie in values:
        if not cookie:
            continue
        low = str(cookie).lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            name = str(cookie).split("=", 1)[0].strip()[:64]
            issues.append({"cookie": name, "missing": missing})
    return issues


def _build_transaction(url, url_entry, phase):
    """Map one httpx by_url entry to an ingest transaction dict."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname or url_entry.get("host") or ""
    if not host:
        return None
    port = parts.port or (443 if scheme == "https" else 80)

    # Normalize to dash-lowercase keys so passive signals + stored headers are
    # consistent regardless of httpx's underscore / CRLF-string serialization.
    norm_headers = _normalize_headers(url_entry.get("headers"))

    body, full_size = _truncate(url_entry.get("body"))
    content_length = _parse_int(url_entry.get("content_length"))

    body_hash = url_entry.get("body_hash") or {}
    resp_body_sha = body_hash.get("body_sha256") if isinstance(body_hash, dict) else None

    tls = url_entry.get("tls") or {}
    tls_version = tls.get("version") if isinstance(tls, dict) else None

    set_cookie = norm_headers.get("set-cookie")
    security_missing = [h for h in _SECURITY_HEADERS if h not in norm_headers]
    cookie_issues = _cookie_flag_issues(set_cookie) if set_cookie else []

    return {
        "tool": "httpx",
        "phase": phase,
        "method": "GET",
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": parts.path or "/",
        "query": ("?" + parts.query) if parts.query else None,
        "reqHeaders": {},
        "respHeaders": norm_headers,
        "respBody": body,
        "respBodySize": content_length if content_length is not None else full_size,
        "respContentType": url_entry.get("content_type"),
        "respBodySha": resp_body_sha,
        "statusCode": _parse_int(url_entry.get("status_code")),
        "responseTimeMs": _parse_duration_ms(url_entry.get("response_time_ms")),
        "targetIp": url_entry.get("ip"),
        "isTls": scheme == "https",
        "tlsVersion": tls_version,
        "hasSetCookie": bool(set_cookie),
        "securityHeadersMissing": security_missing,
        "cookieFlagIssues": cookie_issues,
        "startedAt": datetime.now(timezone.utc).isoformat(),
    }


def capture_httpx_transactions(httpx_results, settings, phase="informational"):
    """
    Persist httpx probe transactions to the /traffic store.

    Must be called BEFORE http_probe pops the bodies. No-op unless
    CAPTURE_PROXY_ENABLED is on. Never raises — capture is best-effort.
    """
    try:
        if not settings or not settings.get("CAPTURE_PROXY_ENABLED"):
            return

        by_url = (httpx_results or {}).get("by_url") or {}
        if not by_url:
            return

        project_id = os.environ.get("PROJECT_ID", "")
        webapp_url = os.environ.get("WEBAPP_API_URL", "")
        if not project_id or not webapp_url:
            logger.warning("[traffic-capture] missing PROJECT_ID/WEBAPP_API_URL; skipping")
            return

        # Full recon sets RECON_RUN_ID; partial / ai-attack containers set their
        # own run id. Fall back so captures are grouped whatever spawned httpx.
        run_id = (
            os.environ.get("RECON_RUN_ID")
            or os.environ.get("PARTIAL_RECON_RUN_ID")
            or os.environ.get("AI_ATTACK_RUN_ID")
            or None
        )

        transactions = []
        for url, url_entry in by_url.items():
            if not isinstance(url_entry, dict):
                continue
            txn = _build_transaction(url, url_entry, phase)
            if txn:
                transactions.append(txn)

        if not transactions:
            return

        import requests

        from recon.helpers.scan_auth import scan_auth_headers

        headers = {**scan_auth_headers(), "Content-Type": "application/json"}
        url = f"{webapp_url.rstrip('/')}/api/traffic/{project_id}/ingest"

        stored = 0
        for i in range(0, len(transactions), _BATCH_SIZE):
            batch = transactions[i:i + _BATCH_SIZE]
            payload = {"source": "recon", "runId": run_id, "transactions": batch}
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=30)
                if resp.status_code in (200, 201, 202):
                    stored += resp.json().get("stored", 0)
                else:
                    logger.warning(
                        "[traffic-capture] ingest returned %s: %s",
                        resp.status_code, resp.text[:200],
                    )
            except Exception as e:  # noqa: BLE001 — best-effort, never break the scan
                logger.warning("[traffic-capture] batch POST failed: %s", e)

        logger.info("[traffic-capture] stored %s/%s httpx transactions", stored, len(transactions))
    except Exception as e:  # noqa: BLE001
        logger.warning("[traffic-capture] capture failed (ignored): %s", e)

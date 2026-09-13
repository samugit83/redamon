"""
traffic-ingest — trusted spool consumer (plan §11.2b, §15.2, §15.4).

Runs on redamon-network (NOT pentest-net). It is the only capture component
that holds a DB credential, and only a scoped role granted INSERT on exactly
`captured_http_transactions`. It:

  1. tails the append-only spool directory (atomically-published *.json files);
  2. VERIFIES the HMAC `ctx_token` (recon->SCANNER_API_KEY, agent->INTERNAL_API_KEY)
     and derives user_id/project_id from the verified claims ONLY — never from
     anything the proxy or a target could influence;
  3. optionally redacts known-sensitive material before storage (§15.4);
  4. INSERTs the row (bodies were already deduped into the shared content store
     by the proxy; we only reference them by sha).

A record with a missing/invalid tag is rejected (moved aside), never inserted.

Residual (documented, not fully closed): the tag authenticates only the tenant
claims, with no nonce/expiry and no binding to the request content. A FULLY
compromised proxy therefore sees valid tags for the tenants it proxies and could
replay one to attribute *fabricated* rows to that tenant. This is bounded by the
INSERT-only role (forged rows are non-readable, purgeable, and land only in a
tenant whose traffic the proxy already saw) and is the price of keeping the proxy
credential-free. Closing it fully needs a content-digest + short expiry in the
tag (a future hardening). See plan §15.13.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, Optional

from capture_lib import ensure_dir_writable
from ioc_match import match_transaction
from redamon_ctx import verify_tag

# Header/param names whose values are masked when redaction is on. A salted hash
# is kept so identical secrets still correlate without storing the plaintext.
_SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "proxy-authorization",
})

_REDACT_SALT = os.environ.get("CAPTURE_REDACT_SALT", "redamon-capture")


def _mask(value: Any) -> str:
    digest = hashlib.sha256((_REDACT_SALT + str(value)).encode("utf-8")).hexdigest()[:16]
    return f"[redacted:{digest}]"


def redact_headers(headers: Dict[str, Any]) -> (Dict[str, Any], list):
    """Return (redacted_headers, redacted_field_names)."""
    if not isinstance(headers, dict):
        return headers, []
    out: Dict[str, Any] = {}
    hit = []
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADERS:
            hit.append(k)
            out[k] = [_mask(x) for x in v] if isinstance(v, list) else _mask(v)
        else:
            out[k] = v
    return out, hit


INT4_MAX = 2147483647


def _clamp_int4(v):
    if v is None:
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v < 0:
        return 0
    return INT4_MAX if v > INT4_MAX else v


def build_row(payload: Dict[str, Any], rec: Dict[str, Any], redact: bool) -> Dict[str, Any]:
    """Map a verified tag payload + spool record to snake_case DB columns.

    Tenant + attribution come from the VERIFIED `payload`; everything else from
    the (untrusted) proxy record. `id` is generated here because Prisma's cuid
    default is client-side, so a raw INSERT must supply the primary key.
    """
    req_headers = rec.get("reqHeaders") or {}
    resp_headers = rec.get("respHeaders") or {}
    redacted_fields = []
    redacted = False
    if redact:
        req_headers, h1 = redact_headers(req_headers)
        resp_headers, h2 = redact_headers(resp_headers)
        redacted_fields = h1 + h2
        redacted = bool(redacted_fields)

    scheme = (rec.get("scheme") or "http").lower()

    # A1: flag a request to a host a published supply-chain incident names. A
    # local set lookup, no network, no new credential; a missing catalog yields
    # (None, None) rather than failing the row. The TypeScript ingest route sets
    # the same two columns for the same input - a parity test asserts it.
    host = rec.get("host") or ""
    target_ip = rec.get("targetIp")
    ioc_incident_id, ioc_incident_url = match_transaction(host, target_ip)

    return {
        "id": uuid.uuid4().hex,
        "project_id": payload["project_id"],
        "user_id": payload["user_id"],
        "source": payload["source"],
        "run_id": payload.get("run_id"),
        "session_id": payload.get("session_id"),
        "member_id": payload.get("member_id"),
        "tool": payload.get("tool"),
        "phase": payload.get("phase"),
        "step_id": payload.get("step"),
        # Replay lineage — from the VERIFIED tag (a target/proxy can't forge it).
        "is_replay": bool(payload.get("is_replay")),
        "origin_id": payload.get("origin_id"),

        "method": (rec.get("method") or "GET").upper(),
        "scheme": scheme,
        "host": rec.get("host") or "",
        "port": _clamp_int4(rec.get("port")) or (443 if scheme == "https" else 80),
        "path": rec.get("path") or "/",
        "query": rec.get("query"),
        "req_headers": json.dumps(req_headers),
        "req_body": rec.get("reqBody"),
        "req_body_ref": rec.get("reqBodyRef"),
        "req_body_size": _clamp_int4(rec.get("reqBodySize")) or 0,
        "req_content_type": rec.get("reqContentType"),
        "req_body_sha256": rec.get("reqBodySha"),

        "status_code": _clamp_int4(rec.get("statusCode")),
        "resp_headers": json.dumps(resp_headers),
        "resp_body": rec.get("respBody"),
        "resp_body_ref": rec.get("respBodyRef"),
        "resp_body_size": _clamp_int4(rec.get("respBodySize")) or 0,
        "resp_content_type": rec.get("respContentType"),
        "resp_body_sha256": rec.get("respBodySha"),
        "response_time_ms": _clamp_int4(rec.get("responseTimeMs")),

        "target_ip": rec.get("targetIp"),
        "http_version": rec.get("httpVersion"),
        "is_tls": scheme == "https" or rec.get("isTls") is True,
        "tls_version": rec.get("tlsVersion"),

        "in_scope": rec.get("inScope") is not False,
        "blocked": rec.get("blocked") is True,
        "error_text": rec.get("errorText"),

        "redacted": redacted,
        "redacted_fields": json.dumps(redacted_fields) if redacted_fields else None,

        "has_set_cookie": rec.get("hasSetCookie") is True,
        "had_auth": rec.get("hadAuth") is True,
        "reflected_params": rec.get("reflectedParams") is True,
        "security_headers_missing": json.dumps(rec.get("securityHeadersMissing")) if rec.get("securityHeadersMissing") is not None else None,
        "cookie_flag_issues": json.dumps(rec.get("cookieFlagIssues")) if rec.get("cookieFlagIssues") is not None else None,

        "started_at": rec.get("startedAt"),

        "ioc_incident_id": ioc_incident_id,
        "ioc_incident_url": ioc_incident_url,
    }


_JSONB_COLS = frozenset({
    "req_headers", "resp_headers", "redacted_fields",
    "security_headers_missing", "cookie_flag_issues",
})


def _insert_sql(row: Dict[str, Any]) -> (str, list):
    cols = list(row.keys())
    placeholders = []
    values = []
    for c in cols:
        # JSON columns are passed as text and cast to jsonb in SQL.
        placeholders.append("%s::jsonb" if c in _JSONB_COLS else "%s")
        values.append(row[c])
    col_sql = ", ".join(f'"{c}"' for c in cols)
    ph_sql = ", ".join(placeholders)
    return f'INSERT INTO captured_http_transactions ({col_sql}) VALUES ({ph_sql})', values


# --------------------------------------------------------------------------
# Runtime loop (not exercised by unit tests; needs psycopg3 + a live DB).
# --------------------------------------------------------------------------
def _keys() -> Dict[str, str]:
    return {
        "recon": os.environ.get("SCANNER_API_KEY", ""),
        "agent": os.environ.get("INTERNAL_API_KEY", ""),
        # Operator-recording tags are minted by the webapp with INTERNAL_API_KEY.
        "operator": os.environ.get("INTERNAL_API_KEY", ""),
    }


def _redact_enabled() -> bool:
    return os.environ.get("CAPTURE_PROXY_REDACT_SECRETS", "true").lower() != "false"


def run() -> None:  # pragma: no cover - integration path
    import psycopg  # psycopg3 (already a dependency via the agent checkpointer)

    spool_dir = os.environ.get("CAPTURE_SPOOL_DIR", "/spool")
    reject_dir = os.path.join(spool_dir, ".rejected")
    ensure_dir_writable(reject_dir)
    # Bodies store is shared with the webapp (different uid) for read + GC.
    bodies_dir = os.environ.get("CAPTURE_BODIES_DIR", "/bodies")
    ensure_dir_writable(bodies_dir)
    try:
        os.chmod(bodies_dir, 0o777)
    except OSError:
        pass
    keys = _keys()
    redact = _redact_enabled()
    dsn = os.environ["TRAFFIC_INGEST_DATABASE_URL"]

    print("[traffic-ingest] started", flush=True)
    while True:
        files = sorted(
            f for f in os.listdir(spool_dir)
            if f.endswith(".json") and not f.startswith(".")
        )
        if not files:
            time.sleep(1.0)
            continue
        try:
            with psycopg.connect(dsn, autocommit=True) as conn:
                for fname in files:
                    path = os.path.join(spool_dir, fname)
                    _process_one(conn, path, reject_dir, keys, redact)
        except Exception as e:
            print(f"[traffic-ingest] db error: {e}", flush=True)
            time.sleep(2.0)


def _process_one(conn, path, reject_dir, keys, redact) -> None:  # pragma: no cover
    try:
        with open(path, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except (OSError, json.JSONDecodeError):
        _reject(path, reject_dir)
        return
    payload = verify_tag(rec.get("ctx_token") or "", keys)
    if not payload or not payload.get("project_id") or not payload.get("user_id"):
        _reject(path, reject_dir)
        return

    # Operator recording: extract the session BEFORE redaction and hand it to the
    # webapp, which folds it into the ProjectAuthProfile. Best-effort — the corpus
    # row below is still stored redacted, so raw secrets never persist here.
    if payload.get("source") == "operator":
        _observe_operator_session(payload, rec)

    row = build_row(payload, rec, redact)
    sql, values = _insert_sql(row)
    try:
        conn.execute(sql, values)
        os.unlink(path)
    except Exception as e:
        import psycopg
        # Permanent data/constraint problems: the row can never insert -> reject.
        if isinstance(e, (psycopg.DataError, psycopg.IntegrityError, psycopg.ProgrammingError)):
            print(f"[traffic-ingest] rejecting bad row: {e}", flush=True)
            _reject(path, reject_dir)
        else:
            # Transient (connection reset, deadlock, timeout, Postgres restart):
            # leave the spool file in place and re-raise so the outer loop
            # reconnects and retries — never discard a validly-captured record.
            print(f"[traffic-ingest] transient insert error (will retry): {e}", flush=True)
            raise


def _observe_operator_session(payload, rec) -> None:  # pragma: no cover
    """POST extracted login material to the webapp observe endpoint.

    Retried a few times: the spool file is consumed by the insert that follows,
    so a webapp restart of a few seconds would otherwise discard the operator's
    captured login for good, with the modal still showing "0 captured" and no
    lastError (the endpoint that records lastError is the one that is down).
    Still fail-open after the retries — ingest must never block on this.
    """
    import json as _json
    import urllib.request
    from session_extract import extract_session

    material = extract_session(rec)
    if not material:
        return
    webapp = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
    project_id = payload["project_id"]
    body = _json.dumps({
        "sessionId": payload.get("session_id"),
        "host": material.get("host") or rec.get("host"),
        "material": material,
    }).encode()

    last_err = None
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(
                f"{webapp}/api/internal/auth-profile/{project_id}/observe",
                data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "x-internal-key": os.environ.get("INTERNAL_API_KEY", "")},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec - internal
                resp.read()
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt < 3:
                time.sleep(1.0)
    print(f"[traffic-ingest] operator observe FAILED after 3 attempts for project "
          f"{project_id} session {payload.get('session_id')}: {last_err} — the "
          f"recorded login for this request was lost; re-record.", flush=True)


def _reject(path, reject_dir) -> None:  # pragma: no cover
    try:
        os.replace(path, os.path.join(reject_dir, os.path.basename(path)))
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":  # pragma: no cover
    run()

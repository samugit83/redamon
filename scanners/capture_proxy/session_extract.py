"""
Session extraction for operator-recorded traffic.

Runs in the ingest worker on an ``operator``-source record BEFORE redaction (the
only point where the raw Cookie/Authorization/Set-Cookie are still present), and
returns the login material for the webapp to fold into the project's
ProjectAuthProfile. The corpus row itself is still stored redacted.

Contract: NEVER raises (matches the ingest fail-open style) and returns ``{}``
when there is nothing usable, so a normal page load never disturbs a saved
profile.
"""

import re
from typing import Any, Dict

# Request headers whose presence hints at a CSRF token to carry alongside auth.
_CSRF_HEADER_NAMES = ("x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token")
_HIDDEN_CSRF_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']*(?:csrf|xsrf|authenticity)[^"\']*)["\'][^>]+value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_MAX_VALUE_LEN = 8192


def _capped(value: str):
    """The value, or None when it exceeds the cap. NEVER truncates.

    A sliced cookie/token is a *corrupt* credential that still passes the
    downstream length check (which rejects only > cap), so it would be stored and
    then silently fail every authenticated request. Dropping it instead surfaces
    honestly as "no login detected".
    """
    if not value:
        return None
    return value if len(value) <= _MAX_VALUE_LEN else None


def _first(value: Any) -> str:
    """Header dicts collapse duplicates to a list; take the first string value."""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def _all(value: Any):
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value is not None else []


def _lower_keys(headers: Any) -> Dict[str, Any]:
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): v for k, v in headers.items()}


def _parse_set_cookie(set_cookie_values) -> Dict[str, str]:
    """name=value from each Set-Cookie line (attributes like Path/HttpOnly dropped)."""
    jar: Dict[str, str] = {}
    for line in set_cookie_values:
        first = str(line).split(";", 1)[0].strip()
        if "=" in first:
            name, val = first.split("=", 1)
            name = name.strip()
            if name and val:
                jar[name] = val.strip()
    return jar


def _merge_cookie_header(existing: str, jar: Dict[str, str]) -> str:
    """Overlay freshly-set cookies onto the request's Cookie header."""
    pairs: Dict[str, str] = {}
    for part in str(existing or "").split(";"):
        part = part.strip()
        if "=" in part:
            n, v = part.split("=", 1)
            if n.strip():
                pairs[n.strip()] = v.strip()
    pairs.update(jar)  # Set-Cookie is the freshest state
    return "; ".join(f"{n}={v}" for n, v in pairs.items())


def extract_session(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Pull login material from a raw (pre-redaction) captured record.

    Returns ``{host, cookie?, authorization?, extra?}`` — an empty dict when
    nothing usable was seen. ``extra`` holds CSRF-style headers/fields.
    """
    try:
        out: Dict[str, Any] = {}
        req_h = _lower_keys(rec.get("reqHeaders"))
        resp_h = _lower_keys(rec.get("respHeaders"))

        cookie = _capped(_merge_cookie_header(_first(req_h.get("cookie")),
                                              _parse_set_cookie(_all(resp_h.get("set-cookie")))))
        if cookie:
            out["cookie"] = cookie

        authz = _capped(_first(req_h.get("authorization")).strip())
        if authz:
            out["authorization"] = authz

        extra: Dict[str, str] = {}
        for name in _CSRF_HEADER_NAMES:
            val = _capped(_first(req_h.get(name)).strip())
            if val:
                # Preserve the header's real casing where the record has it.
                extra[_original_case(rec.get("reqHeaders"), name)] = val

        body = rec.get("respBody")
        if isinstance(body, str) and "csrf" in body.lower():
            m = _HIDDEN_CSRF_RE.search(body)
            if m and m.group(1) and m.group(2):
                _val = _capped(m.group(2))
                if _val:
                    extra.setdefault(m.group(1)[:256], _val)
        if extra:
            out["extra"] = extra

        if out:
            out["host"] = str(rec.get("host") or "")
        return out
    except Exception:
        return {}


def _original_case(headers: Any, lower_name: str) -> str:
    if isinstance(headers, dict):
        for k in headers:
            if str(k).lower() == lower_name:
                return str(k)
    return lower_name

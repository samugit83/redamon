"""Leaked one-time links, secrets and web-shell traces in URLs, and the quarantine.

Archived URLs (urlscan, GAU, ParamSpider) are other people's links: a password
reset e-mailed to a user and submitted to urlscan by their mail gateway, an
invite, a payment link, an unsubscribe link. Requesting one uses a real
person's token. This module decides, offline and without raising, which URLs
are never requested (the quarantine) and the masked form every archived URL
takes wherever it is requested or used as an identity (parameter values
``***``, path tokens ``{token}``). The secret and the full URL are kept only as
display fields for the operator (``inspect_url(..., with_values=True)``).

Pure: no network, no I/O. A JWT is decoded locally (header and payload only)
to read ``alg`` and ``exp``; no claim is kept.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Iterable, Optional
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

MASK = "***"
PATH_TOKEN = "{token}"

#: The words that mark a one-time link, per kind. Phrases are matched as a
#: whole path segment or parameter name; single words as one of the words a
#: segment or name splits into on - _ . (so `display` is not `pay`).
LINK_PHRASES = {
    "account_setup": ("set-password", "create-password", "set_password", "create_password"),
}
LINK_WORDS = {
    "password_reset": ("reset", "forgot", "recover", "password"),
    "account_setup": ("activate", "activation", "setup", "onboard"),
    "invite": ("invite", "invitation", "join"),
    "payment": ("pay", "payment", "checkout", "invoice", "order", "billing"),
    "login_link": ("magic", "login", "signin"),
}
#: E-mail verification words: a one-time link only with a token PARAMETER
#: (`/verify?token=`). The path form (`/confirm/<tok>`, `/email/verify/<id>/<hash>`)
#: is quarantined - opening it confirms a real person - but is no finding.
PARAM_ONLY_LINK_WORDS = {"login_link": ("verify", "confirm")}
LINK_KIND_ORDER = ("account_setup", "password_reset", "invite", "payment", "login_link")

#: Parameters that carry a one-time link's token.
TOKEN_PARAMS = frozenset({
    "token", "t", "key", "code", "hash", "sig", "signature", "otp", "reset_token",
    "invite_token", "confirmation_token", "auth",
})
#: What mail gateways and marketing tools append: never a token of the target.
TRACKING_PARAMS = frozenset({"gclid", "fbclid", "msclkid", "yclid", "mc_eid", "mkt_tok",
                             "_hsenc", "_hsmi", "trk"})
#: Words that make a URL change state when opened. Route Exposure's list plus the
#: e-mail confirmation words; they quarantine a URL only together with a value
#: or a path token (a bare archived `/logout` changes nothing for anyone).
EXTRA_STATE_WORDS = frozenset({"unsubscribe", "activate", "verify", "confirm", "magic"})

PLACEHOLDERS = frozenset({"null", "none", "undefined", "nil", "true", "false", "test",
                          "example", "token", "value", "string", "changeme"})

SECRET_PARAMS = {
    "password": ("password", "passwd", "pwd"),
    "api_key": ("apikey", "api_key", "access_key", "client_secret", "private_key"),
    "token": ("token", "access_token", "id_token", "auth_token", "jsessionid", "phpsessid"),
}
#: Generic names that are a secret only when the value is token-like (`?key=1` is nothing).
SHAPED_SECRET_PARAMS = {"api_key": ("key", "secret"), "token": ("session", "sid")}

WEB_SHELL_PARAMS = frozenset({"cmd", "command", "exec", "execute", "shell", "run", "system"})
WEB_SHELL_MARKERS = ("/etc/", "/bin/", "whoami", "uname", "cat ")

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_HEX20 = re.compile(r"[0-9a-fA-F]{20,}")
_TOKEN_CHARS = re.compile(r"[A-Za-z0-9_\-.~=+/%]+")
_WORD_SPLIT = re.compile(r"[-_.]+")


# ---------------------------------------------------------------------------
# Value shapes
# ---------------------------------------------------------------------------

def is_placeholder(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return True
    if v in PLACEHOLDERS or v == MASK or v == PATH_TOKEN:
        return True
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("<") and v.endswith(">")) \
            or (v.startswith(":") and len(v) > 1) or v.startswith("$"):
        return True
    return bool(re.fullmatch(r"(x)\1{2,}|(\*)\2{2,}|fuzz", v))


def is_jwt(value: str) -> bool:
    return bool(_JWT.fullmatch((value or "").strip()))


def is_token_like(value: str) -> bool:
    """16+ characters with letters and digits mixed, a hex string of 20+, or a JWT;
    never a plain number, an empty value or a placeholder."""
    v = (value or "").strip()
    if is_placeholder(v) or v.isdigit():
        return False
    if is_jwt(v):
        return True
    if not _TOKEN_CHARS.fullmatch(v):
        return False
    letters = any(c.isalpha() for c in v)
    digits = any(c.isdigit() for c in v)
    if len(v) >= 16 and letters and digits:
        return True
    return bool(_HEX20.fullmatch(v)) and letters


def _words(name: str) -> list:
    return [w for w in _WORD_SPLIT.split((name or "").lower()) if w]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _split(url: str):
    """(parts, path segments, [(name, value, where)]), never raising."""
    parts = urlsplit(url)
    path = parts.path or ""
    segments = []
    params = []
    for raw in path.split("/"):
        if not raw:
            continue
        seg, _, matrix = raw.partition(";")
        segments.append(unquote(seg))
        if matrix:
            for item in matrix.split(";"):
                name, _, value = item.partition("=")
                params.append((unquote(name), unquote(value), "path"))
    for name, value in parse_qsl(parts.query or "", keep_blank_values=True):
        params.append((name, value, "query"))
    if parts.fragment and "=" in parts.fragment:
        frag = parts.fragment.lstrip("!/")
        for name, value in parse_qsl(frag, keep_blank_values=True):
            params.append((name, value, "fragment"))
    return parts, segments, params


def _is_tracking(name: str) -> bool:
    n = (name or "").lower()
    return n.startswith("utm_") or n in TRACKING_PARAMS


# ---------------------------------------------------------------------------
# Masking (S1, S4)
# ---------------------------------------------------------------------------

def _path_token_positions(segments: list) -> set:
    """Indexes of path segments that are tokens: a JWT anywhere, or a token-like
    segment within the two segments after a link word or a state-changing word."""
    positions = {i for i, s in enumerate(segments) if is_jwt(s)}
    anchors = set()
    for i, seg in enumerate(segments):
        low = seg.lower()
        words = set(_words(low)) | {low}
        if words & _ALL_PATH_WORDS or low in _ALL_PHRASES:
            anchors.add(i)
    for i in anchors:
        for j in (i + 1, i + 2):
            if j < len(segments) and is_token_like(segments[j]):
                positions.add(j)
    return positions


def mask_url(url: str) -> str:
    """The URL as it may be stored: every parameter value ``***`` and every path
    token ``{token}``. Names, host and the rest of the path are kept."""
    try:
        parts, segments, _params = _split(url)
    except Exception:  # noqa: BLE001 - an unparseable URL is stored as nothing
        return ""
    try:
        tokens = _path_token_positions(segments)
        out_segments = []
        idx = 0
        for raw in (parts.path or "").split("/"):
            if not raw:
                out_segments.append(raw)
                continue
            seg, sep, matrix = raw.partition(";")
            if idx in tokens:
                seg = PATH_TOKEN
            if matrix:
                matrix = ";".join(f"{n.partition('=')[0]}={MASK}" if "=" in n else n
                                  for n in matrix.split(";"))
            out_segments.append(seg + sep + matrix)
            idx += 1
        path = "/".join(out_segments)
        query = "&".join(f"{quote(n, safe='[]')}={MASK}" if v != "" else f"{quote(n, safe='[]')}="
                         for n, v in parse_qsl(parts.query or "", keep_blank_values=True))
        fragment = parts.fragment or ""
        if fragment and "=" in fragment:
            fragment = "&".join(f"{n}={MASK}" for n, _v in
                                parse_qsl(fragment.lstrip("!/"), keep_blank_values=True))
        return urlunsplit((parts.scheme, parts.netloc, path, query, fragment))
    except Exception:  # noqa: BLE001
        return ""


def mask_path(path: str) -> str:
    """A bare path with its tokens as ``{token}`` (for Endpoint.path and IDs)."""
    masked = mask_url("http://x" + (path if (path or "").startswith("/") else "/" + (path or "")))
    return urlsplit(masked).path if masked else ""


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

_ALL_PATH_WORDS = frozenset(w for ws in LINK_WORDS.values() for w in ws) \
    | frozenset(w for ws in PARAM_ONLY_LINK_WORDS.values() for w in ws) | EXTRA_STATE_WORDS
_ALL_PHRASES = frozenset(p for ps in LINK_PHRASES.values() for p in ps)


def _state_words() -> frozenset:
    try:
        from recon.route_exposure.seeds import STATE_CHANGING_TOKENS
        return frozenset(STATE_CHANGING_TOKENS) | EXTRA_STATE_WORDS
    except Exception:  # noqa: BLE001
        return EXTRA_STATE_WORDS | {"logout", "delete", "reset", "cancel", "unsubscribe"}


def _kinds_in(names: Iterable[str], *, with_param_only: bool) -> list:
    found = []
    for name in names:
        low = (name or "").lower()
        words = set(_words(low))
        for kind, phrases in LINK_PHRASES.items():
            if low in phrases:
                found.append(kind)
        for kind, ws in LINK_WORDS.items():
            if words & set(ws):
                found.append(kind)
        if with_param_only:
            for kind, ws in PARAM_ONLY_LINK_WORDS.items():
                if words & set(ws):
                    found.append(kind)
    return found


def _first_kind(kinds: list) -> Optional[str]:
    for kind in LINK_KIND_ORDER:
        if kind in kinds:
            return kind
    return None


def _oauth_flow(segments: list, names: set) -> bool:
    low = "/".join(segments).lower()
    return bool({"state", "session_state", "client_id", "response_type"} & names) \
        or any(w in low for w in ("callback", "oauth", "authorize"))


def _link_kind(segments: list, params: list) -> Optional[str]:
    names = {n.lower() for n, _v, _w in params}
    oauth = _oauth_flow(segments, names)
    token_params = [
        (n.lower(), v) for n, v, _w in params
        if not _is_tracking(n) and n.lower() in TOKEN_PARAMS and is_token_like(v)
        and not (oauth and n.lower() == "code")
    ]
    path_tokens = []
    for i, seg in enumerate(segments):
        low = seg.lower()
        if _kinds_in([low], with_param_only=False):
            if any(j < len(segments) and is_token_like(segments[j]) for j in (i + 1, i + 2)):
                path_tokens.append(low)
    if token_params:
        word_sources = [s for s in segments] + [n for n, _v, _w in params if not _is_tracking(n)]
        kind = _first_kind(_kinds_in(word_sources, with_param_only=True))
        if kind:
            return kind
    if path_tokens:
        return _first_kind(_kinds_in(path_tokens, with_param_only=False))
    return None


def _b64json(segment: str) -> dict:
    pad = "=" * (-len(segment) % 4)
    data = json.loads(base64.urlsafe_b64decode(segment + pad).decode("utf-8", "replace"))
    return data if isinstance(data, dict) else {}


def decode_jwt(value: str, now: Optional[float] = None) -> dict:
    """{'alg', 'expired'} from a JWT's header and payload, decoded locally.
    Never raises; unknown fields are None. No claim is returned."""
    out = {"alg": None, "expired": None}
    try:
        header_b64, payload_b64 = value.strip().split(".")[:2]
        header = _b64json(header_b64)
        alg = header.get("alg")
        out["alg"] = str(alg)[:20] if alg is not None else None
        exp = _b64json(payload_b64).get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            out["expired"] = exp < (time.time() if now is None else now)
    except Exception:  # noqa: BLE001
        pass
    return out


def value_hmac(value: str, key: str) -> Optional[str]:
    """HMAC-SHA256 of a secret value under a key kept outside the data, so the
    same secret is recognised across scans without a reversible hash."""
    if not key or value is None:
        return None
    return hmac.new(key.encode(), value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def _secrets(params: list, segments: list, *, hmac_key: str = "", now=None,
             with_values: bool = False) -> list:
    found = []
    seen = set()

    def _add(secret_type: str, name: str, value: str, where: str):
        key = (secret_type, name.lower(), value)
        if key in seen:
            return
        seen.add(key)
        item = {"secret_type": secret_type, "param_name": name.lower(), "location": where,
                "value_length": len(value)}
        if with_values:
            item["value"] = value
        digest = value_hmac(value, hmac_key)
        if digest:
            item["value_hmac"] = digest
        if secret_type == "jwt":
            jwt = decode_jwt(value, now)
            item["jwt_alg"], item["jwt_expired"] = jwt["alg"], jwt["expired"]
        found.append(item)

    for name, value, where in params:
        low = (name or "").lower()
        if _is_tracking(low) or is_placeholder(value):
            continue
        if is_jwt(value):
            _add("jwt", name, value, where)
            continue
        matched = None
        for secret_type, names in SECRET_PARAMS.items():
            if low in names:
                matched = secret_type
        if matched is None and low == "pass":
            v = value.strip()
            if len(v) >= 6 and not v.isdigit() and v.lower() not in ("true", "false"):
                matched = "password"
        if matched is None:
            for secret_type, names in SHAPED_SECRET_PARAMS.items():
                if low in names and is_token_like(value):
                    matched = secret_type
        if matched:
            _add(matched, name, value, where)
    for seg in segments:
        if is_jwt(seg):
            _add("jwt", "path", seg, "path")
    return found


def _web_shell(params: list) -> bool:
    for name, value, _where in params:
        if (name or "").lower() in WEB_SHELL_PARAMS:
            v = (value or "").lower()
            if any(m in v for m in WEB_SHELL_MARKERS):
                return True
    return False


def _state_changing(segments: list, params: list, path_tokens: set) -> bool:
    words = _state_words()
    hit = False
    for seg in segments:
        low = seg.lower()
        if re.sub(r"[^a-z0-9]", "", low) in words or set(_words(low)) & words:
            hit = True
            break
    if not hit:
        hit = any(set(_words(n)) & words for n, _v, _w in params)
    if not hit:
        return False
    has_value = any(not is_placeholder(v) and not _is_tracking(n) for n, v, _w in params)
    return has_value or bool(path_tokens)


def inspect_url(url: str, *, hmac_key: str = "", now: Optional[float] = None,
                with_values: bool = False) -> dict:
    """Everything this module knows about one URL. Never raises.

    Returns {link_kind, secrets, web_shell, quarantined, reasons, masked_url, masked_path}.
    Each ``secrets`` item holds its length, its HMAC (with ``hmac_key``), and for
    a JWT its ``alg`` and whether it had expired. Only ``with_values`` adds the
    secret itself (``value``) and the URL as given (``url``): the display-only
    copies the operator reads. What is requested or used as an identity stays
    the masked form.
    """
    verdict = {"link_kind": None, "secrets": [], "web_shell": False, "quarantined": False,
               "reasons": [], "masked_url": "", "masked_path": ""}
    if with_values:
        verdict["url"] = url.strip() if isinstance(url, str) else ""
    if not isinstance(url, str) or not url.strip():
        return verdict
    try:
        _parts, segments, params = _split(url.strip())
    except Exception:  # noqa: BLE001
        verdict.update(quarantined=True, reasons=["unparseable"])
        return verdict
    try:
        path_tokens = _path_token_positions(segments)
        verdict["link_kind"] = _link_kind(segments, params)
        verdict["secrets"] = _secrets(params, segments, hmac_key=hmac_key, now=now,
                                      with_values=with_values)
        verdict["web_shell"] = _web_shell(params)
        reasons = []
        if verdict["link_kind"]:
            reasons.append("one_time_link")
        if verdict["secrets"]:
            reasons.append("secret")
        if any(is_jwt(s) for s in segments) or any(is_jwt(v) for _n, v, _w in params):
            reasons.append("jwt")
        if verdict["web_shell"]:
            reasons.append("web_shell")
        if path_tokens:
            reasons.append("path_token")
        if _state_changing(segments, params, path_tokens):
            reasons.append("state_changing")
        verdict["reasons"] = sorted(set(reasons))
        verdict["quarantined"] = bool(verdict["reasons"])
    except Exception:  # noqa: BLE001 - fail closed: an URL we cannot judge is never requested
        verdict.update(quarantined=True, reasons=["unjudged"])
    verdict["masked_url"] = mask_url(url.strip())
    verdict["masked_path"] = urlsplit(verdict["masked_url"]).path if verdict["masked_url"] else ""
    return verdict


def is_quarantined(url: str) -> bool:
    return inspect_url(url)["quarantined"]


def host_path_key(url: str) -> tuple:
    try:
        parts = urlsplit(url)
        return ((parts.hostname or "").lower(), parts.path or "/")
    except Exception:  # noqa: BLE001
        return ("", "")


def split_quarantined(urls: Iterable[str]) -> tuple:
    """(kept, quarantined) in input order. A web-shell trace quarantines every
    URL on its host + path, whichever order they come in."""
    urls = [u for u in urls if isinstance(u, str)]
    verdicts = [inspect_url(u) for u in urls]
    shells = {host_path_key(u) for u, v in zip(urls, verdicts) if v["web_shell"]}
    kept, quarantined = [], []
    for u, v in zip(urls, verdicts):
        if v["quarantined"] or host_path_key(u) in shells:
            quarantined.append(u)
        else:
            kept.append(u)
    return kept, quarantined


# ---------------------------------------------------------------------------
# Exposed files and documents (item 3)
# ---------------------------------------------------------------------------

#: file_kind -> severity, for a file seen on urlscan (history alone: at most high).
FILE_SEVERITY = {
    "env": "high", "vcs": "high", "db_dump": "high", "installer": "high", "private_key": "high",
    "backup": "medium", "log": "medium", "debug_page": "medium", "config": "low",
    "web_shell_trace": "high", "file_manager": "high", "debug_console": "high",
    "memory_dump": "high", "salesforce_aura": "medium",
}
_BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".save", ".swp", "~")
_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip", ".tar", ".rar", ".7z")
_BACKUP_ARCHIVE_WORDS = ("backup", "bak", "dump", "db", "database", "site", "www", "htdocs",
                         "public_html")
_KEY_SUFFIXES = (".key", ".p12", ".pfx", ".ppk", ".pem")
_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
_DUMP_SUFFIXES = (".sql", ".sql.gz", ".sql.zip", ".dump", ".sqlite", ".sqlite3")
_CONFIG_NAMES = ("config.json", "appsettings.json", "web.config")
_DOC_MIME = (
    ("application/pdf", "pdf"),
    ("application/msword", "office"), ("application/vnd.openxmlformats", "office"),
    ("application/vnd.ms-", "office"), ("application/vnd.oasis.opendocument", "office"),
    ("application/zip", "archive"), ("application/x-7z-compressed", "archive"),
    ("application/x-rar", "archive"), ("application/vnd.rar", "archive"),
    ("application/gzip", "archive"), ("application/x-gzip", "archive"), ("application/x-tar", "archive"),
    ("text/csv", "csv"), ("application/json", "json"),
)
_DOC_EXT = (
    (".pdf", "pdf"), (".docx", "office"), (".doc", "office"), (".xlsx", "office"), (".xls", "office"),
    (".pptx", "office"), (".ppt", "office"), (".odt", "office"), (".ods", "office"),
    (".csv", "csv"), (".tar.gz", "archive"), (".zip", "archive"), (".rar", "archive"),
    (".7z", "archive"), (".json", "json"),
)
_RAW_MIME = ("text/plain", "application/octet-stream", "application/xml", "text/xml")


def _sensitive_kind(path: str, host: str) -> Optional[tuple]:
    low = (path or "/").lower()
    name = low.rstrip("/").rsplit("/", 1)[-1]
    if any(seg in low for seg in ("/.git/", "/.svn/", "/.hg/")) or low.rstrip("/").endswith(
            ("/.git", "/.svn", "/.hg")):
        return "vcs", "high"
    if "/sfsites/aura" in low:
        return "salesforce_aura", "medium"
    if "/_profiler/" in low or name == "app_dev.php":
        return "debug_console", "high"
    if "/elfinder/" in low or "/kcfinder/" in low or name in ("filemanager.php", "tinyfilemanager.php"):
        return "file_manager", "high"
    if name == "heapdump":
        return "memory_dump", "high"
    if name.endswith(_BACKUP_SUFFIXES):
        stem = name
        for suffix in _BACKUP_SUFFIXES:
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        # A config file's backup holds its passwords.
        is_config = "config" in stem or stem.startswith(".env") or stem in ("settings.py", "wp-config.php")
        return "backup", "high" if is_config else "medium"
    if name == ".env" or name.startswith(".env."):
        return "env", "high"
    if name.endswith(".pub"):
        return None
    if name.endswith(_KEY_SUFFIXES) or name in _KEY_NAMES:
        return "private_key", "medium" if name.endswith(".pem") else "high"
    if name.endswith(_DUMP_SUFFIXES):
        return "db_dump", "high"
    if name.endswith(_ARCHIVE_SUFFIXES):
        host_word = (host or "").lower().split(".")[0]
        words = _BACKUP_ARCHIVE_WORDS + ((host_word,) if host_word else ())
        stem = name.split(".", 1)[0]
        if any(w and w in stem for w in words):
            return "backup", "medium"
        return None
    if name.endswith(".log") or name in ("error_log", "access_log"):
        return "log", "medium"
    if name in _CONFIG_NAMES or (name.startswith("appsettings.") and name.endswith(".json")):
        return "config", "low"
    if name in ("phpinfo.php", "info.php", "debug.php"):
        return "debug_page", "medium"
    if name in ("setup-config.php", "install.php", "installer.php"):
        return "installer", "high"
    return None


def _has_extension(name: str) -> bool:
    return "." in name.strip(".") and len(name.rsplit(".", 1)[-1]) <= 6


def classify_file(url: str, mime_type: str = "") -> dict:
    """What kind of file an archived URL opened directly. Never raises.

    {"file_kind", "severity"} for a file that should never be public (matched on
    the path's last part, never the host name), {"document_type"} for a document
    or data rather than a page, else {}. A path that is a sensitive file stays
    one, whatever its content type.
    """
    try:
        parts = urlsplit(url or "")
        path = unquote(parts.path or "/")
        found = _sensitive_kind(path, parts.hostname or "")
        if found:
            return {"file_kind": found[0], "severity": found[1]}
        mime = (mime_type or "").split(";", 1)[0].strip().lower()
        for prefix, doc in _DOC_MIME:
            if mime.startswith(prefix):
                return {"document_type": doc}
        name = path.lower().rstrip("/").rsplit("/", 1)[-1]
        for suffix, doc in _DOC_EXT:
            if name.endswith(suffix):
                return {"document_type": doc}
        # Raw text served as a page with no known extension: environment dumps,
        # logs, bucket listings, WSDL.
        if mime in _RAW_MIME and name and not _has_extension(name):
            return {"document_type": "raw"}
    except Exception:  # noqa: BLE001
        pass
    return {}

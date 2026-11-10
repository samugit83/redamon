"""Content signals of one response: PII shapes, sensitive key names, secrets.

PII becomes a list of types and one record count, sensitive fields become key
paths, secrets become detector names plus their values in ``secret_values``,
the display-only copy the operator reads (graph_db/display_only.py); the body
itself never leaves the function that read it. ``mask_text`` is the only way
body text reaches a snippet or a model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from recon.route_exposure import seeds

MAX_SENSITIVE_FIELDS = 20
MAX_KEY_PATH_CHARS = 80
MAX_KEY_PATHS = 60
#: Secrets are matched in the head of a body: the matcher is regex-heavy and a
#: secret in a JSON or env answer sits near its start.
SECRET_SCAN_BYTES = 128 * 1024
#: Distinct secret values one response keeps for display.
MAX_SECRET_VALUES = 20
_MAX_LEAVES = 20000

#: The detector categories that name a credential; e-mail addresses, internal
#: URLs and debug flags the same matcher reports are not secrets.
_SECRET_CATEGORIES = frozenset({"auth", "secret", "cloud", "payment", "ai_llm", "js_service"})

PII_TYPES = ("email", "phone", "card", "iban", "ssn", "codice_fiscale", "dob")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 ().-]{5,22}[0-9]$")
_CARD_SEPARATED_RE = re.compile(r"\b\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7}\b")
_DIGITS_RE = re.compile(r"^\d{13,19}$")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_CF_RE = re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b")

_PHONE_KEYS = frozenset({"phone", "mobile", "tel", "telephone", "cell", "msisdn"})
_CARD_KEYS = frozenset({"card", "cc", "pan", "ccnum", "cardnumber", "creditcard"})
_SSN_KEYS = frozenset({"ssn"})
_DOB_KEYS = frozenset({"dob", "birth", "birthday", "birthdate", "dateofbirth"})

SENSITIVE_TOKENS = frozenset(
    "password secret token key ssn credit card bank pin cvv salary medical hash reset otp "
    "mfa apikey private role admin permission internal cost margin passwd pwd".split()
)

_MASK_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_MASK_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")
_MASK_DIGITS = re.compile(r"\d{6,}")
_PII_LOOKING_KEY = re.compile(r"@|\d{6,}")


def mask_text(text: str, tokens: bool = True) -> str:
    """Replace e-mails, long digit runs and (with `tokens`) token-shaped strings
    with placeholders. The operator's evidence snippet keeps the tokens: a
    secret it shows is the finding; what a model reads masks them."""
    text = _MASK_EMAIL.sub("<email>", text or "")
    if tokens:
        text = _MASK_TOKEN.sub("<tok>", text)
    return _MASK_DIGITS.sub("<n>", text)


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _iban_ok(value: str) -> bool:
    rearranged = value[4:] + value[:4]
    try:
        number = int("".join(str(int(c, 36)) for c in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


@dataclass
class Signals:
    """What a body showed. Types, counts and key names only."""
    pii_types: list = field(default_factory=list)
    pii_record_estimate: int = 0
    pii_others: bool = False
    sensitive_fields: list = field(default_factory=list)
    secret_types: list = field(default_factory=list)
    #: The secrets themselves and, at the same index, their detector names.
    #: Display only: never sent to a model.
    secret_values: list = field(default_factory=list)
    secret_value_types: list = field(default_factory=list)
    key_paths: list = field(default_factory=list)
    max_array_len: int = 0
    structured: bool = False

    @property
    def leak_signals(self) -> list:
        out = []
        if self.pii_types:
            out.append("pii")
        if self.pii_others:
            out.append("pii_others")
        if self.sensitive_fields:
            out.append("sensitive_fields")
        if self.secret_types:
            out.append("secret")
        return out


def _key_tokens(key: str) -> set:
    toks = set(seeds.tokens(key))
    toks |= {t[:-1] for t in toks if len(t) > 3 and t.endswith("s")}
    joined = re.sub(r"[^a-z0-9]", "", (key or "").lower())
    if joined:
        toks.add(joined)
    return toks


def _safe_key(key: str) -> str:
    return "<k>" if _PII_LOOKING_KEY.search(key or "") else str(key)


def _walk(node, path: str, leaves: list, paths: dict, stats: dict, depth: int = 0) -> None:
    """Collect (key, path, scalar) leaves; arrays collapse to `[]` in the path."""
    if len(leaves) >= _MAX_LEAVES or depth > 32:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            key = _safe_key(str(k))
            child = f"{path}.{key}" if path else key
            paths.setdefault(child, str(k))
            _walk(v, child, leaves, paths, stats, depth + 1)
            if not isinstance(v, (dict, list)):
                leaves.append((str(k), child, v))
    elif isinstance(node, list):
        stats["max_array_len"] = max(stats["max_array_len"], len(node))
        for item in node:
            _walk(item, f"{path}[]", leaves, paths, stats, depth + 1)


def _parse_json(text: str):
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def _pii_from_leaves(leaves: list, found: dict) -> None:
    for key, _path, value in leaves:
        if value is None or isinstance(value, bool):
            continue
        sval = str(value).strip()
        if not sval:
            continue
        ktoks = _key_tokens(key)
        for email in _EMAIL_RE.findall(sval):
            found["email"].add(email.lower())
        if ktoks & _PHONE_KEYS and _PHONE_RE.match(sval) and sum(c.isdigit() for c in sval) >= 7:
            found["phone"].add(re.sub(r"\D", "", sval))
        digits = re.sub(r"[ -]", "", sval)
        if ((ktoks & _CARD_KEYS and _DIGITS_RE.match(digits)) or _CARD_SEPARATED_RE.fullmatch(sval)) \
                and _DIGITS_RE.match(digits) and _luhn(digits):
            found["card"].add(digits)
        for iban in _IBAN_RE.findall(sval.replace(" ", "").upper()):
            if _iban_ok(iban):
                found["iban"].add(iban)
        if ktoks & _SSN_KEYS and _SSN_RE.match(sval):
            found["ssn"].add(sval)
        for cf in _CF_RE.findall(sval.upper()):
            found["codice_fiscale"].add(cf)
        if ktoks & _DOB_KEYS:
            found["dob"].add(sval)


def _pii_from_text(text: str, found: dict) -> None:
    for email in _EMAIL_RE.findall(text):
        found["email"].add(email.lower())
    for match in _CARD_SEPARATED_RE.findall(text):
        digits = re.sub(r"[ -]", "", match)
        if _DIGITS_RE.match(digits) and _luhn(digits):
            found["card"].add(digits)
    for iban in _IBAN_RE.findall(text):
        if _iban_ok(iban):
            found["iban"].add(iban)
    for cf in _CF_RE.findall(text):
        found["codice_fiscale"].add(cf)


def _sensitive_fields(paths: dict) -> list:
    out = []
    for path, raw_key in paths.items():
        if _key_tokens(raw_key) & SENSITIVE_TOKENS:
            out.append(path[:MAX_KEY_PATH_CHARS])
            if len(out) >= MAX_SENSITIVE_FIELDS:
                break
    return out


def _secret_matches(text: str, source_url: str) -> list:
    """[(detector name, secret value)] of the credentials in a body's head."""
    try:
        from recon.helpers.js_recon.patterns import scan_js_content
    except ImportError:  # pragma: no cover - spawned-container import shim
        from helpers.js_recon.patterns import scan_js_content
    findings, _ = scan_js_content(text[:SECRET_SCAN_BYTES], source_url, min_confidence="medium")
    out = []
    for finding in findings:
        if finding.get("category") in _SECRET_CATEGORIES and finding.get("name"):
            value = finding.get("secret_value") or finding.get("matched_text") or ""
            out.append((str(finding["name"]), str(value)))
    return out


def analyse(body: bytes, *, content_class: str, pii: bool = True, secrets: bool = False,
            source_url: str = "") -> Signals:
    """The signals of one (capped, decoded) body. Never raises."""
    signals = Signals()
    if not body or content_class == "binary":
        return signals
    try:
        text = body.decode("utf-8", "replace")
        document = _parse_json(text) if content_class in ("json", "text", "other") else None
        found = {t: set() for t in PII_TYPES}
        if document is not None:
            leaves, paths, stats = [], {}, {"max_array_len": 0}
            _walk(document, "", leaves, paths, stats)
            signals.structured = True
            signals.max_array_len = stats["max_array_len"]
            signals.key_paths = [p[:MAX_KEY_PATH_CHARS] for p in list(paths)[:MAX_KEY_PATHS]]
            signals.sensitive_fields = _sensitive_fields(paths)
            if pii:
                _pii_from_leaves(leaves, found)
        elif pii:
            _pii_from_text(text, found)
        if content_class == "xml":
            signals.structured = True
        if pii:
            signals.pii_types = [t for t in PII_TYPES if found[t]]
            signals.pii_record_estimate = max((len(v) for v in found.values()), default=0)
            signals.pii_others = len(found["email"]) >= 3 or len(found["phone"]) >= 3
        if secrets:
            matches = _secret_matches(text, source_url)
            signals.secret_types = sorted({name for name, _value in matches})
            for name, value in matches:
                if value and value not in signals.secret_values \
                        and len(signals.secret_values) < MAX_SECRET_VALUES:
                    signals.secret_values.append(value)
                    signals.secret_value_types.append(name)
    except Exception:  # noqa: BLE001 - a body that breaks a detector carries no signal
        return Signals()
    return signals


def content_class(content_type: str, body: bytes) -> str:
    """json | html | text | xml | binary | other, from the header then the bytes."""
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if "json" in ctype:
        return "json"
    if "html" in ctype:
        return "html"
    if "xml" in ctype:
        return "xml"
    if ctype.startswith("text/"):
        return "text"
    if ctype.startswith(("image/", "audio/", "video/", "font/")) or ctype in (
            "application/octet-stream", "application/pdf", "application/zip",
            "application/gzip", "application/x-gzip", "application/x-tar",
            "application/x-7z-compressed", "application/vnd.rar", "application/x-sqlite3"):
        return "binary"
    head = (body or b"")[:512]
    if not head:
        return "other"
    stripped = head.lstrip().lower()
    if stripped.startswith((b"{", b"[")):
        return "json"
    if stripped.startswith((b"<!doctype html", b"<html")):
        return "html"
    if stripped.startswith(b"<?xml"):
        return "xml"
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
    return "text" if printable >= len(head) * 0.9 else "binary"


def size_bucket(size: int) -> str:
    if size < 1024:
        return "<1k"
    if size < 10 * 1024:
        return "1-10k"
    if size < 100 * 1024:
        return "10-100k"
    return ">100k"

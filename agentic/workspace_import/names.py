"""File and folder names that come from a URL, a header or a forge."""
from __future__ import annotations

import unicodedata

MAX_NAME_BYTES = 120


def sanitize_name(raw, fallback: str = "download") -> str:
    """A single safe path segment: no separators, NUL or control characters,
    no leading/trailing dots or spaces, at most 120 UTF-8 bytes."""
    text = "".join(
        "_" if ch in "/\\" or unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch
        for ch in str(raw or "")
    ).strip(" .")
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_NAME_BYTES:
        text = encoded[:MAX_NAME_BYTES].decode("utf-8", "ignore").rstrip(" .")
    if not text or text in (".", ".."):
        return fallback
    return text

"""Strip credentials and secrets from URLs before anything logs or stores them.

A private GitHub tarball redirects to a codeload URL that carries a temporary
token in its query, and exception text from httpx or git can quote any URL.
"""
from __future__ import annotations

import re
import traceback
import urllib.parse

_URL_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+")


def redact_url(url: str) -> str:
    """scheme://host[:port]/path: no userinfo, query or fragment."""
    try:
        u = urllib.parse.urlsplit(str(url))
        host = u.hostname or ""
    except ValueError:
        return "<unparseable url>"
    if ":" in host:
        host = f"[{host}]"
    try:
        port = f":{u.port}" if u.port else ""
    except ValueError:
        port = ""
    if not u.scheme or not host:
        return "<unparseable url>"
    return f"{u.scheme.lower()}://{host.lower()}{port}{u.path}"


def redact_text(text: str) -> str:
    """Every scheme://… in `text`, redacted."""
    return _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)), str(text))


def safe_traceback(e: BaseException) -> str:
    """The stack frames of `e`, redacted, without its message: an exception's
    text can quote a URL with a token in its query, or an upstream's words."""
    return redact_text("".join(traceback.format_tb(e.__traceback__)))

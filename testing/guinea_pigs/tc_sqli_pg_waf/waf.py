"""The lab's signature WAF: a WSGI layer in front of the login app.

It decodes what the app would decode (URL encoding, nested any number of times up to
``ROUNDS``, HTML entities, ``\\uXXXX`` / ``%uXXXX`` / ``\\xXX`` escapes and PostgreSQL's
``U&'\\0073'`` / ``\\+000073`` escapes), drops inline ``/* */`` comments, quotes and
the ``'||'`` glue of a split string literal, lower-cases the result, and refuses the
request when it names a sleep function or a function that runs a query held in a string.
The second rule is what makes the lab a time-based injection through a *heavy query*:
``query_to_xml('select pg_sl'||'eep(5)', ...)`` or a ``DO`` block would otherwise rebuild
``pg_sleep`` from pieces the first rule never sees.
"""
from __future__ import annotations

import html
import io
import itertools
import re
from urllib.parse import unquote_plus

ROUNDS = 6
BLOCK_STATUS = "403 Forbidden"

_ESCAPES = re.compile(
    r"\\u([0-9a-fA-F]{4})|%u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\\+([0-9a-fA-F]{6})|\\([0-9a-fA-F]{4})"
)
_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_GLUE = re.compile(r"'\s*\|\|\s*'")
_DROP = re.compile(r"[\"`\s]")

RULES = (
    ("942-sleep", re.compile(r"sleep")),
    # Whitespace is gone by now: "DO $$" reads "do$$", "EXECUTE 'x'" reads "execute'x'".
    ("942-dynamic-sql", re.compile(r"query_to_xml|\bdo\$|execute['(]|executeformat|dblink")),
)

BLOCK_PAGE = (
    "<!doctype html><html><head><title>403 Request blocked</title></head><body>"
    "<h1>Request blocked</h1><p>TC-WAF blocked this request (rule {rule}). "
    "Incident id: {incident}.</p></body></html>"
)


def _unescape(match: re.Match) -> str:
    code = next(g for g in match.groups() if g)
    try:
        return chr(int(code, 16))
    except (ValueError, OverflowError):
        return match.group(0)


def normalise(text: str) -> str:
    current = text
    for _ in range(ROUNDS):
        decoded = _ESCAPES.sub(_unescape, html.unescape(unquote_plus(current)))
        if decoded == current:
            break
        current = decoded
    current = _COMMENT.sub("", current)
    current = _GLUE.sub("", current)
    return _DROP.sub("", current).lower()


def verdict(*parts: str) -> str | None:
    """The rule a request breaks, or None."""
    joined = normalise("\n".join(p for p in parts if p))
    for name, pattern in RULES:
        if pattern.search(joined):
            return name
    return None


class Waf:
    """Wraps a WSGI app; ``/health`` is never inspected (the runner and Compose poll it)."""

    def __init__(self, app):
        self.app = app
        # itertools.count is safe to advance from the server's threads; a generator is not.
        self._ids = itertools.count(1)

    def __call__(self, environ, start_response):
        if environ.get("PATH_INFO") == "/health":
            return self.app(environ, start_response)
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        body = environ["wsgi.input"].read(length) if length > 0 else b""
        environ["wsgi.input"] = io.BytesIO(body)
        rule = verdict(
            environ.get("PATH_INFO", ""),
            environ.get("QUERY_STRING", ""),
            body.decode("latin-1"),
            environ.get("HTTP_COOKIE", ""),
            environ.get("HTTP_USER_AGENT", ""),
            environ.get("HTTP_REFERER", ""),
            environ.get("HTTP_X_FORWARDED_FOR", ""),
        )
        if rule is None:
            return self.app(environ, start_response)
        page = BLOCK_PAGE.format(rule=rule, incident=f"tcw-{next(self._ids):06d}").encode()
        start_response(BLOCK_STATUS, [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(page))),
            ("Server", "tc-waf/1.4"),
            ("X-TC-WAF", "blocked"),
        ])
        return [page]

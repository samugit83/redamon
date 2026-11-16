"""robots.txt for the crawl and Check URL (RFC 9309, as the workspace mirror reads it).

One read per origin (scheme, host, port), through ``fetch.fetch_raw`` like every other
request. The status decides before the text does (RFC 9309 §2.3.1): a 2xx answer is parsed;
a 4xx means there are no rules, so everything is allowed; a 5xx, or no answer at all, means
the site could not say, so everything is disallowed. ``Sitemap:`` lines are exposed for the
Auto strategy and Check URL whatever the status, only from a 2xx answer.

The rules are matched against ``fetching.userAgent``, the name the crawl sends.
"""

from __future__ import annotations

import asyncio
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from urllib.robotparser import RobotFileParser

from tradecraft.ingest import fetch
from tradecraft.settings import EffectiveSettings

# RFC 9309 §2.5: a crawler must parse at least the first 500 KiB; what lies beyond is ignored.
MAX_BYTES = 500 * 1024

ALLOW_ALL = "allow_all"
DISALLOW_ALL = "disallow_all"
PARSED = "parsed"


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` of ``url`` (lowercased, default port dropped), or ""."""
    try:
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return ""
    if scheme not in ("http", "https") or not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


@dataclass
class Robots:
    """The verdict for one origin: ``allow_all`` (4xx), ``disallow_all`` (5xx, no answer) or
    ``parsed`` (2xx, the parser decides)."""

    origin: str
    mode: str
    status: int = 0
    sitemaps: list[str] = field(default_factory=list)
    _parser: Optional[RobotFileParser] = None

    def allows(self, url: str, user_agent: str) -> bool:
        if self.mode == ALLOW_ALL:
            return True
        if self.mode == DISALLOW_ALL or self._parser is None:
            return False
        return self._parser.can_fetch(user_agent or "*", url)


def parse(origin: str, status: int, text: str) -> Robots:
    """The verdict from one answer. ``status`` 0 is "no answer" (the network failed)."""
    if 200 <= status < 300:
        parser = RobotFileParser()
        parser.parse((text or "").splitlines())
        # RFC 9309 wants absolute URLs; a relative line is read against the origin.
        sitemaps = [urllib.parse.urljoin(origin + "/", sm.strip()) for sm in (parser.site_maps() or []) if sm.strip()]
        return Robots(origin, PARSED, status, sitemaps, parser)
    if 400 <= status < 500:
        return Robots(origin, ALLOW_ALL, status)
    return Robots(origin, DISALLOW_ALL, status)


async def read(url: str, settings: EffectiveSettings) -> Robots:
    """The robots.txt of ``url``'s origin. Redirects are followed by the web boundary (up to
    its limit, RFC 9309 §2.3.1.2), each hop judged by the address guard."""
    origin = origin_of(url)
    if not origin:
        return Robots("", DISALLOW_ALL, 0)
    resp = await fetch.fetch_raw(origin + "/robots.txt", settings, headers={"Accept": "text/plain"},
                                 max_bytes=MAX_BYTES)
    if resp.error:
        return Robots(origin, DISALLOW_ALL, 0)
    return parse(origin, resp.status, resp.text)


class RobotsCache:
    """Reads each origin's robots.txt once per crawl, even when parallel fetches ask at once."""

    def __init__(self, settings: EffectiveSettings) -> None:
        self._settings = settings
        self._user_agent = settings.str("fetching.userAgent")
        self._rules: dict[str, Robots] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def get(self, url: str) -> Robots:
        origin = origin_of(url)
        lock = self._locks.setdefault(origin, asyncio.Lock())
        async with lock:
            if origin not in self._rules:
                self._rules[origin] = await read(url, self._settings)
        return self._rules[origin]

    async def allows(self, url: str) -> bool:
        return (await self.get(url)).allows(url, self._user_agent)

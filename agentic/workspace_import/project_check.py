"""Does a project still exist? Asked of the web app, which owns the project rows.

Used before an upload or import places its result, every few minutes during a
long crawl, and by the purge route, which must never wipe the workspace of a
project that still exists. Only a 404 means "deleted"; anything else raises,
and callers fail closed.
"""
from __future__ import annotations

import os
import re
from typing import Optional

import httpx

# Injectable for tests.
TRANSPORT: Optional[httpx.AsyncBaseTransport] = None
TIMEOUT_SEC = 10.0
_PID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class ProjectCheckFailed(Exception):
    """The web app gave no definite answer."""


async def project_exists(project_id: str) -> bool:
    if not _PID_RE.match(project_id or ""):
        raise ProjectCheckFailed("invalid project id")
    base = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
    headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    try:
        async with httpx.AsyncClient(transport=TRANSPORT, timeout=TIMEOUT_SEC, follow_redirects=False) as client:
            # Streamed: the 200 body is the whole project, and only the status matters.
            async with client.stream("GET", f"{base}/api/projects/{project_id}", headers=headers) as resp:
                status = resp.status_code
    except httpx.HTTPError as e:
        raise ProjectCheckFailed(type(e).__name__) from None
    if status == 200:
        return True
    if status == 404:
        return False
    raise ProjectCheckFailed(f"status {status}")

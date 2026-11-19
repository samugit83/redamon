"""AI Navigator stream events (plan Appendix B), built here and only here.

The webapp validates every event again and drops what it does not know. Summaries are built by
code, never by the model, and no event ever carries a tool result.
"""
from __future__ import annotations

import json
import re

from navigator.limits import (MAX_DELTA_CHARS, MAX_DETAIL_CHARS, MAX_ERROR_MESSAGE_CHARS,
                              MAX_SUMMARY_CHARS, ROUTES)

_CODE_RE = re.compile(r"^[a-z_]{1,40}$")


def _cap(value, n: int) -> str:
    s = value if isinstance(value, str) else str(value or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def meta(run_id: str, model_used: str) -> dict:
    return {"type": "meta", "run_id": _cap(run_id, 80), "model_used": _cap(model_used, 200)}


def route(routes: list[str]) -> dict:
    return {"type": "route", "routes": [r for r in routes if r in ROUTES]}


def refused_route(route_name: str, reason_code: str) -> dict:
    return {"type": "refused_route", "route": route_name, "reason_code": _cap(reason_code, 40)}


def tool(route_name: str, name: str, status: str, summary: str, detail: str | None = None) -> dict:
    ev = {"type": "tool", "route": route_name, "name": _cap(name, 60), "status": status,
          "summary": _cap(summary, MAX_SUMMARY_CHARS)}
    if detail:
        ev["detail"] = _cap(detail, MAX_DETAIL_CHARS)
    return ev


def delta(text: str) -> list[dict]:
    """One or more delta events; a long chunk is split at the cap."""
    return [{"type": "delta", "text": text[i:i + MAX_DELTA_CHARS]} for i in range(0, len(text), MAX_DELTA_CHARS)]


def citations(items: list[dict]) -> dict:
    return {"type": "citations", "items": items}


def handoff() -> dict:
    return {"type": "handoff", "target": "ai_agent"}


def done() -> dict:
    return {"type": "done", "status": "complete"}


def error(code: str, message: str) -> dict:
    return {"type": "error", "code": code if _CODE_RE.match(code or "") else "navigator_error",
            "message": _cap(message, MAX_ERROR_MESSAGE_CHARS)}


def ndjson(event: dict) -> bytes:
    return (json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

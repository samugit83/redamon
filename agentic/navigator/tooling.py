"""The tool shape every AI Navigator specialist binds: a name, an OpenAI-format JSON schema the
model sees, and an async runner. Local tools (wiki, graph schema) and remote tools (the webapp's
manifest) share it, so the specialist loop has one path for both.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional


@dataclass
class ToolOutcome:
    #: What the model reads; wrapped as untrusted data before it reaches the model.
    content: str
    ok: bool
    #: Built by code, shown in the trace; never a tool result.
    summary: str
    #: Generated Cypher (or SQL), for the "How I got this" trace.
    detail: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class NavTool:
    name: str
    description: str
    parameters: dict
    route: str
    run: Callable[[dict], Awaitable[ToolOutcome]]

    def schema(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.parameters}}


def as_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def refused(code: str, message: str, summary: str) -> ToolOutcome:
    return ToolOutcome(as_json({"ok": False, "code": code, "message": message}), False, summary, error_code=code)

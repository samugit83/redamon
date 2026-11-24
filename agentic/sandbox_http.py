"""Bounded reads of a Kali sandbox's answers (group 1).

Whoever is root in a per-user sandbox controls what its ports answer (NET_ADMIN lets a shell
redirect them; anyone can replace a listener). The agent reads those answers in the one
process every tenant shares, so an answer must never cost it more than MAX_ANSWER_BYTES of
memory and a fixed wall-clock time:

- the request asks for ``Accept-Encoding: identity``, and an answer with any other
  Content-Encoding is refused without decoding a byte: httpx inflates every encoding it is
  given, stacked ones too, synchronously, so a few KB of ``gzip, gzip`` became gigabytes in
  the agent before any timeout could fire;
- the raw bytes are counted as they arrive (``aiter_raw``) and the read stops past the cap;
  a declared Content-Length over the cap is refused before reading;
- one deadline bounds the whole exchange, a slow drip included;
- JSON is parsed only from the capped buffer.

Every read of a sandbox's own HTTP servers (the session manager, the progress streams, the
tunnel manager, ngrok's API) goes through ``read_answer``.
"""

from __future__ import annotations

import asyncio
import json as _json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import httpx

import sandbox_contract as contract

MAX_ANSWER_BYTES = 1024 * 1024
ANSWER_DEADLINE_S = contract.FANOUT_TIMEOUT_S
REFUSAL_REASONS = ("encoding", "too_large", "deadline")


class SandboxAnswerRefused(Exception):
    """The answer was not read: ``reason`` is ``encoding`` (compressed), ``too_large`` or
    ``deadline``. Nothing of its body is kept."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"sandbox answer refused ({reason})")


@dataclass(frozen=True)
class SandboxAnswer:
    status: int
    body: bytes

    def json(self) -> Any:
        """The body as JSON; ValueError when it is empty or not JSON."""
        if not self.body:
            raise ValueError("empty answer")
        return _json.loads(self.body.decode("utf-8"))


def _encodings(response: httpx.Response) -> list:
    values = []
    for header in response.headers.get_list("content-encoding"):
        values += [v.strip().lower() for v in header.split(",")]
    return [v for v in values if v]


async def _read(client: httpx.AsyncClient, method: str, url: str, headers: dict,
                json: Any, max_bytes: int, deadline: float) -> SandboxAnswer:
    loop = asyncio.get_running_loop()
    async with client.stream(method, url, headers=headers, json=json) as response:
        if any(v != "identity" for v in _encodings(response)):
            raise SandboxAnswerRefused("encoding")
        declared = response.headers.get("content-length")
        if declared is not None and declared.strip().isdigit() and int(declared) > max_bytes:
            raise SandboxAnswerRefused("too_large")
        if response.is_stream_consumed:
            # A transport that read the body itself (a test double): only its size is left.
            if len(response.content) > max_bytes:
                raise SandboxAnswerRefused("too_large")
            return SandboxAnswer(status=response.status_code, body=response.content)
        chunks, total = [], 0
        async for chunk in response.aiter_raw():
            total += len(chunk)
            if total > max_bytes:
                raise SandboxAnswerRefused("too_large")
            if loop.time() > deadline:
                raise SandboxAnswerRefused("deadline")
            chunks.append(chunk)
        return SandboxAnswer(status=response.status_code, body=b"".join(chunks))


async def read_answer(client: httpx.AsyncClient, method: str, url: str, *,
                      headers: Optional[Mapping[str, str]] = None, json: Any = None,
                      max_bytes: int = MAX_ANSWER_BYTES,
                      deadline_s: float = ANSWER_DEADLINE_S) -> SandboxAnswer:
    """One request to a sandbox, its answer read under the cap and the deadline.

    Raises SandboxAnswerRefused for an answer it will not read, and httpx's own errors for an
    exchange that failed."""
    sent = {k: v for k, v in (headers or {}).items() if k.lower() != "accept-encoding"}
    sent["Accept-Encoding"] = "identity"
    deadline = asyncio.get_running_loop().time() + deadline_s
    try:
        return await asyncio.wait_for(_read(client, method, url, sent, json, max_bytes, deadline),
                                      timeout=deadline_s)
    except asyncio.TimeoutError:
        raise SandboxAnswerRefused("deadline") from None

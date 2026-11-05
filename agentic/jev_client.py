"""The only native Jev transport (direct TypeSafe or Jev-only OpenRouter).

Recon never sees credentials: `/jev/*` resolves the owner's exact selected
provider from persisted project state. Null selection uses recon's fallbacks.

- Backend origins/models are constants, never user-configurable. Immutable
  provider contexts keep each token bound to its backend. No redirects.
- Every failure raises `JevError` with a fixed message. The httpx exception
  text, the key and the state never appear in it: recon prints agent error
  bodies into the recon drawer.
- One attempt, 5 s, no retries. The recon breaker owns retry policy.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import logging
import math
import os
import re
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://api.typesafe.ai"
# Recon thresholds are calibrated against this version, never a drifting alias.
JEV_MODEL = "jev-1.13.0"
OPENROUTER_BASE_URL = "https://openrouter.ai/api"
OPENROUTER_MODEL = "typesafe/jev-1.13"
#: OpenRouter runs a request above about 32,000 bytes of text in TypeSafe's
#: long-context mode, which it documents as slower and less accurate than the
#: mode the recon thresholds were calibrated in. It is not a size limit: the
#: hooks split their batches below it (`body_limit`), and only a single item
#: that cannot fit on its own is refused.
OPENROUTER_BODY_LIMIT = 32_000
#: Both backends answer with the version they served, optionally as a dated
#: snapshot (OpenRouter documents `typesafe/jev-1.13-20260917`). Any other
#: version means the calibration no longer holds, so the answer is refused.
_OPENROUTER_MODEL_RE = re.compile(r"typesafe/jev-1\.13(?:-\d{8})?")
_DIRECT_MODEL_RE = re.compile(r"jev-1\.13\.0(?:-\d{8})?")


@dataclass(frozen=True)
class JevProvider:
    """One validated request's immutable routing; the secret is never repr'd."""

    provider_type: str
    api_key: str = field(repr=False)
    provider_id: str = ""

    def __post_init__(self):
        if not isinstance(self.provider_type, str) or self.provider_type not in {"jev", "jev_openrouter"}:
            raise JevError("jev_not_configured")
        _auth_headers(self.api_key)

    @property
    def base_url(self) -> str:
        return OPENROUTER_BASE_URL if self.provider_type == "jev_openrouter" else BASE_URL

    @property
    def wire_model(self) -> str:
        return OPENROUTER_MODEL if self.provider_type == "jev_openrouter" else JEV_MODEL


def _provider(value: JevProvider | str) -> JevProvider:
    # Key-only callers are legacy direct-transport fixtures, never API resolution.
    return value if isinstance(value, JevProvider) else JevProvider("jev", value)

TIMEOUT_S = 5.0
_WEBAPP_TIMEOUT_S = 10.0

#: Printable ASCII with no whitespace. A CR/LF in a header value makes httpx
#: raise an error that quotes the value, which would put the key in a log.
_KEY_RE = re.compile(r"[\x21-\x7e]{8,512}")

ERROR_MESSAGES = {
    "jev_auth": "The Jev backend rejected the API key",
    "jev_no_credit": "The Jev backend account has no credit left",
    "jev_bad_request": "The Jev backend refused the request or its size",
    "jev_rate_limited": "Jev backend rate limit reached",
    "jev_overloaded": "The Jev backend is unavailable",
    "jev_timeout": "The Jev backend did not answer in time",
    "jev_bad_response": "The Jev backend returned an unexpected answer",
    "jev_not_configured": "No valid Jev provider selected for this project",
    "jev_unavailable": "The project's Jev provider could not be loaded",
    "jev_forbidden": "The project does not belong to this user",
}


class JevError(Exception):
    """A Jev call failed. `error_type` is a key of ERROR_MESSAGES."""

    def __init__(self, error_type: str, retry_after: float | None = None):
        if error_type not in ERROR_MESSAGES:
            error_type = "jev_bad_response"
        super().__init__(ERROR_MESSAGES[error_type])
        self.error_type = error_type
        self.message = ERROR_MESSAGES[error_type]
        self.retry_after = retry_after


def _retry_after(headers) -> float | None:
    try:
        value = float(headers.get("retry-after", ""))
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _error_for_status(status: int, headers) -> JevError:
    if status in (401, 403):
        return JevError("jev_auth")
    if status == 402:
        return JevError("jev_no_credit")
    if status in (400, 422):
        # The live API answers a malformed body with 400; the docs say 422.
        return JevError("jev_bad_request")
    if status == 429:
        return JevError("jev_rate_limited", retry_after=_retry_after(headers))
    if status >= 500:
        return JevError("jev_overloaded")
    return JevError("jev_bad_response")


def _auth_headers(key: str) -> dict:
    if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
        raise JevError("jev_auth")
    return {"Authorization": f"Bearer {key}"}


def _serialize(payload: dict) -> bytes:
    try:
        return json.dumps(payload, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        raise JevError("jev_bad_request") from None


def body_limit(provider: JevProvider | str) -> int | None:
    """The request-body budget the hooks must batch under, or None for no budget."""
    return OPENROUTER_BODY_LIMIT if _provider(provider).provider_type == "jev_openrouter" else None


def request_size(provider: JevProvider | str, state, questions: dict) -> int:
    """Bytes of the System One body exactly as `_request` would send it."""
    provider = _provider(provider)
    return len(_serialize({"model": provider.wire_model, "state": state, "questions": questions}))


def _body(provider: JevProvider, payload: dict) -> bytes:
    body = _serialize(payload)
    limit = body_limit(provider)
    if limit is not None and len(body) >= limit:
        raise JevError("jev_bad_request")
    return body


def validate_request_size(provider: JevProvider | str, state, questions: dict) -> None:
    provider = _provider(provider)
    _body(provider, {"model": provider.wire_model, "state": state, "questions": questions})


async def _request(method: str, path: str, key: JevProvider | str, payload: dict | None = None):
    provider = _provider(key)
    headers = _auth_headers(provider.api_key)
    kwargs = {}
    if payload is not None:
        kwargs["content"] = _body(provider, payload)
        headers["Content-Type"] = "application/json"
    try:
        async with httpx.AsyncClient(headers=headers, timeout=TIMEOUT_S,
                                     follow_redirects=False) as client:
            resp = await client.request(method, f"{provider.base_url}{path}", **kwargs)
    except httpx.HTTPError:
        # Timeouts and connection errors alike; the exception text is dropped.
        raise JevError("jev_timeout") from None
    except (TypeError, ValueError):
        # A state that does not serialise to JSON.
        raise JevError("jev_bad_request") from None
    if not 200 <= resp.status_code < 300:
        raise _error_for_status(resp.status_code, resp.headers)
    try:
        return resp.json()
    except ValueError:
        raise JevError("jev_bad_response") from None


async def list_models(key: str) -> list[str]:
    """The direct TypeSafe model list. Free: spends no credit."""
    data = await _request("GET", "/v1/models", JevProvider("jev", key))
    models = data.get("models") if isinstance(data, dict) else None
    if not isinstance(models, list):
        raise JevError("jev_bad_response")
    return [m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)]


def _is_finite(value) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _is_unit(value) -> bool:
    return _is_finite(value) and 0.0 <= value <= 1.0


def _valid_answer(question: dict, answer) -> bool:
    if not isinstance(answer, dict) or answer.get("type") != question.get("type"):
        return False
    if "confidence" in answer and not _is_unit(answer["confidence"]):
        return False
    if "probabilities" in answer:
        probabilities = answer["probabilities"]
        criteria = question.get("criteria") or {}
        if question["type"] == "score":
            criteria = {str(i) for i in range(len(criteria))}
        if (not isinstance(probabilities, dict)
                or any(not isinstance(name, str) or name not in criteria or not _is_unit(value)
                       for name, value in probabilities.items())):
            return False
    qtype = question["type"]
    if qtype == "noul":
        return _is_unit(answer.get("noul"))
    if qtype == "choice":
        choice = answer.get("choice")
        # isinstance first: `in` hashes the value, and a list or object would raise
        # TypeError, which no caller handles (only JevError is).
        return (isinstance(choice, str) and choice in (question.get("criteria") or {})
                and _is_unit(answer.get("confidence")))
    if qtype == "score":
        score = answer.get("score")
        return (_is_finite(score) and 0 <= score <= len(question["criteria"]) - 1
                and _is_unit(answer.get("confidence")))
    return False


async def system_one(key: JevProvider | str, model: str, state, questions: dict) -> dict:
    """Ask `questions` about `state`. Returns `{"model", "answers"}`.

    Every question must come back with an answer of its own type and in range
    (a Choice must name one of its own options), or the whole call fails with
    `jev_bad_response`: callers never see a partial answer set.
    """
    provider = _provider(key)
    if model != JEV_MODEL:
        raise JevError("jev_bad_request")
    if (not isinstance(questions, dict) or not questions
            or any(not isinstance(q, dict) or q.get("type") not in {"noul", "choice", "score"}
                   or (q.get("type") == "choice" and not isinstance(q.get("criteria"), dict))
                   or (q.get("type") == "score" and
                       (not isinstance(q.get("criteria"), list) or not 2 <= len(q["criteria"]) <= 10))
                   for q in questions.values())):
        raise JevError("jev_bad_request")
    data = await _request("POST", "/v1/systemone", provider,
                          {"model": provider.wire_model, "state": state, "questions": questions})
    answers = data.get("answers") if isinstance(data, dict) else None
    if not isinstance(answers, dict):
        raise JevError("jev_bad_response")
    for name, question in questions.items():
        if not _valid_answer(question, answers.get(name)):
            raise JevError("jev_bad_response")
    returned_model = data.get("model")
    if (provider.provider_type == "jev_openrouter"
            and (not isinstance(returned_model, str)
                 or not _OPENROUTER_MODEL_RE.fullmatch(returned_model))):
        raise JevError("jev_bad_response")
    if (provider.provider_type == "jev"
            and (not isinstance(returned_model, str)
                 or not _DIRECT_MODEL_RE.fullmatch(returned_model))):
        raise JevError("jev_bad_response")
    logger.info("jev backend=%s canonical_model=%s wire_model=%s",
                provider.provider_type, JEV_MODEL, returned_model)
    return {
        "model": returned_model,
        "answers": {name: answers[name] for name in questions},
    }


# ---------------------------------------------------------------------------
# Owner binding: a /jev/* caller names a project and a user; both must match.
# ---------------------------------------------------------------------------

def _fetch_project(project_id: str) -> dict | None:
    """Trusted persisted state, fetched fresh to observe selection/owner changes."""
    import requests

    webapp_url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
    url = f"{webapp_url}/api/projects/{urllib.parse.quote(project_id, safe='')}"
    resp = requests.get(url, headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
                        timeout=_WEBAPP_TIMEOUT_S)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise JevError("jev_unavailable")
    return data


async def selected_provider_id(project_id: str, user_id: str) -> str:
    """Bind ownership and selection from ONE fresh trusted project snapshot.

    Deliberately uncached: a revoked ownership or a cleared selection must take
    effect on the next request, before any credential is read.
    """
    try:
        project = await asyncio.to_thread(_fetch_project, project_id)
    except Exception:
        raise JevError("jev_unavailable") from None
    if not project or project.get("userId") != user_id:
        raise JevError("jev_forbidden")
    selected = project.get("jevProviderId")
    if not isinstance(selected, str) or not selected:
        raise JevError("jev_not_configured")
    return selected


def resolve_provider(providers: list, selected_id: str, owner_id: str) -> JevProvider:
    """Resolve exactly one row from the trusted owner's credential list."""
    if not isinstance(selected_id, str) or not selected_id:
        raise JevError("jev_not_configured")
    matches = [row for row in providers or []
               if isinstance(row, dict) and row.get("id") == selected_id]
    if len(matches) != 1:
        raise JevError("jev_not_configured")
    row = matches[0]
    if row.get("userId", owner_id) != owner_id:
        raise JevError("jev_not_configured")
    return JevProvider(row.get("providerType"), row.get("apiKey"), selected_id)


async def test_provider(provider: JevProvider) -> dict:
    """A free check of the key and the pinned model. Spends no credit.

    Authentication plus catalog metadata does not prove the account can pay for
    a decision call, so the result never claims that.
    """
    if provider.provider_type == "jev":
        models = await list_models(provider.api_key)
        if JEV_MODEL not in models:
            raise JevError("jev_bad_response")
        return {"success": True, "model": JEV_MODEL,
                "proof": "key_and_model_listing", "billed": False,
                "response_text": "TypeSafe accepted the key and lists Jev 1.13.0; inference not tested (free)."}
    key_data = await _request("GET", "/v1/key", provider)
    if not isinstance(key_data, dict) or not isinstance(key_data.get("data"), dict):
        raise JevError("jev_bad_response")
    metadata = await _request("GET", f"/v1/models/{OPENROUTER_MODEL}/endpoints", provider)
    data = metadata.get("data") if isinstance(metadata, dict) else None
    if (not isinstance(data, dict) or data.get("id") != OPENROUTER_MODEL
            or not isinstance(data.get("endpoints"), list) or not data["endpoints"]):
        raise JevError("jev_bad_response")
    return {"success": True, "model": JEV_MODEL, "wire_model": OPENROUTER_MODEL,
            "proof": "key_and_model_metadata", "billed": False,
            "response_text": "OpenRouter accepted the key and publishes Jev 1.13 endpoints; inference access not tested (free)."}

"""`jev_client`: the only code that talks to TypeSafe AI.

What it guarantees, each asserted below:
- every TypeSafe status maps to one fixed `error_type` and a fixed message;
  neither the key nor the httpx exception text ever appears in an error;
- the key only goes to the constant base URL, redirects are not followed, and a
  malformed key or a non-pinned model id is refused before any request;
- a response missing an answer, or with one of the wrong type or out of range,
  fails the whole call (never a partial answer set);
- the owner binding fails closed and only caches a match;
- the agent's `/llm-provider/test` checks a Jev key by listing models only.

Runs inside the agent container.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jev_client  # noqa: E402
from jev_client import JevError  # noqa: E402

KEY = "apikey_" + "a" * 36 + "_" + "b" * 64
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _transport(handler, seen: list | None = None):
    """Patch httpx.AsyncClient so every client jev_client opens uses `handler`."""
    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(
            lambda req: (seen.append(req) if seen is not None else None) or handler(req))
        return _REAL_ASYNC_CLIENT(*args, **kwargs)
    return patch.object(jev_client.httpx, "AsyncClient", side_effect=factory)


def _json(status: int, body, headers=None):
    return lambda req: httpx.Response(status, json=body, headers=headers or {})


def _run(coro):
    return asyncio.run(coro)


NOUL_Q = {"q": {"type": "noul", "instructions": "Is this a ping?"}}
CHOICE_Q = {"vendor": {"type": "choice", "instructions": "Which vendor?",
                       "criteria": {"cloudflare": None, "akamai": None}}}


def _ok(answers, model="jev-1.13.0"):
    return _json(200, {"model": model, "answers": answers,
                       "usage": {"input_tokens": 10, "output_tokens": 2}})


# ---------------------------------------------------------------------------
# Status -> error_type
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,error_type", [
    (401, "jev_auth"), (403, "jev_auth"), (402, "jev_no_credit"),
    (400, "jev_bad_request"), (422, "jev_bad_request"), (429, "jev_rate_limited"),
    (529, "jev_overloaded"), (500, "jev_overloaded"), (503, "jev_overloaded"),
    (404, "jev_bad_response"), (302, "jev_bad_response"),
])
def test_status_maps_to_one_error_type(status, error_type):
    body = {"detail": {"error_type": "x", "message": f"echo {KEY}"}}
    with _transport(_json(status, body)):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == error_type
    assert str(err.value) == jev_client.ERROR_MESSAGES[error_type]
    assert KEY not in str(err.value)


def test_rate_limit_carries_retry_after():
    with _transport(_json(429, {}, headers={"retry-after": "7"})):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.retry_after == 7.0


def test_rate_limit_with_a_junk_retry_after_has_none():
    with _transport(_json(429, {}, headers={"retry-after": "soon"})):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.retry_after is None


@pytest.mark.parametrize("exc", [
    httpx.ConnectTimeout(f"timed out with {KEY}"),
    httpx.ReadTimeout(f"timed out with {KEY}"),
    httpx.ConnectError(f"refused, Authorization: Bearer {KEY}"),
])
def test_transport_failures_are_timeouts_and_drop_the_exception_text(exc):
    def boom(req):
        raise exc
    with _transport(boom):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == "jev_timeout"
    assert KEY not in str(err.value)
    assert err.value.__cause__ is None and err.value.__suppress_context__


def test_a_non_json_2xx_is_a_bad_response():
    with _transport(lambda req: httpx.Response(200, text="<html>")):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == "jev_bad_response"


def test_an_unknown_error_type_is_coerced_to_a_known_one():
    assert JevError("something_else").error_type == "jev_bad_response"


# ---------------------------------------------------------------------------
# What is sent, and where
# ---------------------------------------------------------------------------

def test_the_request_goes_to_the_constant_base_url_with_the_key_as_bearer():
    seen: list = []
    with _transport(_ok({"q": {"type": "noul", "noul": 0.9}}), seen):
        _run(jev_client.system_one(KEY, "jev-1.13.0", {"server": "nginx"}, NOUL_Q))
    (req,) = seen
    assert str(req.url) == "https://api.typesafe.ai/v1/systemone"
    assert req.method == "POST"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(req.content) == {"model": "jev-1.13.0", "state": {"server": "nginx"},
                                       "questions": NOUL_Q}


def test_a_redirect_is_not_followed():
    seen: list = []
    redirect = lambda req: httpx.Response(302, headers={"location": "https://evil.example/"})  # noqa: E731
    with _transport(redirect, seen):
        with pytest.raises(JevError):
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert len(seen) == 1


@pytest.mark.parametrize("model", ["jev-latest", "jev-preview", "jev-1.14.0", "gpt-4o", "jev-1.13", "../x", "", None])
def test_a_model_that_is_not_a_pinned_version_is_refused_before_any_request(model):
    seen: list = []
    with _transport(_ok({}), seen):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, model, "s", NOUL_Q))
    assert err.value.error_type == "jev_bad_request"
    assert seen == []


@pytest.mark.parametrize("key", ["", "short", KEY + "\r\nX-Evil: 1", "has space " + KEY, None])
def test_a_malformed_key_is_refused_before_any_request(key):
    seen: list = []
    with _transport(_ok({}), seen):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(key, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == "jev_auth"
    assert seen == []


def test_a_state_that_is_not_json_is_a_bad_request():
    with _transport(_ok({})):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", {"x": object()}, NOUL_Q))
    assert err.value.error_type == "jev_bad_request"


def test_no_questions_is_a_bad_request():
    with pytest.raises(JevError) as err:
        _run(jev_client.system_one(KEY, "jev-1.13.0", "s", {}))
    assert err.value.error_type == "jev_bad_request"


# ---------------------------------------------------------------------------
# Answer validation: all or nothing
# ---------------------------------------------------------------------------

def test_valid_answers_are_returned_with_the_model_version():
    with _transport(_ok({"q": {"type": "noul", "noul": 0.25}, "extra": {"type": "noul", "noul": 1}})):
        out = _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert out == {"model": "jev-1.13.0", "answers": {"q": {"type": "noul", "noul": 0.25}}}


@pytest.mark.parametrize("answers", [
    {},                                                    # missing
    {"q": {"type": "choice", "noul": 0.5}},                # wrong type
    {"q": {"type": "noul"}},                               # no value
    {"q": {"type": "noul", "noul": 1.5}},                  # out of range
    {"q": {"type": "noul", "noul": -0.1}},
    {"q": {"type": "noul", "noul": True}},                 # bool is not a number here
    {"q": {"type": "noul", "noul": "0.9"}},
    {"q": "yes"},
])
def test_a_bad_noul_answer_fails_the_call(answers):
    with _transport(_ok(answers)):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == "jev_bad_response"


def test_a_choice_outside_its_own_options_fails_the_call():
    answer = {"vendor": {"type": "choice", "choice": "evilcorp", "confidence": 0.9,
                         "probabilities": {"evilcorp": 1.0}}}
    with _transport(_ok(answer)):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", CHOICE_Q))
    assert err.value.error_type == "jev_bad_response"


def test_a_valid_choice_passes():
    answer = {"vendor": {"type": "choice", "choice": "akamai", "confidence": 0.8,
                         "probabilities": {"akamai": 0.9, "cloudflare": 0.1}}}
    with _transport(_ok(answer)):
        out = _run(jev_client.system_one(KEY, "jev-1.13.0", "s", CHOICE_Q))
    assert out["answers"]["vendor"]["choice"] == "akamai"


def test_answers_not_a_map_fail_the_call():
    with _transport(_json(200, {"model": "jev-1.13.0", "answers": []})):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == "jev_bad_response"


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------

def test_list_models_returns_names_and_uses_a_get():
    seen: list = []
    body = {"models": [{"name": "jev-latest"}, {"name": "jev-preview"}, {"nope": 1}]}
    with _transport(_json(200, body), seen):
        assert _run(jev_client.list_models(KEY)) == ["jev-latest", "jev-preview"]
    assert seen[0].method == "GET"
    assert str(seen[0].url) == "https://api.typesafe.ai/v1/models"


def test_list_models_401_is_auth():
    with _transport(_json(401, {})):
        with pytest.raises(JevError) as err:
            _run(jev_client.list_models(KEY))
    assert err.value.error_type == "jev_auth"


def test_list_models_malformed_is_a_bad_response():
    with _transport(_json(200, {"models": "x"})):
        with pytest.raises(JevError) as err:
            _run(jev_client.list_models(KEY))
    assert err.value.error_type == "jev_bad_response"


# ---------------------------------------------------------------------------
# Owner binding
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_owner_cache():
    jev_client._owner_cache.clear()
    yield
    jev_client._owner_cache.clear()


def test_owner_match_passes_and_is_cached():
    with patch.object(jev_client, "_fetch_project_owner", return_value="u1") as fetch:
        _run(jev_client.verify_owner("p1", "u1"))
        _run(jev_client.verify_owner("p1", "u1"))
    assert fetch.call_count == 1


def test_owner_mismatch_is_forbidden_and_not_cached():
    with patch.object(jev_client, "_fetch_project_owner", return_value="someone-else") as fetch:
        for _ in range(2):
            with pytest.raises(JevError) as err:
                _run(jev_client.verify_owner("p1", "u1"))
            assert err.value.error_type == "jev_forbidden"
    assert fetch.call_count == 2


def test_a_missing_project_is_forbidden():
    with patch.object(jev_client, "_fetch_project_owner", return_value=None):
        with pytest.raises(JevError) as err:
            _run(jev_client.verify_owner("p-gone", "u1"))
    assert err.value.error_type == "jev_forbidden"


def test_an_unreachable_webapp_is_unavailable():
    with patch.object(jev_client, "_fetch_project_owner", side_effect=ConnectionError("down")):
        with pytest.raises(JevError) as err:
            _run(jev_client.verify_owner("p1", "u1"))
    assert err.value.error_type == "jev_unavailable"


def test_fetch_project_owner_reads_user_id_and_maps_404_to_none():
    class _Resp:
        def __init__(self, status, body):
            self.status_code, self._body = status, body

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(self.status_code)

        def json(self):
            return self._body

    with patch("requests.get", return_value=_Resp(200, {"userId": "u1"})) as get:
        assert jev_client._fetch_project_owner("p/1") == "u1"
    assert get.call_args.args[0].endswith("/api/projects/p%2F1")
    with patch("requests.get", return_value=_Resp(404, {})):
        assert jev_client._fetch_project_owner("p1") is None
    with patch("requests.get", return_value=_Resp(500, {})):
        with pytest.raises(RuntimeError):
            jev_client._fetch_project_owner("p1")


def test_resolve_exact_jev_provider_without_first_row_fallback():
    rows = [{"id": "first", "providerType": "jev", "apiKey": "first-key"},
            {"id": "selected", "providerType": "jev", "apiKey": KEY}]
    assert jev_client.resolve_provider(rows, "selected", "u1").api_key == KEY
    for selected in ("missing", "", None):
        with pytest.raises(JevError):
            jev_client.resolve_provider(rows, selected, "u1")


# ---------------------------------------------------------------------------
# The agent's /llm-provider/test for a Jev row
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        import api
        from fastapi.testclient import TestClient
        yield TestClient(api.app)


def _post_test(client, **body):
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        return client.post("/llm-provider/test", headers={"X-Internal-Key": "s3cret"},
                           json={"providerType": "jev", "apiKey": KEY, **body})


def test_provider_test_lists_models_and_never_builds_a_chat_model(client):
    with patch.object(jev_client, "list_models", AsyncMock(return_value=["jev-1.13.0"])) as lm, \
            patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        resp = _post_test(client, baseUrl="http://evil.example")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert resp.json()["model"] == "jev-1.13.0"
    lm.assert_awaited_once_with(KEY)
    setup.assert_not_called()


@pytest.mark.parametrize("error_type,text", [
    ("jev_auth", "TypeSafe rejected the key"),
    ("jev_no_credit", "No TypeSafe credit"),
    ("jev_timeout", jev_client.ERROR_MESSAGES["jev_timeout"]),
])
def test_provider_test_failures_carry_fixed_texts(client, error_type, text):
    with patch.object(jev_client, "list_models", AsyncMock(side_effect=JevError(error_type))):
        resp = _post_test(client)
    assert resp.status_code == 400
    assert resp.json() == {"success": False, "error": text}


# ---------------------------------------------------------------------------
# Regressions found in review
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("choice", [["cloudflare"], {"cloudflare": 1}, [], {}])
def test_an_unhashable_choice_is_a_bad_response_not_a_crash(choice):
    """REGRESSION (unhashable choice escaped as a TypeError): `choice in criteria` hashes the
    value, so a list or object raised TypeError inside system_one. Only JevError is handled
    upstream, so the endpoint answered 500 with a traceback instead of the fixed 503
    jev_bad_response that the recon breaker classifies."""
    answer = {"vendor": {"type": "choice", "choice": choice, "confidence": 0.9, "probabilities": {}}}
    with _transport(_ok(answer)):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY, "jev-1.13.0", "s", CHOICE_Q))
    assert err.value.error_type == "jev_bad_response"


def test_a_key_with_a_trailing_newline_is_refused_before_any_request():
    """REGRESSION (`$` matched before a final newline): the key pattern comment promised no
    whitespace, but `abc\\n` passed. h11 would reject the header later, but the guard must
    not depend on that."""
    seen: list = []
    with _transport(_ok({}), seen):
        with pytest.raises(JevError) as err:
            _run(jev_client.system_one(KEY + "\n", "jev-1.13.0", "s", NOUL_Q))
    assert err.value.error_type == "jev_auth"
    assert seen == []

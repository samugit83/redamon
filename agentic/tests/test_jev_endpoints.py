"""The agent's /jev/* endpoints.

They take the same request bodies as /llm/* and return the same response shapes,
answered by TypeSafe Jev. This locks in:
- user_id and project_id are required (422), so no call lands in the shared
  "anonymous" rate bucket;
- the project is bound to its owner and fails closed (403 mismatch, 503 when the
  webapp is unreachable);
- no Jev row -> 503 jev_not_configured; providers unreachable -> 503 jev_unavailable;
- every Jev-side failure is a 503 with a fixed body, never exception text;
- the Jev token never appears in a response body (asserted on a canary key).

Runs inside the agent container.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

CANARY = "apikey_" + "c" * 36 + "_" + "d" * 64
JEV_ROW = {"id": "p-jev", "providerType": "jev", "apiKey": CANARY, "modelIdentifier": "jev-1.13.0"}

FFUF_BODY = {"url": "http://t/", "headers": {"Server": "nginx"}, "model": "ignored",
             "max_extensions": 6, "user_id": "u1", "project_id": "p1"}
NUCLEI_BODY = {"technologies": ["php"], "servers": ["nginx"], "current_tags": ["cve"],
               "candidates": ["cve", "php", "wordpress"], "model": "ignored", "max_tags": 15,
               "user_id": "u1", "project_id": "p1"}
WAF_BODY = {"url": "http://t/", "status_code": 403, "headers": {"cf-ray": "x"},
            "body_sample": "blocked", "response_time_ms": 100, "model": "ignored",
            "user_id": "u1", "project_id": "p1"}
TAKEOVER_BODY = {"hostname": "h.t", "expected_provider": "heroku", "status_code": 404,
                 "headers": {}, "response_sample": "nope", "model": "ignored",
                 "user_id": "u1", "project_id": "p1"}
BASE_PATHS_BODY = {"candidates": ["admin", "img", "api/v1"], "cap": 2,
                   "user_id": "u1", "project_id": "p1"}
PAGE_TYPE_BODY = {"pages": [{"url": "http://app.example.test/", "host": "app.example.test",
                             "status_code": 200, "title": "Welcome", "body": "hi"}],
                  "user_id": "u1", "project_id": "p1"}
TOOL_HEALTH_BODY = {"tool": "katana", "return_code": 0, "elapsed_s": 3.5, "seed_count": 4,
                    "stderr": "context deadline exceeded", "user_id": "u1", "project_id": "p1"}
CRAWL_SEED_BODY = {"hosts": [{"hostname": "a.example.test", "title": "x"},
                             {"hostname": "b.example.test"}],
                   "user_id": "u1", "project_id": "p1"}
SERIALIZED_BODY = {"blobs": [{"snippet": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
                              "transport": "cookie", "location": "session",
                              "encoding_layers": ["base64"]}],
                   "user_id": "u1", "project_id": "p1"}
ROUTE_PRIVACY_BODY = {"routes": [{"path": "/api/internal/users", "category": "api", "openapi_secured": True},
                                 {"path": "/about"}],
                      "user_id": "u1", "project_id": "p1"}
ROUTE_ASSESS_BODY = {"candidates": [{"path": "/internal/users/export", "anon_status": 200,
                                     "authed_status": 200, "content_class": "json",
                                     "size_bucket": "1-10k", "bodies_match": True,
                                     "key_paths": ["users[].email", "users[].role"], "max_array_len": 50,
                                     "det_signals": ["pii_others"], "auth_expected_by": ["path_word"],
                                     "generated_by": "found"}],
                     "user_id": "u1", "project_id": "p1"}


@pytest.fixture(scope="module")
def client():
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        import api
        from fastapi.testclient import TestClient
        yield TestClient(api.app), api


def _post(client, path, body):
    cl, _ = client
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        return cl.post(path, headers={"X-Internal-Key": "s3cret"}, json=body)


@pytest.fixture(autouse=True)
def _clear_owner_cache():
    import jev_client
    jev_client._owner_cache.clear()
    yield
    jev_client._owner_cache.clear()


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    """Every request here is user u1, and the per-user bucket holds 60: a file this
    size would otherwise start answering 429 halfway through, for reasons unrelated
    to the test that sees it."""
    import llm_guard
    llm_guard.reset_state()
    yield
    llm_guard.reset_state()


def _owner_ok():
    return patch("jev_client.selected_provider_id", AsyncMock(return_value="p-jev"))


def _providers(rows):
    # fetch_user_providers is sync, called via asyncio.to_thread.
    return patch("llm_builder.fetch_user_providers", return_value=rows)


PATHS = {
    "/jev/ffuf-extensions": FFUF_BODY,
    "/jev/nuclei-tags": NUCLEI_BODY,
    "/jev/waf-classify": WAF_BODY,
    "/jev/takeover-classify": TAKEOVER_BODY,
    "/jev/ffuf-base-paths": BASE_PATHS_BODY,
    "/jev/page-type": PAGE_TYPE_BODY,
    "/jev/tool-health": TOOL_HEALTH_BODY,
    "/jev/crawl-seed-order": CRAWL_SEED_BODY,
    "/jev/serialized-classify": SERIALIZED_BODY,
    "/jev/route-privacy-rank": ROUTE_PRIVACY_BODY,
    "/jev/route-exposure-assess": ROUTE_ASSESS_BODY,
}


# ---------------------------------------------------------------------------
# request validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_empty_user_or_project_is_422(client, path, body):
    for missing in ("user_id", "project_id"):
        resp = _post(client, path, {**body, missing: ""})
        assert resp.status_code == 422, resp.text
        assert resp.json()["error_type"] == "jev_bad_request"


# ---------------------------------------------------------------------------
# owner binding
# ---------------------------------------------------------------------------

def test_owner_mismatch_is_403_and_no_token_is_fetched(client):
    import jev_client
    with patch("jev_client.selected_provider_id", AsyncMock(side_effect=jev_client.JevError("jev_forbidden"))), \
            _providers([JEV_ROW]) as fetch:
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 403
    assert resp.json()["error_type"] == "jev_forbidden"
    fetch.assert_not_called()


def test_webapp_unreachable_in_owner_check_is_503(client):
    import jev_client
    with patch("jev_client.selected_provider_id", AsyncMock(side_effect=jev_client.JevError("jev_unavailable"))):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_unavailable"


# ---------------------------------------------------------------------------
# token resolution
# ---------------------------------------------------------------------------

def test_no_jev_row_is_503_not_configured(client):
    with _owner_ok(), _providers([{"providerType": "anthropic", "apiKey": "sk"}]):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_not_configured"


def test_null_selection_rejects_before_fetching_credentials_even_with_body_override(client):
    import jev_client
    with patch("jev_client._fetch_project", return_value={"userId": "u1", "jevProviderId": None}), \
            _providers([JEV_ROW]) as fetch, patch("jev_client.system_one", AsyncMock()) as inference:
        resp = _post(client, "/jev/nuclei-tags", {**NUCLEI_BODY, "jevProviderId": "p-jev"})
    assert resp.status_code == 503 and resp.json()["error_type"] == "jev_not_configured"
    fetch.assert_not_called()
    inference.assert_not_called()


def test_selection_is_loaded_from_persisted_project_not_request(client):
    selected = {**JEV_ROW, "id": "persisted", "providerType": "jev_openrouter"}
    with patch("jev_client._fetch_project", return_value={"userId": "u1", "jevProviderId": "persisted"}), \
            _providers([JEV_ROW, selected]), patch("jev_hooks.nuclei_tags", AsyncMock(return_value={"tags": ["cve"]})) as hook:
        resp = _post(client, "/jev/nuclei-tags", {**NUCLEI_BODY, "jevProviderId": "p-jev"})
    assert resp.status_code == 200
    assert hook.await_args.args[0].provider_id == "persisted"
    assert hook.await_args.args[0].provider_type == "jev_openrouter"


def test_providers_unreachable_is_503_unavailable(client):
    from llm_builder import ProvidersUnreachable
    with _owner_ok(), patch("llm_builder.fetch_user_providers", side_effect=ProvidersUnreachable("down")):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_unavailable"


# ---------------------------------------------------------------------------
# success + failure mapping, and the key never leaks
# ---------------------------------------------------------------------------

def test_nuclei_success_returns_tags_and_never_leaks_the_key(client):
    answers = {"tag_0": {"type": "noul", "noul": 0.9}, "tag_1": {"type": "noul", "noul": 0.9},
               "tag_2": {"type": "noul", "noul": 0.1}}
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})) as s1:
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 200
    assert "cve" in resp.json()["tags"]
    # The token is the one passed to the client, and never appears in the body.
    assert s1.await_args.args[0].api_key == CANARY
    assert s1.await_args.args[0].provider_id == "p-jev"
    assert CANARY not in resp.text


@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_a_jev_failure_is_503_with_a_fixed_body_no_key(client, path, body):
    import jev_client
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(side_effect=jev_client.JevError("jev_rate_limited", retry_after=5))):
        resp = _post(client, path, body)
    assert resp.status_code == 503
    data = resp.json()
    assert data["error_type"] == "jev_rate_limited"
    assert data["retry_after"] == 5
    assert data["error"] == jev_client.ERROR_MESSAGES["jev_rate_limited"]
    assert CANARY not in resp.text


def test_waf_success_shape(client):
    answers = {"edge": {"type": "noul", "noul": 0.9},
               "vendor": {"type": "choice", "choice": "cloudflare", "confidence": 0.9,
                          "probabilities": {"cloudflare": 1.0}}}
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})):
        resp = _post(client, "/jev/waf-classify", WAF_BODY)
    assert resp.status_code == 200
    assert resp.json() == {"waf_detected": True, "waf_type": "cloudflare", "confidence": 90,
                           "reasoning": "", "source": "jev_classifier"}


def test_serialized_success_shape(client):
    answers = {"format": {"type": "choice", "choice": "native_java", "confidence": 0.87},
               "exploitable": {"type": "noul", "noul": 0.62}}
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})):
        resp = _post(client, "/jev/serialized-classify", SERIALIZED_BODY)
    assert resp.status_code == 200
    assert resp.json() == {"labels": [{"format": "native_java", "format_confidence": 87,
                                       "exploitability": 62}],
                           "model": "jev-1.13.0"}
    assert CANARY not in resp.text


@pytest.mark.parametrize("blob", [
    {"snippet": "", "transport": "cookie"},
    # The old contract's marker label alone: it names the format, and is no evidence.
    {"magic": "AC ED 00 05 (Java stream)", "transport": "cookie"},
])
def test_serialized_blob_with_no_snippet_is_422_and_never_reaches_jev(client, blob):
    # Owner and token in place, so only the model's refusal keeps this from Jev.
    with _owner_ok(), _providers([JEV_ROW]), patch("jev_client.system_one", AsyncMock()) as jev:
        resp = _post(client, "/jev/serialized-classify", {**SERIALIZED_BODY, "blobs": [blob]})
    assert resp.status_code == 422
    jev.assert_not_called()


def test_a_lone_surrogate_in_a_refused_body_is_a_422_not_a_500(client):
    """FastAPI's default 422 echoes the refused input, and its UTF-8 render raised on
    a lone surrogate, so the 422 became a 500. Sent pre-encoded: json.dumps escapes
    the surrogate, the way recon's requests.post does."""
    cl, _ = client
    blob = {"snippet": "rO0AB", "location": "x-lone-\udc80"}
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        resp = cl.post("/jev/serialized-classify",
                       headers={"X-Internal-Key": "s3cret", "content-type": "application/json"},
                       content=_json.dumps({**SERIALIZED_BODY, "blobs": [blob]}))
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]                        # the same body FastAPI renders


@pytest.mark.parametrize("blob", [
    {"snippet": "rO0AB", "transport": "smtp"},             # transport outside the closed set
    {"snippet": "rO0AB", "encoding_layers": ["rot13"]},    # layer outside the closed set
    {"snippet": "x" * 201},                                # longer than recon ever sends
    {"snippet": "rO0AB", "encoding_layers": ["url"] * 9},  # more layers than the bound
])
def test_serialized_blob_outside_the_closed_sets_or_bounds_is_422(client, blob):
    resp = _post(client, "/jev/serialized-classify", {**SERIALIZED_BODY, "blobs": [blob]})
    assert resp.status_code == 422


def test_serialized_more_blobs_than_the_bound_is_422(client):
    blob = SERIALIZED_BODY["blobs"][0]
    resp = _post(client, "/jev/serialized-classify", {**SERIALIZED_BODY, "blobs": [blob] * 51})
    assert resp.status_code == 422


def test_owner_binding_runs_before_the_token_fetch(client):
    """selected_provider_id is awaited before any provider is read."""
    order = []
    import jev_client

    async def owner(*a, **k):
        order.append("owner")
        return "p-jev"

    def providers(*a, **k):
        order.append("providers")
        return [JEV_ROW]

    with patch("jev_client.selected_provider_id", owner), patch("llm_builder.fetch_user_providers", providers), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "x", "answers": {
                "tag_0": {"type": "noul", "noul": 0.1}, "tag_1": {"type": "noul", "noul": 0.1},
                "tag_2": {"type": "noul", "noul": 0.1}}})):
        _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert order == ["owner", "providers"]


# ---------------------------------------------------------------------------
# The token never reaches a log, on any path
# ---------------------------------------------------------------------------
#
# Driven through the REAL jev_client over a mock HTTP transport, not through a
# patched system_one: the realistic leak is TypeSafe or httpx echoing the
# Authorization header back in an error body or an exception message, and a
# logger that prints either.

import json as _json
import logging

import httpx

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _mock_typesafe(handler):
    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _REAL_ASYNC_CLIENT(*args, **kwargs)
    return patch("jev_client.httpx.AsyncClient", side_effect=factory)


def _valid_answers(req):
    body = _json.loads(req.content)
    answers = {}
    for name, q in body["questions"].items():
        if q["type"] == "choice":
            answers[name] = {"type": "choice", "choice": next(iter(q["criteria"])),
                             "confidence": 0.9, "probabilities": {}}
        else:
            answers[name] = {"type": "noul", "noul": 0.9}
    return httpx.Response(200, json={"model": "jev-1.13.0", "answers": answers, "usage": {}})


def _bare_key(req) -> str:
    """The key exactly as sent, without the "Bearer " scheme. The agent's log redaction filter
    also scrubs `Bearer <token>`, so echoing the scheme would let the filter, not the code, pass."""
    return req.headers["authorization"].split(" ", 1)[1]


def _echo_401(req):
    return httpx.Response(401, json={"detail": {"error_type": "authentication_error",
                                                 "message": f"rejected {_bare_key(req)}"}})


def _echo_500_html(req):
    return httpx.Response(500, text=f"<html>upstream error for {_bare_key(req)}</html>")


def _echo_exception(req):
    raise httpx.ConnectError(f"cannot reach host with {_bare_key(req)}")


#: Two keys. The first has the shape of a real TypeSafe key, so the agent's RedactingFilter would
#: scrub it from a log line: that is defence in depth, and it is not what this test is for. The
#: second has no shape any redaction pattern knows, so only the code's own discipline (never log
#: a body, a header or an exception message) can keep it out. A leak that the filter happens to
#: hide today would surface the day TypeSafe changes its key format.
RAW_KEY = "zzq-Plain_Looking_Key_0123456789"
LEAK_KEYS = [("known_shape", CANARY), ("shape_the_filter_cannot_know", RAW_KEY)]

LEAK_SCENARIOS = [
    ("success", _valid_answers, 200),
    ("typesafe_401_echoes_the_header", _echo_401, 503),
    ("typesafe_500_echoes_the_header", _echo_500_html, 503),
    ("connect_error_echoes_the_header", _echo_exception, 503),
]


@pytest.mark.parametrize("key_name,key", LEAK_KEYS, ids=[k[0] for k in LEAK_KEYS])
@pytest.mark.parametrize("name,handler,status", LEAK_SCENARIOS, ids=[s[0] for s in LEAK_SCENARIOS])
@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_the_token_is_never_logged_or_returned(client, caplog, path, body, name, handler, status, key_name, key):
    caplog.set_level(logging.DEBUG)
    with _owner_ok(), _providers([dict(JEV_ROW, apiKey=key)]), _mock_typesafe(handler):
        resp = _post(client, path, body)
    assert resp.status_code == status, resp.text
    assert key not in resp.text
    assert key not in caplog.text
    assert not any(key in r.getMessage() or key in str(r.args) or key in str(r.exc_info)
                   for r in caplog.records)
    # Not vacuous: the endpoint did log this call, so a leak here would have shown.
    assert any(r.getMessage().startswith("jev ") for r in caplog.records), caplog.text


@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_the_token_is_never_logged_on_the_owner_mismatch_path(client, caplog, path, body):
    import jev_client
    caplog.set_level(logging.DEBUG)
    with patch("jev_client.selected_provider_id", AsyncMock(side_effect=jev_client.JevError("jev_forbidden"))), \
            _providers([JEV_ROW]) as fetch:
        resp = _post(client, path, body)
    assert resp.status_code == 403
    assert CANARY not in resp.text and CANARY not in caplog.text
    fetch.assert_not_called()                      # the token was never even loaded
    assert any(r.getMessage().startswith("jev ") for r in caplog.records), caplog.text


def test_an_unexpected_error_inside_a_hook_is_a_fixed_503_logged_by_class_only(client, caplog):
    """REGRESSION (a non-JevError became a 500 with a traceback): only JevError was handled, so
    any other exception escaped as an unhandled 500 and skipped the per-call log line. Recon
    reads an error_type from a 503, so an unclassified 500 was also the one failure the Jev
    breaker could not name. The exception text is never returned or logged: it can carry
    state."""
    caplog.set_level(logging.DEBUG)
    boom = RuntimeError(f"unexpected {CANARY}")
    with _owner_ok(), _providers([JEV_ROW]), patch("jev_hooks.nuclei_tags", AsyncMock(side_effect=boom)):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_bad_response"
    assert CANARY not in resp.text and CANARY not in caplog.text
    assert any("RuntimeError" in r.getMessage() and r.getMessage().startswith("jev ") for r in caplog.records), caplog.text


# ---------------------------------------------------------------------------
# The per-item endpoints: bounded request models and response shapes
# ---------------------------------------------------------------------------

def _noul_answers_for(req):
    body = _json.loads(req.content)
    return httpx.Response(200, json={"model": "jev-1.13.0", "usage": {}, "answers": {
        name: {"type": "noul", "noul": 0.8} for name in body["questions"]}})


@pytest.mark.parametrize("path,patch_body", [
    ("/jev/ffuf-base-paths", {"candidates": ["a", "a"]}),                  # duplicates
    ("/jev/ffuf-base-paths", {"candidates": []}),
    ("/jev/ffuf-base-paths", {"candidates": [f"d{i}" for i in range(401)]}),
    ("/jev/ffuf-base-paths", {"candidates": ["x" * 201]}),
    ("/jev/ffuf-base-paths", {"candidates": [""]}),
    ("/jev/ffuf-base-paths", {"cap": 0}),
    ("/jev/ffuf-base-paths", {"cap": 51}),
    ("/jev/page-type", {"pages": []}),
    ("/jev/page-type", {"pages": [{"url": "u"}] * 51}),
    ("/jev/page-type", {"pages": [{"status_code": -1}]}),
    ("/jev/page-type", {"pages": [{"word_count": -5}]}),
    ("/jev/tool-health", {"tool": "nmap"}),                                # not a crawler we ask about
    ("/jev/tool-health", {"stderr": ""}),
    ("/jev/tool-health", {"elapsed_s": -1}),
    ("/jev/crawl-seed-order", {"hosts": []}),
    ("/jev/crawl-seed-order", {"hosts": [{"hostname": ""}]}),
    ("/jev/crawl-seed-order", {"hosts": [{"hostname": "h"}] * 401}),
    ("/jev/route-privacy-rank", {"routes": []}),
    ("/jev/route-privacy-rank", {"routes": [{"path": "/a"}] * 401}),
    ("/jev/route-privacy-rank", {"routes": [{"path": ""}]}),
    ("/jev/route-privacy-rank", {"routes": [{"path": "/" + "x" * 200}]}),
    ("/jev/route-privacy-rank", {"routes": [{"path": "/a", "method": "POST"}]}),   # recon never probes it
    ("/jev/route-privacy-rank", {"routes": [{"path": "/a", "category": "secret"}]}),
    ("/jev/route-exposure-assess", {"candidates": []}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a"}] * 51}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "content_class": "pdf"}]}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "det_signals": ["ssn"]}]}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "generated_by": "guess"}]}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "key_paths": ["k" * 81]}]}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "key_paths": ["k"] * 61}]}),
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "anon_status": 1000}]}),
    # The verdict is never an input: Jev's kind must stay a second opinion.
    ("/jev/route-exposure-assess", {"candidates": [{"path": "/a", "route_class": "internal_api"}]}),
])
def test_the_per_item_request_models_refuse_out_of_bounds_bodies(client, path, patch_body):
    s1 = AsyncMock()
    with _owner_ok(), _providers([JEV_ROW]), patch("jev_client.system_one", s1):
        resp = _post(client, path, {**PATHS[path], **patch_body})
    assert resp.status_code == 422, resp.text
    s1.assert_not_called()


def test_ffuf_base_paths_success_shape(client):
    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(_noul_answers_for):
        resp = _post(client, "/jev/ffuf-base-paths", BASE_PATHS_BODY)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ranked": ["admin", "api/v1"], "scores": [0.8, 0.8, 0.8],
                           "model": "jev-1.13.0"}


def test_page_type_success_shape(client):
    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(_noul_answers_for):
        resp = _post(client, "/jev/page-type", PAGE_TYPE_BODY)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"labels": [{"page_class": "login_only", "confidence": 80}],
                           "model": "jev-1.13.0"}


def test_tool_health_success_shape(client):
    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(_noul_answers_for):
        resp = _post(client, "/jev/tool-health", TOOL_HEALTH_BODY)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"transient": True, "confidence": 80, "model": "jev-1.13.0"}


def test_route_privacy_rank_success_shape(client):
    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(_noul_answers_for):
        resp = _post(client, "/jev/route-privacy-rank", ROUTE_PRIVACY_BODY)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"scores": [0.8, 0.8], "model": "jev-1.13.0"}


def test_route_exposure_assess_success_shape(client):
    answers = {"kind": {"type": "choice", "choice": "data_export", "confidence": 0.83},
               "sensitive": {"type": "noul", "noul": 0.91}}
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})):
        resp = _post(client, "/jev/route-exposure-assess", ROUTE_ASSESS_BODY)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"labels": [{"kind": "data_export", "kind_confidence": 83, "sensitivity": 91}],
                           "model": "jev-1.13.0"}
    assert CANARY not in resp.text


def test_crawl_seed_order_success_shape(client):
    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(_noul_answers_for):
        resp = _post(client, "/jev/crawl-seed-order", CRAWL_SEED_BODY)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"scores": [0.8, 0.8], "model": "jev-1.13.0"}


@pytest.mark.parametrize("path,questions", [
    ("/jev/ffuf-base-paths", 3), ("/jev/page-type", 5), ("/jev/tool-health", 1),
    ("/jev/crawl-seed-order", 2), ("/jev/serialized-classify", 2),
    ("/jev/route-privacy-rank", 2), ("/jev/route-exposure-assess", 2),
])
def test_the_per_item_log_line_counts_the_questions_asked(client, caplog, path, questions):
    caplog.set_level(logging.INFO)
    # These two ask a choice, which a noul-only answer would fail.
    answers = _valid_answers if path in ("/jev/serialized-classify", "/jev/route-exposure-assess") \
        else _noul_answers_for
    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(answers):
        _post(client, path, PATHS[path])
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("jev ")]
    assert any(f" questions={questions} model=jev-1.13.0 " in ln and ln.endswith(" ok") for ln in lines), lines


def test_a_jev_answer_out_of_range_fails_the_per_item_hook_closed(client):
    """A NaN or a value above 1 on any one item fails the whole call (503), so recon
    falls back instead of ranking on a forged score."""
    def nan_answers(req):
        body = _json.loads(req.content)
        names = list(body["questions"])
        answers = {n: {"type": "noul", "noul": 0.5} for n in names}
        answers[names[-1]] = {"type": "noul", "noul": 1.5}
        return httpx.Response(200, json={"model": "jev-1.13.0", "answers": answers})

    for path in ("/jev/ffuf-base-paths", "/jev/page-type", "/jev/crawl-seed-order", "/jev/tool-health"):
        with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(nan_answers):
            resp = _post(client, path, PATHS[path])
        assert resp.status_code == 503, (path, resp.text)
        assert resp.json()["error_type"] == "jev_bad_response"


def test_a_serialized_answer_out_of_range_fails_closed(client):
    """A valid format choice with an exploitability above 1 is a forged score:
    the whole call is a 503, never a label recon would record."""
    def over_one(req):
        resp = _valid_answers(req)
        body = _json.loads(resp.content)
        body["answers"]["exploitable"]["noul"] = 1.5
        return httpx.Response(200, json=body)

    with _owner_ok(), _providers([JEV_ROW]), _mock_typesafe(over_one):
        resp = _post(client, "/jev/serialized-classify", SERIALIZED_BODY)
    assert resp.status_code == 503, resp.text
    assert resp.json()["error_type"] == "jev_bad_response"

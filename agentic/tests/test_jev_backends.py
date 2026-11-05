"""Native Jev backend routing, ownership and free-vs-billed proof contracts."""
import asyncio
import json
import os
from dataclasses import FrozenInstanceError
from unittest.mock import AsyncMock, patch

import httpx
import pytest

import jev_client as jc
import jev_hooks

KEY = "synthetic-openrouter-key-12345678"
OR = jc.JevProvider("jev_openrouter", KEY, "selected")
Q = {"q": {"type": "noul", "instructions": "Is this synthetic?"}}
_REAL_CLIENT = httpx.AsyncClient


def run(coro):
    return asyncio.run(coro)


def transport(handler, seen):
    def factory(*args, **kwargs):
        assert kwargs["timeout"] == 5.0
        assert kwargs["follow_redirects"] is False
        def handle(req):
            seen.append(req)
            return handler(req)
        kwargs["transport"] = httpx.MockTransport(handle)
        return _REAL_CLIENT(*args, **kwargs)
    return patch.object(jc.httpx, "AsyncClient", side_effect=factory)


def answer(req, model="typesafe/jev-1.13-20260917"):
    questions = json.loads(req.content)["questions"]
    return httpx.Response(200, json={"model": model, "answers": {
        name: {"type": "noul", "noul": 0.8} for name in questions}})


@pytest.mark.parametrize("model", [jc.OPENROUTER_MODEL, "typesafe/jev-1.13-20260917"])
def test_openrouter_native_payload_and_model_identity(model):
    seen = []
    with transport(lambda req: answer(req, model), seen):
        out = run(jc.system_one(OR, jc.JEV_MODEL, {"synthetic": True}, Q))
    assert out["model"] == model
    assert out["answers"]["q"]["noul"] == 0.8
    req, = seen
    assert str(req.url) == "https://openrouter.ai/api/v1/systemone"
    assert req.headers["authorization"] == "Bearer " + KEY
    assert json.loads(req.content) == {"model": jc.OPENROUTER_MODEL,
                                      "state": {"synthetic": True}, "questions": Q}


@pytest.mark.parametrize("model", [None, "", "jev-1.13.0", "typesafe/jev-1.14",
                                   "typesafe/jev-1.13-free", "typesafe/jev-1.13-20260917\n"])
def test_openrouter_refuses_wrong_or_missing_returned_model(model):
    seen = []
    with transport(lambda req: answer(req, model), seen), pytest.raises(jc.JevError) as err:
        run(jc.system_one(OR, jc.JEV_MODEL, "synthetic", Q))
    assert err.value.error_type == "jev_bad_response"
    assert len(seen) == 1


@pytest.mark.parametrize("status,kind", [(401, "jev_auth"), (402, "jev_no_credit"),
    (429, "jev_rate_limited"), (503, "jev_overloaded"), (302, "jev_bad_response")])
def test_openrouter_no_retry_redirect_or_failover(status, kind):
    seen = []
    with transport(lambda req: httpx.Response(status, json={"error": KEY}, headers={
        "location": "https://example.test/", "retry-after": "3"}), seen):
        with pytest.raises(jc.JevError) as err:
            run(jc.system_one(OR, jc.JEV_MODEL, "synthetic", Q))
    assert err.value.error_type == kind
    assert KEY not in str(err.value)
    assert "TypeSafe" not in str(err.value)
    assert len(seen) == 1
    if status == 429:
        assert err.value.retry_after == 3


def test_openrouter_timeout_is_one_attempt_with_safe_error():
    seen = []
    def fail(req):
        raise httpx.ReadTimeout(KEY)
    with transport(fail, seen), pytest.raises(jc.JevError) as err:
        run(jc.system_one(OR, jc.JEV_MODEL, "synthetic", Q))
    assert err.value.error_type == "jev_timeout"
    assert len(seen) == 1 and KEY not in str(err.value)


@pytest.mark.parametrize("size,passes", [(31_999, True), (32_000, False), (32_001, False)])
def test_openrouter_serialized_byte_boundary(size, passes):
    payload = {"model": jc.OPENROUTER_MODEL, "state": "", "questions": Q}
    overhead = len(jc._body(OR, payload))
    state = "x" * (size - overhead)
    seen = []
    with transport(answer, seen):
        if passes:
            run(jc.system_one(OR, jc.JEV_MODEL, state, Q))
            assert len(seen[0].content) == size
        else:
            with pytest.raises(jc.JevError) as err:
                run(jc.system_one(OR, jc.JEV_MODEL, state, Q))
            assert err.value.error_type == "jev_bad_request"
            assert not seen


def test_utf8_bytes_not_characters_are_bounded_and_direct_is_unaffected():
    seen = []
    with transport(answer, seen), pytest.raises(jc.JevError):
        run(jc.system_one(OR, jc.JEV_MODEL, "\u00e9" * 16_000, Q))
    assert not seen
    direct = jc.JevProvider("jev", "synthetic-direct-key")
    with transport(lambda req: answer(req, jc.JEV_MODEL), seen):
        run(jc.system_one(direct, jc.JEV_MODEL, "x" * 40_000, Q))
    assert str(seen[0].url).startswith(jc.BASE_URL)


def test_preflight_all_batches_before_spending_and_no_partial_result(monkeypatch):
    monkeypatch.setattr(jev_hooks, "JEV_MAX_QUESTIONS_PER_CALL", 1)
    questions = {"first": Q["q"], "later": {"type": "noul", "instructions": "x" * 32_000}}
    with patch.object(jc, "system_one", AsyncMock()) as call, pytest.raises(jc.JevError):
        run(jev_hooks._ask(OR, "synthetic", questions))
    call.assert_not_called()


def test_item_batches_are_preflighted_before_any_call(monkeypatch):
    monkeypatch.setattr(jev_hooks, "JEV_MAX_QUESTIONS_PER_CALL", 1)
    items = {"first": "small", "later": "x" * 32_000}
    questions = {"first": {"first": Q["q"]}, "later": {"later": Q["q"]}}
    with patch.object(jc, "system_one", AsyncMock()) as call, pytest.raises(jc.JevError):
        run(jev_hooks._ask_items(OR, {}, items, questions))
    call.assert_not_called()


def test_failed_later_batch_never_returns_partial_answers(monkeypatch):
    monkeypatch.setattr(jev_hooks, "JEV_MAX_QUESTIONS_PER_CALL", 1)
    good = {"model": jc.OPENROUTER_MODEL, "answers": {"first": {"type": "noul", "noul": 1}}}
    with patch.object(jc, "system_one", AsyncMock(side_effect=[good, jc.JevError("jev_auth")])) as call:
        with pytest.raises(jc.JevError):
            run(jev_hooks._ask(OR, "synthetic", {"first": Q["q"], "later": Q["q"]}))
    assert call.await_count == 2
    assert all(c.args[0] is OR for c in call.await_args_list)


def test_provider_is_immutable_and_does_not_repr_credentials():
    with pytest.raises(FrozenInstanceError):
        OR.provider_type = "jev"
    assert KEY not in repr(OR)


def test_concurrent_projects_cannot_swap_backend_or_credentials():
    direct = jc.JevProvider("jev", "synthetic-direct-key")
    seen = []
    async def handler(req):
        await asyncio.sleep(0)
        model = json.loads(req.content)["model"]
        return answer(req, model)
    async def both():
        return await asyncio.gather(jc.system_one(direct, jc.JEV_MODEL, "direct", Q),
                                    jc.system_one(OR, jc.JEV_MODEL, "or", Q))
    with transport(handler, seen):
        outputs = run(both())
    assert {out["model"] for out in outputs} == {jc.JEV_MODEL, jc.OPENROUTER_MODEL}
    assert {(req.url.host, req.headers["authorization"]) for req in seen} == {
        ("api.typesafe.ai", "Bearer " + direct.api_key), ("openrouter.ai", "Bearer " + KEY)}


@pytest.mark.parametrize("answers", [
    {}, {"q": {"type": "noul", "noul": True}}, {"q": {"type": "noul", "noul": 1.1}},
    {"q": {"type": "noul", "noul": float("nan")}},
    {"q": {"type": "noul", "noul": 0.5, "confidence": float("inf")}},
])
def test_openrouter_typed_answers_are_all_or_nothing(answers):
    async def fake(*args):
        return {"model": jc.OPENROUTER_MODEL, "answers": answers}
    with patch.object(jc, "_request", fake), pytest.raises(jc.JevError) as err:
        run(jc.system_one(OR, jc.JEV_MODEL, "synthetic", Q))
    assert err.value.error_type == "jev_bad_response"


@pytest.mark.parametrize("provider_type", ["jev", "jev_openrouter"])
def test_choice_and_score_types_are_validated(provider_type):
    provider = jc.JevProvider(provider_type, KEY)
    questions = {"choice": {"type": "choice", "criteria": {"a": "A", "b": "B"}},
                 "score": {"type": "score", "criteria": ["Low", "High"]}}
    good = {"choice": {"type": "choice", "choice": "a", "confidence": 0.9,
                       "probabilities": {"a": 0.9, "b": 0.1}},
            "score": {"type": "score", "score": 0.4, "confidence": 0.8,
                      "probabilities": {"0": 0.6, "1": 0.4}}}
    with patch.object(jc, "_request", AsyncMock(return_value={"model": provider.wire_model, "answers": good})):
        assert run(jc.system_one(provider, jc.JEV_MODEL, "synthetic", questions))["answers"] == good
    for bad in ({"type": "score", "score": float("inf"), "confidence": 0.8},
                {"type": "score", "score": True, "confidence": 0.8},
                {"type": "score", "score": 1.1, "confidence": 0.8},
                {"type": "score", "score": 10 ** 1000, "confidence": 0.8},
                {"type": "score", "score": 0.5, "confidence": 0.8,
                 "probabilities": {"2": 1.0}}):
        with patch.object(jc, "_request", AsyncMock(return_value={"model": provider.wire_model,
             "answers": {**good, "score": bad}})), pytest.raises(jc.JevError):
            run(jc.system_one(provider, jc.JEV_MODEL, "synthetic", questions))


@pytest.mark.parametrize("project,kind", [(None, "jev_forbidden"),
    ({"userId": "other", "jevProviderId": "selected"}, "jev_forbidden"),
    ({"userId": "owner", "jevProviderId": None}, "jev_not_configured"),
    ({"userId": "owner"}, "jev_not_configured")])
def test_selection_is_owner_bound_and_explicit(project, kind):
    with patch.object(jc, "_fetch_project", return_value=project), pytest.raises(jc.JevError) as err:
        run(jc.selected_provider_id("project", "owner"))
    assert err.value.error_type == kind


def test_selection_fetch_failure_is_safe_and_does_not_resolve_credentials():
    with patch.object(jc, "_fetch_project", side_effect=RuntimeError(KEY)), pytest.raises(jc.JevError) as err:
        run(jc.selected_provider_id("project", "owner"))
    assert err.value.error_type == "jev_unavailable" and KEY not in str(err.value)


def test_selection_and_ownership_are_fresh_not_cached():
    with patch.object(jc, "_fetch_project", side_effect=[
        {"userId": "owner", "jevProviderId": "selected"},
        {"userId": "owner", "jevProviderId": None},
        {"userId": "other", "jevProviderId": "selected"}]) as fetch:
        assert run(jc.selected_provider_id("project", "owner")) == "selected"
        for kind in ("jev_not_configured", "jev_forbidden"):
            with pytest.raises(jc.JevError) as err:
                run(jc.selected_provider_id("project", "owner"))
            assert err.value.error_type == kind
    assert fetch.call_count == 3


def test_duplicate_selected_rows_are_refused_not_arbitrarily_chosen():
    row = {"id": "selected", "providerType": "jev", "apiKey": KEY}
    with pytest.raises(jc.JevError):
        jc.resolve_provider([row, row], "selected", "owner")


@pytest.mark.parametrize("row", [None, {"id": "selected", "providerType": "openrouter", "apiKey": KEY},
    {"id": "selected", "providerType": "jev", "userId": "other", "apiKey": KEY}])
def test_selected_missing_chat_or_foreign_row_never_falls_back(row):
    rows = [{"id": "first", "providerType": "jev", "apiKey": "synthetic-direct-key"}]
    if row:
        rows.append(row)
    with pytest.raises(jc.JevError):
        jc.resolve_provider(rows, "selected", "owner")


@pytest.fixture(scope="module")
def client():
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "synthetic-internal-key"}):
        import api
        from fastapi.testclient import TestClient
        yield TestClient(api.app)


def post_test(client, **fields):
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "synthetic-internal-key"}):
        return client.post("/llm-provider/test", headers={"X-Internal-Key": "synthetic-internal-key"},
            json={"providerType": "jev_openrouter", "apiKey": KEY, **fields})


def test_openrouter_test_default_is_free_key_and_specific_metadata_only(client):
    seen = []
    def free(req):
        if req.url.path.endswith("/key"):
            return httpx.Response(200, json={"data": {"label": "synthetic"}})
        return httpx.Response(200, json={"data": {"id": jc.OPENROUTER_MODEL, "endpoints": [{}]}})
    with transport(free, seen), patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        response = post_test(client, baseUrl="https://example.test/", modelIdentifier="typesafe/jev-1.14",
                             defaultHeaders={"Authorization": "wrong"})
    assert response.status_code == 200
    assert response.json()["proof"] == "key_and_model_metadata"
    assert response.json()["billed"] is False
    assert "inference access not tested" in response.json()["response_text"]
    assert [str(req.url) for req in seen] == ["https://openrouter.ai/api/v1/key",
        "https://openrouter.ai/api/v1/models/typesafe/jev-1.13/endpoints"]
    assert all(req.method == "GET" for req in seen)
    assert KEY not in response.text
    setup.assert_not_called()


def test_capability_requires_explicit_test_mode_and_uses_typed_native_call(client):
    result = {"model": "typesafe/jev-1.13-20260917", "answers": {}}
    with patch.object(jc, "system_one", AsyncMock(return_value=result)) as inference:
        response = post_test(client, testMode="capability")
    assert response.status_code == 200
    assert response.json()["proof"] == "typed_capability" and response.json()["billed"] is True
    context, model, state, questions = inference.await_args.args
    assert context.provider_type == "jev_openrouter" and context.api_key == KEY
    assert model == jc.JEV_MODEL
    assert {q["type"] for q in questions.values()} == {"noul", "choice", "score"}
    assert state == {"kind": "synthetic test"}


def test_invalid_test_mode_cannot_trigger_inference(client):
    with patch.object(jc, "system_one", AsyncMock()) as inference:
        assert post_test(client, testMode="yes").status_code == 422
    inference.assert_not_called()


def test_direct_free_proof_requires_the_pinned_model(client):
    with patch.object(jc, "list_models", AsyncMock(return_value=["jev-latest"])), \
         patch.object(jc, "system_one", AsyncMock()) as inference:
        response = post_test(client, providerType="jev")
    assert response.status_code == 400 and response.json()["success"] is False
    inference.assert_not_called()

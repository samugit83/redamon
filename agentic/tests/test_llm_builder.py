"""The shared "Models by feature" LLM builder (`agentic/llm_builder.py`).

Three guarantees, each the fix for a way one user's feature ran on the wrong
model or the wrong keys:

- a `custom/<id>` model resolves to THAT provider or fails; it never falls back
  to another custom provider (deleting a provider used to move the feature onto
  a different endpoint and key, silently);
- a provider list that cannot be fetched raises `ProvidersUnreachable` instead
  of building with no keys (which read as "your model is broken");
- the user id is URL-encoded into the fetch path.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm_builder  # noqa: E402

CUSTOM_A = {"id": "prov-a", "providerType": "openai_compatible",
            "baseUrl": "http://a.example.com/v1", "modelIdentifier": "m-a", "apiKey": "ka"}
CUSTOM_B = {"id": "prov-b", "providerType": "openai_compatible",
            "baseUrl": "http://b.example.com/v1", "modelIdentifier": "m-b", "apiKey": "kb"}


def test_exact_custom_match_returns_the_named_provider():
    assert llm_builder.exact_custom_provider([CUSTOM_A, CUSTOM_B], "custom/prov-b") is CUSTOM_B


def test_a_deleted_custom_provider_is_never_replaced_by_another():
    assert llm_builder.exact_custom_provider([CUSTOM_A], "custom/prov-gone") is None


def test_a_builtin_model_takes_no_custom_provider():
    assert llm_builder.exact_custom_provider([CUSTOM_A], "gpt-5") is None


def test_build_passes_the_exact_custom_config_and_the_keys():
    providers = [CUSTOM_A, {"providerType": "anthropic", "apiKey": "sk-ant"}]
    with patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        llm_builder.build_llm_from_providers("custom/prov-a", providers)
    assert setup.call_args.args[0] == "custom/prov-a"
    assert setup.call_args.kwargs["custom_llm_config"] is CUSTOM_A
    assert setup.call_args.kwargs["anthropic_api_key"] == "sk-ant"


def test_build_with_a_missing_custom_provider_passes_none_so_setup_refuses():
    with patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        llm_builder.build_llm_from_providers("custom/prov-gone", [CUSTOM_A])
    assert setup.call_args.kwargs["custom_llm_config"] is None


def test_the_real_setup_refuses_a_custom_model_without_its_provider():
    with pytest.raises(ValueError):
        llm_builder.build_llm_from_providers("custom/prov-gone", [CUSTOM_A])


def test_an_empty_model_is_refused_before_any_build():
    with patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        with pytest.raises(ValueError):
            llm_builder.build_llm_from_providers("", [CUSTOM_A])
    setup.assert_not_called()


def test_bedrock_credentials_are_forwarded():
    bedrock = {"providerType": "bedrock", "awsAccessKeyId": "AKIAEXAMPLE",
               "awsSecretKey": "secret", "awsRegion": "eu-west-1"}
    with patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        llm_builder.build_llm_from_providers("bedrock/some-model", [bedrock])
    kwargs = setup.call_args.kwargs
    assert kwargs["aws_access_key_id"] == "AKIAEXAMPLE"
    assert kwargs["aws_secret_access_key"] == "secret"
    assert kwargs["aws_region"] == "eu-west-1"


def test_a_fetch_failure_raises_providers_unreachable():
    with patch("requests.get", side_effect=OSError("webapp down")):
        with pytest.raises(llm_builder.ProvidersUnreachable):
            llm_builder.fetch_user_providers("user-1")


def test_an_http_error_raises_providers_unreachable():
    resp = MagicMock()
    resp.raise_for_status.side_effect = RuntimeError("500")
    with patch("requests.get", return_value=resp):
        with pytest.raises(llm_builder.ProvidersUnreachable):
            llm_builder.fetch_user_providers("user-1")


def test_a_non_list_body_raises_providers_unreachable():
    resp = MagicMock()
    resp.json.return_value = {"error": "nope"}
    with patch("requests.get", return_value=resp):
        with pytest.raises(llm_builder.ProvidersUnreachable):
            llm_builder.fetch_user_providers("user-1")


def test_the_user_id_is_url_encoded(monkeypatch):
    monkeypatch.setenv("WEBAPP_API_URL", "http://webapp:3000")
    monkeypatch.setenv("INTERNAL_API_KEY", "k" * 32)
    resp = MagicMock()
    resp.json.return_value = []
    with patch("requests.get", return_value=resp) as get:
        assert llm_builder.fetch_user_providers("a/../b?x=1") == []
    url = get.call_args.args[0]
    assert url == "http://webapp:3000/api/users/a%2F..%2Fb%3Fx%3D1/llm-providers?internal=true"
    assert get.call_args.kwargs["headers"] == {"X-Internal-Key": "k" * 32}


def test_no_user_id_is_refused():
    with pytest.raises(ValueError):
        llm_builder.fetch_user_providers("")


class _Status(Exception):
    def __init__(self, status):
        super().__init__(f"status {status}")
        self.status_code = status


class AuthenticationError(Exception):
    pass


def test_unavailable_errors_are_recognised():
    assert llm_builder.is_model_unavailable_error(_Status(401))
    assert llm_builder.is_model_unavailable_error(_Status(404))
    assert llm_builder.is_model_unavailable_error(AuthenticationError("bad key"))
    wrapped = RuntimeError("langchain wrapper")
    wrapped.__cause__ = _Status(403)
    assert llm_builder.is_model_unavailable_error(wrapped)


def test_transient_errors_are_not_unavailable():
    assert not llm_builder.is_model_unavailable_error(_Status(429))
    assert not llm_builder.is_model_unavailable_error(_Status(500))
    assert not llm_builder.is_model_unavailable_error(TimeoutError())


def test_an_aws_access_denied_is_unavailable():
    err = Exception("denied")
    err.response = {"Error": {"Code": "AccessDeniedException"}}
    assert llm_builder.is_model_unavailable_error(err)


class TestTheClassifierMissedCommonBadKeyAndModelShapes:
    """Review finding: these users got "try again" forever and never the gate."""

    def test_langchain_cores_model_error_family(self):
        from langchain_core import exceptions as lc
        for cls in (lc.ModelAuthenticationError, lc.ModelPermissionDeniedError,
                    lc.ModelNotFoundError):
            assert llm_builder.is_model_unavailable_error(cls("refused")), cls.__name__
        for cls in (lc.ModelRateLimitError, lc.ModelAPIError, lc.ModelTimeoutError,
                    lc.ModelInvalidRequestError):
            assert not llm_builder.is_model_unavailable_error(cls("transient")), cls.__name__

    def test_a_gemini_401_wrapped_with_no_response(self):
        errors = pytest.importorskip("google.genai.errors")
        wrapper = RuntimeError("ChatGoogleGenerativeAIError: Error calling model")
        wrapper.__cause__ = errors.ClientError(401, {"error": {"message": "unauthenticated"}})
        assert llm_builder.is_model_unavailable_error(wrapper)

    def test_a_bad_gemini_key_is_a_400_told_apart_by_its_reason(self):
        errors = pytest.importorskip("google.genai.errors")
        bad_key = errors.ClientError(400, {"error": {
            "code": 400, "status": "INVALID_ARGUMENT", "message": "API key not valid. Please pass a valid API key.",
            "details": [{"reason": "API_KEY_INVALID"}]}})
        assert llm_builder.is_model_unavailable_error(bad_key)
        too_long = errors.ClientError(400, {"error": {
            "code": 400, "status": "INVALID_ARGUMENT", "message": "The input token count exceeds the maximum"}})
        assert not llm_builder.is_model_unavailable_error(too_long)

    def test_a_bedrock_unknown_model_id(self):
        bad_model = Exception("validation")
        bad_model.response = {"Error": {"Code": "ValidationException",
                                        "Message": "The provided model identifier is invalid."}}
        assert llm_builder.is_model_unavailable_error(bad_model)
        too_long = Exception("validation")
        too_long.response = {"Error": {"Code": "ValidationException",
                                       "Message": "Input is too long for requested model."}}
        assert not llm_builder.is_model_unavailable_error(too_long)

    def test_a_close_code_is_not_a_status(self):
        closed = Exception("socket closed")
        closed.code = 1011
        assert not llm_builder.is_model_unavailable_error(closed)


class RateLimitError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.status_code = 429


class TestProviderErrorDetails:
    """What a person may see of a provider failure: class and status, never the text."""

    def test_the_status_and_its_class_are_read_through_a_wrapper(self):
        wrapper = RuntimeError("langchain wrapper")
        wrapper.__cause__ = RateLimitError("sk-live-123 is over quota")
        assert llm_builder.provider_error_details(wrapper) == {
            "error_class": "RateLimitError", "provider_status": 429,
            "provider_error_kind": "rate_limited"}

    def test_the_message_never_appears(self):
        details = llm_builder.provider_error_details(RateLimitError("key sk-live-123"))
        assert "sk-live-123" not in repr(details)

    def test_a_response_status_and_a_google_code(self):
        err = Exception("bad")
        err.response = MagicMock(status_code=401)
        assert llm_builder.provider_error_details(err)["provider_status"] == 401
        google = Exception("quota")
        google.code = 429
        assert llm_builder.provider_error_details(google)["provider_status"] == 429

    def test_a_bedrock_client_error_reports_its_http_status(self):
        err = Exception("throttled")
        err.response = {"Error": {"Code": "ThrottlingException"},
                        "ResponseMetadata": {"HTTPStatusCode": 429}}
        assert llm_builder.provider_error_details(err)["provider_status"] == 429

    def test_no_status_keeps_only_the_class(self):
        assert llm_builder.provider_error_details(TimeoutError()) == {"error_class": "TimeoutError"}

    def test_a_close_code_or_a_bool_is_not_a_status(self):
        closed = Exception("socket closed")
        closed.code = 1011
        assert "provider_status" not in llm_builder.provider_error_details(closed)
        flag = Exception("x")
        flag.status_code = True
        assert "provider_status" not in llm_builder.provider_error_details(flag)

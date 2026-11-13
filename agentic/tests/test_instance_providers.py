"""Instance LLM providers in the agent (step 6.11, GV-15, OQ-42).

An administrator's provider reaches the agent only as a marked row of the
project owner's provider list (`GET /api/users/{owner}/llm-providers?internal=true`,
master key only), and only while it is assigned to a permission set the owner
holds. A model `instance/<providerId>/<model>` is built from exactly that row:

- the prefix routes to the instance provider, with the row's own key only;
- an `instance/` id the list does not hold (switch off, deleted, not entitled)
  is refused with `instance_provider_unavailable`, never sent to OpenAI with the
  owner's key (an unknown prefix used to fall through to OpenAI);
- an instance row never serves anything else: not a bare model id, not a
  `custom/<id>`, not the "first custom provider" fallback;
- the `loop/` refusal stays on every session-less builder, and an instance
  provider never serves a loop id either.

Runs inside the agent container (`./agentic/run_tests.sh tests/test_instance_providers.py`).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm_builder  # noqa: E402
from llm_builder import InstanceProviderUnavailable  # noqa: E402

INSTANCE_KEY = "sk-INSTANCE-CANARY-only-for-instance-ids"
OWNER_KEY = "sk-OWNER-own-openai-key"

INST_OPENAI = {"id": "inst-1", "providerType": "instance", "instanceProviderType": "openai",
               "name": "Shared OpenAI", "apiKey": INSTANCE_KEY, "userId": "owner-1"}
INST_ANTHROPIC = {"id": "inst-2", "providerType": "instance", "instanceProviderType": "anthropic",
                  "name": "Shared Claude", "apiKey": "sk-ant-instance", "userId": "owner-1"}
INST_COMPAT = {"id": "inst-3", "providerType": "instance", "instanceProviderType": "openai_compatible",
               "name": "Shared vLLM", "apiKey": "k-compat", "baseUrl": "http://llm.example.com/v1",
               "modelIdentifier": "qwen-72b", "userId": "owner-1"}
INST_BEDROCK = {"id": "inst-4", "providerType": "instance", "instanceProviderType": "bedrock",
                "name": "Shared Bedrock", "awsAccessKeyId": "AKIAEXAMPLE", "awsSecretKey": "aws-secret",
                "awsBearerToken": "", "awsRegion": "eu-west-1", "userId": "owner-1"}
OWN_OPENAI = {"id": "own-1", "providerType": "openai", "apiKey": OWNER_KEY, "userId": "owner-1"}
OWN_CUSTOM = {"id": "own-2", "providerType": "openai_compatible", "apiKey": "k-own",
              "baseUrl": "http://own.example.com/v1", "modelIdentifier": "m-own", "userId": "owner-1"}


# ---------------------------------------------------------------------------
# prefix routes to the instance provider
# ---------------------------------------------------------------------------

def test_the_prefix_is_routed():
    from orchestrator_helpers.llm_setup import parse_model_provider
    assert parse_model_provider("instance/inst-1/gpt-5") == ("instance", "inst-1/gpt-5")
    # existing prefixes are untouched
    assert parse_model_provider("custom/own-2") == ("custom", "own-2")
    assert parse_model_provider("gpt-5") == ("openai", "gpt-5")


def test_prefix_routes_to_the_instance_provider_with_its_own_key():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        llm_setup.setup_llm("instance/inst-1/gpt-4o", openai_api_key=OWNER_KEY,
                            custom_llm_config=INST_OPENAI)
    kwargs = chat_openai.call_args.kwargs
    assert kwargs["model"] == "gpt-4o"
    assert kwargs["api_key"] == INSTANCE_KEY
    assert "base_url" not in kwargs


def test_an_anthropic_instance_provider_builds_claude_with_its_key():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatAnthropic") as chat_anthropic, \
            patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        llm_setup.setup_llm("instance/inst-2/claude-opus-4-6", custom_llm_config=INST_ANTHROPIC)
    chat_openai.assert_not_called()
    assert chat_anthropic.call_args.kwargs["api_key"] == "sk-ant-instance"
    assert chat_anthropic.call_args.kwargs["model"] == "claude-opus-4-6"


def test_an_openai_compatible_instance_provider_uses_its_endpoint():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        llm_setup.setup_llm("instance/inst-3/custom/inst-3", custom_llm_config=INST_COMPAT)
    kwargs = chat_openai.call_args.kwargs
    assert kwargs["base_url"] == "http://llm.example.com/v1"
    assert kwargs["api_key"] == "k-compat"
    assert kwargs["model"] == "qwen-72b"


def test_bedrock_instance_credentials_are_the_rows():
    native, kwargs = llm_builder.instance_build_args("instance/inst-4/bedrock/anthropic.claude-x", INST_BEDROCK)
    assert native == "bedrock/anthropic.claude-x"
    assert kwargs == {"aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "aws-secret",
                      "aws_bearer_token": None, "aws_region": "eu-west-1"}


def test_the_build_args_carry_only_the_rows_key():
    native, kwargs = llm_builder.instance_build_args("instance/inst-1/gpt-5", INST_OPENAI)
    assert (native, kwargs) == ("gpt-5", {"openai_api_key": INSTANCE_KEY})
    native, kwargs = llm_builder.instance_build_args("instance/inst-3/custom/inst-3", INST_COMPAT)
    assert native == "custom/inst-3"
    assert kwargs["custom_llm_config"]["providerType"] == "openai_compatible"
    assert "instanceProviderType" not in kwargs["custom_llm_config"]


# ---------------------------------------------------------------------------
# an unresolvable instance/ id is refused, never sent to OpenAI
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("config", [
    None,                                  # the owner's list holds no such row
    OWN_CUSTOM,                            # what the old "first custom provider" fallback gave
    OWN_OPENAI,
    dict(INST_OPENAI, id="inst-other"),    # another instance provider
    dict(INST_OPENAI, providerType="openai"),  # an own row that happens to carry the id
])
def test_an_unresolvable_instance_id_is_refused_never_sent_to_openai(config):
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai, \
            patch.object(llm_setup, "ChatAnthropic") as chat_anthropic:
        with pytest.raises(InstanceProviderUnavailable) as err:
            llm_setup.setup_llm("instance/inst-1/gpt-5", openai_api_key=OWNER_KEY,
                                custom_llm_config=config)
    chat_openai.assert_not_called()
    chat_anthropic.assert_not_called()
    assert err.value.code == "instance_provider_unavailable"
    assert OWNER_KEY not in str(err.value) and INSTANCE_KEY not in str(err.value)


@pytest.mark.parametrize("model, row", [
    ("instance/inst-2/gpt-5", INST_ANTHROPIC),            # an Anthropic key for an OpenAI model
    ("instance/inst-1/claude-opus-4-6", INST_OPENAI),     # and the other way round
    ("instance/inst-1/openrouter/x", INST_OPENAI),
    ("instance/inst-3/custom/own-2", INST_COMPAT),        # an endpoint serves only its own id
    ("instance/inst-3/qwen-72b", INST_COMPAT),
    ("instance/inst-1/instance/inst-1/gpt-5", INST_OPENAI),  # nested
    ("instance/inst-1/", INST_OPENAI),
    ("instance//gpt-5", INST_OPENAI),
    ("instance/inst-1", INST_OPENAI),
    ("instance/inst-1/gpt-5", dict(INST_OPENAI, instanceProviderType="jev")),
    ("instance/inst-1/gpt-5", dict(INST_OPENAI, instanceProviderType="jev_openrouter")),
    ("instance/inst-1/gpt-5", dict(INST_OPENAI, instanceProviderType="unknown")),
    ("instance/inst-1/gpt-5", dict(INST_OPENAI, instanceProviderType=None)),
])
def test_an_instance_provider_serves_only_the_models_of_its_kind(model, row):
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai, \
            patch.object(llm_setup, "ChatAnthropic") as chat_anthropic:
        with pytest.raises(InstanceProviderUnavailable):
            llm_setup.setup_llm(model, openai_api_key=OWNER_KEY, anthropic_api_key="sk-ant-own",
                                custom_llm_config=row)
    chat_openai.assert_not_called()
    chat_anthropic.assert_not_called()


def test_the_refusal_has_its_code_and_is_never_retried_as_transient():
    from orchestrator_helpers.llm_setup import llm_setup_failure
    exc = InstanceProviderUnavailable()
    assert llm_setup_failure("instance/inst-1/gpt-5", exc) == {
        "code": "instance_provider_unavailable", "model": "instance/inst-1/gpt-5"}
    text = str(exc).lower()
    for phrase in ("timeout", "connection", " is required for model ", "503", "502"):
        assert phrase not in text


# ---------------------------------------------------------------------------
# exact resolution, and an instance row never serves anything else
# ---------------------------------------------------------------------------

def test_exact_instance_provider_is_exact():
    rows = [OWN_OPENAI, INST_OPENAI, INST_ANTHROPIC]
    assert llm_builder.exact_instance_provider(rows, "instance/inst-2/claude-x") is INST_ANTHROPIC
    assert llm_builder.exact_instance_provider(rows, "instance/inst-gone/gpt-5") is None
    assert llm_builder.exact_instance_provider(rows, "instance/own-1/gpt-5") is None
    assert llm_builder.exact_instance_provider(rows, "gpt-5") is None
    assert llm_builder.exact_instance_provider(None, "instance/inst-1/gpt-5") is None


def test_an_instance_model_never_falls_back_to_a_custom_provider():
    assert llm_builder.custom_provider_or_fallback([OWN_CUSTOM], "instance/inst-gone/gpt-5") is None
    assert llm_builder.custom_provider_or_fallback([OWN_CUSTOM, INST_OPENAI],
                                                   "instance/inst-1/gpt-5") is INST_OPENAI


def test_an_instance_row_is_never_a_custom_provider_or_its_fallback():
    assert llm_builder.exact_custom_provider([INST_COMPAT], "custom/inst-3") is None
    assert llm_builder.custom_provider_or_fallback([INST_COMPAT], "custom/gone") is None
    assert llm_builder.custom_provider_or_fallback([INST_COMPAT, OWN_CUSTOM], "custom/gone") is OWN_CUSTOM


def test_an_instance_key_never_serves_a_bare_model_id():
    from orchestrator_helpers import llm_setup
    assert llm_setup._resolve_provider_key([INST_OPENAI], "openai") is None
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        with pytest.raises(ValueError):
            llm_builder.build_llm_from_providers("gpt-5", [INST_OPENAI])
    chat_openai.assert_not_called()


def test_the_feature_builder_takes_the_instance_key_not_the_owners():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        llm_builder.build_llm_from_providers("instance/inst-1/gpt-5", [OWN_OPENAI, INST_OPENAI])
    assert chat_openai.call_args.kwargs["api_key"] == INSTANCE_KEY


def test_the_feature_builder_refuses_an_instance_id_it_cannot_resolve():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        with pytest.raises(InstanceProviderUnavailable):
            llm_builder.build_llm_from_providers("instance/inst-1/gpt-5", [OWN_OPENAI])
    chat_openai.assert_not_called()


# ---------------------------------------------------------------------------
# loop prefix still refused on the new path
# ---------------------------------------------------------------------------

def test_loop_prefix_still_refused_on_the_new_path():
    from agent_in_the_loop.errors import LoopModelNotSupportedHere
    with pytest.raises(LoopModelNotSupportedHere):
        llm_builder.build_llm_from_providers("loop/mcp", [INST_OPENAI])
    with pytest.raises(InstanceProviderUnavailable):
        llm_builder.build_llm_from_providers("instance/inst-1/loop/mcp", [INST_OPENAI])


def test_an_instance_provider_never_builds_a_loop_model():
    from orchestrator_helpers import llm_setup
    with patch("agent_in_the_loop.model.LoopChatModel") as loop_model:
        with pytest.raises(InstanceProviderUnavailable):
            llm_setup.setup_llm("instance/inst-1/loop/mcp", custom_llm_config=INST_OPENAI)
    loop_model.assert_not_called()


# ---------------------------------------------------------------------------
# the agent session (project_settings) and the CypherFix loaders
# ---------------------------------------------------------------------------

def _fake_webapp(providers, model):
    def get(url, *args, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "/llm-providers" in url:
            resp.json.return_value = providers
        elif "/api/projects/" in url:
            resp.json.return_value = {"userId": "owner-1", "agentOpenaiModel": model}
        elif "/tradecraft-resources" in url:
            resp.json.return_value = []
        else:
            resp.json.return_value = {}
        return resp
    return get


def test_session_resolves_the_owners_instance_row_exactly():
    import project_settings as ps
    with patch("requests.get", side_effect=_fake_webapp([OWN_CUSTOM, INST_OPENAI], "instance/inst-1/gpt-5")):
        settings = ps.fetch_agent_settings("p1", "http://webapp")
    assert settings["CUSTOM_LLM_CONFIG"] is INST_OPENAI or settings["CUSTOM_LLM_CONFIG"] == INST_OPENAI
    assert settings["OPENAI_MODEL"] == "instance/inst-1/gpt-5"


def test_switch_off_a_project_on_an_instance_model_fails_closed():
    """Switch off (or not entitled), the webapp sends no instance row: no config,
    no fallback, the model id is kept, and the run gets no client."""
    import project_settings as ps
    from orchestrator_helpers import llm_setup
    with patch("requests.get", side_effect=_fake_webapp([OWN_OPENAI, OWN_CUSTOM], "instance/inst-1/gpt-5")):
        settings = ps.fetch_agent_settings("p1", "http://webapp")
    assert settings["CUSTOM_LLM_CONFIG"] is None
    assert settings["OPENAI_MODEL"] == "instance/inst-1/gpt-5"

    orchestrator = MagicMock(spec=[])
    with patch.object(llm_setup, "load_project_settings", return_value=settings), \
            patch.object(llm_setup, "ChatOpenAI") as chat_openai, \
            patch.object(llm_setup, "set_llm_context"):
        llm_setup.apply_project_settings(orchestrator, "p1")
    chat_openai.assert_not_called()
    assert orchestrator.llm is None
    assert orchestrator.llm_setup_failure == {"code": "instance_provider_unavailable",
                                              "model": "instance/inst-1/gpt-5"}


def test_a_session_on_an_instance_model_builds_from_the_instance_row():
    from orchestrator_helpers import llm_setup
    settings = {"OPENAI_MODEL": "instance/inst-1/gpt-5", "USER_LLM_PROVIDERS": [OWN_OPENAI, INST_OPENAI],
                "CUSTOM_LLM_CONFIG": INST_OPENAI}
    orchestrator = MagicMock(spec=[])
    with patch.object(llm_setup, "load_project_settings", return_value=settings), \
            patch.object(llm_setup, "ChatOpenAI") as chat_openai, \
            patch.object(llm_setup, "set_llm_context"):
        llm_setup.apply_project_settings(orchestrator, "p1")
    assert chat_openai.call_args.kwargs["api_key"] == INSTANCE_KEY
    assert orchestrator.llm_setup_failure is None


def _cypherfix_client(providers, feature_models):
    class _Resp:
        def __init__(self, body):
            self._body = body
            self.status_code = 200

        def json(self):
            return self._body

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **_kwargs):
            if url.endswith("/llm-providers"):
                return _Resp(providers)
            if url.endswith("/settings"):
                return _Resp({"featureModels": feature_models})
            return _Resp({"userId": "owner-1"})

    return _Client


@pytest.mark.parametrize("module_name, feature", [
    ("cypherfix_triage.project_settings", "triage"),
    ("cypherfix_codefix.project_settings", "codefix"),
])
def test_cypherfix_loaders_resolve_instance_rows_exactly(module_name, feature):
    import importlib
    module = importlib.import_module(module_name)

    def load(model):
        client = _cypherfix_client([OWN_CUSTOM, INST_OPENAI], {feature: model})
        with patch.object(module.httpx, "AsyncClient", client):
            return asyncio.run(module.load_cypherfix_settings("p1"))

    assert load("instance/inst-1/gpt-5")["custom_llm_config"] == INST_OPENAI
    assert "custom_llm_config" not in load("instance/inst-gone/gpt-5")
    assert "custom_llm_config" not in load("custom/inst-1")
    assert load("custom/own-2")["custom_llm_config"] == OWN_CUSTOM


# ---------------------------------------------------------------------------
# api.py paths (read only here): recon planners behind /llm/* and text-to-cypher
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api_module():
    import api
    return api


def _providers_response(rows):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = rows
    return resp


def test_scan_container_path_resolves_the_instance_row_on_the_agent_side(api_module):
    """A scan container calls /llm/* with its job credential and names only a
    model; the agent fetches the owner's list with the master key and builds
    from the instance row. The key never travels toward the container."""
    from orchestrator_helpers import llm_setup
    with patch("requests.get", return_value=_providers_response([OWN_CUSTOM, INST_OPENAI])) as get, \
            patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        api_module._build_llm_with_model_for_user("instance/inst-1/gpt-5", "owner-1")
    assert "/api/users/owner-1/llm-providers?internal=true" in get.call_args.args[0]
    assert chat_openai.call_args.kwargs["api_key"] == INSTANCE_KEY


def test_scan_container_path_refuses_an_instance_id_the_owner_lost(api_module):
    from orchestrator_helpers import llm_setup
    with patch("requests.get", return_value=_providers_response([OWN_OPENAI, OWN_CUSTOM])), \
            patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        with pytest.raises(InstanceProviderUnavailable):
            api_module._build_llm_with_model_for_user("instance/inst-1/gpt-5", "owner-1")
    chat_openai.assert_not_called()


def _cypher_manager(api_module, model, rows):
    """text-to-cypher's (and /graph/nl-query's) builder with the project on `model` and the
    owner's provider list `rows`: (the manager or the _CypherSetupError, ChatOpenAI mock)."""
    import project_settings as ps
    from orchestrator_helpers import llm_setup
    with patch.object(ps, "fetch_agent_settings", return_value={"OPENAI_MODEL": model}), \
            patch("requests.get", return_value=_providers_response(rows)) as get, \
            patch.object(llm_setup, "ChatOpenAI") as chat_openai, \
            patch("langchain_community.graphs.Neo4jGraph", MagicMock()):
        try:
            result = asyncio.run(api_module._build_cypher_manager("owner-1", "p1"))
        except api_module._CypherSetupError as e:
            result = e
    assert "/api/users/owner-1/llm-providers?internal=true" in get.call_args.args[0]
    return result, chat_openai


def test_text_to_cypher_builds_an_instance_model_from_its_row(api_module):
    """The project's `instance/` model is built from exactly the owner's marked row,
    with that row's key, never the owner's own."""
    result, chat_openai = _cypher_manager(api_module, "instance/inst-1/gpt-5",
                                          [OWN_OPENAI, OWN_CUSTOM, INST_OPENAI])
    assert not isinstance(result, api_module._CypherSetupError), getattr(result, "message", "")
    kwargs = chat_openai.call_args.kwargs
    assert kwargs["model"] == "gpt-5"
    assert kwargs["api_key"] == INSTANCE_KEY
    assert "base_url" not in kwargs


def test_text_to_cypher_builds_an_openai_compatible_instance_model(api_module):
    result, chat_openai = _cypher_manager(api_module, "instance/inst-3/custom/inst-3",
                                          [OWN_CUSTOM, INST_COMPAT])
    assert not isinstance(result, api_module._CypherSetupError), getattr(result, "message", "")
    assert chat_openai.call_args.kwargs["api_key"] == "k-compat"
    assert chat_openai.call_args.kwargs["base_url"] == "http://llm.example.com/v1"


@pytest.mark.parametrize("model,rows", [
    ("instance/inst-1/gpt-5", [OWN_OPENAI]),                      # never the owner's own key
    ("instance/inst-1/gpt-5", [OWN_OPENAI, OWN_CUSTOM]),          # never the first custom provider
    ("instance/inst-1/gpt-5", [OWN_OPENAI, dict(INST_OPENAI, id="inst-9")]),  # never another instance row
    ("instance/inst-1/gpt-5", []),
    ("instance/inst-1/claude-opus-4-6", [OWN_OPENAI, INST_OPENAI]),  # a model of another kind
])
def test_text_to_cypher_refuses_an_instance_model_the_owner_lacks(api_module, model, rows):
    """An `instance/` id the owner's list cannot serve fails closed (400) with its code,
    and no client is built on any key."""
    result, chat_openai = _cypher_manager(api_module, model, rows)
    assert isinstance(result, api_module._CypherSetupError)
    assert result.status == 400
    assert result.fields.get("code") == "instance_provider_unavailable"
    chat_openai.assert_not_called()
    assert INSTANCE_KEY not in result.message and OWNER_KEY not in result.message


def test_text_to_cypher_custom_models_resolve_as_before(api_module):
    result, chat_openai = _cypher_manager(api_module, "custom/own-2", [OWN_OPENAI, OWN_CUSTOM, INST_OPENAI])
    assert not isinstance(result, api_module._CypherSetupError), getattr(result, "message", "")
    assert chat_openai.call_args.kwargs["api_key"] == "k-own"

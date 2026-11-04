"""A TypeSafe Jev token row must never be used as a chat LLM.

A Jev row is a `user_llm_providers` row with `providerType = "jev"`. Every path
that builds a chat model from "a provider row" used to accept any type, and
`setup_llm`'s custom branch builds `ChatOpenAI(api_key=<row key>)` with no base
URL for an unknown type, so the Jev token would be sent to api.openai.com. The
two `providers[0]` fallbacks for a stale `custom/<id>` (the agent session and
text-to-cypher) were the reachable ones.

Runs inside the agent container.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm_builder  # noqa: E402

JEV_KEY = "ts-JEV-CANARY-must-never-reach-a-chat-client"
JEV = {"id": "prov-jev", "providerType": "jev", "name": "TypeSafe AI (Jev)",
       "apiKey": JEV_KEY, "modelIdentifier": "jev-1.13.0", "baseUrl": ""}
ANTHROPIC = {"id": "prov-anth", "providerType": "anthropic", "apiKey": "sk-ant"}
CUSTOM = {"id": "prov-custom", "providerType": "openai_compatible", "apiKey": "kc",
          "baseUrl": "http://llm.example.com/v1", "modelIdentifier": "m-c"}


@pytest.mark.parametrize("provider_type", ["jev", "jev_openrouter"])
def test_chat_providers_drops_the_jev_row(provider_type):
    row = dict(JEV, providerType=provider_type)
    assert llm_builder.chat_providers([row, ANTHROPIC, CUSTOM]) == [ANTHROPIC, CUSTOM]
    assert llm_builder.exact_custom_provider([row], "custom/prov-jev") is None
    assert llm_builder.custom_provider_or_fallback([row], "custom/prov-gone") is None


def test_chat_providers_tolerates_none_and_junk():
    assert llm_builder.chat_providers(None) == []
    assert llm_builder.chat_providers(["x", None, CUSTOM]) == [CUSTOM]


def test_an_exact_custom_id_naming_the_jev_row_resolves_to_none():
    assert llm_builder.exact_custom_provider([JEV], "custom/prov-jev") is None


def test_a_stale_custom_id_never_falls_back_to_the_jev_row():
    assert llm_builder.custom_provider_or_fallback([JEV], "custom/prov-gone") is None


def test_a_stale_custom_id_never_falls_back_to_a_builtin_row():
    assert llm_builder.custom_provider_or_fallback([JEV, ANTHROPIC], "custom/prov-gone") is None


def test_a_stale_custom_id_falls_back_to_the_first_custom_capable_row():
    assert llm_builder.custom_provider_or_fallback(
        [JEV, ANTHROPIC, CUSTOM], "custom/prov-gone") is CUSTOM


def test_an_exact_custom_id_wins_over_the_fallback():
    other = dict(CUSTOM, id="prov-other")
    assert llm_builder.custom_provider_or_fallback(
        [CUSTOM, other], "custom/prov-other") is other


# ---------------------------------------------------------------------------
# setup_llm: the last line of defence for every exact-id path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider_type", ["jev", "jev_openrouter"])
def test_setup_llm_refuses_a_jev_config_before_building_any_client(provider_type):
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai, \
            patch.object(llm_setup, "ChatAnthropic") as chat_anthropic:
        with pytest.raises(ValueError) as err:
            llm_setup.setup_llm("custom/prov-jev", custom_llm_config=dict(JEV, providerType=provider_type))
    chat_openai.assert_not_called()
    chat_anthropic.assert_not_called()
    assert JEV_KEY not in str(err.value)


def test_build_llm_from_providers_with_the_jev_id_never_builds_a_client():
    from orchestrator_helpers import llm_setup
    with patch.object(llm_setup, "ChatOpenAI") as chat_openai:
        with pytest.raises(ValueError):
            llm_builder.build_llm_from_providers("custom/prov-jev", [JEV])
    chat_openai.assert_not_called()


# ---------------------------------------------------------------------------
# The agent session's settings load (project_settings.fetch_agent_settings)
# ---------------------------------------------------------------------------

def _fake_webapp(providers, model):
    def get(url, *args, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "/llm-providers" in url:
            resp.json.return_value = providers
        elif "/api/projects/" in url:
            resp.json.return_value = {"userId": "u1", "agentOpenaiModel": model}
        elif "/tradecraft-resources" in url:
            resp.json.return_value = []
        else:
            resp.json.return_value = {}
        return resp
    return get


def test_session_with_a_stale_custom_model_and_only_a_jev_row_gets_no_config():
    import project_settings as ps
    with patch("requests.get", side_effect=_fake_webapp([JEV, ANTHROPIC], "custom/prov-gone")):
        settings = ps.fetch_agent_settings("p1", "http://webapp")
    assert settings["CUSTOM_LLM_CONFIG"] is None
    assert settings["OPENAI_MODEL"] == "custom/prov-gone"


def test_session_with_a_stale_custom_model_falls_back_past_the_jev_row():
    import project_settings as ps
    with patch("requests.get", side_effect=_fake_webapp([JEV, CUSTOM], "custom/prov-gone")):
        settings = ps.fetch_agent_settings("p1", "http://webapp")
    assert settings["CUSTOM_LLM_CONFIG"] == CUSTOM
    assert settings["OPENAI_MODEL"] == "custom/prov-custom"


# ---------------------------------------------------------------------------
# api.py: _pick_custom_provider and text-to-cypher
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api_module():
    import api
    return api


def test_pick_custom_provider_never_returns_the_jev_row(api_module):
    assert api_module._pick_custom_provider([JEV], "custom/prov-jev") is None
    assert api_module._pick_custom_provider([JEV], "claude-opus-4-6") is None
    assert api_module._pick_custom_provider([JEV, CUSTOM], "gpt-5") is CUSTOM


def test_text_to_cypher_with_a_stale_custom_model_never_uses_the_jev_row(api_module):
    import project_settings as ps

    providers_resp = MagicMock()
    providers_resp.raise_for_status = MagicMock()
    providers_resp.json.return_value = [JEV]

    with patch.object(ps, "fetch_agent_settings",
                      return_value={"OPENAI_MODEL": "custom/prov-gone"}), \
            patch("requests.get", return_value=providers_resp), \
            patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        with pytest.raises(api_module._CypherSetupError) as err:
            asyncio.run(api_module._build_cypher_manager("u1", "p1"))
    setup.assert_not_called()
    assert err.value.status == 400
    assert JEV_KEY not in err.value.message

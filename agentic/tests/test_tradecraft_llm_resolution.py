"""Unit + regression tests for _build_llm_for_user / _pick_custom_provider.

Covers the bug where an out-of-run endpoint (the 1.x Tradecraft verify, gone since
the cut-over, T9.2; the guardrail today) hardcoded the default model
(claude-opus-4-6) even when the user had configured an OpenAI-compatible custom
provider — crashing with
``LLM not configured: Anthropic API key is required for model 'claude-opus-4-6'``.

These tests do NOT instantiate real LLM clients; they patch
``setup_llm`` and the webapp ``requests.get`` so the suite runs in
isolation and stays deterministic.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

import api as agent_api


def _provider(**overrides: Any) -> dict:
    base = {
        "id": "prov-deepseek-1",
        "providerType": "openai_compatible",
        "displayName": "DeepSeek",
        "baseUrl": "http://172.18.0.1:8080/v1",
        "modelIdentifier": "deepseek-v4-flash-free",
        "apiKey": "sk-test",
    }
    base.update(overrides)
    return base


class _FakeResponse:
    """Minimal stand-in for requests.Response — only what _build_llm_for_user reads."""

    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class PickCustomProviderTests(unittest.TestCase):
    """Direct unit tests for the resolution helper."""

    def test_returns_none_when_no_providers(self):
        self.assertIsNone(agent_api._pick_custom_provider([], "claude-opus-4-6"))

    def test_returns_none_when_only_canonical_providers(self):
        providers = [{"id": "x", "providerType": "anthropic", "apiKey": "k"}]
        self.assertIsNone(agent_api._pick_custom_provider(providers, "claude-opus-4-6"))

    def test_picks_first_openai_compatible(self):
        providers = [
            {"id": "a", "providerType": "anthropic", "apiKey": "k"},
            _provider(id="b"),
        ]
        picked = agent_api._pick_custom_provider(providers, "claude-opus-4-6")
        self.assertIsNotNone(picked)
        self.assertEqual(picked["id"], "b")

    def test_picks_bedrock_custom(self):
        providers = [_provider(id="bc", providerType="bedrock_custom")]
        picked = agent_api._pick_custom_provider(providers, "claude-opus-4-6")
        self.assertIsNotNone(picked)
        self.assertEqual(picked["providerType"], "bedrock_custom")

    def test_picks_ollama_local(self):
        providers = [_provider(id="ol", providerType="ollama_local")]
        picked = agent_api._pick_custom_provider(providers, "claude-opus-4-6")
        self.assertIsNotNone(picked)
        self.assertEqual(picked["providerType"], "ollama_local")

    def test_custom_prefix_picks_matching_id(self):
        providers = [_provider(id="a"), _provider(id="b")]
        picked = agent_api._pick_custom_provider(providers, "custom/b")
        self.assertIsNotNone(picked)
        self.assertEqual(picked["id"], "b")

    def test_custom_prefix_unknown_id_falls_back_to_first_custom(self):
        providers = [_provider(id="a")]
        picked = agent_api._pick_custom_provider(providers, "custom/does-not-exist")
        self.assertIsNotNone(picked)
        # falls back to the first openai_compatible-style record
        self.assertEqual(picked["id"], "a")


class BuildLlmForUserTests(unittest.TestCase):
    """End-to-end behavior: webapp fetch + setup_llm dispatch.

    The webapp HTTP call and setup_llm are patched. We assert the
    EXACT arguments setup_llm is invoked with — the regression bug
    was exactly that custom_llm_config was never passed.
    """

    def setUp(self):
        self.sentinel_llm = object()

        # _build_llm_for_user does ``from orchestrator_helpers.llm_setup import setup_llm``
        # at call time, so we patch on that module — not on api.
        self.setup_llm_patcher = mock.patch(
            "orchestrator_helpers.llm_setup.setup_llm",
            return_value=self.sentinel_llm,
        )
        self.mock_setup_llm = self.setup_llm_patcher.start()
        self.addCleanup(self.setup_llm_patcher.stop)

        # Make get_settings predictable: simulate "no project loaded".
        # That's the exact state where the bug surfaces.
        self.settings_patcher = mock.patch(
            "project_settings.get_settings",
            return_value={},
        )
        self.settings_patcher.start()
        self.addCleanup(self.settings_patcher.stop)

    def _patch_webapp(self, providers: list[dict]):
        return mock.patch("requests.get", return_value=_FakeResponse(providers))

    def test_custom_openai_compatible_provider_is_used(self):
        """Regression: deepseek bridge user — previously crashed with
        Anthropic-key error. Now must dispatch via custom/ path."""
        provider = _provider(id="prov-deepseek-1")

        with self._patch_webapp([provider]):
            llm = agent_api._build_llm_for_user("user-123")

        self.assertIs(llm, self.sentinel_llm)
        self.mock_setup_llm.assert_called_once()
        args, kwargs = self.mock_setup_llm.call_args
        # First positional arg is the model name in custom/<id> form
        self.assertEqual(args[0], "custom/prov-deepseek-1")
        self.assertEqual(kwargs.get("custom_llm_config"), provider)
        # When the custom path is taken, we must NOT also leak canonical keys —
        # otherwise the call signature differs from the working text-to-cypher
        # endpoint and would mask config errors.
        self.assertNotIn("anthropic_api_key", kwargs)
        self.assertNotIn("openai_api_key", kwargs)

    def test_bug_repro_no_anthropic_key_with_only_custom_provider(self):
        """The exact v4.10.1 repro: a single OpenAI-compatible provider
        configured, no Anthropic key. Before the fix this raised
        ``ValueError: Anthropic API key is required...``. Now the call
        must reach setup_llm via the custom path and succeed."""
        provider = _provider(
            id="prov-1",
            baseUrl="http://172.18.0.1:8080/v1",
            modelIdentifier="deepseek-v4-flash-free",
        )

        with self._patch_webapp([provider]):
            # Should not raise.
            llm = agent_api._build_llm_for_user("user-bug")

        self.assertIs(llm, self.sentinel_llm)
        called_model = self.mock_setup_llm.call_args.args[0]
        self.assertTrue(called_model.startswith("custom/"))

    def test_canonical_anthropic_provider_still_uses_canonical_path(self):
        """Regression guard: a user with ONLY an Anthropic provider configured
        must keep using the canonical (non-custom) setup_llm dispatch."""
        provider = {
            "id": "anth-1",
            "providerType": "anthropic",
            "apiKey": "sk-anthropic-xxx",
        }

        with self._patch_webapp([provider]):
            agent_api._build_llm_for_user("user-anth")

        self.mock_setup_llm.assert_called_once()
        args, kwargs = self.mock_setup_llm.call_args
        # Model name comes from settings/default — NOT custom/<id>
        self.assertFalse(args[0].startswith("custom/"))
        self.assertEqual(kwargs.get("anthropic_api_key"), "sk-anthropic-xxx")
        self.assertNotIn("custom_llm_config", kwargs)

    def test_no_providers_falls_back_to_canonical_path(self):
        """No user providers at all (empty DB) — must still call setup_llm
        on the canonical path so the existing error message about the
        missing key is preserved (not silently hidden)."""
        with self._patch_webapp([]):
            agent_api._build_llm_for_user("user-empty")

        self.mock_setup_llm.assert_called_once()
        args, kwargs = self.mock_setup_llm.call_args
        self.assertFalse(args[0].startswith("custom/"))
        self.assertNotIn("custom_llm_config", kwargs)

    def test_mixed_providers_prefer_custom_over_canonical(self):
        """When both canonical (anthropic) and custom (openai_compatible)
        providers exist and no project is active, the user almost certainly
        configured the custom one as a stand-in — pick it."""
        providers = [
            {"id": "anth-1", "providerType": "anthropic", "apiKey": "k"},
            _provider(id="ds-1"),
        ]

        with self._patch_webapp(providers):
            agent_api._build_llm_for_user("user-mixed")

        args, kwargs = self.mock_setup_llm.call_args
        self.assertEqual(args[0], "custom/ds-1")
        self.assertEqual(kwargs.get("custom_llm_config"), providers[1])

    def test_webapp_unreachable_does_not_crash(self):
        """If the webapp lookup fails we must still try setup_llm with
        whatever defaults we have — same behavior as before the patch."""
        with mock.patch("requests.get", side_effect=ConnectionError("no route")):
            agent_api._build_llm_for_user("user-net")

        # Falls through to canonical path with empty provider list.
        self.mock_setup_llm.assert_called_once()
        args, kwargs = self.mock_setup_llm.call_args
        self.assertFalse(args[0].startswith("custom/"))


if __name__ == "__main__":
    unittest.main()

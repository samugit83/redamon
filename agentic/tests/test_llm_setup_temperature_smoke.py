"""Smoke tests: setup_llm wires temperature correctly per provider.

Constructs the real chat-model objects (no network — API keys are fake, and
ChatOpenAI/ChatAnthropic don't call out at construction time) and inspects the
resolved ``temperature`` attribute. This locks two decisions:

  * Kimi (Moonshot) omits temperature entirely (``None``) — its k3/k2.6
    reasoning models reject any value but 1, and there is no per-model signal,
    so we let each model use its own default. Regression guard for the reported
    "invalid temperature: only 1 is allowed" bug.
  * Every other OpenAI-compatible provider still pins ``temperature=0`` for
    reproducibility, except OpenAI reasoning families (o-series, gpt-5+),
    which omit it. Anything else that rejects 0 is handled at call time by
    the ``heal_llm_param_error`` self-heal.

Run (inside agent container):
    docker run --rm -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -v "/path/knowledge_base:/app/knowledge_base:ro" \\
        -w /app redamon-agent python -m unittest \\
        tests.test_llm_setup_temperature_smoke -v
"""

from __future__ import annotations

import os
import sys
import unittest

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from orchestrator_helpers.llm_setup import setup_llm  # noqa: E402


# (model_name, setup kwarg carrying the api key)
_PINNED_ZERO_PROVIDERS = [
    ("gpt-4o", "openai_api_key"),
    ("deepseek/deepseek-chat", "deepseek_api_key"),
    ("glm/glm-4.5", "glm_api_key"),
    ("qwen/qwen-max", "qwen_api_key"),
    ("xai/grok-4", "xai_api_key"),
    ("mistral/mistral-large-latest", "mistral_api_key"),
    ("openrouter/anthropic/claude-3.5-sonnet", "openrouter_api_key"),
]


class SetupLlmTemperatureSmokeTests(unittest.TestCase):

    def test_kimi_omits_temperature(self):
        llm = setup_llm("kimi/kimi-k3", kimi_api_key="fake-key-abc")
        self.assertIsNone(
            llm.temperature,
            "Kimi must NOT pin temperature=0 — k3/k2.6 reject it; the model's "
            "own default (1) must be used instead.",
        )
        # Sanity: it still routed to the Moonshot endpoint.
        self.assertIn("moonshot.ai", str(llm.openai_api_base or llm.root_client.base_url))

    def test_kimi_v1_model_also_omits_temperature(self):
        # Provider-wide omit — not model-specific — so classic moonshot-v1 too.
        llm = setup_llm("kimi/moonshot-v1-8k", kimi_api_key="fake-key-abc")
        self.assertIsNone(llm.temperature)

    def test_other_openai_compatible_providers_pin_zero(self):
        for model_name, key_kwarg in _PINNED_ZERO_PROVIDERS:
            with self.subTest(model=model_name):
                llm = setup_llm(model_name, **{key_kwarg: "fake-key-abc"})
                self.assertEqual(
                    llm.temperature, 0,
                    f"{model_name}: reproducibility default temperature=0 must hold",
                )

    def test_openai_reasoning_model_omits_temperature(self):
        # o-series / gpt-5+ only accept the default (1); setup_llm drops the
        # param at construction so paths without the self-heal don't 400.
        llm = setup_llm("o3-mini", openai_api_key="fake-key-abc")
        self.assertIsNone(llm.temperature)


class AnthropicApiVersionTests(unittest.TestCase):
    """anthropic 2.x sends API version 2026-10-21, on which every model answers
    `temperature` with a 400 ("temperature: Extra inputs are not permitted").
    claude-opus-4-6, the default agent model, failed every call that way."""

    def _sent_temperature(self, llm):
        """The temperature the request JSON carries. langchain-anthropic moves it
        into `extra_body` for SDK 2.x, which still sends it."""
        from langchain_core.messages import HumanMessage
        payload = llm._get_request_payload([HumanMessage(content="hi")])
        return payload.get("temperature", (payload.get("extra_body") or {}).get("temperature"))

    def test_anthropic_calls_send_no_temperature_on_api_version_2026_10_21(self):
        import anthropic
        if int(anthropic.__version__.split(".")[0]) < 2:
            self.skipTest(f"anthropic {anthropic.__version__} still sends 2023-06-01")
        custom = {"providerType": "anthropic", "apiKey": "fake", "modelIdentifier": "claude-sonnet-4-6"}
        for llm in (setup_llm("claude-opus-4-6", anthropic_api_key="fake"),
                    setup_llm("claude-haiku-4-5", anthropic_api_key="fake"),
                    setup_llm("custom/row1", custom_llm_config=custom)):
            with self.subTest(model=llm.model):
                self.assertIsNone(self._sent_temperature(llm))

    def test_an_sdk_on_2023_06_01_keeps_the_per_model_rule(self):
        from unittest import mock
        with mock.patch("anthropic.__version__", "1.9.0"):
            self.assertEqual(self._sent_temperature(setup_llm("claude-opus-4-6", anthropic_api_key="fake")), 0)
            self.assertIsNone(self._sent_temperature(setup_llm("claude-opus-5", anthropic_api_key="fake")))


if __name__ == "__main__":
    unittest.main()

"""Integration tests for the 5 LLM-backed `/llm/*` endpoints under both
OpenAI-style (string content) AND Bedrock-style (list-of-blocks content)
provider responses.

Pre-fix bug:
    raw_text = (getattr(response, 'content', None) or '').strip()
This raised `AttributeError: 'list' object has no attribute 'strip'` whenever
the underlying LangChain model was `ChatBedrockConverse`, because Bedrock
returns content as `[{"type":"text","text":"..."}]`. All recon AI classifiers
(ffuf, nuclei tags, WAF, nuclei FP filter, takeover) crashed with HTTP 500.

Post-fix:
    raw_text = normalize_content(getattr(response, 'content', None)).strip()

This test patches `_build_llm_with_model_for_user` to return a stub LLM that
emits the chosen content shape, then asserts:
1. The endpoint returns 200 (no 500 crash).
2. The parsed payload matches what the model "intended" — proving the
   normalizer reassembled the JSON correctly regardless of provider shape.

Each endpoint is exercised under BOTH shapes to lock in cross-provider parity.

Run inside the agent container:
    python -m unittest tests.test_llm_endpoints_provider_compat
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


# ---------------------------------------------------------------------------
# Stub LLM (mimics LangChain ChatModel; emits canned `.content` of any shape)
# ---------------------------------------------------------------------------

class _StubLLM:
    """Returns a configurable `.content` shape from .ainvoke().

    Pass `content` as a str (OpenAI/Anthropic plain), a list of blocks
    (Bedrock Converse), or any other type to exercise edge cases.
    """

    def __init__(self, content):
        self._content = content

    async def ainvoke(self, _messages):
        class _R:
            pass
        r = _R()
        r.content = self._content
        return r


def _openai_str(payload_dict: dict) -> str:
    """Shape #1: OpenAI/Anthropic plain string."""
    return json.dumps(payload_dict)


def _bedrock_blocks(payload_dict: dict) -> list:
    """Shape #2: ChatBedrockConverse list-of-content-blocks."""
    return [{"type": "text", "text": json.dumps(payload_dict)}]


def _bedrock_blocks_split(payload_dict: dict) -> list:
    """Shape #3: Bedrock splitting one JSON answer across multiple text blocks
    (rare but legal — happens when the model interleaves reasoning with
    structured output)."""
    s = json.dumps(payload_dict)
    half = len(s) // 2
    return [
        {"type": "text", "text": s[:half]},
        {"type": "text", "text": s[half:]},
    ]


def _bedrock_with_tool_use(payload_dict: dict) -> list:
    """Shape #4: Bedrock mixed text + tool_use blocks. The tool_use block
    MUST NOT pollute the text output — normalize_content should drop it."""
    return [
        {"type": "text", "text": json.dumps(payload_dict)},
        {"type": "tool_use", "id": "tool_1", "name": "irrelevant", "input": {}},
    ]


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

class _LLMEndpointFixture(unittest.TestCase):
    """Shared boilerplate: import api module under a fake lifespan, build
    a TestClient, and provide a helper that patches the LLM resolver."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.TestClient = TestClient

    def _client(self):
        return self.TestClient(self.api_module.app)

    def _post_with_stub_llm(self, endpoint: str, body: dict, llm_content):
        """POST to `endpoint`, with `_build_llm_with_model_for_user` patched
        to return a StubLLM emitting `llm_content`."""
        # The webapp's master key: the /llm/* routes fail closed without one (step 1.16).
        master = "provider-compat-test-master-key"
        with patch.object(
            self.api_module,
            "_build_llm_with_model_for_user",
            return_value=_StubLLM(llm_content),
        ), patch.dict(os.environ, {"INTERNAL_API_KEY": master}):
            return self._client().post(endpoint, json=body, headers={"x-internal-key": master})


# ---------------------------------------------------------------------------
# /llm/ffuf-extensions
# ---------------------------------------------------------------------------

class FfufExtensionsProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "url": "https://target.example.com/upload",
        "headers": {"Server": "nginx", "X-Powered-By": "PHP/8.1"},
        "model": "test-model",
        "max_extensions": 4,
    }
    PAYLOAD = {"extensions": ["php", "phtml", "php5", "php7"]}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["extensions"], self.PAYLOAD["extensions"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["extensions"], self.PAYLOAD["extensions"])

    def test_bedrock_split_blocks(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _bedrock_blocks_split(self.PAYLOAD))
        # Joining splits inserts "\n" between halves, which breaks json.loads —
        # so endpoint should respond 502 ("non-JSON"), NOT crash with 500.
        # This pins the boundary between "normalizer crashed" (500) and
        # "model returned unparseable JSON" (502, expected).
        self.assertEqual(r.status_code, 502, r.text)
        self.assertIn("non-JSON", r.json().get("error", ""))

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["extensions"], self.PAYLOAD["extensions"])


# ---------------------------------------------------------------------------
# /llm/nuclei-tags
# ---------------------------------------------------------------------------

class NucleiTagsProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "technologies": ["nginx", "php"],
        "servers": ["nginx"],
        "current_tags": [],
        "candidates": ["nginx", "php", "lfi", "sqli", "xss"],
        "model": "test-model",
        "max_tags": 3,
    }
    PAYLOAD = {"tags": ["nginx", "php", "lfi"]}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-tags", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-tags", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/nuclei-tags", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])

    def test_bedrock_with_markdown_fence(self):
        """Bedrock+Claude often wraps JSON in ```json fences. The endpoint
        already handles fence-stripping post-normalization."""
        fenced = "```json\n" + json.dumps(self.PAYLOAD) + "\n```"
        r = self._post_with_stub_llm(
            "/llm/nuclei-tags", self.REQUEST,
            [{"type": "text", "text": fenced}],
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])


# ---------------------------------------------------------------------------
# /llm/waf-classify
# ---------------------------------------------------------------------------

class WafClassifyProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "url": "https://target.example.com/admin",
        "status_code": 403,
        "headers": {"server": "cloudflare", "cf-ray": "8abc-FRA"},
        "body_sample": "Attention Required! | Cloudflare",
        "response_time_ms": 120,
        "model": "test-model",
    }
    PAYLOAD = {
        "waf_detected": True,
        "waf_type": "cloudflare",
        "confidence": 95,
        "reasoning": "cf-ray header + cloudflare body fingerprint",
    }

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/waf-classify", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["waf_detected"])
        self.assertEqual(r.json()["waf_type"], "cloudflare")

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/waf-classify", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["waf_detected"])

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/waf-classify", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["confidence"], 95)


# ---------------------------------------------------------------------------
# /llm/nuclei-fp-filter
# ---------------------------------------------------------------------------

class NucleiFpFilterProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "template_id": "CVE-2024-1234",
        "tags": ["wordpress", "rce"],
        "status_line": "403 Forbidden",
        "response_sample": "Just a moment...",
        "model": "test-model",
    }
    PAYLOAD = {"is_blocked": True, "confidence": 88, "reason": "challenge page"}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-fp-filter", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["is_blocked"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-fp-filter", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["is_blocked"])
        self.assertEqual(r.json()["confidence"], 88)


# ---------------------------------------------------------------------------
# /llm/takeover-classify
# ---------------------------------------------------------------------------

class TakeoverClassifyProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "hostname": "abandoned.example.com",
        "expected_provider": "github",
        "status_code": 404,
        "headers": {"server": "GitHub.com"},
        "response_sample": "There isn't a GitHub Pages site here.",
        "model": "test-model",
    }
    PAYLOAD = {"is_waf_block": False, "confidence": 92, "reason": "genuine github 404 takeover signature"}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/takeover-classify", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["is_waf_block"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/takeover-classify", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["is_waf_block"])

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/takeover-classify", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["confidence"], 92)


# ---------------------------------------------------------------------------
# Regression: would-have-crashed-pre-fix proof
# ---------------------------------------------------------------------------

class PreFixCrashProofTests(_LLMEndpointFixture):
    """Direct proof that the OLD code path would crash on Bedrock content.

    We simulate the OLD code (`(getattr(resp, 'content', None) or '').strip()`)
    against a Bedrock-style list and confirm it raises AttributeError. This
    locks in WHY the fix matters; if normalize_content's contract ever loosens
    (e.g. it stops handling list inputs), this test will go green when the
    old form starts "working" — alerting us that something is wrong.
    """

    def test_old_code_path_would_have_crashed_on_bedrock(self):
        bedrock_content = [{"type": "text", "text": '{"tags": ["nginx"]}'}]

        class _OldStyleResponse:
            content = bedrock_content

        with self.assertRaises(AttributeError) as ctx:
            (getattr(_OldStyleResponse(), 'content', None) or '').strip()
        self.assertIn("'list' object has no attribute 'strip'", str(ctx.exception))

    def test_new_code_path_handles_bedrock_correctly(self):
        from orchestrator_helpers.json_utils import normalize_content

        bedrock_content = [{"type": "text", "text": '{"tags": ["nginx"]}'}]

        class _NewStyleResponse:
            content = bedrock_content

        text = normalize_content(getattr(_NewStyleResponse(), 'content', None)).strip()
        self.assertEqual(text, '{"tags": ["nginx"]}')
        # And it parses correctly:
        self.assertEqual(json.loads(text), {"tags": ["nginx"]})


# ---------------------------------------------------------------------------
# _build_llm_with_model_for_user — provider resolution regression tests
# ---------------------------------------------------------------------------

class BuildLLMProviderResolutionTests(unittest.TestCase):
    """Verify that _build_llm_with_model_for_user passes the correct arguments
    to setup_llm for every provider type.

    Each test mocks the webapp HTTP call (provider list) and setup_llm itself,
    then asserts which kwargs setup_llm received.  This locks in two things:

    1. Custom LLM regression (38b2c24): custom/<id> models must resolve
       custom_llm_config to the matching UserLlmProvider record — before the
       fix custom_llm_config was always None, causing setup_llm to raise
       "Custom LLM config is required".

    2. Standard-provider regression: openai / anthropic / etc. models must
       still carry the correct API key and receive custom_llm_config=None.
    """

    _OPENAI_P    = {"id": "p-openai",  "providerType": "openai",    "apiKey": "sk-openai-test"}
    _ANTHROPIC_P = {"id": "p-anth",    "providerType": "anthropic", "apiKey": "sk-ant-test"}
    _DEEPSEEK_P  = {"id": "p-ds",      "providerType": "deepseek",  "apiKey": "sk-ds-test"}
    _GEMINI_P    = {"id": "p-gem",     "providerType": "gemini",    "apiKey": "gem-test"}
    _CUSTOM_A    = {
        "id": "custom-abc",
        "providerType": "openai_compatible",
        "apiKey": "compat-key-a",
        "modelIdentifier": "llama3",
        "baseUrl": "http://ollama:11434/v1",
    }
    _CUSTOM_B    = {
        "id": "custom-xyz",
        "providerType": "openai_compatible",
        "apiKey": "compat-key-b",
        "modelIdentifier": "mistral-7b",
        "baseUrl": "http://other:11434/v1",
    }

    @classmethod
    def setUpClass(cls):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module

    def _call(self, model_name: str, providers: list, user_id: str = "u1") -> dict:
        """Invoke _build_llm_with_model_for_user and return the kwargs that
        setup_llm received.  HTTP is stubbed; setup_llm is replaced with a spy."""
        import unittest.mock as _mock
        import requests as _requests

        mock_resp = _mock.MagicMock()
        mock_resp.json.return_value = providers
        mock_resp.raise_for_status.return_value = None

        captured: dict = {}

        def _spy_setup_llm(model, **kw):
            captured.update(kw)
            captured["_model"] = model
            return _mock.MagicMock()

        with patch.object(_requests, "get", return_value=mock_resp), \
             patch("orchestrator_helpers.llm_setup.setup_llm", side_effect=_spy_setup_llm):
            self.api_module._build_llm_with_model_for_user(model_name, user_id)

        return captured

    # --- Custom LLM regression ---

    def test_custom_id_resolves_matching_provider(self):
        """custom/<id> must pass the record with that exact id as custom_llm_config.
        Pre-fix: custom_llm_config was None → setup_llm raised ValueError."""
        kwargs = self._call("custom/custom-abc", [self._OPENAI_P, self._CUSTOM_A, self._CUSTOM_B])
        self.assertEqual(kwargs["custom_llm_config"], self._CUSTOM_A)

    def test_custom_id_picks_by_id_not_position(self):
        """custom/<id> must select the second custom provider when its id matches."""
        kwargs = self._call("custom/custom-xyz", [self._OPENAI_P, self._CUSTOM_A, self._CUSTOM_B])
        self.assertEqual(kwargs["custom_llm_config"], self._CUSTOM_B)

    def test_custom_id_no_match_falls_back_to_first_custom_type(self):
        """Unknown custom/<id> falls back to the first openai_compatible/etc. provider."""
        kwargs = self._call("custom/nonexistent", [self._OPENAI_P, self._CUSTOM_A])
        self.assertEqual(kwargs["custom_llm_config"], self._CUSTOM_A)

    def test_custom_id_no_providers_custom_llm_config_is_none(self):
        """Unknown custom/<id> with no custom providers → custom_llm_config=None."""
        kwargs = self._call("custom/nonexistent", [self._OPENAI_P, self._ANTHROPIC_P])
        self.assertIsNone(kwargs["custom_llm_config"])

    def test_old_code_path_would_miss_custom_config(self):
        """Document the pre-fix failure: resolving by providerType=='custom' (which
        doesn't exist) always returned None, making setup_llm raise."""
        from orchestrator_helpers.llm_setup import setup_llm as real_setup_llm

        providers = [self._CUSTOM_A]
        custom_config_if_unfixed = next(
            (p for p in providers if p.get("providerType") == "custom"), None
        )
        self.assertIsNone(
            custom_config_if_unfixed,
            "Pre-fix lookup by providerType=='custom' always yielded None — "
            "confirming the bug exists without the ID-based resolution.",
        )

    # --- Standard provider regression ---

    def test_openai_model_gets_api_key(self):
        kwargs = self._call("gpt-4o", [self._OPENAI_P])
        self.assertEqual(kwargs["openai_api_key"], "sk-openai-test")

    def test_anthropic_model_gets_api_key(self):
        kwargs = self._call("claude-opus-4-8", [self._ANTHROPIC_P])
        self.assertEqual(kwargs["anthropic_api_key"], "sk-ant-test")

    def test_deepseek_model_gets_api_key(self):
        kwargs = self._call("deepseek/deepseek-chat", [self._DEEPSEEK_P])
        self.assertEqual(kwargs["deepseek_api_key"], "sk-ds-test")

    def test_gemini_model_gets_api_key(self):
        kwargs = self._call("gemini/gemini-2.0-flash", [self._GEMINI_P])
        self.assertEqual(kwargs["gemini_api_key"], "gem-test")

    def test_standard_model_keys_absent_when_provider_not_configured(self):
        """Standard models must pass None for unconfigured provider keys."""
        kwargs = self._call("gpt-4o", [self._ANTHROPIC_P])
        self.assertIsNone(kwargs["openai_api_key"])

    def test_no_user_id_makes_no_http_call_and_does_not_crash(self):
        """user_id=None → HTTP is skipped, all provider keys are None, no crash."""
        import unittest.mock as _mock

        captured: dict = {}

        def _spy(model, **kw):
            captured.update(kw)
            return _mock.MagicMock()

        with patch("orchestrator_helpers.llm_setup.setup_llm", side_effect=_spy):
            self.api_module._build_llm_with_model_for_user("gpt-4o", None)

        self.assertIsNone(captured.get("openai_api_key"))
        self.assertIsNone(captured.get("custom_llm_config"))


if __name__ == "__main__":
    unittest.main()

"""Tests for the new `model` field on POST /tradecraft/verify.

The endpoint must resolve the LLM in this order:
  1. If `body.model` is set, build a provider-agnostic LLM via
     `_build_llm_with_model_for_user(model, user_id)` — the same path the
     five recon AI classifiers use. This decouples tradecraft ingestion
     from the agent's current chat model and from project-load order
     (fixes the 401 path the user hit after a container restart).
  2. Else, if `orchestrator.llm` is set, reuse it (back-compat for old
     resources written before this field existed).
  3. Else, fall back to `_build_llm_for_user(user_id)`.

We assert on the LLM-resolution branch by injecting stub builders that
return tagged identities, then capturing which identity ends up in the
`verify_resource(llm=...)` call.

Run inside the agent container:
    python -m unittest tests.test_tradecraft_verify_model_param
"""
from __future__ import annotations

import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch, AsyncMock

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

# /tradecraft/verify takes the configured master key only (NF-01, step 1.9): every request
# here carries it; test_scanner_key_scope.py covers the refusals.
MASTER = "step19-master-key"
MASTER_HEADERS = {"x-internal-key": MASTER}
_master_env = patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})


def setUpModule():
    _master_env.start()


def tearDownModule():
    _master_env.stop()


class _Tag:
    """Tagged identity so we can tell which build-path the endpoint took."""

    def __init__(self, source):
        self.source = source

    def __repr__(self):
        return f"<LLM:{self.source}>"


# Stub the validator so we never hit network resolution for example.com.
def _stub_validate_ok(_url):
    return True, ""


def _stub_verify_resource_factory(captured):
    async def _stub_verify_resource(url, *, github_token, force, llm, mcp_manager, bounds):
        captured["llm"] = llm
        captured["url"] = url
        captured["force"] = force
        return {
            "summary": "stub",
            "resource_type": "agentic-crawl",
            "sitemap": {},
            "crawl_stopped_because": "",
            "crawl_stats": {},
            "last_error": "",
        }
    return _stub_verify_resource


class TradecraftVerifyModelParamTests(unittest.TestCase):
    """Three branches × one back-compat-default case."""

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
        return self.TestClient(self.api_module.app, headers=MASTER_HEADERS)

    def _post_verify(self, *, model=None, user_id="user-1", orchestrator_llm=_Tag("orchestrator")):
        captured = {}

        # Module-level patches: orchestrator + tradecraft helpers.
        # `verify_resource` is imported lazily inside the endpoint, so we
        # patch it where it lives (orchestrator_helpers.tradecraft_lookup).
        with patch.object(self.api_module, "orchestrator") as orch, \
             patch(
                 "orchestrator_helpers.tradecraft_lookup.verify_resource",
                 new=_stub_verify_resource_factory(captured),
             ), \
             patch(
                 "orchestrator_helpers.tradecraft_lookup.validate_url",
                 side_effect=_stub_validate_ok,
             ), \
             patch.object(
                 self.api_module, "_build_llm_with_model_for_user",
                 side_effect=lambda m, uid: _Tag(f"model:{m}:{uid}"),
             ), \
             patch.object(
                 self.api_module, "_build_llm_for_user",
                 side_effect=lambda uid: _Tag(f"build-for-user:{uid}"),
             ):
            orch._initialized = True
            orch.llm = orchestrator_llm
            # `getattr(orchestrator, '_mcp_manager', None)` in the endpoint.
            orch._mcp_manager = None

            body = {
                "url": "https://example.com/resource",
                "user_id": user_id,
                "force": False,
            }
            if model is not None:
                body["model"] = model
            r = self._client().post("/tradecraft/verify", json=body)
        return r, captured

    # ------------------------------------------------------------------
    # Branch 1: body.model is set -> _build_llm_with_model_for_user.
    # ------------------------------------------------------------------

    def test_explicit_model_uses_with_model_builder(self):
        r, captured = self._post_verify(
            model="bedrock/minimax.minimax-m2.5",
            user_id="user-1",
            orchestrator_llm=_Tag("orchestrator-should-not-be-used"),
        )
        self.assertEqual(r.status_code, 200, r.text)
        # The LLM passed to verify_resource came from the model-aware builder,
        # NOT from orchestrator.llm — exactly the decoupling we wanted.
        self.assertEqual(captured["llm"].source, "model:bedrock/minimax.minimax-m2.5:user-1")

    def test_explicit_model_with_no_user_id(self):
        """user_id can be absent (direct API caller) — the builder still wins."""
        r, captured = self._post_verify(
            model="claude-haiku-4-5",
            user_id=None,
            orchestrator_llm=_Tag("orchestrator"),
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(captured["llm"].source, "model:claude-haiku-4-5:None")

    def test_explicit_model_overrides_orchestrator_llm(self):
        """This is the bug fix: even when orchestrator.llm is set to a known-broken
        provider (e.g. an Anthropic client with an invalid key after a container
        restart), passing body.model routes around it."""
        r, captured = self._post_verify(
            model="bedrock/amazon.nova-micro-v1:0",
            user_id="user-1",
            orchestrator_llm=_Tag("orchestrator-broken-anthropic"),
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("orchestrator", captured["llm"].source)
        self.assertIn("bedrock/amazon.nova-micro-v1:0", captured["llm"].source)

    # ------------------------------------------------------------------
    # Branch 2: model omitted + orchestrator.llm set -> reuse orchestrator.llm.
    # (Back-compat: rows written before the column existed have llmModel="".
    # The webapp sends model="" → falsey → back-compat path.)
    # ------------------------------------------------------------------

    def test_no_model_falls_back_to_orchestrator_llm(self):
        r, captured = self._post_verify(
            model=None,
            user_id="user-1",
            orchestrator_llm=_Tag("orchestrator-chat-llm"),
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(captured["llm"].source, "orchestrator-chat-llm")

    def test_empty_string_model_treated_as_unset(self):
        """Webapp sends '' for legacy rows; the agent treats it as unset."""
        r, captured = self._post_verify(
            model="",
            user_id="user-1",
            orchestrator_llm=_Tag("orchestrator-chat-llm"),
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(captured["llm"].source, "orchestrator-chat-llm")

    # ------------------------------------------------------------------
    # Branch 3: model omitted + orchestrator.llm None -> _build_llm_for_user.
    # ------------------------------------------------------------------

    def test_no_model_no_orchestrator_llm_falls_back_to_user_builder(self):
        r, captured = self._post_verify(
            model=None,
            user_id="user-2",
            orchestrator_llm=None,
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(captured["llm"].source, "build-for-user:user-2")

    # ------------------------------------------------------------------
    # Failure path: builder raises -> 503 + LLM never called.
    # ------------------------------------------------------------------

    def test_builder_failure_returns_503_without_invoking_verify_resource(self):
        captured = {}
        with patch.object(self.api_module, "orchestrator") as orch, \
             patch(
                 "orchestrator_helpers.tradecraft_lookup.verify_resource",
                 new=_stub_verify_resource_factory(captured),
             ), \
             patch(
                 "orchestrator_helpers.tradecraft_lookup.validate_url",
                 side_effect=_stub_validate_ok,
             ), \
             patch.object(
                 self.api_module, "_build_llm_with_model_for_user",
                 side_effect=RuntimeError("no provider key for openai"),
             ):
            orch._initialized = True
            orch.llm = _Tag("orchestrator")
            orch._mcp_manager = None
            r = self._client().post("/tradecraft/verify", json={
                "url": "https://example.com/x",
                "user_id": "u",
                "model": "gpt-4o",
            })
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("LLM not configured", r.json().get("error", ""))
        self.assertNotIn("llm", captured)  # verify_resource never called

    # ------------------------------------------------------------------
    # Schema sanity: model field is optional and string-typed.
    # ------------------------------------------------------------------

    def test_request_schema_accepts_model_field(self):
        """Pydantic accepts the new field. If someone removes the field from
        the BaseModel, this test fails."""
        from api import TradecraftVerifyRequest
        req = TradecraftVerifyRequest(
            url="https://example.com",
            user_id="u",
            model="claude-haiku-4-5",
        )
        self.assertEqual(req.model, "claude-haiku-4-5")

    def test_request_schema_model_field_is_optional(self):
        from api import TradecraftVerifyRequest
        req = TradecraftVerifyRequest(url="https://example.com")
        self.assertIsNone(req.model)


if __name__ == "__main__":
    unittest.main()

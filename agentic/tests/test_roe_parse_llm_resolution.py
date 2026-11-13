"""The RoE parse endpoint must resolve an LLM without a project loaded.

The bug this pins, found by driving the real feature end to end:

The endpoint read `USER_LLM_PROVIDERS` out of the orchestrator's loaded PROJECT
settings. But a RoE document is uploaded while a project is being CREATED - that
is the only place the UI offers the upload - so there is no project, and on a
freshly started agent no project has ever been loaded. The provider list was
empty, no API key resolved, and `setup_llm` raised. Every parse answered 503 for
every model, with two working providers configured in the database.

It looked like a model-routing problem and was not. It was an endpoint reading
its credentials out of a scope it does not have.

The endpoint now builds through the shared "Models by feature" builder, which
ALWAYS fetches the caller's own providers: a loaded project cannot lend its
owner's keys to someone else's parse, and no loaded project is no longer fatal.
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

MASTER = "dummy-master-key-roe-parse"

REPO_ROOT = Path(__file__).resolve().parents[2]
for path in (str(REPO_ROOT), str(REPO_ROOT / "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

WEBAPP_ROUTE = REPO_ROOT / "webapp" / "src" / "app" / "api" / "roe" / "parse" / "route.ts"
AGENT_API = REPO_ROOT / "agentic" / "api.py"


@pytest.fixture(scope="module")
def api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with patch("api.lifespan", fake_lifespan):
        import api as api_module
    return api_module


class _Answer:
    content = '{"projectName": "x"}'


class _Llm:
    async def ainvoke(self, _messages):
        return _Answer()


def test_the_request_model_carries_a_user_id():
    """Without it the agent has nothing to resolve providers against."""
    source = AGENT_API.read_text(encoding="utf-8")
    block = source[source.index("class RoeParseRequest"):]
    block = block[:block.index("\n\n\n")] if "\n\n\n" in block else block
    assert "user_id" in block


def test_the_webapp_route_sends_the_caller_id():
    """It is the only party that knows who is asking."""
    source = WEBAPP_ROUTE.read_text(encoding="utf-8")
    assert "getEffectiveUser" in source or "requireEffectiveUser" in source
    assert "user_id: userId" in source or "user_id: eff.userId" in source


def test_no_project_loaded_still_uses_the_callers_providers(api, monkeypatch):
    """The regression itself: an empty project scope must not decide the answer."""
    from fastapi.testclient import TestClient

    # The route takes the master key and refuses a keyless agent (GHSA-8whg-rvcr-r88r).
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    monkeypatch.delenv("SCANNER_API_KEY", raising=False)
    fetched: list[str] = []

    def fake_fetch(user_id):
        fetched.append(user_id)
        return [{"providerType": "deepseek", "apiKey": "sk-test", "name": "DeepSeek"}]

    with patch.object(api, "fetch_user_providers", fake_fetch), \
         patch("orchestrator_helpers.llm_setup.setup_llm", return_value=_Llm()) as setup, \
         patch.object(api, "_prompt_skew", return_value=None):
        res = TestClient(api.app).post("/roe/parse", headers={"x-internal-key": MASTER}, json={
            "text": "scope: example.com", "model": "deepseek/deepseek-chat",
            "user_id": "user-123",
        })

    assert res.status_code == 200, res.text
    assert fetched == ["user-123"], "the caller's providers were never fetched"
    assert setup.call_args.kwargs.get("deepseek_api_key") == "sk-test"
    assert res.json()["model_used"] == "deepseek/deepseek-chat"


def test_a_loaded_project_never_lends_its_keys(api, monkeypatch):
    """Whatever project the agent last loaded belongs to someone; the parse
    runs on the CALLER's keys even when that project's list is non-empty."""
    from fastapi.testclient import TestClient

    # The route takes the master key and refuses a keyless agent (GHSA-8whg-rvcr-r88r).
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    monkeypatch.delenv("SCANNER_API_KEY", raising=False)
    with patch.object(api, "fetch_user_providers",
                      return_value=[{"providerType": "kimi", "apiKey": "sk-caller"}]), \
         patch("project_settings.get_settings", return_value={"USER_LLM_PROVIDERS": [
             {"providerType": "kimi", "apiKey": "sk-someone-else"}]}), \
         patch("orchestrator_helpers.llm_setup.setup_llm", return_value=_Llm()) as setup, \
         patch.object(api, "_prompt_skew", return_value=None):
        TestClient(api.app).post("/roe/parse", headers={"x-internal-key": MASTER}, json={
            "text": "t", "model": "kimi/kimi-k2", "user_id": "user-123"})

    assert setup.call_args.kwargs.get("kimi_api_key") == "sk-caller"


def test_the_old_project_scoped_helper_is_gone(api):
    """Its fallback to the loaded project's providers is the cross-user leak."""
    assert not hasattr(api, "_setup_llm_for_endpoint")

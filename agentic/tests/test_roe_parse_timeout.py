"""The RoE parse stops its own model call before the webapp stops waiting.

The provider SDK timeouts are per attempt and retried (Anthropic 300 s x5,
openai 600 s x2), so without a cap of its own the agent kept a slow parse
running long after the webapp had dropped the request, and the person saw a
bare network failure instead of "try a faster model".
"""
from __future__ import annotations

import asyncio
import re
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


@pytest.fixture(scope="module")
def api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with patch("api.lifespan", fake_lifespan):
        import api as api_module
    return api_module


class _SlowLlm:
    async def ainvoke(self, _messages):
        await asyncio.sleep(5)


class _Answer:
    content = '{"roeGlobalMaxRps": 5}'


class _FastLlm:
    async def ainvoke(self, _messages):
        return _Answer()


def _post(api, llm, monkeypatch):
    from fastapi.testclient import TestClient

    # The route takes the master key and refuses a keyless agent (GHSA-8whg-rvcr-r88r).
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    monkeypatch.delenv("SCANNER_API_KEY", raising=False)
    with patch.object(api, "fetch_user_providers", return_value=[{"providerType": "deepseek", "apiKey": "k"}]), \
         patch("orchestrator_helpers.llm_setup.setup_llm", return_value=llm), \
         patch.object(api, "_prompt_skew", return_value=None), \
         patch.object(api, "ROE_PARSE_TIMEOUT_S", 0.2):
        return TestClient(api.app).post("/roe/parse", headers={"x-internal-key": MASTER}, json={
            "text": "Maximum 5 requests per second.", "model": "deepseek/deepseek-chat", "user_id": "u1",
        })


def test_a_slow_model_is_stopped_with_the_coded_timeout(api, monkeypatch):
    res = _post(api, _SlowLlm(), monkeypatch)
    assert res.status_code == 504, res.text
    body = res.json()
    assert body["code"] == "agent_timeout"
    # Without the marker the webapp would read this as an outdated agent.
    assert body["model_used"] == "deepseek/deepseek-chat"


def test_a_model_within_the_cap_still_answers(api, monkeypatch):
    res = _post(api, _FastLlm(), monkeypatch)
    assert res.status_code == 200, res.text
    assert res.json()["fields"] == {"roeGlobalMaxRps": 5}


def test_the_cap_sits_under_the_webapp_wait():
    """270 s here, 285 s in the webapp, 300 s undici: each layer answers first."""
    import api as api_module

    route = (REPO_ROOT / "webapp" / "src" / "app" / "api" / "roe" / "parse" / "route.ts").read_text(encoding="utf-8")
    match = re.search(r"AGENT_TIMEOUT_MS\s*=\s*([\d_]+)", route)
    assert match, "the parse route names no AGENT_TIMEOUT_MS"
    webapp_ms = int(match.group(1).replace("_", ""))
    assert api_module.ROE_PARSE_TIMEOUT_S * 1000 < webapp_ms < 300_000


def test_the_model_char_cap_is_the_one_the_webapp_reports():
    import api as api_module

    limits = (REPO_ROOT / "webapp" / "src" / "lib" / "roe" / "limits.ts").read_text(encoding="utf-8")
    match = re.search(r"MAX_MODEL_CHARS\s*=\s*([\d_]+)", limits)
    assert match
    assert int(match.group(1).replace("_", "")) == api_module.ROE_PARSE_MAX_CHARS

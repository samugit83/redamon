"""
What the chat drawer is told when something fails on /ws/agent.

An ERROR frame used to carry `str(exc)`: a provider 401 could quote part of the
key, a 400 the prompt, a Neo4j error the Cypher with target data. Others carried
nothing ("WebSocket authentication failed", "LLM not configured" for any model
build failure). Each frame now carries a fixed sentence plus a code and, for an
exception, its class and the provider's HTTP status, never its text.

Run: ./agentic/run_tests.sh tests/test_ws_error_frames.py
"""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

try:
    import websocket_api
    from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager, StreamingCallback
    _HAVE_WS = True
except Exception:  # pragma: no cover - deps missing on a bare host
    _HAVE_WS = False

SECRET_TEXT = "sk-ant-api03-LEAKED-KEY scan of 10.1.2.3"


class _FakeWS:
    def __init__(self):
        self.sent = []
        self.closed = False
        self.close_code = None
        self.close_reason = None
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        self.closed = True
        self.close_code = code
        self.close_reason = reason


class RateLimitError(Exception):
    """Shaped like an SDK error: the status on the exception, the key in the text."""
    status_code = 429


def _conn(authenticated=True):
    c = WebSocketConnection(_FakeWS())
    c.user_id, c.project_id, c.session_id = "u", "p", "s"
    c.authenticated = authenticated
    return c


def _errors(conn):
    return [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]


@unittest.skipUnless(_HAVE_WS, "agent deps unavailable (run in-container)")
class TicketRejection(unittest.TestCase):
    def _init(self, payload, secret):
        prev = os.environ.get("AGENT_WS_TICKET_SECRET")
        if secret is None:
            os.environ.pop("AGENT_WS_TICKET_SECRET", None)
        else:
            os.environ["AGENT_WS_TICKET_SECRET"] = secret
        try:
            conn = WebSocketConnection(_FakeWS())
            handler = WebSocketHandler(orchestrator=None, ws_manager=WebSocketManager())
            asyncio.run(handler.handle_init(conn, payload))
            return conn
        finally:
            if prev is None:
                os.environ.pop("AGENT_WS_TICKET_SECRET", None)
            else:
                os.environ["AGENT_WS_TICKET_SECRET"] = prev

    def test_unset_secret_names_the_cause_in_the_frame_and_the_close(self):
        conn = self._init({"user_id": "u", "project_id": "p", "session_id": "s"}, None)
        [err] = _errors(conn)
        self.assertEqual(err["message"], "WebSocket authentication failed: ticket auth not configured")
        self.assertEqual(err["code"], "ws_ticket_not_configured")
        self.assertFalse(err["recoverable"])
        self.assertEqual((conn.websocket.close_code, conn.websocket.close_reason),
                         (1008, "ticket auth not configured"))

    def test_bad_ticket_is_told_apart_from_a_missing_secret(self):
        conn = self._init({"user_id": "u", "project_id": "p", "session_id": "s", "ticket": "x.y.z"}, "0" * 64)
        [err] = _errors(conn)
        self.assertEqual(err["message"], "WebSocket authentication failed: Invalid or missing ticket")
        self.assertEqual(err["code"], "ws_ticket_invalid")
        self.assertEqual(conn.websocket.close_code, 1008)


@unittest.skipUnless(_HAVE_WS, "agent deps unavailable (run in-container)")
class InvalidFrames(unittest.TestCase):
    def test_invalid_init_names_the_field_never_its_value(self):
        conn = WebSocketConnection(_FakeWS())
        handler = WebSocketHandler(orchestrator=None, ws_manager=WebSocketManager())
        asyncio.run(handler.handle_init(conn, {"user_id": "u", "project_id": {"leak": SECRET_TEXT}}))
        [err] = _errors(conn)
        self.assertEqual(err["code"], "invalid_frame")
        self.assertEqual(err["fields"], ["project_id", "session_id"])
        self.assertEqual(err["message"], "Invalid initialization message: project_id, session_id")
        self.assertNotIn("LEAKED", json.dumps(err))

    def test_invalid_query_names_the_field(self):
        conn = _conn()
        handler = WebSocketHandler(orchestrator=None, ws_manager=WebSocketManager())
        asyncio.run(handler.handle_query(conn, {"question": {"x": 1}}))
        [err] = _errors(conn)
        self.assertEqual(err["message"], "Invalid query format: question")
        self.assertTrue(err["recoverable"])

    def test_not_authenticated_carries_a_code(self):
        conn = _conn(authenticated=False)
        handler = WebSocketHandler(orchestrator=None, ws_manager=WebSocketManager())
        asyncio.run(handler.handle_approval(conn, {"decision": "approve"}))
        [err] = _errors(conn)
        self.assertEqual((err["message"], err["code"]), ("Not authenticated", "not_authenticated"))


@unittest.skipUnless(_HAVE_WS, "agent deps unavailable (run in-container)")
class RunFailures(unittest.TestCase):
    def test_a_failed_query_sends_the_class_and_provider_status_not_the_text(self):
        class _Orch:
            async def invoke_with_streaming(self, **_kw):
                raise RateLimitError(SECRET_TEXT)

        async def scenario():
            conn = _conn()
            handler = WebSocketHandler(orchestrator=_Orch(), ws_manager=WebSocketManager())
            with patch.object(websocket_api, "save_chat_message", new=AsyncMock(return_value=None)), \
                    patch.object(websocket_api, "update_conversation", new=AsyncMock()):
                cb = StreamingCallback(conn, handler.ws_manager)
                await handler._run_orchestrator_query(conn, "q", cb)
            return conn

        conn = asyncio.run(scenario())
        [err] = _errors(conn)
        self.assertEqual(err["message"], "Error processing query")
        self.assertEqual(err["code"], "query_failed")
        self.assertEqual((err["error_class"], err["provider_status"]), ("RateLimitError", 429))
        self.assertNotIn("LEAKED", json.dumps(err))

    def test_on_error_adds_the_code_and_details(self):
        async def scenario():
            conn = _conn()
            with patch.object(websocket_api, "save_chat_message", new=AsyncMock(return_value=None)):
                cb = StreamingCallback(conn, WebSocketManager())
                await cb.on_error("The agent run failed", recoverable=False,
                                  code="agent_run_failed", error_class="TimeoutError")
                await cb.drain_persist_queue()
            return conn

        [err] = _errors(asyncio.run(scenario()))
        self.assertEqual(err, {"message": "The agent run failed", "recoverable": False,
                               "code": "agent_run_failed", "error_class": "TimeoutError"})


@unittest.skipUnless(_HAVE_WS, "agent deps unavailable (run in-container)")
class PersistFailureNotice(unittest.TestCase):
    def _run(self, save):
        async def scenario():
            conn = _conn()
            with patch.object(websocket_api, "save_chat_message", side_effect=save):
                cb = StreamingCallback(conn, WebSocketManager())
                cb._persist("thinking", {"thought": "a"})
                cb._persist("thinking", {"thought": "b"})
                await cb.drain_persist_queue()
            return conn
        return _errors(asyncio.run(scenario()))

    def test_a_refused_save_is_said_once_with_the_webapp_status(self):
        async def refuse(**_kw):
            return {"http_status": 503}

        [notice] = self._run(refuse)
        self.assertEqual(notice["code"], "persist_failed")
        self.assertEqual(notice["http_status"], 503)
        self.assertTrue(notice["recoverable"])
        self.assertIn("not being saved", notice["message"])

    def test_an_unreachable_webapp_is_said_with_the_class(self):
        async def boom(**_kw):
            raise ConnectionError(SECRET_TEXT)

        [notice] = self._run(boom)
        self.assertEqual(notice["error_class"], "ConnectionError")
        self.assertNotIn("LEAKED", json.dumps(notice))

    def test_saved_rows_send_nothing(self):
        async def ok(**_kw):
            return None

        self.assertEqual(self._run(ok), [])


class SaveChatMessageResult(unittest.TestCase):
    def test_a_refusal_returns_the_status_and_a_crash_the_class(self):
        from orchestrator_helpers import chat_persistence as cp

        class _Resp:
            status_code = 500
            text = SECRET_TEXT

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                return _Resp()

        with patch.object(cp.httpx, "AsyncClient", _Client):
            self.assertEqual(asyncio.run(cp.save_chat_message("s", "thinking", {})), {"http_status": 500})

        class _Down(_Client):
            async def post(self, *a, **k):
                raise ConnectionRefusedError(SECRET_TEXT)

        with patch.object(cp.httpx, "AsyncClient", _Down):
            self.assertEqual(asyncio.run(cp.save_chat_message("s", "thinking", {})),
                             {"error_class": "ConnectionRefusedError"})


class LlmSetupFailure(unittest.TestCase):
    def test_a_missing_key_keeps_the_not_configured_code(self):
        from orchestrator_helpers.llm_setup import llm_setup_failure
        exc = ValueError("Anthropic API key is required for model 'claude-opus-4-6'")
        self.assertEqual(llm_setup_failure("claude-opus-4-6", exc),
                         {"code": "llm_not_configured", "model": "claude-opus-4-6"})

    def test_any_other_build_failure_is_llm_setup_failed_with_the_class(self):
        from orchestrator_helpers.llm_setup import llm_setup_failure
        out = llm_setup_failure("custom/m1", TypeError(SECRET_TEXT))
        self.assertEqual(out, {"code": "llm_setup_failed", "model": "custom/m1", "error_class": "TypeError"})

    def test_apply_project_settings_records_and_clears_the_failure(self):
        from orchestrator_helpers import llm_setup

        class _Orch:
            model_name = None
            llm = None
            neo4j_manager = None

        orch = _Orch()
        settings = {"OPENAI_MODEL": "custom/m1", "USER_LLM_PROVIDERS": [], "USER_SETTINGS": {}}
        with patch.object(llm_setup, "load_project_settings", return_value=settings), \
                patch.object(llm_setup, "setup_llm", side_effect=TypeError(SECRET_TEXT)):
            llm_setup.apply_project_settings(orch, "p")
        self.assertIsNone(orch.llm)
        self.assertEqual(orch.llm_setup_failure["code"], "llm_setup_failed")

        with patch.object(llm_setup, "load_project_settings", return_value=settings), \
                patch.object(llm_setup, "setup_llm", return_value=object()):
            llm_setup.apply_project_settings(orch, "p")
        self.assertIsNone(orch.llm_setup_failure)


class _Callback:
    def __init__(self):
        self.errors = []

    async def on_error(self, message, recoverable=True, **details):
        self.errors.append({"message": message, "recoverable": recoverable, **details})


class OrchestratorFrames(unittest.TestCase):
    def _orchestrator(self):
        from orchestrator import AgentOrchestrator
        return AgentOrchestrator.__new__(AgentOrchestrator)

    def test_a_build_failure_is_not_reported_as_a_missing_key(self):
        orch = self._orchestrator()
        orch.llm_setup_failure = {"code": "llm_setup_failed", "model": "custom/m1", "error_class": "TypeError"}
        cb = _Callback()
        resp = asyncio.run(orch._report_llm_unavailable(cb, "u", "p", "s"))
        [err] = cb.errors
        self.assertEqual(err["message"], "Could not set up the model custom/m1. Check its provider in Global Settings.")
        self.assertEqual((err["code"], err["model"], err["error_class"]), ("llm_setup_failed", "custom/m1", "TypeError"))
        self.assertNotIn("API key", err["message"])
        self.assertEqual(resp.error, err["message"])

    def test_a_missing_key_keeps_its_message(self):
        orch = self._orchestrator()
        orch.llm_setup_failure = {"code": "llm_not_configured", "model": "claude-opus-4-6"}
        cb = _Callback()
        asyncio.run(orch._report_llm_unavailable(cb, "u", "p", "s"))
        [err] = cb.errors
        self.assertEqual(err["message"], "LLM not configured. Please add an API key in Global Settings.")
        self.assertEqual(err["code"], "llm_not_configured")

    def test_no_recorded_failure_still_says_not_configured(self):
        orch = self._orchestrator()
        cb = _Callback()
        asyncio.run(orch._report_llm_unavailable(cb, "u", "p", "s"))
        self.assertEqual(cb.errors[0]["code"], "llm_not_configured")

    def test_a_run_failure_carries_the_class_and_status_only(self):
        orch = self._orchestrator()
        cb = _Callback()
        resp = asyncio.run(orch._report_run_failure(cb, "The agent run failed", RateLimitError(SECRET_TEXT)))
        [err] = cb.errors
        self.assertEqual(err, {"message": "The agent run failed", "recoverable": False,
                               "code": "agent_run_failed", "error_class": "RateLimitError",
                               "provider_status": 429, "provider_error_kind": "rate_limited"})
        self.assertEqual(resp.error, "The agent run failed")


class LlmErrorReason(unittest.TestCase):
    def test_the_reason_names_the_class_and_status_never_the_text(self):
        from orchestrator_helpers.llm_retry import llm_error_reason
        reason = llm_error_reason(RateLimitError(SECRET_TEXT))
        self.assertEqual(reason, "llm_error: RateLimitError (provider HTTP 429)")

    def test_an_error_without_status_keeps_its_class(self):
        from orchestrator_helpers.llm_retry import llm_error_reason
        self.assertEqual(llm_error_reason(TimeoutError(SECRET_TEXT)), "llm_error: TimeoutError")


if __name__ == "__main__":
    unittest.main(verbosity=2)

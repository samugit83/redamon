"""Token usage of streamed OpenAI-compatible responses (issue #242).

`setup_llm` streams `openai_compatible` providers with `stream_usage=True`, and
LangChain sums `usage_metadata` over the chunks when `ainvoke()` aggregates
them. That is right for a server that sends usage once, in the final chunk, as
the OpenAI spec does. Some servers (vLLM with continuous usage stats) send a
cumulative `usage` object on every chunk instead, and summing those reported
~10,000x the metered tokens. These tests run the real ChatOpenAI that
`setup_llm` builds against a loopback SSE server and check the counts that
reach the agent.
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.llm_setup import setup_llm  # noqa: E402

_PROMPT_TOKENS = 20
_CACHED_TOKENS = 8
_WORDS = ["one", " two", " three", " four", " five"]


def _usage(completion_tokens: int) -> dict:
    return {
        "prompt_tokens": _PROMPT_TOKENS,
        "completion_tokens": completion_tokens,
        "total_tokens": _PROMPT_TOKENS + completion_tokens,
        "prompt_tokens_details": {"cached_tokens": _CACHED_TOKENS},
    }


def _chunk(content: str | None, usage: dict | None, finish: str | None = None) -> dict:
    choices = [] if content is None else [
        {"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": finish}
    ]
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "test-model",
        "choices": choices,
        "usage": usage,
    }


def _cumulative_stream() -> list[dict]:
    """vLLM continuous usage stats: the running totals on every chunk."""
    last = len(_WORDS) - 1
    return [
        _chunk(word, _usage(i + 1), "stop" if i == last else None) for i, word in enumerate(_WORDS)
    ]


def _final_usage_stream() -> list[dict]:
    """The OpenAI spec: `usage: null` on content chunks, then one usage chunk."""
    last = len(_WORDS) - 1
    content = [_chunk(word, None, "stop" if i == last else None) for i, word in enumerate(_WORDS)]
    return content + [_chunk(None, _usage(len(_WORDS)))]


def _split_usage_stream() -> list[dict]:
    """Usage split over chunks that are not running totals: still summed."""
    first = {"prompt_tokens": _PROMPT_TOKENS, "completion_tokens": 2, "total_tokens": _PROMPT_TOKENS + 2}
    rest = {"prompt_tokens": 0, "completion_tokens": 3, "total_tokens": 3}
    return [_chunk("one two", first), _chunk(" three four five", rest, "stop")]


def _issue_242_stream() -> list[dict]:
    """The capture in #242: a first chunk with no output yet, the running totals on
    every chunk, then a usage-only chunk (no choices) repeating the final totals."""
    return [_chunk("", _usage(0))] + _cumulative_stream() + [_chunk(None, _usage(len(_WORDS)))]


def _late_prompt_stream() -> list[dict]:
    """Running output totals with the prompt count left at 0 until the last chunk."""
    def usage(prompt: int, completion: int) -> dict:
        return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}
    content = [_chunk(word, usage(0, i + 1)) for i, word in enumerate(_WORDS)]
    return content + [_chunk(None, usage(_PROMPT_TOKENS, len(_WORDS)))]


def _no_usage_stream() -> list[dict]:
    """A server that ignores stream_options and reports no usage at all."""
    return [_chunk(word, None) for word in _WORDS]


class _SSEHandler(BaseHTTPRequestHandler):
    chunks: list[dict] = []

    def do_POST(self):  # noqa: N802 - http.server API
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for chunk in self.chunks:
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")

    def log_message(self, *_):
        pass


class StreamUsageTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _SSEHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _invoke(self, chunks: list[dict], *, sync: bool = False):
        _SSEHandler.chunks = chunks
        base_url = f"http://127.0.0.1:{self.server.server_port}/v1"
        cfg = {
            "id": "custom-test",
            "providerType": "openai_compatible",
            "apiKey": "test-key",
            "modelIdentifier": "test-model",
            "baseUrl": base_url,
        }
        llm = setup_llm("custom/custom-test", custom_llm_config=cfg)
        if sync:
            return llm.invoke("Count to five.")
        return asyncio.run(llm.ainvoke("Count to five."))

    def test_cumulative_usage_on_every_chunk_is_counted_once(self):
        msg = self._invoke(_cumulative_stream())
        self.assertEqual(msg.content, "one two three four five")
        usage = msg.usage_metadata
        self.assertEqual(usage["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(usage["output_tokens"], len(_WORDS))
        self.assertEqual(usage["total_tokens"], _PROMPT_TOKENS + len(_WORDS))
        self.assertEqual(usage["input_token_details"]["cache_read"], _CACHED_TOKENS)

    def test_spec_usage_in_final_chunk_is_unchanged(self):
        msg = self._invoke(_final_usage_stream())
        self.assertEqual(msg.content, "one two three four five")
        usage = msg.usage_metadata
        self.assertEqual(usage["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(usage["output_tokens"], len(_WORDS))
        self.assertEqual(usage["input_token_details"]["cache_read"], _CACHED_TOKENS)

    def test_usage_split_over_chunks_is_still_summed(self):
        usage = self._invoke(_split_usage_stream()).usage_metadata
        self.assertEqual(usage["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(usage["output_tokens"], len(_WORDS))

    def test_issue_242_capture_with_a_trailing_usage_chunk_is_counted_once(self):
        msg = self._invoke(_issue_242_stream())
        self.assertEqual(msg.content, "one two three four five")
        usage = msg.usage_metadata
        self.assertEqual(usage["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(usage["output_tokens"], len(_WORDS))
        self.assertEqual(usage["input_token_details"]["cache_read"], _CACHED_TOKENS)

    def test_running_totals_with_a_late_prompt_count_are_counted_once(self):
        usage = self._invoke(_late_prompt_stream()).usage_metadata
        self.assertEqual(usage["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(usage["output_tokens"], len(_WORDS))

    def test_sync_invoke_counts_running_totals_once(self):
        msg = self._invoke(_issue_242_stream(), sync=True)
        self.assertEqual(msg.content, "one two three four five")
        self.assertEqual(msg.usage_metadata["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(msg.usage_metadata["output_tokens"], len(_WORDS))

    def test_a_stream_without_usage_reports_none(self):
        msg = self._invoke(_no_usage_stream())
        self.assertEqual(msg.content, "one two three four five")
        self.assertIsNone(msg.usage_metadata)

    def test_legacy_openai_compat_prefix_counts_cumulative_usage_once(self):
        _SSEHandler.chunks = _cumulative_stream()
        base_url = f"http://127.0.0.1:{self.server.server_port}/v1"
        llm = setup_llm(
            "openai_compat/test-model",
            openai_compat_base_url=base_url,
            openai_compat_api_key="test-key",
        )
        usage = asyncio.run(llm.ainvoke("Count to five.")).usage_metadata
        self.assertEqual(usage["input_tokens"], _PROMPT_TOKENS)
        self.assertEqual(usage["output_tokens"], len(_WORDS))


if __name__ == "__main__":
    unittest.main()

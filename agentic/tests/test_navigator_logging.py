"""AI Navigator logs ids, codes and timings only (plan §8.12): a canary in the message and in a
tool result never reaches a log line, at any level."""
import asyncio
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from navigator.graph import ChatRequest, run_navigator  # noqa: E402
from navigator.tooling import ToolOutcome  # noqa: E402
from navigator.wiki_index import build_index  # noqa: E402
from navigator_fakes import FakeLLM, route_json, text, tool_call, write_wiki  # noqa: E402

CANARY_MSG = "CANARY-MSG-7f3a91"
CANARY_TOOL = "CANARY-TOOL-c0ffee"
CANARY_CYPHER = "CANARY_CYPHER_LABEL"


class LoggingCanaryTest(unittest.TestCase):
    def test_no_canary_in_logs(self):
        tmp = tempfile.TemporaryDirectory()
        write_wiki(tmp.name)
        index = build_index(tmp.name)
        records = []

        class Grab(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = Grab(level=logging.DEBUG)
        root = logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            async def manifest(_c):
                return [{"name": "run_cypher", "route": "graph", "description": "d",
                         "parameters": {"type": "object", "properties": {"cypher": {"type": "string"}}}}]

            async def call(name, args, cred, client=None):
                return ToolOutcome(json.dumps({"rows": [CANARY_TOOL]}), True, "Ran a graph query", detail=args.get("cypher"))

            llm = FakeLLM([route_json(["graph"], CANARY_MSG),
                           tool_call("run_cypher", {"cypher": f"MATCH (n:{CANARY_CYPHER}) RETURN n LIMIT 1"}),
                           RuntimeError(f"provider said {CANARY_TOOL}")])
            req = ChatRequest(run_id="r", credential="c" * 43, user_id="u", actor_id=None, project_id="p",
                              tenant_id="t", model="m", history=[{"role": "user", "content": CANARY_MSG}],
                              message=CANARY_MSG, allowed_routes=["docs", "graph", "direct"])
            events = []

            async def emit(ev):
                events.append(ev)

            async def checkpoint():
                return None
            with mock.patch("navigator.remote_tools.call_tool", call):
                asyncio.run(run_navigator(req, llm, emit, checkpoint, index_provider=lambda: index,
                                          manifest_fetcher=manifest))
        finally:
            root.removeHandler(handler)
            root.setLevel(old)
            tmp.cleanup()
        self.assertTrue(records)
        blob = "\n".join(records)
        for canary in (CANARY_MSG, CANARY_TOOL, CANARY_CYPHER):
            self.assertNotIn(canary, blob)
        self.assertEqual(events[-1]["code"], "model_error")


if __name__ == "__main__":
    unittest.main()

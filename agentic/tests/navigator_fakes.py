"""Scripted doubles for the AI Navigator tests: a chat model that answers from a script and records
every call, and a tiny wiki on disk. Not a test file (no `test_` prefix)."""
from __future__ import annotations

import json
from typing import Callable, Union

from langchain_core.messages import AIMessage, AIMessageChunk

Step = Union[AIMessage, Callable[[list], AIMessage], Exception]


def tool_call(name: str, args: dict, cid: str = "c1") -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": cid, "type": "tool_call"}])


def text(t: str) -> AIMessage:
    return AIMessage(content=t)


class FakeLLM:
    """`script` is consumed in order by every call (router, specialists, synthesizer)."""

    def __init__(self, script: list[Step], *, can_bind: bool = True):
        self.script = list(script)
        self.calls: list[dict] = []
        self.can_bind = can_bind
        self._tools = None

    def bind_tools(self, tools):
        if not self.can_bind:
            raise NotImplementedError("no tools")
        bound = FakeLLM.__new__(FakeLLM)
        bound.__dict__ = self.__dict__.copy()
        bound._parent = self
        bound._tools = [t["function"]["name"] for t in tools]
        return bound

    def _root(self):
        return getattr(self, "_parent", self)

    def _next(self, messages, config):
        root = self._root()
        root.calls.append({"messages": list(messages), "config": config, "tools": self._tools})
        if not root.script:
            return AIMessage(content="(script exhausted)")
        step = root.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step(messages) if callable(step) else step

    async def ainvoke(self, messages, config=None):
        return self._next(messages, config)

    async def astream(self, messages, config=None):
        msg = self._next(messages, config)
        if msg.tool_calls:
            yield AIMessageChunk(content=msg.content or "", tool_call_chunks=[
                {"name": c["name"], "args": json.dumps(c["args"]), "id": c["id"], "index": i}
                for i, c in enumerate(msg.tool_calls)])
            return
        content = msg.content if isinstance(msg.content, str) else ""
        for i in range(0, len(content), 7):
            yield AIMessageChunk(content=content[i:i + 7])


def route_json(routes, question="q", language="en", action=False) -> AIMessage:
    return AIMessage(content=json.dumps({"routes": routes, "standalone_question": question,
                                         "language": language, "action_request": action}))


WIKI_PAGES = {
    "Home.md": "<!-- canonical-banner -->\n> read **[https://www.redamon.org/docs](https://www.redamon.org/docs)**\n"
               "<!-- canonical-banner -->\n\n# RedAmon Wiki\n\nWelcome to the guide.\n",
    "Scan-Timeline.md": "<!-- canonical-banner -->\n> **[https://www.redamon.org/docs/scan-timeline](https://www.redamon.org/docs/scan-timeline)**\n"
                        "<!-- canonical-banner -->\n\n# Scan Timeline\n\n"
                        "<a href=\"x\"><img src=\"badge.svg\"/></a>\n\n"
                        "The timeline lists every scan.\n\n## Scans\n\nAll scans.\n\n"
                        "### Creating a schedule\n\nPick weekly in the schedule dialog to schedule a weekly scan.\n\n"
                        "## Scans\n\nA duplicate heading.\n",
    "Unpublished-Page.md": "# Unpublished Page\n\nNo banner here.\n\n## Café & Crème — Notes\n\nUnicode heading.\n",
    "_Sidebar.md": "**[Home](Home)**\n\n- [Scan Timeline](Scan-Timeline)\n",
    "_Footer.md": "# Footer\n\nnever indexed\n",
}


def write_wiki(root) -> None:
    import os
    os.makedirs(root, exist_ok=True)
    for name, body in WIKI_PAGES.items():
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    os.makedirs(os.path.join(root, "hacklab"), exist_ok=True)
    with open(os.path.join(root, "hacklab", "Secret.md"), "w") as fh:
        fh.write("# Secret\n\nnever indexed\n")

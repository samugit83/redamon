"""The Tradecraft 2.0 tools the executor registers at start-up, as stand-ins that import the real
tool (``agent_tools``) only when they are called.

Building ``PhaseAwareToolExecutor`` must not import langchain or langgraph through tradecraft:
the agent's tests stub those packages in ``sys.modules`` before they build an executor, and the
real tools' import chain reaches them (``agent_tools`` -> ``library.reader`` -> ``net`` ->
``orchestrator_helpers``). This module imports nothing beyond the standard library.
"""

from __future__ import annotations

import importlib
from typing import Any

V2_TOOL_NAMES = ("tradecraft_lookup", "tradecraft_search", "tradecraft_ask")


class LazyTool:
    """Answers ``ainvoke`` with the real tool of the same name; in a run with no catalog bound
    that tool says it is not available."""

    def __init__(self, name: str) -> None:
        self.name = name

    async def ainvoke(self, tool_input: Any, config: Any = None, **kwargs: Any) -> Any:
        tools = importlib.import_module("tradecraft.agent_tools").V2_TOOLS
        return await tools[self.name].ainvoke(tool_input, config, **kwargs)

    def __repr__(self) -> str:
        return f"LazyTool({self.name!r})"


def registered_tools() -> dict:
    """{name: stand-in} for the executor to register once, whatever the run."""
    return {name: LazyTool(name) for name in V2_TOOL_NAMES}

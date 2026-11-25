"""One person's Kali sandbox, for tests of what the executor's system tools send (group 1).

A system Kali tool call always runs in the sandbox of the person doing the work
(tools.PhaseAwareToolExecutor._execute_routed): there is no other path to a Kali tool. A
test of what such a call carries (a key, a tag, a credential, a deadline, an offload, a
session note) needs that sandbox. `route_to(test, tools)` makes every routed call acquire
one person's handle and run on a client whose tools are `tools` (a name -> tool dict, or a
callable returning one, such as the executor's own table), so the test keeps asserting
what the tool received. Routing by person is tested on its own in
test_sandbox_executor_routing.py and test_sandbox_router.py. Not a test file (no
``test_`` prefix).
"""
from __future__ import annotations

import dataclasses
from contextlib import ExitStack, contextmanager
from unittest import mock

import sandbox_contract as contract
import sandbox_router

PERSON = "alice"
INSTANCE = "a1b2c3"
TOKEN = "one-sandbox-mcp-token-0123456789"
TUNNEL_TOKEN = "one-sandbox-tunnel-token-0123456789"


def handle(person: str = PERSON, view: str = contract.VIEW_OWN, instance: str = INSTANCE, **fields):
    values = dict(user_id=person, view=view, instance=instance,
                  host=contract.container_name(person, view, instance), token=TOKEN,
                  tunnel_token=TUNNEL_TOKEN, ports=contract.PORTS,
                  reverse_port=contract.DEFAULT_REVERSE_PORT)
    values.update(fields)
    return sandbox_router.SandboxHandle(**values)


class Client:
    """The person's MCP client: the tools it serves, and its reconnect: `reconnect` (an
    async callable answering (generation, tools)), else one that finds no new client (a
    transport error then reads as the sandbox gone)."""

    def __init__(self, tools, reconnect=None):
        self._tools = tools
        self._reconnect = reconnect
        self.generation = 0
        self.reconnects = 0

    def list_tools(self) -> list:
        tools = self._tools() if callable(self._tools) else self._tools
        if not isinstance(tools, dict):
            return list(tools)
        for name, tool in tools.items():
            if not isinstance(getattr(tool, "name", None), str):
                tool.name = name
        return list(tools.values())

    async def reconnect(self, seen_generation, reason="", force=False):
        self.reconnects += 1
        if self._reconnect is not None:
            return await self._reconnect(seen_generation, reason=reason, force=force)
        return self.generation, []


class OneSandbox:
    def __init__(self, tools, reconnect=None, **handle_fields):
        self.template = handle(**handle_fields)
        self.client = Client(tools, reconnect)
        self.acquired: list = []
        self.released: list = []

    async def acquire(self, user_id, *, project_id, kind, wait=True, view=None):
        self.acquired.append({"user_id": user_id, "project_id": project_id, "kind": kind})
        return dataclasses.replace(self.template, project_id=project_id, kind=kind)

    async def release(self, held) -> None:
        if held is not None:
            held.released = True
            self.released.append(held)

    async def client_for(self, held):
        return self.client


def _patchers(box: OneSandbox) -> list:
    return [mock.patch.object(sandbox_router, name, getattr(box, name))
            for name in ("acquire", "release", "client_for")]


def route_to(test, tools, reconnect=None, **handle_fields) -> OneSandbox:
    """Route every system tool call of `test` to one person's sandbox serving `tools`."""
    box = OneSandbox(tools, reconnect, **handle_fields)
    for patcher in _patchers(box):
        patcher.start()
        test.addCleanup(patcher.stop)
    return box


@contextmanager
def routed(tools, reconnect=None, **handle_fields):
    """`route_to` for the calls inside the block (a test without addCleanup)."""
    box = OneSandbox(tools, reconnect, **handle_fields)
    with ExitStack() as stack:
        for patcher in _patchers(box):
            stack.enter_context(patcher)
        yield box

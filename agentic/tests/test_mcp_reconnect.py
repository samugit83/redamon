"""
Unit tests for MCP dead-session detection and automatic reconnect.

Covers the bug where the kali-sandbox MCP SSE server half-closes the stream
(typically a long-running tool tripping sse_read_timeout), the anyio TaskGroup
holding the ClientSession cancels, and every later tool.ainvoke() fails with
"Connection closed" / "unhandled errors in a TaskGroup" — previously fixable
only by restarting the agent container.

Run with: python -m pytest tests/test_mcp_reconnect.py -v
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Stub heavy deps that only exist inside the Docker image, same pattern as the
# sibling test modules.
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.language_models',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

# Real-ish @tool decorator so tools.py import succeeds.
import functools

def _fake_tool(fn):
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        return await fn(*args, **kwargs)
    wrapper.name = fn.__name__
    wrapper.ainvoke = lambda args_dict: fn(**args_dict)
    return wrapper

sys.modules['langchain_core.tools'].tool = _fake_tool

# httpx must be stub-only: real httpx isn't installed locally, and the
# detector only needs type().__name__, so fake exception classes work.
if 'httpx' not in sys.modules:
    sys.modules['httpx'] = MagicMock()


# ---------------------------------------------------------------------------
# Fake transport exception types. The detector matches type(e).__name__, so
# we construct classes whose __name__ is the one httpx/anyio would raise.
# ---------------------------------------------------------------------------

class RemoteProtocolError(Exception):
    """Stand-in for httpx.RemoteProtocolError / httpcore.RemoteProtocolError."""


class ClosedResourceError(Exception):
    """Stand-in for anyio.ClosedResourceError."""


class BrokenResourceError(Exception):
    """Stand-in for anyio.BrokenResourceError."""


class ConnectError(Exception):
    """Stand-in for httpx.ConnectError."""


class ReadError(Exception):
    """Stand-in for httpx.ReadError."""


# ---------------------------------------------------------------------------
# _is_mcp_transport_error detection
# ---------------------------------------------------------------------------

class IsMcpTransportErrorTests(unittest.TestCase):
    """Deep coverage of the exception-classification heuristic."""

    def setUp(self):
        from tools import _is_mcp_transport_error
        self.detect = _is_mcp_transport_error

    # -- direct type match --------------------------------------------------

    def test_remote_protocol_error_detected(self):
        self.assertTrue(self.detect(RemoteProtocolError("peer closed")))

    def test_closed_resource_error_detected(self):
        self.assertTrue(self.detect(ClosedResourceError()))

    def test_broken_resource_error_detected(self):
        self.assertTrue(self.detect(BrokenResourceError()))

    def test_connect_error_detected(self):
        self.assertTrue(self.detect(ConnectError("Connection refused")))

    def test_read_error_detected(self):
        self.assertTrue(self.detect(ReadError("read failed")))

    # -- message-pattern match ---------------------------------------------

    def test_peer_closed_connection_message(self):
        # Generic Exception with the httpcore message should still match.
        self.assertTrue(self.detect(
            Exception("peer closed connection without sending complete message body")
        ))

    def test_connection_closed_message(self):
        self.assertTrue(self.detect(Exception("Connection closed")))

    def test_taskgroup_message(self):
        # This is BaseExceptionGroup.__str__() from anyio's TaskGroup unwind —
        # the exact form every dead-session error takes after the first one.
        self.assertTrue(self.detect(
            Exception("unhandled errors in a TaskGroup (1 sub-exception)")
        ))

    def test_case_insensitive_message_match(self):
        self.assertTrue(self.detect(Exception("CONNECTION CLOSED")))
        self.assertTrue(self.detect(Exception("Unhandled Errors in a TaskGroup")))

    # -- false-positive guards ---------------------------------------------

    def test_plain_value_error_not_detected(self):
        self.assertFalse(self.detect(ValueError("bad tool arg")))

    def test_runtime_error_unrelated_message_not_detected(self):
        self.assertFalse(self.detect(RuntimeError("something else broke")))

    def test_empty_exception_not_detected(self):
        self.assertFalse(self.detect(Exception()))

    # -- cause / context chain walk ----------------------------------------

    def test_explicit_cause_chain_walked(self):
        try:
            try:
                raise RemoteProtocolError("peer closed")
            except Exception as inner:
                raise RuntimeError("wrapper around transport error") from inner
        except Exception as e:
            self.assertTrue(self.detect(e))

    def test_implicit_context_walked(self):
        # `raise X` inside an except block attaches __context__, not __cause__.
        try:
            try:
                raise ClosedResourceError()
            except Exception:
                raise RuntimeError("wrapped without from")
        except Exception as e:
            self.assertTrue(self.detect(e))

    def test_deep_cause_chain_walked(self):
        try:
            try:
                try:
                    raise RemoteProtocolError("inner")
                except Exception as a:
                    raise RuntimeError("mid") from a
            except Exception as b:
                raise RuntimeError("outer") from b
        except Exception as e:
            self.assertTrue(self.detect(e))

    # -- ExceptionGroup / BaseExceptionGroup -------------------------------

    def test_exception_group_sub_exception_detected(self):
        # Python 3.11+: TaskGroup cancellation surfaces ExceptionGroup.
        try:
            raise ExceptionGroup("grp", [RemoteProtocolError("peer closed")])
        except ExceptionGroup as e:
            self.assertTrue(self.detect(e))

    def test_exception_group_with_unrelated_then_transport(self):
        try:
            raise ExceptionGroup(
                "grp",
                [ValueError("unrelated"), ClosedResourceError()],
            )
        except ExceptionGroup as e:
            self.assertTrue(self.detect(e))

    def test_exception_group_only_unrelated_not_detected(self):
        try:
            raise ExceptionGroup("grp", [ValueError("a"), RuntimeError("b")])
        except ExceptionGroup as e:
            self.assertFalse(self.detect(e))

    def test_nested_exception_groups(self):
        try:
            raise ExceptionGroup(
                "outer",
                [ExceptionGroup("inner", [BrokenResourceError()])],
            )
        except ExceptionGroup as e:
            self.assertTrue(self.detect(e))

    def test_exception_group_inside_cause_chain(self):
        try:
            try:
                raise ExceptionGroup("grp", [RemoteProtocolError("peer closed")])
            except ExceptionGroup as grp:
                raise RuntimeError("wrapper") from grp
        except Exception as e:
            self.assertTrue(self.detect(e))

    # -- safety --------------------------------------------------------------

    def test_none_cause_context_safe(self):
        # The walker must accept exceptions with no chain at all.
        e = ValueError("plain")
        self.assertIsNone(e.__cause__)
        self.assertIsNone(e.__context__)
        self.assertFalse(self.detect(e))

    def test_self_referential_chain_does_not_loop(self):
        # Pathological: an exception whose __cause__ points to itself.
        # The seen-id set must break the cycle.
        e = ValueError("self-ref")
        e.__cause__ = e  # normally impossible, but belt-and-braces
        # Should terminate and return False without hanging / recursing forever.
        self.assertFalse(self.detect(e))


# ---------------------------------------------------------------------------
# MCPToolsManager: generation counter, reconnect serialisation
# ---------------------------------------------------------------------------

class McpToolsManagerGenerationTests(unittest.IsolatedAsyncioTestCase):
    """Generation bumps, reconnect lock, skip-when-already-rebuilt."""

    def _make_fake_tool(self, name):
        t = MagicMock()
        t.name = name
        t.ainvoke = AsyncMock(return_value=f"result-of-{name}")
        return t

    def _patch_client(self, tool_sets):
        """
        Patch MultiServerMCPClient so each successive instantiation returns
        tools from the next entry of `tool_sets` (or raises if the entry is
        an exception instance/class).
        """
        call_count = {"n": 0}

        def factory(servers):
            idx = call_count["n"]
            call_count["n"] += 1
            entry = tool_sets[min(idx, len(tool_sets) - 1)]
            client = MagicMock()
            if isinstance(entry, BaseException) or (
                isinstance(entry, type) and issubclass(entry, BaseException)
            ):
                client.get_tools = AsyncMock(side_effect=entry)
            else:
                client.get_tools = AsyncMock(return_value=entry)
            return client

        from tools import MCPToolsManager  # noqa: F401 — imported for the patch path
        return patch("tools.MultiServerMCPClient", side_effect=factory), call_count

    async def test_initial_state_has_generation_zero(self):
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        self.assertEqual(mgr.generation, 0)
        self.assertIsNone(mgr.client)
        self.assertEqual(mgr.list_tools(), [])

    async def test_get_tools_bumps_generation_to_one(self):
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        tools = [self._make_fake_tool("execute_ffuf"), self._make_fake_tool("execute_curl")]
        ctx, _ = self._patch_client([tools])
        with ctx:
            loaded = await mgr.get_tools(max_retries=1, retry_delay=0)
        self.assertEqual(mgr.generation, 1)
        self.assertEqual(len(loaded), 2)
        self.assertEqual({t.name for t in mgr.list_tools()}, {"execute_ffuf", "execute_curl"})

    async def test_repeated_get_tools_keeps_bumping_generation(self):
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        tools_a = [self._make_fake_tool("t1")]
        tools_b = [self._make_fake_tool("t2")]
        ctx, _ = self._patch_client([tools_a, tools_b])
        with ctx:
            await mgr.get_tools(max_retries=1, retry_delay=0)
            self.assertEqual(mgr.generation, 1)
            await mgr.get_tools(max_retries=1, retry_delay=0)
        self.assertEqual(mgr.generation, 2)

    async def test_get_tools_failure_leaves_generation_untouched(self):
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        ctx, _ = self._patch_client([RuntimeError("MCP server down")])
        with ctx:
            loaded = await mgr.get_tools(max_retries=1, retry_delay=0)
        self.assertEqual(loaded, [])
        self.assertEqual(mgr.generation, 0)
        self.assertEqual(mgr.list_tools(), [])

    async def test_reconnect_bumps_generation(self):
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        initial = [self._make_fake_tool("execute_ffuf")]
        rebuilt = [self._make_fake_tool("execute_ffuf")]
        ctx, _ = self._patch_client([initial, rebuilt])
        with ctx:
            await mgr.get_tools(max_retries=1, retry_delay=0)
            self.assertEqual(mgr.generation, 1)
            new_gen, new_tools = await mgr.reconnect(seen_generation=1, reason="test")
        self.assertEqual(new_gen, 2)
        self.assertEqual(mgr.generation, 2)
        self.assertEqual(len(new_tools), 1)
        # Crucially, the tool object after reconnect is a NEW reference
        # (not the stale one bound to the dead client).
        self.assertIsNot(new_tools[0], initial[0])

    async def test_reconnect_skips_when_generation_already_advanced(self):
        """
        A fireteam wave that all fail together must collapse to one rebuild:
        the first racer sees gen=1 and rebuilds to 2; subsequent racers that
        also saw gen=1 notice gen=2 > 1 under the lock and skip.
        """
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        initial = [self._make_fake_tool("t")]
        rebuilt1 = [self._make_fake_tool("t")]
        # A second rebuild attempt would fetch the third entry; if the skip
        # works, factory is called exactly twice (initial + first rebuild).
        sentinel_third = [self._make_fake_tool("should-not-load")]
        ctx, call_count = self._patch_client([initial, rebuilt1, sentinel_third])
        with ctx:
            await mgr.get_tools(max_retries=1, retry_delay=0)  # gen -> 1
            # First racer: sees gen=1, calls reconnect(1), rebuild to gen=2.
            gen_a, tools_a = await mgr.reconnect(seen_generation=1, reason="first")
            # Second racer: also saw gen=1 pre-failure, calls reconnect(1).
            # Because gen is now 2, it must skip.
            gen_b, tools_b = await mgr.reconnect(seen_generation=1, reason="second")
        self.assertEqual(gen_a, 2)
        self.assertEqual(gen_b, 2)
        self.assertEqual(call_count["n"], 2, "Client factory should have been called exactly twice")
        # Both callers receive the same current tool set
        self.assertEqual([t.name for t in tools_a], [t.name for t in tools_b])

    async def test_concurrent_reconnects_serialized_by_lock(self):
        """Five parallel tasks that all see gen=1 → only one rebuild happens."""
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        initial = [self._make_fake_tool("t")]
        rebuilt = [self._make_fake_tool("t")]
        # Sentinel list for any extra unwanted rebuilds
        extras = [[self._make_fake_tool("extra")] for _ in range(5)]
        ctx, call_count = self._patch_client([initial, rebuilt, *extras])
        with ctx:
            await mgr.get_tools(max_retries=1, retry_delay=0)
            results = await asyncio.gather(*[
                mgr.reconnect(seen_generation=1, reason=f"racer-{i}")
                for i in range(5)
            ])
        # Every racer sees the same post-rebuild generation.
        for gen, _ in results:
            self.assertEqual(gen, 2)
        # Factory called exactly twice: initial + one rebuild.
        self.assertEqual(call_count["n"], 2)

    async def test_reconnect_failure_leaves_generation_unchanged(self):
        """If the rebuild itself can't connect, gen stays put and tools are []."""
        from tools import MCPToolsManager
        mgr = MCPToolsManager()
        initial = [self._make_fake_tool("t")]
        ctx, _ = self._patch_client([initial, RuntimeError("still down"),
                                     RuntimeError("still down"),
                                     RuntimeError("still down")])
        with ctx:
            await mgr.get_tools(max_retries=1, retry_delay=0)  # gen=1
            new_gen, new_tools = await mgr.reconnect(seen_generation=1, reason="dead")
        self.assertEqual(new_gen, 1, "Generation must not advance on failed rebuild")
        self.assertEqual(new_tools, [])
        self.assertEqual(mgr.generation, 1)


# ---------------------------------------------------------------------------
# PhaseAwareToolExecutor.register_mcp_tools: stale reference cleanup
# ---------------------------------------------------------------------------

class RegisterMcpToolsTests(unittest.TestCase):
    """Re-registering must drop stale tool references bound to the dead client."""

    def _make_executor(self):
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        mgr = MCPToolsManager()
        return PhaseAwareToolExecutor(mgr, graph_tool=None)

    def _fake_tool(self, name):
        t = MagicMock()
        t.name = name
        return t

    def test_initial_registration_populates_names(self):
        ex = self._make_executor()
        t1, t2 = self._fake_tool("execute_ffuf"), self._fake_tool("execute_curl")
        ex.register_mcp_tools([t1, t2])
        self.assertEqual(ex._mcp_tool_names, {"execute_ffuf", "execute_curl"})
        self.assertIs(ex._all_tools["execute_ffuf"], t1)
        self.assertIs(ex._all_tools["execute_curl"], t2)

    def test_reregister_drops_tools_no_longer_in_new_set(self):
        ex = self._make_executor()
        ex.register_mcp_tools([self._fake_tool("execute_ffuf"),
                                self._fake_tool("execute_curl")])
        ex.register_mcp_tools([self._fake_tool("execute_nmap")])
        self.assertEqual(ex._mcp_tool_names, {"execute_nmap"})
        self.assertNotIn("execute_ffuf", ex._all_tools)
        self.assertNotIn("execute_curl", ex._all_tools)

    def test_reregister_replaces_object_for_same_name(self):
        """
        Post-reconnect tools share names with pre-reconnect tools but are
        different Python objects (bound to the new MCP client session).
        Re-registering must point _all_tools at the NEW object.
        """
        ex = self._make_executor()
        stale = self._fake_tool("execute_ffuf")
        ex.register_mcp_tools([stale])
        fresh = self._fake_tool("execute_ffuf")
        ex.register_mcp_tools([fresh])
        self.assertIs(ex._all_tools["execute_ffuf"], fresh)
        self.assertIsNot(ex._all_tools["execute_ffuf"], stale)

    def test_reregister_with_empty_list_clears_mcp_tools(self):
        ex = self._make_executor()
        ex.register_mcp_tools([self._fake_tool("t")])
        ex.register_mcp_tools([])
        self.assertEqual(ex._mcp_tool_names, set())
        self.assertNotIn("t", ex._all_tools)

    def test_reregister_does_not_touch_non_mcp_tools(self):
        """
        query_graph / web_search live in _all_tools but NOT in _mcp_tool_names.
        A reconnect must not nuke them.
        """
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        graph_tool = self._fake_tool("query_graph")
        ex = PhaseAwareToolExecutor(MCPToolsManager(), graph_tool=graph_tool)
        ex.register_mcp_tools([self._fake_tool("execute_ffuf")])
        self.assertIn("query_graph", ex._all_tools)
        # Simulate reconnect clearing MCP tools
        ex.register_mcp_tools([self._fake_tool("execute_ffuf")])
        self.assertIn("query_graph", ex._all_tools)
        self.assertIs(ex._all_tools["query_graph"], graph_tool)


# ---------------------------------------------------------------------------
# PhaseAwareToolExecutor.execute(): end-to-end reconnect-on-transport-error
# ---------------------------------------------------------------------------

class ExecuteReconnectTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end behaviour of the execute() retry-after-reconnect path."""

    def _make_mcp_tool(self, name, ainvoke):
        t = MagicMock()
        t.name = name
        t.ainvoke = ainvoke
        return t

    def _build(self, stale_ainvoke, fresh_ainvoke=None,
               reconnect_result=None):
        """
        Build an executor with:
          - a stale MCP tool 'execute_ffuf' (currently in _all_tools),
          - a mock mcp_manager.reconnect() that returns (new_gen, [fresh_tool])
            when called, or whatever `reconnect_result` overrides.
        """
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        mgr = MCPToolsManager()
        mgr._generation = 1  # pretend we already loaded once

        stale = self._make_mcp_tool("execute_ffuf", stale_ainvoke)
        fresh = None
        if fresh_ainvoke is not None:
            fresh = self._make_mcp_tool("execute_ffuf", fresh_ainvoke)

        # Default: reconnect returns (2, [fresh]) if fresh given; else (1, []).
        if reconnect_result is None:
            if fresh is not None:
                reconnect_result = (2, [fresh])
            else:
                reconnect_result = (1, [])
        mgr.reconnect = AsyncMock(return_value=reconnect_result)

        ex = PhaseAwareToolExecutor(mgr, graph_tool=None)
        ex.register_mcp_tools([stale])
        return ex, mgr, stale, fresh

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_mcp_tool_success_first_try_no_reconnect(self, _phase):
        ok = AsyncMock(return_value="ffuf output")
        ex, mgr, _, _ = self._build(stale_ainvoke=ok, fresh_ainvoke=None)
        result = await ex.execute("execute_ffuf", {"args": "-u x"}, phase="informational")
        self.assertTrue(result["success"])
        self.assertEqual(result["output"], "ffuf output")
        self.assertIsNone(result["error"])
        mgr.reconnect.assert_not_awaited()

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_transport_error_triggers_reconnect_and_retry_succeeds(self, _phase):
        stale = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        fresh = AsyncMock(return_value="recovered output")
        ex, mgr, _, _ = self._build(stale_ainvoke=stale, fresh_ainvoke=fresh)
        result = await ex.execute("execute_ffuf", {"args": "-u x"}, phase="informational")
        self.assertTrue(result["success"], result)
        self.assertEqual(result["output"], "recovered output")
        mgr.reconnect.assert_awaited_once()
        # Reconnect snapshot must be the pre-call generation (1)
        kwargs = mgr.reconnect.await_args.kwargs
        args = mgr.reconnect.await_args.args
        snap = kwargs.get("seen_generation", args[0] if args else None)
        self.assertEqual(snap, 1)
        # Stale tool was called once; fresh tool was called once (the retry)
        self.assertEqual(stale.await_count, 1)
        self.assertEqual(fresh.await_count, 1)

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_taskgroup_message_also_triggers_reconnect(self, _phase):
        """The second-and-beyond failures in a wave surface as TaskGroup strings."""
        stale = AsyncMock(
            side_effect=Exception("unhandled errors in a TaskGroup (1 sub-exception)")
        )
        fresh = AsyncMock(return_value="ok")
        ex, mgr, _, _ = self._build(stale_ainvoke=stale, fresh_ainvoke=fresh)
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertTrue(result["success"])
        mgr.reconnect.assert_awaited_once()

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_reconnect_fails_surfaces_original_error(self, _phase):
        stale = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        # reconnect returns (1, []) — i.e., no rebuild happened
        ex, mgr, _, _ = self._build(
            stale_ainvoke=stale, fresh_ainvoke=None, reconnect_result=(1, [])
        )
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertFalse(result["success"])
        self.assertIn("peer closed", result["error"])
        mgr.reconnect.assert_awaited_once()

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_retry_fails_surfaces_retry_error_not_original(self, _phase):
        stale = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        fresh = AsyncMock(side_effect=RuntimeError("target actually 500'd"))
        ex, mgr, _, _ = self._build(stale_ainvoke=stale, fresh_ainvoke=fresh)
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertFalse(result["success"])
        # The retry's error is the one the caller needs to see, not the
        # transport noise that caused the reconnect.
        self.assertIn("target actually 500'd", result["error"])
        self.assertNotIn("peer closed", result["error"])

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_non_transport_error_does_not_reconnect(self, _phase):
        # ValueError (bad tool args) must not spuriously rebuild the client.
        stale = AsyncMock(side_effect=ValueError("bad args"))
        ex, mgr, _, _ = self._build(stale_ainvoke=stale, fresh_ainvoke=None)
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertFalse(result["success"])
        self.assertIn("bad args", result["error"])
        mgr.reconnect.assert_not_awaited()

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_transport_error_on_non_mcp_tool_does_not_reconnect(self, _phase):
        """
        If query_graph or web_search somehow raise a look-alike transport error,
        we must NOT trigger an MCP rebuild — those tools don't use MCP at all.
        """
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        mgr = MCPToolsManager()
        mgr._generation = 1
        mgr.reconnect = AsyncMock(return_value=(2, []))
        graph_tool = MagicMock()
        graph_tool.name = "query_graph"
        graph_tool.ainvoke = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        ex = PhaseAwareToolExecutor(mgr, graph_tool=graph_tool)
        result = await ex.execute("query_graph", {"question": "hi"}, phase="informational")
        self.assertFalse(result["success"])
        mgr.reconnect.assert_not_awaited()

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_retry_uses_fresh_tool_reference_not_stale(self, _phase):
        """
        The retry must invoke the NEW tool object returned by reconnect,
        not the stale one that raised. If we accidentally re-used the stale
        reference, its AsyncMock would be called twice.
        """
        stale = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        fresh = AsyncMock(return_value="fresh output")
        ex, mgr, stale_tool, fresh_tool = self._build(
            stale_ainvoke=stale, fresh_ainvoke=fresh
        )
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertTrue(result["success"])
        self.assertEqual(stale.await_count, 1, "stale tool used once for the first try only")
        self.assertEqual(fresh.await_count, 1, "fresh tool used once for the retry")
        # After a successful reconnect, _all_tools must point at the fresh tool.
        self.assertIs(ex._all_tools["execute_ffuf"], fresh_tool)

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_wpscan_token_injection_preserved_on_retry(self, _phase):
        """API-key injection must apply to both the first call AND the retry."""
        stale = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        captured = []
        async def fresh_impl(args):
            captured.append(args)
            return "ok"
        fresh = AsyncMock(side_effect=fresh_impl)
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        mgr = MCPToolsManager()
        mgr._generation = 1
        stale_tool = MagicMock(); stale_tool.name = "execute_wpscan"; stale_tool.ainvoke = stale
        fresh_tool = MagicMock(); fresh_tool.name = "execute_wpscan"; fresh_tool.ainvoke = fresh
        mgr.reconnect = AsyncMock(return_value=(2, [fresh_tool]))
        ex = PhaseAwareToolExecutor(mgr, graph_tool=None)
        ex.register_mcp_tools([stale_tool])
        ex.set_wpscan_api_token("TOKEN123")

        result = await ex.execute(
            "execute_wpscan",
            {"args": "--url https://x"},
            phase="informational",
        )
        self.assertTrue(result["success"])
        # The retry call must have the injected token, not the raw args.
        self.assertEqual(len(captured), 1)
        self.assertIn("--api-token TOKEN123", captured[0]["args"])
        self.assertIn("--url https://x", captured[0]["args"])

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_gau_urlscan_key_injection_preserved_on_retry(self, _phase):
        stale = AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        captured = []
        async def fresh_impl(args):
            captured.append(args)
            return "ok"
        fresh = AsyncMock(side_effect=fresh_impl)
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        mgr = MCPToolsManager()
        mgr._generation = 1
        stale_tool = MagicMock(); stale_tool.name = "execute_gau"; stale_tool.ainvoke = stale
        fresh_tool = MagicMock(); fresh_tool.name = "execute_gau"; fresh_tool.ainvoke = fresh
        mgr.reconnect = AsyncMock(return_value=(2, [fresh_tool]))
        ex = PhaseAwareToolExecutor(mgr, graph_tool=None)
        ex.register_mcp_tools([stale_tool])
        ex.set_gau_urlscan_api_key("URLSCAN_KEY")

        await ex.execute("execute_gau", {"args": "example.com"}, phase="informational")
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["urlscan_api_key"], "URLSCAN_KEY")
        self.assertEqual(captured[0]["args"], "example.com")

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_exception_group_from_taskgroup_triggers_reconnect(self, _phase):
        """Python 3.11+ TaskGroup cancellation surfaces ExceptionGroup, not str."""
        grp = ExceptionGroup("mcp failure", [RemoteProtocolError("peer closed")])
        stale = AsyncMock(side_effect=grp)
        fresh = AsyncMock(return_value="recovered")
        ex, mgr, _, _ = self._build(stale_ainvoke=stale, fresh_ainvoke=fresh)
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertTrue(result["success"])
        self.assertEqual(result["output"], "recovered")
        mgr.reconnect.assert_awaited_once()

    @patch("tools.is_tool_allowed_in_phase", return_value=False)
    async def test_phase_check_failure_skips_execution_and_reconnect(self, _phase):
        """A phase-disallowed call must not hit the tool OR the reconnect path."""
        stale = AsyncMock(side_effect=RemoteProtocolError("should not be called"))
        ex, mgr, _, _ = self._build(stale_ainvoke=stale, fresh_ainvoke=None)
        result = await ex.execute("execute_ffuf", {"args": ""}, phase="informational")
        self.assertFalse(result["success"])
        self.assertIn("not allowed", result["error"].lower())
        stale.assert_not_awaited()
        mgr.reconnect.assert_not_awaited()

    @patch("tools.is_tool_allowed_in_phase", return_value=True)
    async def test_concurrent_transport_errors_share_one_rebuild(self, _phase):
        """
        Five parallel tool calls all die on a shared dead SSE session.
        mcp_manager.reconnect must be called by each caller, but internally
        the lock + generation check must collapse to one real rebuild. Here
        we test the executor side: each caller awaits reconnect, then uses
        whichever fresh tool is now registered.
        """
        from tools import PhaseAwareToolExecutor, MCPToolsManager
        mgr = MCPToolsManager()
        mgr._generation = 1
        # Real reconnect-like stub: first caller bumps gen to 2, provides a
        # fresh tool; subsequent callers see gen advanced and reuse it.
        fresh_tool = self._make_mcp_tool("execute_ffuf",
                                          AsyncMock(return_value="ok"))
        lock = asyncio.Lock()
        current = {"gen": 1, "tools": None}
        async def fake_reconnect(seen_generation, reason=""):
            async with lock:
                if current["gen"] > seen_generation:
                    return current["gen"], current["tools"] or []
                current["gen"] += 1
                current["tools"] = [fresh_tool]
                return current["gen"], current["tools"]
        mgr.reconnect = AsyncMock(side_effect=fake_reconnect)

        stale_tool = self._make_mcp_tool(
            "execute_ffuf", AsyncMock(side_effect=RemoteProtocolError("peer closed"))
        )
        ex = PhaseAwareToolExecutor(mgr, graph_tool=None)
        ex.register_mcp_tools([stale_tool])

        results = await asyncio.gather(*[
            ex.execute("execute_ffuf", {"args": f"-{i}"}, phase="informational")
            for i in range(5)
        ])
        for r in results:
            self.assertTrue(r["success"], r)
            self.assertEqual(r["output"], "ok")
        # Exactly one real rebuild (gen 1 -> 2); subsequent racers fast-pathed.
        self.assertEqual(current["gen"], 2)


if __name__ == "__main__":
    unittest.main()

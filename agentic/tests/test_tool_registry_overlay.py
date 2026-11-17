"""
Tier 3 / Stage 5: the per-project `tradecraft_lookup` system-prompt catalog is
bound to the current session via a ContextVar overlay instead of mutating the
global TOOL_REGISTRY (which raced -> one project's catalog leaked into another's
prompt). Since the cut-over (T9.2) the overlay holds the run's tradecraft entries
({tool name: entry}, `swap_tradecraft_v2_entries`); the helpers below bind one
`tradecraft_lookup` entry, as the 1.x swap/pop did, so every check is unchanged.

Proves:
  - PARITY: with no overlay, visible_registry() IS the global TOOL_REGISTRY (the
    default prompt-building path is byte-identical), and _get_visible_tools reads
    exactly the same entries as the old direct-TOOL_REGISTRY logic.
  - NO GLOBAL MUTATION: swap/pop never touch the shared dict.
  - ORDER: tradecraft is inserted before MCP-injected entries (preserving the
    historical [built-ins, tradecraft, mcp] order / prompt-prefix stability).
  - ISOLATION: two concurrent sessions (separate contextvars.Context) each see
    their OWN tradecraft catalog.
"""
import os
import contextvars
import unittest

os.environ.setdefault("WEBAPP_API_URL", "http://fake-webapp")

from prompts import tool_registry as tr
from prompts.tool_registry import (
    visible_registry, swap_tradecraft_v2_entries,
    TOOL_REGISTRY, _tradecraft_v2_overlay as _tradecraft_overlay,
)
from prompts.base import _get_visible_tools


def swap_tradecraft_entry(entry):
    swap_tradecraft_v2_entries({"tradecraft_lookup": entry})


def pop_tradecraft_entry():
    swap_tradecraft_v2_entries(None)

_TC = {"purpose": "P", "when_to_use": "W",
       "args_format": '"resource_id": "x"', "description": "D"}


class TestTradecraftOverlay(unittest.TestCase):
    def tearDown(self):
        _tradecraft_overlay.set(None)

    # ---- parity: default path unchanged ----
    def test_default_path_returns_global_identity(self):
        _tradecraft_overlay.set(None)
        self.assertIs(visible_registry(), TOOL_REGISTRY)

    def test_get_visible_tools_parity_when_no_overlay(self):
        _tradecraft_overlay.set(None)
        allowed = set(list(TOOL_REGISTRY.keys())[:5]) | {"tradecraft_lookup"}
        old = [(n, i) for n, i in TOOL_REGISTRY.items() if n in allowed]
        self.assertEqual(_get_visible_tools(allowed), old)

    # ---- no global mutation ----
    def test_swap_does_not_mutate_global(self):
        had = "tradecraft_lookup" in TOOL_REGISTRY
        swap_tradecraft_entry(_TC)
        self.assertIn("tradecraft_lookup", visible_registry())
        self.assertEqual(("tradecraft_lookup" in TOOL_REGISTRY), had)  # unchanged

    def test_pop_restores_default(self):
        swap_tradecraft_entry(_TC)
        self.assertIn("tradecraft_lookup", visible_registry())
        pop_tradecraft_entry()
        self.assertIs(visible_registry(), TOOL_REGISTRY)

    # ---- ordering ----
    def test_tradecraft_appended_after_builtins_when_no_mcp(self):
        swap_tradecraft_entry(_TC)
        keys = list(visible_registry().keys())
        self.assertEqual(keys[-1], "tradecraft_lookup")
        # built-in prefix is exactly the global's key order
        self.assertEqual(keys[:-1], [k for k in TOOL_REGISTRY.keys()
                                     if k != "tradecraft_lookup"])

    def test_tradecraft_before_mcp_entries(self):
        try:
            tr.TOOL_REGISTRY["mcp_tool_x"] = dict(_TC)
            tr._mcp_injected_keys.add("mcp_tool_x")
            swap_tradecraft_entry(_TC)
            keys = list(visible_registry().keys())
            self.assertLess(keys.index("tradecraft_lookup"), keys.index("mcp_tool_x"))
        finally:
            tr.TOOL_REGISTRY.pop("mcp_tool_x", None)
            tr._mcp_injected_keys.discard("mcp_tool_x")

    # ---- isolation across concurrent sessions ----
    def test_isolation_across_contexts(self):
        tc_a = {**_TC, "description": "catalog-A"}
        tc_b = {**_TC, "description": "catalog-B"}

        def sess(entry):
            swap_tradecraft_entry(entry)  # binds to THIS context
            return visible_registry()["tradecraft_lookup"]["description"]

        ctx_a = contextvars.copy_context()
        ctx_b = contextvars.copy_context()
        a = ctx_a.run(sess, tc_a)
        b = ctx_b.run(sess, tc_b)
        self.assertEqual(a, "catalog-A")
        self.assertEqual(b, "catalog-B")
        # the outer context was never given an overlay
        self.assertIsNone(_tradecraft_overlay.get())
        self.assertNotIn("tradecraft_lookup", TOOL_REGISTRY)

    def test_disabled_session_sees_no_tradecraft_while_other_has_it(self):
        def with_tc():
            swap_tradecraft_entry(_TC)
            return "tradecraft_lookup" in visible_registry()

        def without_tc():
            pop_tradecraft_entry()  # this project disabled tradecraft
            return "tradecraft_lookup" in visible_registry()

        self.assertTrue(contextvars.copy_context().run(with_tc))
        self.assertFalse(contextvars.copy_context().run(without_tc))


if __name__ == "__main__":
    unittest.main(verbosity=2)

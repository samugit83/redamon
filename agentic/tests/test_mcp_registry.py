"""
Tests for agentic/mcp_registry.py — schema validation, default-phase fallback,
and to_mcp_servers_dict transport branching.

Run with: python -m pytest tests/test_mcp_registry.py -v
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

import mcp_registry as reg  # noqa: E402


def _http_server(**overrides):
    base = {
        "id": "myhttp",
        "name": "My HTTP MCP",
        "transport": "streamable_http",
        "url": "http://example.local:8080/mcp",
        "tools": [],
    }
    base.update(overrides)
    return base


def _stdio_server(**overrides):
    base = {
        "id": "mystdio",
        "name": "My Stdio MCP",
        "transport": "stdio",
        "command": "uvx",
        "args": ["mcp-server-time"],
        "tools": [],
    }
    base.update(overrides)
    return base


def _tool(**overrides):
    base = {
        "name": "do_thing",
        "purpose": "Does the thing",
        "when_to_use": "When you need a thing done",
        "args_format": '"x": "y"',
        "description": "Multi-line description here.",
    }
    base.update(overrides)
    return base


class SchemaValidationTests(unittest.TestCase):

    def test_minimal_http_server_validates(self):
        srv = reg.MCPServer.model_validate(_http_server())
        self.assertEqual(srv.id, "myhttp")
        self.assertEqual(srv.transport, "streamable_http")

    def test_minimal_stdio_server_validates(self):
        srv = reg.MCPServer.model_validate(_stdio_server())
        self.assertEqual(srv.transport, "stdio")
        self.assertEqual(srv.command, "uvx")

    def test_http_requires_url(self):
        with self.assertRaises(Exception):
            reg.MCPServer.model_validate(_http_server(url=None))

    def test_stdio_requires_command(self):
        with self.assertRaises(Exception):
            reg.MCPServer.model_validate(_stdio_server(command=None))

    def test_duplicate_tool_name_within_server_rejected(self):
        with self.assertRaises(Exception):
            reg.MCPServer.model_validate(_http_server(tools=[_tool(), _tool()]))

    def test_id_pattern_enforced(self):
        with self.assertRaises(Exception):
            reg.MCPServer.model_validate(_http_server(id="not a slug"))

    def test_default_phases_default_to_all_three(self):
        srv = reg.MCPServer.model_validate(_http_server())
        self.assertEqual(set(srv.default_phases), set(reg.PHASES))


class CrossServerValidationTests(unittest.TestCase):

    def test_duplicate_id_rejected(self):
        a = reg.MCPServer.model_validate(_http_server(id="dup"))
        b = reg.MCPServer.model_validate(_http_server(id="dup"))
        valid, errors = reg.validate_servers([a, b], is_user_supplied=True)
        self.assertEqual(len(valid), 1)
        self.assertTrue(any(e.code == "duplicate_id" for e in errors))

    def test_system_id_collision_rejected_for_user(self):
        # 'nmap' is reserved
        s = reg.MCPServer.model_validate(_http_server(id="nmap"))
        valid, errors = reg.validate_servers([s], is_user_supplied=True)
        self.assertEqual(len(valid), 0)
        self.assertTrue(any(e.code == "system_id_collision" for e in errors))

    def test_system_id_allowed_for_system_servers(self):
        s = reg.MCPServer.model_validate(_http_server(id="nmap"))
        valid, errors = reg.validate_servers([s], is_user_supplied=False)
        self.assertEqual(len(valid), 1)
        self.assertEqual(len(errors), 0)


class VerbatimPassthroughTests(unittest.TestCase):
    """Headers and stdio env values are passed through to the upstream
    MCP client verbatim — no string substitution / interpolation."""

    def test_headers_passed_verbatim(self):
        srv = reg.MCPServer.model_validate(_http_server(
            headers={"X-Custom": "literal-value", "X-Project-Id": "abc-123"},
        ))
        cfg, warnings = reg.to_mcp_servers_dict([srv])
        self.assertEqual(cfg["myhttp"]["headers"]["X-Custom"], "literal-value")
        self.assertEqual(cfg["myhttp"]["headers"]["X-Project-Id"], "abc-123")
        self.assertEqual(warnings, [])

    def test_stdio_env_passed_verbatim(self):
        # As `env -i` arguments (NF-14): an `env` value would be ${VAR}-expanded by the adapter.
        srv = reg.MCPServer.model_validate(_stdio_server(
            env={"FOO": "bar", "BAZ": "qux-with-special-chars-$%"},
        ))
        cfg, warnings = reg.to_mcp_servers_dict([srv])
        self.assertNotIn("env", cfg["mystdio"])
        self.assertIn("FOO=bar", cfg["mystdio"]["args"])
        self.assertIn("BAZ=qux-with-special-chars-$%", cfg["mystdio"]["args"])
        self.assertEqual(warnings, [])

    def test_dollar_brace_pattern_not_interpreted(self):
        # Was previously interpolated; now stored as a literal string.
        srv = reg.MCPServer.model_validate(_http_server(
            headers={"X-Token": "${SOME_VAR}"},
        ))
        cfg, _ = reg.to_mcp_servers_dict([srv])
        self.assertEqual(cfg["myhttp"]["headers"]["X-Token"], "${SOME_VAR}")


class ToMcpServersDictTests(unittest.TestCase):

    def test_http_transport_dict_shape(self):
        srv = reg.MCPServer.model_validate(_http_server(transport="sse"))
        cfg, warnings = reg.to_mcp_servers_dict([srv])
        self.assertIn("myhttp", cfg)
        self.assertEqual(cfg["myhttp"]["transport"], "sse")
        self.assertEqual(cfg["myhttp"]["url"], "http://example.local:8080/mcp")
        self.assertEqual(cfg["myhttp"]["sse_read_timeout"], 600)
        self.assertEqual(warnings, [])

    def test_stdio_transport_dict_shape(self):
        srv = reg.MCPServer.model_validate(_stdio_server(env={"FOO": "bar"}))
        cfg, warnings = reg.to_mcp_servers_dict([srv])
        self.assertEqual(cfg["mystdio"]["transport"], "stdio")
        # Started through `env -i` with exactly its own env plus PATH/HOME/LANG (NF-14).
        self.assertEqual(cfg["mystdio"]["command"], reg.STDIO_ENV_LAUNCHER)
        self.assertEqual(cfg["mystdio"]["args"][:2], ["-i", "--"])
        self.assertEqual(cfg["mystdio"]["args"][-3:], ["FOO=bar", "uvx", "mcp-server-time"])
        self.assertNotIn("env", cfg["mystdio"])

    def test_disabled_server_skipped(self):
        srv = reg.MCPServer.model_validate(_http_server(enabled=False))
        cfg, _ = reg.to_mcp_servers_dict([srv])
        self.assertEqual(cfg, {})

    def test_bearer_auth_resolves_env(self):
        # A system server's only (OQ-R1): test_mcp_user_token_env_var.py has the user side.
        with patch.dict(os.environ, {"MY_TOKEN": "secret123"}, clear=False):
            srv = reg.MCPServer.model_validate(_http_server(
                id="nmap", auth={"type": "bearer", "token_env_var": "MY_TOKEN"},
            ))
            cfg, warnings = reg.to_mcp_servers_dict([srv])
            self.assertEqual(cfg["nmap"]["headers"]["Authorization"], "Bearer secret123")
            self.assertEqual(warnings, [])

    def test_missing_auth_env_surfaces_warning(self):
        with patch.dict(os.environ, {}, clear=True):
            srv = reg.MCPServer.model_validate(_http_server(
                id="nmap", auth={"type": "bearer", "token_env_var": "ABSENT_TOKEN"},
            ))
            cfg, warnings = reg.to_mcp_servers_dict([srv])
            self.assertTrue(any(w.code == "env_var_unset" for w in warnings))
            # Without the token, no Authorization header is added
            self.assertNotIn("headers", cfg["nmap"])

    def test_bearer_auth_direct_token_used_verbatim(self):
        srv = reg.MCPServer.model_validate(_http_server(
            auth={"type": "bearer", "token": "ghp_abc123literal"},
        ))
        cfg, warnings = reg.to_mcp_servers_dict([srv])
        self.assertEqual(cfg["myhttp"]["headers"]["Authorization"], "Bearer ghp_abc123literal")
        self.assertEqual(warnings, [])

    def test_bearer_auth_direct_token_used_verbatim_no_interpolation(self):
        # ${...} patterns in the literal token are NOT substituted — the
        # whole string is sent as-is. This is intentional: ${VAR}
        # interpolation was removed from the codebase, so a token like
        # "${MY_TOKEN}" is shipped to the upstream MCP literally.
        with patch.dict(os.environ, {"MY_TOKEN": "should_not_be_used"}, clear=False):
            srv = reg.MCPServer.model_validate(_http_server(
                auth={"type": "bearer", "token": "${MY_TOKEN}"},
            ))
            cfg, _ = reg.to_mcp_servers_dict([srv])
            self.assertEqual(cfg["myhttp"]["headers"]["Authorization"], "Bearer ${MY_TOKEN}")

    def test_bearer_auth_direct_token_takes_priority_over_env_var(self):
        # If both are set, direct token wins. token_env_var is fallback only.
        with patch.dict(os.environ, {"FALLBACK": "from_env"}, clear=False):
            srv = reg.MCPServer.model_validate(_http_server(
                auth={"type": "bearer", "token": "direct_wins", "token_env_var": "FALLBACK"},
            ))
            cfg, _ = reg.to_mcp_servers_dict([srv])
            self.assertEqual(cfg["myhttp"]["headers"]["Authorization"], "Bearer direct_wins")

    def test_bearer_auth_requires_at_least_one_field(self):
        with self.assertRaises(Exception):
            reg.MCPServer.model_validate(_http_server(
                auth={"type": "bearer"},
            ))


class RedactionTests(unittest.TestCase):

    def test_redact_masks_literal_token(self):
        srv = reg.MCPServer.model_validate(_http_server(
            auth={"type": "bearer", "token": "ghp_supersecret_abc1234"},
        ))
        out = reg.redact_for_api([srv])
        self.assertEqual(len(out), 1)
        self.assertNotEqual(out[0]["auth"]["token"], "ghp_supersecret_abc1234")
        self.assertTrue(out[0]["auth"]["token"].endswith("1234"))
        self.assertIn("•", out[0]["auth"]["token"])

    def test_redact_keeps_env_var_name_intact(self):
        srv = reg.MCPServer.model_validate(_http_server(
            auth={"type": "bearer", "token_env_var": "MY_VAR"},
        ))
        out = reg.redact_for_api([srv])
        self.assertEqual(out[0]["auth"]["token_env_var"], "MY_VAR")
        # No literal token, nothing to mask
        self.assertIsNone(out[0]["auth"].get("token"))

    def test_redact_short_tokens_get_full_mask(self):
        srv = reg.MCPServer.model_validate(_http_server(
            auth={"type": "bearer", "token": "abc"},
        ))
        out = reg.redact_for_api([srv])
        self.assertEqual(out[0]["auth"]["token"], "••••")


class CurrentStateAndFallbackTests(unittest.TestCase):

    def setUp(self):
        # Reset registry state
        reg.set_current([])

    def tearDown(self):
        reg.set_current([])

    def test_default_phases_for_unknown_tool(self):
        # No servers loaded -> falls back to ALL_PHASES
        self.assertEqual(set(reg.default_phases_for("ghost_tool")), set(reg.ALL_PHASES))

    def test_default_phases_for_declared_tool_uses_server_default(self):
        srv = reg.MCPServer.model_validate(_http_server(
            id="srv1",
            default_phases=["informational"],
            tools=[_tool(name="t1")],
        ))
        reg.set_current([srv])
        self.assertEqual(reg.default_phases_for("t1"), ["informational"])

    def test_default_phases_for_declared_tool_with_override(self):
        srv = reg.MCPServer.model_validate(_http_server(
            id="srv1",
            default_phases=["informational"],
            tools=[_tool(name="t1", default_phases=["exploitation", "post_exploitation"])],
        ))
        reg.set_current([srv])
        self.assertEqual(set(reg.default_phases_for("t1")), {"exploitation", "post_exploitation"})

    def test_disabled_server_excluded_from_default_phases_lookup(self):
        srv = reg.MCPServer.model_validate(_http_server(
            id="srv1", enabled=False,
            default_phases=["informational"],
            tools=[_tool(name="t1")],
        ))
        reg.set_current([srv])
        # Disabled -> falls through to ALL_PHASES default
        self.assertEqual(set(reg.default_phases_for("t1")), set(reg.ALL_PHASES))


class ParseUserServersTests(unittest.TestCase):

    def test_invalid_payload_returns_error(self):
        valid, errors = reg.parse_user_servers("not a list")
        self.assertEqual(valid, [])
        self.assertTrue(any(e.code == "invalid_payload" for e in errors))

    def test_none_returns_empty_clean(self):
        # Users with no UserSettings row → API returns null mcpServers.
        # Must not raise, must not produce errors.
        valid, errors = reg.parse_user_servers(None)
        self.assertEqual(valid, [])
        self.assertEqual(errors, [])

    def test_empty_list_returns_clean(self):
        valid, errors = reg.parse_user_servers([])
        self.assertEqual(valid, [])
        self.assertEqual(errors, [])

    def test_partial_failure_keeps_valid(self):
        raw = [
            _http_server(id="good", tools=[_tool(name="ok")]),
            {"id": "bad", "transport": "stdio"},  # missing command
        ]
        valid, errors = reg.parse_user_servers(raw)
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0].id, "good")
        self.assertTrue(len(errors) >= 1)

    def test_cross_server_tool_name_collision_rejected(self):
        raw = [
            _http_server(id="a", tools=[_tool(name="shared")]),
            _http_server(id="b", tools=[_tool(name="shared")]),
        ]
        valid, errors = reg.parse_user_servers(raw)
        # First server gets in; second is rejected.
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0].id, "a")
        self.assertTrue(any(e.code == "duplicate_tool_name" for e in errors))


class RegistryMutationTests(unittest.TestCase):

    def setUp(self):
        from prompts import tool_registry as tr
        self.tr = tr
        # Ensure clean state
        tr.remove_mcp_manifest_entries()

    def tearDown(self):
        self.tr.remove_mcp_manifest_entries()

    def test_apply_inserts_tool_entries(self):
        srv = reg.MCPServer.model_validate(_http_server(
            id="ext", tools=[_tool(name="ext_tool")],
        ))
        declared = self.tr.apply_mcp_manifests_to_registry([srv])
        self.assertIn("ext_tool", declared)
        self.assertIn("ext_tool", self.tr.TOOL_REGISTRY)
        self.assertEqual(self.tr.TOOL_REGISTRY["ext_tool"]["purpose"], "Does the thing")

    def test_apply_replaces_previous_set(self):
        s1 = reg.MCPServer.model_validate(_http_server(id="s1", tools=[_tool(name="t1")]))
        s2 = reg.MCPServer.model_validate(_http_server(id="s2", tools=[_tool(name="t2")]))
        self.tr.apply_mcp_manifests_to_registry([s1])
        self.tr.apply_mcp_manifests_to_registry([s2])
        self.assertNotIn("t1", self.tr.TOOL_REGISTRY)
        self.assertIn("t2", self.tr.TOOL_REGISTRY)

    def test_remove_clears_injected_only(self):
        builtin_count_before = len(self.tr.TOOL_REGISTRY)
        srv = reg.MCPServer.model_validate(_http_server(
            id="ext", tools=[_tool(name="ext_tool")],
        ))
        self.tr.apply_mcp_manifests_to_registry([srv])
        self.tr.remove_mcp_manifest_entries()
        # Built-in count restored, ext_tool gone.
        self.assertEqual(len(self.tr.TOOL_REGISTRY), builtin_count_before)
        self.assertNotIn("ext_tool", self.tr.TOOL_REGISTRY)

    def test_insertion_order_is_deterministic(self):
        # Two different input orderings of the same server set must produce
        # the same TOOL_REGISTRY iteration order. This is what keeps the
        # Anthropic system-prompt prefix cache hot across re-applies.
        s1 = reg.MCPServer.model_validate(_http_server(
            id="z_srv", tools=[_tool(name="z_tool")],
        ))
        s2 = reg.MCPServer.model_validate(_http_server(
            id="a_srv", tools=[_tool(name="a_tool")],
        ))
        self.tr.apply_mcp_manifests_to_registry([s1, s2])
        order_a = [k for k in self.tr.TOOL_REGISTRY.keys()
                   if k in self.tr._mcp_injected_keys]

        self.tr.remove_mcp_manifest_entries()

        # Reapply with reversed input order.
        self.tr.apply_mcp_manifests_to_registry([s2, s1])
        order_b = [k for k in self.tr.TOOL_REGISTRY.keys()
                   if k in self.tr._mcp_injected_keys]

        self.assertEqual(order_a, order_b)
        # And the order is the alphabetic-by-id one we promised.
        self.assertEqual(order_a, ["a_tool", "z_tool"])


if __name__ == "__main__":
    unittest.main()

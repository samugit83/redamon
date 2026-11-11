"""GET /kali/toolbox — the Kali catalogue the inbound MCP server serves.

The webapp's `kali_toolbox` tool reads this endpoint and nothing else. It exists
so the MCP layer never holds MCP_AUTH_TOKEN and never speaks to the
kali-sandbox: the catalogue is a constant in THIS image, so the answer costs no
container call and still arrives when the sandbox is stopped.

The behaviours pinned here are the ones whose absence produces a FALSE NEGATIVE:
an empty catalogue reads as "this image ships no tools", which would have an
agent report a capability gap that does not exist. The other is drift: the
catalogue must BE the registry description, not a copy of it, or it will promise
tools the image does not carry.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


def _route(path, method):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return r
    return None


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class RouteRegistrationTests(unittest.TestCase):
    def test_it_is_registered_and_auth_gated(self):
        route = _route("/kali/toolbox", "GET")
        self.assertIsNotNone(route)
        deps = _dep_names(route)
        # The master key only, like /graph/schema-doc (NF-01: the webapp is its
        # only caller). It costs no LLM call, so the LLM token bucket and daily
        # cap must not throttle it.
        self.assertIn("require_configured_master_auth", deps)
        self.assertNotIn("require_internal_auth", deps)
        self.assertNotIn("require_internal_auth_only", deps)

    def test_it_takes_no_arguments(self):
        """No projectId, so there is no tenant data to leak and no ownership
        check to forget. The MCP tool advertises an empty input schema on the
        strength of this."""
        import inspect

        self.assertEqual(list(inspect.signature(api.kali_toolbox).parameters), [])


class CatalogueTests(unittest.IsolatedAsyncioTestCase):
    async def test_it_serves_the_kali_shell_registry_description(self):
        """One source, no second copy. A transcription would drift from the
        image the moment a tool is added or removed.

        The catalogue is embedded verbatim; what follows it is a short note
        correcting the one part written for the in-app agent (see
        McpCallerNoteTests)."""
        from prompts.tool_registry import TOOL_REGISTRY

        expected = TOOL_REGISTRY["kali_shell"]["description"].strip()
        body = _body(await api.kali_toolbox())
        self.assertIn(expected, body["toolbox"])

    async def test_the_catalogue_is_categorised_and_substantial(self):
        """Guards the registry entry being gutted to a stub: the tool's whole
        value is that an agent can tell what exists before planning around it."""
        body = _body(await api.kali_toolbox())
        toolbox = body["toolbox"]
        self.assertGreater(len(toolbox), 2000)
        for category in ("Exploitation:", "Password cracking:", "Windows/AD:"):
            self.assertIn(category, toolbox)

    async def test_a_missing_description_is_an_error_not_an_empty_catalogue(self):
        """An empty string would read as "no tools installed". A 500 makes the
        MCP tool raise, which is the honest answer."""
        from prompts import tool_registry

        with mock.patch.dict(tool_registry.TOOL_REGISTRY, {"kali_shell": {}}, clear=False):
            resp = await api.kali_toolbox()
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("toolbox", _body(resp))

    async def test_a_renamed_registry_key_is_an_error_not_an_empty_catalogue(self):
        from prompts import tool_registry

        registry = {k: v for k, v in tool_registry.TOOL_REGISTRY.items() if k != "kali_shell"}
        with mock.patch.object(tool_registry, "TOOL_REGISTRY", registry):
            resp = await api.kali_toolbox()
        self.assertEqual(resp.status_code, 500)


if __name__ == "__main__":
    unittest.main()


class RouteBindingTests(unittest.IsolatedAsyncioTestCase):
    """REGRESSION: the decorator bound to a HELPER, not the handler.

    A helper was inserted between `@app.get("/kali/toolbox")` and
    `async def kali_toolbox()`, so FastAPI routed the helper. GET /kali/toolbox
    answered 200 with a bare JSON string instead of {"toolbox": ...}, the second
    section never shipped, and the MCP tool failed with "The Kali toolbox could
    not be loaded."

    Every existing test in this file passed throughout, because they all call
    `api.kali_toolbox()` as a plain function and never touch the routing. The
    agent-side log said 200 OK. Found by a parallel session probing the real
    endpoint from inside the webapp container.
    """

    def test_the_route_resolves_to_the_handler(self):
        route = _route("/kali/toolbox", "GET")
        self.assertIsNotNone(route)
        self.assertIs(
            route.endpoint, api.kali_toolbox,
            f"/kali/toolbox is bound to {route.endpoint.__name__}, not kali_toolbox",
        )

    async def test_the_routed_endpoint_answers_the_documented_shape(self):
        """What the webapp actually parses: an OBJECT with a string `toolbox`.
        kaliClient.ts rejects anything else, so a bare string is a hard failure."""
        route = _route("/kali/toolbox", "GET")
        body = _body(await route.endpoint())
        self.assertIsInstance(body, dict, "the body must be an object, not a bare string")
        self.assertIsInstance(body.get("toolbox"), str)
        self.assertIn("kali_shell", body["toolbox"])
        self.assertIn("NOTE FOR MCP CALLERS", body["toolbox"])

    def test_no_kali_route_is_bound_to_a_private_helper(self):
        """The same mistake in any of the other kali routes."""
        for r in api.app.routes:
            path = getattr(r, "path", "")
            if path.startswith("/kali"):
                name = getattr(r, "endpoint", None).__name__
                self.assertFalse(
                    name.startswith("_"),
                    f"{path} is bound to private helper {name}",
                )


class McpCallerNoteTests(unittest.IsolatedAsyncioTestCase):
    """The catalogue is written for the IN-APP agent and ends by telling the
    reader not to use kali_shell for curl, nmap, nuclei, httpx, ffuf and the
    rest, because that agent has dedicated tools for them.

    An MCP caller has no dedicated tools. kali_exec is the only way it runs
    anything, so read literally that line tells it not to use the one tool it
    has. The fix is a note appended after the catalogue rather than a second,
    forked copy of it.
    """

    async def test_the_catalogue_still_ships_verbatim(self):
        from prompts.tool_registry import TOOL_REGISTRY

        body = _body(await api.kali_toolbox())
        self.assertIn(TOOL_REGISTRY["kali_shell"]["description"].strip(), body["toolbox"])

    async def test_the_dedicated_tool_advice_is_corrected_for_this_surface(self):
        toolbox = _body(await api.kali_toolbox())["toolbox"]
        self.assertIn("NOTE FOR MCP CALLERS", toolbox)
        self.assertIn("You do not", toolbox)
        # It has to name the tools the catalogue steered the caller away from.
        for tool in ("curl", "nmap", "nuclei", "httpx", "ffuf"):
            self.assertIn(tool, toolbox.split("NOTE FOR MCP CALLERS")[1])

    async def test_it_states_the_shell_is_unrestricted_and_capped(self):
        toolbox = _body(await api.kali_toolbox())["toolbox"]
        tail = toolbox.split("NOTE FOR MCP CALLERS")[1]
        self.assertIn("no allowlist", tail)
        self.assertIn("300 seconds", tail)

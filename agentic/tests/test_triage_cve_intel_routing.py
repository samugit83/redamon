"""Triage's `cve_intel` call runs in the sandbox of the person who ran triage (group 1, S12,
WI-S12-2; I11, T5).

A triage run reads and publishes the TENANT's graph (the project's owner, `user_id`), but the
person it is for is `actor_user_id` (who pressed Start, or the MCP token's owner), with the
admin behind an act-as in `real_actor_user_id`. Its one Kali call, `cve_intel`, carries the
owner's ProjectDiscovery key as an argument, so it must run in that person's sandbox:

- `acquire(actor, project_id=None, check_project=<project>, kind="triage")`: the gateway
  checks the person may use the project, but no mount is asked, so a running sandbox that
  lacks the project is served as it is (asking for the mount would replace it and end its
  sessions and tunnels); in the `act_as` view when an admin
  acts as the person (TD-26), through that handle's own client (its own bearer); the owner's
  key reaches only that handle's sandbox, never the tenant's, never the old shared address
  (MCP_NETWORK_RECON_URL with MCP_AUTH_TOKEN, set here to show neither is read);
- one lease for a whole refresh, released at its end;
- a refused or unavailable sandbox degrades to the class priors (no call at all), as any
  intel failure does.

The router's public functions are stubbed.

Run: ./agentic/run_tests.sh tests/test_triage_cve_intel_routing.py
"""
import asyncio
import os
import sys
import unittest
from contextlib import contextmanager
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
from cypherfix_triage import intel  # noqa: E402

OWNER_KEY = "pdcp-owner-key-goes-only-to-the-actors-sandbox"
SHARED_TOKEN = "shared-mcp-token"


def handle(person, view=contract.VIEW_OWN, instance="a1b2c3"):
    return router.SandboxHandle(
        user_id=person, view=view, instance=instance,
        host=contract.container_name(person, view, instance),
        token="tok-" + person + "-" + "x" * 20, tunnel_token="", ports=contract.PORTS,
        reverse_port=4444)


class FakeTool:
    def __init__(self, name, handle):
        self.name = name
        self.handle = handle
        self.calls = []

    async def ainvoke(self, args):
        self.calls.append(args)
        return '[{"cve_id": "CVE-2021-41773", "is_kev": true}]'


class Router:
    """The router's public interface, recording who asked for which sandbox."""

    def __init__(self, refuse=None):
        self.refuse = refuse
        self.acquired = []
        self.released = []
        self.tools = []

    async def acquire(self, user_id, *, project_id, kind, wait=True, view=None, check_project=None):
        seen_view = router.sandbox_view() if view is None else view
        self.acquired.append({"user_id": user_id, "project_id": project_id, "kind": kind,
                              "check_project": check_project,
                              "view": seen_view, "bound_person": router.sandbox_user()})
        if self.refuse:
            raise router.SandboxUnavailable(self.refuse)
        return handle(user_id, seen_view)

    async def release(self, h):
        self.released.append(h)

    async def tool_for(self, name, h):
        tool = FakeTool(name, h)
        self.tools.append(tool)
        return tool

    @contextmanager
    def installed(self):
        with mock.patch.object(router, "acquire", self.acquire), \
                mock.patch.object(router, "release", self.release), \
                mock.patch.object(router, "tool_for", self.tool_for):
            yield self


class FakeMCPClient:
    """langchain_mcp_adapters' MultiServerMCPClient, recording its config: a client on a fixed address must never be built."""
    configs = []

    def __init__(self, config):
        FakeMCPClient.configs.append(config)

    async def get_tools(self):
        return [FakeTool(intel.ALLOWED_TOOL, None)]


def run(coro):
    return asyncio.run(coro)


class TestPerUser(unittest.TestCase):

    def test_the_actors_sandbox_never_the_tenants(self):
        """bob ran triage on alice's project: bob's sandbox gets the call and the owner's key."""
        r = Router()
        loader = intel.CveIntel(pdcp_api_key=OWNER_KEY, actor_user_id="bob", project_id="p1")
        with r.installed():
            raw = run(loader._call_tool("CVE-2021-41773"))
        self.assertIn("CVE-2021-41773", raw)
        self.assertEqual([a["user_id"] for a in r.acquired], ["bob"])
        self.assertEqual(r.acquired[0]["kind"], "triage")
        # Checked, never mounted: a mount would replace a running sandbox without it.
        self.assertIsNone(r.acquired[0]["project_id"])
        self.assertEqual(r.acquired[0]["check_project"], "p1")
        self.assertEqual(r.acquired[0]["view"], contract.VIEW_OWN)
        (tool,) = r.tools
        self.assertEqual(tool.name, intel.ALLOWED_TOOL)
        self.assertEqual(tool.handle.user_id, "bob")
        self.assertEqual(tool.calls, [{"args": "CVE-2021-41773", "api_key": OWNER_KEY}])
        self.assertEqual(len(r.released), 1)

    def test_act_as_uses_the_persons_act_as_view(self):
        """An admin acting as bob: bob's act_as sandbox, never bob's own, never the admin's."""
        r = Router()
        loader = intel.CveIntel(pdcp_api_key=OWNER_KEY, actor_user_id="bob",
                                real_actor_user_id="admin", project_id="p1")
        with r.installed():
            run(loader._call_tool("CVE-2021-41773"))
        self.assertEqual(r.acquired[0]["user_id"], "bob")
        self.assertEqual(r.acquired[0]["view"], contract.VIEW_ACT_AS)
        self.assertEqual(r.tools[0].handle.view, contract.VIEW_ACT_AS)
        self.assertNotIn("admin", [a["user_id"] for a in r.acquired])

    def test_the_person_is_bound_during_the_call_and_unbound_after(self):
        r = Router()
        loader = intel.CveIntel(actor_user_id="bob", project_id="p1")
        with r.installed():
            run(loader._call_tool("CVE-2021-41773"))
        self.assertEqual(r.acquired[0]["bound_person"], "bob")
        self.assertFalse(router.current_sandbox_user.get(), "unbound after the call")
        self.assertFalse(router.current_sandbox_acting.get())

    def test_the_old_shared_address_and_token_are_never_used(self):
        r = Router()
        FakeMCPClient.configs = []
        loader = intel.CveIntel(pdcp_api_key=OWNER_KEY, actor_user_id="bob", project_id="p1")
        env = {"MCP_NETWORK_RECON_URL": "http://kali-sandbox:8000/sse", "MCP_AUTH_TOKEN": SHARED_TOKEN}
        with r.installed(), \
                mock.patch.dict(os.environ, env), \
                mock.patch("langchain_mcp_adapters.client.MultiServerMCPClient", FakeMCPClient):
            run(loader._call_tool("CVE-2021-41773"))
        self.assertEqual(FakeMCPClient.configs, [], "no client on the shared address")

    def test_one_lease_for_a_whole_refresh(self):
        r = Router()
        ids = [f"CVE-2021-{n:05d}" for n in range(1, 2 * intel.BATCH_SIZE + 2)]   # three batches
        loader = intel.CveIntel(pdcp_api_key=OWNER_KEY, actor_user_id="bob", project_id="p1")
        with r.installed():
            run(loader._fetch(ids))
        self.assertEqual(len(r.acquired), 1)
        self.assertEqual(len(r.released), 1)
        self.assertEqual(sum(len(t.calls) for t in r.tools), 3)
        self.assertTrue(all(t.handle.user_id == "bob" for t in r.tools))

    def test_a_refused_or_unavailable_sandbox_falls_back_to_priors(self):
        for reason in ("refused", "ram", "hard", "error", "no_user", "stopped"):
            with self.subTest(reason=reason):
                r = Router(refuse=reason)
                FakeMCPClient.configs = []
                loader = intel.CveIntel(pdcp_api_key=OWNER_KEY, actor_user_id="bob", project_id="p1")
                with r.installed(), \
                        mock.patch("langchain_mcp_adapters.client.MultiServerMCPClient", FakeMCPClient):
                    self.assertEqual(run(loader._call_tool("CVE-2021-41773")), "")
                    self.assertEqual(run(loader._fetch(["CVE-2021-41773"])), {})
                self.assertEqual(r.tools, [])
                self.assertEqual(FakeMCPClient.configs, [], "never the shared sandbox instead")

    def test_hostile_arguments_never_reach_the_router(self):
        r = Router()
        loader = intel.CveIntel(actor_user_id="bob", project_id="p1")
        with r.installed():
            self.assertEqual(run(loader._call_tool("CVE-2021-41773; id")), "")
        self.assertEqual(r.acquired, [])


class TestOrchestratorPassesThePerson(unittest.TestCase):
    """TriageOrchestrator hands CveIntel the run's person, its act-as admin and the project;
    the tenant (`user_id`) only keys the graph."""

    def _load(self, **kwargs):
        from cypherfix_triage.orchestrator import TriageOrchestrator

        made = []

        class Recorder:
            def __init__(self, **kw):
                made.append(kw)
                self.intel_date = ""
                self.refreshed = 0

            async def load(self, cve_ids, graph_client):
                return {}

        orch = TriageOrchestrator(user_id="alice", project_id="p1", callback=None, **kwargs)
        with mock.patch("cypherfix_triage.orchestrator.CveIntel", Recorder), \
                mock.patch.object(TriageOrchestrator, "_graph_client", lambda self: object()):
            run(orch._load_intel([{"cve_ids": ["CVE-2021-41773"]}],
                                 {"settings": {"user_settings": {"pdcpApiKey": OWNER_KEY}}}))
        return made

    def test_collaborators_run(self):
        (kw,) = self._load(actor_user_id="bob")
        self.assertEqual(kw["actor_user_id"], "bob")
        self.assertIsNone(kw["real_actor_user_id"])
        self.assertEqual(kw["project_id"], "p1")
        self.assertEqual(kw["pdcp_api_key"], OWNER_KEY)

    def test_act_as_run(self):
        (kw,) = self._load(actor_user_id="bob", real_actor_user_id="admin")
        self.assertEqual((kw["actor_user_id"], kw["real_actor_user_id"]), ("bob", "admin"))

    def test_owners_own_run(self):
        """No actor named: the run is the owner's, so the owner's own sandbox."""
        (kw,) = self._load()
        self.assertEqual(kw["actor_user_id"], "alice")


if __name__ == "__main__":
    unittest.main()

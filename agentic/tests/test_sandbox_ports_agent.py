"""
What the agent is told about its person's reverse-shell port and tunnels (follow-up FU,
items FU-10 to FU-19, decisions D-E, D-F, D-G).

- D-E: the prompt describes the person's sandbox from the first step of every message:
  the run's handle, else the instance the agent last learned for that person and view (an
  ensure answer, or the gateway's list read without starting one), else "not known yet".
  The LHOST/LPORT gate never asks while the sandbox is not known.
- D-F: with no tunnel on and a pool port, LPORT is the pool port wherever the block shows
  it, and the gate counts it as present; with neither, only BIND (or a tunnel) is offered.
- D-G: a call that lands on a new instance says so first, with its port.
- FU-15/16: chisel is ACTIVE only when the sandbox reports it on; an act-as sandbox or a
  restart is never reported as a bad token.
- FU-17: a sandbox's tool servers are dialled with no redirect, and their answers are read
  within a cap.

The webapp gateway is stubbed with httpx.MockTransport; no test dials a sandbox.

Run: ./agentic/run_tests.sh tests/test_sandbox_ports_agent.py
"""
import asyncio
import importlib
import json
import os
import secrets
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
for _p in (_AGENTIC_DIR, _AGENTIC_DIR / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import httpx  # noqa: E402

import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import utils  # noqa: E402
from decision_check import RunActor, current_run_actor  # noqa: E402
from one_sandbox import handle as one_handle  # noqa: E402
from orchestrator_helpers import config as config_mod  # noqa: E402

POOL = 45002
LAN = "192.168.1.50"


def _settings(**values):
    base = {"LHOST": "", "LPORT": None, "BIND_PORT_ON_TARGET": None, "PAYLOAD_USE_HTTPS": False,
            "NGROK_TUNNEL_ENABLED": False, "CHISEL_TUNNEL_ENABLED": False}
    base.update(values)
    return mock.patch.object(utils, "get_setting", side_effect=lambda k, d=None: base.get(k, d))


def _handle(**fields):
    return one_handle(**fields)


def _flat(text):
    return " ".join(text.split())


class Gateway:
    """The webapp's internal sandbox routes: one running instance per (person, view), whose
    ensure and list answers carry `reverse_port` (and `reverse_port_state` when set)."""

    def __init__(self):
        self.requests = []
        self.instances = {}
        self.list_ports = True

    def add(self, person, view="own", port=POOL, state="assigned"):
        self.instances[(person, view)] = {
            "instance": contract.new_instance(), "token": secrets.token_urlsafe(32),
            "tunnel_token": secrets.token_urlsafe(32), "port": port, "state": state}
        return self.instances[(person, view)]

    def handler(self, request):
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.path, body))
        path = request.url.path
        if path == contract.INTERNAL_ROUTE_ENSURE:
            view = contract.VIEW_ACT_AS if body.get("actingAs") else contract.VIEW_OWN
            key = (body["userId"], view)
            if key not in self.instances:
                self.add(*key)
            inst = self.instances[key]
            answer = {"user_id": key[0], "view": view, "instance": inst["instance"],
                      "host": contract.container_name(key[0], view, inst["instance"]),
                      "token": inst["token"], "tunnel_token": inst["tunnel_token"],
                      "ports": dict(contract.PORTS), "reverse_port": inst["port"],
                      "projects": ["p1"], "state": "running", "fresh": False,
                      "stop_at": 2e10, "stop_reason": None, "warn": False}
            if inst["state"]:
                answer["reverse_port_state"] = inst["state"]
            return httpx.Response(200, json=answer)
        if path == contract.INTERNAL_ROUTE_LEASE:
            return httpx.Response(200, json={"expires_at": 1e10, "state": "running", "stop_at": 2e10,
                                             "warn": False})
        if path == contract.INTERNAL_ROUTE_RELEASE:
            return httpx.Response(204)
        if path == contract.INTERNAL_ROUTE_LIST:
            entries = []
            for (person, view), inst in self.instances.items():
                entry = {"user_id": person, "view": view, "instance": inst["instance"],
                         "host": contract.container_name(person, view, inst["instance"]),
                         "token": inst["token"], "state": "running"}
                if self.list_ports:
                    entry["reverse_port"] = inst["port"]
                    if inst["state"]:
                        entry["reverse_port_state"] = inst["state"]
                entries.append(entry)
            return httpx.Response(200, json={"sandboxes": entries})
        return httpx.Response(404)

    def paths(self):
        return [p for _m, p, _b in self.requests]


class RouterCase(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.gateway = Gateway()
        router._reset()
        utils._forget_all_tunnel_status()
        patches = [
            mock.patch.object(router, "_transport", httpx.MockTransport(self.gateway.handler)),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", "http://webapp.test:3000"),
            mock.patch.dict(os.environ, {"HOST_LAN_IP": LAN}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    async def asyncTearDown(self):
        await router._settle_lookups()
        await router._shutdown()
        router._reset()
        utils._forget_all_tunnel_status()

    def actor(self, user_id, actor_id=None, session_id="chat-1"):
        token = current_run_actor.set(RunActor(user_id=user_id, tenant_id=user_id, project_id="p1",
                                               session_id=session_id, actor_id=actor_id))
        self.addCleanup(current_run_actor.reset, token)


# =============================================================================
# D-E: the first step of a message knows the sandbox
# =============================================================================

class TheFirstStepKnowsTheSandbox(RouterCase):

    async def test_a_known_instance_without_a_handle_gives_the_pool_port_and_no_question(self):
        """Message 1 used a Kali tool; message 2's first step has no handle yet, and still
        shows the pool port as LPORT with no forced question."""
        self.actor("bob")
        async with router.run_scope("chat-1"):
            await router.acquire("bob", project_id="p1", kind="run")
        async with router.run_scope("chat-1"):
            self.assertIsNone(router.current_handle(), "message 2 has made no Kali call yet")
            with _settings(LHOST="203.0.113.9"):
                text = utils.get_session_config_prompt()
                complete = config_mod.is_session_config_complete()
        self.assertIn("Mode: REVERSE", text)
        self.assertIn(f"set LPORT {POOL}", text)
        self.assertNotIn("PUBLISHES NO PORT", text)
        self.assertNotIn("PAYLOAD DIRECTION NOT CONFIGURED", text)
        self.assertEqual(complete, (True, []))

    async def test_a_new_agent_process_learns_the_instance_from_the_list_without_starting_one(self):
        """No ensure in this process (the webapp warmed the sandbox up): the run's start
        looks the instance up in the list, and the first prompt shows its port."""
        self.gateway.add("bob")
        self.actor("bob")
        async with router.run_scope("chat-1"):
            await router._settle_lookups()
            with _settings(LHOST="203.0.113.9"):
                text = utils.get_session_config_prompt()
        self.assertIn(f"set LPORT {POOL}", text)
        self.assertEqual(self.gateway.paths(), [contract.INTERNAL_ROUTE_LIST], "nothing was started")

    async def test_the_list_never_gives_another_persons_or_views_instance(self):
        self.gateway.add("alice", port=45007)
        self.gateway.add("bob", view="act_as", port=45008)
        self.actor("bob")
        async with router.run_scope("chat-1"):
            await router._settle_lookups()
            self.assertIsNone(router.known_sandbox())
            with _settings(LHOST="203.0.113.9"):
                text = utils.get_session_config_prompt()
        self.assertNotIn("45007", text)
        self.assertNotIn("45008", text)
        self.assertIn("not known yet", text)

    async def test_an_act_as_run_reads_the_act_as_instance_only(self):
        self.gateway.add("bob", port=45007)
        self.gateway.add("bob", view="act_as", port=45008)
        self.actor("bob", actor_id="admin-1")
        async with router.run_scope("chat-1"):
            await router._settle_lookups()
            known = router.known_sandbox()
        self.assertEqual((known.view, known.reverse_port), ("act_as", 45008))

    async def test_a_list_entry_without_a_port_is_unknown_not_none(self):
        """An orchestrator older than D-B lists no port: "not known yet", never "no port"."""
        self.gateway.add("bob")
        self.gateway.list_ports = False
        self.actor("bob")
        async with router.run_scope("chat-1"):
            await router._settle_lookups()
            with _settings(LHOST="203.0.113.9"):
                text = utils.get_session_config_prompt()
                complete = config_mod.is_session_config_complete()
        self.assertIn("not known yet", text)
        self.assertNotIn("NO DIRECT REVERSE SHELL", text)
        self.assertEqual(complete, (True, []))

    async def test_a_stopped_instance_is_forgotten(self):
        self.actor("bob")
        async with router.run_scope("chat-1"):
            await router.acquire("bob", project_id="p1", kind="run")
        await router.drop("bob")
        self.assertIsNone(router.known_sandbox())


class NothingKnownYet(unittest.TestCase):

    def setUp(self):
        router._reset()
        self.addCleanup(router._reset)

    def test_an_unknown_sandbox_says_not_known_yet_and_asks_nothing(self):
        with _settings(LHOST="203.0.113.9", LPORT=4444), \
                mock.patch.object(router, "current_handle", lambda project_id=None: None):
            text = utils.get_session_config_prompt()
            complete = config_mod.is_session_config_complete()
        self.assertIn("Your Kali sandbox: not known yet.", text)
        self.assertIn("do NOT ask the user for LHOST or LPORT", _flat(text))
        self.assertNotIn("PUBLISHES NO PORT", text)
        self.assertNotIn("NO DIRECT REVERSE SHELL", text)
        self.assertNotIn("ask_user", text)
        self.assertEqual(complete, (True, []))

    def test_the_gate_asks_nothing_while_the_sandbox_is_unknown(self):
        think_node = importlib.import_module("orchestrator_helpers.nodes.think_node")

        with _settings(), mock.patch.object(router, "current_handle", lambda project_id=None: None):
            self.assertEqual(think_node.missing_session_params([]), [])


# =============================================================================
# D-F: the pool port is LPORT
# =============================================================================

class ThePoolPortIsLport(unittest.TestCase):

    def setUp(self):
        router._reset()
        self.addCleanup(router._reset)
        utils._forget_all_tunnel_status()
        self.addCleanup(utils._forget_all_tunnel_status)

    def render(self, sandbox, **settings):
        with _settings(**settings), \
                mock.patch.object(router, "current_handle", lambda project_id=None: sandbox), \
                mock.patch.dict(os.environ, {"HOST_LAN_IP": LAN}):
            return utils.get_session_config_prompt(), config_mod.is_session_config_complete()

    def test_the_command_block_uses_the_pool_port_not_the_projects(self):
        text, complete = self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9", LPORT=4444)
        self.assertIn(f"set LPORT {POOL}", text)
        self.assertIn(f"203.0.113.9:{POOL}", text, "the diagram")
        self.assertIn(f"LHOST=203.0.113.9 LPORT={POOL}", text, "the msfvenom line")
        self.assertNotIn("set LPORT 4444", text)
        self.assertNotIn("LPORT=4444", text)
        self.assertIn("The project's LPORT setting (`4444`) does not apply", _flat(text))
        self.assertEqual(complete, (True, []))

    def test_an_empty_project_lport_is_complete_with_a_pool_port(self):
        """The norm (LPORT empty): no "enter LPORT" question on every exploit."""
        _text, complete = self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9")
        self.assertEqual(complete, (True, []))

    def test_without_lhost_only_lhost_is_asked_and_lport_is_the_pool_port(self):
        text, complete = self.render(_handle(reverse_port=POOL))
        self.assertEqual(complete, (False, ["LHOST"]))
        self.assertIn(f"use LPORT `{POOL}`", text)
        self.assertIn(LAN, text)

    def test_the_post_exploitation_text_names_the_values_and_the_old_handler(self):
        text, _ = self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9")
        flat = _flat(text)
        self.assertIn("`jobs -k <id>`", flat)
        self.assertIn(f"`setg LPORT {POOL}`", flat)
        self.assertIn("`setg LHOST 203.0.113.9`", flat)
        self.assertIn("4433", flat)

    def test_one_port_serves_every_chat_and_a_running_handler_is_reused(self):
        flat = _flat(self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9")[0])
        self.assertIn("One reverse port for all of this person's chats", flat)
        self.assertIn("reuse it (do not start a second one)", flat)

    def test_the_removed_wait_tool_is_never_named(self):
        for sandbox, settings in ((_handle(reverse_port=POOL), {"LHOST": "203.0.113.9"}),
                                  (_handle(), {"BIND_PORT_ON_TARGET": 4444})):
            text, _ = self.render(sandbox, **settings)
            self.assertNotIn("msf_wait_for_session", text)
            self.assertIn("sessions -l", text)

    def test_the_dropper_text_offers_no_second_port(self):
        flat = _flat(self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9")[0])
        self.assertIn("Never set SRVHOST/SRVPORT", flat)
        self.assertIn("CMDSTAGER::FLAVOR printf", flat)
        self.assertNotIn("set SRVPORT", flat)


# =============================================================================
# FU-13: no pool port and no tunnel: BIND only
# =============================================================================

class NoPortNoTunnelIsBindOnly(ThePoolPortIsLport):

    def test_a_configured_reverse_project_gets_no_reverse_instructions(self):
        text, complete = self.render(_handle(reverse_port_state="no_pool"),
                                     LHOST="203.0.113.9", LPORT=4444, BIND_PORT_ON_TARGET=4444)
        self.assertIn("Mode: BIND", text)
        self.assertNotIn("Mode: REVERSE", text)
        self.assertNotIn("set LHOST", text)
        self.assertNotIn("reverse_tcp`", text)
        self.assertIn("NO DIRECT REVERSE SHELL", text)
        self.assertEqual(complete, (True, []))

    def test_without_a_bind_port_it_asks_for_bind_or_a_tunnel_only(self):
        text, complete = self.render(_handle(reverse_port_state="no_pool"), LHOST="203.0.113.9", LPORT=4444)
        flat = _flat(text)
        self.assertEqual(complete, (False, ["BIND_PORT_ON_TARGET"]))
        self.assertIn("**A tunnel**, for a reverse payload", flat)
        self.assertNotIn("REVERSE** (target connects back to you)", flat)
        self.assertNotIn(LAN, flat)

    def test_pool_full_and_no_pool_say_different_things(self):
        full = _flat(self.render(_handle(reverse_port_state="pool_full"))[0])
        none = _flat(self.render(_handle(reverse_port_state="no_pool"))[0])
        self.assertIn("the port pool is full", full)
        self.assertNotIn("the port pool is full", none)
        self.assertIn("no port pool is configured", none)
        self.assertNotIn("no port pool is configured", full)

    def test_an_older_orchestrators_4444_is_no_port_with_no_reason(self):
        flat = _flat(self.render(_handle())[0])
        self.assertIn("your Kali sandbox has no reverse-shell port, and no tunnel", flat)

    def test_a_bind_answer_satisfies_the_gate(self):
        think_node = importlib.import_module("orchestrator_helpers.nodes.think_node")

        qa = [{"question": {"question": "Please provide ...: BIND_PORT_ON_TARGET"},
               "answer": {"answer": "4444"}}]
        with _settings(LHOST="203.0.113.9"), \
                mock.patch.object(router, "current_handle", lambda project_id=None: _handle(reverse_port_state="no_pool")):
            self.assertEqual(think_node.missing_session_params([]), ["BIND_PORT_ON_TARGET"])
            self.assertEqual(think_node.missing_session_params(qa), [])
            question = think_node.session_params_question(["BIND_PORT_ON_TARGET"], "exploitation")
        self.assertIn("turn on a tunnel", question["context"])


# =============================================================================
# FU-12: post-exploitation gets the block
# =============================================================================

class PostExploitationGetsTheBlock(unittest.TestCase):

    def test_statefull_post_exploitation_needs_the_payload_settings(self):
        from prompts import session_config_needed

        self.assertTrue(session_config_needed("post_exploitation", True, "cve_exploit"))
        self.assertFalse(session_config_needed("post_exploitation", False, "cve_exploit"))

    def test_the_post_exploitation_tools_carry_the_block(self):
        import prompts

        with mock.patch.object(prompts, "get_session_config_prompt", return_value="SESSION-CONFIG-BLOCK"), \
                mock.patch.object(prompts, "get_allowed_tools_for_phase", return_value=["metasploit_console"]), \
                mock.patch.object(prompts, "build_kali_install_prompt", return_value=""), \
                mock.patch.object(prompts, "build_tool_availability_table", return_value=""), \
                mock.patch.object(prompts, "build_informational_tool_descriptions", return_value=""):
            text = prompts.get_phase_tools("post_exploitation", True, "statefull", "cve_exploit")
        self.assertIn("SESSION-CONFIG-BLOCK", text)


# =============================================================================
# FU-15 / FU-16: tunnels from the sandbox's own status, and honest texts
# =============================================================================

class TunnelsFromTheSandbox(ThePoolPortIsLport):

    def setUp(self):
        super().setUp()
        # The tunnel state is the sandbox's: the webapp's stored configuration is never asked.
        legacy = mock.patch("requests.get", side_effect=OSError("the webapp was asked"))
        legacy.start()
        self.addCleanup(legacy.stop)

    def seed(self, sandbox, status):
        import time
        utils._tunnel_status[sandbox.key] = (time.monotonic(), status)

    def test_chisel_is_active_only_when_the_sandbox_says_on(self):
        sandbox = _handle(reverse_port=POOL)
        webapp = mock.Mock(status_code=200, json=lambda: {"chiselServerUrl": "https://vps.example:8443"})
        webapp.raise_for_status = lambda: None
        with mock.patch("requests.get", return_value=webapp) as legacy, \
                mock.patch.object(router, "current_handle", lambda project_id=None: sandbox):
            self.seed(sandbox, {"chisel": {"active": True, "status": "error: remote port 4444 refused",
                                           "host": "vps.example"}, "ngrok": {"active": False}})
            self.assertIsNone(utils._query_chisel_tunnel(), "a refused remote port is no tunnel")
            self.seed(sandbox, {"chisel": {"active": False}, "ngrok": {"active": False}})
            self.assertIsNone(utils._query_chisel_tunnel(), "the database says nothing about the sandbox")
            self.seed(sandbox, {"chisel": {"active": True, "status": "on", "host": "vps.example"}})
            self.assertEqual(utils._query_chisel_tunnel(),
                             {"host": "vps.example", "port": 4444, "hostname": "vps.example"})
        legacy.assert_not_called()

    def test_ngrok_with_a_status_other_than_on_is_not_active(self):
        data = {"ngrok": {"active": True, "status": "error: auth", "host": "0.tcp.ngrok.io", "port": 14444}}
        self.assertEqual(utils.tunnels_from_status(data), (None, None))
        data["ngrok"]["status"] = "on"
        self.assertEqual(utils.tunnels_from_status(data)[0]["port"], 14444)

    def test_a_failed_chisel_is_reported_failed_and_the_pool_port_is_used(self):
        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"chisel": {"active": True, "status": "error: remote port refused", "host": "vps.example"}})
        text, complete = self.render(sandbox, LHOST="203.0.113.9", CHISEL_TUNNEL_ENABLED=True)
        flat = _flat(text)
        self.assertIn("Chisel Tunnel: FAILED", flat)
        self.assertNotIn("Chisel Tunnel: ACTIVE", flat)
        self.assertIn(f"set LPORT {POOL}", flat)
        self.assertEqual(complete, (True, []))

    def test_an_act_as_sandbox_is_not_reported_as_a_bad_token(self):
        text, _ = self.render(_handle(view="act_as", reverse_port=POOL), LHOST="203.0.113.9",
                              NGROK_TUNNEL_ENABLED=True, CHISEL_TUNNEL_ENABLED=True)
        flat = _flat(text)
        self.assertIn("ngrok Tunnel: not available", flat)
        self.assertIn("act-as sandbox, which never has a tunnel", flat)
        self.assertNotIn("auth token", flat)
        self.assertNotIn("not set or invalid", flat)
        self.assertIn(f"set LPORT {POOL}", flat)

    def test_a_tunnel_that_is_off_names_the_switch_and_the_restart_not_the_token_alone(self):
        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"ngrok": {"active": False}, "chisel": {"active": False}})
        flat = _flat(self.render(sandbox, NGROK_TUNNEL_ENABLED=True)[0])
        self.assertIn("ngrok Tunnel: OFF", flat)
        self.assertIn("a sandbox restart also turns it off", flat)
        self.assertNotIn("API unreachable", flat)
        # A pool port reaches the sandbox without the tunnel: its LHOST hint is given.
        self.assertIn(LAN, flat)

    def test_tunnel_mode_sets_lport_explicitly_in_every_block_despite_a_pool_port(self):
        """msfconsole starts with `setg LPORT <pool port>` (D-C): through a tunnel, every block
        names the tunnel's LPORT (and ngrok's local bind 4444) itself, or the pool port wins."""
        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"ngrok": {"active": True, "status": "on", "host": "0.tcp.ngrok.io", "port": 14444},
                            "chisel": {"active": False}})
        flat = _flat(self.render(sandbox, NGROK_TUNNEL_ENABLED=True)[0])
        for line in ("set LPORT 14444", "set ReverseListenerBindAddress 127.0.0.1",
                     "set ReverseListenerBindPort 4444", "LPORT=14444 -f elf",
                     "`set LPORT 14444` plus `set ReverseListenerBindAddress 127.0.0.1` and "
                     "`set ReverseListenerBindPort 4444`",
                     "`setg LPORT 14444`, `setg ReverseListenerBindAddress 127.0.0.1` and "
                     "`setg ReverseListenerBindPort 4444`"):
            self.assertIn(line, flat)
        self.assertNotIn(str(POOL), flat)

        self.seed(sandbox, {"ngrok": {"active": False},
                            "chisel": {"active": True, "status": "on", "host": "vps.example"}})
        flat = _flat(self.render(sandbox, CHISEL_TUNNEL_ENABLED=True)[0])
        for line in ("set LPORT 4444", "set ReverseListenerBindPort 4444", "LPORT=4444 -f elf",
                     "`set LPORT 4444` plus", "`setg LPORT 4444`", "`setg LHOST vps.example`"):
            self.assertIn(line, flat)
        self.assertNotIn(str(POOL), flat)

    def test_a_tunnel_not_read_yet_asks_nothing(self):
        text, complete = self.render(_handle(reverse_port=POOL), NGROK_TUNNEL_ENABLED=True)
        self.assertIn("not read yet", text)
        self.assertEqual(complete, (True, []))


# =============================================================================
# D-G: a call on a new instance says so first
# =============================================================================

class TheRestartNote(RouterCase):

    async def test_a_fresh_instance_is_announced_once(self):
        self.actor("bob")
        fresh = _handle(person="bob", reverse_port=POOL, reverse_port_state="assigned", fresh=True)
        note = router.new_instance_note(fresh)
        self.assertTrue(note.startswith("[Kali sandbox started]"))
        self.assertIn("tunnels (ngrok, chisel) are off until the person turns them on again", note)
        self.assertIn(f"`{POOL}`", note)
        self.assertEqual(router.new_instance_note(fresh), "", "one note per instance")

    async def test_a_restart_names_the_lost_sessions_and_the_new_port(self):
        self.actor("bob")
        first = _handle(person="bob", instance="aaaaaa", reverse_port=POOL, reverse_port_state="assigned")
        router.new_instance_note(first)
        second = _handle(person="bob", instance="bbbbbb", reverse_port=45003, reverse_port_state="assigned")
        note = router.new_instance_note(second)
        self.assertTrue(note.startswith("[Kali sandbox restarted]"))
        self.assertIn("sessions, jobs and handlers are gone", note)
        self.assertIn("now `45003` (it was `45002`)", note)
        third = _handle(person="bob", instance="cccccc", reverse_port=45003, reverse_port_state="assigned")
        self.assertIn("unchanged: `45003`", router.new_instance_note(third))

    async def test_another_chat_on_the_old_instance_is_told_too(self):
        self.actor("bob", session_id="chat-a")
        router.new_instance_note(_handle(person="bob", instance="aaaaaa", reverse_port=POOL))
        self.actor("bob", session_id="chat-b")
        router.new_instance_note(_handle(person="bob", instance="aaaaaa", reverse_port=POOL))
        self.actor("bob", session_id="chat-a")
        self.assertIn("[Kali sandbox restarted]",
                      router.new_instance_note(_handle(person="bob", instance="bbbbbb", reverse_port=POOL)))
        self.actor("bob", session_id="chat-b")
        self.assertIn("[Kali sandbox restarted]",
                      router.new_instance_note(_handle(person="bob", instance="bbbbbb", reverse_port=POOL)))

    async def test_an_acquire_on_a_replaced_instance_carries_the_previous_one(self):
        self.actor("bob")
        async with router.run_scope("chat-1"):
            first = await router.acquire("bob", project_id="p1", kind="run")
        del self.gateway.instances[("bob", "own")]
        self.gateway.add("bob", port=45003)
        async with router.run_scope("chat-2"):
            second = await router.acquire("bob", project_id="p1", kind="run")
            note = router.new_instance_note(second)
        self.assertEqual(second.previous[:2], (first.instance, POOL))
        self.assertIn("now `45003` (it was `45002`)", note)

    def _executor(self, answer="uid=0(root)", **handle_fields):
        import tools
        from one_sandbox import route_to

        class Shell:
            name = "kali_shell"
            calls = 0

            async def ainvoke(self, args):
                Shell.calls += 1
                return answer

        route_to(self, {"kali_shell": Shell()}, person="bob", **handle_fields)
        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        executor._all_tools, executor._mcp_tool_names = {}, set()
        patch = mock.patch.object(tools, "is_tool_allowed_in_phase", return_value=True)
        patch.start()
        self.addCleanup(patch.stop)
        return executor, Shell

    async def test_a_chat_call_keeps_its_output_and_carries_the_note_beside_it(self):
        """The note is for the chat's model (the think nodes show it); `output` stays the
        tool's own, byte for byte (round-2 C1)."""
        executor, _ = self._executor(fresh=True, reverse_port=POOL)
        self.actor("bob")
        async with router.run_scope("chat-1"):
            first = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
            second = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
        self.assertEqual(first["output"], "uid=0(root)")
        self.assertTrue(first["sandbox_note"].startswith("[Kali sandbox started]"), first)
        self.assertEqual(second, {"success": True, "output": "uid=0(root)", "error": None})

    async def test_an_exec_or_job_call_carries_no_note_and_leaves_it_for_the_chat(self):
        """kali_exec and background jobs read `output`/`error` themselves; they neither
        get the note nor use up the chat's (round-2 C1, P2)."""
        import tools

        executor, _ = self._executor(fresh=True, reverse_port=POOL)
        self.actor("bob")
        exec_result = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
        self.assertEqual(exec_result, {"success": True, "output": "uid=0(root)", "error": None})
        with tools.bound_sandbox(_handle(person="bob", fresh=True), "job"):
            job_result = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
        self.assertEqual(job_result, {"success": True, "output": "uid=0(root)", "error": None})
        async with router.run_scope("chat-1"):
            chat = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
        self.assertTrue(chat.get("sandbox_note", "").startswith("[Kali sandbox started]"), chat)

    async def test_a_failed_chat_call_carries_no_note_and_keeps_it_for_the_next(self):
        import tools
        from one_sandbox import route_to

        class Shell:
            name = "kali_shell"
            calls = 0

            async def ainvoke(self, args):
                Shell.calls += 1
                if Shell.calls == 1:
                    raise ValueError("bad arguments")
                return "uid=0(root)"

        route_to(self, {"kali_shell": Shell()}, person="bob", fresh=True, reverse_port=POOL)
        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        executor._all_tools, executor._mcp_tool_names = {}, set()
        self.actor("bob")
        with mock.patch.object(tools, "is_tool_allowed_in_phase", return_value=True):
            async with router.run_scope("chat-1"):
                failed = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
                ok = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
        self.assertEqual(failed, {"success": False, "output": None, "error": "bad arguments"})
        self.assertTrue(ok["sandbox_note"].startswith("[Kali sandbox started]"), ok)

    async def test_the_body_sweep_leaves_the_note_for_the_chat(self):
        """The run's own end-of-run `rm` (body_sweep) is read by no model: it must not use up
        the restart note (round 3)."""
        from orchestrator_helpers.body_sweep import sweep_session_bodies

        executor, _ = self._executor(fresh=True, reverse_port=POOL)
        self.actor("bob")
        async with router.run_scope("chat-1"):
            swept = await sweep_session_bodies(
                executor, {"execution_trace": [{"tool_args": {"command": "cat /tmp/rex-abc"}}]})
            chat = await executor.execute("kali_shell", {"command": "id"}, "exploitation")
        self.assertEqual(swept, 1)
        self.assertTrue(chat.get("sandbox_note", "").startswith("[Kali sandbox started]"), chat)

    async def test_kali_exec_failing_on_a_fresh_sandbox_is_failed_with_its_own_error(self):
        """The reviewer's repro (round-2 C1): MCP kali_exec on a cold sandbox, the command
        fails. It is failed/1, its error is the tool's own `[ERROR]` text, and the job log
        starts with it, as before the restart note existed; also after a restart."""
        import tempfile

        import api
        import tools
        from one_sandbox import Client
        from sandbox_route_fakes import WEBAPP, Fleet
        from test_kali_exec_endpoint import _FakeRegistry

        fail = "[ERROR] kali_shell failed: returncode=7, stderr=boom"

        class Shell:
            name = "kali_shell"

            async def ainvoke(self, args):
                return fail

        class Registry(_FakeRegistry):
            async def spawn(self, project_id, tool_name, args, runner, label=None):
                async def keep(*a):
                    self.result = await runner(*a)
                    return self.result
                return await super().spawn(project_id, tool_name, args, keep, label)

        async def run(restart):
            router._reset()
            fleet = Fleet()
            if restart:
                fleet.add("alice")
            else:
                fleet.cold.add(("alice", "own"))
            root = tempfile.mkdtemp()
            registry = Registry(root)
            executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
            executor._all_tools, executor._mcp_tool_names = {}, set()

            async def client_for(handle):
                return Client({"kali_shell": Shell()})

            patches = [
                mock.patch.dict(os.environ, {"WORKSPACE_ROOT": root}),
                mock.patch.object(api, "orchestrator", mock.Mock(tool_executor=executor)),
                mock.patch.object(api.job_runner, "get_registry", return_value=registry),
                mock.patch.object(router, "_transport", fleet.transport()),
                mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
                mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
                mock.patch.object(router, "client_for", client_for),
                mock.patch.object(tools, "is_tool_allowed_in_phase", return_value=True),
            ]
            for p in patches:
                p.start()
            try:
                if restart:
                    await api.kali_exec(api.KaliExecRequest(project_id="p1", command="false", user_id="alice"))
                    for box in fleet.sandboxes:
                        box.state = "stopped"
                    fleet.add("alice")
                    registry.job_id = "c" * 32
                resp = await api.kali_exec(api.KaliExecRequest(project_id="p1", command="false", user_id="alice"))
                body = json.loads(bytes(resp.body).decode())
                log = open(os.path.join(root, "p1", "jobs", f"{registry.job_id}.log")).read()
                return body, registry.result, log
            finally:
                for p in patches:
                    p.stop()
                await router.shutdown()

        for restart in (False, True):
            with self.subTest(restart=restart):
                body, result, log = await run(restart)
                self.assertEqual((body.get("status"), body.get("exit_code")), ("failed", 1), body)
                self.assertEqual(result, {"success": False, "output": None, "error": fail})
                self.assertEqual(log, fail)


# =============================================================================
# FU-17: no redirect, and a capped read
# =============================================================================

class TheSandboxAnswersAreBounded(unittest.IsolatedAsyncioTestCase):

    async def test_a_sandbox_tool_server_redirect_is_not_followed(self):
        from mcp.shared._httpx_utils import create_mcp_http_client
        from tools import _build_system_mcp_servers
        import mcp_registry

        host = contract.container_name("bob", "own", "a1b2c3")
        config, _ = mcp_registry.to_mcp_servers_dict(_build_system_mcp_servers(host, "t" * 43))
        seen = []

        def answer(request):
            seen.append(str(request.url))
            if request.url.host == host:
                return httpx.Response(302, headers={"location": "http://webapp:3000/api/internal/x"})
            return httpx.Response(200, text="followed")

        for sid, entry in config.items():
            # What the MCP SDK uses for the SSE connection: the entry's factory, or its own.
            factory = entry.get("httpx_client_factory", create_mcp_http_client)
            async with factory(headers=entry.get("headers")) as client:
                client._transport = httpx.MockTransport(answer)
                resp = await client.get(entry["url"])
            self.assertEqual(resp.status_code, 302, sid)
        self.assertTrue(seen)
        self.assertFalse([u for u in seen if "webapp" in u], "the agent followed a sandbox's redirect")

    async def test_a_huge_tool_answer_is_cut_with_a_marker(self):
        import output_offload
        import tools
        from one_sandbox import route_to

        size = getattr(tools, "SANDBOX_OUTPUT_MAX_CHARS", 32 * 1024 * 1024) + 1024

        class Flood:
            name = "kali_shell"

            async def ainvoke(self, args):
                return "A" * size

        route_to(self, {"kali_shell": Flood()}, person="bob")
        token = current_run_actor.set(RunActor(user_id="bob", tenant_id="bob", project_id="p1",
                                               session_id="chat-1"))
        self.addCleanup(current_run_actor.reset, token)
        router._reset()
        self.addCleanup(router._reset)
        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        executor._all_tools, executor._mcp_tool_names = {}, set()
        with mock.patch.object(tools, "is_tool_allowed_in_phase", return_value=True), \
                mock.patch.object(output_offload, "maybe_offload", lambda _p, _t, text, override=None: text):
            result = await executor.execute("kali_shell", {"command": "cat big"}, "exploitation")
        out = result["output"]
        self.assertLess(len(out), size)
        self.assertTrue(out.startswith("A" * 1000))
        self.assertIn(f"[OUTPUT TRUNCATED by RedAmon: the Kali sandbox answered {size} characters", out)

    async def test_an_ordinary_large_answer_is_kept_whole(self):
        import tools

        text = "x" * (5 * 1024 * 1024)
        self.assertIs(tools._cap_sandbox_output(text), text)

    async def test_an_oversized_progress_answer_is_not_read(self):
        import tools

        handle = _handle(person="bob")
        big = {"active": True, "output": "B" * (2 * 1024 * 1024), "line_count": 1, "elapsed_seconds": 1}
        small = {"active": True, "output": "line 1", "line_count": 1, "elapsed_seconds": 1}
        answers = [big]
        chunks = []

        def answer(request):
            return httpx.Response(200, json=answers[0])

        real = httpx.AsyncClient

        def client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(answer)
            return real(*args, **kwargs)

        async def callback(tool, chunk, final):
            chunks.append(chunk)

        async def poll():
            task = asyncio.create_task(asyncio.sleep(0.2))
            with mock.patch.object(tools.httpx, "AsyncClient", client), \
                    mock.patch.object(tools, "current_sandbox_handle", lambda project_id=None: handle):
                await tools.PhaseAwareToolExecutor._poll_progress(task, "metasploit_console", callback, 0.05,
                                                                  "sessions")

        await poll()
        self.assertEqual(chunks, [], "a 2 MB progress answer was read")
        answers[0] = small
        await poll()
        self.assertTrue(chunks and "line 1" in chunks[0])


# =============================================================================
# Round 2: the note reaches the chat's model only
# =============================================================================

class TheNoteReachesOnlyTheModel(unittest.IsolatedAsyncioTestCase):

    async def test_the_executor_nodes_keep_the_output_and_store_the_note(self):
        """Both executor paths keep `tool_output` the tool's own (the embedded-error check
        and the stream read it) and store the note beside it."""
        from unittest.mock import AsyncMock, MagicMock

        import project_settings as ps
        from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node
        from orchestrator_helpers.nodes.execute_tool_node import execute_tool_node

        note = "[Kali sandbox started] NOTE"
        result = {"success": True, "output": "[ERROR] boom", "error": None, "sandbox_note": note}
        ex = MagicMock()
        ex.execute = AsyncMock(return_value=result)
        ex.execute_with_progress = AsyncMock(return_value=result)
        config = {"configurable": {"user_id": "u1", "project_id": "p1", "session_id": "s1"}}
        base = {"messages": [], "current_iteration": 1, "current_phase": "exploitation"}
        step = {"tool_name": "execute_nmap", "tool_args": {"args": "-sV 10.0.0.1"}}
        with mock.patch.object(ps, "_settings", dict(ps.DEFAULT_AGENT_SETTINGS)):
            single = await execute_tool_node({**base, "_current_step": dict(step)}, config,
                                             tool_executor=ex, streaming_callbacks={})
            plan = await execute_plan_node({**base, "_current_plan": {"steps": [dict(step)]}}, config,
                                           tool_executor=ex, streaming_callbacks={})
        for got in (single["_current_step"], plan["_current_plan"]["steps"][0]):
            self.assertEqual(got["tool_output"], "[ERROR] boom")
            self.assertEqual(got["sandbox_note"], note)

    def test_the_model_reads_the_note_before_the_untrusted_output(self):
        from prompt_safety import wrap_untrusted

        fireteam = importlib.import_module("orchestrator_helpers.nodes.fireteam_member_think_node")
        note = "[Kali sandbox restarted] NOTE"
        section = fireteam._build_pending_output_section(
            {"_current_step": {"tool_name": "kali_shell", "tool_args": {}, "success": True,
                               "tool_output": "uid=0", "sandbox_note": note}})
        self.assertIn(note, section)
        # RedAmon's own text, outside (and before) the untrusted envelope.
        self.assertLess(section.index(note), section.index("<<<UNTRUSTED_TOOL_OUTPUT"))
        self.assertLess(section.index("<<<UNTRUSTED_TOOL_OUTPUT"), section.index("uid=0"))
        self.assertTrue(wrap_untrusted("x").startswith("<<<UNTRUSTED_TOOL_OUTPUT"))
        self.assertEqual(router.model_note({"tool_output": "x"}), "")
        # The main think node renders both of its pending-output sections the same way.
        source = (_AGENTIC_DIR / "orchestrator_helpers" / "nodes" / "think_node.py").read_text()
        self.assertIn("tool_output=model_note(pending_step)", source)
        self.assertIn("{model_note(s)}{wrap_untrusted(output)}", source)
        self.assertIn("{model_note(s)}{wrap_untrusted(output)}",
                      (_AGENTIC_DIR / "orchestrator_helpers" / "nodes" / "fireteam_member_think_node.py").read_text())


# =============================================================================
# Round 2: a cut answer is never sent again (P4), a drop is not undone (P5)
# =============================================================================

class TheCutAnswer(unittest.IsolatedAsyncioTestCase):

    async def test_the_sandbox_client_cuts_an_oversized_or_compressed_answer(self):
        import gzip

        import mcp_registry

        sent = []

        def answer(request):
            sent.append(request.headers.get("accept-encoding"))
            if request.url.path == "/big":
                return httpx.Response(200, content=b"x" * 2048)
            return httpx.Response(200, content=gzip.compress(b"{}"), headers={"content-encoding": "gzip"})

        with mock.patch.object(mcp_registry, "_system_transport", httpx.MockTransport(answer)), \
                mock.patch.object(mcp_registry, "SYSTEM_ANSWER_MAX_BYTES", 1024):
            for path, reason in (("/big", "too_large"), ("/gz", "encoding")):
                cut = []
                token = mcp_registry.sandbox_answer_cut.set(cut)
                try:
                    async with mcp_registry.system_server_http_client() as client:
                        with self.assertRaises(mcp_registry.SandboxAnswerCut):
                            async with client.stream("GET", f"http://sandbox.test{path}") as resp:
                                async for _chunk in resp.aiter_raw():
                                    pass
                finally:
                    mcp_registry.sandbox_answer_cut.reset(token)
                self.assertEqual(cut, [reason])
        self.assertEqual(sent, ["identity", "identity"])

    async def test_a_cut_answer_fails_once_and_is_never_sent_again(self):
        """The SDK reports a cut stream as a closed connection, which reads as a dead
        session: without the guard the reconnect logic would run the command twice."""
        import mcp_registry
        import tools
        from one_sandbox import route_to

        class Shell:
            name = "kali_shell"
            calls = 0

            async def ainvoke(self, args):
                Shell.calls += 1
                guard = getattr(mcp_registry, "sandbox_answer_cut", None)
                if guard is not None and guard.get() is not None:
                    guard.get().append("too_large")
                raise RuntimeError("Connection closed")

        box = route_to(self, {"kali_shell": Shell()}, person="bob")
        router._reset()
        self.addCleanup(router._reset)
        executor = tools.PhaseAwareToolExecutor.__new__(tools.PhaseAwareToolExecutor)
        executor._all_tools, executor._mcp_tool_names = {}, set()
        with mock.patch.object(tools, "is_tool_allowed_in_phase", return_value=True):
            result = await executor.execute("kali_shell", {"command": "nmap -oX - 10.0.0.0/8"}, "exploitation")
        self.assertEqual(Shell.calls, 1, "the command was sent again")
        self.assertEqual(box.client.reconnects, 0)
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("[ERROR] The Kali sandbox's answer to this tool was larger"))

    async def test_through_the_mcp_sdk_a_cut_answer_is_named_by_the_guard(self):
        """The real SDK path: an SSE session whose tool answer passes the cap ends as a
        closed connection (a "dead session" to the reconnect logic), and the guard says why."""
        from mcp import ClientSession
        from mcp.client.sse import sse_client
        from mcp.types import LATEST_PROTOCOL_VERSION

        import mcp_registry
        import tools

        events: asyncio.Queue = asyncio.Queue()

        async def stream():
            yield b"event: endpoint\ndata: /messages/?session_id=abc\n\n"
            while True:
                event = await events.get()
                if event is None:
                    return
                yield event

        def message(payload):
            return b"event: message\ndata: " + json.dumps(payload).encode() + b"\n\n"

        async def answer(request):
            if request.method == "GET":
                return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=stream())
            body = json.loads(request.content)
            if body.get("method") == "initialize":
                await events.put(message({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
                    "serverInfo": {"name": "fake", "version": "1"}}}))
            elif body.get("method") == "tools/call":
                await events.put(message({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "content": [{"type": "text", "text": "A" * 8192}], "isError": False}}))
            return httpx.Response(202)

        cut = []
        token = mcp_registry.sandbox_answer_cut.set(cut)
        raised = None
        try:
            with mock.patch.object(mcp_registry, "_system_transport", httpx.MockTransport(answer)), \
                    mock.patch.object(mcp_registry, "SYSTEM_ANSWER_MAX_BYTES", 4096):
                try:
                    async with sse_client("http://sandbox.test:8000/sse",
                                          httpx_client_factory=mcp_registry.system_server_http_client) as (r, w):
                        async with ClientSession(r, w) as session:
                            await asyncio.wait_for(session.initialize(), 10)
                            await asyncio.wait_for(session.call_tool("kali_shell", {"command": "id"}), 10)
                except Exception as exc:  # noqa: BLE001 - what the SDK raises is the point
                    raised = exc
        finally:
            mcp_registry.sandbox_answer_cut.reset(token)
            await events.put(None)
        self.assertIsNotNone(raised, "the oversized answer was read")
        self.assertNotIsInstance(raised, asyncio.TimeoutError)
        self.assertEqual(cut, ["too_large"])
        self.assertTrue(tools._is_mcp_transport_error(raised), "why the guard is needed")


class ADropIsNotUndone(RouterCase):

    async def test_a_list_answered_after_a_drop_does_not_bring_the_instance_back(self):
        self.gateway.add("bob")
        gate = asyncio.Event()

        async def slow(request):
            if request.url.path == contract.INTERNAL_ROUTE_LIST:
                await gate.wait()
            return self.gateway.handler(request)

        self.actor("bob")
        with mock.patch.object(router, "_transport", httpx.MockTransport(slow)):
            self.assertIsNone(router.known_sandbox())
            await asyncio.sleep(0.05)
            await router.drop("bob")
            gate.set()
            await router._settle_lookups()
            self.assertIsNone(router.known_sandbox(), "the dropped instance came back from an older list")


# =============================================================================
# Round 2: texts (P1 connecting, P3 listener globals, the one-port rules, wording)
# =============================================================================

class _Texts(unittest.TestCase):
    """The block's text for one sandbox and project settings (no tests of its own)."""

    def setUp(self):
        router._reset()
        self.addCleanup(router._reset)
        utils._forget_all_tunnel_status()
        self.addCleanup(utils._forget_all_tunnel_status)

    def render(self, sandbox, **settings):
        with _settings(**settings), \
                mock.patch.object(router, "current_handle", lambda project_id=None: sandbox), \
                mock.patch.dict(os.environ, {"HOST_LAN_IP": LAN}):
            return utils.get_session_config_prompt(), config_mod.is_session_config_complete()

    def seed(self, sandbox, status):
        import time
        utils._tunnel_status[sandbox.key] = (time.monotonic(), status)


class RoundTwoTexts(_Texts):

    def test_a_connecting_tunnel_asks_nothing_and_is_not_called_off(self):
        sandbox = _handle(reverse_port_state="no_pool")
        self.seed(sandbox, {"chisel": {"active": True, "status": "connecting"}, "ngrok": {"active": False}})
        text, complete = self.render(sandbox, CHISEL_TUNNEL_ENABLED=True)
        self.assertIn("Your tunnel: connecting.", text)
        self.assertNotIn("Chisel Tunnel: OFF", text)
        self.assertNotIn("BIND_PORT_ON_TARGET", text)
        self.assertEqual(complete, (True, []))
        self.assertLess(utils._status_ttl({"chisel": {"status": "connecting"}}), utils._TUNNEL_STATUS_TTL_S)
        self.assertEqual(utils._status_ttl({"chisel": {"status": "on"}}), utils._TUNNEL_STATUS_TTL_S)

    def test_pool_mode_clears_what_a_tunnel_left_in_the_console(self):
        flat = _flat(self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9")[0])
        self.assertIn("unsetg ReverseListenerBindAddress ReverseListenerBindPort set PAYLOAD", flat)
        self.assertIn("`setg LPORT 45002` (after `unsetg ReverseListenerBindAddress ReverseListenerBindPort`", flat)

    def test_every_downloading_cmdstager_flavor_is_named(self):
        for sandbox, settings in ((_handle(reverse_port=POOL), {"LHOST": "203.0.113.9"}),
                                  (_handle(reverse_port_state="no_pool"), {"BIND_PORT_ON_TARGET": 4444})):
            flat = _flat(self.render(sandbox, **settings)[0])
            for flavor in ("wget", "curl", "tftp", "ftp_http", "certutil", "lwprequest",
                           "psh_invokewebrequest", "fetch"):
                self.assertIn(f"`{flavor}`", flat)

    def test_the_target_rule_is_one_rule(self):
        flat = _flat(self.render(_handle(reverse_port=POOL), LHOST="203.0.113.9")[0])
        self.assertNotIn("You MUST first set a Dropper/Staged TARGET", flat)
        self.assertIn("TARGET: pick one that lands the payload with no download from you", flat)
        self.assertIn("a Command target ('Unix Command', 'Windows Command') with a stageless payload", flat)

    def test_chisel_names_only_the_one_port_methods(self):
        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"chisel": {"active": True, "status": "on", "host": "vps.example"}})
        flat = _flat(self.render(sandbox, CHISEL_TUNNEL_ENABLED=True)[0])
        self.assertNotIn("Method A or B", flat)
        self.assertIn("(B1 or B3; never B4, `office_word_hta`, which needs SRVPORT)", flat)

    def test_bind_mode_warns_that_nothing_serves_a_download(self):
        flat = _flat(self.render(_handle(reverse_port_state="no_pool"), BIND_PORT_ON_TARGET=4444)[0])
        self.assertIn("Mode: BIND", flat)
        self.assertIn("**No download from you:** in bind mode nothing of yours serves the target", flat)

    def test_a_null_port_state_is_unknown_never_no_pool(self):
        """A starting instance sends `reverse_port_state: null` until its port is allocated
        (P1 round 2): "not known yet", no question; an absent key is an older orchestrator."""
        self.assertEqual(router._reverse_port_of({"reverse_port": 4444, "reverse_port_state": None}),
                         (4444, None, False))
        self.assertEqual(router._reverse_port_of({"reverse_port": 4444}), (4444, None, True))
        listed = router._listed_handles({"sandboxes": [{
            "user_id": "bob", "view": "own", "instance": "a1b2c3",
            "host": contract.container_name("bob", "own", "a1b2c3"), "token": "t" * 43,
            "state": "running", "reverse_port": 4444, "reverse_port_state": None}]})
        text, complete = self.render(listed[0], LHOST="203.0.113.9")
        self.assertIn("not known yet", text)
        self.assertNotIn("NO DIRECT REVERSE SHELL", text)
        self.assertEqual(complete, (True, []))

    def test_a_failed_chisel_says_each_person_needs_their_own_server(self):
        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"chisel": {"active": True, "status": "error: remote port refused", "host": "vps.example"}})
        flat = _flat(self.render(sandbox, CHISEL_TUNNEL_ENABLED=True)[0])
        self.assertIn("each person needs their own chisel server", flat)

    def test_not_known_yet_stays_true_after_a_retire_mid_run(self):
        text, _ = self.render(None)
        self.assertIn("Your Kali sandbox: not known yet.", text)
        self.assertNotIn("This message has not used a Kali tool", text)


# =============================================================================
# Round 3: the caps agree, a stuck tunnel, the method names
# =============================================================================

class TheCapsAgree(unittest.IsolatedAsyncioTestCase):

    async def test_a_full_answer_at_three_bytes_a_character_sent_twice_passes_the_wire_cap(self):
        """fastmcp sends a `-> str` tool's text twice, JSON-escaped with non-ASCII as raw
        UTF-8: an answer the agent keeps whole (SANDBOX_OUTPUT_MAX_CHARS characters, at 3
        bytes each) must pass the wire cap."""
        import mcp_registry
        import tools

        n = tools.SANDBOX_OUTPUT_MAX_CHARS
        step = 1 << 16
        piece = json.dumps("\u20ac" * step, ensure_ascii=False)[1:-1].encode("utf-8")
        self.assertEqual(len(piece), 3 * step)

        async def body():
            yield b'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"'
            for _ in range(n // step):
                yield piece
            yield b'"}],"structuredContent":{"result":"'
            for _ in range(n // step):
                yield piece
            yield b'"},"isError":false}}\n\n'

        def answer(request):
            return httpx.Response(200, content=body(), headers={"content-type": "text/event-stream"})

        cut, total = [], 0
        token = mcp_registry.sandbox_answer_cut.set(cut)
        try:
            with mock.patch.object(mcp_registry, "_system_transport", httpx.MockTransport(answer)):
                async with mcp_registry.system_server_http_client() as client:
                    async with client.stream("GET", "http://sandbox.test:8000/sse") as resp:
                        async for chunk in resp.aiter_raw():
                            total += len(chunk)
        finally:
            mcp_registry.sandbox_answer_cut.reset(token)
        self.assertEqual(cut, [])
        self.assertGreaterEqual(total, 2 * 3 * n)
        self.assertLessEqual(total, mcp_registry.SYSTEM_ANSWER_MAX_BYTES)


class RoundThreeTexts(_Texts):

    def test_a_tunnel_stuck_connecting_counts_as_off_and_the_pool_port_is_used(self):
        import time

        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"chisel": {"active": True, "status": "connecting"}, "ngrok": {"active": False}})
        utils._connecting_since[(sandbox.key, "chisel")] = time.monotonic() - 60
        text, complete = self.render(sandbox, LHOST="203.0.113.9", CHISEL_TUNNEL_ENABLED=True)
        flat = _flat(text)
        self.assertIn("Chisel Tunnel: did not come up", flat)
        self.assertIn(f"set LPORT {POOL}", flat)
        self.assertNotIn("Your tunnel: connecting.", flat)
        self.assertEqual(complete, (True, []))

    def test_the_connecting_time_is_read_after_read_and_restarts(self):
        key = _handle().key
        utils._note_connecting(key, {"chisel": {"status": "connecting"}})
        first = utils._connecting_since[(key, "chisel")]
        utils._note_connecting(key, {"chisel": {"status": "connecting"}})
        self.assertEqual(utils._connecting_since[(key, "chisel")], first, "kept while connecting")
        utils._note_connecting(key, {"chisel": {"status": "on"}})
        self.assertNotIn((key, "chisel"), utils._connecting_since)
        utils._note_connecting(key, {"chisel": {"status": "connecting"}})
        utils.forget_tunnel_status([key])
        self.assertNotIn((key, "chisel"), utils._connecting_since, "a push starts it anew")

    def test_the_chisel_block_names_no_method_c_or_d(self):
        sandbox = _handle(reverse_port=POOL)
        self.seed(sandbox, {"chisel": {"active": True, "status": "on", "host": "vps.example"}})
        flat = _flat(self.render(sandbox, CHISEL_TUNNEL_ENABLED=True)[0])
        self.assertNotIn("Method C", flat)
        self.assertNotIn("Method D", flat)
        self.assertIn("No web delivery or HTA server through chisel", flat)


if __name__ == "__main__":
    unittest.main()

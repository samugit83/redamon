"""
The capture proxy's egress guard checks the address mitmproxy really dials.

mitmproxy connects to the request's own target (the absolute URL authority, or
the CONNECT target inside a tunnel) and builds a new server connection for it,
while ``Request.pretty_host`` comes from the client's ``Host`` header. A guard
that checks the header can be steered past with ``Host: 1.1.1.1`` to any address,
the per-user sandbox pool, cloud metadata and RedAmon's own services included.

These tests drive the addon's hooks with real mitmproxy objects (this section's
image ships mitmproxy): the ``request`` hook on the request's real target, and the
``server_connect`` hook that runs before every upstream dial (HTTP, TLS, WebSocket,
raw TCP and the DNS layer alike). A Host header naming another host is left to the
tester (vhost probing, Host-header injection) and recorded under the real target.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
for _p in (str(ROOT), str(REPO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mitmproxy import http  # noqa: E402
from mitmproxy.addons.proxyserver import Proxyserver  # noqa: E402
from mitmproxy.connection import ConnectionState, Server  # noqa: E402
from mitmproxy.flow import Error as flow_error  # noqa: E402
from mitmproxy.proxy.layers.http import GetHttpConnection  # noqa: E402
from mitmproxy.proxy.server_hooks import ServerConnectionHookData  # noqa: E402
from mitmproxy.test import taddons, tflow  # noqa: E402

POOL = "10.214.0.0/16"
PUBLIC_IP = "93.184.216.34"

capture_addon = None
egress = None
ADDON = None
_TMP = ""


def setUpModule():
    # capture_addon builds its mitmdump singleton at import: point its spool, body
    # store and config file at a throwaway folder, and only for the import.
    global capture_addon, egress, ADDON, _TMP
    _TMP = tempfile.mkdtemp(prefix="egress-real-target-")
    env = {
        "CAPTURE_SPOOL_DIR": _TMP,
        "CAPTURE_BODIES_DIR": os.path.join(_TMP, "bodies"),
        "CAPTURE_CONFIG_FILE": os.path.join(_TMP, "absent.json"),
        "CAPTURE_CONFIG_POLL_SEC": "3600",
        "CAPTURE_BLOCKED_IPS": POOL,
    }
    with mock.patch.dict(os.environ, env):
        capture_addon = importlib.import_module("capture_addon")
        egress = importlib.import_module("egress")
    ADDON = capture_addon.addons[0]


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


class FakeDNS:
    """Answers per name; a list of answers is consumed one lookup at a time (the
    last one repeats), which is how a rebinding name behaves. IP literals pass
    through as ``resolve_host`` does."""

    def __init__(self, answers):
        self.answers = {k: (list(v) if v and isinstance(v[0], list) else [v]) for k, v in answers.items()}
        self.lookups = []

    def __call__(self, host):
        self.lookups.append(host)
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        queue = self.answers.get(host)
        if not queue:
            return []
        return list(queue.pop(0) if len(queue) > 1 else queue[0])


def _policy(**toggles):
    return egress.EgressPolicy(**toggles)


def _all_toggles_off():
    return egress.EgressPolicy(**{f: False for f in egress.POLICY_ENV})


def _req(host, port=80, *, host_headers=(), authority="", http_version="HTTP/1.1", scheme="http"):
    return http.Request(
        host=host, port=port, method=b"GET", scheme=scheme.encode(),
        authority=authority.encode(), path=b"/", http_version=http_version.encode(),
        headers=http.Headers([(b"Host", h.encode()) for h in host_headers]),
        content=b"", trailers=None, timestamp_start=0.0, timestamp_end=0.0,
    )


def _hook(name):
    fn = getattr(ADDON, name, None)
    if fn is None:
        raise AssertionError(f"the capture addon has no `{name}` hook: nothing checks the address mitmproxy dials")
    return fn


def _run(fn, *args):
    # mitmproxy's addon manager accepts sync and async hooks alike.
    res = fn(*args)
    if inspect.isawaitable(res):
        asyncio.run(res)


def _connect(server, client=None):
    data = ServerConnectionHookData(server=server, client=client or tflow.tclient_conn())
    _run(_hook("server_connect"), data)
    return data


def _request(req, sni=None):
    f = tflow.tflow(req=req)
    f.client_conn.sni = sni
    _run(ADDON.request, f)
    return f


def _gov(name):
    return str(name).split(":")[0].rstrip(".").lower().endswith(".gov")


def _records(fn, *args):
    """The spool records `fn(*args)` enqueues."""
    with mock.patch.object(ADDON, "_enqueue") as enqueue:
        _run(fn, *args)
    return [c.args[0] for c in enqueue.call_args_list]


class _GuardCase(unittest.TestCase):
    policy = None

    def setUp(self):
        ADDON.egress_policy = self.policy or egress.EgressPolicy()
        ADDON.extra_blocked_ips = [POOL]
        ADDON.active_recording = None
        self.dns = FakeDNS({
            "public.example": [PUBLIC_IP],
            "other.example": ["93.184.216.35"],
            "app.example": ["93.184.216.36"],
            "intranet.example": ["10.1.2.3"],
            "mixed.example": [PUBLIC_IP, "10.214.0.9"],
        })
        patcher = mock.patch.object(egress, "resolve_host", side_effect=self.dns)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assertRefused(self, f, reason_part=""):
        self.assertIsNotNone(f.response, "the request was let through to the upstream")
        self.assertEqual(f.response.status_code, 403)
        self.assertIn(b"egress guard", f.response.content)
        self.assertIn(reason_part, f.metadata.get("redamon_blocked", ""))

    def assertAllowed(self, f):
        self.assertIsNone(f.response, f"refused: {f.metadata.get('redamon_blocked')}")
        self.assertNotIn("redamon_blocked", f.metadata)

    def assertConnectRefused(self, data, address):
        self.assertTrue(data.server.error, f"the dial to {address} was not refused")
        self.assertIn("egress guard", data.server.error)
        # The client sees this text: no resolved or internal address in it.
        self.assertNotIn(str(address[0]), data.server.error)
        self.assertEqual(tuple(data.server.address), address)


class RequestHookChecksTheRealTarget(_GuardCase):
    def test_spoofed_host_to_a_pool_address_is_refused(self):
        f = _request(_req("10.214.0.5", 4040, authority="10.214.0.5:4040", host_headers=["1.1.1.1"]))
        self.assertRefused(f)

    def test_tunnelled_request_with_a_spoofed_host_is_refused(self):
        # Inside CONNECT 10.214.0.5:4040 the request is origin-form; its target is the tunnel's.
        f = _request(_req("10.214.0.5", 4040, host_headers=["1.1.1.1"]))
        self.assertRefused(f)

    def test_spoofed_host_to_cloud_metadata_is_refused(self):
        f = _request(_req("169.254.169.254", 80, authority="169.254.169.254", host_headers=["public.example"]))
        self.assertRefused(f)

    def test_http2_authority_naming_another_host_to_a_pool_target_is_refused(self):
        f = _request(_req("10.214.0.5", 443, authority="1.1.1.1", http_version="HTTP/2.0", scheme="https"))
        self.assertRefused(f)

    def test_vhost_probe_of_a_public_target_passes_and_is_checked_on_the_target(self):
        # Vhost probing by IP and Host-header injection are pentest work: the Host
        # header is the tester's, the target is what the guard checks and pins.
        for headers in (["other.example"], ["10.214.0.5"], ["public.example", "169.254.169.254"]):
            self.dns.lookups.clear()
            f = _request(_req("public.example", 80, authority="public.example", host_headers=headers))
            self.assertAllowed(f)
            self.assertEqual(f.metadata.get("redamon_pinned_ip"), PUBLIC_IP)
            self.assertEqual(self.dns.lookups, ["public.example"], f"the guard looked up {self.dns.lookups}")
            data = _connect(Server(address=("public.example", 80)))
            self.assertFalse(data.server.error)
            self.assertEqual(tuple(data.server.address), (PUBLIC_IP, 80))

    def test_public_host_header_to_an_internal_target_is_refused_at_connect_too(self):
        # Even with the request check off the path (fail-open on a guard error),
        # the dial to the real target is refused.
        ADDON.egress_policy = _policy(fail_closed_on_error=False)
        with mock.patch.object(capture_addon, "check_egress", side_effect=[RuntimeError("boom")]):
            f = _request(_req("10.214.0.5", 4040, authority="10.214.0.5:4040", host_headers=["public.example"]))
        self.assertAllowed(f)
        self.assertConnectRefused(_connect(Server(address=("10.214.0.5", 4040))), ("10.214.0.5", 4040))

    def test_a_spoofed_host_is_recorded_under_the_real_target(self):
        f = _request(_req("public.example", 80, authority="public.example", host_headers=["other.example"]))
        f.response = http.Response.make(200, b"ok")
        (record,) = _records(ADDON.response, f)
        self.assertEqual(record["host"], "public.example")
        self.assertEqual(record["reqHeaders"].get("host"), "other.example")

    def test_a_refused_spoofed_host_is_recorded_under_the_real_target(self):
        f = tflow.tflow(req=_req("10.214.0.5", 4040, authority="10.214.0.5:4040", host_headers=["1.1.1.1"]))
        (record,) = _records(ADDON.request, f)
        self.assertRefused(f)
        self.assertTrue(record["blocked"])
        self.assertEqual(record["host"], "10.214.0.5")

    def test_honest_public_request_is_allowed_and_records_the_checked_ip(self):
        f = _request(_req("public.example", 80, authority="public.example", host_headers=["public.example"]))
        self.assertAllowed(f)
        self.assertEqual(f.metadata.get("redamon_pinned_ip"), PUBLIC_IP)
        self.assertIn("public.example", self.dns.lookups)

    def test_request_without_host_header_checks_its_target(self):
        self.assertRefused(_request(_req("intranet.example", 80, authority="intranet.example")))
        self.assertAllowed(_request(_req("public.example", 80, authority="public.example")))

    def test_recording_scope_follows_the_real_target(self):
        ADDON.active_recording = {"tag": "operator-tag", "scope_hosts": ["app.example"], "expires_at": None}
        spoofed = _request(_req("public.example", 80, authority="public.example", host_headers=["app.example"]))
        self.assertIsNone(spoofed.metadata.get("redamon_ctx"),
                          "a Host header naming the recorded scope stamped the operator tag on another target")
        honest = _request(_req("app.example", 80, authority="app.example", host_headers=["app.example"]))
        self.assertEqual(honest.metadata.get("redamon_ctx"), "operator-tag")


class ClientNamesRecordsAndTiming(_GuardCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(capture_addon, "_hard_blocked", side_effect=_gov)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_hard_guardrail_name_in_the_host_header_is_refused(self):
        f = _request(_req(PUBLIC_IP, 80, authority=PUBLIC_IP, host_headers=["portal.rvtest.gov"]))
        self.assertRefused(f, "hard-guardrail")

    def test_hard_guardrail_name_in_a_second_host_header_is_refused(self):
        f = _request(_req(PUBLIC_IP, 80, authority=PUBLIC_IP, host_headers=["public.example", "portal.rvtest.gov:80"]))
        self.assertRefused(f, "hard-guardrail")

    def test_hard_guardrail_name_in_the_tls_sni_is_refused(self):
        f = _request(_req(PUBLIC_IP, 443, host_headers=[PUBLIC_IP], scheme="https"), sni="portal.rvtest.gov")
        self.assertRefused(f, "hard-guardrail")

    def test_hard_guardrail_name_in_the_dial_sni_is_refused_at_connect(self):
        server = Server(address=(PUBLIC_IP, 443))
        server.sni = "portal.rvtest.gov"
        self.assertConnectRefused(_connect(server), (PUBLIC_IP, 443))
        client = tflow.tclient_conn()
        client.sni = "portal.rvtest.gov"
        self.assertConnectRefused(_connect(Server(address=(PUBLIC_IP, 443)), client), (PUBLIC_IP, 443))

    def test_other_names_in_host_and_sni_stay_allowed(self):
        f = _request(_req(PUBLIC_IP, 443, host_headers=["admin.public.example"], scheme="https"),
                     sni="admin.public.example")
        self.assertAllowed(f)

    def test_guardrail_names_pass_when_the_operator_turns_the_guardrail_off(self):
        ADDON.egress_policy = _policy(block_hard_guardrail=False)
        self.assertAllowed(_request(_req(PUBLIC_IP, 80, host_headers=["portal.rvtest.gov"]), sni="portal.rvtest.gov"))

    def test_a_dial_refused_after_the_request_check_writes_a_blocked_record(self):
        # A name that rebinds between the request check and the dial (or a large
        # body mitmproxy streamed before the request hook) is refused at connect.
        self.dns.answers["rebind.example"] = [[PUBLIC_IP], ["10.214.0.7"]]
        req = _req("rebind.example", 80, authority="rebind.example", host_headers=["rebind.example"])
        req.headers["X-Redamon-Ctx"] = "tag-1"
        f = _request(req)
        self.assertAllowed(f)
        data = _connect(Server(address=("rebind.example", 80)), f.client_conn)
        self.assertTrue(data.server.error)
        f.error = flow_error(f"Connection killed: {data.server.error}")
        (record,) = _records(ADDON.error, f)
        self.assertTrue(record["blocked"])
        self.assertEqual(record["ctx_token"], "tag-1")
        self.assertEqual(record["host"], "rebind.example")
        self.assertEqual(record["errorText"], "egress:internal-ip")
        self.assertNotIn("10.214.0.7", json.dumps(record))

    def test_a_failed_dial_the_guard_allowed_writes_no_blocked_record(self):
        f = _request(_req("public.example", 80, authority="public.example"))
        f.error = flow_error("Connection killed: blocked by redamon capture proxy egress guard")
        self.assertEqual(_records(ADDON.error, f), [])

    def test_target_ip_is_the_address_the_socket_is_on(self):
        a, b = PUBLIC_IP, "93.184.216.35"
        self.dns.answers["two.example"] = [[a, b], [b, a]]
        f = _request(_req("two.example", 80, authority="two.example"))
        self.assertEqual(f.metadata.get("redamon_pinned_ip"), a)
        data = _connect(Server(address=("two.example", 80)), f.client_conn)
        data.server.state, data.server.peername = ConnectionState.OPEN, (b, 80)
        _run(_hook("server_connected"), data)
        f.server_conn = data.server
        f.response = http.Response.make(200, b"ok")
        (record,) = _records(ADDON.response, f)
        self.assertEqual(record["targetIp"], b)

    def test_a_refusal_record_names_the_class_not_the_address(self):
        self.dns.answers["sandbox-b"] = [["10.214.0.7"]]
        f = tflow.tflow(req=_req("sandbox-b", 4040, authority="sandbox-b:4040"))
        (record,) = _records(ADDON.request, f)
        self.assertRefused(f)
        self.assertEqual(record["errorText"], "egress:internal-ip")
        self.assertNotIn("10.214.0.7", json.dumps(record))
        self.assertNotIn("10.214.0.7", f.metadata.get("redamon_blocked", ""))

    def test_a_slow_name_does_not_delay_another_client(self):
        # The proxy serves every person's sandbox from one event loop: a lookup
        # that blocks it stalls everybody's traffic.
        dns = self.dns

        def resolve(host):
            if host == "slow.example":
                time.sleep(2.0)
                return [PUBLIC_IP]
            return dns(host)

        async def call(f):
            res = ADDON.request(f)
            if inspect.isawaitable(res):
                await res

        async def scenario():
            slow = tflow.tflow(req=_req("slow.example", 80, authority="slow.example"))
            fast = tflow.tflow(req=_req("public.example", 80, authority="public.example"))
            started = time.monotonic()
            pending = asyncio.ensure_future(call(slow))
            await asyncio.sleep(0)
            await call(fast)
            fast_done = time.monotonic() - started
            await pending
            return fast_done

        with mock.patch.object(egress, "resolve_host", side_effect=resolve):
            fast_done = asyncio.run(scenario())
        self.assertLess(fast_done, 1.0, f"another client's request waited {fast_done:.1f} s for a slow name")

    def test_the_tag_is_off_the_request_before_a_large_body_streams(self):
        # mitmproxy streams a body over stream_large_bodies upstream after
        # `requestheaders` and before `request`.
        req = _req("public.example", 80, authority="public.example")
        req.headers["X-Redamon-Ctx"] = "tag-2"
        f = tflow.tflow(req=req)
        _run(_hook("requestheaders"), f)
        self.assertNotIn("X-Redamon-Ctx", f.request.headers)
        self.assertEqual(f.metadata.get("redamon_ctx"), "tag-2")
        _run(ADDON.request, f)
        self.assertEqual(f.metadata.get("redamon_ctx"), "tag-2")


class RequestHookWithEveryToggleOff(_GuardCase):
    def setUp(self):
        self.policy = _all_toggles_off()
        super().setUp()

    def test_spoofed_host_to_a_pool_address_is_still_refused(self):
        f = _request(_req("10.214.0.5", 4040, authority="10.214.0.5:4040", host_headers=["1.1.1.1"]))
        self.assertRefused(f)

    def test_private_lab_target_is_allowed_when_the_operator_allows_private(self):
        self.assertAllowed(_request(_req("10.50.0.9", 80, authority="10.50.0.9", host_headers=["10.50.0.9"])))


class ServerConnectChecksEveryDial(_GuardCase):
    def test_connect_to_a_pool_address_is_refused(self):
        self.assertConnectRefused(_connect(Server(address=("10.214.0.5", 4040))), ("10.214.0.5", 4040))

    def test_connect_to_cloud_metadata_is_refused(self):
        self.assertConnectRefused(_connect(Server(address=("169.254.169.254", 80))), ("169.254.169.254", 80))

    def test_dns_layer_dial_to_an_internal_resolver_is_refused(self):
        # A CONNECT to :53 or :5353 makes mitmproxy run its DNS layer, which never
        # calls the request hook; its upstream dial is the same server_connect.
        for address in (("10.214.0.5", 53), ("127.0.0.11", 53), ("10.214.0.5", 5353)):
            f = tflow.tdnsflow()
            f.server_conn.address = address
            f.server_conn.state = ConnectionState.CLOSED
            data = ServerConnectionHookData(server=f.server_conn, client=f.client_conn)
            _run(_hook("server_connect"), data)
            self.assertConnectRefused(data, address)

    def test_name_resolving_to_an_internal_address_is_refused(self):
        self.assertConnectRefused(_connect(Server(address=("intranet.example", 80))), ("intranet.example", 80))

    def test_every_resolved_address_must_pass(self):
        self.assertConnectRefused(_connect(Server(address=("mixed.example", 443))), ("mixed.example", 443))

    def test_unresolvable_name_is_refused(self):
        self.assertConnectRefused(_connect(Server(address=("nowhere.example", 80))), ("nowhere.example", 80))

    def test_hard_guardrail_name_is_refused_at_connect(self):
        self.dns.answers["agency.gov"] = [[PUBLIC_IP]]
        with mock.patch.object(capture_addon, "_hard_blocked", side_effect=lambda h: h.endswith(".gov")):
            self.assertConnectRefused(_connect(Server(address=("agency.gov", 443))), ("agency.gov", 443))

    def test_dns_rebinding_between_the_request_check_and_the_dial_is_refused(self):
        self.dns.answers["rebind.example"] = [[PUBLIC_IP], ["10.214.0.5"]]
        f = _request(_req("rebind.example", 80, authority="rebind.example", host_headers=["rebind.example"]))
        self.assertAllowed(f)
        self.assertConnectRefused(_connect(Server(address=("rebind.example", 80))), ("rebind.example", 80))

    def test_honest_name_is_pinned_to_the_checked_ip_with_sni_kept(self):
        server = Server(address=("public.example", 443))
        server.sni, server.tls = "public.example", True
        data = _connect(server)
        self.assertFalse(data.server.error)
        # mitmproxy dials `*server.address`: that is the checked IP.
        self.assertEqual(tuple(data.server.address), (PUBLIC_IP, 443))
        host, port = data.server.address
        self.assertEqual((host, port), (PUBLIC_IP, 443))
        self.assertEqual(data.server.sni, "public.example")

    def test_sni_left_unset_stays_unset(self):
        data = _connect(Server(address=("public.example", 443)))
        self.assertEqual(tuple(data.server.address), (PUBLIC_IP, 443))
        self.assertIsNone(data.server.sni)

    def test_pinned_dial_keeps_mitmproxy_bookkeeping_per_name(self):
        # mitmproxy reuses a connection whose address equals the next request's
        # (host, port) and allows five connections per address (a dict keyed on it).
        # Keyed on the IP, one client naming many vhosts of one CDN address stalled
        # on the sixth name; keyed on the name, it behaves as without a pin.
        self.dns.answers["a.cdn.example"] = [[PUBLIC_IP]]
        self.dns.answers["b.cdn.example"] = [[PUBLIC_IP]]
        a = _connect(Server(address=("a.cdn.example", 80))).server
        b = _connect(Server(address=("b.cdn.example", 80))).server
        self.assertEqual(tuple(a.address), tuple(b.address))
        self.assertEqual(len({a.address, b.address}), 2)
        self.assertEqual(a.address, ("a.cdn.example", 80))
        self.assertEqual(hash(a.address), hash(("a.cdn.example", 80)))
        self.assertFalse(a.address != ("a.cdn.example", 80))
        self.assertTrue(GetHttpConnection(("a.cdn.example", 80), False, None, "tcp").connection_spec_matches(a))
        self.assertFalse(GetHttpConnection(("b.cdn.example", 80), False, None, "tcp").connection_spec_matches(a))

    def test_name_is_given_back_once_connected(self):
        server = Server(address=("public.example", 443))
        server.tls = True
        data = _connect(server)
        server.state, server.peername = ConnectionState.OPEN, (PUBLIC_IP, 443)
        _run(_hook("server_connected"), data)
        self.assertEqual(tuple(server.address), ("public.example", 443))
        self.assertEqual(server.peername, (PUBLIC_IP, 443))
        self.assertTrue(GetHttpConnection(("public.example", 443), True, None, "tcp").connection_spec_matches(server))

    def test_name_is_given_back_after_a_failed_dial(self):
        server = Server(address=("public.example", 80))
        data = _connect(server)
        server.error = "Connection refused"
        _run(_hook("server_connect_error"), data)
        self.assertEqual(tuple(server.address), ("public.example", 80))

    def test_ip_literal_public_target_is_left_as_it_is(self):
        data = _connect(Server(address=(PUBLIC_IP, 80)))
        self.assertFalse(data.server.error)
        self.assertEqual(tuple(data.server.address), (PUBLIC_IP, 80))

    def test_guard_error_fails_closed_by_default(self):
        with mock.patch.object(capture_addon, "check_egress", side_effect=RuntimeError("boom 10.0.0.1")):
            self.assertConnectRefused(_connect(Server(address=("public.example", 80))), ("public.example", 80))

    def test_guard_error_with_fail_open_leaves_the_dial_alone(self):
        ADDON.egress_policy = _policy(fail_closed_on_error=False)
        with mock.patch.object(capture_addon, "check_egress", side_effect=RuntimeError("boom")):
            data = _connect(Server(address=("public.example", 80)))
        self.assertFalse(data.server.error)
        self.assertEqual(tuple(data.server.address), ("public.example", 80))


class ServerConnectWithPrivateAllowed(_GuardCase):
    def setUp(self):
        self.policy = _policy(block_private=False)
        super().setUp()

    def test_pool_address_is_still_refused(self):
        self.assertConnectRefused(_connect(Server(address=("10.214.3.4", 4040))), ("10.214.3.4", 4040))

    def test_cloud_metadata_is_still_refused(self):
        self.assertConnectRefused(_connect(Server(address=("169.254.169.254", 80))), ("169.254.169.254", 80))

    def test_private_lab_address_outside_the_pool_is_allowed(self):
        data = _connect(Server(address=("10.50.0.9", 80)))
        self.assertFalse(data.server.error)


class ServerConnectWithEveryToggleOff(_GuardCase):
    def setUp(self):
        self.policy = _all_toggles_off()
        super().setUp()

    def test_pool_address_is_still_refused(self):
        self.assertConnectRefused(_connect(Server(address=("10.214.0.5", 4040))), ("10.214.0.5", 4040))

    def test_name_resolving_into_the_pool_is_still_refused(self):
        self.dns.answers["sandbox.example"] = [["10.214.0.5"]]
        self.assertConnectRefused(_connect(Server(address=("sandbox.example", 8013))), ("sandbox.example", 8013))


def _with_body(req, *, length=None, chunked=False, stream=False, tag=None):
    if length is not None:
        req.headers["Content-Length"] = str(length)
    if chunked:
        req.headers["Transfer-Encoding"] = "chunked"
    if tag:
        req.headers["X-Redamon-Ctx"] = tag
    req.method = "POST"
    # mitmproxy marks a body over stream_large_bodies for streaming before the
    # requestheaders hook when its Content-Length announces it.
    req.stream = stream
    return req


class NamesAreCheckedBeforeABodyStreams(_GuardCase):
    """mitmproxy dials and sends the headers and a body over stream_large_bodies
    after `requestheaders` and before `request`; a chunked body (or an HTTP/2 one
    without a length) switches to streaming once 5 MB of it are in. A protected
    name must be refused before that, and a request that reached its target must
    never be recorded as refused."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(capture_addon, "_hard_blocked", side_effect=_gov)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assertKilledAndRecorded(self, f, records, tag):
        self.assertIsNotNone(f.error, "the request was let through: its body streams upstream")
        self.assertEqual(f.error.msg, flow_error.KILLED_MESSAGE)
        # mitmproxy raises when a response is set on a request it streams.
        self.assertIsNone(f.response)
        (record,) = records
        self.assertTrue(record["blocked"])
        self.assertEqual(record["errorText"], "egress:hard-guardrail")
        self.assertEqual(record["ctx_token"], tag)

    def test_a_body_over_stream_large_bodies_is_killed_before_it_streams(self):
        f = tflow.tflow(req=_with_body(_req(PUBLIC_IP, 80, host_headers=["portal.rvtest.gov"]),
                                       length=6_000_000, stream=True, tag="t-cl"))
        self.assertKilledAndRecorded(f, _records(_hook("requestheaders"), f), "t-cl")

    def test_a_chunked_body_is_killed_before_it_can_stream(self):
        f = tflow.tflow(req=_with_body(_req(PUBLIC_IP, 80, host_headers=["portal.rvtest.gov"]),
                                       chunked=True, tag="t-chunked"))
        self.assertKilledAndRecorded(f, _records(_hook("requestheaders"), f), "t-chunked")

    def test_a_protected_name_in_a_second_host_header_is_killed_before_the_body(self):
        f = tflow.tflow(req=_with_body(_req(PUBLIC_IP, 80, host_headers=[f"{PUBLIC_IP}:80", "portal.rvtest.gov"]),
                                       length=6_000_000, stream=True, tag="t-second"))
        self.assertKilledAndRecorded(f, _records(_hook("requestheaders"), f), "t-second")

    def test_an_http2_host_header_beside_the_authority_is_killed_before_the_body(self):
        # h2 compares :authority with the last Host header only, and mitmproxy
        # forwards every Host header upstream.
        req = _req(PUBLIC_IP, 443, authority=f"{PUBLIC_IP}:443", host_headers=["portal.rvtest.gov", f"{PUBLIC_IP}:443"],
                   http_version="HTTP/2.0", scheme="https")
        f = tflow.tflow(req=_with_body(req, tag="t-h2"))
        self.assertKilledAndRecorded(f, _records(_hook("requestheaders"), f), "t-h2")

    def test_a_request_with_no_body_is_answered_403_and_recorded_once(self):
        f = tflow.tflow(req=_req(PUBLIC_IP, 80, host_headers=["portal.rvtest.gov"]))
        records = _records(_hook("requestheaders"), f)
        self.assertRefused(f, "hard-guardrail")
        self.assertIsNone(f.error)
        self.assertEqual(len(records), 1)
        self.assertEqual(_records(ADDON.request, f), [], "the request hook recorded the refusal a second time")
        self.assertEqual(f.response.status_code, 403)

    def test_a_body_known_to_stay_under_the_stream_limit_is_answered_403(self):
        proxyserver = Proxyserver()
        with taddons.context(proxyserver) as tctx:
            tctx.configure(proxyserver, stream_large_bodies="5m")
            f = tflow.tflow(req=_with_body(_req(PUBLIC_IP, 80, host_headers=["portal.rvtest.gov"]), length=1000))
            _run(_hook("requestheaders"), f)
        self.assertRefused(f, "hard-guardrail")
        self.assertIsNone(f.error)

    def test_other_names_pass_requestheaders_untouched(self):
        f = tflow.tflow(req=_with_body(_req(PUBLIC_IP, 80, host_headers=["admin.public.example"]),
                                       length=6_000_000, stream=True))
        self.assertEqual(_records(_hook("requestheaders"), f), [])
        self.assertIsNone(f.error)
        self.assertIsNone(f.response)

    def test_a_streamed_request_that_reached_its_target_is_not_refused_or_recorded(self):
        # Its dial was checked (and pinned) at server_connect; by the request hook
        # the body is upstream, so a refusal there would only be a false record.
        self.dns.answers["rebind.example"] = [[PUBLIC_IP], ["10.214.0.7"]]
        f = tflow.tflow(req=_with_body(_req("rebind.example", 80, host_headers=["rebind.example"]),
                                       length=6_000_000, stream=True, tag="t-reached"))
        _run(_hook("requestheaders"), f)
        data = _connect(Server(address=("rebind.example", 80)), f.client_conn)
        self.assertFalse(data.server.error)
        self.assertEqual(_records(ADDON.request, f), [])
        self.assertIsNone(f.response)
        self.assertNotIn("redamon_blocked", f.metadata)

    def test_a_flow_that_reached_its_target_is_never_recorded_as_a_refused_dial(self):
        # The client's earlier dial to the same address was refused (its HTTP flow
        # never errored, or it carried none); this flow's own dial passed, reached
        # the target and then failed there.
        self.dns.answers["rebind.example"] = [["10.214.0.7"], [PUBLIC_IP]]
        f = tflow.tflow(req=_req("rebind.example", 80, host_headers=["rebind.example"]))
        self.assertConnectRefused(_connect(Server(address=("rebind.example", 80)), f.client_conn), ("rebind.example", 80))
        self.assertFalse(_connect(Server(address=("rebind.example", 80)), f.client_conn).server.error)
        f.error = flow_error("peer closed connection")
        self.assertEqual(_records(ADDON.error, f), [])

    def test_hard_guardrail_name_in_an_http2_host_header_beside_the_authority_is_refused(self):
        f = _request(_req(PUBLIC_IP, 443, authority=f"{PUBLIC_IP}:443",
                          host_headers=["portal.rvtest.gov", f"{PUBLIC_IP}:443"], http_version="HTTP/2.0", scheme="https"))
        self.assertRefused(f, "hard-guardrail")


NET_A, NET_B = "10.214.0.2", "10.214.0.18"  # the proxy's own address on two sandbox networks
NETWORKS = ("10.214.0.0/28", "10.214.0.16/28")
GATEWAY, PENTEST_NET = "10.251.77.1", "10.251.77.0/24"  # the proxy's default route, as in the review's lab
PROXY_ON_PENTEST_NET = "10.251.77.5"


def _client(peer, local=NET_A):
    """A client connection from `peer`, taken on the proxy's address `local`."""
    client = tflow.tclient_conn()
    client.peername = (peer, 40000)
    client.sockname = (local, 8888)
    return client


def _flow_from(peer, host, port=80, local=NET_A, tag=None):
    req = _req(host, port, authority=host)
    if tag:
        req.headers["X-Redamon-Ctx"] = tag
    return tflow.tflow(req=req, client_conn=_client(peer, local))


async def _call(fn, *args):
    res = fn(*args)
    if inspect.isawaitable(res):
        await res


class GuardLookupsPerNetwork(_GuardCase):
    """One event loop serves every sandbox. A target that is an IP address needs
    no lookup; a name's lookup runs in threads of the guard's own, a few at a
    time per network the client came in on (the proxy's own address there, which
    a client cannot choose), so one network's names that never answer cannot hold
    the threads another network's check needs, and a client that adds addresses
    is still one network. On the default route's network (pentest-net) host-net
    recon arrives from the gateway's address and, in the shared mode, every
    person's Kali from one address: there each run (its X-Redamon-Ctx value) has
    its own line, and none is refused for capacity."""

    SLOW = 1.0
    A, A2, B = "10.214.0.5", "10.214.0.6", "10.214.0.20"

    def setUp(self):
        super().setUp()
        dns = self.dns
        self.threads = []
        self.started = {}
        self.slow_now = self.slow_most = 0
        lock = threading.Lock()

        def resolve(host):
            self.threads.append(threading.current_thread())
            self.started[host] = time.monotonic()
            if not host.endswith(".slow.example"):
                return dns(host)
            with lock:
                self.slow_now += 1
                self.slow_most = max(self.slow_most, self.slow_now)
            time.sleep(self.SLOW)
            with lock:
                self.slow_now -= 1
            return [PUBLIC_IP]

        patcher = mock.patch.object(egress, "resolve_host", side_effect=resolve)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.route = (GATEWAY, [ipaddress.ip_network(PENTEST_NET)],
                      [ipaddress.ip_network(n) for n in (PENTEST_NET, *NETWORKS)])
        route = mock.patch.object(capture_addon, "_read_default_route", create=True,
                                  side_effect=lambda *a: self.route)
        route.start()
        self.addCleanup(route.stop)
        for attr in ("_route_at", "_route_missed_at"):
            if hasattr(ADDON, attr):
                self.addCleanup(setattr, ADDON, attr, None)
                setattr(ADDON, attr, None)

    def _small_lookups(self, attr="_lookups", **limits):
        self.addCleanup(setattr, ADDON, attr, getattr(ADDON, attr))
        setattr(ADDON, attr, capture_addon._GuardLookups(**limits))

    def test_an_ip_literal_target_is_checked_without_a_lookup_thread(self):
        self.assertAllowed(_request(_req(PUBLIC_IP, 80, authority=PUBLIC_IP)))
        self.assertFalse(_connect(Server(address=(PUBLIC_IP, 80))).server.error)
        self.assertConnectRefused(_connect(Server(address=("10.214.0.5", 4040))), ("10.214.0.5", 4040))
        self.assertEqual({t.name for t in self.threads}, {threading.main_thread().name})

    def test_a_full_default_executor_does_not_delay_the_guard(self):
        async def scenario():
            asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=2))
            started = time.monotonic()
            slow = [asyncio.ensure_future(_call(ADDON.request, _flow_from(self.A, f"n{i}.slow.example")))
                    for i in range(4)]
            await asyncio.sleep(0.05)
            fast = _flow_from(self.B, "public.example", local=NET_B)
            await _call(ADDON.request, fast)
            took = time.monotonic() - started
            await asyncio.gather(*slow)
            return fast, took

        fast, took = asyncio.run(scenario())
        self.assertAllowed(fast)
        self.assertLess(took, 0.5, f"another network's check waited {took:.1f} s for slow names")

    def test_one_networks_slow_names_leave_another_network_a_lookup_thread(self):
        self._small_lookups(threads=3, per_line=2, queued_per_line=64)

        async def scenario():
            started = time.monotonic()
            slow = [asyncio.ensure_future(_call(ADDON.request, _flow_from(self.A, f"n{i}.slow.example")))
                    for i in range(4)]
            slow.append(asyncio.ensure_future(
                _call(ADDON.server_connect, ServerConnectionHookData(
                    server=Server(address=("dial.slow.example", 80)), client=_client(self.A)))))
            await asyncio.sleep(0.05)
            fast = _flow_from(self.B, "public.example", local=NET_B)
            await _call(ADDON.request, fast)
            dial = ServerConnectionHookData(server=Server(address=("public.example", 80)),
                                            client=_client(self.B, NET_B))
            await _call(ADDON.server_connect, dial)
            took = time.monotonic() - started
            await asyncio.gather(*slow)
            return fast, dial, took

        fast, dial, took = asyncio.run(scenario())
        self.assertAllowed(fast)
        self.assertFalse(dial.server.error)
        self.assertLess(took, 0.5, f"another network's checks waited {took:.1f} s for slow names")

    def test_addresses_on_one_network_share_its_line(self):
        # A container with NET_ADMIN can add addresses from its own /28; it stays
        # one client, since the proxy's own address on that network is the key.
        self._small_lookups(threads=8, per_line=2, queued_per_line=64)

        async def scenario():
            flows = [_flow_from(peer, f"{peer}.slow.example") for peer in (self.A, self.A2, "10.214.0.7", "10.214.0.8")]
            await asyncio.gather(*(_call(ADDON.request, f) for f in flows))
            return flows

        for f in asyncio.run(scenario()):
            self.assertAllowed(f)
        self.assertEqual(self.slow_most, 2, "one network's added addresses ran more lookups at once than its line")

    def test_a_network_over_its_line_is_refused_even_when_the_guard_fails_open(self):
        self._small_lookups(threads=2, per_line=1, queued_per_line=1)
        ADDON.egress_policy = _policy(fail_closed_on_error=False)

        async def scenario():
            waiting = [_flow_from(self.A, f"n{i}.slow.example") for i in range(2)]
            pending = [asyncio.ensure_future(_call(ADDON.request, f)) for f in waiting]
            await asyncio.sleep(0.05)
            over = _flow_from(self.A2, "public.example")
            with mock.patch.object(ADDON, "_enqueue") as enqueue:
                await _call(ADDON.request, over)
            dial = ServerConnectionHookData(server=Server(address=("public.example", 80)), client=_client(self.A))
            await _call(ADDON.server_connect, dial)
            await asyncio.gather(*pending)
            return waiting, over, enqueue, dial

        waiting, over, enqueue, dial = asyncio.run(scenario())
        self.assertRefused(over, "lookup-capacity")
        (record,) = [c.args[0] for c in enqueue.call_args_list]
        self.assertEqual(record["errorText"], "egress:lookup-capacity")
        self.assertConnectRefused(dial, ("public.example", 80))
        for f in waiting:
            self.assertAllowed(f)

    def test_runs_through_the_host_ingress_do_not_wait_for_each_other(self):
        # Every host-net recon container arrives from the gateway address: keyed on
        # it, one run's names that never answer held every other run's lookups.
        async def scenario():
            started = time.monotonic()
            slow = [asyncio.ensure_future(_call(ADDON.request, _flow_from(
                GATEWAY, f"n{i}.slow.example", local=PROXY_ON_PENTEST_NET, tag="run-a"))) for i in range(10)]
            await asyncio.sleep(0.05)
            other = _flow_from(GATEWAY, "public.example", local=PROXY_ON_PENTEST_NET, tag="run-b")
            await _call(ADDON.request, other)
            untagged = _flow_from(GATEWAY, "other.example", local=PROXY_ON_PENTEST_NET)
            await _call(ADDON.request, untagged)
            took = time.monotonic() - started
            await asyncio.gather(*slow)
            return other, untagged, took

        other, untagged, took = asyncio.run(scenario())
        self.assertAllowed(other)
        self.assertAllowed(untagged)
        self.assertLess(took, 0.5, f"another run's check waited {took:.1f} s behind one run's slow names")

    def test_a_dial_through_the_host_ingress_takes_its_runs_line(self):
        # server_connect sees no request; untagged dials share one line there.
        async def scenario():
            started = time.monotonic()
            untagged = [asyncio.ensure_future(_call(ADDON.server_connect, ServerConnectionHookData(
                server=Server(address=(f"u{i}.slow.example", 80)), client=_client(GATEWAY, PROXY_ON_PENTEST_NET))))
                for i in range(10)]
            await asyncio.sleep(0.05)
            f = _flow_from(GATEWAY, "public.example", local=PROXY_ON_PENTEST_NET, tag="run-b")
            _run(_hook("requestheaders"), f)
            dial = ServerConnectionHookData(server=Server(address=("public.example", 80)), client=f.client_conn)
            await _call(ADDON.server_connect, dial)
            took = time.monotonic() - started
            await asyncio.gather(*untagged)
            return dial, took

        dial, took = asyncio.run(scenario())
        self.assertFalse(dial.server.error)
        self.assertLess(took, 0.5, f"a run's dial waited {took:.1f} s behind untagged slow dials")

    def test_the_host_ingress_queues_a_run_beyond_its_line_and_refuses_none(self):
        self._small_lookups("_run_lookups", threads=4, per_line=1, queued_per_line=None)
        self.SLOW = 0.3

        async def scenario():
            flows = [_flow_from(GATEWAY, f"n{i}.slow.example", local=PROXY_ON_PENTEST_NET, tag="run-a")
                     for i in range(4)]
            await asyncio.gather(*(_call(ADDON.request, f) for f in flows))
            return flows

        for f in asyncio.run(scenario()):
            self.assertAllowed(f)
        self.assertEqual(self.slow_most, 1)

    def test_the_shared_kali_on_pentest_net_gets_a_line_per_run_too(self):
        # In the shared mode every person's tools reach the proxy from the one
        # shared Kali on pentest-net: one person's run must not hold another's.
        async def scenario():
            started = time.monotonic()
            slow = [asyncio.ensure_future(_call(ADDON.request, _flow_from(
                "10.251.77.9", f"n{i}.slow.example", local=PROXY_ON_PENTEST_NET, tag="alice-run")))
                for i in range(10)]
            await asyncio.sleep(0.05)
            other = _flow_from("10.251.77.9", "public.example", local=PROXY_ON_PENTEST_NET, tag="bob-run")
            await _call(ADDON.request, other)
            took = time.monotonic() - started
            await asyncio.gather(*slow)
            return other, took

        other, took = asyncio.run(scenario())
        self.assertAllowed(other)
        self.assertLess(took, 0.5, f"another person's run waited {took:.1f} s on the shared Kali")

    def test_a_tag_chooses_no_line_on_a_sandbox_network(self):
        # A sandbox could pick any tag: on its network one line holds them all.
        self._small_lookups(threads=8, per_line=1, queued_per_line=64)

        async def scenario():
            flows = [_flow_from(self.A, "a.slow.example", local=NET_A, tag="run-a"),
                     _flow_from(self.A2, "b.slow.example", local=NET_A, tag="run-b"),
                     _flow_from(self.A, "c.slow.example", local=NET_A, tag="run-c")]
            await asyncio.gather(*(_call(ADDON.request, f) for f in flows))

        asyncio.run(scenario())
        self.assertEqual(self.slow_most, 1, "a tag or an address chose a line on a sandbox network")

    def test_a_lookup_that_never_answers_is_refused_at_the_time_limit(self):
        # The thread stays counted until the resolver gives up, so the line never
        # holds more stuck lookups than its share.
        self._small_lookups(threads=4, per_line=1, queued_per_line=64, time_limit=0.3)
        ADDON.egress_policy = _policy(fail_closed_on_error=False)

        async def scenario():
            started = time.monotonic()
            first = _flow_from(self.A, "n0.slow.example")
            with mock.patch.object(ADDON, "_enqueue") as enqueue:
                await _call(ADDON.request, first)
            took = time.monotonic() - started
            dial = ServerConnectionHookData(server=Server(address=("dial.slow.example", 80)), client=_client(self.A))
            await _call(ADDON.server_connect, dial)
            await asyncio.sleep(self.SLOW)
            return first, took, enqueue, dial

        first, took, enqueue, dial = asyncio.run(scenario())
        self.assertRefused(first, "lookup-timeout")
        self.assertLess(took, 0.8, f"the check waited {took:.1f} s for a name that does not answer")
        (record,) = [c.args[0] for c in enqueue.call_args_list]
        self.assertEqual(record["errorText"], "egress:lookup-timeout")
        self.assertConnectRefused(dial, ("dial.slow.example", 80))
        self.assertEqual(self.slow_most, 1)


    def test_the_time_limit_counts_the_lookup_not_the_wait_for_a_thread(self):
        # Every thread of the pool is busy with never-answering names: another
        # line's honest name waits its turn, then resolves at once, and is not
        # refused for the time it spent waiting.
        self._small_lookups("_run_lookups", threads=2, per_line=8, queued_per_line=None, time_limit=0.5)

        async def scenario():
            slow = [asyncio.ensure_future(_call(ADDON.request, _flow_from(
                GATEWAY, f"n{i}.slow.example", local=PROXY_ON_PENTEST_NET, tag="run-a"))) for i in range(4)]
            await asyncio.sleep(0.05)
            honest = _flow_from(GATEWAY, "public.example", local=PROXY_ON_PENTEST_NET, tag="honest-run")
            await _call(ADDON.request, honest)
            await asyncio.gather(*slow)
            return honest

        self.assertAllowed(asyncio.run(scenario()))

    def test_lines_take_turns_for_the_pools_threads(self):
        # A pool never takes more jobs than it has threads; a freed thread goes to
        # the next line in turn, not to the longest queue.
        self._small_lookups(threads=2, per_line=8, queued_per_line=64)
        self.SLOW = 0.3

        async def scenario():
            started = time.monotonic()
            flood = [asyncio.ensure_future(_call(ADDON.request, _flow_from(self.A, f"n{i}.slow.example")))
                     for i in range(10)]
            await asyncio.sleep(0.05)
            other = asyncio.ensure_future(_call(ADDON.request, _flow_from(self.B, "b.slow.example", local=NET_B)))
            await asyncio.gather(*flood, other)
            return started

        started = asyncio.run(scenario())
        took = self.started["b.slow.example"] - started
        self.assertLess(took, 0.5, f"another network's lookup started after {took:.1f} s, behind the whole flood")

    def test_the_line_is_the_network_of_the_peer_not_the_address_it_called(self):
        # A sandbox with NET_ADMIN can route the proxy's pentest-net address, or its
        # address on another sandbox network, through its own network; the reply
        # can only come back on that network, so the peer's address names it.
        self._small_lookups(threads=8, per_line=1, queued_per_line=64)

        async def scenario():
            flows = [_flow_from(self.A, "a.slow.example", local=PROXY_ON_PENTEST_NET, tag="run-1"),
                     _flow_from(self.A, "b.slow.example", local=PROXY_ON_PENTEST_NET, tag="run-2"),
                     _flow_from(self.A2, "c.slow.example", local=NET_B)]
            await asyncio.gather(*(_call(ADDON.request, f) for f in flows))
            return flows

        for f in asyncio.run(scenario()):
            self.assertAllowed(f)
        self.assertEqual(self.slow_most, 1, "a sandbox chose a line by the proxy address it called")

    def test_a_peer_on_no_network_of_the_proxy_is_refused(self):
        ADDON.egress_policy = _policy(fail_closed_on_error=False)
        f = _flow_from("192.0.2.7", "public.example", local=NET_A)
        records = _records(ADDON.request, f)
        self.assertRefused(f, "unknown-network")
        self.assertEqual([r["errorText"] for r in records], ["egress:unknown-network"])
        dial = ServerConnectionHookData(server=Server(address=("public.example", 80)), client=_client("192.0.2.7"))
        _run(_hook("server_connect"), dial)
        self.assertConnectRefused(dial, ("public.example", 80))

    def test_a_network_the_proxy_joined_since_its_last_read_is_found(self):
        joined = (GATEWAY, self.route[1], self.route[2] + [ipaddress.ip_network("10.214.0.32/28")])
        f = _flow_from("10.214.0.36", "public.example", local="10.214.0.34")
        _run(ADDON.request, _flow_from(self.A, "public.example"))  # the table is read without it
        self.route = joined
        _run(ADDON.request, f)
        self.assertAllowed(f)

    def test_the_proxys_own_loopback_keeps_the_address_it_called(self):
        f = _flow_from("127.0.0.1", "public.example", local="127.0.0.1")
        _run(ADDON.request, f)
        self.assertAllowed(f)

    def test_a_network_joined_in_the_same_second_is_found_for_a_newer_connection(self):
        # A miss re-reads at most once a second; a connection newer than the last
        # read still gets one read of its own, so its first request is not refused.
        _run(ADDON.request, _flow_from("192.0.2.9", "public.example"))  # a miss: the table is re-read now
        self.route = (GATEWAY, self.route[1], self.route[2] + [ipaddress.ip_network("10.214.0.32/28")])
        f = _flow_from("10.214.0.36", "public.example", local="10.214.0.34")
        f.client_conn.timestamp_start = time.time() + 0.01
        _run(ADDON.request, f)
        self.assertAllowed(f)

    def test_a_clients_waiting_checks_end_when_it_disconnects(self):
        # Its sockets are closed: its queued checks must not keep the line.
        self._small_lookups(threads=2, per_line=1, queued_per_line=64)

        async def scenario():
            gone = _client(self.A)
            flows = [tflow.tflow(req=_req(f"g{i}.slow.example", 80, authority=f"g{i}.slow.example"), client_conn=gone)
                     for i in range(5)]
            pending = [asyncio.ensure_future(_call(ADDON.request, f)) for f in flows]
            await asyncio.sleep(0.05)
            ADDON.client_disconnected(gone)
            started = time.monotonic()
            honest = _flow_from(self.A2, "public.example")
            await _call(ADDON.request, honest)
            took = time.monotonic() - started
            await asyncio.gather(*pending)
            return honest, took, flows

        with mock.patch.object(ADDON, "_enqueue") as enqueue:
            honest, took, flows = asyncio.run(scenario())
        self.assertAllowed(honest)
        self.assertLess(took, self.SLOW + 0.5, f"the network's next check waited {took:.1f} s behind a gone client's queue")
        self.assertEqual([f.metadata.get("redamon_blocked") for f in flows[1:]], ["client-gone"] * 4)
        self.assertNotIn("egress:client-gone", [c.args[0]["errorText"] for c in enqueue.call_args_list])


class ReadingIsHeldOnlyForABacklog(unittest.TestCase):
    """A connection's reading is paused only while the request bytes queued behind
    its waiting streams pass the high-water mark, and resumed once they fall
    under the low one: normal traffic never pauses."""

    def setUp(self):
        self.calls = []
        self.backlog = capture_addon._Backlog(
            high=1000, low=250, pause=lambda c: self.calls.append(("pause", c.id)) or True,
            resume=lambda c: self.calls.append(("resume", c.id)))
        self.client = tflow.tclient_conn()

    def test_traffic_under_the_mark_never_pauses(self):
        for n in (100, 900, 0, 1000, 0):
            self.backlog.update(self.client, "s1", n)
        self.assertEqual(self.calls, [])

    def test_a_refused_dial_beside_a_pending_one_keeps_the_connection_held(self):
        # Two streams wait for their dials with bodies queued; one dial is refused
        # (its queue goes): the other still holds more than the low mark.
        self.backlog.update(self.client, "s1", 900)
        self.backlog.update(self.client, "s2", 900)
        self.assertEqual(self.calls, [("pause", self.client.id)])
        self.backlog.update(self.client, "s1", 0)
        self.backlog.update(self.client, "s1", 0)  # told twice, as mitmproxy may
        self.assertEqual(self.calls, [("pause", self.client.id)], "a refusal lifted the hold of another dial")
        self.backlog.update(self.client, "s2", 200)
        self.assertEqual(self.calls, [("pause", self.client.id), ("resume", self.client.id)])

    def test_a_gone_connection_is_forgotten(self):
        self.backlog.update(self.client, "s1", 5000)
        self.backlog.forget(self.client.id)
        other = tflow.tclient_conn()
        self.backlog.update(other, "s1", 10)
        self.assertEqual(self.calls, [("pause", self.client.id)])
        self.assertEqual(self.backlog.queued(self.client.id), 0)

    def test_the_streams_backlog_is_measured_where_mitmproxy_queues_it(self):
        from mitmproxy.proxy.layers.http import HttpStream
        self.assertTrue(getattr(HttpStream.handle_event, "redamon_watched", False))


class MitmproxyHeadsAreBounded(unittest.TestCase):
    def test_request_and_response_heads_are_read_through_the_bound(self):
        # mitmproxy 11.1.3 keeps a head until its blank line with no limit
        # ("FIXME: protect against header size DoS"); the addon wraps both readers.
        from mitmproxy.proxy.layers.http import _http1
        for cls in (_http1.Http1Server, _http1.Http1Client):
            self.assertTrue(getattr(cls.read_headers, "redamon_bounded", False), cls.__name__)
        self.assertLessEqual(capture_addon._MAX_HEAD_BYTES, 1 << 20)

    def test_every_receive_buffer_is_read_through_the_bound(self):
        # mitmproxy appends every chunk to a connection's buffer in every state but
        # the raw pipe, and leaves it unread while a request waits for its answer.
        from mitmproxy.proxy.layers.http import _http1
        self.assertTrue(getattr(_http1.Http1Connection._handle_event, "redamon_bounded", False))
        for cls in (_http1.Http1Server, _http1.Http1Client):
            self.assertIs(cls._handle_event, _http1.Http1Connection._handle_event, cls.__name__)


class ResolverAndRouteReading(unittest.TestCase):
    def _file(self, text):
        fd, path = tempfile.mkstemp(prefix="egress-real-target-")
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_the_time_limit_is_never_shorter_than_the_resolver_gives_up(self):
        give_up = capture_addon._resolver_gives_up_after
        self.assertEqual(give_up(self._file("nameserver 127.0.0.11\noptions ndots:0\n")), 10.0)
        self.assertEqual(give_up(self._file("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
                                            "options timeout:3 attempts:4\n")), 24.0)
        self.assertEqual(give_up(self._file("nameserver a\nnameserver b\nnameserver c\nnameserver d\n"
                                            "options timeout:99 attempts:9\n")), 30.0 * 5 * 3)
        self.assertEqual(give_up("/nonexistent/resolv.conf"), 10.0)
        self.assertGreaterEqual(capture_addon._LOOKUP_TIME_LIMIT, give_up())

    def test_the_default_route_is_read_from_the_kernel_table(self):
        table = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                 "eth0\t00000000\t010050AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
                 "eth0\t000050AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
                 "eth1\t0000D60A\t00000000\t0001\t0\t0\t0\tF0FFFFFF\t0\t0\t0\n")
        gateway, default_networks, networks = capture_addon._read_default_route(self._file(table))
        self.assertEqual(gateway, "172.80.0.1")
        self.assertEqual(default_networks, [ipaddress.ip_network("172.80.0.0/16")])
        self.assertEqual(networks, [ipaddress.ip_network("172.80.0.0/16"), ipaddress.ip_network("10.214.0.0/28")])
        self.assertIsNone(capture_addon._read_default_route(self._file(table.splitlines(True)[0])))
        self.assertIsNone(capture_addon._read_default_route("/nonexistent/route"))


class TheImagePinsTheTestedMitmproxy(unittest.TestCase):
    def test_the_dockerfile_pins_exactly_the_mitmproxy_these_tests_run(self):
        # The addon relies on mitmproxy internals (the pinned dial, the close of a
        # socket mitmproxy left open): the image must carry the version tested.
        import re
        from mitmproxy import version
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertEqual(re.findall(r'"mitmproxy([^"]*)"', dockerfile), [f"=={version.VERSION}"])


if __name__ == "__main__":
    unittest.main()

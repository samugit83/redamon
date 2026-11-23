"""
No person can point the agent at another person's Kali sandbox (group 1, S10; S01 review
R1-F6: T5, E3, I9).

The agent joins every sandbox network (contract B.5), and on each sandbox some ports
check nothing: ngrok's agent API on 4040 and the reverse-shell listener. A person
controls two URLs the agent dials from its own network namespace: a custom LLM
`baseUrl` (whose guard allows RFC 1918 on purpose, for self-hosted models) and the URL
of an MCP server they add. Either one aimed at the sandbox pool would reach another
person's sandbox. Both refuse any address in the contract's SUBNET_POOL, judged on the
resolved addresses, never on the spelling.

Run: ./agentic/run_tests.sh tests/test_sandbox_pool_outbound_guard.py
"""
import asyncio
import http.server
import ipaddress
import socket
import ssl
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402

import mcp_registry  # noqa: E402
import sandbox_contract as contract  # noqa: E402
from orchestrator_helpers import llm_url_guard as guard  # noqa: E402
from orchestrator_helpers.llm_url_guard import BaseUrlValidationError, validate_llm_base_url  # noqa: E402

POOL = ipaddress.ip_network(contract.SUBNET_POOL)
IN_POOL = str(next(POOL.subnets(new_prefix=contract.SUBNET_PREFIX))[2])  # a sandbox, e.g. 10.214.0.2
POOL_LAST = str(POOL[-2])


def _resolver(mapping):
    def getaddrinfo(host, *args, **kwargs):
        if host in mapping:
            return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, None, None, "", (ip, 0))
                    for ip in mapping[host]]
        try:
            ipaddress.ip_address(host)
            return [(socket.AF_INET, None, None, "", (host, 0))]
        except ValueError:
            raise OSError("Name or service not known")
    return getaddrinfo


class LlmBaseUrl(unittest.TestCase):

    def test_a_pool_address_is_refused(self):
        for url in (f"http://{IN_POOL}:4040/api/tunnels", f"https://{POOL_LAST}/v1",
                    f"http://[::ffff:{IN_POOL}]:4444/v1"):
            with self.subTest(url=url):
                with self.assertRaises(BaseUrlValidationError) as ctx:
                    validate_llm_base_url(url)
                self.assertIn("sandbox", str(ctx.exception))

    def test_a_name_resolving_into_the_pool_is_refused(self):
        resolver = _resolver({"redamon-kali-0123456789abcdef-a1b2c3": [IN_POOL],
                              "model.lan.test": ["192.168.1.9", IN_POOL]})
        with mock.patch("socket.getaddrinfo", resolver):
            for host in ("redamon-kali-0123456789abcdef-a1b2c3", "model.lan.test"):
                with self.subTest(host=host):
                    with self.assertRaises(BaseUrlValidationError):
                        validate_llm_base_url(f"http://{host}:8000/v1")

    def test_self_hosted_models_still_pass(self):
        resolver = _resolver({"ollama": ["172.20.0.3"], "localhost": ["127.0.0.1"]})
        with mock.patch("socket.getaddrinfo", resolver):
            for url in ("http://ollama:11434/v1", "http://localhost:11434/v1",
                        "http://10.213.255.254:8000/v1", "http://10.215.0.1:8000/v1",
                        "http://192.168.1.50:11434/v1"):
                with self.subTest(url=url):
                    validate_llm_base_url(url)


def _server(url, transport="sse", sid="srv-x"):
    return {"id": sid, "name": "X", "transport": transport, "url": url,
            "tools": [{"name": "x_tool", "purpose": "p", "when_to_use": "w",
                       "args_format": "a", "description": "d"}]}


class UserMcpServerUrl(unittest.TestCase):

    def test_a_pool_address_is_refused(self):
        for transport in ("sse", "streamable_http"):
            for url in (f"http://{IN_POOL}:4040/sse", f"http://[::ffff:{IN_POOL}]:8000/sse"):
                with self.subTest(transport=transport, url=url):
                    valid, errors = mcp_registry.parse_user_servers([_server(url, transport)])
                    self.assertEqual(valid, [])
                    self.assertEqual([e.code for e in errors], [mcp_registry.SANDBOX_ADDRESS_REFUSED])

    def test_other_servers_still_load(self):
        resolver = _resolver({"mcp.example.test": ["203.0.113.7"], "mcp-lan": ["192.168.1.20"]})
        with mock.patch("socket.getaddrinfo", resolver):
            valid, errors = mcp_registry.parse_user_servers([
                _server("https://mcp.example.test/sse", sid="a"),
                {**_server("http://mcp-lan:9000/mcp", "streamable_http", sid="b"),
                 "tools": [{"name": "y_tool", "purpose": "p", "when_to_use": "w",
                            "args_format": "a", "description": "d"}]},
                _server("http://unresolvable.invalid/sse", sid="c") | {
                    "tools": [{"name": "z_tool", "purpose": "p", "when_to_use": "w",
                               "args_format": "a", "description": "d"}]},
            ])
        self.assertEqual(errors, [])
        self.assertEqual([s.id for s in valid], ["a", "b", "c"])

    def test_a_draft_is_judged_by_the_same_helper(self):
        """/mcp/test connects to a draft without loading it: it is to ask the same helper
        (S11), and its connection goes through the guard either way."""
        draft = mcp_registry.MCPServer.model_validate(_server(f"http://{IN_POOL}:4040/sse"))
        refused = mcp_registry.sandbox_address_refusal(draft)
        self.assertEqual(refused.code, mcp_registry.SANDBOX_ADDRESS_REFUSED)
        ok = mcp_registry.MCPServer.model_validate(_server("http://192.168.1.20:9000/sse"))
        self.assertIsNone(mcp_registry.sandbox_address_refusal(ok))
        stdio = mcp_registry.MCPServer(id="s", name="s", transport="stdio", command="npx")
        self.assertIsNone(mcp_registry.sandbox_address_refusal(stdio))

    def test_the_system_servers_are_not_user_supplied(self):
        system = mcp_registry.MCPServer(id="network_recon", name="n", transport="sse",
                                        url=f"http://{IN_POOL}:8000/sse")
        valid, errors = mcp_registry.validate_servers([system])
        self.assertEqual((len(valid), errors), (1, []))


# =============================================================================
# Connect time: redirects, rebinding, and no DNS on the event loop
# =============================================================================

class _Redirector(http.server.BaseHTTPRequestHandler):
    """An allowed server that sends every request on to `target` (307 keeps the POST)."""

    target = ""

    def _redirect(self):
        self.send_response(307)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = _redirect

    def log_message(self, *args):
        return None


class _Server:
    def __init__(self, target):
        handler = type("Handler", (_Redirector,), {"target": target})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _rebinding(mapping):
    """`_resolve_ips` answering each name in turn from its list (the last one repeats);
    any other host resolves as usual."""
    real = guard._resolve_ips
    calls = {}

    def resolve(host):
        if host in mapping:
            answers = mapping[host]
            n = calls.get(host, 0)
            calls[host] = n + 1
            return [answers[min(n, len(answers) - 1)]] if answers else []
        return real(host)
    return resolve


class ConnectTimeGuard(unittest.IsolatedAsyncioTestCase):
    """Both clients judge the peer of every connection, so a redirect or a second DNS
    answer cannot reach the pool, and resolve off the event loop."""

    async def _clients(self):
        mcp_client = mcp_registry.user_server_http_client()
        _sync, llm_client = guard.llm_guarded_clients()
        return {"user MCP server": mcp_client, "custom model": llm_client}

    async def test_no_redirect_is_followed_and_a_forced_one_is_refused(self):
        with _Server(f"http://{IN_POOL}:4040/api/tunnels") as base:
            for name, client in (await self._clients()).items():
                with self.subTest(client=name):
                    async with client:
                        self.assertFalse(client.follow_redirects)
                        resp = await client.post(f"{base}/v1/chat/completions", json={})
                        self.assertEqual(resp.status_code, 307, "the redirect was followed")
                        with self.assertRaises(guard.OutboundAddressRefused):
                            await client.get(f"{base}/sse", follow_redirects=True)

    async def test_a_redirect_to_a_name_in_the_pool_is_refused(self):
        with mock.patch.object(guard, "_resolve_ips", _rebinding({"ngrok.pool.test": [IN_POOL]})):
            with _Server("http://ngrok.pool.test:4040/api/tunnels") as base:
                for name, client in (await self._clients()).items():
                    with self.subTest(client=name):
                        async with client:
                            with self.assertRaises(guard.OutboundAddressRefused):
                                await client.get(f"{base}/sse", follow_redirects=True)

    async def test_a_name_that_rebinds_into_the_pool_is_refused_at_connect(self):
        resolver = _rebinding({"model.rebind.test": ["203.0.113.7", IN_POOL],
                               "mcp.rebind.test": [IN_POOL]})
        with mock.patch.object(guard, "_resolve_ips", resolver):
            validate_llm_base_url("http://model.rebind.test:8000/v1")   # the first answer passes
            # Loading resolves no name: the name is judged when the connection opens.
            valid, errors = mcp_registry.parse_user_servers([_server("http://mcp.rebind.test:9/sse")])
            self.assertEqual((len(valid), errors), (1, []))
            clients = await self._clients()
            for name, url in (("custom model", "http://model.rebind.test:8000/v1/models"),
                              ("user MCP server", "http://mcp.rebind.test:9/sse")):
                with self.subTest(client=name):
                    async with clients[name]:
                        with self.assertRaises(guard.OutboundAddressRefused):
                            await clients[name].get(url)

    async def test_a_host_unresolvable_at_check_time_is_judged_at_connect(self):
        resolver = _rebinding({"late.rebind.test": []})
        with mock.patch.object(guard, "_resolve_ips", resolver):
            validate_llm_base_url("http://late.rebind.test/v1")
        resolver = _rebinding({"late.rebind.test": [IN_POOL]})
        with mock.patch.object(guard, "_resolve_ips", resolver):
            _sync, client = guard.llm_guarded_clients()
            async with client:
                with self.assertRaises(guard.OutboundAddressRefused):
                    await client.get("http://late.rebind.test/v1/models")

    async def test_connect_time_resolution_leaves_the_loop_free(self):
        def slow(host):
            time.sleep(0.6)
            return []

        gaps = []

        async def ticker(stop):
            last = time.monotonic()
            while not stop.is_set():
                await asyncio.sleep(0.01)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        stop = asyncio.Event()
        tick = asyncio.create_task(ticker(stop))
        with mock.patch.object(guard, "_resolve_ips", slow):
            client = mcp_registry.user_server_http_client()
            async with client:
                with self.assertRaises(httpx.ConnectError):
                    await client.get("http://slow.resolver.test/sse")
        stop.set()
        await tick
        self.assertLess(max(gaps), 0.3, "name resolution blocked the event loop")


class LoadingResolvesNoName(unittest.IsolatedAsyncioTestCase):
    """Loading a user's servers runs on the event loop: it resolves no name (one slow DNS
    answer per server stalled every chat and route of the agent)."""

    async def test_loading_user_servers_resolves_no_name(self):
        calls = []

        def slow(host, *args, **kwargs):
            calls.append(host)
            time.sleep(1.0)
            raise OSError("slow")

        servers = [
            _server(f"http://slow{i}.example.test/sse", sid=f"s{i}") | {
                "tools": [{"name": f"t{i}", "purpose": "p", "when_to_use": "w", "args_format": "a",
                           "description": "d"}]}
            for i in range(3)]
        with mock.patch("socket.getaddrinfo", slow):
            start = time.monotonic()
            valid, errors = mcp_registry.parse_user_servers(servers)
            elapsed = time.monotonic() - start
        self.assertEqual((len(valid), errors), (3, []))
        self.assertEqual(calls, [])
        self.assertLess(elapsed, 0.5)


class WhoGetsTheGuard(unittest.TestCase):

    def test_user_servers_connect_through_the_guard_system_servers_do_not(self):
        from tools import _build_system_mcp_servers
        user = mcp_registry.MCPServer.model_validate(_server("https://mcp.example.test/sse"))
        host = contract.container_name("bob", "own", "a1b2c3")
        cfg, _ = mcp_registry.to_mcp_servers_dict([user, *_build_system_mcp_servers(host, "t" * 43)])
        self.assertIs(cfg["srv-x"]["httpx_client_factory"], mcp_registry.user_server_http_client)
        for sid in mcp_registry.SYSTEM_SERVER_IDS:
            self.assertNotIn("httpx_client_factory", cfg[sid])

    def test_a_payload_cannot_mark_itself_a_system_server(self):
        forged = mcp_registry.MCPServer.model_validate({**_server(f"http://{IN_POOL}:8000/sse"),
                                                        "_system": True, "system": True})
        cfg, _ = mcp_registry.to_mcp_servers_dict([forged])
        self.assertIn("httpx_client_factory", cfg["srv-x"])

    def test_a_per_user_sandbox_keeps_its_own_unguarded_servers(self):
        import sandbox_router
        handle = sandbox_router.SandboxHandle(
            user_id="bob", view="own", instance="a1b2c3",
            host=contract.container_name("bob", "own", "a1b2c3"), token="t" * 43, tunnel_token="",
            ports=contract.PORTS, reverse_port=4444)
        cfg = sandbox_router.server_configs_for(handle)
        self.assertEqual(set(cfg), set(mcp_registry.SYSTEM_SERVER_IDS))
        for entry in cfg.values():
            self.assertNotIn("httpx_client_factory", entry)


class CustomModelClients(unittest.TestCase):

    def test_openai_compatible_and_anthropic_endpoints_get_guarded_clients(self):
        from orchestrator_helpers.llm_setup import setup_llm
        oai = setup_llm("custom/m", custom_llm_config={
            "providerType": "openai_compatible", "baseUrl": "http://127.0.0.1:9/v1", "apiKey": "k"})
        anth = setup_llm("custom/m", custom_llm_config={
            "providerType": "anthropic", "baseUrl": "http://127.0.0.1:9", "apiKey": "k",
            "modelIdentifier": "claude-test"})
        for name, client in (("openai sync", oai.http_client), ("openai async", oai.http_async_client),
                             ("anthropic sync", anth._client._client),
                             ("anthropic async", anth._async_client._client)):
            with self.subTest(client=name):
                self.assertFalse(client.follow_redirects)
                backend = client._transport._pool._network_backend
                self.assertIn(type(backend).__name__, ("_GuardedAsyncBackend", "_GuardedSyncBackend"))
                self.assertIs(backend._refuse, guard.llm_endpoint_refusal)
        self.assertEqual(type(anth).__name__, "ChatAnthropic", "prompt caching reads the class name")

    def test_tls_off_still_applies_inside_the_guard(self):
        from orchestrator_helpers.llm_setup import setup_llm
        oai = setup_llm("custom/m", custom_llm_config={
            "providerType": "openai_compatible", "baseUrl": "https://10.0.0.5/v1", "apiKey": "k",
            "sslVerify": False})
        self.assertEqual(type(oai.http_async_client._transport._pool._network_backend).__name__,
                         "_GuardedAsyncBackend")
        self.assertEqual(oai.http_async_client._transport._pool._ssl_context.verify_mode, ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main()

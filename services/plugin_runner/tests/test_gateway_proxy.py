"""The plugin-gateway proxy: the only door between the plugins network and the rest of the
stack (TD-05, D-40, D-72). :7071 lets workers and the runner reach the Gateway and the
run list, and nothing else of the webapp; :7072 lets the webapp reach the supervisor."""

import http.client
import io
import os
import socket
import subprocess
import sys
import threading

import pytest

from gateway_proxy import proxy
from tests.support import RUNNER_ROOT, StubServer, free_port, wait_until

ALLOWED_UPSTREAM_HEADERS = {"authorization", "content-type", "content-length", "x-plugin-runner-key",
                            "host", "connection"}


class Proxy:
    def __init__(self, kind, upstream, **kw):
        self.log = io.StringIO()
        self.port = free_port()
        self.server = proxy.build_server(kind, "127.0.0.1", self.port, upstream,
                                         log=lambda line: self.log.write(line + "\n"), **kw)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                                       daemon=True)
        self.thread.start()

    def raw(self, method, path, body=b"", headers=None):
        """Sends the request line exactly as given: no client-side path normalisation."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", "plugin-gateway")
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if body or method == "POST":
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body or None)
        r = conn.getresponse()
        out = (r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read())
        conn.close()
        return out

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def upstream():
    srv = StubServer()
    srv.answer_json(200, {"ok": True})
    yield srv
    srv.close()


@pytest.fixture
def gateway(upstream):
    p = Proxy("gateway", upstream.base_url)
    yield p
    p.close()


@pytest.fixture
def runner_door(upstream):
    p = Proxy("runner", upstream.base_url)
    yield p
    p.close()


def test_a_gateway_call_is_forwarded_with_only_the_allowed_headers(gateway, upstream):
    status, headers, body = gateway.raw(
        "POST", "/api/plugin-gateway/v1/data/get", b'{"collection":"c"}',
        {"Authorization": "Bearer tok", "Content-Type": "application/json", "Cookie": "redamon-auth=x",
         "X-Internal-Key": "master", "X-Forwarded-For": "198.51.100.7", "X-User-Id": "admin",
         "X-Plugin-Runner-Key": "rk"})
    assert status == 200 and body == b'{"ok": true}'
    sent = upstream.requests[0]
    assert (sent.method, sent.path, sent.body) == ("POST", "/api/plugin-gateway/v1/data/get", b'{"collection":"c"}')
    assert set(sent.headers) <= ALLOWED_UPSTREAM_HEADERS
    assert sent.headers["authorization"] == "Bearer tok"
    assert sent.headers["x-plugin-runner-key"] == "rk"
    assert "cookie" not in sent.headers and "x-internal-key" not in sent.headers


def test_the_run_list_is_reachable_with_get(gateway, upstream):
    status, _, _ = gateway.raw("GET", "/api/plugin-runner/v1/run-list", headers={"X-Plugin-Runner-Key": "rk"})
    assert status == 200
    assert upstream.requests[0].method == "GET" and upstream.requests[0].path == "/api/plugin-runner/v1/run-list"


def test_only_the_content_type_comes_back(gateway, upstream):
    upstream.reply = lambda r: (201, {"Content-Type": "application/json", "Set-Cookie": "a=b",
                                      "X-Powered-By": "Next.js"}, b'{"x":1}')
    status, headers, body = gateway.raw("POST", "/api/plugin-gateway/v1/data/put", b"{}")
    assert status == 201 and body == b'{"x":1}'
    assert headers["content-type"] == "application/json"
    assert "set-cookie" not in headers and "x-powered-by" not in headers


@pytest.mark.parametrize("path", [
    "/api/projects",
    "/api/plugin-gateway/v1/../projects",
    "/api/plugin-gateway/v1/%2e%2e/projects",
    "/api/plugin-gateway/v1/a%2fb",
    "/api/plugin-gateway/v1/%41",
    "/api/plugin-gateway/v1//data/get",
    "/api/plugin-gateway/v1/a\\b",
    "/api/plugin-gatewayx/v1/data/get",
    "/api/plugin-gateway/v10/data/get",
    "/api/plugin-gateway/v1/",
    "/api/plugin-gateway/v1/Data/Get",
    "/api/internal/plugins/reconcile",
    "/api/plugin-gateway/v1/data/get#frag",
    "http://webapp:3000/api/plugin-gateway/v1/data/get",
    "*",
])
def test_paths_outside_the_two_prefixes_are_refused(gateway, upstream, path):
    status, _, body = gateway.raw("POST", path, b"{}")
    assert status == 404, (path, body)
    assert upstream.requests == []


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"])
def test_only_get_and_post_pass(gateway, upstream, method):
    status, _, _ = gateway.raw(method, "/api/plugin-gateway/v1/data/get")
    assert status in (404, 405)
    assert upstream.requests == []


def test_a_query_string_only_on_get_and_short(gateway, upstream):
    assert gateway.raw("POST", "/api/plugin-gateway/v1/data/get?x=1", b"{}")[0] == 400
    assert gateway.raw("GET", "/api/plugin-runner/v1/run-list?" + "a" * 513)[0] == 400
    assert upstream.requests == []
    assert gateway.raw("GET", "/api/plugin-runner/v1/run-list?a=1")[0] == 200
    assert upstream.requests[0].path == "/api/plugin-runner/v1/run-list?a=1"


def test_a_body_over_eight_megabytes_is_refused_unread(gateway, upstream):
    conn = http.client.HTTPConnection("127.0.0.1", gateway.port, timeout=10)
    conn.putrequest("POST", "/api/plugin-gateway/v1/data/put", skip_accept_encoding=True)
    conn.putheader("Content-Length", str(9 * 1024 * 1024))
    conn.endheaders()  # the body is never sent: the length alone is refused
    assert conn.getresponse().status == 413
    assert upstream.requests == []


def test_a_chunked_body_is_refused(gateway, upstream):
    conn = http.client.HTTPConnection("127.0.0.1", gateway.port, timeout=10)
    conn.putrequest("POST", "/api/plugin-gateway/v1/data/put", skip_accept_encoding=True)
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(b"2\r\n{}\r\n0\r\n\r\n")
    assert conn.getresponse().status == 411
    assert upstream.requests == []


def test_a_body_on_get_is_refused(gateway, upstream):
    assert gateway.raw("GET", "/api/plugin-runner/v1/run-list", b"{}")[0] == 400
    assert upstream.requests == []


def test_the_runner_door_forwards_only_runner_paths(runner_door, upstream):
    assert runner_door.raw("GET", "/runner/v1/health", headers={"X-Plugin-Runner-Key": "rk"})[0] == 200
    assert runner_door.raw("POST", "/runner/v1/plugins/echo/actions/echo", b"{}")[0] == 200
    assert runner_door.raw("GET", "/runner/v1/plugins/echo/logs?lines=5")[0] == 200
    for path in ("/api/plugin-gateway/v1/data/get", "/runner/v2/health", "/runner/v1/../v1/health",
                 "/runner/v1//health", "/runner/v1/%68ealth", "/", "/runner/v1"):
        assert runner_door.raw("GET", path)[0] == 404, path
    assert [r.path for r in upstream.requests] == ["/runner/v1/health", "/runner/v1/plugins/echo/actions/echo",
                                                   "/runner/v1/plugins/echo/logs?lines=5"]
    assert upstream.requests[0].headers["x-plugin-runner-key"] == "rk"


def test_a_slow_upstream_is_504(upstream):
    upstream.delay = 2
    p = Proxy("gateway", upstream.base_url, timeout=0.5)
    try:
        assert p.raw("POST", "/api/plugin-gateway/v1/llm/invoke", b"{}")[0] == 504
    finally:
        p.close()


def test_an_unreachable_upstream_is_502():
    p = Proxy("gateway", f"http://127.0.0.1:{free_port()}")
    try:
        assert p.raw("POST", "/api/plugin-gateway/v1/data/get", b"{}")[0] == 502
    finally:
        p.close()


def test_an_oversized_answer_is_502(upstream):
    upstream.answer_raw(200, "x" * 4096, "text/plain")
    p = Proxy("gateway", upstream.base_url, max_response=1024)
    try:
        assert p.raw("POST", "/api/plugin-gateway/v1/data/get", b"{}")[0] == 502
    finally:
        p.close()


def test_the_log_line_has_no_header_body_or_query(gateway, upstream):
    gateway.raw("POST", "/api/plugin-gateway/v1/data/put", b'{"v":"body-secret-1"}',
                {"Authorization": "Bearer header-secret-2"})
    gateway.raw("GET", "/api/plugin-runner/v1/run-list?q=query-secret-3",
                headers={"X-Plugin-Runner-Key": "key-secret-4"})
    gateway.raw("POST", "/api/projects", b'{"v":"body-secret-5"}')
    wait_until(lambda: gateway.log.getvalue().count("\n") >= 3)
    text = gateway.log.getvalue()
    for secret in ("body-secret-1", "header-secret-2", "query-secret-3", "key-secret-4", "body-secret-5"):
        assert secret not in text
    lines = text.strip().splitlines()
    assert lines[0].split()[:4] == ["[plugin-gateway]", "gateway", "POST", "/api/plugin-gateway/v1/data/put"]
    assert lines[0].split()[4] == "200" and lines[0].endswith("ms")
    assert " 404 " in lines[2]


def _probe(gateway_port, runner_port):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(RUNNER_ROOT),
           "PLUGIN_PROXY_GATEWAY_PORT": str(gateway_port), "PLUGIN_PROXY_RUNNER_PORT": str(runner_port)}
    return subprocess.run([sys.executable, "-m", "gateway_proxy.healthcheck"], env=env, cwd="/",
                          capture_output=True, timeout=30).returncode


def test_the_probe_needs_both_listeners(gateway, runner_door):
    assert _probe(gateway.port, runner_door.port) == 0
    assert _probe(gateway.port, free_port()) == 1
    assert _probe(free_port(), runner_door.port) == 1


def test_the_proxy_imports_only_the_standard_library():
    import ast
    allowed = set(sys.stdlib_module_names) | {"gateway_proxy", "__future__"}
    for path in (RUNNER_ROOT / "gateway_proxy").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else [])
            for name in names:
                assert name.split(".")[0] in allowed, f"{path.name} imports {name}"


def test_main_listens_on_both_ports(monkeypatch):
    g, r = free_port(), free_port()
    env = dict(os.environ, PYTHONPATH=str(RUNNER_ROOT), PLUGIN_PROXY_BIND="127.0.0.1",
               PLUGIN_PROXY_GATEWAY_PORT=str(g), PLUGIN_PROXY_RUNNER_PORT=str(r),
               PLUGIN_GATEWAY_UPSTREAM="http://127.0.0.1:9", PLUGIN_RUNNER_UPSTREAM="http://127.0.0.1:9")
    proc = subprocess.Popen([sys.executable, "-m", "gateway_proxy.proxy"], env=env, cwd="/",
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        def both_up():
            for port in (g, r):
                with socket.socket() as s:
                    if s.connect_ex(("127.0.0.1", port)) != 0:
                        return False
            return True
        wait_until(both_up)
    finally:
        proc.terminate()
        proc.wait(10)


# --- one plugin must not take the proxy down for every other caller (phase 03 review) ---

def _closed_within(sock, seconds):
    """True when the proxy closes `sock` within `seconds` (whatever it sends first)."""
    sock.settimeout(seconds)
    try:
        while sock.recv(4096):
            pass
        return True
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False


def test_an_idle_or_stalled_connection_is_closed(monkeypatch, upstream):
    monkeypatch.setattr(proxy, "CLIENT_TIMEOUT", 1.0)
    p = Proxy("gateway", upstream.base_url)
    try:
        idle = socket.create_connection(("127.0.0.1", p.port))
        stalled = socket.create_connection(("127.0.0.1", p.port))
        stalled.sendall(b"POST /api/plugin-gateway/v1/data/get HTTP/1.1\r\nHost: x\r\n"
                        b"Content-Length: 100\r\n\r\n{")
        assert _closed_within(idle, 5) and _closed_within(stalled, 5)
        idle.close()
        stalled.close()
        assert upstream.requests == []
    finally:
        p.close()


def test_a_full_listener_refuses_at_once_and_the_other_listener_still_answers(monkeypatch, upstream):
    monkeypatch.setattr(proxy, "MAX_CONNECTIONS", 4)
    gateway, runner_door = Proxy("gateway", upstream.base_url), Proxy("runner", upstream.base_url)
    # Accepted in order, each taking its slot in the accept loop: the fifth finds none.
    held = [socket.create_connection(("127.0.0.1", gateway.port)) for _ in range(4)]

    def answers_again():
        try:
            return gateway.raw("POST", "/api/plugin-gateway/v1/data/get", b"{}")[0] == 200
        except (BrokenPipeError, ConnectionResetError):
            return False  # still refused at accept while the closed sockets free their slots

    try:
        # A full listener writes its 503 at accept and closes without reading the request,
        # so a client that sends first can meet a broken pipe: read the answer before sending.
        with socket.create_connection(("127.0.0.1", gateway.port), timeout=10) as fifth:
            answer = b"".join(iter(lambda: fifth.recv(4096), b""))
        assert answer.startswith(b"HTTP/1.1 503") and b"proxy_busy" in answer
        assert runner_door.raw("GET", "/runner/v1/health")[0] == 200
        for s in held:
            s.close()
        wait_until(answers_again, timeout=10)
    finally:
        for s in held:
            s.close()
        gateway.close()
        runner_door.close()


def test_buffered_bodies_and_answers_share_a_memory_budget(monkeypatch, upstream):
    monkeypatch.setattr(proxy, "BUFFER_BYTES", 1024 * 1024)
    p = Proxy("gateway", upstream.base_url)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
        conn.putrequest("POST", "/api/plugin-gateway/v1/data/put", skip_accept_encoding=True)
        conn.putheader("Content-Length", str(2 * 1024 * 1024))
        conn.endheaders()  # refused on the length alone, before a byte of it is read
        r = conn.getresponse()
        assert r.status == 503 and b"proxy_busy" in r.read() and upstream.requests == []
        conn.close()
        upstream.answer_raw(200, "y" * (2 * 1024 * 1024), "text/plain")
        status, _, body = p.raw("POST", "/api/plugin-gateway/v1/data/get", b"{}")
        assert status == 503 and b"proxy_busy" in body
        # Released after each request: a small call passes again.
        upstream.answer_json(200, {"ok": True})
        assert p.raw("POST", "/api/plugin-gateway/v1/data/get", b"{}")[0] == 200
    finally:
        p.close()


# Never under 660 s: the Gateway's LLM calls take up to 600 s whatever the action cap.
@pytest.mark.parametrize("value,expected", [(None, 960.0), ("1200", 1260.0), ("120", 660.0), ("", 960.0),
                                            ("abc", 960.0), ("0", 960.0)])
def test_the_upstream_timeout_outlasts_the_action_cap(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("PLUGIN_ACTION_MAX_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("PLUGIN_ACTION_MAX_TIMEOUT", value)
    assert proxy.upstream_timeout() == expected

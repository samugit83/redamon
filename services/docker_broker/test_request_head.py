"""The daemon must get one request per connection, and only the one checked.

The daemon's Go HTTP server ends a line at a bare LF and keeps a connection
open for the next request. The broker split heads on CRLF and forwarded the
client's header bytes, so `GET /_ping ...\\nContent-Length: 0\\n\\nGET
/containers/<not ours>/json ...` was one allowed ping to the broker and two
requests to the daemon: the second, never checked, returned another container's
inspect (or created a container with a refused bind and no owner label). And an
attach was piped both ways at once: when the daemon refused it before taking the
connection over (an API version too old, a bad query), it read the client's next
bytes as a new request. Both reproduced on Docker Engine 29.10.

`GoLikeDaemon` reads requests as Go does (LF line ends, keep-alive, attach
refused below API 1.40 or on a bad query escape); "refused" means a 403 and
that the daemon never received the smuggled request.
"""
import asyncio
import contextlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import INFRA, Daemon, request_bytes, run_through_broker, status_of  # noqa: E402

V = "/v1.57"
OWNED = "redamon-tool-owned"


class GoLikeDaemon:
    def __init__(self, attach_answer_after=0.0, attach_never_answers_for=None):
        self.labels = {INFRA: {"com.docker.compose.service": "recon-orchestrator"},
                       OWNED: {broker._OWNER_LABEL: "1"}}
        self.received = []
        self.attach_answer_after = attach_answer_after
        self.attach_never_answers_for = attach_never_answers_for
        self.ids = {}          # name or id prefix -> the container's full id
        self.states = {}       # full id or name -> State.Status
        self.live = 0          # broker-owned containers not exited (what /containers/json counts)
        self.running = 0       # of which running
        self.waits_closed = []  # monotonic times at which the broker closed a held wait

    async def serve(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                request_line = line.rstrip(b"\r\n").decode("latin1")
                if not request_line:
                    continue
                headers = {}
                while True:
                    h = await reader.readline()
                    if not h or h.rstrip(b"\r\n") == b"":
                        break
                    k, _, v = h.decode("latin1").rstrip("\r\n").partition(":")
                    headers[k.strip().lower()] = v.strip()
                n = int(headers.get("content-length", "0") or 0)
                body = await reader.readexactly(n) if n else b""
                method, target = request_line.split(" ")[:2]
                path, _, query = target.partition("?")
                self.received.append({"method": method, "path": path, "headers": headers, "body": body})
                close = "close" in headers.get("connection", "").lower()
                if path.endswith("/attach"):
                    if self.attach_never_answers_for is not None:
                        await asyncio.sleep(self.attach_never_answers_for)
                        return
                    await asyncio.sleep(self.attach_answer_after)
                    version = re.match(r"^/v(\d+)\.(\d+)/", path)
                    too_old = version and (int(version.group(1)), int(version.group(2))) < (1, 40)
                    if too_old or re.search(r"%(?![0-9A-Fa-f]{2})", query):
                        self._answer(writer, 400, {"message": "refused before the upgrade"}, close)
                        await writer.drain()
                        if close:
                            return
                        continue
                    writer.write(b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\n"
                                 b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
                    await writer.drain()
                    while True:          # the "container" echoes its stdin
                        data = await reader.read(65536)
                        if not data:
                            return
                        writer.write(data)
                        await writer.drain()
                if method == "POST" and path.endswith("/wait"):
                    # The daemon sends its headers at once, then nothing until the
                    # container exits: for one never started, never.
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n")
                    await writer.drain()
                    while await reader.read(65536):
                        pass
                    self.waits_closed.append(time.monotonic())
                    return
                if method == "GET" and re.match(r"^/(?:v[\d.]+/)?containers/json$", path):
                    flt = json.loads(urllib.parse.parse_qs(query).get("filters", ["{}"])[0])
                    count = self.live if "created" in flt.get("status", []) else self.running
                    self._answer(writer, 200, [{"Id": f"c{i}"} for i in range(count)], close)
                    await writer.drain()
                    if close:
                        return
                    continue
                inspect = re.match(r"^/(?:v[\d.]+/)?containers/([^/]+)/json$", path)
                if method == "GET" and inspect:
                    name = inspect.group(1)
                    full = self.ids.get(name, name)
                    labels = self.labels.get(name, self.labels.get(full))
                    if labels is None:
                        self._answer(writer, 404, {"message": "No such container"}, close)
                    else:
                        self._answer(writer, 200, {"Id": full, "Config": {"Labels": labels},
                                                   "State": {"Status": self.states.get(full, "created")}}, close)
                elif method == "POST" and path.endswith("/containers/create"):
                    cid = uuid.uuid4().hex
                    self.labels[cid] = (json.loads(body or b"{}").get("Labels") or {})
                    self._answer(writer, 201, {"Id": cid, "Warnings": []}, close)
                else:
                    self._answer(writer, 200, {}, close)
                await writer.drain()
                if close:
                    return
        finally:
            writer.close()

    @staticmethod
    def _answer(writer, status, payload, close):
        data = json.dumps(payload).encode()
        writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n"
                     f"{'Connection: close' + chr(13) + chr(10) if close else ''}\r\n".encode() + data)

    def got(self, method, path):
        return any(r["method"] == method and r["path"] == path for r in self.received)


async def _exchange(daemon, raw, after_upgrade=None):
    """Send raw bytes through the broker; read the answer to EOF (2 s idle).
    With after_upgrade, send it once a 101 is in and keep reading."""
    tmp = tempfile.mkdtemp(prefix="broker-head-")
    up_sock, br_sock = os.path.join(tmp, "up.sock"), os.path.join(tmp, "br.sock")
    old = broker.UPSTREAM_SOCK
    broker.UPSTREAM_SOCK = up_sock
    try:
        up = await asyncio.start_unix_server(daemon.serve, path=up_sock)
        br = await asyncio.start_unix_server(broker.handle_client, path=br_sock)
        async with up, br:
            reader, writer = await asyncio.open_unix_connection(br_sock)
            writer.write(raw)
            await writer.drain()
            out, sent = b"", False
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=2)
                    if not chunk:
                        break
                    out += chunk
                    if after_upgrade and not sent and out.startswith(b"HTTP/1.1 101") and b"\r\n\r\n" in out:
                        writer.write(after_upgrade)
                        await writer.drain()
                        writer.write_eof()
                        sent = True
            except asyncio.TimeoutError:
                pass
            writer.close()
    finally:
        broker.UPSTREAM_SOCK = old
    return out


def _run(raw, after_upgrade=None):
    daemon = GoLikeDaemon()
    return asyncio.run(_exchange(daemon, raw, after_upgrade)), daemon


# ---------------------------------------------------------------------------
# S1: a head the daemon could split differently never reaches it
# ---------------------------------------------------------------------------

def test_a_bare_lf_cannot_smuggle_an_inspect_of_a_container_the_broker_did_not_create():
    raw = (b"GET /v1.57/_ping HTTP/1.1\r\nHost: x\nContent-Length: 0\n\n"
           b"GET /v1.57/containers/" + INFRA.encode() + b"/json HTTP/1.1\nHost: y\nX-Pad: z\r\n\r\n")
    out, daemon = _run(raw)
    assert status_of(out) == 403, out[:300]
    assert b"recon-orchestrator" not in out
    assert not daemon.got("GET", f"{V}/containers/{INFRA}/json")
    assert not daemon.received


def test_a_bare_lf_cannot_smuggle_an_unchecked_create():
    body = json.dumps({"Image": "alpine", "HostConfig": {"Binds": ["/etc:/hostetc"]}}).encode()
    raw = (b"GET /v1.57/_ping HTTP/1.1\r\nHost: x\nContent-Length: 0\n\n"
           b"POST /v1.57/containers/create?name=smuggled HTTP/1.1\nHost: y\nContent-Type: application/json\n"
           b"X-Pad: z\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    out, daemon = _run(raw)
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/create")


INFO = b"GET /v1.57/info HTTP/1.1\r\n"
MALFORMED = {
    "bare-LF-in-a-header": INFO + b"Host: x\nX-A: b\r\n\r\n",
    "bare-LF-after-the-request-line": b"GET /v1.57/info HTTP/1.1\nHost: x\r\n\r\n",
    "bare-CR": INFO + b"Host: x\rX-A: b\r\n\r\n",
    "NUL": INFO + b"Host: x\x00y\r\n\r\n",
    "vertical-tab": INFO + b"Host: x\x0by\r\n\r\n",
    "DEL": INFO + b"Host: x\x7fy\r\n\r\n",
    "folded-line-space": INFO + b"Host: x\r\n y\r\n\r\n",
    "folded-line-tab": INFO + b"Host: x\r\n\ty\r\n\r\n",
    "space-in-a-name": INFO + b"Host: x\r\nX A: b\r\n\r\n",
    "space-before-the-colon": INFO + b"Host: x\r\nX-A : b\r\n\r\n",
    "no-colon": INFO + b"Host: x\r\nfoo\r\n\r\n",
    "empty-name": INFO + b"Host: x\r\n: b\r\n\r\n",
    "repeated-Content-Length": INFO + b"Host: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
    "Transfer-Encoding": INFO + b"Host: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding-and-Content-Length": INFO + b"Host: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
    "Content-Length-plus": INFO + b"Host: x\r\nContent-Length: +0\r\n\r\n",
    "Content-Length-list": INFO + b"Host: x\r\nContent-Length: 0, 0\r\n\r\n",
    "Content-Length-5000-digits": INFO + b"Host: x\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n",
    "repeated-Host": INFO + b"Host: x\r\nHost: y\r\n\r\n",
    "request-line-extra-word": b"GET /v1.57/info HTTP/1.1 x\r\nHost: x\r\n\r\n",
    "request-line-version": b"GET /v1.57/info HTTP/2.0\r\nHost: x\r\n\r\n",
}


@pytest.mark.parametrize("raw", list(MALFORMED.values()), ids=list(MALFORMED))
def test_a_head_the_daemon_could_read_differently_is_refused(raw, capsys):
    [resp], daemon = run_through_broker([raw], Daemon())
    assert status_of(resp) == 403, resp[:300]
    assert b"malformed request head" in resp
    assert not daemon.received
    assert "DENY" in capsys.readouterr().out


def test_the_daemon_gets_only_the_allowlisted_headers():
    body = json.dumps({"Image": "alpine"}).encode()
    raw = (b"POST /v1.57/containers/create HTTP/1.1\r\nHost: api.moby.localhost\r\n"
           b"User-Agent: Docker-Client/29.10.0 (linux)\r\nAccept-Encoding: gzip\r\n"
           b"Content-Type: application/json\r\nX-Redamon-Run: full_recon:p:r\r\nX-Evil: 1\r\n"
           b"Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nExpect: 100-continue\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    out, daemon = _run(raw)
    assert status_of(out) == 201, out[:300]
    [create] = [r for r in daemon.received if r["path"] == f"{V}/containers/create"]
    assert set(create["headers"]) == {"host", "user-agent", "content-type", "content-length", "connection"}
    assert create["headers"]["connection"] == "close"
    assert create["headers"]["user-agent"] == "Docker-Client/29.10.0 (linux)"
    assert create["headers"]["host"] == "api.moby.localhost"
    assert int(create["headers"]["content-length"]) == len(create["body"])


def test_a_pull_keeps_its_registry_auth():
    raw = (b"POST /v1.57/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=latest HTTP/1.1\r\n"
           b"Host: api.moby.localhost\r\nUser-Agent: Docker-Client/29.10.0 (linux)\r\nContent-Length: 0\r\n"
           b"X-Redamon-Run: full_recon:p:r\r\nX-Registry-Auth: e30=\r\nAccept-Encoding: gzip\r\n\r\n")
    out, daemon = _run(raw)
    assert status_of(out) == 200, out[:300]
    [pull] = daemon.received
    assert pull["headers"]["x-registry-auth"] == "e30="
    assert set(pull["headers"]) == {"host", "user-agent", "x-registry-auth", "content-length", "connection"}


# ---------------------------------------------------------------------------
# S2: an attach is piped only once the daemon has taken the connection over
# ---------------------------------------------------------------------------

ATTACH = ("POST {path}?stream=1&stdout=1&stderr=1{extra} HTTP/1.1\r\nHost: api.moby.localhost\r\n"
          "Content-Length: 0\r\nContent-Type: text/plain\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
SMUGGLED = f"GET {V}/containers/{INFRA}/json HTTP/1.1\r\nHost: y\r\nConnection: close\r\n\r\n".encode()


@pytest.mark.parametrize("path,extra", [
    (f"/v1.24/containers/{OWNED}/attach", ""),        # API version below the daemon's minimum
    (f"{V}/containers/{OWNED}/attach", "&x=%zz"),     # a query the daemon cannot decode
], ids=["too-old", "bad-escape"])
def test_an_attach_the_daemon_refuses_never_pipes_the_next_request(path, extra):
    out, daemon = _run(ATTACH.format(path=path, extra=extra).encode() + SMUGGLED)
    assert status_of(out) == 400, out[:300]
    assert b"recon-orchestrator" not in out
    assert not daemon.got("GET", f"{V}/containers/{INFRA}/json")


def test_an_attach_without_the_upgrade_is_refused():
    raw = (f"POST {V}/containers/{OWNED}/attach?stream=1&stdout=1 HTTP/1.1\r\nHost: x\r\n"
           f"Content-Length: 0\r\n\r\n").encode() + SMUGGLED
    out, daemon = _run(raw)
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/{OWNED}/attach")
    assert not daemon.got("GET", f"{V}/containers/{INFRA}/json")


def test_an_upgraded_attach_still_streams_both_ways():
    out, daemon = _run(ATTACH.format(path=f"{V}/containers/{OWNED}/attach", extra="").encode(),
                       after_upgrade=b"hello from stdin\n")
    head, _, stream = out.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 101"), out[:300]
    assert stream == b"hello from stdin\n"
    [attach] = [r for r in daemon.received if r["path"].endswith("/attach")]
    assert attach["headers"]["upgrade"] == "tcp" and attach["headers"]["connection"] == "Upgrade"
    assert urllib.parse.urlsplit("x://h" + attach["path"]).path == f"{V}/containers/{OWNED}/attach"


# ---------------------------------------------------------------------------
# Round 3. A: the head is read in one bounded readuntil, not a byte at a time;
# B: heads and bodies have deadlines, idle connections a budget, attach
# streams a budget, and a flood logs a few lines; D: an attach waits long for
# the daemon's answer and logs when it gives up.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _fresh_log_marks(monkeypatch):
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)


@contextlib.asynccontextmanager
async def _broker(daemon):
    tmp = tempfile.mkdtemp(prefix="broker-r3-")
    up_sock, br_sock = os.path.join(tmp, "up.sock"), os.path.join(tmp, "br.sock")
    old = broker.UPSTREAM_SOCK
    broker.UPSTREAM_SOCK = up_sock
    up = await asyncio.start_unix_server(daemon.serve, path=up_sock)
    # As main() starts it: the reader limit bounds the head.
    br = await asyncio.start_unix_server(broker.handle_client, path=br_sock,
                                         limit=getattr(broker, "HEAD_MAX", 2 ** 16))
    try:
        yield br_sock
    finally:
        broker.UPSTREAM_SOCK = old
        up.close()
        br.close()


async def _answer(reader, timeout):
    """(first bytes of the answer or b"", seconds) within timeout, or (None, timeout)."""
    t = time.monotonic()
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout)
    except asyncio.TimeoutError:
        return None, timeout
    except ConnectionError:
        data = b""
    return data, time.monotonic() - t


async def _ping(sock, timeout=10):
    t = time.monotonic()
    r, w = await asyncio.open_unix_connection(sock)
    w.write(b"GET /v1.57/_ping HTTP/1.1\r\nHost: docker\r\n\r\n")
    data, _ = await _answer(r, timeout)
    w.close()
    return status_of(data or b""), time.monotonic() - t


def _within(coro, seconds=30):
    return asyncio.run(asyncio.wait_for(coro, seconds))


def test_a_head_over_the_limit_is_refused_at_once_and_a_ping_meanwhile_is_answered():
    async def go():
        async with _broker(GoLikeDaemon()) as sock:
            r, w = await asyncio.open_unix_connection(sock)
            w.write(b"GET /v1.57/_ping HTTP/1.1\r\nX-Pad: " + b"a" * (200 * 1024))
            pinged = asyncio.ensure_future(_ping(sock))
            answer = await _answer(r, 5)
            w.close()
            return answer, await pinged
    (answer, refused_in), (ping_status, ping_in) = _within(go())
    assert answer is not None and status_of(answer) == 403, answer
    assert f"request head over {broker.HEAD_MAX} bytes".encode() in answer
    assert refused_in < 1.0, refused_in
    assert ping_status == 200 and ping_in < 1.0, (ping_status, ping_in)


def test_a_large_registry_credential_still_fits_the_head():
    auth = "e" * 22000            # an 8 KiB password + 8 KiB identity token, base64-encoded: 22 KB
    raw = (b"POST /v1.57/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=latest HTTP/1.1\r\n"
           b"Host: api.moby.localhost\r\nContent-Length: 0\r\nX-Registry-Auth: " + auth.encode() + b"\r\n\r\n")
    out, daemon = _run(raw)
    assert status_of(out) == 200, out[:300]
    [pull] = daemon.received
    assert pull["headers"]["x-registry-auth"] == auth


def test_a_head_that_never_ends_is_dropped_at_the_head_deadline(monkeypatch):
    monkeypatch.setattr(broker, "HEAD_TIMEOUT", 0.3, raising=False)

    async def go():
        async with _broker(GoLikeDaemon()) as sock:
            r, w = await asyncio.open_unix_connection(sock)
            w.write(b"GET /v1.57/_ping HTTP/1.1\r\nHost: docker\r\n")
            answer = await _answer(r, 3)
            w.close()
            return answer
    answer, after = _within(go())
    assert answer is not None and b"request head not complete within" in answer, answer
    assert after < 2.0


def test_a_body_shorter_than_its_length_is_dropped_at_the_body_deadline(monkeypatch):
    monkeypatch.setattr(broker, "BODY_TIMEOUT", 0.3, raising=False)
    daemon = GoLikeDaemon()

    async def go():
        async with _broker(daemon) as sock:
            r, w = await asyncio.open_unix_connection(sock)
            w.write(b"POST /v1.57/containers/create HTTP/1.1\r\nHost: docker\r\n"
                    b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"Image\":\"alp")
            answer = await _answer(r, 3)
            w.close()
            return answer
    answer, after = _within(go())
    assert answer is not None and b"request body not complete within" in answer, answer
    assert after < 2.0
    assert not daemon.got("POST", f"{V}/containers/create")


def test_idle_connections_cannot_keep_a_request_out(monkeypatch):
    # With the budget full, the connection waiting longest for its head is closed.
    monkeypatch.setattr(broker, "MAX_PENDING_HEADS", 4, raising=False)
    monkeypatch.setattr(broker, "HEAD_TIMEOUT", 5, raising=False)

    async def go():
        async with _broker(GoLikeDaemon()) as sock:
            idle = []
            for _ in range(6):
                r, w = await asyncio.open_unix_connection(sock)
                w.write(b"G")
                idle.append((r, w))
                await asyncio.sleep(0.05)
            status, took = await _ping(sock)
            fates = [await _answer(r, 0.5) for r, _ in idle]
            for _, w in idle:
                w.close()
            return status, took, fates
    status, took, fates = _within(go())
    assert status == 200 and took < 1.0, (status, took)
    closed = [data is not None for data, _ in fates]
    assert closed == [True, True, True, False, False, False], fates


def test_an_attach_the_daemon_never_answers_counts_in_the_attach_budget_and_is_dropped_logged(monkeypatch, capsys):
    monkeypatch.setattr(broker, "MAX_ATTACH_STREAMS", 1, raising=False)
    monkeypatch.setattr(broker, "ATTACH_ANSWER_TIMEOUT", 0.8, raising=False)
    daemon = GoLikeDaemon(attach_never_answers_for=1.5)
    daemon.labels["redamon-tool-owned-2"] = {broker._OWNER_LABEL: "1"}

    async def go():
        async with _broker(daemon) as sock:
            r1, w1 = await asyncio.open_unix_connection(sock)
            w1.write(ATTACH.format(path=f"{V}/containers/{OWNED}/attach", extra="").encode())
            await asyncio.sleep(0.3)
            r2, w2 = await asyncio.open_unix_connection(sock)
            w2.write(ATTACH.format(path=f"{V}/containers/redamon-tool-owned-2/attach", extra="").encode())
            second = await _answer(r2, 2)
            first = await _answer(r1, 3)
            w1.close()
            w2.close()
            return first, second
    (first, first_after), (second, _) = _within(go())
    assert second is not None and status_of(second) == 403, second
    assert b"attach streams are already open" in second
    assert first == b"", first          # dropped once ATTACH_ANSWER_TIMEOUT passed
    out = capsys.readouterr().out
    assert "DROP POST" in out and "did not answer the attach within" in out


def test_an_attach_answered_late_is_still_relayed():
    out = asyncio.run(_exchange(GoLikeDaemon(attach_answer_after=1.5),
                                ATTACH.format(path=f"{V}/containers/{OWNED}/attach", extra="").encode(),
                                after_upgrade=b"late\n"))
    assert out.startswith(b"HTTP/1.1 101"), out[:200]
    assert out.endswith(b"late\n")


def test_the_attach_answer_bound_is_long():
    assert broker.ATTACH_ANSWER_TIMEOUT >= 600


def test_the_open_file_limit_is_raised_to_the_hard_limit_and_sizes_the_budgets(monkeypatch):
    resource = pytest.importorskip("resource")
    before = resource.getrlimit(resource.RLIMIT_NOFILE)
    for name in ("MAX_PENDING_HEADS", "MAX_ATTACH_STREAMS"):
        monkeypatch.setattr(broker, name, getattr(broker, name, None), raising=False)
    try:
        soft = broker.raise_nofile_limit()
        now = resource.getrlimit(resource.RLIMIT_NOFILE)
        if before[1] != resource.RLIM_INFINITY:
            assert now == (before[1], before[1]) and soft == before[1]
        assert broker.MAX_PENDING_HEADS == max(16, min(4096, soft // 8))
        assert broker.MAX_ATTACH_STREAMS == broker.MAX_LONG_CALLS == max(16, min(1024, soft // 8))
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, before)


def test_a_flood_of_loop_errors_logs_one_line_and_then_the_count(monkeypatch, capsys):
    error = {"message": "socket.accept() out of system resource", "exception": OSError(24, "Too many open files")}
    for _ in range(500):
        broker._loop_exception(None, error)
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1 and "Too many open files" in out[0], out
    monkeypatch.setattr(broker, "_LOG_INTERVAL", 0.0)
    broker._loop_exception(None, error)
    assert "(and 499 more like it)" in capsys.readouterr().out


def test_a_flood_of_bad_heads_is_refused_and_logged_once(capsys):
    raw = INFO + b"Host: x\nX-A: b\r\n\r\n"
    responses, daemon = run_through_broker([raw] * 30, Daemon())
    assert [status_of(r) for r in responses] == [403] * 30
    assert not daemon.received
    assert len([ln for ln in capsys.readouterr().out.splitlines() if "DENY" in ln]) == 1


def test_a_refused_header_line_is_never_echoed(capsys):
    secret = b"c2VjcmV0LXJlZ2lzdHJ5LXRva2Vu"
    raw = (b"POST /v1.57/images/create?fromImage=alpine&tag=latest HTTP/1.1\r\nHost: x\r\n"
           b"X-Registry-Auth : " + secret + b"\r\nContent-Length: 0\r\n\r\n")
    [resp], daemon = run_through_broker([raw], Daemon())
    assert status_of(resp) == 403, resp[:300]
    assert secret not in resp
    assert not daemon.received
    out = capsys.readouterr().out
    assert "DENY" in out and secret.decode() not in out


# ---------------------------------------------------------------------------
# Round 4. 1: one attach, wait and logs per container (by its full id), and a
# created or restarted container counts against the container cap; 2: a caller
# that hangs up closes the daemon side of its call, long calls have a budget;
# 5: the pending-head budget and the listen backlog.
# ---------------------------------------------------------------------------

FULL_ID = "f" * 64


def _owned_by_name_and_id(daemon):
    """OWNED reachable as its name, its full id and a 12-character prefix."""
    for alias in (OWNED, FULL_ID, FULL_ID[:12]):
        daemon.ids[alias] = FULL_ID
        daemon.labels[alias] = {broker._OWNER_LABEL: "1"}
    return daemon


async def _held_attach(sock, name):
    r, w = await asyncio.open_unix_connection(sock)
    w.write(ATTACH.format(path=f"{V}/containers/{name}/attach", extra="").encode())
    head, _ = await _answer(r, 2)
    return r, w, head


def test_one_attach_per_container_whatever_name_it_is_reached_by():
    daemon = _owned_by_name_and_id(GoLikeDaemon())

    async def go():
        async with _broker(daemon) as sock:
            r1, w1, first = await _held_attach(sock, OWNED)
            seconds = [(await _held_attach(sock, alias))[2] for alias in (OWNED, FULL_ID, FULL_ID[:12])]
            w1.close()                       # the first attach ends: the container is free again
            await asyncio.sleep(0.3)
            r3, w3, again = await _held_attach(sock, FULL_ID[:12])
            w3.close()
            return first, seconds, again
    first, seconds, again = _within(go())
    assert first.startswith(b"HTTP/1.1 101"), first
    for second in seconds:
        assert status_of(second) == 403 and b"already has an open attach" in second, second
    assert again.startswith(b"HTTP/1.1 101"), again


def _create(daemon, body=None):
    raw = request_bytes("POST", f"{V}/containers/create", body or {"Image": "alpine"})
    [resp], _ = run_through_broker([raw], daemon)
    return resp


def test_a_created_container_counts_against_the_container_cap(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 2)
    daemon = GoLikeDaemon()
    daemon.live, daemon.running = 2, 0      # two created, none started yet
    resp = _create(daemon)
    assert status_of(resp) == 403 and b"count cap reached (2/2)" in resp, resp[:300]
    assert not daemon.got("POST", f"{V}/containers/create")


def test_a_start_of_an_exited_container_is_capped_and_of_a_created_one_is_not(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 1)
    daemon = _owned_by_name_and_id(GoLikeDaemon())
    daemon.live = 1
    daemon.states[FULL_ID] = "exited"
    [resp], _ = run_through_broker([request_bytes("POST", f"{V}/containers/{OWNED}/start")], daemon)
    assert status_of(resp) == 403 and b"count cap reached (1/1)" in resp, resp[:300]
    assert not daemon.got("POST", f"{V}/containers/{OWNED}/start")
    daemon.states[FULL_ID] = "created"      # already counted: starting it adds nothing
    [resp], _ = run_through_broker([request_bytes("POST", f"{V}/containers/{OWNED}/start")], daemon)
    assert status_of(resp) == 200, resp[:300]


def test_a_caller_that_hangs_up_closes_the_daemon_side_of_its_wait():
    daemon = _owned_by_name_and_id(GoLikeDaemon())

    async def go():
        async with _broker(daemon) as sock:
            r, w = await asyncio.open_unix_connection(sock)
            w.write(request_bytes("POST", f"{V}/containers/{OWNED}/wait?condition=next-exit"))
            head, _ = await _answer(r, 2)
            hung_up = time.monotonic()
            w.close()
            for _ in range(20):
                if daemon.waits_closed:
                    break
                await asyncio.sleep(0.05)
            return head, hung_up
    head, hung_up = _within(go())
    assert head.startswith(b"HTTP/1.1 200"), head
    assert daemon.waits_closed, "the broker kept the daemon side of an abandoned wait open"
    assert daemon.waits_closed[0] - hung_up < 1.0


def test_one_wait_per_container_and_a_budget_for_long_calls(monkeypatch):
    daemon = _owned_by_name_and_id(GoLikeDaemon())
    daemon.labels["redamon-tool-owned-2"] = {broker._OWNER_LABEL: "1"}
    monkeypatch.setattr(broker, "MAX_LONG_CALLS", 1, raising=False)

    async def go():
        async with _broker(daemon) as sock:
            r1, w1 = await asyncio.open_unix_connection(sock)
            w1.write(request_bytes("POST", f"{V}/containers/{OWNED}/wait?condition=next-exit"))
            first, _ = await _answer(r1, 2)
            answers = []
            for name in (FULL_ID[:12], "redamon-tool-owned-2"):
                r, w = await asyncio.open_unix_connection(sock)
                w.write(request_bytes("POST", f"{V}/containers/{name}/wait?condition=next-exit"))
                answers.append((await _answer(r, 2))[0])
                w.close()
            w1.close()
            return first, answers
    first, (same_container, other_container) = _within(go())
    assert first.startswith(b"HTTP/1.1 200"), first
    assert status_of(same_container) == 403 and b"already has an open wait" in same_container, same_container
    assert status_of(other_container) == 403 and b"long calls (wait, logs) are already open" in other_container


def test_main_listens_with_the_head_limit_a_large_backlog_and_raised_budgets(monkeypatch, tmp_path):
    resource = pytest.importorskip("resource")
    before = resource.getrlimit(resource.RLIMIT_NOFILE)
    seen = {}

    class _Server:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def serve_forever(self):
            return None

    async def fake_start(handler, path=None, **kw):
        seen.update(kw, path=path)
        return _Server()

    for name in ("MAX_PENDING_HEADS", "MAX_ATTACH_STREAMS", "MAX_LONG_CALLS"):
        monkeypatch.setattr(broker, name, getattr(broker, name, None), raising=False)
    monkeypatch.setattr(broker.asyncio, "start_unix_server", fake_start)
    monkeypatch.setattr(broker, "LISTEN_SOCK", str(tmp_path / "b.sock"))
    try:
        asyncio.run(broker.main())
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, before)
    assert seen.get("limit") == broker.HEAD_MAX
    assert seen.get("backlog", 100) >= 1024
    if before[1] >= 8 * 4096:
        assert broker.MAX_PENDING_HEADS == 4096


def test_the_deadlines_leave_room_for_a_paused_caller():
    assert broker.HEAD_TIMEOUT >= 60 and broker.BODY_TIMEOUT >= 60

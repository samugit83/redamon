"""A fake Docker daemon for driving the broker's real request handling in tests.

`run_through_broker(requests)` serves `broker.handle_client` and this fake
daemon on two unix sockets, sends each request through the broker on its own
connection (the Docker CLI's pattern), and returns what came back plus what the
daemon actually received. The daemon remembers the containers the broker
created, by id and by `?name=`, so the broker's ownership check finds the
`redamon.broker-owned` label it stamped, exactly as on a real daemon.
"""
import asyncio
import json
import os
import re
import tempfile
import urllib.parse
import uuid

import broker

INFRA = "redamon-recon-orchestrator"


class Daemon:
    def __init__(self, preexisting=None):
        # name or id -> labels; INFRA stands in for every container the broker did not create
        self.labels = {INFRA: {"com.docker.compose.service": "recon-orchestrator"}}
        self.labels.update(preexisting or {})
        self.received = []

    async def serve(self, reader, writer):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await reader.read(1)
            if not chunk:
                break
            head += chunk
        text = head.decode("latin1")
        line = text.split("\r\n", 1)[0]
        headers = {k.strip().lower(): v.strip() for k, v in
                   (h.split(":", 1) for h in text.split("\r\n")[1:] if ":" in h)}
        body = b""
        n = int(headers.get("content-length", "0") or 0)
        while len(body) < n:
            chunk = await reader.read(n - len(body))
            if not chunk:
                break
            body += chunk
        method, target = line.split(" ")[:2]
        path, _, query = target.partition("?")
        self.received.append({"method": method, "path": path, "query": query, "body": body})
        status, payload = self._answer(method, path, query, body)
        if status == 101:
            writer.write(b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\n"
                         b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
        else:
            data = json.dumps(payload).encode()
            writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
                         f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
        try:
            await writer.drain()
        finally:
            writer.close()

    def _answer(self, method, path, query, body):
        inspect = re.match(r"^/(?:v[\d.]+/)?containers/([^/]+)/json$", path)
        if method == "GET" and inspect:
            labels = self.labels.get(inspect.group(1))
            if labels is None:
                return 404, {"message": "No such container"}
            return 200, {"Id": inspect.group(1), "Config": {"Labels": labels}}
        if method == "POST" and re.match(r"^/(?:v[\d.]+/)?containers/create$", path):
            cfg = json.loads(body or b"{}")
            cid = uuid.uuid4().hex * 2
            self.labels[cid] = cfg.get("Labels") or {}
            name = urllib.parse.parse_qs(query).get("name", [""])[0]
            if name:
                self.labels[name] = self.labels[cid]
            return 201, {"Id": cid, "Warnings": []}
        if method == "POST" and re.search(r"/attach$", path):
            return 101, None
        return 200, {}

    def got(self, method, path):
        """Did the daemon receive this request (the ownership inspect aside)?"""
        return any(r["method"] == method and r["path"] == path for r in self.received)


def request_bytes(method, target, body=None, headers=()):
    data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    lines = [f"{method} {target} HTTP/1.1", "Host: api.moby.localhost"]
    if data or method in ("POST", "PUT"):
        lines += ["Content-Type: application/json", f"Content-Length: {len(data)}"]
    lines += list(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + data


async def _send(sock, raw):
    reader, writer = await asyncio.open_unix_connection(sock)
    writer.write(raw)
    await writer.drain()
    out = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=3)
            if not chunk:
                break
            out += chunk
            if out.startswith(b"HTTP/1.1 101"):
                break  # an attach stream: the upgrade is the answer
    except asyncio.TimeoutError:
        pass
    writer.close()
    return out


def status_of(response: bytes) -> int:
    try:
        return int(response.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


async def _run(daemon, steps):
    tmp = tempfile.mkdtemp(prefix="broker-mock-")
    up_sock, br_sock = os.path.join(tmp, "up.sock"), os.path.join(tmp, "br.sock")
    old = broker.UPSTREAM_SOCK
    broker.UPSTREAM_SOCK = up_sock
    results = []
    try:
        up = await asyncio.start_unix_server(daemon.serve, path=up_sock)
        br = await asyncio.start_unix_server(broker.handle_client, path=br_sock)
        async with up, br:
            for step in steps:
                raw = step(results) if callable(step) else step
                if raw is None:   # what the CLI does after a refused create: stop
                    break
                results.append(await _send(br_sock, raw))
    finally:
        broker.UPSTREAM_SOCK = old
    return results


def run_through_broker(steps, daemon=None):
    """Send each step through the broker; a step is raw request bytes, or a
    callable that builds them from the responses so far (to use a created id)
    and returns None to end the exchange. Returns (responses, daemon)."""
    daemon = daemon or Daemon()
    return asyncio.run(_run(daemon, steps)), daemon


def created_id(response: bytes):
    """The new container's id, or None when the create was refused."""
    if status_of(response) != 201:
        return None
    return json.loads(response.split(b"\r\n\r\n", 1)[1])["Id"]

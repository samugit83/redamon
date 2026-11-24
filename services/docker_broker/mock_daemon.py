"""A fake Docker daemon for driving the broker's real request handling in tests.

`run_through_broker(requests)` serves `broker.handle_client` and this fake
daemon on two unix sockets, sends each request through the broker on its own
connection (the Docker CLI's pattern), and returns what came back plus what the
daemon actually received. The daemon remembers the containers the broker
created, by id and by `?name=`, so the broker's ownership check finds the
`redamon.broker-owned` label it stamped, exactly as on a real daemon.
"""
import asyncio
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import uuid

import broker

INFRA = "redamon-recon-orchestrator"


class Daemon:
    def __init__(self, preexisting=None, auto_remove=()):
        # Every container by its full id, as the daemon keeps them, and found
        # as the daemon finds them (find). INFRA stands in for every container
        # the broker did not create; `preexisting` maps names to labels.
        self.containers = {}       # full id -> {"name", "labels"}
        self.auto_remove = set()   # full ids of the containers the daemon removes on exit
        self.states = {}           # name or full id -> State.Status ("created" when absent)
        self.received = []
        for name, labels in {INFRA: {"com.docker.compose.service": "recon-orchestrator"},
                             **(preexisting or {})}.items():
            cid = self._add(name, labels)
            if name in auto_remove:
                self.auto_remove.add(cid)

    def _add(self, name, labels):
        cid = uuid.uuid4().hex * 2
        self.containers[cid] = {"name": name, "labels": labels}
        return cid

    def find(self, ref):
        """The full id `ref` names, in the daemon's order (moby GetContainer):
        a full id, then an exact name, then a unique id prefix."""
        if ref in self.containers:
            return ref
        for cid, c in self.containers.items():
            if c["name"] == ref:
                return cid
        hits = [cid for cid in self.containers if cid.startswith(ref)]
        return hits[0] if len(hits) == 1 else None

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
            cid = self.find(inspect.group(1))
            if cid is None:
                return 404, {"message": "No such container"}
            c = self.containers[cid]
            return 200, {"Id": cid, "Name": "/" + c["name"], "Config": {"Labels": c["labels"]},
                         "HostConfig": {"AutoRemove": cid in self.auto_remove},
                         "State": {"Status": self.states.get(cid, self.states.get(c["name"], "created"))}}
        if method == "POST" and re.match(r"^/(?:v[\d.]+/)?containers/create$", path):
            cfg = json.loads(body or b"{}")
            name = urllib.parse.parse_qs(query).get("name", [""])[0]
            cid = self._add(name, cfg.get("Labels") or {})
            if (cfg.get("HostConfig") or {}).get("AutoRemove") is True:
                self.auto_remove.add(cid)
            return 201, {"Id": cid, "Warnings": []}
        if method == "POST" and re.search(r"/attach$", path):
            return 101, None
        network = re.match(r"^/(?:v[\d.]+/)?networks/([^/]+)$", path)
        if method == "GET" and network:
            # Any network the tests name exists, as the daemon answers: by its
            # name, with a full id (the broker checks the reference is one of them).
            name = network.group(1)
            return 200, {"Name": name, "Id": hashlib.sha256(name.encode()).hexdigest(), "Labels": {},
                         "IPAM": {"Config": []}}
        return 200, {}

    def got(self, method, path):
        """Did the daemon receive this request (the ownership inspect aside)?
        A call on a container counts whether it named it or its full id, which
        the broker forwards."""
        return any(r["method"] == method and r["path"] in _by_name_or_id(self, path) for r in self.received)


def _by_name_or_id(daemon, path):
    """`path`, and the same path naming its container by full id."""
    m = re.match(r"^(/(?:v[\d.]+/)?containers/)([^/]+)(.*)$", path)
    find = getattr(daemon, "was", daemon.find)
    cid = find(m.group(2)) if m and m.group(2) not in ("create", "json") else None
    return {path, m.group(1) + cid + m.group(3)} if cid else {path}


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


class ToolDaemon:
    """A daemon that keeps each container's state as the broker's checks read
    it: labels, HostConfig.AutoRemove, Config.StopTimeout and State.Status in
    the inspect; a listing that applies label and status filters (what the
    container cap counts and a run lists); and the calls that last: an attach,
    a wait, a stop, held until the broker closes them (`closed` records when).
    A create can be answered late (`create_delay`), as a loaded daemon does.
    A reference is resolved as the daemon resolves it (find), and
    `after_inspect(daemon, ref)` runs right after each inspect is answered: it
    stands in for a call the daemon handles between the broker's check and
    its forward."""

    def __init__(self, create_delay=0.0, stop_hold=30.0, after_inspect=None, create_close_delay=0.0):
        self.containers = {}   # full id -> {"name", "labels", "auto_remove", "stop_timeout", "status"}
        self.received = []     # {"method", "path", "query", "headers", "body"}
        self.closed = []       # (method, path) of held calls whose connection the broker closed
        self.create_delay = create_delay
        self.stop_hold = stop_hold
        self.counts = 0        # filtered listings answered (the cap's counts among them)
        self.after_inspect = after_inspect
        self.env = {}          # full id -> Config.Env (what an infrastructure container would leak)
        self.networks = {}     # name -> {full id: endpoint}, as a network inspect lists them
        self.gone = {}         # name -> full id of the containers removed (so got() still names them)
        self.create_close_delay = create_close_delay
        self.ended_streams = []    # (method, path) of attaches and waits the daemon itself ended
        self.attach_output = {}    # full id -> bytes an attach to it writes at once
        self.exit_codes = {}       # full id -> the StatusCode a held wait answers with
        self._stream_ends = {}     # full id -> asyncio.Event set by end_streams

    def _stream_end(self, cid):
        return self._stream_ends.setdefault(cid, asyncio.Event())

    def end_streams(self, cid):
        """The container's output ends (it exited): the daemon ends its attaches."""
        self._stream_end(cid).set()

    def was(self, ref):
        """The full id a name had, removed or not."""
        return self.find(ref) or self.gone.get(ref)

    def add(self, name, labels=None, status="created", auto_remove=False, stop_timeout=None, owned=True):
        cid = uuid.uuid4().hex + uuid.uuid4().hex
        labels = dict(labels or {})
        if owned:
            labels[broker._OWNER_LABEL] = "1"
        self.containers[cid] = {"name": name, "labels": labels, "auto_remove": auto_remove,
                                "stop_timeout": stop_timeout, "status": status}
        return cid

    find = Daemon.find

    def got(self, method, path):
        return any(r["method"] == method and r["path"] in _by_name_or_id(self, path) for r in self.received)

    def queries(self, method, path):
        paths = _by_name_or_id(self, path)
        return [r["query"] for r in self.received if r["method"] == method and r["path"] in paths]

    @staticmethod
    def _send(writer, status, payload=None, ctype="application/json"):
        data = b"" if payload is None else json.dumps(payload).encode()
        writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {len(data)}\r\n"
                     f"Connection: close\r\n\r\n".encode() + data)

    async def _hold(self, reader, method, path, seconds=None):
        try:
            if seconds is None:
                while await reader.read(65536):
                    pass
            else:
                await asyncio.wait_for(reader.read(), seconds)
        except (asyncio.TimeoutError, ConnectionError):
            return False
        self.closed.append((method, path))
        return True

    def _listing(self, query):
        flt = json.loads(urllib.parse.parse_qs(query).get("filters", ["{}"])[0] or "{}")
        labels = flt.get("label", [])
        labels = list(labels) if isinstance(labels, (list, dict)) else []
        statuses = flt.get("status")
        out = []
        for cid, c in self.containers.items():
            if statuses and c["status"] not in statuses:
                continue
            ok = True
            for want in labels:
                k, has_value, v = want.partition("=")
                if k not in c["labels"] or (has_value and c["labels"][k] != v):
                    ok = False
            if ok:
                out.append({"Id": cid, "Names": [f"/{c['name']}"], "Labels": c["labels"], "State": c["status"]})
        return out

    async def serve(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        lines = head.decode("latin1").split("\r\n")
        headers = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in lines[1:] if h)}
        n = int(headers.get("content-length", "0") or 0)
        body = await reader.readexactly(n) if n else b""
        method, target = lines[0].split(" ")[:2]
        path, _, query = target.partition("?")
        self.received.append({"method": method, "path": path, "query": query, "headers": headers, "body": body})
        try:
            await self._answer(reader, writer, method, path, query, body)
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()

    async def _answer(self, reader, writer, method, path, query, body):
        p = re.sub(r"^/v[\d.]+", "", path)
        m = re.match(r"^/containers/([^/]+)(?:/(\w+))?$", p)
        if method == "GET" and p == "/containers/json":
            self.counts += 1
            return self._send(writer, 200, self._listing(query))
        if method == "POST" and p == "/containers/create":
            if self.create_delay:
                await asyncio.sleep(self.create_delay)
            cfg = json.loads(body or b"{}")
            hc = cfg.get("HostConfig") or {}
            name = urllib.parse.parse_qs(query).get("name", [""])[0] or f"anon-{uuid.uuid4().hex[:8]}"
            cid = self.add(name, cfg.get("Labels"), auto_remove=hc.get("AutoRemove") is True,
                           stop_timeout=cfg.get("StopTimeout"), owned=False)
            self._send(writer, 201, {"Id": cid, "Warnings": []})
            if self.create_close_delay:      # the answer is out; the connection closes later
                await writer.drain()
                await asyncio.sleep(self.create_close_delay)
            return
        net = re.match(r"^/networks/([^/]+)$", p)
        if method == "GET" and net:
            if net.group(1) not in self.networks:
                return self._send(writer, 404, {"message": "network not found"})
            return self._send(writer, 200, {"Name": net.group(1), "Id": "9" * 64, "Driver": "bridge",
                                            "Containers": self.networks[net.group(1)], "Services": {}})
        if not m:
            return self._send(writer, 200, {})
        cid = self.find(m.group(1))
        verb = m.group(2) or ("remove" if method == "DELETE" else "")
        if cid is None:
            return self._send(writer, 404, {"message": "No such container"})
        c = self.containers[cid]
        if verb == "json":
            self._send(writer, 200, {
                "Id": cid, "Name": f"/{c['name']}",
                "Config": {"Labels": c["labels"], "StopTimeout": c["stop_timeout"], "Env": self.env.get(cid, [])},
                "HostConfig": {"AutoRemove": c["auto_remove"]}, "State": {"Status": c["status"]}})
            await writer.drain()
            if self.after_inspect:
                self.after_inspect(self, m.group(1))
            return
        if verb == "attach":
            writer.write(b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\n"
                         b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
            out = self.attach_output.pop(cid, b"")
            # The tool's output, written as the broker takes it: a client that
            # does not read leaves it queued at the broker.
            writer.write(out)
            # Held until the broker closes it, or the daemon ends the stream
            # (end_streams: the container's output ended).
            ended = self._stream_end(cid)
            hold = asyncio.ensure_future(self._hold(reader, method, path))
            drained = asyncio.ensure_future(writer.drain())
            done, _ = await asyncio.wait({hold, asyncio.ensure_future(ended.wait())},
                                         return_when=asyncio.FIRST_COMPLETED)
            if hold not in done:
                await drained
                hold.cancel()
                self.ended_streams.append((method, path))
            else:
                drained.cancel()
            return
        if verb == "wait":
            condition = urllib.parse.parse_qs(query).get("condition", ["not-running"])[0]
            if condition == "not-running" and c["status"] != "running":
                return self._send(writer, 200, {"StatusCode": 0})
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
            await writer.drain()
            # Held until the broker closes it, or the daemon answers it
            # (end_streams: the condition came true).
            hold = asyncio.ensure_future(self._hold(reader, method, path))
            done, _ = await asyncio.wait({hold, asyncio.ensure_future(self._stream_end(cid).wait())},
                                         return_when=asyncio.FIRST_COMPLETED)
            if hold not in done:
                hold.cancel()
                data = json.dumps({"StatusCode": self.exit_codes.get(cid, 0)}).encode()
                writer.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data))
                self.ended_streams.append((method, path))
            return
        if verb == "stop":
            # Holds as the daemon does while the container takes `t` to stop
            # (bounded here by stop_hold), unless the broker closes it first.
            if await self._hold(reader, method, path, self.stop_hold) is False:
                c["status"] = "exited"
                return self._send(writer, 204)
            return
        if verb == "start":
            c["status"] = "running"
            return self._send(writer, 204)
        if verb in ("kill",):
            c["status"] = "exited"
            return self._send(writer, 204)
        if verb == "remove":
            self.gone[c["name"]] = cid
            del self.containers[cid]
            return self._send(writer, 204)
        return self._send(writer, 200, {})


async def serve_broker(daemon):
    """(broker socket, a coroutine function that closes both servers)."""
    tmp = tempfile.mkdtemp(prefix="broker-tool-")
    up_sock, br_sock = os.path.join(tmp, "up.sock"), os.path.join(tmp, "br.sock")
    old = broker.UPSTREAM_SOCK
    broker.UPSTREAM_SOCK = up_sock
    up = await asyncio.start_unix_server(daemon.serve, path=up_sock)
    br = await asyncio.start_unix_server(broker.handle_client, path=br_sock, limit=broker.HEAD_MAX)

    async def close():
        broker.UPSTREAM_SOCK = old
        for server in (br, up):
            server.close()

    return br_sock, close


async def call(sock, raw, timeout=3.0, half_close=False, keep=False):
    """Send one request; the answer read to EOF or `timeout` (only its first
    chunk when `keep`, which returns (answer, reader, writer) for the caller to
    hold). `half_close` shuts the write side after the request, as `nc -N` does."""
    reader, writer = await asyncio.open_unix_connection(sock)
    writer.write(raw)
    await writer.drain()
    if half_close:
        writer.write_eof()
    out = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            out += chunk
            if keep and b"\r\n\r\n" in out:
                return out, reader, writer
    except (asyncio.TimeoutError, ConnectionError):
        pass
    if keep:
        return out, reader, writer
    writer.close()
    return out

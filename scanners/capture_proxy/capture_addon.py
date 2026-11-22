"""
redamon-capture-proxy — mitmdump addon (plan §11.1, §11.2).

The target-facing, CREDENTIAL-FREE capture component. It runs `mitmdump -s
capture_addon.py` on pentest-net. Responsibilities:

  requestheaders / request hooks:
    - lift the opaque `X-Redamon-Ctx` tag off the request and DELETE the header
      so it never leaks to the target (§7.2), before a large body is streamed.
      The proxy carries it verbatim; it holds NO signing key and never
      decodes/verifies it (that's traffic-ingest).
    - refuse, at requestheaders and so before a body over stream_large_bodies
      goes upstream, a request whose target, Host headers, `:authority` or TLS
      SNI the hard guardrail names. By name only, with no lookup: any other host
      there (vhost probing, Host-header injection) is the tester's business,
      recorded under the real target.
    - enforce the egress guard (§15.3, §20.5) on the request's REAL target
      (`request.host`, the address mitmproxy dials) at the request hook. A name's
      lookup runs off the event loop with a time limit, a few at a time per
      network the client came in on (per run on pentest-net); an IP address
      needs none. Blocked requests get a 403 (or, when their body may
      already be streaming, are killed) and a `blocked=true` spool record; they
      are NOT forwarded.

  server_connect hook:
    - the same guard on every upstream dial (HTTP, TLS, WebSocket, raw TCP and
      the DNS layer, which never calls the request hook): resolve, refuse, or pin
      the dial to the checked IP so a re-resolution cannot land elsewhere. The
      `error` hook records an HTTP request whose dial it refused.

  response hook:
    - assemble the transaction, apply body inline/offload + dedup, stamp cheap
      passive signals, and append it to the append-only spool as one
      atomically-renamed file (concurrency-safe under many coroutines).

  backpressure:
    - a bounded queue drained by a writer thread; if it backs up, drop-and-count
      (never block the proxy data path).

Everything the LLM/analyst eventually sees is stamped from the VERIFIED tag by
traffic-ingest, never from anything this proxy or a target controls.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import queue
import threading
import time
import uuid
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from mitmproxy import ctx, http

from capture_lib import (
    build_record, classify_family, decide_body, ensure_dir_writable,
    normalize_headers, parse_body_rules, sha256_hex,
)
from egress import check_egress, policy_from_dict, policy_from_env

try:
    from hard_guardrail import is_hard_blocked  # bundled into the image
except Exception:  # pragma: no cover - guardrail must exist in the image
    def is_hard_blocked(domain):
        return (False, "")


# mitmproxy 11.1.3 keeps an HTTP/1 head (a client's request head, a target's
# response head) until its blank line, with no limit ("FIXME: protect against
# header size DoS", proxy/layers/http/_http1.py), and appends every chunk a
# connection sends to that same buffer in every state but the raw pipe, unread
# while a request waits for its answer. The proxy is on every sandbox network,
# so one client, or one target it reaches, could grow it until it is killed and
# capture stops for everyone. 256 KiB is far above any head a server takes
# (nginx 32 KiB; Apache about 100 fields of 8 KiB) and above what an HTTP/1
# client sends ahead of an answer it waits for.
_MAX_HEAD_BYTES = 256 * 1024


def _bound_heads() -> None:
    """Bound every HTTP/1 receive buffer at _MAX_HEAD_BYTES. A head still
    incomplete past it is refused as mitmproxy refuses one it cannot parse: a
    request with 431 and the connection closed, a response with the client's
    request failed (a 502). mitmproxy reads at most 64 KiB at a time, so a head
    that is complete has been parsed before the bound is looked at. In any other
    state (a request waiting for its answer, data after a complete message) the
    connection is closed and its stream told, as when the peer disconnects; a
    body being read drains the buffer and never reaches the bound."""
    try:
        from mitmproxy.proxy import commands, events
        from mitmproxy.proxy.layers.http import _http1
    except Exception:  # not mitmproxy's own layout (test_capture_config stubs it)
        return

    def bounded(read_headers, refuse):
        if getattr(read_headers, "redamon_bounded", False):
            return read_headers

        def read_headers_bounded(self, event):
            yield from read_headers(self, event)
            if (isinstance(event, events.DataReceived) and self.state == self.read_headers
                    and len(self.buf) > _MAX_HEAD_BYTES):
                self.buf.maybe_extract_at_most(len(self.buf))  # let the memory go now
                yield from refuse(self)
                self.state = self.done

        read_headers_bounded.redamon_bounded = True
        return read_headers_bounded

    def refuse_request(self):
        yield commands.SendData(self.conn, _http1.make_error_response(431, "Request head too large"))
        yield commands.CloseConnection(self.conn)
        yield commands.Log(f"request head over {_MAX_HEAD_BYTES} bytes refused")

    def refuse_response(self):
        yield commands.CloseConnection(self.conn)
        if self.stream_id is not None:
            yield _http1.ReceiveHttp(_http1.ResponseProtocolError(
                self.stream_id, f"response head over {_MAX_HEAD_BYTES} bytes"))

    _http1.Http1Server.read_headers = bounded(_http1.Http1Server.read_headers, refuse_request)
    _http1.Http1Client.read_headers = bounded(_http1.Http1Client.read_headers, refuse_response)

    handle_event = _http1.Http1Connection._handle_event
    if getattr(handle_event, "redamon_bounded", False):
        return

    def handle_event_bounded(self, event):
        yield from handle_event(self, event)
        if (isinstance(event, events.DataReceived) and len(self.buf) > _MAX_HEAD_BYTES
                and self.state not in (self.passthrough, self.done)):
            self.buf.maybe_extract_at_most(len(self.buf))
            yield commands.CloseConnection(self.conn)
            if self.stream_id is not None and (self.request is not None or self.response is not None):
                yield _http1.ReceiveHttp(self.ReceiveProtocolError(
                    self.stream_id, f"over {_MAX_HEAD_BYTES} bytes received ahead of the message's turn"))
            yield commands.Log(f"over {_MAX_HEAD_BYTES} bytes buffered, connection closed")
            self.state = self.done

    handle_event_bounded.redamon_bounded = True
    _http1.Http1Connection._handle_event = handle_event_bounded


_bound_heads()


def _hard_blocked(host: str) -> bool:
    blocked, _ = is_hard_blocked(host)
    return blocked


def _client_names(flow) -> list:
    """The host names a client put on a request besides its target: every Host
    header, the `:authority` and the TLS SNI of its tunnel. HTTP/2 may carry
    Host headers beside `:authority` (h2 compares it with the last one only), and
    mitmproxy forwards them all upstream, so each one is a name the client sent."""
    req = flow.request
    names = [part for value in req.headers.get_all("host") for part in value.split(",")]
    names.append(req.authority)
    names.append(getattr(getattr(flow, "client_conn", None), "sni", None))
    return [n.strip() for n in names if n and n.strip()]


def _refused_by_name(names, policy):
    """"hard-guardrail" when the hard guardrail names one of `names`, else None.
    Matched by name and never looked up: a tester may put any other host in a
    Host header or an SNI (vhost probing, Host-header injection), but no
    protected domain."""
    if policy.block_hard_guardrail:
        for name in names:
            if _hard_blocked(name):
                return "hard-guardrail"
    return None


def _check_target(target: str, names, extra_blocked_ips, policy):
    """check_egress on the address mitmproxy dials, after refusing any of the
    client's `names` that the hard guardrail names."""
    reason = _refused_by_name(names, policy)
    if reason:
        return (False, None, reason)
    return check_egress(target, hard_blocked=_hard_blocked,
                        extra_blocked_ips=extra_blocked_ips, policy=policy)


def _is_ip_literal(host) -> bool:
    """True when check_egress would take `host` as an address and look nothing
    up (its own normalisation, then resolve_host's test)."""
    try:
        ipaddress.ip_address((host or "").strip().strip(".").lower())
        return True
    except ValueError:
        return False


def _body_may_stream(request) -> bool:
    """Whether mitmproxy may still stream this request's body upstream: it was
    marked for streaming before requestheaders (a Content-Length over
    stream_large_bodies), or its length is unknown, so it switches to streaming
    once that much has arrived (chunked; HTTP/2 or 3 without a Content-Length,
    whose END_STREAM the addon cannot see). mitmproxy raises when it starts to
    stream a request that has a response set, so such a refusal is a kill."""
    if request.stream or "transfer-encoding" in request.headers:
        return True
    length = request.headers.get("content-length")
    if length is None:
        # HTTP/1 frames a request with neither header as body-less.
        return not request.http_version.upper().startswith("HTTP/1")
    try:
        from mitmproxy.utils import human  # here: test_capture_config stubs mitmproxy as a module
        limit = human.parse_size(ctx.options.stream_large_bodies)
        return limit is not None and int(length) > limit
    except Exception:  # the option or the length unreadable: assume it may
        return True


def _address(conn, attr: str) -> str:
    value = getattr(conn, attr, None)
    return str(value[0]) if value else ""


def _read_default_route(path: str = "/proc/net/route"):
    """(gateway, [networks of its interface], [every network of the proxy]) of
    the IPv4 default route, or None.

    The proxy runs on pentest-net with its default route there and joins the
    per-user sandbox networks below it (GwPriority). On pentest-net come host-net
    recon, through the loopback publish and so from the gateway's address, and in
    the shared mode the one shared Kali; no per-user sandbox is on it."""
    try:
        with open(path) as fh:
            rows = [line.split() for line in fh.read().splitlines()[1:]]
    except OSError:
        return None

    def ip(hex_le):
        return str(ipaddress.IPv4Address(int(hex_le, 16).to_bytes(4, "little")))

    try:
        default = next((r for r in rows if len(r) > 7 and r[1] == "00000000" and int(r[3], 16) & 0x2), None)
        if default is None:
            return None
        links = [(r[0], ipaddress.ip_network(f"{ip(r[1])}/{ip(r[7])}", strict=False))
                 for r in rows if len(r) > 7 and r[1] != "00000000" and int(r[2], 16) == 0]
        return ip(default[2]), [net for iface, net in links if iface == default[0]], [net for _, net in links]
    except ValueError:
        return None


def _resolver_gives_up_after(path: str = "/etc/resolv.conf") -> float:
    """How long glibc's getaddrinfo keeps asking about a name that never answers:
    `attempts` rounds over every nameserver, `timeout` seconds each (resolv.conf(5):
    defaults 5 s and 2, at most 30 s, 5 rounds and 3 nameservers)."""
    timeout, attempts, servers = 5, 2, 0
    try:
        with open(path) as fh:
            for line in fh:
                words = line.split()
                if words and words[0] == "nameserver":
                    servers += 1
                elif words and words[0] == "options":
                    for option in words[1:]:
                        name, _, value = option.partition(":")
                        if name == "timeout" and value.isdigit():
                            timeout = min(int(value), 30)
                        elif name == "attempts" and value.isdigit():
                            attempts = min(int(value), 5)
    except OSError:
        pass
    return float(timeout * attempts * min(max(servers, 1), 3))


# A name that never answers costs its check this long at most: the resolver's own
# give-up time (on pentest-net Docker's embedded resolver alone, 5 s x 2) plus 5 s,
# so an honest answer the resolver still takes, a retried query, passes as before.
# On expiry the check is refused, as an unresolvable name is; its thread stays
# counted until the resolver gives up.
_LOOKUP_TIME_LIMIT = _resolver_gives_up_after() + 5.0


def _close_left_open(client) -> None:
    """Close a client socket mitmproxy 11.1 left open.

    Its handle_connection closes the socket only when it ends normally. When the
    proxy closes a client that is still sending (the refusal or the kill of a
    request whose body streams), the reader task is cancelled while it waits for
    the connection's event lock, which that function does not catch: the socket
    stays open, read by no one, until the client gives up (measured: its whole
    timeout), and a client could pile up the proxy's sockets and memory that
    way. A socket closed normally is gone from `transports` by now."""
    writer = getattr(_client_io(client), "writer", None)
    try:
        if writer is not None and not writer.is_closing():
            writer.close()
    except Exception:  # another mitmproxy layout: nothing this can do
        pass


def _pause_reading(client) -> bool:
    io = _client_io(client)
    try:
        io.writer.transport.pause_reading()
    except Exception:  # no such connection (tests), or another layout
        return False
    # asyncio's reader resumes a transport it paused itself; not this one.
    if getattr(io.reader, "_paused", False):
        io.reader._paused = False
    return True


def _resume_reading(client) -> None:
    try:
        transport = _client_io(client).writer.transport
        if not transport.is_closing():
            transport.resume_reading()
    except Exception:
        pass


class _Backlog:
    """The request bytes queued behind a client connection's waiting streams,
    and the pause of its reading they cause.

    mitmproxy reads on while a stream waits (for its dial, above all: our lookup,
    then the TCP connect and mitmproxy's own five-connections-per-address limit)
    and queues every chunk of its body behind it, so one client could grow the
    shared proxy without limit. A connection stops being read only while what its
    streams hold queued passes `high`, and is read again once it falls under
    `low`; normal traffic never comes near, so no HTTP/2 connection freezes for a
    stream that merely waits (one whose body piles past the mark stops its
    connection until it moves). The kernel keeps the bytes and TCP slows the
    client, so an upload whose dial is slow still arrives whole."""

    def __init__(self, high=1 << 20, low=256 << 10, pause=_pause_reading, resume=_resume_reading):
        self._high, self._low = high, low
        self._pause, self._resume = pause, resume
        self._held = {}     # client connection id -> {stream: bytes queued}
        self._paused = set()  # client connection ids whose reading this paused

    def queued(self, client_id) -> int:
        return sum(self._held.get(client_id, {}).values())

    def update(self, client, stream, nbytes) -> None:
        held = self._held.get(client.id)
        if nbytes:
            held = self._held.setdefault(client.id, {})
            held[stream] = nbytes
        elif held is not None:
            held.pop(stream, None)
            if not held:
                del self._held[client.id]
        total = self.queued(client.id)
        if total > self._high and client.id not in self._paused:
            if self._pause(client):
                self._paused.add(client.id)
        elif total <= self._low and client.id in self._paused:
            self._paused.discard(client.id)
            self._resume(client)

    def forget(self, client_id) -> None:
        self._held.pop(client_id, None)
        self._paused.discard(client_id)


_BACKLOG = _Backlog()


def _watch_backlogs() -> None:
    """Measure, after each event a stream handles, the request bytes it holds
    queued while it waits, where mitmproxy 11.1.3 keeps them (the stream layer's
    `_paused_event_queue`)."""
    try:
        from mitmproxy.proxy.layers.http import HttpStream
        from mitmproxy.proxy.layers.http._events import RequestData
    except Exception:  # not mitmproxy's own layout (test_capture_config stubs it)
        return
    handle_event = HttpStream.handle_event
    if getattr(handle_event, "redamon_watched", False):
        return

    def handle_event_watched(self, event):
        yield from handle_event(self, event)
        queued = 0
        if self._paused is not None:
            for waiting in self._paused_event_queue:
                if isinstance(waiting, RequestData):
                    queued += len(waiting.data)
        _BACKLOG.update(self.context.client, id(self), queued)

    handle_event_watched.redamon_watched = True
    HttpStream.handle_event = handle_event_watched


_watch_backlogs()


def _client_io(client):
    """mitmproxy's reader and writer of a client connection, or None."""
    try:
        # mitmproxy keys a client's handler by the client's id until it is done.
        handler = ctx.master.addons.get("proxyserver").connections.get(client.id)
        if handler is not None and handler.client is client:
            return handler.transports.get(client)
    except Exception:  # another mitmproxy layout, or no proxy server (tests)
        pass
    return None


class _NoLookupSlot(Exception):
    """A line already has all its checks waiting."""


class _LookupTimedOut(Exception):
    """A lookup outlived the time limit."""


class _UnknownNetwork(Exception):
    """The client's address is on none of the proxy's networks."""


class _ClientGone(Exception):
    """The client disconnected while its check waited for a lookup thread."""


_LOOKUP_REFUSAL = {_NoLookupSlot: "lookup-capacity", _LookupTimedOut: "lookup-timeout",
                   _UnknownNetwork: "unknown-network", _ClientGone: "client-gone"}


class _Line:
    __slots__ = ("busy", "waiting", "in_turn")

    def __init__(self):
        self.busy, self.waiting, self.in_turn = 0, deque(), False


class _PoolState:
    __slots__ = ("busy", "lines", "turns")

    def __init__(self):
        self.busy = 0
        self.lines = {}       # line id -> _Line
        self.turns = deque()  # ids of lines with a check waiting for a thread, in turn


def _wake(future) -> None:
    if not future.done():
        future.set_result(None)


class _GuardLookups:
    """Runs the guard's DNS lookups off the event loop, in threads of its own
    (asyncio's default executor is shared with mitmproxy and holds few).

    A pool is never handed more lookups than it has threads, and a line runs at
    most `per_line` at once; the other checks wait, and a freed thread goes to the
    next line in turn (round robin), so one line's names that never answer hold
    only its share and another line's check soon gets a thread. With
    `queued_per_line`, a check that finds its line's queue full raises
    _NoLookupSlot, which the caller refuses; with None it waits. The time limit
    counts from when the lookup starts in its thread, never the wait for one: a
    lookup that outlives it raises _LookupTimedOut, which the caller refuses.

    A thread is given back when its lookup really ends, not when the check that
    waited for it is cancelled or timed out, so a line cannot pile up stuck
    threads. State is kept per event loop; the proxy runs one."""

    def __init__(self, threads, per_line=8, queued_per_line=512, time_limit=_LOOKUP_TIME_LIMIT):
        self._pool = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="egress-lookup")
        self._threads = threads
        self._per_line = per_line
        self._queued_per_line = queued_per_line
        self._time_limit = time_limit
        self._states = {}  # event loop -> _PoolState
        self._waiting_of = {}  # client connection id -> its checks waiting for a thread

    def give_up(self, owner) -> None:
        """End the checks a client still has waiting for a thread (it is gone)."""
        for turn in list(self._waiting_of.pop(owner, ())):
            if not turn.done():
                turn.set_exception(_ClientGone(owner))

    async def run(self, line_id, fn, *args, owner=None):
        loop = asyncio.get_running_loop()
        state = self._states.setdefault(loop, _PoolState())
        line = state.lines.get(line_id)
        if line is None:
            line = state.lines[line_id] = _Line()
        if line.busy < self._per_line and state.busy < self._threads and not state.turns:
            line.busy += 1
            state.busy += 1
        else:
            await self._wait_for_a_thread(loop, state, line_id, line, owner)
        started = loop.create_future()

        def lookup():
            try:
                loop.call_soon_threadsafe(_wake, started)
            except RuntimeError:  # the loop is gone, and nobody waits for this
                pass
            return fn(*args)

        try:
            job = self._pool.submit(lookup)
        except BaseException:
            self._release(loop, state, line_id)
            raise
        job.add_done_callback(lambda _job: self._from_thread(loop, state, line_id))
        result = asyncio.wrap_future(job)
        await started
        try:
            return await asyncio.wait_for(result, self._time_limit)
        except TimeoutError:
            raise _LookupTimedOut(line_id) from None

    async def _wait_for_a_thread(self, loop, state, line_id, line, owner):
        if self._queued_per_line is not None and len(line.waiting) >= self._queued_per_line:
            raise _NoLookupSlot(line_id)
        turn = loop.create_future()
        line.waiting.append(turn)
        if owner is not None:
            mine = self._waiting_of.setdefault(owner, set())
            mine.add(turn)
            turn.add_done_callback(lambda _turn: self._forget_turn(owner, _turn))
        if line.busy < self._per_line and not line.in_turn:
            line.in_turn = True
            state.turns.append(line_id)
        self._admit(state)
        try:
            await turn  # _admit hands a thread over by resolving it
        except (asyncio.CancelledError, _ClientGone):
            if turn.done() and not turn.cancelled() and turn.exception() is None:
                self._release(loop, state, line_id)
            else:
                try:
                    line.waiting.remove(turn)
                except ValueError:
                    pass
                self._drop_if_idle(state, line_id, line)
            raise

    def _forget_turn(self, owner, turn) -> None:
        mine = self._waiting_of.get(owner)
        if mine is not None:
            mine.discard(turn)
            if not mine:
                del self._waiting_of[owner]

    def _admit(self, state) -> None:
        while state.busy < self._threads and state.turns:
            line_id = state.turns.popleft()
            line = state.lines.get(line_id)
            if line is None:
                continue
            line.in_turn = False
            while line.waiting and line.waiting[0].done():
                line.waiting.popleft()  # cancelled, or its client gone, while waiting
            if not line.waiting or line.busy >= self._per_line:
                self._drop_if_idle(state, line_id, line)
                continue
            line.busy += 1
            state.busy += 1
            line.waiting.popleft().set_result(None)
            if line.waiting and line.busy < self._per_line:
                line.in_turn = True
                state.turns.append(line_id)

    @staticmethod
    def _drop_if_idle(state, line_id, line) -> None:
        # Lines are made per tag as checks come: an idle one must not stay.
        if not line.waiting and line.busy <= 0 and state.lines.get(line_id) is line:
            del state.lines[line_id]

    def _from_thread(self, loop, state, line_id):
        try:
            loop.call_soon_threadsafe(self._release, loop, state, line_id)
        except RuntimeError:  # the loop is closed, and nothing waits in its lines
            self._states.pop(loop, None)

    def _release(self, loop, state, line_id) -> None:
        state.busy -= 1
        line = state.lines.get(line_id)
        if line is not None:
            line.busy -= 1
            if line.waiting and not line.in_turn:
                line.in_turn = True
                state.turns.append(line_id)
            else:
                self._drop_if_idle(state, line_id, line)
        self._admit(state)
        if not state.lines and state.busy <= 0 and self._states.get(loop) is state:
            del self._states[loop]


def _reason_class(reason: str) -> str:
    """The refusal's class without its detail: a record goes back to the person
    who sent the request, and `internal-ip:<ip>` would tell them the address a
    name has on RedAmon's networks (another sandbox's, by its container name)."""
    return str(reason).split(":", 1)[0]


class _CheckedDial(tuple):
    """The ``(ip, port)`` that server_connect checked, standing in for the
    ``(name, port)`` mitmproxy was asked to dial.

    It unpacks and indexes as the IP, so ``asyncio.open_connection(*address)``
    reaches exactly the checked address. It compares and hashes as the name, so
    mitmproxy's per-address bookkeeping stays what it is without a pin: a later
    request to the same name reuses the connection, and its limit of five
    connections per address counts each name apart. Keyed on the IP, a client
    that reuses one proxy connection for many names on one CDN address would
    stall on the sixth name until the target closes an idle connection."""

    def __new__(cls, ip, port, name):
        self = super().__new__(cls, (ip, port))
        self.checked_name = (name, port)
        return self

    def __eq__(self, other):
        return self.checked_name == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.checked_name)


def _host_in_recording_scope(host: str, scope_hosts) -> bool:
    """Exact host or ``*.suffix`` match for the operator-recording window.

    Deliberately narrow: no wildcards implied, apex not matched by ``*.``. The
    webapp already resolves scope from the project target, so this only enforces.
    """
    if not host or not scope_hosts:
        return False
    h = host.strip().rstrip(".").lower()
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    for entry in scope_hosts:
        entry = str(entry).strip().rstrip(".").lower()
        if not entry:
            continue
        if entry.startswith("*."):
            if h.endswith(entry[1:]):
                return True
        elif h == entry:
            return True
    return False


def _recording_expired(expires_at) -> bool:
    """True if the recording window has lapsed. Unparseable/absent => treat as
    NOT expired (the webapp only emits an unexpired window; the reconciler drops
    the block within one poll of stop), so a clock/format mismatch can't wedge a
    live recording. The bound is enforced authoritatively webapp-side."""
    if not expires_at:
        return False
    try:
        from datetime import datetime, timezone
        s = str(expires_at).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


def _num_env(name: str, default, cast):
    """Parse a numeric env var, falling back to `default` on missing/empty/garbage.
    Kept fail-safe because this runs in RedamonCapture.__init__, which is OUTSIDE
    the response-hook exception guard: a bad value here would crash-load the addon
    and silently kill all capture."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return cast(raw)
    except (ValueError, TypeError):
        return default


class RedamonCapture:
    CTX_HEADER = "X-Redamon-Ctx"
    # The client sees this text: never the reason, which can name an internal address.
    REFUSED_DIAL = "blocked by redamon capture proxy egress guard"

    def __init__(self) -> None:
        # (client id, host, port) -> reason class of a dial server_connect refused.
        self._refused_dials: "OrderedDict[tuple, str]" = OrderedDict()
        # The proxy container runs under pids_limit=256 (container_manager.py):
        # 96 + 32 lookup threads leave room for mitmproxy's own.
        self._lookups = _GuardLookups(threads=96)
        # pentest-net carries every project's host-net recon (from one address, the
        # gateway) and, in the shared mode, every person's Kali: a line per run
        # there (its X-Redamon-Ctx value, which decides nothing else), threads of
        # its own, and no refusal for capacity, so one run never refuses another.
        self._run_lookups = _GuardLookups(threads=32, queued_per_line=None)
        self._route = None
        self._route_at = None
        self._route_missed_at = None
        self._route_read_wall = None  # time.time() of the last read, to compare with a connection's start
        # client connection id -> the last tag its requests carried, for its dials.
        self._conn_tags: "OrderedDict[str, str]" = OrderedDict()
        self.spool_dir = os.environ.get("CAPTURE_SPOOL_DIR", "/spool")
        self.bodies_dir = os.environ.get("CAPTURE_BODIES_DIR", "/bodies")
        # --- Reloadable runtime config: egress guard + body-storage policy -------
        # SINGLE SOURCE OF TRUTH is the DB (Global Settings > TrafficMind). The
        # trusted control plane (orchestrator) materialises those DB settings to a
        # JSON file on the shared spool volume; THIS proxy only READS that file and
        # HOT-RELOADS it on change. The proxy never connects to the DB — it is the
        # credential-free, target-facing component (§11.1). Env vars are ONLY the
        # pre-file cold-start default, and every one is fail-safe (block/keep), so a
        # missing or partially-written file can never open the egress guard.
        self.config_file = os.environ.get(
            "CAPTURE_CONFIG_FILE", os.path.join(self.spool_dir, ".capture-config.json"))
        self._config_sig = None
        self._config_lock = threading.Lock()
        self.active_recording = None     # set by _apply_config when a recording is live
        raw, sig = self._read_config()
        self._apply_config(raw)          # sets egress_policy + all body-storage knobs
        self._config_sig = sig
        self._cfg_watcher = threading.Thread(
            target=self._config_watch, name="config-watch", daemon=True)
        self._cfg_watcher.start()
        self.tmp_dir = os.path.join(self.spool_dir, ".tmp")
        ensure_dir_writable(self.tmp_dir)
        ensure_dir_writable(self.bodies_dir)
        # The bodies store is shared with the webapp (different uid) which reads
        # + ref-counted-GCs blobs, so make it group/other writable. Internal
        # volume only; blobs are never served by raw path (§15.7).
        try:
            os.chmod(self.bodies_dir, 0o777)
        except OSError:
            pass

        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=int(os.environ.get("CAPTURE_QUEUE_MAX", "2000")))
        self.dropped = 0
        self._writer = threading.Thread(target=self._drain, name="spool-writer", daemon=True)
        self._writer.start()

    # ---- reloadable config (DB -> control-plane file -> hot-reload) --------
    @staticmethod
    def _as_bool(v, default: bool = True) -> bool:
        """Fail-safe truthiness for file/env values. Missing/None/empty -> default
        (block/keep). Only an explicit false-like value turns a toggle OFF."""
        if v is None:
            return default
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s == "":
            return default
        return s not in ("false", "0", "no", "off")

    def _read_config(self):
        """Return (raw_dict_or_None, signature). No file -> (None, None). Present but
        unreadable/invalid -> ({}, signature): fall back to fail-safe defaults rather
        than keep a possibly stale-open policy.

        The signature is the raw file BYTES, so change detection is exact — no reliance
        on mtime resolution (float precision / coarse-granularity or network volumes),
        and a rewrite with identical content is correctly treated as no-change."""
        try:
            with open(self.config_file, "rb") as f:
                data = f.read()
        except OSError:
            return None, None
        try:
            raw = json.loads(data.decode("utf-8"))
            return (raw if isinstance(raw, dict) else {}), data
        except ValueError:  # JSONDecodeError + UnicodeDecodeError are both ValueError
            return {}, data

    def _apply_config(self, raw) -> None:
        """Build the reloadable settings from the file (authoritative when present)
        or, per section, from env (cold-start fallback), then assign atomically.
        The egress guard NEVER relaxes from a malformed file: policy_from_dict /
        policy_from_env both default every check to block."""
        raw = raw if isinstance(raw, dict) else {}
        egress = raw.get("egress")
        if isinstance(egress, dict):
            policy, esrc = policy_from_dict(egress), "file"
        else:
            policy, esrc = policy_from_env(os.environ), "env"

        body = raw.get("body")
        if isinstance(body, dict):
            store_bodies = self._as_bool(body.get("store_bodies"), True)
            store_req = self._as_bool(body.get("store_req_bodies"), True)
            store_resp = self._as_bool(body.get("store_resp_bodies"), True)
            try:
                max_body_kb = int(body.get("max_body_kb") or 64)
            except (ValueError, TypeError):
                max_body_kb = 64
            try:
                _msm = body.get("max_store_mb")
                max_store_mb = float(_msm if _msm is not None else 5.0)
            except (ValueError, TypeError):
                max_store_mb = 5.0
            body_rules = parse_body_rules(body.get("body_rules") or "")
            bsrc = "file"
        else:
            store_bodies = os.environ.get("CAPTURE_PROXY_STORE_BODIES", "true").lower() != "false"
            store_req = os.environ.get("CAPTURE_STORE_REQ_BODIES", "true").lower() != "false"
            store_resp = os.environ.get("CAPTURE_STORE_RESP_BODIES", "true").lower() != "false"
            max_body_kb = _num_env("CAPTURE_PROXY_MAX_BODY_KB", 64, int)
            max_store_mb = _num_env("CAPTURE_MAX_STORE_MB", 5.0, float)
            body_rules = parse_body_rules(os.environ.get("CAPTURE_BODY_RULES", ""))
            bsrc = "env"

        # The RedAmon-service IP denylist is a SECURITY invariant, NOT a DB-tunable
        # knob: it is ALWAYS sourced from env CAPTURE_BLOCKED_IPS and can never be
        # relaxed by the config file (egress.is_internal_ip enforces it un-gated).
        extra_blocked = [ip for ip in os.environ.get("CAPTURE_BLOCKED_IPS", "").split(",") if ip.strip()]

        # Operator-recording window (Phase 2): when the webapp is recording a
        # login for a project, the reconciled config carries a pre-signed
        # `operator` tag + its scope + expiry. The proxy mints NOTHING; it stamps
        # this verbatim tag onto UNTAGGED, in-scope requests (see request()).
        # A malformed/absent block => no injection (fail closed).
        ar = raw.get("active_recording")
        active_recording = None
        if isinstance(ar, dict) and ar.get("tag"):
            scope = ar.get("scope_hosts")
            active_recording = {
                "tag": str(ar["tag"]),
                "scope_hosts": [str(h).strip().lower() for h in scope if str(h).strip()] if isinstance(scope, list) else [],
                "expires_at": ar.get("expires_at"),
            }

        with self._config_lock:
            self.egress_policy = policy
            self.store_bodies = store_bodies
            self.store_req_bodies = store_req
            self.store_resp_bodies = store_resp
            self.max_body_bytes = int(max_body_kb) * 1024
            self.max_store_bytes = int(max_store_mb * 1024 * 1024) if max_store_mb > 0 else 0
            self.extra_blocked_ips = extra_blocked
            self.body_rules = body_rules
            self.active_recording = active_recording
        print(f"[capture] config applied: egress<-{esrc} body<-{bsrc} "
              f"block_private={policy.block_private} store_bodies={store_bodies} "
              f"max_body_bytes={self.max_body_bytes} extra_blocked={len(extra_blocked)}", flush=True)

    def _config_watch(self) -> None:
        """Poll the config file; re-read + re-apply whenever its CONTENT changes. Any
        error keeps the current (already-applied) settings — a bad write never crashes
        capture."""
        interval = _num_env("CAPTURE_CONFIG_POLL_SEC", 5.0, float) or 5.0
        while True:
            time.sleep(interval)
            try:
                raw, sig = self._read_config()
                if sig != self._config_sig:
                    self._apply_config(raw)
                    self._config_sig = sig
            except Exception as e:  # never let the watcher die
                print(f"[capture] config-watch error (keeping current config): {e}", flush=True)

    # ---- mitmproxy hooks ---------------------------------------------------
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # A body over stream_large_bodies (or a chunked one, once that much is in)
        # goes upstream after this hook and before `request`: the tag must be off
        # the request and the client's names checked by then.
        try:
            self._take_tag(flow)
        finally:
            self._check_names(flow)
        self._remember_tag(flow)

    def _remember_tag(self, flow: http.HTTPFlow) -> None:
        # server_connect sees no request: its lookup takes the line of the last
        # tag on its client connection (it dials after this hook).
        token = flow.metadata.get("redamon_ctx")
        if token:
            self._conn_tags[flow.client_conn.id] = token
            self._conn_tags.move_to_end(flow.client_conn.id)
            while len(self._conn_tags) > 4096:
                self._conn_tags.popitem(last=False)

    def client_disconnected(self, client) -> None:
        self._conn_tags.pop(client.id, None)
        _BACKLOG.forget(client.id)
        # Its checks still waiting for a lookup thread would keep their place in
        # the line with nobody to answer (on pentest-net a run's queue has no cap).
        self._lookups.give_up(client.id)
        self._run_lookups.give_up(client.id)
        _close_left_open(client)

    def request(self, flow: http.HTTPFlow):
        """Take the tag (unless requestheaders did), then hand mitmproxy the egress
        check as a coroutine, which it awaits. The check's DNS lookup runs off the
        event loop: the proxy serves every person's sandbox, and one slow name
        must not stall anyone else's traffic.

        A streamed request is already upstream by now: its names were checked at
        requestheaders and its dial at server_connect, and a refusal here would
        only record as blocked a request that reached its target."""
        self._take_tag(flow)
        if flow.metadata.get("redamon_blocked") or flow.request.stream:
            return None
        return self._check_request(flow)

    def _check_names(self, flow: http.HTTPFlow) -> None:
        """Refuse a request whose target or client names the hard guardrail names."""
        policy = self.egress_policy
        try:
            reason = _refused_by_name([flow.request.host, *_client_names(flow)], policy)
        except Exception as e:
            if not policy.fail_closed_on_error:
                return  # fail-open: the request hook and server_connect still check
            reason = f"guard-error:{e}"
        if reason:
            self._refuse_request(flow, reason, kill=_body_may_stream(flow.request))

    def _take_tag(self, flow: http.HTTPFlow) -> None:
        if "redamon_ctx" in flow.metadata:
            return
        # Lift + strip the internal tag BEFORE anything can forward it upstream.
        token = flow.request.headers.pop(self.CTX_HEADER, None)

        # Operator recording (Phase 2): only when there is NO real tag (never
        # override a scanner/agent tag) AND a recording window is active AND the
        # request's real target is in the recording scope, stamp the pre-signed
        # operator tag. Out-of-scope operator browsing stays untagged -> rejected
        # at ingest, so it never lands in the corpus. The proxy mints nothing.
        if token is None:
            ar = getattr(self, "active_recording", None)
            if ar and not _recording_expired(ar.get("expires_at")) \
                    and _host_in_recording_scope(flow.request.host, ar.get("scope_hosts") or []):
                token = ar["tag"]

        flow.metadata["redamon_ctx"] = token
        flow.metadata["redamon_started"] = time.time()

    def _default_route(self, missed: bool = False, conn_started=None):
        now = time.monotonic()
        # A miss re-reads at once, at most once a second, or whenever the table is
        # older than the client's connection (at most once for that connection):
        # a sandbox network the proxy has just joined is not in an older table.
        stale = self._route_at is None or now - self._route_at > 60
        due = missed and (self._route_missed_at is None or now - self._route_missed_at > 1)
        newer = (missed and conn_started is not None
                 and (self._route_read_wall is None or self._route_read_wall < conn_started))
        if stale or due or newer:
            if missed:
                self._route_missed_at = now
            self._route, self._route_at, self._route_read_wall = _read_default_route(), now, time.time()
        return self._route

    def _network_of(self, peer, conn_started=None):
        for missed in (False, True):
            route = self._default_route(missed, conn_started)
            if route is None:
                return route, None
            found = [net for net in route[2] if peer in net]
            if found:
                return route, max(found, key=lambda net: net.prefixlen)
        return route, None

    def _lookup_line(self, conn, tag):
        """The pool and line for a client connection's lookups: the proxy network
        that holds the client's address, which a client cannot fake and still
        complete its TCP handshake (the reply goes out on that network). So a
        sandbox that adds addresses from its /28, or calls the proxy's address on
        another network through its own, is still its own network's one line. On
        the default route's network (pentest-net) every project's and person's
        traffic arrives together, host-net recon all from the gateway's address:
        there each run has a line, by its tag, in a pool of its own. An IPv4
        client on none of the proxy's networks is refused (_UnknownNetwork)."""
        local = _address(conn, "sockname")
        try:
            peer = ipaddress.ip_address(_address(conn, "peername"))
        except ValueError:
            peer = None
        if peer is None or peer.version != 4:
            return self._lookups, local  # the routing table read is IPv4 only
        route, network = self._network_of(peer, getattr(conn, "timestamp_start", None))
        if route is None:
            return self._lookups, local
        if network is None:
            if peer.is_loopback:
                return self._lookups, local  # the proxy's own loopback
            raise _UnknownNetwork(str(peer))
        if network in route[1]:
            return self._run_lookups, tag or ""
        return self._lookups, str(network)

    async def _guard(self, conn, tag, target: str, names, policy):
        if _is_ip_literal(target):
            return _check_target(target, names, self.extra_blocked_ips, policy)
        pool, line = self._lookup_line(conn, tag)  # may raise _UnknownNetwork
        return await pool.run(line, _check_target, target, names, self.extra_blocked_ips, policy,
                              owner=getattr(conn, "id", None))

    async def _check_request(self, flow: http.HTTPFlow) -> None:
        # `request.host` is what mitmproxy dials; the Host header and the TLS SNI
        # are the client's words, checked by name against the hard guardrail only.
        target = flow.request.host
        policy = self.egress_policy
        try:
            allowed, pinned_ip, reason = await self._guard(
                flow.client_conn, flow.metadata.get("redamon_ctx"), target, _client_names(flow), policy)
        except _ClientGone:
            # Nobody to answer and nothing to audit: the request never left.
            flow.metadata["redamon_blocked"] = "client-gone"
            if flow.killable:
                flow.kill()
            return
        except (_NoLookupSlot, _LookupTimedOut, _UnknownNetwork) as e:
            # Refused whatever the fail-open toggle says: not a guard error.
            allowed, pinned_ip, reason = (False, None, _LOOKUP_REFUSAL[type(e)])
        except Exception as e:
            # On a guard-internal error: fail CLOSED (block) by default. The
            # operator can flip this to fail-open via the "Fail closed on guard
            # error" toggle; dangerous, but exposed for completeness. Fail-open
            # forwards without this check; server_connect still checks the dial.
            if policy.fail_closed_on_error:
                allowed, pinned_ip, reason = (False, None, f"guard-error:{e}")
            else:
                allowed, pinned_ip, reason = (True, None, f"guard-error-failopen:{e}")

        if not allowed:
            self._refuse_request(flow, reason)
            return

        # The dial itself is checked and pinned in server_connect: mitmproxy opens
        # a NEW server connection for the request's target, so an address set on
        # flow.server_conn here would never be used.
        flow.metadata["redamon_pinned_ip"] = pinned_ip

    def _refuse_request(self, flow: http.HTTPFlow, reason: str, kill: bool = False) -> None:
        """Do not forward; record the attempt for the scope audit. A 403 needs a
        request mitmproxy will not stream; any other is killed (no answer). The
        refusal comes first: mitmproxy logs an exception raised in a hook and
        goes on with the request."""
        flow.metadata["redamon_blocked"] = _reason_class(reason)
        if kill:
            if flow.killable:  # always, in requestheaders: mitmproxy sets the flow live first
                flow.kill()
        else:
            flow.response = http.Response.make(
                403, f"{self.REFUSED_DIAL}\n".encode(),
                {"Content-Type": "text/plain"},
            )
        print(f"[capture] BLOCKED {flow.request.host} ({reason})", flush=True)
        try:
            self._emit_blocked(flow, reason)
        except Exception as e:  # the refusal stands; only its record is lost
            print(f"[capture] emit failed: {e}", flush=True)

    async def server_connect(self, data) -> None:
        """Check every upstream dial before mitmproxy opens it, with the request
        check's rules (hard guardrail, every resolved address against the policy
        and the always-on denylist), then pin the dial to the checked IP so a
        re-resolution cannot land elsewhere (DNS rebinding, §20.5). This is the
        only place mitmproxy dials from, so it also covers CONNECT tunnels, raw
        TCP and the DNS layer that a CONNECT to :53/:5353 selects.

        The dial goes to the first resolved address only: a name whose first
        address does not answer fails (502) where mitmproxy would have tried the
        next one.

        mitmproxy logs an exception raised here and dials anyway, so every error
        is turned into a decision below."""
        server = data.server
        if not server.address:
            return  # mitmproxy refuses an address-less dial itself
        host, port = server.address[0], server.address[1]
        policy = self.egress_policy
        names = [n for n in (server.sni, data.client.sni) if n]
        refusal = None
        try:
            try:
                allowed, pinned_ip, reason = await self._guard(
                    data.client, self._conn_tags.get(data.client.id), host, names, policy)
            except (_NoLookupSlot, _LookupTimedOut, _UnknownNetwork, _ClientGone) as e:
                allowed, pinned_ip, reason = (False, None, _LOOKUP_REFUSAL[type(e)])
            if not allowed or not pinned_ip:
                refusal = reason
            elif pinned_ip != host:
                server.address = _CheckedDial(pinned_ip, port, host)
        except Exception as e:
            if policy.fail_closed_on_error:
                refusal = f"guard-error:{e}"
            else:
                print(f"[capture] connect {host}:{port} not checked (guard-error-failopen:{e})", flush=True)
        if refusal is not None:
            self._refuse_dial(data, host, port, refusal)

    def _refuse_dial(self, data, host, port, reason) -> None:
        data.server.error = self.REFUSED_DIAL
        print(f"[capture] BLOCKED connect {host}:{port} ({reason})", flush=True)
        # Kept for the `error` hook, which records the HTTP flow this dial was for.
        self._refused_dials[(data.client.id, host, port)] = _reason_class(reason)
        while len(self._refused_dials) > 1024:
            self._refused_dials.popitem(last=False)

    def error(self, flow: http.HTTPFlow) -> None:
        # A request that passed the request check but whose dial server_connect
        # refused (a name that rebound, or a large body mitmproxy streamed before
        # the request hook) is recorded as blocked too. Dials that carry no HTTP
        # flow (DNS, raw TCP) carry no tag either; the proxy log has them.
        if flow.request is None or flow.metadata.get("redamon_blocked"):
            return
        # Only a flow whose own dial was refused: a refusal kept for an earlier
        # dial of this client to the same address must not mark as blocked a
        # request that reached its target and failed there.
        if self.REFUSED_DIAL not in str(getattr(flow.error, "msg", "")):
            return
        key = (flow.client_conn.id, flow.request.host, flow.request.port)
        reason = self._refused_dials.pop(key, None)
        if reason is None:
            return
        flow.metadata["redamon_blocked"] = reason
        try:
            self._emit_blocked(flow, reason)
        except Exception as e:  # never break the proxy path
            print(f"[capture] emit failed: {e}", flush=True)

    def server_connected(self, data) -> None:
        # Back to mitmproxy's usual state for a dial by name: `address` the name
        # (the TLS SNI fallback and the logs read it), `peername` the checked IP the
        # socket is on. The two compare equal, so mitmproxy allows it on an open
        # connection.
        self._restore_name(data.server)

    def server_connect_error(self, data) -> None:
        self._restore_name(data.server)

    @staticmethod
    def _restore_name(server) -> None:
        if isinstance(server.address, _CheckedDial):
            server.address = server.address.checked_name

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("redamon_blocked"):
            return  # already emitted in request hook
        try:
            self._emit(flow)
        except Exception as e:  # never break the proxy path
            print(f"[capture] emit failed: {e}", flush=True)

    # ---- internals ---------------------------------------------------------
    def _emit_blocked(self, flow: http.HTTPFlow, reason: str) -> None:
        req_headers = normalize_headers(flow.request.headers.items(multi=True))
        rec = build_record(
            ctx_token=flow.metadata.get("redamon_ctx"),
            method=flow.request.method, scheme=flow.request.scheme,
            host=flow.request.host, port=flow.request.port,
            path=flow.request.path.split("?", 1)[0],
            query=flow.request.path.split("?", 1)[1] if "?" in flow.request.path else "",
            req_headers=req_headers, resp_headers={}, status_code=None,
            req_body_inline=None, req_body_ref=None, req_body_size=0, req_body_sha=None,
            resp_body_inline=None, resp_body_ref=None, resp_body_size=0, resp_body_sha=None,
            http_version=None, is_tls=flow.request.scheme == "https", tls_version=None,
            target_ip=None, response_time_ms=None,
            started_at=datetime.now(timezone.utc).isoformat(),
            blocked=True, in_scope=False, error_text=f"egress:{_reason_class(reason)}",
        )
        self._enqueue(rec)

    def _emit(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        req_headers = normalize_headers(req.headers.items(multi=True))
        resp_headers = normalize_headers(resp.headers.items(multi=True)) if resp else {}

        req_raw = req.raw_content if req and req.raw_content else None
        resp_raw = resp.raw_content if resp and resp.raw_content else None

        # Classify each body into a storage family (content-type, with a URL
        # filename-extension fallback that rescues octet-stream-mislabeled files).
        req_family = classify_family(req_headers.get("content-type"), path=req.path)
        resp_family = classify_family(resp_headers.get("content-type"), path=req.path)
        rb_inline, rb_ref, rb_size, rb_sha = decide_body(
            req_raw, family=req_family, rules=self.body_rules,
            inline_cap_bytes=self.max_body_bytes, max_store_bytes=self.max_store_bytes,
            store=self.store_bodies and self.store_req_bodies)
        sb_inline, sb_ref, sb_size, sb_sha = decide_body(
            resp_raw, family=resp_family, rules=self.body_rules,
            inline_cap_bytes=self.max_body_bytes, max_store_bytes=self.max_store_bytes,
            store=self.store_bodies and self.store_resp_bodies)

        # Offload bodies to the content-addressed store (dedup by sha).
        if rb_ref and req_raw is not None:
            self._offload(rb_ref, req_raw)
        if sb_ref and resp_raw is not None:
            self._offload(sb_ref, resp_raw)

        started = flow.metadata.get("redamon_started")
        rt_ms = int((time.time() - started) * 1000) if started else None
        # The address the socket is really on; the request check's own lookup
        # may have answered another one.
        peer = getattr(flow.server_conn, "peername", None)
        target_ip = peer[0] if peer else flow.metadata.get("redamon_pinned_ip")
        path = req.path.split("?", 1)[0]
        query = req.path.split("?", 1)[1] if "?" in req.path else ""

        rec = build_record(
            ctx_token=flow.metadata.get("redamon_ctx"),
            # The real target: a Host header naming another host stays in req_headers.
            method=req.method, scheme=req.scheme, host=req.host, port=req.port,
            path=path, query=query, req_headers=req_headers, resp_headers=resp_headers,
            status_code=resp.status_code if resp else None,
            req_body_inline=rb_inline, req_body_ref=rb_ref, req_body_size=rb_size, req_body_sha=rb_sha,
            resp_body_inline=sb_inline, resp_body_ref=sb_ref, resp_body_size=sb_size, resp_body_sha=sb_sha,
            http_version=getattr(resp, "http_version", None) if resp else None,
            is_tls=req.scheme == "https", tls_version=None,
            target_ip=target_ip,
            response_time_ms=rt_ms, started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._enqueue(rec)

    def _offload(self, sha: str, raw: bytes) -> None:
        dest = os.path.join(self.bodies_dir, sha)
        if os.path.exists(dest):
            return  # dedup
        # The temp file MUST live in bodies_dir so os.replace is a SAME-FILESYSTEM
        # rename. /spool and /bodies are separate mounts, so staging the temp in
        # /spool/.tmp made os.replace raise EXDEV ("cross-device link") — which the
        # old bare `except OSError` swallowed silently, dropping every offloaded
        # blob while the DB ref was still written (dangling resp_body_ref rows).
        tmp = os.path.join(self.bodies_dir, f".tmp-{uuid.uuid4().hex}")
        try:
            with open(tmp, "wb") as f:
                f.write(raw)
            os.replace(tmp, dest)  # atomic within bodies_dir (same filesystem)
        except OSError as e:
            print(f"[capture] body offload failed (sha={sha[:12]}): {e}", flush=True)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _enqueue(self, rec: dict) -> None:
        try:
            self._q.put_nowait(rec)
        except queue.Full:
            self.dropped += 1
            if self.dropped % 100 == 1:
                print(f"[capture] spool queue full, dropped={self.dropped}", flush=True)

    def _drain(self) -> None:
        while True:
            rec = self._q.get()
            try:
                self._write_spool(rec)
            except Exception as e:
                print(f"[capture] spool write failed: {e}", flush=True)
            finally:
                self._q.task_done()

    def _write_spool(self, rec: dict) -> None:
        name = f"{time.time_ns()}-{uuid.uuid4().hex}.json"
        tmp = os.path.join(self.tmp_dir, name)
        final = os.path.join(self.spool_dir, name)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False)
        os.replace(tmp, final)  # atomic publish; ingest only ever sees complete files


addons = [RedamonCapture()]

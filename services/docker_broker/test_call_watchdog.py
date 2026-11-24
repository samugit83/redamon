"""Attaches and long calls end when their container does (SBK round 6, F2 and F3).

The daemon never ends an attach to a container removed before it started
(measured on Engine 29: none of 16 such attaches ended), and the broker kept an
attach until both sides closed, so create, attach, remove, keep the socket: one
attach slot gone for good per cycle, until MAX_ATTACH_STREAMS refused every
scan's `docker run`. A scan stopped between a tool's attach and its start
leaked one too. And a container ending between the broker's check and its
forward let a wait for its next exit (or an attach) hold a place for good, and
a start forwarded after a running container exited restart it unadmitted.

Now: an attach ends once the daemon ends its stream; a removal the broker
forwards ends the container's open calls at once; a watchdog re-inspects every
container with an open attach or long call and ends them when it is gone or
has been ended for ENDED_GRACE; a start is refused unless the container is
created or ended, and only one runs per container at a time.
"""
import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import ToolDaemon, call, request_bytes, serve_broker, status_of  # noqa: E402

V = "/v1.57"
RUN = dict(zip(broker.RUN_LABELS, ("full_recon", "cmprojwatch00000000", "runwatch")))
HDR = ("X-Redamon-Run: full_recon:cmprojwatch00000000:runwatch",)
ATT = ("Connection: Upgrade", "Upgrade: tcp")


@pytest.fixture(autouse=True)
def _fast_watchdog(monkeypatch):
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)
    monkeypatch.setattr(broker, "_admitted", 0, raising=False)
    monkeypatch.setattr(broker, "WATCH_INTERVAL", 0.1, raising=False)
    monkeypatch.setattr(broker, "ENDED_GRACE", 0.2, raising=False)


def _req(method, verb_path, extra=()):
    return request_bytes(method, f"{V}/containers/{verb_path}", headers=HDR + tuple(extra))


def _attach(ref):
    return _req("POST", f"{ref}/attach?stream=1&stdout=1&stderr=1", ATT)


def _run(daemon, go, seconds=30):
    async def main():
        sock, close = await serve_broker(daemon)
        try:
            return await go(sock)
        finally:
            await close()
    return asyncio.run(asyncio.wait_for(main(), seconds))


async def _eof_within(reader, seconds):
    """Did the broker end the stream (EOF) within `seconds`?"""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), seconds)
            if not chunk:
                return True
    except (asyncio.TimeoutError, ConnectionError):
        return False


def test_attaches_to_removed_containers_do_not_use_up_the_attach_budget(monkeypatch):
    """The reviewer's cycle: create (never started), attach, remove through the
    broker, keep the attach socket; with a budget of 3, the 4th container's
    attach was refused, for good."""
    monkeypatch.setattr(broker, "MAX_ATTACH_STREAMS", 3, raising=False)
    daemon = ToolDaemon()

    async def go(sock):
        held = []
        for i in range(4):
            daemon.add(f"sbk-att-{i}", RUN)
            out, r, w = await call(sock, _attach(f"sbk-att-{i}"), timeout=1, keep=True)
            assert out.startswith(b"HTTP/1.1 101"), (i, out[:200])
            removed = await call(sock, _req("DELETE", f"sbk-att-{i}?force=1"))
            assert status_of(removed) == 204, removed[:200]
            held.append((r, w))
        ended = [await _eof_within(r, 1) for r, _ in held]
        daemon.add("sbk-att-fresh", RUN)
        fresh, _, fw = await call(sock, _attach("sbk-att-fresh"), timeout=1, keep=True)
        for _, w in held:
            w.close()
        fw.close()
        return ended, fresh, len(broker._ATTACH_STREAMS)
    ended, fresh, open_streams = _run(daemon, go)
    assert ended == [True] * 4, ended          # the broker ended each attach at the removal
    assert fresh.startswith(b"HTTP/1.1 101"), fresh[:200]


def test_the_watchdog_ends_an_attach_whose_container_was_removed_behind_the_broker(monkeypatch):
    """A scan stopped between a tool's attach and its start: the orchestrator
    removes the tool container on the real socket, the broker never sees it."""
    monkeypatch.setattr(broker, "MAX_ATTACH_STREAMS", 1, raising=False)
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-gone", RUN)
        out, r, w = await call(sock, _attach("sbk-gone"), timeout=1, keep=True)
        assert out.startswith(b"HTTP/1.1 101"), out[:200]
        del daemon.containers[cid]                       # removed at the daemon directly
        ended = await _eof_within(r, 2)
        daemon.add("sbk-next", RUN)
        nxt, _, w2 = await call(sock, _attach("sbk-next"), timeout=1, keep=True)
        w.close()
        w2.close()
        return ended, nxt
    ended, nxt = _run(daemon, go)
    assert ended, "the broker kept an attach to a container that no longer exists"
    assert nxt.startswith(b"HTTP/1.1 101"), nxt[:200]


def test_an_attach_ends_when_the_daemon_ends_its_stream_whatever_the_client_does():
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-out", RUN, status="running")
        out, r, w = await call(sock, _attach("sbk-out"), timeout=1, keep=True)
        daemon.end_streams(cid)                          # the container's output ended
        ended = await _eof_within(r, 2)
        await asyncio.sleep(0.1)                         # the handler's own clean-up after the EOF
        left = len(broker._ATTACH_STREAMS)
        w.close()
        return out, ended, left
    out, ended, left = _run(daemon, go)
    assert out.startswith(b"HTTP/1.1 101")
    assert ended and left == 0


def test_a_wait_for_the_next_exit_held_after_its_container_exited_is_ended(monkeypatch):
    """The check sees it running, it exits before the forward (the hook): the
    daemon holds the wait for a start that never comes."""
    monkeypatch.setattr(broker, "MAX_LONG_CALLS", 1, raising=False)

    def exits_after_the_check(daemon, ref):
        cid = daemon.find(ref)
        if cid:
            daemon.containers[cid]["status"] = "exited"
    daemon = ToolDaemon(after_inspect=exits_after_the_check)

    async def go(sock):
        daemon.add("sbk-exit", RUN, status="running")
        out, r, w = await call(sock, _req("POST", "sbk-exit/wait?condition=next-exit"), timeout=1, keep=True)
        assert status_of(out) == 200, out[:200]
        ended = await _eof_within(r, 3)
        daemon.after_inspect = None
        daemon.add("sbk-other", RUN, status="running")
        other, _, w2 = await call(sock, _req("POST", "sbk-other/wait?condition=next-exit"), timeout=1, keep=True)
        w.close()
        w2.close()
        return ended, other
    ended, other = _run(daemon, go)
    assert ended, "a wait on an exited container held its long-call place"
    assert status_of(other) == 200, other[:200]        # the place is free again


def test_the_watchdog_leaves_the_calls_of_a_running_or_created_container_alone():
    daemon = ToolDaemon()

    async def go(sock):
        daemon.add("sbk-run", RUN, status="running")
        daemon.add("sbk-new", RUN, status="created")
        _, r1, w1 = await call(sock, _req("POST", "sbk-run/wait?condition=next-exit"), timeout=1, keep=True)
        _, r2, w2 = await call(sock, _attach("sbk-new"), timeout=1, keep=True)
        ended = [await _eof_within(r, 1.0) for r in (r1, r2)]   # ten watchdog passes
        w1.close()
        w2.close()
        return ended
    assert _run(daemon, go) == [False, False]


def test_the_watchdog_keeps_the_calls_when_the_daemon_does_not_answer():
    class Unsure(ToolDaemon):
        silent = False

        async def _answer(self, reader, writer, method, path, query, body):
            if self.silent and method == "GET" and path.endswith("/json"):
                return self._send(writer, 500, {"message": "daemon busy"})
            return await super()._answer(reader, writer, method, path, query, body)
    daemon = Unsure()

    async def go(sock):
        daemon.add("sbk-unsure", RUN, status="running")
        _, r, w = await call(sock, _req("POST", "sbk-unsure/wait?condition=next-exit"), timeout=1, keep=True)
        daemon.silent = True
        ended = await _eof_within(r, 1.0)
        w.close()
        return ended
    assert _run(daemon, go) is False


def test_a_removal_through_the_broker_ends_the_containers_open_wait():
    daemon = ToolDaemon()

    async def go(sock):
        daemon.add("sbk-rm", RUN, status="running")
        _, r, w = await call(sock, _req("POST", "sbk-rm/wait?condition=next-exit"), timeout=1, keep=True)
        removed = await call(sock, _req("DELETE", "sbk-rm?force=1"))
        ended = await _eof_within(r, 0.5)                 # before any watchdog grace
        w.close()
        return status_of(removed), ended
    assert _run(daemon, go) == (204, True)


@pytest.mark.parametrize("status", ["running", "paused", "restarting", "removing"])
def test_a_start_of_a_container_that_is_not_created_or_ended_is_refused(status):
    daemon = ToolDaemon()

    async def go(sock):
        daemon.add("sbk-st", RUN, status=status)
        return await call(sock, _req("POST", "sbk-st/start"))
    out = _run(daemon, go)
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/sbk-st/start")


@pytest.mark.parametrize("status", ["created", "exited"])
def test_a_start_of_a_created_or_exited_container_goes_through(status):
    daemon = ToolDaemon()

    async def go(sock):
        daemon.add("sbk-st", RUN, status=status)
        return await call(sock, _req("POST", "sbk-st/start"))
    assert status_of(_run(daemon, go)) == 204


def test_one_start_per_container_at_a_time(monkeypatch):
    class SlowStart(ToolDaemon):
        async def _answer(self, reader, writer, method, path, query, body):
            if path.endswith("/start"):
                await asyncio.sleep(0.3)
            return await super()._answer(reader, writer, method, path, query, body)
    daemon = SlowStart()

    async def go(sock):
        daemon.add("sbk-twice", RUN, status="exited")
        return await asyncio.gather(*(call(sock, _req("POST", "sbk-twice/start")) for _ in range(2)))
    statuses = sorted(status_of(a) for a in _run(daemon, go))
    assert statuses == [204, 403], statuses


def test_a_start_raced_against_its_containers_exit_is_never_unadmitted(monkeypatch):
    """Cap 1, one running container: its start used to be forwarded unadmitted
    (a running one is already counted), and if it exited in between, restarted
    it past the cap. A start of a running container is now refused."""
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 1)

    def exits_after_the_check(daemon, ref):
        cid = daemon.find(ref)
        if cid:
            daemon.containers[cid]["status"] = "exited"
    daemon = ToolDaemon(after_inspect=exits_after_the_check)
    daemon.add("sbk-other-live", RUN, status="running")     # the cap's one place is taken

    async def go(sock):
        daemon.add("sbk-race", RUN, status="running")
        return await call(sock, _req("POST", "sbk-race/start"))
    out = _run(daemon, go)
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/sbk-race/start")


# ---------------------------------------------------------------------------
# Round 7. W1: a wait for the removal of a container the daemon removes on
# exit was ended two passes after it showed `exited`, while the daemon took
# longer to remove it (`docker run --rm` exit 125: "error waiting for
# container: unexpected EOF", and the tool's output discarded); W2: a 404 at a
# pass ended the calls at once, though the daemon answers that wait just after
# the container leaves its store; W3: an attach whose client had not read for a
# while (a paused recon container) was ended when its tool exited, losing the
# output still queued. Passes are run by hand here (watch_once).
# ---------------------------------------------------------------------------

@pytest.fixture
def manual_passes(monkeypatch):
    monkeypatch.setattr(broker, "WATCH_INTERVAL", 1000.0, raising=False)
    monkeypatch.setattr(broker, "ENDED_GRACE", 0.0, raising=False)
    monkeypatch.setattr(broker, "REMOVAL_GRACE", 1000.0, raising=False)


async def _rest(reader, seconds=3):
    out = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(1 << 20), seconds)
            if not chunk:
                return out, True
            out += chunk
    except (asyncio.TimeoutError, ConnectionError):
        return out, False


def test_a_wait_for_removal_outlasts_a_slow_removal(manual_passes):
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-slow-rm", RUN, status="running", auto_remove=True)
        daemon.exit_codes[cid] = 3
        head, r, w = await call(sock, _req("POST", "sbk-slow-rm/wait?condition=removed"), timeout=1, keep=True)
        daemon.containers[cid]["status"] = "exited"
        for _ in range(3):
            await broker.watch_once()
        daemon.containers[cid]["status"] = "removing"
        for _ in range(3):
            await broker.watch_once()
        daemon.end_streams(cid)                  # the removal is done: the daemon answers the wait
        rest, eof = await _rest(r)
        w.close()
        return head + rest
    answer = _run(daemon, go)
    assert b'{"StatusCode": 3}' in answer, answer[-200:]


def test_a_wait_for_removal_of_a_dead_container_is_still_ended(manual_passes):
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-dead", RUN, status="running", auto_remove=True)
        _, r, w = await call(sock, _req("POST", "sbk-dead/wait?condition=removed"), timeout=1, keep=True)
        daemon.containers[cid]["status"] = "dead"      # its removal failed: no answer will come
        for _ in range(2):
            await broker.watch_once()
        ended = await _eof_within(r, 1)
        w.close()
        return ended
    assert _run(daemon, go)


def test_a_wait_answered_just_after_its_container_left_the_store_is_not_cut(manual_passes):
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-gone-wait", RUN, status="running", auto_remove=True)
        daemon.exit_codes[cid] = 3
        head, r, w = await call(sock, _req("POST", "sbk-gone-wait/wait?condition=removed"), timeout=1, keep=True)
        del daemon.containers[cid]               # out of the store: the inspect says 404
        await broker.watch_once()                # a pass lands in the gap
        daemon.end_streams(cid)                  # and the daemon answers just after
        rest, _ = await _rest(r)
        w.close()
        return head + rest
    answer = _run(daemon, go)
    assert b'{"StatusCode": 3}' in answer, answer[-200:]


def test_a_call_whose_container_stays_gone_is_ended_at_a_later_pass(manual_passes):
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-gone-att", RUN)
        _, r, w = await call(sock, _attach("sbk-gone-att"), timeout=1, keep=True)
        del daemon.containers[cid]
        await broker.watch_once()
        after_first = await _eof_within(r, 0.3)
        await broker.watch_once()
        after_second = await _eof_within(r, 1)
        w.close()
        return after_first, after_second
    assert _run(daemon, go) == (False, True)


OUTPUT = 4_000_000


def test_an_attach_whose_client_has_not_read_its_output_keeps_it(manual_passes):
    """A recon container paused while its tool writes 4 MB and exits: the
    output must still all arrive once it reads again."""
    daemon = ToolDaemon()

    async def go(sock):
        cid = daemon.add("sbk-frozen", RUN, status="running")
        daemon.attach_output[cid] = b"x" * OUTPUT
        head, r, w = await call(sock, _attach("sbk-frozen"), timeout=1, keep=True)
        await asyncio.sleep(0.5)                 # the broker queues what it can toward the client
        daemon.containers[cid]["status"] = "exited"
        for _ in range(3):
            await broker.watch_once()
        daemon.end_streams(cid)
        rest, eof = await _rest(r, 5)
        w.close()
        return head.partition(b"\r\n\r\n")[2] + rest, eof
    got, eof = _run(daemon, go, seconds=60)
    assert eof and len(got) == OUTPUT, len(got)


# ---------------------------------------------------------------------------
# Round 8 (R7-2, R7-3). W3's kept calls had no bound: a client that never
# reads kept attach (and long-call) slots on ended containers for good, the
# attacker refilling those the 3/4 eviction freed. Now every container with an
# open call counts against the cap until the call ends, a kept call ends after
# KEPT_MAX whatever its client, and a new call that finds its budget full ends
# a kept one first, from the run holding the most.
# ---------------------------------------------------------------------------

RUN_B = dict(zip(broker.RUN_LABELS, ("partial_recon", "cmprojother000000000", "runother")))
HDR_B = ("X-Redamon-Run: partial_recon:cmprojother000000000:runother",)


async def _kept_attach(daemon, sock, name, run=RUN, hdr=HDR):
    """An attach to a container that writes 4 MB and exits; its client never reads."""
    cid = daemon.add(name, run, status="running")
    daemon.attach_output[cid] = b"z" * OUTPUT
    head, r, w = await call(sock, request_bytes("POST", f"{V}/containers/{name}/attach?stream=1&stdout=1",
                                                headers=hdr + ATT), timeout=1, keep=True)
    assert head.startswith(b"HTTP/1.1 101"), head[:200]
    await asyncio.sleep(0.3)
    daemon.containers[cid]["status"] = "exited"
    return cid, r, w


def test_a_kept_call_never_blocks_a_live_containers_attach(manual_passes, monkeypatch):
    monkeypatch.setattr(broker, "MAX_ATTACH_STREAMS", 3, raising=False)
    daemon = ToolDaemon()

    async def go(sock):
        held = [await _kept_attach(daemon, sock, f"sbk-kept-{i}") for i in range(3)]
        await broker.watch_once()
        await broker.watch_once()
        kept = sum(w.kept for w in broker._WATCHED.values())
        daemon.add("sbk-live", RUN_B, status="created")
        live, _, lw = await call(sock, request_bytes("POST", f"{V}/containers/sbk-live/attach?stream=1&stdout=1",
                                                     headers=HDR_B + ATT), timeout=1, keep=True)
        for _, _, w in held:
            w.close()
        lw.close()
        return kept, live
    kept, live = _run(daemon, go, seconds=60)
    assert kept == 3
    assert live.startswith(b"HTTP/1.1 101"), live[:200]


def test_a_full_budget_takes_a_kept_call_from_the_run_holding_the_most(manual_passes, monkeypatch):
    monkeypatch.setattr(broker, "MAX_ATTACH_STREAMS", 3, raising=False)
    daemon = ToolDaemon()

    async def go(sock):
        a = await _kept_attach(daemon, sock, "sbk-a-0")                       # run A's, the oldest
        b = [await _kept_attach(daemon, sock, f"sbk-b-{i}", RUN_B, HDR_B) for i in range(2)]
        await broker.watch_once()
        await broker.watch_once()
        daemon.add("sbk-new", RUN, status="created")
        new, _, nw = await call(sock, _attach("sbk-new"), timeout=1, keep=True)
        await asyncio.sleep(0.3)
        alive = {name: any(k[1] == daemon.find(name) for k in broker._WATCHED)
                 for name in ("sbk-a-0", "sbk-b-0", "sbk-b-1")}
        for _, _, w in [a] + b:
            w.close()
        nw.close()
        return new, alive
    new, alive = _run(daemon, go, seconds=60)
    assert new.startswith(b"HTTP/1.1 101")
    assert alive == {"sbk-a-0": True, "sbk-b-0": False, "sbk-b-1": True}, alive


def test_a_container_with_an_open_call_counts_against_the_cap(manual_passes, monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 2)
    daemon = ToolDaemon()

    async def go(sock):
        cid, r, w = await _kept_attach(daemon, sock, "sbk-ended")            # exited, its attach open
        first = await call(sock, request_bytes("POST", f"{V}/containers/create?name=sbk-c1", {"Image": "alpine"},
                                               headers=HDR))
        second = await call(sock, request_bytes("POST", f"{V}/containers/create?name=sbk-c2", {"Image": "alpine"},
                                                headers=HDR))
        w.close()                                                             # the caller lets it go
        await asyncio.sleep(0.5)
        third = await call(sock, request_bytes("POST", f"{V}/containers/create?name=sbk-c3", {"Image": "alpine"},
                                               headers=HDR))
        return first, second, third
    first, second, third = _run(daemon, go, seconds=60)
    assert status_of(first) == 201
    assert status_of(second) == 403 and b"count cap reached (2/2)" in second, second[:300]
    assert status_of(third) == 201, third[:300]


def test_a_client_that_never_reads_holds_no_more_than_the_cap(manual_passes, monkeypatch):
    """The reviewer's x15: budget 16, cap 4, every attacker container writes
    its output and exits while its attach is never read."""
    monkeypatch.setattr(broker, "MAX_ATTACH_STREAMS", 16, raising=False)
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 4)
    daemon = ToolDaemon()

    async def go(sock):
        held, created = [], 0
        for i in range(16):
            out = await call(sock, request_bytes("POST", f"{V}/containers/create?name=sbk-x{i}", {"Image": "alpine"},
                                                 headers=HDR))
            if status_of(out) != 201:
                continue
            created += 1
            cid = daemon.find(f"sbk-x{i}")
            daemon.attach_output[cid] = b"y" * OUTPUT
            _, r, w = await call(sock, _attach(f"sbk-x{i}"), timeout=1, keep=True)
            held.append(w)
            await asyncio.sleep(0.2)
            daemon.containers[cid]["status"] = "exited"
            await broker.watch_once()
        streams = len(broker._ATTACH_STREAMS)
        for w in held:
            w.close()
        return created, streams
    created, streams = _run(daemon, go, seconds=90)
    assert created <= 4 and streams <= 4, (created, streams)


def test_a_kept_call_ends_at_kept_max_whatever_its_client(manual_passes, monkeypatch):
    monkeypatch.setattr(broker, "KEPT_MAX", 0.5, raising=False)
    daemon = ToolDaemon()

    async def go(sock):
        cid, r, w = await _kept_attach(daemon, sock, "sbk-forever")
        await broker.watch_once()
        await broker.watch_once()
        kept_at_first = any(v.kept for v in broker._WATCHED.values())
        await asyncio.sleep(0.6)
        await broker.watch_once()
        await asyncio.sleep(0.3)
        left = len(broker._ATTACH_STREAMS)
        w.close()
        return kept_at_first, left
    assert _run(daemon, go, seconds=60) == (True, 0)


def test_a_kept_call_whose_caller_goes_away_ends_at_once(manual_passes):
    daemon = ToolDaemon()

    async def go(sock):
        cid, r, w = await _kept_attach(daemon, sock, "sbk-teardown")
        await broker.watch_once()
        await broker.watch_once()
        w.transport.abort()                      # the recon container is stopped
        t = time.monotonic()
        while broker._ATTACH_STREAMS and time.monotonic() - t < 3:
            await asyncio.sleep(0.05)
        return len(broker._ATTACH_STREAMS), time.monotonic() - t
    left, took = _run(daemon, go, seconds=60)
    assert left == 0 and took < 1.0, (left, took)

"""Round 5 of the broker's bounds (SBK): what a caller can hold, and what it can hide.

1. The container cap admits creates (and starts of exited containers) one count
   at a time, counting those admitted that the daemon has not answered yet: 20
   concurrent creates all read the same count below a cap of 3 and all went
   through.
3. DENY lines are limited per refusal class (the reason with its client values
   masked), not per kind of call: a flood of junk refusals hid the line of a
   privileged create or a smuggled head. The total stays bounded.
4. A long call on a container that has ended is refused (an attach, a wait for
   its next exit), and so is a wait for the removal of a container the daemon
   does not remove on exit: each held a long-call place for good once the
   container no longer counted against the cap.
5. `stop` always reaches the daemon with `t` <= STOP_TIMEOUT_MAX (`t=-1`, a huge
   `t`, or the container's own StopTimeout held it for good, unbudgeted), and
   counts as a long call.
6. Volume and network bodies are capped at 64 KiB, container creates at 256 KiB
   (round 6: 64 KiB refused real nuclei and naabu creates).
7. Only a long call is ended when its caller hangs up: a caller that half-closes
   after its request (`nc -N`) got an empty answer to every call.
8. A paused container counts against the cap (documented in the code).
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import (Daemon, ToolDaemon, call, request_bytes, run_through_broker,  # noqa: E402
                         serve_broker, status_of)

V = "/v1.57"
ATTACH_HEADERS = ("Connection: Upgrade", "Upgrade: tcp")
# getattr: so that this file collects on a broker without them (the tests then fail).
STOP_MAX = getattr(broker, "STOP_TIMEOUT_MAX", 30)
STOP_DEFAULT = getattr(broker, "STOP_TIMEOUT_DEFAULT", 10)


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)
    monkeypatch.setattr(broker, "_admitted", 0, raising=False)


def _with_daemon(daemon, go, seconds=60):
    async def main():
        sock, close = await serve_broker(daemon)
        try:
            return await go(sock)
        finally:
            await close()
    return asyncio.run(asyncio.wait_for(main(), seconds))


def _create(name, body=None):
    return request_bytes("POST", f"{V}/containers/create?name={name}", body or {"Image": "alpine"})


def _deny_lines(capsys):
    return [ln for ln in capsys.readouterr().out.splitlines() if "DENY" in ln]


# ---------------------------------------------------------------------------
# 1. The container cap is admitted atomically
# ---------------------------------------------------------------------------

def test_concurrent_creates_cannot_beat_the_cap(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 3)
    daemon = ToolDaemon(create_delay=0.2)

    async def go(sock):
        return await asyncio.gather(*(call(sock, _create(f"sbk-c{i}")) for i in range(20)))
    answers = _with_daemon(daemon, go)
    statuses = sorted(status_of(a) for a in answers)
    assert statuses.count(201) == 3 and statuses.count(403) == 17, statuses
    assert len(daemon.containers) == 3
    refused = [a for a in answers if status_of(a) == 403]
    assert all(b"count cap reached" in a for a in refused)


def test_an_admission_is_released_once_the_daemon_has_answered(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 2)
    daemon = ToolDaemon()

    async def go(sock):
        first = [status_of(await call(sock, _create(f"sbk-s{i}"))) for i in range(2)]
        over = status_of(await call(sock, _create("sbk-s2")))
        for c in list(daemon.containers.values()):
            c["status"] = "exited"          # both tools ended: two places free again
        again = [status_of(await call(sock, _create(f"sbk-t{i}"))) for i in range(2)]
        return first, over, again, broker._admitted
    first, over, again, admitted = _with_daemon(daemon, go)
    assert first == [201, 201] and over == 403 and again == [201, 201]
    assert admitted == 0


def test_a_refused_or_failed_create_gives_its_place_back(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 1)
    daemon = ToolDaemon()

    async def go(sock):
        bad = status_of(await call(sock, _create("sbk-p", {"Image": "alpine", "HostConfig": {"Privileged": True}})))
        good = status_of(await call(sock, _create("sbk-q")))
        return bad, good, broker._admitted
    assert _with_daemon(daemon, go) == (403, 201, 0)


def test_concurrent_starts_of_exited_containers_cannot_beat_the_cap(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 2)
    daemon = ToolDaemon()
    for i in range(6):
        daemon.add(f"sbk-e{i}", status="exited")

    async def go(sock):
        return await asyncio.gather(*(call(sock, request_bytes("POST", f"{V}/containers/sbk-e{i}/start"))
                                      for i in range(6)))
    statuses = sorted(status_of(a) for a in _with_daemon(daemon, go))
    assert statuses.count(204) == 2 and statuses.count(403) == 4, statuses
    assert sum(c["status"] == "running" for c in daemon.containers.values()) == 2


def test_a_count_the_daemon_never_answers_does_not_hold_every_create(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 5)
    monkeypatch.setattr(broker, "COUNT_TIMEOUT", 0.3, raising=False)

    class SilentCount(ToolDaemon):
        async def _answer(self, reader, writer, method, path, query, body):
            if path.endswith("/containers/json"):
                await asyncio.sleep(30)
            return await super()._answer(reader, writer, method, path, query, body)

    async def go(sock):
        return await asyncio.gather(*(call(sock, _create(f"sbk-u{i}"), timeout=5) for i in range(3)))
    answers = _with_daemon(SilentCount(), go, seconds=20)
    # Unknown count: admitted, as before (a daemon hiccup must not block a spawn).
    assert [status_of(a) for a in answers] == [201, 201, 201]


# ---------------------------------------------------------------------------
# 3. DENY lines per refusal class
# ---------------------------------------------------------------------------

PRIVILEGED = {"Image": "alpine", "HostConfig": {"Privileged": True}}


def test_junk_refusals_cannot_hide_a_privileged_create(capsys):
    junk = [request_bytes("POST", f"{V}/containers/create", {"Image": f"attacker/junk-{i}"}) for i in range(200)]
    responses, daemon = run_through_broker(junk + [request_bytes("POST", f"{V}/containers/create", PRIVILEGED)],
                                           Daemon())
    assert all(status_of(r) == 403 for r in responses)
    lines = _deny_lines(capsys)
    assert any("Privileged=true denied" in ln for ln in lines), lines[-3:]
    assert len(lines) <= broker.DENY_BURST + 1


def test_junk_heads_cannot_hide_a_smuggled_head(capsys):
    junk = [b"GET /_ping" + b"\x01" * (i % 7 + 1) + b" HTTP/1.1\r\nHost: x\r\n\r\n" for i in range(100)]
    smuggled = b"GET /v1.57/_ping HTTP/1.1\r\nHost: x\nContent-Length: 0\n\nGET /v1.57/info HTTP/1.1\r\n\r\n"
    responses, daemon = run_through_broker(junk + [smuggled], Daemon())
    assert all(status_of(r) == 403 for r in responses) and not daemon.received
    lines = _deny_lines(capsys)
    assert any("a bare CR or LF" in ln for ln in lines), lines


def test_junk_calls_off_the_allowlist_cannot_hide_an_exec(capsys):
    junk = [request_bytes("GET", f"{V}/junk{i}") for i in range(200)]
    exec_ = request_bytes("POST", f"{V}/containers/redamon-recon-orchestrator/exec", {"Cmd": ["env"]})
    responses, _ = run_through_broker(junk + [exec_], Daemon())
    assert all(status_of(r) == 403 for r in responses)
    lines = _deny_lines(capsys)
    assert any("/exec" in ln for ln in lines), lines[-3:]


def test_client_values_do_not_make_refusal_classes():
    variants = [
        [f"image not on allowlist: {v!r}" for v in ("a/b", "x" * 400, ["l", ["m"]], {"k": [1, {"z": 2}]}, None, 7)],
        [f"capability not allowed: {v!r}" for v in ("SYS_ADMIN", "ALL", "X1Y2")],
        [f"PidMode={v!r} denied" for v in ("host", "container:abc", "host:x")],
        [f"mount type not allowed: {v!r}" for v in ("tmpfs", "npipe", "cluster")],
        [f"keys {a!r} and {b!r} in HostConfig.Mounts[{i}] both name the Docker API field 'Type'"
         for a, b, i in (("type", "Type", 0), ("tYpe", "TYPE", 12))],
        [f"broker container count cap reached ({n}/48)" for n in (48, 49, 1000)],
        [f"container {c!r} is not a tool container of this run; no such container" for c in ("a", "b" * 64)],
    ]
    for group in variants:
        classes = {broker._refusal_class(r) for r in group}
        assert len(classes) == 1, classes
    assert broker._refusal_class("Privileged=true denied") != broker._refusal_class("VolumesFrom denied")
    exec_ = broker._refusal_class(broker._OFF_THE_ALLOWLIST, f"{V}/containers/x/exec")
    junk = {broker._refusal_class(broker._OFF_THE_ALLOWLIST, f"{V}/junk{i}") for i in range(50)}
    assert len(junk) == 1 and exec_ not in junk


def test_a_flood_of_varied_refusals_stays_bounded(capsys):
    reqs = []
    for i in range(300):
        reqs += [
            request_bytes("POST", f"{V}/containers/create", {"Image": f"evil/{i}"}),
            request_bytes("POST", f"{V}/containers/create", {"Image": "alpine", "HostConfig": {"CapAdd": [f"C{i}X"]}}),
            request_bytes("POST", f"{V}/containers/create", {"Image": "alpine", "HostConfig": {"PidMode": f"host{i}"}}),
            request_bytes("POST", f"{V}/containers/x{i}/kill"),
            request_bytes("GET", f"{V}/nope/{i}"),
        ]
    responses, _ = run_through_broker(reqs, Daemon())
    assert all(status_of(r) == 403 for r in responses)
    lines = _deny_lines(capsys)
    # Five classes: each shows its first line, the rest share DENY_SHARED.
    assert len(lines) <= 5 + broker.DENY_SHARED, len(lines)
    classes = {k for k in broker._log_marks if k[0] == "deny"}
    assert len(classes) <= 5, classes


def test_the_limiter_table_stays_bounded_whatever_the_keys(monkeypatch, capsys):
    monkeypatch.setattr(broker, "MAX_LOG_KEYS", 50, raising=False)
    for i in range(5000):
        broker._log_limited(("deny", f"k{i}"), "x", burst=1, shared=10)
    assert len(broker._log_marks) <= 50 + 2      # + the overflow key and its pool
    assert len(capsys.readouterr().out.splitlines()) <= 50 + 1


# ---------------------------------------------------------------------------
# 4. Long calls on containers that have ended
# ---------------------------------------------------------------------------

def _tool(daemon, name, status, auto_remove=False):
    daemon.add(name, status=status, auto_remove=auto_remove)


def _held(daemon, raw):
    async def go(sock):
        out, _, writer = await call(sock, raw, timeout=1, keep=True)
        writer.close()
        return out
    return _with_daemon(daemon, go)


@pytest.mark.parametrize("status", ["exited", "dead", "removing"])
def test_an_attach_to_a_container_that_has_ended_is_refused(status):
    daemon = ToolDaemon()
    _tool(daemon, "sbk-x", status, auto_remove=True)
    out = _held(daemon, request_bytes("POST", f"{V}/containers/sbk-x/attach?stream=1&stdout=1",
                                      headers=ATTACH_HEADERS))
    assert status_of(out) == 403 and b"has ended" in out, out[:300]
    assert not daemon.got("POST", f"{V}/containers/sbk-x/attach")


@pytest.mark.parametrize("status,condition,auto_remove,refused", [
    ("exited", "next-exit", True, True),
    ("dead", "next-exit", False, True),
    ("exited", "removed", False, True),       # never removed: waits for good
    ("running", "removed", False, True),      # would hold once it exits
    ("dead", "removed", True, True),          # its removal failed
    ("created", "removed", True, False),      # `docker run --rm`
    ("running", "removed", True, False),
    ("created", "next-exit", False, False),   # `docker run`
    ("running", "next-exit", False, False),
    ("exited", "not-running", False, False),  # answered at once
    ("exited", "", False, False),             # `docker wait`: not-running
], ids=lambda v: str(v))
def test_a_wait_must_be_able_to_end(status, condition, auto_remove, refused):
    daemon = ToolDaemon()
    _tool(daemon, "sbk-w", status, auto_remove)
    query = f"?condition={condition}" if condition else ""
    out = _held(daemon, request_bytes("POST", f"{V}/containers/sbk-w/wait{query}"))
    assert (status_of(out) == 403) is refused, out[:300]
    assert daemon.got("POST", f"{V}/containers/sbk-w/wait") is not refused


@pytest.mark.parametrize("query", ["?condition=removed&condition=not-running", "?condition=whenever",
                                   "?condit%69on=removed&condition=next-exit"])
def test_a_wait_condition_the_daemon_could_read_otherwise_is_refused(query):
    daemon = ToolDaemon()
    _tool(daemon, "sbk-w", "running", auto_remove=False)
    out = _held(daemon, request_bytes("POST", f"{V}/containers/sbk-w/wait{query}"))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/sbk-w/wait")


def test_logs_of_a_container_that_has_ended_are_still_answered():
    daemon = ToolDaemon()
    _tool(daemon, "sbk-l", "exited")
    out = _held(daemon, request_bytes("GET", f"{V}/containers/sbk-l/logs?stdout=1&stderr=1&follow=1"))
    assert status_of(out) == 200, out[:300]


# ---------------------------------------------------------------------------
# 5. stop
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("query,own,sent_t", [
    ("?t=-1", None, STOP_MAX),
    ("?t=999999999", None, STOP_MAX),
    ("?t=5", None, 5),
    ("?t=0", None, 0),
    ("?t=%2B7", None, 7),
    ("?t=5&t=-1", None, 5),                     # the daemon reads the first
    ("", 100000, STOP_MAX),      # the container's own StopTimeout
    ("", -1, STOP_MAX),
    ("", 7, 7),
    ("", None, STOP_DEFAULT),
    ("?signal=SIGINT", None, STOP_DEFAULT),
], ids=lambda v: str(v))
def test_a_stop_reaches_the_daemon_with_a_bounded_timeout(query, own, sent_t):
    daemon = ToolDaemon(stop_hold=0.05)
    daemon.add("sbk-st", status="running", stop_timeout=own)
    out = _held(daemon, request_bytes("POST", f"{V}/containers/sbk-st/stop{query}"))
    assert status_of(out) == 204, out[:300]
    [sent] = daemon.queries("POST", f"{V}/containers/sbk-st/stop")
    params = dict(p.split("=", 1) for p in sent.split("&"))
    assert params["t"] == str(sent_t), sent
    if "signal" in query:
        assert params["signal"] == "SIGINT"


@pytest.mark.parametrize("query", ["?t=abc", "?t=+5", "?t=1.5", "?t=1e3"])
def test_a_stop_timeout_that_is_not_an_integer_is_refused(query):
    daemon = ToolDaemon(stop_hold=0.05)
    daemon.add("sbk-st", status="running")
    out = _held(daemon, request_bytes("POST", f"{V}/containers/sbk-st/stop{query}"))
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/sbk-st/stop")


def test_a_stop_is_a_long_call_one_per_container_and_within_the_budget(monkeypatch):
    monkeypatch.setattr(broker, "MAX_LONG_CALLS", 2, raising=False)
    daemon = ToolDaemon(stop_hold=30)
    for name in ("sbk-a", "sbk-b", "sbk-c"):
        daemon.add(name, status="running")

    async def go(sock):
        first, _, w1 = await call(sock, request_bytes("POST", f"{V}/containers/sbk-a/stop"), timeout=0.5, keep=True)
        same = await call(sock, request_bytes("POST", f"{V}/containers/sbk-a/stop"), timeout=1)
        second, _, w2 = await call(sock, request_bytes("POST", f"{V}/containers/sbk-b/stop"), timeout=0.5, keep=True)
        third = await call(sock, request_bytes("POST", f"{V}/containers/sbk-c/stop"), timeout=1)
        w1.close()
        w2.close()
        await asyncio.sleep(0.3)
        return first, same, second, third
    first, same, second, third = _with_daemon(daemon, go)
    assert first == b"" and second == b""        # held by the daemon
    assert status_of(same) == 403 and b"already has an open stop" in same, same[:300]
    assert status_of(third) == 403 and b"long calls" in third, third[:300]
    assert daemon.got("POST", f"{V}/containers/sbk-a/stop")
    assert ("POST", f"{V}/containers/{daemon.find('sbk-a')}/stop") in daemon.closed \
        or ("POST", f"{V}/containers/sbk-a/stop") in daemon.closed     # the hang-up reached the daemon


# ---------------------------------------------------------------------------
# 6. Body cap
# ---------------------------------------------------------------------------

def test_the_body_caps_are_256_kib_for_a_create_and_64_kib_for_a_volume_or_network():
    # Round 6 (F7): 64 KiB refused real nuclei and naabu creates.
    assert broker.body_max("create") == broker.CREATE_BODY_MAX == 256 * 1024
    assert broker.body_max("volume-create") == broker.body_max("network-create") == broker.JSON_BODY_MAX == 64 * 1024


def _padded(size, extra=None):
    base = {"Image": "alpine", "Labels": {"pad": ""}, **(extra or {})}
    body = json.dumps({**base, "Labels": {"pad": "v" * (size - len(json.dumps(base)))}}).encode()
    assert len(body) == size
    return body


@pytest.mark.parametrize("size,refused", [(256 * 1024 + 1, True), (300 * 1024, True),
                                          (256 * 1024, False), (100 * 1024, False), (65 * 1024, False)])
def test_a_create_body_over_256_kib_is_refused(size, refused):
    raw = request_bytes("POST", f"{V}/containers/create", _padded(size))
    if refused:      # refused on the Content-Length: send the head and a little of the body only
        raw = raw[:raw.index(b"\r\n\r\n") + 4 + 64]
    [resp], daemon = run_through_broker([raw], Daemon())
    assert (status_of(resp) == 403) is refused, (size, resp[:200])
    assert daemon.got("POST", f"{V}/containers/create") is not refused


@pytest.mark.parametrize("path,kind", [("volumes/create", "volume"), ("networks/create", "network")])
def test_a_volume_or_network_body_over_64_kib_is_refused(path, kind):
    raw = (f"POST {V}/{path} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\n"
           f"Content-Length: {64 * 1024 + 1}\r\n\r\n").encode()
    [resp], daemon = run_through_broker([raw], Daemon())
    assert status_of(resp) == 403 and b"request body over 65536 bytes" in resp, resp[:200]


def test_a_nuclei_create_with_a_thousand_custom_templates_still_goes_through():
    """recon/helpers/nuclei_helpers.py passes each selected custom template as
    its own `-t`; 1000 of them made a 71 KB body, refused at 64 KiB."""
    cmd = ["-l", "/targets/targets.txt", "-jsonl", "-o", "/output/nuclei.jsonl"]
    for i in range(1000):
        cmd += ["-t", f"/custom-templates/project-templates/cmproj0123456789abc/template-{i:04d}-check.yaml"]
    body = {"Image": "projectdiscovery/nuclei:latest", "Cmd": cmd,
            "HostConfig": {"Binds": ["/tmp/redamon/.nuclei_temp_0123456789ab:/output"], "NetworkMode": "host"}}
    size = len(json.dumps(body))
    assert 64 * 1024 < size < broker.CREATE_BODY_MAX, size
    [resp], daemon = run_through_broker([request_bytes("POST", f"{V}/containers/create", body)], Daemon())
    assert status_of(resp) == 201, resp[:300]


def test_the_pending_body_budget_holds_32_mib_at_most(monkeypatch):
    resource = pytest.importorskip("resource")
    for name in ("MAX_PENDING_HEADS", "MAX_PENDING_BODIES", "MAX_ATTACH_STREAMS", "MAX_LONG_CALLS"):
        monkeypatch.setattr(broker, name, getattr(broker, name))
    monkeypatch.setattr(resource, "getrlimit", lambda _: (524288, 524288))
    monkeypatch.setattr(resource, "setrlimit", lambda *_: None)
    broker.raise_nofile_limit()
    assert broker.MAX_PENDING_BODIES == 128
    assert broker.MAX_PENDING_BODIES * broker.CREATE_BODY_MAX <= 32 * 1024 * 1024
    monkeypatch.setattr(resource, "getrlimit", lambda _: (1024, 1024))
    broker.raise_nofile_limit()
    assert broker.MAX_PENDING_BODIES == 64


# ---------------------------------------------------------------------------
# 7. The hang-up watch only on long calls
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,target,body", [
    ("GET", f"{V}/info", None),
    ("GET", f"{V}/containers/sbk-h/json", None),
    ("POST", f"{V}/containers/sbk-h/kill", None),
    ("POST", f"{V}/containers/create?name=sbk-new", {"Image": "alpine"}),
    ("HEAD", "/_ping", None),
], ids=lambda v: str(v)[:40])
def test_a_caller_that_half_closes_after_its_request_still_gets_the_answer(method, target, body):
    class SlowDaemon(ToolDaemon):
        async def _answer(self, reader, writer, *a):
            await asyncio.sleep(0.2)        # the caller's EOF arrives first
            return await super()._answer(reader, writer, *a)

    daemon = SlowDaemon()
    daemon.add("sbk-h", status="running")

    async def go(sock):
        return await call(sock, request_bytes(method, target, body), timeout=2, half_close=True)
    out = _with_daemon(daemon, go)
    assert status_of(out) in (200, 201, 204), out[:300]


def test_a_wait_whose_caller_hangs_up_is_still_closed_at_the_daemon():
    daemon = ToolDaemon()
    daemon.add("sbk-h", status="running")

    async def go(sock):
        out, _, writer = await call(sock, request_bytes("POST", f"{V}/containers/sbk-h/wait?condition=next-exit"),
                                    timeout=1, keep=True)
        writer.close()
        for _ in range(40):
            if daemon.closed:
                break
            await asyncio.sleep(0.05)
        return out
    out = _with_daemon(daemon, go)
    assert status_of(out) == 200
    assert ("POST", f"{V}/containers/{daemon.find('sbk-h')}/wait") in daemon.closed \
        or ("POST", f"{V}/containers/sbk-h/wait") in daemon.closed


# ---------------------------------------------------------------------------
# 8. Paused containers count
# ---------------------------------------------------------------------------

def test_a_paused_container_counts_against_the_cap(monkeypatch):
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 1)
    daemon = ToolDaemon()
    daemon.add("sbk-paused", status="paused")

    async def go(sock):
        return await call(sock, _create("sbk-more"))
    out = _with_daemon(daemon, go)
    assert status_of(out) == 403 and b"count cap reached (1/1)" in out, out[:300]
    assert "paused" in broker._LIVE_STATES


# ---------------------------------------------------------------------------
# Round 6. F4: the log volume of a class-cycling flood (round 5 logged the
# first line of every class: ~500 decoder messages made 570 lines, 98 KB, per
# 10 s); F5: refused calls off the allowlist carry their method and resource;
# F8: a create's StopTimeout is capped; the admission is given back as soon as
# the daemon has answered.
# ---------------------------------------------------------------------------

DANGEROUS = [("DELETE", f"{V}/volumes/redamon-osv-db"), ("DELETE", f"{V}/images/redamon-recon:latest"),
             ("DELETE", f"{V}/networks/redamon_default"), ("POST", f"{V}/auth"), ("POST", f"{V}/plugins/pull"),
             ("POST", f"{V}/session"), ("POST", f"{V}/grpc"), ("POST", f"{V}/exec/abc/start"),
             ("POST", f"{V}/containers/redamon-recon-orchestrator/exec")]


def _flood():
    reqs = [request_bytes("POST", f"{V}/containers/create", bytes([b]) + b'{"a":1}') for b in range(256)]
    reqs += [request_bytes("POST", f"{V}/containers/create", b'{\x00"\x00' + bytes([b])) for b in range(64)]
    reqs += [request_bytes("POST", f"{V}/volumes/create", b'{"a":"' + bytes([b]) + b'A"}') for b in range(128, 192)]
    verbs = "exec archive export commit update rename restart resize top changes stats prune push tag load".split()
    reqs += [request_bytes("POST", f"{V}" + "/a" * 150 + f"/containers/x/{verb}") for verb in verbs]
    reqs += [request_bytes("GET", f"{V}/info/x/{verb}") for verb in verbs]
    reqs += [request_bytes(m, f"{V}/{r}/x") for m in ("GET", "PUT", "PATCH") for r in ("swarm", "nodes", "tasks")]
    reqs += [request_bytes("POST", f"{V}/containers/create", {"Image": "evil/" + "x" * 400 + str(i)}) for i in range(200)]
    reqs += [request_bytes("GET", f"{V}/junk{i}") for i in range(200)]
    return reqs


def test_a_class_cycling_flood_writes_little_and_hides_no_attempt(capsys):
    attempts = [request_bytes("POST", f"{V}/containers/create", PRIVILEGED),
                request_bytes("POST", f"{V}/containers/create", b'{"Image":"alpine","Labels":{"a":"1"},"Labels":{}}'),
                b"GET /v1.57/_ping HTTP/1.1\r\nHost: x\nContent-Length: 0\n\nGET /v1.57/info HTTP/1.1\r\n\r\n"]
    attempts += [request_bytes(m, p) for m, p in DANGEROUS]
    responses, daemon = run_through_broker(_flood() + attempts, Daemon())
    assert all(status_of(r) == 403 for r in responses)
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "DENY" in ln]
    # The parent (kind-keyed) logged 80 lines / 14 KB for a flood like this.
    assert len(lines) <= 120 and sum(len(ln) + 1 for ln in lines) <= 25_000, (len(lines), sum(map(len, lines)))
    for needle in ["Privileged=true denied", "repeated key", "a bare CR or LF"] + [p for _, p in DANGEROUS]:
        assert any(needle in ln for ln in lines), needle


def test_bodies_that_do_not_parse_are_one_class_per_kind_and_a_repeated_key_its_own():
    reasons = {}
    undecodable = [bytes([b]) + b'{"a":1}' for b in range(256) if bytes([b]) not in b" \t\r\n"]
    for raw in undecodable + [b'{"a":', b"[1,]", b"nul", b"\xef\xbb\xbf\x00{}"]:
        try:
            broker.parse_body(raw)
        except Exception as e:  # noqa: BLE001
            reasons[str(e)] = e
    assert len(reasons) > 50          # the decoder's own texts differ
    # (handle_client keys them as one class; through the broker:)

    async def go():
        sock, close = await serve_broker(Daemon())
        try:
            for raw in undecodable:
                await call(sock, request_bytes("POST", f"{V}/containers/create", raw))
            await call(sock, request_bytes("POST", f"{V}/containers/create", b'{"Image":"alpine","Image":"x"}'))
        finally:
            await close()
    asyncio.run(go())
    classes = {k[2] for k in broker._log_marks if k[0] == "deny"}
    assert classes == {"create body does not parse", "create body repeats a key"}, classes


@pytest.mark.parametrize("method,path", DANGEROUS)
def test_a_dangerous_call_off_the_allowlist_is_not_in_the_junk_class(method, path):
    junk = broker._refusal_class(broker._OFF_THE_ALLOWLIST, f"{V}/junk1", "", "GET")
    mine = broker._refusal_class(broker._OFF_THE_ALLOWLIST, path, "", method)
    assert mine != junk
    others = {broker._refusal_class(broker._OFF_THE_ALLOWLIST, p, "", m) for m, p in DANGEROUS if (m, p) != (method, path)}
    assert mine not in others
    # Round 7 (N1): each in the alarm pool, so its first line always shows.
    assert broker._off_allowlist_pool(method, path) == "alarm"


def test_more_capped_classes_than_the_cap_log_the_cap_and_one_summary(capsys):
    for i in range(10):
        broker._log_limited(("deny", "noise", f"class {i}"), f"DENY line {i}", burst=5, shared=50, first_cap=4)
    for i in range(10):
        broker._log_limited(("deny", "alarm", f"class {i}"), f"DENY alarm {i}", burst=5, shared=50)
    out = capsys.readouterr().out.splitlines()
    assert [ln for ln in out if "DENY line" in ln] == [f"[docker-broker] DENY line {i}" for i in range(4)]
    assert len([ln for ln in out if "the rest are only counted" in ln]) == 1
    assert len([ln for ln in out if "DENY alarm" in ln]) == 10        # alarm first lines are never capped


@pytest.mark.parametrize("given,sent", [(-1, 30), (100000, 30), (31, 30), (30, 30), (7, 7), (0, 0), (None, None)])
def test_a_create_has_its_stop_timeout_capped(given, sent):
    body = {"Image": "alpine"} if given is None else {"Image": "alpine", "StopTimeout": given}
    [resp], daemon = run_through_broker([request_bytes("POST", f"{V}/containers/create", body)], Daemon())
    assert status_of(resp) == 201, resp[:300]
    [fwd] = [r for r in daemon.received if r["path"] == f"{V}/containers/create"]
    assert json.loads(fwd["body"]).get("StopTimeout") == sent


@pytest.mark.parametrize("given", ["30", 1.5, True, [1]])
def test_a_create_stop_timeout_that_is_not_an_integer_is_refused(given):
    [resp], daemon = run_through_broker(
        [request_bytes("POST", f"{V}/containers/create", {"Image": "alpine", "StopTimeout": given})], Daemon())
    assert status_of(resp) == 403, resp[:300]


def test_the_admission_is_given_back_once_the_daemon_has_answered(monkeypatch):
    """Cap 2, one container live: a create the daemon has answered (its
    connection still open) held its place until the relay ended, so a second
    create at the edge was refused one early."""
    monkeypatch.setattr(broker, "BROKER_MAX_CONTAINERS", 2)
    daemon = ToolDaemon(create_close_delay=1.0)
    daemon.add("sbk-live", status="running")

    async def go(sock):
        first, _, w = await call(sock, _create("sbk-first"), timeout=0.5, keep=True)
        daemon.create_close_delay = 0
        daemon.containers[daemon.find("sbk-live")]["status"] = "exited"
        second = await call(sock, _create("sbk-second"))
        w.close()
        return first, second
    first, second = _with_daemon(daemon, go)
    assert status_of(first) == 201 and status_of(second) == 201, (first[:200], second[:200])


# ---------------------------------------------------------------------------
# Round 7. N1: an exec on an infrastructure container shared "POST containers"
# with junk in the capped endpoint pool, so one same-class junk call and a
# drained allowance, or 64 other endpoint classes first, kept it out of the
# log; N2: a validator refusal's pool was chosen by searching the raw reason,
# client values included, so a bind refused with "is not an integer" in its
# destination went to the capped noise pool.
# ---------------------------------------------------------------------------

ESCAPES = [("POST", f"{V}/containers/redamon-recon-orchestrator/exec", {"Cmd": ["sh"]}),
           ("PUT", f"{V}/containers/redamon-recon-orchestrator/archive?path=/", None),
           ("POST", f"{V}/containers/redamon-recon-orchestrator/update", None),
           ("POST", f"{V}/exec/abc/start", None), ("POST", f"{V}/build", None),
           ("POST", f"{V}/images/redamon-recon:latest/push", None), ("DELETE", f"{V}/volumes/redamon-osv-db", None),
           ("POST", f"{V}/plugins/pull?remote=evil", None), ("POST", f"{V}/swarm/init", None)]
DRAIN = [request_bytes("POST", f"{V}/containers/create", {"Image": "alpine", "HostConfig": hc})
         for hc in ({"Privileged": True}, {"VolumesFrom": ["x"]}, {"Devices": [{"PathOnHost": "/dev/sda"}]})
         for _ in range(21)]


def _logged(prelude, attempts, capsys):
    run_through_broker(prelude + attempts, Daemon())
    return capsys.readouterr().out


@pytest.mark.parametrize("prelude", ["same-class junk then a drained allowance", "64 other endpoint classes"])
def test_an_escape_call_off_the_allowlist_is_always_logged(prelude, capsys):
    if prelude.startswith("same"):
        before = [request_bytes("POST", f"{V}/containers/x/junk"), request_bytes("PUT", f"{V}/containers/x/junk"),
                  request_bytes("POST", f"{V}/images/x/junk")] + DRAIN
    else:
        methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]
        resources = ["images", "volumes", "networks", "containers", "info", "version", "_ping", "nodes", "tasks",
                     "services", "secrets", "configs", "system", "events", "distribution", "auth", "session"]
        before = [request_bytes(m, f"{V}/{r}/x/y") for m in methods for r in resources
                  if broker.match_route(m, f"{V}/{r}/x/y")[0] is None][:100]
        assert len(before) == 100      # more endpoint classes than DENY_FIRST_ENDPOINT (64) allowed
    out = _logged(before, [request_bytes(m, p, b) for m, p, b in ESCAPES], capsys)
    for _, p, _ in ESCAPES:
        assert f"{p.split('?')[0]}:" in out, p


@pytest.mark.parametrize("hc", [
    {"Binds": ["/:/host is not an integer"]},
    {"Binds": ["/var/run/docker.sock:/s is not a JSON object"]},
    {"Binds": ["/etc:/e is not a JSON array"]},
    {"Mounts": [{"Type": "bind", "Source": "/", "Target": "/h is not an integer"}]},
    {"CapAdd": ["SYS_ADMIN is not an integer"]},
    {"PidMode": "host is not a JSON object"},
    {"NetworkMode": "container:x is not a JSON array"},
    {"SecurityOpt": ["seccomp=unconfined is not an integer"]},
    {"VolumeDriver": "evil is not a JSON object"},
    {"Mounts": [{"Type": "tmpfs is not an integer"}]},
    {"Mounts": [{"Type": "volume", "Source": "redamon_postgres_data is not a JSON object"}]},
], ids=lambda hc: next(iter(hc)))
def test_an_escape_refusal_is_an_alarm_whatever_its_values(hc, capsys):
    body = {"Image": "alpine", "HostConfig": hc}
    ok, reason = broker.validate_create(json.loads(json.dumps(body)))
    assert not ok and broker._validator_pool(reason) == "alarm", reason
    noise = [request_bytes("POST", f"{V}/containers/create", {"Image": "alpine", "HostConfig": {k: v}})
             for k, v in (("Memory", "x"), ("Binds", "x"), ("PidsLimit", 1.5), ("LogConfig", 1), ("Mounts", 1),
                          ("Ulimits", 1), ("RestartPolicy", 1), ("CapAdd", 1), ("SecurityOpt", 1))]
    noise += [request_bytes("POST", f"{V}/containers/create", b"{" * (i + 1)) for i in range(4)]
    noise += [request_bytes("GET", f"{V}/zz{i}/x") for i in range(4)]
    out = _logged(noise + DRAIN, [request_bytes("POST", f"{V}/containers/create", body)], capsys)
    assert reason[:40] in out, reason
    assert any(k[0] == "deny" and k[1] == "alarm" and k[2] == broker._refusal_class(reason, "", "")
               or k[0] == "deny" and k[1] == "alarm" and k[2].startswith(broker._refusal_class(reason)[:20])
               for k in broker._log_marks), reason


@pytest.mark.parametrize("reason", ["HostConfig is not a JSON object", "HostConfig.Mounts[0] is not a JSON object",
                                    "NetworkingConfig.EndpointsConfig['n'] is not a JSON object",
                                    "HostConfig.Binds is not a JSON array", "HostConfig.Memory is not an integer",
                                    "StopTimeout is not an integer", "unexpected value in the body (TypeError)",
                                    "create body is not a JSON object", "the body is not a JSON object",
                                    "unparseable volume create body"])
def test_a_shape_refusal_is_still_noise(reason):
    assert broker._validator_pool(reason) == "noise"


# ---------------------------------------------------------------------------
# Round 8 (R7-1): the daemon decodes the path once before routing (`%69nfo`,
# `containers%2Fjson`, `ex%65c` all reach their handlers), but the classes read
# it raw, so an encoded exec, archive, volume delete or plugin install landed
# in the capped pools; and the websocket attach was not on the dangerous list.
# ---------------------------------------------------------------------------

ENCODED = [("POST", f"{V}/containers/redamon-recon-orchestrator/ex%65c"),
           ("POST", f"{V}/c%6Fntainers/redamon-recon-orchestrator/exec"),
           ("POST", f"{V}/containers%2Fredamon-recon-orchestrator%2Fexec"),
           ("POST", f"{V}/%65xec/0123abcd/start"),
           ("PUT", f"{V}/containers/redamon-recon-orchestrator/%61rchive?path=/"),
           ("DELETE", f"{V}/v%6Flumes/redamon-osv-db"),
           ("POST", f"{V}/pl%75gins/pull?remote=x"),
           ("GET", f"{V}/containers/redamon-recon-orchestrator/attach/ws?stdin=1&stream=1"),
           ("POST", f"{V}/containers/redamon-recon-orchestrator/%2565xec")]       # encoded twice


@pytest.mark.parametrize("method,path", ENCODED, ids=lambda v: v.split("/", 2)[-1][:40] if "/" in v else v)
def test_an_encoded_or_websocket_escape_call_is_an_alarm(method, path):
    assert broker._off_allowlist_pool(method, broker._normalize_path(path)) == "alarm"


def _noise_flood():
    """More noise classes than DENY_FIRST_NOISE: junk paths, shape errors, bodies that do not parse."""
    flood = [request_bytes(m, f"{V}/zz/x") for m in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")]
    flood += [request_bytes("POST", f"{V}/containers/create", {"Image": "alpine", "HostConfig": {k: v}})
              for k, v in (("Memory", "x"), ("MemorySwap", "x"), ("PidsLimit", "x"), ("Binds", "x"), ("CapAdd", "x"),
                           ("SecurityOpt", "x"), ("LogConfig", 1), ("RestartPolicy", 1), ("Mounts", 1), ("Ulimits", 1))]
    flood += [request_bytes("POST", f"{V}/containers/create", body) for body in
              ({"Image": "alpine", "HostConfig": "x"}, {"Image": "alpine", "Healthcheck": 1},
               {"Image": "alpine", "NetworkingConfig": 1}, {"Image": "alpine", "StopTimeout": "x"}, b"{")]
    flood += [request_bytes("POST", f"{V}/volumes/create", b"{"), request_bytes("POST", f"{V}/networks/create", b"{")]
    return flood


def _endpoint_flood():
    """Junk in the endpoint classes an encoded call off the allowlist read as raw
    (no delete of an image, volume or network: those are attempts of their own)."""
    return [request_bytes(m, f"{V}/{r}/x/junk") for m in ("GET", "POST", "PUT", "DELETE")
            for r in ("containers", "images", "volumes", "networks") if m != "DELETE" or r == "containers"]


@pytest.mark.parametrize("flood", ["noise", "endpoint"])
@pytest.mark.parametrize("method,path", ENCODED[:7], ids=lambda v: v.split("/", 2)[-1][:40] if "/" in v else v)
def test_an_encoded_escape_call_is_logged_after_a_flood(method, path, flood, capsys):
    before = (_noise_flood() if flood == "noise" else _endpoint_flood()) + DRAIN
    out = _logged(before, [request_bytes(method, path)], capsys)
    assert f"{broker._normalize_path(path)}:" in out, path


def test_a_decoded_path_still_names_the_same_endpoint_for_an_ordinary_call():
    assert broker._call_shape("GET", f"{V}/c%6Fntainers/x/junk") == ("GET", "containers")
    assert broker._off_allowlist_pool("GET", f"{V}/zz%2Fy") == "noise"

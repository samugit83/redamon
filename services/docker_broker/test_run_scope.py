"""A caller reaches only its own run's tool containers (SBK round 5, item 2).

Every recon container shares one broker socket, and names its run in the
`X-Redamon-Run: <kind>:<project>:<run>` header its Docker CLI sends on every
call; the broker stamps that run on each container it creates. Before this, any
caller could list every run's tool containers and attach to, wait on, stop or
kill any of them, and since a container takes one attach, one wait and one
logs at a time, one run could take another run's slot before that run's own
`docker run` did, which then failed.

Now a listing shows, and a call on an existing container reaches, only the
containers stamped with exactly the run the request names; a request with no
(or a malformed) header reaches only containers stamped with no run, and lists
none. The header is a claim (the broker cannot authenticate its callers): a
forged one reaches the run it names, and never more than that one run.
"""
import asyncio
import json
import os
import sys
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import INFRA, ToolDaemon, call, request_bytes, serve_broker, status_of  # noqa: E402

V = "/v1.57"
PROJECT = "cmproj0123456789abc"
RUN_A = ("full_recon", PROJECT, "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
RUN_B = ("partial_recon", "cmprojother000000000", "0a1b2c3d-0000-4a6b-8c7d-9e0f1a2b3c4d")
ATTACH_HEADERS = ("Connection: Upgrade", "Upgrade: tcp")


def header(run):
    return f"X-Redamon-Run: {':'.join(run)}"


def labelled(run):
    return dict(zip(broker.RUN_LABELS, run))


@pytest.fixture(autouse=True)
def _fresh_log_marks(monkeypatch):
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)


def _with_daemon(daemon, steps):
    async def go():
        sock, close = await serve_broker(daemon)
        try:
            out = []
            for step in steps:
                out.append(await step(sock))
            return out
        finally:
            await close()
    return asyncio.run(asyncio.wait_for(go(), 60))


def _req(method, target, run=None, body=None, extra=()):
    return request_bytes(method, target, body, headers=((header(run),) if run else ()) + tuple(extra))


def _one(daemon, method, target, run=None, body=None, extra=(), **kw):
    async def step(sock):
        return await call(sock, _req(method, target, run, body, extra), **kw)
    [out] = _with_daemon(daemon, [step])
    return out


def _two_runs():
    daemon = ToolDaemon()
    a = daemon.add("naabu-a", labelled(RUN_A), auto_remove=True)
    b = daemon.add("naabu-b", labelled(RUN_B), auto_remove=True)
    none = daemon.add("analyzer-x", {}, auto_remove=True)          # a caller with no run made it
    return daemon, a, b, none


# Every call on an existing container the broker forwards, as the CLI sends it.
CALLS = [
    ("POST", "kill", ()), ("POST", "stop", ()), ("POST", "start", ()), ("POST", "pause", ()),
    ("POST", "unpause", ()), ("POST", "wait?condition=removed", ()), ("GET", "logs?stdout=1", ()),
    ("GET", "json", ()), ("DELETE", "", ()), ("POST", "attach?stream=1&stdout=1", ATTACH_HEADERS),
]
IDS = [f"{m} {v.split('?')[0] or 'remove'}" for m, v, _ in CALLS]


def _target(ref, verb):
    return f"{V}/containers/{ref}" + (f"/{verb}" if verb else "")


@pytest.mark.parametrize("method,verb,extra", CALLS, ids=IDS)
def test_a_run_reaches_its_own_containers(method, verb, extra):
    daemon, a, _, _ = _two_runs()
    out = _one(daemon, method, _target("naabu-a", verb), RUN_A, extra=extra, timeout=1)
    assert status_of(out) != 403, out[:300]
    assert daemon.got(method, _target("naabu-a", verb.split("?")[0]))


@pytest.mark.parametrize("method,verb,extra", CALLS, ids=IDS)
@pytest.mark.parametrize("caller", ["other-run", "no-header", "malformed-header"])
def test_another_run_or_no_run_cannot_reach_a_runs_container(method, verb, extra, caller, capsys):
    daemon, a, _, _ = _two_runs()
    if caller == "other-run":
        out = _one(daemon, method, _target("naabu-a", verb), RUN_B, extra=extra, timeout=1)
    elif caller == "no-header":
        out = _one(daemon, method, _target("naabu-a", verb), None, extra=extra, timeout=1)
    else:
        out = _one(daemon, method, _target("naabu-a", verb), None, timeout=1,
                   extra=extra + ("X-Redamon-Run: full_recon:../x:y",))
    assert status_of(out) == 403, out[:300]
    assert b"is not a tool container of this run" in out
    assert not daemon.got(method, _target("naabu-a", verb.split("?")[0]))
    # The operator's log says which case it was; the caller's answer does not.
    assert "created for another run" in capsys.readouterr().out
    assert b"another run" not in out


def test_the_answer_is_the_same_for_another_runs_an_infra_and_an_absent_container():
    daemon, _, _, _ = _two_runs()
    daemon.add(INFRA, {"com.docker.compose.service": "recon-orchestrator"}, owned=False)
    answers = {ref: _one(daemon, "POST", _target(ref, "kill"), RUN_A, timeout=1)
               for ref in ("naabu-b", INFRA, "no-such-container")}
    bodies = {ref: out.split(b"\r\n\r\n", 1)[1].replace(ref.encode(), b"X") for ref, out in answers.items()}
    assert len(set(bodies.values())) == 1, bodies


def test_a_container_made_with_no_run_is_reached_only_with_no_run():
    daemon, _, _, _ = _two_runs()
    assert status_of(_one(daemon, "POST", _target("analyzer-x", "kill"), None)) != 403
    for run in (RUN_A, RUN_B):
        daemon2, _, _, _ = _two_runs()
        out = _one(daemon2, "POST", _target("analyzer-x", "kill"), run)
        assert status_of(out) == 403, out[:300]
        assert not daemon2.got("POST", _target("analyzer-x", "kill"))


def test_a_container_is_reached_by_its_id_and_an_id_prefix_only_from_its_run():
    daemon, a, _, _ = _two_runs()
    for ref in (a, a[:12]):
        assert status_of(_one(daemon, "POST", _target(ref, "kill"), RUN_B)) == 403
        assert status_of(_one(daemon, "POST", _target(ref, "kill"), RUN_A)) != 403


def test_one_run_cannot_take_another_runs_single_attach_slot():
    """The targeted start failure: B attaches to A's container first, so A's own
    `docker run` attach was refused ("already has an open attach")."""
    daemon, a, _, _ = _two_runs()
    attach = _target("naabu-a", "attach?stream=1&stdout=1&stderr=1")

    async def b_first(sock):
        b_out, b_r, b_w = await call(sock, _req("POST", attach, RUN_B, extra=ATTACH_HEADERS), timeout=1, keep=True)
        a_out, a_r, a_w = await call(sock, _req("POST", attach, RUN_A, extra=ATTACH_HEADERS), timeout=1, keep=True)
        b_w.close()
        a_w.close()
        return b_out, a_out
    [(b_out, a_out)] = _with_daemon(daemon, [b_first])
    assert status_of(b_out) == 403, b_out[:300]
    assert a_out.startswith(b"HTTP/1.1 101"), a_out[:300]


def test_one_run_cannot_take_another_runs_single_wait_slot():
    daemon, a, _, _ = _two_runs()
    wait = _target("naabu-a", "wait?condition=removed")

    async def b_first(sock):
        b_out, _, b_w = await call(sock, _req("POST", wait, RUN_B), timeout=1, keep=True)
        a_out, _, a_w = await call(sock, _req("POST", wait, RUN_A), timeout=1, keep=True)
        b_w.close()
        a_w.close()
        return b_out, a_out
    [(b_out, a_out)] = _with_daemon(daemon, [b_first])
    assert status_of(b_out) == 403, b_out[:300]
    assert status_of(a_out) == 200, a_out[:300]


def _listed(out):
    return sorted(c["Names"][0].lstrip("/") for c in json.loads(out.split(b"\r\n\r\n", 1)[1]))


@pytest.mark.parametrize("query", ["?all=1", "", '?all=1&filters={"label":["redamon.broker-owned=1"]}',
                                   '?filters={"label":{"redamon.run_id=x":true}}'])
def test_a_listing_shows_only_the_callers_run(query):
    daemon, _, _, _ = _two_runs()
    daemon.add(INFRA, {}, owned=False)
    target = f"{V}/containers/json" + query.replace('"', "%22").replace("{", "%7B").replace("}", "%7D")
    out_a = _one(daemon, "GET", target, RUN_A)
    out_b = _one(daemon, "GET", target, RUN_B)
    assert status_of(out_a) == 200 and status_of(out_b) == 200
    if "run_id=x" in query:      # the caller's own filter still narrows
        assert _listed(out_a) == [] and _listed(out_b) == []
    else:
        assert _listed(out_a) == ["naabu-a"] and _listed(out_b) == ["naabu-b"]


def test_a_listing_with_no_run_shows_nothing():
    daemon, _, _, _ = _two_runs()
    out = _one(daemon, "GET", f"{V}/containers/json?all=1", None)
    assert status_of(out) == 200, out[:300]
    assert _listed(out) == []


def test_the_listing_the_daemon_gets_carries_the_owner_and_run_filters():
    daemon, _, _, _ = _two_runs()
    _one(daemon, "GET", f"{V}/containers/json?all=1", RUN_A)
    [query] = daemon.queries("GET", f"{V}/containers/json")
    labels = json.loads(urllib.parse.parse_qs(query)["filters"][0])["label"]
    assert set(labels) == {"redamon.broker-owned=1", *(f"{k}={v}" for k, v in labelled(RUN_A).items())}


def test_a_forged_header_reaches_at_most_the_run_it_names():
    """The residual, pinned: a caller that names run A (knowing its project and
    run id) reaches A's containers, and still none of B's or the run-less ones."""
    daemon, _, _, _ = _two_runs()
    reach = {name: status_of(_one(daemon, "POST", _target(name, "kill"), RUN_A)) != 403
             for name in ("naabu-a", "naabu-b", "analyzer-x")}
    assert reach == {"naabu-a": True, "naabu-b": False, "analyzer-x": False}


def test_a_create_still_carries_the_run_its_header_names():
    daemon = ToolDaemon()
    out = _one(daemon, "POST", f"{V}/containers/create?name=naabu-new", RUN_A,
               body={"Image": "projectdiscovery/naabu:latest", "Labels": labelled(RUN_B)})
    assert status_of(out) == 201, out[:300]
    [c] = daemon.containers.values()
    assert {k: c["labels"].get(k) for k in broker.RUN_LABELS} == labelled(RUN_A)


def test_a_docker_run_and_a_kill_of_one_run_go_through_end_to_end():
    """What a tool does: create (the run stamped), attach, wait, start, and a
    kill by name on timeout, every call naming the run."""
    daemon = ToolDaemon()
    create = _req("POST", f"{V}/containers/create?name=nuclei-run-a", RUN_A,
                  body={"Image": "projectdiscovery/nuclei:latest", "HostConfig": {"AutoRemove": True}})

    async def run(sock):
        created = await call(sock, create)
        cid = json.loads(created.split(b"\r\n\r\n", 1)[1])["Id"]
        att, _, att_w = await call(sock, _req("POST", _target(cid, "attach?stderr=1&stdout=1&stream=1"), RUN_A,
                                              extra=ATTACH_HEADERS), timeout=1, keep=True)
        wait, _, wait_w = await call(sock, _req("POST", _target(cid, "wait?condition=removed"), RUN_A),
                                     timeout=1, keep=True)
        start = await call(sock, _req("POST", _target(cid, "start"), RUN_A))
        kill = await call(sock, _req("POST", _target("nuclei-run-a", "kill"), RUN_A))
        att_w.close()
        wait_w.close()
        return [status_of(x) for x in (created, att, wait, start, kill)]
    [statuses] = _with_daemon(daemon, [run])
    assert statuses == [201, 101, 200, 204, 204]


# ---------------------------------------------------------------------------
# Round 6 (F6): a network inspect named every container on the network, every
# run's and every tenant's (full ids, names, addresses): the TruffleHog
# verifier's network holds the orchestrator's TruffleHog scans, whose
# environment carries tenants' tokens. The tools read only the exit code.
# ---------------------------------------------------------------------------

NET = "redamon-trufflehog-net"


def _net_daemon():
    daemon = ToolDaemon()
    a = daemon.add("trufflehog-a", labelled(RUN_A))
    b = daemon.add("redamon-trufflehog-scan-tenant-b", {}, owned=False)
    daemon.networks[NET] = {a: {"Name": "trufflehog-a", "IPv4Address": "172.30.0.2/16"},
                            b: {"Name": "redamon-trufflehog-scan-tenant-b", "IPv4Address": "172.30.0.3/16"}}
    return daemon, a, b


def test_a_network_inspect_answers_without_the_networks_containers():
    daemon, a, b = _net_daemon()
    out = _one(daemon, "GET", f"{V}/networks/{NET}", RUN_A)
    head, _, body = out.partition(b"\r\n\r\n")
    assert status_of(out) == 200, out[:300]
    doc = json.loads(body)
    assert doc["Name"] == NET and doc["Driver"] == "bridge"
    assert "Containers" not in doc and "Services" not in doc
    assert a.encode() not in out and b.encode() not in out and b"tenant-b" not in out
    assert f"Content-Length: {len(body)}".encode() in head


def test_a_missing_network_is_still_a_404_for_the_cli():
    daemon, _, _ = _net_daemon()
    out = _one(daemon, "GET", f"{V}/networks/redamon-supply-chain-net", RUN_A)
    assert status_of(out) == 404, out[:300]


@pytest.mark.parametrize("answer", [b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nnot json!", b"garbage", b""])
def test_a_network_answer_the_broker_cannot_read_is_not_relayed(answer):
    class Garbled(ToolDaemon):
        async def _answer(self, reader, writer, method, path, query, body):
            if "/networks/" in path:
                writer.write(answer)
                return
            return await super()._answer(reader, writer, method, path, query, body)
    out = _one(Garbled(), "GET", f"{V}/networks/{NET}", RUN_A)
    assert status_of(out) == 502, out[:300]


def test_a_chunked_network_answer_is_read_whole():
    class Chunked(ToolDaemon):
        async def _answer(self, reader, writer, method, path, query, body):
            if "/networks/" in path:
                data = json.dumps({"Name": NET, "Containers": {"c" * 64: {"Name": "x"}}}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                             + b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data))
                return
            return await super()._answer(reader, writer, method, path, query, body)
    out = _one(Chunked(), "GET", f"{V}/networks/{NET}", RUN_A)
    assert status_of(out) == 200 and json.loads(out.partition(b"\r\n\r\n")[2]) == {"Name": NET}, out[:300]

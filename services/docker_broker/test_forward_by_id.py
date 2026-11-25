"""A call on a container reaches the container the broker checked (SBK round 6, F1).

The broker checked the container the client's reference names, then forwarded
the client's reference, which the daemon resolves again: a full id, then an
exact name, then a unique id prefix. So a caller names its own container with
another container's id prefix (`docker create --name <prefix>`), the check
finds its own (the name wins), and if the caller removes it between the check
and the forward, the forwarded reference is only a prefix, of the other
container: an infrastructure container's inspect (its environment holds the
master keys), logs, kill, stop, pause or forced removal. Now every call is
forwarded on the full id the check read.

`ToolDaemon` resolves references in the daemon's order, and its after_inspect
hook removes the caller's container right after the broker's inspect: the
race, made deterministic.
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402
from mock_daemon import INFRA, ToolDaemon, call, request_bytes, serve_broker, status_of  # noqa: E402

V = "/v1.57"
RUN = ("full_recon", "cmprojattacker000000", "runattacker")
HDR = (f"X-Redamon-Run: {':'.join(RUN)}",)
SECRET = "NEO4J_PASSWORD=s3cret-master"


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    monkeypatch.setattr(broker, "_log_marks", {}, raising=False)


def _raced(armed=True):
    """A daemon with a running infrastructure container (the victim) and the
    caller's own container named with the victim's first 12 hex characters;
    the caller's container is removed right after the broker inspects it."""
    state = {"armed": armed}

    def after_inspect(daemon, ref):
        own = daemon.find(ref)
        if state["armed"] and own and daemon.containers[own]["name"] == ref:
            del daemon.containers[own]
            state["armed"] = False
    daemon = ToolDaemon(after_inspect=after_inspect, stop_hold=0.05)
    victim = daemon.add(INFRA, {"com.docker.compose.service": "recon-orchestrator"}, status="running", owned=False)
    daemon.env[victim] = [SECRET]
    prefix = victim[:12]
    own = daemon.add(prefix, dict(zip(broker.RUN_LABELS, RUN)), status="created")
    return daemon, victim, prefix, own


def _send(daemon, method, target, extra=()):
    async def go():
        sock, close = await serve_broker(daemon)
        try:
            return await call(sock, request_bytes(method, target, headers=HDR + tuple(extra)), timeout=1)
        finally:
            await close()
    return asyncio.run(asyncio.wait_for(go(), 30))


def test_an_inspect_raced_against_the_removal_of_the_callers_container_never_reads_another():
    daemon, victim, prefix, own = _raced()
    out = _send(daemon, "GET", f"{V}/containers/{prefix}/json")
    assert SECRET.encode() not in out and b"recon-orchestrator" not in out, out[:400]
    assert status_of(out) == 404, out[:300]           # the caller's own container, now gone
    forwarded = [r["path"] for r in daemon.received if r["method"] == "GET"]
    assert f"{V}/containers/{own}/json" in forwarded, forwarded
    assert f"{V}/containers/{prefix}/json" not in forwarded


@pytest.mark.parametrize("method,verb,extra", [
    ("GET", "logs?stdout=1", ()),
    ("POST", "kill", ()),
    ("POST", "stop?t=1", ()),
    ("POST", "pause", ()),
    ("POST", "unpause", ()),
    ("DELETE", "?force=1", ()),
    ("POST", "wait?condition=not-running", ()),
    ("POST", "attach?stream=1&stdout=1", ("Connection: Upgrade", "Upgrade: tcp")),
], ids=lambda v: str(v).split("?")[0] if isinstance(v, str) else "")
def test_no_call_raced_that_way_reaches_the_other_container(method, verb, extra):
    daemon, victim, prefix, own = _raced()
    target = f"{V}/containers/{prefix}" + (verb if verb.startswith("?") else f"/{verb}")
    _send(daemon, method, target, extra)
    assert victim in daemon.containers and daemon.containers[victim]["status"] == "running"
    named = [r["path"][len(f"{V}/containers/"):].split("/")[0] for r in daemon.received
             if r["path"].startswith(f"{V}/containers/")]
    assert named == [own], named      # forwarded once, on the checked container's full id


@pytest.mark.parametrize("target,expected", [
    ("{ref}/json", "{id}/json"),
    ("{ref}/logs?stdout=1&follow=0", "{id}/logs"),
    ("{ref}?force=1&v=1", "{id}"),
    ("{ref}/kill?signal=KILL", "{id}/kill"),
])
def test_every_call_is_forwarded_on_the_full_id_with_its_query(target, expected):
    daemon = ToolDaemon()
    cid = daemon.add("naabu-x", dict(zip(broker.RUN_LABELS, RUN)), status="running")
    method = "DELETE" if target.startswith("{ref}?") else "GET" if "json" in target or "logs" in target else "POST"
    out = _send(daemon, method, f"{V}/containers/" + target.format(ref="naabu-x"))
    assert status_of(out) != 403, out[:300]
    [sent] = [r for r in daemon.received if r["path"].startswith(f"{V}/containers/")]
    assert sent["path"] == f"{V}/containers/" + expected.format(id=cid)
    assert sent["query"] == target.partition("?")[2]


def test_a_stop_is_forwarded_on_the_full_id_with_its_bounded_timeout():
    daemon = ToolDaemon(stop_hold=0.05)
    cid = daemon.add("naabu-x", dict(zip(broker.RUN_LABELS, RUN)), status="running")
    _send(daemon, "POST", f"{V}/containers/naabu-x/stop?t=-1")
    [sent] = [r for r in daemon.received if r["path"].endswith("/stop")]
    assert sent["path"] == f"{V}/containers/{cid}/stop" and sent["query"] == f"t={broker.STOP_TIMEOUT_MAX}"


@pytest.mark.parametrize("given", ["naabu-x", "abc", "", None])
def test_a_daemon_answer_without_a_full_id_is_refused(given):
    class NoFullId(ToolDaemon):
        async def _answer(self, reader, writer, method, path, query, body):
            if method == "GET" and path.endswith("/json") and "/containers/" in path and "/containers/json" not in path:
                doc = {"Config": {"Labels": {broker._OWNER_LABEL: "1", **dict(zip(broker.RUN_LABELS, RUN))}},
                       "State": {"Status": "running"}}
                if given is not None:
                    doc["Id"] = given
                return self._send(writer, 200, doc)
            return await super()._answer(reader, writer, method, path, query, body)
    daemon = NoFullId()
    out = _send(daemon, "POST", f"{V}/containers/naabu-x/kill")
    assert status_of(out) == 403, out[:300]
    assert not daemon.got("POST", f"{V}/containers/naabu-x/kill")

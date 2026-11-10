#!/usr/bin/env python3
"""E1 — broker operate-on-existing ownership gating.

Runs the broker against a MOCK upstream that answers GET /containers/<id>/json
with a marker label iff the id contains "owned", and asserts:
  * create injects the broker-owned marker label,
  * exec/attach/kill/archive on an UNLABELLED container -> 403, not forwarded,
  * kill/start on a LABELLED container -> forwarded (exec stays refused: no
    tool uses it, so it is off the D4 allowlist),
  * GET /containers/json is rewritten to force the ownership label filter.

Run: cd docker_broker && python3 test_ownership.py
"""
import asyncio
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402

TMP = tempfile.mkdtemp(prefix="broker-own-")
MOCK_SOCK = os.path.join(TMP, "upstream.sock")
BROKER_SOCK = os.path.join(TMP, "broker.sock")

received = []
PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {desc}")
    else:
        FAIL += 1; print(f"  FAIL {desc}")


async def mock_upstream(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout=2)
    except asyncio.TimeoutError:
        data = b""
    received.append(data)
    line = data.split(b"\r\n", 1)[0].decode("latin1") if data else ""
    m = re.match(r"GET /(?:v[\d.]+/)?containers/([^/]+)/json", line)
    if m:
        cid = m.group(1)
        labels = {"redamon.broker-owned": "1"} if "owned" in cid else {"role": "infra"}
        body = json.dumps({"Config": {"Labels": labels}}).encode()
    else:
        body = b'{"Id":"deadbeef"}'
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                 b"Connection: close\r\n\r\n" + body)
    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()


def make_request(method, path, body_obj=None):
    body = b"" if body_obj is None else json.dumps(body_obj).encode()
    head = (f"{method} {path} HTTP/1.1\r\n"
            f"Host: docker\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode()
    return head + body


async def send(raw):
    r, w = await asyncio.open_unix_connection(BROKER_SOCK)
    w.write(raw)
    await w.drain()
    resp = b""
    try:
        while True:
            chunk = await asyncio.wait_for(r.read(4096), timeout=2)
            if not chunk:
                break
            resp += chunk
    except asyncio.TimeoutError:
        pass
    w.close()
    return resp


def _forwarded_op(verb_substr):
    """Was an operate request (POST/GET/PUT containing verb_substr in the target)
    forwarded to upstream? Ignores the ownership-inspect GET .../json."""
    for r in received:
        line = r.split(b"\r\n", 1)[0]
        if verb_substr.encode() in line and b"/json" not in line:
            return True
    return False


async def main():
    broker.UPSTREAM_SOCK = MOCK_SOCK

    up = await asyncio.start_unix_server(mock_upstream, path=MOCK_SOCK)
    br = await asyncio.start_unix_server(broker.handle_client, path=BROKER_SOCK)

    async with up, br:
        # test_create_injects_owner_label
        received.clear()
        await send(make_request("POST", "/v1.43/containers/create",
                                {"Image": "projectdiscovery/naabu:latest"}))
        check("create injects redamon.broker-owned label",
              len(received) == 1 and b"redamon.broker-owned" in received[0])

        # test_exec_denied_on_unlabelled
        received.clear()
        resp = await send(make_request("POST", "/v1.43/containers/redamon-recon-orchestrator/exec",
                                       {"Cmd": ["sh"]}))
        check("exec on unlabelled infra -> 403", b"403" in resp)
        check("exec on unlabelled infra -> NOT forwarded", not _forwarded_op("/exec"))

        # D4: no tool runs `docker exec`, so it is off the allowlist even on a
        # broker-owned container; start, the verb `docker run` uses, is forwarded.
        received.clear()
        resp = await send(make_request("POST", "/v1.43/containers/owned-scan-123/exec",
                                       {"Cmd": ["sh"]}))
        check("exec on labelled -> 403 (not on the allowlist)", b"403" in resp and not _forwarded_op("/exec"))
        received.clear()
        resp = await send(make_request("POST", "/v1.43/containers/owned-scan-123/start"))
        check("start on labelled -> forwarded", _forwarded_op("/start"))

        # attach (hijack) on unlabelled -> denied
        received.clear()
        resp = await send(make_request("POST", "/v1.43/containers/redamon-docker-broker/attach"))
        check("attach on unlabelled infra -> 403", b"403" in resp)
        check("attach on unlabelled infra -> NOT forwarded", not _forwarded_op("/attach"))

        # kill on unlabelled -> denied; on labelled -> forwarded
        received.clear()
        resp = await send(make_request("POST", "/v1.43/containers/redamon-postgres/kill"))
        check("kill on unlabelled infra -> 403", b"403" in resp)
        received.clear()
        resp = await send(make_request("POST", "/v1.43/containers/owned-scan-9/kill"))
        check("kill on labelled -> forwarded", _forwarded_op("/kill"))

        # archive read on unlabelled -> denied
        received.clear()
        resp = await send(make_request("GET", "/v1.43/containers/redamon-agent/archive?path=/etc"))
        check("archive on unlabelled infra -> 403", b"403" in resp)

        # test_list_scoped_to_owned
        received.clear()
        await send(make_request("GET", "/v1.43/containers/json?all=1"))
        check("list forwarded with ownership label filter",
              len(received) == 1 and b"redamon.broker-owned%3D1" in received[0] or
              (len(received) == 1 and b"redamon.broker-owned=1" in received[0]))

    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    for s in (MOCK_SOCK, BROKER_SOCK):
        try:
            os.unlink(s)
        except Exception:
            pass
    return 0 if FAIL == 0 else 1


def test_main_all_checks_pass():
    """pytest entrypoint: main() returns non-zero if any check failed."""
    import asyncio
    assert asyncio.run(main()) == 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

#!/usr/bin/env python3
"""A half-closed attach stream must survive a garbage-collection pass.

`docker run` half-closes its attach connection right after the 101 and before the
container starts. Nothing in the event loop held the broker's handler for that
stream, so a cyclic GC pass destroyed it mid-stream: the attach socket closed, the
tool's stdout/stderr never reached the client, and `docker run` still exited 0.
Under concurrent scans katana and hakrawler reported 0 URLs as a genuine empty crawl.

The mock upstream answers the attach with the 101, then holds the "container
output" until the test has half-closed and forced a GC; with the handler gone the
output has nowhere to go.

Run: cd services/docker_broker && python3 test_hijack_gc.py
"""
import asyncio
import gc
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402

CID = "c0ffee"
OUTPUT = b"https://app.example.test/admin\nhttps://app.example.test/api/v1/users\n"


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(1)
        if not chunk:
            break
        head += chunk
    return head


async def _attach_through_broker(tmp: str) -> tuple:
    """One attach exchange: (101 head, relayed output, loop errors, handlers left)."""
    upstream_sock = os.path.join(tmp, "upstream.sock")
    broker_sock = os.path.join(tmp, "broker.sock")
    release = asyncio.Event()
    errors = []
    asyncio.get_running_loop().set_exception_handler(
        lambda _loop, ctx: errors.append(ctx.get("message", "")))

    async def upstream(reader, writer):
        head = await _read_head(reader)
        line = head.split(b"\r\n", 1)[0].decode("latin1")
        if line.startswith("GET ") and f"/containers/{CID}/json" in line:
            body = json.dumps({"Id": CID.ljust(64, "0"), "Config": {"Labels": {broker._OWNER_LABEL: "1"}},
                               "State": {"Status": "created"}}).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                         b"Connection: close\r\n\r\n" + body)
        elif "/attach" in line:
            writer.write(b"HTTP/1.1 101 UPGRADED\r\n"
                         b"Content-Type: application/vnd.docker.raw-stream\r\n"
                         b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
            await writer.drain()
            await release.wait()
            writer.write(OUTPUT)
        await writer.drain()
        writer.close()

    broker.UPSTREAM_SOCK = upstream_sock
    up = await asyncio.start_unix_server(upstream, path=upstream_sock)
    br = await asyncio.start_unix_server(broker.handle_client, path=broker_sock)
    async with up, br:
        reader, writer = await asyncio.open_unix_connection(broker_sock)
        writer.write(f"POST /v1.43/containers/{CID}/attach?stream=1&stdout=1&stderr=1 HTTP/1.1\r\n"
                     f"Host: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(_read_head(reader), 5)
        writer.write_eof()  # what `docker run` does once the 101 is in
        for _ in range(5):  # let the broker read the EOF, then sweep reference cycles
            await asyncio.sleep(0.05)
            gc.collect()
        release.set()
        output = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), 5)
                if not chunk:
                    break
                output += chunk
        except asyncio.TimeoutError:
            pass
        writer.close()
        await asyncio.sleep(0.1)
        left = len(getattr(broker, "_IN_FLIGHT", ()))
    return head, output, errors, left


def _run() -> tuple:
    with tempfile.TemporaryDirectory(prefix="broker-gc-") as tmp:
        return asyncio.run(_attach_through_broker(tmp))


def test_attach_output_survives_a_gc_pass_after_the_client_half_closes():
    head, output, errors, _ = _run()
    assert b"101" in head.split(b"\r\n", 1)[0]
    assert output == OUTPUT, f"the container output was lost: got {output!r}"
    assert not [e for e in errors if "destroyed" in e.lower()], errors


def test_a_finished_handler_is_not_kept_alive():
    """The anchor set is per request, not a leak: it is empty once the stream ends."""
    *_, left = _run()
    assert left == 0


if __name__ == "__main__":
    test_attach_output_survives_a_gc_pass_after_the_client_half_closes()
    test_a_finished_handler_is_not_kept_alive()
    print("OK")

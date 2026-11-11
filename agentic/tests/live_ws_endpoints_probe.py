#!/usr/bin/env python3
"""LIVE probe (S3/S4, HD-25): the terminal + cypherfix WS endpoints reject an
unticketed / bad-origin connection and a ticket minted for another socket, and
accept a valid ticket for their own socket.

Runs INSIDE the agent container against ws://localhost:8080. Mints a valid
ticket locally using AGENT_WS_TICKET_SECRET (same HS256 format the webapp uses).

  docker compose exec -T agent python3 tests/live_ws_endpoints_probe.py
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time

import websockets

SECRET = os.environ.get("AGENT_WS_TICKET_SECRET", "")
BASE = "ws://localhost:8080"
ENDPOINTS = ["/ws/kali-terminal", "/ws/cypherfix-triage", "/ws/cypherfix-codefix"]

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {desc}")
    else:
        FAIL += 1; print(f"  FAIL {desc}")


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint(aud, sub="u1", pid="p1", sid="s1", ttl=60):
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": sub, "pid": pid, "sid": sid, "aud": aud,
                               "iat": int(time.time()), "exp": int(time.time()) + ttl}).encode())
    sig = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


async def _connect_state(uri, origin=None):
    """Return 'rejected' if the handshake/connection is closed 1008, else 'accepted'."""
    kwargs = {}
    if origin is not None:
        # websockets version-agnostic origin header
        kwargs["additional_headers"] = {"Origin": origin}
    try:
        async with websockets.connect(uri, open_timeout=5, **kwargs) as ws:
            # Accepted the handshake. See if it closes us out immediately (post-accept 1008).
            try:
                await asyncio.wait_for(ws.recv(), timeout=1.5)
            except asyncio.TimeoutError:
                return "accepted"   # open, waiting for our frame (cypherfix) or bridging (terminal)
            except websockets.ConnectionClosed as e:
                return "rejected" if e.code == 1008 else "accepted"
            return "accepted"
    except TypeError:
        # older websockets: retry with extra_headers kwarg name
        kwargs2 = {"extra_headers": {"Origin": origin}} if origin is not None else {}
        try:
            async with websockets.connect(uri, open_timeout=5, **kwargs2) as ws:
                try:
                    await asyncio.wait_for(ws.recv(), timeout=1.5)
                except asyncio.TimeoutError:
                    return "accepted"
                except websockets.ConnectionClosed as e:
                    return "rejected" if e.code == 1008 else "accepted"
                return "accepted"
        except Exception:
            return "rejected"
    except Exception:
        return "rejected"


async def main():
    if not SECRET:
        print("SKIP: AGENT_WS_TICKET_SECRET not set in this container")
        return 0

    for ep in ENDPOINTS:
        ticket = mint(ep.rsplit("/", 1)[1])
        # 1. no ticket -> rejected
        st = await _connect_state(f"{BASE}{ep}")
        check(f"{ep}: no ticket -> rejected", st == "rejected")
        # 1b. a chat ticket (any project member can mint one) -> rejected
        st = await _connect_state(f"{BASE}{ep}?ticket={mint('agent')}", origin="http://localhost:8080")
        check(f"{ep}: another socket's ticket -> rejected", st == "rejected")
        # 2. valid ticket, same-origin (localhost) -> accepted
        st = await _connect_state(f"{BASE}{ep}?ticket={ticket}", origin="http://localhost:8080")
        check(f"{ep}: valid ticket -> accepted", st == "accepted")
        # 3. valid ticket but cross-site Origin -> rejected
        st = await _connect_state(f"{BASE}{ep}?ticket={ticket}", origin="http://evil.example.com")
        check(f"{ep}: cross-site Origin -> rejected", st == "rejected")

    print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

"""Agent-container half of tests/rbac_approval_cap_live.sh (RBAC step 3.9b). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after the assignments the shell
prepends: T_AGENT (an `agent` ticket the webapp minted for member A on its project PA, right
before), MEMBER_ID, PROJECT_ID and SESSION_ID (that member, PA and PA's seeded conversation).
It also signs tickets of its own, with the agent's AGENT_WS_TICKET_SECRET read from this
container's environment, for the same member with a chosen `cap`, and checks on /ws/agent that:

- a person holding only `agent:fireteam` (a Recon operator's cap) is refused a phase approval
  (`agent:approve_phase`), a dangerous-tool confirmation and a Fireteam member confirmation
  (`agent:approve_dangerous`), each with an error frame coded `permission_required`;
- a person holding only `agent:approve_dangerous` is refused a Fireteam member confirmation
  (`agent:fireteam`);
- the webapp's ticket (Default member: all four) is not refused, and its Fireteam answer is saved
  in the seeded conversation (the shell reads the saved row's actor).

No refused frame starts a run; the Fireteam answer of the webapp's ticket names a wave no run
holds, so it decides nothing. Prints PASS/FAIL lines and `RESULT_WS <pass> <fail>`; never a
ticket or a key.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import time

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

AGENT_WS = "ws://localhost:8080/ws/agent"
PASS = 0
FAIL = 0
FT = {"wave_id": "rbac-live-39b-wave", "member_id": "rbac-live-39b-member", "decision": "approve"}


def check(name, ok, why=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS  {name}", flush=True)
    else:
        FAIL += 1
        print(f"FAIL  {name}  {why}", flush=True)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign(cap):
    """An `agent` ticket for the member, signed as the webapp signs one, with `cap`."""
    now = int(time.time())
    claims = {"sub": MEMBER_ID, "pid": PROJECT_ID, "sid": SESSION_ID, "aud": "agent",  # noqa: F821
              "iat": now, "exp": now + 60, "cap": cap}
    head = _b64url(json.dumps({"alg": "HS256"}).encode())
    body = _b64url(json.dumps(claims).encode())
    key = os.environ.get("AGENT_WS_TICKET_SECRET", "").encode()
    sig = hmac.new(key, f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


async def answer(ticket, frame_type, payload):
    """Open /ws/agent with `ticket`, send one frame, then a ping; return the error frames seen before the pong."""
    async with websockets.connect(AGENT_WS, open_timeout=15) as ws:
        await ws.send(json.dumps({"type": "init", "payload": {
            "user_id": "ignored", "project_id": "ignored", "session_id": "ignored", "ticket": ticket}}))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 15
        connected = False
        while not connected and loop.time() < deadline:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
            if msg.get("type") == "error":
                raise RuntimeError(f"init refused: {msg['payload'].get('code')}")
            connected = msg.get("type") == "connected"
        await ws.send(json.dumps({"type": frame_type, "payload": payload}))
        await ws.send(json.dumps({"type": "ping", "payload": {}}))
        errors = []
        while loop.time() < deadline:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
            if msg.get("type") == "pong":
                return errors
            if msg.get("type") == "error":
                errors.append(msg.get("payload") or {})
        raise RuntimeError("no pong")


def refused_with(errors, permission):
    return any(e.get("code") == "permission_required" and e.get("permission") == permission
               and e.get("recoverable") is True for e in errors)


def codes(errors):
    return ",".join(f"{e.get('code')}:{e.get('permission', '')}" for e in errors) or "none"


async def main():
    recon_operator = sign(["agent:fireteam"])
    for frame_type, payload, permission in (
            ("approval", {"decision": "approve"}, "agent:approve_phase"),
            ("tool_confirmation", {"decision": "approve"}, "agent:approve_dangerous"),
            ("fireteam_member_confirmation", FT, "agent:approve_dangerous")):
        errors = await answer(recon_operator, frame_type, payload)
        check(f"cap [agent:fireteam]: {frame_type} refused naming {permission} -> {codes(errors)}",
              refused_with(errors, permission))

    errors = await answer(sign(["agent:approve_dangerous"]), "fireteam_member_confirmation", FT)
    check(f"cap [agent:approve_dangerous]: Fireteam confirmation refused naming agent:fireteam -> {codes(errors)}",
          refused_with(errors, "agent:fireteam"))

    errors = await answer(sign([]), "approval", {"decision": "abort"})
    check(f"cap []: approval refused -> {codes(errors)}", refused_with(errors, "agent:approve_phase"))

    errors = await answer(T_AGENT, "fireteam_member_confirmation", FT)  # noqa: F821
    check(f"the webapp's ticket (all four): Fireteam confirmation not refused -> {codes(errors)}",
          not any(e.get("code") == "permission_required" for e in errors))


try:
    asyncio.run(main())
except (InvalidStatus, ConnectionClosed, OSError, RuntimeError, asyncio.TimeoutError) as e:
    check("the agent-side checks ran to the end", False, type(e).__name__)
print(f"RESULT_WS {PASS} {FAIL}", flush=True)

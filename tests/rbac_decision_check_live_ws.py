"""Agent-container half of tests/rbac_decision_check_live.sh (RBAC step 5.4). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after the assignments the shell
prepends: OWNER_ID (member A), STRANGER_ID (member B, who has no access to A's project),
PROJECT_ID (A's project PA) and SESSION_ID (PA's seeded conversation). It signs `agent`
tickets with the agent's AGENT_WS_TICKET_SECRET, each holding all four agent permissions in
`cap`, so only the decision-time check can refuse, and checks on /ws/agent that:

- B's ticket (a socket whose access is gone: its cap still says yes) is refused a phase
  approval, a dangerous-tool confirmation, a Fireteam member confirmation and an answer to a
  question, each with `permission_required`, `reason: project_not_visible` and its `answer`;
- A's ticket (the owner) is not refused a Fireteam member confirmation (it names a wave no run
  holds, so it decides nothing).

No frame starts a run. Prints PASS/FAIL lines and `RESULT_WS <pass> <fail>`; never a ticket or
a key.
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
CAP_ALL = ["agent:approve_phase", "agent:approve_dangerous", "agent:fireteam", "agent:kali_exec"]
FT = {"wave_id": "rbac-live-54-wave", "member_id": "rbac-live-54-member", "decision": "approve"}
PASS = 0
FAIL = 0


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


def sign(sub):
    now = int(time.time())
    claims = {"sub": sub, "ten": OWNER_ID, "pid": PROJECT_ID, "sid": SESSION_ID, "aud": "agent",  # noqa: F821
              "iat": now, "exp": now + 60, "cap": CAP_ALL}
    head = _b64url(json.dumps({"alg": "HS256"}).encode())
    body = _b64url(json.dumps(claims).encode())
    key = os.environ.get("AGENT_WS_TICKET_SECRET", "").encode()
    sig = hmac.new(key, f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


async def answer(ticket, frame_type, payload):
    """Open /ws/agent, send one frame then a ping; return the error frames seen before the pong."""
    async with websockets.connect(AGENT_WS, open_timeout=15) as ws:
        await ws.send(json.dumps({"type": "init", "payload": {
            "user_id": "ignored", "project_id": "ignored", "session_id": "ignored", "ticket": ticket}}))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 20
        connected = False
        while not connected and loop.time() < deadline:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
            if msg.get("type") == "error":
                raise RuntimeError(f"init refused: {msg['payload'].get('code')}")
            connected = msg.get("type") == "connected"
        await ws.send(json.dumps({"type": frame_type, "payload": payload}))
        await ws.send(json.dumps({"type": "ping", "payload": {}}))
        errors = []
        while loop.time() < deadline:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
            if msg.get("type") == "pong":
                return errors
            if msg.get("type") == "error":
                errors.append(msg.get("payload") or {})
        raise RuntimeError("no pong")


def codes(errors):
    return ",".join(f"{e.get('code')}:{e.get('permission', '')}:{e.get('reason', '')}" for e in errors) or "none"


async def main():
    stranger = sign(STRANGER_ID)  # noqa: F821
    for frame_type, payload, permission, answer_kind in (
            ("approval", {"decision": "approve"}, "agent:approve_phase", "approval"),
            ("tool_confirmation", {"decision": "approve"}, "agent:approve_dangerous", "tool_confirmation"),
            ("fireteam_member_confirmation", FT, "agent:fireteam", "fireteam_member_confirmation"),
            ("answer", {"answer": "443"}, "agent:chat", "question")):
        errors = await answer(stranger, frame_type, payload)
        ok = any(e.get("code") == "permission_required" and e.get("permission") == permission
                 and e.get("reason") == "project_not_visible" and e.get("answer") == answer_kind
                 and e.get("recoverable") is True for e in errors)
        check(f"a cap that still says yes, access gone: {frame_type} refused at decision time -> {codes(errors)}", ok)

    errors = await answer(sign(OWNER_ID), "fireteam_member_confirmation", FT)  # noqa: F821
    check(f"the owner's Fireteam confirmation is not refused -> {codes(errors)}",
          not any(e.get("code") in ("permission_required", "decision_check_unavailable") for e in errors))


try:
    asyncio.run(main())
except (InvalidStatus, ConnectionClosed, OSError, RuntimeError, asyncio.TimeoutError) as e:
    check("the agent-side checks ran to the end", False, type(e).__name__)
print(f"RESULT_WS {PASS} {FAIL}", flush=True)

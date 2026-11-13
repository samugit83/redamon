"""WebSocket half of tests/rbac_ticket_tenant_live.sh (RBAC step 5.3). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after the assignments the shell
prepends: OWNER_ID, OWNER_PID (a project the owner owns), COLLAB_ID (another fixture account)
and SESSION_ID. It signs its own tickets with the agent's AGENT_WS_TICKET_SECRET, read from
the container's environment: a collaborator cannot mint an agent ticket from the webapp until
step 5.6 opens Use AI agent, and the split under test is the agent's. Reaches the agent on
localhost:8080. Prints PASS/FAIL lines and `RESULT_WS <pass> <fail>`; never a ticket, a key or
terminal output.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

AGENT_WS = "ws://localhost:8080"
AGENT_HTTP = "http://localhost:8080"
KEY = os.environ.get("INTERNAL_API_KEY", "")
PASS = 0
FAIL = 0


def check(name, ok, why=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}  {why}")


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def ticket(aud, sub, **claims):
    payload = {"sub": sub, "pid": OWNER_PID, "sid": SESSION_ID, "aud": aud,  # noqa: F821
               "iat": int(time.time()), "exp": int(time.time()) + 60, **claims}
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    sig = hmac.new(os.environ["AGENT_WS_TICKET_SECRET"].encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


def post(path, body):
    req = urllib.request.Request(f"{AGENT_HTTP}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "x-internal-key": KEY})
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, None


def close_code(exc):
    rcvd = getattr(exc, "rcvd", None)
    return rcvd.code if rcvd is not None else None


async def agent_init(tk):
    """Open /ws/agent, send init; (socket, first frame) - the caller closes the socket."""
    ws = await websockets.connect(f"{AGENT_WS}/ws/agent", open_timeout=10)
    await ws.send(json.dumps({"type": "init", "payload": {"user_id": "spoof", "project_id": "spoof",
                                                          "session_id": "spoof", "ticket": tk}}))
    frame = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
    return ws, frame


async def closed_with(ws, seconds=10):
    try:
        while True:
            await asyncio.wait_for(ws.recv(), timeout=seconds)
    except ConnectionClosed as e:
        return close_code(e)
    except asyncio.TimeoutError:
        return "still open"


async def main():
    owner, collab = OWNER_ID, COLLAB_ID  # noqa: F821

    # A malformed tenant never verifies.
    ws, frame = await agent_init(ticket("agent", collab, ten=""))
    check("an agent ticket with an empty ten is refused at init",
          frame.get("type") == "error" and (frame.get("payload") or {}).get("code") == "ws_ticket_invalid",
          str(frame.get("type")))
    await ws.close()

    # The collaborator's chat socket opens on the owner's project (the run would read its graph);
    # the owner's own socket on the same project stays open when the collaborator's access ends.
    c_ws, c_frame = await agent_init(ticket("agent", collab, ten=owner))
    o_ws, o_frame = await agent_init(ticket("agent", owner, ten=owner))
    check("a collaborator's agent ticket naming the owner as ten opens the chat socket",
          c_frame.get("type") == "connected", str(c_frame.get("type")))
    check("the owner's agent ticket opens too", o_frame.get("type") == "connected", str(o_frame.get("type")))
    status, body = post("/ws/close", {"user_id": collab, "project_id": OWNER_PID, "kinds": ["agent"]})  # noqa: F821
    check("POST /ws/close for the collaborator on the project closes one socket",
          status == 200 and (body or {}).get("closed") == 1, f"{status} {body}")
    check("the collaborator's socket is closed 4403", await closed_with(c_ws) == 4403)
    check("the owner's socket on the same project stays open", await closed_with(o_ws, 3) == "still open")
    await o_ws.close()

    # The session stop by project and session (purge-orphan-chains): an agent from before step 5.3
    # answers 422 to a body without user_id.
    status, body = post("/agent-session/stop", {"project_id": OWNER_PID, "session_id": SESSION_ID})  # noqa: F821
    check("POST /agent-session/stop without user_id is accepted", status == 200 and body == {"stopped": False},
          f"{status} {body}")

    # The collaborator's terminal: its shell runs as the project's tenant (redagraph and the traffic
    # tag name the owner); its socket is still the collaborator's.
    marker = f"RBACTEN={owner}:{OWNER_PID}:END".encode()  # noqa: F821
    out = b""
    try:
        async with websockets.connect(f"{AGENT_WS}/ws/kali-terminal?ticket={ticket('kali-terminal', collab, ten=owner)}",
                                      open_timeout=10) as ws:
            await ws.send("echo RBACTEN=$REDAMON_USER_ID:$REDAMON_PROJECT_ID:END\r")
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 20
            while marker not in out and loop.time() < deadline:
                try:
                    frame = await asyncio.wait_for(ws.recv(), timeout=2)
                except asyncio.TimeoutError:
                    continue
                out += frame if isinstance(frame, bytes) else frame.encode()
            check("the collaborator's terminal shell runs as the owner (the graph tenant)", marker in out,
                  "marker not seen")
            status, body = post("/ws/close", {"user_id": owner, "project_id": OWNER_PID, "kinds": ["kali-terminal"]})  # noqa: F821
            check("closing the owner's sockets leaves the collaborator's terminal open",
                  status == 200 and (body or {}).get("closed") == 0, f"{status} {body}")
            status, body = post("/ws/close", {"user_id": collab, "project_id": OWNER_PID, "kinds": ["kali-terminal"]})  # noqa: F821
            check("closing the collaborator's sockets closes their terminal",
                  status == 200 and (body or {}).get("closed") == 1, f"{status} {body}")
    except (InvalidStatus, ConnectionClosed, OSError) as e:
        check("the collaborator's terminal opens", False, type(e).__name__)

    print(f"RESULT_WS {PASS} {FAIL}")


asyncio.run(main())

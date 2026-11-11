"""WebSocket half of tests/rbac_legacy_review_live.sh (RBAC step 1.18). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after three assignments the
shell prepends: T_LEGACY (a legacy holder's terminal ticket, minted right before),
LEGACY_ID and LEGACY_PID (that holder and its project). It opens the holder's Kali
terminal, prints `OPEN` once the shell answers, and then waits for the socket to close
while the shell removes the grant through the admin review. Prints PASS/FAIL lines and
`RESULT_WS <pass> <fail>`; never a ticket or terminal output.
"""
import asyncio
import json
import sys

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

AGENT_WS = "ws://localhost:8080"
WAIT_FOR_CLOSE_S = 60
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


async def main():
    marker = f"RBACID={LEGACY_ID}:{LEGACY_PID}:END".encode()  # noqa: F821
    out = b""
    try:
        async with websockets.connect(f"{AGENT_WS}/ws/kali-terminal?ticket={T_LEGACY}", open_timeout=10) as ws:  # noqa: F821
            await ws.send(json.dumps({"type": "init"}))
            await ws.send("echo RBACID=$REDAMON_USER_ID:$REDAMON_PROJECT_ID:END\r")
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 20
            while marker not in out and loop.time() < deadline:
                try:
                    frame = await asyncio.wait_for(ws.recv(), timeout=2)
                except asyncio.TimeoutError:
                    continue
                out += frame if isinstance(frame, bytes) else frame.encode()
            check("the legacy holder's terminal is open", marker in out, "marker not seen")
            if marker not in out:
                return
            print("OPEN", flush=True)
            code = None
            try:
                while True:
                    await asyncio.wait_for(ws.recv(), timeout=WAIT_FOR_CLOSE_S)
            except ConnectionClosed as e:
                rcvd = getattr(e, "rcvd", None)
                code = rcvd.code if rcvd is not None else None
            except asyncio.TimeoutError:
                code = "still open"
            check("removing the grant closed the open terminal (4403)", code == 4403, str(code))
    except (InvalidStatus, ConnectionClosed, OSError) as e:
        check("the legacy holder's terminal opens", False, type(e).__name__)


try:
    asyncio.run(main())
finally:
    print(f"RESULT_WS {PASS} {FAIL}", flush=True)
    sys.stdout.flush()

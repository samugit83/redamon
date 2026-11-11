"""WebSocket half of tests/rbac_kali_terminal_live.sh (RBAC step 1.14). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after four assignments the
shell prepends: T_AGENT (a member's chat ticket), T_LEGACY (a legacy holder's
terminal ticket), LEGACY_ID and LEGACY_PID (that holder and its project). Tickets
live 60 s, so the shell mints them right before this runs. Reaches the agent on
localhost:8080 and the sandbox's terminal on KALI_TERMINAL_WS_URL. Prints PASS/FAIL
lines and `RESULT_WS <pass> <fail>`; never a ticket, a key or terminal output.
"""
import asyncio
import json
import os
import urllib.error
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

AGENT_WS = "ws://localhost:8080"
AGENT_HTTP = "http://localhost:8080"
KALI_WS = os.environ.get("KALI_TERMINAL_WS_URL", "ws://kali-sandbox:8016")
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


def close_code(exc):
    rcvd = getattr(exc, "rcvd", None)
    return rcvd.code if rcvd is not None else None


async def refused(url, headers=None):
    """('handshake', status) | ('closed', code) | ('open', None)."""
    try:
        async with websockets.connect(url, additional_headers=headers or {}, open_timeout=10) as ws:
            try:
                await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                return "open", None
            except ConnectionClosed as e:
                return "closed", close_code(e)
            return "open", None
    except InvalidStatus as e:
        return "handshake", e.response.status_code
    except ConnectionClosed as e:
        return "closed", close_code(e)


def ws_close(body, key):
    req = urllib.request.Request(f"{AGENT_HTTP}/ws/close", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"x-internal-key": key} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, None


async def main():
    # P0-07: a chat ticket, which any project member can mint, never opens the terminal.
    state = await refused(f"{AGENT_WS}/ws/kali-terminal?ticket={T_AGENT}")  # noqa: F821
    # Closed before accept: uvicorn answers the handshake 403.
    check("a member's chat ticket on /ws/kali-terminal is refused", state in (("handshake", 403), ("closed", 1008)), str(state))
    state = await refused(f"{AGENT_WS}/ws/cypherfix-triage?ticket={T_LEGACY}")  # noqa: F821
    check("a terminal ticket on /ws/cypherfix-triage is refused (1008)", state == ("closed", 1008), str(state))

    # NF-04: the sandbox's terminal admits only the agent's bearer.
    kali = f"{KALI_WS}/?user_id=rbac-probe&project_id=rbac-probe&session_id=rbac-probe"
    state = await refused(kali)
    check("raw upgrade to the sandbox terminal without a bearer -> 401", state == ("handshake", 401), str(state))
    state = await refused(kali, {"Authorization": "Bearer rbac-not-the-token"})
    check("raw upgrade with a wrong bearer -> 401", state == ("handshake", 401), str(state))

    # The legacy holder's terminal: identity from the proxy, not the spoofed init frame.
    marker = f"RBACID={LEGACY_ID}:{LEGACY_PID}:END".encode()  # noqa: F821
    out = b""
    try:
        async with websockets.connect(f"{AGENT_WS}/ws/kali-terminal?ticket={T_LEGACY}", open_timeout=10) as ws:  # noqa: F821
            await ws.send(json.dumps({"type": "init", "user_id": "rbac-spoof", "project_id": "rbac-spoof"}))
            await ws.send("echo RBACID=$REDAMON_USER_ID:$REDAMON_PROJECT_ID:END\r")
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 20
            while marker not in out and loop.time() < deadline:
                try:
                    frame = await asyncio.wait_for(ws.recv(), timeout=2)
                except asyncio.TimeoutError:
                    continue
                out += frame if isinstance(frame, bytes) else frame.encode()
            check("the legacy holder's terminal opens and its shell runs as the ticket's user and project",
                  marker in out, "marker not seen")
            check("the spoofed init frame's ids never reach the shell", b"RBACID=rbac-spoof" not in out)

            # DV-21: the agent closes it on demand (what a removed grant will do, step 1.18).
            status, _ = ws_close({"user_id": LEGACY_ID, "kinds": ["kali-terminal"]}, key=None)  # noqa: F821
            check("POST /ws/close without the master key -> 401", status == 401, str(status))
            status, body = ws_close({"user_id": LEGACY_ID, "kinds": ["kali-terminal"]},  # noqa: F821
                                    key=os.environ.get("INTERNAL_API_KEY", ""))
            check("POST /ws/close with the master key closes the holder's terminal",
                  status == 200 and (body or {}).get("by_kind", {}).get("kali-terminal", 0) >= 1, f"{status} {body}")
            code = None
            try:
                while True:
                    await asyncio.wait_for(ws.recv(), timeout=10)
            except ConnectionClosed as e:
                code = close_code(e)
            except asyncio.TimeoutError:
                code = "still open"
            check("the open terminal socket is closed 4403", code == 4403, str(code))
    except (InvalidStatus, ConnectionClosed, OSError) as e:
        check("the legacy holder's terminal opens", False, type(e).__name__)

    print(f"RESULT_WS {PASS} {FAIL}")


asyncio.run(main())

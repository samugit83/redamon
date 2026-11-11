"""Agent-container half of tests/rbac_run_credential_live.sh (RBAC step 1.15). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container (cwd /app, so the agent's
machine_credential imports), after three assignments the shell prepends: T_TERM (a
legacy holder's terminal ticket, minted right before), HOLDER_ID and HOLDER_PID
(that holder and its project). Prints PASS/FAIL lines and `RESULT_WS <pass> <fail>`;
never a ticket, a key, a credential or terminal output.
"""
import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

AGENT_WS = "ws://localhost:8080"
AGENT_HTTP = "http://localhost:8080"
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


def post(path, body, headers):
    req = urllib.request.Request(f"{AGENT_HTTP}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def code_of(body):
    detail = body.get("detail") if isinstance(body, dict) else None
    return (detail if isinstance(detail, dict) else body or {}).get("code", "")


def routes():
    """HD-21 / NF-01: the bare scanner key opens no in-sandbox route; a credential decides the tenant."""
    from machine_credential import mint_run_credential

    scanner = {"x-internal-key": os.environ.get("SCANNER_API_KEY", "")}
    master = {"x-internal-key": os.environ.get("INTERNAL_API_KEY", "")}
    graph_body = {"op": "types", "user_id": HOLDER_ID, "project_id": HOLDER_PID}  # noqa: F821
    for path, body in (("/graph/exec", graph_body),
                       ("/text-to-cypher", {"question": "rbac live probe", **graph_body}),
                       ("/traffic/exec", {"ctx": "rbac-live-probe", "op": "sitemap"})):
        status, _ = post(path, body, scanner)
        check(f"{path} refuses the bare scanner key -> {status}", status == 401)
        status, _ = post(path, body, {})
        check(f"{path} refuses no credential at all -> {status}", status == 401)

    status, _ = post("/graph/exec", graph_body, master)
    check(f"/graph/exec with the master key (the webapp's path) -> {status}", status == 200)

    cred = mint_run_credential("graph", HOLDER_ID, HOLDER_PID, "rbac-live-115", 600)  # noqa: F821
    status, _ = post("/graph/exec", {**graph_body, "user_id": "rbac-not-this-user"}, {"X-Redamon-Run": cred})
    check(f"/graph/exec with a graph run credential, body naming another user -> {status}", status == 200)

    expired = mint_run_credential("graph", HOLDER_ID, HOLDER_PID, "rbac-live-115", 60,  # noqa: F821
                                  now=time.time() - 3600)
    status, body = post("/graph/exec", graph_body, {"X-Redamon-Run": expired})
    check(f"an expired credential -> {status} {code_of(body)}", status == 401 and code_of(body) == "run_credential_expired")

    traffic = mint_run_credential("traffic", HOLDER_ID, HOLDER_PID, "rbac-live-115", 600)  # noqa: F821
    status, body = post("/graph/exec", graph_body, {"X-Redamon-Run": traffic})
    check(f"a traffic credential on /graph/exec -> {status} {code_of(body)}",
          status == 401 and code_of(body) == "run_credential_wrong_audience")


async def terminal():
    """HD-18 (E2E-P0-09, terminal half) and redagraph with the connection's credential."""
    probes = {
        "ENV": "env | grep -cE 'SCANNER_API_KEY|MCP_AUTH_TOKEN|TUNNEL_AUTH_TOKEN'",
        "SUFFIX": "env | cut -d= -f1 | grep -ciE '_(KEY|TOKEN|SECRET|PASSWORD)$'",
        "CRED": "env | grep -c '^REDAMON_RUN_CREDENTIAL='",
        "TYPES": "redagraph types >/dev/null 2>&1; echo $?",
        "LS": "redagraph ls Domain >/dev/null 2>&1; echo $?",
    }
    # $((1+1)) so the marker is printed only by the shell, never by the PTY echo of the line.
    line = "; ".join(f"echo RBAC$((1+1)){k}=$({cmd})" for k, cmd in probes.items()) + "\r"
    out = b""
    try:
        async with websockets.connect(f"{AGENT_WS}/ws/kali-terminal?ticket={T_TERM}", open_timeout=15) as ws:  # noqa: F821
            await ws.send(json.dumps({"type": "init"}))
            await ws.send(line)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 90
            while b"RBAC2LS=" not in out and loop.time() < deadline:
                try:
                    frame = await asyncio.wait_for(ws.recv(), timeout=2)
                except asyncio.TimeoutError:
                    continue
                out += frame if isinstance(frame, bytes) else frame.encode()
            await asyncio.sleep(1)
    except (InvalidStatus, ConnectionClosed, OSError) as e:
        check("the holder's terminal opens", False, type(e).__name__)
        return
    seen = dict(re.findall(rb"RBAC2([A-Z]+)=(\d+)", out))
    got = {k.decode(): v.decode() for k, v in seen.items()}
    check(f"terminal: no SCANNER_API_KEY / MCP_AUTH_TOKEN / TUNNEL_AUTH_TOKEN in env -> {got.get('ENV')}",
          got.get("ENV") == "0")
    check(f"terminal: no *_KEY/_TOKEN/_SECRET/_PASSWORD name in env -> {got.get('SUFFIX')}", got.get("SUFFIX") == "0")
    check(f"terminal: the shell holds its run credential -> {got.get('CRED')}", got.get("CRED") == "1")
    check(f"terminal: `redagraph types` answers -> exit {got.get('TYPES')}", got.get("TYPES") == "0")
    check(f"terminal: `redagraph ls Domain` answers -> exit {got.get('LS')}", got.get("LS") == "0")


routes()
asyncio.run(terminal())
print(f"RESULT_WS {PASS} {FAIL}")

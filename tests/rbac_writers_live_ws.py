"""Agent-container half of tests/rbac_writers_live.sh (step 5.11 follow-up). Not a pytest file.

Fed on stdin to `python3 -` inside the agent container, after the assignments the shell prepends:
OWNER_ID and OWNER_EMAIL (rbac-member-c, who owns the throwaway project), COLLAB_ID (rbac-member-b),
PROJECT_ID and OWNER_RUN_ID (the id of the owner's synthetic triage run). Only with sharing in force.

The collaborator's `agent` ticket is signed with the agent's AGENT_WS_TICKET_SECRET (`ten` = the
owner, `cap` holding every agent permission), as tests/rbac_decision_check_live_ws.py does: the
per-run check reads who is writing, not the person's access, so no share or consent is needed. It
checks on /ws/agent that:

- the collaborator's socket opens while nobody writes the project (CONNECTED);
- the owner then starts a writer (a live TriageRun row of the owner, written here through
  DATABASE_URL: a partial recon would need a target, and the scan source is the unit tests');
- the collaborator's next message, and a resume, are each refused with `project_writer_busy`, the
  frame naming the owner by email and the run's kind, and no run starts: no conversation row ever
  appears for the session (a started query's first save of the person's message creates it);
- the owner's own socket with a 201-character session id (signed here, as a mint without the bound
  would have signed it) is refused its message too, the writer check's 400 naming HTTP 400: an
  answer the request can provoke never lets even the owner's run through (the owner's only writer
  is their own, so the 400 alone refuses it), and nothing is saved for that session either.
The shell also checks the agent logged no run start for either session.

The owner's run row is left live for the shell's route checks; the shell's trap deletes it. Prints
PASS/FAIL lines and `RESULT_WS <pass> <fail>`; never a ticket or a key.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import time

import psycopg
import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

AGENT_WS = "ws://localhost:8080/ws/agent"
CAP_ALL = ["agent:approve_phase", "agent:approve_dangerous", "agent:fireteam", "agent:kali_exec"]
SESSION_ID = "rbac-writers-collab-session"
#: One character over the writer check's bound (webapp/src/lib/wsTicket.ts WS_SESSION_ID_MAX).
LONG_SESSION_ID = "rbac-writers-long-" + "s" * 183
#: How long a started run's first save would take to land at most (the agent's persistence timeout).
SAVE_WAIT_S = 6
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


def sign(sub, sid=SESSION_ID):
    now = int(time.time())
    claims = {"sub": sub, "ten": OWNER_ID, "pid": PROJECT_ID, "sid": sid, "aud": "agent",  # noqa: F821
              "iat": now, "exp": now + 120, "cap": CAP_ALL}
    head = _b64url(json.dumps({"alg": "HS256"}).encode())
    body = _b64url(json.dumps(claims).encode())
    key = os.environ.get("AGENT_WS_TICKET_SECRET", "").encode()
    sig = hmac.new(key, f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


def sql(statement, params=()):
    with psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=5) as conn:
        cur = conn.execute(statement, params)
        return cur.fetchall() if cur.description else None


async def recv_until(ws, kinds, deadline):
    """Frames until one of `kinds`; returns (that frame, the error payloads seen on the way)."""
    loop = asyncio.get_running_loop()
    errors = []
    while loop.time() < deadline:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=max(1, deadline - loop.time())))
        if msg.get("type") == "error":
            errors.append(msg.get("payload") or {})
        if msg.get("type") in kinds:
            return msg, errors
    raise RuntimeError(f"no {kinds} frame")


def busy_refusal(errors, start, *names):
    names = names or (OWNER_EMAIL, "a triage run")  # noqa: F821
    hit = [e for e in errors if e.get("code") == "project_writer_busy"]
    ok = bool(hit) and hit[0].get("recoverable") is True and "answer" not in hit[0] \
        and all(n in str(hit[0].get("busy")) for n in names)
    got = ",".join(str(e.get("code")) for e in errors) or "none"
    return ok, f"{start}: {got}"


def conversations(sid):
    return sql("SELECT count(*) FROM conversations WHERE session_id = %s", (sid,))[0][0]


async def never_saved(sid):
    """0 when no conversation row appeared for `sid` within SAVE_WAIT_S, else the count seen."""
    loop = asyncio.get_running_loop()
    until = loop.time() + SAVE_WAIT_S
    while loop.time() < until:
        seen = conversations(sid)
        if seen:
            return seen
        await asyncio.sleep(0.5)
    return 0


async def open_socket(sub, sid, deadline):
    ws = await websockets.connect(AGENT_WS, open_timeout=15)
    await ws.send(json.dumps({"type": "init", "payload": {
        "user_id": "ignored", "project_id": "ignored", "session_id": "ignored", "ticket": sign(sub, sid)}}))
    msg, errors = await recv_until(ws, ("connected", "error"), deadline)
    return ws, msg, errors


async def main():
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 90
    before = (conversations(SESSION_ID), conversations(LONG_SESSION_ID))
    if before != (0, 0):
        check("the sessions start with no conversation row", False, str(before))
        return
    ws, msg, errors = await open_socket(COLLAB_ID, SESSION_ID, deadline)  # noqa: F821
    async with ws:
        check("the collaborator's socket opens while nobody writes the project",
              msg.get("type") == "connected", ",".join(str(e.get("code")) for e in errors))
        if msg.get("type") != "connected":
            return

        sql("INSERT INTO triage_runs (id, project_id, actor_user_id, status, started_at, heartbeat_at) "
            "VALUES (%s, %s, %s, 'running', now(), now()) "
            "ON CONFLICT (id) DO UPDATE SET status = 'running', heartbeat_at = now(), finished_at = NULL",
            (OWNER_RUN_ID, PROJECT_ID, OWNER_ID))  # noqa: F821

        await ws.send(json.dumps({"type": "query", "payload": {"question": "list the hosts"}}))
        await ws.send(json.dumps({"type": "ping", "payload": {}}))
        _, errors = await recv_until(ws, ("pong",), deadline)
        ok, why = busy_refusal(errors, "query")
        check("the owner started a writer since: the collaborator's next message is refused, naming the owner", ok, why)

        await ws.send(json.dumps({"type": "stop", "payload": {}}))
        await recv_until(ws, ("stopped",), deadline)
        await ws.send(json.dumps({"type": "resume", "payload": {}}))
        await ws.send(json.dumps({"type": "ping", "payload": {}}))
        _, errors = await recv_until(ws, ("pong",), deadline)
        ok, why = busy_refusal(errors, "resume")
        check("a resume on the same socket is refused the same way", ok, why)

    seen = await never_saved(SESSION_ID)
    check("no run started: the collaborator's message was never saved (no conversation row for its session)",
          seen == 0, f"{seen} row(s)")

    ws, msg, errors = await open_socket(OWNER_ID, LONG_SESSION_ID, deadline)  # noqa: F821
    async with ws:
        if msg.get("type") != "connected":
            check("the owner's socket with a 201-character session id opens", False,
                  ",".join(str(e.get("code")) for e in errors))
            return
        await ws.send(json.dumps({"type": "query", "payload": {"question": "list the hosts"}}))
        await ws.send(json.dumps({"type": "ping", "payload": {}}))
        _, errors = await recv_until(ws, ("pong",), deadline)
        ok, why = busy_refusal(errors, "query", "the webapp answered HTTP 400")
        check("the owner's 201-character session id: the writer check's 400 refuses the owner's message too", ok, why)
    seen = await never_saved(LONG_SESSION_ID)
    check("and nothing was saved for that session", seen == 0, f"{seen} row(s)")


try:
    asyncio.run(main())
except (InvalidStatus, ConnectionClosed, OSError, RuntimeError, asyncio.TimeoutError, psycopg.Error) as e:
    check("the agent-side checks ran to the end", False, type(e).__name__)
print(f"RESULT_WS {PASS} {FAIL}", flush=True)

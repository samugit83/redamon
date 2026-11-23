"""
Live half of tests/ghsa_w454_msf_lease_live.sh (GHSA-w454-6hwp-fm58): run INSIDE one
person's Kali sandbox, fed on stdin. It starts a second Metasploit server from
$MSF_SERVER_DIR on loopback ports (18003 MCP, 18013 session manager) with its own real
msfconsole and a 20 s idle window, so the sandbox's own console is never touched, then
plays the advisory through the console instead of the routes.

A sandbox's console serves every project its person may use: their own and those shared
with them, which hold other tenants' data. So the two players are two projects of that
one person, as the agent stamps them:

  Project A opens a handler job and a real shell session on loopback; project B asks for
  `sessions -l`, `sessions -c "id" -i 1`, `irb`, `sessions -K`, `jobs -K` and
  msf_restart, and forges the session's chat link. Each must be refused and A's session
  must survive, while A still drives it. When A is done and idle, B gets a restarted
  console and A is the one refused.

Tokens and command output are never printed; each check prints PASS or FAIL. A server
whose tools take no `_redamon_owner` (the code before the fix) is called without one,
so pointing $MSF_SERVER_DIR at the old file shows the advisory reproduced (FAILs).
"""
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from fastmcp import Client
from fastmcp.client.transports import SSETransport

TOKEN = os.environ["MCP_AUTH_TOKEN"]
SERVER_DIR = os.environ.get("MSF_SERVER_DIR", "/opt/mcp_servers")
MCP_PORT, HTTP_PORT, LPORT = 18003, 18013, 4455
IDLE_S = 20
# One person (the sandbox's), two of their projects: the lease is per project.
PERSON = "w454-person"
PROJECT_A = {"project_id": "w454-project-a", "user_id": PERSON, "chat_session_id": "chat-a"}
PROJECT_B = {"project_id": "w454-project-b", "user_id": PERSON, "chat_session_id": "chat-b"}

LAUNCH = """
import os, sys
sys.path.insert(0, os.environ["MSF_SERVER_DIR"])
import metasploit_server as m
from _auth_middleware import serve_sse_with_auth
m.start_progress_server(int(os.environ["MSF_PROGRESS_PORT"]))
serve_sse_with_auth(m.mcp, host="127.0.0.1", port=int(os.environ["METASPLOIT_PORT"]))
"""

failures = []


def check(name, ok):
    print(f"{'PASS' if ok else 'FAIL'}  {name}", flush=True)
    if not ok:
        failures.append(name)


def http(method, path, body=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{HTTP_PORT}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def listing():
    return http("GET", "/sessions")[1]


def wait_for(pred, timeout, step=2.0):
    end = time.time() + timeout
    while time.time() < end:
        value = pred()
        if value:
            return value
        time.sleep(step)
    return None


class Console:
    def __init__(self, client, owner_param):
        self.client = client
        self.owner_param = owner_param

    async def call(self, tool, owner, **args):
        if self.owner_param and owner is not None:
            args["_redamon_owner"] = json.dumps(owner)
        res = await self.client.call_tool(tool, args, raise_on_error=False, timeout=600)
        return "".join(getattr(c, "text", "") for c in res.content)

    async def msf(self, owner, command):
        return await self.call("metasploit_console", owner, command=command)

    async def drive(self, owner, sid):
        """`id` in session `sid`. A generic shell's answer lands after the console's quiet
        period, at the head of the next call's output, so that call is read too."""
        first = await self.msf(owner, f'sessions -c "id" -i {sid}')
        return first, first + await self.msf(owner, "sessions -l")


def refused(text):
    return text.startswith("[REFUSED]")


async def scenario():
    transport = SSETransport(f"http://127.0.0.1:{MCP_PORT}/sse",
                             headers={"Authorization": f"Bearer {TOKEN}"})
    async with Client(transport, timeout=600) as client:
        tools = {t.name: t for t in await client.list_tools()}
        owner_param = "_redamon_owner" in tools["metasploit_console"].inputSchema.get("properties", {})
        print(f"INFO  server takes _redamon_owner: {owner_param}", flush=True)
        c = Console(client, owner_param)

        for command in ("use exploit/multi/handler", "set payload generic/shell_reverse_tcp",
                        "set LHOST 127.0.0.1", f"set LPORT {LPORT}", "set ExitOnSession false",
                        "exploit -j"):
            await c.msf(PROJECT_A, command)
        # `exploit -j` answers before msfconsole has bound the handler.
        check("project A's handler listens on loopback", bool(wait_for(lambda: _listening(LPORT), 60, 1.0)))
        shell = subprocess.Popen(["bash", "-c", f"bash -i >& /dev/tcp/127.0.0.1/{LPORT} 0>&1"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            data = wait_for(lambda: (lambda d: d if d.get("sessions") else None)(listing()), 90)
            sessions = (data or {}).get("sessions", [])
            sid = sessions[0]["id"] if sessions else 1
            check("project A's handler job and real shell session are live",
                  bool(sessions) and bool((data or {}).get("jobs")))
            if owner_param:
                # GET /sessions answers the session manager's cached rows, each carrying the chat link
                # as it stood at the cache's last refresh: the first listing that shows the session
                # may predate its link, which a later refresh adds.
                linked = wait_for(lambda: next((s.get("chat_session_id") for s in listing().get("sessions", [])
                                                if s.get("id") == sid and s.get("chat_session_id")), None), 30, 1.0)
                check(f"the console linked the new session to project A's chat -> {linked or 'no link within 30 s'}",
                      linked == "chat-a")

            check("project B: `sessions -l` refused", refused(await c.msf(PROJECT_B, "sessions -l")))
            first, both = await c.drive(PROJECT_B, sid)
            check("project B: `sessions -c id -i <A's>` refused, nothing ran",
                  refused(first) and "uid=" not in both)
            check("project B: `irb` over framework.sessions refused",
                  refused(await c.msf(PROJECT_B, 'irb -e "puts framework.sessions.keys.inspect"')))
            status, _ = http("POST", "/session-chat-map",
                             {"msf_session_id": sid, "chat_session_id": "chat-b"})
            check("project B's forged session link refused (409)", status == 409)
            if owner_param:
                check("a call naming no project refused",
                      "names no project" in await c.msf(None, "sessions -l"))

            check("project A still drives its own session", "uid=" in (await c.drive(PROJECT_A, sid))[1])

            check("project B: `sessions -K` refused", refused(await c.msf(PROJECT_B, "sessions -K")))
            check("project B: `jobs -K` refused", refused(await c.msf(PROJECT_B, "jobs -K")))
            check("project B: msf_restart refused", refused(await c.call("msf_restart", PROJECT_B)))
            time.sleep(5)
            alive = listing()
            check("project A's session and job survived project B",
                  any(s.get("id") == sid for s in alive.get("sessions", [])) and bool(alive.get("jobs")))

            if not owner_param:
                return
            await c.msf(PROJECT_A, "sessions -K")
            await c.msf(PROJECT_A, "jobs -K")
            empty = wait_for(lambda: (lambda d: d if not d.get("sessions") and not d.get("jobs") else None)(listing()), 60)
            check("project A ended its session and job", empty is not None)
            time.sleep(IDLE_S + 5)
            out = await c.msf(PROJECT_B, "sessions -l")
            check("project B takes the idle, empty console (restarted for it)",
                  not refused(out) and "No active sessions" in out)
            check("project A is now the one refused", refused(await c.msf(PROJECT_A, "sessions -l")))
        finally:
            os.killpg(shell.pid, signal.SIGKILL)


def main():
    env = dict(os.environ, MSF_SERVER_DIR=SERVER_DIR, MCP_TRANSPORT="sse",
               METASPLOIT_PORT=str(MCP_PORT), MSF_PROGRESS_PORT=str(HTTP_PORT),
               MSF_PROJECT_LEASE_IDLE_S=str(IDLE_S))
    log = open("/tmp/ghsa_w454_msf_server.log", "w")
    server = subprocess.Popen([sys.executable, "-c", LAUNCH], env=env, stdout=log,
                              stderr=subprocess.STDOUT, start_new_session=True)
    try:
        up = wait_for(lambda: http("GET", "/health")[0] == 200 if _port_open() else None, 60, 1.0)
        if not up:
            print("FAIL  the side Metasploit server did not start (see /tmp/ghsa_w454_msf_server.log)")
            return 1
        asyncio.run(scenario())
    finally:
        os.killpg(server.pid, signal.SIGKILL)
        log.close()
    print(f"{len(failures)} check(s) failed" if failures else "all checks passed", flush=True)
    return 1 if failures else 0


def _listening(port):
    """A LISTEN socket on `port`, read from /proc so that checking opens no connection
    (a probe connection would itself become a session)."""
    want = f":{port:04X}"
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table) as f:
                rows = f.read().splitlines()[1:]
        except OSError:
            continue
        if any(r.split()[1].endswith(want) and r.split()[3] == "0A" for r in rows):
            return True
    return False


def _port_open():
    import socket
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", HTTP_PORT)) == 0


if __name__ == "__main__":
    sys.exit(main())

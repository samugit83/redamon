#!/usr/bin/env python3
"""
Reverse-shell ports of per-user Kali sandboxes, end to end on the LIVE stack (follow-up FU,
section 4: E1-E9, E11, E12; E10 is the UI spec's group E). Entry point and lock:
tests/kali_reverse_ports_live.sh. Runs on the host, standard library only.

Every scenario asserts three things, each its own PASS/FAIL line:
  <E>.told       what the agent (its think prompt, read by the driver) or the MCP client was told
  <E>.published  what the sandbox publishes: `docker port`, its labels, MSF_REVERSE_PORT
  <E>.landed     where the shell, the callback or the command landed: whose sandbox, whose chat

The model is Agent in the Loop (`loop/mcp`): a driver thread answers each model step of a
chat over /api/mcp-server with the person's own driver token (agent:loop + recon:read, minted
here, revoked at the end), so every run is deterministic, and the driver reads the payload
settings block of the real think prompt and builds its handler from the LHOST/LPORT that block
gives (a run that used another port would not get its shell). The chat itself goes over the
agent socket with the person's ticket, as the drawer sends it; approvals and dangerous-tool
confirmations are answered "approve" there, by the person.

Phases (the orchestrator is recreated for each with KALI_SANDBOX_PORT_POOL and
KALI_SANDBOX_PORT_HOLD_HOURS set in this process only, every other input replayed, and put
back at the end; see Orchestrator in kali_reverse_ports_live_lib.py). The pool is bound on the
pentest network's gateway address, which the labs reach and the host owns:
  nopool   E11 (I6 plant), E4 (bind only), E2 (chisel, second person on the same server)
  pool     3 ports: E12 (MCP kali_exec), E1 (pool port as LPORT), E6 (two chats, and another
           project), E10a (a member stops her own job), E3 (pool and chisel), E7 (restart), E9 (act-as)
  pool1    1 port, hold 24 h: E5 (pool full), E8 (late callback after a stop, the hold)
  nohold   the same port, hold 0: E8c, the control (the freed port goes to the other person)
  cleanup  hold 0 over every port used: one start prunes every hold the run made

Synthetic data only: the g1 seed (g1-alice, g1-bob, g1-PA/PB/PS with `.invalid` targets), the
.env admin, guinea-pig labs (testing/guinea_pigs/apache_2.4.49's image, busybox) and a chisel
server from the Kali image, all labelled fu-p7-e2e=1 and removed at the end and at the next
start. What the run changes on the accounts (project fields, a 3-hour platform:tunnels grant,
the tunnel settings) is recorded in ${G1_STATE}.fu-p7-restore.json first and put back at the
end, or at the next start after a killed run.

  python3 tests/kali_reverse_ports_live.py                 every phase
  python3 tests/kali_reverse_ports_live.py --only E1,E7    those scenarios (and their phases)
  python3 tests/kali_reverse_ports_live.py --plan          what would run; touches nothing
  python3 tests/kali_reverse_ports_live.py --self-test     the offline parsers; touches nothing

Exit 0 when every check passed, 1 on any FAIL, 2 when the stack is not ready (no skip: this
is milestone evidence). Takes about 60-80 minutes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kali_reverse_ports_live_lib as L  # noqa: E402
from kali_reverse_ports_live_lib import AGAIN, Fatal, read_plan, seed  # noqa: E402

SCENARIOS = ("E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "E10a", "E11", "E12")
POOL_BASE = int(os.environ.get("FU_P7_POOL_BASE", "40190"))
LOOP_MODEL = "loop/mcp"
# The payload fields a scenario sets on a g1 project (recorded first, put back at the end).
PAYLOAD_FIELDS = ("agentOpenaiModel", "agentLhost", "agentLport", "agentBindPortOnTarget",
                  "agentChiselTunnelEnabled", "agentNgrokTunnelEnabled")

# Texts the run expects, with where they come from (kept here so a wording change is one edit).
MCP_PORT_SENTENCE = "Your reverse-shell port is $MSF_REVERSE_PORT inside the sandbox"   # webapp/src/lib/mcp/server.ts kali_exec
MOTD_PORT = "Your reverse-shell port (LPORT): {port}"                                   # mcp/kali-sandbox/redamon-motd.sh
MOTD_NONE = "No reverse-shell port is published for this sandbox"
RESTARTED = "[Kali sandbox restarted]"                                                  # agentic/sandbox_router.py new_instance_note
PORT_UNCHANGED = "Its reverse-shell port is unchanged: `{port}`."
BUSY_PORT = "[REDAMON] Port {port} is already in use in your Kali sandbox"              # mcp/servers/metasploit_server.py handler_busy_note
HELD_BY_PROJECT = "[REFUSED] Metasploit in your Kali sandbox is held by another of your projects"
ACT_AS_BANNER = "this run acts as another person"                                       # agentic/utils.py _tunnel_banner
CHISEL_IN_USE = "remote port 4444 in use on the chisel server"                          # mcp/servers/tunnel_manager.py _chisel_error


@dataclass
class Ctx:
    out: L.Out
    orch: L.Orchestrator
    restore: L.Restore
    people: dict
    admin: L.Person
    projects: dict
    gw: str
    nonce: str
    pool: list = field(default_factory=list)
    labs: list = field(default_factory=list)
    edge: Optional[L.ChiselEdge] = None
    chats: list = field(default_factory=list)   # (person key, session id)
    acting: bool = False
    # E1's chat, lab and session, which E6 and E10a build on.
    e1: dict = field(default_factory=dict)

    @property
    def alice(self) -> L.Person:
        return self.people["alice"]

    @property
    def bob(self) -> L.Person:
        return self.people["bob"]

    def https(self) -> dict:
        return {k: p.http for k, p in self.people.items()}


# ---- small steps ---------------------------------------------------------------------

def port_line(ctx: Ctx, person: L.Person, project_key: str, extra: str = "") -> dict:
    """MCP kali_exec in the person's own sandbox (starting it): MSF_REVERSE_PORT and the login
    message's port line, as the person's external client reads them."""
    cmd = ("echo FU-P7-PORT=$MSF_REVERSE_PORT; bash -lc true 2>/dev/null | sed 's/\\x1b\\[[0-9;]*m//g' "
           "| grep -i 'reverse-shell port' || true" + (f"; {extra}" if extra else ""))
    res = L.kali_exec(person.mcp_token, ctx.projects[project_key], cmd)
    m = re.search(r"FU-P7-PORT=(\d+)", res["output"])
    res["port"] = int(m.group(1)) if m else None
    return res


def own_box(person: L.Person, view: str = "own", timeout: float = 240) -> Optional[L.Box]:
    return L.wait_box(person.id, view, timeout)


def pool_ports(box: Optional[L.Box]) -> list[tuple[int, str, int]]:
    return L.published(box.name) if box else []


def reverse_port_state(http, view: str = "own") -> tuple[Optional[int], Optional[str]]:
    rows = [r for r in L.sandbox_status(http) if r.get("state") == "running"]
    row = rows[0] if rows else {}
    return row.get("reverse_port"), row.get("reverse_port_state")


def end_shells(ctx: Ctx, person: L.Person) -> None:
    """Stops every session and job the person's own list shows (D-D: their sandbox's jobs too)."""
    lst = L.sessions_of(person.http)
    for row in lst.get("sessions") or []:
        L.kill_row(person.http, "sessions", row)
    for row in lst.get("jobs") or []:
        L.kill_row(person.http, "jobs", row)


def set_fields(ctx: Ctx, person: L.Person, project_key: str, **fields) -> None:
    if not ctx.restore.set_project(person.http, person.key, ctx.projects[project_key], fields):
        raise Fatal(f"setting {', '.join(fields)} on {project_key} was refused")


def payload_fields(lhost="", lport=None, bind=None, chisel=False) -> dict:
    return {"agentOpenaiModel": LOOP_MODEL, "agentLhost": lhost, "agentLport": lport,
            "agentBindPortOnTarget": bind, "agentChiselTunnelEnabled": chisel, "agentNgrokTunnelEnabled": False}


def chat(ctx: Ctx, person: L.Person, project_key: str, label: str, question: str, moves: list,
         http=None, target: str = "lab") -> L.Chat:
    c = L.run_loop_chat(ctx.out, f"{label}", http or person.http, ctx.projects[project_key], question,
                        person.driver_token, moves, target=target)
    ctx.chats.append((person.key, c.session_id))
    for e in c.errors:
        ctx.out.info(f"{label}: {e}")
    return c


def session_of_chat(person: L.Person, session_id: str, timeout: float = 60) -> Optional[dict]:
    """The Metasploit session the person's list links to `session_id`, waited for (the console
    links a new session one refresh later, ~3 s)."""
    until = time.time() + timeout
    while time.time() < until:
        for row in L.sessions_of(person.http).get("sessions") or []:
            if row.get("chat_session_id") == session_id:
                return row
        time.sleep(3)
    return None


def all_sessions(person: L.Person) -> list[dict]:
    return list(L.sessions_of(person.http).get("sessions") or [])


def shell_answers(person: L.Person, row: dict, nonce: str) -> str:
    return L.interact(person.http, row, f"echo FU-SHELL-$((6*7))-{nonce}; hostname")


def local_end(row: dict) -> str:
    return str(row.get("connection") or "").split("->")[0].strip()


# Moves of a scripted chat (kali_reverse_ports_live_lib.run_loop_chat).

def m_exploitation():
    return lambda prompt, c: L.to_exploitation()


def m_plan(key: str = "plan", ready: Callable = lambda p: True):
    """Waits (with preparatory Kali steps) until the payload block says what to use, then keeps it."""
    def move(prompt, c):
        p = read_plan(prompt)
        if not p.found or p.mode in ("", "unknown") or not ready(p):
            c.facts[key + "_waits"] = c.facts.get(key + "_waits", 0) + 1
            return AGAIN
        c.facts[key] = p
        return None
    return move


def m_tool(thought: str, tool: str, args: Callable):
    return lambda prompt, c: L.use_tool(thought, tool, args(c))


def m_keep(key: str):
    def move(prompt, c):
        c.facts[key] = prompt
        return None
    return move


def m_hook(fn: Callable):
    def move(prompt, c):
        fn(prompt, c)
        return None
    return move


def handler_started(text: str, port: Optional[int]) -> bool:
    """Whether a handler command's own output says it started: its background job, or its
    listener on `port`. Only Metasploit prints these (no prompt text carries them), and the
    agent has nothing else to tell it the listener is up before it fires a payload."""
    return ("Payload handler running as background job" in text
            or (port is not None and re.search(rf"Started reverse TCP handler on \S+:{port}\b", text) is not None))


def handler_cmd(p: L.Plan, payload: str = "generic/shell_reverse_tcp") -> str:
    """The handler as the block's own commands say (a tunnel's bind address and port included)."""
    if p.bind_listen_4444:
        return (f"use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {p.lhost}; set LPORT {p.lport}; "
                "set ReverseListenerBindAddress 127.0.0.1; set ReverseListenerBindPort 4444; run -j")
    return f"handler -p {payload} -H {p.lhost} -P {p.lport}"


# ---- E11: the I6 plant ---------------------------------------------------------------

def e11(ctx: Ctx) -> None:
    a, pa = ctx.alice, ctx.projects["PA"]
    ids = {k: secrets.token_hex(16) for k in ("cmdline", "hostname", "fifo", "metalink")}
    plant = " && ".join([
        f"mkdir -p /workspace/{pa}/jobs", f"cd /workspace/{pa}/jobs",
        *[f"printf '{{\"job_id\":\"%s\",\"status\":\"done\",\"exit_code\":0}}' {i} > {i}.meta.json"
          for k, i in ids.items() if k != "metalink"],
        f"ln -sf /proc/self/cmdline {ids['cmdline']}.log", f"ln -sf /etc/hostname {ids['hostname']}.log",
        f"mkfifo {ids['fifo']}.log", f"ln -sf /proc/self/environ {ids['metalink']}.meta.json",
        f"echo plain > {ids['metalink']}.log", "ls -l | grep -c -- '->' ; echo FU-P7-PLANTED"])
    since = L.utc_now()
    try:
        res = L.kali_exec(a.mcp_token, pa, plant)
        planted = "FU-P7-PLANTED" in res["output"]
        ctx.out.check("E11.control", planted, "Alice planted three log links, a FIFO and a meta link in her own jobs/",
                      res["error"] or res["status"])
        agent_host = ((L.inspect(L.AGENT) or {}).get("Config") or {}).get("Hostname") or "<agent>"
        leaks, slow = [], []
        for kind, jid in ids.items():
            answer, err, took = L.kali_output_raw(a.mcp_token, pa, jid)
            text = json.dumps(answer) if answer else err
            if took > 30:
                slow.append(f"{kind} {took:.0f}s")
            if kind == "cmdline" and ("uvicorn" in text or "api:app" in text):
                leaks.append("the agent's /proc/self/cmdline")
            if kind == "hostname" and agent_host in text:
                leaks.append("the agent container's /etc/hostname")
            if kind == "metalink" and ("INTERNAL_API_KEY" in text or "PATH=" in text):
                leaks.append("the agent's environment through a meta link")
        ctx.out.check("E11.told", planted and not leaks and not slow,
                      "kali_output through each plant answers none of the agent's files and never hangs",
                      "; ".join(leaks + slow))
        # job_runner.note_refusal: "[jobs] refused '<name>' in project ...", on stdout or in /app/logs.
        names = [f"{ids[k]}.log" for k in ("cmdline", "hostname", "fifo")]
        log = L.logs_since(L.AGENT, since)
        _, files = L.sh_in(L.AGENT, "grep -rhsF -- '[jobs] refused' /app/logs 2>/dev/null | tail -n 200")
        refused = [nm for nm in names if f"refused '{nm}'" in log + files]
        ctx.out.check("E11.landed", planted and len(refused) == len(names),
                      "the agent refused each planted log in Alice's folder (job_runner.note_refusal) instead of "
                      "following it", f"refused {len(refused)} of {len(names)}")
    finally:
        L.kali_exec(a.mcp_token, pa, f"cd /workspace/{pa}/jobs && rm -f " + " ".join(f"{i}.log {i}.meta.json" for i in ids.values()))


# ---- E4: no pool, no tunnel: bind only -------------------------------------------------

def e4(ctx: Ctx) -> None:
    a, n = ctx.alice, ctx.nonce
    start = port_line(ctx, a, "PA")
    box = own_box(a)
    lab = L.bind_lab(n + "e4")
    ctx.labs.append(lab)
    lab_ip = lab.join(a.id)
    set_fields(ctx, a, "PA", **payload_fields(bind=L.LAB_SHELL_PORT))
    c = chat(ctx, a, "PA", "E4", f"FU-P7 E4 {n}: the lab at {lab_ip} (a local guinea pig, in scope) has a shell "
                                 f"bound on a port. Open a session on it.", [
        # A bind-only project is BIND before the sandbox is known; its "no pool" line shows once it is.
        m_exploitation(), m_plan(ready=lambda p: p.no_port != ""),
        m_tool("a bind handler as the block says", "metasploit_console",
               lambda c: {"command": f"handler -p generic/shell_bind_tcp -H {lab_ip} -P {c.facts['plan'].lport}"}),
        m_tool("list the sessions", "metasploit_console", lambda c: {"command": "sessions -l"}),
    ], target=lab_ip)
    p = c.facts.get("plan") or L.Plan()
    ctx.out.check("E4.told", p.mode == "bind" and p.lport == L.LAB_SHELL_PORT and p.no_port == "no_pool"
                  and "**Mode: REVERSE**" not in p.text and c.questions == 0,
                  "the block offers BIND only (port 5555), says no pool is configured, asks nothing",
                  f"mode={p.mode} lport={p.lport} no_port={p.no_port} questions={c.questions}")
    pub = pool_ports(box)
    ctx.out.check("E4.published", box is not None and pub == [] and start["port"] == L.DEFAULT_REVERSE_PORT
                  and (box.port_label in ("", None)),
                  "Alice's sandbox publishes nothing; MSF_REVERSE_PORT is 4444; no port label",
                  f"box={box and box.name} published={pub} env={start['port']} label={box and box.port_label}")
    row = session_of_chat(a, c.session_id)
    ans = shell_answers(a, row, n) if row else ""
    ctx.out.check("E4.landed", bool(row) and row.get("sandbox") == (box and box.instance)
                  and f"FU-SHELL-42-{n}" in ans and lab.hostname in ans,
                  "the bind session is in Alice's sandbox, linked to her chat, and answers from the lab",
                  f"row={row and {k: row.get(k) for k in ('id', 'sandbox', 'connection')}}")
    end_shells(ctx, a)
    lab.stop()


# ---- E2: chisel without a pool; a second person on the same server -------------------

def tunnel_on(ctx: Ctx, person: L.Person, url: str, timeout: float = 120, want: str = "on") -> dict:
    ctx.restore.record_tunnel(person)
    res = person.http.call("PUT", f"/api/users/{person.id}/settings", {"chiselServerUrl": url, "tunnelsEnabled": True})
    if not res.ok:
        raise Fatal(f"turning on {person.key}'s tunnel answered {res.status} {res.code}")
    until, st = time.time() + timeout, {}
    while time.time() < until:
        st = (L.tunnel_status(person.http).get("chisel") or {})
        if str(st.get("status") or "").startswith(want):
            break
        time.sleep(3)
    return st


def tunnel_off(person: L.Person) -> None:
    person.http.call("PUT", f"/api/users/{person.id}/settings", {"tunnelsEnabled": False, "chiselServerUrl": ""})


def chisel_chat(ctx: Ctx, person: L.Person, project_key: str, label: str, lab: L.Lab, lab_ip: str) -> L.Chat:
    n = ctx.nonce
    return chat(ctx, person, project_key, label,
                f"FU-P7 {label} {n}: the lab at http://{lab_ip}/ (Apache 2.4.49, a local guinea pig, in scope). "
                "Get a reverse shell on it.", [
        m_exploitation(), m_plan(ready=lambda p: p.chisel == "active"),
        m_tool("the handler as the tunnel block says", "metasploit_console",
               lambda c: {"command": handler_cmd(c.facts["plan"])}),
        m_tool("the lab's RCE dials LHOST:LPORT", "kali_shell",
               lambda c: {"command": L.rce_command(lab_ip, L.reverse_shell_body(
                   f"FU-RCE-{n}", c.facts["plan"].lhost, c.facts["plan"].lport))}),
        m_tool("list the sessions", "metasploit_console", lambda c: {"command": "sessions -l"}),
    ], target=lab_ip)


def ensure_edge(ctx: Ctx) -> L.ChiselEdge:
    if ctx.edge is None:
        ctx.edge = L.ChiselEdge(ctx.nonce)
    return ctx.edge


def grant_tunnels(ctx: Ctx, person: L.Person) -> None:
    admin_password = seed.env_value("UI_LOGIN_PASSWORD")
    if not ctx.restore.grant(ctx.admin.http, admin_password, person.id, "platform:tunnels"):
        raise Fatal(f"granting {person.key} platform:tunnels was refused")


def e2(ctx: Ctx) -> None:
    a, b, n = ctx.alice, ctx.bob, ctx.nonce
    for p in (a, b):
        grant_tunnels(ctx, p)
    port_line(ctx, a, "PA")
    box = own_box(a)
    edge = ensure_edge(ctx)
    lab = L.apache_lab(n + "e2")
    ctx.labs.append(lab)
    lab_ip = lab.join(a.id)
    url_a = edge.url_for(a.id)
    st = tunnel_on(ctx, a, url_a)
    set_fields(ctx, a, "PA", **payload_fields(chisel=True))
    c = chisel_chat(ctx, a, "PA", "E2", lab, lab_ip)
    p = c.facts.get("plan") or L.Plan()
    edge_host = url_a.split("//")[1].split(":")[0]
    ctx.out.check("E2.told", p.chisel == "active" and p.mode == "reverse" and p.lport == 4444 and p.lhost == edge_host
                  and p.bind_listen_4444 and c.questions == 0,
                  "the block shows Chisel ACTIVE: LHOST the server, LPORT 4444, the handler bound on 127.0.0.1:4444",
                  f"tunnel={st.get('status')} chisel={p.chisel} lhost={p.lhost} lport={p.lport} bind4444={p.bind_listen_4444}")
    _, chisel_out = L.sh_in(box.name, "pgrep -x chisel >/dev/null && echo yes || echo no") if box else (1, "no")
    ctx.out.check("E2.published", box is not None and pool_ports(box) == [] and "yes" in chisel_out,
                  "Alice's sandbox publishes nothing (no pool) and runs the chisel client itself",
                  f"published={pool_ports(box)} chisel={chisel_out.strip()}")
    row = session_of_chat(a, c.session_id)
    ans = shell_answers(a, row, n) if row else ""
    ctx.out.check("E2.landed", bool(row) and row.get("sandbox") == (box and box.instance)
                  and local_end(row).startswith("127.0.0.1:4444") and lab.hostname in ans,
                  "the shell arrived through the tunnel (127.0.0.1:4444) in Alice's sandbox, linked to her chat",
                  f"connection={row and row.get('connection')}")

    # Bob asks the same server for the same remote port: refused, and shown as failed.
    port_line(ctx, b, "PB")
    bbox = own_box(b)
    st_b = tunnel_on(ctx, b, edge.url_for(b.id), timeout=90, want="error")
    set_fields(ctx, b, "PB", **payload_fields(chisel=True))
    cb = chat(ctx, b, "PB", "E2-bob", f"FU-P7 E2-bob {n}: check how a reverse shell would reach you.", [
        m_exploitation(), m_plan(ready=lambda p: p.chisel not in ("", "unread", "connecting")),
    ])
    pb = cb.facts.get("plan") or L.Plan()
    status_b = str(st_b.get("status") or "")
    ctx.out.check("E2.told-second", status_b.startswith("error") and CHISEL_IN_USE in status_b and "host" not in st_b
                  and pb.chisel == "failed" and pb.mode != "reverse",
                  "Bob on the same chisel server: his tunnel status is an error (remote port 4444 in use), never ACTIVE, "
                  "and his agent's block says FAILED and offers no reverse payload through it",
                  f"status={status_b[:120]} chisel={pb.chisel} mode={pb.mode}")
    _, bob_chisel = L.sh_in(bbox.name, "pgrep -x chisel >/dev/null && echo yes || echo no") if bbox else (1, "no")
    ctx.out.check("E2.landed-second", bbox is not None and "yes" in bob_chisel and not session_of_chat(b, cb.session_id, 5),
                  "Bob's chisel client runs in his own sandbox and nothing landed for him")
    end_shells(ctx, a)
    for p in (a, b):
        tunnel_off(p)
    lab.stop()


# ---- the pool phase -------------------------------------------------------------------

def e12(ctx: Ctx) -> None:
    a, b, n = ctx.alice, ctx.bob, ctx.nonce
    desc = L.tool_description(a.mcp_token, "kali_exec")
    res_a = port_line(ctx, a, "PA", extra=f"echo FU-P7-{n} > /tmp/fu-p7-{n}-e12")
    box_a = own_box(a)
    res_b = port_line(ctx, b, "PB")
    box_b = own_box(b)
    pa_ = pool_ports(box_a)
    port_a = pa_[0][2] if len(pa_) == 1 else None
    ctx.out.check("E12.told", MCP_PORT_SENTENCE in desc and res_a["port"] == port_a
                  and MOTD_PORT.format(port=port_a) in res_a["output"],
                  "the kali_exec description names $MSF_REVERSE_PORT; Alice's command prints her port and her login "
                  "message names it", f"desc={'yes' if MCP_PORT_SENTENCE in desc else 'no'} env={res_a['port']} published={pa_}")
    pb_ = pool_ports(box_b)
    ctx.out.check("E12.published", len(pa_) == 1 and pa_[0][0] == pa_[0][2] and pa_[0][1] == ctx.gw and pa_[0][2] in ctx.pool
                  and box_a.port_label == str(port_a) and len(pb_) == 1 and pb_[0][2] in ctx.pool and pb_[0][2] != port_a
                  and res_b["port"] == pb_[0][2],
                  "each sandbox publishes exactly its own pool port, at the same number, on the pool's address; "
                  "the label names it; Alice's and Bob's differ", f"alice={pa_} bob={pb_}")
    holders = [bx.name for bx in L.sandboxes() if L.sh_in(bx.name, f"test -e /tmp/fu-p7-{n}-e12")[0] == 0]
    ctx.out.check("E12.landed", holders == [box_a.name] if box_a else False,
                  "Alice's MCP command ran in her own sandbox only", f"holders={holders}")
    L.sh_in(box_a.name, f"rm -f /tmp/fu-p7-{n}-e12") if box_a else None


def e1(ctx: Ctx) -> L.Chat:
    a, n = ctx.alice, ctx.nonce
    box = own_box(a)
    port = (pool_ports(box) or [(None, None, None)])[0][2]
    lab = L.apache_lab(n + "e1")
    ctx.labs.append(lab)
    lab_ip = lab.join(a.id)
    set_fields(ctx, a, "PA", **payload_fields(lhost=ctx.gw))
    c = chat(ctx, a, "PA", "E1", f"FU-P7 E1 {n}: the lab at http://{lab_ip}/ (Apache 2.4.49, a local guinea pig, "
                                 "in scope). Get a reverse shell on it.", [
        m_exploitation(), m_plan(),
        m_tool("the handler with the block's LHOST and LPORT", "metasploit_console",
               lambda c: {"command": handler_cmd(c.facts["plan"])}),
        m_keep("after_handler"),
        m_tool("the lab's RCE dials LHOST:LPORT", "kali_shell",
               lambda c: {"command": L.rce_command(lab_ip, L.reverse_shell_body(
                   f"FU-RCE-{n}", c.facts["plan"].lhost, c.facts["plan"].lport))}),
        m_tool("list the sessions", "metasploit_console", lambda c: {"command": "sessions -l"}),
    ], target=lab_ip)
    p = c.facts.get("plan") or L.Plan()
    # "[REDAMON]" is only ever tool output (handler_busy_note): a normal pool handler start has none.
    ctx.out.check("E1.told", p.mode == "reverse" and p.lport == port and p.pool_port == port and p.lhost == ctx.gw
                  and not p.asks_user and c.questions == 0 and "[REDAMON]" not in c.facts.get("after_handler", ""),
                  "the first exploit step's block gives LPORT = the pool port and the project's LHOST, asks nothing, "
                  "and the handler starts without a busy-port note",
                  f"mode={p.mode} lport={p.lport} pool={p.pool_port} lhost={p.lhost} questions={c.questions} "
                  f"waits={c.facts.get('plan_waits', 0)}")
    started = handler_started(c.facts.get("after_handler", ""), port)
    # The RCE fires at the next step: a handler the agent was not told is up may not listen yet.
    ctx.out.check("E1.handler", started,
                  "the handler command's own output says it started (its job, or its listener on the pool port) "
                  "before the RCE fires")
    pub = pool_ports(box)
    ctx.out.check("E1.published", pub == [(port, ctx.gw, port)] if port else False,
                  "Alice's sandbox publishes only that port, on the pool address", f"published={pub}")
    row = session_of_chat(a, c.session_id)
    ans = shell_answers(a, row, n) if row else ""
    bob_sees = [r for r in all_sessions(ctx.bob) if r.get("chat_session_id") == c.session_id]
    ctx.out.check("E1.landed", bool(row) and row.get("sandbox") == (box and box.instance)
                  and local_end(row).endswith(f":{port}") and f"FU-SHELL-42-{n}" in ans and lab.hostname in ans
                  and not bob_sees,
                  "the reverse shell came in on the pool port, in Alice's sandbox, linked to her chat; Bob does not list it",
                  f"row={row and {k: row.get(k) for k in ('id', 'sandbox', 'connection')}} bob_sees={len(bob_sees)}")
    ctx.e1 = {"chat": c, "lab": lab, "lab_ip": lab_ip, "port": port, "row": row, "handler_started": started}
    return c


def e6(ctx: Ctx) -> None:
    """E1's chat (chat 1) keeps its handler and session. Chat 2 on the same project starts the same
    handler again and gets the busy-port note; it then fires the RCE, and the shell is caught by
    chat 1's handler. Chat 3 on Alice's other project is refused the console."""
    a, n = ctx.alice, ctx.nonce
    e1f = ctx.e1
    if not e1f or not e1f.get("row"):
        ctx.out.check("E6.told", False, "E6 needs E1's handler and session", "E1 opened no session")
        return
    port, lab_ip, chat1 = e1f["port"], e1f["lab_ip"], e1f["chat"].session_id
    before = {r.get("id") for r in all_sessions(a)}
    c2 = chat(ctx, a, "PA", "E6-chat2", f"FU-P7 E6 {n}: another chat on the same lab http://{lab_ip}/.", [
        m_exploitation(), m_plan(),
        m_tool("the same handler again, as a second chat would", "metasploit_console",
               lambda c: {"command": handler_cmd(c.facts["plan"])}),
        m_keep("after_second_handler"),
        m_tool("see the jobs", "metasploit_console", lambda c: {"command": "jobs"}),
        m_tool("fire the RCE at the shared port", "kali_shell",
               lambda c: {"command": L.rce_command(lab_ip, L.reverse_shell_body(
                   f"FU-RCE2-{n}", c.facts["plan"].lhost, c.facts["plan"].lport))}),
        m_tool("list the sessions", "metasploit_console", lambda c: {"command": "sessions -l"}),
    ], target=lab_ip)
    p2 = c2.facts.get("plan") or L.Plan()
    note = c2.facts.get("after_second_handler", "")
    set_fields(ctx, a, "PS", **payload_fields(lhost=ctx.gw))
    c3 = chat(ctx, a, "PS", "E6-chat3", f"FU-P7 E6 {n}: a chat on Alice's other project.", [
        m_exploitation(), m_plan(),
        m_tool("Metasploit from another project", "metasploit_console", lambda c: {"command": "jobs"}),
        m_keep("after_console"),
        m_tool("a listener on the same port", "kali_shell",
               lambda c: {"command": f"timeout 5 nc -lvnp {port} 2>&1; echo FU-P7-NC-RC=$?"}),
        m_keep("after_nc"),
    ], target=lab_ip)
    # Tool-output markers only (the system prompt's shared-port text also says "reuse it").
    ctx.out.check("E6.told", p2.lport == port and p2.shared_port_text and BUSY_PORT.format(port=port) in note
                  and "already listens on it" in note and HELD_BY_PROJECT in c3.facts.get("after_console", "")
                  and "Address already in use" in c3.facts.get("after_nc", "") and bool(e1f.get("handler_started")),
                  "chat 1 was told its handler started; chat 2 is told the one shared port and, starting a second "
                  "handler, that port P is in use by its own job (reuse it); chat 3 on another project is refused the "
                  "console and its listener cannot bind",
                  f"chat1_started={e1f.get('handler_started')} lport={p2.lport} shared={p2.shared_port_text} "
                  f"busy={BUSY_PORT.format(port=port) in note} refused={HELD_BY_PROJECT in c3.facts.get('after_console', '')}")
    box = own_box(a)
    ctx.out.check("E6.published", pool_ports(box) == [(port, ctx.gw, port)],
                  "still one published port for all of Alice's chats", f"published={pool_ports(box)}")
    new = [r for r in all_sessions(a) if r.get("id") not in before]
    chats_of_new = sorted({str(r.get("chat_session_id")) for r in new})
    ctx.out.check("E6.landed", len(new) == 1 and new[0].get("chat_session_id") == chat1
                  and new[0].get("sandbox") == (box and box.instance) and c3.session_id not in chats_of_new,
                  "the second shell was caught by chat 1's handler and is linked to chat 1 (the chat whose handler "
                  "caught it, metasploit_server._chat_of_new_session), never to the other project's chat",
                  f"new={len(new)} linked={['chat1' if x == chat1 else ('chat2' if x == c2.session_id else x[:12]) for x in chats_of_new]}")


def e10a(ctx: Ctx) -> None:
    """D-D through the routes: a member lists and stops the handler job of her own sandbox."""
    a = ctx.alice
    box = own_box(a, timeout=30)
    jobs = [j for j in L.sessions_of(a.http).get("jobs") or [] if j.get("sandbox") == (box and box.instance)]
    bob_jobs = [j for j in L.sessions_of(ctx.bob.http).get("jobs") or [] if j.get("sandbox") == (box and box.instance)]
    codes = [L.kill_row(a.http, "jobs", j) for j in jobs]
    # The list is the session manager's cache, refreshed every ~3 s: a stopped job leaves it a refresh later.
    until = time.time() + 30
    while True:
        left = [j for j in L.sessions_of(a.http).get("jobs") or [] if j.get("sandbox") == (box and box.instance)]
        if not left or time.time() > until:
            break
        time.sleep(3)
    ctx.out.check("E10a.landed", bool(jobs) and all(c == 200 for c in codes) and not left and not bob_jobs,
                  "Alice (a member) lists her own sandbox's handler job and stops it; Bob lists none of it",
                  f"jobs={len(jobs)} kills={codes} left={len(left)} bob={len(bob_jobs)}")
    end_shells(ctx, a)
    lab = ctx.e1.get("lab")
    if lab:
        lab.stop()


def e3(ctx: Ctx) -> None:
    a, n = ctx.alice, ctx.nonce
    grant_tunnels(ctx, a)
    box = own_box(a)
    port = (pool_ports(box) or [(None, None, None)])[0][2]
    edge = ensure_edge(ctx)
    lab = L.apache_lab(n + "e3")
    ctx.labs.append(lab)
    lab_ip = lab.join(a.id)
    url = edge.url_for(a.id)
    st = tunnel_on(ctx, a, url)
    set_fields(ctx, a, "PA", **payload_fields(lhost=ctx.gw, chisel=True))
    c = chisel_chat(ctx, a, "PA", "E3", lab, lab_ip)
    p = c.facts.get("plan") or L.Plan()
    edge_host = url.split("//")[1].split(":")[0]
    ctx.out.check("E3.told", p.chisel == "active" and p.lport == 4444 and p.lhost == edge_host and p.bind_listen_4444
                  and p.pool_port is None and f"LHOST={edge_host}" in p.text and "LPORT=4444" in p.text,
                  "with a pool port and chisel on, the tunnel path is used and every value agrees (LHOST the server, "
                  "LPORT 4444, bind 127.0.0.1:4444; no pool-port note)",
                  f"tunnel={st.get('status')} lhost={p.lhost} lport={p.lport} pool_note={p.pool_port}")
    ctx.out.check("E3.published", pool_ports(box) == [(port, ctx.gw, port)],
                  "the pool port stays published (unused by this shell)", f"published={pool_ports(box)}")
    row = session_of_chat(a, c.session_id)
    ans = shell_answers(a, row, n) if row else ""
    ctx.out.check("E3.landed", bool(row) and row.get("sandbox") == (box and box.instance)
                  and local_end(row).startswith("127.0.0.1:4444") and lab.hostname in ans,
                  "the shell came through the tunnel into Alice's sandbox, linked to her chat",
                  f"connection={row and row.get('connection')}")
    end_shells(ctx, a)
    tunnel_off(a)
    set_fields(ctx, a, "PA", agentChiselTunnelEnabled=False)
    lab.stop()


def e7(ctx: Ctx) -> None:
    a, n = ctx.alice, ctx.nonce
    seen = {}

    def stop_now(prompt, c):
        box = own_box(a, timeout=30)
        seen["old"] = box
        seen["old_port"] = (pool_ports(box) or [(None, None, None)])[0][2]
        seen["stopped"] = ctx.orch.stop_person(a.id)

    second = f"echo FU-P7-E7-B-{n} $MSF_REVERSE_PORT > /tmp/fu-p7-{n}-e7; cat /tmp/fu-p7-{n}-e7"

    def note_or_retry(prompt, c):
        # The note rides the first SUCCESSFUL call on the new instance; a call the stop failed
        # carries none (sandbox_router.new_instance_note), so it is sent again, at most twice.
        if RESTARTED in prompt:
            c.facts["note"] = prompt
            return None
        c.facts["retries"] = c.facts.get("retries", 0) + 1
        if c.facts["retries"] > 2:
            return None
        return L.use_tool("the call again", "kali_shell", {"command": second})

    set_fields(ctx, a, "PA", **payload_fields(lhost=ctx.gw))
    c = chat(ctx, a, "PA", "E7", f"FU-P7 E7 {n}: run two commands in your Kali sandbox.", [
        m_tool("a first Kali call", "kali_shell", lambda c: {"command": f"echo FU-P7-E7-A-{n} $MSF_REVERSE_PORT"}),
        m_hook(stop_now),
        m_tool("a call after the sandbox stopped", "kali_shell", lambda c: {"command": second}),
        note_or_retry, note_or_retry, note_or_retry,
    ])
    old, old_port = seen.get("old"), seen.get("old_port")
    note = c.facts.get("note", "")
    ctx.out.check("E7.told", bool(seen.get("stopped")) and RESTARTED in note and PORT_UNCHANGED.format(port=old_port) in note,
                  "after the stop, the next Kali call's output starts with the restart note naming the same port",
                  f"stopped={seen.get('stopped')} note={'yes' if RESTARTED in note else 'no'} port={old_port}")
    new = own_box(a, timeout=60)
    ctx.out.check("E7.published", bool(old and new and new.instance != old.instance)
                  and pool_ports(new) == [(old_port, ctx.gw, old_port)],
                  "a new instance publishes the same pool port (held for Alice, given back to her)",
                  f"old={old and old.instance} new={new and new.instance} published={pool_ports(new)}")
    holders = [bx.name for bx in L.sandboxes() if L.sh_in(bx.name, f"test -e /tmp/fu-p7-{n}-e7")[0] == 0]
    ctx.out.check("E7.landed", bool(new) and holders == [new.name] and f"FU-P7-E7-B-{n} {old_port}" in c.last_think() + note,
                  "the second call ran in Alice's new instance, which reads the same MSF_REVERSE_PORT",
                  f"holders={holders}")
    if new:
        L.sh_in(new.name, f"rm -f /tmp/fu-p7-{n}-e7")


def e9(ctx: Ctx) -> None:
    b, admin, n = ctx.bob, ctx.admin, ctx.nonce
    bob_own = own_box(b, timeout=30)
    bob_port = (pool_ports(bob_own) or [(None, None, None)])[0][2]
    set_fields(ctx, b, "PB", **payload_fields(lhost=ctx.gw, chisel=True))
    res = admin.http.call("POST", "/api/auth/act-as", {"targetUserId": b.id, "reason": "fu-p7 e2e: act-as port",
                                                       "durationMinutes": 15,
                                                       "stepUpPassword": seed.env_value("UI_LOGIN_PASSWORD")})
    for value in admin.http.cookies.values():
        ctx.out.redact.add(value)
    if res.status != 200:
        ctx.out.check("E9.published", False, "the admin acts as Bob", f"act-as answered {res.status} {res.code}")
        return
    ctx.acting = True
    try:
        c = chat(ctx, b, "PB", "E9", f"FU-P7 E9 {n}: (an administrator acting as Bob) how would a reverse shell reach you?", [
            m_exploitation(), m_plan(ready=lambda p: p.chisel not in ("", "unread", "connecting")),
            m_tool("a Kali call under act-as", "kali_shell",
                   lambda c: {"command": f"echo FU-P7-E9-{n} $MSF_REVERSE_PORT > /tmp/fu-p7-{n}-e9; cat /tmp/fu-p7-{n}-e9"}),
        ], http=admin.http)
        actas = own_box(b, "act_as", timeout=60)
        pub = pool_ports(actas)
        port = pub[0][2] if len(pub) == 1 else None
        env_port = L.env_in(actas.name, "MSF_REVERSE_PORT") if actas else None
        ctx.out.check("E9.published", bool(actas) and port in ctx.pool and port != bob_port
                      and env_port == str(port) and actas.port_label == str(port),
                      "Bob's act_as sandbox publishes a pool port of its own, apart from his own sandbox's",
                      f"act_as={pub} own={bob_port} env={env_port}")
        p = c.facts.get("plan") or L.Plan()
        st_port, st_state = reverse_port_state(admin.http)
        ctx.out.check("E9.told", p.chisel == "act_as" and ACT_AS_BANNER in p.text and p.lport == port
                      and st_port == port and st_state == "assigned",
                      "under act-as the block says the tunnel is not available (another person's act-as sandbox), "
                      "gives the act_as port as LPORT, and the admin's status route shows that port",
                      f"chisel={p.chisel} lport={p.lport} status={st_port}/{st_state}")
        holders = [bx.name for bx in L.sandboxes() if L.sh_in(bx.name, f"test -e /tmp/fu-p7-{n}-e9")[0] == 0]
        ctx.out.check("E9.landed", bool(actas) and holders == [actas.name] and f"FU-P7-E9-{n} {port}" in c.last_think(),
                      "the act-as run's Kali call ran in Bob's act_as sandbox only (not his own), with its own port",
                      f"holders={holders}")
    finally:
        admin.http.call("DELETE", "/api/auth/act-as")
        ctx.acting = False


# ---- pool of one -------------------------------------------------------------------------

def listener(ctx: Ctx, person: L.Person, project_key: str, port_expr: str, tag: str) -> None:
    """A background nc on `port_expr` in the person's own sandbox, writing what it gets to /tmp."""
    L.kali_exec(person.mcp_token, ctx.projects[project_key],
                f"setsid nohup sh -c 'nc -lvnp {port_expr} > /tmp/fu-p7-{ctx.nonce}-{tag}.log 2>&1' "
                ">/dev/null 2>&1 & sleep 1; echo FU-P7-LISTENING")


def caught(box: Optional[L.Box], ctx: Ctx, tag: str, marker: str) -> bool:
    if not box:
        return False
    rc, text = L.sh_in(box.name, f"cat /tmp/fu-p7-{ctx.nonce}-{tag}*.log 2>/dev/null")
    return marker in text


def e5(ctx: Ctx) -> None:
    a, b, n = ctx.alice, ctx.bob, ctx.nonce
    port = ctx.pool[0]
    res_a = port_line(ctx, a, "PA")
    box_a = own_box(a)
    res_b = port_line(ctx, b, "PB")
    box_b = own_box(b)
    st_port, st_state = reverse_port_state(b.http)
    set_fields(ctx, b, "PB", **payload_fields(lhost=ctx.gw))
    c = chat(ctx, b, "PB", "E5", f"FU-P7 E5 {n}: how would a reverse shell reach you?", [m_exploitation(), m_plan()])
    p = c.facts.get("plan") or L.Plan()
    ctx.out.check("E5.told", res_b["port"] == L.DEFAULT_REVERSE_PORT and MOTD_NONE in res_b["output"]
                  and st_state == "pool_full" and p.no_port == "pool_full" and p.mode in ("bind", "ask")
                  and "**Mode: REVERSE**" not in p.text,
                  "Bob is told the pool is full: MSF_REVERSE_PORT 4444 and the login line, the status route's "
                  "pool_full, and his agent's block (no reverse payload)",
                  f"env={res_b['port']} status={st_port}/{st_state} no_port={p.no_port} mode={p.mode}")
    ctx.out.check("E5.published", pool_ports(box_a) == [(port, ctx.gw, port)] and box_b is not None
                  and pool_ports(box_b) == [] and box_b.port_label in ("", None) and res_a["port"] == port,
                  "Alice publishes the one pool port; Bob's sandbox publishes nothing",
                  f"alice={pool_ports(box_a)} bob={pool_ports(box_b)}")
    listener(ctx, a, "PA", "$MSF_REVERSE_PORT", "e5a")
    listener(ctx, b, "PB", "$MSF_REVERSE_PORT", "e5b4444")
    listener(ctx, b, "PB", str(port), "e5bpool")
    rc, _ = L.probe_connect(ctx.gw, port, f"FU-P7-E5-{n}")
    time.sleep(2)
    ctx.out.check("E5.landed", rc == 0 and caught(box_a, ctx, "e5a", f"FU-P7-E5-{n}")
                  and not caught(box_b, ctx, "e5b", f"FU-P7-E5-{n}"),
                  "a callback to the pool port lands in Alice's sandbox, never in Bob's", f"probe rc={rc}")


def e8(ctx: Ctx) -> None:
    a, b, n = ctx.alice, ctx.bob, ctx.nonce
    port = ctx.pool[0]
    since = L.utc_now()
    stopped = ctx.orch.stop_person(a.id)
    held = f"pool port {port} held for key={L.sandbox_key(a.id)}" in L.logs_since(L.ORCH, since)
    free_now = L.publishers_of(port) == []
    ctx.orch.stop_person(b.id)
    res_b = port_line(ctx, b, "PB")
    box_b = own_box(b)
    st_port, st_state = reverse_port_state(b.http)
    ctx.out.check("E8.told", stopped and held and res_b["port"] == L.DEFAULT_REVERSE_PORT and st_state == "pool_full",
                  "after Alice's stop her port is held for her: Bob's new sandbox is told pool_full (4444)",
                  f"stopped={stopped} held_log={held} bob_env={res_b['port']} status={st_state}")
    listener(ctx, b, "PB", str(port), "e8bpool")
    listener(ctx, b, "PB", "$MSF_REVERSE_PORT", "e8b4444")
    rc, _ = L.probe_connect(ctx.gw, port, f"FU-P7-E8-{n}")
    time.sleep(2)
    ctx.out.check("E8.landed", free_now and rc != 0 and pool_ports(box_b) == [] and not caught(box_b, ctx, "e8b", f"FU-P7-E8-{n}"),
                  "a late callback to Alice's port reaches nobody (refused), and never Bob's sandbox",
                  f"publishers_after_stop={L.publishers_of(port)} probe rc={rc}")
    res_a = port_line(ctx, a, "PA")
    box_a = own_box(a)
    ctx.out.check("E8.published", res_a["port"] == port and pool_ports(box_a) == [(port, ctx.gw, port)],
                  "within the hold Alice gets the same port back on her next start", f"alice={pool_ports(box_a)}")


def e8c(ctx: Ctx) -> None:
    """The control: with no hold the freed port goes to Bob at once, and the same probe lands in his
    sandbox, so E8's "reaches nobody" is the hold's doing, not a probe that cannot land."""
    a, b, n = ctx.alice, ctx.bob, ctx.nonce
    port = ctx.pool[0]
    port_line(ctx, a, "PA")
    ctx.orch.stop_person(a.id)
    res_b = port_line(ctx, b, "PB")
    box_b = own_box(b)
    listener(ctx, b, "PB", "$MSF_REVERSE_PORT", "e8cb")
    rc, _ = L.probe_connect(ctx.gw, port, f"FU-P7-E8C-{n}")
    time.sleep(2)
    ctx.out.check("E8c.control", res_b["port"] == port and rc == 0 and caught(box_b, ctx, "e8cb", f"FU-P7-E8C-{n}"),
                  "with KALI_SANDBOX_PORT_HOLD_HOURS=0 Bob gets Alice's freed port and the late callback lands in his "
                  "sandbox (FU-1's failure, which the hold prevents)", f"bob_env={res_b['port']} probe rc={rc}")


# ---- phases ------------------------------------------------------------------------------

@dataclass
class Phase:
    name: str
    managed: Callable[[Ctx], dict]
    pool: Callable[[Ctx], list]
    steps: list


def pool_text(ctx: Ctx, first: int, last: int) -> str:
    return f"{ctx.gw}:{first}-{last}"


PHASES = [
    Phase("nopool", lambda c: {"KALI_SANDBOX_PORT_POOL": ""}, lambda c: [],
          [("E11", e11), ("E4", e4), ("E2", e2)]),
    Phase("pool", lambda c: {"KALI_SANDBOX_PORT_POOL": pool_text(c, POOL_BASE, POOL_BASE + 2),
                             "KALI_SANDBOX_PORT_HOLD_HOURS": "24"},
          lambda c: [POOL_BASE, POOL_BASE + 1, POOL_BASE + 2],
          [("E12", e12), ("E1", e1), ("E6", e6), ("E10a", e10a), ("E3", e3), ("E7", e7), ("E9", e9)]),
    Phase("pool1", lambda c: {"KALI_SANDBOX_PORT_POOL": pool_text(c, POOL_BASE + 3, POOL_BASE + 3),
                              "KALI_SANDBOX_PORT_HOLD_HOURS": "24"},
          lambda c: [POOL_BASE + 3], [("E5", e5), ("E8", e8)]),
    Phase("nohold", lambda c: {"KALI_SANDBOX_PORT_POOL": pool_text(c, POOL_BASE + 3, POOL_BASE + 3),
                               "KALI_SANDBOX_PORT_HOLD_HOURS": "0"},
          lambda c: [POOL_BASE + 3], [("E8", e8c)]),
]
# E12 starts the sandboxes the later pool scenarios use; E6 and E10a build on E1.
NEEDS = {"E1": ["E12"], "E6": ["E12", "E1"], "E10a": ["E12", "E1"], "E3": ["E12"], "E7": ["E12"], "E9": ["E12"],
         "E8": ["E5"]}


def selected(only: Optional[set]) -> set:
    if not only:
        return set(SCENARIOS)
    want = set(only)
    for s in list(want):
        want.update(NEEDS.get(s, []))
    return want


def stop_people(ctx: Ctx) -> None:
    for p in [*ctx.people.values(), ctx.admin]:
        if not ctx.orch.stop_person(p.id):
            raise Fatal(f"{p.key}'s sandboxes did not stop")


def prune_holds(ctx: Ctx, ports: list[int]) -> None:
    """Hold 0 over every port the run used, one start per person: the first release saves the
    holds again, dropping every one that is over (all of them, with hold 0)."""
    ctx.orch.set_phase({"KALI_SANDBOX_PORT_POOL": pool_text(ctx, min(ports), max(ports)),
                        "KALI_SANDBOX_PORT_HOLD_HOURS": "0"})
    stop_people(ctx)
    for key, project in (("alice", "PA"), ("bob", "PB")):
        port_line(ctx, ctx.people[key], project)
        ctx.orch.stop_person(ctx.people[key].id)
    left = ctx.orch.holds_in(ports)
    ctx.out.check("cleanup.holds", left == [], "no pool port hold of this run is left in the orchestrator's holds file",
                  f"left={left}")


# ---- the run -----------------------------------------------------------------------------

def preflight(out: L.Out) -> None:
    if not seed.webapp_up():
        raise Fatal(f"the webapp does not answer {seed.base_url()}/api/health")
    for name in (L.AGENT, L.ORCH, L.PROXY):
        if not ((L.inspect(name) or {}).get("State") or {}).get("Running"):
            raise Fatal(f"{name} is not running")
    for image in (L.KALI_IMAGE, L.APACHE_IMAGE, L.BUSYBOX_IMAGE):
        if L.docker("image", "inspect", image)[0] != 0:
            raise Fatal(f"the image {image} is missing")
    for key in ("AGENT_IN_THE_LOOP_ENABLED", "MCP_SERVER_ENABLED", "MCP_KALI_EXEC_ENABLED"):
        if seed.env_value(key).lower() not in ("true", "1"):
            raise Fatal(f"{key} is not on in .env")


def known_people(ctx: Ctx) -> set:
    return {p.id for p in ctx.people.values()} | {ctx.admin.id}


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", default="", help="comma-separated scenarios, e.g. E1,E7 (their prerequisites run too)")
    ap.add_argument("--plan", action="store_true", help="print what would run and exit")
    ap.add_argument("--self-test", action="store_true", help="check the offline parsers and exit")
    args = ap.parse_args(argv)
    names = {s.upper(): s for s in SCENARIOS}
    asked = [s.strip() for s in args.only.split(",") if s.strip()]
    unknown = [s for s in asked if s.upper() not in names]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    only = {names[s.upper()] for s in asked} or None
    want = selected(only)
    if args.self_test:
        return self_test()
    if args.plan:
        for ph in PHASES:
            steps = [s for s, _ in ph.steps if s in want]
            if steps:
                print(f"phase {ph.name}: {', '.join(steps)}")
        print("then: cleanup (hold 0 over every port, holds pruned), the orchestrator put back, the accounts restored")
        return 0

    out = L.Out()

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt()

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    ctx: Optional[Ctx] = None
    rc = 1
    try:
        preflight(out)
        out.line("== FU P7: reverse-shell ports of per-user Kali sandboxes, end to end ==")
        for gone in L.remove_run_resources():
            out.info(f"removed a leftover {gone}")
        # Its stdout carries ids and outcomes only; kept off this log anyway.
        seeded = subprocess.run([sys.executable, "-I", os.path.join(L.HERE, "kali_sandbox_seed_live.py")],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        state = seed.read_state()
        if seeded.returncode != 0 or not state:
            raise Fatal("the g1 seed failed (run python3 tests/kali_sandbox_seed_live.py for its reason)")
        for key in ("alice", "bob"):
            out.redact.add(state[key]["password"], state[key]["token"])
        admin_email, admin_password = seed.env_value("UI_LOGIN_USERNAME"), seed.env_value("UI_LOGIN_PASSWORD")
        out.redact.add(admin_password)
        orch = L.Orchestrator(out)
        restore = L.Restore((seed.state_path()) + ".fu-p7-restore.json")
        people = {}
        for key in ("alice", "bob"):
            http, uid = L.sign_in(out, state[key]["email"], state[key]["password"])
            people[key] = L.Person(key, uid, state[key]["email"], state[key]["password"], state[key]["token"], http)
        ahttp, aid = L.sign_in(out, admin_email, admin_password)
        admin = L.Person("admin", aid, admin_email, admin_password, "", ahttp)
        gw = L.network_gateway(L.pentest_network())
        if not gw:
            raise Fatal("the pentest network has no gateway address")
        ctx = Ctx(out, orch, restore, people, admin, dict(state["projects"]), gw, secrets.token_hex(3))
        # A killed run's leftovers on the accounts go back first.
        failed = restore.restore_tunnels(people) + restore.restore_projects(ctx.https())
        if failed:
            raise Fatal(f"an earlier run's changes could not be put back: {', '.join(failed)}")
        foreign = [b.name for b in L.sandboxes() if b.user not in known_people(ctx)]
        if foreign and os.environ.get("FU_P7_ALLOW_FOREIGN") != "1":
            raise Fatal(f"another person's sandbox runs ({len(foreign)}); a pool change would drain it "
                        "(FU_P7_ALLOW_FOREIGN=1 to go on anyway)")
        for port in range(POOL_BASE, POOL_BASE + 4):
            if L.publishers_of(port):
                raise Fatal(f"host port {port} is already published: set FU_P7_POOL_BASE")
        for p in people.values():
            L.mint_driver_token(out, p)
        orch.begin()
        stop_people(ctx)
        used: list[int] = []
        for ph in PHASES:
            steps = [(s, fn) for s, fn in ph.steps if s in want]
            if not steps:
                continue
            out.line(f"== phase {ph.name} ==")
            stop_people(ctx)
            orch.set_phase(ph.managed(ctx))
            ctx.pool = ph.pool(ctx)
            used += ctx.pool
            for sid, fn in steps:
                out.line(f"-- {sid} --")
                try:
                    fn(ctx)
                except Fatal as e:
                    out.check(f"{sid}.run", False, "the scenario ran to its end", str(e))
                except Exception as e:  # one scenario's failure is its own; the run goes on
                    out.check(f"{sid}.run", False, "the scenario ran to its end", f"{type(e).__name__}: {e}")
        if used:
            out.line("== cleanup: holds ==")
            prune_holds(ctx, sorted(set(used)))
        rc = 0 if out.failed == 0 else 1
    except Fatal as e:
        out.line(f"FAIL  setup  {e}")
        rc = 2
    except KeyboardInterrupt:
        out.line("FAIL  interrupted")
        rc = 130
    finally:
        if ctx is not None:
            rc = teardown(ctx, rc)
        out.line(f"== RESULT: {out.passed} passed, {out.failed} failed"
                 + (f" ({', '.join(out.failures)})" if out.failures else "") + " ==")
    return rc


def teardown(ctx: Ctx, rc: int) -> int:
    out = ctx.out
    problems = []
    if ctx.acting:
        ctx.admin.http.call("DELETE", "/api/auth/act-as")
    for key in ("alice", "bob"):
        try:
            end_shells(ctx, ctx.people[key])
        except Exception:
            problems.append(f"{key}'s shells")
    for key, sid in ctx.chats:
        L.delete_conversation(ctx.people[key].http, sid)
    for lab in ctx.labs:
        lab.stop()
    if ctx.edge:
        ctx.edge.stop()
    L.remove_run_resources()
    try:
        stop_people(ctx)
    except Fatal as e:
        problems.append(str(e))
    problems += ctx.restore.restore_tunnels(ctx.people) + ctx.restore.restore_projects(ctx.https())
    for p in ctx.people.values():
        if not L.revoke_driver_token(p):
            problems.append(f"{p.key}'s loop driver token")
    if not ctx.orch.restore():
        problems.append(f"{L.ORCH} could not be put back (originals kept in {ctx.orch.originals_path})")
    # Last: removing a grant signs that account out everywhere.
    problems += ctx.restore.restore_grants(ctx.admin.http, seed.env_value("UI_LOGIN_PASSWORD"))
    if problems:
        out.line(f"FAIL  teardown  not put back: {'; '.join(problems)} (recorded for the next run)")
        return rc or 1
    out.info("teardown: labs, edge, chats, shells and sandboxes gone; projects, tunnels, tokens, grants and "
             f"{L.ORCH} put back")
    return rc


# ---- offline checks of the parsers (no stack) ------------------------------------------

def self_test() -> int:
    ok = True

    def expect(what, cond):
        nonlocal ok
        print(("ok    " if cond else "FAIL  ") + what)
        ok = ok and bool(cond)

    sample = os.environ.get("FU_P7_SAMPLE_BLOCKS")
    if sample:
        blocks = json.load(open(sample, encoding="utf-8"))
        for name, text in blocks.items():
            p = read_plan("=== SYSTEM ===\nprefix\n" + text + "\n## Next section\nnot in the block")
            want = json.loads(name)
            expect(f"block {want['case']}: mode={p.mode} lport={p.lport} lhost={p.lhost} pool={p.pool_port} "
                   f"chisel={p.chisel} no_port={p.no_port}",
                   all(getattr(p, k) == v for k, v in want.items() if k != "case"))
    inputs = L.service_inputs([os.path.join(L.ROOT, "docker-compose.yml")])
    names = {k for k, _ in inputs}
    expect("the orchestrator's compose inputs name the pool and the hold", {"KALI_SANDBOX_PORT_POOL",
                                                                           "KALI_SANDBOX_PORT_HOLD_HOURS"} <= names)
    expect("its limits and port are replayed", {"@mem", "@pids", "@cpus", "@port"} <= names)
    expect("the sandbox key is the contract's",
           L.sandbox_key("abc") == "ba7816bf8f01cfea" and L.sandbox_network("abc", "act_as").startswith("redamon-sbx-"))
    body = L.reverse_shell_body("M", "172.28.0.1", 40190)
    expect("the RCE body carries no single quote", "'" not in body and "/dev/tcp/172.28.0.1/40190" in body)
    expect("the RCE command quotes the body whole", L.rce_command("10.214.0.5", body).startswith("printf '%s' 'echo "))
    print("self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

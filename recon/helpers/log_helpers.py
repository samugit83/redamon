"""
Standard logging helpers shared across the recon pipeline.

The most important one is ``print_effective_settings`` -- every tool calls it
at the start of its main entry function so the operator can audit, in the
Recon Logs Drawer, exactly what configuration a given run used.

Output format (designed to be readable in the drawer's monospace terminal):

    [*][Naabu] Effective settings for this run:
    [*][Naabu]   # Docker image
    [*][Naabu]   NAABU_DOCKER_IMAGE        = 'projectdiscovery/naabu:latest'
    [*][Naabu]   # Port configuration
    [*][Naabu]   NAABU_TOP_PORTS           = 1000
    [*][Naabu]   NAABU_CUSTOM_PORTS        = '21,22,80,443,3306,...' (47 chars)
    ...

Sensitive values (API keys, tokens) are auto-redacted so credentials never
land in the logs drawer.
"""

from __future__ import annotations

from typing import Iterable, Optional, Union

# Sensitive keys -- substring match. Any setting whose name contains one of
# these tokens has its value masked in the dump (e.g. "SHODAN_API_KEY",
# "CENSYS_API_TOKEN", "VULNERS_KEY_ROTATOR").
_SENSITIVE_TOKENS = (
    "API_KEY",
    "API_TOKEN",
    "KEY_ROTATOR",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "ORG_ID",       # Censys-style identifier; safe to redact alongside the token
)

KeyEntry = Union[str, tuple[str, str]]
"""Either a bare key name or (key, group_label) tuple."""


def is_sensitive_key(key: str) -> bool:
    """Return True if the key looks like a credential and should be redacted."""
    upper = key.upper()
    return any(token in upper for token in _SENSITIVE_TOKENS)


def _format_value(key: str, value, masked: bool) -> str:
    """Render a setting value for the dump in a readable, bounded form."""
    if value is None:
        return "<unset>"
    # A switch named after what it looks for (URLSCAN_SECRETS_IN_URLS) holds
    # no credential: a boolean is never masked.
    if isinstance(value, bool):
        return repr(value)
    # Empty credentials should render as <unset> (not '') so the operator can
    # tell at a glance that the slot is empty. Only applies to masked keys --
    # for non-credential settings an empty string can be a legitimate value
    # (e.g. NAABU_CUSTOM_PORTS="" meaning "use the top-ports default").
    if masked and value == "":
        return "<unset>"
    if masked:
        # Show length so the operator knows it is configured, without leaking it.
        s = str(value)
        return f"<redacted, {len(s)} chars>"
    if isinstance(value, bool):
        return repr(value)
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        if len(value) > 100:
            # Long blobs (e.g. custom wordlists) -> show length only
            line_count = sum(
                1 for ln in value.splitlines() if ln.strip() and not ln.strip().startswith("#")
            )
            return f"<{len(value)} chars, {line_count} non-comment lines>"
        return repr(value)
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            return "[]"
        if len(value) <= 6:
            return repr(list(value))
        return f"[{value[0]!r}, {value[1]!r}, ..., {value[-1]!r}] ({len(value)} items)"
    if isinstance(value, dict):
        if not value:
            return "{}"
        return f"<dict, {len(value)} keys>"
    return repr(value)


def _ip_hostname_forced(settings: dict) -> dict:
    """The keys the IP-mode hostname mode forces this run, so the dump says why
    a toggle the operator switched on reads False. Never raises: a log line must
    not stop the tool it describes."""
    if not settings.get("IP_MODE"):
        return {}
    try:
        from recon.project_settings import ip_hostname_overrides
        return ip_hostname_overrides(settings)
    except Exception:  # noqa: BLE001 - the marker is cosmetic, the override is not
        return {}


def print_effective_settings(
    tool_label: str,
    settings: dict,
    keys: Iterable[KeyEntry],
    *,
    redact: Optional[Iterable[str]] = None,
    extra_lines: Optional[Iterable[str]] = None,
) -> None:
    """
    Print a tool's effective settings in a standard, readable format.

    Call this at the top of the tool's main entry function (after settings
    have been parsed but before any work begins) so the operator can audit
    in the Recon Logs Drawer what config the run used.

    Args:
        tool_label: the bracketed log prefix, e.g. "Naabu" -> "[*][Naabu]"
        settings: the full settings dict from get_settings()
        keys: iterable of either:
              - bare key name (str): printed in current group
              - (key, group_label) tuple: when group_label changes from the
                previous entry, a "# group_label" header line is emitted first
              Pass keys in the order you want them displayed.
        redact: extra keys to mask beyond auto-detected sensitive ones
        extra_lines: free-form lines appended after the keys (e.g. derived
                     values like "Total candidates per IP: 31")
    """
    explicit_redact = set(k.upper() for k in (redact or []))
    forced = _ip_hostname_forced(settings)
    print(f"[*][{tool_label}] Effective settings for this run:")
    last_group: Optional[str] = None
    longest_key = max(
        (len(k if isinstance(k, str) else k[0]) for k in keys),
        default=0,
    )
    pad = max(longest_key, 30)

    # Re-iterate (the previous call exhausted the iterable if it was a generator)
    for entry in keys:
        if isinstance(entry, tuple) and len(entry) == 2:
            key, group = entry
        else:
            key, group = entry, None

        if group and group != last_group:
            print(f"[*][{tool_label}]   # {group}")
            last_group = group

        masked = is_sensitive_key(key) or key.upper() in explicit_redact
        value = settings.get(key, None)
        present = key in settings
        display = _format_value(key, value, masked) if present else "<unset>"
        if key in forced:
            display += f" (forced by Hostnames on target IPs: {settings.get('IP_HOSTNAME_MODE')})"
        print(f"[*][{tool_label}]   {key.ljust(pad)} = {display}")

    for line in (extra_lines or []):
        print(f"[*][{tool_label}]   {line}")

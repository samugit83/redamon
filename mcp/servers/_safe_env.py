"""
The environment for every process the sandbox starts for a person or the agent.

The servers in this container run as root with MCP_AUTH_TOKEN and
TUNNEL_AUTH_TOKEN in their environment: they validate inbound calls with them.
A child process inherits that environment by default, and every child here runs
something a person typed (the terminal), the agent wrote (kali_shell,
execute_code, proxy_brain) or the agent chose the arguments of (`execute_curl -d
@/proc/self/environ`). So no spawn passes the inherited environment through: each
passes `env=safe_env(...)`, the servers' environment without those tokens and
without any name ending in _KEY, _TOKEN, _SECRET or _PASSWORD, plus only what the
wrapper adds on purpose. tests/test_kali_shell_env_scrub.py fails on a spawn in
mcp/servers/*.py that does not.

A root shell can still read /proc/<pid>/environ of the servers themselves; that
residual is stated in docs/readmes/README.SECURITY_POSTURE.md.
"""
import os
from typing import Dict, Mapping, Optional

from _run_registry import run_tag

# REDAMON_RUN_CREDENTIAL is the one a process is handed explicitly (the terminal
# shell, the proxy_brain child): one left over in a server's own environment must
# not reach a child it was not meant for.
SCRUBBED_NAMES = frozenset({"MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN", "REDAMON_RUN_CREDENTIAL"})
SECRET_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD")


def is_secret_name(name: str) -> bool:
    upper = name.upper()
    return upper in SCRUBBED_NAMES or upper.endswith(SECRET_SUFFIXES)


def safe_env(extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """A copy of os.environ without secrets, then the agent run's tag when the
    spawn happens inside a tagged tool call (_run_registry), then `extra` (the
    caller's own additions)."""
    env = {name: value for name, value in os.environ.items() if not is_secret_name(name)}
    env.update(run_tag())
    if extra:
        env.update({name: value for name, value in extra.items() if value is not None})
    return env

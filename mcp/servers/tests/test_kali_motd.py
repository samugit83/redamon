"""The terminal's login message names the person's reverse-shell port (FU-9).

mcp/kali-sandbox/redamon-motd.sh is copied to /etc/profile.d/ in the Kali image, so every
login shell of the terminal (terminal_server.py runs `bash --login`) sources it. The
orchestrator sets MSF_REVERSE_PORT to the sandbox's pool port, or 4444 without one; the
terminal's environment keeps it (safe_env drops only secret-looking names). The message
names the port, or, without one, says a reverse shell needs the person's own tunnel or a
bind payload. Sourced into the person's shell, it leaves no variable behind.

Run (root-agent section, agent image): python -m pytest mcp/servers/tests/test_kali_motd.py -q
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SERVERS = Path(__file__).resolve().parents[1]
MOTD = SERVERS.parent / "kali-sandbox" / "redamon-motd.sh"
DOCKERFILE = SERVERS.parent / "kali-sandbox" / "Dockerfile"
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def login_message(port, shell="sh"):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if port is not None:
        env["MSF_REVERSE_PORT"] = port
    out = subprocess.run([shell, "-c", f'. "{MOTD}"; echo "left:${{_redamon_lport-unset}}"'],
                         env=env, capture_output=True, text=True, timeout=10)
    assert out.returncode == 0, out.stderr
    return ANSI.sub("", out.stdout)


@pytest.mark.parametrize("shell", ["sh", "bash"])
def test_a_pool_port_is_named(shell):
    text = login_message("45001", shell)
    assert "Your reverse-shell port (LPORT): 45001" in text
    # Loopback by default; reached once the operator opens it (deploy.sh revshell-open).
    assert "once the operator has opened it" in text
    assert "No reverse-shell port" not in text
    assert "left:unset" in text


@pytest.mark.parametrize("port", ["4444", None, "", "45001; rm -rf /", "$(id)"])
def test_without_a_pool_port_a_tunnel_or_a_bind_payload(port):
    text = login_message(port)
    assert "Your reverse-shell port" not in text
    assert "No reverse-shell port is published for this sandbox." in text
    assert "your own tunnel" in text and "bind payload" in text
    assert "rm -rf" not in text and "uid=" not in text


def test_the_redagraph_hint_stays():
    assert "redagraph ask list CVEs" in login_message("45001")


def test_every_login_shell_sources_it_and_the_terminal_keeps_the_port():
    assert "COPY kali-sandbox/redamon-motd.sh /etc/profile.d/" in DOCKERFILE.read_text()
    import _safe_env
    assert not _safe_env.is_secret_name("MSF_REVERSE_PORT")

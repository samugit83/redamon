"""
Nmap MCP Server - Network Mapper

Exposes nmap as an MCP tool for agentic penetration testing.
Nmap provides deep service detection, OS fingerprinting, and NSE scripting.

Tools:
    - execute_nmap: Execute nmap with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import re
import os

from _safe_env import safe_env

# Strip ANSI escape codes (terminal colors) from output
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Server configuration
SERVER_NAME = "nmap"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NMAP_PORT", "8004"))

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_nmap(args: str) -> str:
    """
    Execute nmap network scanner with any valid CLI arguments.

    Nmap is the standard network discovery and security auditing tool.
    Use for service version detection, OS fingerprinting, and NSE scripts.

    Args:
        args: Command-line arguments for nmap (without the 'nmap' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Service version detection:
        - "-sV 10.0.0.5 -p 80,443"

        Aggressive scan (version + OS + scripts + traceroute):
        - "-A 10.0.0.5 -p 22,80"

        Default scripts + version detection:
        - "-sV -sC 10.0.0.5 -p 80,443,8080"

        Vulnerability scanning with NSE:
        - "-sV --script vuln 10.0.0.5"

        OS fingerprinting:
        - "-O 10.0.0.5"

        Specific NSE script:
        - "--script http-enum 10.0.0.5 -p 80"

        UDP scan:
        - "-sU 10.0.0.5 --top-ports 20"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["nmap"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=600,
            env=safe_env()
        )
        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            if clean_stderr.strip():
                output += f"\n[STDERR]: {clean_stderr}"
        return output if output.strip() else "[INFO] No results returned"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 600 seconds. Consider scanning fewer ports or using --host-timeout."
    except FileNotFoundError:
        return "[ERROR] nmap not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] {str(e)}"


if __name__ == "__main__":
    import sys

    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")

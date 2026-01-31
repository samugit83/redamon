"""
Naabu MCP Server - Fast Port Scanner

Exposes naabu port scanner as MCP tools for agentic penetration testing.
Uses dynamic CLI wrapper approach for maximum flexibility.

Tools:
    - execute_naabu: Execute naabu with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import os

# Server configuration
SERVER_NAME = "naabu"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NAABU_PORT", "8000"))

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_naabu(args: str) -> str:
    """
    Execute naabu port scanner with any valid CLI arguments.

    Naabu is a fast port scanner written in Go that allows you to enumerate
    valid ports for hosts in a fast and reliable manner. It can also integrate
    with nmap for service detection using the -nmap-cli flag.

    Args:
        args: Command-line arguments for naabu (without the 'naabu' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Basic port scan:
        - "-host 10.0.0.5 -p 1-1000 -json"

        Scan with top ports:
        - "-host 192.168.1.0/24 -top-ports 100 -json"

        Scan from file:
        - "-list targets.txt -p 22,80,443,8080 -json"

        With nmap service detection:
        - "-host 10.0.0.5 -p 80,443 -nmap-cli 'nmap -sV -sC'"

        Fast scan with high rate:
        - "-host 10.0.0.5 -p 1-65535 -rate 5000 -json"

        Scan specific ports:
        - "-host 10.0.0.5 -p 21,22,23,25,53,80,443,445,3306,3389,5432,8080 -json"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["naabu"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout
        if result.stderr:
            # Filter out progress/info messages, keep errors
            stderr_lines = [
                line for line in result.stderr.split('\n')
                if line and not line.startswith('[INF]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No open ports found"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 seconds. Consider using a smaller port range or higher rate."
    except FileNotFoundError:
        return "[ERROR] naabu not found. Ensure it is installed and in PATH."
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

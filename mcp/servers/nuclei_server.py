"""
Nuclei MCP Server - Vulnerability Scanner

Exposes nuclei vulnerability scanner as MCP tools for agentic penetration testing.
Uses dynamic CLI wrapper approach for maximum flexibility.

Tools:
    - execute_nuclei: Execute nuclei with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import os

# Server configuration
SERVER_NAME = "nuclei"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NUCLEI_PORT", "8002"))

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_nuclei(args: str) -> str:
    """
    Execute nuclei vulnerability scanner with any valid CLI arguments.

    Nuclei is a fast and customizable vulnerability scanner based on simple
    YAML-based templates. It can detect CVEs, misconfigurations, exposed panels,
    and more using its extensive template library.

    Args:
        args: Command-line arguments for nuclei (without the 'nuclei' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Basic vulnerability scan:
        - "-u http://10.0.0.5 -severity critical,high -jsonl"

        Scan for specific CVE:
        - "-u http://10.0.0.5 -id CVE-2021-41773 -jsonl"

        Scan with tags:
        - "-u http://10.0.0.5 -tags cve,rce,lfi -jsonl"

        Scan multiple URLs from file:
        - "-l urls.txt -severity critical,high -jsonl"

        Use custom template:
        - "-u http://10.0.0.5 -t /opt/nuclei-templates/custom.yaml"

        Scan with all templates:
        - "-u http://10.0.0.5 -jsonl"

        Technology detection:
        - "-u http://10.0.0.5 -tags tech -jsonl"

        Scan for exposed panels:
        - "-u http://10.0.0.5 -tags panel -jsonl"

        Rate limited scan:
        - "-u http://10.0.0.5 -rate-limit 10 -jsonl"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["nuclei"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=600
        )
        output = result.stdout
        if result.stderr:
            # Filter out progress/info messages
            stderr_lines = [
                line for line in result.stderr.split('\n')
                if line and not any(x in line for x in ['[INF]', '[WRN]', 'Templates Loaded'])
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No vulnerabilities found"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 600 seconds. Consider reducing scope or using specific templates."
    except FileNotFoundError:
        return "[ERROR] nuclei not found. Ensure it is installed and in PATH."
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

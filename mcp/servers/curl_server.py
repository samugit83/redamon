"""
Curl MCP Server - HTTP Client

Exposes curl HTTP client as MCP tools for agentic penetration testing.
Uses dynamic CLI wrapper approach for maximum flexibility.

Tools:
    - execute_curl: Execute curl with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import os

# Server configuration
SERVER_NAME = "curl"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("CURL_PORT", "8001"))

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_curl(args: str) -> str:
    """
    Execute curl HTTP client with any valid CLI arguments.

    Curl is a command-line tool for transferring data with URLs. It supports
    HTTP, HTTPS, FTP, and many other protocols. Useful for HTTP enumeration,
    API testing, and exploiting web vulnerabilities.

    Args:
        args: Command-line arguments for curl (without the 'curl' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Basic GET request with headers:
        - "-s -i http://10.0.0.5/"

        POST request with JSON:
        - "-s -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"pass\":\"admin\"}' http://10.0.0.5/api/login"

        HEAD request (headers only):
        - "-s -I http://10.0.0.5/"

        Custom User-Agent:
        - "-s -i -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' http://10.0.0.5/"

        Follow redirects:
        - "-s -i -L http://10.0.0.5/"

        HTTPS with insecure (skip cert verification):
        - "-s -k https://10.0.0.5/"

        Get only HTTP status code:
        - "-s -o /dev/null -w '%{http_code}' http://10.0.0.5/"

        Send cookie:
        - "-s -i -b 'session=abc123' http://10.0.0.5/admin"

        Upload file:
        - "-s -X POST -F 'file=@/path/to/file.txt' http://10.0.0.5/upload"

        Basic authentication:
        - "-s -i -u admin:password http://10.0.0.5/admin"

        Custom timeout:
        - "-s -i --connect-timeout 10 --max-time 30 http://10.0.0.5/"

        Path traversal test:
        - "-s -i 'http://10.0.0.5/../../../../etc/passwd'"

        LFI test:
        - "-s -i 'http://10.0.0.5/index.php?page=../../../etc/passwd'"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["curl"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output if output.strip() else "[INFO] No response received"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 60 seconds. Consider using --connect-timeout and --max-time flags."
    except FileNotFoundError:
        return "[ERROR] curl not found. Ensure it is installed and in PATH."
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

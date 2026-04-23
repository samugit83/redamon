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
import yaml

# Server configuration
SERVER_NAME = "nuclei"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NUCLEI_PORT", "8002"))
CUSTOM_TEMPLATES_DIR = "/opt/nuclei-templates"

mcp = FastMCP(SERVER_NAME)


# ---------------------------------------------------------------------------
# Scan custom templates at startup to build dynamic docstring
# ---------------------------------------------------------------------------

def _discover_custom_templates() -> str:
    """Scan /opt/nuclei-templates/ at startup and return a docstring fragment."""
    if not os.path.isdir(CUSTOM_TEMPLATES_DIR):
        return ""

    templates = []
    dirs_seen = set()
    for root, _dirs, files in os.walk(CUSTOM_TEMPLATES_DIR):
        for fname in sorted(files):
            if not fname.endswith(('.yaml', '.yml')):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, CUSTOM_TEMPLATES_DIR)
            rel_dir = os.path.dirname(rel_path)
            try:
                with open(fpath, 'r') as f:
                    data = next(yaml.safe_load_all(f), None)
                if not isinstance(data, dict):
                    continue
                info = data.get('info', {})
                templates.append({
                    "id": data.get("id", fname),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", "unknown"),
                    "path": f"/opt/nuclei-templates/{rel_path}",
                })
                if rel_dir:
                    dirs_seen.add(rel_dir)
            except Exception:
                pass

    if not templates:
        return ""

    lines = [
        "",
        "    Custom templates available at /opt/nuclei-templates/:",
    ]
    for t in templates:
        lines.append(f"      - [{t['severity']}] {t['id']}: {t['name']}")
        lines.append(f"        path: {t['path']}")

    if dirs_seen:
        lines.append("")
        lines.append("    Scan entire custom directory:")
        for d in sorted(dirs_seen):
            lines.append(f"      - \"-u URL -t /opt/nuclei-templates/{d}/ -jsonl\"")

    return "\n".join(lines)


_CUSTOM_TEMPLATES_DOC = _discover_custom_templates()


# ---------------------------------------------------------------------------
# Build the execute_nuclei docstring dynamically
# ---------------------------------------------------------------------------

_EXECUTE_NUCLEI_DOC = f"""Execute nuclei vulnerability scanner with any valid CLI arguments.

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
{_CUSTOM_TEMPLATES_DOC}"""


@mcp.tool()
def execute_nuclei(args: str) -> str:
    __doc__ = _EXECUTE_NUCLEI_DOC  # noqa: F841 — assigned for clarity; actual doc set below
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["nuclei"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=1800  # 30 min — full template scans routinely take 20-40 min
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

# Set the docstring after definition (f-string can't be used directly as docstring)
execute_nuclei.__doc__ = _EXECUTE_NUCLEI_DOC


if __name__ == "__main__":
    import sys

    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")

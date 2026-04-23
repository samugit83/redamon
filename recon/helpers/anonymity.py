"""
Anonymity Module - Tor/Proxychains Integration
Routes traffic through Tor for anonymous reconnaissance.
"""

import socket
import subprocess
import shutil
from typing import Optional
from functools import wraps

# Try importing requests with SOCKS support
try:
    import requests
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
except ImportError:
    requests = None

# Try importing PySocks for SOCKS proxy support
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False


# ============================================================================
# Configuration
# ============================================================================

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
CHECK_URL = "https://check.torproject.org/api/ip"
FALLBACK_CHECK_URL = "https://api.ipify.org?format=json"


# ============================================================================
# Tor Status Checks
# ============================================================================

def is_tor_running() -> bool:
    """
    Check if Tor service is running by testing the SOCKS port.

    Returns:
        True if Tor SOCKS port is accepting connections.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((TOR_SOCKS_HOST, TOR_SOCKS_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False

def is_proxychains_available() -> bool:
    """Check if proxychains is installed."""
    return shutil.which("proxychains4") is not None or shutil.which("proxychains") is not None


def get_proxychains_cmd() -> str:
    """Get the proxychains command name."""
    if shutil.which("proxychains4"):
        return "proxychains4"
    elif shutil.which("proxychains"):
        return "proxychains"
    return ""


def check_tor_connection() -> dict:
    """
    Verify Tor connectivity and get exit node IP.

    Returns:
        Dictionary with connection status and IP info.
    """
    result = {
        "tor_running": is_tor_running(),
        "connected_via_tor": False,
        "exit_ip": None,
        "real_ip": None
    }

    if not result["tor_running"]:
        return result

    if requests is None:
        return result

    try:
        # Get real IP first
        real_resp = requests.get(FALLBACK_CHECK_URL, timeout=10)
        if real_resp.status_code == 200:
            result["real_ip"] = real_resp.json().get("ip")

        # Check Tor connection
        session = get_tor_session(log_exit_ip=False)
        if session:
            tor_resp = session.get(CHECK_URL, timeout=15)
            if tor_resp.status_code == 200:
                data = tor_resp.json()
                result["connected_via_tor"] = data.get("IsTor", False)
                result["exit_ip"] = data.get("IP")
            session.close()
    except Exception:
        pass

    return result


# ============================================================================
# Tor Session Management
# ============================================================================

def get_tor_exit_ip(session: 'requests.Session') -> Optional[str]:
    """
    Get the current Tor exit node IP address.
    This is the IP that target servers will see.

    Args:
        session: A Tor-configured requests session.

    Returns:
        Exit IP address or None if check fails.
    """
    try:
        resp = session.get(CHECK_URL, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("IsTor", False):
                return data.get("IP")

        resp = session.get(FALLBACK_CHECK_URL, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("ip")
    except Exception:
        pass

    return None


def get_tor_session(log_exit_ip: bool = True) -> Optional['requests.Session']:
    """
    Create a requests Session configured to use Tor SOCKS proxy.

    Args:
        log_exit_ip: Whether to log the exit IP to terminal.

    Returns:
        Configured requests Session or None if Tor not available.
    """
    if requests is None:
        print("[!][Tor] requests library not available")
        return None

    if not is_tor_running():
        print("[!][Tor] Tor is not running on port 9050")
        print("[*][Tor] Start with: sudo systemctl start tor")
        return None

    session = requests.Session()

    # Configure SOCKS5 proxy
    proxy_url = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    session.proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

    # Add retry logic
    retry = Retry(total=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    if log_exit_ip:
        exit_ip = get_tor_exit_ip(session)
        if exit_ip:
            print(f"\n{'=' * 50}")
            print(f"[+][Tor] TOR SESSION ACTIVE")
            print(f"{'=' * 50}")
            print(f"[*][Tor] Exit IP (what targets see): {exit_ip}")
            print(f"[*][Tor] Your real IP: HIDDEN")
            print(f"{'=' * 50}\n")
        else:
            print("[!][Tor] Tor session created but could not verify exit IP")

    return session


class TorProxy:
    """
    Context manager for Tor-proxied requests.

    Usage:
        with TorProxy() as session:
            response = session.get("https://example.com")
    """

    def __init__(self, verify_connection: bool = True, log_exit_ip: bool = True):
        self.verify = verify_connection
        self.log_exit_ip = log_exit_ip
        self.session = None
        self.exit_ip = None

    def __enter__(self) -> Optional['requests.Session']:
        self.session = get_tor_session(log_exit_ip=self.log_exit_ip)

        if self.session and self.verify:
            self.exit_ip = get_tor_exit_ip(self.session)
            if not self.exit_ip:
                print("[!][Tor] Warning: Could not verify Tor connection")

        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.close()
        return False

    def get_exit_ip(self) -> Optional[str]:
        return self.exit_ip


# ============================================================================
# Proxychains Subprocess Wrapper
# ============================================================================

def run_through_tor(command: list, timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Run a command through proxychains/Tor.

    Args:
        command: Command and arguments as list.
        timeout: Timeout in seconds.

    Returns:
        CompletedProcess result.
    """
    proxychains = get_proxychains_cmd()

    if not proxychains:
        raise RuntimeError(
            "proxychains not found. Install with: sudo apt install proxychains4"
        )

    if not is_tor_running():
        raise RuntimeError(
            "Tor is not running. Start with: sudo systemctl start tor"
        )

    full_command = [proxychains, "-q"] + command

    print(f"[*][Tor] Running through Tor: {' '.join(command)}")

    return subprocess.run(
        full_command,
        capture_output=True,
        text=True,
        timeout=timeout
    )


def run_command_anonymous(command: list, timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Run a command anonymously, trying proxychains first.
    Falls back to direct execution with warning if Tor not available.
    """
    if is_proxychains_available() and is_tor_running():
        return run_through_tor(command, timeout)
    else:
        print("[!][Tor] Warning: Running without Tor anonymization")
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

# ============================================================================
# Utility Functions
# ============================================================================

def get_real_ip() -> Optional[str]:
    """Get your real public IP address (not through Tor)."""
    if requests is None:
        return None
    try:
        resp = requests.get(FALLBACK_CHECK_URL, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("ip")
    except Exception:
        pass
    return None


def print_anonymity_status():
    """Print current anonymity configuration status."""
    print("\n" + "=" * 50)
    print("[*][Tor] ANONYMITY STATUS")
    print("=" * 50)

    # Check Tor
    tor_status = "Running" if is_tor_running() else "Not running"
    print(f"[*][Tor] Tor Service:      {tor_status}")

    # Check proxychains
    pc_status = "Available" if is_proxychains_available() else "Not installed"
    print(f"[*][Tor] Proxychains:      {pc_status}")

    # Get and display IPs
    print("\n" + "-" * 50)
    print("[*][Tor] IP ADDRESSES")
    print("-" * 50)

    real_ip = get_real_ip()
    if real_ip:
        print(f"[*][Tor] Your Real IP:     {real_ip}")
    else:
        print("[*][Tor] Your Real IP:     Could not determine")

    # Check Tor exit IP
    if is_tor_running():
        session = get_tor_session(log_exit_ip=False)
        if session:
            exit_ip = get_tor_exit_ip(session)
            session.close()
            if exit_ip:
                print(f"[+][Tor] Tor Exit IP:      {exit_ip} <- Targets see this!")
                print(f"\n[+][Tor] Tor is working! Your real IP is hidden.")
            else:
                print("[*][Tor] Tor Exit IP:      Could not verify")
                print(f"\n[!][Tor] WARNING: Tor running but could not verify connection")
    else:
        print("[*][Tor] Tor Exit IP:      N/A (Tor not running)")
        print(f"\n[!][Tor] WARNING: Your real IP is EXPOSED!")
        print("[*][Tor] Start Tor with: sudo systemctl start tor")

    print("=" * 50 + "\n")


def require_tor(func):
    """Decorator to ensure Tor is running before executing a function."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not is_tor_running():
            raise RuntimeError(
                "Tor is required but not running. "
                "Start with: sudo systemctl start tor"
            )
        return func(*args, **kwargs)
    return wrapper


# ============================================================================
# Main (for testing)
# ============================================================================

if __name__ == "__main__":
    print_anonymity_status()

    if is_tor_running():
        print(f"\n[*][Tor] Testing Tor connection...")
        with TorProxy(log_exit_ip=False) as session:
            if session:
                try:
                    resp = session.get("https://httpbin.org/ip", timeout=15)
                    print(f"[+][Tor] httpbin.org sees IP: {resp.json().get('origin')}")
                except Exception as e:
                    print(f"[!][Tor] Test failed: {e}")
    else:
        print(f"\n[*][Tor] To enable Tor anonymity:")
        print("[*][Tor]    sudo apt install tor proxychains4")
        print("[*][Tor]    sudo systemctl start tor")

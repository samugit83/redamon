#!/usr/bin/env python3
"""
MCP Server Runner - Launches all MCP servers for RedAmon Agentic AI

This script starts all MCP servers (naabu, nuclei, curl, metasploit) either
in stdio mode (for direct integration) or SSE mode (for network access).

Usage:
    python run_servers.py              # Run in SSE mode (default for container)
    python run_servers.py --stdio      # Run single server in stdio mode
    python run_servers.py --server naabu --stdio  # Run specific server
"""

import os
import sys
import signal
import logging
import time
from multiprocessing import Process
from typing import Dict

# =============================================================================
# METASPLOIT TIMING CONFIGURATION
# =============================================================================
# Timing for different Metasploit command types (timeout, quiet_period) in seconds
#
# - timeout: Maximum total wait time before giving up
# - quiet_period: Time of silence (no output) before assuming command completed
#
# When command runs, output comes periodically. The quiet_period timer resets
# on each output line. When no output for quiet_period seconds, we return.

# Brute force attacks (run command) - SSH login attempts
# With VERBOSE=true, output comes for each attempt, so shorter quiet period is fine
MSF_RUN_TIMEOUT = 1800      # 30 minutes total timeout
MSF_RUN_QUIET_PERIOD = 60  # 2min period (with VERBOSE=true)

# CVE exploits (exploit command) - staged payloads may have delays
MSF_EXPLOIT_TIMEOUT = 600   # 10 minutes total timeout
MSF_EXPLOIT_QUIET_PERIOD = 60  # 2min quiet period

# Other commands (search, sessions, show, info, etc.)
MSF_DEFAULT_TIMEOUT = 180   # 3 minutes total timeout
MSF_DEFAULT_QUIET_PERIOD = 5  # 5 seconds quiet period

# =============================================================================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mcp-runner")

# Server configurations
SERVERS = {
    "network_recon": {
        "module": "network_recon_server",
        "port": 8000,
        "description": "HTTP Client & Port Scanner"
    },
    "nuclei": {
        "module": "nuclei_server",
        "port": 8002,
        "description": "Vulnerability Scanner"
    },
    "metasploit": {
        "module": "metasploit_server",
        "port": 8003,
        "description": "Exploitation Framework"
    },
    "nmap": {
        "module": "nmap_server",
        "port": 8004,
        "description": "Network Mapper"
    },
    "playwright": {
        "module": "playwright_server",
        "port": 8005,
        "description": "Browser Automation"
    }
}


def run_server(name: str, config: dict, transport: str = "sse"):
    """Run a single MCP server."""
    import importlib

    logger.info(f"Starting {name} server ({config['description']}) on port {config['port']}")

    # Set environment variables for the server
    os.environ["MCP_TRANSPORT"] = transport
    os.environ[f"{name.upper()}_PORT"] = str(config["port"])

    # Set Metasploit timing configuration
    if name == "metasploit":
        os.environ["MSF_RUN_TIMEOUT"] = str(MSF_RUN_TIMEOUT)
        os.environ["MSF_RUN_QUIET_PERIOD"] = str(MSF_RUN_QUIET_PERIOD)
        os.environ["MSF_EXPLOIT_TIMEOUT"] = str(MSF_EXPLOIT_TIMEOUT)
        os.environ["MSF_EXPLOIT_QUIET_PERIOD"] = str(MSF_EXPLOIT_QUIET_PERIOD)
        os.environ["MSF_DEFAULT_TIMEOUT"] = str(MSF_DEFAULT_TIMEOUT)
        os.environ["MSF_DEFAULT_QUIET_PERIOD"] = str(MSF_DEFAULT_QUIET_PERIOD)

    try:
        # Import and run the server module
        module = importlib.import_module(config["module"])

        if transport == "sse":
            # Start progress server for metasploit (for live progress updates)
            if name == "metasploit" and hasattr(module, 'start_progress_server'):
                progress_port = int(os.getenv("MSF_PROGRESS_PORT", "8013"))
                module.start_progress_server(progress_port)
                logger.info(f"Started metasploit progress server on port {progress_port}")

            # Start progress server for network_recon (for Hydra live progress updates)
            if name == "network_recon" and hasattr(module, 'start_hydra_progress_server'):
                hydra_progress_port = int(os.getenv("HYDRA_PROGRESS_PORT", "8014"))
                module.start_hydra_progress_server(hydra_progress_port)
                logger.info(f"Started Hydra progress server on port {hydra_progress_port}")

            module.mcp.run(
                transport="sse",
                host="0.0.0.0",
                port=config["port"]
            )
        else:
            module.mcp.run(transport="stdio")

    except Exception as e:
        logger.error(f"Error starting {name} server: {e}")
        raise


def run_all_servers_sse():
    """
    Run all MCP servers in SSE mode, with supervision.

    Each server runs in its own child process. If a server crashes (seen
    previously with network_recon dying under heavy fireteam concurrency and
    leaving port 8000 refusing connections while the container stayed "up"
    and other ports kept serving), the supervisor detects the dead child
    and respawns it. No more manual `docker compose restart kali-sandbox`.
    """
    processes: Dict[str, Process] = {}
    restart_counts: Dict[str, int] = {name: 0 for name in SERVERS}
    parent_pid = os.getpid()
    shutting_down = False

    def spawn(name: str, config: dict) -> Process:
        p = Process(target=run_server, args=(name, config, "sse"), name=f"mcp-{name}")
        p.start()
        processes[name] = p
        logger.info(f"Started {name} server (PID: {p.pid}, port {config['port']})")
        return p

    def shutdown(signum, frame):
        nonlocal shutting_down
        # Guard: when uvicorn inside a child process catches SIGTERM and
        # re-raises it, Python invokes our inherited handler in the CHILD,
        # where `processes[]` holds Process objects whose _parent_pid is
        # the original parent — calling is_alive() from a non-parent asserts.
        # If we're not the supervisor, just exit cleanly.
        if os.getpid() != parent_pid:
            sys.exit(0)
            return
        shutting_down = True
        logger.info("Shutting down all MCP servers...")
        for p in processes.values():
            try:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=5)
            except Exception as e:
                logger.warning(f"Error terminating {p.name}: {e}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    for name, config in SERVERS.items():
        spawn(name, config)

    logger.info("All MCP servers started successfully")
    logger.info("Servers available at:")
    for name, config in SERVERS.items():
        logger.info(f"  - {name}: http://0.0.0.0:{config['port']}")

    # Supervision loop. A crashed child is detected and respawned on the
    # next 5-second poll. restart_counts is logged so operators can see
    # churn (repeated crashes are a symptom of a bug in the server module
    # itself — this supervisor doesn't fix bugs, it just prevents a single
    # crash from taking the whole agent down).
    SUPERVISION_POLL_SEC = 5
    try:
        while not shutting_down:
            time.sleep(SUPERVISION_POLL_SEC)
            if shutting_down:
                break
            for name in list(processes.keys()):
                p = processes[name]
                if p.is_alive():
                    continue
                restart_counts[name] += 1
                exit_code = p.exitcode
                logger.error(
                    f"[supervisor] MCP server '{name}' died "
                    f"(pid={p.pid}, exitcode={exit_code}); respawning "
                    f"(restart #{restart_counts[name]})"
                )
                try:
                    spawn(name, SERVERS[name])
                except Exception as e:
                    logger.error(f"[supervisor] failed to respawn '{name}': {e}")
    except KeyboardInterrupt:
        shutdown(None, None)


def run_single_server_stdio(server_name: str):
    """Run a single server in stdio mode."""
    if server_name not in SERVERS:
        logger.error(f"Unknown server: {server_name}")
        logger.info(f"Available servers: {', '.join(SERVERS.keys())}")
        sys.exit(1)

    config = SERVERS[server_name]
    run_server(server_name, config, "stdio")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="RedAmon MCP Server Runner"
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run in stdio mode (for direct MCP integration)"
    )
    parser.add_argument(
        "--server",
        choices=list(SERVERS.keys()),
        help="Specific server to run (required for stdio mode)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available servers"
    )

    args = parser.parse_args()

    if args.list:
        print("Available MCP Servers:")
        for name, config in SERVERS.items():
            print(f"  - {name}: {config['description']} (port {config['port']})")
        sys.exit(0)

    if args.stdio:
        if not args.server:
            logger.error("--server is required when using --stdio mode")
            sys.exit(1)
        run_single_server_stdio(args.server)
    else:
        # Default: run all servers in SSE mode
        run_all_servers_sse()


if __name__ == "__main__":
    main()

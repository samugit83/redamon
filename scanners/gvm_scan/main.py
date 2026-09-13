#!/usr/bin/env python3
"""
RedAmon - Vulnerability Scanner Main Entry Point
=================================================
Orchestrates GVM/OpenVAS vulnerability scanning using recon data.

Reads targets from recon JSON files and runs vulnerability scans
against discovered IPs and hostnames using GVM.

Usage:
    # From project root (with GVM running in Docker):
    python gvm_scan/main.py

    # Or run via Docker Compose:
    docker compose --profile scanner up python-scanner
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Runtime parameters from environment variables (set by orchestrator)
PROJECT_ID = os.environ.get("PROJECT_ID", "")
USER_ID = os.environ.get("USER_ID", "")
TARGET_DOMAIN = os.environ.get("TARGET_DOMAIN", "")

# GVM project settings (fetched from webapp API or defaults)
try:
    from gvm_scan.project_settings import get_setting, load_project_settings
except ImportError:
    from project_settings import get_setting, load_project_settings

from gvm_scan.gvm_scanner import (
    GVMScanner,
    extract_targets_from_recon,
    load_recon_file,
    save_vuln_results,
    update_graph_from_gvm_results,
    GVM_AVAILABLE,
)


# Output directory for vulnerability results
OUTPUT_DIR = Path(__file__).parent / "output"

# A STACK-level fault (no scanner running, gvmd unreachable) fails every target
# identically, so walking the whole list only multiplies the wait: 1140 targets
# took 18 hours to get four IPs into a scan that could never have worked (issue
# #174). Stop once the failures are plainly not target-specific.
MAX_CONSECUTIVE_TARGET_FAILURES = 3


class ScanAborted(RuntimeError):
    """The stack, not the target, is broken - continuing cannot help."""


def check_failure_streak(result: dict, streak: int, target: str) -> int:
    """Count consecutive failed targets, aborting the scan when they pile up.

    Returns the updated streak (0 after any target that worked).
    """
    if result.get("status") != "error":
        return 0

    streak += 1
    if streak >= MAX_CONSECUTIVE_TARGET_FAILURES:
        raise ScanAborted(
            f"Aborting after {streak} consecutive failed targets (last: {target} - "
            f"{result.get('error', 'no detail')}). Failing on every target means the "
            f"GVM stack is broken, not the targets: check that redamon-gvm-ospd is "
            f"running and that its feed loader redamon-gvm-vt completed."
        )
    return streak


def check_recon_has_live_targets(recon_data: dict) -> tuple:
    """
    Check if recon data indicates any reachable/live targets.
    
    GVM can scan network-level vulnerabilities (SSH, FTP, etc.), not just HTTP.
    However, if both port_scan AND http_probe found nothing, hosts are likely 
    completely unreachable and GVM will also fail.
    
    Args:
        recon_data: Reconnaissance data from recon/main.py
        
    Returns:
        Tuple of (has_live_targets: bool, warning_message: str or None)
    """
    # Check port_scan results
    port_scan_data = recon_data.get('port_scan', {})
    port_summary = port_scan_data.get('summary', {})
    open_ports = port_summary.get('total_open_ports', 0)
    
    # Check http_probe results
    http_probe_data = recon_data.get('http_probe', {})
    http_summary = http_probe_data.get('summary', {})
    live_urls = http_summary.get('live_urls', 0)
    
    # Check if active scans were already skipped in recon pipeline
    active_scans_skipped = recon_data.get('metadata', {}).get('active_scans_skipped', False)
    
    # Case 1: Both port_scan and http_probe ran but found nothing
    port_scan_ran = 'port_scan' in recon_data
    http_probe_ran = 'http_probe' in recon_data
    
    if port_scan_ran and http_probe_ran:
        if open_ports == 0 and live_urls == 0:
            return False, (
                "No open ports and no live HTTP services found in recon data. "
                "Targets appear to be unreachable or heavily firewalled."
            )
    
    # Case 2: Only http_probe ran and found nothing (port_scan might have been skipped)
    if http_probe_ran and not port_scan_ran:
        if live_urls == 0:
            return False, (
                "No live HTTP services found in recon data. "
                "Port scan was not performed - GVM may still find vulnerabilities."
            )
    
    # Case 3: Active scans were skipped in recon pipeline
    if active_scans_skipped:
        return False, (
            "Active scans (resource_enum, vuln_scan) were skipped in recon pipeline. "
            "No live targets were found."
        )
    
    # Targets seem reachable
    return True, None


def run_vulnerability_scan(
    domain: str = TARGET_DOMAIN,
    project_id: str = PROJECT_ID,
) -> dict:
    """
    Run vulnerability scan against targets from recon data.

    Args:
        domain: Target domain for display purposes
        project_id: Project ID (reads from recon_<project_id>.json)

    Returns:
        Complete vulnerability scan results
    """
    # Read scan settings from project settings (fetched from webapp API)
    scan_config = get_setting('SCAN_CONFIG', 'Full and fast')
    scan_targets = get_setting('SCAN_TARGETS', 'both')
    task_timeout = get_setting('TASK_TIMEOUT', 14400)
    poll_interval = get_setting('POLL_INTERVAL', 30)
    no_progress_timeout = get_setting('NO_PROGRESS_TIMEOUT', 1800)
    cleanup = get_setting('CLEANUP_AFTER_SCAN', True)

    print("\n" + "=" * 70)
    print("           RedAmon - GVM Vulnerability Scanner")
    print("=" * 70)
    print(f"  Target Domain: {domain}")
    print(f"  Scan Config:   {scan_config}")
    print(f"  Scan Strategy: {scan_targets}")
    print(f"  Task Timeout:  {task_timeout}s")
    print(f"  Poll Interval: {poll_interval}s")
    print(f"  Stall Limit:   {no_progress_timeout}s (no-progress watchdog)")
    print(f"  Cleanup After: {cleanup}")
    print("=" * 70 + "\n")

    # Check if GVM library is available
    if not GVM_AVAILABLE:
        print("[!] ERROR: python-gvm library not installed")
        print("[!] Install with: pip install python-gvm")
        return {"error": "python-gvm not installed"}

    # Load recon data (required - GVM scan always uses recon output)
    root_domain = domain  # Default to input domain

    print("[*] Loading recon data...")
    try:
        recon_data = load_recon_file(project_id)
        # Get root_domain from recon metadata (consistent with recon/main.py)
        root_domain = recon_data.get("metadata", {}).get("root_domain", domain)
        print(f"    [+] Loaded: recon_{project_id}.json")
        print(f"    [+] Root domain: {root_domain}")
    except FileNotFoundError as e:
        print(f"[!] ERROR: {e}")
        print(f"[!] Run domain recon first: python recon/main.py")
        return {"error": str(e)}

    # Check if recon data indicates reachable targets
    has_live_targets, warning_message = check_recon_has_live_targets(recon_data)

    if not has_live_targets:
        print(f"\n{'=' * 70}")
        print(f"[!] SKIPPING GVM SCAN: {warning_message}")
        print(f"{'=' * 70}")
        return {
            "error": "No live targets",
            "reason": warning_message,
            "skipped": True,
            "metadata": {
                "scan_type": "vulnerability_scan",
                "scan_timestamp": datetime.now().isoformat(),
                "target_domain": root_domain,
                "skipped_reason": warning_message
            }
        }

    # Clear previous GVM graph data for this project
    if project_id and USER_ID:
        print("[*] Clearing previous GVM graph data...")
        try:
            from graph_db import Neo4jClient
            from graph_db.mixins.base_mixin import run_timestamp
            # X7: taken BEFORE the ingest, so everything this scan writes has a
            # later `updated_at` and survives the prune at the end.
            global _GVM_RUN_STARTED_AT
            _GVM_RUN_STARTED_AT = run_timestamp()
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    clear_stats = graph_client.clear_gvm_data(USER_ID, project_id)
                    total = (clear_stats["vulnerabilities_deleted"] +
                             clear_stats["technologies_deleted"] +
                             clear_stats["cves_deleted"])
                    print(f"    [+] Cleared: {total} GVM nodes removed, "
                          f"{clear_stats['technologies_cleaned']} shared technologies cleaned")
                else:
                    print("    [!] Could not connect to Neo4j - skipping clear")
        except Exception as e:
            print(f"    [!] Failed to clear GVM data (continuing): {e}")

    # Extract targets from recon
    ips, hostnames = extract_targets_from_recon(recon_data)

    print(f"    [+] Found {len(ips)} unique IPs")
    print(f"    [+] Found {len(hostnames)} unique hostnames")

    if not ips and not hostnames:
        print("[!] No targets found in recon data")
        return {"error": "No targets found"}

    # Initialize results structure (use root_domain from recon metadata)
    results = {
        "metadata": {
            "scan_type": "vulnerability_scan",
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": root_domain,
            "scan_strategy": scan_targets,
            "recon_file": f"recon_{project_id}.json",
            "targets": {
                "ips": list(ips),
                "hostnames": list(hostnames)
            }
        },
        "scans": [],
        "summary": {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "log": 0,
            "hosts_scanned": 0,
        }
    }
    
    # Connect to GVM
    print("\n[*] Connecting to GVM...")
    scanner = GVMScanner()
    
    if not scanner.connect():
        print("[!] ERROR: Failed to connect to GVM")
        print("[!] Make sure GVM is running:")
        print("[!]   docker compose up -d")
        print("[!]   docker compose logs -f gvmd  # Wait for 'Starting GVMd'")
        return {"error": "Failed to connect to GVM"}
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"gvm_{project_id}.json"
    
    def save_incremental():
        """Save current results incrementally."""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    try:
        # =====================================================================
        # PHASE 1: Scan IPs (one at a time for incremental saving)
        # =====================================================================
        if scan_targets in ("both", "ips_only") and ips:
            ip_list = list(ips)
            print(f"\n[*] PHASE 1: Scanning {len(ip_list)} IP addresses (individually)...")
            print("-" * 50)
            
            failure_streak = 0
            for i, ip in enumerate(ip_list, 1):
                print(f"\n[*] IP {i}/{len(ip_list)}: {ip}")
                
                ip_results = scanner.scan_targets(
                    targets=[ip],
                    target_name=f"IP_{ip.replace('.', '_')}",
                    cleanup=cleanup
                )
                ip_results["scan_type"] = "ip_scan"
                ip_results["target_ip"] = ip
                results["scans"].append(ip_results)
                
                # Update summary
                if "severity_summary" in ip_results:
                    for sev, count in ip_results["severity_summary"].items():
                        results["summary"][sev] += count
                results["summary"]["total_vulnerabilities"] += ip_results.get("vulnerability_count", 0)
                results["summary"]["hosts_scanned"] += ip_results.get("hosts_scanned", 0)
                
                # Save after each IP
                save_incremental()
                print(f"    [+] Progress saved to {output_file}")

                failure_streak = check_failure_streak(ip_results, failure_streak, ip)
        
        # =====================================================================
        # PHASE 2: Scan Hostnames (one at a time for incremental saving)
        # Reconnect to GVM to avoid stale socket after long Phase 1 scans
        # =====================================================================
        if scan_targets in ("both", "hostnames_only") and hostnames:
            if scan_targets == "both" and ips:
                print("\n[*] Reconnecting to GVM before Phase 2...")
                scanner.disconnect()
                time.sleep(30)  # Give GVM time to release resources
                if not scanner.connect(max_retries=10, retry_interval=15):
                    raise RuntimeError("Failed to reconnect to GVM before Phase 2")
            hostname_list = list(hostnames)
            print(f"\n[*] PHASE 2: Scanning {len(hostname_list)} hostnames (individually)...")
            print("-" * 50)
            
            failure_streak = 0
            for i, hostname in enumerate(hostname_list, 1):
                print(f"\n[*] Hostname {i}/{len(hostname_list)}: {hostname}")
                
                hostname_results = scanner.scan_targets(
                    targets=[hostname],
                    target_name=f"Host_{hostname.replace('.', '_')}",
                    cleanup=cleanup
                )
                hostname_results["scan_type"] = "hostname_scan"
                hostname_results["target_hostname"] = hostname
                results["scans"].append(hostname_results)
                
                # Update summary
                if "severity_summary" in hostname_results:
                    for sev, count in hostname_results["severity_summary"].items():
                        results["summary"][sev] += count
                results["summary"]["total_vulnerabilities"] += hostname_results.get("vulnerability_count", 0)
                results["summary"]["hosts_scanned"] += hostname_results.get("hosts_scanned", 0)

                # Save after each hostname
                save_incremental()
                print(f"    [+] Progress saved to {output_file}")

                failure_streak = check_failure_streak(hostname_results, failure_streak, hostname)
        
        # Final save
        save_vuln_results(results, project_id)

    except ScanAborted as e:
        # Not an error path to hide: report it, keep the partial findings, and
        # fall through to the normal summary/graph update below.
        print(f"\n[!] {e}")
        results["aborted"] = str(e)
        save_vuln_results(results, project_id)

    finally:
        scanner.disconnect()
    
    # Print summary
    summary = results["summary"]
    print(f"\n{'=' * 70}")
    print(f"[+] VULNERABILITY SCAN COMPLETE")
    print(f"[+] Domain: {root_domain}")
    print(f"[+] Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"    • Critical: {summary['critical']}")
    print(f"    • High: {summary['high']}")
    print(f"    • Medium: {summary['medium']}")
    print(f"    • Low: {summary['low']}")
    print(f"    • Log: {summary['log']}")
    print(f"[+] Hosts scanned: {summary['hosts_scanned']}")
    print(f"[+] Output: {output_file}")
    print(f"{'=' * 70}")

    # Update Neo4j graph with GVM results
    graph_stats = update_graph_from_gvm_results(results)
    if "error" not in graph_stats:
        results["graph_update"] = graph_stats
        _prune_gvm_findings(graph_stats, project_id)

    return results


#: When this GVM run started, for the prune. Set by the clear, and absent when
#: the clear never ran, which is what stops a failed run pruning anything.
_GVM_RUN_STARTED_AT = None


def _prune_gvm_findings(graph_stats, project_id):
    """Remove the GVM findings this scan stopped reporting (X7).

    Only after an ingest that actually wrote something: a GVM run that produced
    no vulnerabilities is far more often a scan that failed than a target that
    became clean, and pruning on it would empty the project's GVM findings.

    Findings an operator muted or judged are kept and stamped stale rather than
    deleted, so their decision survives.
    """
    if not _GVM_RUN_STARTED_AT or not project_id or not USER_ID:
        return
    if not graph_stats.get("vulnerabilities_created"):
        return
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                graph_client.prune_unseen_findings(
                    USER_ID, project_id, ["gvm"], _GVM_RUN_STARTED_AT)
    except Exception as e:
        # Housekeeping must never fail a completed scan.
        print(f"    [!] Could not prune stale GVM findings: {e}")


def main():
    """Main entry point."""

    if not PROJECT_ID:
        print("[!] ERROR: PROJECT_ID environment variable not set")
        return 1

    # Load per-project settings from webapp API (or use defaults)
    load_project_settings(PROJECT_ID)

    # Run the scan
    start_time = datetime.now()

    try:
        results = run_vulnerability_scan(
            domain=TARGET_DOMAIN,
            project_id=PROJECT_ID,
        )
        
        if "error" in results:
            print(f"\n[!] Scan failed: {results['error']}")
            return 1
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        raise
    
    # Print duration
    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Total scan time: {duration:.2f} seconds")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())


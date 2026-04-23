#!/usr/bin/env python3
"""
RedAmon - TruffleHog Secret Scanner Main Entry Point
======================================================
Orchestrates TruffleHog deep secret scanning using project settings from the webapp API.

Uses TruffleHog's 700+ secret detectors with optional credential verification
to scan GitHub repositories for exposed secrets, API keys, and credentials.

Usage:
    # Run via Docker (managed by recon orchestrator):
    # Container receives PROJECT_ID and WEBAPP_API_URL as environment variables

    # Or run standalone:
    PROJECT_ID=xxx WEBAPP_API_URL=http://localhost:3000 python trufflehog_scan/main.py
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Runtime parameters from environment variables (set by orchestrator)
PROJECT_ID = os.environ.get("PROJECT_ID", "")

# TruffleHog project settings (fetched from webapp API or defaults)
try:
    from trufflehog_scan.project_settings import get_setting, load_project_settings
except ImportError:
    from project_settings import get_setting, load_project_settings

try:
    from trufflehog_scan.trufflehog_runner import TrufflehogRunner
except ImportError:
    from trufflehog_runner import TrufflehogRunner


def run_trufflehog_scan(project_id: str) -> dict:
    """
    Run TruffleHog secret scanning with settings from the webapp API.

    Args:
        project_id: Project ID for output file naming and settings lookup

    Returns:
        Dictionary with scan results or error info
    """
    # Read scan settings from project settings (fetched from webapp API)
    token = get_setting('GITHUB_ACCESS_TOKEN', '')
    target_org = get_setting('TRUFFLEHOG_GITHUB_ORG', '')
    target_repos = get_setting('TRUFFLEHOG_GITHUB_REPOS', '')
    only_verified = get_setting('TRUFFLEHOG_ONLY_VERIFIED', False)
    no_verification = get_setting('TRUFFLEHOG_NO_VERIFICATION', False)
    concurrency = get_setting('TRUFFLEHOG_CONCURRENCY', 8)
    include_detectors = get_setting('TRUFFLEHOG_INCLUDE_DETECTORS', '')
    exclude_detectors = get_setting('TRUFFLEHOG_EXCLUDE_DETECTORS', '')

    print("\n" + "=" * 70)
    print("           RedAmon - TruffleHog Secret Scanner")
    print("=" * 70)
    print(f"  Target Org:          {target_org or '(not set)'}")
    print(f"  Target Repos:        {target_repos or '(not set)'}")
    print(f"  Only Verified:       {only_verified}")
    print(f"  Skip Verification:   {no_verification}")
    print(f"  Concurrency:         {concurrency}")
    print(f"  Include Detectors:   {include_detectors or '(all)'}")
    print(f"  Exclude Detectors:   {exclude_detectors or '(none)'}")
    print("=" * 70 + "\n")

    # Validate required settings
    if not token:
        print("[!] ERROR: GitHub access token not configured")
        print("[!] Set it in the project settings (Other Scans → GitHub Secret Hunting)")
        return {"error": "GitHub access token not configured"}

    if not target_org and not target_repos:
        print("[!] ERROR: No scan target configured (need org or repos)")
        print("[!] Set target org or repos in project settings (Other Scans → TruffleHog)")
        return {"error": "No scan target configured (set org or repos)"}

    # Run the scanner
    print("[*] Initializing TruffleHog Scanner...")
    runner = TrufflehogRunner(
        token=token,
        target_org=target_org,
        target_repos=target_repos,
        project_id=project_id,
        only_verified=only_verified,
        no_verification=no_verification,
        concurrency=concurrency,
        include_detectors=include_detectors,
        exclude_detectors=exclude_detectors,
    )

    findings = runner.run()

    # Print scan summary
    print("\n" + "=" * 70)
    print("                    SCAN SUMMARY")
    print("=" * 70)
    print(f"  Total findings:      {runner.stats['total_findings']}")
    print(f"  Verified:            {runner.stats['verified_findings']}")
    print(f"  Unverified:          {runner.stats['unverified_findings']}")
    print(f"  Repos scanned:       {runner.stats['repositories_scanned']}")
    if runner.stats['detector_types']:
        print(f"  Detector breakdown:")
        for det, count in sorted(runner.stats['detector_types'].items(), key=lambda x: -x[1]):
            print(f"    {det}: {count}")
    print("=" * 70 + "\n")

    # Update Neo4j graph database with findings
    user_id = os.environ.get("USER_ID", "")
    if runner.output_file and Path(runner.output_file).exists():
        try:
            from graph_db import Neo4jClient

            with open(runner.output_file, 'r') as f:
                trufflehog_data = json.load(f)

            print("\n" + "=" * 50)
            print("[*] Updating Neo4j graph with TruffleHog results...")
            print("=" * 50)

            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_stats = graph_client.update_graph_from_trufflehog(
                        trufflehog_data, user_id, project_id
                    )
                    print(f"[+] Graph database updated successfully")
                else:
                    print("[!] Could not connect to Neo4j - skipping graph update")
        except ImportError:
            print("[!] Neo4j client not available - skipping graph update")
        except Exception as e:
            print(f"[!] Graph DB update failed (non-fatal): {e}")

    return {
        "target": target_org or target_repos,
        "findings_count": len(findings),
        "statistics": runner.stats,
        "output_file": str(runner.output_file),
    }


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
        results = run_trufflehog_scan(project_id=PROJECT_ID)

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

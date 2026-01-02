#!/usr/bin/env python3
"""
RedAmon - Main Reconnaissance Controller
=========================================
Orchestrates all OSINT reconnaissance modules:
1. WHOIS lookup (integrated into domain recon JSON)
2. Subdomain discovery & DNS resolution
3. Port scanning (fast, lightweight)
4. HTTP probing & technology detection
5. Vulnerability scanning + MITRE CWE/CAPEC enrichment
6. GitHub secret hunting (separate JSON output)

Pipeline: domain_discovery -> port_scan -> http_probe -> vuln_scan -> github

Note: vuln_scan automatically includes MITRE CWE/CAPEC enrichment for all CVEs.

Run this file to execute the full recon pipeline.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
import tldextract

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    TARGET_DOMAIN,
    SUBDOMAIN_LIST,
    USE_TOR_FOR_RECON,
    USE_BRUTEFORCE_FOR_SUBDOMAINS,
    SCAN_MODULES,
    GITHUB_ACCESS_TOKEN,
    GITHUB_TARGET_ORG,
    UPDATE_GRAPH_DB,
    USER_ID,
    PROJECT_ID,
)

# Import recon modules
from recon.whois_recon import whois_lookup
from recon.domain_recon import discover_subdomains
from recon.github_secret_hunt import GitHubSecretHunter
from recon.port_scan import run_port_scan
from recon.http_probe import run_http_probe
from recon.vuln_scan import run_vuln_scan
from recon.add_mitre import run_mitre_enrichment

# Output directory
OUTPUT_DIR = Path(__file__).parent / "output"


def parse_target(target: str, subdomain_list: list = None) -> dict:
    """
    Parse target domain and determine scan mode based on SUBDOMAIN_LIST.

    Args:
        target: Root domain (e.g., "example.com", "vulnweb.com")
        subdomain_list: List of subdomain prefixes to filter (e.g., ["testphp.", "www."])
                       Empty list = full discovery mode (scan all subdomains)

    Returns:
        Dictionary with:
        - target: original target (root domain)
        - root_domain: the root domain (e.g., "example.com")
        - filtered_mode: True if SUBDOMAIN_LIST has entries (filtered scan)
        - subdomain_list: list of subdomain prefixes to scan
        - full_subdomains: list of full subdomain names (prefix + root domain)
    """
    extracted = tldextract.extract(target)
    root_domain = f"{extracted.domain}.{extracted.suffix}"

    # Determine if we're in filtered mode (SUBDOMAIN_LIST has entries)
    subdomain_list = subdomain_list or []
    filtered_mode = len(subdomain_list) > 0

    # Build full subdomain names from prefixes
    full_subdomains = []
    if filtered_mode:
        for prefix in subdomain_list:
            # Handle both "testphp." and "testphp" formats
            clean_prefix = prefix.rstrip('.')
            full_subdomain = f"{clean_prefix}.{root_domain}"
            full_subdomains.append(full_subdomain)

    return {
        "target": target,
        "root_domain": root_domain,
        "filtered_mode": filtered_mode,
        "subdomain_list": subdomain_list,
        "full_subdomains": full_subdomains
    }


def build_scan_type() -> str:
    """Build dynamic scan type based on enabled modules."""
    modules = []
    if "domain_discovery" in SCAN_MODULES:
        modules.append("domain_discovery")
    if "port_scan" in SCAN_MODULES:
        modules.append("port_scan")
    if "http_probe" in SCAN_MODULES:
        modules.append("http_probe")
    if "vuln_scan" in SCAN_MODULES:
        modules.append("vuln_scan")
    if "github" in SCAN_MODULES:
        modules.append("github")
    return "_".join(modules) if modules else "custom"


def save_recon_file(data: dict, output_file: Path):
    """Save recon data to JSON file."""
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)


def run_domain_recon(target: str, anonymous: bool = False, bruteforce: bool = False,
                     target_info: dict = None) -> dict:
    """
    Run combined WHOIS + subdomain discovery + DNS resolution.
    Produces a single unified JSON file with incremental saves.

    Scan modes based on SUBDOMAIN_LIST:
    - Empty list []: Full subdomain discovery (discover and scan all subdomains)
    - With entries ["testphp.", "www."]: Filtered mode (only scan specified subdomains)

    Args:
        target: Root domain (e.g., "vulnweb.com", "example.com")
        anonymous: Use Tor to hide real IP
        bruteforce: Enable Knockpy bruteforce mode (only for full discovery mode)
        target_info: Parsed target info from parse_target()

    Returns:
        Complete reconnaissance data including WHOIS and subdomains
    """
    # Parse target if not provided
    if target_info is None:
        target_info = parse_target(target, SUBDOMAIN_LIST)

    filtered_mode = target_info["filtered_mode"]
    root_domain = target_info["root_domain"]
    full_subdomains = target_info["full_subdomains"]

    print("\n" + "=" * 70)
    print("               RedAmon - Domain Reconnaissance")
    print("=" * 70)
    print(f"  Target: {root_domain}")
    if filtered_mode:
        print(f"  Mode: FILTERED SUBDOMAIN SCAN")
        print(f"  Subdomains: {', '.join(full_subdomains)}")
    else:
        print(f"  Mode: FULL DISCOVERY (all subdomains)")
    print(f"  Anonymous Mode: {anonymous}")
    if not filtered_mode:
        print(f"  Bruteforce Mode: {bruteforce}")
    print("=" * 70 + "\n")

    # Setup output file
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"recon_{root_domain}.json"

    # Initialize result structure with dynamic scan_type and empty modules_executed
    combined_result = {
        "metadata": {
            "scan_type": build_scan_type(),
            "scan_timestamp": datetime.now().isoformat(),
            "target": root_domain,
            "root_domain": root_domain,
            "filtered_mode": filtered_mode,
            "subdomain_filter": full_subdomains if filtered_mode else [],
            "anonymous_mode": anonymous,
            "bruteforce_mode": bruteforce if not filtered_mode else False,
            "modules_executed": []
        },
        "domain": root_domain,
        "whois": {},
        "subdomains": [],
        "subdomain_count": 0,
        "dns": {}
    }

    # Step 1: WHOIS lookup (always on root domain)
    print("[PHASE 1] WHOIS Lookup")
    print("-" * 40)
    whois_target = root_domain
    print(f"[*] Performing WHOIS on root domain: {whois_target}")
    try:
        whois_result = whois_lookup(whois_target, save_output=False)
        combined_result["whois"] = whois_result.get("whois_data", {})
        print(f"[+] WHOIS data retrieved successfully")
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        combined_result["whois"] = {"error": str(e)}

    combined_result["metadata"]["modules_executed"].append("whois")
    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")

    # Step 2: Subdomain discovery & DNS resolution
    if filtered_mode:
        # FILTERED MODE: Only scan the specified subdomains from SUBDOMAIN_LIST
        print(f"\n[PHASE 2] Filtered Subdomain DNS Resolution")
        print("-" * 40)
        print(f"[*] Resolving DNS for {len(full_subdomains)} specified subdomain(s)")

        # Import dns_lookup from domain_recon
        from recon.domain_recon import dns_lookup

        # Resolve each specified subdomain
        subdomains_dns = {}
        for subdomain in full_subdomains:
            print(f"[*] Resolving: {subdomain}")
            subdomain_dns = dns_lookup(subdomain)
            subdomains_dns[subdomain] = subdomain_dns

            if subdomain_dns["ips"]["ipv4"] or subdomain_dns["ips"]["ipv6"]:
                all_ips = subdomain_dns["ips"]["ipv4"] + subdomain_dns["ips"]["ipv6"]
                print(f"[+] {subdomain} -> {', '.join(all_ips)}")
            else:
                print(f"[-] {subdomain}: No DNS records found")

        combined_result["subdomains"] = full_subdomains
        combined_result["subdomain_count"] = len(full_subdomains)
        combined_result["dns"] = {
            "domain": {},  # No root domain DNS in filtered mode
            "subdomains": subdomains_dns
        }

        combined_result["metadata"]["modules_executed"].append("dns_resolution")
    else:
        # FULL DISCOVERY MODE: Discover all subdomains
        print(f"\n[PHASE 2] Subdomain Discovery & DNS Resolution")
        print("-" * 40)
        recon_result = discover_subdomains(
            root_domain,
            anonymous=anonymous,
            bruteforce=bruteforce,
            resolve=True,
            save_output=False
        )

        combined_result["subdomains"] = recon_result.get("subdomains", [])
        combined_result["subdomain_count"] = recon_result.get("subdomain_count", 0)
        combined_result["metadata"]["modules_executed"].append("subdomain_discovery")
        save_recon_file(combined_result, output_file)
        print(f"[+] Saved: {output_file}")

        # Step 3: DNS resolution (already done in discover_subdomains)
        combined_result["dns"] = recon_result.get("dns", {})
        combined_result["metadata"]["modules_executed"].append("dns_resolution")

    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")

    # Update Graph DB after domain_discovery completes
    if UPDATE_GRAPH_DB:
        print(f"\n[PHASE 3] Graph Database Update")
        print("-" * 40)
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    stats = graph_client.update_graph_from_domain_discovery(combined_result, USER_ID, PROJECT_ID)
                    combined_result["metadata"]["graph_db_updated"] = True
                    combined_result["metadata"]["graph_db_stats"] = stats
                    print(f"[+] Graph database updated successfully")
                else:
                    print(f"[!] Could not connect to Neo4j - skipping graph update")
                    combined_result["metadata"]["graph_db_updated"] = False
        except ImportError:
            print(f"[!] Neo4j client not available - skipping graph update")
            combined_result["metadata"]["graph_db_updated"] = False
        except Exception as e:
            print(f"[!] Graph DB update failed: {e}")
            combined_result["metadata"]["graph_db_updated"] = False
            combined_result["metadata"]["graph_db_error"] = str(e)

        save_recon_file(combined_result, output_file)

    # Step 3: Port scanning (fast port discovery)
    if "port_scan" in SCAN_MODULES:
        combined_result = run_port_scan(combined_result, output_file=output_file)
        combined_result["metadata"]["modules_executed"].append("port_scan")
        save_recon_file(combined_result, output_file)

        # Update Graph DB with port scan data
        if UPDATE_GRAPH_DB:
            print(f"\n[GRAPH UPDATE] Port Scan Data")
            print("-" * 40)
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        port_stats = graph_client.update_graph_from_port_scan(combined_result, USER_ID, PROJECT_ID)
                        combined_result["metadata"]["graph_db_port_scan_updated"] = True
                        combined_result["metadata"]["graph_db_port_scan_stats"] = port_stats
                        print(f"[+] Graph database updated with port scan data")
                    else:
                        print(f"[!] Could not connect to Neo4j - skipping port scan graph update")
                        combined_result["metadata"]["graph_db_port_scan_updated"] = False
            except ImportError:
                print(f"[!] Neo4j client not available - skipping port scan graph update")
                combined_result["metadata"]["graph_db_port_scan_updated"] = False
            except Exception as e:
                print(f"[!] Port scan graph update failed: {e}")
                combined_result["metadata"]["graph_db_port_scan_updated"] = False
                combined_result["metadata"]["graph_db_port_scan_error"] = str(e)

            save_recon_file(combined_result, output_file)

    # Step 4: HTTP probing (technology detection, live URL discovery)
    if "http_probe" in SCAN_MODULES:
        combined_result = run_http_probe(combined_result, output_file=output_file)
        combined_result["metadata"]["modules_executed"].append("http_probe")
        save_recon_file(combined_result, output_file)

        # Update Graph DB with http probe data
        if UPDATE_GRAPH_DB:
            print(f"\n[GRAPH UPDATE] HTTP Probe Data")
            print("-" * 40)
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        http_stats = graph_client.update_graph_from_http_probe(combined_result, USER_ID, PROJECT_ID)
                        combined_result["metadata"]["graph_db_http_probe_updated"] = True
                        combined_result["metadata"]["graph_db_http_probe_stats"] = http_stats
                        print(f"[+] Graph database updated with http probe data")
                    else:
                        print(f"[!] Could not connect to Neo4j - skipping http probe graph update")
                        combined_result["metadata"]["graph_db_http_probe_updated"] = False
            except ImportError:
                print(f"[!] Neo4j client not available - skipping http probe graph update")
                combined_result["metadata"]["graph_db_http_probe_updated"] = False
            except Exception as e:
                print(f"[!] HTTP probe graph update failed: {e}")
                combined_result["metadata"]["graph_db_http_probe_updated"] = False
                combined_result["metadata"]["graph_db_http_probe_error"] = str(e)

            save_recon_file(combined_result, output_file)

    # Step 5: Vulnerability scanning (web application vulns) + MITRE enrichment
    if "vuln_scan" in SCAN_MODULES:
        combined_result = run_vuln_scan(combined_result, output_file=output_file)
        combined_result["metadata"]["modules_executed"].append("vuln_scan")
        save_recon_file(combined_result, output_file)

        # Automatically run MITRE CWE/CAPEC enrichment after vuln_scan
        combined_result = run_mitre_enrichment(combined_result, output_file=output_file)
        save_recon_file(combined_result, output_file)

        # Update Graph DB with vuln scan data
        if UPDATE_GRAPH_DB:
            print(f"\n[GRAPH UPDATE] Vuln Scan Data")
            print("-" * 40)
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        vuln_stats = graph_client.update_graph_from_vuln_scan(combined_result, USER_ID, PROJECT_ID)
                        combined_result["metadata"]["graph_db_vuln_scan_updated"] = True
                        combined_result["metadata"]["graph_db_vuln_scan_stats"] = vuln_stats
                        print(f"[+] Graph database updated with vuln scan data")
                    else:
                        print(f"[!] Could not connect to Neo4j - skipping vuln scan graph update")
                        combined_result["metadata"]["graph_db_vuln_scan_updated"] = False
            except ImportError:
                print(f"[!] Neo4j client not available - skipping vuln scan graph update")
                combined_result["metadata"]["graph_db_vuln_scan_updated"] = False
            except Exception as e:
                print(f"[!] Vuln scan graph update failed: {e}")
                combined_result["metadata"]["graph_db_vuln_scan_updated"] = False
                combined_result["metadata"]["graph_db_vuln_scan_error"] = str(e)

            save_recon_file(combined_result, output_file)

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[+] DOMAIN RECON COMPLETE")
    if filtered_mode:
        print(f"[+] Mode: Filtered ({len(full_subdomains)} subdomain(s))")
    else:
        print(f"[+] Subdomains found: {combined_result['subdomain_count']}")
    
    # Port scan stats
    if "port_scan" in SCAN_MODULES and "port_scan" in combined_result:
        port_summary = combined_result["port_scan"].get("summary", {})
        print(f"[+] Open ports: {port_summary.get('total_open_ports', 0)}")
    
    # HTTP probe stats
    if "http_probe" in SCAN_MODULES and "http_probe" in combined_result:
        http_summary = combined_result["http_probe"].get("summary", {})
        print(f"[+] Live URLs: {http_summary.get('live_urls', 0)}")
        print(f"[+] Technologies: {http_summary.get('technology_count', 0)}")
    
    # Vuln scan stats (includes MITRE enrichment)
    if "vuln_scan" in SCAN_MODULES and "vuln_scan" in combined_result:
        vuln_summary = combined_result["vuln_scan"].get("summary", {})
        vuln_total = combined_result["vuln_scan"].get("vulnerabilities", {}).get("total", 0)
        print(f"[+] Vuln findings: {vuln_summary.get('total_findings', 0)} ({vuln_total} vulnerabilities)")

        # MITRE enrichment stats (part of vuln_scan)
        mitre_meta = combined_result.get("metadata", {}).get("mitre_enrichment", {})
        if mitre_meta:
            print(f"[+] MITRE enriched: {mitre_meta.get('total_cves_enriched', 0)}/{mitre_meta.get('total_cves_processed', 0)} CVEs")

    print(f"[+] Output saved: {output_file}")
    print(f"{'=' * 70}")

    return combined_result


def run_github_recon(token: str, target: str) -> list:
    """
    Run GitHub secret hunting.
    Produces a separate JSON file for GitHub findings.
    
    Args:
        token: GitHub personal access token
        target: Organization or username to scan
        
    Returns:
        List of findings
    """
    print("\n" + "=" * 70)
    print("               RedAmon - GitHub Secret Hunt")
    print("=" * 70)
    print(f"  Target: {target}")
    print("=" * 70 + "\n")
    
    if not token:
        print("[!] GitHub access token not configured. Skipping GitHub recon.")
        return []
    
    hunter = GitHubSecretHunter(token, target)
    findings = hunter.run()
    
    return findings


def main():
    """
    Main entry point - runs the complete recon pipeline.

    Pipeline: domain_discovery -> port_scan -> http_probe -> vuln_scan -> github

    Scan modes based on SUBDOMAIN_LIST:
    - Empty list []: Full subdomain discovery (discover and scan all subdomains)
    - With entries ["testphp.", "www."]: Filtered mode (only scan specified subdomains)
    """
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "RedAmon OSINT Framework" + " " * 25 + "║")
    print("║" + " " * 15 + "Automated Reconnaissance Pipeline" + " " * 18 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    start_time = datetime.now()

    # Parse target with SUBDOMAIN_LIST filter
    target_info = parse_target(TARGET_DOMAIN, SUBDOMAIN_LIST)
    filtered_mode = target_info["filtered_mode"]
    root_domain = target_info["root_domain"]
    full_subdomains = target_info["full_subdomains"]

    print(f"[*] Target: {root_domain}")
    if filtered_mode:
        print(f"[*] Mode: FILTERED SUBDOMAIN SCAN")
        print(f"[*] Subdomains: {', '.join(full_subdomains)}")
    else:
        print(f"[*] Mode: FULL DISCOVERY (all subdomains)")
    print()

    # Check anonymity status if Tor is enabled
    if USE_TOR_FOR_RECON:
        try:
            from utils.anonymity import print_anonymity_status
            print_anonymity_status()
        except ImportError:
            print("[!] Anonymity module not found, proceeding without Tor status check")

    # Phase 1 & 2: Domain recon (WHOIS + Subdomains + DNS) - Combined JSON
    output_file = Path(__file__).parent / "output" / f"recon_{root_domain}.json"

    if "domain_discovery" in SCAN_MODULES:
        domain_result = run_domain_recon(
            TARGET_DOMAIN,
            anonymous=USE_TOR_FOR_RECON,
            bruteforce=USE_BRUTEFORCE_FOR_SUBDOMAINS,
            target_info=target_info
        )
    else:
        # Load existing recon file if domain_discovery not in modules
        if output_file.exists():
            with open(output_file, 'r') as f:
                domain_result = json.load(f)
            print(f"[*] Loaded existing recon file: {output_file}")
        else:
            print(f"[!] No existing recon file found: {output_file}")
            print(f"[!] Add 'domain_discovery' to SCAN_MODULES to create it first")
            return 1
        
        # Run port_scan if in SCAN_MODULES (when domain_discovery is skipped)
        if "port_scan" in SCAN_MODULES:
            domain_result = run_port_scan(domain_result, output_file=output_file)
            if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                if "port_scan" not in domain_result["metadata"]["modules_executed"]:
                    domain_result["metadata"]["modules_executed"].append("port_scan")
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

            # Update Graph DB with port scan data
            if UPDATE_GRAPH_DB:
                print(f"\n[GRAPH UPDATE] Port Scan Data")
                print("-" * 40)
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            port_stats = graph_client.update_graph_from_port_scan(domain_result, USER_ID, PROJECT_ID)
                            domain_result["metadata"]["graph_db_port_scan_updated"] = True
                            domain_result["metadata"]["graph_db_port_scan_stats"] = port_stats
                            print(f"[+] Graph database updated with port scan data")
                        else:
                            print(f"[!] Could not connect to Neo4j - skipping port scan graph update")
                            domain_result["metadata"]["graph_db_port_scan_updated"] = False
                except ImportError:
                    print(f"[!] Neo4j client not available - skipping port scan graph update")
                    domain_result["metadata"]["graph_db_port_scan_updated"] = False
                except Exception as e:
                    print(f"[!] Port scan graph update failed: {e}")
                    domain_result["metadata"]["graph_db_port_scan_updated"] = False
                    domain_result["metadata"]["graph_db_port_scan_error"] = str(e)

                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)
        
        # Run http_probe if in SCAN_MODULES (when domain_discovery is skipped)
        if "http_probe" in SCAN_MODULES:
            domain_result = run_http_probe(domain_result, output_file=output_file)
            if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                if "http_probe" not in domain_result["metadata"]["modules_executed"]:
                    domain_result["metadata"]["modules_executed"].append("http_probe")
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

            # Update Graph DB with http probe data
            if UPDATE_GRAPH_DB:
                print(f"\n[GRAPH UPDATE] HTTP Probe Data")
                print("-" * 40)
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            http_stats = graph_client.update_graph_from_http_probe(domain_result, USER_ID, PROJECT_ID)
                            domain_result["metadata"]["graph_db_http_probe_updated"] = True
                            domain_result["metadata"]["graph_db_http_probe_stats"] = http_stats
                            print(f"[+] Graph database updated with http probe data")
                        else:
                            print(f"[!] Could not connect to Neo4j - skipping http probe graph update")
                            domain_result["metadata"]["graph_db_http_probe_updated"] = False
                except ImportError:
                    print(f"[!] Neo4j client not available - skipping http probe graph update")
                    domain_result["metadata"]["graph_db_http_probe_updated"] = False
                except Exception as e:
                    print(f"[!] HTTP probe graph update failed: {e}")
                    domain_result["metadata"]["graph_db_http_probe_updated"] = False
                    domain_result["metadata"]["graph_db_http_probe_error"] = str(e)

                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)
        
        # Run vuln_scan if in SCAN_MODULES (when domain_discovery is skipped)
        # vuln_scan automatically includes MITRE CWE/CAPEC enrichment
        if "vuln_scan" in SCAN_MODULES:
            domain_result = run_vuln_scan(domain_result, output_file=output_file)
            if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                if "vuln_scan" not in domain_result["metadata"]["modules_executed"]:
                    domain_result["metadata"]["modules_executed"].append("vuln_scan")
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

            # Automatically run MITRE CWE/CAPEC enrichment after vuln_scan
            domain_result = run_mitre_enrichment(domain_result, output_file=output_file)
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

            # Update Graph DB with vuln scan data
            if UPDATE_GRAPH_DB:
                print(f"\n[GRAPH UPDATE] Vuln Scan Data")
                print("-" * 40)
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            vuln_stats = graph_client.update_graph_from_vuln_scan(domain_result, USER_ID, PROJECT_ID)
                            domain_result["metadata"]["graph_db_vuln_scan_updated"] = True
                            domain_result["metadata"]["graph_db_vuln_scan_stats"] = vuln_stats
                            print(f"[+] Graph database updated with vuln scan data")
                        else:
                            print(f"[!] Could not connect to Neo4j - skipping vuln scan graph update")
                            domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                except ImportError:
                    print(f"[!] Neo4j client not available - skipping vuln scan graph update")
                    domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                except Exception as e:
                    print(f"[!] Vuln scan graph update failed: {e}")
                    domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                    domain_result["metadata"]["graph_db_vuln_scan_error"] = str(e)

                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

    # Phase 3: GitHub secret hunt - Separate JSON (if enabled)
    github_findings = []
    if "github" in SCAN_MODULES:
        github_findings = run_github_recon(GITHUB_ACCESS_TOKEN, GITHUB_TARGET_ORG)
    else:
        print("\n[*] GitHub Secret Hunt: SKIPPED (add 'github' to SCAN_MODULES to enable)")

    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 22 + "RECON PIPELINE COMPLETE" + " " * 23 + "║")
    print("╠" + "═" * 68 + "╣")
    print(f"║  Duration: {duration:.2f} seconds" + " " * (55 - len(f"{duration:.2f}")) + "║")
    print(f"║  Target: {root_domain}" + " " * (58 - len(root_domain)) + "║")
    if filtered_mode:
        filter_info = f"Filtered ({len(full_subdomains)} subdomain(s))"
        print(f"║  Mode: {filter_info}" + " " * (60 - len(filter_info)) + "║")
    else:
        print(f"║  Mode: Full discovery" + " " * 46 + "║")
        print(f"║  Subdomains found: {domain_result.get('subdomain_count', 0)}" + " " * (48 - len(str(domain_result.get('subdomain_count', 0)))) + "║")

    # Port scan stats
    if "port_scan" in SCAN_MODULES and "port_scan" in domain_result:
        port_summary = domain_result["port_scan"].get("summary", {})
        ports = port_summary.get('total_open_ports', 0)
        hosts = port_summary.get('hosts_with_open_ports', 0)
        port_info = f"{hosts} hosts, {ports} ports"
        print(f"║  Port Scan: {port_info}" + " " * (55 - len(port_info)) + "║")
    elif "port_scan" not in SCAN_MODULES:
        print(f"║  Port scan: SKIPPED" + " " * 48 + "║")

    # HTTP probe stats
    if "http_probe" in SCAN_MODULES and "http_probe" in domain_result:
        http_summary = domain_result["http_probe"].get("summary", {})
        live = http_summary.get('live_urls', 0)
        techs = http_summary.get('technology_count', 0)
        http_info = f"{live} live URLs, {techs} technologies"
        print(f"║  HTTP Probe: {http_info}" + " " * (54 - len(http_info)) + "║")
    elif "http_probe" not in SCAN_MODULES:
        print(f"║  HTTP probe: SKIPPED" + " " * 47 + "║")

    # Vuln scan stats (includes MITRE enrichment)
    if "vuln_scan" in SCAN_MODULES and "vuln_scan" in domain_result:
        vuln_summary = domain_result["vuln_scan"].get("summary", {})
        total_findings = vuln_summary.get("total_findings", 0)
        crit = vuln_summary.get("critical", 0)
        high = vuln_summary.get("high", 0)
        vuln_info = f"{total_findings} findings"
        if crit > 0 or high > 0:
            vuln_info += f" ({crit} critical, {high} high)"
        print(f"║  Vuln Scan: {vuln_info}" + " " * (55 - len(vuln_info)) + "║")

        # MITRE enrichment stats (part of vuln_scan)
        mitre_meta = domain_result.get("metadata", {}).get("mitre_enrichment", {})
        if mitre_meta:
            enriched = mitre_meta.get('total_cves_enriched', 0)
            total = mitre_meta.get('total_cves_processed', 0)
            mitre_info = f"{enriched}/{total} CVEs enriched"
            print(f"║  MITRE CWE/CAPEC: {mitre_info}" + " " * (49 - len(mitre_info)) + "║")
    elif "vuln_scan" not in SCAN_MODULES:
        print(f"║  Vuln scan: SKIPPED" + " " * 48 + "║")

    github_status = str(len(github_findings)) if "github" in SCAN_MODULES else "SKIPPED"
    print(f"║  GitHub findings: {github_status}" + " " * (49 - len(github_status)) + "║")
    print("╠" + "═" * 68 + "╣")
    print("║  Output Files:" + " " * 53 + "║")
    
    # Build suffix string
    suffixes = []
    if "port_scan" in SCAN_MODULES:
        suffixes.append("PortScan")
    if "http_probe" in SCAN_MODULES:
        suffixes.append("HTTPProbe")
    if "vuln_scan" in SCAN_MODULES:
        suffixes.append("VulnScan+MITRE")
    all_suffixes = " + " + " + ".join(suffixes) if suffixes else ""
    
    if filtered_mode:
        print(f"║    • recon_{root_domain}.json (WHOIS + DNS{all_suffixes})" + " " * max(0, 18 - len(root_domain) - len(all_suffixes)) + "║")
    else:
        print(f"║    • recon_{root_domain}.json (WHOIS + DNS + Subs{all_suffixes})" + " " * max(0, 10 - len(root_domain) - len(all_suffixes)) + "║")
    if "github" in SCAN_MODULES:
        print(f"║    • github_secrets_{GITHUB_TARGET_ORG}.json" + " " * max(0, 24 - len(GITHUB_TARGET_ORG)) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())

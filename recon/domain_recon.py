"""
Subdomain Discovery & DNS Resolution - Unified OSINT tool
Discovers subdomains using crt.sh, HackerTarget, and Knockpy.
Resolves full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for domain and all subdomains.
Outputs a single JSON report.
"""

import subprocess
import requests
import re
import glob
import json
import time
import dns.resolver
from pathlib import Path
from datetime import datetime
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.params import DNS_MAX_RETRIES

OUTPUT_DIR = Path(__file__).parent / "output"
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']


def get_tor_session(anonymous: bool):
    """Get requests session, optionally through Tor."""
    if anonymous:
        try:
            from recon.helpers.anonymity import get_tor_session, is_tor_running
            if is_tor_running():
                session = get_tor_session()
                if session:
                    return session
            print("[!] Tor not available, using direct connection")
        except ImportError:
            print("[!] Anonymity module not found")
    return requests.Session()


def get_proxychains_prefix(anonymous: bool) -> list:
    """Get proxychains command prefix if enabled."""
    if anonymous:
        try:
            from recon.helpers.anonymity import get_proxychains_cmd, is_tor_running
            if is_tor_running():
                cmd = get_proxychains_cmd()
                if cmd:
                    print(f"[🧅] Using {cmd} for Knockpy")
                    return [cmd, "-q"]
        except ImportError:
            pass
    return []


def get_passive_subdomains(domain: str, session) -> set:
    """Combine crt.sh and HackerTarget passive discovery."""
    subdomains = set()
    
    # crt.sh
    print(f"[*] Querying crt.sh...")
    try:
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
        if resp.status_code == 200:
            for entry in resp.json():
                for sub in entry['name_value'].lower().split('\n'):
                    if not sub.startswith('*.'):
                        subdomains.add(sub.strip())
            print(f"[+] crt.sh: {len(subdomains)} found")
    except Exception as e:
        print(f"[!] crt.sh error: {e}")

    # HackerTarget
    print(f"[*] Querying HackerTarget...")
    try:
        resp = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            count = 0
            for line in resp.text.strip().split('\n'):
                if ',' in line:
                    subdomains.add(line.split(',')[0].strip())
                    count += 1
            print(f"[+] HackerTarget: {count} found")
    except Exception as e:
        print(f"[!] HackerTarget error: {e}")
    
    return subdomains


def run_knockpy(domain: str, proxychains_prefix: list, bruteforce: bool = False) -> set:
    """Run Knockpy to get subdomains."""
    subdomains = set()
    mode = "recon + bruteforce" if bruteforce else "recon only"
    print(f"[*] Running Knockpy ({mode})...")
    
    command = ['knockpy', '-d', domain, '--recon']
    if bruteforce:
        command.append('--bruteforce')
    if proxychains_prefix:
        command = proxychains_prefix + command
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        
        # Strip ANSI color codes from output before parsing
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', result.stdout.lower())
        
        # Extract everything that looks like a subdomain
        matches = re.findall(r'([\w.-]+\.' + re.escape(domain) + r')', clean_output)
        subdomains.update(matches)
        
        if subdomains:
            print(f"[+] Knockpy: {len(subdomains)} found")
        else:
            print(f"[*] Knockpy: 0 found")
            
    except subprocess.TimeoutExpired:
        print("[!] Knockpy timed out")
    except FileNotFoundError:
        print("[!] Knockpy not installed (pip install knockpy)")
    except Exception as e:
        print(f"[!] Knockpy error: {e}")
    finally:
        # Clean up knockpy's auto-generated files
        for f in glob.glob(str(PROJECT_ROOT / f"{domain}_*.json")):
            try:
                Path(f).unlink()
            except Exception:
                pass
    
    return subdomains


def dns_lookup_single(hostname: str, rtype: str, max_retries: int = None) -> list:
    """
    Perform DNS lookup for a single record type with retry logic.
    
    Args:
        hostname: Domain or subdomain to resolve
        rtype: DNS record type (A, AAAA, MX, etc.)
        max_retries: Maximum retry attempts (defaults to DNS_MAX_RETRIES)
        
    Returns:
        List of DNS records or None if not found/failed
    """
    if max_retries is None:
        max_retries = DNS_MAX_RETRIES
    
    last_error = None
    
    for attempt in range(max_retries):
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            return [rr.to_text() for rr in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # These are expected "not found" responses - no retry needed
            return None
        except (dns.resolver.NoNameservers, dns.resolver.Timeout) as e:
            # Temporary failures - worth retrying
            last_error = e
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                time.sleep(delay)
                continue
            return None
        except Exception as e:
            # Unexpected errors - retry
            last_error = e
            if attempt < max_retries - 1:
                delay = 2 ** attempt
                time.sleep(delay)
                continue
            return None
    
    return None


def dns_lookup(hostname: str, max_retries: int = None) -> dict:
    """
    Perform full DNS lookup for all record types with retry logic.
    
    Args:
        hostname: Domain or subdomain to resolve
        max_retries: Maximum retry attempts per record type (defaults to DNS_MAX_RETRIES)
        
    Returns:
        Dictionary with all DNS records
    """
    if max_retries is None:
        max_retries = DNS_MAX_RETRIES
    
    dns_data = {}
    
    for rtype in DNS_RECORD_TYPES:
        dns_data[rtype] = dns_lookup_single(hostname, rtype, max_retries)
    
    # Extract IPs for convenience
    ips = {
        "ipv4": dns_data.get("A") or [],
        "ipv6": dns_data.get("AAAA") or []
    }
    
    return {
        "records": dns_data,
        "ips": ips,
        "has_records": any(v for v in dns_data.values() if v)
    }


def verify_domain_ownership(domain: str, token: str, txt_prefix: str = "_redamon-verify") -> dict:
    """
    Verify domain ownership via DNS TXT record.

    Checks for a TXT record at {txt_prefix}.{domain} containing "redamon-verify={token}".

    Args:
        domain: Root domain to verify (e.g., "example.com")
        token: Expected ownership token
        txt_prefix: DNS record prefix (default: "_redamon-verify")

    Returns:
        Dictionary with:
        - verified: True if ownership verified, False otherwise
        - record_name: Full DNS record name checked
        - expected_value: The value we're looking for
        - found_values: List of TXT values found (if any)
        - error: Error message if verification failed
    """
    record_name = f"{txt_prefix}.{domain}"
    expected_value = f"redamon-verify={token}"

    result = {
        "verified": False,
        "record_name": record_name,
        "expected_value": expected_value,
        "found_values": [],
        "error": None
    }

    print(f"[*] Verifying domain ownership: {record_name}")

    try:
        # Query TXT records
        txt_records = dns_lookup_single(record_name, "TXT")

        if txt_records is None:
            result["error"] = f"No TXT record found at {record_name}"
            return result

        # Clean up TXT records (remove quotes)
        cleaned_records = []
        for record in txt_records:
            cleaned = record.strip('"').strip("'")
            cleaned_records.append(cleaned)

        result["found_values"] = cleaned_records

        # Check if expected value is in the records
        if expected_value in cleaned_records:
            result["verified"] = True
            print(f"[+] Domain ownership verified")
        else:
            result["error"] = f"TXT record found but value doesn't match"

    except Exception as e:
        result["error"] = f"DNS lookup failed: {str(e)}"

    return result


def resolve_all_dns(domain: str, subdomains: list) -> dict:
    """
    Resolve DNS for domain and all subdomains.
    
    Args:
        domain: Root domain
        subdomains: List of discovered subdomains
        
    Returns:
        Dictionary with DNS data for domain and each subdomain
    """
    print(f"\n[*] Resolving DNS for {len(subdomains) + 1} hosts...")
    
    result = {
        "domain": {},
        "subdomains": {}
    }
    
    # Resolve root domain
    print(f"  [*] {domain} (root)")
    result["domain"] = dns_lookup(domain)
    if result["domain"]["ips"]["ipv4"]:
        print(f"      → {', '.join(result['domain']['ips']['ipv4'])}")
    
    # Resolve each subdomain
    for subdomain in subdomains:
        if subdomain == domain:
            continue
        
        dns_result = dns_lookup(subdomain)
        result["subdomains"][subdomain] = dns_result
        
        if dns_result["ips"]["ipv4"] or dns_result["ips"]["ipv6"]:
            all_ips = dns_result["ips"]["ipv4"] + dns_result["ips"]["ipv6"]
            print(f"  [+] {subdomain} → {', '.join(all_ips)}")
    
    # Stats
    resolved_count = sum(1 for v in result["subdomains"].values() if v["has_records"])
    print(f"[+] Resolved: {resolved_count}/{len(subdomains)} subdomains")
    
    return result


def discover_subdomains(domain: str, anonymous: bool = False, bruteforce: bool = False, 
                        resolve: bool = True, save_output: bool = True) -> dict:
    """
    Main discovery function - subdomain enumeration + DNS resolution.
    
    Args:
        domain: Target domain (e.g., "example.com")
        anonymous: Use Tor to hide real IP
        bruteforce: Enable Knockpy bruteforce mode (slower but more thorough)
        resolve: Whether to resolve DNS for all hosts
        save_output: Whether to save JSON report
        
    Returns:
        Complete reconnaissance data for domain and subdomains
    """
    print(f"\n{'=' * 50}")
    print(f"[*] TARGET: {domain}")
    if anonymous:
        print(f"[🧅] ANONYMOUS MODE")
    if bruteforce:
        print(f"[⚡] BRUTEFORCE MODE")
    print(f"{'=' * 50}\n")
    
    # Setup
    session = get_tor_session(anonymous)
    pc_prefix = get_proxychains_prefix(anonymous)
    
    # Subdomain Discovery
    passive = get_passive_subdomains(domain, session)
    active = run_knockpy(domain, pc_prefix, bruteforce)
    
    # Combine, filter, sort
    all_subs = passive.union(active)
    all_subs = sorted([s for s in all_subs if s.endswith(domain)])
    
    # Build result structure
    result = {
        "metadata": {
            "scan_type": "subdomain_dns_discovery",
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": domain,
            "anonymous_mode": anonymous,
            "bruteforce_mode": bruteforce
        },
        "domain": domain,
        "subdomains": all_subs,
        "subdomain_count": len(all_subs),
        "dns": None
    }
    
    # DNS Resolution for domain + all subdomains
    if resolve:
        result["dns"] = resolve_all_dns(domain, all_subs)
    
    # Save JSON output
    if save_output:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_file = OUTPUT_DIR / f"recon_{domain}.json"
        
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"\n{'=' * 50}")
        print(f"[+] TOTAL: {len(all_subs)} unique subdomains")
        print(f"[+] SAVED: {output_file}")
        print(f"{'=' * 50}\n")
    
    if anonymous and session:
        session.close()
    
    return result



"""
Subdomain Discovery & DNS Resolution - Unified OSINT tool
Discovers subdomains using crt.sh, HackerTarget, Subfinder, Amass, and Knockpy.
Resolves full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for domain and all subdomains.
Outputs a single JSON report.

Parallelization:
- All 5 discovery tools run concurrently via ThreadPoolExecutor (fan-out/fan-in)
- DNS resolution runs concurrently across subdomains (configurable worker count)
"""

import os
import subprocess
import requests
import re
import glob
import json
import time
import shutil
import dns.resolver
import dns.reversename
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Settings are passed from main.py to avoid multiple database queries

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
            print("[!][Tor] Not available, using direct connection")
        except ImportError:
            print("[!][Tor] Anonymity module not found")
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


def query_crtsh(domain: str, anonymous: bool = False, settings: dict = None) -> dict:
    """Query crt.sh certificate transparency logs for subdomains.

    Thread-safe: creates its own requests.Session.

    Returns dict {subdomain: set_of_sources} for per-source attribution.
    """
    if settings is None:
        settings = {}

    if not settings.get('CRTSH_ENABLED', True):
        print(f"[-][crt.sh] Disabled — skipping")
        return {}

    sourced = {}
    session = get_tor_session(anonymous)
    try:
        print(f"[*][crt.sh] Querying certificate transparency logs...")
        crtsh_subs = set()
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
        if resp.status_code == 200:
            for entry in resp.json():
                for sub in entry['name_value'].lower().split('\n'):
                    if not sub.startswith('*.'):
                        crtsh_subs.add(sub.strip())
            max_results = settings.get('CRTSH_MAX_RESULTS', 5000)
            if len(crtsh_subs) > max_results:
                crtsh_subs = set(sorted(crtsh_subs)[:max_results])
                print(f"[*][crt.sh] Capped at {max_results} results")
            print(f"[+][crt.sh] Found {len(crtsh_subs)} subdomains")
            for s in crtsh_subs:
                sourced.setdefault(s, set()).add("crt.sh")
    except Exception as e:
        print(f"[!][crt.sh] Error: {e}")
    finally:
        session.close()

    return sourced


def query_hackertarget(domain: str, anonymous: bool = False, settings: dict = None) -> dict:
    """Query HackerTarget API for subdomains.

    Thread-safe: creates its own requests.Session.

    Returns dict {subdomain: set_of_sources} for per-source attribution.
    """
    if settings is None:
        settings = {}

    if not settings.get('HACKERTARGET_ENABLED', True):
        print(f"[-][HackerTarget] Disabled — skipping")
        return {}

    sourced = {}
    session = get_tor_session(anonymous)
    try:
        print(f"[*][HackerTarget] Querying host search API...")
        ht_subs = set()
        resp = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split('\n'):
                if ',' in line:
                    ht_subs.add(line.split(',')[0].strip())
            max_results = settings.get('HACKERTARGET_MAX_RESULTS', 5000)
            if len(ht_subs) > max_results:
                ht_subs = set(sorted(ht_subs)[:max_results])
                print(f"[*][HackerTarget] Capped at {max_results} results")
            print(f"[+][HackerTarget] Found {len(ht_subs)} subdomains")
            for s in ht_subs:
                sourced.setdefault(s, set()).add("hackertarget")
    except Exception as e:
        print(f"[!][HackerTarget] Error: {e}")
    finally:
        session.close()

    return sourced


def get_passive_subdomains(domain: str, session, settings: dict = None) -> dict:
    """Combine crt.sh and HackerTarget passive discovery (legacy sequential wrapper).

    Returns dict {subdomain: set_of_sources} for per-source attribution.
    """
    if settings is None:
        settings = {}
    sourced = {}
    for s, sources in query_crtsh(domain, anonymous=False, settings=settings).items():
        sourced.setdefault(s, set()).update(sources)
    for s, sources in query_hackertarget(domain, anonymous=False, settings=settings).items():
        sourced.setdefault(s, set()).update(sources)
    return sourced


def run_knockpy(domain: str, proxychains_prefix: list, bruteforce: bool = False, settings: dict = None) -> set:
    """Run Knockpy to get subdomains."""
    if settings is None:
        settings = {}

    # Check if Knockpy recon mode is enabled
    if not settings.get('KNOCKPY_RECON_ENABLED', True) and not bruteforce:
        print(f"[-][Knockpy] Disabled — skipping")
        return set()

    subdomains = set()
    mode = "recon + bruteforce" if bruteforce else "recon only"
    print(f"[*][Knockpy] Running ({mode})...")
    
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
        
        max_results = settings.get('KNOCKPY_RECON_MAX_RESULTS', 5000)
        if len(subdomains) > max_results:
            subdomains = set(sorted(subdomains)[:max_results])
            print(f"[*][Knockpy] Capped at {max_results} results")
        if subdomains:
            print(f"[+][Knockpy] Found {len(subdomains)} subdomains")
        else:
            print(f"[*][Knockpy] Found 0 subdomains")

    except subprocess.TimeoutExpired:
        print("[!][Knockpy] Timed out")
    except FileNotFoundError:
        print("[!][Knockpy] Not installed (pip install knockpy)")
    except Exception as e:
        print(f"[!][Knockpy] Error: {e}")
    finally:
        # Clean up knockpy's auto-generated files
        for f in glob.glob(str(PROJECT_ROOT / f"{domain}_*.json")):
            try:
                Path(f).unlink()
            except Exception:
                pass
    
    return subdomains


def run_subfinder(domain: str, settings: dict = None) -> set:
    """Run Subfinder passive subdomain enumeration via Docker."""
    if settings is None:
        settings = {}

    if not settings.get('SUBFINDER_ENABLED', True):
        print(f"[-][Subfinder] Disabled — skipping")
        return set()

    docker_image = settings.get('SUBFINDER_DOCKER_IMAGE', 'projectdiscovery/subfinder:latest')
    max_results = settings.get('SUBFINDER_MAX_RESULTS', 5000)

    print(f"[*][Subfinder] Running passive enumeration...")

    command = [
        'docker', 'run', '--rm',
        docker_image,
        '-d', domain,
        '-json', '-silent',
        '-timeout', '30',
        '-max-time', '10',
    ]

    subdomains = set()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=720)

        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get('host', '').strip().lower()
                if host:
                    subdomains.add(host)
            except json.JSONDecodeError:
                continue

        if len(subdomains) > max_results:
            subdomains = set(sorted(subdomains)[:max_results])
            print(f"[*][Subfinder] Capped at {max_results} results")

        if subdomains:
            print(f"[+][Subfinder] Found {len(subdomains)} subdomains")
        else:
            print(f"[*][Subfinder] Found 0 subdomains")

    except subprocess.TimeoutExpired:
        print("[!][Subfinder] Timed out")
    except FileNotFoundError:
        print("[!][Subfinder] Docker not found — cannot run")
    except Exception as e:
        print(f"[!][Subfinder] Error: {e}")

    return subdomains


def run_amass(domain: str, settings: dict = None) -> set:
    """Run OWASP Amass subdomain enumeration via Docker."""
    if settings is None:
        settings = {}

    if not settings.get('AMASS_ENABLED', False):
        print(f"[-][Amass] Disabled — skipping")
        return set()

    docker_image = settings.get('AMASS_DOCKER_IMAGE', 'caffix/amass:latest')
    max_results = settings.get('AMASS_MAX_RESULTS', 5000)
    timeout_min = settings.get('AMASS_TIMEOUT', 10)
    active = settings.get('AMASS_ACTIVE', False)
    brute = settings.get('AMASS_BRUTE', False)

    mode_parts = ["active" if active else "passive"]
    if brute:
        mode_parts.append("brute")
    mode = "+".join(mode_parts)
    print(f"[*][Amass] Running enumeration ({mode})...")

    # Amass v4 needs a writable config dir
    amass_temp = Path("/tmp/redamon/.amass_temp")
    amass_temp.mkdir(parents=True, exist_ok=True)

    # The wordlist is inside this container at /app/recon/wordlists/
    container_wordlist = '/app/recon/wordlists/jhaddix-all.txt'

    # For the Amass sibling container, we need the HOST path.
    # HOST_RECON_OUTPUT_PATH = <host_project>/recon/output
    # parent = <host_project>/recon
    # wordlist = <host_project>/recon/wordlists/jhaddix-all.txt
    host_recon_output = os.environ.get('HOST_RECON_OUTPUT_PATH', '')
    if host_recon_output:
        host_recon_dir = os.path.dirname(host_recon_output)
        wordlist_host_path = os.path.join(host_recon_dir, 'wordlists', 'jhaddix-all.txt')
    else:
        wordlist_host_path = ''

    # Check the file exists INSIDE this container (not host path check)
    wordlist_available = os.path.isfile(container_wordlist)

    brute_wordlists = settings.get('AMASS_BRUTE_WORDLISTS', ['default'])

    command = [
        'docker', 'run', '--rm',
        '-v', f'{amass_temp}:/root/.config/amass',
        docker_image,
        'enum', '-d', domain,
        '-timeout', str(timeout_min),
    ]

    if active:
        command.append('-active')
    if brute:
        command.append('-brute')
        if 'jhaddix-all' in brute_wordlists and wordlist_available and wordlist_host_path:
            # Insert volume mount BEFORE the docker image name in the command
            img_idx = command.index(docker_image)
            command.insert(img_idx, f'{wordlist_host_path}:/wordlist/jhaddix-all.txt:ro')
            command.insert(img_idx, '-v')
            command += ['-w', '/wordlist/jhaddix-all.txt']
            print(f"[*][Amass] Using jhaddix all.txt wordlist (~2.18M entries) for brute force")
        else:
            print(f"[*][Amass] Using Amass built-in wordlist (~8K entries) for brute force")

    subdomains = set()
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=(timeout_min * 60) + 120
        )

        # Output format: "name (FQDN) --> record_type --> target (FQDN)"
        # Capture ALL FQDNs per line (both source and target can be subdomains)
        fqdn_pattern = re.compile(r'([\w.\-]+)\s+\(FQDN\)')
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            for match in fqdn_pattern.finditer(line):
                host = match.group(1).strip().lower()
                if host:
                    subdomains.add(host)

        if len(subdomains) > max_results:
            subdomains = set(sorted(subdomains)[:max_results])
            print(f"[*][Amass] Capped at {max_results} results")

        if subdomains:
            print(f"[+][Amass] Found {len(subdomains)} subdomains")
        else:
            print(f"[*][Amass] Found 0 subdomains")

    except subprocess.TimeoutExpired:
        print("[!][Amass] Timed out")
    except FileNotFoundError:
        print("[!][Amass] Docker not found — cannot run")
    except Exception as e:
        print(f"[!][Amass] Error: {e}")
    finally:
        shutil.rmtree(amass_temp, ignore_errors=True)

    return subdomains


def dns_lookup_single(hostname: str, rtype: str, max_retries: int = 3) -> list:
    """
    Perform DNS lookup for a single record type with retry logic.

    Args:
        hostname: Domain or subdomain to resolve
        rtype: DNS record type (A, AAAA, MX, etc.)
        max_retries: Maximum retry attempts

    Returns:
        List of DNS records or None if not found/failed
    """
    
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


def dns_lookup(hostname: str, max_retries: int = 3, parallel: bool = True) -> dict:
    """
    Perform full DNS lookup for all record types with retry logic.

    Args:
        hostname: Domain or subdomain to resolve
        max_retries: Maximum retry attempts per record type
        parallel: Query all 7 record types concurrently (default True)

    Returns:
        Dictionary with all DNS records
    """

    dns_data = {}

    if parallel and len(DNS_RECORD_TYPES) > 1:
        with ThreadPoolExecutor(max_workers=len(DNS_RECORD_TYPES)) as executor:
            future_to_rtype = {
                executor.submit(dns_lookup_single, hostname, rtype, max_retries): rtype
                for rtype in DNS_RECORD_TYPES
            }
            for future in as_completed(future_to_rtype):
                rtype = future_to_rtype[future]
                try:
                    dns_data[rtype] = future.result()
                except Exception:
                    dns_data[rtype] = None
    else:
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

    print(f"[*][DNS] Verifying domain ownership: {record_name}")

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
            print(f"[+][DNS] Domain ownership verified")
        else:
            result["error"] = f"TXT record found but value doesn't match"

    except Exception as e:
        result["error"] = f"DNS lookup failed: {str(e)}"

    return result


def resolve_all_dns(domain: str, subdomains: list, max_workers: int = 20, record_parallelism: bool = True) -> dict:
    """
    Resolve DNS for domain and all subdomains using parallel workers.

    Args:
        domain: Root domain
        subdomains: List of discovered subdomains
        max_workers: Max concurrent DNS resolution threads (default: 20)
        record_parallelism: Query 7 record types in parallel per host (default: True)

    Returns:
        Dictionary with DNS data for domain and each subdomain
    """
    subs_to_resolve = [s for s in subdomains if s != domain]
    print(f"\n[*][DNS] Resolving {len(subs_to_resolve) + 1} hosts ({max_workers} parallel workers)...")

    result = {
        "domain": {},
        "subdomains": {}
    }

    # Resolve root domain first
    print(f"[*][DNS] {domain} (root)")
    result["domain"] = dns_lookup(domain, parallel=record_parallelism)
    if result["domain"]["ips"]["ipv4"]:
        print(f"[+][DNS] {domain} → {', '.join(result['domain']['ips']['ipv4'])}")

    # Resolve all subdomains in parallel
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dns") as executor:
        future_to_sub = {
            executor.submit(dns_lookup, sub, 3, record_parallelism): sub
            for sub in subs_to_resolve
        }
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            try:
                dns_result = future.result()
                result["subdomains"][subdomain] = dns_result
                if dns_result["ips"]["ipv4"] or dns_result["ips"]["ipv6"]:
                    all_ips = dns_result["ips"]["ipv4"] + dns_result["ips"]["ipv6"]
                    print(f"[+][DNS] {subdomain} → {', '.join(all_ips)}")
            except Exception as e:
                print(f"[!][DNS] {subdomain}: error: {e}")
                result["subdomains"][subdomain] = {
                    "records": {}, "ips": {"ipv4": [], "ipv6": []}, "has_records": False
                }

    # Stats
    resolved_count = sum(1 for v in result["subdomains"].values() if v["has_records"])
    print(f"[+][DNS] Resolved: {resolved_count}/{len(subs_to_resolve)} subdomains")

    return result


def run_puredns_resolve(subdomains: list, domain: str, settings: dict = None) -> list:
    """
    Filter subdomains using puredns resolve to remove wildcards and DNS-poisoned entries.

    Runs puredns via Docker-in-Docker. Takes the combined subdomain list from all
    discovery tools, validates each entry against public DNS resolvers, and returns
    only the subdomains that are confirmed to exist (not wildcards or poisoned).

    On any error, returns the original unfiltered list (graceful degradation).
    """
    if settings is None:
        settings = {}

    if not settings.get('PUREDNS_ENABLED', True):
        print(f"[-][Puredns] Disabled — skipping wildcard filtering")
        return subdomains

    if not subdomains:
        print(f"[-][Puredns] No subdomains to validate")
        return subdomains

    docker_image = settings.get('PUREDNS_DOCKER_IMAGE', 'frost19k/puredns:latest')
    threads = settings.get('PUREDNS_THREADS', 0)
    rate_limit = settings.get('PUREDNS_RATE_LIMIT', 0)
    wildcard_batch = settings.get('PUREDNS_WILDCARD_BATCH', 0)
    skip_validation = settings.get('PUREDNS_SKIP_VALIDATION', False)

    print(f"[*][Puredns] Validating {len(subdomains)} subdomains (wildcard filtering)...")

    # Prepare temp files in /tmp/redamon (same path inside and outside container)
    data_dir = Path("/tmp/redamon")
    data_dir.mkdir(parents=True, exist_ok=True)
    input_file = data_dir / f"puredns_input_{domain}.txt"
    output_file = data_dir / f"puredns_output_{domain}.txt"
    resolver_src = Path("/app/recon/data/resolvers.txt")
    resolver_shared = data_dir / "resolvers.txt"

    # Copy resolvers to shared volume (if not already there)
    if resolver_src.exists() and not resolver_shared.exists():
        shutil.copy2(resolver_src, resolver_shared)
    elif not resolver_src.exists() and not resolver_shared.exists():
        print(f"[!][Puredns] No resolver list found — skipping")
        return subdomains

    # Write input subdomain list
    with open(input_file, 'w') as f:
        f.write('\n'.join(subdomains))

    command = [
        'docker', 'run', '--rm',
        '-v', f'{data_dir}:/data',
        docker_image,
        'resolve', f'/data/{input_file.name}',
        '-r', '/data/resolvers.txt',
        '--write', f'/data/{output_file.name}',
        '-q',
    ]

    if threads > 0:
        command.extend(['-t', str(threads)])
    if rate_limit > 0:
        command.extend(['--rate-limit', str(rate_limit)])
    if wildcard_batch > 0:
        command.extend(['--wildcard-batch', str(wildcard_batch)])
    if skip_validation:
        command.append('--skip-validation')

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)

        if output_file.exists():
            with open(output_file, 'r') as f:
                filtered = [line.strip() for line in f if line.strip()]
            removed = len(subdomains) - len(filtered)
            print(f"[+][Puredns] Validated: {len(filtered)} real, {removed} filtered (wildcards/poisoned)")
            return filtered
        else:
            print(f"[!][Puredns] No output file produced — returning unfiltered list")
            if result.stderr:
                print(f"[!][Puredns] stderr: {result.stderr[:500]}")
            return subdomains

    except subprocess.TimeoutExpired:
        print("[!][Puredns] Timed out (600s) — returning unfiltered list")
        return subdomains
    except FileNotFoundError:
        print("[!][Puredns] Docker not found — cannot run")
        return subdomains
    except Exception as e:
        print(f"[!][Puredns] Error: {e} — returning unfiltered list")
        return subdomains
    finally:
        # Cleanup temp files (may be root-owned from Docker)
        for tmp in [input_file, output_file]:
            try:
                tmp.unlink(missing_ok=True)
            except PermissionError:
                subprocess.run(
                    ["docker", "run", "--rm", "-v", f"{data_dir}:/cleanup",
                     "alpine", "rm", "-f", f"/cleanup/{tmp.name}"],
                    capture_output=True
                )


def discover_subdomains(domain: str, anonymous: bool = False, bruteforce: bool = False,
                        resolve: bool = True, save_output: bool = True, project_id: str = None,
                        settings: dict = None) -> dict:
    """
    Main discovery function - subdomain enumeration + DNS resolution.

    Args:
        domain: Target domain (e.g., "example.com")
        anonymous: Use Tor to hide real IP
        bruteforce: Enable Knockpy bruteforce mode (slower but more thorough)
        resolve: Whether to resolve DNS for all hosts
        save_output: Whether to save JSON report
        project_id: Project ID for filename (if None, falls back to domain)
        settings: Project settings dict for tool toggles

    Returns:
        Complete reconnaissance data for domain and subdomains
    """
    print(f"\n{'=' * 50}")
    print(f"[*][Discovery] TARGET: {domain}")
    if anonymous:
        print(f"[🧅] ANONYMOUS MODE")
    if bruteforce:
        print(f"[⚡] BRUTEFORCE MODE")
    print(f"{'=' * 50}\n")
    
    # Setup
    pc_prefix = get_proxychains_prefix(anonymous)

    # Subdomain Discovery — fan-out all 5 tools in parallel
    print(f"[*][Discovery] Launching 5 discovery tools in parallel...")
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="discovery") as executor:
        futures = {
            executor.submit(query_crtsh, domain, anonymous, settings): "crtsh",
            executor.submit(query_hackertarget, domain, anonymous, settings): "hackertarget",
            executor.submit(run_subfinder, domain, settings): "subfinder",
            executor.submit(run_amass, domain, settings): "amass",
            executor.submit(run_knockpy, domain, pc_prefix, bruteforce, settings): "knockpy",
        }

        discovery_results = {}
        for future in as_completed(futures):
            label = futures[future]
            try:
                discovery_results[label] = future.result()
            except Exception as e:
                print(f"[!][{label}] Failed: {e}")
                # crtsh/hackertarget return dict, others return set
                discovery_results[label] = {} if label in ("crtsh", "hackertarget") else set()

    print(f"[+][Discovery] All discovery tools complete — merging results")

    # Fan-in: combine results from all tools
    # crtsh and hackertarget return {subdomain: set_of_sources}
    # subfinder, amass, knockpy return set of subdomains
    sourced_subs = {}  # domain -> set of source labels
    for s, sources in discovery_results.get("crtsh", {}).items():
        sourced_subs.setdefault(s, set()).update(sources)
    for s, sources in discovery_results.get("hackertarget", {}).items():
        sourced_subs.setdefault(s, set()).update(sources)
    for s in discovery_results.get("subfinder", set()):
        sourced_subs.setdefault(s, set()).add("subfinder")
    for s in discovery_results.get("amass", set()):
        sourced_subs.setdefault(s, set()).add("amass")
    for s in discovery_results.get("knockpy", set()):
        sourced_subs.setdefault(s, set()).add("knockpy")

    filtered_subs = []
    external_domain_entries = []
    for s, sources in sourced_subs.items():
        if s == domain or s.endswith("." + domain):
            filtered_subs.append(s)
        elif s and '@' not in s:  # non-empty, out-of-scope (skip email addresses from crt.sh)
            for source in sources:
                external_domain_entries.append({"domain": s, "source": source})
    all_subs = sorted(filtered_subs)

    # Puredns wildcard filtering (after discovery fan-in, before DNS resolution)
    pre_filter_count = len(all_subs)
    all_subs = run_puredns_resolve(all_subs, domain, settings)
    if len(all_subs) < pre_filter_count:
        print(f"[+][Puredns] Wildcard filtering: {pre_filter_count} → {len(all_subs)} subdomains")

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
        "dns": {},
        "external_domains": external_domain_entries,
    }
    
    # DNS Resolution for domain + all subdomains
    if resolve:
        dns_workers = (settings or {}).get('DNS_MAX_WORKERS', 50)
        dns_record_parallel = (settings or {}).get('DNS_RECORD_PARALLELISM', True)
        result["dns"] = resolve_all_dns(domain, all_subs, max_workers=dns_workers, record_parallelism=dns_record_parallel)

    # Build subdomain status map from DNS results
    subdomain_status_map = {}
    if result["dns"]:
        dns_subs = result["dns"].get("subdomains", {})
        for s in all_subs:
            info = result["dns"].get("domain", {}) if s == domain else dns_subs.get(s, {})
            if info.get("has_records", False):
                subdomain_status_map[s] = "resolved"
    else:
        # DNS step was skipped (resolve=False) — assume all are resolved
        for s in all_subs:
            subdomain_status_map[s] = "resolved"
    result["subdomain_status_map"] = subdomain_status_map

    # Save JSON output (use project_id for filename if provided, fallback to domain)
    if save_output:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        file_id = project_id if project_id else domain
        output_file = OUTPUT_DIR / f"recon_{file_id}.json"

        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)

        print(f"\n{'=' * 50}")
        print(f"[+][Discovery] TOTAL: {len(all_subs)} unique subdomains")
        print(f"[+][Discovery] SAVED: {output_file}")
        print(f"{'=' * 50}\n")
    
    return result


def reverse_dns_lookup(ip_address: str, max_retries: int = 3):
    """
    Perform reverse DNS (PTR) lookup for an IP address.

    Args:
        ip_address: IPv4 or IPv6 address string
        max_retries: Number of retry attempts

    Returns:
        Hostname string if PTR record found, None otherwise
    """
    for attempt in range(max_retries):
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = dns.resolver.resolve(rev_name, 'PTR')
            # Return first PTR record, strip trailing dot
            hostname = str(answers[0]).rstrip('.')
            return hostname
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None
        except dns.resolver.LifetimeTimeout:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return None
        except Exception:
            return None
    return None


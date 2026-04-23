"""
RedAmon - ParamSpider Helpers
=============================
Passive URL parameter discovery from Wayback Machine using ParamSpider.
"""

import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from concurrent.futures import ThreadPoolExecutor, as_completed

from .classification import classify_parameter, classify_endpoint
from .gau_helpers import parse_gau_url_to_endpoint


def _create_temp_dir() -> Path:
    """Create a temp directory under /tmp/redamon for ParamSpider output files."""
    temp_dir = Path(f"/tmp/redamon/.paramspider_{uuid.uuid4().hex[:8]}")
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def run_paramspider_for_domain(
    domain: str,
    placeholder: str,
    timeout: int,
    use_proxy: bool = False,
    tmp_dir: Path = None,
) -> List[str]:
    """
    Run ParamSpider for a single domain.

    Args:
        domain: Target domain to query
        placeholder: Placeholder for parameter values (e.g., "FUZZ")
        timeout: Command timeout in seconds
        use_proxy: Whether to use Tor SOCKS proxy
        tmp_dir: Working directory for output files

    Returns:
        List of discovered URLs with parameters
    """
    cmd = ['paramspider', '-d', domain, '-s', '-p', placeholder]

    if use_proxy:
        cmd.extend(['--proxy', '127.0.0.1:9050'])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(tmp_dir) if tmp_dir else None,
        )

        urls = set()

        # Parse stdout (streamed URLs, one per line)
        if result.stdout:
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line and line.startswith('http'):
                    urls.add(line)

        # Also read output file as fallback (ParamSpider writes results/{domain}.txt)
        if tmp_dir:
            output_file = tmp_dir / 'results' / f'{domain}.txt'
            if output_file.exists():
                for line in output_file.read_text().splitlines():
                    line = line.strip()
                    if line and line.startswith('http'):
                        urls.add(line)

        return sorted(urls)

    except subprocess.TimeoutExpired:
        print(f"[!][ParamSpider] Timeout after {timeout}s for {domain}")
        return []
    except FileNotFoundError:
        print("[!][ParamSpider] paramspider binary not found — is it installed?")
        return []
    except Exception as e:
        print(f"[!][ParamSpider] Error for {domain}: {e}")
        return []


def run_paramspider_discovery(
    target_domains: Set[str],
    placeholder: str,
    timeout: int,
    use_proxy: bool = False,
    workers: int = 5,
) -> Tuple[List[str], Dict[str, List[str]]]:
    """
    Run ParamSpider passive parameter discovery for multiple domains.

    Args:
        target_domains: Set of domains to query
        placeholder: Placeholder for parameter values (default: "FUZZ")
        timeout: Per-domain timeout in seconds
        use_proxy: Whether to use Tor proxy

    Returns:
        Tuple of (all_discovered_urls, urls_by_domain)
    """
    print(f"\n[*][ParamSpider] Running passive parameter discovery...")
    print(f"[*][ParamSpider] Placeholder: {placeholder}")
    print(f"[*][ParamSpider] Domains: {len(target_domains)}")
    print(f"[*][ParamSpider] Workers: {workers}")

    all_discovered_urls = set()
    urls_by_domain = {}
    tmp_dir = _create_temp_dir()

    try:
        max_workers = min(workers, len(target_domains))
        print(f"[*][ParamSpider] Processing {len(target_domains)} domains with {max_workers} parallel workers...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {}
            for domain in sorted(target_domains):
                future = executor.submit(
                    run_paramspider_for_domain,
                    domain=domain,
                    placeholder=placeholder,
                    timeout=timeout,
                    use_proxy=use_proxy,
                    tmp_dir=tmp_dir,
                )
                future_to_domain[future] = domain

            completed = 0
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1
                try:
                    domain_urls = future.result()
                    urls_by_domain[domain] = domain_urls
                    all_discovered_urls.update(domain_urls)
                    print(f"[+][ParamSpider] [{completed}/{len(target_domains)}] {domain}: {len(domain_urls)} parameterized URLs")
                except Exception as e:
                    print(f"[!][ParamSpider] [{completed}/{len(target_domains)}] {domain} failed: {e}")

        urls_list = sorted(all_discovered_urls)
        print(f"[+][ParamSpider] Discovered {len(urls_list)} total parameterized URLs")

        return urls_list, urls_by_domain

    finally:
        # Clean up temp directory
        if tmp_dir and tmp_dir.exists():
            try:
                shutil.rmtree(tmp_dir)
            except Exception:
                pass


def merge_paramspider_into_by_base_url(
    paramspider_urls: List[str],
    by_base_url: Dict,
    target_domains: Set[str] = None,
) -> Tuple[Dict, Dict[str, int]]:
    """
    Merge ParamSpider endpoints into existing by_base_url structure.

    Follows the same merge pattern as merge_gau_into_by_base_url:
    - endpoints use 'sources' array (e.g., ['katana', 'paramspider'])
    - parameters use 'source' string (e.g., 'paramspider')

    Args:
        paramspider_urls: List of ParamSpider-discovered URLs
        by_base_url: Existing by_base_url structure
        target_domains: Optional set of in-scope domains for filtering

    Returns:
        Tuple of (updated by_base_url, merge stats)
    """
    stats = {
        "paramspider_total": len(paramspider_urls),
        "paramspider_parsed": 0,
        "paramspider_new": 0,
        "paramspider_overlap": 0,
        "paramspider_out_of_scope": 0,
    }

    for url in paramspider_urls:
        # Scope filtering
        if target_domains:
            try:
                host = urlparse(url).netloc.split(':')[0].lower()
                in_scope = any(
                    host == d or host.endswith('.' + d)
                    for d in target_domains
                )
                if not in_scope:
                    stats["paramspider_out_of_scope"] += 1
                    continue
            except Exception:
                stats["paramspider_out_of_scope"] += 1
                continue

        parsed = parse_gau_url_to_endpoint(url)
        if not parsed:
            continue

        stats["paramspider_parsed"] += 1
        base = parsed["base_url"]
        path = parsed["path"]

        # Create base_url entry if it doesn't exist
        if base not in by_base_url:
            by_base_url[base] = {
                'base_url': base,
                'endpoints': {},
                'summary': {
                    'total_endpoints': 0,
                    'total_parameters': 0,
                    'methods': {},
                    'categories': {}
                }
            }

        endpoints = by_base_url[base]['endpoints']

        if path in endpoints:
            # Existing endpoint — append source
            existing_sources = endpoints[path].get('sources', [])
            if not existing_sources:
                old_source = endpoints[path].get('source', '')
                if old_source:
                    existing_sources = [old_source]
            if 'paramspider' not in existing_sources:
                existing_sources.append('paramspider')
                stats["paramspider_overlap"] += 1
            endpoints[path]['sources'] = existing_sources
            endpoints[path].pop('source', None)

            # Merge GET method into existing methods
            existing_methods = set(endpoints[path].get('methods', []))
            if 'GET' not in existing_methods:
                existing_methods.add('GET')
                endpoints[path]['methods'] = sorted(list(existing_methods))
                by_base_url[base]['summary']['methods']['GET'] = \
                    by_base_url[base]['summary']['methods'].get('GET', 0) + 1

            # Merge parameters
            existing_query = endpoints[path].get('parameters', {}).get('query', [])
            new_query = parsed["parameters"].get("query", [])

            if new_query:
                if isinstance(existing_query, list):
                    existing_names = [p.get('name', p) if isinstance(p, dict) else p for p in existing_query]
                else:
                    existing_names = []

                for param_name in new_query:
                    if param_name not in existing_names:
                        param_info = {
                            'name': param_name,
                            'category': classify_parameter(param_name),
                            'source': 'paramspider'
                        }
                        if 'parameters' not in endpoints[path]:
                            endpoints[path]['parameters'] = {'query': [], 'body': [], 'path': []}
                        if 'query' not in endpoints[path]['parameters']:
                            endpoints[path]['parameters']['query'] = []
                        endpoints[path]['parameters']['query'].append(param_info)
        else:
            # New endpoint
            stats["paramspider_new"] += 1

            query_params = []
            for param_name in parsed["parameters"].get("query", []):
                query_params.append({
                    'name': param_name,
                    'category': classify_parameter(param_name),
                    'source': 'paramspider'
                })

            category = classify_endpoint(path, ['GET'], {'query': query_params, 'body': [], 'path': []})

            endpoints[path] = {
                'methods': ['GET'],
                'parameters': {
                    'query': query_params,
                    'body': [],
                    'path': []
                },
                'sources': ['paramspider'],
                'category': category,
                'parameter_count': {
                    'query': len(query_params),
                    'body': 0,
                    'path': 0,
                    'total': len(query_params)
                },
                'sample_urls': [url]
            }

            by_base_url[base]['summary']['total_endpoints'] += 1
            by_base_url[base]['summary']['total_parameters'] += len(query_params)
            by_base_url[base]['summary']['methods']['GET'] = \
                by_base_url[base]['summary']['methods'].get('GET', 0) + 1
            by_base_url[base]['summary']['categories'][category] = \
                by_base_url[base]['summary']['categories'].get(category, 0) + 1

    return by_base_url, stats

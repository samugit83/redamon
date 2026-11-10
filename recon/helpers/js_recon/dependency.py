"""
JS Recon Dependency Confusion Detection

Detects npm dependency confusion vulnerabilities by extracting scoped package
names from JS imports and checking if they exist on the public npm registry.
"""

import re
import hashlib
import threading
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import Optional


# Patterns to extract package names from JS content
_IMPORT_PATTERNS = [
    # ES6 import: import ... from '@scope/package'
    re.compile(r'''import\s+.*?from\s+['"](@[^'"\/]+\/[^'"\/]+)['"]'''),
    # CommonJS require: require('@scope/package')
    re.compile(r'''require\(\s*['"](@[^'"\/]+\/[^'"\/]+)['"]\s*\)'''),
    # Dynamic import: import('@scope/package')
    re.compile(r'''import\(\s*['"](@[^'"\/]+\/[^'"\/]+)['"]\s*\)'''),
    # Re-export: export ... from '@scope/package'
    re.compile(r'''export\s+.*?from\s+['"](@[^'"\/]+\/[^'"\/]+)['"]'''),
]

# Webpack chunk patterns
_WEBPACK_CHUNK_NAME_RE = re.compile(r'webpackChunkName:\s*["\']([^"\']+)["\']')
_WEBPACK_MODULE_RE = re.compile(r'__webpack_require__\(\s*["\']([^"\']+)["\']\s*\)')

# Thread-safe cache for npm registry lookups (package_name -> exists)
_npm_cache = {}
_npm_cache_lock = threading.Lock()


def _check_npm_registry(package_name: str, timeout: int = 10) -> Optional[bool]:
    """
    Check if a package exists on the public npm registry.

    Returns True if the package exists, False if 404 (potential confusion
    target), None when the registry gave no answer (not checked).
    """
    with _npm_cache_lock:
        if package_name in _npm_cache:
            return _npm_cache[package_name]

    from recon.helpers import circuit_breaker as cb
    breaker = cb.get_breaker("npm", label="npm", threshold=cb.INTERNAL_THRESHOLD)
    # The open breaker spares an unreachable registry 10s per package. A
    # skipped or failed call is "not checked", never "published": read as
    # published, an outage run looks clean and the prune deletes every earlier
    # finding. detect_dependency_confusion hands such packages back to
    # js_recon, which keeps their importing hosts' findings and whose report
    # scope names the breaker.
    if not breaker.allow():
        return None

    def classify(resp):
        # 404 is a real answer ("not published"), not a failure.
        return cb.json_result(resp, keyed=False, no_data=(404,))

    res = cb.guarded_call(
        breaker,
        lambda: requests.get(f'https://registry.npmjs.org/{package_name}', timeout=timeout,
                             headers={'Accept': 'application/json'}),
        classify)
    if not res.answered:
        # A failure is not cached: a later package retries once the breaker heals.
        return None
    exists = res.ok
    with _npm_cache_lock:
        _npm_cache[package_name] = exists
    return exists


def extract_scoped_packages(content: str) -> list:
    """
    Extract scoped npm package names from JavaScript content.

    Returns list of unique scoped package names (e.g., '@myorg/mylib').
    """
    packages = set()

    for pattern in _IMPORT_PATTERNS:
        for match in pattern.finditer(content):
            pkg = match.group(1)
            # Validate package name format
            if '/' in pkg and pkg.startswith('@'):
                packages.add(pkg)

    return list(packages)


def extract_webpack_packages(content: str) -> list:
    """
    Extract package names from webpack chunk configurations.

    Returns list of package name strings.
    """
    packages = set()

    for match in _WEBPACK_CHUNK_NAME_RE.finditer(content):
        name = match.group(1)
        # Webpack chunk names that look like package names
        if '/' in name or name.startswith('@'):
            packages.add(name)

    return list(packages)


def detect_dependency_confusion(
    js_files: list,
    settings: dict,
    unchecked: Optional[list] = None,
) -> list:
    """
    Detect potential npm dependency confusion vulnerabilities.

    Args:
        js_files: List of dicts with 'url' and 'content'
        settings: Project settings dict
        unchecked: when given, receives, for each package the registry did
            not answer for, the list of every file that imports it (or
            ``custom_packages_file``); such a package yields no finding

    Returns:
        List of dependency confusion finding dicts
    """
    if not settings.get('JS_RECON_DEPENDENCY_CHECK', True):
        return []

    # Load known internal packages from custom file
    known_internal = set()
    custom_file = settings.get('JS_RECON_CUSTOM_PACKAGES', '')
    if custom_file:
        try:
            with open(custom_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        known_internal.add(line)
        except Exception as e:
            print(f"[!][JsRecon] Failed to load custom packages file: {e}")

    # Collect all scoped packages across all JS files
    package_sources = {}  # package_name -> list of source_urls

    for js_file in js_files:
        try:
            url = js_file.get('url', '')
            content = js_file.get('content', '')

            if not content:
                continue

            # Extract scoped packages
            scoped = extract_scoped_packages(content)
            for pkg in scoped:
                if pkg not in package_sources:
                    package_sources[pkg] = []
                if url not in package_sources[pkg]:
                    package_sources[pkg].append(url)

            # Extract webpack packages
            webpack_pkgs = extract_webpack_packages(content)
            for pkg in webpack_pkgs:
                if pkg.startswith('@') and pkg not in package_sources:
                    package_sources[pkg] = []
                if pkg.startswith('@') and url not in package_sources.get(pkg, []):
                    package_sources.setdefault(pkg, []).append(url)
        except Exception as e:
            print(f"[!][JsRecon] Dependency extraction failed for {js_file.get('url', '?')}: {e}")

    # Add known internal packages that should be checked
    for pkg in known_internal:
        if pkg not in package_sources:
            package_sources[pkg] = ['custom_packages_file']

    # Build the candidate list (skip well-known public scopes)
    public_scopes = ('@types', '@babel', '@angular', '@vue', '@react', '@next',
                     '@nuxt', '@svelte', '@emotion', '@mui', '@chakra-ui',
                     '@radix-ui', '@headlessui', '@tanstack', '@trpc',
                     '@prisma', '@nestjs', '@aws-sdk', '@azure', '@google-cloud',
                     '@stripe', '@sentry', '@datadog', '@testing-library',
                     '@jest', '@vitest', '@eslint', '@typescript-eslint',
                     '@rollup', '@vitejs', '@webpack', '@storybook')

    candidates = []
    for package_name, source_urls in package_sources.items():
        scope = package_name.split('/')[0] if '/' in package_name else ''
        if scope in public_scopes:
            continue
        candidates.append((package_name, scope, source_urls))

    # Parallel npm registry lookups. npm rate-limits anonymous traffic, so
    # cap workers conservatively (<= 10) regardless of JS_RECON_CONCURRENCY.
    workers = max(1, min(settings.get('JS_RECON_CONCURRENCY', 10), 10))
    existence = {}
    if candidates:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for (pkg, _, _), exists in zip(
                candidates,
                ex.map(_check_npm_registry, [c[0] for c in candidates]),
            ):
                existence[pkg] = exists

    # Build findings sequentially (cheap CPU work)
    findings = []
    for package_name, scope, source_urls in candidates:
        npm_exists = existence.get(package_name)

        if npm_exists is None:
            if unchecked is not None:
                unchecked.append(list(source_urls))
        elif not npm_exists:
            finding_id = hashlib.sha256(f"depconf:{package_name}".encode()).hexdigest()[:16]
            findings.append({
                'id': finding_id,
                'finding_type': 'dependency_confusion',
                'package_name': package_name,
                'scope': scope,
                'npm_exists': False,
                'severity': 'critical',
                'confidence': 'high',
                'title': f'Dependency confusion: {package_name} not on public npm',
                'detail': f'Package {package_name} is imported in JS but does not exist on the public npm registry. '
                          f'An attacker could register this package name and execute arbitrary code.',
                'source_urls': source_urls[:5],
                'recommendation': f'Register {package_name} on npm as a placeholder or use a private registry.',
            })
        elif package_name in known_internal:
            # Package exists on npm but user marked it as internal -- potential takeover
            finding_id = hashlib.sha256(f"depconf-exists:{package_name}".encode()).hexdigest()[:16]
            findings.append({
                'id': finding_id,
                'finding_type': 'dependency_confusion',
                'package_name': package_name,
                'scope': scope,
                'npm_exists': True,
                'severity': 'high',
                'confidence': 'medium',
                'title': f'Potential dependency confusion: {package_name} exists on npm but marked as internal',
                'detail': f'Package {package_name} exists on public npm but was marked as an internal package. '
                          f'Verify that the public version is owned by your organization.',
                'source_urls': source_urls[:5],
                'recommendation': f'Verify npm ownership of {package_name}.',
            })

    return findings

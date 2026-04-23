"""
JS Recon Dependency Confusion Detection

Detects npm dependency confusion vulnerabilities by extracting scoped package
names from JS imports and checking if they exist on the public npm registry.
"""

import re
import hashlib
import threading
import requests
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

# Patterns for unscoped internal-looking packages
_INTERNAL_PACKAGE_INDICATORS = [
    'internal', 'private', 'core', 'shared', 'common', 'utils',
    'helpers', 'lib', 'sdk', 'api-client', 'client-sdk',
]

# Webpack chunk patterns
_WEBPACK_CHUNK_NAME_RE = re.compile(r'webpackChunkName:\s*["\']([^"\']+)["\']')
_WEBPACK_MODULE_RE = re.compile(r'__webpack_require__\(\s*["\']([^"\']+)["\']\s*\)')

# Thread-safe cache for npm registry lookups (package_name -> exists)
_npm_cache = {}
_npm_cache_lock = threading.Lock()


def _check_npm_registry(package_name: str, timeout: int = 10) -> bool:
    """
    Check if a package exists on the public npm registry.

    Returns True if the package exists, False if 404 (potential confusion target).
    """
    with _npm_cache_lock:
        if package_name in _npm_cache:
            return _npm_cache[package_name]

    try:
        resp = requests.get(
            f'https://registry.npmjs.org/{package_name}',
            timeout=timeout,
            headers={'Accept': 'application/json'},
        )
        exists = resp.status_code == 200
        with _npm_cache_lock:
            _npm_cache[package_name] = exists
        return exists
    except requests.RequestException:
        # On error, assume it exists (conservative -- don't flag as confusion)
        return True


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


def _looks_internal(package_name: str) -> bool:
    """Check if an unscoped package name looks like an internal package."""
    name_lower = package_name.lower()
    return any(indicator in name_lower for indicator in _INTERNAL_PACKAGE_INDICATORS)


def detect_dependency_confusion(
    js_files: list,
    settings: dict,
) -> list:
    """
    Detect potential npm dependency confusion vulnerabilities.

    Args:
        js_files: List of dicts with 'url' and 'content'
        settings: Project settings dict

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

    # Check each scoped package against npm registry
    findings = []

    for package_name, source_urls in package_sources.items():
        scope = package_name.split('/')[0] if '/' in package_name else ''

        # Skip well-known public scopes
        if scope in ('@types', '@babel', '@angular', '@vue', '@react', '@next',
                      '@nuxt', '@svelte', '@emotion', '@mui', '@chakra-ui',
                      '@radix-ui', '@headlessui', '@tanstack', '@trpc',
                      '@prisma', '@nestjs', '@aws-sdk', '@azure', '@google-cloud',
                      '@stripe', '@sentry', '@datadog', '@testing-library',
                      '@jest', '@vitest', '@eslint', '@typescript-eslint',
                      '@rollup', '@vitejs', '@webpack', '@storybook'):
            continue

        npm_exists = _check_npm_registry(package_name)

        if not npm_exists:
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

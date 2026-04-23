"""
JS Recon Deep Endpoint Extraction

Extracts API endpoints, GraphQL queries, WebSocket connections, router
definitions, and admin/debug paths from JavaScript content. Goes beyond
jsluice with pattern-aware parsing.

Reuses classify_endpoint() and classify_parameter() from
recon/helpers/resource_enum/classification.py.
"""

import re
import hashlib
from urllib.parse import urlparse, parse_qs
from typing import Optional


# ========== REST API Patterns ==========
_REST_PATTERNS = [
    # fetch('url') or fetch("url")
    re.compile(r'''fetch\(\s*['"]([^'"]+)['"]'''),
    # axios.get/post/put/delete/patch('url')
    re.compile(r'''axios\.(?:get|post|put|delete|patch|head|options)\(\s*['"]([^'"]+)['"]'''),
    # $.ajax({url: 'url'})
    re.compile(r'''\$\.ajax\(\s*\{[^}]*url:\s*['"]([^'"]+)['"]'''),
    # XMLHttpRequest.open('METHOD', 'url')
    re.compile(r'''\.open\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"],\s*['"]([^'"]+)['"]'''),
    # http.get/post/put/delete('url') (node http client)
    re.compile(r'''(?:http|https|client|api)\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]'''),
    # request('url') or request({url: 'url'})
    re.compile(r'''request\(\s*['"]([^'"]+)['"]'''),
    # superagent: superagent.get('url'), agent.post('url')
    re.compile(r'''(?:superagent|agent)\.(?:get|post|put|del|patch)\(\s*['"]([^'"]+)['"]'''),
]

# Method extraction from fetch/axios patterns
_METHOD_PATTERNS = [
    re.compile(r'''fetch\([^)]*,\s*\{[^}]*method:\s*['"](\w+)['"]''', re.DOTALL),
    re.compile(r'''axios\.(get|post|put|delete|patch|head|options)\('''),
    re.compile(r'''\.open\(\s*['"](\w+)['"]'''),
]

# ========== Config Object Patterns ==========
_CONFIG_PATTERNS = [
    # baseURL: 'url'
    re.compile(r'''baseURL:\s*['"]([^'"]+)['"]'''),
    # apiUrl: 'url', API_URL: 'url'
    re.compile(r'''(?:api[_-]?(?:url|base|endpoint|host)|API[_-]?(?:URL|BASE|ENDPOINT|HOST))\s*[:=]\s*['"]([^'"]+)['"]''', re.IGNORECASE),
    # serverUrl, backendUrl
    re.compile(r'''(?:server|backend|service)[_-]?(?:url|host|base)\s*[:=]\s*['"]([^'"]+)['"]''', re.IGNORECASE),
]

# ========== GraphQL Patterns ==========
_GRAPHQL_ENDPOINT_RE = re.compile(r'''['"]([^'"]*(?:graphql|gql)[^'"]*)['"]\s*''', re.IGNORECASE)
_GRAPHQL_QUERY_RE = re.compile(r'''(?:query|mutation|subscription)\s+(\w+)\s*[\({]''')
_GRAPHQL_INTROSPECTION_RE = re.compile(r'''(?:__schema|__type|IntrospectionQuery)''')

# ========== WebSocket Patterns ==========
_WEBSOCKET_PATTERNS = [
    re.compile(r'''new\s+WebSocket\(\s*['"]([^'"]+)['"]'''),
    re.compile(r'''io\(\s*['"]([^'"]+)['"]'''),
    re.compile(r'''io\.connect\(\s*['"]([^'"]+)['"]'''),
    re.compile(r'''(?:socket|ws)[_-]?(?:url|endpoint|server)\s*[:=]\s*['"]([^'"]+)['"]''', re.IGNORECASE),
]

# ========== Router Definition Patterns ==========
_ROUTER_PATTERNS = [
    # React Router: path="/route" or path='/route'
    re.compile(r'''(?:path|to)\s*[:=]\s*['"]([/][^'"]+)['"]'''),
    # Vue Router: { path: '/route' }
    re.compile(r'''path:\s*['"]([/][^'"]+)['"]'''),
    # Express-style: app.get('/route'), router.post('/route')
    re.compile(r'''(?:app|router)\.(?:get|post|put|delete|patch|use|all)\(\s*['"]([/][^'"]+)['"]'''),
]

# ========== API Documentation Endpoints ==========
_API_DOC_PATHS = [
    '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
    '/api-docs', '/api/docs', '/api/documentation',
    '/openapi.json', '/openapi.yaml', '/openapi',
    '/graphql/playground', '/graphiql', '/graphql/explorer',
    '/redoc', '/api/redoc',
]

# ========== Debug/Admin Endpoints ==========
_ADMIN_DEBUG_PATHS = [
    '/debug', '/admin', '/internal', '/actuator', '/actuator/health',
    '/actuator/env', '/actuator/info', '/health', '/healthcheck',
    '/metrics', '/prometheus', '/env', '/config', '/status',
    '/_debug', '/_admin', '/_internal', '/_config',
    '/phpinfo', '/server-status', '/server-info',
    '/wp-admin', '/wp-login.php',
    '/elmah.axd', '/trace.axd',
]

# ========== Auth Endpoints ==========
_AUTH_PATHS = [
    '/login', '/signin', '/sign-in', '/auth', '/authenticate',
    '/oauth', '/oauth/authorize', '/oauth/token', '/oauth/callback',
    '/token', '/refresh-token', '/api/token',
    '/register', '/signup', '/sign-up',
    '/password', '/forgot-password', '/reset-password',
    '/logout', '/signout', '/sign-out',
    '/sso', '/saml', '/cas',
    '/mfa', '/2fa', '/verify',
]

# Hidden parameter names
_HIDDEN_PARAMS = {
    'debug', 'admin', 'test', 'verbose', 'trace', 'dev',
    'internal', 'staging', 'preview', 'beta', 'experimental',
}


def _extract_method(line: str) -> str:
    """Try to extract HTTP method from a code line."""
    for pattern in _METHOD_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1).upper()
    if 'post' in line.lower() or 'POST' in line:
        return 'POST'
    if 'put' in line.lower() or 'PUT' in line:
        return 'PUT'
    if 'delete' in line.lower() or 'DELETE' in line:
        return 'DELETE'
    return 'GET'


def _extract_params_from_url(url: str) -> list:
    """Extract query parameter names from a URL."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    except Exception:
        return []


def _is_likely_path(s: str) -> bool:
    """Check if a string looks like a URL path (not a CSS selector, variable name, etc.)."""
    if not s or len(s) < 2:
        return False
    if not s.startswith(('/', 'http://', 'https://', 'ws://', 'wss://')):
        return False
    # Skip obvious non-paths
    if any(ext in s for ext in ('.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf', '.eot')):
        return False
    # Skip SPA hash routes (only for paths, not full URLs)
    if s.startswith('/#') or s.startswith('/#!/'):
        return False
    # Skip node_modules paths
    if 'node_modules' in s:
        return False
    return True


def _classify_path(path: str) -> dict:
    """Classify a path into categories."""
    path_lower = path.lower()

    # API documentation
    for doc_path in _API_DOC_PATHS:
        if doc_path in path_lower:
            return {'category': 'api_documentation', 'severity': 'medium'}

    # Admin/debug
    for admin_path in _ADMIN_DEBUG_PATHS:
        if admin_path in path_lower:
            return {'category': 'admin_debug', 'severity': 'high'}

    # Auth endpoints
    for auth_path in _AUTH_PATHS:
        if auth_path in path_lower:
            return {'category': 'authentication', 'severity': 'medium'}

    # API versioning
    if re.search(r'/v[0-9]+/', path):
        return {'category': 'api', 'severity': 'info'}

    # File upload
    if any(kw in path_lower for kw in ('upload', 'attach', 'import', 'file')):
        return {'category': 'file_upload', 'severity': 'medium'}

    return {'category': 'endpoint', 'severity': 'info'}


def extract_endpoints(
    js_files: list,
    settings: dict,
) -> list:
    """
    Extract API endpoints from JavaScript files.

    Args:
        js_files: List of dicts with 'url' and 'content'
        settings: Project settings dict

    Returns:
        List of endpoint finding dicts
    """
    if not settings.get('JS_RECON_EXTRACT_ENDPOINTS', True):
        return []

    # Load custom keywords
    custom_keywords = []
    custom_file = settings.get('JS_RECON_CUSTOM_ENDPOINT_KEYWORDS', '')
    if custom_file:
        try:
            with open(custom_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        custom_keywords.append(line)
        except Exception as e:
            print(f"[!][JsRecon] Failed to load custom endpoint keywords: {e}")

    all_endpoints = {}  # url -> endpoint_dict (for deduplication)
    graphql_findings = []
    websocket_findings = []

    # Pre-compile custom keyword regexes once
    compiled_keywords = [(kw, re.compile(re.escape(kw), re.IGNORECASE)) for kw in custom_keywords]

    for js_file in js_files:
        source_url = js_file.get('url', '')
        content = js_file.get('content', '')
        if not content:
            continue

        try:
            lines = content.split('\n')

            # Extract REST endpoints
            for line_num, line in enumerate(lines, 1):
                for pattern in _REST_PATTERNS:
                    for match in pattern.finditer(line):
                        url = match.group(1)
                        if not _is_likely_path(url):
                            continue

                        method = _extract_method(line)
                        params = _extract_params_from_url(url)
                        classification = _classify_path(url)

                        try:
                            parsed = urlparse(url)
                            path = parsed.path or url
                            base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ''
                        except Exception:
                            path = url
                            base = ''

                        key = f"{method}:{path}"
                        if key not in all_endpoints:
                            finding_id = hashlib.sha256(f"ep:{key}".encode()).hexdigest()[:16]
                            all_endpoints[key] = {
                                'id': finding_id,
                                'method': method,
                                'path': path,
                                'full_url': url,
                                'type': 'rest',
                                'base_url': base,
                                'source_js': source_url,
                                'parameters': params,
                                'category': classification['category'],
                                'severity': classification['severity'],
                                'line_number': line_num,
                            }

                # Extract config object URLs
                for pattern in _CONFIG_PATTERNS:
                    for match in pattern.finditer(line):
                        url = match.group(1)
                        if _is_likely_path(url) or url.startswith('http'):
                            key = f"CONFIG:{url}"
                            if key not in all_endpoints:
                                finding_id = hashlib.sha256(f"cfg:{url}".encode()).hexdigest()[:16]
                                all_endpoints[key] = {
                                    'id': finding_id,
                                    'method': 'GET',
                                    'path': url,
                                    'full_url': url,
                                    'type': 'config',
                                    'base_url': '',
                                    'source_js': source_url,
                                    'parameters': [],
                                    'category': 'api_config',
                                    'severity': 'info',
                                    'line_number': line_num,
                                }

            # Extract GraphQL patterns
            for match in _GRAPHQL_ENDPOINT_RE.finditer(content):
                gql_url = match.group(1)
                if _is_likely_path(gql_url):
                    finding_id = hashlib.sha256(f"gql:{gql_url}".encode()).hexdigest()[:16]
                    graphql_findings.append({
                        'id': finding_id,
                        'method': 'POST',
                        'path': gql_url,
                        'full_url': gql_url,
                        'type': 'graphql',
                        'source_js': source_url,
                        'parameters': [],
                        'category': 'graphql',
                        'severity': 'medium',
                    })

            # Check for GraphQL introspection
            if _GRAPHQL_INTROSPECTION_RE.search(content):
                finding_id = hashlib.sha256(f"gql-intro:{source_url}".encode()).hexdigest()[:16]
                graphql_findings.append({
                    'id': finding_id,
                    'method': 'POST',
                    'path': '/graphql',
                    'full_url': '',
                    'type': 'graphql_introspection',
                    'source_js': source_url,
                    'parameters': [],
                    'category': 'graphql',
                    'severity': 'medium',
                    'title': 'GraphQL introspection query detected',
                })

            # Extract WebSocket endpoints
            for pattern in _WEBSOCKET_PATTERNS:
                for match in pattern.finditer(content):
                    ws_url = match.group(1)
                    finding_id = hashlib.sha256(f"ws:{ws_url}".encode()).hexdigest()[:16]
                    websocket_findings.append({
                        'id': finding_id,
                        'method': 'WS',
                        'path': ws_url,
                        'full_url': ws_url,
                        'type': 'websocket',
                        'source_js': source_url,
                        'parameters': [],
                        'category': 'websocket',
                        'severity': 'info',
                    })

            # Extract router definitions
            for pattern in _ROUTER_PATTERNS:
                for match in pattern.finditer(content):
                    route = match.group(1)
                    if len(route) > 2 and route.startswith('/') and _is_likely_path(route):
                        classification = _classify_path(route)
                        key = f"ROUTE:{route}"
                        if key not in all_endpoints:
                            finding_id = hashlib.sha256(f"route:{route}".encode()).hexdigest()[:16]
                            all_endpoints[key] = {
                                'id': finding_id,
                                'method': 'GET',
                                'path': route,
                                'full_url': route,
                                'type': 'route',
                                'base_url': '',
                                'source_js': source_url,
                                'parameters': [],
                                'category': classification['category'],
                                'severity': classification['severity'],
                            }

            # Search for custom keywords (pre-compiled outside the file loop)
            for keyword, keyword_re in compiled_keywords:
                for match in keyword_re.finditer(content):
                    # Try to extract the surrounding URL context
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    url_match = re.search(r'''['"]([^'"]*''' + re.escape(keyword) + r'''[^'"]*)['"]\s*''', context, re.IGNORECASE)
                    if url_match:
                        url = url_match.group(1)
                        key = f"CUSTOM:{url}"
                        if key not in all_endpoints:
                            finding_id = hashlib.sha256(f"custom:{url}".encode()).hexdigest()[:16]
                            all_endpoints[key] = {
                                'id': finding_id,
                                'method': 'GET',
                                'path': url,
                                'full_url': url,
                                'type': 'custom_keyword',
                                'base_url': '',
                                'source_js': source_url,
                                'parameters': [],
                                'category': 'custom',
                                'severity': 'medium',
                            }
        except Exception as e:
            print(f"[!][JsRecon] Endpoint extraction failed for {source_url or '?'}: {e}")

    # Combine all findings
    results = list(all_endpoints.values()) + graphql_findings + websocket_findings

    # Deduplicate by id
    seen = set()
    deduped = []
    for ep in results:
        if ep['id'] not in seen:
            seen.add(ep['id'])
            deduped.append(ep)

    return deduped

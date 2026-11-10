"""
JS Recon Deep Endpoint Extraction

Extracts API endpoints, GraphQL queries, WebSocket connections, router
definitions, and admin/debug paths from JavaScript content. Goes beyond
jsluice with pattern-aware parsing.

Every endpoint gets the shared word in `category` (classify_endpoint() from
recon/helpers/resource_enum/classification.py, as every other module writes),
and JS Recon's own label (api_documentation, admin_debug, file_upload,
graphql, websocket...) with its severity in `js_recon_category`, which Route
Exposure's ranking and the AI route ranking read.
"""

import re
import hashlib
from urllib.parse import urlsplit, urlparse, parse_qs
from typing import Optional


# ========== REST API Patterns ==========
# The URL argument: a quoted or backtick literal, optionally after a base the
# code adds in front (fetch(API_BASE + "/v2/items")), whose literal part is
# the path.
_LITERAL = r'''(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|`(?P<bt>[^`]*)`)'''
_BASE_PLUS = r'''(?:[\w$.]+(?:\(\))?\s*\+\s*)?'''
_URL_ARG = _BASE_PLUS + _LITERAL
_VERB_NAMES = 'get|post|put|patch|delete|head|options'
_VERBS = f'(?:{_VERB_NAMES})'

# (pattern, relative): a path without a leading slash (api.get("v1/accounts"))
# counts only from a call that is HTTP by name; from any other receiver
# (map.get("key"), params.get("q"), headers.get("content-type")) it is a
# lookup key, not a path.
_REST_PATTERNS = [
    (re.compile(r'''(?<![\w$.])fetch\(\s*''' + _URL_ARG), True),
    (re.compile(r'''(?<![\w$])axios\.(?:''' + _VERB_NAMES + r'''|request)\(\s*''' + _URL_ARG), True),
    (re.compile(r'''\$\.ajax\(\s*\{[^}]*url:\s*''' + _URL_ARG), True),
    # XMLHttpRequest.open('METHOD', 'url')
    (re.compile(r'''\.open\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"],\s*''' + _URL_ARG), True),
    # http/https/client/api clients (node http, axios instances, $http)
    (re.compile(r'''(?<![\w$])(?:http|https|client|api|apiClient|httpClient|\$http)\.''' + _VERBS
                + r'''\(\s*''' + _URL_ARG), True),
    (re.compile(r'''(?<![\w$.])request\(\s*''' + _URL_ARG), False),
    # superagent: superagent.get('url'), agent.post('url')
    (re.compile(r'''(?<![\w$])(?:superagent|agent)\.(?:get|post|put|del|patch)\(\s*''' + _URL_ARG), True),
    # Any receiver's HTTP verb: this.get("/v1/orders"), minified n.get("/users").
    # Express-style app/router calls are routes (_ROUTER_PATTERNS).
    (re.compile(r'''(?<![\w$])(?!(?:app|router)\.)[\w$]+\.''' + _VERBS + r'''\(\s*''' + _URL_ARG), False),
    # A request object as the call's argument: r({url: "/api/export", method: "GET"})
    (re.compile(r'''[\w$]\(\s*\{[^{}]*?\burl\s*:\s*''' + _URL_ARG), False),
]
# A path relative to the client's base: segments of path characters, at least
# two, the first not a host name (no dot) and not ./ or ../.
_RELATIVE_PATH = re.compile(r'''[A-Za-z0-9_~-]+(?:/[A-Za-z0-9_~.%:@!$&'()*+,;=-]*)+(?:\?\S*)?''')


def _literal_url(match: re.Match) -> tuple:
    """``(path, template)`` from a call's URL literal. A template literal keeps
    its literal prefix up to the first ``${`` (``/api/users/`` from
    ``/api/users/${id}``), after a leading ``${base}`` when there is one;
    ``template`` is the whole literal then, else None."""
    if match.group('bt') is not None:
        text = match.group('bt')
        if '${' not in text:
            return text, None
        rest = text
        if rest.startswith('${'):
            close = rest.find('}')
            rest = rest[close + 1:] if close != -1 else ''
        return rest.split('${', 1)[0], text
    return (match.group('dq') if match.group('dq') is not None else match.group('sq')), None

# An endpoint's method comes from its own call, never from the rest of the
# line: a minified bundle is one line, and one `postMessage` on it made every
# endpoint POST. The verb the call names (axios.post, client.put, agent.del,
# xhr.open('PATCH', ...)) wins; then a `method:` / `type:` key in the call's
# own arguments; a call that names neither is a GET, as fetch, request and
# $.ajax default to.
_HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
_CALL_VERB_RE = re.compile(
    r'''\.(get|post|put|patch|delete|del|head|options)\(|\.open\(\s*['"](\w+)['"]''',
    re.IGNORECASE)
_OPTION_METHOD_RE = re.compile(r'''\b(?:method|type)\s*:\s*['"]([A-Za-z]+)['"]''')
# How far past the URL a call's own arguments are read, when its closing
# parenthesis is not reached first.
_METHOD_WINDOW = 150

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


def _normalize_method(word: str) -> str:
    method = (word or '').upper()
    method = 'DELETE' if method == 'DEL' else method
    return method if method in _HTTP_METHODS else ''


def _call_arguments(line: str, end: int) -> str:
    """What follows the matched URL inside the same call, up to the parenthesis
    that closes it (at most _METHOD_WINDOW characters)."""
    tail = line[end:end + _METHOD_WINDOW]
    depth = 1
    for i, ch in enumerate(tail):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return tail[:i]
    return tail


def _extract_method(line: str, match: re.Match) -> str:
    """The HTTP method of the call `match` found in `line`."""
    call = match.group(0)
    verb = _CALL_VERB_RE.search(call)
    if verb:
        method = _normalize_method(verb.group(1) or verb.group(2))
        if method:
            return method
    option = _OPTION_METHOD_RE.search(call + _call_arguments(line, match.end()))
    if option:
        return _normalize_method(option.group(1)) or 'GET'
    return 'GET'


def _endpoint_origin(url: str, source_url: str) -> str:
    """The origin an extracted endpoint belongs to, for deduplication.

    One run reads the bundles of many hosts, and ``/api/users`` called from
    app.example.com and from admin.example.com are two endpoints. Keyed on the
    path alone, the first file read would hide the other host's, and a
    third-party absolute URL (which the writer drops) would hide every in-scope
    one. An absolute or protocol-relative URL carries its own origin; a
    relative path belongs to the file that named it, as the writer and the
    endpoint probe resolve it. An uploaded file names no host, so its relative
    paths share one origin, like the writer's single 'upload' base.
    """
    for candidate, schemes in ((url, None), (source_url, ('http', 'https'))):
        try:
            parts = urlsplit(candidate or '')
        except ValueError:
            continue
        if parts.netloc and (schemes is None or parts.scheme.lower() in schemes):
            return f"{parts.scheme}://{parts.netloc}".lower()
    return ''


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

    # Deduplication across every file of the run; each key carries the
    # endpoint's origin (_endpoint_origin), and each id is that key's hash.
    all_endpoints = {}
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
                for pattern, relative_ok in _REST_PATTERNS:
                    for match in pattern.finditer(line):
                        url, template = _literal_url(match)
                        if relative_ok and _RELATIVE_PATH.fullmatch(url or ''):
                            url = '/' + url
                        if not _is_likely_path(url):
                            continue

                        method = _extract_method(line, match)
                        params = _extract_params_from_url(url)
                        classification = _classify_path(url)

                        try:
                            parsed = urlparse(url)
                            path = parsed.path or url
                            base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ''
                        except Exception:
                            path = url
                            base = ''

                        key = f"{method}:{_endpoint_origin(url, source_url)}:{path}"
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
                                # A template literal: `path` is its literal prefix.
                                'parameterized': template is not None,
                            }
                            if template is not None:
                                all_endpoints[key]['path_template'] = template[:500]

                # Extract config object URLs
                for pattern in _CONFIG_PATTERNS:
                    for match in pattern.finditer(line):
                        url = match.group(1)
                        if _is_likely_path(url) or url.startswith('http'):
                            origin = _endpoint_origin(url, source_url)
                            key = f"CONFIG:{origin}:{url}"
                            if key not in all_endpoints:
                                finding_id = hashlib.sha256(f"cfg:{origin}:{url}".encode()).hexdigest()[:16]
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
                    origin = _endpoint_origin(gql_url, source_url)
                    finding_id = hashlib.sha256(f"gql:{origin}:{gql_url}".encode()).hexdigest()[:16]
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
                    origin = _endpoint_origin(ws_url, source_url)
                    finding_id = hashlib.sha256(f"ws:{origin}:{ws_url}".encode()).hexdigest()[:16]
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
                        origin = _endpoint_origin(route, source_url)
                        key = f"ROUTE:{origin}:{route}"
                        if key not in all_endpoints:
                            finding_id = hashlib.sha256(f"route:{origin}:{route}".encode()).hexdigest()[:16]
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
                        origin = _endpoint_origin(url, source_url)
                        key = f"CUSTOM:{origin}:{url}"
                        if key not in all_endpoints:
                            finding_id = hashlib.sha256(f"custom:{origin}:{url}".encode()).hexdigest()[:16]
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

    from recon.helpers.resource_enum.classification import classify_endpoint
    for ep in deduped:
        if 'js_recon_category' not in ep:
            ep['js_recon_category'] = ep.get('category') or 'endpoint'
            path = str(ep.get('path') or '')
            if '://' in path:
                path = urlsplit(path).path or '/'
            ep['category'] = classify_endpoint(path, [ep.get('method') or 'GET'], {})
    return deduped

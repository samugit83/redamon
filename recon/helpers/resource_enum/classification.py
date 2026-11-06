"""
RedAmon - Classification Helpers
================================
Parameter and endpoint classification utilities for resource enumeration.
"""

import re
from typing import Dict, List


# =============================================================================
# Parameter Name Patterns for Classification
# =============================================================================

PARAM_PATTERNS = {
    'id_params': [
        r'^id$', r'_id$', r'Id$', r'^uid$', r'^pid$', r'^aid$', r'^cid$',
        r'^user_?id$', r'^product_?id$', r'^item_?id$', r'^post_?id$',
        r'^article_?id$', r'^page_?id$', r'^cat_?id$', r'^category_?id$',
        r'^artist$', r'^cat$', r'^pic$', r'^num$', r'^no$', r'^index$'
    ],
    'file_params': [
        r'^file$', r'^filename$', r'^path$', r'^filepath$', r'^download$',
        r'^include$', r'^require$', r'^read$', r'^load$', r'^src$',
        r'^template$', r'^page$', r'^doc$', r'^document$', r'^img$',
        r'^image$', r'^attachment$'
    ],
    'search_params': [
        r'^q$', r'^query$', r'^search$', r'^s$', r'^keyword$', r'^term$',
        r'^find$', r'^filter$', r'^text$', r'^input$'
    ],
    'auth_params': [
        r'^user$', r'^username$', r'^login$', r'^email$', r'^mail$',
        r'^password$', r'^passwd$', r'^pass$', r'^pwd$', r'^token$',
        r'^auth$', r'^key$', r'^apikey$', r'^api_key$', r'^secret$',
        r'^session$', r'^cookie$'
    ],
    'redirect_params': [
        r'^url$', r'^redirect$', r'^return$', r'^next$', r'^goto$',
        r'^target$', r'^dest$', r'^destination$', r'^continue$', r'^ref$',
        r'^callback$', r'^returnurl$', r'^return_url$',
        # Exact names only: `to` is mostly a date range or a recipient; a
        # `?to=https://...` is caught by its value (infer_parameter_type).
        r'^uri$', r'^redirect_uri$', r'^redirect_url$', r'^forward$', r'^forwarded$'
    ],
    'command_params': [
        r'^cmd$', r'^command$', r'^exec$', r'^execute$', r'^run$',
        r'^shell$', r'^system$', r'^ping$', r'^host$', r'^ip$'
    ]
}


# =============================================================================
# Parameter Classification
# =============================================================================

def classify_parameter(param_name: str) -> str:
    """
    Classify a parameter name into a category.
    
    Categories: id_params, file_params, search_params, auth_params, 
                redirect_params, command_params, other
    """
    param_lower = param_name.lower()

    for category, patterns in PARAM_PATTERNS.items():
        for pattern in patterns:
            if re.match(pattern, param_lower, re.IGNORECASE):
                return category

    return 'other'


_URL_VALUE = re.compile(
    r"^(?:https?://|https?%3a|https?%253a|%2f%2f|//[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[:/?#]|$))", re.IGNORECASE)
_NAME_WORDS = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


def _name_words(name: str) -> List[str]:
    """`next_page_url` -> [next, page, url]; `videoId` -> [video, id]."""
    words = []
    for part in re.split(r"[_\-.\[\]]+", name or ""):
        words += [w.lower() for w in _NAME_WORDS.findall(part)]
    return words


def is_url_value(value: str) -> bool:
    """A web address, plain or URL-encoded (once or twice), or scheme-relative."""
    return bool(_URL_VALUE.match((value or "").strip()))


def infer_parameter_type(param_name: str, sample_values: List[str]) -> str:
    """
    Infer the data type of a parameter from its name and sample values.

    Returns: integer, path, email, url, datetime, boolean, or string

    A web address is checked first: `https://a.b/x.html` is a url, not a path,
    and `https://a.b/c@d` is a url, not an email. Name words are matched whole
    (`video` is not `id`, `valid` is not `id`).
    """
    values = [v for v in (sample_values or []) if isinstance(v, str) and v]

    if values:
        if any(is_url_value(v) for v in values):
            return 'url'

        if all(v.isdigit() or (v.startswith('-') and v[1:].isdigit()) for v in values):
            return 'integer'

        if any('/' in v or '\\' in v or '.' in v for v in values):
            if any(v.endswith(('.jpg', '.png', '.gif', '.pdf', '.txt', '.html', '.php', '.js'))
                   for v in values):
                return 'path'

        if any('@' in v and '.' in v for v in values):
            return 'email'

    words = set(_name_words(param_name))
    lower = (param_name or "").lower()
    if words & {'url', 'uri', 'link', 'redirect', 'callback', 'href'}:
        return 'url'
    if words & {'id', 'num', 'count', 'page', 'limit', 'offset', 'size'} or lower in ('uid', 'pid'):
        return 'integer'
    if words & {'file', 'path', 'dir', 'template', 'include', 'filename', 'filepath'}:
        return 'path'
    if words & {'email', 'mail'}:
        return 'email'
    if words & {'date', 'time', 'timestamp'}:
        return 'datetime'
    if words & {'bool', 'flag', 'enabled', 'active'} or (_name_words(param_name)[:1] in (['is'], ['has'])):
        return 'boolean'

    return 'string'


# =============================================================================
# Endpoint Classification
# =============================================================================

def classify_endpoint(path: str, methods: List[str], params: Dict) -> str:
    """
    Classify an endpoint into a category based on path, methods, and parameters.

    Categories:
    - authentication: login, signup, logout, auth-related
    - file_access: file download, image serving, document access
    - api: REST API endpoints
    - admin: admin panels, dashboards
    - dynamic: PHP/ASP/JSP pages with parameters
    - static: HTML, CSS, JS, images
    - upload: file upload endpoints
    - search: search functionality
    - other: default category
    """
    path_lower = path.lower()

    # Check for authentication endpoints
    auth_patterns = ['/login', '/signin', '/signup', '/register', '/logout', '/signout',
                     '/auth', '/oauth', '/password', '/reset', '/forgot', '/session',
                     '/token', '/jwt', '/sso']
    if any(p in path_lower for p in auth_patterns):
        return 'authentication'
    # OpenID Connect and SAML flows, as whole segments only: their public
    # metadata documents (/.well-known/openid-configuration, /saml/metadata) are
    # not login endpoints, and Route Exposure skips authentication paths.
    segments = [seg for seg in path_lower.split('/') if seg]
    if set(segments) & {'oidc', 'openid', 'saml', 'saml2'} and 'metadata' not in segments:
        return 'authentication'

    # Check for admin endpoints
    admin_patterns = ['/admin', '/dashboard', '/panel', '/manage', '/control',
                      '/backend', '/cms', '/wp-admin', '/administrator']
    if any(p in path_lower for p in admin_patterns):
        return 'admin'

    # Check for API endpoints
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
                    '/json', '/xml', '/rpc']
    if any(p in path_lower for p in api_patterns):
        return 'api'

    # Check for file access endpoints
    file_patterns = ['/download', '/file', '/image', '/img', '/media', '/upload',
                     '/attach', '/document', '/doc', '/pdf', '/export']
    if any(p in path_lower for p in file_patterns):
        # Check if it's upload vs download
        if any(p in path_lower for p in ['/upload', '/import']):
            return 'upload'
        return 'file_access'

    # Check for search endpoints
    search_patterns = ['/search', '/find', '/query', '/filter', '/browse']
    if any(p in path_lower for p in search_patterns):
        return 'search'

    # Check body params for auth indicators
    body_params = params.get('body', [])
    body_param_names = [p.get('name', '').lower() for p in body_params]
    if any(p in body_param_names for p in ['username', 'password', 'email', 'login']):
        return 'authentication'

    # Check for static files
    static_extensions = ['.html', '.htm', '.css', '.js', '.txt', '.xml', '.json',
                        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
                        '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip']
    if any(path_lower.endswith(ext) for ext in static_extensions):
        return 'static'

    # Check for dynamic pages (with query params)
    dynamic_extensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl']
    if any(path_lower.endswith(ext) for ext in dynamic_extensions):
        return 'dynamic'

    # If has query params, likely dynamic
    if params.get('query'):
        return 'dynamic'

    # Default
    return 'other'



# =============================================================================
# Labels from page titles (item 4f)
# =============================================================================

#: Product pages that are only a login form.
_LOGIN_ONLY_TITLES = ("login - adminer", "login to webmin", "cpanel login", "sign in [jenkins]",
                      "sign in - jenkins", "jupyter notebook", "phpmyadmin")
#: Products whose page looks the same logged in or not: an admin surface.
_ADMIN_TITLES = ("grafana", "kibana", "kubernetes dashboard", "portainer", "rabbitmq management",
                 "consul by hashicorp", "solr admin", "sonarqube", "argo cd", "rancher",
                 "minio console", "pgadmin", "node-red", "metabase", "zabbix", "airflow",
                 "admin panel")
_LOGIN_TITLE_WORDS = re.compile(r"\b(?:log ?in|sign[ -]in)\b", re.IGNORECASE)
_API_DOC_TITLE = re.compile(r"^(?:swagger ui|redoc)$|api documentation", re.IGNORECASE)


def _norm_title(title) -> str:
    return re.sub(r"\s+", " ", str(title or "")).strip().lower()


def category_from_title(title) -> str:
    """'authentication', 'admin' or '' from a page title. A label, never a
    finding; the caller uses it only where the path rule said 'other'."""
    t = _norm_title(title)
    if not t:
        return ""
    if any(t == x or t.startswith(x) for x in _LOGIN_ONLY_TITLES):
        return "authentication"
    if any(t == x or t.startswith(x + " ") or t.endswith(" " + x) or f" {x} " in f" {t} "
           for x in _ADMIN_TITLES):
        return "admin"
    if _LOGIN_TITLE_WORDS.search(t):
        return "authentication"
    return ""


def is_api_doc_title(title) -> bool:
    """A Swagger UI or ReDoc page, whatever its path: an OpenAPI seed."""
    return bool(_API_DOC_TITLE.search(_norm_title(title)))


def endpoint_category(path: str, methods: List[str], params: Dict, title=None) -> str:
    """The path rule, then the title rule when the path said 'other': computed
    once, before any writer runs (the endpoint writer sets it unconditionally)."""
    category = classify_endpoint(path, methods, params)
    if category == "other" and title:
        return category_from_title(title) or category
    return category

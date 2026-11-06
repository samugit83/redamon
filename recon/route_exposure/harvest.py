"""S1: one Route per (base URL, path, method) out of the in-memory recon corpus.

Reads resource_enum (crawl, ffuf, kiterunner, arjun, OpenAPI), js_recon's
endpoints and http_probe's pages; requests nothing. Every route it keeps is GET
only, concrete, not a static asset, not an auth flow and not state-changing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlsplit

from recon.route_exposure import seeds

try:
    from recon.helpers.resource_enum.classification import classify_endpoint
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.resource_enum.classification import classify_endpoint

# Base-page classes (the page-type hook) whose host serves no application.
_DEAD_PAGE_CLASSES = frozenset({"parked", "default", "placeholder"})
_TEMPLATED = re.compile(r"\{[^/]*\}|/:[A-Za-z_]|<[^/>]+>|\*")
_MAX_PATH_LEN = 2048


@dataclass
class Route:
    """One route the scan may request. Identity is (baseurl, path, method)."""
    baseurl: str
    path: str
    method: str = "GET"
    category: str = "other"
    sources: tuple = ()
    generated_by: str = "found"
    variant_of: str = ""
    discovery_status: Optional[int] = None
    openapi_security: Optional[list] = None
    openapi_tags: tuple = ()
    declared_only: bool = False
    js_only: bool = False
    router: bool = False
    #: An API the bundle defining a client-side router route calls under that route's
    #: first segment (/admin/dashboard -> /api/admin/stats): hidden only by the client.
    client_gated: bool = False
    #: "get" (one GET), "backup" (HEAD then a Range read) or "head" (HEAD only)
    request: str = "get"
    score: int = 0
    floor: bool = False
    hints: list = field(default_factory=list)
    #: Jev's privacy noul (route_privacy_rank), None when Jev was not asked or did not answer.
    jev_rank: Optional[float] = None

    @property
    def url(self) -> str:
        return self.baseurl.rstrip("/") + self.path

    @property
    def key(self) -> tuple:
        return (self.baseurl, self.path, self.method)


def base_of(url: str) -> str:
    """`scheme://netloc`, the BaseURL node's own spelling (http_mixin._split_url)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def has_extension(path: str) -> str:
    """The last segment's extension (".php"), or "" for a directory-like path."""
    last = (path or "").rstrip("/").rsplit("/", 1)[-1]
    if "." not in last.strip("."):
        return ""
    return "." + last.rsplit(".", 1)[-1].lower()


def is_static(path: str) -> bool:
    return has_extension(path) in seeds.STATIC_EXTENSIONS


def is_auth_path(path: str) -> bool:
    low = (path or "").lower()
    if classify_endpoint(low, ["GET"], {}) == "authentication":
        return True
    return any(p in low for p in seeds.AUTH_PATHS)


def is_state_changing(path: str) -> bool:
    """True when any whole token of any segment names an action that changes state."""
    for segment in (path or "").split("/"):
        if not segment:
            continue
        joined = re.sub(r"[^a-z0-9]", "", segment.lower())
        if joined in seeds.STATE_CHANGING_TOKENS:
            return True
        if any(t in seeds.STATE_CHANGING_TOKENS for t in seeds.tokens(segment)):
            return True
    return False


def unsafe_reason(path: str) -> str:
    """Why a path is never requested ("" when it may be)."""
    if not path.startswith("/") or len(path) > _MAX_PATH_LEN or _TEMPLATED.search(path):
        return "template"
    if is_static(path):
        return "static"
    if is_state_changing(path):
        return "state_changing"
    if is_auth_path(path):
        return "auth"
    return ""


def _methods(endpoint: dict) -> list:
    """resource_enum stores `methods`; partial and older shapes carry `method`."""
    methods = endpoint.get("methods") or endpoint.get("method") or ["GET"]
    if isinstance(methods, str):
        methods = [methods]
    return [str(m or "GET").upper() for m in methods] or ["GET"]


def _int_or_none(value) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


@dataclass
class Corpus:
    """What the harvest found: routes, the hosts, and what it refused."""
    routes: dict = field(default_factory=dict)
    bases: list = field(default_factory=list)
    technologies: dict = field(default_factory=dict)
    dead_bases: set = field(default_factory=set)
    unsafe: int = 0
    api_prefixes: dict = field(default_factory=dict)

    def add(self, route: Route) -> bool:
        reason = unsafe_reason(route.path)
        if reason:
            self.unsafe += 1
            return False
        if route.baseurl in self.dead_bases:
            return False
        existing = self.routes.get(route.key)
        if existing is None:
            self.routes[route.key] = route
            return True
        _merge(existing, route)
        return False


#: The stricter request wins a merge, whichever source came first: a heap dump
#: found by a crawler (GET) and by urlscan (HEAD) is probed with HEAD, never
#: downloaded, and a backup is read by its magic bytes, not fetched whole.
_REQUEST_STRICTNESS = {"head": 0, "backup": 1, "get": 2}


def _merge(kept: Route, other: Route) -> None:
    if _REQUEST_STRICTNESS.get(other.request, 2) < _REQUEST_STRICTNESS.get(kept.request, 2):
        kept.request = other.request
    if "backup" in (kept.generated_by, other.generated_by):
        # The backup signatures fire only for routes generated_by 'backup'.
        kept.generated_by = "backup"
    kept.sources = tuple(dict.fromkeys(kept.sources + other.sources))
    if kept.openapi_security is None:
        kept.openapi_security = other.openapi_security
    kept.openapi_tags = tuple(dict.fromkeys(kept.openapi_tags + other.openapi_tags))
    kept.declared_only = kept.declared_only and other.declared_only
    kept.js_only = kept.js_only and other.js_only
    if kept.discovery_status is None:
        kept.discovery_status = other.discovery_status
    if kept.category in ("other", "endpoint", "") and other.category:
        kept.category = other.category
    kept.router = kept.router and other.router


def _read_http_probe(corpus: Corpus, combined_result: dict) -> None:
    by_url = (combined_result.get("http_probe") or {}).get("by_url") or {}
    for url, entry in by_url.items():
        if not isinstance(entry, dict):
            continue
        base = base_of(str(entry.get("url") or url))
        if not base:
            continue
        techs = entry.get("technologies") or []
        if isinstance(techs, list):
            corpus.technologies.setdefault(base, set()).update(
                str(t) for t in techs if isinstance(t, str))
        path = urlsplit(str(entry.get("url") or url)).path or "/"
        if path in ("", "/") and str(entry.get("page_class") or "") in _DEAD_PAGE_CLASSES:
            corpus.dead_bases.add(base)
        if base not in corpus.bases:
            corpus.bases.append(base)


def _note_api_prefix(corpus: Corpus, base: str, path: str) -> None:
    """`/api`, `/api/v2`, `/v1`: the prefixes the seeds are requested under."""
    segments = [s for s in path.split("/") if s]
    prefix = []
    for seg in segments[:3]:
        low = seg.lower()
        if low in ("api", "rest") or re.fullmatch(r"v\d{1,2}", low):
            prefix.append(seg)
            continue
        break
    if prefix:
        corpus.api_prefixes.setdefault(base, set()).add("/" + "/".join(prefix))


def _read_resource_enum(corpus: Corpus, combined_result: dict) -> None:
    by_base = (combined_result.get("resource_enum") or {}).get("by_base_url") or {}
    for base_url, base_data in by_base.items():
        if not isinstance(base_data, dict) or not base_of(str(base_url)):
            continue
        base = str(base_url)
        if base not in corpus.bases:
            corpus.bases.append(base)
        for path, endpoint in (base_data.get("endpoints") or {}).items():
            if not isinstance(endpoint, dict) or not isinstance(path, str):
                continue
            methods = _methods(endpoint)
            openapi = endpoint.get("openapi") if isinstance(endpoint.get("openapi"), dict) else {}
            if not ({"GET", "HEAD"} & set(methods)):
                # A POST/PUT/DELETE route is only requested when its own record
                # says it also answers GET; otherwise a GET to it means nothing.
                corpus.unsafe += 1
                continue
            meta = openapi.get("GET") or openapi.get("HEAD") or {}
            security = meta.get("security") if isinstance(meta, dict) and meta else None
            sources = endpoint.get("sources") or ([endpoint["source"]] if endpoint.get("source") else [])
            category = str(endpoint.get("category") or "other")
            status = _int_or_none(endpoint.get("status_code"))
            route = Route(
                baseurl=base, path=path, category=category,
                sources=tuple(str(s) for s in sources if s),
                discovery_status=status,
                openapi_security=list(security) if isinstance(security, list) else None,
                openapi_tags=tuple(str(t) for t in (meta.get("tags") or []) if isinstance(t, str))
                if isinstance(meta, dict) else (),
                declared_only=endpoint.get("declared_only") is True,
            )
            # ffuf's own label says it answered 403; older data held it in `category`.
            if "forbidden" in (category, endpoint.get("ffuf_category")):
                route.discovery_status = route.discovery_status or 403
            if corpus.add(route):
                _note_api_prefix(corpus, base, path)


_API_LEAD = re.compile(r"^(api|v\d{1,2})$", re.I)


def _head_segment(path: str, *, skip_api: bool = False) -> str:
    segs = [s.lower() for s in (path or "").split("/") if s]
    while skip_api and segs and _API_LEAD.match(segs[0]):
        segs = segs[1:]
    return segs[0] if segs else ""


def _read_js_recon(corpus: Corpus, combined_result: dict, *, routers: bool) -> None:
    endpoints = (combined_result.get("js_recon") or {}).get("endpoints") or []
    router_heads: dict = {}
    calls: dict = {}
    for endpoint in endpoints if isinstance(endpoints, list) else []:
        if not isinstance(endpoint, dict) or endpoint.get("parameterized"):
            continue
        kind = endpoint.get("type")
        is_router = kind == "route"
        if kind not in ("rest", "route", None) or (is_router and not routers):
            continue
        method = str(endpoint.get("method") or "GET").upper()
        if method not in ("GET", "HEAD"):
            continue
        url = endpoint.get("resolved_url") or _resolve(endpoint)
        base = base_of(url)
        if not base:
            continue
        path = urlsplit(url).path or "/"
        # JS Recon's own word ranks the route (admin_debug ranks like admin);
        # `category` holds the shared one.
        route = Route(baseurl=base, path=path,
                      category=str(endpoint.get("js_recon_category") or endpoint.get("category") or "endpoint"),
                      sources=("js_recon",), js_only=True, router=is_router)
        # A route another source also saw is merged: it is no longer js_only.
        if corpus.add(route):
            _note_api_prefix(corpus, base, path)
        source = str(endpoint.get("source_js") or "")
        if is_router:
            head = _head_segment(path)
            if head:
                router_heads.setdefault(source, set()).add(head)
        else:
            calls.setdefault(source, []).append(route.key)
    for source, heads in router_heads.items():
        for key in calls.get(source, []):
            route = corpus.routes.get(key)
            if route is not None and _head_segment(route.path, skip_api=True) in heads:
                route.client_gated = True


def _resolve(endpoint: dict) -> str:
    candidate = endpoint.get("full_url") or endpoint.get("path") or ""
    if not isinstance(candidate, str) or not candidate.strip():
        return ""
    candidate = candidate.strip()
    if candidate.startswith(("http://", "https://")):
        return candidate
    source = endpoint.get("source_js") or ""
    if not isinstance(source, str) or urlsplit(source).scheme not in ("http", "https"):
        return ""
    if candidate.startswith("//"):
        return f"{urlsplit(source).scheme}:{candidate}"
    return urljoin(source, candidate)


_VCS_PROOFS = {".git": ("/.git/HEAD", "/.git/config"), ".svn": ("/.svn/wc.db", "/.svn/entries"),
               ".hg": ("/.hg/requires",)}


def urlscan_handovers(path: str, file_kind: str) -> list:
    """[(path, request, generated_by)] for a sensitive file urlscan saw: only the
    kinds a signature here can prove, each requested the way its signature
    needs. A kind with no signature is not requested at all (a 200 alone
    proves nothing: many sites answer 200 to every path), and a web-shell
    trace is quarantined, never requested."""
    path = (path or "").split("?", 1)[0]
    low = path.lower()
    if not path.startswith("/") or "{" in path:
        return []
    if file_kind == "env":
        return [(path, "get", "found")]
    if file_kind == "vcs":
        for folder, proofs in _VCS_PROOFS.items():
            i = low.find("/" + folder)
            if i >= 0:
                prefix = path[:i]
                return [(prefix + proof, "get", "found") for proof in proofs]
        return []
    if file_kind in ("db_dump", "backup"):
        return [(path, "backup", "backup")]
    if file_kind == "config":
        return [(path, "get", "found")] if low.rstrip("/").endswith("/web.config") else []
    if file_kind == "debug_page":
        return [(path, "get", "found")]
    if file_kind == "debug_console":
        return [(path, "get", "found")] if "/_profiler" in low else []
    if file_kind == "memory_dump":
        return [(path, "head", "found")] if low.rstrip("/").endswith("/actuator/heapdump") else []
    return []


def _read_urlscan(corpus: Corpus, combined_result: dict) -> None:
    """The sensitive files public urlscan visits opened (item 3), on a base that
    is live in this scan: the scan proves from the content whether each one
    is still exposed. Path only, never a query string."""
    for f in (combined_result.get("urlscan") or {}).get("findings") or []:
        if not isinstance(f, dict) or f.get("type") != "sensitive_file_seen":
            continue
        host = str(f.get("host") or "").lower()
        own = base_of(str(f.get("url") or ""))
        live = [b for b in corpus.bases if (urlsplit(b).hostname or "").lower() == host]
        bases = [own] if own in live else live[:1]
        for base in bases:
            for path, request, generated_by in urlscan_handovers(str(f.get("path") or ""),
                                                                 str(f.get("kind") or "")):
                corpus.add(Route(baseurl=base, path=path, sources=("urlscan",),
                                 request=request, generated_by=generated_by))


def harvest(combined_result: dict, *, routers: bool = False) -> Corpus:
    """Build the route corpus. Never requests anything."""
    corpus = Corpus()
    _read_http_probe(corpus, combined_result)
    _read_resource_enum(corpus, combined_result)
    _read_js_recon(corpus, combined_result, routers=routers)
    _read_urlscan(corpus, combined_result)
    # A base whose root page is parked or a default page serves no application.
    if corpus.dead_bases:
        corpus.routes = {k: r for k, r in corpus.routes.items() if r.baseurl not in corpus.dead_bases}
        corpus.bases = [b for b in corpus.bases if b not in corpus.dead_bases]
    return corpus

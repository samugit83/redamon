"""One form for an Endpoint's path, used by every writer before its MERGE.

Endpoint nodes key on (path, method, baseurl). Crawlers, httpx, uncover and
urlscan kept a trailing slash; GAU, ParamSpider and ffuf stripped it, so
`/docs/` and `/docs` became two nodes for one page.
"""


def normalize_endpoint_path(path) -> str:
    """`/docs/` -> `/docs`; the root stays `/`; a path without a leading slash gets one."""
    p = str(path or "").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"

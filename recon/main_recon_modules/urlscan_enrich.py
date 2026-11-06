"""
URLScan.io Passive Enrichment Module

Passive OSINT enrichment using the URLScan.io Search API. Reads the visits
urlscan already recorded for the target to discover subdomains, IPs, TLS info,
server technologies, domain age and screenshots, without touching the target.

Without an API key urlscan returns only the last 30 days of visits, 100 per
search, without its verdicts; RedAmon then reads at most 1,000 visits. A key
reaches older visits (how far depends on the urlscan plan) and larger pages.

Every search of a run goes through one search budget (URLSCAN_MAX_SEARCHES),
shared by every scope group and every caller: the main search here, the
redirect search and Origin Discovery's file-fingerprint search.
"""
import logging
import os
import threading
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

import requests

logger = logging.getLogger(__name__)

# Lets the urlscan lab stand a fake urlscan in. Unset in any real deployment:
# whatever it names receives the project's urlscan API key.
URLSCAN_API_BASE = (os.environ.get("URLSCAN_API_BASE") or "").strip() or "https://urlscan.io/api/v1"

# urlscan answers at most 100 results per search without a key, whatever `size`
# asks (checked live, Nov 2026); with a key a search returns up to 10,000.
KEYLESS_PAGE_SIZE = 100
KEYED_PAGE_SIZE = 10000
# What one run reads at most per root: 10 keyless searches stay under the
# anonymous limit of 30 searches a minute.
KEYLESS_MAX_RESULTS = 1000
KEYED_MAX_RESULTS = 10000
DEFAULT_MAX_RESULTS = 10000
DEFAULT_MAX_SEARCHES = 60

#: The finding sources the urlscan module writes. A run that could not read
#: urlscan in full (rate limit, refused page, spent budget) must not prune them.
URLSCAN_FINDING_SOURCES = ("urlscan_leak", "urlscan")

MAIN_BREAKER = "urlscan:search"


class SearchResults(list):
    """The visits one search returned, with how complete the answer is.

    ``rate_limited``: urlscan answered 429 before any visit arrived.
    ``truncated``: more visits matched than were read (a refused or rate-limited
    later page, the result cap, or the run's search budget).
    """

    def __init__(self, items=(), *, rate_limited=False, failed=False, truncated=False,
                 total=None, searches=0, date_limit_days=None, budget_exhausted=False,
                 cut_reason=""):
        super().__init__(items)
        self.rate_limited = rate_limited
        self.failed = failed
        self.truncated = truncated
        self.total = total
        self.searches = searches
        self.date_limit_days = date_limit_days
        self.budget_exhausted = budget_exhausted
        self.cut_reason = cut_reason


class RateLimitedResults(SearchResults):
    """An empty search result that was a 429, not a real "nothing found".

    Still a list, so every caller that treats it as [] keeps working. Partial
    recon's per-root loop checks for it to wait and retry the root.
    """

    def __init__(self, items=(), **kw):
        kw.setdefault("rate_limited", True)
        super().__init__(items, **kw)


# ---------------------------------------------------------------------------
# The run's search budget
# ---------------------------------------------------------------------------

class SearchBudget:
    """One counter for every urlscan search of a run.

    Spent in this order: the first page of the main search for every root, then
    the redirect search's first page for every root, then further pages, then
    Origin Discovery's hash searches. Those first pages are reserved when the
    run starts (``reserve``), so a later page or an extra search of one root
    never takes the one search another root needs.
    """

    def __init__(self, limit: int):
        try:
            self.limit = max(0, int(limit))
        except (TypeError, ValueError):
            self.limit = DEFAULT_MAX_SEARCHES
        self.used = 0
        self.exhausted = False
        self._pending: set = set()
        self._lock = threading.Lock()

    def reserve(self, caller: str, root: str) -> None:
        with self._lock:
            self._pending.add((caller, (root or "").lower()))

    def take(self, caller: str, root: str = "", *, first: bool = False) -> bool:
        key = (caller, (root or "").lower())
        with self._lock:
            others = len(self._pending - {key}) if first else len(self._pending)
            ok = self.used + others < self.limit
            if first:
                self._pending.discard(key)
            if ok:
                self.used += 1
            else:
                self.exhausted = True
            return ok

    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self.used)


_RUN_BUDGET: Optional[SearchBudget] = None
_RUN_BUDGET_LOCK = threading.Lock()


def _max_searches(settings: dict) -> int:
    value = (settings or {}).get("URLSCAN_MAX_SEARCHES", DEFAULT_MAX_SEARCHES)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return DEFAULT_MAX_SEARCHES


def start_search_budget(settings: dict, roots=()) -> SearchBudget:
    """Start the run's budget (once per full or partial run) and reserve each
    root's first pages."""
    global _RUN_BUDGET
    budget = SearchBudget(_max_searches(settings))
    for root in roots or ():
        if isinstance(root, str) and root:
            budget.reserve("search", root)
            if (settings or {}).get("URLSCAN_REDIRECT_SEARCH"):
                budget.reserve("redirect", root)
    with _RUN_BUDGET_LOCK:
        _RUN_BUDGET = budget
    return budget


def end_search_budget() -> None:
    global _RUN_BUDGET
    with _RUN_BUDGET_LOCK:
        _RUN_BUDGET = None


def search_budget(settings: Optional[dict] = None) -> SearchBudget:
    """The run's budget; a caller outside a started run (a test, a direct call)
    gets a budget of its own."""
    with _RUN_BUDGET_LOCK:
        budget = _RUN_BUDGET
    return budget if budget is not None else SearchBudget(_max_searches(settings or {}))


def effective_max_results(settings: dict, keyed: bool) -> int:
    """What one root's search may read: the saved value, capped at scan start
    (nothing is rewritten, so a code revert restores the saved behaviour)."""
    saved = (settings or {}).get("URLSCAN_MAX_RESULTS", DEFAULT_MAX_RESULTS)
    try:
        saved = int(saved)
    except (TypeError, ValueError):
        saved = DEFAULT_MAX_RESULTS
    return max(1, min(saved, KEYED_MAX_RESULTS if keyed else KEYLESS_MAX_RESULTS))


# ---------------------------------------------------------------------------
# The search
# ---------------------------------------------------------------------------

def _breaker(key: str = MAIN_BREAKER):
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker(key, label="URLScan", parent="urlscan")


def _urlscan_breaker():
    return _breaker(MAIN_BREAKER)


def _classifier(local_refusals: bool):
    """The classify step. For an extra query (not the main search) a 400 or 403
    is that query's own refusal: ``local=True`` keeps it off the provider, so it
    neither switches the main search off nor rejects the key."""
    from recon.helpers import circuit_breaker as cb

    def classify(sent):
        resp, keyed = sent
        res = cb.json_result(resp, keyed=keyed)
        if local_refusals and not res.ok and cb.status_of(resp) in (400, 403):
            return cb.CallResult(None, res.outcome, res.detail, local=True)
        return res
    return classify


def _was_rate_limited(res, breaker) -> bool:
    from recon.helpers import circuit_breaker as cb
    return res.outcome is cb.Outcome.RATE_LIMIT or (
        res.outcome is cb.Outcome.SKIPPED and not breaker.is_fatal
        and (breaker.open_outcome is cb.Outcome.RATE_LIMIT
             or (breaker.parent is not None and breaker.parent.open_outcome is cb.Outcome.RATE_LIMIT)))


def urlscan_search(query: str, api_key: str = "", *, max_results: int = DEFAULT_MAX_RESULTS,
                   key_rotator=None, breaker_key: str = MAIN_BREAKER, caller: str = "search",
                   root: str = "", page: bool = True, local_refusals: bool = False,
                   budget: Optional[SearchBudget] = None) -> SearchResults:
    """Run one urlscan search and return its visits, newest first. Never raises.

    ``page``: follow ``search_after`` until a page comes back empty, the match
    count (``total``) or ``max_results`` is reached. ``has_more`` is not read: it
    is true only above 10,000 matches and does not say a next page exists.
    Every page takes one unit of ``budget``; the first page of a root is the
    one the budget reserved for it.
    """
    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(key_rotator, api_key or "", label="URLScan")
    breaker = _breaker(breaker_key)
    url = f"{URLSCAN_API_BASE}/search/"
    max_results = max(1, int(max_results or 1))
    budget = budget if budget is not None else search_budget()
    keyed_run = keys.has_key
    page_size = KEYED_PAGE_SIZE if keyed_run else KEYLESS_PAGE_SIZE

    collected: list = []
    total = None
    date_limit = None
    searches = 0
    search_after = None
    cut_reason = ""

    while len(collected) < max_results:
        if not budget.take(caller, root, first=(searches == 0)):
            cut_reason = "search budget reached"
            break
        size = min(page_size, max_results - len(collected))

        def send(key, _size=size, _after=search_after):
            params = {"q": query, "size": _size}
            if _after:
                params["search_after"] = _after
            headers = {"API-Key": key} if key else {}
            return requests.get(url, params=params, headers=headers, timeout=60), bool(key)

        res = cb.guarded_call(breaker, send, _classifier(local_refusals), keys=keys)
        searches += 1
        if not res.ok:
            rate_limited = _was_rate_limited(res, breaker)
            if not collected:
                if res.answered:
                    break
                if rate_limited:
                    print("[!][URLScan] Rate limit hit -- try adding an API key in Global Settings")
                    return RateLimitedResults(searches=searches)
                if res.outcome is not cb.Outcome.SKIPPED:
                    print(f"[!][URLScan] Search failed ({res.detail})")
                return SearchResults(failed=True, searches=searches)
            cut_reason = "rate limited" if rate_limited else f"a later page failed ({res.detail})"
            break
        data = res.data if isinstance(res.data, dict) else {}
        if total is None and isinstance(data.get("total"), int):
            total = data["total"]
        if date_limit is None and isinstance(data.get("search_date_limit_days"), int):
            date_limit = data["search_date_limit_days"]
        results = list(data.get("results") or [])
        if not results:
            break
        collected.extend(results[:max_results - len(collected)])
        if not page:
            break
        if total is not None and len(collected) >= total:
            break
        last_sort = results[-1].get("sort") if isinstance(results[-1], dict) else None
        if not isinstance(last_sort, list) or not last_sort:
            break
        search_after = ",".join(str(v) for v in last_sort)

    truncated = bool(cut_reason)
    if not cut_reason and len(collected) >= max_results and (total is None or total > len(collected)):
        truncated, cut_reason = True, "result cap reached"
    if not page and total is not None and total > len(collected):
        truncated = True
    logger.info(f"URLScan search returned {len(collected)} results in {searches} search(es)")
    return SearchResults(collected, truncated=truncated, total=total, searches=searches,
                         date_limit_days=date_limit,
                         budget_exhausted=cut_reason == "search budget reached",
                         cut_reason=cut_reason)


def main_query(domain: str) -> str:
    # page.domain:X matches X and every subdomain, with or without a key
    # (checked live, Nov 2026); the keyed `OR page.domain:*.X` added nothing.
    return f"page.domain:{domain}"


def _urlscan_search(domain: str, api_key: str, max_results: int = DEFAULT_MAX_RESULTS,
                    key_rotator=None, *, budget: Optional[SearchBudget] = None) -> SearchResults:
    """The main search for one root (Q182)."""
    return urlscan_search(main_query(domain), api_key, max_results=max_results,
                          key_rotator=key_rotator, breaker_key=MAIN_BREAKER,
                          caller="search", root=domain, budget=budget)


def _parse_url_path(full_url: str) -> dict | None:
    """Parse a URL into base_url, path, and query params.

    Returns None for root paths (/) or URLs without meaningful paths.
    """
    try:
        parsed = urlparse(full_url)
        path = parsed.path or "/"
        if path == "/" and not parsed.query:
            return None

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        params = {}
        if parsed.query:
            raw_params = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: v[0] if len(v) == 1 else v for k, v in raw_params.items()}

        return {
            "full_url": full_url,
            "base_url": base_url,
            "path": path,
            "params": params,
        }
    except Exception:
        return None


def _extract_domain_from_url(url: str, root_domain: str) -> str | None:
    """Extract subdomain from a URL, only if it belongs to the root domain."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname and (hostname == root_domain or hostname.endswith("." + root_domain)):
            return hostname
    except Exception:
        pass
    return None


def run_urlscan_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run URLScan.io passive enrichment on the target domain.

    Runs after domain discovery, before port scanning.
    Discovers additional subdomains, IPs, and metadata from historical scans.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'urlscan' key added
    """
    if not settings.get("URLSCAN_ENABLED", False):
        return combined_result

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "URLScan",
        settings,
        keys=[
            ("URLSCAN_ENABLED", "Toggle"),
            ("URLSCAN_MAX_RESULTS", "Limits"),
            ("URLSCAN_MAX_SEARCHES", "Limits"),
            ("URLSCAN_LEAKED_LINKS", "Leak detection"),
            ("URLSCAN_SECRETS_IN_URLS", "Leak detection"),
            ("URLSCAN_API_KEY", "API credentials"),
            ("URLSCAN_KEY_ROTATOR", "API credentials"),
        ],
    )

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)

    # URLScan indexes by domain, not IP — skip in IP mode
    if is_ip_mode or not domain:
        return combined_result

    api_key = settings.get("URLSCAN_API_KEY", "")
    key_rotator = settings.get("URLSCAN_KEY_ROTATOR")
    from recon.helpers import circuit_breaker as cb
    keyed = cb.KeyPool(key_rotator, api_key or "", label="URLScan").has_key
    max_results = effective_max_results(settings, keyed)
    budget = search_budget(settings)

    print(f"\n[PHASE] URLScan.io Passive Enrichment")
    print("-" * 40)
    if keyed:
        print(f"[+][URLScan] Using an API key: how far back urlscan answers depends on its plan")
    else:
        print(f"[*][URLScan] No API key: urlscan returns only the last 30 days, "
              f"{KEYLESS_PAGE_SIZE} visits per search, at most {KEYLESS_MAX_RESULTS} read")
    print(f"[*][URLScan] Querying for domain: {domain} (max {max_results} results, "
          f"{budget.remaining()} search(es) left this run)")

    urlscan_scope = cb.scope("urlscan", label="URLScan", unit="search(es)")
    results = _urlscan_search(domain, api_key, max_results, key_rotator=key_rotator, budget=budget)
    coverage = _coverage(results, max_results)
    _note_coverage_gap(domain, results)

    if not results:
        print(f"[-][URLScan] No results found for {domain}")
        combined_result["urlscan"] = {
            "results_count": 0,
            "subdomains_discovered": [],
            "ips_discovered": [],
            "urls_with_paths": [],
            "entries": [],
            "rate_limited": isinstance(results, RateLimitedResults),
            "coverage": coverage,
        }
        urlscan_scope.finish("urlscan_enrich", sources=URLSCAN_FINDING_SOURCES,
                             payload=combined_result["urlscan"])
        return combined_result

    # Parse results
    entries = []
    subdomains: set[str] = set()
    ips: set[str] = set()
    urls_with_paths: list[dict] = []
    quarantined_urls: list[dict] = []
    seen_urls: set[str] = set()
    quarantine = UrlQuarantine(_in_scope_urls(results, domain), hmac_key=_hmac_key())
    scope = HostScope(settings, domain)
    leak_inputs: list = []
    from recon.helpers.url_leaks import mask_url

    # Track domain age (take max from all results)
    domain_age_days = None
    apex_domain_age_days = None
    external_domain_entries = []  # Collect out-of-scope domains for situational awareness

    for result in results:
        page = result.get("page", {})
        task = result.get("task", {})

        page_url = page.get("url", "")
        page_domain = page.get("domain", "")
        page_ip = page.get("ip", "")
        page_asn = page.get("asn", "")
        page_asnname = page.get("asnname", "")
        page_country = page.get("country", "")
        page_server = page.get("server", "")
        page_status = str(page.get("status") or "")
        page_title = page.get("title", "")
        page_tls_issuer = page.get("tlsIssuer", "")
        page_tls_valid_days = page.get("tlsValidDays")
        page_tls_valid_from = page.get("tlsValidFrom", "")
        page_tls_age_days = page.get("tlsAgeDays")
        page_domain_age = page.get("domainAgeDays")
        page_apex_age = page.get("apexDomainAgeDays")
        screenshot = result.get("screenshot", "")
        scan_time = task.get("time", "")

        # Check if this result belongs to the target domain
        # URLScan can return unrelated domains in search results
        is_in_scope = (
            page_domain and
            (page_domain == domain or page_domain.endswith("." + domain))
        )

        # Track subdomain discovery (in-scope only)
        if is_in_scope:
            subdomains.add(page_domain)

        # Also discover subdomains from the URL itself
        url_domain = _extract_domain_from_url(page_url, domain)
        if url_domain:
            subdomains.add(url_domain)
            is_in_scope = True  # URL hostname confirms scope

        # Collect out-of-scope domains for situational awareness. Only the
        # origin is kept: a third party's path is often a private link.
        if not is_in_scope and page_domain:
            external_domain_entries.append({
                "domain": page_domain,
                "source": "urlscan",
                "url": _origin(page_url),
                "status_code": int(page_status) if page_status.isdigit() else None,
                "title": page_title,
                "server": page_server,
                "ip": page_ip,
                "country": page_country,
            })

        # An address a visit recorded is history, not current DNS: kept only for
        # a host the scan may target (group scope, RoE) and when it is routable.
        host_in_scope = bool(is_in_scope and page_domain and scope.host_ok(page_domain))
        ip_in_scope = bool(host_in_scope and page_ip and scope.ip_ok(page_ip))
        if ip_in_scope:
            ips.add(page_ip)

        # Track domain age (in-scope only — foreign domain ages are irrelevant)
        if is_in_scope:
            if page_domain_age is not None:
                if domain_age_days is None or page_domain_age > domain_age_days:
                    domain_age_days = page_domain_age
            if page_apex_age is not None:
                if apex_domain_age_days is None or page_apex_age > apex_domain_age_days:
                    apex_domain_age_days = page_apex_age

        # Parse URL paths for Phase B endpoint creation (in-scope only). A
        # quarantined URL (a one-time link, a secret, a state-changing link with
        # a value, a web-shell trace) never reaches a list anything requests.
        for candidate in (page_url, task.get("url") or ""):
            if candidate and _extract_domain_from_url(candidate, domain):
                leak_inputs.append((candidate, result))
        if page_url and page_url not in seen_urls and is_in_scope:
            seen_urls.add(page_url)
            if quarantine.holds(page_url):
                quarantined_urls.append(quarantine.row(page_url, "page", result))
            else:
                parsed = _parse_url_path(page_url)
                if parsed:
                    urls_with_paths.append(_stored_row(parsed, mask_url))
        task_url = task.get("url", "") or ""
        if (task_url and task_url not in seen_urls and _extract_domain_from_url(task_url, domain)
                and quarantine.holds(task_url)):
            seen_urls.add(task_url)
            quarantined_urls.append(quarantine.row(task_url, "task", result))

        # Build entry. Every URL is stored masked; a quarantined visit keeps no
        # screenshot and no scan ID (either opens the unmasked scan on urlscan).
        visit_quarantined = bool(page_url) and quarantine.holds(page_url)
        entry = {
            # A third party's page keeps its origin only: its path is often a
            # private link (a shared document, a meeting room).
            "url": (mask_url(page_url) if is_in_scope else _origin(page_url)) if page_url else "",
            "domain": page_domain,
            "ip": page_ip,
            "asn": page_asn,
            "asn_name": page_asnname,
            "country": page_country,
            "server": page_server,
            "status": page_status,
            "title": page_title,
            "tls_issuer": page_tls_issuer,
            "tls_valid_days": page_tls_valid_days,
            "tls_valid_from": page_tls_valid_from,
            "tls_age_days": page_tls_age_days,
            "domain_age_days": page_domain_age,
            "screenshot_url": "" if visit_quarantined else screenshot,
            "scan_time": scan_time,
            "scan_id": "" if visit_quarantined else (task.get("uuid") or ""),
            "visibility": task.get("visibility") or "",
            "mime_type": page.get("mimeType") or "",
            "in_scope": host_in_scope,
            "ip_in_scope": ip_in_scope,
            "quarantined": visit_quarantined,
        }
        entries.append(entry)

    # Remove root domain from subdomain list (it's not a "discovery")
    subdomains.discard(domain)

    findings, url_secrets = _leak_findings(leak_inputs, quarantine, scope, settings)

    urlscan_data = {
        "results_count": len(results),
        "subdomains_discovered": sorted(subdomains),
        "ips_discovered": sorted(ips),
        "domain_age_days": domain_age_days,
        "apex_domain_age_days": apex_domain_age_days,
        "urls_with_paths": urls_with_paths,
        "quarantined_urls": quarantined_urls,
        "entries": entries,
        "external_domains": external_domain_entries,
        "coverage": coverage,
        "findings": findings,
        "url_secrets": url_secrets,
    }

    print(f"[+][URLScan] {len(results)} scans found")
    print(f"[+][URLScan] Subdomains discovered: {len(subdomains)}")
    print(f"[+][URLScan] Unique IPs found: {len(ips)}")
    print(f"[+][URLScan] URLs with paths: {len(urls_with_paths)} "
          f"({len(quarantined_urls)} quarantined: never requested)")
    if findings or url_secrets:
        print(f"[+][URLScan] Findings from public visits: {len(findings)}, "
              f"secrets in URLs: {len(url_secrets)}")
    if domain_age_days is not None:
        print(f"[+][URLScan] Domain age: {domain_age_days} days")

    if coverage["truncated"]:
        print(f"[!][URLScan] Read {len(results)} of {coverage.get('total') or 'more'} matching "
              f"visits ({coverage['cut_reason']})")
    urlscan_scope.finish("urlscan_enrich", sources=URLSCAN_FINDING_SOURCES, payload=urlscan_data)
    combined_result["urlscan"] = urlscan_data
    return combined_result


def _coverage(results: SearchResults, max_results: int) -> dict:
    """How much of urlscan's answer this run read: kept in the recon JSON."""
    times = [((r.get("task") or {}).get("time") or "") for r in results if isinstance(r, dict)]
    times = [t for t in times if t]
    return {
        "truncated": bool(getattr(results, "truncated", False)),
        "cut_reason": getattr(results, "cut_reason", "") or "",
        "visits_read": len(results),
        "total": getattr(results, "total", None),
        "max_results": max_results,
        "oldest_seen": min(times) if times else None,
        "searches_used": getattr(results, "searches", 0),
        "search_date_limit_days": getattr(results, "date_limit_days", None),
    }


def _note_coverage_gap(domain: str, results: SearchResults) -> None:
    """Record a cut-short read for the run's coverage record.

    A spent budget or a refused later page leaves visits unread, so the earlier
    urlscan findings are kept (no prune of URLSCAN_FINDING_SOURCES). The result
    cap is the operator's own limit: recorded as a gap only.
    """
    from recon.helpers import circuit_breaker as cb
    reason = getattr(results, "cut_reason", "")
    if not getattr(results, "truncated", False) or not reason:
        return
    if reason == "result cap reached":
        unread = max(0, (getattr(results, "total", 0) or 0) - len(results))
        cb.note_degraded("urlscan_enrich", entries=[{
            "source": "urlscan", "reason": f"urlscan: result cap reached for {domain}",
            "skipped": unread}])
        return
    label = "search budget reached" if getattr(results, "budget_exhausted", False) else reason
    cb.note_degraded("urlscan_enrich", sources=URLSCAN_FINDING_SOURCES,
                     reason=f"urlscan: {label}")


def _origin(url: str) -> str:
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
    except Exception:  # noqa: BLE001
        return ""


def _stored_row(parsed: dict, mask_url) -> dict:
    """A urls_with_paths row as it may be stored and handed on: the URL with
    every value masked, parameter names kept, and each parameter's type
    computed from its value here, before the value is gone (S4)."""
    from recon.helpers.resource_enum.classification import infer_parameter_type
    params = parsed.get("params") or {}
    types = {}
    for name, value in params.items():
        values = value if isinstance(value, list) else [value]
        try:
            types[name] = infer_parameter_type(name, [str(v) for v in values])
        except Exception:  # noqa: BLE001
            types[name] = "string"
    return {
        "full_url": mask_url(parsed["full_url"]) or parsed["full_url"].split("?", 1)[0],
        "base_url": parsed["base_url"],
        "path": parsed["path"],
        "params": {name: "***" for name in params},
        "param_types": types,
    }


class HostScope:
    """Whether a urlscan host, and the address a visit recorded for it, may be
    written as part of the target: the host's scope group (an EXACT group
    lists its hosts; a scan root is a target only with Include Root) and the
    RoE; the address must also be routable and not excluded."""

    def __init__(self, settings: dict, domain: str):
        settings = settings or {}
        self._excluded = list(settings.get("ROE_EXCLUDED_HOSTS") or []) if settings.get("ROE_ENABLED") else []
        self._domain = (domain or "").lower()
        try:
            from recon.helpers.batch_groups import settings_scope_groups
            groups = settings_scope_groups(settings)
        except Exception:  # noqa: BLE001
            groups = []
        self._groups = sorted(
            [g for g in groups if isinstance(g, dict) and g.get("scanRoot")],
            key=lambda g: len(g["scanRoot"]), reverse=True)

    def _roe(self, value: str) -> bool:
        if not self._excluded:
            return False
        from recon.helpers.roe_scope import _is_roe_excluded
        return _is_roe_excluded(value, self._excluded)

    def host_ok(self, host: str) -> bool:
        h = (host or "").strip().strip(".").lower()
        if not h or self._roe(h):
            return False
        for g in self._groups:
            root = str(g["scanRoot"]).strip().lower()
            if h == root:
                return bool(g.get("includeRoot"))
            if h.endswith("." + root):
                if g.get("mode") == "exact":
                    return h in {str(x).strip().lower() for x in g.get("exactHosts") or []}
                return True
        return h == self._domain or h.endswith("." + self._domain)

    def ip_ok(self, ip: str) -> bool:
        import ipaddress
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return False
        if (addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified):
            return False
        return not self._roe(str(addr))


def _hmac_key() -> str:
    # Generated in .env by redamon.sh and forwarded by the orchestrator; empty
    # means no value_hmac, and one Secret per host, type and parameter.
    return (os.environ.get("REDAMON_SECRET_HMAC_KEY") or "").strip()


LINK_SEVERITY = {"password_reset": "high", "account_setup": "high", "login_link": "high",
                 "invite": "medium", "payment": "medium"}
LINK_LABEL = {"password_reset": "password-reset", "account_setup": "account-setup",
              "login_link": "magic-login or verification", "invite": "invitation",
              "payment": "payment or invoice"}
SECRET_SEVERITY = {"password": "high", "api_key": "high", "token": "medium", "jwt": "medium"}


def _is_public(result: dict) -> bool:
    """Only a public visit is an exposure (a keyed search can also return the
    account's own private or unlisted scans). An anonymous search returns only
    public ones, sometimes without saying so."""
    visibility = ((result or {}).get("task") or {}).get("visibility")
    return visibility in (None, "", "public")


def _span(rows: list) -> tuple:
    times = sorted(t for t in rows if t)
    return (times[0], times[-1]) if times else ("", "")


def _leak_findings(inputs: list, quarantine: "UrlQuarantine", scope: "HostScope",
                   settings: dict) -> tuple:
    """Item 2: the target's leaked one-time links (URLSCAN_LEAKED_LINKS) and the
    secrets written in its URLs (URLSCAN_SECRETS_IN_URLS), from public visits of
    target hosts. Grouped: one finding per host, masked path and kind; one
    Secret per value (its HMAC), else per host, type and parameter. Nothing
    raw is kept: masked URLs, lengths and HMACs only, and no scan ID."""
    want_links = bool(settings.get("URLSCAN_LEAKED_LINKS", True))
    want_secrets = bool(settings.get("URLSCAN_SECRETS_IN_URLS", True))
    if not (want_links or want_secrets):
        return [], []
    links: dict = {}
    secrets: dict = {}
    seen = set()
    for url, result in inputs:
        if not _is_public(result):
            continue
        host = (urlparse(url).hostname or "").lower()
        if not host or not scope.host_ok(host):
            continue
        scan_time = ((result or {}).get("task") or {}).get("time") or ""
        scan_id = ((result or {}).get("task") or {}).get("uuid") or ""
        key = (url, scan_id)
        if key in seen:
            continue
        seen.add(key)
        v = quarantine.verdict(url)
        if want_links and v["link_kind"]:
            slot = links.setdefault((host, v["masked_path"], v["link_kind"]), {
                "masked_url": v["masked_url"], "times": [], "count": 0})
            slot["count"] += 1
            slot["times"].append(scan_time)
            slot["masked_url"] = v["masked_url"]
        if want_secrets:
            for sec in v["secrets"]:
                ident = sec.get("value_hmac") or sec["param_name"]
                slot = secrets.setdefault((host, sec["secret_type"], ident), {
                    "sec": sec, "times": [], "count": 0, "masked_url": v["masked_url"]})
                slot["count"] += 1
                slot["times"].append(scan_time)
                if scan_time >= max(slot["times"]):
                    slot["masked_url"] = v["masked_url"]
                    slot["sec"] = sec
    findings = []
    for (host, path, kind), slot in sorted(links.items()):
        first, last = _span(slot["times"])
        label = LINK_LABEL.get(kind, kind)
        findings.append({
            "type": "leaked_one_time_link", "kind": kind, "kind_field": "link_kind",
            "host": host, "path": path or "/", "url": slot["masked_url"],
            "severity": LINK_SEVERITY.get(kind, "medium"),
            "name": f"Leaked {label} link seen on urlscan",
            "description": (
                f"{host}{path} has {label} links in {slot['count']} public urlscan scan(s), seen "
                f"from {first[:10] or 'unknown'} to {last[:10] or 'unknown'}: anyone searching urlscan "
                f"can open them. RedAmon never opened one and cannot tell whether a link still works. "
                f"Make one-time links expire within minutes and work once, and ask urlscan to "
                f"remove the scans; test the lifetime with a link for your own test account."),
            "first_seen": first, "last_seen": last,
            "props": {"link_count": slot["count"]},
        })
    url_secrets = []
    for (host, stype, _ident), slot in sorted(secrets.items()):
        first, last = _span(slot["times"])
        sec = slot["sec"]
        severity = SECRET_SEVERITY.get(stype, "medium")
        if stype == "jwt" and sec.get("jwt_expired") is True:
            severity = "low"
        parsed = urlparse(slot["masked_url"] or "")
        url_secrets.append({
            "host": host, "secret_type": stype, "param_name": sec["param_name"],
            "value_length": sec["value_length"], "value_hmac": sec.get("value_hmac"),
            "jwt_alg": sec.get("jwt_alg"), "jwt_expired": sec.get("jwt_expired"),
            "masked_url": slot["masked_url"],
            "base_url": f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"https://{host}",
            "severity": severity, "first_seen": first, "last_seen": last, "count": slot["count"],
        })
    return findings, url_secrets


def _in_scope_urls(results: list, domain: str) -> list:
    urls = []
    for result in results:
        if not isinstance(result, dict):
            continue
        for part in ("page", "task"):
            url = ((result.get(part) or {}).get("url") or "")
            if url and _extract_domain_from_url(url, domain):
                urls.append(url)
    return urls


class UrlQuarantine:
    """The quarantine verdicts for one search's in-scope URLs. A web-shell trace
    quarantines every URL on its host + path, whichever visit comes first."""

    def __init__(self, urls: list, hmac_key: str = ""):
        from recon.helpers import url_leaks
        self._ul = url_leaks
        self._hmac_key = hmac_key
        self._verdicts = {u: url_leaks.inspect_url(u, hmac_key=hmac_key) for u in dict.fromkeys(urls)}
        self._shells = {url_leaks.host_path_key(u) for u, v in self._verdicts.items() if v["web_shell"]}

    def verdict(self, url: str) -> dict:
        v = self._verdicts.get(url)
        if v is None:
            v = self._verdicts[url] = self._ul.inspect_url(url, hmac_key=self._hmac_key)
        return v

    def holds(self, url: str) -> bool:
        return self.verdict(url)["quarantined"] or self._ul.host_path_key(url) in self._shells

    def row(self, url: str, field: str, result: dict) -> dict:
        """What the graph may keep of a quarantined URL: no value, no scan ID."""
        v = self.verdict(url)
        parsed = urlparse(url)
        reasons = list(v["reasons"])
        if self._ul.host_path_key(url) in self._shells and "web_shell" not in reasons:
            reasons.append("web_shell_host")
        return {
            "base_url": f"{parsed.scheme}://{parsed.netloc}",
            "path": v["masked_path"] or "/",
            "masked_url": v["masked_url"],
            "param_names": sorted({n for n, _ in parse_qs(parsed.query, keep_blank_values=True).items()}),
            "reasons": sorted(reasons),
            "field": field,
            "scan_time": ((result or {}).get("task") or {}).get("time", ""),
        }


def run_urlscan_discovery_only(domain: str, settings: dict[str, Any]) -> dict:
    """
    Run URLScan.io discovery and return only the 'urlscan' data dict.

    Thread-safe: does not need or mutate combined_result. Designed for
    parallel execution alongside other discovery tools (WHOIS, subdomain enum).

    Args:
        domain: Root domain to query
        settings: Project settings dict

    Returns:
        The 'urlscan' data dictionary, or empty dict if disabled/no results.
    """
    if not settings.get("URLSCAN_ENABLED", False):
        return {}

    if not domain:
        return {}

    # Build a minimal combined_result just for the enrichment function
    fake_combined = {
        "domain": domain,
        "metadata": {"ip_mode": False},
    }
    run_urlscan_enrichment(fake_combined, settings)
    return fake_combined.get("urlscan", {})

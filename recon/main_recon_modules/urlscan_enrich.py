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
from datetime import datetime, timezone
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
REDIRECT_BREAKER = "urlscan:redirect"


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


def redirect_query(apex: str) -> str:
    # task.apexDomain / page.apexDomain are the registrable domains of the start
    # and the end, so subdomains are included without a (keyed-only) wildcard;
    # NOT page.apexDomain asks what page.redirected:off-domain does, without
    # depending on that field (absent when nothing redirected).
    return f"task.apexDomain:{apex} AND NOT page.apexDomain:{apex}"


def _under(host: str, root: str) -> bool:
    host, root = (host or "").lower().strip("."), (root or "").lower().strip(".")
    return bool(host) and (host == root or host.endswith("." + root))


def _is_outbound(result: dict, root: str, apex: str) -> bool:
    """A visit that started on this scan root (the query asks for the whole org)
    and ended outside the org."""
    task, page = (result or {}).get("task") or {}, (result or {}).get("page") or {}
    start = (urlparse(task.get("url") or "").hostname or task.get("domain") or "").lower()
    end = (page.get("domain") or urlparse(page.get("url") or "").hostname or "").lower()
    return _under(start, root) and bool(end) and not _under(end, apex)


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
            ("URLSCAN_INJECT_MAX_AGE_DAYS", "Names that join the scan"),
            ("URLSCAN_MAX_INJECTED_HOSTS", "Names that join the scan"),
            ("URLSCAN_REDIRECT_SEARCH", "Outbound redirects"),
            ("URLSCAN_LEAKED_LINKS", "Leak detection"),
            ("URLSCAN_SECRETS_IN_URLS", "Leak detection"),
            ("URLSCAN_SENSITIVE_FILES", "Exposed files"),
            ("URLSCAN_DOCUMENT_LINKS", "Exposed files"),
            ("URLSCAN_TAKEOVER_PAGES", "Problem pages"),
            ("URLSCAN_PROBLEM_PAGES", "Problem pages"),
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

    rate_limited = isinstance(results, RateLimitedResults)
    if not results:
        print(f"[-][URLScan] No results found for {domain}")

    # Item 1: visits that STARTED on the target and ended on another site. A
    # separate search, so they never push the target's own pages out of the
    # main search's results; run whenever the main search was not rate
    # limited (an empty main answer is no reason to skip it).
    redirect_results: list = []
    if settings.get("URLSCAN_REDIRECT_SEARCH") and not rate_limited:
        apex = (combined_result.get("org_domain") or domain).lower()
        redirect_results = urlscan_search(
            redirect_query(apex), api_key, max_results=max_results, key_rotator=key_rotator,
            breaker_key=REDIRECT_BREAKER, caller="redirect", root=domain,
            local_refusals=True, budget=budget)
        redirect_results = [r for r in redirect_results if _is_outbound(r, domain, apex)]
        print(f"[*][URLScan] Outbound redirects: {len(redirect_results)} visit(s) started on "
              f"{domain} and ended elsewhere")

    # Parse results
    entries = []
    subdomains: set[str] = set()
    ips: set[str] = set()
    urls_with_paths: list[dict] = []
    quarantined_urls: list[dict] = []
    seen_urls: set[str] = set()
    redirect_starts = [((r.get("task") or {}).get("url") or "") for r in redirect_results]
    quarantine = UrlQuarantine(_in_scope_urls(results, domain) + [u for u in redirect_starts if u],
                               hmac_key=_hmac_key())
    scope = HostScope(settings, domain)
    leak_inputs: list = []
    from recon.helpers.url_leaks import mask_url

    # Track domain age (take max from all results)
    domain_age_days = None
    apex_domain_age_days = None
    external_domain_entries = []  # Collect out-of-scope domains for situational awareness
    host_last_seen: dict = {}

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
        # When each target host was last seen, for F1 (a recent name joins the scan).
        for seen_url in (page_url, task.get("url") or ""):
            seen_host = _extract_domain_from_url(seen_url, domain) if seen_url else None
            if seen_host and seen_host != domain and scope.host_ok(seen_host):
                host_last_seen[seen_host] = max(host_last_seen.get(seen_host, ""), scan_time or "")

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
                    row = _stored_row(parsed, mask_url)
                    _tag_file_row(row, page_url, page.get("mimeType") or "", settings)
                    if page_title:
                        # Labels a page by its title (item 4f); third-party text.
                        row["title"] = page_title
                    urls_with_paths.append(row)
        task_url = task.get("url", "") or ""
        if (task_url and task_url not in seen_urls and _extract_domain_from_url(task_url, domain)
                and quarantine.holds(task_url)):
            seen_urls.add(task_url)
            quarantined_urls.append(quarantine.row(task_url, "task", result))

        # Build entry. `url` is the masked form; `unmasked_url` is the target's
        # page as urlscan recorded it, for the operator to open.
        visit_quarantined = bool(page_url) and quarantine.holds(page_url)
        entry = {
            # A third party's page keeps its origin only: its path is often a
            # private link (a shared document, a meeting room).
            "url": (mask_url(page_url) if is_in_scope else _origin(page_url)) if page_url else "",
            "unmasked_url": page_url if (page_url and is_in_scope) else "",
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
            "screenshot_url": screenshot,
            "scan_time": scan_time,
            "scan_id": task.get("uuid") or "",
            "visibility": task.get("visibility") or "",
            "mime_type": page.get("mimeType") or "",
            "in_scope": host_in_scope,
            "ip_in_scope": ip_in_scope,
            "quarantined": visit_quarantined,
        }
        entries.append(entry)

    # Remove root domain from subdomain list (it's not a "discovery")
    subdomains.discard(domain)

    redirect = _redirect_rows(redirect_results, domain, quarantine, scope, mask_url)
    leak_inputs += redirect["leak_inputs"]
    quarantined_urls += redirect["quarantined_urls"]
    external_domain_entries += redirect["external_domains"]
    findings, url_secrets = _leak_findings(leak_inputs, quarantine, scope, settings)
    problem_pages, takeover_pages = _problem_pages(
        results, domain, quarantine, scope, settings, combined_result.get("dns") or {})
    findings += _without_titled_pages(_file_findings(leak_inputs, quarantine, scope, settings),
                                      problem_pages)

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
        "findings": findings + redirect["findings"],
        "problem_pages": problem_pages,
        "takeover_pages": takeover_pages,
        "host_last_seen": host_last_seen,
        "url_secrets": url_secrets,
        "redirect_entries": redirect["redirect_entries"],
        "redirect_start_hosts": redirect["start_hosts"],
        "open_redirects": redirect["open_redirects"],
        "rate_limited": rate_limited,
    }

    print(f"[+][URLScan] {len(results)} scans found")
    print(f"[+][URLScan] Subdomains discovered: {len(subdomains)}")
    print(f"[+][URLScan] Unique IPs found: {len(ips)}")
    print(f"[+][URLScan] URLs with paths: {len(urls_with_paths)} "
          f"({len(quarantined_urls)} quarantined: never requested)")
    if findings or url_secrets:
        print(f"[+][URLScan] Findings from public visits: {len(findings)}, "
              f"secrets in URLs: {len(url_secrets)}")
    if problem_pages or takeover_pages:
        print(f"[+][URLScan] Problem pages: {len(problem_pages)}, deleted-service pages: "
              f"{len(takeover_pages)} host(s), checked after httpx")
    if domain_age_days is not None:
        print(f"[+][URLScan] Domain age: {domain_age_days} days")

    if coverage["truncated"]:
        print(f"[!][URLScan] Read {len(results)} of {coverage.get('total') or 'more'} matching "
              f"visits ({coverage['cut_reason']})")
    urlscan_scope.finish("urlscan_enrich", sources=URLSCAN_FINDING_SOURCES, payload=urlscan_data)
    combined_result["urlscan"] = urlscan_data
    return combined_result


DEFAULT_INJECT_MAX_AGE_DAYS = 90
DEFAULT_MAX_INJECTED_HOSTS = 200


def injectable_hosts(urlscan_data: dict, settings: dict, now: Optional[datetime] = None) -> list:
    """F1: the target host names urlscan saw recently enough to join this
    scan, newest first, at most URLSCAN_MAX_INJECTED_HOSTS. A name whose
    deleted-service page item 5 matched is left out: its verdict comes after
    httpx, and probing a parked name is no discovery. merge_group_hosts then
    applies the group scope, the RoE, the syntax, the wildcard check and the
    address guards."""
    settings = settings or {}
    try:
        cap = int(settings.get("URLSCAN_MAX_INJECTED_HOSTS", DEFAULT_MAX_INJECTED_HOSTS))
        max_age = int(settings.get("URLSCAN_INJECT_MAX_AGE_DAYS", DEFAULT_INJECT_MAX_AGE_DAYS))
    except (TypeError, ValueError):
        return []
    if cap <= 0 or not isinstance(urlscan_data, dict):
        return []
    now = now or datetime.now(timezone.utc)
    takeover = {str(p.get("host") or "").lower() for p in urlscan_data.get("takeover_pages") or []
                if isinstance(p, dict)}
    recent = []
    for host, when in (urlscan_data.get("host_last_seen") or {}).items():
        if not isinstance(host, str) or host.lower() in takeover:
            continue
        try:
            seen = datetime.fromisoformat(str(when).replace("Z", "+00:00"))
        except ValueError:
            continue
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        if (now - seen).days <= max_age:
            recent.append((seen, host.lower()))
    recent.sort(key=lambda item: (-item[0].timestamp(), item[1]))
    return [host for _seen, host in recent[:cap]]


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
    """A urls_with_paths row as it is handed on: `full_url` with every value
    masked (the form every request list reads), parameter names kept, each
    parameter's type computed from its value, and `unmasked_url`, the URL as
    seen, for display only."""
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
        "unmasked_url": parsed["full_url"],
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
    Secret per value (its HMAC), else per host, type and parameter. Identities
    are the masked URL and the HMAC; the links themselves (`unmasked_url`,
    `unmasked_urls`) and the secret (`secret_value`) ride along for display."""
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
                "masked_url": v["masked_url"], "times": [], "count": 0, "seen": []})
            slot["count"] += 1
            slot["times"].append(scan_time)
            slot["masked_url"] = v["masked_url"]
            slot["seen"].append((scan_time, url))
        if want_secrets:
            for sec in v["secrets"]:
                ident = sec.get("value_hmac") or sec["param_name"]
                slot = secrets.setdefault((host, sec["secret_type"], ident), {
                    "sec": sec, "times": [], "count": 0, "masked_url": v["masked_url"],
                    "url": url})
                slot["count"] += 1
                slot["times"].append(scan_time)
                if scan_time >= max(slot["times"]):
                    slot["masked_url"] = v["masked_url"]
                    slot["url"] = url
                    slot["sec"] = sec
    findings = []
    for (host, path, kind), slot in sorted(links.items()):
        first, last = _span(slot["times"])
        label = LINK_LABEL.get(kind, kind)
        unmasked = newest_unique_urls(slot["seen"])
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
            "props": {"link_count": slot["count"], "masked_url": slot["masked_url"],
                      "unmasked_url": unmasked[0] if unmasked else None,
                      "unmasked_urls": unmasked or None},
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
            "secret_value": sec.get("value"), "unmasked_url": slot["url"],
            "base_url": f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"https://{host}",
            "severity": severity, "first_seen": first, "last_seen": last, "count": slot["count"],
        })
    return findings, url_secrets


#: How many distinct links of one grouped finding keep their full form.
MAX_UNMASKED_URLS = 25


def newest_unique_urls(seen: list) -> list:
    """The distinct URLs of [(time, url)], newest first, at most MAX_UNMASKED_URLS."""
    out = []
    for _when, url in sorted(seen, key=lambda pair: pair[0] or "", reverse=True):
        if url and url not in out:
            out.append(url)
        if len(out) >= MAX_UNMASKED_URLS:
            break
    return out


def _tag_file_row(row: dict, url: str, mime_type: str, settings: dict) -> None:
    """Item 3 on a urls_with_paths row (the only list the endpoint writer reads):
    a document's type and content type, and a sensitive file's kind, which partial
    Route Exposure reads back to request it the way its kind needs."""
    from recon.helpers.url_leaks import classify_file
    found = classify_file(url, mime_type)
    if found.get("file_kind") and settings.get("URLSCAN_SENSITIVE_FILES", True):
        row["urlscan_file_kind"] = found["file_kind"]
    if found.get("document_type") and settings.get("URLSCAN_DOCUMENT_LINKS", True):
        row["document_type"] = found["document_type"]
        if mime_type:
            row["urlscan_mime_type"] = mime_type.split(";", 1)[0].strip().lower()


FILE_LABEL = {
    "env": "environment file (.env)", "vcs": "version-control folder", "private_key": "private key",
    "db_dump": "database dump", "backup": "backup file", "log": "log file", "config": "config file",
    "debug_page": "debug page (phpinfo)", "installer": "unfinished installer",
    "web_shell_trace": "web-shell command trace", "file_manager": "web file manager",
    "debug_console": "debug console", "memory_dump": "memory dump (heapdump)",
    "salesforce_aura": "Salesforce Aura API",
}


def _file_findings(inputs: list, quarantine: "UrlQuarantine", scope: "HostScope",
                   settings: dict) -> list:
    """Item 3: files and pages that should never be public, opened directly in
    public urlscan visits of target hosts: one finding per host, path and kind,
    with the newest scan and its full URL as evidence. A web-shell trace comes
    from the quarantine."""
    if not settings.get("URLSCAN_SENSITIVE_FILES", True):
        return []
    from recon.helpers.url_leaks import classify_file
    groups: dict = {}
    seen = set()
    for url, result in inputs:
        if not _is_public(result):
            continue
        host = (urlparse(url).hostname or "").lower()
        if not host or not scope.host_ok(host):
            continue
        task = (result or {}).get("task") or {}
        page = (result or {}).get("page") or {}
        key = (url, task.get("uuid") or "")
        if key in seen:
            continue
        seen.add(key)
        v = quarantine.verdict(url)
        if v["web_shell"]:
            kind, severity = "web_shell_trace", "high"
        else:
            mime = (page.get("mimeType") or "") if page.get("url") == url else ""
            found = classify_file(url, mime)
            if not found.get("file_kind"):
                continue
            kind, severity = found["file_kind"], found["severity"]
        slot = groups.setdefault((host, v["masked_path"] or "/", kind), {
            "url": v["masked_url"], "severity": severity, "times": [], "newest": ("", ""),
            "unmasked_url": url})
        slot["times"].append(task.get("time") or "")
        if (task.get("time") or "") >= slot["newest"][0]:
            slot["newest"] = (task.get("time") or "", task.get("uuid") or "")
            slot["unmasked_url"] = url
    out = []
    for (host, path, kind), slot in sorted(groups.items()):
        first, last = _span(slot["times"])
        label = FILE_LABEL.get(kind, kind)
        out.append({
            "type": "sensitive_file_seen", "kind": kind, "kind_field": "file_kind",
            "host": host, "path": path, "url": slot["url"].split("?", 1)[0] if kind != "web_shell_trace"
            else slot["url"], "severity": slot["severity"],
            "name": f"Exposed {label} seen on urlscan",
            "description": (
                f"{host}{path} ({label}) was opened in {len(slot['times'])} public urlscan scan(s), "
                f"seen from {first[:10] or 'unknown'} to {last[:10] or 'unknown'}. RedAmon did not "
                f"request it" + (": someone ran commands through a web shell, so the site may "
                                 "already be compromised." if kind == "web_shell_trace" else
                                 "; turn on Route Exposure to check whether it is still online.")),
            "first_seen": first, "last_seen": last,
            "urlscan_scan_id": slot["newest"][1],
            "props": {"sightings": len(slot["times"]), "unmasked_url": slot["unmasked_url"]},
        })
    return out


def _visit_cname(dns: dict, host: str):
    """The host's CNAME from this scan's DNS map: a list (empty for none) when
    the map knows the host, None when it does not."""
    entry = ((dns or {}).get("subdomains") or {}).get(host)
    if not isinstance(entry, dict) or "records" not in entry:
        return None
    cname = (entry.get("records") or {}).get("CNAME")
    if isinstance(cname, str):
        return [cname]
    return [c for c in cname if isinstance(c, str)] if isinstance(cname, list) else []


def _problem_pages(results: list, domain: str, quarantine: "UrlQuarantine", scope: "HostScope",
                   settings: dict, dns: dict) -> tuple:
    """Item 5: the page titles, Server headers and certificates urlscan already
    returned, checked against the problem-page catalog (page_signals.py).

    Returns (problem findings, takeover pages). A problem page is one finding
    per host, path and problem (per host for a server or a certificate). A
    deleted-service page is only collected here, one per host: whether it still
    describes the host is decided after httpx (urlscan_takeover.py), since a
    CNAME to the provider is the normal state of a healthy site."""
    want_takeover = bool(settings.get("URLSCAN_TAKEOVER_PAGES", True))
    want_problems = bool(settings.get("URLSCAN_PROBLEM_PAGES", True))
    if not (want_takeover or want_problems):
        return [], []
    from recon.helpers import page_signals as ps
    groups: dict = {}
    takeovers: dict = {}
    for result in results:
        if not isinstance(result, dict) or not _is_public(result):
            continue
        page = result.get("page") or {}
        task = result.get("task") or {}
        url = page.get("url") or ""
        host = (urlparse(url).hostname or "").lower() if url else ""
        if not host or not _extract_domain_from_url(url, domain) or not scope.host_ok(host):
            continue
        v = quarantine.verdict(url)
        when, uuid = task.get("time") or "", task.get("uuid") or ""
        matches = ps.match_page(page.get("title"), page.get("server"), page.get("status"),
                                urlparse(url).path or "/", page.get("mimeType"), host, url,
                                _visit_cname(dns, host))
        if want_problems and url.lower().startswith("https://"):
            matches += ps.match_certificate(page.get("tlsIssuer"), "", page.get("tlsAgeDays"),
                                            page.get("tlsValidDays"))
        for m in matches:
            if m["family"] == "takeover":
                if not want_takeover:
                    continue
                slot = takeovers.setdefault(host, {"times": [], "newest": "", **m})
                slot["times"].append(when)
                if when >= slot["newest"]:
                    slot.update({**m, "newest": when, "scan_id": uuid,
                                 "url": (v["masked_url"] or url).split("?", 1)[0],
                                 "unmasked_url": url,
                                 "title": page.get("title") or "", "server": page.get("server") or "",
                                 "status": page.get("status")})
                continue
            if not want_problems:
                continue
            per_host = m["family"] in ps.PER_HOST_FAMILIES
            path = "/" if per_host else (v["masked_path"] or "/")
            slot = groups.setdefault((host, path, m["family"], m["problem"]),
                                     {"times": [], "newest": "", **m})
            slot["times"].append(when)
            if when >= slot["newest"]:
                origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
                slot.update({"newest": when, "scan_id": uuid, "matched": m["matched"],
                             "url": origin if per_host else (v["masked_url"] or url).split("?", 1)[0],
                             "unmasked_url": origin if per_host else url})
    problems = []
    for (host, path, family, problem), slot in sorted(groups.items()):
        first, last = _span(slot["times"])
        what = f"{slot['label']} ({ps.FAMILY_LABEL[family]})"
        problems.append({
            "type": ps.FAMILY_TYPES[family][1], "kind": problem, "kind_field": "problem",
            "host": host, "path": path, "url": slot["url"], "severity": slot["severity"],
            "name": f"{what[0].upper()}{what[1:]} seen on urlscan",
            "description": (
                f"{host}{'' if path == '/' else path} showed a {what} in {len(slot['times'])} "
                f"public urlscan scan(s), seen from {first[:10] or 'unknown'} to "
                f"{last[:10] or 'unknown'} (matched: {slot['matched']}). RedAmon did not request "
                f"it; the Security Checks' Page Content group checks this scan's live pages."),
            "first_seen": first, "last_seen": last, "urlscan_scan_id": slot["scan_id"],
            "props": {"family": family, "matched": slot["matched"], "sightings": len(slot["times"]),
                      "unmasked_url": slot.get("unmasked_url")},
        })
    pages = []
    for host, slot in sorted(takeovers.items()):
        first, last = _span(slot["times"])
        pages.append({
            "host": host, "provider": slot["provider"], "problem": slot["problem"],
            "label": slot["label"], "outcome": slot["outcome"], "matched": slot["matched"],
            "title": slot["title"], "server": slot["server"], "status": slot["status"],
            "url": slot["url"], "unmasked_url": slot.get("unmasked_url"),
            "first_seen": first, "last_seen": last,
            "urlscan_scan_id": slot["scan_id"], "sightings": len(slot["times"]),
        })
    return problems, pages


#: Item 3's path-based kinds that a matching title (item 5) names more precisely.
_TITLED_FILE_KINDS = {"installer": "unfinished_installer", "debug_page": "debug_page",
                      "debug_console": "debug_page"}


def _without_titled_pages(file_findings: list, problem_pages: list) -> list:
    """One finding for one page: an installer or a debug page found by its path
    (item 3) and by its title (item 5) keeps the title's, which says what the
    page showed."""
    titled = {(p["host"], p["path"], p["props"]["family"]) for p in problem_pages}
    return [f for f in file_findings
            if (f.get("host"), f.get("path"), _TITLED_FILE_KINDS.get(f.get("kind"))) not in titled]


#: Sign-in flows send the user back to a registered address on purpose: an
#: identity provider redirecting is no open redirect (OAuth / OpenID Connect, SAML).
_SIGN_IN_PARAMS = frozenset({"client_id", "response_type", "redirect_uri", "state",
                             "samlrequest", "samlresponse", "relaystate"})


def _names_destination(value: str, end_domain: str) -> bool:
    from urllib.parse import unquote
    v = (value or "").lower()
    for _ in range(3):
        v = unquote(v)
    end = (end_domain or "").lower()
    return bool(end) and (f"//{end}" in v or v == end or v.startswith(end + "/"))


def _redirect_rows(results: list, root: str, quarantine: "UrlQuarantine", scope: "HostScope",
                   mask_url) -> dict:
    """Item 1's lists from the outbound visits. The other site is recorded by its
    origin only (its paths are often a third party's private links) and never
    scanned; the start URL is the target's own, masked where it is requested or
    keyed and kept whole (`unmasked_*`) for display; the open-redirect rule (N1)
    runs on the raw values."""
    from urllib.parse import parse_qsl
    out = {"redirect_entries": [], "external_domains": [], "start_hosts": [], "open_redirects": [],
           "findings": [], "quarantined_urls": [], "leak_inputs": []}
    hosts, redirects = set(), {}
    for r in results:
        task, page = r.get("task") or {}, r.get("page") or {}
        start = task.get("url") or ""
        start_parts = urlparse(start)
        host = (start_parts.hostname or "").lower()
        if not host or not scope.host_ok(host):
            continue
        end_domain = (page.get("domain") or urlparse(page.get("url") or "").hostname or "").lower()
        end_parts = urlparse(page.get("url") or "")
        end_origin = (f"{end_parts.scheme}://{end_parts.netloc}" if end_parts.scheme and end_parts.netloc
                      else f"https://{end_domain}")
        held = quarantine.holds(start)
        masked = mask_url(start) or ""
        scan_time, scan_id = task.get("time") or "", task.get("uuid") or ""
        out["leak_inputs"].append((start, r))
        params = parse_qsl(start_parts.query, keep_blank_values=True)
        names = sorted({n for n, _v in params})
        if held:
            out["quarantined_urls"].append(quarantine.row(start, "task", r))
        else:
            out["redirect_entries"].append({
                "start_url": masked, "unmasked_start_url": start,
                "base_url": f"{start_parts.scheme}://{start_parts.netloc}",
                "path": start_parts.path or "/", "param_names": names, "end_origin": end_origin,
                "end_domain": end_domain, "scan_time": scan_time, "scan_id": scan_id,
            })
        out["external_domains"].append({"domain": end_domain, "source": "urlscan_redirect",
                                        "url": end_origin, "redirect_from_url": masked,
                                        "unmasked_redirect_from_url": start})
        if host != root.lower():
            hosts.add(host)
        if {n.lower() for n in names} & _SIGN_IN_PARAMS:
            continue
        for name, value in params:
            if _names_destination(value, end_domain):
                path = quarantine.verdict(start)["masked_path"] or start_parts.path or "/"
                slot = redirects.setdefault((host, path, name), {
                    "destination_domain": end_domain, "times": [], "scan_id": "", "newest": "",
                    "unmasked_url": start})
                slot["times"].append(scan_time)
                if scan_time >= slot["newest"]:
                    slot["newest"], slot["scan_id"] = scan_time, scan_id
                    slot["unmasked_url"] = start
    out["start_hosts"] = sorted(hosts)
    for (host, path, name), slot in sorted(redirects.items()):
        first, last = _span(slot["times"])
        out["open_redirects"].append({"host": host, "path": path, "param_name": name,
                                      "destination_domain": slot["destination_domain"],
                                      "first_seen": first, "last_seen": last,
                                      "scan_id": slot["scan_id"],
                                      "unmasked_url": slot["unmasked_url"]})
        out["findings"].append({
            "type": "open_redirect_seen", "kind": name, "kind_field": "",
            "host": host, "path": path, "url": f"https://{host}{path}?{name}=***",
            "severity": "medium", "name": "Open redirect seen on urlscan",
            "description": (
                f"A public urlscan scan on {last[:10] or 'unknown'} started on {host}{path} with the "
                f"parameter {name} naming {slot['destination_domain']}, and the browser ended on that "
                f"site: {host} redirects to a site a parameter names. RedAmon did not request it; "
                f"test {name} with a site you control."),
            "first_seen": first, "last_seen": last, "urlscan_scan_id": slot["scan_id"],
            "props": {"param_name": name, "destination_domain": slot["destination_domain"],
                      "unmasked_url": slot["unmasked_url"]},
        })
    return out


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
        self._verdicts = {u: url_leaks.inspect_url(u, hmac_key=hmac_key, with_values=True)
                          for u in dict.fromkeys(urls)}
        self._shells = {url_leaks.host_path_key(u) for u, v in self._verdicts.items() if v["web_shell"]}

    def verdict(self, url: str) -> dict:
        v = self._verdicts.get(url)
        if v is None:
            v = self._verdicts[url] = self._ul.inspect_url(url, hmac_key=self._hmac_key,
                                                           with_values=True)
        return v

    def holds(self, url: str) -> bool:
        return self.verdict(url)["quarantined"] or self._ul.host_path_key(url) in self._shells

    def row(self, url: str, field: str, result: dict) -> dict:
        """A quarantined URL as the graph keeps it: the masked path and the
        parameter names (what readers key on and skip), plus the URL itself
        (`unmasked_url`) for display."""
        v = self.verdict(url)
        parsed = urlparse(url)
        reasons = list(v["reasons"])
        if self._ul.host_path_key(url) in self._shells and "web_shell" not in reasons:
            reasons.append("web_shell_host")
        return {
            "base_url": f"{parsed.scheme}://{parsed.netloc}",
            "path": v["masked_path"] or "/",
            "masked_url": v["masked_url"],
            "unmasked_url": url,
            "param_names": sorted({n for n, _ in parse_qs(parsed.query, keep_blank_values=True).items()}),
            "reasons": sorted(reasons),
            "field": field,
            "scan_time": ((result or {}).get("task") or {}).get("time", ""),
        }


def run_urlscan_discovery_only(domain: str, settings: dict[str, Any], org_domain: str = "") -> dict:
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

    # Build a minimal combined_result just for the enrichment function. An
    # IP-mode project's root is ip-targets.<project id>: the enrichment skips
    # IP mode, so the project id is never searched for (B-19, D-11).
    fake_combined = {
        "domain": domain,
        "org_domain": org_domain or domain,
        "metadata": {"ip_mode": bool(settings.get("IP_MODE"))},
    }
    run_urlscan_enrichment(fake_combined, settings)
    return fake_combined.get("urlscan", {})

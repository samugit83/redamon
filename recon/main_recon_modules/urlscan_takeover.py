"""Item 5, the takeover verdict: which deleted-service pages urlscan recorded
(``urlscan.takeover_pages``, collected in GROUP 1) still describe the host now.

A CNAME to the provider is the normal state of a healthy site, so history
alone proves nothing: a brief "No such app" during a deploy, on a Heroku app
that is live today, must not become a high finding. Decided after httpx
(GROUP 4) with this scan's data, per host:

    httpx shows the same error page now          -> the row's outcome
    no live page, the CNAME target is NXDOMAIN   -> possible_takeover
                                                    (likely_takeover for a likely row)
    the CNAME points to the provider, normal page -> nothing (healthy now)
    no CNAME to that provider                     -> nothing (Subdomain Takeover
                                                    covers the A-record providers)
    never probed, the CNAME target resolves       -> nothing (unverified)

The CNAME comes from the DNS map for a host it knows; a host only urlscan
knows costs one CNAME query, and its target one more, both through the
circuit breaker. Hosts with a kept finding become ``urlscan.takeover_hosts``,
which Subdomain Takeover adds to its list when it is on.
"""
from __future__ import annotations

from typing import Callable, Optional
from urllib.parse import urlsplit

from recon.helpers import circuit_breaker as cb
from recon.helpers import page_signals as ps
from recon.helpers.takeover_helpers import (
    provider_from_cname,
    resolve_cname_target,
    same_provider_family,
)

DNS_BREAKER = "dns:takeover-verdict"
#: Matches are rare (one per host whose urlscan title matched); this only
#: bounds the DNS work if a target has thousands of parked names.
MAX_VERDICT_HOSTS = 200


def _breaker():
    return cb.get_breaker(DNS_BREAKER, label="DNS (takeover verdict)")


def _cname_send(host: str):
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 5.0
    try:
        answer = resolver.resolve(host, "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.resolver.NoNameservers as exc:
        raise ConnectionError("no nameserver answered") from exc
    except dns.exception.Timeout as exc:
        raise TimeoutError("DNS timeout") from exc
    return [str(r.target).rstrip(".").lower() for r in answer]


def query_cname(host: str) -> Optional[list]:
    """The host's CNAME targets ([] for none), or None when DNS did not answer."""
    res = cb.guarded_call(
        _breaker(), lambda: _cname_send(host),
        lambda data: cb.CallResult(data, cb.Outcome.OK if data else cb.Outcome.NO_DATA))
    return list(res.data or []) if res.answered else None


def target_state(cname: str) -> Optional[str]:
    """"nxdomain", "resolves", or None when unknown (a DNS failure)."""
    def classify(state):
        if state.get("nxdomain"):
            return cb.CallResult("nxdomain", cb.Outcome.NO_DATA)
        if state.get("resolves"):
            return cb.CallResult("resolves", cb.Outcome.OK)
        return cb.CallResult(None, cb.Outcome.TRANSIENT, "no answer")
    res = cb.guarded_call(_breaker(), lambda: resolve_cname_target(cname), classify)
    return res.data if res.answered else None


def live_pages_by_host(by_url: dict) -> dict:
    """{host: [page]} from httpx's by_url, each page described by its last hop
    (httpx's title is the last hop's)."""
    out: dict = {}
    for url, info in (by_url or {}).items():
        if not isinstance(info, dict) or info.get("status_code") is None:
            continue
        host = (info.get("host") or urlsplit(str(url)).hostname or "").lower()
        if not host:
            continue
        out.setdefault(host, []).append({
            "final_url": info.get("final_url") or url, "title": info.get("title"),
            "server": info.get("server"), "status": info.get("status_code"),
            "content_type": info.get("content_type"), "cname": info.get("cname"),
        })
    return out


def _dns_map_cname(dns_subdomains: dict, host: str) -> Optional[list]:
    entry = (dns_subdomains or {}).get(host)
    if not isinstance(entry, dict) or "records" not in entry:
        return None
    cname = (entry.get("records") or {}).get("CNAME")
    if isinstance(cname, str):
        return [cname.rstrip(".").lower()]
    return [str(c).rstrip(".").lower() for c in cname or [] if isinstance(c, str)]


def cname_resolver(dns_subdomains: dict, live_by_host: dict) -> Callable[[str], Optional[list]]:
    """The host's CNAME: the DNS map's for a host it knows, else httpx's, else
    one query (a host only urlscan knows)."""
    def cname_of(host: str) -> Optional[list]:
        known = _dns_map_cname(dns_subdomains, host)
        if known is not None:
            return known
        for page in live_by_host.get(host) or []:
            found = page.get("cname")
            if found:
                return [str(c).rstrip(".").lower() for c in (found if isinstance(found, list) else [found])]
        return query_cname(host)
    return cname_of


def decide(pages: list, live_by_host: dict, cname_of: Callable[[str], Optional[list]],
           state_of: Callable[[str], Optional[str]]) -> tuple:
    """(findings, hosts) for the takeover pages, by the table in the module
    docstring. `cname_of` and `state_of` do the DNS; injected for the tests."""
    findings, hosts = [], []
    for page in pages[:MAX_VERDICT_HOSTS]:
        host = (page.get("host") or "").lower()
        provider = page.get("provider") or ""
        if not host or not provider:
            continue
        cnames = cname_of(host)
        if not cnames:
            continue
        pointing = [c for c in cnames if same_provider_family(provider_from_cname(c), provider)]
        if not pointing:
            continue
        live = live_by_host.get(host) or []
        if live:
            same = any(
                m["family"] == "takeover" and m["problem"] == page.get("problem")
                for p in live
                for m in ps.match_page(p.get("title"), p.get("server"), p.get("status"),
                                       urlsplit(str(p.get("final_url") or "")).path or "/",
                                       p.get("content_type"), host, str(p.get("final_url") or ""),
                                       cnames))
            if not same:
                continue
            outcome, basis = page.get("outcome") or "possible_takeover", "live_page"
        else:
            if state_of(pointing[0]) != "nxdomain":
                continue
            outcome = "likely_takeover" if page.get("outcome") == "likely_takeover" else "possible_takeover"
            basis = "cname_target_nxdomain"
        findings.append(_finding(page, outcome, basis, pointing[0], live=bool(live)))
        hosts.append(host)
    return findings, sorted(set(hosts))


_OUTCOME_WORDS = {"likely_takeover": "likely subdomain takeover",
                  "possible_takeover": "possible subdomain takeover",
                  "dangling_dns": "dangling DNS record"}


def _finding(page: dict, outcome: str, basis: str, cname: str, live: bool) -> dict:
    host, label = page["host"], page.get("label") or page.get("provider")
    now = ("httpx got the same error page in this scan" if basis == "live_page"
           else f"the CNAME target {cname} does not exist (NXDOMAIN) in this scan")
    return {
        "type": "takeover_page_seen", "kind": page["provider"], "kind_field": "provider",
        "host": host, "path": "/", "url": page.get("url") or f"https://{host}/",
        "severity": ps.OUTCOME_SEVERITY.get(outcome, "medium"), "live": live,
        "name": f"{label} deleted-service page on {host}: {_OUTCOME_WORDS.get(outcome, outcome)}",
        "description": (
            f"A public urlscan scan recorded {label}'s page for a deleted service on {host} "
            f"('{page.get('matched')}', seen from {(page.get('first_seen') or '')[:10] or 'unknown'} "
            f"to {(page.get('last_seen') or '')[:10] or 'unknown'}). {host} still points to "
            f"{cname}, and {now}. Remove the DNS record, or claim the name on {label} again."),
        "first_seen": page.get("first_seen") or "", "last_seen": page.get("last_seen") or "",
        "urlscan_scan_id": page.get("urlscan_scan_id") or "",
        "props": {"outcome": outcome, "cname": cname, "cname_still_points": True,
                  "problem": page.get("problem"), "matched": page.get("matched"),
                  "verdict_basis": basis, "unmasked_url": page.get("unmasked_url")},
    }


def run_partial_verdict(pages: list, live_by_host: dict) -> tuple:
    """Partial urlscan's verdict: no httpx step and no DNS map, so the live
    pages are the graph's (the last httpx run) and every CNAME is queried."""
    scope = cb.scope(DNS_BREAKER, label="Takeover verdict", unit="host(s)")
    try:
        return decide(pages, live_by_host, cname_resolver({}, live_by_host), target_state)
    finally:
        scope.finish("urlscan_takeover", sources=("urlscan_leak",))


def run_takeover_verdict(combined_result: dict, settings: dict) -> dict:
    """The full run's step after GROUP 4: never raises, sends nothing to the
    target (DNS only), and runs with httpx off (then only the NXDOMAIN row can
    keep a finding)."""
    urlscan = combined_result.get("urlscan") if isinstance(combined_result, dict) else None
    if not isinstance(urlscan, dict):
        return combined_result
    pages = [p for p in urlscan.get("takeover_pages") or [] if isinstance(p, dict)]
    if not pages or not settings.get("URLSCAN_TAKEOVER_PAGES", True):
        return combined_result
    try:
        print(f"\n[*][URLScan] Takeover verdict for {len(pages)} host(s) with a deleted-service page")
        scope = cb.scope(DNS_BREAKER, label="Takeover verdict", unit="host(s)")
        dns_subdomains = (combined_result.get("dns") or {}).get("subdomains") or {}
        live = live_pages_by_host((combined_result.get("http_probe") or {}).get("by_url") or {})
        findings, hosts = decide(pages, live, cname_resolver(dns_subdomains, live), target_state)
        urlscan["takeover_findings"], urlscan["takeover_hosts"] = findings, hosts
        print(f"[+][URLScan] Takeover verdict: {len(findings)} of {len(pages)} host(s) kept")
        scope.finish("urlscan_takeover", sources=("urlscan_leak",))
    except Exception as e:  # noqa: BLE001
        print(f"[!][URLScan] Takeover verdict failed: {e}")
    return combined_result

"""
RedAmon - hostnames seen on IP-mode target addresses (the pipeline side)
=======================================================================
An IP-mode run sees names on its target addresses: PTR answers, certificate
SANs and CNs, redirects, passive DNS and the search engines' host records.
This module turns them into one candidate per name, bound to the target IPs
it was seen on, gives each the selection rule's reason
(recon_settings/ip_hostnames.py, the one rule every service shares) and logs
what it found. The graph writer is update_graph_from_ip_hostnames.

ip_only looks no name up and keeps none (I-7). record_only records every
candidate and scans none. record_filter and scan_all select names the rule
admits, resolve each to target addresses only, pin that answer, add the names
to the run's scope and scan them on it (design §5.4 steps 3-9); every other
name is recorded with its reason.
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Iterable, Optional

from recon_settings.hard_guardrail import is_hard_blocked
from recon_settings.ip_hostnames import (
    MODES,
    SCANNED,
    canonical_ip,
    evaluate,
    normalize_name,
    parse_entries,
    post_probe_verdict,
)

#: Decision D-23. A shared-hosting /24 in a passive-DNS index can name far more
#: hosts than anyone reviews; what is cut is counted, never written.
MAX_CANDIDATES_PER_IP = 500
MAX_CANDIDATES_PER_RUN = 20000

#: Observed from the target or its DNS during this run; kept first when the
#: volume bound cuts. Everything else is a third-party index.
LIVE_SOURCES = frozenset({
    "ptr", "tlsx_san", "tlsx_cn", "httpx_san", "httpx_cn", "attribution_cert", "http_redirect",
})

#: How the per-IP log line groups the sources. Index certificates (Censys,
#: FOFA) stay with their index: "cert" means a certificate served this run.
_FAMILY = {
    "ptr": "ptr", "http_redirect": "redirect",
    "tlsx_san": "cert", "tlsx_cn": "cert", "httpx_san": "cert", "httpx_cn": "cert",
    "attribution_cert": "cert",
    "shodan_rdns": "shodan", "shodan_hostnames": "shodan",
    "otx_passive_dns": "otx",
    "censys_rdns": "censys", "censys_cert": "censys",
    "fofa_host": "fofa", "fofa_domain": "fofa", "fofa_cname": "fofa", "fofa_cert": "fofa",
    "netlas_host": "netlas",
    "zoomeye_hostname": "zoomeye", "zoomeye_rdns": "zoomeye",
}
_FAMILY_ORDER = ("cert", "ptr", "redirect", "shodan", "otx", "censys", "fofa", "netlas", "zoomeye")

_IP_MODE_ROOT_PREFIX = "ip-targets."
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_ATTRIBUTION_FAILED = "attribution failed"   # ip_attribution.ATTRIBUTION_FAILED

#: The reasons a name may never be sent anywhere, recorded or not.
NEVER_SENT = frozenset({"invalid_name", "hard_blocked", "roe_excluded"})

#: The modes that select names to scan.
SELECTING = frozenset({"record_filter", "scan_all"})

#: The `source` of a selected name's DNS entry and of its Subdomain node.
SELECTION_SOURCE = "ip_hostname_selection"

#: Refusals that mean "not checked this run" rather than a decision: the name
#: may still be the project's, so the prune keeps what it found there before.
_NOT_CHECKED = {
    "cap_reached": "over the per-run hostname cap",
    "resolver_unavailable": "the DNS resolver was unavailable",
    "dns_disabled": "DNS lookups are disabled",
}


# ---------------------------------------------------------------------------
# Mode
# ---------------------------------------------------------------------------

def hostname_mode(settings: Optional[dict]) -> str:
    """The run's hostname mode; anything unknown or missing is ip_only, which
    looks no name up."""
    mode = (settings or {}).get("IP_HOSTNAME_MODE")
    return mode if mode in MODES else "ip_only"


def is_ip_mode(combined_result: Optional[dict], settings: Optional[dict] = None) -> bool:
    metadata = (combined_result or {}).get("metadata") or {}
    return bool(metadata.get("ip_mode") or (settings or {}).get("IP_MODE"))


def names_off(combined_result: Optional[dict], settings: Optional[dict]) -> bool:
    """IP mode in ip_only: a module neither asks for nor keeps any hostname."""
    return is_ip_mode(combined_result, settings) and hostname_mode(settings) == "ip_only"


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def candidate_name(raw: Any) -> Optional[str]:
    """A source's spelling as the rule's canonical name, or None.

    A wildcard SAN covers names but is none itself; an address, a dashed
    placeholder (a single label) and the synthetic IP-mode root are no
    hostnames. An e-mail address (passive DNS and SANs carry some) names a
    mailbox, not a host: the rule's normaliser would keep its domain.
    """
    if not isinstance(raw, str) or raw.strip().startswith("*") or "@" in raw:
        return None
    name = normalize_name(raw)
    if name is None or name.startswith(_IP_MODE_ROOT_PREFIX):
        return None
    return name


def _day(value: Any) -> Optional[str]:
    match = _DAY.match(str(value or "").strip())
    return match.group(0) if match else None


def _items(values: Any) -> list:
    if isinstance(values, (list, tuple, set)):
        return list(values)
    return [values] if values else []


def _dicts(values: Any) -> list:
    return [v for v in _items(values) if isinstance(v, dict)]


def _url_host(url: Any) -> str:
    """The host of a URL (or of a bare host[:port]), brackets kept off."""
    text = str(url or "").strip()
    text = text.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    return text if text.count(":") > 1 else text.split(":", 1)[0]


class _Collector:
    def __init__(self, expanded_ips: Iterable[Any]):
        self.order: dict[str, int] = {}
        self.targets: dict[str, str] = {}
        for ip in expanded_ips or ():
            spelled = str(ip)
            self.targets.setdefault(canonical_ip(spelled), spelled)
            self.order.setdefault(spelled, len(self.order))
        self.seen: dict[str, dict[str, dict]] = {}
        self.certs: dict[str, list[list[str]]] = {}

    def target(self, address: Any) -> Optional[str]:
        """The target as the run listed it, for any spelling of its address."""
        if not address:
            return None
        return self.targets.get(canonical_ip(_url_host(address)))

    def add(self, raw: Any, address: Any, source: str, first: Any = None, last: Any = None) -> None:
        ip = self.target(address)
        name = candidate_name(raw) if ip else None
        if name is None:
            return
        evidence = self.seen.setdefault(name, {}).setdefault(
            ip, {"sources": set(), "first_seen": None, "last_seen": None})
        evidence["sources"].add(source)
        first, last = _day(first), _day(last)
        if first and (evidence["first_seen"] is None or first < evidence["first_seen"]):
            evidence["first_seen"] = first
        if last and (evidence["last_seen"] is None or last > evidence["last_seen"]):
            evidence["last_seen"] = last

    def add_cert(self, address: Any, cn: Any, sans: Any, cn_source: str, san_source: str) -> None:
        """A certificate served on a target IP this run: its names are
        candidates, and it covers whatever its CN and SANs match."""
        ip = self.target(address)
        if not ip:
            return
        names = [n for n in [cn, *_items(sans)] if isinstance(n, str) and n.strip()]
        if names:
            self.certs.setdefault(ip, []).append(names)
        self.add(cn, ip, cn_source)
        for san in _items(sans):
            self.add(san, ip, san_source)


def _ptr(c: _Collector, data: dict) -> None:
    for ip, names in ((data.get("ip_hostnames") or {}).get("ptr") or {}).items():
        for name in _items(names):
            c.add(name, ip, "ptr")


def _shodan(c: _Collector, data: dict) -> None:
    shodan = data.get("shodan") or {}
    for ip, names in (shodan.get("reverse_dns") or {}).items():
        for name in _items(names):
            c.add(name, ip, "shodan_rdns")
    for host in _dicts(shodan.get("hosts")):
        for name in _items(host.get("hostnames")):
            c.add(name, host.get("ip"), "shodan_hostnames")


def _otx(c: _Collector, data: dict) -> None:
    for report in _dicts((data.get("otx") or {}).get("ip_reports")):
        records = report.get("passive_dns") or [
            {"hostname": h} for h in _items(report.get("passive_dns_hostnames"))]
        for rec in _dicts(records):
            c.add(rec.get("hostname"), report.get("ip"), "otx_passive_dns",
                  first=rec.get("first"), last=rec.get("last"))


def _censys(c: _Collector, data: dict) -> None:
    for host in _dicts((data.get("censys") or {}).get("hosts")):
        ip, last = host.get("ip"), host.get("last_updated")
        for name in _items(host.get("reverse_dns_names")):
            c.add(name, ip, "censys_rdns", last=last)
        for service in _dicts(host.get("services")):
            tls = service.get("tls") if isinstance(service.get("tls"), dict) else {}
            for name in [tls.get("subject_cn"), *_items(tls.get("san"))]:
                c.add(name, ip, "censys_cert", last=last)


def _fofa(c: _Collector, data: dict) -> None:
    for row in _dicts((data.get("fofa") or {}).get("results")):
        for field, source in (("host", "fofa_host"), ("domain", "fofa_domain"),
                              ("cname", "fofa_cname"), ("certs_subject_cn", "fofa_cert")):
            c.add(row.get(field), row.get("ip"), source, last=row.get("lastupdatetime"))


def _netlas(c: _Collector, data: dict) -> None:
    for row in _dicts((data.get("netlas") or {}).get("results")):
        c.add(row.get("host"), row.get("ip"), "netlas_host")


def _zoomeye(c: _Collector, data: dict) -> None:
    for row in _dicts((data.get("zoomeye") or {}).get("results")):
        for field in ("hostname", "rdns"):
            c.add(row.get(field), row.get("ip"), f"zoomeye_{field}", last=row.get("update_time"))


def _tlsx(c: _Collector, data: dict) -> None:
    for entry in (((data.get("tlsx") or {}).get("by_target")) or {}).values():
        if isinstance(entry, dict):
            # `san` has its wildcards stripped; `san_raw` still says which were.
            sans = entry.get("san_raw") if entry.get("san_raw") is not None else entry.get("san")
            c.add_cert(entry.get("scanned_ip") or entry.get("ip"), entry.get("subject_cn"), sans,
                       "tlsx_cn", "tlsx_san")


def _http_probe(c: _Collector, data: dict) -> None:
    probe = data.get("http_probe") or {}
    for url, info in (probe.get("by_url") or {}).items():
        if not isinstance(info, dict):
            continue
        address = info.get("ip") or info.get("host") or _url_host(url)
        cert = ((info.get("tls") or {}).get("certificate")) or {}
        if cert:
            c.add_cert(address, cert.get("subject_cn"), cert.get("san"), "httpx_cn", "httpx_san")
        if info.get("redirected_off_host"):
            c.add(_url_host(info.get("final_url")), address, "http_redirect")
    for entry in _dicts(probe.get("external_domains")):
        # The redirect left from a target address: the name was seen on it.
        c.add(entry.get("domain"), _url_host(entry.get("redirect_from_url")), "http_redirect")


def _attribution(c: _Collector, data: dict) -> None:
    for ip, entry in (((data.get("ip_attribution") or {}).get("by_ip")) or {}).items():
        if isinstance(entry, dict):
            c.add_cert(ip, None, entry.get("default_cert_names"), "attribution_cert", "attribution_cert")


_SOURCES = (_ptr, _shodan, _otx, _censys, _fofa, _netlas, _zoomeye, _tlsx, _http_probe, _attribution)


def collect(combined_result: dict) -> dict:
    """{name: candidate} for every name a source saw on a target address.

    A candidate carries `ips_seen` (target IPs, in target-list order),
    `sources`, `first_seen` / `last_seen` (only dated sources date it),
    `cert_covers` (a certificate served on one of those IPs this run covers
    it), `org_domain` and `seen_on` (that evidence per target IP).
    """
    metadata = combined_result.get("metadata") or {}
    c = _Collector(metadata.get("expanded_ips") or ())
    for source in _SOURCES:
        source(c, combined_result)

    from recon.helpers.public_suffix import org_domain
    from recon.main_recon_modules.tls_scan import _host_matches_cert

    out = {}
    for name, by_ip in c.seen.items():
        seen_on = {}
        for ip in sorted(by_ip, key=lambda a: c.order.get(a, 0)):
            ev = by_ip[ip]
            seen_on[ip] = {
                "sources": sorted(ev["sources"]),
                "first_seen": ev["first_seen"],
                "last_seen": ev["last_seen"],
                "cert_covers": any(_host_matches_cert(name, names) for names in c.certs.get(ip, ())),
            }
        out[name] = _summarise(name, seen_on, org_domain(name))
    return out


def _summarise(name: str, seen_on: dict, org: Optional[str]) -> dict:
    firsts = [e["first_seen"] for e in seen_on.values() if e["first_seen"]]
    lasts = [e["last_seen"] for e in seen_on.values() if e["last_seen"]]
    return {
        "ips_seen": list(seen_on),
        "sources": sorted({s for e in seen_on.values() for s in e["sources"]}),
        "first_seen": min(firsts) if firsts else None,
        "last_seen": max(lasts) if lasts else None,
        "cert_covers": any(e["cert_covers"] for e in seen_on.values()),
        "org_domain": org,
        "seen_on": seen_on,
    }


# ---------------------------------------------------------------------------
# Volume bound (D-23)
# ---------------------------------------------------------------------------

def _ranked(names: Iterable[str], evidence) -> list:
    """Live sources first, then dated sources newest first, then by name.

    `evidence(name)` is the list of evidence dicts the rank reads.
    """
    def live(name):
        return any(s in LIVE_SOURCES for e in evidence(name) for s in e["sources"])

    def last(name):
        return max((e["last_seen"] or "" for e in evidence(name)), default="")

    out = sorted(names)
    out.sort(key=last, reverse=True)
    out.sort(key=lambda n: not live(n))
    return out


def bound(candidates: dict) -> tuple[dict, dict, dict, int]:
    """Cut to the per-IP and per-run limits.

    Returns (kept candidates, {ip: names cut on it by the per-IP limit},
    {ip: names cut on it by the per-run limit}, names kept nowhere).
    """
    on_ip: dict[str, list[str]] = {}
    for name, cand in candidates.items():
        for ip in cand["seen_on"]:
            on_ip.setdefault(ip, []).append(name)

    kept_on: dict[str, dict] = {name: dict(cand["seen_on"]) for name, cand in candidates.items()}
    per_ip_cut: dict[str, int] = {}
    for ip, names in on_ip.items():
        ranked = _ranked(names, lambda n, ip=ip: [candidates[n]["seen_on"][ip]])
        for name in ranked[MAX_CANDIDATES_PER_IP:]:
            del kept_on[name][ip]
            per_ip_cut[ip] = per_ip_cut.get(ip, 0) + 1

    survivors = [n for n, seen in kept_on.items() if seen]
    dropped = len(candidates) - len(survivors)
    ranked = _ranked(survivors, lambda n: list(kept_on[n].values()))
    run_cut: dict[str, int] = {}
    for name in ranked[MAX_CANDIDATES_PER_RUN:]:
        for ip in kept_on[name]:
            run_cut[ip] = run_cut.get(ip, 0) + 1
    dropped += max(0, len(ranked) - MAX_CANDIDATES_PER_RUN)

    kept = {}
    for name in sorted(ranked[:MAX_CANDIDATES_PER_RUN]):
        cand = candidates[name]
        kept[name] = _summarise(name, kept_on[name], cand["org_domain"])
    return kept, per_ip_cut, run_cut, dropped


# ---------------------------------------------------------------------------
# The hook (design §5.4 steps 1-2 and the record part)
# ---------------------------------------------------------------------------

def _empty_summary() -> dict:
    return {"found": 0, "scanned": 0, "recorded": 0, "truncated": 0, "ips_with_names": 0, "reasons": {}}


def _counted(values: Iterable[str]) -> dict:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def _attribution_sets(combined_result: dict) -> tuple[Optional[set], Optional[set]]:
    """(shared-edge target IPs, IPs whose attribution failed); both None when
    IP attribution did not run.

    The step writes its key even when it crashed before it listed any IP, and
    it attributes every target when it works: a target it never tagged has no
    attribution, so it counts as failed (D-14 fails closed on it)."""
    attribution = combined_result.get("ip_attribution")
    if not isinstance(attribution, dict):
        return None, None
    by_ip = attribution.get("by_ip") or {}
    entries = {canonical_ip(ip): e for ip, e in by_ip.items() if isinstance(e, dict)}
    edge = {ip for ip, e in entries.items() if e.get("ownership") == "shared_edge"}
    failed = {ip for ip, e in entries.items() if _ATTRIBUTION_FAILED in (e.get("ownership_reasons") or ())}
    for ip in (combined_result.get("metadata") or {}).get("expanded_ips") or ():
        if canonical_ip(str(ip)) not in entries:
            failed.add(canonical_ip(str(ip)))
    return edge, failed


class ResolverDown(Exception):
    """No definitive answer for a name: the rule refuses it (resolver_unavailable)."""


def dns_resolver(settings: dict) -> Callable[[str], list]:
    """resolve(name) -> its A and AAAA answers (design §5.4 step 3).

    Only those two types: they are where a scanner connects. NXDOMAIN or no
    answer is an empty list (no_current_resolution). A transient failure goes
    through the resolver breaker's canary like every recon lookup; when the
    resolver is down, or no attempt gave a definitive answer, it raises, so
    the name is refused rather than judged on half an answer (I-6).
    """
    import dns.resolver
    from recon.main_recon_modules.domain_recon import _dns_definitive_errors, resolver_breaker

    try:
        retries = max(1, min(int(settings.get("DNS_MAX_RETRIES") or 3), 5))
    except (TypeError, ValueError):
        retries = 3
    definitive = _dns_definitive_errors()

    def lookup(name: str, rtype: str) -> list:
        for attempt in range(retries):
            if resolver_breaker.is_open():
                raise ResolverDown(name)
            try:
                return [rr.to_text() for rr in dns.resolver.resolve(name, rtype)]
            except definitive:
                return []
            except Exception:  # noqa: BLE001 - transient: the canary decides
                if resolver_breaker.note_transient():
                    raise ResolverDown(name)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
        raise ResolverDown(name)

    def resolve(name: str) -> list:
        return lookup(name, "A") + lookup(name, "AAAA")

    return resolve


def _arm_resolver(canary: str) -> bool:
    """Arm the resolver breaker with a canary before the first lookup, and say
    whether lookups may run. Nothing else arms it in an IP-mode run: without a
    canary a dead resolver reads as "no such name" for every name."""
    from recon.main_recon_modules.domain_recon import resolver_breaker
    resolver_breaker.set_canary(canary)
    resolver_breaker.recheck()
    return not resolver_breaker.is_open()


def _canary(mode: str, include: Optional[list], candidates: dict) -> str:
    """The org domain of the first include entry (record_filter), else of the
    first candidate by name: a root the operator's names live under."""
    from recon.helpers.public_suffix import org_domain
    if mode == "record_filter":
        patterns, _ = parse_entries(include or [])
        if patterns:
            return org_domain(patterns[0].host) or patterns[0].host
    return next((candidates[n]["org_domain"] for n in sorted(candidates) if candidates[n].get("org_domain")), "")


def _workers(settings: dict) -> int:
    try:
        return max(1, min(int(settings.get("DNS_MAX_WORKERS") or 10), 20))
    except (TypeError, ValueError):
        return 1


def _evaluate(candidates: dict, combined_result: dict, settings: dict, mode: str, edge, failed,
              resolve: Optional[Callable[[str], Any]]):
    """The rule over the run's candidates; returns (Evaluation, TargetSet).

    Recording modes resolve nothing (the rule stops at check 4); the
    guardrail and the RoE still come first.
    """
    from recon.helpers.roe_scope import _is_roe_excluded
    from recon.helpers.target_admission import target_set

    excluded = list(settings.get("ROE_EXCLUDED_HOSTS") or []) if settings.get("ROE_ENABLED") else []
    targets = target_set((combined_result.get("metadata") or {}).get("expanded_ips") or ())
    evidence = {name: {"ips_seen": c["ips_seen"], "org_domain": c["org_domain"]} for name, c in candidates.items()}
    common = dict(targets=targets, shared_edge=edge, attribution_failed=failed,
                  hard_blocked=lambda n: bool(is_hard_blocked(n)[0]),
                  roe_excluded=lambda n: bool(_is_roe_excluded(n, excluded)),
                  wildcard_zone=set())
    if mode not in SELECTING:
        return evaluate(evidence, mode=mode, include=[], exclude=[], resolve=lambda _n: (),
                        dns_enabled=False, resolver_up=False, cap=0, **common), targets
    # A list the loader could not read is unknown, which the rule refuses
    # (invalid_filter), never an empty filter.
    include = settings.get("IP_HOSTNAME_INCLUDE") if isinstance(settings.get("IP_HOSTNAME_INCLUDE"), list) else None
    exclude = settings.get("IP_HOSTNAME_EXCLUDE") if isinstance(settings.get("IP_HOSTNAME_EXCLUDE"), list) else None
    dns_enabled = settings.get("DNS_ENABLED", True) is True
    resolver_up = dns_enabled and bool(candidates) and _arm_resolver(_canary(mode, include, candidates))
    evaluation = evaluate(evidence, mode=mode, include=include, exclude=exclude,
                          resolve=resolve or dns_resolver(settings), dns_enabled=dns_enabled,
                          resolver_up=resolver_up, cap=settings.get("IP_HOSTNAME_MAX_SCANNED"),
                          workers=_workers(settings), **common)
    return evaluation, targets


# ---------------------------------------------------------------------------
# Selected names: into the run, scanned, and out again if they moved
# ---------------------------------------------------------------------------

def insert_selected(combined_result: dict, selected: Iterable[str], candidates: dict, resolved: dict) -> None:
    """Make the selected names targets of this run, before the late scan
    (design §5.4 step 4): a DNS entry with the pinned answer, the run's
    subdomains, its scope list (so httpx keeps their results and the target
    gate admits them) and metadata.ip_mode_hosts (the graph writers' admit
    set, name -> org domain)."""
    dns_subs = combined_result.setdefault("dns", {}).setdefault("subdomains", {})
    subdomains = combined_result.setdefault("subdomains", [])
    metadata = combined_result.setdefault("metadata", {})
    scope = metadata.setdefault("subdomain_filter", [])
    hosts = metadata.setdefault("ip_mode_hosts", {})
    for name in selected:
        answer = [str(a) for a in resolved.get(name) or []]
        v4 = [a for a in answer if ":" not in a]
        v6 = [a for a in answer if ":" in a]
        dns_subs[name] = {"has_records": True, "ips": {"ipv4": v4, "ipv6": v6},
                          "records": {k: v for k, v in (("A", v4), ("AAAA", v6)) if v},
                          "source": SELECTION_SOURCE, "ip_mode": True}
        if name not in subdomains:
            subdomains.append(name)
        if name not in scope:
            scope.append(name)
        hosts[name] = (candidates.get(name) or {}).get("org_domain")
    combined_result["subdomain_count"] = len(subdomains)


def withdraw_selected(combined_result: dict, name: str, sub: Optional[dict] = None) -> None:
    """Take a selected name out of the run, and out of the late scan's subset
    the graph is given (design §5.4 step 6): no later tool, writer or gate
    sees it as a target again."""
    from recon.helpers.late_names import drop_http_rows
    for run in (combined_result, sub):
        if not isinstance(run, dict):
            continue
        subs = (run.get("dns") or {}).get("subdomains")
        if isinstance(subs, dict):
            subs.pop(name, None)
        metadata = run.get("metadata") or {}
        for listed in (run.get("subdomains"), metadata.get("subdomain_filter")):
            if isinstance(listed, list) and name in listed:
                listed.remove(name)
        if isinstance(metadata.get("ip_mode_hosts"), dict):
            metadata["ip_mode_hosts"].pop(name, None)
        port_scan = run.get("port_scan") or {}
        (port_scan.get("by_host") or {}).pop(name, None)
        for row in (port_scan.get("by_ip") or {}).values():
            if isinstance(row, dict) and name in (row.get("hostnames") or []):
                row["hostnames"].remove(name)
        if isinstance(run.get("http_probe"), dict):
            drop_http_rows(run["http_probe"], name)
    if isinstance(combined_result.get("subdomains"), list):
        combined_result["subdomain_count"] = len(combined_result["subdomains"])


def _probe_rows(combined_result: dict, names: Iterable[str]) -> dict:
    """{name: [its by_url rows]} from the run's http_probe."""
    wanted = set(names)
    rows: dict[str, list] = {}
    for info in (((combined_result.get("http_probe") or {}).get("by_url")) or {}).values():
        host = str(info.get("host") or "").lower().rstrip(".") if isinstance(info, dict) else ""
        if host in wanted:
            rows.setdefault(host, []).append(info)
    return rows


def _default_late_scan(settings: dict):
    def scan(combined_result, names, pinned, targets):
        from recon.helpers import late_names
        return late_names.scan_late_names(combined_result, names, settings, probe_http=True, label="IpNames",
                                          pinned=pinned, targets=targets)
    return scan


def _scan_selected(combined_result: dict, candidates: dict, evaluation, targets, late_scan) -> dict:
    """Insert, scan, guard (design §5.4 steps 4-6). Returns {probed, live}."""
    from recon.helpers import circuit_breaker
    selected = list(evaluation.selected)
    insert_selected(combined_result, selected, candidates, evaluation.resolved)
    try:
        sub = late_scan(combined_result, selected, {n: list(evaluation.resolved[n]) for n in selected}, targets)
    except Exception as e:  # noqa: BLE001 - the names lose their scan, never the run
        print(f"[!][IpNames] Late scan of the selected hostnames failed ({type(e).__name__}): "
              f"their earlier findings are kept")
        circuit_breaker.note_degraded("ip_hostnames", hosts=selected, host_source="ip_hostnames",
                                      reason="late-name scan failed")
        return {"probed": 0, "live": 0}
    # httpx resolved each name itself: a probe that answered from anywhere but
    # a target (DNS changed since the selection), or reported no address, is
    # not the target's, and the name is no target any more.
    for name, rows in _probe_rows(combined_result, selected).items():
        outside = next((row.get("ip") for row in rows if post_probe_verdict(row.get("ip"), targets)), False)
        if outside is not False:
            print(f"[!][IpNames] {name} answered from {outside or 'no reported address'}, "
                  f"outside the target IPs: its results are dropped")
            candidates[name]["reason"] = "moved_during_scan"
            withdraw_selected(combined_result, name, sub)
    # The subset's summary is the run's (the http writer stamps it on the
    # Domain); dropping rows from the subset recounted it as its own.
    run_summary = (combined_result.get("http_probe") or {}).get("summary")
    if isinstance((sub or {}).get("http_probe"), dict) and isinstance(run_summary, dict):
        sub["http_probe"]["summary"] = dict(run_summary)
    live = {name for name, rows in _probe_rows(combined_result, selected).items()
            if any(isinstance(r.get("status_code"), int) and r["status_code"] < 500 for r in rows)}
    return {"probed": len((sub or {}).get("late_probed") or []), "live": len(live)}


def _note_not_checked(candidates: dict) -> None:
    """Names cut for the cap, the resolver or DNS off were not checked, not
    judged: note them so the end-of-run prune keeps their earlier findings
    (design §5.4 step 9). Bare names: the prune matches them on any port."""
    from recon.helpers import circuit_breaker
    for reason, why in _NOT_CHECKED.items():
        names = sorted(n for n, c in candidates.items() if c["reason"] == reason)
        if names:
            circuit_breaker.note_degraded("ip_hostnames", hosts=names, host_source="ip_hostnames",
                                          reason=f"hostnames not checked: {why}")


def _families(names: Iterable[str], candidates: dict, ip: str) -> dict:
    return _counted(
        family for name in names
        for family in {_FAMILY.get(s, s) for s in candidates[name]["seen_on"][ip]["sources"]})


def _families_text(counts: dict) -> str:
    return ", ".join(f"{k} {counts[k]}" for k in _FAMILY_ORDER if counts.get(k))


def _reasons_text(counts: dict) -> str:
    return ", ".join(f"{counts[k]} {k}" for k in sorted(counts, key=lambda k: (-counts[k], k)))


def _mode_line(mode: str, settings: dict) -> str:
    def count(key):
        value = settings.get(key)
        return len(value) if isinstance(value, list) else "?"

    if mode == "record_filter":
        return (f"[*][IpNames] Mode: record_filter (include {count('IP_HOSTNAME_INCLUDE')}, "
                f"exclude {count('IP_HOSTNAME_EXCLUDE')})")
    if mode == "scan_all":
        return "[*][IpNames] Mode: scan_all (shared CDN edges never scanned)"
    return f"[*][IpNames] Mode: {mode}"


def hostname_step(combined_result: dict, settings: Optional[dict], *,
                  resolve: Optional[Callable[[str], Any]] = None,
                  late_scan: Optional[Callable[[dict, list, dict, Any], Optional[dict]]] = None) -> Optional[dict]:
    """Collect the hostnames seen on the target IPs, select, scan and record.

    Writes combined_result["ip_hostnames"] and returns it; None outside IP
    mode. In the record modes it also sets each attributed IP's
    current_dns_names to the names recorded on it (decision D-10).

    `resolve(name)` is the A/AAAA lookup (dns_resolver by default) and
    `late_scan(combined_result, names, pinned, targets)` scans the selected
    names on their pinned answer and returns the subset recon dict the graph
    is given (late_names.scan_late_names by default); the caller writes it
    after this step, which by then has withdrawn every moved name from it.
    """
    if not is_ip_mode(combined_result):
        return None
    settings = settings or {}
    mode = hostname_mode(settings)
    block = combined_result.setdefault("ip_hostnames", {})
    block.update({"mode": mode, "candidates": {}, "by_ip": {}, "summary": _empty_summary()})
    if mode == "ip_only":
        print("[-][IpNames] IP only: hostname discovery off")
        return block

    print(_mode_line(mode, settings))
    rule_mode = mode
    if mode == "scan_all" and settings.get("IP_HOSTNAME_SCAN_ALL_CONFIRMED") is not True:
        # The settings loader refuses the run first; this is the hook's own
        # fail-closed answer should an unconfirmed scan_all ever reach it.
        print("[!][IpNames] scan_all is not confirmed: every name is recorded, none is scanned")
        rule_mode = "record_only"

    kept, per_ip_cut, run_cut, dropped = bound(collect(combined_result))
    edge, failed = _attribution_sets(combined_result)
    evaluation, target_ips = _evaluate(kept, combined_result, settings, rule_mode, edge, failed, resolve)
    for name, cand in kept.items():
        cand["on_shared_edge"] = None if edge is None else any(
            canonical_ip(ip) in edge for ip in cand["ips_seen"])
        cand["reason"] = evaluation.reasons[name]
        if name in evaluation.resolved:
            answer = evaluation.resolved[name]
            cand["resolves_to_now"] = list(answer)
            cand["resolves_here"] = bool(answer) and all(a in target_ips for a in answer)

    probe = {"probed": 0, "live": 0}
    if evaluation.selected:
        probe = _scan_selected(combined_result, kept, evaluation, target_ips,
                               late_scan or _default_late_scan(settings))
    _note_not_checked(kept)

    targets = [str(ip) for ip in (combined_result.get("metadata") or {}).get("expanded_ips") or ()]
    by_ip = {}
    for ip in targets:
        names = [n for n in kept if ip in kept[n]["seen_on"]]
        cut = per_ip_cut.get(ip, 0) + run_cut.get(ip, 0)
        if not names and not cut:
            continue
        scanned = sum(1 for n in names if kept[n]["reason"] == SCANNED)
        ip_reasons = _counted(kept[n]["reason"] for n in names if kept[n]["reason"] != SCANNED)
        by_ip[ip] = {"found": len(names), "scanned": scanned, "recorded": len(names) - scanned,
                     "truncated": cut, "reasons": ip_reasons, "sources": _families(names, kept, ip)}
        families = _families_text(by_ip[ip]["sources"])
        line = f"[*][IpNames] {ip}: {len(names)} found" + (f" ({families})" if families else "")
        line += f" → {scanned} scanned, {len(names) - scanned} recorded"
        line += f" ({_reasons_text(ip_reasons)})" if ip_reasons else ""
        if per_ip_cut.get(ip):
            line += f" (+{per_ip_cut[ip]} not kept: per-IP limit)"
        if run_cut.get(ip):
            line += f" (+{run_cut[ip]} not kept: per-run limit)"
        print(line)

    scanned_total = sum(1 for c in kept.values() if c["reason"] == SCANNED)
    summary = {"found": len(kept), "scanned": scanned_total, "recorded": len(kept) - scanned_total,
               "truncated": dropped, "ips_with_names": sum(1 for e in by_ip.values() if e["found"]),
               "reasons": _counted(c["reason"] for c in kept.values())}
    if rule_mode in SELECTING:
        summary.update(probe)
    total = (f"[+][IpNames] Total: {summary['found']} found on {summary['ips_with_names']} of "
             f"{len(targets)} IPs → {scanned_total} scanned, {summary['recorded']} recorded")
    if rule_mode in SELECTING and evaluation.selected:
        total += f"; {probe['probed']} probed by httpx, {probe['live']} live"
    print(total + (f"; {dropped} not kept (volume limit)" if dropped else ""))

    block.update({"candidates": kept, "by_ip": by_ip, "summary": summary})
    _count_names_on_attributed_ips(combined_result, by_ip)
    return block


def _count_names_on_attributed_ips(combined_result: dict, by_ip: dict) -> None:
    """D-10: an attributed IP-mode IP's current_dns_names is the number of names
    recorded on it, so a shared host shows as one."""
    found = {canonical_ip(ip): entry["found"] for ip, entry in by_ip.items()}
    attributed = ((combined_result.get("ip_attribution") or {}).get("by_ip")) or {}
    for ip, entry in attributed.items():
        if isinstance(entry, dict):
            entry["current_dns_names"] = found.get(canonical_ip(ip), 0)


def may_send(candidate: Any) -> bool:
    """A recorded name a module may send to a target IP it was seen on (as a
    vhost / SNI): never one the guardrail or the RoE refused, nor one the
    rule gave no reason."""
    reason = candidate.get("reason") if isinstance(candidate, dict) else None
    return isinstance(reason, str) and reason not in NEVER_SENT

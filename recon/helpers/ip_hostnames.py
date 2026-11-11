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
candidate and scans none. Selecting names to scan (record_filter, scan_all)
is not wired yet: those modes record the same way and say so.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from recon_settings.hard_guardrail import is_hard_blocked
from recon_settings.ip_hostnames import MODES, canonical_ip, evaluate, normalize_name

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
    IP attribution did not run."""
    attribution = combined_result.get("ip_attribution")
    if not isinstance(attribution, dict):
        return None, None
    by_ip = attribution.get("by_ip") or {}
    entries = {canonical_ip(ip): e for ip, e in by_ip.items() if isinstance(e, dict)}
    edge = {ip for ip, e in entries.items() if e.get("ownership") == "shared_edge"}
    failed = {ip for ip, e in entries.items() if _ATTRIBUTION_FAILED in (e.get("ownership_reasons") or ())}
    return edge, failed


def _record_only(candidates: dict, combined_result: dict, settings: dict, edge, failed) -> dict:
    """{name: reason}: the rule in record_only, so the guardrail and the RoE
    still come first."""
    from recon.helpers.roe_scope import _is_roe_excluded
    from recon.helpers.target_admission import target_set

    excluded = list(settings.get("ROE_EXCLUDED_HOSTS") or []) if settings.get("ROE_ENABLED") else []
    evaluation = evaluate(
        {name: {"ips_seen": c["ips_seen"], "org_domain": c["org_domain"]} for name, c in candidates.items()},
        mode="record_only", include=[], exclude=[],
        targets=target_set((combined_result.get("metadata") or {}).get("expanded_ips") or ()),
        shared_edge=edge, attribution_failed=failed,
        hard_blocked=lambda n: bool(is_hard_blocked(n)[0]),
        roe_excluded=lambda n: bool(_is_roe_excluded(n, excluded)),
        # record_only resolves nothing: the rule stops at check 4.
        resolve=lambda _n: (), dns_enabled=False, resolver_up=False, cap=0, wildcard_zone=set(),
    )
    return evaluation.reasons


def _families(names: Iterable[str], candidates: dict, ip: str) -> dict:
    return _counted(
        family for name in names
        for family in {_FAMILY.get(s, s) for s in candidates[name]["seen_on"][ip]["sources"]})


def _families_text(counts: dict) -> str:
    return ", ".join(f"{k} {counts[k]}" for k in _FAMILY_ORDER if counts.get(k))


def _reasons_text(counts: dict) -> str:
    return ", ".join(f"{counts[k]} {k}" for k in sorted(counts, key=lambda k: (-counts[k], k)))


def hostname_step(combined_result: dict, settings: Optional[dict]) -> Optional[dict]:
    """Collect and record the hostnames seen on the target IPs.

    Writes combined_result["ip_hostnames"] and returns it; None outside IP
    mode. In the record modes it also sets each attributed IP's
    current_dns_names to the names recorded on it (decision D-10).
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

    print(f"[*][IpNames] Mode: {mode}")
    if mode != "record_only":
        print("[!][IpNames] Selecting hostnames to scan is not available in this build: "
              "every name is recorded, none is scanned")

    kept, per_ip_cut, run_cut, dropped = bound(collect(combined_result))
    edge, failed = _attribution_sets(combined_result)
    reasons = _record_only(kept, combined_result, settings, edge, failed)
    for name, cand in kept.items():
        cand["on_shared_edge"] = None if edge is None else any(
            canonical_ip(ip) in edge for ip in cand["ips_seen"])
        cand["reason"] = reasons[name]

    targets = [str(ip) for ip in (combined_result.get("metadata") or {}).get("expanded_ips") or ()]
    by_ip = {}
    for ip in targets:
        names = [n for n in kept if ip in kept[n]["seen_on"]]
        cut = per_ip_cut.get(ip, 0) + run_cut.get(ip, 0)
        if not names and not cut:
            continue
        ip_reasons = _counted(kept[n]["reason"] for n in names)
        by_ip[ip] = {"found": len(names), "scanned": 0, "recorded": len(names), "truncated": cut,
                     "reasons": ip_reasons, "sources": _families(names, kept, ip)}
        families = _families_text(by_ip[ip]["sources"])
        line = f"[*][IpNames] {ip}: {len(names)} found" + (f" ({families})" if families else "")
        line += f" → 0 scanned, {len(names)} recorded"
        line += f" ({_reasons_text(ip_reasons)})" if ip_reasons else ""
        if per_ip_cut.get(ip):
            line += f" (+{per_ip_cut[ip]} not kept: per-IP limit)"
        if run_cut.get(ip):
            line += f" (+{run_cut[ip]} not kept: per-run limit)"
        print(line)

    summary = {"found": len(kept), "scanned": 0, "recorded": len(kept), "truncated": dropped,
               "ips_with_names": sum(1 for e in by_ip.values() if e["found"]),
               "reasons": _counted(c["reason"] for c in kept.values())}
    total = (f"[+][IpNames] Total: {summary['found']} found on {summary['ips_with_names']} of "
             f"{len(targets)} IPs → 0 scanned, {summary['recorded']} recorded")
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

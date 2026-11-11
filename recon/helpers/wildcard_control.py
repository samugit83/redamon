"""RedAmon's own wildcard-DNS control.

A zone with wildcard DNS (``*.example.com A 203.0.113.10``) answers every name,
so a guessed name "exists". puredns drops those at discovery, but it can be
skipped (switched off, stealth mode, a failure), and the names added after it
(certificate SANs, tlsx, js_recon, uncover) never go through it. This control
covers both:

1. Each zone the candidates sit under is probed with up to
   ``LABELS_PER_ZONE`` random labels (``rdm-<uuid12>.<zone>``). An answer
   means the zone is a wildcard zone, and the answers are its wildcard
   addresses (the union over the labels, for round-robin wildcards).
2. A candidate is dropped when its own A/AAAA set is non-empty and a subset of
   its zone's wildcard addresses, unless it is a real record (``_drops``).

The zones are the scan roots, plus each deeper parent with at least
``DEEP_PARENT_MIN_CANDIDATES`` direct candidates; a candidate is checked against
its nearest probed ancestor. Results are cached for the run.

Engagement limits: at most ``LABELS_PER_ZONE`` labels per zone and
``MAX_ZONES_PER_RUN`` zones per run, probes one at a time through the DNS step's
resolver and its breaker, paced to the RoE ceiling; a zone the RoE excludes is
never queried, and with DNS resolution off the control does not run. Stealth
mode keeps DNS resolution on, so the control is what stands in for puredns
there. A probe that fails is never evidence: nothing under that zone is
dropped, and the cut is recorded as a coverage note.
"""

from __future__ import annotations

import ipaddress
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from recon.helpers import request_pacer

LABELS_PER_ZONE = 3
MAX_ZONES_PER_RUN = 50
DEEP_PARENT_MIN_CANDIDATES = 5
LATE_LOOKUP_MAX_WORKERS = 10
QUERY_LIFETIME_S = 5.0

NOTE_SOURCE = "wildcard_control"
REASON_DNS_OFF = "DNS resolution off; names not checked for wildcard DNS"
REASON_FAILED = "wildcard probe failed; names not checked for wildcard DNS"

# Zone probes run one at a time, and the label accounting is read-modify-write.
_probe_lock = threading.Lock()
_pace_lock = threading.Lock()


@dataclass(frozen=True)
class Zone:
    name: str
    state: str                       # "wildcard" | "none" | "unknown"
    ips: frozenset = frozenset()
    cnames: frozenset = frozenset()
    why: str = ""                    # for "unknown": "failed", "cap" or "roe"

    @property
    def is_wildcard(self) -> bool:
        return self.state == "wildcard"

    def payload(self) -> dict:
        return {"is_wildcard": self.is_wildcard, "ips": sorted(self.ips, key=_ip_sort_key)}


@dataclass
class FilterResult:
    kept: list
    dropped: list = field(default_factory=list)
    # zone -> {"is_wildcard", "ips"} for every zone with a definite answer
    zones: dict = field(default_factory=dict)


def _ip_sort_key(value: str):
    try:
        address = ipaddress.ip_address(value)
        return (address.version, int(address))
    except ValueError:
        return (9, 0)


def _norm_name(name) -> str:
    return str(name or "").strip().rstrip(".").lower()


def _norm_ip(value) -> str:
    text = str(value or "").strip()
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text


def _parent(name: str) -> str:
    return name.split(".", 1)[1] if "." in name else ""


def _cache(name: str):
    from recon.helpers import circuit_breaker as cb
    return cb.run_cache(name)


# --------------------------------------------------------------------------- #
# The resolver seam
# --------------------------------------------------------------------------- #
def _query(name: str, rtype: str) -> tuple:
    """``(status, records)``: "ok", "nx" (no such name), "none" (the name
    exists, no record of this type) or "fail" (no answer at all)."""
    import dns.resolver
    from recon.main_recon_modules.domain_recon import _dns_definitive_errors, resolver_breaker

    if resolver_breaker.is_open():
        return "fail", []
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=QUERY_LIFETIME_S)
        return "ok", [rr.to_text() for rr in answers]
    except dns.resolver.NoAnswer:
        return "none", []
    except _dns_definitive_errors():
        return "nx", []
    except Exception:  # noqa: BLE001 - a timeout or a dead resolver is never an answer
        resolver_breaker.note_transient()
        return "fail", []


def _rps_ceiling(settings: dict) -> float:
    """The RoE ceiling, under the RoE capper's own rule (RoE on, rate > 0)."""
    if not settings.get("ROE_ENABLED", False):
        return 0.0
    try:
        rps = float(settings.get("ROE_GLOBAL_MAX_RPS") or 0)
    except (TypeError, ValueError):
        return 0.0
    return rps if rps > 0 else 0.0


def _pace(settings: dict) -> None:
    """The control's own clock, then a slot of the RoE clock every in-process
    requester shares (inert with no ceiling): its own alone would let the
    probes use the whole ceiling while the other requesters use it too."""
    rps = _rps_ceiling(settings)
    if rps:
        cache = _cache("wildcard_control")
        with _pace_lock:
            now = time.monotonic()
            found, next_at = cache.get("next_query_at")
            start = max(now, next_at) if found else now
            cache.put("next_query_at", start + 1.0 / rps)
        if start > now:
            time.sleep(start - now)
    request_pacer.acquire()


def _ask(name: str, rtype: str, settings: dict) -> tuple:
    _pace(settings)
    return _query(name, rtype)


# --------------------------------------------------------------------------- #
# Zones
# --------------------------------------------------------------------------- #
def _roe_excluded(zone: str, settings: dict) -> bool:
    excluded = settings.get("ROE_EXCLUDED_HOSTS") or []
    if not settings.get("ROE_ENABLED", False) or not excluded:
        return False
    from recon.helpers.roe_scope import _is_roe_excluded
    # A probe label is a subdomain of the zone, so a `*.zone` exclusion forbids
    # it even when the zone name itself is allowed.
    return _is_roe_excluded(zone, excluded) or _is_roe_excluded(f"rdm-probe.{zone}", excluded)


def _spend_label(zone: str) -> str:
    """Book one probe label for ``zone``: "" when allowed, else why not."""
    spent = _cache("wildcard_zone_labels")
    found, used = spent.get(zone)
    if not found and len(spent) >= MAX_ZONES_PER_RUN:
        return "cap"
    used = used if found else 0
    if used >= LABELS_PER_ZONE:
        return "failed"
    spent.put(zone, used + 1)
    return ""


def _probe(zone: str, settings: dict) -> Zone:
    ips, cnames = set(), set()
    answered = False
    for index in range(LABELS_PER_ZONE):
        refused = _spend_label(zone)
        if refused:
            if answered:
                break
            return Zone(zone, "unknown", why=refused)
        label = f"rdm-{uuid.uuid4().hex[:12]}.{zone}"
        status, records = _ask(label, "A", settings)
        if status == "fail":
            if answered:
                break
            return Zone(zone, "unknown", why="failed")
        if status == "nx":
            break
        answered = True
        ips.update(_norm_ip(r) for r in records)
        status, records = _ask(label, "AAAA", settings)
        if status == "fail":
            break
        ips.update(_norm_ip(r) for r in records)
        if index == 0:
            status, records = _ask(label, "CNAME", settings)
            if status == "ok":
                cnames.update(_norm_name(r) for r in records)
        if not ips:
            break  # a wildcard with no address answer: more labels add nothing
    return Zone(zone, "wildcard" if answered else "none", frozenset(ips), frozenset(cnames))


def zone(name: str, settings: dict) -> Zone:
    """The wildcard answer of ``name``, probed once per run. A failed probe is
    not cached, so a later caller may retry it within the label budget."""
    name = _norm_name(name)
    with _probe_lock:
        found, cached = _cache("wildcard_zone").get(name)
        if found:
            return cached
        if _roe_excluded(name, settings):
            return Zone(name, "unknown", why="roe")
        result = _probe(name, settings)
        if result.state != "unknown":
            _cache("wildcard_zone").put(name, result)
        return result


def _root_of(name: str, roots: list):
    best = None
    for root in roots:
        if (name == root or name.endswith("." + root)) and (best is None or len(root) > len(best)):
            best = root
    return best


def assign_zones(names: list, roots: list) -> dict:
    """``{name: zone}`` for every name strictly under a root. A root itself is
    a target the operator chose and is never checked."""
    roots = [r for r in (_norm_name(r) for r in roots or []) if r]
    under = {}
    for name in names:
        root = _root_of(name, roots)
        if root and name != root:
            under[name] = root
    counts = Counter(_parent(n) for n in under)
    deep = {parent for parent, count in counts.items()
            if count >= DEEP_PARENT_MIN_CANDIDATES and _root_of(parent, roots) != parent}
    assigned = {}
    for name, root in under.items():
        parent = _parent(name)
        while parent != root and parent not in deep:
            parent = _parent(parent)
        assigned[name] = parent
    return assigned


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #
def _drops(ips, cnames, guessed: bool, zone_answer: Zone) -> bool:
    if not zone_answer.is_wildcard:
        return False
    ips = {_norm_ip(a) for a in ips}
    if not ips or not ips <= zone_answer.ips:
        return False
    # A name a passive source saw (a CT log, passive DNS, a certificate) with a
    # CNAME that is not the wildcard's own is an explicit record whose target
    # shares the wildcard's addresses (one CDN or load balancer behind both).
    # A guessed name never earns this: under a wildcard every guess resolves,
    # so how it resolves proves nothing.
    cnames = {_norm_name(c) for c in cnames or []}
    if not guessed and cnames and not cnames <= zone_answer.cnames:
        return False
    return True


def note_unchecked(count: int, reason: str) -> None:
    """Record that ``count`` names went in without a wildcard check. A gap
    note: no prune effect, shown in the report's Coverage Limitations."""
    if count <= 0:
        return
    try:
        from recon.helpers import circuit_breaker as cb
        cb.note_degraded(NOTE_SOURCE, entries=[
            {"source": NOTE_SOURCE, "reason": reason, "skipped": int(count)}])
    except Exception:  # noqa: BLE001 - a lost note must not fail discovery
        pass


def _check(names: list, roots: list, settings: dict, lookup, guessed, label: str) -> FilterResult:
    assigned = assign_zones(names, roots)
    counts = Counter(assigned.values())
    # Most-used zones first, so the per-run cap cuts the least useful ones.
    answers = {z: zone(z, settings) for z in sorted(counts, key=lambda z: (-counts[z], z))}

    unchecked = Counter()
    for name, z in assigned.items():
        if answers[z].state == "unknown" and answers[z].why in ("failed", "cap"):
            unchecked[answers[z].why] += 1
    if unchecked["failed"]:
        note_unchecked(unchecked["failed"], REASON_FAILED)
    if unchecked["cap"]:
        note_unchecked(unchecked["cap"],
                       f"zone cap ({MAX_ZONES_PER_RUN}) reached; names not checked for wildcard DNS")

    candidates = [n for n in names if n in assigned and answers[assigned[n]].is_wildcard]
    info = lookup(candidates) if candidates else {}
    dropped = [n for n in candidates
               if _drops(*info.get(n, ([], [])), guessed(n), answers[assigned[n]])]
    dropped_set = set(dropped)

    for z, answer in answers.items():
        if answer.is_wildcard:
            gone = sum(1 for n in dropped if assigned[n] == z)
            ips = ", ".join(answer.payload()["ips"]) or "no address"
            print(f"[*][WildcardDNS] {z} answers every name ({ips}): "
                  f"dropped {gone} {label} name(s) that only resolve through it")
    return FilterResult(
        kept=[n for n in names if n not in dropped_set],
        dropped=dropped,
        zones={z: a.payload() for z, a in answers.items() if a.state != "unknown"},
    )


def filter_discovered(domain: str, names: list, dns_result: dict, sources: dict,
                      settings: dict, guessing: set) -> FilterResult:
    """The control over discovery's own names, after resolve_all_dns: their
    addresses and CNAMEs are already in ``dns_result``. ``sources`` maps a name
    to the discovery sources that listed it; a name is guessed when every one
    of them is in ``guessing``."""
    settings = settings or {}
    names = list(names or [])
    if not names:
        return FilterResult(kept=[])
    dns_subs = (dns_result or {}).get("subdomains") or {}

    def lookup(candidates):
        out = {}
        for name in candidates:
            entry = dns_subs.get(name) or {}
            ips = entry.get("ips") or {}
            records = entry.get("records") or {}
            out[name] = (list(ips.get("ipv4") or []) + list(ips.get("ipv6") or []),
                         list(records.get("CNAME") or []))
        return out

    def guessed(name):
        seen = set((sources or {}).get(name) or ())
        return bool(seen) and seen <= set(guessing or ())

    return _check(names, [domain], settings, lookup, guessed, "guessed or stale")


def _lookup_name(name: str, settings: dict) -> tuple:
    ips, cnames = [], []
    for rtype in ("A", "AAAA"):
        status, records = _ask(name, rtype, settings)
        if status == "ok":
            ips.extend(records)
    status, records = _ask(name, "CNAME", settings)
    if status == "ok":
        cnames.extend(records)
    return ips, cnames


def filter_late_names(names: list, roots: list, settings: dict, label: str = "late") -> FilterResult:
    """The control over names added after puredns (certificate SANs, tlsx,
    js_recon, uncover). They come from sources that observed them, never from
    guessing. Only names under a wildcard zone are looked up, so a plain zone
    costs one query per run."""
    settings = settings or {}
    names = list(names or [])
    if not names:
        return FilterResult(kept=[])
    if not settings.get("DNS_ENABLED", True):
        note_unchecked(len(names), REASON_DNS_OFF)
        return FilterResult(kept=names)

    def lookup(candidates):
        try:
            workers = int(settings.get("DNS_MAX_WORKERS") or 1)
        except (TypeError, ValueError):
            workers = 1
        workers = max(1, min(workers, LATE_LOOKUP_MAX_WORKERS, len(candidates)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="wildcard") as pool:
            return dict(zip(candidates, pool.map(lambda n: _lookup_name(n, settings), candidates)))

    return _check(names, roots, settings, lookup, lambda _name: False, label)

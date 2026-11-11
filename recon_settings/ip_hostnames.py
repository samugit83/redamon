"""Hostnames on target IPs: the one selection rule, for every service.

An IP-mode project's targets are addresses, but a run sees names on them
(certificate SANs, PTR answers, passive DNS, redirects). This module decides
which of those names may be scanned, and gives every other one a reason code.
It is the single implementation (invariant I-5): the recon pipeline, partial
recon, the orchestrator, the agent and the AI attack-surface scanner call it;
`webapp/src/lib/ipHostnameFilter.ts` mirrors its non-DNS part for the form
preview; both answer `tests/fixtures/ip_hostname_vectors.json`.

Standard library only, and nothing from `recon.*`: `recon_settings/` is mounted
or baked into the recon containers, the orchestrator and the agent, and only
recon ships `publicsuffixlist`. So the registrable domain (`org_domain`) is
computed by the caller and passed in, and a public-suffix filter entry is
refused by the callers that have a PSL (webapp, recon loader), not here.

Fail closed: a name that does not normalise, a filter entry that does not parse,
scan_all without IP attribution, DNS off, a resolver that is down or raises, an
address that is not a target - each is a reason code, never a scan.
"""
from __future__ import annotations

import ipaddress
import math
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Collection, Iterable, Mapping, TypedDict

MODES = ("ip_only", "record_only", "record_filter", "scan_all")
# ip_only discovers no name, so there is nothing to evaluate: a call in that
# mode is a caller bug, refused rather than given a default.
_EVALUATING_MODES = frozenset(("record_only", "record_filter", "scan_all"))

SCANNED = "scanned"

#: Every code a hostname can carry, in the order of the checks (design §4.2).
#: The last two are set after evaluate(): moved_during_scan by the post-probe
#: guard (post_probe_verdict), out_of_policy by the webapp's narrowing marker on
#: an already scanned name (design §6.3), which no function here returns.
REASON_CODES = (
    "invalid_name",
    "hard_blocked",
    "roe_excluded",
    "record_only",
    "invalid_filter",
    "filter_excluded",
    "filter_no_match",
    "no_registrable_domain",
    "attribution_unavailable",
    "shared_edge_ip",
    "dns_disabled",
    "resolver_unavailable",
    "no_current_resolution",
    "never_scannable_address",
    "resolves_outside_targets",
    "wildcard_zone",
    "cap_reached",
    SCANNED,
    "moved_during_scan",
    "out_of_policy",
)

MAX_HOSTNAME_LENGTH = 253

#: How a refused non-string filter entry is reported (both languages).
NOT_A_STRING = "<not a string>"

# JavaScript's String.prototype.trim() set, so an entry trims here exactly as in
# the form: str.strip() also eats \x1c-\x1f and \x85, which trim keeps, and the
# rule would then accept an entry the form refuses.
_TRIM = (
    "\t\n\v\f\r          "
    "        　﻿"
)
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_CHARSET = re.compile(r"[a-z0-9.-]+")
_TLD = re.compile(r"[a-z]{2,}")

# A /24 or an IPv6 /112 expands into a set once (O(1) lookups); anything larger
# stays a range, because the webapp accepts IPv6 targets down to /104.
_EXPAND_LIMIT = 1 << 16


class Candidate(TypedDict, total=False):
    """The evidence evaluate() reads for one name (the recon JSON candidate)."""

    ips_seen: list[str]
    org_domain: str | None


@dataclass(frozen=True)
class Pattern:
    """One parsed filter entry: `*.host` (strict subdomains) or `host` (exactly)."""

    host: str
    wildcard: bool

    @property
    def token(self) -> str:
        return f"*.{self.host}" if self.wildcard else self.host

    def matches(self, name: str) -> bool:
        return name.endswith("." + self.host) if self.wildcard else name == self.host


@dataclass(frozen=True)
class Invalid:
    """A refused filter entry, as typed (trimmed), with a Domain-batch reason."""

    entry: str
    reason: str


@dataclass(frozen=True)
class MatchResult:
    included: bool
    excluded: bool
    matched_by: str | None


@dataclass(frozen=True)
class Evaluation:
    selected: list[str]
    reasons: dict[str, str]
    #: The A/AAAA answer each verdict used, canonical and sorted. Callers scan
    #: with THIS answer and never re-resolve: a second lookup could return an
    #: address nobody checked against the target list.
    resolved: dict[str, list[str]]


# ---------------------------------------------------------------------------
# Normalisation: webapp/src/lib/domainBatch.ts normalizeHost, splitWildcard and
# parseEntry, minus the public-suffix check.
# ---------------------------------------------------------------------------

def normalize_host(raw: Any) -> str:
    """Strip what people paste around a hostname: scheme, credentials, path,
    query, port, surrounding whitespace and trailing root dots. An IPv6 literal
    is kept whole so it can be refused as an address rather than mangled."""
    h = ("" if raw is None else str(raw)).strip(_TRIM).lower()
    h = _SCHEME.sub("", h, count=1)
    h = h.split("/")[0].split("?")[0].split("#")[0]
    h = h.rsplit("@", 1)[-1]
    if h.startswith("["):
        end = h.find("]")
        return h[1:] if end == -1 else h[1:end]
    if h.count(":") > 1:
        return h
    return h.split(":")[0].rstrip(".")


def split_wildcard(host: str) -> tuple[bool, str]:
    """`*.x` and `*x` both mean "under x". Only one marker is stripped, so
    `**.x` keeps a star and is refused as malformed."""
    if host.startswith("*."):
        return True, host[2:]
    if host.startswith("*"):
        return True, host[1:]
    return False, host


# The webapp refuses an IP literal with tldts' `parse(host).isIp`
# (publicSuffix.isIpLiteral), a heuristic over tldts' URL hostname extraction:
# `01.02.03.04` IS an address there, `[::1]` normalised to `::1` is NOT (the
# extraction cuts at the last colon). The three helpers below port tldts-core
# 7.0.28 (is-valid.js, extract-hostname.js, is-ip.js) so a refused entry carries
# the same reason on both sides; the ip_literal / not_hostname vectors pin it.

def _tldts_valid_char(code: int) -> bool:
    return 97 <= code <= 122 or 48 <= code <= 57 or code > 127


def _tldts_is_valid_hostname(host: str) -> bool:
    if len(host) > 255 or not host:
        return False
    first = ord(host[0])
    if not _tldts_valid_char(first) and first not in (46, 95):
        return False
    last_dot, last_code = -1, -1
    for i, char in enumerate(host):
        code = ord(char)
        if code == 46:
            if i - last_dot > 64 or last_code in (46, 45, 95):
                return False
            last_dot = i
        elif not (_tldts_valid_char(code) or code in (45, 95)):
            return False
        last_code = code
    return len(host) - last_dot - 1 <= 63 and last_code != 45


def _tldts_extract_hostname(url: str, is_valid: bool) -> str | None:
    # normalize_host has already removed every '/', '?', '#' and '@' and lowered
    # the case, so tldts' scheme, path, credential and upper-case steps never
    # apply to what reaches here and are not ported.
    start, end = 0, len(url)
    if not is_valid:
        while start < len(url) and ord(url[start]) <= 32:
            start += 1
        while end > start + 1 and ord(url[end - 1]) <= 32:
            end -= 1
        closing, port = url.rfind("]", start, end), url.rfind(":", start, end)
        if url[start:start + 1] == "[":
            return url[start + 1:closing].lower() if closing != -1 else None
        if port > start:
            end = port
    while end > start + 1 and url[end - 1] == ".":
        end -= 1
    return url[start:end]


def _tldts_probably_ip(host: str) -> bool:
    v6_start = 1 if host.startswith("[") else 0
    v6_end = len(host) - 1 if host.endswith("]") else len(host)
    if len(host) >= 3 and v6_end - v6_start <= 39:
        body = host[v6_start:v6_end]
        if ":" in body and all(c == ":" or "0" <= c <= "9" or "a" <= c <= "f" or "A" <= c <= "Z" for c in body):
            return True
    if not 7 <= len(host) <= 15 or not all(c == "." or "0" <= c <= "9" for c in host):
        return False
    return host.count(".") == 3 and host[0] != "." and host[-1] != "."


def _is_ip_literal(host: str) -> bool:
    hostname = _tldts_extract_hostname(host, _tldts_is_valid_hostname(host))
    return hostname is not None and _tldts_probably_ip(hostname)


def _js_length(text: str) -> int:
    """String.length: UTF-16 code units, so the 253 limit counts as in the form."""
    return len(text.encode("utf-16-le")) // 2


def _is_hostname_shape(host: str) -> bool:
    """Two or more labels of 1-63 characters from [a-z0-9-], no label starting or
    ending with a hyphen, and an alphabetic TLD (so no address passes)."""
    if not _CHARSET.fullmatch(host):
        return False
    labels = host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return False
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return _TLD.fullmatch(labels[-1]) is not None


def normalize_name(raw: Any) -> str | None:
    """The canonical spelling of a hostname, or None when it is not one.

    This is check 1 of the rule. A wildcard SAN, an IP literal, a dashed IP
    placeholder and a single label are all None.
    """
    if not isinstance(raw, str):
        return None
    host = normalize_host(raw)
    if len(host) > MAX_HOSTNAME_LENGTH or not _is_hostname_shape(host):
        return None
    return host


def _parse_entry(raw: str) -> Pattern | str:
    wildcard, rest = split_wildcard(normalize_host(raw))
    if "*" in rest or (wildcard and not rest):
        return "malformed_wildcard"
    if _is_ip_literal(rest):
        return "ip_literal"
    if _js_length(rest) > MAX_HOSTNAME_LENGTH:
        return "too_long"
    if not _is_hostname_shape(rest):
        return "not_hostname"
    return Pattern(rest, wildcard)


def parse_entries(entries: Iterable[Any] | None) -> tuple[list[Pattern], list[Invalid]]:
    """Parse include/exclude entries with the Domain-batch syntax.

    Blank strings (empty textarea lines) are skipped. A non-string entry is
    refused, unlike the Domain batch, which skips it: an exclude entry the rule
    cannot read must not silently widen what is scanned. Patterns are
    deduplicated on their token and keep the operator's order; each refused
    entry is reported once.
    """
    patterns: list[Pattern] = []
    invalid: list[Invalid] = []
    seen: set[str] = set()
    for raw in entries or ():
        if not isinstance(raw, str):
            entry, parsed = NOT_A_STRING, "not_hostname"
        elif not raw.strip(_TRIM):
            continue
        else:
            entry, parsed = raw.strip(_TRIM), _parse_entry(raw)
        if isinstance(parsed, str):
            if all(i.entry != entry for i in invalid):
                invalid.append(Invalid(entry, parsed))
            continue
        if parsed.token not in seen:
            seen.add(parsed.token)
            patterns.append(parsed)
    return patterns, invalid


def matches(name: str, include: Iterable[Pattern], exclude: Iterable[Pattern]) -> MatchResult:
    """Exclude wins; `matched_by` is the first deciding entry in operator order."""
    host = normalize_host(name)
    for pattern in exclude:
        if pattern.matches(host):
            return MatchResult(False, True, pattern.token)
    for pattern in include:
        if pattern.matches(host):
            return MatchResult(True, False, pattern.token)
    return MatchResult(False, False, None)


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

def is_never_scannable_ip(ip_str: Any) -> bool:
    """A stdlib copy of `recon/main_recon_modules/ip_filter.is_never_scannable_ip`.

    Loopback, link-local (169.254.169.254 is cloud metadata), unspecified and
    multicast are wrong for a scanner whoever owns the estate; anything that is
    not an address fails closed. Private addresses are NOT here: IP-mode
    engagements are often internal. Pinned against the original, address by
    address, by recon/tests/test_ip_hostname_rule.py.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast


def _in_hosts(net: ipaddress.IPv4Network | ipaddress.IPv6Network, addr: Any) -> bool:
    """Membership in `net.hosts()` without expanding it: no network address,
    and no broadcast address for IPv4 (the pipeline expands CIDRs with hosts())."""
    if addr not in net or addr == net.network_address:
        return False
    return net.version == 6 or addr != net.broadcast_address


class TargetSet:
    """The project's expanded target addresses, built once, compared canonically.

    A CIDR means what the pipeline's expansion means (`network.hosts()`, plus the
    address of a /32 or /128), so a name resolving to a network or broadcast
    address is outside the targets, as no scanner ever sent it a packet.

    Build it from the EXPANDED target list after the RoE filter, never from the
    raw CIDR entries: a range kept whole cannot subtract RoE exclusions.

    The rule takes targets only as a TargetSet (see _require_targets).
    """

    __slots__ = ("_addresses", "_networks", "invalid")

    def __init__(self, addresses: Collection[Any], networks: Collection[Any], invalid: Iterable[str]):
        self._addresses = set(addresses)
        self._networks = tuple(networks)
        #: Entries that are neither an address nor a CIDR. They add nothing,
        #: which narrows the set; kept so a caller can log them.
        self.invalid = tuple(invalid)

    @classmethod
    def from_entries(cls, entries: Iterable[Any] | None) -> TargetSet:
        addresses: set[Any] = set()
        networks: list[Any] = []
        invalid: list[str] = []
        for raw in entries or ():
            text = "" if raw is None else str(raw).strip()
            if not text:
                continue
            try:
                if "/" not in text:
                    addresses.add(ipaddress.ip_address(text))
                    continue
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                invalid.append(text)
                continue
            if net.num_addresses > _EXPAND_LIMIT:
                networks.append(net)
                continue
            addresses.update(net.hosts())
            if net.prefixlen == net.max_prefixlen:
                addresses.add(net.network_address)
        return cls(addresses, networks, invalid)

    def __contains__(self, address: Any) -> bool:
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return False
        return addr in self._addresses or any(_in_hosts(net, addr) for net in self._networks)


def _require_targets(targets: Any) -> TargetSet:
    """Refuse anything but a TargetSet, before any check runs.

    `in` means something else on every other type: on a str it is a substring
    test ('3.0.113.2' in '203.0.113.200' is True), on a list or set an exact
    string match that ignores CIDRs and canonical forms. A TypeError selects
    nothing, like the other unusable inputs that raise.
    """
    if not isinstance(targets, TargetSet):
        raise TypeError(f"targets must be a TargetSet, got {type(targets).__name__}")
    return targets


def address_verdict(addresses: Iterable[Any] | None, targets: TargetSet) -> str | None:
    """None when there is at least one address and every one is a target.

    Checks 12-14 of the rule, in that order: no answer, a never-scannable
    address (even a listed one), an address outside the targets.
    """
    _require_targets(targets)
    answer = list(addresses or ())
    if not answer:
        return "no_current_resolution"
    if any(is_never_scannable_ip(a) for a in answer):
        return "never_scannable_address"
    if any(a not in targets for a in answer):
        return "resolves_outside_targets"
    return None


def post_probe_verdict(observed: Iterable[Any] | str | None, targets: TargetSet) -> str | None:
    """The post-probe guard's check (I-1 c), for a name that was scanned.

    `observed` is what the late probe reported for the name (httpx's `ip`, one
    address or several). Any address outside the targets means DNS changed
    between selection and probe: `moved_during_scan`. None only when at least
    one address was reported and every one is a target.

    A probe that reported no address is also `moved_during_scan`: nothing then
    proves the probe stayed on a target, and I-6 fails closed. The code is
    reused rather than a new one added, so the vocabulary stays design §4.2's.
    """
    _require_targets(targets)
    if isinstance(observed, str):
        observed = [observed]
    addresses = list(observed or ())
    if addresses and all(canonical_ip(a) in targets for a in addresses):
        return None
    return "moved_during_scan"


def canonical_ip(value: Any) -> str:
    """The one spelling of an address, for comparing and for the pinned answer.

    RFC 5952 for IPv6, as `ipaddress` prints it, except that an IPv4-mapped
    address is always written `::ffff:a.b.c.d`: CPython changed how it prints
    those in a patch release (3.11.15 dotted, 3.12.3 hex), and the canonical form
    must not depend on the image. Not an address: the trimmed text, unchanged.
    The webapp mirror (canonicalIp) answers the same `canonical` vectors.
    """
    text = str(value).strip(_TRIM)
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        scope = f"%{addr.scope_id}" if addr.scope_id else ""
        return f"::ffff:{addr.ipv4_mapped}{scope}"
    return str(addr)


def _pin(answer: Iterable[Any] | None) -> list[str]:
    return sorted({canonical_ip(a) for a in answer or ()})


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------

def _passes(check: Callable[[str], Any], name: str) -> bool:
    """Only a literal False lets a name through an injected check.

    None, a tuple, any other value, or a raise refuses the name with that
    check's code: a predicate that cannot answer must never widen the selection
    (I-6). The guardrail copies return (blocked, reason), so callers pass
    `lambda n: is_hard_blocked(n)[0]`, never the copy itself.
    """
    try:
        return check(name) is False
    except Exception:  # noqa: BLE001 - a broken check refuses the name, not the run
        return False


def _address_set(values: Any) -> set[str] | None:
    """Canonical addresses, or None (unknown) when any entry is not a string.

    A single address is one address, not its characters: iterating a str would
    make an edge IP unrecognisable and let its names through. An entry nobody
    can read (None, a number) makes the whole set unknown for the same reason.
    """
    if values is None:
        return None
    if isinstance(values, str):
        values = [values]
    values = list(values)
    if not all(isinstance(v, str) for v in values):
        return None
    return {canonical_ip(v) for v in values}


def _name_set(values: Any) -> set[str] | None:
    if values is None:
        return None
    return {values} if isinstance(values, str) else set(values)


def _cap(value: Any) -> int:
    # A finite number, truncated; anything else (None, a string, a bool, NaN,
    # infinity) scans nothing. JavaScript numbers are read the same way.
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return 0
    return max(int(value), 0)


def _resolve_one(resolve: Callable[[str], Any], name: str) -> list[str] | None:
    try:
        return _pin(resolve(name))
    except Exception:  # noqa: BLE001 - an unknown answer must refuse the name, not the run
        return None


def _resolve_all(names: list[str], resolve: Callable[[str], Any], workers: int) -> list[list[str] | None]:
    if workers > 1 and len(names) > 1:
        with ThreadPoolExecutor(max_workers=min(workers, len(names))) as pool:
            return list(pool.map(lambda name: _resolve_one(resolve, name), names))
    return [_resolve_one(resolve, name) for name in names]


def evaluate(
    candidates: Mapping[str, Candidate | None],
    *,
    mode: str,
    include: Iterable[str] | None,
    exclude: Iterable[str] | None,
    targets: TargetSet,
    shared_edge: Collection[str] | None,
    hard_blocked: Callable[[str], Any],
    roe_excluded: Callable[[str], Any],
    resolve: Callable[[str], Iterable[str] | None],
    dns_enabled: bool,
    resolver_up: bool,
    cap: int,
    wildcard_zone: Collection[str] | None,
    attribution_failed: Iterable[str] | None = None,
    workers: int = 1,
) -> Evaluation:
    """Select the names to scan; give every other name the first failing check.

    Every input that is missing or unreadable refuses names, never admits them
    (I-6):

    - `candidates` maps canonical names (see normalize_name) to their evidence;
      a non-string or empty `org_domain` is check 7.
    - `include` / `exclude`: None (unknown) is `invalid_filter` in
      record_filter, like an entry that does not parse.
    - `shared_edge`: the target IPs tagged shared_edge, None when IP attribution
      did not run. `attribution_failed`: the target IPs whose attribution
      failed, None when unknown. In scan_all either None, or a candidate with no
      `ips_seen`, is `attribution_unavailable`, and check 9 refuses a name seen
      on an edge IP or resolving to one (an edge serves any tenant's site under
      the name, so the answer alone must not reach it). Ignored in the other
      modes.
    - `hard_blocked`, `roe_excluded`: strict predicates (see _passes).
    - `dns_enabled`, `resolver_up`: only True passes.
    - `cap`: anything but a finite number is 0.
    - an IP list given as one string is one address; a list holding an entry
      that is not a string is unknown (None).
    - `wildcard_zone` (required): the names wildcard DNS control dropped; pass
      an empty set when expansion did not run. None (unknown) is `wildcard_zone`
      for every record_filter name that reaches check 15.

    Names are walked in sorted order, so the cap keeps the same names for the
    same input. Only names that pass checks 1-11 are resolved, at most 2 x cap
    of them; the rest get cap_reached unresolved, which bounds the DNS load.
    `resolve` is called once per name, in parallel when `workers` > 1.

    `targets` must be a TargetSet built from the expanded target list after the
    RoE filter (not the raw CIDR entries, which cannot subtract exclusions).
    """
    _require_targets(targets)
    if mode not in _EVALUATING_MODES:
        raise ValueError(f"evaluate() needs a recording mode {sorted(_EVALUATING_MODES)}, got {mode!r}")
    include_patterns, include_invalid = parse_entries(include)
    exclude_patterns, exclude_invalid = parse_entries(exclude)
    filters_readable = include is not None and exclude is not None and not (include_invalid or exclude_invalid)
    edge = _address_set(shared_edge)
    failed = _address_set(attribution_failed)
    wildcard_names = _name_set(wildcard_zone)
    cap = _cap(cap)

    def before_dns(name: Any, candidate: Mapping[str, Any]) -> str | None:
        if normalize_name(name) != name:
            return "invalid_name"
        if not _passes(hard_blocked, name):
            return "hard_blocked"
        if not _passes(roe_excluded, name):
            return "roe_excluded"
        if mode == "record_only":
            return "record_only"
        if mode == "record_filter":
            if not filters_readable:
                return "invalid_filter"
            verdict = matches(name, include_patterns, exclude_patterns)
            if verdict.excluded:
                return "filter_excluded"
            if not verdict.included:
                return "filter_no_match"
        org = candidate.get("org_domain")
        if not isinstance(org, str) or not org:
            return "no_registrable_domain"
        if mode == "scan_all":
            # A name seen on no target IP cannot be attributed to one, so
            # neither half of check 8 can clear it.
            seen = _address_set(candidate.get("ips_seen")) or set()
            if edge is None or failed is None or not seen or seen & failed:
                return "attribution_unavailable"
            if seen & edge:
                return "shared_edge_ip"
        if dns_enabled is not True:
            return "dns_disabled"
        if resolver_up is not True:
            return "resolver_unavailable"
        return None

    reasons: dict[Any, str] = {}
    survivors: list[str] = []
    for name in sorted(candidates, key=str):
        reason = before_dns(name, candidates[name] or {})
        if reason is None:
            survivors.append(name)
        else:
            reasons[name] = reason

    budget = survivors[: 2 * cap]
    for name in survivors[2 * cap:]:
        reasons[name] = "cap_reached"

    selected: list[str] = []
    resolved: dict[str, list[str]] = {}
    for name, answer in zip(budget, _resolve_all(budget, resolve, workers)):
        if answer is None:
            reasons[name] = "resolver_unavailable"
            continue
        resolved[name] = answer
        # Check 9 on the answer, before 12-14 as its number says.
        if mode == "scan_all" and edge is not None and edge.intersection(answer):
            reason = "shared_edge_ip"
        else:
            reason = address_verdict(answer, targets)
        if reason is None and mode == "record_filter" and (wildcard_names is None or name in wildcard_names):
            reason = "wildcard_zone"
        if reason is None and len(selected) >= cap:
            reason = "cap_reached"
        if reason is None:
            selected.append(name)
            reason = SCANNED
        reasons[name] = reason

    return Evaluation(
        selected=selected,
        reasons=dict(sorted(reasons.items(), key=lambda item: str(item[0]))),
        resolved=resolved,
    )

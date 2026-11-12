import os
import sys
import time
from pathlib import Path

# Add project root to path (for lazy imports in other modules)
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Multi-root scope
#
# A Domain-batch project has one Domain node per root. The orchestrator decides
# which roots a run may touch and writes them to config["domains"]; partial_recon
# .main re-checks them against the container's own settings. Every module reads
# its roots through scope_roots(), never config["domain"] directly.
# ---------------------------------------------------------------------------

STATUS_OK = "ok"
STATUS_NO_RESULTS = "no_results"
STATUS_RATE_LIMITED = "rate_limited"
# The root ran but a circuit breaker / HostHealth cut some of its coverage.
# It counts as a root that ran (exit 0), and is listed with its reason.
STATUS_DEGRADED = "degraded"

# Pacing for the per-root API loops. Module constants rather than a project
# setting, which keeps the settings cascade out of this change.
ROOT_PAUSE_S = 2
RATE_LIMIT_RETRY_DELAY_S = 30


def scope_roots(config: dict) -> list:
    """The roots this run covers: config["domains"], else the legacy single domain."""
    roots = config.get("domains")
    if isinstance(roots, list):
        cleaned = [r for r in roots if isinstance(r, str) and r]
        if cleaned:
            return cleaned
    legacy = config.get("domain")
    return [legacy] if isinstance(legacy, str) and legacy else []


from recon.helpers.batch_groups import settings_scope_groups  # noqa: E402,F401 - re-exported


def _norm_host(value) -> str:
    return str(value or "").strip().strip(".").lower()


def root_for_host(host: str, roots: list, ip_mode: bool = False):
    """The longest root that `host` equals or sits under, or None.

    IP mode has one synthetic root (ip-targets.<project_id>) whose Subdomains
    are dashed IPs rather than names under it, so every host belongs to it.
    The root is returned as stored, because it is matched against Domain.name.
    """
    h = _norm_host(host)
    if not h or not roots:
        return None
    if ip_mode:
        return roots[0]
    best, best_len = None, -1
    for root in roots:
        r = _norm_host(root)
        if r and (h == r or h.endswith("." + r)) and len(r) > best_len:
            best, best_len = root, len(r)
    return best


def host_in_roots(host: str, roots: list) -> bool:
    return root_for_host(host, roots) is not None


def typed_host_ok(host: str, roots: list, groups) -> bool:
    """A host the operator typed: the §4.6 partial rule when the run has scope
    groups (an EXACT group's list, strictly under an ENUMERATE root, a root only
    with Include Root), else under any root as before. The run's start already
    applied it (filter_partial_user_input); this keeps a module honest on its own.
    IP mode: a name the run may scan (S), which a typed name joined only when
    the rule selected it on live DNS."""
    if run_is_ip_mode():
        return is_run_ip_hostname(host)
    if groups and all(isinstance(g, dict) and "mode" in g for g in groups):
        return admits_partial_host(groups, host)
    return host_in_roots(host, roots)


def typed_host_domain(host, roots: list):
    """The Domain a typed host's Subdomain hangs off: the org of its scan root,
    or in IP mode the org Domain of a name in S. Never the synthetic
    ip-targets root, which is no parent of a real name; None for a host the
    run may not scan (the writer's MATCH then links nothing)."""
    if run_is_ip_mode():
        return _RUN_IP_HOSTNAMES.get(_norm_host(host))
    return attach_org(root_for_host(host, roots))


def _group_for(root: str, groups: list):
    r = _norm_host(root)
    for group in groups or []:
        if isinstance(group, dict) and _norm_host(group.get("rootDomain")) == r:
            return group
    return None


def include_root_for(root: str, groups: list) -> bool:
    """Is the scan root itself a target? The group's includeRoot, or for a
    legacy entry, a "." among its prefixes."""
    group = _group_for(root, groups)
    if group is None:
        return False
    if "includeRoot" in group:
        return bool(group["includeRoot"])
    from recon.helpers.batch_groups import parse_target
    return parse_target(root, list(group.get("prefixes") or []))["include_root_domain"]


def allowed_hosts_for(root: str, groups: list):
    """The exact hosts an EXACT group may scan, or None for "any host under root".

    An EXACT group scans its listed hosts (and its scan root when Root is on),
    nothing else, whether it is a batch group or the one group of a
    single-domain project with a prefix list (§4.6). An ENUMERATE group scans
    whatever lies under its root.
    """
    group = _group_for(root, groups)
    if group is None:
        return None
    if "mode" in group:
        if group["mode"] == "enumerate":
            return None
        hosts = {_norm_host(h) for h in group.get("exactHosts") or []}
        if group.get("includeRoot"):
            hosts.add(_norm_host(root))
        return hosts
    from recon.helpers.batch_groups import parse_target
    if not group.get("batch"):
        return None
    info = parse_target(root, list(group.get("prefixes") or []))
    if info["wildcard_mode"]:
        return None
    return {_norm_host(h) for h in info["full_subdomains"]}


# Every scan root of the project, set once by partial_recon._prepare_scope from
# the container's settings. A graph host belongs to the LONGEST scan root it
# sits under across the whole project, not only the roots this run covers.
_PROJECT_SCAN_ROOTS: list = []


_ROOT_ORGS: dict = {}


def scope_groups_payload(groups) -> list:
    """Scope groups in the recon-file shape (snake_case) the graph writers read."""
    out = []
    for g in groups or []:
        if isinstance(g, dict) and "scanRoot" in g:
            out.append({"scan_root": g["scanRoot"], "org_domain": g.get("orgDomain") or g["scanRoot"],
                        "mode": g["mode"], "include_root": bool(g.get("includeRoot")),
                        "exact_hosts": list(g.get("exactHosts") or [])})
    return out


def set_project_scope(groups) -> None:
    """Record the project's scan roots and each one's org, from the container's
    settings (partial_recon._prepare_scope), for the builders and the writers.

    The writers get the groups too, as the run's default for a recon dict that
    carries none: a partial run builds its dicts in many places, and a writer
    without the groups would attach a deeper scan root's hosts to a Domain
    named after the root, which the org model never creates.
    """
    global _PROJECT_SCAN_ROOTS, _ROOT_ORGS
    _PROJECT_SCAN_ROOTS, _ROOT_ORGS = [], {}
    from graph_db.mixins.recon.scope import set_run_scope_groups
    set_run_scope_groups(scope_groups_payload(groups))
    for g in groups or []:
        root = _norm_host(g.get("scanRoot")) if isinstance(g, dict) else ""
        if root:
            _PROJECT_SCAN_ROOTS.append(root)
            _ROOT_ORGS[root] = _norm_host(g.get("orgDomain")) or root


def project_scan_roots() -> list:
    return list(_PROJECT_SCAN_ROOTS)


# The run's RoE exclusions, set once by partial_recon._prepare_scope. The graph
# builders read hosts and IPs straight from Neo4j and receive no settings, so
# without this an excluded host (or an IP in an excluded CIDR) that an earlier
# run wrote would become a partial run's target.
_RUN_ROE_EXCLUDED: list = []


def set_run_roe(settings: dict) -> None:
    global _RUN_ROE_EXCLUDED
    settings = settings or {}
    excluded = settings.get("ROE_EXCLUDED_HOSTS") if settings.get("ROE_ENABLED") else None
    _RUN_ROE_EXCLUDED = [e for e in (excluded or []) if isinstance(e, str) and e.strip()]


def roe_excluded(host_or_ip) -> bool:
    """True when the run's RoE excludes this host name or IP."""
    if not _RUN_ROE_EXCLUDED or not host_or_ip:
        return False
    from recon.helpers.roe_scope import _is_roe_excluded
    return _is_roe_excluded(str(host_or_ip), _RUN_ROE_EXCLUDED)


# IP mode: the run's expanded target list, set once by partial_recon._prepare_scope
# (None outside IP mode). The graph builders get no settings, and every recon
# dict a partial run hands a scanner must declare the list.
_RUN_IP_TARGETS = None
_EXPANDED_TARGETS: dict = {}
_EXPANDED_TARGETS_MAX = 4


def ip_mode_target_list(settings: dict):
    """IP mode: the project's targets as run_ip_recon expands them, or None.

    A CIDR is its hosts (a /32 or /128 its address), an address is kept as
    listed, duplicates go, then the RoE's excluded addresses. The same list
    the full run writes to metadata.expanded_ips, so a partial dict never
    declares raw CIDRs (B-23). Built once per list.
    """
    settings = settings or {}
    if not settings.get("IP_MODE"):
        return None
    raw = tuple(str(e).strip() for e in settings.get("TARGET_IPS") or [] if str(e or "").strip())
    excluded = tuple(e for e in (settings.get("ROE_EXCLUDED_HOSTS") or []) if isinstance(e, str) and e.strip()) \
        if settings.get("ROE_ENABLED") else ()
    key = (raw, excluded)
    if key not in _EXPANDED_TARGETS:
        import ipaddress as _ipaddress
        expanded = []
        for entry in raw:
            if "/" not in entry:
                expanded.append(entry)
                continue
            try:
                network = _ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            expanded.extend(str(host) for host in network.hosts())
            if network.prefixlen in (32, 128):
                expanded.append(str(network.network_address))
        expanded = list(dict.fromkeys(expanded))
        if excluded:
            from recon.helpers.roe_scope import _is_roe_excluded
            expanded = [ip for ip in expanded if not _is_roe_excluded(ip, list(excluded))]
        while len(_EXPANDED_TARGETS) >= _EXPANDED_TARGETS_MAX:
            _EXPANDED_TARGETS.pop(next(iter(_EXPANDED_TARGETS)))
        _EXPANDED_TARGETS[key] = expanded
    return list(_EXPANDED_TARGETS[key])


def set_run_ip_targets(settings: dict) -> None:
    """Set the run's target list; the run's hostnames start empty again, as
    they are judged against this list (set_run_ip_hostnames)."""
    global _RUN_IP_TARGETS
    _RUN_IP_TARGETS = ip_mode_target_list(settings)
    set_run_ip_hostnames({})


def run_ip_targets():
    """The run's expanded IP-mode targets, or None outside IP mode."""
    return None if _RUN_IP_TARGETS is None else list(_RUN_IP_TARGETS)


def run_is_ip_mode() -> bool:
    """The run is an IP-mode one; no copy of the list, for a per-row check."""
    return _RUN_IP_TARGETS is not None


# IP mode: the hostnames this run may scan (S, name -> org Domain) and the
# answer each was judged on, set once by partial_recon._prepare_scope
# (ip_hostname_scope.run_hostname_scope). Empty in ip_only and record_only,
# and outside IP mode. Every reader of the run keeps a real name only when it
# is here: a graph name's own reason is never trusted on its own (design §6.3).
_RUN_IP_HOSTNAMES: dict = {}
_RUN_IP_HOSTNAME_ANSWERS: dict = {}


def set_run_ip_hostnames(names, answers=None) -> None:
    global _RUN_IP_HOSTNAMES, _RUN_IP_HOSTNAME_ANSWERS
    _RUN_IP_HOSTNAMES = {_norm_host(n): o for n, o in (names or {}).items() if _norm_host(n) and o}
    _RUN_IP_HOSTNAME_ANSWERS = {_norm_host(n): list(a or []) for n, a in (answers or {}).items()
                                if _norm_host(n) in _RUN_IP_HOSTNAMES}


def run_ip_hostnames() -> dict:
    """S: {name: org Domain} for an IP-mode run, else {}."""
    return dict(_RUN_IP_HOSTNAMES)


def run_ip_hostname_answer(name) -> list:
    """The pinned answer ``name`` was selected on (a tool scans with it and
    never re-resolves); [] for a name not in S."""
    return list(_RUN_IP_HOSTNAME_ANSWERS.get(_norm_host(name)) or [])


def is_run_ip_hostname(host) -> bool:
    return _norm_host(host) in _RUN_IP_HOSTNAMES


def keep_selected_names(recon_data: dict) -> dict:
    """IP mode with S: tell httpx to keep the results of the run's names.

    Outside filtered mode httpx keeps a name only under the run's roots, and
    the synthetic root is no parent of a real name, so a probed name's rows
    were dropped. Filtered mode keeps exactly the listed hosts, as the full
    run lists its selected names: the targets (each spelling, as httpx may
    echo either) and S. Without S the dict is left alone.
    """
    if _RUN_IP_TARGETS is None or not _RUN_IP_HOSTNAMES:
        return recon_data
    from recon_settings.ip_hostnames import canonical_ip
    hosts = list(dict.fromkeys([*_RUN_IP_TARGETS, *(canonical_ip(t) for t in _RUN_IP_TARGETS),
                                *sorted(_RUN_IP_HOSTNAMES)]))
    metadata = recon_data.setdefault("metadata", {})
    metadata["filtered_mode"] = True
    metadata["subdomain_filter"] = hosts
    return recon_data


def ip_mode_recon(recon_data: dict, settings: dict = None) -> dict:
    """Stamp a partial run's recon dict with its IP-mode facts, in place, and return it.

    Every reader that keeps to the targets asks metadata.ip_mode and the
    expanded metadata.expanded_ips: the admission gate, the OSINT IP lists,
    the DNS-only security checks, Shodan's and urlscan's domain lookups,
    build_target_urls' name source. A dict without them reads as a domain run
    and hands the synthetic root, which is the project id, to third parties
    (B-19). The list comes from ``settings`` when given, else from the run.
    Outside IP mode the dict is left as it is.
    test_partial_ip_mode_metadata_guard.py fails a recon dict built in a
    partial module without it.

    The run's hostnames (S) ride along as metadata.ip_mode_hosts, the graph
    writers' admit set (scope.classify_host): a finding on a name in S
    attaches to its Subdomain under its org Domain, any other name stays out.
    And metadata.ip_to_hostname, as the full run writes it (ip_to_hostname_map).
    """
    targets = ip_mode_target_list(settings) if settings is not None else _RUN_IP_TARGETS
    if targets is None:
        return recon_data
    metadata = recon_data.setdefault("metadata", {})
    metadata["ip_mode"] = True
    metadata["expanded_ips"] = list(targets)
    metadata["ip_to_hostname"] = ip_to_hostname_map(targets)
    if _RUN_IP_HOSTNAMES:
        metadata["ip_mode_hosts"] = dict(_RUN_IP_HOSTNAMES)
    return recon_data


_IP_TO_HOSTNAME: dict = {}


def ip_to_hostname_map(targets) -> dict:
    """metadata.ip_to_hostname for an IP-mode dict, as run_ip_recon writes it:
    each target address -> its placeholder label, and each name in S -> itself.

    httpx probes a target by its address, so http_probe.by_host is keyed by
    the IP literal while the graph holds the label; the HTTP writer
    translates through this map (http_mixin, L-18), and without it a partial
    run gave no label Subdomain its HTTP status. A canonical spelling of each
    address maps too, as the graph may store that one. A selected name is
    probed by its own name and maps to itself. Built once per list: every
    dict of a run shares it, and nothing writes to it.
    """
    from recon.helpers.ip_placeholders import placeholder_for
    from recon_settings.ip_hostnames import canonical_ip
    key = (tuple(targets), tuple(sorted(_RUN_IP_HOSTNAMES)))
    if key not in _IP_TO_HOSTNAME:
        mapping: dict = {}
        for ip in targets:
            label = placeholder_for(ip)
            mapping[ip] = label
            mapping.setdefault(canonical_ip(ip), label)
        for name in sorted(_RUN_IP_HOSTNAMES):
            mapping[name] = name
        _IP_TO_HOSTNAME.clear()
        _IP_TO_HOSTNAME[key] = mapping
    return _IP_TO_HOSTNAME[key]


def is_target_label(value, targets) -> bool:
    """``value`` is the IP-mode label of one of ``targets`` (expanded addresses)."""
    from recon.helpers.ip_placeholders import is_placeholder
    return is_placeholder(value) and any(is_placeholder(value, ip) for ip in targets or ())


def typed_ip_attach_to(user_targets):
    """The Subdomain the operator's typed IPs hang off, or None (B-20).

    Each module writes that link as a RESOLVES_TO with no source, which every
    later partial run reads as forward DNS. In IP mode only a target's own
    label may take one, so a PTR name never gains an address it does not
    resolve to. Outside IP mode the value is the one filter_partial_user_input
    left.
    """
    value = (user_targets or {}).get("ip_attach_to")
    if not value or _RUN_IP_TARGETS is None or is_target_label(value, _RUN_IP_TARGETS):
        return value
    print(f"[!][Partial Recon] Not attaching typed IPs to {str(value)[:120]!r}: "
          f"in IP mode only a target's own label takes them")
    return None


# The tools a partial run refuses in IP mode, and why: each looks up or
# enumerates names, and an IP-mode run's one root is the synthetic
# ip-targets.<project id>.
IP_MODE_REFUSED_TOOLS = {
    "SubdomainDiscovery": "subdomain enumeration of the synthetic root would send the project id out",
    "Urlscan": "urlscan.io searches by domain, and the synthetic root is the project id (D-11)",
    "OriginDiscovery": "it probes candidate origin addresses that are not targets (B-08)",
}
IP_MODE_REFUSAL = "refused: IP mode"

# The tools that work on hostnames only. In ip_only and record_only no
# hostname is a target, so they have nothing to scan; in record_filter and
# scan_all they scan S. Mirrored by IP_MODE_NAME_ONLY_TOOLS in
# webapp/src/lib/partialReconScope.ts, which disables them in the modal.
IP_MODE_NAME_ONLY_TOOLS = {
    "Gau": "it asks web archives about hostnames",
    "ParamSpider": "it asks web archives about hostnames",
    "SubdomainTakeover": "it checks hostnames for dangling DNS records",
}

_MODE_LABELS = {"ip_only": "IP only", "record_only": "Record hostnames",
                "record_filter": "Record + scan matching", "scan_all": "Record + scan all"}


def ip_hostname_mode_label(settings: dict) -> str:
    from recon.helpers.ip_hostnames import hostname_mode
    return _MODE_LABELS[hostname_mode(settings)]


def ip_mode_refusal(tool_id: str, settings: dict):
    """The run-report reason an IP-mode project refuses ``tool_id`` with, or None."""
    settings = settings or {}
    if not settings.get("IP_MODE"):
        return None
    if tool_id in IP_MODE_REFUSED_TOOLS:
        return f"{IP_MODE_REFUSAL} ({IP_MODE_REFUSED_TOOLS[tool_id]})"
    if tool_id in IP_MODE_NAME_ONLY_TOOLS:
        from recon.helpers.ip_hostnames import SELECTING, hostname_mode
        if hostname_mode(settings) not in SELECTING:
            return (f"{IP_MODE_REFUSAL} ({IP_MODE_NAME_ONLY_TOOLS[tool_id]}, and with Hostnames on "
                    f"target IPs set to {ip_hostname_mode_label(settings)} no hostname is a target)")
    return None


def typed_name_refusal(name, settings: dict):
    """Why an IP-mode run refuses a hostname the operator typed, or None.

    The pattern half of the selection rule (recon_settings/ip_hostnames.py):
    no name in ip_only or record_only; in record_filter the include and
    exclude entries decide (exclude wins, an unreadable list admits nothing);
    in scan_all any name. The hard guardrail applies to every typed name, as
    no guardrailed root sits above it. The RoE and the live DNS check (every
    address a target) come after, in filter_partial_user_input and
    ip_hostname_scope. Mirrored by batch_scope.ip_typed_name_refusal in the
    orchestrator and typedHostnameRefusal in the modal.
    """
    from recon.helpers.ip_hostnames import SELECTING, hostname_mode
    from recon_settings.hard_guardrail import is_hard_blocked
    from recon_settings.ip_hostnames import matches, normalize_name, parse_entries
    mode = hostname_mode(settings)
    if mode not in SELECTING:
        return (f"Hostnames on target IPs is {_MODE_LABELS[mode]}: "
                f"no typed hostname is scanned")
    canonical = normalize_name(name)
    if canonical is None:
        return "not a hostname"
    blocked, why = is_hard_blocked(canonical)
    if blocked:
        return f"hard guardrail: {why}"
    if mode == "record_filter":
        include, exclude = settings.get("IP_HOSTNAME_INCLUDE"), settings.get("IP_HOSTNAME_EXCLUDE")
        if not isinstance(include, list) or not isinstance(exclude, list):
            return "the hostname filter cannot be read"
        include_patterns, include_invalid = parse_entries(include)
        exclude_patterns, exclude_invalid = parse_entries(exclude)
        if include_invalid or exclude_invalid:
            return "the hostname filter cannot be read"
        verdict = matches(canonical, include_patterns, exclude_patterns)
        if verdict.excluded:
            return f"matches an exclude entry of the hostname filter: {verdict.matched_by}"
        if not verdict.included:
            return "matches no include entry of the hostname filter"
    return None


def root_orgs(roots) -> dict:
    """{scan root: org} for create_user_input_node, which attaches a UserInput
    to the org of the root its first host sits under."""
    return {r: attach_org(r) for r in roots or [] if r}


def attach_org(root):
    """The Domain a scan root's hosts attach to: its org (the graph names a
    Domain after the org). The root itself when no group names it (IP mode,
    a test); None stays None, so a host under no root attaches nowhere."""
    if not root:
        return root
    return _ROOT_ORGS.get(_norm_host(root), root)


def org_for_root(root: str, groups: list) -> str:
    """The registrable domain (org) of a scan root, as its group carries it."""
    group = _group_for(root, groups)
    org = (group or {}).get("orgDomain")
    return _norm_host(org) if org else _norm_host(root)


def partial_domain_groups(settings: dict, roots: list) -> list:
    """Scope entries for `roots`, built from the container's own validated settings.

    SCOPE_GROUPS went through the settings parser's re-validation (charset,
    Python suffix list), so the groups are always rebuilt from settings, never
    from anything in the config. Each entry carries the scope group's fields
    plus the legacy `rootDomain`/`prefixes`/`batch` keys the graph builders read.
    """
    if settings.get("IP_MODE"):
        return []
    wanted = {_norm_host(r) for r in roots}
    batch = bool(settings.get("DOMAIN_BATCH_MODE"))
    out = []
    for group in settings_scope_groups(settings):
        root = _norm_host(group.get("scanRoot"))
        if not root or root not in wanted or any(e["rootDomain"] == root for e in out):
            continue
        prefixes = ["*"] if group["mode"] == "enumerate" else []
        if group.get("includeRoot"):
            prefixes.append(".")
        prefixes += [f"{h[:-len(root) - 1]}." for h in group.get("exactHosts") or []]
        out.append({
            "rootDomain": root, "prefixes": prefixes, "batch": batch,
            "scanRoot": root, "orgDomain": group.get("orgDomain") or root,
            "mode": group["mode"], "includeRoot": bool(group.get("includeRoot")),
            "exactHosts": list(group.get("exactHosts") or []),
        })
    return out


def settings_project_roots(settings: dict, project_id: str) -> list:
    """Every root the project scans according to the container's settings."""
    if settings.get("IP_MODE"):
        return [f"ip-targets.{project_id}"]
    roots = []
    for group in settings_scope_groups(settings):
        root = _norm_host(group.get("scanRoot"))
        if root and root not in roots:
            roots.append(root)
    return roots


def partial_settings(config: dict) -> dict:
    """The settings partial_recon.main loaded once and checked the roots against.

    A module that re-fetched would scan with settings the refusal never saw. The
    copy is shallow: modules only reassign top-level keys (force-enabling their
    own tool). Called outside main (a unit test), it falls back to a fetch.
    """
    loaded = config.get("_settings")
    if loaded is None:
        from recon.project_settings import get_settings
        return get_settings()
    return dict(loaded)


def _coverage_signature():
    """A cheap snapshot of what the run has noted degraded so far, or None when
    circuit breakers are off / unavailable. Used to tell whether ``fn(root)``
    cut any coverage (a provider skipped, a host unreachable)."""
    try:
        from recon.helpers import circuit_breaker as cb
        report = cb.coverage_report()
        return (frozenset(report.degraded_sources), len(report.skipped_hosts),
                report.nuclei_truncated, len(report.gaps))
    except Exception:  # noqa: BLE001 - accumulator faulted or breakers off
        return None


def _run_one_root(fn, root: str) -> str:
    before = _coverage_signature()
    try:
        result = fn(root)
    except (Exception, SystemExit) as e:  # noqa: BLE001 - one root must not end the run
        # The class name only: API client exceptions carry request details
        # (URLs with keys, headers) in their text.
        print(f"[!][Partial Recon] {root}: failed ({type(e).__name__})")
        return f"failed: {type(e).__name__}"
    if result in (STATUS_NO_RESULTS, STATUS_RATE_LIMITED, STATUS_DEGRADED):
        return result
    # A root that otherwise looks OK is DEGRADED when it recorded new coverage
    # gaps (e.g. every OSINT provider was refused): those _one_root functions
    # return STATUS_OK regardless, so the accumulator is the truth.
    after = _coverage_signature()
    if before is not None and after is not None and after != before:
        print(f"[!][Partial Recon] {root}: completed with degraded coverage")
        return STATUS_DEGRADED
    return STATUS_OK


def _recheck_resolver() -> None:
    """Give the shared DNS resolver latch a fresh canary probe for this root:
    one bad moment on an earlier root must not leave this one unresolved."""
    try:
        from recon.main_recon_modules.domain_recon import resolver_breaker
        resolver_breaker.recheck()
    except Exception:  # noqa: BLE001 - the latch is an optimisation, never a failure
        pass


def run_per_root(roots: list, fn, tool: str) -> dict:
    """Run `fn(root)` once per root and return {root: status}.

    `fn` returns STATUS_NO_RESULTS or STATUS_RATE_LIMITED to say so; anything
    else is STATUS_OK. A raise or a sys.exit() inside `fn` fails that root only,
    so the remaining roots still run and partial_recon.main's `finally` (the
    node-filter sweep) is never skipped. A rate-limited root waits and is
    retried once.
    """
    from recon.helpers import shutdown
    statuses = {}
    for index, root in enumerate(roots):
        if shutdown.stop_requested():
            # A stop's handler raises nothing, so this loop is what keeps it
            # from starting the next root's traffic.
            print(f"[!][Partial Recon] {tool}: stop requested, "
                  f"{len(roots) - index} root(s) not started")
            for skipped in roots[index:]:
                statuses[skipped] = "stopped"
            break
        if index:
            time.sleep(ROOT_PAUSE_S)
        print(f"\n[*][Partial Recon] {tool}: root {index + 1}/{len(roots)}: {root}")
        _recheck_resolver()
        status = _run_one_root(fn, root)
        if status == STATUS_RATE_LIMITED:
            print(f"[!][Partial Recon] {tool}: {root} was rate limited, "
                  f"retrying once in {RATE_LIMIT_RETRY_DELAY_S}s")
            time.sleep(RATE_LIMIT_RETRY_DELAY_S)
            status = _run_one_root(fn, root)
        statuses[root] = status
    return statuses


def run_exit_code(statuses: dict) -> int:
    """0 when at least one root ran (ok, no_results or degraded), 1 when nothing did."""
    ran = (STATUS_OK, STATUS_NO_RESULTS, STATUS_DEGRADED)
    return 0 if any(s in ran for s in statuses.values()) else 1


def print_run_report(tool: str, statuses: dict, refused: dict) -> None:
    """The one block every run ends with: what was scanned, and why the rest was not."""
    scanned = [r for r, s in statuses.items() if s == STATUS_OK]
    others = [(r, s) for r, s in statuses.items() if s != STATUS_OK]
    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Run report: {tool}")
    print(f"[*][Partial Recon] Roots scanned ({len(scanned)}): {', '.join(scanned) or 'none'}")
    for root, reason in others + list(refused.items()):
        print(f"[*][Partial Recon]   {root}: {reason}")
    print(f"{'=' * 50}\n")


def _classify_ip(address: str, version: str = None) -> str:
    """Return 'ipv4' or 'ipv6' for an IP address."""
    if version:
        v = version.lower()
        if "4" in v:
            return "ipv4"
        if "6" in v:
            return "ipv6"
    import ipaddress as _ipaddress
    try:
        return "ipv4" if _ipaddress.ip_address(address).version == 4 else "ipv6"
    except ValueError:
        return "ipv4"


def _resolve_hostname(hostname: str) -> dict:
    """
    Resolve a hostname to IPs via socket.getaddrinfo.

    Returns {"ipv4": [...], "ipv6": [...]}.

    IP mode: a name the run may scan (S) answers with the addresses it was
    selected on. A second lookup could return an address nobody checked
    against the target list.
    """
    if is_run_ip_hostname(hostname):
        answer = run_ip_hostname_answer(hostname)
        return {"ipv4": [a for a in answer if ":" not in a], "ipv6": [a for a in answer if ":" in a]}
    import socket
    ips = {"ipv4": [], "ipv6": []}
    try:
        results = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in results:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in ips["ipv4"]:
                ips["ipv4"].append(addr)
            elif family == socket.AF_INET6 and addr not in ips["ipv6"]:
                ips["ipv6"].append(addr)
    except socket.gaierror:
        pass
    return ips


def _is_ip_or_cidr(value: str) -> bool:
    """Check if value is an IP address or CIDR range."""
    import ipaddress as _ipaddress
    try:
        if "/" in value:
            _ipaddress.ip_network(value, strict=False)
        else:
            _ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_HOSTNAME_RE = None

def _is_valid_hostname(value: str) -> bool:
    """Check if value looks like a valid hostname/subdomain."""
    global _HOSTNAME_RE
    if _HOSTNAME_RE is None:
        import re
        _HOSTNAME_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(_HOSTNAME_RE.match(value))


def _is_valid_url(value: str) -> bool:
    """Check if value looks like a valid HTTP/HTTPS URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def admits_partial_host(groups: list, host: str) -> bool:
    """§4.6, partial-recon typed hosts: strictly under an ENUMERATE scan root,
    or one of an EXACT group's hosts; a scan root itself only when it is a
    target. Mirrors recon_orchestrator/batch_scope.py:admits_partial_host."""
    h = _norm_host(host)
    if not h:
        return False
    for g in groups or []:
        root = _norm_host(g.get("scanRoot") or g.get("rootDomain"))
        if h == root:
            if include_root_for(root, groups):
                return True
            continue
        allowed = allowed_hosts_for(root, groups)
        if allowed is None:
            if h.endswith("." + root):
                return True
        elif h in allowed:
            return True
    return False


# The CIDR widths the modal accepts (PartialReconModal), enforced server-side too.
_IP_PREFIX_LIMITS = {4: (24, 32), 6: (120, 128)}


def _valid_user_ip(value: str) -> bool:
    import ipaddress as _ipaddress
    try:
        if "/" in value:
            net = _ipaddress.ip_network(value, strict=False)
            low, high = _IP_PREFIX_LIMITS[net.version]
            return low <= net.prefixlen <= high
        _ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _url_host(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(str(url).strip()).hostname or "").lower()
    except ValueError:
        return ""


def filter_partial_user_input(config: dict, settings: dict) -> list:
    """Drop what the operator typed that this run may not touch; returns the refusals.

    The orchestrator already filtered the same payload (PAR-10); this is the
    container's own check against its own settings, so a job that reached the
    container another way is held to the same rule. Hosts and URL hosts pass the
    §4.6 partial rule for the run's groups (in IP mode, a URL host must be one
    of the project's addresses); IPs and CIDRs get the modal's width limits.

    Then the RoE exclusion list, as the graph builders apply it to what they
    read: an excluded host, URL host, address or attach target is dropped, and
    a typed CIDR holding an excluded address becomes its other hosts (the ones
    the modules would expand it to). Under RoE IP or CIDR entries a typed name
    (host, URL host, the name typed IPs attach to) passes only when the
    admission gate admits every address it resolves to (D2): the tools are
    handed the name and resolve it themselves, so one excluded address refuses
    it, and so does no address at all (nothing shows it stays off the ranges).
    Mirrors the orchestrator's copy; both run
    recon/tests/fixtures/partial_typed_input_roe_vectors.json.

    The hard guardrail is not repeated here: every pattern is a suffix match,
    so a host the scope rule admits is blocked only if its scan root is, and
    the roots were guardrailed by the orchestrator before this container ran.

    IP mode (B-20, B-22): a typed address, URL host or CIDR host must be one of
    the project's targets, by address (CIDR-aware, any IPv6 spelling); a typed
    CIDR keeps only its target hosts. IPs attach only to a target's own label.
    A typed name (host or URL host) passes the pattern half of the hostname
    rule (typed_name_refusal: none in ip_only / record_only, the filter in
    record_filter, any name in scan_all, the hard guardrail on each) and the
    RoE; its live DNS check comes next, in ip_hostname_scope, which drops it
    unless every address it resolves to is a target.
    """
    import ipaddress as _ipaddress
    from recon.helpers.roe_scope import _is_roe_excluded

    refused: list = []
    groups = config.get("domain_groups") or []
    ip_mode = bool(settings.get("IP_MODE"))
    ip_targets = None
    if ip_mode:
        # The listed entries: the RoE half below refuses an excluded target
        # as excluded, which is how the run report must name it.
        from recon.helpers.target_admission import is_target, target_set
        ip_targets = target_set(str(i).strip() for i in settings.get("TARGET_IPS") or [] if str(i or "").strip())
    excluded = [e for e in (settings.get("ROE_EXCLUDED_HOSTS") or []) if isinstance(e, str) and e.strip()] \
        if settings.get("ROE_ENABLED") else []
    roe_cut = 0
    roe_unresolved = 0
    # IP mode resolves no typed name here: ip_hostname_scope checks each one
    # live against the targets, which the RoE already took its addresses from.
    from recon.helpers.target_admission import admission_context, admit_targets
    check_addresses = bool(excluded) and not ip_mode and admission_context(settings).ip_rules
    answers: dict = {}

    def host_refusal(host: str):
        """None when the scope admits ``host``, else what the refusal line
        adds after the value ("" for the plain scope refusal)."""
        if ip_mode:
            h = _norm_host(host)
            if _is_ip_or_cidr(h.strip("[]")) or "/" in h:
                return None if is_target(h, ip_targets) else ""
            why = typed_name_refusal(h, settings)
            return None if why is None else f" ({why})"
        return None if admits_partial_host(groups, host) else ""

    def typed_host(host: str) -> str:
        """The spelling a kept host is passed on in: an IP-mode name in the
        rule's canonical form (no port, no trailing dot), as S holds it."""
        h = _norm_host(host)
        if ip_mode and not _is_ip_or_cidr(h.strip("[]")):
            from recon_settings.ip_hostnames import normalize_name
            return normalize_name(h) or h
        return h

    def keep_targets(ip: str, hosts: list) -> list:
        """IP mode: the target addresses among what ``ip`` stands for (itself,
        or a typed CIDR's hosts), the rest refused."""
        if not ip_mode:
            return hosts
        inside = [h for h in hosts if is_target(h, ip_targets)]
        if len(inside) < len(hosts):
            outside = [h for h in hosts if h not in inside]
            shown = ", ".join(outside[:5]) + (", ..." if len(outside) > 5 else "")
            refused.append(f"ip {shown}" + (f" in {ip!r}" if "/" in ip else "")
                           + " (not one of the project's target IPs)")
        return inside

    def roe_out(host_or_ip: str) -> bool:
        return bool(excluded) and _is_roe_excluded(host_or_ip, excluded)

    def refuse_roe(what: str) -> None:
        nonlocal roe_cut
        roe_cut += 1
        refused.append(f"{what} (excluded by the Rules of Engagement)")

    def address_refused(what: str, host: str) -> bool:
        """Refuse a typed name the gate does not admit on every address it
        resolves to; True when refused. Each name is resolved once, as the
        modules resolve it (_resolve_hostname)."""
        nonlocal roe_cut, roe_unresolved
        name = _norm_host(host)
        if not check_addresses or not name or _is_ip_or_cidr(name):
            return False
        if name not in answers:
            try:
                found = _resolve_hostname(name)
                answers[name] = found["ipv4"] + found["ipv6"]
            except (OSError, UnicodeError):
                answers[name] = []
        admission = admit_targets(settings, None, names={name: answers[name]},
                                  module="partial_recon", resolves_names=True, record=False)
        if name in admission.names:
            return False
        if not answers[name]:
            roe_unresolved += 1
            refused.append(f"{what} (no address, while the Rules of Engagement exclude IP ranges)")
            return True
        cut = [r.target for r in admission.refusals if r.name == name]
        roe_cut += 1
        refused.append(f"{what} (resolves to {', '.join(cut[:5])}{', ...' if len(cut) > 5 else ''},"
                       f" excluded by the Rules of Engagement)")
        return True

    def keep_hosts(values, label):
        kept = []
        for v in values if isinstance(values, list) else []:
            why = host_refusal(v) if isinstance(v, str) else ""
            if why is not None:
                refused.append(f"{label} {str(v)[:120]!r}{why}")
            elif roe_out(v):
                refuse_roe(f"{label} {str(v)[:120]!r}")
            elif not address_refused(f"{label} {str(v)[:120]!r}", v):
                kept.append(typed_host(v))
        return kept

    if "user_inputs" in config:
        config["user_inputs"] = keep_hosts(config.get("user_inputs"), "subdomain")
    user_targets = config.get("user_targets")
    if isinstance(user_targets, dict):
        user_targets = dict(user_targets)
        if "subdomains" in user_targets:
            user_targets["subdomains"] = keep_hosts(user_targets["subdomains"], "subdomain")
        if "urls" in user_targets:
            kept = []
            for u in user_targets["urls"] if isinstance(user_targets["urls"], list) else []:
                why = host_refusal(_url_host(u)) if isinstance(u, str) else ""
                if why is not None:
                    refused.append(f"url {str(u)[:120]!r}{why}")
                elif roe_out(_url_host(u)):
                    refuse_roe(f"url {str(u)[:120]!r}")
                elif not address_refused(f"url {str(u)[:120]!r}", _url_host(u)):
                    kept.append(u.strip())
            user_targets["urls"] = kept
        if "ips" in user_targets:
            kept = []
            for ip in user_targets["ips"] if isinstance(user_targets["ips"], list) else []:
                if not (isinstance(ip, str) and _valid_user_ip(ip.strip())):
                    refused.append(f"ip {str(ip)[:60]!r}")
                    continue
                ip = ip.strip()
                if "/" not in ip:
                    if roe_out(ip):
                        refuse_roe(f"ip {ip!r}")
                    else:
                        kept.extend(keep_targets(ip, [ip]))
                    continue
                network = _ipaddress.ip_network(ip, strict=False)
                hosts = [str(h) for h in network.hosts()] if excluded or ip_mode else []
                cut = {h for h in hosts if roe_out(h)}
                if cut and len(cut) == len(hosts):
                    refuse_roe(f"ip {ip!r}")
                    continue
                if cut:
                    shown = ", ".join(sorted(cut)[:5]) + (", ..." if len(cut) > 5 else "")
                    refuse_roe(f"ip {shown} in {ip!r}")
                left = [h for h in hosts if h not in cut]
                inside = keep_targets(ip, left)
                if not cut and len(inside) == len(left):
                    kept.append(ip)
                else:
                    kept.extend(inside)
            user_targets["ips"] = kept
        # ip_attach_to names a Subdomain, url_attach_to a BaseURL. In IP mode
        # url_attach_to is a graph node the modules look up, and ip_attach_to
        # may only be a target's own label: every module writes it as a
        # source-less RESOLVES_TO that later runs read as forward DNS (B-20).
        # An excluded one is dropped in either mode. An ip_attach_to name is
        # also checked on its addresses, as modules hand it to tools that
        # resolve it (httpx's by_host); url_attach_to is only a graph link.
        for key, host_of in (("ip_attach_to", str), ("url_attach_to", _url_host)):
            value = user_targets.get(key)
            if value and ip_mode and key == "ip_attach_to" and not is_target_label(
                    value, ip_mode_target_list(settings)):
                refused.append(f"{key} {str(value)[:120]!r} (not a target's own label)")
                user_targets[key] = None
            elif value and not ip_mode and not (isinstance(value, str) and host_refusal(host_of(value)) is None):
                refused.append(f"{key} {str(value)[:120]!r}")
                user_targets[key] = None
            elif value and isinstance(value, str) and roe_out(host_of(value)):
                refuse_roe(f"{key} {value[:120]!r}")
                user_targets[key] = None
            elif value and key == "ip_attach_to" and isinstance(value, str) and address_refused(
                    f"{key} {value[:120]!r}", value):
                user_targets[key] = None
        config["user_targets"] = user_targets
    elif user_targets is not None:
        config["user_targets"] = {}
    if roe_cut or roe_unresolved:
        # A partial run never prunes, so this only reaches the run's coverage
        # record; _prepare_scope prints each refusal once.
        from recon.helpers import circuit_breaker
        entries = []
        if roe_cut:
            entries.append({"source": "roe_excluded",
                            "reason": "typed partial-recon input excluded by the Rules of Engagement",
                            "skipped": roe_cut})
        if roe_unresolved:
            entries.append({"source": "roe_excluded",
                            "reason": "typed partial-recon name with no address while RoE IP/CIDR "
                                      "exclusions are set",
                            "skipped": roe_unresolved})
        circuit_breaker.note_degraded("partial_recon", entries=entries)
    return refused


def _should_include_root_domain(settings: dict) -> bool:
    """
    Derive the "Include Root Domain" flag from project settings.

    Mirrors recon/main.py:parse_target() exactly: the apex is in scope if
    SUBDOMAIN_LIST contains "." (or any prefix that strips to empty). Used
    by partial-recon graph builders to honor the same scope rules as the
    full pipeline.
    """
    subdomain_list = settings.get("SUBDOMAIN_LIST") or []
    return any(p == "." or p.rstrip(".") == "" for p in subdomain_list)


def _scope_partial_urls(
    graph_urls: list,
    user_urls: list,
    graph_subdomains: list,
    settings: dict,
    domain,
    domain_groups: list = None,
) -> tuple:
    """Scope a partial run's URL inputs; returns ``(urls, scope_hosts)``.

    Graph URLs outside the project scope are dropped rather than fetched: an
    Endpoint written before JS recon enforced scope can carry a third-party
    baseurl. Typed URLs were already filtered when the run started; they are
    kept, but an unscoped host never joins ``scope_hosts``.
    ``scope_hosts`` belongs in ``recon_data["subdomains"]``, the set the graph
    mixins store nodes under (graph_db/mixins/recon/scope.py); left empty there,
    the scope collapses to the apex and every subdomain's results are dropped.

    ``domain`` is the run's roots (or one root). With ``domain_groups`` each
    root's apex follows its group and a literal batch group keeps only its
    listed hosts; without, the project-wide Include Root Domain flag applies.
    """
    from urllib.parse import urlparse

    roots = [domain] if isinstance(domain, str) else list(domain or [])
    roots = [r for r in roots if r]
    if domain_groups is None:
        included = set(roots) if _should_include_root_domain(settings) else set()
        allowed = {}
    else:
        included = {r for r in roots if include_root_for(r, domain_groups)}
        allowed = {}
        for root in roots:
            hosts = allowed_hosts_for(root, domain_groups)
            if hosts is not None:
                allowed[root] = hosts

    def _in_scope(host: str) -> bool:
        if not _is_host_in_scope(host, settings, roots, included):
            return False
        hosts = allowed.get(root_for_host(host, roots))
        return hosts is None or _norm_host(host) in hosts

    def _host(url: str) -> str:
        try:
            return (urlparse(url).hostname or "").lower()
        except ValueError:
            return ""

    urls, hosts, dropped = [], set(), 0
    for url in graph_urls:
        host = _host(url)
        if not _in_scope(host):
            dropped += 1
            continue
        hosts.add(host)
        if url not in urls:
            urls.append(url)
    for url in user_urls:
        # Typed URLs were filtered at the run's start (filter_partial_user_input).
        # Their host still joins the writer's scope only when the scope admits
        # it, so a caller that skipped the filter cannot widen what is written.
        host = _host(url)
        if host and _in_scope(host):
            hosts.add(host)
        if url not in urls:
            urls.append(url)
    for sub in graph_subdomains:
        if isinstance(sub, str) and _in_scope(sub):
            hosts.add(sub.strip(".").lower())

    if dropped:
        print(f"[*][Partial Recon] Dropped {dropped} out-of-scope graph URL(s)")
    return urls, sorted(hosts)


def _is_host_in_scope(
    host: str,
    settings: dict,
    requested_domain="",
    include_root_domain=False,
) -> bool:
    """
    Decide whether a hostname is in scope for the current scan.

    Single source of truth for partial-recon scope checks. Two regimes:

    1. **IP mode** (settings["IP_MODE"] is True): the project targets raw
       IPs, not a domain. The synthetic ``ip-targets.<project_id>`` pseudo-
       domain used elsewhere in the pipeline is NOT a real scope rule, so
       we ignore it here. A host is in scope when it is one of T, the
       expanded target list after the RoE (ip_mode_target_list: a CIDR is
       its hosts(), any IPv6 spelling matches), or a name the run may scan
       (S, set by ip_hostname_scope). ``localhost`` stands for a listed
       loopback target. An empty list admits nothing: a graph row is no
       proof of scope, whatever its address looks like (fail closed).

    2. **Domain mode** (default): ``requested_domain`` is one root or a list
       of roots. Accept the host if it is a subdomain of any of them, or if it
       equals a root whose apex is included. ``include_root_domain`` is either
       a bool for every root or the set of roots whose apex is included.

    Empty/None hosts are out of scope.
    """
    import ipaddress

    host = (host or "").strip().strip(".").lower()
    if not host:
        return False

    # Strip "[ipv6]:port" → "ipv6", or "host:port" → "host". Must not mangle
    # bare IPv6 addresses (where every colon is part of the address, e.g. "::1"
    # or "2001:db8::1"). Strategy:
    #   1. Bracketed form has unambiguous port boundary at "]"
    #   2. Otherwise, try to parse as an IP first — IPv6 wins
    #   3. Only then fall back to the host:port split for plain hostnames
    if host.startswith("["):
        end = host.find("]")
        if end > 0:
            host = host[1:end]
    else:
        try:
            ipaddress.ip_address(host)
            # Already a valid IP (v4 or v6) — leave intact
        except ValueError:
            if ":" in host:
                host = host.split(":", 1)[0]

    if settings.get("IP_MODE"):
        from recon.helpers.roe_scope import _is_roe_excluded
        from recon.helpers.target_admission import is_target, target_set
        # The listed entries as the rule's TargetSet (a CIDR means its hosts(),
        # a wide IPv6 range stays a range rather than being expanded), less the
        # RoE's exclusions: the same membership as the expanded list.
        targets = target_set(str(e).strip() for e in settings.get("TARGET_IPS") or [] if str(e or "").strip())
        excluded = [e for e in settings.get("ROE_EXCLUDED_HOSTS") or [] if isinstance(e, str) and e.strip()] \
            if settings.get("ROE_ENABLED") else []

        def target(address: str) -> bool:
            return is_target(address, targets) and not (excluded and _is_roe_excluded(address, excluded))

        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host == "localhost":
                return target("127.0.0.1") or target("::1")
            return is_run_ip_hostname(host)
        return target(host)

    # Domain mode (default)
    raw_roots = [requested_domain] if isinstance(requested_domain, str) else list(requested_domain or [])
    roots = [_norm_host(r) for r in raw_roots if _norm_host(r)]
    if not roots:
        # No domain configured (degenerate case) — accept anything.
        return True
    if isinstance(include_root_domain, bool):
        included = set(roots) if include_root_domain else set()
    else:
        included = {_norm_host(r) for r in include_root_domain or ()}
    if host in roots:
        return host in included
    return any(host.endswith(f".{root}") for root in roots)

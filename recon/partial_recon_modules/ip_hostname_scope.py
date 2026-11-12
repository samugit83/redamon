"""IP mode: the hostnames one partial run may scan (S), decided once at its start.

A full IP-mode run selects the names it scans with the hostname policy and
writes them as Subdomain {source: 'ip_hostname_selection', ip_hostname_reason:
'scanned'} under their org Domain; every other name it saw is an
ExternalDomain with SEEN_ON evidence (design §6). A partial run never trusts
those reasons on their own (§6.3): the policy may have narrowed since, or a
name may have moved off the targets. So partial_recon._prepare_scope calls
run_hostname_scope once; it reads the candidates from the graph, runs the one
selection rule over them with the project's CURRENT policy and live DNS (the
full run's wiring, recon.helpers.ip_hostnames._evaluate: guardrail, RoE,
filter, attribution, every address a target, the cap), and every builder, URL
predicate and typed-input check of the run then keeps a name only in S
(helpers.set_run_ip_hostnames):

  - ip_only, record_only: S is empty, nothing is read or resolved;
  - record_filter, scan_all: the scanned Subdomains and the recorded names
    the rule selects now, plus the names the operator typed that it selects.
    A name the narrowing marker set out_of_policy is never one (D-19).

Up to twelve partial runs of a project run at once, so two started seconds
apart can hold different S when DNS changes between them; each is right for
its own check.

A typed name the rule selects is written like a selected name, through the
hostname writer (update_graph_from_ip_hostnames): under its org Domain (made by
the one allowed Domain-MERGE site, ensure_root_domains), never under the
synthetic root.
"""
from collections import Counter

from recon.partial_recon_modules.graph_builders import FORWARD_DNS
from recon.partial_recon_modules.helpers import (
    _is_ip_or_cidr,
    _url_host,
    ip_hostname_mode_label,
    ip_mode_recon,
    run_ip_hostname_answer,
    run_ip_hostnames,
    run_ip_targets,
    scope_roots,
    set_run_ip_hostnames,
)

#: The source a typed name's Subdomain carries in its ip_hostname_sources.
TYPED_SOURCE = "partial_recon_user_input"

# Every name a selection wrote, whatever its reason now: only 'scanned' makes a
# candidate, any other reason (out_of_policy) keeps the name out of S.
_SELECTION_ROWS = """
MATCH (s:Subdomain {user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'})
OPTIONAL MATCH (s)-[r:RESOLVES_TO]->(i:IP {user_id: $uid, project_id: $pid})
WHERE """ + FORWARD_DNS + """
RETURN s.name AS name, s.ip_hostname_reason AS reason, collect(DISTINCT i.address) AS ips
"""

_RECORDED_ROWS = """
MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid})-[:SEEN_ON]->(i:IP {user_id: $uid, project_id: $pid})
RETURN ed.domain AS name, ed.ip_hostname_reason AS reason, collect(DISTINCT i.address) AS ips
"""

_OWNERSHIP_ROWS = """
MATCH (i:IP {user_id: $uid, project_id: $pid})
WHERE i.ownership IS NOT NULL
RETURN i.address AS ip, i.ownership AS ownership, i.ownership_reasons AS reasons
"""

_EMPTY_GRAPH = {"scanned": {}, "recorded": {}, "excluded": set(), "attribution": None}


def _addresses(values) -> list:
    from recon_settings.ip_hostnames import canonical_ip
    return list(dict.fromkeys(canonical_ip(a) for a in values or () if a))


def read_candidates(user_id: str, project_id: str):
    """The graph's hostname candidates, or None when the graph cannot be read.

    {"scanned": {name: [addresses]}, "recorded": {name: {"ips", "reason"}},
     "excluded": {names a selection wrote with any reason but scanned},
     "attribution": {target IP: (ownership, reasons)} or None when no IP
     carries one (IP attribution never ran)}. Names in the rule's canonical
    spelling; a recorded name that is also excluded is dropped.
    """
    from recon_settings.ip_hostnames import canonical_ip, normalize_name
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as client:
            if not client.verify_connection():
                print("[!][IpNames] Neo4j not reachable: no hostname found by an earlier run is read")
                return None
            with client.driver.session() as session:
                params = {"uid": user_id, "pid": project_id}
                scanned, excluded = {}, set()
                for row in session.run(_SELECTION_ROWS, **params):
                    name = normalize_name(row["name"])
                    if name is None:
                        continue
                    if row["reason"] == "scanned":
                        scanned[name] = _addresses(row["ips"])
                    else:
                        excluded.add(name)
                recorded = {}
                for row in session.run(_RECORDED_ROWS, **params):
                    name = normalize_name(row["name"])
                    if name is not None and name not in excluded:
                        recorded[name] = {"ips": _addresses(row["ips"]), "reason": row["reason"]}
                attribution = {canonical_ip(row["ip"]): (row["ownership"], list(row["reasons"] or []))
                               for row in session.run(_OWNERSHIP_ROWS, **params) if row["ip"]}
    except Exception as e:  # noqa: BLE001 - an unread graph selects nothing
        print(f"[!][IpNames] Could not read the hostnames on the target IPs ({type(e).__name__})")
        return None
    for name in scanned:
        recorded.pop(name, None)
    return {"scanned": scanned, "recorded": recorded, "excluded": excluded,
            "attribution": attribution or None}


def _typed_names(config: dict) -> set:
    """The hostnames the operator typed (hosts and URL hosts), canonical; the
    addresses are judged elsewhere (filter_partial_user_input)."""
    from recon_settings.ip_hostnames import normalize_name
    targets = config.get("user_targets") or {}
    values = [*(config.get("user_inputs") or []), *(targets.get("subdomains") or [])]
    values += [_url_host(u) for u in targets.get("urls") or [] if isinstance(u, str)]
    names = set()
    for value in values:
        if isinstance(value, str) and not _is_ip_or_cidr(value.strip().strip("[]")):
            name = normalize_name(value)
            if name:
                names.add(name)
    return names


def _drop_typed(config: dict, names: set) -> None:
    """Take the typed names the rule refused out of the run's inputs."""
    from recon_settings.ip_hostnames import normalize_name
    if not names:
        return
    if isinstance(config.get("user_inputs"), list):
        config["user_inputs"] = [v for v in config["user_inputs"] if normalize_name(v) not in names]
    targets = config.get("user_targets")
    if isinstance(targets, dict):
        targets = dict(targets)
        if isinstance(targets.get("subdomains"), list):
            targets["subdomains"] = [v for v in targets["subdomains"] if normalize_name(v) not in names]
        if isinstance(targets.get("urls"), list):
            targets["urls"] = [u for u in targets["urls"]
                               if not isinstance(u, str) or normalize_name(_url_host(u)) not in names]
        config["user_targets"] = targets


def run_hostname_scope(config: dict, settings: dict, user_id: str, project_id: str, *,
                       resolve=None) -> dict:
    """Compute S for this run and keep the typed names in it; returns the run
    report's lines, {"hostname <name>": why it is not scanned}, for a typed name
    the rule refused and for a name an earlier run scanned that it refuses now.

    ``resolve(name) -> [addresses]`` defaults to the full run's A/AAAA lookup;
    each name is resolved at most once, and its answer is the pinned one.
    """
    from recon.helpers import ip_hostnames as hn
    from recon.helpers.public_suffix import org_domain
    from recon_settings.ip_hostnames import SCANNED, canonical_ip

    set_run_ip_hostnames({})
    mode = hn.hostname_mode(settings)
    label = ip_hostname_mode_label(settings)
    # What the run decided, for a module or a test to read back.
    config["ip_hostname_scope"] = {"mode": mode, "names": {}, "refused": {}}
    if mode not in hn.SELECTING:
        print(f"[*][IpNames] Hostnames on target IPs: {label}: no hostname is a target, only the target IPs")
        return {}

    graph = read_candidates(user_id, project_id) or _EMPTY_GRAPH
    typed = _typed_names(config)
    # D-19: a name the narrowing marker set out_of_policy stays out, even
    # when it is also recorded and the policy admits it again.
    candidates = {name: {"ips_seen": info["ips"], "org_domain": org_domain(name)}
                  for name, info in graph["recorded"].items() if name not in graph["excluded"]}
    for name, ips in graph["scanned"].items():
        candidates[name] = {"ips_seen": ips, "org_domain": org_domain(name)}
    if not candidates and not typed:
        print(f"[*][IpNames] Hostnames on target IPs: {label}: no hostname recorded or typed yet")
        return {}

    base = resolve or hn.dns_resolver(settings)
    answers: dict = {}

    def pinned(name: str) -> list:
        # A raise is not cached: the rule refuses the name (resolver_unavailable).
        if name not in answers:
            answers[name] = list(base(name) or [])
        return answers[name]

    dns_on = settings.get("DNS_ENABLED", True) is True
    for name in typed:
        seen = []
        if mode == "scan_all" and dns_on:
            # A typed name was seen on no target IP: the targets it resolves to
            # are where it would be scanned, so the attribution check reads them.
            try:
                seen = [canonical_ip(a) for a in pinned(name)]
            except Exception:  # noqa: BLE001 - no answer, no attribution: refused below
                seen = []
        candidates[name] = {"ips_seen": seen, "org_domain": org_domain(name)}

    targets = run_ip_targets() or []
    edge = failed = None
    if mode == "scan_all" and graph["attribution"]:
        by_ip = {ip: {"ownership": owner, "ownership_reasons": reasons}
                 for ip, (owner, reasons) in graph["attribution"].items()}
        edge, failed = hn._attribution_sets({"ip_attribution": {"by_ip": by_ip},
                                             "metadata": {"expanded_ips": targets}})
    evaluation, _ = hn._evaluate(candidates, {"metadata": {"expanded_ips": targets}}, settings, mode,
                                 edge, failed, pinned)
    selected = {name: candidates[name]["org_domain"] for name in evaluation.selected}
    set_run_ip_hostnames(selected, evaluation.resolved)

    refused = {}
    dropped = typed - set(selected)
    _drop_typed(config, dropped)
    for name in sorted(dropped):
        refused[f"hostname {name}"] = f"typed, not scanned ({evaluation.reasons.get(name)})"
    for name in sorted(set(graph["scanned"]) - set(selected) - typed):
        refused[f"hostname {name}"] = f"scanned before, not now ({evaluation.reasons.get(name)})"
    config["ip_hostname_scope"] = {"mode": mode, "names": dict(selected), "refused": dict(refused)}

    others = Counter(reason for reason in evaluation.reasons.values() if reason != SCANNED)
    print(f"[*][IpNames] Hostnames on target IPs: {label}: {len(selected)} hostname(s) in scope "
          f"({len(set(selected) & set(graph['scanned']))} scanned before, "
          f"{len(set(selected) & set(graph['recorded']))} recorded, {len(set(selected) & typed)} typed)"
          + (f"; not in scope: {sum(others.values())} ("
             + ", ".join(f"{reason} {count}" for reason, count in sorted(others.items())) + ")"
             if others else ""))

    new_typed = (set(selected) & typed) - set(graph["scanned"])
    if new_typed:
        roots = scope_roots(config)
        _record_typed(new_typed, selected, evaluation.resolved, user_id, project_id,
                      roots[0] if roots else f"ip-targets.{project_id}")
    return refused


def _record_typed(names, orgs: dict, resolved: dict, user_id: str, project_id: str, mock_root: str) -> None:
    """Write the typed names the rule selected as scanned names, before the
    tool runs, so its builders read them under their org Domain and every
    later reader (the agent, the next partial run) sees them as the policy's.
    The run's hostname mode is not stamped: no recording ran."""
    from recon_settings.ip_hostnames import SCANNED
    names = sorted(names or ())
    if not names or not user_id or not project_id:
        return
    candidates = {name: {"reason": SCANNED, "org_domain": orgs[name], "sources": [TYPED_SOURCE],
                         "resolves_to_now": list(resolved.get(name) or []),
                         "ips_seen": list(resolved.get(name) or [])} for name in names}
    recon_data = ip_mode_recon({"domain": mock_root, "metadata": {"root_domain": mock_root},
                                "ip_hostnames": {"candidates": candidates}})
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as client:
            if not client.verify_connection():
                print("[!][IpNames] Neo4j not reachable: the typed hostnames are scanned but not written")
                return
            stats = client.update_graph_from_ip_hostnames(recon_data, user_id, project_id) or {}
        if stats.get("errors"):
            print(f"[!][IpNames] Typed hostnames: {len(stats['errors'])} write(s) failed")
    except Exception as e:  # noqa: BLE001 - the scan still runs; the tool writes its own nodes
        print(f"[!][IpNames] Could not write the typed hostnames ({type(e).__name__})")


def vhost_hostnames_block(user_id: str, project_id: str, settings: dict) -> dict:
    """The ``ip_hostnames`` block VHost/SNI reads its IP-mode candidates from,
    rebuilt from the graph (a partial run has no hook data).

    The recorded names (ExternalDomain, SEEN_ON the target IPs they were seen
    on, with their reason: vhost_sni tries only a reason may_send allows) and
    the run's hostnames (S, on their pinned answer). Nothing in ip_only
    (D-09), nor when the graph cannot be read.
    """
    from recon.helpers.ip_hostnames import hostname_mode
    from recon_settings.ip_hostnames import SCANNED
    mode = hostname_mode(settings)
    block = {"mode": mode, "candidates": {}}
    if mode == "ip_only":
        return block
    graph = read_candidates(user_id, project_id)
    if graph is None:
        return block
    for name, info in graph["recorded"].items():
        block["candidates"][name] = {"reason": info["reason"], "ips_seen": list(info["ips"])}
    for name in run_ip_hostnames():
        block["candidates"][name] = {"reason": SCANNED, "ips_seen": [],
                                     "resolves_to_now": run_ip_hostname_answer(name)}
    return block

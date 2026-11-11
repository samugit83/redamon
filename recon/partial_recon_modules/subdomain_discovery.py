import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import (
    STATUS_NO_RESULTS,
    STATUS_OK,
    _group_for,
    _norm_host,
    admits_partial_host,
    attach_org,
    host_in_roots,
    include_root_for,
    partial_settings,
    root_for_host,
    run_per_root,
    scope_groups_payload,
    scope_roots,
)
from recon.helpers.roe_scope import _filter_roe_excluded


def _remove_discoveries(result: dict, dropped) -> list:
    """Remove names from the list, the DNS map and the status map of a
    discover_subdomains result, in place. Returns the kept subdomain list."""
    discovered = result.get("subdomains", [])
    dropped = set(dropped)
    if not dropped:
        return discovered
    kept = [name for name in discovered if name not in dropped]
    result["subdomains"] = kept
    result["subdomain_count"] = len(kept)
    dns_subs = (result.get("dns") or {}).get("subdomains")
    if isinstance(dns_subs, dict):
        for name in dropped:
            dns_subs.pop(name, None)
    status_map = result.get("subdomain_status_map")
    if isinstance(status_map, dict):
        for name in dropped:
            status_map.pop(name, None)
    return kept


def _drop_roe_excluded_discoveries(result: dict, settings: dict) -> list:
    """Remove RoE-excluded names from a discover_subdomains result, in place.

    The full pipeline drops them from the same three places (merge_group_hosts,
    through _drop_roe_excluded_subdomains). The graph writer MERGEs every name
    in result["subdomains"], and partial Naabu/httpx/Nuclei later read their
    targets back from the graph, so a name left here is actively scanned.
    Returns the kept subdomain list.
    """
    discovered = result.get("subdomains", [])
    kept = _filter_roe_excluded(discovered, settings, label="discovered subdomain")
    return _remove_discoveries(result, set(discovered) - set(kept))


def _drop_never_scannable_discoveries(result: dict, domain: str, operator_hosts) -> list:
    """Remove discovered names that resolve to a never-scannable address, in place.

    merge_group_hosts' SSRF guard: a discovered name is the domain owner's DNS,
    and `localhost.<domain> -> 127.0.0.1` or a name on 169.254.169.254 (cloud
    metadata) is no host a scanner may probe. The scan root and the hosts the
    operator typed are kept, as in the full pipeline: scanning them is the
    operator's decision. Private addresses are kept too (is_never_scannable_ip).
    Reads the addresses the run's DNS pass already resolved. Returns the kept
    subdomain list.
    """
    from recon.main_recon_modules.ip_filter import is_never_scannable_ip

    dns_subs = (result.get("dns") or {}).get("subdomains") or {}
    dropped = {}
    for host in result.get("subdomains", []):
        if host == domain or host in operator_hosts:
            continue
        ips = (dns_subs.get(host) or {}).get("ips") or {}
        flat = list(ips.get("ipv4") or []) + list(ips.get("ipv6") or [])
        if any(is_never_scannable_ip(a) for a in flat):
            dropped[host] = flat
    for host, flat in dropped.items():
        print(f"[!][Scope] Dropped discovered host {host} -> {flat}: "
              f"loopback/link-local/multicast is never a scan target")
    return _remove_discoveries(result, dropped)


def _enumerable_roots(roots: list, config: dict, settings: dict) -> list:
    """The roots subdomain enumeration may run on.

    A group enumerates only in ENUMERATE mode, a single-domain project's
    included: an EXACT group is scanned exactly as listed (no discovery).
    Groups without a mode (a caller not yet migrated) follow the legacy rule: a
    single-domain project always enumerates, a batch only a wildcard group.
    Decided by the same group_discovery_enabled the full pipeline calls per
    group, with the run-wide toggle forced on because the operator explicitly
    triggered this tool.
    """
    from recon.helpers.batch_groups import group_discovery_enabled, parse_target

    groups = config.get("domain_groups") or []
    batch_groups = groups if config.get("batch_mode") else []
    enumerable = []
    for root in roots:
        group = next((g for g in groups
                      if _norm_host(g.get("rootDomain")) == _norm_host(root)), None)
        if group is not None and "mode" in group:
            if group["mode"] == "enumerate":
                enumerable.append(root)
            continue
        info = parse_target(root, list(group.get("prefixes") or []) if group else [])
        info["root_domain"] = root
        if group_discovery_enabled(settings, batch_groups, info):
            enumerable.append(root)
    return enumerable


def run_subdomain_discovery(config: dict) -> dict:
    """
    Run partial subdomain discovery, once per enumerable root, using the exact
    same functions as the full pipeline in domain_recon.py.

    Over a Domain batch only wildcard roots enumerate; a literal group is scanned
    exactly as uploaded and is reported as skipped. With no enumerable root, the
    run exits 1.
    """
    from recon.main_recon_modules.domain_recon import discover_subdomains, resolve_all_dns, run_puredns_resolve

    roots = scope_roots(config)
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)

    # The operator explicitly triggered discovery, so the run-wide toggle is on;
    # the per-root wildcard rule still decides which roots enumerate.
    settings["SUBDOMAIN_DISCOVERY_ENABLED"] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Subdomain Discovery")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    if user_inputs:
        print(f"[*][Partial Recon] User inputs: {len(user_inputs)} custom subdomains")
    print(f"{'=' * 50}\n")

    enumerable = _enumerable_roots(roots, config, settings)
    skipped = {r: "not scanned: a literal group is scanned as uploaded, not enumerated"
               for r in roots if r not in enumerable}
    for root in skipped:
        print(f"[!][Partial Recon] {root}: {skipped[root]}")

    if not enumerable:
        print("[!][Partial Recon] No root may enumerate subdomains "
              "(every group is literal; nothing to discover).")
        sys.exit(1)

    # Validate user inputs against ANY root; each is scanned with the root it
    # sits under.
    valid_user_subs = []
    for sub in user_inputs:
        sub = sub.strip().lower()
        groups = config.get("domain_groups") or []
        in_scope = (admits_partial_host(groups, sub) if groups and "mode" in groups[0]
                    else host_in_roots(sub, roots))
        if sub and in_scope:
            valid_user_subs.append(sub)
        elif sub:
            print(f"[!][Partial Recon] Skipping invalid user input: {sub} (outside the scope)")
    # The full pipeline drops the operator's explicit hosts the same way before
    # any phase runs: an excluded host is never resolved, written or probed.
    valid_user_subs = _filter_roe_excluded(valid_user_subs, settings,
                                           label="user-provided subdomain")

    def _one_root(domain: str) -> str:
        print(f"[*][Partial Recon] Running subdomain discovery for {domain}...")
        result = discover_subdomains(
            domain=domain,
            bruteforce=settings.get("USE_BRUTEFORCE_FOR_SUBDOMAINS", False),
            resolve=True,
            save_output=False,
            project_id=project_id,
            settings=settings,
        )

        discovered_subs = result.get("subdomains", [])
        print(f"[+][Partial Recon] {domain}: discovery found {len(discovered_subs)} subdomains")
        discovered_subs = _drop_roe_excluded_discoveries(result, settings)

        my_user_subs = [s for s in valid_user_subs if root_for_host(s, roots) == domain]
        new_user_subs = [s for s in my_user_subs if s not in discovered_subs]
        if new_user_subs:
            print(f"[*][Partial Recon] Adding {len(new_user_subs)} user-provided subdomains under {domain}")
            all_subs = sorted(set(discovered_subs + new_user_subs))
            all_subs, wildcard_filter = run_puredns_resolve(all_subs, domain, settings)
            result.setdefault("metadata", {})["wildcard_filter"] = wildcard_filter
            print(f"[*][Partial Recon] Resolving DNS for {len(all_subs)} subdomains...")
            result["subdomains"] = all_subs
            result["subdomain_count"] = len(all_subs)
            dns_workers = settings.get('DNS_MAX_WORKERS', 50)
            dns_record_parallel = settings.get('DNS_RECORD_PARALLELISM', True)
            result["dns"] = resolve_all_dns(domain, all_subs, max_workers=dns_workers,
                                            record_parallelism=dns_record_parallel, settings=settings)
            subdomain_status_map = {}
            if result["dns"]:
                dns_subs = result["dns"].get("subdomains", {})
                for s in all_subs:
                    info = result["dns"].get("domain", {}) if s == domain else dns_subs.get(s, {})
                    if info.get("has_records", False):
                        subdomain_status_map[s] = "resolved"
            result["subdomain_status_map"] = subdomain_status_map
        listed = {_norm_host(h) for h in (_group_for(domain, config.get("domain_groups"))
                                          or {}).get("exactHosts") or []}
        _drop_never_scannable_discoveries(result, domain, listed | set(my_user_subs))

        result["domain"] = domain
        groups = config.get("domain_groups") or []
        if groups and "mode" in groups[0] and not include_root_for(domain, groups):
            # The scan root itself is no target: the writer would make it a
            # scan-root Subdomain (§4.6).
            result["subdomains"] = [s for s in result.get("subdomains", []) if s != domain]
            result["subdomain_count"] = len(result["subdomains"])
            if isinstance(result.get("dns"), dict):
                result["dns"]["domain"] = {}
                (result["dns"].get("subdomains") or {}).pop(domain, None)
        # The writers attach to the org and classify by the project's groups.
        from recon.helpers.batch_groups import settings_scope_groups
        result["scope_groups"] = scope_groups_payload(
            settings_scope_groups(config.get("_settings") or {}) or config.get("domain_groups"))
        result["all_project_roots"] = list(roots)
        final_count = len(result.get("subdomains", []))
        print(f"[+][Partial Recon] {domain}: final subdomain count: {final_count}")

        # Update the graph database
        print(f"[*][Partial Recon] Updating graph database...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
                return STATUS_NO_RESULTS if not final_count else STATUS_OK

            # UserInput node NOW (after scan succeeded), only for this root's inputs.
            user_input_id = None
            if my_user_subs:
                user_input_id = str(uuid.uuid4())
                graph_client.create_user_input_node(
                    domain=domain,
                    user_input_data={
                        "id": user_input_id,
                        "input_type": "subdomains",
                        "values": my_user_subs,
                        "tool_id": "SubdomainDiscovery",
                    },
                    user_id=user_id,
                    project_id=project_id,
                    root_orgs={domain: attach_org(domain)},
                )

            stats = graph_client.update_graph_from_partial_discovery(
                recon_data=result,
                user_id=user_id,
                project_id=project_id,
                user_input_id=user_input_id,
                org_domain=attach_org(domain),
            )

            if user_input_id:
                graph_client.update_user_input_status(user_input_id, "completed", stats, user_id=user_id, project_id=project_id)
                print(f"[+][Partial Recon] Created UserInput + linked to discovery results")

            print(f"[+][Partial Recon] {domain}: {json.dumps(stats, default=str)}")

        return STATUS_OK if (final_count or my_user_subs) else STATUS_NO_RESULTS

    statuses = run_per_root(enumerable, _one_root, "SubdomainDiscovery")
    statuses.update(skipped)
    return statuses

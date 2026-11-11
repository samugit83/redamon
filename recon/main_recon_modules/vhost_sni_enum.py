"""
RedAmon - VHost & SNI Enumeration Module
=========================================

Discovers hidden virtual hosts on every target IP by sending crafted curl
requests with overridden Host headers (L7 test) and forced TLS SNI values
(L4 test). Compares each response against a baseline (raw IP request) and
flags anomalies as Vulnerability findings.

Why two tests:
    L7 (Host header)  catches classic Apache/Nginx vhosts that route on the
                       HTTP application layer.
    L4 (TLS SNI)      catches modern reverse proxies (NGINX ingress, Traefik,
                       Cloudflare, k8s) that route at the TLS handshake before
                       reading any HTTP header.

Tools used: curl + httpx (both already present in the recon container image).
No new dependencies. Runs in GROUP 6 Phase A as the 4th parallel branch
alongside Nuclei, GraphQL scan, and Subdomain Takeover.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, NamedTuple, Optional

from recon.helpers import request_pacer
from recon.helpers.roe_scope import _is_roe_excluded
from recon.helpers.catchall import canonical_bytes, replace_hostnames as _replace_hostnames


# Marker that separates the response body from curl's --write-out metadata in
# the same stdout stream. Length + arbitrary bytes make accidental collision
# with a real response body vanishingly unlikely.
_PROBE_META_SENTINEL = b"\n___VHOSTSNI_PROBE_META_b3d8a1c2___ "

# Cap on body bytes captured for hashing; protects against multi-MB pages
# without losing the discriminating power of the first chunk.
_PROBE_BODY_MAX_BYTES = 1_048_576  # 1 MiB


# Hostname prefixes that strongly suggest an internal/admin app — used to
# escalate severity when one of these is the discovered hidden vhost.
INTERNAL_KEYWORDS = {
    "admin", "administrator", "adm", "manage", "management", "mgmt", "console",
    "control", "panel", "dashboard", "portal", "internal", "intranet",
    "private", "staging", "stage", "dev", "develop", "test", "qa", "uat",
    "preprod", "sandbox", "beta", "alpha", "canary", "demo", "lab",
    "jenkins", "gitlab", "gitea", "github", "bitbucket", "jira", "confluence",
    "wiki", "nexus", "artifactory", "sonar", "sonarqube", "harbor", "registry",
    "grafana", "kibana", "prometheus", "alertmanager", "splunk", "elastic",
    "kafka", "rabbitmq", "redis", "mongo", "mysql", "postgres", "phpmyadmin",
    "pgadmin", "adminer", "portainer", "rancher", "kubernetes", "k8s", "kube",
    "argocd", "argo", "spinnaker", "consul", "vault", "nomad", "ldap", "ad",
    "sso", "auth", "keycloak", "okta", "vpn", "openvpn", "wireguard",
    "rdp", "ssh", "sftp", "ftp", "exchange", "owa", "webmail", "zimbra",
    "proxmox", "vcenter", "esxi", "nas", "synology", "qnap", "truenas",
    "swagger", "graphiql", "playground", "actuator", "metrics", "debug",
    "ide", "vscode", "code-server", "jupyter",
}

DEFAULT_WORDLIST_CONTAINER_PATH = "/app/recon/wordlists/vhost-common.txt"

# How many suppressed "host:port" names an IP node keeps. A permissive frontend
# answers every one of up to VHOST_SNI_MAX_CANDIDATES_PER_IP names per port, so
# the full list would not fit sensibly on one property.
SUPPRESSED_SAMPLE_MAX = 20

_SOURCE = "vhost_sni_enum"


# =============================================================================
# Entry points
# =============================================================================
def run_vhost_sni_enrichment(
    combined_result: dict,
    settings: Optional[dict] = None,
) -> dict:
    """
    Run VHost & SNI enumeration. Mutates combined_result["vhost_sni"] and
    returns combined_result.
    """
    print("\n" + "=" * 70)
    print("[*][VhostSni] RedAmon - VHost & SNI Enumeration")
    print("=" * 70)

    settings = settings or {}

    if not settings.get("VHOST_SNI_ENABLED", False):
        print("[-][VhostSni] Disabled via settings -- skipping")
        combined_result["vhost_sni"] = _empty_result(reason="disabled")
        return combined_result

    test_l7 = bool(settings.get("VHOST_SNI_TEST_L7", True))
    test_l4 = bool(settings.get("VHOST_SNI_TEST_L4", True))
    if not test_l7 and not test_l4:
        print("[-][VhostSni] Both L7 and L4 tests disabled -- nothing to do")
        combined_result["vhost_sni"] = _empty_result(reason="all_layers_disabled")
        return combined_result

    timeout = max(1, int(settings.get("VHOST_SNI_TIMEOUT", 3)))
    concurrency = max(1, int(settings.get("VHOST_SNI_CONCURRENCY", 20)))
    size_tolerance = max(0, int(settings.get("VHOST_SNI_BASELINE_SIZE_TOLERANCE", 50)))
    max_candidates_per_ip = max(1, int(settings.get("VHOST_SNI_MAX_CANDIDATES_PER_IP", 2000)))
    inject_discovered = bool(settings.get("VHOST_SNI_INJECT_DISCOVERED", True))
    use_default_wordlist = bool(settings.get("VHOST_SNI_USE_DEFAULT_WORDLIST", True))
    use_graph_candidates = bool(settings.get("VHOST_SNI_USE_GRAPH_CANDIDATES", True))
    custom_wordlist_raw = settings.get("VHOST_SNI_CUSTOM_WORDLIST", "") or ""

    # --------------------------------------------------------------
    # 0. Dump effective settings to logs so the operator can audit
    #    what config this run actually used (visible in the Recon
    #    Logs Drawer of the webapp).
    # --------------------------------------------------------------
    from recon.helpers import print_effective_settings
    print_effective_settings(
        "VhostSni",
        settings,
        keys=[
            ("VHOST_SNI_TEST_L7", "Test layers"),
            ("VHOST_SNI_TEST_L4", "Test layers"),
            ("VHOST_SNI_USE_GRAPH_CANDIDATES", "Candidate sources"),
            ("VHOST_SNI_USE_DEFAULT_WORDLIST", "Candidate sources"),
            ("VHOST_SNI_CUSTOM_WORDLIST", "Candidate sources"),
            ("VHOST_SNI_MAX_CANDIDATES_PER_IP", "Candidate sources"),
            ("VHOST_SNI_TIMEOUT", "Performance"),
            ("VHOST_SNI_CONCURRENCY", "Performance"),
            ("VHOST_SNI_BASELINE_SIZE_TOLERANCE", "Anomaly detection"),
            ("VHOST_SNI_INJECT_DISCOVERED", "Output"),
        ],
    )

    # --------------------------------------------------------------
    # 1. Build IP -> ports map from prior pipeline data
    # --------------------------------------------------------------
    ip_port_map = _collect_ip_targets(combined_result, settings)
    if not ip_port_map:
        print("[-][VhostSni] No IP targets available -- skipping")
        combined_result["vhost_sni"] = _empty_result(reason="no_ip_targets")
        return combined_result

    # --------------------------------------------------------------
    # 2. Resolve apex domain for wordlist expansion
    # --------------------------------------------------------------
    apex = _detect_apex_domain(combined_result)
    from recon.helpers.recon_scope import recon_scope
    if apex and recon_scope(combined_result).exact and not isinstance(combined_result.get("domains"), list):
        # An EXACT group scans its listed hosts: no wordlist names under it.
        print("[*][VhostSni] Listed hosts only (exact scope) -- wordlist disabled")
        apex = None
        use_default_wordlist = False
    elif not apex:
        print("[!][VhostSni] Cannot determine apex domain -- wordlist disabled")
        use_default_wordlist = False
        # custom_wordlist still works since it can already contain FQDNs

    # --------------------------------------------------------------
    # 3. Load wordlist sources
    # --------------------------------------------------------------
    default_prefixes: list[str] = []
    if use_default_wordlist:
        default_prefixes = _load_default_wordlist()
        print(f"[*][VhostSni] Default wordlist: {len(default_prefixes)} prefixes loaded")

    custom_lines = _parse_custom_wordlist(custom_wordlist_raw)
    if custom_lines:
        print(f"[*][VhostSni] Custom wordlist: {len(custom_lines)} entries provided")

    # --------------------------------------------------------------
    # 4. Curl availability check
    # --------------------------------------------------------------
    from recon.helpers import circuit_breaker as _cb
    if not _is_curl_available():
        # Meant to run and re-checked nothing: the earlier findings stay.
        print("[!][VhostSni] curl binary not found in PATH -- aborting, previous findings are kept")
        _cb.note_degraded(_SOURCE, sources=(_SOURCE,), reason="curl unavailable")
        combined_result["vhost_sni"] = _empty_result(reason="curl_unavailable")
        return combined_result

    started = time.time()

    by_ip: dict[str, dict] = {}
    findings_flat: list[dict] = []
    discovered_baseurls: set[str] = set()
    summary_counts = {
        "ips_tested": 0,
        "candidates_total": 0,
        "anomalies_l7": 0,
        "anomalies_l4": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
        "info_severity": 0,
    }

    vhost_scope = _cb.scope((), label="VhostSni", unit="port(s)")
    # IP:ports this module gave up on while they may still answer the other
    # tools (a failed baseline, a probing error): cut for this source only.
    unchecked_ports: list[str] = []
    candidate_scope = _build_candidate_scope(combined_result, settings)

    # A shared CDN edge answers almost any name with some customer's site or
    # its own catch-all, so a wordlist there finds the CDN, not the target.
    # Its graph names (and the custom lines) are still tried. Only edges are
    # skipped: a Kubernetes ingress or a shared reverse proxy is exactly where
    # real hidden apps live.
    edge_ips = _shared_edge_ips(combined_result, ip_port_map) if use_default_wordlist else set()
    wordlist_skipped = sorted(edge_ips)
    if wordlist_skipped:
        print(f"[-][VhostSni] Default wordlist skipped on {len(wordlist_skipped)} shared CDN edge IP(s)")
        _cb.note_degraded("vhost_sni", entries=[{
            "source": "vhost_sni_wordlist", "reason": "shared CDN edge",
            "skipped": len(wordlist_skipped),
        }])
    ip_mode_names = _ip_mode_names(combined_result, settings, ip_port_map) if use_graph_candidates else None

    # IP mode's base URLs are its addresses: a name answering on one is a
    # finding on that address, never a new URL to probe (a recorded name is no
    # target, I-4; a selected one reaches httpx through the name selection).
    if inject_discovered and (combined_result.get("metadata") or {}).get("ip_mode"):
        print("[-][VhostSni] IP mode: a hidden vhost is reported on its IP, never added as a base URL")
        inject_discovered = False

    print(f"[*][VhostSni] Probing {len(ip_port_map)} IP target(s) with concurrency={concurrency}")
    for ip, ports in ip_port_map.items():
        try:
            ip_result = _probe_single_ip(
                ip=ip,
                ports=ports,
                apex_domain=apex,
                default_prefixes=default_prefixes if use_default_wordlist and ip not in edge_ips else [],
                custom_lines=custom_lines,
                graph_candidates=(
                    [] if not use_graph_candidates
                    else ip_mode_names.get(ip, []) if ip_mode_names is not None
                    else _collect_graph_candidates(combined_result, ip)),
                test_l7=test_l7,
                test_l4=test_l4,
                timeout=timeout,
                concurrency=concurrency,
                size_tolerance=size_tolerance,
                max_candidates=max_candidates_per_ip,
                scope=candidate_scope,
                dns_known=_dns_known_names(combined_result, ip),
            )
        except Exception as e:
            print(f"[!][VhostSni] IP {ip} probing failed: {e} -- its previous findings are kept")
            unchecked_ports.extend(_port_key(ip, p.get("port")) for p in ports)
            continue

        for dead in ip_result.get("unreachable_ports", []):
            vhost_scope.note_host_skipped(dead)
        unchecked_ports.extend(ip_result.get("unchecked_ports", []))
        if ip_result.get("ports_tested") == 0:
            # by_ip is what the graph writer stamps vhost_sni_tested and
            # hidden_vhost_count=0 on; with no usable baseline that would claim
            # "checked, nothing hidden". The IP node keeps what it had.
            print(f"[!][VhostSni] IP {ip}: no port gave a usable baseline -- not marked as tested")
            continue
        by_ip[ip] = ip_result
        summary_counts["ips_tested"] += 1
        summary_counts["candidates_total"] += ip_result.get("candidates_tested", 0)

        for anomaly in ip_result.get("anomalies", []):
            summary_counts[f"{anomaly.get('severity', 'info')}_severity"] = (
                summary_counts.get(f"{anomaly.get('severity', 'info')}_severity", 0) + 1
            )
            if anomaly.get("layer") == "L7":
                summary_counts["anomalies_l7"] += 1
            elif anomaly.get("layer") == "L4":
                summary_counts["anomalies_l4"] += 1
            elif anomaly.get("layer") == "both":
                summary_counts["anomalies_l7"] += 1
                summary_counts["anomalies_l4"] += 1

            findings_flat.append(_build_finding_record(anomaly, ip, ip_result))

            # http_probe already has a DNS-known name; injecting it would only
            # re-label a public site as discovered by this module.
            if inject_discovered and not anomaly.get("dns_known"):
                base_url = _build_baseurl(anomaly["hostname"], anomaly["port"], anomaly.get("scheme", "https"))
                if base_url:
                    discovered_baseurls.add(base_url)

    # --------------------------------------------------------------
    # 5. Inject discovered hidden vhosts back into http_probe.by_url so
    #    downstream graph methods (and subsequent partial recon runs) see them
    # --------------------------------------------------------------
    if inject_discovered and discovered_baseurls:
        _inject_into_http_probe(combined_result, sorted(discovered_baseurls))

    duration = round(time.time() - started, 2)
    now_iso = datetime.now(timezone.utc).isoformat()

    result = {
        "by_ip": by_ip,
        "findings": findings_flat,
        "discovered_baseurls": sorted(discovered_baseurls),
        "summary": summary_counts,
        "scan_metadata": {
            "duration_sec": duration,
            "scan_timestamp": now_iso,
            "wordlist_default_used": use_default_wordlist,
            "wordlist_default_count": len(default_prefixes),
            "wordlist_skipped_edge_ips": wordlist_skipped,
            "wordlist_custom_count": len(custom_lines),
            "graph_candidates_used": use_graph_candidates,
            "test_l7": test_l7,
            "test_l4": test_l4,
            "size_tolerance": size_tolerance,
            "concurrency": concurrency,
            "timeout": timeout,
        },
    }

    # IP:ports that died mid-run: the prune keeps their previous findings.
    vhost_scope.finish(_SOURCE, host_source=_SOURCE, payload=result)
    if unchecked_ports:
        unchecked_ports = sorted(set(unchecked_ports))
        print(f"[!][VhostSni] {len(unchecked_ports)} IP:port(s) not checked this run -- "
              f"their previous vhost findings are kept")
        _cb.note_degraded(_SOURCE, hosts=unchecked_ports, host_source=_SOURCE,
                          source_only_hosts=True, reason="baseline probe failed or probing errored")
        result["unchecked_ports"] = unchecked_ports
    combined_result["vhost_sni"] = result

    print(
        f"[✓][VhostSni] {summary_counts['ips_tested']} IP(s) tested, "
        f"{summary_counts['candidates_total']} candidate probes, "
        f"{len(findings_flat)} anomalies "
        f"(high={summary_counts['high_severity']} med={summary_counts['medium_severity']} "
        f"low={summary_counts['low_severity']} info={summary_counts['info_severity']}) "
        f"in {duration}s"
    )
    return combined_result


def run_vhost_sni_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """
    Thread-safe isolated wrapper for GROUP 6 Phase A fan-out in recon/main.py.
    Deep-copies combined_result, runs the scan on the copy, returns only the
    vhost_sni payload dict.
    """
    snapshot = copy.deepcopy(combined_result)
    run_vhost_sni_enrichment(snapshot, settings=settings)
    return snapshot.get("vhost_sni", {})


# =============================================================================
# Per-IP probing
# =============================================================================
def _scoped_candidates(
    apex_domain: Optional[str],
    default_prefixes: list[str],
    custom_lines: list[str],
    graph_candidates: list[str],
    scope: Optional["_CandidateScope"],
) -> tuple[list[str], int]:
    """The sorted candidate hostnames for one IP, and how many were out of scope.

    Graph names must sit under a project root; the wordlist and the user's
    custom lines are deliberate, so only an RoE exclusion removes them, except
    in an EXACT group, where nothing off its list is tried.
    """
    skipped: set[str] = set()
    if scope is not None:
        in_scope = [h for h in graph_candidates if _candidate_in_scope(h, scope)]
        skipped |= {h.strip().strip(".").lower() for h in graph_candidates} - {h.strip().strip(".").lower() for h in in_scope}
        graph_candidates = in_scope
    candidate_set = _build_candidate_set(
        apex_domain=apex_domain,
        default_prefixes=default_prefixes,
        custom_lines=custom_lines,
        graph_candidates=graph_candidates,
    )
    if scope is not None and scope.roe_excluded:
        excluded = {h for h in candidate_set if _is_roe_excluded(h, list(scope.roe_excluded))}
        skipped |= excluded
        candidate_set -= excluded
    if scope is not None and scope.exact is not None:
        outside = {h for h in candidate_set if h not in scope.exact}
        skipped |= outside
        candidate_set -= outside
    return sorted(candidate_set), len(skipped)


def _probe_single_ip(
    ip: str,
    ports: list[dict],
    apex_domain: Optional[str],
    default_prefixes: list[str],
    custom_lines: list[str],
    graph_candidates: list[str],
    test_l7: bool,
    test_l4: bool,
    timeout: int,
    concurrency: int,
    size_tolerance: int,
    max_candidates: int,
    scope: Optional["_CandidateScope"] = None,
    dns_known: Iterable[str] = (),
) -> dict:
    """Run baseline + L7/L4 anomaly probes for one IP across all its ports.

    ``dns_known`` names resolve to this IP in public DNS: they are probed, but
    only a routing inconsistency (L7 and L4 serving different pages) on one of
    them is kept, since a site anyone can resolve is not a hidden vhost.
    """
    dns_known = {h.strip().lower().rstrip(".") for h in dns_known if isinstance(h, str)}

    candidates, out_of_scope_skipped = _scoped_candidates(
        apex_domain, default_prefixes, custom_lines, graph_candidates, scope)
    if out_of_scope_skipped:
        print(f"[*][VhostSni] IP {ip}: skipped {out_of_scope_skipped} candidate(s) outside the project scope")
    if len(candidates) > max_candidates:
        # Deterministic cap (sorted) so repeated runs hit the same set
        candidates = candidates[:max_candidates]

    print(f"[*][VhostSni] IP {ip}: {len(ports)} port(s), {len(candidates)} candidate(s)")

    baselines: dict[tuple[int, str], dict] = {}
    anomalies: list[dict] = []
    is_permissive_frontend = False
    suppressed_by_control_total = 0
    suppressed_unstable_total = 0
    suppressed_dns_known: set[str] = set()
    suppressed_as_noise: list[str] = []
    dead_ports: list[str] = []
    unchecked_ports: list[str] = []

    for port_info in ports:
        port = int(port_info.get("port", 443))
        scheme = port_info.get("scheme") or _scheme_for_port(port)

        # A port a requests-based module already proved unreachable is skipped.
        # curl's own silence cannot prove a host dead, so it never marks one.
        port_key = _port_key(ip, port)
        if _known_down(f"{scheme}://{port_key}"):
            dead_ports.append(port_key)
            print(f"[!][VhostSni] IP {port_key} ({scheme}) is unreachable this run -- skipping port")
            continue

        baseline = _curl_probe(
            scheme=scheme,
            host_header=None,
            sni_hostname=None,
            target=ip,
            port=port,
            timeout=timeout,
        )
        if baseline is None:
            # Nothing on this port was re-checked, so it must not read as
            # "checked, no hidden vhost": its earlier findings are kept.
            unchecked_ports.append(port_key)
            print(f"[!][VhostSni] IP {port_key} ({scheme}) baseline failed -- skipping port")
            continue
        baselines[(port, scheme)] = baseline

        # Calibrate: send a few bogus-hostname probes to learn what the IP
        # returns for any unknown vhost. Candidates whose response matches
        # these controls are the IP's default-unknown-vhost behavior, not a
        # real hidden vhost (suppressed below).
        l7_controls, l4_controls = _run_control_probes(
            scheme, ip, port, timeout, test_l7=test_l7, test_l4=test_l4,
            apex_domain=apex_domain,
        )
        if l7_controls or l4_controls:
            print(
                f"[*][VhostSni] IP {ip}:{port} ({scheme}) calibration: "
                f"L7 controls={len(l7_controls)}/{_CONTROL_PROBE_COUNT} "
                f"L4 controls={len(l4_controls)}/{_CONTROL_PROBE_COUNT}"
            )

        # L7 + L4 probes for this (port, scheme), each candidate
        per_candidate_results: dict[str, dict] = {}

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="vhostsni") as pool:
            futures = {}
            for hostname in candidates:
                if test_l7:
                    futures[pool.submit(_curl_probe, scheme, hostname, None, ip, port, timeout)] = (hostname, "L7")
                if test_l4 and scheme == "https":
                    futures[pool.submit(_curl_probe, scheme, hostname, hostname, ip, port, timeout)] = (hostname, "L4")
            none_streak = 0
            for fut in as_completed(futures):
                hostname, layer = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res is None:
                    none_streak += 1
                    # A run of silent candidates may just be a quiet vhost set;
                    # re-asking the baseline tells a dead target apart. Only a
                    # dead baseline stops the port (never on a streak alone).
                    if none_streak >= _DEAD_STREAK and _breakers_on():
                        if _curl_probe(scheme=scheme, host_header=None, sni_hostname=None,
                                       target=ip, port=port, timeout=timeout) is None:
                            for pending in futures:
                                pending.cancel()
                            dead_ports.append(port_key)
                            print(f"[!][VhostSni] IP {port_key} ({scheme}) stopped answering "
                                  f"mid-run -- skipping its remaining candidates")
                            break
                        none_streak = 0
                    continue
                none_streak = 0
                per_candidate_results.setdefault(hostname, {})[layer] = res

        # Per-port collection so the noisy-frontend guard can scope its decision
        # to a single (port, scheme) bucket.
        port_anomalies: list[dict] = []
        port_suppressed_by_control = 0

        for hostname, layer_results in per_candidate_results.items():
            l7_res = layer_results.get("L7")
            l4_res = layer_results.get("L4")
            # A rate limiter's 429 says nothing about the name asked for.
            l7_raw = _is_anomaly(l7_res, baseline, size_tolerance) if _usable(l7_res) else False
            l4_raw = _is_anomaly(l4_res, baseline, size_tolerance) if _usable(l4_res) else False
            raw_was_anomaly = l7_raw or l4_raw

            # Suppress probes whose response matches the IP's unknown-vhost shape
            l7_anomaly = l7_raw and not _matches_any_control(l7_res, l7_controls)
            l4_anomaly = l4_raw and not _matches_any_control(l4_res, l4_controls)

            if not l7_anomaly and not l4_anomaly:
                if raw_was_anomaly:
                    port_suppressed_by_control += 1
                continue

            if l7_anomaly and l4_anomaly:
                layer = "both"
                obs = l4_res or l7_res
            elif l7_anomaly:
                layer = "L7"
                obs = l7_res
            else:
                layer = "L4"
                obs = l4_res

            severity = _classify_severity(
                hostname=hostname,
                layer=layer,
                baseline=baseline,
                observed=obs,
                l7_res=l7_res,
                l4_res=l4_res,
                size_tolerance=size_tolerance,
            )
            port_anomalies.append({
                "hostname": hostname,
                "ip": ip,
                "port": port,
                "scheme": scheme,
                "layer": layer,
                "layers_differ": layer == "both" and not _same_response(l7_res, l4_res, size_tolerance),
                "dns_known": hostname in dns_known,
                "baseline_status": baseline["status"],
                "baseline_size": baseline["size"],
                "observed_status": obs["status"],
                "observed_size": obs["size"],
                "observed_fingerprint": obs.get("canon_hash") or "",
                "size_delta": obs["size"] - baseline["size"],
                "severity": severity,
                "internal_pattern_match": _matched_internal_keyword(hostname),
            })

        # Safety net: if the control filter missed and the remaining anomalies
        # cluster on one or two response shapes, the IP is a permissive frontend.
        kept, port_is_noisy = _detect_noisy_frontend(port_anomalies, len(candidates))
        if port_is_noisy:
            is_permissive_frontend = True
            suppressed_as_noise.extend(f"{a['hostname']}:{port}" for a in port_anomalies)
            print(
                f"[!][VhostSni] IP {ip}:{port} ({scheme}) appears to be a "
                f"permissive frontend ({len(port_anomalies)}/{len(candidates)} "
                f"candidates clustered on a single response shape) -- suppressing findings"
            )
        if port_suppressed_by_control:
            print(
                f"[*][VhostSni] IP {ip}:{port} ({scheme}) suppressed "
                f"{port_suppressed_by_control} candidate(s) matching control probes"
            )
        suppressed_by_control_total += port_suppressed_by_control

        # Set aside before the re-probe (no traffic for a name that cannot be
        # reported) and again after it, since a re-probe can reduce a routing
        # inconsistency to one layer.
        kept = _set_aside_dns_known(kept, suppressed_dns_known)
        if port_key in dead_ports:
            unstable = 0  # the port stopped answering: a second probe would only time out
        else:
            kept, unstable = _drop_unstable(
                kept, per_candidate_results, l7_controls, l4_controls,
                scheme=scheme, ip=ip, port=port, timeout=timeout, concurrency=concurrency,
                baseline=baseline, size_tolerance=size_tolerance,
            )
        kept = _set_aside_dns_known(kept, suppressed_dns_known)
        if unstable:
            print(
                f"[*][VhostSni] IP {ip}:{port} ({scheme}) dropped {unstable} "
                f"candidate(s) whose response changed or matched a control on a second probe"
            )
        suppressed_unstable_total += unstable
        anomalies.extend(kept)

    if suppressed_dns_known:
        print(f"[*][VhostSni] IP {ip}: {len(suppressed_dns_known)} name(s) public DNS already "
              f"points here served their own site -- not reported as hidden")

    # Build the per-IP summary
    primary_baseline = next(iter(baselines.values()), None)
    is_reverse_proxy = any(a.get("layer") in ("L4", "both") for a in anomalies)

    return {
        "ip": ip,
        "baseline": primary_baseline or {"status": None, "size": None},
        "baselines_per_port": {f"{p}:{s}": b for (p, s), b in baselines.items()},
        "candidates_tested": len(candidates),
        "ports_tested": len(baselines),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "is_reverse_proxy": is_reverse_proxy,
        "is_permissive_frontend": is_permissive_frontend,
        "suppressed_by_control": suppressed_by_control_total,
        "suppressed_unstable": suppressed_unstable_total,
        "suppressed_dns_known": len(suppressed_dns_known),
        "out_of_scope_skipped": out_of_scope_skipped,
        # A permissive frontend's anomalies are discarded as noise, not written
        # as findings; the count and a bounded sample keep that discard visible.
        "suppressed_as_noise": len(suppressed_as_noise),
        "suppressed_as_noise_sample": sorted(suppressed_as_noise)[:SUPPRESSED_SAMPLE_MAX],
        "hosts_hidden_vhosts": len(anomalies) > 0,
        **({"unreachable_ports": dead_ports} if dead_ports else {}),
        **({"unchecked_ports": unchecked_ports} if unchecked_ports else {}),
    }


# =============================================================================
# Curl wrapper
# =============================================================================
# Consecutive silent candidate probes on one port before its baseline is asked
# again. High enough that a quiet vhost list never triggers it on a live port.
_DEAD_STREAK = 10


def _port_key(ip: str, port: int) -> str:
    """``ip:port`` in HostHealth's key form (an IPv6 address is bracketed)."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _breakers_on() -> bool:
    try:
        from recon.helpers import circuit_breaker as cb
        return cb.enabled()
    except Exception:  # noqa: BLE001
        return False


def _known_down(target: str) -> bool:
    try:
        from recon.helpers import circuit_breaker as cb
        return cb.host_health.is_down(target)
    except Exception:  # noqa: BLE001
        return False


def _curl_probe(
    scheme: str,
    host_header: Optional[str],
    sni_hostname: Optional[str],
    target: str,
    port: int,
    timeout: int,
) -> Optional[dict]:
    """
    Single curl invocation. Returns {"status": int, "size": int, "body_hash": str}
    or None on error. host_header overrides the HTTP Host header (L7 test).
    sni_hostname, when set, swaps the URL hostname AND uses --resolve to pin DNS
    to target IP so the TLS handshake carries that name as SNI (L4 test).

    body_hash is a SHA-1 over the raw response body (capped at 1 MiB).
    canon_hash fingerprints the response with the probed hostname and
    per-request tokens normalised away (see _canonical_fingerprint); the
    control filter, the noisy-frontend guard and the severity rule compare it,
    so a provider error page that echoes the hostname or a Ray ID still
    matches the same page served for a random name.
    """
    write_out = _PROBE_META_SENTINEL.decode("ascii") + "\t".join(
        ("%{http_code}", "%{size_download}", "%{redirect_url}", "%{content_type}")
    )
    # An IPv6 literal must be bracketed in a URL and in --resolve.
    addr = f"[{target}]" if ":" in target else target
    if sni_hostname and scheme == "https":
        # L4 test: URL is the hostname, --resolve forces it to the IP
        url = f"{scheme}://{sni_hostname}:{port}/"
        cmd = [
            "curl", "-sk",
            "-o", "-",
            "-w", write_out,
            "--max-filesize", str(_PROBE_BODY_MAX_BYTES),
            "--resolve", f"{sni_hostname}:{port}:{addr}",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout * 3),
            url,
        ]
    else:
        # Baseline (no host_header) or L7 test (host_header set)
        url = f"{scheme}://{addr}:{port}/"
        cmd = [
            "curl", "-sk",
            "-o", "-",
            "-w", write_out,
            "--max-filesize", str(_PROBE_BODY_MAX_BYTES),
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout * 3),
        ]
        if host_header:
            cmd += ["-H", f"Host: {host_header}"]
        cmd.append(url)

    # One curl is one request (no -L): its slot of the process-wide RoE pacer
    # keeps the whole worker pool, with every other in-process requester,
    # under the ceiling. Inert with no ceiling.
    request_pacer.acquire()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=False,  # bytes, so body bytes hash deterministically
            timeout=timeout * 3 + 2,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    raw = proc.stdout or b""
    has_meta = _PROBE_META_SENTINEL in raw
    if has_meta:
        body, meta_bytes = raw.rsplit(_PROBE_META_SENTINEL, 1)
    else:
        body = b""
        meta_bytes = raw

    try:
        meta = meta_bytes.decode("ascii", errors="replace").strip("\r\n ")
    except Exception:
        return None

    parts = meta.split("\t") if "\t" in meta else meta.split()
    if len(parts) < 2:
        return None
    try:
        status = int(parts[0])
        size = int(parts[1])
    except ValueError:
        return None
    redirect_url = parts[2].strip() if "\t" in meta and len(parts) > 2 else ""
    content_type = parts[3].strip() if "\t" in meta and len(parts) > 3 else ""

    # Status 0 means curl could not connect at all -- treat as no data.
    if status == 0:
        return None

    body_hash = hashlib.sha1(body).hexdigest() if body else ""
    # Without the sentinel the body is unknown, so there is nothing to
    # fingerprint and the control filter must not suppress on it.
    probed = [h for h in (host_header, sni_hostname) if h]
    canon_hash = (
        _canonical_fingerprint(status, redirect_url, content_type, body, probed)
        if has_meta else ""
    )
    return {"status": status, "size": size, "body_hash": body_hash, "canon_hash": canon_hash,
            "title": _canonical_title(body, probed) if has_meta else None}


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _canonical_title(body: bytes, hostnames: list[str]) -> Optional[str]:
    """The page <title> with the probed hostname normalised, or None."""
    m = _TITLE_RE.search(body or b"")
    if not m:
        return None
    title = _replace_hostnames(m.group(1), hostnames)
    return b" ".join(title.split()).decode("utf-8", "replace")[:200]


def _canonical_fingerprint(
    status: int,
    redirect_url: str,
    content_type: str,
    body: bytes,
    hostnames: list[str],
) -> str:
    """SHA-1 over status, redirect target, MIME type and body, each with the
    probed hostname replaced by {HOST} and per-request tokens stripped.

    A shared CDN answers every unknown name with one template that echoes the
    name (Fastly) or carries a fresh Ray ID (Cloudflare); the raw bytes then
    differ per probe while this fingerprint does not.
    """
    mime = content_type.split(";", 1)[0].strip().lower()
    parts = [
        str(status).encode("ascii"),
        canonical_bytes(redirect_url.encode("utf-8", "ignore"), hostnames),
        mime.encode("ascii", "ignore"),
        canonical_bytes(body, hostnames),
    ]
    return hashlib.sha1(b"\x00".join(parts)).hexdigest()


# A rate limiter or an overloaded edge answers whatever was asked: no data.
_INCONCLUSIVE_STATUSES = frozenset({429, 503})


def _usable(probe: Optional[dict]) -> bool:
    return bool(probe) and probe["status"] != 429


def _is_anomaly(probe: dict, baseline: dict, size_tolerance: int) -> bool:
    """Anomaly = different status, OR same status with size delta beyond tolerance."""
    if probe is None or baseline is None:
        return False
    if probe["status"] != baseline["status"]:
        return True
    return abs(probe["size"] - baseline["size"]) > size_tolerance


# =============================================================================
# Control-probe filter (false-positive suppression)
# =============================================================================
#
# Many real-world targets sit behind a permissive frontend (Cloudflare,
# generic reverse proxies, k8s ingress catch-alls) that returns the SAME
# response for ANY unrecognized Host/SNI header. Without a calibration step
# the detector flags every wordlist entry as a "hidden vhost" because each
# probe trivially differs from the raw-IP baseline.
#
# The fix is the same pattern wfuzz/ffuf use: send a few probes with random
# bogus hostnames first and treat their response shape as the IP's
# "unknown-vhost default". Any candidate with the same status and canonical
# fingerprint (hostname and per-request tokens normalised) gets suppressed.
#
# Two of the three controls sit under the apex: a CDN that routes by zone
# answers an unknown name inside a customer's zone differently from a name
# under `.invalid`, and the wordlist candidates are all inside the zone.

_CONTROL_PROBE_COUNT = 3
_CONTROL_LABEL_PREFIX = "vhostsni-ctrl-"


def _control_hostnames(apex_domain: Optional[str]) -> list[str]:
    names = []
    for i in range(_CONTROL_PROBE_COUNT):
        label = f"{_CONTROL_LABEL_PREFIX}{uuid.uuid4().hex[:10]}-{i}"
        in_zone = apex_domain and i < _CONTROL_PROBE_COUNT - 1
        names.append(f"{label}.{apex_domain}" if in_zone else f"{label}.invalid")
    return names


def _run_control_probes(
    scheme: str,
    ip: str,
    port: int,
    timeout: int,
    *,
    test_l7: bool,
    test_l4: bool,
    apex_domain: Optional[str] = None,
) -> tuple[list[dict], list[dict]]:
    """Send `_CONTROL_PROBE_COUNT` probes with random bogus hostnames and
    return (l7_controls, l4_controls). Used to characterize what the IP
    returns for any unknown vhost so we can suppress matching candidates."""
    l7_controls: list[dict] = []
    l4_controls: list[dict] = []
    for bogus in _control_hostnames(apex_domain):
        if test_l7:
            r = _curl_probe(scheme, bogus, None, ip, port, timeout)
            if r:
                l7_controls.append(r)
        if test_l4 and scheme == "https":
            r = _curl_probe(scheme, None, bogus, ip, port, timeout)
            if r:
                l4_controls.append(r)
    return l7_controls, l4_controls


def _matches_any_control(probe: Optional[dict], controls: list[dict]) -> bool:
    """True iff the probe is indistinguishable from the IP's default
    unknown-vhost behavior: same status and same canonical fingerprint, or,
    for a probe without one, the same raw body hash. A probe with neither
    (curl output without the meta sentinel) is never suppressed, so a real
    finding is never silently dropped on missing data."""
    if not probe or not controls:
        return False
    probe_canon = probe.get("canon_hash")
    probe_hash = probe.get("body_hash")
    if not probe_canon and not probe_hash:
        return False
    for c in controls:
        if probe["status"] != c.get("status"):
            continue
        if probe_canon and probe_canon == c.get("canon_hash"):
            return True
        if probe_hash and probe_hash == c.get("body_hash"):
            return True
    return False


def _same_response(a: Optional[dict], b: Optional[dict], size_tolerance: int = 0) -> bool:
    """Same status and, when both carry one, the same canonical fingerprint;
    without fingerprints, the same size. With `size_tolerance`, fingerprints
    that differ still count as the same page while the title matches and the
    sizes stay within it: a live app's response time or counter changes a few
    bytes, a different backend changes the title or the size."""
    if not a or not b or a["status"] != b["status"]:
        return False
    if a.get("canon_hash") and b.get("canon_hash"):
        if a["canon_hash"] == b["canon_hash"]:
            return True
        # Without a title there is nothing to tell a moving page from a
        # different one, so only an identical fingerprint is the same page.
        return (size_tolerance > 0 and a.get("title") is not None and a.get("title") == b.get("title")
                and abs(a["size"] - b["size"]) <= size_tolerance)
    return abs(a["size"] - b["size"]) <= size_tolerance


def _drop_unstable(
    anomalies: list[dict],
    first_results: dict[str, dict],
    l7_controls: list[dict],
    l4_controls: list[dict],
    *,
    scheme: str,
    ip: str,
    port: int,
    timeout: int,
    concurrency: int,
    baseline: Optional[dict] = None,
    size_tolerance: int = 0,
) -> tuple[list[dict], int]:
    """Probe each surviving candidate's firing layer(s) a second time and drop
    a layer when its status changed or its answer now matches a control: a
    transient answer (a backend that briefly served something else, a
    load-balancer flap) is not a vhost. A page whose body moves between
    requests (a response time, a counter, a nonce) is a live application and
    stays. A "both" finding with one stable layer is kept as that layer.

    Only fingerprinted probes are re-checked. A re-probe that failed or was
    rate-limited (429/503) keeps the layer, since it proves nothing.
    """
    jobs: list[tuple[int, str, dict]] = []
    for idx, a in enumerate(anomalies):
        layers = ("L7", "L4") if a["layer"] == "both" else (a["layer"],)
        for layer in layers:
            first = (first_results.get(a["hostname"]) or {}).get(layer)
            if first and first.get("canon_hash"):
                jobs.append((idx, layer, first))
    if not jobs:
        return anomalies, 0

    unstable: dict[int, set] = {}
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="vhostsni-re") as pool:
        futures = {}
        for idx, layer, first in jobs:
            host = anomalies[idx]["hostname"]
            sni = host if layer == "L4" else None
            host_header = None if layer == "L4" else host
            futures[pool.submit(_curl_probe, scheme, host_header, sni, ip, port, timeout)] = (idx, layer, first)
        for fut in as_completed(futures):
            idx, layer, first = futures[fut]
            try:
                again = fut.result()
            except Exception:
                again = None
            if again is None or again["status"] in _INCONCLUSIVE_STATUSES:
                continue
            controls = l4_controls if layer == "L4" else l7_controls
            if again["status"] != first["status"] or _matches_any_control(again, controls):
                unstable.setdefault(idx, set()).add(layer)

    kept: list[dict] = []
    dropped = 0
    for idx, a in enumerate(anomalies):
        bad = unstable.get(idx, set())
        fired = {"L7", "L4"} if a["layer"] == "both" else {a["layer"]}
        if not bad:
            kept.append(a)
        elif bad >= fired:
            dropped += 1
        else:
            (layer,) = fired - bad
            obs = (first_results.get(a["hostname"]) or {})[layer]
            a = dict(a, layer=layer, layers_differ=False, observed_status=obs["status"],
                     observed_size=obs["size"], observed_fingerprint=obs.get("canon_hash") or "")
            if baseline is not None:
                a["size_delta"] = obs["size"] - baseline["size"]
                a["severity"] = _classify_severity(a["hostname"], layer, baseline, obs, None, None, size_tolerance)
            kept.append(a)
    return kept, dropped


def _set_aside_dns_known(anomalies: list[dict], set_aside: set) -> list[dict]:
    """Drop the anomalies on DNS-known names that are not a routing
    inconsistency, adding their hostnames to ``set_aside``."""
    kept = []
    for a in anomalies:
        if a.get("dns_known") and not a.get("layers_differ"):
            set_aside.add(a["hostname"])
        else:
            kept.append(a)
    return kept


def _detect_noisy_frontend(
    anomalies: list[dict],
    candidates_count: int,
    *,
    min_candidates: int = 10,
    fire_rate_threshold: float = 0.70,
    cluster_threshold: float = 0.85,
) -> tuple[list[dict], bool]:
    """Safety net for cases the control filter misses (e.g. controls returned
    different shapes by coincidence but real candidates all clustered on one
    shape). Returns (kept_anomalies, is_noisy_frontend).

    Activates only with enough candidates to draw a statistical conclusion --
    small unit-test wordlists never trip it.
    """
    if candidates_count < min_candidates or not anomalies:
        return anomalies, False
    if len(anomalies) / candidates_count < fire_rate_threshold:
        return anomalies, False
    # Two groupings, either one enough: by canonical fingerprint (a template
    # echoing the hostname has a different size for every hostname length) and
    # by exact size (a constant-size template whose per-request token no
    # normalisation rule knows gives every name its own fingerprint).
    for key in ("observed_fingerprint", "observed_size"):
        buckets = Counter((a["observed_status"], a.get(key) or a["observed_size"]) for a in anomalies)
        top_two = sum(count for _, count in buckets.most_common(2))
        if top_two / len(anomalies) >= cluster_threshold:
            return [], True
    return anomalies, False


def _classify_severity(
    hostname: str,
    layer: str,
    baseline: dict,
    observed: dict,
    l7_res: Optional[dict],
    l4_res: Optional[dict],
    size_tolerance: int = 0,
) -> str:
    """
    high   -- L7 and L4 serve different pages for the same hostname (proxy
              bypass primitive); a byte difference that normalises away (a
              Ray ID, the echoed hostname) is the same page, not a bypass
    medium -- hidden vhost with hostname matching internal keyword pattern
    low    -- different status code (confirmed hidden vhost)
    info   -- different size only, status unchanged
    """
    if layer == "both" and l7_res and l4_res and not _same_response(l7_res, l4_res, size_tolerance):
        return "high"

    if _matched_internal_keyword(hostname):
        return "medium"

    if observed["status"] != baseline["status"]:
        return "low"

    return "info"


def _matched_internal_keyword(hostname: str) -> Optional[str]:
    """
    Return the matched internal keyword (e.g. 'admin') or None.

    For compound hostnames like 'admin-portal' that contain MULTIPLE keywords,
    return the LONGEST match (more specific = higher signal). Iteration order
    of INTERNAL_KEYWORDS (a set) is not guaranteed, so picking the longest
    match also makes the result deterministic across Python invocations.
    """
    label = hostname.split(".")[0].lower()
    if label in INTERNAL_KEYWORDS:
        return label
    # Compound matches like 'admin-portal', 'jenkins-internal'
    matches = []
    for kw in INTERNAL_KEYWORDS:
        if (label.startswith(f"{kw}-") or label.startswith(f"{kw}_")
                or label.endswith(f"-{kw}") or label.endswith(f"_{kw}")):
            matches.append(kw)
    if not matches:
        return None
    # Longest match wins; tie-breaker: lexicographic for determinism
    return max(matches, key=lambda k: (len(k), k))


# =============================================================================
# Candidate building
# =============================================================================
class _CandidateScope(NamedTuple):
    """Which graph-derived hostnames may be tried as a vhost on a target IP.

    The graph sources include every subdomain's CNAME target, PTR names and
    certificate SANs, which name third parties (an identity provider's tenant
    host, a CDN edge name, another customer on a shared certificate). Those
    are not the target's vhosts, and on a shared CDN IP the probe reaches the
    third party's service. ``roots`` empty (IP mode) disables the root check,
    since an IP-mode project has no domain to compare against.

    ``exact`` is an EXACT group's whole target list: then every candidate,
    wordlist and custom lines included, must be on it. ``include_root`` False
    keeps a root itself out (an ENUMERATE group whose root is not a target).
    """
    roots: tuple = ()
    roe_excluded: tuple = ()
    exact: Optional[frozenset] = None
    include_root: bool = True


def _build_candidate_scope(combined_result: dict, settings: dict) -> _CandidateScope:
    metadata = combined_result.get("metadata") or {}
    declared = combined_result.get("domains")
    roots = [r for r in declared if isinstance(r, str) and r.strip()] if isinstance(declared, list) else []
    if not roots:
        apex = _detect_apex_domain(combined_result)
        roots = [apex] if apex else []
    roots = [r.strip().strip(".").lower() for r in roots]
    if metadata.get("ip_mode") or any(r.startswith("ip-targets.") for r in roots):
        roots = []
    excluded = settings.get("ROE_EXCLUDED_HOSTS") if settings.get("ROE_ENABLED") else None
    exact, include_root = None, True
    if roots and not isinstance(declared, list):
        from recon.helpers.recon_scope import recon_scope
        group = recon_scope(combined_result)
        if group.mode:
            include_root = group.include_root
            if group.exact:
                exact = frozenset(group.targets())
    return _CandidateScope(
        roots=tuple(roots),
        # Candidates are lower-case without a trailing dot; so are the entries.
        roe_excluded=tuple(e.strip().strip(".").lower() for e in (excluded or []) if isinstance(e, str) and e.strip()),
        exact=exact,
        include_root=include_root,
    )


def _candidate_in_scope(hostname: str, scope: _CandidateScope) -> bool:
    host = (hostname or "").strip().strip(".").lower()
    if not host:
        return False
    if scope.roe_excluded and _is_roe_excluded(host, list(scope.roe_excluded)):
        return False
    if scope.exact is not None:
        return host in scope.exact
    if not scope.roots:
        return True
    return any((host == r and scope.include_root) or host.endswith(f".{r}") for r in scope.roots)


def _build_candidate_set(
    apex_domain: Optional[str],
    default_prefixes: list[str],
    custom_lines: list[str],
    graph_candidates: list[str],
) -> set[str]:
    """Combine all candidate sources, dedupe, return a clean set of FQDNs."""
    cset: set[str] = set()

    for h in graph_candidates:
        if isinstance(h, str) and "." in h:
            cset.add(h.strip().lower().rstrip("."))

    if apex_domain:
        for prefix in default_prefixes:
            prefix = prefix.strip().lower()
            if not prefix or "." in prefix:
                continue
            cset.add(f"{prefix}.{apex_domain}")

    for line in custom_lines:
        line = line.strip().lower().rstrip(".")
        if not line:
            continue
        # Custom lines may be either a full FQDN or a prefix to expand.
        if "." in line:
            cset.add(line)
        elif apex_domain:
            cset.add(f"{line}.{apex_domain}")

    # Filter out clearly invalid hostnames
    valid = set()
    for h in cset:
        if _is_valid_hostname(h):
            valid.add(h)
    return valid


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    # Use \Z (absolute end of string), not $, because $ matches before a
    # trailing \n in Python regexes — a newline-injected hostname like
    # "evil\n.example.com" would otherwise pass and corrupt the curl
    # --resolve syntax (newline = header injection in HTTP context).
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)\Z", re.IGNORECASE)
    return all(allowed.match(label) for label in hostname.split("."))


def _resolves_here(dns_entry, ip: str) -> bool:
    ip_set = (dns_entry or {}).get("ips") if isinstance(dns_entry, dict) else None
    if not isinstance(ip_set, dict):
        return False
    return ip in (ip_set.get("ipv4") or []) or ip in (ip_set.get("ipv6") or [])


def _dns_subdomains_on(combined_result: dict, ip: str) -> set[str]:
    """Subdomains whose A/AAAA in this run's dns block include ``ip``."""
    subs = ((combined_result.get("dns") or {}).get("subdomains")) or {}
    return {name.strip().lower().rstrip(".") for name, info in subs.items()
            if isinstance(name, str) and _resolves_here(info, ip)}


def _dns_known_names(combined_result: dict, ip: str) -> set[str]:
    """Names public DNS points at ``ip`` this run: its subdomains, the apex, and
    the names httpx resolved to it.

    Anyone can resolve them, so a site served for one of them is not hidden,
    however much it differs from the raw-IP answer. On a shared CDN or proxy IP
    every customer's site does differ, so without this each DNS-known name was
    reported as a hidden vhost.

    The httpx part matters for names found after the DNS phase (certificate
    SANs, JS): they join the dns block with no addresses, and http_probe's
    ``ip`` for a hostname URL is the address its own lookup returned.
    """
    names = _dns_subdomains_on(combined_result, ip)
    apex = _detect_apex_domain(combined_result)
    if apex and _resolves_here((combined_result.get("dns") or {}).get("domain"), ip):
        names.add(apex)
    by_url = ((combined_result.get("http_probe") or {}).get("by_url")) or {}
    for info in by_url.values():
        if not isinstance(info, dict) or info.get("ip") != ip:
            continue
        host = str(info.get("host") or "").strip().lower().rstrip(".")
        if host and not _looks_like_ip(host):
            names.add(host)
    # IP mode keeps its names out of the dns block: every hostname the run
    # recorded on its targets was seen there (a PTR answer, a certificate,
    # passive DNS), so it is that host's own site, never a hidden one.
    if (combined_result.get("metadata") or {}).get("ip_mode"):
        names |= set(((combined_result.get("ip_hostnames") or {}).get("candidates")) or {})
    return names


def _collect_graph_candidates(combined_result: dict, ip: str) -> list[str]:
    """
    Pull every hostname from the recon data that resolves to (or sits on) this
    IP. Sources: dns map, http_probe.by_host, urlscan/external domains, TLS
    SAN list captured by httpx.
    """
    # 1. DNS resolved subdomains pointing at this IP
    out: set[str] = set(_dns_subdomains_on(combined_result, ip))
    dns = combined_result.get("dns") or {}

    # 2. http_probe.by_host (alive hosts httpx already resolved)
    http_probe = combined_result.get("http_probe") or {}
    for host_key, host_info in (http_probe.get("by_host") or {}).items():
        if not isinstance(host_info, dict):
            continue
        host_ip = host_info.get("ip") or host_info.get("a") or ""
        if host_ip == ip:
            out.add(host_key.strip().lower())

    # 3. TLS SAN list captured per-URL by http_probe. The real path is
    # info["tls"]["certificate"]["san"]; the old code read tls_subject_alt_names
    # / tls_sans, which NOTHING writes, so this source was dead in production.
    for url, info in (http_probe.get("by_url") or {}).items():
        if not isinstance(info, dict):
            continue
        if (info.get("host") or "") == ip or info.get("ip") == ip:
            cert = ((info.get("tls") or {}).get("certificate") or {})
            for san in (cert.get("san") or []):
                if isinstance(san, str) and san.strip():
                    out.add(san.strip().lower().lstrip("*."))

    # 4. External domains seen on this IP. The pipeline aggregates them only
    # after this module ran, so the aggregate is built here when absent; its
    # entries are {domain, ips_seen} (recon/helpers/external_domains.py).
    aggregated = combined_result.get("external_domains_aggregated")
    if aggregated is None:
        from recon.helpers.external_domains import _aggregate_external_domains
        aggregated = _aggregate_external_domains(combined_result)
    for ed in aggregated or []:
        if isinstance(ed, dict) and ed.get("domain") and ip in (ed.get("ips_seen") or []):
            out.add(str(ed["domain"]).strip().lower())

    # 5. CNAME targets from DNSRecord-shaped entries in dns map
    for sub_name, sub_info in (dns.get("subdomains") or {}).items():
        records = (sub_info or {}).get("records") or {}
        cnames = records.get("CNAME") or records.get("cname") or []
        if isinstance(cnames, str):
            cnames = [cnames]
        for cn in cnames:
            if isinstance(cn, str) and cn.strip():
                out.add(cn.strip().lower().rstrip("."))

    # 6. tlsx SAN list, matched on the scanned IP. Covers non-HTTP TLS ports and
    # bare IPs httpx never dialled; empty when tlsx is off (harmless).
    tlsx = combined_result.get("tlsx") or {}
    for _key, entry in (tlsx.get("by_target") or {}).items():
        if not isinstance(entry, dict):
            continue
        if entry.get("scanned_ip") == ip or entry.get("ip") == ip:
            for san in (entry.get("san") or []):
                if isinstance(san, str) and san.strip():
                    out.add(san.strip().lower().lstrip("*."))

    return [h for h in out if h and "." in h]


def _ip_mode_names(combined_result: dict, settings: dict, ips: Iterable[str]) -> Optional[dict[str, list[str]]]:
    """IP mode: {target IP: the recorded hostnames this probe may try on it};
    None outside IP mode, where the graph sources above apply.

    A name is tried only on a target IP it was seen on, so the probe stays on
    the targets. None in IP only (D-09: the custom FQDN lines are its only
    names). None at all when IP attribution did not run, and none on a shared
    CDN edge or on an IP whose attribution failed (B-31): an edge answers a
    name with whichever tenant's site it serves.
    """
    if not (combined_result.get("metadata") or {}).get("ip_mode"):
        return None
    from recon.helpers.ip_hostnames import hostname_mode, may_send
    from recon.main_recon_modules.ip_attribution import ATTRIBUTION_FAILED
    if hostname_mode(settings) == "ip_only":
        print("[-][VhostSni] IP only: no discovered hostname is tried (custom FQDN lines only)")
        return {}
    attribution = combined_result.get("ip_attribution")
    if not isinstance(attribution, dict):
        print("[-][VhostSni] IP attribution did not run: no recorded hostname is tried on the target IPs")
        return {}
    by_ip = attribution.get("by_ip") or {}
    usable, edges = set(), set()
    for ip in ips:
        entry = by_ip.get(ip)
        if not isinstance(entry, dict) or ATTRIBUTION_FAILED in (entry.get("ownership_reasons") or ()):
            continue
        (edges if entry.get("ownership") == "shared_edge" else usable).add(ip)
    if edges:
        print(f"[-][VhostSni] Recorded hostnames are not tried on {len(edges)} shared CDN edge IP(s)")
    out: dict[str, list[str]] = {}
    for name, candidate in (((combined_result.get("ip_hostnames") or {}).get("candidates")) or {}).items():
        if may_send(candidate):
            for ip in candidate.get("ips_seen") or ():
                if ip in usable:
                    out.setdefault(ip, []).append(name)
    return out


# =============================================================================
# IP / port / wordlist / apex helpers
# =============================================================================
def _collect_ip_targets(combined_result: dict, settings: Optional[dict] = None) -> dict[str, list[dict]]:
    """
    Build {ip: [{port, protocol, scheme}, ...]} by MERGING every available source
    (no fallback / either-or). Sources walked in order:

      1. port_scan.by_host  -- authoritative ports + optional scheme overrides
      2. dns.subdomains[*].ips -- IPs we know about via DNS but for which port
         scanning may have been skipped or partial; default 80/443 added
      3. dns.domain.ips -- the apex domain's resolved IPs, same default 80/443

    Merging (rather than the previous fallback-on-empty behaviour) ensures that
    a partial-recon run with both a custom IP AND a graph-known IP probes BOTH
    instead of silently dropping the graph IPs.

    Every address then passes the RoE admission gate (``settings``, else the
    RoE a partial builder stamped in ``metadata.roe``).
    """
    ip_to_ports: dict[str, list[dict]] = {}

    # ---- 1. port_scan.by_host (authoritative) ----------------------------
    port_scan = combined_result.get("port_scan") or {}
    by_host = port_scan.get("by_host") or {}

    for host_key, host_info in by_host.items():
        if not isinstance(host_info, dict):
            continue
        ip = host_info.get("ip") or (host_key if _looks_like_ip(host_key) else None)
        if not ip:
            continue
        ports = host_info.get("ports") or []
        for p in ports:
            scheme_override = None
            if isinstance(p, dict):
                port_num = p.get("port") or p.get("number")
                # Honour an explicit scheme if the upstream provided one
                # (e.g. http_probe knows the port speaks https on a
                # non-standard port like 9443 or 8443).
                if p.get("scheme") in ("http", "https"):
                    scheme_override = p["scheme"]
            elif isinstance(p, int):
                port_num = p
            else:
                continue
            if not port_num:
                continue
            scheme = scheme_override or _scheme_for_port(int(port_num))
            ip_to_ports.setdefault(ip, []).append({
                "port": int(port_num),
                "protocol": "tcp",
                "scheme": scheme,
            })

    # ---- 2. dns.subdomains[*].ips (always-merged, default 80/443) ---------
    dns = combined_result.get("dns") or {}
    for sub_info in (dns.get("subdomains") or {}).values():
        ip_set = (sub_info or {}).get("ips") or {}
        for ip in (ip_set.get("ipv4") or []):
            ip_to_ports.setdefault(ip, []).extend([
                {"port": 443, "protocol": "tcp", "scheme": "https"},
                {"port": 80, "protocol": "tcp", "scheme": "http"},
            ])

    # ---- 3. dns.domain.ips (apex Domain, when it is a target) -------------
    from recon.helpers.recon_scope import recon_scope
    apex_dns = (dns.get("domain") or {}) if recon_scope(combined_result).include_root else {}
    domain_ips = (apex_dns.get("ips") or {}).get("ipv4") or []
    for ip in domain_ips:
        ip_to_ports.setdefault(ip, []).extend([
            {"port": 443, "protocol": "tcp", "scheme": "https"},
            {"port": 80, "protocol": "tcp", "scheme": "http"},
        ])

    # ---- IP mode: the target addresses only -----------------------------
    # Every probe is pinned to the IP it is built for, so an address a DNS
    # answer brought in that is not a target is never one to probe (B-01).
    from recon.helpers.target_admission import clamp_to_targets
    kept = set(clamp_to_targets(combined_result, list(ip_to_ports)))
    ip_to_ports = {ip: plist for ip, plist in ip_to_ports.items() if ip in kept}

    # ---- RoE: an excluded address is never probed ------------------------
    # Every source can bring one: a name resolving into an excluded range, a
    # graph row, a partial run's typed IP. Inert with no exclusion in force.
    from recon.helpers.target_admission import admit_targets
    admitted = set(admit_targets(settings, combined_result, ips=list(ip_to_ports),
                                 module="vhost_sni").ips)
    ip_to_ports = {ip: plist for ip, plist in ip_to_ports.items() if ip in admitted}

    # ---- Dedupe ports per IP (port + scheme key, preserves first occurrence) ---
    for ip, plist in ip_to_ports.items():
        seen = set()
        unique = []
        for p in plist:
            key = (p["port"], p["scheme"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        ip_to_ports[ip] = unique

    return ip_to_ports


def _shared_edge_ips(combined_result: dict, ips: Iterable[str]) -> set[str]:
    """The target IPs IP attribution tagged shared_edge.

    An IP with no tag (the step was off, or a graph written before it) falls
    back to the CDN checks: flagged by naabu, httpx or tlsx with an edge-only
    CDN name, or inside a CDN's published edge prefix. Plain cloud-hosting
    labels (aws, azure, gcp) do not count; those IPs serve the application
    itself.
    """
    from recon.helpers.cdn_ranges import collect_reliable_edge_ips, edge_cdn_for_ip
    ips = set(ips)
    by_ip = ((combined_result.get("ip_attribution") or {}).get("by_ip")) or {}
    tags = {ip: by_ip[ip].get("ownership") for ip in ips
            if isinstance(by_ip.get(ip), dict) and by_ip[ip].get("ownership")}
    untagged = ips - set(tags)
    fallback = ((collect_reliable_edge_ips(combined_result) & untagged)
                | {ip for ip in untagged if edge_cdn_for_ip(ip)})
    return {ip for ip, tag in tags.items() if tag == "shared_edge"} | fallback


def _scheme_for_port(port: int) -> str:
    if port in (443, 8443, 9443, 4443, 10443):
        return "https"
    if port in (80, 8080, 8000, 8888, 5000, 3000):
        return "http"
    return "https" if port >= 1024 and (port % 1000 == 443 or port == 443) else "http"


def _looks_like_ip(value: str) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return ":" in value  # crude IPv6 check


def _detect_apex_domain(combined_result: dict) -> Optional[str]:
    # IP mode's root is a synthetic name: `www.ip-targets.<id>` is no vhost.
    if (combined_result.get("metadata") or {}).get("ip_mode"):
        return None
    candidates = [
        combined_result.get("domain"),
        (combined_result.get("metadata") or {}).get("target"),
        (combined_result.get("metadata") or {}).get("target_domain"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip() and "." in c and not c.strip().lower().startswith("ip-targets."):
            return c.strip().lower().rstrip(".")
    return None


def _load_default_wordlist() -> list[str]:
    """Read /app/recon/wordlists/vhost-common.txt -- comments and blanks stripped."""
    path = Path(DEFAULT_WORDLIST_CONTAINER_PATH)
    if not path.exists():
        # Try local dev path (running outside container)
        local = Path(__file__).resolve().parent.parent / "wordlists" / "vhost-common.txt"
        if local.exists():
            path = local
        else:
            print(f"[!][VhostSni] Default wordlist not found at {path} or {local}")
            return []
    try:
        # utf-8-sig auto-strips a BOM if present (Windows-edited wordlists are
        # a common foot-gun otherwise).
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except Exception as e:
        print(f"[!][VhostSni] Failed to read wordlist {path}: {e}")
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line_lower = line.lower()
        if line_lower in seen:
            continue
        seen.add(line_lower)
        out.append(line_lower)
    return out


def _parse_custom_wordlist(raw: str) -> list[str]:
    """Custom wordlist arrives as newline-separated text from the project setting."""
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low in seen:
            continue
        seen.add(low)
        out.append(low)
    return out


def _is_curl_available() -> bool:
    try:
        proc = subprocess.run(["curl", "--version"], capture_output=True, text=True, timeout=5, check=False)
        return proc.returncode == 0
    except Exception:
        return False


# =============================================================================
# Output assembly helpers
# =============================================================================
def finding_id(hostname: str, ip: str, port, layer: str) -> str:
    """The Vulnerability id of one (hostname, IP, port, layer) anomaly.

    A hash of the exact values: folding punctuation to "_" made dev-api and
    dev.api (and IPv6 addresses sharing their digits) one node, and a 253-char
    name overran the 200-char id the Priority Board and MCP accept. The IP is
    canonicalised so one address spelled two ways stays one finding.
    tooling/scripts/vhost_finding_rekey.py computes the same id (a recon test
    pins the two together); change both or neither.
    """
    host = str(hostname or "").strip().lower().rstrip(".")
    addr = str(ip or "").strip()
    try:
        addr = ipaddress.ip_address(addr).compressed
    except ValueError:
        addr = addr.lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        pass
    key = f"{host}|{addr}|{port}|{str(layer or '').lower()}"
    return "vhost_sni_" + hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]


def _build_finding_record(anomaly: dict, ip: str, ip_result: dict) -> dict:
    """Convert an anomaly dict into a Vulnerability-shaped record for the graph."""
    hostname = anomaly["hostname"]
    port = anomaly["port"]
    layer = anomaly["layer"]
    severity = anomaly["severity"]
    internal_kw = anomaly.get("internal_pattern_match")
    # Only a split between the layers is a routing inconsistency; when both
    # reach the same page it is a hidden vhost seen twice. An anomaly built
    # without the flag is "high" exactly when its layers differ.
    layers_differ = anomaly.get("layers_differ")
    if layers_differ is None:
        layers_differ = layer == "both" and severity == "high"

    if layer == "both" and layers_differ:
        vuln_type = "host_header_bypass"
        vuln_name = f"Routing Inconsistency (L7 vs L4): {hostname}"
        description = (
            f"The hostname {hostname} returns different responses depending on whether "
            f"the routing decision is made at the HTTP Host header (L7) or the TLS SNI (L4). "
            f"This inconsistency can be abused to bypass authorization checks performed at "
            f"one layer but not the other."
        )
    elif layer == "L4":
        vuln_type = "hidden_sni_route"
        vuln_name = f"Hidden SNI-Routed Virtual Host: {hostname}"
        description = (
            f"The TLS reverse proxy on {ip}:{port} routes the SNI {hostname} to a backend "
            f"that does not respond to a bare IP request. This indicates an ingress controller "
            f"(NGINX, Traefik, k8s, Cloudflare) is fronting a hidden application."
        )
    elif layer == "both":
        vuln_type = "hidden_vhost"
        vuln_name = f"Hidden Virtual Host: {hostname}"
        description = (
            f"Setting Host: {hostname}, or the TLS SNI {hostname}, on {ip}:{port} returns the "
            f"same page on both layers, and it differs from the baseline IP request. This "
            f"typically reveals a vhost not exposed via DNS."
        )
    else:  # L7
        vuln_type = "hidden_vhost"
        vuln_name = f"Hidden Virtual Host: {hostname}"
        description = (
            f"Setting Host: {hostname} on {ip}:{port} returns a different response than the "
            f"baseline IP request. This typically reveals a vhost not exposed via DNS."
        )

    if internal_kw:
        description += f" The hostname pattern '{internal_kw}' suggests an internal/admin application."

    return {
        "id": finding_id(hostname, ip, port, layer),
        "name": vuln_name,
        "type": vuln_type,
        "severity": severity,
        "source": "vhost_sni_enum",
        "hostname": hostname,
        "ip": ip,
        "port": port,
        "scheme": anomaly.get("scheme", "https"),
        "layer": layer,
        "baseline_status": anomaly["baseline_status"],
        "baseline_size": anomaly["baseline_size"],
        "observed_status": anomaly["observed_status"],
        "observed_size": anomaly["observed_size"],
        "size_delta": anomaly["size_delta"],
        "internal_pattern_match": internal_kw,
        "dns_known": bool(anomaly.get("dns_known")),
        "description": description,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


def _build_baseurl(hostname: str, port: int, scheme: str) -> Optional[str]:
    if not hostname or "." not in hostname:
        return None
    # Drop default port for cleaner URLs
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _inject_into_http_probe(combined_result: dict, baseurls: list[str]) -> None:
    """
    Add discovered hidden vhost URLs into combined_result["http_probe"]["by_url"]
    so the graph mixin's update_graph_from_http_probe (or a follow-up partial
    recon job) can pick them up. Does NOT overwrite existing entries.
    """
    http_probe = combined_result.setdefault("http_probe", {})
    by_url = http_probe.setdefault("by_url", {})
    for url in baseurls:
        if url in by_url:
            continue
        by_url[url] = {
            "url": url,
            "discovered_by": "vhost_sni_enum",
            "discovery_source": "vhost_sni_enum",
            "status_code": None,
            "live": True,
        }


def _empty_result(reason: str = "") -> dict:
    return {
        "by_ip": {},
        "findings": [],
        "discovered_baseurls": [],
        "summary": {
            "ips_tested": 0,
            "candidates_total": 0,
            "anomalies_l7": 0,
            "anomalies_l4": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "info_severity": 0,
        },
        "scan_metadata": {
            "skipped_reason": reason,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

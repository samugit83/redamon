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
from typing import Iterable, Optional


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
    ip_port_map = _collect_ip_targets(combined_result)
    if not ip_port_map:
        print("[-][VhostSni] No IP targets available -- skipping")
        combined_result["vhost_sni"] = _empty_result(reason="no_ip_targets")
        return combined_result

    # --------------------------------------------------------------
    # 2. Resolve apex domain for wordlist expansion
    # --------------------------------------------------------------
    apex = _detect_apex_domain(combined_result)
    if not apex:
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
    if not _is_curl_available():
        print("[!][VhostSni] curl binary not found in PATH -- aborting")
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

    print(f"[*][VhostSni] Probing {len(ip_port_map)} IP target(s) with concurrency={concurrency}")
    for ip, ports in ip_port_map.items():
        try:
            ip_result = _probe_single_ip(
                ip=ip,
                ports=ports,
                apex_domain=apex,
                default_prefixes=default_prefixes if use_default_wordlist else [],
                custom_lines=custom_lines,
                graph_candidates=_collect_graph_candidates(combined_result, ip) if use_graph_candidates else [],
                test_l7=test_l7,
                test_l4=test_l4,
                timeout=timeout,
                concurrency=concurrency,
                size_tolerance=size_tolerance,
                max_candidates=max_candidates_per_ip,
            )
        except Exception as e:
            print(f"[!][VhostSni] IP {ip} probing failed: {e}")
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

            if inject_discovered:
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
            "wordlist_custom_count": len(custom_lines),
            "graph_candidates_used": use_graph_candidates,
            "test_l7": test_l7,
            "test_l4": test_l4,
            "size_tolerance": size_tolerance,
            "concurrency": concurrency,
            "timeout": timeout,
        },
    }

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
) -> dict:
    """Run baseline + L7/L4 anomaly probes for one IP across all its ports."""

    candidate_set = _build_candidate_set(
        apex_domain=apex_domain,
        default_prefixes=default_prefixes,
        custom_lines=custom_lines,
        graph_candidates=graph_candidates,
    )
    if len(candidate_set) > max_candidates:
        # Deterministic cap (sorted) so repeated runs hit the same set
        candidate_set = sorted(candidate_set)[:max_candidates]
    candidates = sorted(candidate_set)

    print(f"[*][VhostSni] IP {ip}: {len(ports)} port(s), {len(candidates)} candidate(s)")

    baselines: dict[tuple[int, str], dict] = {}
    anomalies: list[dict] = []
    is_permissive_frontend = False
    suppressed_by_control_total = 0

    for port_info in ports:
        port = int(port_info.get("port", 443))
        scheme = port_info.get("scheme") or _scheme_for_port(port)

        baseline = _curl_probe(
            scheme=scheme,
            host_header=None,
            sni_hostname=None,
            target=ip,
            port=port,
            timeout=timeout,
        )
        if baseline is None:
            print(f"[!][VhostSni] IP {ip}:{port} ({scheme}) baseline failed -- skipping port")
            continue
        baselines[(port, scheme)] = baseline

        # Calibrate: send a few bogus-hostname probes to learn what the IP
        # returns for any unknown vhost. Candidates whose response is byte-
        # identical to these controls are the IP's default-unknown-vhost
        # behavior, not a real hidden vhost (suppressed below).
        l7_controls, l4_controls = _run_control_probes(
            scheme, ip, port, timeout, test_l7=test_l7, test_l4=test_l4,
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
            for fut in as_completed(futures):
                hostname, layer = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res is None:
                    continue
                per_candidate_results.setdefault(hostname, {})[layer] = res

        # Per-port collection so the noisy-frontend guard can scope its decision
        # to a single (port, scheme) bucket.
        port_anomalies: list[dict] = []
        port_suppressed_by_control = 0

        for hostname, layer_results in per_candidate_results.items():
            l7_res = layer_results.get("L7")
            l4_res = layer_results.get("L4")
            l7_raw = _is_anomaly(l7_res, baseline, size_tolerance) if l7_res else False
            l4_raw = _is_anomaly(l4_res, baseline, size_tolerance) if l4_res else False
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
            )
            port_anomalies.append({
                "hostname": hostname,
                "ip": ip,
                "port": port,
                "scheme": scheme,
                "layer": layer,
                "baseline_status": baseline["status"],
                "baseline_size": baseline["size"],
                "observed_status": obs["status"],
                "observed_size": obs["size"],
                "size_delta": obs["size"] - baseline["size"],
                "severity": severity,
                "internal_pattern_match": _matched_internal_keyword(hostname),
            })

        # Safety net: if the control filter missed and the remaining anomalies
        # cluster on one or two response shapes, the IP is a permissive frontend.
        kept, port_is_noisy = _detect_noisy_frontend(port_anomalies, len(candidates))
        if port_is_noisy:
            is_permissive_frontend = True
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
        anomalies.extend(kept)

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
        "hosts_hidden_vhosts": len(anomalies) > 0,
    }


# =============================================================================
# Curl wrapper
# =============================================================================
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

    body_hash is a SHA-1 over the response body (capped at 1 MiB), used by the
    control-probe filter to distinguish "this hostname returns unique content"
    from "the IP returns the same generic page for every unknown vhost".
    """
    write_out = _PROBE_META_SENTINEL.decode("ascii") + "%{http_code} %{size_download}"
    if sni_hostname and scheme == "https":
        # L4 test: URL is the hostname, --resolve forces it to the IP
        url = f"{scheme}://{sni_hostname}:{port}/"
        cmd = [
            "curl", "-sk",
            "-o", "-",
            "-w", write_out,
            "--max-filesize", str(_PROBE_BODY_MAX_BYTES),
            "--resolve", f"{sni_hostname}:{port}:{target}",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout * 3),
            url,
        ]
    else:
        # Baseline (no host_header) or L7 test (host_header set)
        url = f"{scheme}://{target}:{port}/"
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
    if _PROBE_META_SENTINEL in raw:
        body, meta_bytes = raw.rsplit(_PROBE_META_SENTINEL, 1)
    else:
        body = b""
        meta_bytes = raw

    try:
        meta = meta_bytes.decode("ascii", errors="replace").strip()
    except Exception:
        return None

    parts = meta.split()
    if len(parts) < 2:
        return None
    try:
        status = int(parts[0])
        size = int(parts[1])
    except ValueError:
        return None

    # Status 0 means curl could not connect at all -- treat as no data.
    if status == 0:
        return None

    body_hash = hashlib.sha1(body).hexdigest() if body else ""
    return {"status": status, "size": size, "body_hash": body_hash}


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
# "unknown-vhost default". Any candidate whose response is byte-identical
# (same status + same body hash) gets suppressed.

_CONTROL_PROBE_COUNT = 3


def _run_control_probes(
    scheme: str,
    ip: str,
    port: int,
    timeout: int,
    *,
    test_l7: bool,
    test_l4: bool,
) -> tuple[list[dict], list[dict]]:
    """Send `_CONTROL_PROBE_COUNT` probes with random bogus hostnames and
    return (l7_controls, l4_controls). Used to characterize what the IP
    returns for any unknown vhost so we can suppress matching candidates."""
    l7_controls: list[dict] = []
    l4_controls: list[dict] = []
    for i in range(_CONTROL_PROBE_COUNT):
        bogus = f"vhostsni-ctrl-{uuid.uuid4().hex[:10]}-{i}.invalid"
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
    unknown-vhost behavior. Requires a body_hash on BOTH sides -- when one is
    missing (mocked tests, zero-byte responses) we err on the side of NOT
    suppressing so we never silently drop a real finding."""
    if not probe or not controls:
        return False
    probe_hash = probe.get("body_hash")
    if not probe_hash:
        return False
    for c in controls:
        if probe["status"] != c.get("status"):
            continue
        if probe_hash == c.get("body_hash"):
            return True
    return False


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
    buckets = Counter((a["observed_status"], a["observed_size"]) for a in anomalies)
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
) -> str:
    """
    high   -- L7 and L4 disagree on the same hostname (proxy bypass primitive)
    medium -- hidden vhost with hostname matching internal keyword pattern
    low    -- different status code (confirmed hidden vhost)
    info   -- different size only, status unchanged
    """
    if layer == "both" and l7_res and l4_res:
        if l7_res["status"] != l4_res["status"]:
            return "high"
        if abs(l7_res["size"] - l4_res["size"]) > 0:
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


def _collect_graph_candidates(combined_result: dict, ip: str) -> list[str]:
    """
    Pull every hostname from the recon data that resolves to (or sits on) this
    IP. Sources: dns map, http_probe.by_host, urlscan/external domains, TLS
    SAN list captured by httpx.
    """
    out: set[str] = set()

    # 1. DNS resolved subdomains pointing at this IP
    dns = combined_result.get("dns") or {}
    for sub_name, sub_info in (dns.get("subdomains") or {}).items():
        if not isinstance(sub_info, dict):
            continue
        ip_set = (sub_info.get("ips") or {})
        ipv4 = ip_set.get("ipv4") if isinstance(ip_set, dict) else None
        ipv6 = ip_set.get("ipv6") if isinstance(ip_set, dict) else None
        if (ipv4 and ip in ipv4) or (ipv6 and ip in ipv6):
            out.add(sub_name.strip().lower())

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

    # 4. ExternalDomain / aggregated external_domains co-resident on IP
    for ed in (combined_result.get("external_domains_aggregated") or []):
        if isinstance(ed, dict):
            for ed_ip in (ed.get("ips") or []):
                if ed_ip == ip and ed.get("name"):
                    out.add(str(ed["name"]).strip().lower())

    # 5. CNAME targets from DNSRecord-shaped entries in dns map
    for sub_name, sub_info in (dns.get("subdomains") or {}).items():
        records = (sub_info or {}).get("records") or {}
        cnames = records.get("CNAME") or records.get("cname") or []
        if isinstance(cnames, str):
            cnames = [cnames]
        for cn in cnames:
            if isinstance(cn, str) and cn.strip():
                out.add(cn.strip().lower().rstrip("."))

    # 6. Reverse DNS PTR records on this IP
    ip_recon = combined_result.get("ip_recon") or {}
    ptr = (ip_recon.get(ip) or {}).get("reverse_dns")
    if isinstance(ptr, str) and ptr.strip():
        out.add(ptr.strip().lower().rstrip("."))

    # 8. tlsx SAN list, matched on the scanned IP. Covers non-HTTP TLS ports and
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


# =============================================================================
# IP / port / wordlist / apex helpers
# =============================================================================
def _collect_ip_targets(combined_result: dict) -> dict[str, list[dict]]:
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

    # ---- 3. dns.domain.ips (apex Domain, also always-merged) --------------
    domain_ips = ((dns.get("domain") or {}).get("ips") or {}).get("ipv4") or []
    for ip in domain_ips:
        ip_to_ports.setdefault(ip, []).extend([
            {"port": 443, "protocol": "tcp", "scheme": "https"},
            {"port": 80, "protocol": "tcp", "scheme": "http"},
        ])

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
    candidates = [
        combined_result.get("domain"),
        (combined_result.get("metadata") or {}).get("target"),
        (combined_result.get("metadata") or {}).get("target_domain"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip() and "." in c:
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
def _build_finding_record(anomaly: dict, ip: str, ip_result: dict) -> dict:
    """Convert an anomaly dict into a Vulnerability-shaped record for the graph."""
    hostname = anomaly["hostname"]
    port = anomaly["port"]
    layer = anomaly["layer"]
    severity = anomaly["severity"]
    internal_kw = anomaly.get("internal_pattern_match")

    if layer == "both":
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
    else:  # L7
        vuln_type = "hidden_vhost"
        vuln_name = f"Hidden Virtual Host: {hostname}"
        description = (
            f"Setting Host: {hostname} on {ip}:{port} returns a different response than the "
            f"baseline IP request. This typically reveals a vhost not exposed via DNS."
        )

    if internal_kw:
        description += f" The hostname pattern '{internal_kw}' suggests an internal/admin application."

    finding_id = "vhost_sni_{h}_{i}_{p}_{l}".format(
        h=re.sub(r"[^a-z0-9]", "_", hostname.lower()),
        i=re.sub(r"[^0-9.]", "_", ip),
        p=port,
        l=layer.lower(),
    )

    return {
        "id": finding_id,
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

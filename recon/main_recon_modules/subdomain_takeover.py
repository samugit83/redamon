"""
RedAmon - Subdomain Takeover Scanner Module
===========================================
Layered subdomain takeover detection:
    1. Subjack              primary, DNS-first, installed as Go binary
    2. Nuclei takeovers     fingerprint-based, reuses projectdiscovery/nuclei
       invoked with -t http/takeovers/ -t dns/ (template paths resolved
       against the mounted nuclei-templates volume)

Layered findings are deduplicated by (hostname, provider, method), scored,
and emitted with a verdict of confirmed | likely | manual_review. The graph
mixin then writes them as Vulnerability nodes with source = "takeover_scan".
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import uuid
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from recon.helpers import (
    BADDNS_DEFAULT_MODULES,
    build_baddns_command,
    build_nuclei_command,
    build_subjack_command,
    dedupe_findings,
    ensure_templates_volume,
    finding_id,
    fix_file_ownership,
    is_docker_installed,
    is_docker_running,
    normalize_baddns_finding,
    normalize_nuclei_takeover,
    normalize_subjack_result,
    parse_nuclei_finding,
    provider_from_cname,
    provider_from_cert,
    pull_nuclei_docker_image,
    resolve_cname_target,
    score_finding,
)
from recon.helpers import request_pacer
from recon.helpers.docker_helpers import run_tool_container, tool_container_name
from recon.helpers.takeover_helpers import (
    is_placeholder_provider,
    provider_from_sans,
    same_provider_family,
)

_FINDING_SOURCE = "takeover_scan"


def _note_layer_unchecked(layer: str, targets: Iterable[str], reason: str) -> None:
    """Keep the earlier takeover findings of the hosts a layer did not check. Never raises.

    A layer that times out, crashes or cannot start returns what a clean run
    returns, and this module reports its own failures to nobody, so the prune
    would read "no takeover finding on these hosts" as "gone". Every layer
    writes takeover_scan and every finding names its host, so the cut is by
    host (README "Degrade by host before degrading by source") and for
    takeover_scan alone: the other modules reached those hosts. ``reason`` is
    a fixed phrase or an exception class name, never tool output.
    """
    try:
        from recon.helpers import circuit_breaker as cb
        hosts = sorted({cb.host_key(t) for t in targets if isinstance(t, str)} - {""})
        if not hosts:
            return
        cb.note_degraded("subdomain_takeover", hosts=hosts, host_source=_FINDING_SOURCE,
                         source_only_hosts=True, reason=f"{layer} {reason}")
        print(f"[!][Takeover] {layer} {reason}: {len(hosts)} host(s) not checked, "
              f"their earlier takeover findings are kept")
    except Exception:  # noqa: BLE001 - coverage bookkeeping never fails the scan
        pass


def _hosts_answering_2xx(recon_data: dict) -> set[str]:
    """Hostnames http_probe saw serve a 2xx response on any URL."""
    from urllib.parse import urlparse
    out: set[str] = set()
    for url, info in ((recon_data.get("http_probe") or {}).get("by_url") or {}).items():
        if not isinstance(info, dict):
            continue
        status = info.get("status_code")
        if not isinstance(status, int) or not 200 <= status < 300:
            continue
        try:
            host = urlparse(url).hostname
        except ValueError:
            continue
        if host:
            out.add(host.lower().rstrip("."))
    return out


def _is_active_resource(finding: dict, manual_review_auto_publish: bool = False) -> bool:
    """A demoted CNAME candidate whose resource is proven live and claimed: the
    CNAME target resolves, the host served a 2xx page, and a clean certificate
    names the host. Some SaaS answer an unclaimed name with a 200 page, but
    never with a valid certificate for the customer's name. DNS-level methods
    (MX, SPF, TXT, NS) are about records, not the web page, and never drop."""
    if manual_review_auto_publish:
        return False
    cert_clean = not (finding.get("cert_expired") or finding.get("cert_self_signed")
                      or finding.get("cert_mismatched"))
    return (
        finding.get("verdict") == "manual_review"
        and (finding.get("takeover_method") or "cname") == "cname"
        and bool(finding.get("cname_target"))
        and bool(finding.get("cname_alive"))
        and bool(finding.get("host_answers_2xx"))
        and bool(finding.get("cert_name_match")) and cert_clean
        and not finding.get("cname_nxdomain")
        and not finding.get("cert_provider_default")
        and not finding.get("cert_absent")
    )


def _cert_names_host(host: str, subject_cn, sans) -> bool:
    """True if the certificate names `host` (CN or SAN, one wildcard level)."""
    if not host:
        return False
    host = host.strip().lower().rstrip(".")
    names = ([subject_cn] if subject_cn else []) + list(sans or [])
    for raw in names:
        if not isinstance(raw, str) or not raw:
            continue
        name = raw.strip().lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0:
                return True
    return False


# =============================================================================
# Entry points
# =============================================================================
def run_subdomain_takeover(
    recon_data: dict,
    output_file: Optional[Path] = None,
    settings: Optional[dict] = None,
) -> dict:
    """
    Run the subdomain takeover pipeline.

    Writes results to `recon_data["subdomain_takeover"]` and returns recon_data.
    Key fields in the output:
        by_target      {hostname: [finding, ...]}
        findings       flat list of scored findings
        summary        {total, confirmed, likely, manual_review, by_provider}
        scan_metadata  timing + enabled tool list
    """
    print("\n" + "=" * 70)
    print("[*][Takeover] RedAmon - Subdomain Takeover Scanner")
    print("=" * 70)

    settings = settings or {}

    if not settings.get("SUBDOMAIN_TAKEOVER_ENABLED", False):
        print("[-][Takeover] Disabled via settings -- skipping")
        recon_data["subdomain_takeover"] = _empty_result(reason="disabled")
        return recon_data

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "Takeover",
        settings,
        keys=[
            ("SUBDOMAIN_TAKEOVER_ENABLED", "Toggle"),
            ("TAKEOVER_CONFIDENCE_THRESHOLD", "Scoring"),
            ("TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH", "Scoring"),
            ("TAKEOVER_CNAME_VALIDATION_ENABLED", "Scoring"),
            ("SUBJACK_ENABLED", "Subjack layer"),
            ("SUBJACK_THREADS", "Subjack layer"),
            ("SUBJACK_TIMEOUT", "Subjack layer"),
            ("SUBJACK_SSL", "Subjack layer"),
            ("SUBJACK_ALL", "Subjack layer"),
            ("SUBJACK_CHECK_NS", "Subjack layer"),
            ("SUBJACK_CHECK_AR", "Subjack layer"),
            ("SUBJACK_CHECK_MAIL", "Subjack layer"),
            ("SUBJACK_RUN_TIMEOUT", "Subjack layer"),
            ("NUCLEI_TAKEOVERS_ENABLED", "Nuclei layer"),
            ("NUCLEI_DOCKER_IMAGE", "Nuclei layer"),
            ("TAKEOVER_SEVERITY", "Nuclei layer"),
            ("TAKEOVER_RATE_LIMIT", "Nuclei layer"),
            ("NUCLEI_TAKEOVER_RUN_TIMEOUT", "Nuclei layer"),
            ("BADDNS_ENABLED", "BadDNS layer"),
            ("BADDNS_DOCKER_IMAGE", "BadDNS layer"),
            ("BADDNS_MODULES", "BadDNS layer"),
            ("BADDNS_NAMESERVERS", "BadDNS layer"),
            ("BADDNS_RUN_TIMEOUT", "BadDNS layer"),
            ("TAKEOVER_AI_CLASSIFIER", "AI cascade"),
            ("AI_PIPELINE_MODEL", "AI cascade"),
        ],
    )

    subjack_enabled = settings.get("SUBJACK_ENABLED", True)
    nuclei_takeovers_enabled = settings.get("NUCLEI_TAKEOVERS_ENABLED", True)
    confidence_threshold = int(settings.get("TAKEOVER_CONFIDENCE_THRESHOLD", 60))
    manual_review_auto_publish = bool(settings.get("TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH", False))
    ai_classifier_enabled = bool(settings.get("TAKEOVER_AI_CLASSIFIER", False))
    ai_use_jev = bool(settings.get("TAKEOVER_AI_USE_JEV", False))
    ai_pipeline_model = settings.get("AI_PIPELINE_MODEL", "claude-opus-4-6")

    # Announce the AI cascade state up-front, regardless of whether candidates
    # are produced later. Without this banner, a "no candidates" run is
    # indistinguishable from a "cascade is off" run in the logs -- you can't
    # tell whether the wiring is broken or just had nothing to do.
    if ai_classifier_enabled and ai_pipeline_model:
        print(f"[*][Takeover-AI] Classifier cascade enabled, model={ai_pipeline_model}")
    else:
        print(f"[-][Takeover-AI] Classifier cascade disabled (TAKEOVER_AI_CLASSIFIER={ai_classifier_enabled}, model={ai_pipeline_model!r})")

    # --------------------------------------------------------------
    # 1. Target collection
    # --------------------------------------------------------------
    subdomains = _collect_subdomains(recon_data, settings)
    alive_urls = _collect_alive_urls(recon_data, settings)

    print(f"[*][Takeover] {len(subdomains)} subdomain(s), {len(alive_urls)} alive URL(s)")

    if not subdomains and not alive_urls:
        print("[-][Takeover] No targets -- skipping")
        recon_data["subdomain_takeover"] = _empty_result(reason="no_targets")
        return recon_data

    # --------------------------------------------------------------
    # 2. Execute scanners
    # --------------------------------------------------------------
    started = time.time()
    # Use /tmp/redamon (bind-mounted between recon container and host) so that
    # Docker-in-Docker sibling containers (nuclei, baddns) see the same paths.
    shared_root = Path("/tmp/redamon")
    shared_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="redamon_takeover_", dir=str(shared_root)))
    # World-readable so the non-root baddns user inside the sidecar can read.
    try:
        work_dir.chmod(0o755)
    except Exception:
        pass
    try:
        normalized: list[dict] = []

        # A layer that raises costs its own targets, not the other layers.
        if subjack_enabled and subdomains:
            try:
                subjack_raw = _run_subjack(
                    subdomains=sorted(subdomains),
                    work_dir=work_dir,
                    settings=settings,
                )
                for raw in subjack_raw:
                    norm = normalize_subjack_result(raw)
                    if norm:
                        normalized.append(norm)
                print(f"[+][Takeover] Subjack: {sum(1 for r in subjack_raw if r.get('vulnerable'))} vulnerable row(s)")
            except Exception as e:
                print(f"[!][Takeover] Subjack layer failed ({type(e).__name__})")
                _note_layer_unchecked("Subjack", subdomains, f"raised {type(e).__name__}")

        if nuclei_takeovers_enabled and alive_urls:
            try:
                nuclei_raw = _run_nuclei_takeover(
                    urls=alive_urls,
                    work_dir=work_dir,
                    settings=settings,
                )
                for raw in nuclei_raw:
                    parsed = parse_nuclei_finding(raw)
                    norm = normalize_nuclei_takeover(parsed)
                    if norm:
                        normalized.append(norm)
                print(f"[+][Takeover] Nuclei takeovers: {len(nuclei_raw)} raw finding(s)")
            except Exception as e:
                print(f"[!][Takeover] Nuclei takeover scan failed ({type(e).__name__})")
                _note_layer_unchecked("Nuclei", alive_urls, f"raised {type(e).__name__}")

        if settings.get("BADDNS_ENABLED", False) and subdomains:
            try:
                baddns_raw = _run_baddns(
                    subdomains=sorted(subdomains),
                    work_dir=work_dir,
                    settings=settings,
                )
                for raw in baddns_raw:
                    norm = normalize_baddns_finding(raw)
                    if norm:
                        normalized.append(norm)
                print(f"[+][Takeover] BadDNS: {len(baddns_raw)} raw finding(s)")
            except Exception as e:
                print(f"[!][Takeover] BadDNS scan failed ({type(e).__name__})")
                _note_layer_unchecked("BadDNS", subdomains, f"raised {type(e).__name__}")

        # --------------------------------------------------------------
        # 3. Enrich with CNAME resolution + live-target validation
        # --------------------------------------------------------------
        # Two false-positive suppressors:
        #   (a) provider_mismatch -- subjack's body-content fingerprints can
        #       collide on generic 404s (e.g. flagging instatus.com as
        #       Gemfury). When the actual CNAME maps to a different known
        #       provider, mark the disagreement so the scorer can demote.
        #   (b) cname_alive -- if the CNAME target resolves to live A/AAAA
        #       records and the provider is NOT in AUTO_EXPLOITABLE_PROVIDERS,
        #       the SaaS edge is up serving the legitimate customer. Auto-
        #       exploitable providers wildcard-resolve at the SaaS edge even
        #       when dangling, so we exempt them from this rule (the scorer
        #       enforces the exemption).
        #   (c) host_answers_2xx -- http_probe saw the host serve a normal 2xx
        #       page; an unclaimed resource answers with the provider's error.
        dns_data = recon_data.get("dns", {})
        cname_validation = bool(settings.get("TAKEOVER_CNAME_VALIDATION_ENABLED", True))
        answered_2xx = _hosts_answering_2xx(recon_data)
        for n in normalized:
            if n["hostname"] in answered_2xx:
                n["host_answers_2xx"] = True
            cname = n.get("cname_target") or _lookup_cname_from_dns(dns_data, n["hostname"])
            if not cname:
                continue
            n["cname_target"] = cname
            cname_provider = provider_from_cname(cname)
            current_provider = (n.get("takeover_provider") or "").lower()
            if is_placeholder_provider(current_provider):
                if cname_provider:
                    n["takeover_provider"] = cname_provider
            elif cname_provider and not same_provider_family(cname_provider, current_provider):
                # Only a CNAME that names ANOTHER known provider disagrees: the
                # suffix table is not complete (regional S3 endpoints, a SaaS's
                # second edge domain), so an unknown CNAME proves nothing.
                n["provider_mismatch"] = True
                n["cname_provider"] = cname_provider
            if cname_validation:
                try:
                    probe = resolve_cname_target(cname)
                    if probe.get("resolves"):
                        n["cname_alive"] = True
                    if probe.get("nxdomain"):
                        n["cname_nxdomain"] = True
                except Exception as e:
                    # Probe failure is non-fatal -- leave fields unset so the
                    # scorer treats DNS state as unknown.
                    print(f"[!][Takeover] CNAME probe failed for {cname}: {e}")

        # --------------------------------------------------------------
        # 3a2. Certificate-derived signals (Phase 3)
        # --------------------------------------------------------------
        # Gated on TAKEOVER_CERT_VALIDATION_ENABLED (mirrors the CNAME toggle
        # above). Reads whatever get_cert_for returns: the 443 cert httpx
        # captured with tlsx off, plus non-HTTP-port / bare-IP certs with tlsx
        # on. A certificate answers directly two facts the module otherwise
        # reconstructs from weak signals -- and works with NO CNAME at all.
        cert_validation = bool(settings.get("TAKEOVER_CERT_VALIDATION_ENABLED", True))
        if cert_validation:
            from recon.helpers.cert_access import get_cert_for
            for n in normalized:
                host = n.get("hostname")
                if not host:
                    continue
                cert = get_cert_for(recon_data, host, 443)
                if cert is None:
                    # No certificate data collected for this host: unknown, NOT
                    # evidence of a dangling target. Leave every cert signal unset
                    # so an unprobed host is not falsely promoted.
                    continue
                if cert.get("probe_status") is False:
                    # A 443 handshake that was attempted and FAILED entirely is
                    # consistent with a dangling target (positive signal).
                    n["cert_absent"] = True
                    continue
                sans = [s for s in (cert.get("san") or []) if isinstance(s, str)]
                n["cert_issuer"] = cert.get("issuer")
                n["cert_subject_cn"] = cert.get("subject_cn")
                n["cert_sans"] = sans
                n["cert_expired"] = bool(cert.get("expired"))
                n["cert_self_signed"] = bool(cert.get("self_signed"))
                n["cert_mismatched"] = bool(cert.get("mismatched"))
                n["cert_name_match"] = _cert_names_host(host, cert.get("subject_cn"), sans)
                cert_prov = provider_from_cert(cert.get("issuer"), sans)
                if cert_prov:
                    n["cert_provider"] = cert_prov
                # Only a SAN on the provider's own edge domain says which edge
                # serves the host. An issuer says who signed the certificate
                # (Google Trust Services also signs Cloudflare's; ACM and
                # Cloudflare sign customers' own names), so it is recorded
                # above and never names, nor contradicts, the provider.
                edge_prov = provider_from_sans(sans)
                if edge_prov:
                    current = (n.get("takeover_provider") or "").lower()
                    if is_placeholder_provider(current):
                        n["takeover_provider"] = edge_prov
                    elif not same_provider_family(edge_prov, current):
                        # Same rule as the CNAME check: the edge's default
                        # certificate (*.azurewebsites.net) corroborates a
                        # generic `azure` template, it does not contradict it.
                        n["cert_provider_mismatch"] = True
                    # The edge presents its own default cert and does NOT
                    # name this host -> claimable.
                    if not n["cert_name_match"]:
                        n["cert_provider_default"] = True

        # --------------------------------------------------------------
        # 3b. AI cascade: WAF-block disambiguation
        # --------------------------------------------------------------
        # Subjack/Nuclei body fingerprints collide with WAF "no host" pages.
        # When AI is enabled, probe each finding's hostname, short-circuit on
        # third-party vendor tokens (proves the response is from the SaaS),
        # and otherwise ask the LLM to classify the body. AI verdict feeds
        # ai_waf_likely back into score_finding() which subtracts 40 points
        # so AI-flagged collisions land in manual_review.
        if ai_classifier_enabled and ai_pipeline_model:
            # The probe is a request of its own, so it goes only to a host this
            # run admitted (scope and RoE, every address). A Nuclei finding is
            # named after the URL that matched, which a followed redirect can put
            # on a host no layer was handed.
            from urllib.parse import urlsplit
            admitted = set(subdomains)
            for url in alive_urls:
                try:
                    host = (urlsplit(url).hostname or "").rstrip(".")
                except ValueError:
                    continue
                if host:
                    admitted.add(host)
            probe_able = [n for n in normalized if n.get("hostname") in admitted]
            if len(probe_able) != len(normalized):
                print(f"[-][Takeover-AI] {len(normalized) - len(probe_able)} candidate(s) on a host "
                      "this run did not admit -- not probed, their static signal stands")
            # Skip the LLM for findings the certificate already settles: a clean
            # cert naming this host proves the SaaS edge serves the legit
            # customer, so the WAF-collision question is moot. A handshake is
            # cheaper and deterministic than an LLM call.
            to_disambiguate = [
                n for n in probe_able
                if not (n.get("cert_name_match") and not (n.get("cert_expired")
                        or n.get("cert_self_signed") or n.get("cert_mismatched")))
            ]
            if to_disambiguate:
                settled = len(probe_able) - len(to_disambiguate)
                print(f"[*][Takeover-AI] Disambiguating {len(to_disambiguate)} candidate(s) via LLM cascade"
                      + (f" ({settled} settled by certificate)" if settled else ""))
                try:
                    _apply_ai_waf_disambiguation(
                        findings=to_disambiguate,
                        model=ai_pipeline_model,
                        user_id=os.environ.get("USER_ID", ""),
                        project_id=os.environ.get("PROJECT_ID", ""),
                        engine=("jev" if ai_use_jev else "llm"),
                    )
                except Exception as e:
                    # Never let AI failure abort the takeover scan -- emit warning
                    # and continue with the static findings.
                    print(f"[!][Takeover-AI] Cascade pass failed: {e}")
            elif probe_able:
                # Candidates exist but a clean certificate already settled every
                # one of them. Saying "no candidates" here would misreport a
                # working cost optimisation as an empty scan.
                print(f"[*][Takeover-AI] All {len(probe_able)} candidate(s) settled by "
                      "certificate evidence -- no LLM calls needed")
            elif not normalized:
                # Cascade is on but Subjack/Nuclei produced zero candidates,
                # so there's nothing for the LLM to classify. Log explicitly
                # so the absence of [Takeover-AI] activity is intentional,
                # not a wiring bug.
                print("[*][Takeover-AI] No takeover candidates -- cascade has nothing to classify")

        # --------------------------------------------------------------
        # 4. Dedupe + score
        # --------------------------------------------------------------
        deduped = dedupe_findings(normalized)
        scored = [
            score_finding(
                f,
                confidence_threshold=confidence_threshold,
                manual_review_auto_publish=manual_review_auto_publish,
            )
            for f in deduped
        ]

        # --------------------------------------------------------------
        # 5. Add stable ids + timestamps
        # --------------------------------------------------------------
        now_iso = datetime.now(timezone.utc).isoformat()
        for f in scored:
            f["id"] = finding_id(
                f["hostname"],
                f.get("takeover_provider") or "unknown",
                f.get("takeover_method") or "cname",
            )
            f["detected_at"] = now_iso

        # --------------------------------------------------------------
        # 6. Package results
        # --------------------------------------------------------------
        # A demoted candidate proven live and claimed (see _is_active_resource)
        # is kept in the scan output for audit, not written as a finding. A
        # dangling record (NXDOMAIN, a provider default cert, no TLS at all)
        # always stays.
        active = [f for f in scored if _is_active_resource(f, manual_review_auto_publish)]
        if active:
            print(f"[*][Takeover] {len(active)} candidate(s) are active resources "
                  f"(live CNAME, 2xx page, valid certificate for the host) -- not reported")
        scored = [f for f in scored if not _is_active_resource(f, manual_review_auto_publish)]

        by_target: dict[str, list[dict]] = {}
        by_provider: dict[str, int] = {}
        counts = {"confirmed": 0, "likely": 0, "manual_review": 0}
        for f in scored:
            host = f["hostname"]
            by_target.setdefault(host, []).append(f)
            prov = f.get("takeover_provider") or "unknown"
            by_provider[prov] = by_provider.get(prov, 0) + 1
            verdict = f.get("verdict", "manual_review")
            if verdict in counts:
                counts[verdict] += 1

        result = {
            "findings": scored,
            "by_target": by_target,
            "active_resources": [
                {k: f.get(k) for k in ("hostname", "cname_target", "takeover_provider",
                                       "sources", "confidence", "cname_provider")}
                for f in active
            ],
            "summary": {
                "total": len(scored),
                "confirmed": counts["confirmed"],
                "likely": counts["likely"],
                "manual_review": counts["manual_review"],
                "active_resources": len(active),
                "by_provider": by_provider,
            },
            "scan_metadata": {
                "subjack_enabled": subjack_enabled,
                "nuclei_takeovers_enabled": nuclei_takeovers_enabled,
                "confidence_threshold": confidence_threshold,
                "subdomains_scanned": len(subdomains),
                "alive_urls_scanned": len(alive_urls),
                "duration_sec": round(time.time() - started, 2),
                "scan_timestamp": now_iso,
            },
        }

        recon_data["subdomain_takeover"] = result
        print(
            f"[✓][Takeover] {result['summary']['total']} finding(s) -- "
            f"confirmed={counts['confirmed']} likely={counts['likely']} "
            f"manual_review={counts['manual_review']}"
        )

        if output_file:
            try:
                with open(output_file, "w") as f:
                    json.dump(recon_data, f, indent=2)
            except Exception as e:
                print(f"[!][Takeover] Failed to persist output: {e}")

        return recon_data

    finally:
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


def run_subdomain_takeover_isolated(combined_result: dict, settings: dict) -> dict:
    """
    Thread-safe isolated wrapper for GROUP 6 Phase A fan-out in recon/main.py.
    Deep-copies combined_result, runs the scan on the copy (no incremental
    file saves), and returns only the subdomain_takeover dict.
    """
    snapshot = copy.deepcopy(combined_result)
    run_subdomain_takeover(snapshot, output_file=None, settings=settings)
    return snapshot.get("subdomain_takeover", {})


# =============================================================================
# Subjack (native binary invocation)
# =============================================================================
def _run_subjack(
    subdomains: list[str],
    work_dir: Path,
    settings: dict,
) -> list[dict]:
    """
    Execute subjack as a subprocess, return parsed JSON rows.
    Only vulnerable rows are of interest but we return everything and let the
    normalizer filter -- makes testing easier.
    """
    if not shutil.which("subjack"):
        print("[!][Takeover][Subjack] binary not found in PATH -- skipping subjack layer")
        _note_layer_unchecked("Subjack", subdomains, "binary not found")
        return []

    targets_file = work_dir / "subjack_targets.txt"
    output_file = work_dir / "subjack_results.json"
    targets_file.write_text("\n".join(subdomains) + "\n", encoding="utf-8")

    cmd = build_subjack_command(
        targets_file=str(targets_file),
        output_file=str(output_file),
        threads=int(settings.get("SUBJACK_THREADS", 10)),
        timeout=int(settings.get("SUBJACK_TIMEOUT", 30)),
        ssl=bool(settings.get("SUBJACK_SSL", True)),
        all_urls=bool(settings.get("SUBJACK_ALL", False)),
        check_ns=bool(settings.get("SUBJACK_CHECK_NS", False)),
        check_ar=bool(settings.get("SUBJACK_CHECK_AR", False)),
        check_mail=bool(settings.get("SUBJACK_CHECK_MAIL", False)),
        verbose=False,
    )

    print(f"[*][Takeover][Subjack] {' '.join(cmd)}")

    # Subjack is long-running under pathological conditions -- hard cap.
    run_timeout = max(60, int(settings.get("SUBJACK_RUN_TIMEOUT", 900)))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=run_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # It never says which names it reached, so every one stays unchecked;
        # the rows it already wrote are still real findings.
        print(f"[!][Takeover][Subjack] run timed out after {run_timeout}s")
        _note_layer_unchecked("Subjack", subdomains, f"timed out after {run_timeout}s")
        return _load_subjack_json(output_file) if output_file.exists() else []
    except FileNotFoundError:
        print("[!][Takeover][Subjack] binary not available")
        _note_layer_unchecked("Subjack", subdomains, "binary not available")
        return []

    if proc.returncode not in (0, None):
        # Subjack sometimes exits non-zero when nothing is vulnerable, so the
        # exit code cannot tell a failure from a clean run -- log but continue
        stderr = (proc.stderr or "").strip()
        if stderr:
            print(f"[!][Takeover][Subjack] stderr: {stderr[:300]}")

    if not output_file.exists():
        return []

    return _load_subjack_json(output_file)


def _load_subjack_json(path: Path) -> list[dict]:
    """
    Subjack writes either a JSON array or line-delimited JSON depending on
    version. Handle both.
    """
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except Exception as e:
        print(f"[!][Takeover][Subjack] cannot read {path}: {e}")
        return []

    if not raw:
        return []

    # Try plain JSON array first
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
        except json.JSONDecodeError:
            continue
    return rows


# =============================================================================
# Nuclei takeover templates (via Docker-in-Docker, reuses nuclei image)
# =============================================================================
def _run_nuclei_takeover(urls: list[str], work_dir: Path, settings: dict) -> list[dict]:
    """
    Run nuclei with takeover templates only.

    Uses -t http/takeovers/ -t dns/ so only ~60 takeover-focused templates
    fire instead of the full community set used by vuln_scan.
    """
    if not is_docker_installed() or not is_docker_running():
        print("[!][Takeover][Nuclei] Docker unavailable -- skipping nuclei layer")
        _note_layer_unchecked("Nuclei", urls, "Docker unavailable")
        return []

    nuclei_image = settings.get("NUCLEI_DOCKER_IMAGE", "projectdiscovery/nuclei:latest")
    try:
        pull_nuclei_docker_image(nuclei_image)
    except Exception as e:
        print(f"[!][Takeover][Nuclei] image pull failed: {e}")
    try:
        ensure_templates_volume(nuclei_image, auto_update=False)
    except Exception as e:
        print(f"[!][Takeover][Nuclei] template volume ensure failed: {e}")

    targets_file = work_dir / "nuclei_takeover_targets.txt"
    output_file = work_dir / "nuclei_takeover_output.jsonl"
    targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    # Force takeover-only template dirs. The full template set is mounted at
    # /root/nuclei-templates inside the nuclei container, so relative paths
    # resolve correctly.
    # A uuid name so a timeout kills THIS container. vuln_scan's Nuclei and this
    # one start together in GROUP 6, so a pid-based name would collide.
    container_name = f"redamon-nuclei-takeover-{uuid.uuid4().hex[:12]}"
    cmd = build_nuclei_command(
        targets_file=str(targets_file),
        output_file=str(output_file),
        docker_image=nuclei_image,
        severity=settings.get("TAKEOVER_SEVERITY", ["critical", "high", "medium"]),
        templates=["http/takeovers/", "dns/"],
        rate_limit=int(settings.get("TAKEOVER_RATE_LIMIT", 50)),
        bulk_size=int(settings.get("NUCLEI_BULK_SIZE", 25)),
        concurrency=int(settings.get("NUCLEI_CONCURRENCY", 25)),
        timeout=int(settings.get("NUCLEI_TIMEOUT", 10)),
        retries=int(settings.get("NUCLEI_RETRIES", 1)),
        exclude_tags=[],  # Do NOT inherit global NUCLEI_EXCLUDE_TAGS here
        system_resolvers=bool(settings.get("NUCLEI_SYSTEM_RESOLVERS", True)),
        follow_redirects=bool(settings.get("NUCLEI_FOLLOW_REDIRECTS", True)),
        max_redirects=int(settings.get("NUCLEI_MAX_REDIRECTS", 10)),
        interactsh=False,  # Takeover templates don't need OOB interactions
        container_name=container_name,
        max_host_error=int(settings.get("NUCLEI_MAX_HOST_ERROR", 30)),
        ip_mode=bool(settings.get("IP_MODE")),
    )
    print(f"[*][Takeover][Nuclei] {' '.join(cmd)}")

    run_timeout = max(120, int(settings.get("NUCLEI_TAKEOVER_RUN_TIMEOUT", 1800)))
    try:
        proc = run_tool_container(cmd, tool="nuclei-takeover", timeout=run_timeout,
                                  name=container_name)
    except FileNotFoundError:
        print("[!][Takeover][Nuclei] docker binary missing")
        _note_layer_unchecked("Nuclei", urls, "docker binary missing")
        return []

    if proc.timed_out:
        # Stopped by its name; the JSONL it wrote before the cut is read below.
        print(f"[!][Takeover][Nuclei] run timed out after {run_timeout}s -- container stopped, "
              f"keeping its partial results")
        _note_layer_unchecked("Nuclei", urls, f"timed out after {run_timeout}s")
    elif proc.returncode not in (0, None):
        stderr = (proc.stderr or "").strip()
        if stderr:
            print(f"[!][Takeover][Nuclei] stderr: {stderr[:300]}")
        # Nuclei exits 0 whether or not a template matched: anything else is a
        # docker error, a kill or a fatal nuclei error (as vuln_scan reads it).
        _note_layer_unchecked("Nuclei", urls, f"exited {proc.returncode}")

    # Fix ownership on output so we can read it as the recon user
    try:
        fix_file_ownership(output_file)
    except Exception:
        pass
    return _load_nuclei_jsonl(output_file)


# =============================================================================
# BadDNS (AGPL-3.0 sidecar -- Docker-in-Docker, isolated image)
# =============================================================================
def _run_baddns(
    subdomains: list[str],
    work_dir: Path,
    settings: dict,
) -> list[dict]:
    """
    Run the BadDNS sidecar against the subdomain list.

    Uses Docker-in-Docker against `redamon-baddns:latest` (built separately
    by `docker compose --profile tools build baddns-scanner`). Output is
    NDJSON on stdout -- one Finding per line -- captured via subprocess and
    parsed in-memory.

    AGPL isolation: RedAmon never imports baddns; the process + filesystem
    boundary enforces the license separation.
    """
    if not is_docker_installed() or not is_docker_running():
        print("[!][Takeover][BadDNS] Docker unavailable -- skipping baddns layer")
        _note_layer_unchecked("BadDNS", subdomains, "Docker unavailable")
        return []

    baddns_image = settings.get("BADDNS_DOCKER_IMAGE", "redamon-baddns:latest")
    # Is the image present on the host? If not, skip gracefully -- build via
    # `docker compose --profile tools build baddns-scanner` first.
    try:
        inspect = subprocess.run(
            ["docker", "image", "inspect", baddns_image],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if inspect.returncode != 0:
            print(f"[!][Takeover][BadDNS] image {baddns_image} not found on host -- run `docker compose --profile tools build baddns-scanner`")
            _note_layer_unchecked("BadDNS", subdomains, "image not found")
            return []
    except Exception as e:
        print(f"[!][Takeover][BadDNS] cannot inspect image: {e}")
        _note_layer_unchecked("BadDNS", subdomains, "image inspect failed")
        return []

    targets_filename = "baddns_targets.txt"
    targets_file = work_dir / targets_filename
    targets_file.write_text("\n".join(subdomains) + "\n", encoding="utf-8")
    try:
        targets_file.chmod(0o644)
    except Exception:
        pass

    # Mount the WORK DIR (not the file) -- see build_baddns_command docstring.
    # Convert container path → host path for Docker-in-Docker. /tmp/redamon
    # paths pass through unchanged per get_host_path()'s convention.
    from recon.helpers.nuclei_helpers import get_host_path  # local import to avoid cycles
    work_dir_host = get_host_path(str(work_dir))

    modules = settings.get("BADDNS_MODULES", list(BADDNS_DEFAULT_MODULES))
    if isinstance(modules, str):
        modules = [m.strip() for m in modules.split(",") if m.strip()]

    nameservers = settings.get("BADDNS_NAMESERVERS", []) or []
    if isinstance(nameservers, str):
        nameservers = [n.strip() for n in nameservers.split(",") if n.strip()]

    # Named here (not by run_tool_container) so the printed command shows it.
    container_name = tool_container_name("baddns")
    cmd = build_baddns_command(
        work_dir_host=work_dir_host,
        targets_filename=targets_filename,
        docker_image=baddns_image,
        modules=modules,
        nameservers=nameservers,
        extra_docker_args=["--name", container_name],
    )
    print(f"[*][Takeover][BadDNS] {' '.join(cmd)}")

    run_timeout = max(120, int(settings.get("BADDNS_RUN_TIMEOUT", 1800)))
    try:
        proc = run_tool_container(cmd, tool="baddns", timeout=run_timeout, name=container_name)
    except FileNotFoundError:
        print("[!][Takeover][BadDNS] docker binary missing")
        _note_layer_unchecked("BadDNS", subdomains, "docker binary missing")
        return []

    findings = _parse_baddns_stdout(proc.stdout)
    if proc.timed_out:
        print(f"[!][Takeover][BadDNS] run timed out after {run_timeout}s -- stopped it, "
              f"keeping the {len(findings)} finding(s) it printed")
        _note_layer_unchecked("BadDNS", _baddns_unfinished_targets(subdomains, findings),
                              f"timed out after {run_timeout}s")
    elif proc.returncode != 0:
        stderr = proc.stderr.strip()
        if stderr:
            print(f"[!][Takeover][BadDNS] stderr: {stderr[:400]}")
        # The batch entrypoint ends 0 however its targets went: anything else is
        # a docker error, a kill or a refused targets file.
        _note_layer_unchecked("BadDNS", subdomains, f"exited {proc.returncode}")

    # Surface the entrypoint's summary line on stderr so orchestrator logs
    # show scanned/skipped/findings totals even on successful runs.
    stderr = proc.stderr.strip()
    if stderr:
        for summary_line in stderr.splitlines():
            if ("baddns-batch] summary:" in summary_line
                    or "] timeout after" in summary_line):
                print(f"[*][Takeover][BadDNS] {summary_line}")
    timed_out = _baddns_timed_out_targets(stderr, subdomains)
    if timed_out:
        _note_layer_unchecked("BadDNS", timed_out, "per-target timeout")

    return findings


def _baddns_unfinished_targets(subdomains: list[str], findings: list[dict]) -> list[str]:
    """The names a BadDNS run cut by its deadline may not have finished.

    The batch entrypoint checks the targets file (``subdomains``, in order) one
    name at a time and prints a name's findings only once it is done with it,
    and stdout arrives in order. So every name before the last one with a
    printed finding was finished. That one may have lost lines to the cut, and
    the names after it may never have been reached; with nothing printed, none
    is known finished. Only stdout counts: stderr may arrive out of step with it.
    """
    printed = {str(f.get("target") or "").strip().lower() for f in findings}
    frontier = max((i for i, name in enumerate(subdomains) if name.lower() in printed),
                   default=0)
    return list(subdomains[frontier:])


_BADDNS_TARGET_TIMEOUT = re.compile(r"\[baddns-batch\] timeout after \d+s on (\S+)\s*$")


def _baddns_timed_out_targets(stderr: str, subdomains: Iterable[str]) -> list[str]:
    """The names the batch entrypoint gave up on (its per-target timeout).

    Only names this run asked about count: the line is read back from a
    container's stderr.
    """
    asked = {s.lower() for s in subdomains}
    names = set()
    for line in (stderr or "").splitlines():
        match = _BADDNS_TARGET_TIMEOUT.search(line.strip())
        if match and match.group(1).lower() in asked:
            names.add(match.group(1).lower())
    return sorted(names)


def _parse_baddns_stdout(stdout: str) -> list[dict]:
    """
    Parse BadDNS stdout. Each finding is a JSON object on its own line
    (from `Finding.to_json()` + `print(...)` in baddns). Non-matching
    targets produce nothing. Malformed lines are skipped.
    """
    findings: list[dict] = []
    if not stdout:
        return findings
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                findings.append(obj)
        except json.JSONDecodeError:
            continue
    return findings


def _load_nuclei_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!][Takeover][Nuclei] cannot read {path}: {e}")
    return rows


# =============================================================================
# Target collection
# =============================================================================
def _roe_excluded_list(settings: Optional[dict]) -> list:
    settings = settings or {}
    return list(settings.get("ROE_EXCLUDED_HOSTS") or []) if settings.get("ROE_ENABLED") else []


def _collect_subdomains(recon_data: dict, settings: Optional[dict] = None) -> list[str]:
    """
    Pull every resolvable subdomain from the DNS map. We include the root
    domain too: every root of a Domain batch run (recon_data["domains"]).

    A group's recon file narrows that (§4.6): the scan root only when it is a
    target, an EXACT group's listed hosts and nothing else. IP mode's synthetic
    root is never a name to check. The RoE applies in every mode, partial runs
    (which pass a `domains` list and skip the group scope) included.
    """
    from recon.helpers.recon_scope import recon_scope
    scope = recon_scope(recon_data)
    names: set[str] = set()
    dns_data = recon_data.get("dns") or {}
    roots = recon_data.get("domains")
    if not isinstance(roots, list) or not roots:
        roots = [recon_data.get("domain") or recon_data.get("metadata", {}).get("target", "")]
    for root in roots:
        if isinstance(root, str) and root.strip():
            names.add(root.strip().lower())

    # DNS structure: dns.subdomains = { "sub.example.com": {ips: {...}, has_records: bool} }
    for name in (dns_data.get("subdomains") or {}).keys():
        if isinstance(name, str) and name.strip():
            names.add(name.strip().lower())

    # Defensive: also take the flat subdomains list when present.
    flat = recon_data.get("subdomains")
    if isinstance(flat, list):
        for n in flat:
            if isinstance(n, str) and n.strip():
                names.add(n.strip().lower())

    # Item 5: names whose urlscan deleted-service page this scan's verdict kept.
    # A name from history joins only a group that takes found names (never an
    # EXACT one) and only as a target of its scope; the RoE below applies too.
    root_names = {r.strip().lower() for r in roots if isinstance(r, str) and r.strip()}
    for host in (recon_data.get("urlscan") or {}).get("takeover_hosts") or []:
        if not isinstance(host, str) or not host.strip() or not scope.may_inject:
            continue
        h = host.strip().strip(".").lower()
        if scope.admits(h) if scope.mode else any(h.endswith("." + r) for r in root_names):
            names.add(h)

    names = {n for n in names if not n.startswith("ip-targets.")}
    if scope.mode and not isinstance(recon_data.get("domains"), list):
        if scope.exact:
            names |= set(scope.targets())
        names = {n for n in names if scope.admits(n)}
    names &= _ip_mode_selected(recon_data, names)
    excluded = _roe_excluded_list(settings)
    if excluded:
        from recon.helpers.roe_scope import _is_roe_excluded
        kept = {n for n in names if not _is_roe_excluded(n, excluded)}
        if len(kept) != len(names):
            print(f"[RoE] Takeover: skipped {len(names) - len(kept)} excluded name(s)")
        names = kept
    names = {n for n in names if n and "." in n}
    if excluded and not (recon_data.get("metadata") or {}).get("ip_mode"):
        from recon.helpers.target_admission import admission_context, admit_targets, known_addresses
        if admission_context(settings, recon_data).ip_rules:
            # Subjack and BadDNS resolve each name themselves (and the AI probe
            # fetches it), so they may land on any address it has: under RoE IP
            # or CIDR entries a name goes only when every address the run knows
            # for it is allowed, and one with no known address is refused and
            # kept as not checked (D2). IP mode keeps only names whose every
            # address is an RoE-filtered target already.
            known = known_addresses(recon_data)
            names = set(admit_targets(settings, recon_data,
                                      names={n: known.get(n, []) for n in sorted(names)},
                                      module="takeover", resolves_names=True).names)
    return list(names)


def _ip_mode_selected(recon_data: dict, names) -> set:
    """IP mode: the names the hostname rule selected (metadata.ip_mode_hosts).
    A takeover is a dangling name; an IP-mode run's labels and addresses are
    none, and a recorded name is no target (I-4). Outside IP mode: `names`."""
    metadata = recon_data.get("metadata") or {}
    if not metadata.get("ip_mode"):
        return set(names)
    return set(metadata.get("ip_mode_hosts") or {})


def _collect_alive_urls(recon_data: dict, settings: Optional[dict] = None) -> list[str]:
    """
    Pull live HTTP/HTTPS URLs produced by httpx in GROUP 4. We only probe alive
    hosts with nuclei takeover templates -- dead hosts are subjack's job.

    httpx emits its output as {"by_url": {url: url_info}, "by_host": {...}, ...}.
    A URL is "live" if httpx recorded a response with status_code < 500 (matches
    the "live_urls" counter built in http_probe.py).
    """
    urls: set[str] = set()
    http_probe = recon_data.get("http_probe") or {}

    # Primary: by_url dict keyed by full URL (populated by run_http_probe in GROUP 4)
    by_url = http_probe.get("by_url") or {}
    for url, info in by_url.items():
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        status = (info or {}).get("status_code") if isinstance(info, dict) else None
        if status is None or (isinstance(status, int) and status < 500):
            urls.add(url)

    # Secondary: by_host[host]["live_urls"] (already filtered by httpx)
    for host_info in (http_probe.get("by_host") or {}).values():
        if not isinstance(host_info, dict):
            continue
        for url in host_info.get("live_urls") or []:
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                urls.add(url)

    if (recon_data.get("metadata") or {}).get("ip_mode"):
        from urllib.parse import urlsplit
        selected = _ip_mode_selected(recon_data, ())

        def host_of(url):
            try:
                return (urlsplit(url).hostname or "").rstrip(".").lower()
            except ValueError:
                return ""

        urls = {u for u in urls if host_of(u) in selected}

    excluded = _roe_excluded_list(settings)
    if excluded:
        from recon.helpers.roe_scope import _is_roe_excluded
        urls = {u for u in urls if not _is_roe_excluded(u, excluded)}
        if not (recon_data.get("metadata") or {}).get("ip_mode"):
            from recon.helpers.target_admission import admission_context, admit_urls
            if admission_context(settings, recon_data).ip_rules:
                # Nuclei resolves each URL's host itself: the same address rule
                # as the names Subjack gets.
                urls = set(admit_urls(settings, recon_data, sorted(urls), module="takeover")[0])
    return sorted(urls)


def _lookup_cname_from_dns(dns_data: dict, hostname: str) -> Optional[str]:
    """Best-effort CNAME lookup from the existing DNS map."""
    sub_map = (dns_data or {}).get("subdomains") or {}
    entry = sub_map.get(hostname) or sub_map.get(hostname.rstrip(".")) or {}
    records = entry.get("records") or {}
    cname = records.get("CNAME") or records.get("cname")
    if isinstance(cname, list) and cname:
        return str(cname[0]).strip(".").lower() or None
    if isinstance(cname, str) and cname.strip():
        return cname.strip(".").lower()
    return None


def _probe_for_ai_disambiguation(hostname: str, timeout: int = 10):
    """
    Probe `hostname` and capture the response so the AI classifier has
    something to look at. Returns (status_code, headers_dict, body_text)
    or (None, {}, "") on any error -- callers must handle the empty
    case (no signal -> skip AI for this finding).

    Tries HTTPS first, falls back to HTTP. Caps body to 4KB (the AI helper
    re-trims to 4KB anyway, so capturing more is wasted memory).
    Catches every exception class -- a probe failure must NEVER abort the
    takeover scan.

    Judges the FIRST response and never follows a redirect: a takeover
    candidate is a host someone else may control, so its Location must not
    pick the next destination (cloud metadata, the stack's own services, an
    RoE-excluded host). A 3xx is returned as-is, Location included as data.
    """
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    schemes = ("https", "http")
    headers_base = {"User-Agent": "Mozilla/5.0 (compatible; RedAmon/4.7)"}
    for scheme in schemes:
        # The HTTP fallback is a request of its own: it takes its own RoE slot.
        request_pacer.acquire()
        try:
            r = requests.get(
                f"{scheme}://{hostname}/",
                timeout=timeout,
                allow_redirects=False,
                verify=False,
                headers=headers_base,
            )
            try:
                body = (r.text or "")[:4096]
            except Exception:
                body = ""
            return r.status_code, dict(r.headers or {}), body
        except Exception:
            # RequestException covers most network failures. Catch broader
            # to also handle SSLError-during-handshake-with-bytes-in-message,
            # MemoryError on huge responses, decoding edge cases, etc.
            continue
    return None, {}, ""


def _apply_ai_waf_disambiguation(
    findings: list[dict],
    model: str,
    user_id: str,
    project_id: str,
    engine: str = "llm",
) -> None:
    """
    For each takeover finding, probe the hostname, short-circuit on
    third-party vendor tokens, and otherwise classify the response with
    the AI. Mutates each finding in-place to add ai_waf_likely +
    ai_confidence + ai_reasoning when the AI flags a collision at
    confidence >= 70. Never raises.
    """
    from recon.helpers.ai_planner.takeover_classifier import (
        classify_takeover_response,
        has_third_party_vendor_token,
    )

    cache: dict = {}
    AI_THRESHOLD = 70

    for finding in findings:
        # Per-finding try/except: one bad probe / classification must not
        # abort the whole disambiguation pass.
        try:
            hostname = (finding.get("hostname") or "").strip()
            if not hostname:
                continue

            status, headers, body = _probe_for_ai_disambiguation(hostname)
            if status is None:
                # Probe failed (DNS/connect) -- can't classify, leave the
                # finding to the static pipeline. Most NXDOMAIN takeover
                # cases land here; that's correct behavior (no response =
                # no WAF interaction = static signal stands).
                continue

            # Short-circuit: if the response carries an unambiguous SaaS
            # vendor token, the third-party fingerprint is genuine -- skip
            # the AI call to save cost.
            if has_third_party_vendor_token(headers):
                print(f"[*][Takeover-AI] {hostname}: third-party vendor token present, skipping AI")
                continue

            result = classify_takeover_response(
                hostname=hostname,
                expected_provider=finding.get("takeover_provider") or "",
                response_text=body,
                status_code=status,
                headers=headers,
                model=model,
                cache=cache,
                user_id=user_id,
                project_id=project_id,
                engine=engine,
            )
            if result.get("source") == "ai_unavailable":
                continue
            if result.get("is_waf_block") and result.get("confidence", 0) >= AI_THRESHOLD:
                finding["ai_waf_likely"] = True
                finding["ai_confidence"] = int(result["confidence"])
                finding["ai_reasoning"] = result.get("reason") or ""
                finding["ai_engine"] = "jev" if engine == "jev" else "llm"
        except Exception as e:
            print(f"[!][Takeover-AI] disambiguation failed for {finding.get('hostname','?')}: {e}")
            continue


def _empty_result(reason: str = "") -> dict:
    return {
        "findings": [],
        "by_target": {},
        "summary": {
            "total": 0,
            "confirmed": 0,
            "likely": 0,
            "manual_review": 0,
            "by_provider": {},
        },
        "scan_metadata": {
            "skipped_reason": reason,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

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
import shutil
import subprocess
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
    subdomains = _collect_subdomains(recon_data)
    alive_urls = _collect_alive_urls(recon_data)

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

        if subjack_enabled and subdomains:
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
                print(f"[!][Takeover] Nuclei takeover scan failed: {e}")

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
                print(f"[!][Takeover] BadDNS scan failed: {e}")

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
        dns_data = recon_data.get("dns", {})
        cname_validation = bool(settings.get("TAKEOVER_CNAME_VALIDATION_ENABLED", True))
        for n in normalized:
            cname = n.get("cname_target") or _lookup_cname_from_dns(dns_data, n["hostname"])
            if not cname:
                continue
            n["cname_target"] = cname
            cname_provider = provider_from_cname(cname)
            current_provider = (n.get("takeover_provider") or "").lower()
            if current_provider in ("", "unknown", "none"):
                if cname_provider:
                    n["takeover_provider"] = cname_provider
            elif cname_provider and cname_provider != current_provider:
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
                    current = (n.get("takeover_provider") or "").lower()
                    if current in ("", "unknown", "none"):
                        n["takeover_provider"] = cert_prov
                    elif cert_prov != current:
                        n["cert_provider_mismatch"] = True
                    # The edge presents its own default cert (identifies a
                    # provider) but does NOT name this host -> claimable.
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
            # Skip the LLM for findings the certificate already settles: a clean
            # cert naming this host proves the SaaS edge serves the legit
            # customer, so the WAF-collision question is moot. A handshake is
            # cheaper and deterministic than an LLM call.
            to_disambiguate = [
                n for n in normalized
                if not (n.get("cert_name_match") and not (n.get("cert_expired")
                        or n.get("cert_self_signed") or n.get("cert_mismatched")))
            ]
            if to_disambiguate:
                settled = len(normalized) - len(to_disambiguate)
                print(f"[*][Takeover-AI] Disambiguating {len(to_disambiguate)} candidate(s) via LLM cascade"
                      + (f" ({settled} settled by certificate)" if settled else ""))
                try:
                    _apply_ai_waf_disambiguation(
                        findings=to_disambiguate,
                        model=ai_pipeline_model,
                        user_id=os.environ.get("USER_ID", ""),
                        project_id=os.environ.get("PROJECT_ID", ""),
                    )
                except Exception as e:
                    # Never let AI failure abort the takeover scan -- emit warning
                    # and continue with the static findings.
                    print(f"[!][Takeover-AI] Cascade pass failed: {e}")
            elif normalized:
                # Candidates exist but a clean certificate already settled every
                # one of them. Saying "no candidates" here would misreport a
                # working cost optimisation as an empty scan.
                print(f"[*][Takeover-AI] All {len(normalized)} candidate(s) settled by "
                      "certificate evidence -- no LLM calls needed")
            else:
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
            "summary": {
                "total": len(scored),
                "confirmed": counts["confirmed"],
                "likely": counts["likely"],
                "manual_review": counts["manual_review"],
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
        print(f"[!][Takeover][Subjack] run timed out after {run_timeout}s")
        return []
    except FileNotFoundError:
        print("[!][Takeover][Subjack] binary not available")
        return []

    if proc.returncode not in (0, None):
        # Subjack sometimes exits non-zero when nothing is vulnerable -- log but continue
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
    )
    print(f"[*][Takeover][Nuclei] {' '.join(cmd)}")

    run_timeout = max(120, int(settings.get("NUCLEI_TAKEOVER_RUN_TIMEOUT", 1800)))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=run_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[!][Takeover][Nuclei] run timed out after {run_timeout}s")
        return []
    except FileNotFoundError:
        print("[!][Takeover][Nuclei] docker binary missing")
        return []

    if proc.returncode not in (0, None):
        stderr = (proc.stderr or "").strip()
        if stderr:
            print(f"[!][Takeover][Nuclei] stderr: {stderr[:300]}")

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
            return []
    except Exception as e:
        print(f"[!][Takeover][BadDNS] cannot inspect image: {e}")
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

    # Unique container name so we can reliably `docker kill` on Python
    # timeout. Without --name, a TimeoutExpired leaves an orphan container
    # running on the host because subprocess.run kills the docker CLI but
    # the daemon-owned container keeps going.
    container_name = f"redamon-baddns-{os.getpid()}-{int(time.time())}"
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
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=run_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[!][Takeover][BadDNS] run timed out after {run_timeout}s -- killing container")
        # Reap the orphan so the host doesn't accumulate zombies
        try:
            subprocess.run(
                ["docker", "kill", container_name],
                capture_output=True, text=True, timeout=15, check=False,
            )
        except Exception as e:
            print(f"[!][Takeover][BadDNS] failed to kill orphan container: {e}")
        return []
    except FileNotFoundError:
        print("[!][Takeover][BadDNS] docker binary missing")
        return []

    if proc.returncode not in (0, None):
        stderr = (proc.stderr or "").strip()
        if stderr:
            print(f"[!][Takeover][BadDNS] stderr: {stderr[:400]}")

    # Surface the entrypoint's summary line on stderr so orchestrator logs
    # show scanned/skipped/findings totals even on successful runs.
    stderr = (proc.stderr or "").strip()
    if stderr:
        for summary_line in stderr.splitlines():
            if ("baddns-batch] summary:" in summary_line
                    or "] timeout after" in summary_line):
                print(f"[*][Takeover][BadDNS] {summary_line}")

    return _parse_baddns_stdout(proc.stdout or "")


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
def _collect_subdomains(recon_data: dict) -> list[str]:
    """
    Pull every resolvable subdomain from the DNS map. We include the root
    domain too.
    """
    names: set[str] = set()
    dns_data = recon_data.get("dns") or {}
    root = recon_data.get("domain") or recon_data.get("metadata", {}).get("target", "")
    if root:
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

    return [n for n in names if n and "." in n]


def _collect_alive_urls(recon_data: dict) -> list[str]:
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
    """
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    schemes = ("https", "http")
    headers_base = {"User-Agent": "Mozilla/5.0 (compatible; RedAmon/4.7)"}
    for scheme in schemes:
        try:
            r = requests.get(
                f"{scheme}://{hostname}/",
                timeout=timeout,
                allow_redirects=True,
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
            )
            if result.get("source") == "ai_unavailable":
                continue
            if result.get("is_waf_block") and result.get("confidence", 0) >= AI_THRESHOLD:
                finding["ai_waf_likely"] = True
                finding["ai_confidence"] = int(result["confidence"])
                finding["ai_reasoning"] = result.get("reason") or ""
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

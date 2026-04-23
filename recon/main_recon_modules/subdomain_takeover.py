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
    pull_nuclei_docker_image,
    score_finding,
)


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

    subjack_enabled = settings.get("SUBJACK_ENABLED", True)
    nuclei_takeovers_enabled = settings.get("NUCLEI_TAKEOVERS_ENABLED", True)
    confidence_threshold = int(settings.get("TAKEOVER_CONFIDENCE_THRESHOLD", 60))
    manual_review_auto_publish = bool(settings.get("TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH", False))

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
        # 3. Enrich with CNAME resolution where provider unknown
        # --------------------------------------------------------------
        dns_data = recon_data.get("dns", {})
        for n in normalized:
            if n["takeover_provider"] in ("unknown", None):
                cname = _lookup_cname_from_dns(dns_data, n["hostname"])
                if cname:
                    n["cname_target"] = n.get("cname_target") or cname
                    detected = provider_from_cname(cname)
                    if detected:
                        n["takeover_provider"] = detected

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
        use_proxy=False,
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

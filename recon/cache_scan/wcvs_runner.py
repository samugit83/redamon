"""
Cache Poisoning Scanner — WCVS breadth engine (Phase 1).

Runs Hackmanit's Web Cache Vulnerability Scanner (WCVS) docker-in-docker against
the discovered URL list and parses its JSON report into candidate findings. WCVS
gives breadth (10+ technique classes, deception, cache-buster discovery); the
RedAmon-native confirmation layer (confirm.py) then re-validates every candidate.

WCVS report schema (pkg/report.go), exact JSON tags:
  Report{ name, version, foundVulnerabilities, hasError, errorMessages, date,
          duration, command, config?, websites[] }
  ReportWebsite{ url, isVulnerable, hasError, cacheIndicator, cacheBusterFound,
                 cacheBuster, errorMessages, results[] }
  reportResult{ technique, hasError, errorMessages, isVulnerable, checks[] }
  reportCheck{ identifier, reason, reflections[]?, request{curlCommand,request,
               response}, secondRequest? }

Report file is written as `WCVS_<date>_<rand>_Report.json` in the generate path.
"""

import glob
import json
import subprocess  # noqa: F401 - the tool tests fake docker through wcvs_runner.subprocess
import uuid
from pathlib import Path

# WCVS technique tokens accepted by -skiptest (see `wcvs --help`).
_DECEPTION_TESTS = ["deception", "css"]
_DOS_TESTS = ["dos"]


def build_wcvs_command(
    targets_file: str,
    output_dir: str,
    docker_image: str,
    threads: int = 20,
    req_rate: float = 0.0,
    cache_header: str = "",
    skip_tests: list[str] | None = None,
    skip_timebased: bool = True,
) -> list[str]:
    """Build the docker-in-docker WCVS command.

    Mirrors the Nuclei/Katana pattern: --net=host (so loopback/lab targets are
    reachable), host-path-translated bind mounts, targets read-only.
    """
    from recon.helpers.nuclei_helpers import get_host_path
    targets_host_dir = get_host_path(str(Path(targets_file).parent))
    output_host_dir = get_host_path(output_dir)
    targets_name = Path(targets_file).name

    cmd = [
        "docker", "run", "--rm", "--net=host",
        "-v", f"{targets_host_dir}:/targets:ro",
        "-v", f"{output_host_dir}:/output",
        docker_image,
        "-u", f"file:/targets/{targets_name}",
        "-gr",                       # generate JSON report
        "-gp", "/output/",           # write all files here
        "-v", "1",                   # normal verbosity (0=quiet, 2=verbose)
        "-t", str(max(1, int(threads))),
    ]
    if req_rate and float(req_rate) > 0:
        cmd.extend(["-rr", str(float(req_rate))])
    if cache_header:
        cmd.extend(["-ch", cache_header])
    if skip_timebased:
        # Time-based cache detection is FP-prone; WCVS itself added this flag to
        # skip it. The native oracle (oracle.py) handles header-based detection.
        cmd.append("-stime")
    if skip_tests:
        cmd.extend(["-st", ",".join(sorted(set(skip_tests)))])
    return cmd


def safety_skip_tests(allow_deception: bool, allow_cpdos: bool) -> list[str]:
    """Build the -skiptest list that enforces the safety profile."""
    skip: list[str] = []
    if not allow_deception:
        skip.extend(_DECEPTION_TESTS)
    if not allow_cpdos:
        skip.extend(_DOS_TESTS)
    return skip


def run_wcvs(target_urls: list[str], settings: dict, work_dir: str = "/tmp/redamon/.cache_scan",
             outcome: dict | None = None) -> list[dict]:
    """Run WCVS over the target URLs and return parsed candidate findings.

    Each candidate dict: {url, technique, vector_name, reason, reflections,
    cache_indicator, cache_buster, cache_buster_found, curl_command,
    raw_request, raw_response, source="wcvs"}.

    Returns [] on any error (non-fatal — the native engine can still run its own
    hypotheses). Temp files are always cleaned up. A run that did not finish
    (a timeout, no report, an error) returns what it got, so ``outcome``, when
    given, gains ``incomplete``: a fixed phrase saying why. The caller cannot
    tell that from a clean sweep that found nothing otherwise.
    """
    outcome = outcome if outcome is not None else {}
    if not target_urls:
        return []

    from recon.cache_scan.safety import is_deception_allowed, is_cpdos_allowed

    docker_image = settings.get("WEB_CACHE_POISON_DOCKER_IMAGE", "redamon-wcvs:latest")
    threads = settings.get("WEB_CACHE_POISON_CONCURRENCY", 10)
    req_rate = settings.get("WEB_CACHE_POISON_MAX_RPS_PER_HOST", 0)
    cache_header = settings.get("WEB_CACHE_POISON_CACHE_HEADER", "") or ""
    timeout = int(settings.get("WEB_CACHE_POISON_TIMEOUT", 1800))

    skip_tests = safety_skip_tests(
        allow_deception=is_deception_allowed(settings),
        allow_cpdos=is_cpdos_allowed(settings),
    )

    run_id = uuid.uuid4().hex[:8]
    out_dir = Path(work_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    targets_file = out_dir / "targets.txt"

    try:
        targets_file.write_text("\n".join(target_urls) + "\n")

        cmd = build_wcvs_command(
            targets_file=str(targets_file),
            output_dir=str(out_dir),
            docker_image=docker_image,
            threads=threads,
            req_rate=req_rate,
            cache_header=cache_header,
            skip_tests=skip_tests,
        )

        print(f"[*][CachePoison] WCVS scanning {len(target_urls)} URL(s) "
              f"(threads={threads}, skip={skip_tests or 'none'})")
        from recon.helpers.docker_helpers import run_tool_container
        if run_tool_container(cmd, tool="wcvs", timeout=timeout).timed_out:
            # Which URLs a cut-short run finished is not known: none counts as swept.
            print(f"[!][CachePoison] WCVS timed out after {timeout}s — stopped it, "
                  f"parsing partial report")
            outcome["incomplete"] = f"timed out after {timeout}s"

        # WCVS writes WCVS_<date>_<rand>_Report.json into out_dir.
        reports = glob.glob(str(out_dir / "*_Report.json"))
        if not reports:
            print("[-][CachePoison] WCVS produced no report")
            outcome.setdefault("incomplete", "produced no report")
            return []
        from recon.helpers.docker_helpers import fix_file_ownership
        for r in reports:
            try:
                fix_file_ownership(Path(r))
            except Exception:
                pass
        candidates: list[dict] = []
        for report_path in reports:
            candidates.extend(parse_wcvs_report(report_path))
        print(f"[+][CachePoison] WCVS surfaced {len(candidates)} candidate(s)")
        return candidates
    except Exception as e:
        print(f"[!][CachePoison] WCVS run failed ({type(e).__name__})")
        outcome["incomplete"] = f"failed ({type(e).__name__})"
        return []
    finally:
        # Clean the run dir (targets + report already parsed into memory).
        try:
            for f in out_dir.glob("*"):
                f.unlink()
            out_dir.rmdir()
        except Exception:
            pass


def parse_wcvs_report(report_path: str) -> list[dict]:
    """Parse a WCVS JSON report into flat candidate dicts."""
    try:
        with open(report_path) as f:
            report = json.load(f)
    except Exception as e:
        print(f"[!][CachePoison] Could not parse WCVS report {report_path}: {e}")
        return []

    candidates: list[dict] = []
    for website in report.get("websites", []) or []:
        url = website.get("url", "")
        cache_indicator = website.get("cacheIndicator", "") or ""
        cb_found = bool(website.get("cacheBusterFound", False))
        cb_name = website.get("cacheBuster", "") or ""
        if not website.get("isVulnerable", False):
            continue
        for result in website.get("results", []) or []:
            if not result.get("isVulnerable", False):
                continue
            technique = result.get("technique", "unknown")
            for check in result.get("checks", []) or []:
                req = check.get("request", {}) or {}
                candidates.append({
                    "url": url,
                    "technique": technique,
                    "vector_name": check.get("identifier", ""),
                    "reason": check.get("reason", ""),
                    "reflections": check.get("reflections", []) or [],
                    "cache_indicator": cache_indicator,
                    "cache_buster": cb_name,
                    "cache_buster_found": cb_found,
                    "curl_command": req.get("curlCommand", ""),
                    "raw_request": req.get("request", ""),
                    "raw_response": req.get("response", ""),
                    "source": "wcvs",
                })
    return candidates

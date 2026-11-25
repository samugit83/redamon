"""
Memory calibration harness (Part 0A).

Measures REAL per-container peak memory via the Docker API and writes
`resource_profile.json` (each value = measured x (1 + MEM_SAFETY_TOLERANCE)) that
resource_governor loads INSTEAD of its built-in fallback constants. Run inside
the orchestrator container (it has the Docker SDK + reaches the orchestrator API):

    docker compose exec recon-orchestrator python3 mem_calibrate.py baseline
    docker compose exec recon-orchestrator python3 mem_calibrate.py scan <project_id> [--seconds 120]

`baseline`  measures the always-on core services -> service_baseline_bytes.
`scan`      additionally starts a real recon scan and samples the recon container
            + its sibling tool containers -> scan_job_envelope + per-tool envelopes.

The bytes-per-unit slopes (URL/JS-file/OSINT-result) need in-pipeline
instrumentation and are left at conservative documented defaults here; the
container/envelope figures — which drive admission, the startup gate, and the
hard caps — are measured.
"""

import argparse
import json
import os
import time
import urllib.request

import docker

TOLERANCE = float(os.environ.get("MEM_SAFETY_TOLERANCE", "0.25") or "0.25")
PROFILE_PATH = os.environ.get("RESOURCE_PROFILE_PATH") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource_profile.json")

# Always-on core services (container names) that make up service_baseline. The
# per-user Kali sandboxes are not among them: the ledger admits each with its own
# envelope, and their image matches no TOOL_KEYS hint, so they are never sampled.
ALWAYS_ON = [
    "redamon-neo4j", "redamon-postgres", "redamon-gvm-gvmd", "redamon-agent",
    "redamon-recon-orchestrator", "redamon-webapp", "redamon-docker-broker",
]

# Sibling tool images -> the tool key used in tool_container_envelope_bytes.
TOOL_KEYS = {
    "naabu": "naabu", "httpx": "httpx", "katana": "katana", "nuclei": "nuclei",
    "gau": "gau", "hakrawler": "hakrawler", "puredns": "puredns",
    "uncover": "uncover", "subfinder": "subfinder", "amass": "amass",
    # The DIRTY supply-chain analyzer is a sibling like any other tool, and the
    # one whose envelope three different spawn paths depend on. Without this hint
    # its figure could never be measured on a real host: a calibration run would
    # sample it and then throw the number away for want of a key.
    # Requires SUPPLY_CHAIN_RECON_ENABLED so it actually runs inside the window.
    "supply-chain-analyzer": "supply_chain_analyzer",
}

# Conservative bytes-per-unit defaults (need in-pipeline instrumentation to
# measure precisely; kept generous so the byte-budget errs safe).
DEFAULT_BYTES_PER_UNIT = {"url": 600, "js_file": 65536, "osint_result": 1024, "vhost_candidate": 256}


def _usage(container) -> int:
    try:
        s = container.stats(stream=False)
        ms = s.get("memory_stats", {}) or {}
        usage = int(ms.get("usage", 0) or 0)
        # Subtract reclaimable page cache when reported (closer to true RSS).
        cache = int((ms.get("stats", {}) or {}).get("inactive_file", 0) or 0)
        return max(0, usage - cache)
    except Exception:
        return 0


def _tool_key(image: str):
    img = (image or "").lower()
    for hint, key in TOOL_KEYS.items():
        if hint in img:
            return key
    return None


def _inflate(measured: float) -> int:
    return int(measured * (1.0 + TOLERANCE) + 0.999)


def sample(client, seconds: float, interval: float = 1.0):
    """Sample memory over `seconds`. Returns (service_peaks, tool_peaks, recon_peak,
    concurrent_scan_peak) — the last is the max observed (recon container + all its
    concurrent siblings) at any single sample, i.e. the true per-job envelope."""
    service_peaks = {n: 0 for n in ALWAYS_ON}
    tool_peaks = {}
    recon_peak = 0
    job_peak = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        recon_now = 0
        siblings_now = 0
        for c in client.containers.list():
            name = c.name
            mem = _usage(c)
            if name in service_peaks:
                service_peaks[name] = max(service_peaks[name], mem)
                continue
            if name.startswith("redamon-recon-") or name.startswith("redamon-partial-recon-"):
                recon_now += mem
                recon_peak = max(recon_peak, mem)
                continue
            tk = _tool_key(c.image.tags[0] if c.image.tags else "")
            if tk:
                tool_peaks[tk] = max(tool_peaks.get(tk, 0), mem)
                siblings_now += mem
        job_peak = max(job_peak, recon_now + siblings_now)
        time.sleep(interval)
    return service_peaks, tool_peaks, recon_peak, job_peak


def _orch(path, method="GET", body=None):
    key = os.environ.get("ORCHESTRATOR_API_KEY", "")
    url = f"http://localhost:8010{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-Orchestrator-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def load_existing():
    try:
        with open(PROFILE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def write_profile(profile):
    profile["_meta"] = {
        "tolerance": TOLERANCE,
        "note": "container/envelope values MEASURED x (1+tolerance); bytes_per_unit are conservative defaults",
    }
    with open(PROFILE_PATH, "w") as f:
        json.dump(profile, f, indent=2)
    print(f"wrote {PROFILE_PATH}")


def cmd_baseline(client, args):
    print(f"sampling {len(ALWAYS_ON)} core services for {args.seconds}s ...")
    service_peaks, _, _, _ = sample(client, args.seconds)
    baseline = sum(service_peaks.values())
    profile = load_existing()
    profile.setdefault("bytes_per_unit", DEFAULT_BYTES_PER_UNIT)
    profile["service_baseline_bytes"] = _inflate(baseline)
    profile["_measured_service_peaks_mb"] = {k: round(v / 1024 / 1024, 1) for k, v in service_peaks.items()}
    for k, v in sorted(service_peaks.items()):
        print(f"  {k:32s} {v/1024/1024:8.1f} MB")
    print(f"service_baseline (measured) = {baseline/1024**3:.2f} GB "
          f"-> stored {profile['service_baseline_bytes']/1024**3:.2f} GB (+{int(TOLERANCE*100)}%)")
    write_profile(profile)


def cmd_scan(client, args):
    # Establish baseline first, then run a real scan and sample the scan job.
    print("measuring baseline ...")
    service_peaks, _, _, _ = sample(client, min(args.seconds, 8))
    baseline = sum(service_peaks.values())

    print(f"starting recon on project {args.project_id} ...")
    proj = _orch(f"/system/stats")  # sanity: reachable
    _orch(f"/recon/{args.project_id}/start", "POST",
          {"project_id": args.project_id, "user_id": args.user_id, "webapp_api_url": "http://webapp:3000"})
    try:
        print(f"sampling scan containers for {args.seconds}s ...")
        svc2, tool_peaks, recon_peak, job_peak = sample(client, args.seconds)
    finally:
        try:
            _orch(f"/recon/{args.project_id}/stop", "POST")
            # The stop is asynchronous: the scan ends within RECON_STOP_GRACE_S.
            print("scan stopping")
        except Exception as e:
            print(f"warning: could not stop scan: {e}")

    # SAFETY: an envelope is a worst-case upper bound, but a fixed-window sample
    # only sees the phases active during it (a 90s window catches naabu, not the
    # later katana/nuclei/gau peaks). So a measurement may only RAISE an envelope
    # above the conservative built-in floor, never lower it — otherwise a partial
    # scan would produce a too-small envelope and admission would over-admit.
    import resource_governor as rg
    fb = rg._FALLBACK_PROFILE
    scan_floor = int(fb["scan_job_envelope_bytes"]["_default"])
    tool_floor = int(fb["tool_container_envelope_bytes"]["_default"])

    profile = load_existing()
    profile.setdefault("bytes_per_unit", DEFAULT_BYTES_PER_UNIT)
    profile["service_baseline_bytes"] = _inflate(baseline)
    prof_scan = profile.setdefault("scan_job_envelope_bytes", {})
    prof_scan["full_recon"] = max(_inflate(job_peak), scan_floor)
    prof_scan["_default"] = max(prof_scan.get("_default", 0), prof_scan["full_recon"])
    prof_tool = profile.setdefault("tool_container_envelope_bytes", {})
    for k, v in tool_peaks.items():
        prof_tool[k] = max(_inflate(v), tool_floor)
    prof_tool["_default"] = max(prof_tool.get("_default", 0), tool_floor)
    profile["_measured_scan_mb"] = {
        "recon_container_peak": round(recon_peak / 1024 / 1024, 1),
        "job_envelope_peak": round(job_peak / 1024 / 1024, 1),
        "tools": {k: round(v / 1024 / 1024, 1) for k, v in tool_peaks.items()},
    }
    print(f"recon container peak = {recon_peak/1024**2:.0f} MB, "
          f"job envelope peak = {job_peak/1024**2:.0f} MB (measured over the window)")
    print(f"-> scan_job_envelope stored = {prof_scan['full_recon']/1024**3:.2f} GB "
          f"(max of measured x tol and the safe floor; a fixed window under-samples peak phases)")
    for k, v in sorted(tool_peaks.items()):
        print(f"  tool {k:12s} {v/1024/1024:8.1f} MB")
    write_profile(profile)


def main():
    p = argparse.ArgumentParser(description="RedAmon memory calibration (Part 0A)")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline")
    b.add_argument("--seconds", type=float, default=10)
    s = sub.add_parser("scan")
    s.add_argument("project_id")
    s.add_argument("--user_id", default="")
    s.add_argument("--seconds", type=float, default=120)
    args = p.parse_args()

    client = docker.from_env()
    if args.cmd == "baseline":
        cmd_baseline(client, args)
    elif args.cmd == "scan":
        cmd_scan(client, args)


if __name__ == "__main__":
    main()

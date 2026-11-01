#!/usr/bin/env python3
"""Drive a full recon of the JS secret lab over MCP.

Creates an `internal` IP-mode project on .10 .11 .12 .14 (and .15 with
--with-realkeys), sets the minimal module set (naabu on 80, httpx, katana with
JS crawl, JS Recon; every AI hook, nuclei, traffic capture, supply chain and
OSINT off), starts the full pipeline and waits for it. Prints PROJECT_ID=<id>
and STARTED_AT=<UTC time> (for canary_report.py --since). No Priority Board
run unless --triage.

    ./up.sh
    python3 e2e_js_secrets.py                                   # E0/E1: a new project
    python3 e2e_js_secrets.py --rerun <id> --log recon.log      # the same project again
    python3 e2e_js_secrets.py --set '{"jsReconTrufflehogEnabled": true, "jsReconValidateKeys": false}'
    python3 e2e_js_secrets.py --with-realkeys --set '{"jsReconTrufflehogEnabled": true, "jsReconValidateKeys": true}'

The MCP token is read from the repo .env by the fp lab's mcp_client, which
never prints it.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fp_regression_target"))
import mcp_client as mcp  # noqa: E402

NET = "192.88.96"
TARGETS = [f"{NET}.{n}" for n in (10, 11, 12, 14)]
REALKEYS = f"{NET}.15"

# Every per-tool AI / Jev hook the pipeline has; aiInPipeline=false alone does
# not switch the Jev-only ones off.
AI_OFF = [
    "portScanAiPortCatalogEnabled", "masscanAiPortCatalogEnabled", "nmapAiVersionRegexEnabled",
    "httpProbeAiHeaderScanEnabled", "httpProbeAiFaviconHashEnabled", "httpProbeAiTitleDetectionEnabled",
    "httpProbeAiWappalyzerEnabled", "httpxJevPageType", "resourceEnumAiClassifierEnabled",
    "resourceEnumAiPathClassifierEnabled", "resourceEnumAiRagPathFlagEnabled",
    "resourceEnumAiParamInjectableFlagEnabled", "resourceEnumAiToolArgPathEnabled", "resourceEnumJevToolHealth",
    "domainReconAiTxtHintEnabled", "domainReconAiNsHintEnabled", "ffufAiExtensions", "ffufJevBasePaths",
    "hakrawlerJevSeedOrder", "nucleiAiTags", "nucleiAiResponseFilter", "wafAiClassifier", "takeoverAiClassifier",
    "routeExposureJevAssess", "routeExposureJevRank", "routeExposureJevWallCheck", "serializedScanJevRank",
]

SETTINGS = {
    "scanModules": ["port_scan", "http_probe", "resource_enum"],
    "stealthMode": False, "aiInPipeline": False, "triageReviewBudget": 0,
    "naabuEnabled": True, "naabuCustomPorts": "80", "naabuTopPorts": "",
    "masscanEnabled": False, "nmapEnabled": False, "bannerGrabEnabled": False,
    "httpxEnabled": True, "tlsxEnabled": False, "wappalyzerEnabled": False, "ipAttributionEnabled": False,
    "vhostSniEnabled": False, "securityCheckEnabled": False, "originDiscoveryEnabled": False,
    "aiSurfaceReconEnabled": False,
    "katanaEnabled": True, "katanaDepth": 2, "katanaJsCrawl": True,
    "hakrawlerEnabled": False, "gauEnabled": False, "ffufEnabled": False, "arjunEnabled": False,
    "kiterunnerEnabled": False, "paramspiderEnabled": False, "openapiEnabled": False,
    "zapAjaxSpiderEnabled": False, "jsluiceEnabled": False,
    "nucleiEnabled": False, "nucleiTakeoversEnabled": False, "cveLookupEnabled": False, "mitreEnabled": False,
    "subjackEnabled": False, "baddnsEnabled": False, "subdomainTakeoverEnabled": False,
    "graphqlSecurityEnabled": False, "graphqlCopEnabled": False, "routeExposureEnabled": False,
    "serializedScanEnabled": False, "captureProxyEnabled": False, "supplyChainReconEnabled": False,
    "webCachePoisonEnabled": False,
    "subdomainDiscoveryEnabled": False, "osintEnrichmentEnabled": False, "whoisEnabled": False,
    "shodanEnabled": False, "censysEnabled": False, "fofaEnabled": False, "netlasEnabled": False,
    "virusTotalEnabled": False, "zoomEyeEnabled": False, "criminalIpEnabled": False, "urlscanEnabled": False,
    "otxEnabled": False, "uncoverEnabled": False,
    "jsReconEnabled": True, "jsReconSourceMaps": True, "jsReconRegexPatterns": True,
    "jsReconMinConfidence": "low", "jsReconIncludeChunks": True, "jsReconIncludeFrameworkJs": True,
    "jsReconIncludeArchivedJs": False,
    # Key validation is per scenario (--set); endpoint probing would only add
    # lab traffic; the dependency check asks registry.npmjs.org about names.
    "jsReconValidateKeys": False, "jsReconValidateEndpoints": False, "jsReconDependencyCheck": False,
    **{k: False for k in AI_OFF},
}


def call(tool, args):
    out, err = mcp.call(tool, args)
    if err:
        raise SystemExit(f"[!] {tool} failed: {json.dumps(out)[:800]}")
    return out


def settable_keys():
    described = call("describe_recon_settings", {})
    return {s["key"] for g in described.get("groups", []) for s in g.get("settings", [])}


def lab_gate(targets):
    """Refuse to scan a lab that is not up: a dead host gives a run that looks clean."""
    for ip in targets:
        try:
            with urllib.request.urlopen(f"http://{ip}/", timeout=5) as resp:
                ok = resp.status == 200
        except OSError:
            ok = False
        if not ok:
            raise SystemExit(f"[!] http://{ip}/ does not answer: run ./up.sh first. Not scanning.")
    if not os.path.isdir(os.path.join(HERE, "generated", "ssrf-bait", "assets")):
        raise SystemExit("[!] .12 has no content (gen_lab.py ran without the canary): run ./up.sh. Not scanning.")
    print(f"[*] lab answers on {', '.join(targets)}", flush=True)


def follow_logs(project_id, path):
    name = "redamon-recon-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", project_id)
    for _ in range(90):
        if subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0:
            print(f"[*] following {name} into {path}", flush=True)
            return subprocess.Popen(["docker", "logs", "-f", name], stdout=open(path, "w"),
                                    stderr=subprocess.STDOUT)
        time.sleep(2)
    print(f"[!] container {name} never appeared: no log", flush=True)
    return None


def start_recon(project_id):
    out, err = mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
    wait_s = re.search(r"Try again in (\d+)s", json.dumps(out)) if err else None
    if wait_s:
        print(f"[*] start_recon rate-limited: waiting {wait_s.group(1)}s", flush=True)
        time.sleep(int(wait_s.group(1)) + 5)
        out, err = mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
    if err:
        raise SystemExit(f"[!] start_recon failed: {json.dumps(out)[:800]}")
    return out


def wait(tool, project_id, done, timeout, every=15):
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
        state = call(tool, {"projectId": project_id})
        view = json.dumps({k: state.get(k) for k in ("status", "phase", "currentPhase", "current_phase",
                                                     "state", "running") if k in state})
        if view != last:
            print(f"    {time.strftime('%H:%M:%S')} {tool}: {view}", flush=True)
            last = view
        if done(state):
            return state
        time.sleep(every)
    raise SystemExit(f"[!] {tool} timed out after {timeout}s")


def _finished(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "stopped", "idle", "done") and not state.get("running")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rerun", metavar="PROJECT_ID", help="scan this project again (only --set is applied)")
    ap.add_argument("--reapply", action="store_true", help="with --rerun: push the lab settings again too")
    ap.add_argument("--name", help="project name (default: 'JS secret lab <time>', or jslab-validation)")
    ap.add_argument("--set", metavar="JSON", help="extra settings, e.g. '{\"jsReconTrufflehogEnabled\": true}'")
    ap.add_argument("--with-realkeys", action="store_true", help="E3: add .15 (the real-key host) to the targets")
    ap.add_argument("--log", metavar="PATH", help="follow docker logs -f redamon-recon-<pid> into PATH")
    ap.add_argument("--triage", action="store_true", help="run the Priority Board after the recon")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    extra = json.loads(args.set) if args.set else {}
    if not isinstance(extra, dict):
        raise SystemExit("[!] --set takes a JSON object")
    targets = TARGETS + ([REALKEYS] if args.with_realkeys else [])
    lab_gate(targets)
    mcp.init()

    if args.rerun:
        project_id = args.rerun
        settings = {**(SETTINGS if args.reapply else {}), **extra}
    else:
        name = args.name or ("jslab-validation" if args.with_realkeys
                             else f"JS secret lab {time.strftime('%Y-%m-%d %H:%M:%S')}")
        out = call("create_project", {"name": name, "engagementKind": "internal", "targetIps": targets,
                                      "description": "Guinea pig: testing/guinea_pigs/js_secret_lab"})
        project_id = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
        if not project_id:
            raise SystemExit(f"[!] create_project returned no id: {json.dumps(out)[:400]}")
        print(f"[+] project {project_id} ({name}) on {', '.join(targets)}", flush=True)
        settings = {**SETTINGS, **extra}

    if settings:
        known = settable_keys()
        # A lab key the server does not know is dropped by name (one unknown key
        # refuses the whole call); a --set key is passed as given, so a setting
        # that is not deployed yet fails loudly.
        dropped = sorted(k for k in settings if k not in known and k not in extra)
        if dropped:
            print(f"[-] not settable here, left out: {', '.join(dropped)}", flush=True)
        settings = {k: v for k, v in settings.items() if k in known or k in extra}
        changed = call("update_recon_settings", {"projectId": project_id, "settings": settings})
        print(f"[*] settings ({len(settings)} fields): {json.dumps(changed)[:300]}", flush=True)
        if extra:
            print(f"[*] --set: {json.dumps(extra)}", flush=True)

    print("[*] preflight:", json.dumps(call("preflight_scope_check", {"projectId": project_id}))[:600], flush=True)
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    started = start_recon(project_id)
    print("[+] start_recon:", json.dumps(started)[:400], flush=True)
    tail = follow_logs(project_id, args.log) if args.log else None
    time.sleep(20)
    final = wait("get_recon_status", project_id, _finished, args.timeout)
    print("[+] recon finished:", json.dumps(final)[:600], flush=True)
    if tail:
        time.sleep(3)
        tail.terminate()

    if args.triage:
        out, err = mcp.call("start_triage_run", {"projectId": project_id})
        if err:
            print(f"[!] start_triage_run failed: {json.dumps(out)[:400]}", flush=True)
        else:
            time.sleep(10)
            tri = wait("get_triage_status", project_id, _finished, 1800)
            print("[+] triage finished:", json.dumps(tri)[:600], flush=True)
    print(f"STARTED_AT={started_at}")
    print(f"PROJECT_ID={project_id}")


if __name__ == "__main__":
    main()

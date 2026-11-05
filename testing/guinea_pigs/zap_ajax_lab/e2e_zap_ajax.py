#!/usr/bin/env python3
"""Run a full recon of the ZAP Ajax Spider lab over MCP and check what it did.

Creates an `internal` IP-mode project on .10 .11 .12, enables port scan (80),
httpx, katana and the ZAP Ajax Spider (every AI hook and every other module
off), starts the pipeline, watches the ZAP containers while it runs, and then
checks the result:

  memory   every ZAP container ran with --memory EXPECTED and the -Xmx sized from it
  oom      no ZAP container died with exit 137
  leftover no redamon-zap-ajax-* container exists after the run
  seeds    the log shows the seed cap (one host left uncrawled), the reflected
           payload path dropped, and the browser count reduced to what fits
  graph    the browser-only routes of .10 are Endpoint nodes; .12, which the
           cap left uncrawled, has none of them

    docker compose up -d
    python3 e2e_zap_ajax.py                     # exit 0 when every check passes

The MCP token is read from the repo .env by the fp lab's mcp_client, which
never prints it.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fp_regression_target"))
sys.path.insert(0, os.path.join(HERE, "..", "js_secret_lab"))
import mcp_client as mcp  # noqa: E402
from e2e_js_secrets import AI_OFF, call, follow_logs, settable_keys, start_recon, wait, _finished  # noqa: E402

NET = "192.88.95"
SPA, CATCHALL, SPA_B = f"{NET}.10", f"{NET}.11", f"{NET}.12"
TARGETS = [SPA, CATCHALL, SPA_B]

# Routes app.js builds at runtime: no static parser can see them.
BROWSER_ONLY = ["/api/v1/session", "/api/v1/items", "/api/v1/preferences", "/api/v1/reports/export", "/help"]

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
    "kiterunnerEnabled": False, "paramspiderEnabled": False, "openapiEnabled": False, "jsluiceEnabled": False,
    "jsReconEnabled": False,
    "nucleiEnabled": False, "nucleiTakeoversEnabled": False, "cveLookupEnabled": False, "mitreEnabled": False,
    "subjackEnabled": False, "baddnsEnabled": False, "subdomainTakeoverEnabled": False,
    "graphqlSecurityEnabled": False, "graphqlCopEnabled": False, "routeExposureEnabled": False,
    "serializedScanEnabled": False, "captureProxyEnabled": False, "supplyChainReconEnabled": False,
    "webCachePoisonEnabled": False,
    "subdomainDiscoveryEnabled": False, "osintEnrichmentEnabled": False, "whoisEnabled": False,
    "shodanEnabled": False, "censysEnabled": False, "fofaEnabled": False, "netlasEnabled": False,
    "virusTotalEnabled": False, "zoomEyeEnabled": False, "criminalIpEnabled": False, "urlscanEnabled": False,
    "otxEnabled": False, "uncoverEnabled": False,
    # ZAP: endpoint seeding so katana's catch-all links (one carrying a payload
    # in its path) become seeds; a cap of 2 over three hosts leaves .12 out;
    # three browsers cannot fit a 3 GiB container, so the run must use one.
    "zapAjaxSpiderEnabled": True, "zapAjaxSpiderSeedMode": "base_urls_and_endpoints",
    "zapAjaxSpiderMaxDuration": 1, "zapAjaxSpiderMaxCrawlDepth": 3, "zapAjaxSpiderMaxSeeds": 2,
    "zapAjaxSpiderParallelism": 2, "zapAjaxSpiderNumberOfBrowsers": 3,
    **{k: False for k in AI_OFF},
}

LOG_EXPECT = {
    "seed cap": r"\[ZAP Ajax\] Capping seeds at 2 \(\d+ dropped, 1 host\(s\) left uncrawled\)",
    "payload path dropped": r"\[ZAP Ajax\] Skipping [1-9]\d* seed URL\(s\) carrying a reflected payload inside the path",
    "browsers reduced": r"\[ZAP Ajax\] 3 browsers do not fit a [\d.]+ GiB container beside the JVM; using 1",
}


def lab_gate():
    for ip in TARGETS:
        try:
            with urllib.request.urlopen(f"http://{ip}/", timeout=5) as resp:
                ok = resp.status == 200
        except OSError:
            ok = False
        if not ok:
            raise SystemExit(f"[!] http://{ip}/ does not answer: run `docker compose up -d` first. Not scanning.")
    print(f"[*] lab answers on {', '.join(TARGETS)}", flush=True)


class ZapWatcher(threading.Thread):
    """Inspect every redamon-zap-ajax-* container while it exists."""

    def __init__(self):
        super().__init__(daemon=True)
        self.seen, self.stop = {}, threading.Event()

    def run(self):
        while not self.stop.is_set():
            names = subprocess.run(["docker", "ps", "--filter", "name=redamon-zap-ajax-", "--format", "{{.Names}}"],
                                   capture_output=True, text=True).stdout.split()
            for name in names:
                if name in self.seen:
                    continue
                out = subprocess.run(["docker", "inspect", name], capture_output=True, text=True).stdout
                try:
                    info = json.loads(out)[0]
                except (ValueError, IndexError):
                    continue
                self.seen[name] = {"memory": info["HostConfig"].get("Memory"),
                                   "xmx": next((a for a in info["Config"].get("Cmd") or [] if a.startswith("-Xmx")), None)}
                stats = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}} {{.MemPerc}}", name],
                                       capture_output=True, text=True).stdout.strip()
                self.seen[name]["stats"] = stats
                print(f"    [zap] {name}: memory={self.seen[name]['memory']} {self.seen[name]['xmx']} ({stats})", flush=True)
            self.stop.wait(3)


def query(project_id, cypher):
    out = call("query_graph", {"projectId": project_id, "cypher": cypher})
    return out.get("records", []) if isinstance(out, dict) else []


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--expect-memory", type=int, default=3 * 1024 ** 3,
                    help="the --memory every ZAP container must get (default 3 GiB)")
    ap.add_argument("--expect-xmx", default="-Xmx1264m", help="the -Xmx that memory implies for one browser")
    ap.add_argument("--log", default=os.path.join(HERE, "_out", "recon.log"))
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    lab_gate()
    mcp.init()
    name = f"ZAP Ajax lab {time.strftime('%Y-%m-%d %H:%M:%S')}"
    out = call("create_project", {"name": name, "engagementKind": "internal", "targetIps": TARGETS,
                                  "description": "Guinea pig: testing/guinea_pigs/zap_ajax_lab"})
    project_id = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
    if not project_id:
        raise SystemExit(f"[!] create_project returned no id: {json.dumps(out)[:400]}")
    print(f"[+] project {project_id} ({name})", flush=True)

    known = settable_keys()
    missing_zap = sorted(k for k in SETTINGS if k.startswith("zapAjaxSpider") and k not in known)
    if missing_zap:
        raise SystemExit(f"[!] this stack does not know {missing_zap}: deploy the ZAP settings first")
    settings = {k: v for k, v in SETTINGS.items() if k in known}
    call("update_recon_settings", {"projectId": project_id, "settings": settings})
    print(f"[*] settings applied ({len(settings)} fields)", flush=True)

    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    watcher = ZapWatcher()
    watcher.start()
    start_recon(project_id)
    tail = follow_logs(project_id, args.log)
    time.sleep(20)
    final = wait("get_recon_status", project_id, _finished, args.timeout)
    print("[+] recon finished:", json.dumps(final)[:300], flush=True)
    time.sleep(5)
    watcher.stop.set()
    if tail:
        tail.terminate()

    results = []

    def check(label, ok, detail=""):
        results.append(ok)
        print(f"  {'PASS' if ok else 'FAIL'}  {label}{(': ' + detail) if detail else ''}", flush=True)

    print("\n[*] checks", flush=True)
    status = str(final.get("status") or final.get("state") or "").lower()
    check("recon completed", status in ("completed", "done", "idle"), status)

    check("ZAP containers ran", bool(watcher.seen), f"{len(watcher.seen)} seen")
    bad_mem = {n: s for n, s in watcher.seen.items()
               if s["memory"] != args.expect_memory or s["xmx"] != args.expect_xmx}
    check("memory and heap", not bad_mem, json.dumps(bad_mem) if bad_mem else f"{args.expect_memory} / {args.expect_xmx}")

    events = subprocess.run(["docker", "events", "--since", started_at, "--until", datetime.now(timezone.utc)
                             .isoformat(timespec="seconds").replace("+00:00", "Z"), "--filter", "type=container",
                             "--filter", "event=die", "--format", "{{json .Actor.Attributes}}"],
                            capture_output=True, text=True, timeout=60).stdout.splitlines()
    zap_deaths = [json.loads(e) for e in events if '"redamon-zap-ajax-' in e]
    oom = [d for d in zap_deaths if str(d.get("exitCode")) == "137"]
    check("no exit 137", not oom, f"{len(zap_deaths)} ZAP exits, codes {sorted({d.get('exitCode') for d in zap_deaths})}")

    left = subprocess.run(["docker", "ps", "-a", "--filter", "name=redamon-zap-ajax-", "--format", "{{.Names}}"],
                          capture_output=True, text=True).stdout.split()
    check("no leftover ZAP container", not left, " ".join(left))

    log = open(args.log, errors="replace").read() if os.path.exists(args.log) else ""
    for label, pattern in LOG_EXPECT.items():
        m = re.search(pattern, log)
        check(f"log: {label}", bool(m), m.group(0) if m else "not found")

    def paths_on(ip):
        rows = query(project_id, f"MATCH (e:Endpoint) WHERE e.baseurl CONTAINS '{ip}' RETURN DISTINCT e.path AS path")
        return {r.get("path") for r in rows}

    found = [p for p in BROWSER_ONLY if p in paths_on(SPA)]
    check("browser-only routes on .10 in the graph", len(found) >= 3, f"{found} of {BROWSER_ONLY}")
    leaked = [p for p in BROWSER_ONLY if p in paths_on(SPA_B)]
    check("capped-out .12 was not crawled by ZAP", not leaked, str(leaked))

    print(f"\nPROJECT_ID={project_id}\nSTARTED_AT={started_at}\nLOG={args.log}")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()

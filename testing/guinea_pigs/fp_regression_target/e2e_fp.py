"""Drive a real full recon against the false-positive lab, entirely over MCP.

Creates an IP-mode project on the lab's targets with exactly the modules under
test, checks its scope, starts the full pipeline, waits for it, then runs the
Priority Board and waits for that. Prints PROJECT_ID=<id> for validate_e2e.py.

    cd testing/guinea_pigs/fp_regression_target
    docker compose up -d --build
    # the orchestrator must forward the Shodan stub (see README.md)
    python3 e2e_fp.py                       # new project + full run
    python3 e2e_fp.py --rerun <projectId>   # a second run on the same project
    python3 e2e_fp.py --http-layer          # the plan-03 HTTP-layer project (own hosts)
    python3 e2e_fp.py --passive-cves        # the plan-04 passive-CVE project (port scan + Shodan)
    python3 e2e_fp.py --rerun <id> --set '{"naabuCustomPorts": "80,443"}' --no-triage
    python3 e2e_fp.py --rerun <id> --shodan-state 'unavailable=192.88.94.13&hide=CVE-2019-11043'
    python3 e2e_fp.py --js-coverage         # the plan-06 JS-coverage project (.20 + the bulk host .29)
    python3 e2e_fp.py --rerun <id> --no-triage --set '{"jsReconMaxFiles": 60}' --spa-state 'hide=/js/app.min.js'
    python3 e2e_fp.py --vhost-origin        # the plan-07 vhost-naming / tlsx CDN-tag project (.31, .32)
    python3 e2e_fp.py --coverage --no-triage        # plan 09: per-host coverage (.10 .13 .20 .22 .33)
    python3 e2e_fp.py --coverage-clean --no-triage  # plan 09: JS Recon finds nothing (.34)
    python3 e2e_fp.py --ip-ownership --no-triage    # plan 11: IP attribution (.10 .31 .32) + Shodan stub
    python3 e2e_fp.py --ip-ownership-stealth --no-triage --log stealth.log   # the same, stealth mode
    python3 e2e_fp.py --ip-ownership-nwlab --no-triage   # plan 11, domain mode, nested-wildcard lab up
    python3 e2e_fp.py --trufflehog on       # the same run with JS Recon's TruffleHog engine on

Reads MCP_SERVER_TOKEN from the repo .env through the lab's mcp_client, which
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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mcp_client as mcp  # noqa: E402

NET = "192.88.94"
TARGETS = [f"{NET}.{n}" for n in (10, 11, 12, 13, 14, 15, 20)]
APEX = "fplab.test"
VHOST_NAMES = ["admin", "wiki", "dev", "staging", "jenkins", "portal-internal", "qa", "grafana", "vpn",
               "api-gateway", "kibana", "ci", "sso", "monitoring", "backoffice", "uat", "x1",
               "preprod-eu-west", "status", "mail", "intranet"]

AI_OFF = [
    "portScanAiPortCatalogEnabled", "masscanAiPortCatalogEnabled", "nmapAiVersionRegexEnabled",
    "httpProbeAiHeaderScanEnabled", "httpProbeAiFaviconHashEnabled", "httpProbeAiTitleDetectionEnabled",
    "httpProbeAiWappalyzerEnabled", "resourceEnumAiClassifierEnabled", "resourceEnumAiPathClassifierEnabled",
    "resourceEnumAiRagPathFlagEnabled", "resourceEnumAiParamInjectableFlagEnabled",
    "resourceEnumAiToolArgPathEnabled", "domainReconAiTxtHintEnabled", "domainReconAiNsHintEnabled",
    "ffufAiExtensions",
]

SETTINGS = {
    "scanModules": ["port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"],
    "naabuEnabled": True, "naabuCustomPorts": "80,443", "naabuTopPorts": "",
    "masscanEnabled": False, "nmapEnabled": False, "bannerGrabEnabled": False, "tlsxEnabled": False,
    "katanaEnabled": True, "katanaDepth": 2, "katanaJsCrawl": True,
    "hakrawlerEnabled": False, "gauEnabled": False, "ffufEnabled": False, "arjunEnabled": False,
    "jsluiceEnabled": False, "captureProxyEnabled": False,
    "nucleiEnabled": False, "securityCheckEnabled": False, "cveLookupEnabled": False, "mitreEnabled": False,
    "whoisEnabled": False, "urlscanEnabled": False, "otxEnabled": False, "subdomainDiscoveryEnabled": False,
    "aiSurfaceReconEnabled": False, "graphqlSecurityEnabled": False, "graphqlCopEnabled": False,
    "serializedScanEnabled": False, "supplyChainReconEnabled": False, "originDiscoveryEnabled": False,
    "subjackEnabled": False, "nucleiTakeoversEnabled": False, "baddnsEnabled": False,
    "scaIntelCorrelationEnabled": False,
    # Under test
    "vhostSniEnabled": True, "vhostSniTestL7": True, "vhostSniTestL4": True,
    "vhostSniUseDefaultWordlist": False, "vhostSniUseGraphCandidates": False,
    "vhostSniInjectDiscovered": False, "vhostSniBaselineSizeTolerance": 50, "vhostSniConcurrency": 8,
    "vhostSniCustomWordlist": "\n".join(f"{w}.{APEX}" for w in VHOST_NAMES),
    "jsReconEnabled": True, "jsReconSourceMaps": True, "jsReconDomSinks": True, "jsReconRegexPatterns": True,
    "jsReconValidateKeys": False, "jsReconValidateEndpoints": False, "jsReconMinConfidence": "low",
    "jsReconIncludeChunks": True, "jsReconIncludeArchivedJs": False,
    "shodanEnabled": True, "shodanHostLookup": True, "shodanPassiveCves": True,
    "shodanReverseDns": False, "shodanDomainDns": False,
    "webCachePoisonEnabled": True, "webCachePoisonScanProfile": "safe-confirm",
    # Rules-only ranking: the tiers under test come from the score model, and a
    # budget above 0 makes the UI ask for a review model first.
    "triageReviewBudget": 0,
    **{k: False for k in AI_OFF},
}


# The HTTP-layer cases (plan 03) run as their own project: the security checks
# and endpoint validation they need are off in the main one. .21 (the vendor
# host serving the SAML page .23 redirects to) stays OUTSIDE the target list.
HTTP_LAYER_TARGETS = [f"{NET}.{n}" for n in (15, 20, 22, 23, 25, 26, 27, 28)]
HTTP_LAYER_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"],
    "securityCheckEnabled": True,
    "jsReconValidateEndpoints": True,
    "vhostSniEnabled": False, "shodanEnabled": False, "webCachePoisonEnabled": False,
}


# The passive-CVE cases (plan 04) run as their own project with only the port
# scan and Shodan, so each of their reruns takes minutes. 22 is in the port list
# and closed on every lab host; .14's Shodan banner is on 22.
PASSIVE_TARGETS = [f"{NET}.{n}" for n in (10, 11, 12, 13, 14)]
PASSIVE_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan"],
    "naabuCustomPorts": "22,80,443",
    "katanaEnabled": False, "vhostSniEnabled": False, "jsReconEnabled": False,
    "webCachePoisonEnabled": False,
}
SHODAN_STUB = f"http://{NET}.30/_lab/shodan"


def _default_katana_excludes():
    """The shipped KATANA_EXCLUDE_PATTERNS (/static/, /_next/static, .min.js, ...),
    read from the recon defaults so the case runs against the real list."""
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))
    from recon.project_settings import DEFAULT_SETTINGS
    return list(DEFAULT_SETTINGS["KATANA_EXCLUDE_PATTERNS"])


# JS coverage (plan 06) runs as its own project: .20's bundles behind the
# default exclude list, and .29's 520 chunks for the file budget. JS recon is
# switched on by jsReconEnabled alone; scanModules holds no "js_recon".
JS_COVERAGE_TARGETS = [f"{NET}.{n}" for n in (20, 29)]
JS_COVERAGE_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "resource_enum"],
    "naabuCustomPorts": "80", "katanaJsCrawl": False,
    "vhostSniEnabled": False, "shodanEnabled": False, "webCachePoisonEnabled": False,
}
SPA_STATE = f"http://{NET}.20/_lab/js"


# Vhost naming and the tlsx CDN tag (plan 07) run as their own project. tlsx
# may read 443 here (it skips HTTP ports by default), so .32's Cloudflare-issued
# certificate reaches it; .31 presents the lab's ordinary certificate.
VHOST_ORIGIN_TARGETS = [f"{NET}.{n}" for n in (31, 32)]
VHOST_ORIGIN_NAMES = ["portal", "split", "admin", "dev", "qa", "status"]
VHOST_ORIGIN_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "vuln_scan"],
    "naabuCustomPorts": "443",
    "tlsxEnabled": True, "tlsxIncludeHttpPorts": True,
    "katanaEnabled": False, "jsReconEnabled": False, "shodanEnabled": False,
    "webCachePoisonEnabled": False,
    "vhostSniCustomWordlist": "\n".join(f"{w}.{APEX}" for w in VHOST_ORIGIN_NAMES),
}


# Per-host coverage (plan 09) runs as its own project: JS Recon and Nuclei both
# stamp the BaseURLs they looked at. .20 serves JavaScript, .22 none, .10 and
# .13 carry the Shodan stub's CVEs (the export/import links), and .33 answers
# 503, so no stamping module ever looks at it. Nuclei runs the info-only "tech"
# templates from the local volume: the case is that it ran, not what it found.
COVERAGE_TARGETS = [f"{NET}.{n}" for n in (10, 13, 20, 22, 33)]
COVERAGE_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "resource_enum", "vuln_scan"],
    "naabuCustomPorts": "80",
    "nucleiEnabled": True, "nucleiTags": ["tech"], "nucleiAutoUpdateTemplates": False,
    "vhostSniEnabled": False, "webCachePoisonEnabled": False,
}
# ... and a second project where JS Recon reads a host's script and finds
# nothing, for the report's "analyzed, no findings" line and the graph-loss check.
COVERAGE_CLEAN_TARGETS = [f"{NET}.34"]
COVERAGE_CLEAN_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "resource_enum"],
    "naabuCustomPorts": "80",
    "vhostSniEnabled": False, "shodanEnabled": False, "webCachePoisonEnabled": False,
}


# IP attribution (plan 11) runs as its own project: .32 behind a Cloudflare-
# issued certificate (tlsx tags it), .31 with the lab's own certificate, .10 with
# no 443. The Shodan stub gives .31 and .32 the same CVE and a PTR name each.
IP_OWNERSHIP_TARGETS = [f"{NET}.{n}" for n in (10, 31, 32)]
IP_OWNERSHIP_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe"],
    "naabuCustomPorts": "80,443",
    "tlsxEnabled": True, "tlsxIncludeHttpPorts": True,
    "katanaEnabled": False, "jsReconEnabled": False, "vhostSniEnabled": False,
    "webCachePoisonEnabled": False,
    "shodanEnabled": True, "shodanHostLookup": True, "shodanPassiveCves": True, "shodanReverseDns": True,
    "ipAttributionEnabled": True, "ipAttributionTlsMaxProbes": 500,
}


# The same step in domain mode, over the nested-wildcard lab (its own DNS):
# web1's default certificate covers nwlab.test. Shodan is on ONLY because the
# orchestrator forwards it to the stub (require_shodan_stub): a real lookup would
# send .test names and a public 6to4 address to Shodan. The other settings are
# the lab's own (nested_wildcard_lab/README.md, "Lab project settings").
NWLAB_SUBDOMAINS = ["www", "api"]
NWLAB_SETTINGS = {
    "scanModules": ["domain_discovery", "http_probe"],
    "masscanEnabled": False, "naabuEnabled": False, "purednsEnabled": False,
    "useBruteforceForSubdomains": False, "knockpyReconEnabled": False, "crtshEnabled": False,
    "hackerTargetEnabled": False, "subfinderEnabled": False, "urlscanEnabled": False, "otxEnabled": False,
    "httpxProbeTlsInfo": False, "jsReconEnabled": False, "nmapEnabled": False, "tlsxEnabled": False,
    "vhostSniEnabled": False, "nucleiEnabled": False, "securityCheckEnabled": False, "whoisEnabled": False,
    "shodanEnabled": True, "shodanHostLookup": True, "shodanReverseDns": True, "shodanDomainDns": True,
    "shodanPassiveCves": False,
    "ipAttributionEnabled": True,
    "triageReviewBudget": 0,
    **{k: False for k in AI_OFF},
}


def require_shodan_stub():
    """Refuse to run unless the orchestrator forwards Shodan to the lab stub.
    Reads only the two override names from its environment; prints no value."""
    raw = subprocess.run(["docker", "inspect", "-f", "{{json .Config.Env}}", "redamon-recon-orchestrator"],
                         capture_output=True, text=True).stdout
    env = dict(e.split("=", 1) for e in json.loads(raw or "[]") if "=" in e)
    want = {"SHODAN_API_BASE": f"http://{NET}.30", "SHODAN_INTERNETDB_BASE": f"http://{NET}.30/internetdb"}
    if any(env.get(k) != v for k, v in want.items()):
        raise SystemExit("[!] the orchestrator does not forward Shodan to the lab stub: restart it with "
                         "SHODAN_API_BASE / SHODAN_INTERNETDB_BASE (README.md, step 1). Not scanning.")
    print("[*] Shodan goes to the lab stub", flush=True)


def nwlab_routing_gate():
    """The nested lab's own gate: its prefix is public, so stop unless it routes
    through the lab bridge and the lab DNS answers."""
    route = subprocess.run(["ip", "route", "get", "192.88.99.60"], capture_output=True, text=True).stdout
    dns = subprocess.run(["resolvectl", "query", "www.nwlab.test"], capture_output=True, text=True).stdout
    if " dev br-" not in route or "192.88.99.60" not in dns:
        raise SystemExit("[!] nested-wildcard lab routing gate failed (nested_wildcard_lab/README.md). Not scanning.")
    print("[*] nested-wildcard lab routing gate ok", flush=True)


def follow_logs(project_id, path):
    """Follow the recon container's log into `path` (the stealth case reads it)."""
    name = "redamon-recon-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", project_id)
    for _ in range(90):
        if subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0:
            return subprocess.Popen(["docker", "logs", "-f", name], stdout=open(path, "w"),
                                    stderr=subprocess.STDOUT)
        time.sleep(2)
    print(f"[!] container {name} never appeared: no log", flush=True)
    return None


def spa_state(query=""):
    """Which .20 paths answer with the SPA shell for the next run ('' resets it)."""
    with urllib.request.urlopen(f"{SPA_STATE}?{query}", timeout=10) as resp:
        return json.loads(resp.read())


def shodan_state(query=""):
    """Set what the Shodan stub answers for the next lookups ('' resets it)."""
    with urllib.request.urlopen(f"{SHODAN_STUB}?{query}", timeout=10) as resp:
        return json.loads(resp.read())


def start_recon(project_id):
    """start_recon, waiting out the token's rate limit once: the passive-CVE
    project starts four runs in a row."""
    import re
    out, err = mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
    wait_s = re.search(r"Try again in (\d+)s", json.dumps(out)) if err else None
    if wait_s:
        print(f"[*] start_recon rate-limited: waiting {wait_s.group(1)}s", flush=True)
        time.sleep(int(wait_s.group(1)) + 5)
        out, err = mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
    if err:
        raise SystemExit(f"[!] start_recon failed: {json.dumps(out)[:800]}")
    return out


def call(tool, args):
    out, err = mcp.call(tool, args)
    if err:
        raise SystemExit(f"[!] {tool} failed: {json.dumps(out)[:800]}")
    return out


def reset_lab():
    """The rate-limit edge counts admin's requests and the cache holds pages:
    restart both so every run starts from the same state."""
    for name in ("redamon-fp-ratelimit", "redamon-fp-cache"):
        subprocess.run(["docker", "restart", name], check=False, capture_output=True)
    time.sleep(2)


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


def _recon_done(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "stopped", "idle") and not state.get("running")


def _triage_done(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "idle", "done") and not state.get("running")


def disposition_decide(project_id):
    """Plan 10A: a person's Real on an AWS key, a person's False positive on the
    Zapier webhook, and an external agent's false_positive review of a high DOM
    sink, all over MCP. Then validate_e2e.py --disposition decided reads what each
    did: reportable, excluded, and still a candidate (an AI review never excludes)."""
    def one(cypher):
        rows = call("query_graph", {"projectId": project_id, "cypher": cypher}).get("records", [])
        if not rows:
            raise SystemExit(f"[!] nothing matched: {cypher}")
        return rows[0]["id"]

    aws = one("MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.secret_type = 'AWS Access Key ID' "
              "RETURN s.id AS id ORDER BY s.id LIMIT 1")
    zap = one("MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.secret_type = 'Zapier Webhook' "
              "RETURN s.id AS id ORDER BY s.id LIMIT 1")
    sink = one("MATCH (f:JsReconFinding) WHERE f.finding_type = 'dom_sink' AND f.severity = 'high' "
               "RETURN f.id AS id ORDER BY f.id LIMIT 1")
    for node, status in ((aws, "confirmed"), (zap, "likely_noise")):
        out = call("set_finding_verdict", {"projectId": project_id, "nodeId": node, "status": status,
                                           "reason": "FP lab, plan 10A disposition check"})
        print(f"[+] {status} on {node}:", json.dumps(out)[:200], flush=True)
    ev = call("get_finding_evidence", {"projectId": project_id, "findingId": sink})
    quote = next((ln.strip() for ln in str(ev.get("evidence", "")).splitlines() if len(ln.strip()) > 20), "")[:200]
    out, err = mcp.call("submit_finding_review", {
        "projectId": project_id, "findingId": sink, "evidenceHash": ev.get("evidenceHash"),
        "verdict": "false_positive", "evidenceQuote": quote,
        "why": "Lab check: an agent calls this sink noise; the finding must stay a candidate."})
    if err and "triage:review" in json.dumps(out):
        # As with triage:run: the case is then not exercised, and D-08 says so.
        print("[!] this MCP token lacks the triage:review scope: no agent review was made", flush=True)
    elif err:
        raise SystemExit(f"[!] submit_finding_review failed: {json.dumps(out)[:800]}")
    else:
        print(f"[+] false_positive review on {sink}:", json.dumps(out)[:200], flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rerun", metavar="PROJECT_ID")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--no-triage", action="store_true")
    ap.add_argument("--http-layer", action="store_true",
                    help="create the plan-03 HTTP-layer project instead of the main one")
    ap.add_argument("--passive-cves", action="store_true",
                    help="create the plan-04 passive-CVE project instead of the main one")
    ap.add_argument("--set", metavar="JSON", help="settings to change before the run (update_recon_settings)")
    ap.add_argument("--shodan-state", metavar="QUERY", default="",
                    help="Shodan stub state for this run, e.g. 'unavailable=<ip>&hide=<cve>'")
    ap.add_argument("--js-coverage", action="store_true",
                    help="create the plan-06 JS-coverage project instead of the main one")
    ap.add_argument("--spa-state", metavar="QUERY", default="",
                    help="SPA (.20) state for this run, e.g. 'hide=/js/app.min.js'")
    ap.add_argument("--vhost-origin", action="store_true",
                    help="create the plan-07 vhost-naming / tlsx CDN-tag project instead of the main one")
    ap.add_argument("--coverage", action="store_true",
                    help="create the plan-09 per-host coverage project instead of the main one")
    ap.add_argument("--coverage-clean", action="store_true",
                    help="create the plan-09 project where JS Recon finds nothing")
    ap.add_argument("--disposition-decide", metavar="PROJECT_ID",
                    help="plan 10A: make three decisions on a scanned project, then exit")
    ap.add_argument("--ip-ownership", action="store_true",
                    help="create the plan-11 IP attribution project instead of the main one")
    ap.add_argument("--ip-ownership-stealth", action="store_true",
                    help="the plan-11 IP attribution project in stealth mode")
    ap.add_argument("--ip-ownership-nwlab", action="store_true",
                    help="the plan-11 IP attribution project in domain mode, over the nested-wildcard lab")
    ap.add_argument("--log", metavar="PATH", help="follow the recon container's log into PATH")
    ap.add_argument("--trufflehog", choices=("on", "off"),
                    help="set jsReconTrufflehogEnabled for this run (JS Recon's TruffleHog engine)")
    args = ap.parse_args()

    mcp.init()
    if args.disposition_decide:
        disposition_decide(args.disposition_decide)
        return
    if args.ip_ownership or args.ip_ownership_stealth or args.ip_ownership_nwlab:
        require_shodan_stub()
    if args.ip_ownership_nwlab:
        nwlab_routing_gate()
    reset_lab()
    if args.rerun:
        project_id = args.rerun
    else:
        kind = (" (HTTP layer)" if args.http_layer else " (passive CVEs)" if args.passive_cves else
                " (JS coverage)" if args.js_coverage else " (vhost and CDN tag)" if args.vhost_origin else
                " (host coverage)" if args.coverage else " (host coverage, clean)" if args.coverage_clean
                else " (IP ownership, stealth)" if args.ip_ownership_stealth
                else " (IP ownership)" if args.ip_ownership else "")
        targets, settings = ((HTTP_LAYER_TARGETS, HTTP_LAYER_SETTINGS) if args.http_layer else
                             (PASSIVE_TARGETS, PASSIVE_SETTINGS) if args.passive_cves else
                             (JS_COVERAGE_TARGETS, {**JS_COVERAGE_SETTINGS,
                                                    "katanaExcludePatterns": _default_katana_excludes()})
                             if args.js_coverage else
                             (VHOST_ORIGIN_TARGETS, VHOST_ORIGIN_SETTINGS) if args.vhost_origin else
                             (COVERAGE_TARGETS, COVERAGE_SETTINGS) if args.coverage else
                             (COVERAGE_CLEAN_TARGETS, COVERAGE_CLEAN_SETTINGS) if args.coverage_clean else
                             (IP_OWNERSHIP_TARGETS, {**IP_OWNERSHIP_SETTINGS, "stealthMode": True})
                             if args.ip_ownership_stealth else
                             (IP_OWNERSHIP_TARGETS, IP_OWNERSHIP_SETTINGS) if args.ip_ownership else
                             (TARGETS, SETTINGS))
        name = f"FP regression lab{kind} {time.strftime('%Y-%m-%d %H:%M:%S')}"
        if args.ip_ownership_nwlab:
            name = f"FP regression lab (IP ownership, nwlab domain mode) {time.strftime('%Y-%m-%d %H:%M:%S')}"
            target = {"targetDomain": "nwlab.test", "subdomainList": NWLAB_SUBDOMAINS, "settings": NWLAB_SETTINGS}
        else:
            target = {"targetIps": targets, "settings": settings}
        out = call("create_project", {"name": name, "engagementKind": "internal",
                                      "description": "Guinea pig: testing/guinea_pigs/fp_regression_target",
                                      **target})
        project_id = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
        print(f"[+] project {project_id} ({name})", flush=True)
    extra = json.loads(args.set) if args.set else {}
    if args.trufflehog:
        extra["jsReconTrufflehogEnabled"] = args.trufflehog == "on"
    if extra:
        changed = call("update_recon_settings", {"projectId": project_id, "settings": extra})
        print("[*] settings:", json.dumps(changed)[:300], flush=True)
    print("[*] Shodan stub:", json.dumps(shodan_state(args.shodan_state)), flush=True)
    print("[*] SPA state:", json.dumps(spa_state(args.spa_state)), flush=True)
    try:
        print("[*] preflight:", json.dumps(call("preflight_scope_check", {"projectId": project_id}))[:600],
              flush=True)
        started = start_recon(project_id)
        print("[+] start_recon:", json.dumps(started)[:400], flush=True)
        tail = follow_logs(project_id, args.log) if args.log else None
        time.sleep(20)
        final = wait("get_recon_status", project_id, _recon_done, args.timeout)
        print("[+] recon finished:", json.dumps(final)[:600], flush=True)
        if tail:
            time.sleep(3)
            tail.terminate()
    finally:
        if args.shodan_state:
            shodan_state("")
        if args.spa_state:
            spa_state("")
    if not args.no_triage:
        out, err = mcp.call("start_triage_run", {"projectId": project_id})
        if err and "triage:run" in json.dumps(out):
            # A token minted without this scope can still drive the recon; the
            # Priority Board is then started from the UI (or a token with the scope).
            print("[!] this MCP token lacks the triage:run scope: start the Priority Board "
                  "run from the UI, then run validate_e2e.py", flush=True)
        elif err:
            raise SystemExit(f"[!] start_triage_run failed: {json.dumps(out)[:800]}")
        else:
            print("[*] start_triage_run:", json.dumps(out)[:400], flush=True)
            time.sleep(10)
            tri = wait("get_triage_status", project_id, _triage_done, 1800)
            print("[+] triage finished:", json.dumps(tri)[:600], flush=True)
    print(f"PROJECT_ID={project_id}")


if __name__ == "__main__":
    main()

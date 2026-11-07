#!/usr/bin/env python3
"""Drive the urlscan lab's runs (plan §10.6): projects over MCP, partial runs over the webapp.

    python3 run_lab.py --plan                          # every run, its project and settings; contacts nothing
    python3 run_lab.py --prepare --schedules-paused    # refuse if another project scans; create the projects
    python3 run_lab.py --run all --schedules-paused    # A, P, A2, A-429, A-budget, the variants, A-off, I, unlisted
    python3 run_lab.py --run B --schedules-paused      # keyed run: Global Settings urlscan key = lab-key first
    python3 run_lab.py --run T --schedules-paused      # after UL_TAKEOVER_DNS=1 ./up.sh
    python3 run_lab.py --run baseline --schedules-paused    # step 0: A on HEAD, kept for D-01
    python3 run_lab.py --collect baseline-after        # after ./redamon.sh update: re-read the baseline graph

Before --run, restart the orchestrator with the three lab hooks and the ids
--prepare printed (README "Run it"); every run checks them first, plus the
route to the lab bridge, the lab DNS, the fake urlscan, the urlscan key state
of the account, and that no other project is scanning.

Projects are named uslab-<project>-<date> and created by the MCP token's owner;
the lab never edits or deletes a project it did not create. After each run
the fake urlscan's log, the hosts' hit logs, the scan container's log and the
lab-hook names on the scan container are saved in generated/runs/<run>/, and
the graph-side checks of expected_results.yaml are frozen there
(validate_urlscan_lab.collect). Credentials are read from .env by name
(fp_regression_target/mcp_client.py, labkit.Webapp) and never printed.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import labkit  # noqa: E402

FAKE_BASE = "http://192.88.97.30/api/v1"
EDGE_PREFIX = "192.88.97.40/32"
MAIN_QUERY = r"^page\.domain:uslab\.test( |$)"
PROJECTS_FILE = labkit.GEN / "projects.json"
BUSY = {"running", "starting", "queued", "pending", "stopping", "in_progress"}

# Every per-tool AI / Jev hook (js_secret_lab's list): aiInPipeline=false alone
# does not switch the Jev-only ones off.
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

# The only external API a run may reach is the fake urlscan: every internet
# source off (nested_wildcard_lab's offline set, plus the ones run A turns on).
OFFLINE = {
    "masscanEnabled": False,          # raw frames ignore the route to the lab bridge: never on here
    "purednsEnabled": False, "useBruteforceForSubdomains": False, "knockpyReconEnabled": False,
    "amassEnabled": False, "crtshEnabled": False, "hackerTargetEnabled": False, "subfinderEnabled": False,
    "shodanEnabled": False, "otxEnabled": False, "censysEnabled": False, "fofaEnabled": False,
    "netlasEnabled": False, "virusTotalEnabled": False, "zoomEyeEnabled": False, "criminalIpEnabled": False,
    "uncoverEnabled": False, "osintEnrichmentEnabled": False, "whoisEnabled": False,
    "gauEnabled": False, "paramspiderEnabled": False, "cveLookupEnabled": False, "mitreEnabled": False,
    "nucleiInteractsh": False, "nucleiAutoUpdateTemplates": False, "wappalyzerAutoUpdate": False,
    "baddnsEnabled": False, "captureProxyEnabled": False, "supplyChainReconEnabled": False,
    "aiSurfaceReconEnabled": False, "vhostSniEnabled": False, "webCachePoisonEnabled": False,
    "httpxProbeTlsInfo": False, "jsReconDependencyCheck": False, "jsReconValidateKeys": False,
    "jsReconValidateEndpoints": False, "aiInPipeline": False, "triageReviewBudget": 0, "stealthMode": False,
    **{k: False for k in AI_OFF},
}

# Run A: every module that turns a stored URL into a request, at its most aggressive.
MODULES = {
    "urlscanEnabled": True, "urlscanMaxResults": 1000,
    "naabuEnabled": True, "naabuCustomPorts": "80,443", "naabuTopPorts": "",
    "httpxEnabled": True, "katanaEnabled": True, "openapiEnabled": True, "openapiAutoDiscover": False,
    # The DAST pass (which builds URLs from stored endpoints, the risk the S/B
    # rows guard) ignores tags by design; "tech" only shrinks the detection
    # pass, whose 5,224 templates over ~260 lab URLs took about 5 hours.
    "nucleiEnabled": True, "nucleiDastMode": True, "nucleiTags": ["tech"],
    "securityCheckEnabled": True, "routeExposureEnabled": True,
    "subdomainTakeoverEnabled": True, "subjackEnabled": True, "nucleiTakeoversEnabled": True,
    "originDiscoveryEnabled": True, "originDiscoveryKeyless": False, "originDiscoveryScanners": False,
    "originDiscoveryPassiveDns": False, "jsReconEnabled": True,
    "roeEnabled": True, "roeExcludedHosts": ["excluded.uslab.test"],
}

# The plan's new switches (items 1-5, 7, F3). A key the deployed registry does
# not know yet is left out by name, so the same script runs on HEAD.
NEW_SWITCHES = {
    "urlscanRedirectSearch": True, "urlscanLeakedLinks": True, "urlscanSecretsInUrls": True,
    "urlscanSensitiveFiles": True, "urlscanDocumentLinks": True, "urlscanTakeoverPages": True,
    "urlscanProblemPages": True, "originDiscoveryUrlscan": True,
    "securityCheckOpenConsoles": True, "securityCheckDebugPages": True,
    "securityCheckUnfinishedInstallers": True, "securityCheckDevServers": True,
    "securityCheckDirectoryListing": True, "securityCheckDefacedPages": True,
    "securityCheckTakeoverErrorPages": True, "securityCheckTestCertificates": True,
}
NEW_LIMITS = {"urlscanMaxSearches": 60}


@dataclass
class Run:
    project: str
    kind: str = "full"                          # full | partial | collect | baseline
    settings: dict = field(default_factory=dict)
    fail: dict | None = None                    # a /__lab/fail rule installed before the run
    key: str = "none"                           # the account's urlscan key state the run needs
    triage: bool = False
    note: str = ""


# A variant checks one or two urlscan rows and none of them reads nuclei, whose
# DAST pass is most of a run's time (about 1.5 h on the lab). The vulnerability
# scan module still runs with it off: the Security Checks need nothing else.
NO_NUCLEI = {"nucleiEnabled": False}

RUNS = {
    "baseline": Run("baseline", kind="baseline", settings=NO_NUCLEI,
                    note="step 0: A on the hooks commit's code, kept for L-03 and D-01"),
    "A": Run("A", triage=True, note="no key, every switch on, DAST on"),
    "P": Run("A", kind="partial", note="partial runs on project A"),
    "A2": Run("A", settings=NO_NUCLEI, note="A again in the same project (S-08)"),
    "A-429": Run("A", settings=NO_NUCLEI, fail={"query_regex": MAIN_QUERY, "status": 429, "times": 1000},
                 note="the main search rate-limited (S-09)"),
    "A-budget": Run("A", settings={**NO_NUCLEI, "urlscanMaxSearches": 2}, note="a search budget of 2 (S-11)"),
    "A-p2": Run("A-p2", settings=NO_NUCLEI, note="A in a second project (S-08)"),
    "A-429p2": Run("A-429p2", settings=NO_NUCLEI, fail={"query_regex": MAIN_QUERY, "status": 429, "times": 1000, "search_after": True},
                   note="429 on page 2 of the main search (B29)"),
    "A-400": Run("A-400", settings=NO_NUCLEI, fail={"query_regex": MAIN_QUERY, "status": 400, "times": 1000},
                 note="the main search refused (I1-05)"),
    "A-nohttpx": Run("A-nohttpx", settings={**NO_NUCLEI, "httpxEnabled": False}, note="httpx off (S-10, B14)"),
    "A-openapi": Run("A-openapi", settings={**NO_NUCLEI, "openapiAutoDiscover": True},
                     note="OpenAPI auto-discover (I4-03)"),
    "A-noorigin": Run("A-noorigin", settings={**NO_NUCLEI, "originDiscoveryUrlscan": False},
                      note="only ORIGIN_DISCOVERY_URLSCAN off (I7-07)"),
    "A-off": Run("A-off", settings={**NO_NUCLEI, **{k: False for k in NEW_SWITCHES}, "urlscanEnabled": False},
                 note="every new switch off and URLScan off"),
    "I": Run("I", settings=NO_NUCLEI, note="IP mode over 192.88.97.10"),
    "unlisted": Run("unlisted", settings=NO_NUCLEI, note="NOT in REDAMON_LAB_PROJECT_IDS (L-04)"),
    "T": Run("T", settings=NO_NUCLEI, note="takeover DNS (UL_TAKEOVER_DNS=1 ./up.sh)"),
    "B": Run("B", key="lab", note="keyed: the account's urlscan key is lab-key"),
    "baseline-after": Run("baseline", kind="collect", note="after ./redamon.sh update (D-01)"),
}
ALL = ["A", "P", "A2", "A-429", "A-budget", "A-p2", "A-429p2", "A-400", "A-nohttpx", "A-openapi",
       "A-noorigin", "A-off", "I", "unlisted"]
PARTIAL_TOOLS = [
    ("Urlscan", None), ("Httpx", None), ("Nuclei", None), ("SecurityChecks", None),
    ("RouteExposure", None), ("OriginDiscovery", {"subdomains": ["www.uslab.test"]}), ("JsRecon", None),
]


# --------------------------------------------------------------------------- helpers

def mcp_call(tool: str, args: dict, *, fatal: bool = True):
    import importlib
    sys.path.insert(0, str(labkit.HERE.parent / "fp_regression_target"))
    mcp = importlib.import_module("mcp_client")  # reads MCP_SERVER_TOKEN from .env by name
    if not getattr(mcp_call, "ready", False):
        mcp.init()
        mcp_call.ready = True
    for _ in range(10):
        try:
            out, err = mcp.call(tool, args)
        except RuntimeError as e:
            # A JSON-RPC error (an unknown tool on an older deployment, a scope error).
            out, err = {"error": str(e)[:300]}, True
        except (OSError, http.client.HTTPException) as e:
            # The webapp restarting, or a dropped connection: wait and ask again,
            # with a new MCP session.
            print(f"[*] {tool}: {type(e).__name__}, retrying", flush=True)
            time.sleep(15)
            try:
                mcp.SESSION["id"] = None
                mcp.init()
            except (OSError, http.client.HTTPException, RuntimeError):
                pass
            out, err = {"error": f"{type(e).__name__}: Try again in 1s"}, True
        # The token's rate limit says how long to wait: a lab window makes many calls.
        wait = re.search(r"Try again in (\d+)s", json.dumps(out)) if err else None
        if not wait:
            break
        print(f"[*] {tool} rate-limited, waiting {wait.group(1)}s", flush=True)
        time.sleep(int(wait.group(1)) + 2)
    if err and fatal:
        raise SystemExit(f"[!] {tool} failed: {json.dumps(out)[:600]}")
    return out, err


def load_projects() -> dict:
    return json.loads(PROJECTS_FILE.read_text()) if PROJECTS_FILE.is_file() else {}


def project_id(key: str) -> str:
    entry = load_projects().get(key)
    if not entry:
        raise SystemExit(f"[!] no project for {key!r} in {PROJECTS_FILE}: run --prepare first")
    return labkit.check_pid(entry["id"])


def lab_ids() -> list[str]:
    return [p["id"] for k, p in load_projects().items() if k != "unlisted"]


def settings_for(run: Run, known: dict) -> tuple[dict, list[str]]:
    """The run's settings, limited to keys this deployment knows. Every boolean
    securityCheck* is on: "Security Checks (all)"."""
    wanted = {**OFFLINE, **MODULES, **NEW_SWITCHES, **NEW_LIMITS}
    for key, meta in known.items():
        if key.startswith("securityCheck") and meta.get("bool"):
            wanted[key] = True
    wanted.update(run.settings)
    dropped = sorted(k for k in wanted if k not in known)
    return {k: v for k, v in wanted.items() if k in known}, dropped


def describe_settings() -> dict:
    described, _ = mcp_call("describe_recon_settings", {})
    known = {}
    for group in (described or {}).get("groups", []):
        for s in group.get("settings", []):
            known[s["key"]] = {"bool": str(s.get("kind") or "").lower() == "boolean"}
    return known


def run_cmd(*cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True)


# --------------------------------------------------------------------------- gates

def gate_lab(run_name: str) -> None:
    route = run_cmd("ip", "route", "get", "192.88.97.10").stdout
    if " dev br-" not in route:
        raise SystemExit(f"[!] 192.88.97.10 does not route through a docker bridge ({route.strip()!r}): "
                         "the lab is down and the prefix would reach the internet. Not scanning.")
    dns = run_cmd("resolvectl", "query", "app.uslab.test")
    if dns.returncode != 0 or "192.88.97.10" not in dns.stdout:
        raise SystemExit("[!] app.uslab.test does not resolve through the host: run ./host_dns_enable.sh")
    try:
        health = labkit.fake("GET", "/__lab/health")
    except OSError as e:
        raise SystemExit(f"[!] the fake urlscan does not answer ({e}): run ./up.sh") from None
    if not health.get("visits"):
        raise SystemExit("[!] the fake urlscan has no visits")
    if run_name == "T":
        tk = run_cmd("resolvectl", "query", "brokenapp.herokuapp.com")
        if "192.88.97.10" not in tk.stdout:
            raise SystemExit("[!] run T needs the takeover DNS: UL_TAKEOVER_DNS=1 ./up.sh")


def gate_hooks(run_name: str, pid: str) -> None:
    hooks = labkit.orchestrator_hooks()
    if hooks.get("URLSCAN_API_BASE") != FAKE_BASE:
        raise SystemExit(f"[!] the orchestrator's URLSCAN_API_BASE is not {FAKE_BASE}: restart it with the "
                         "hooks (README, Run it)")
    if EDGE_PREFIX not in hooks.get("REDAMON_LAB_CDN_PREFIXES", ""):
        raise SystemExit(f"[!] the orchestrator's REDAMON_LAB_CDN_PREFIXES lacks {EDGE_PREFIX}")
    listed = {p.strip() for p in hooks.get("REDAMON_LAB_PROJECT_IDS", "").split(",") if p.strip()}
    if run_name == "unlisted":
        if pid in listed:
            raise SystemExit("[!] the unlisted project is in REDAMON_LAB_PROJECT_IDS: remove it")
    elif pid not in listed:
        raise SystemExit(f"[!] project {pid} is not in REDAMON_LAB_PROJECT_IDS: restart the orchestrator "
                         "with the ids --prepare printed")


def urlscan_key_state(web: labkit.Webapp) -> str:
    """none | lab | other, read from the masked Global Settings (last 4 characters
    at most): a real urlscan key is a UUID, which never ends in "-key"."""
    status, me = web.call("GET", "/api/auth/me")
    if status != 200 or not me.get("id"):
        raise SystemExit(f"[!] /api/auth/me answered {status}")
    status, settings = web.call("GET", f"/api/users/{me['id']}/settings")
    if status != 200:
        raise SystemExit(f"[!] /api/users/<id>/settings answered {status}")
    masked = str(settings.get("urlscanApiKey") or "")
    extra = int(((settings.get("rotationConfigs") or {}).get("urlscan") or {}).get("extraKeyCount") or 0)
    if extra:
        return "other"
    if not masked:
        return "none"
    return "lab" if masked.endswith("-key") else "other"


def gate_key(run: Run, run_name: str, web: labkit.Webapp) -> None:
    state = urlscan_key_state(web)
    if state == run.key:
        return
    if run.key == "lab":
        raise SystemExit("[!] run B needs the urlscan key in Global Settings set to `lab-key` (no extra "
                         "rotation keys). Set it, run B alone, then clear it again.")
    raise SystemExit(f"[!] run {run_name} needs NO urlscan key in Global Settings (found: {state}). "
                     "Whatever key is set is sent to the fake urlscan: clear it for the lab window.")


def gate_idle(own: set[str]) -> None:
    listed, _ = mcp_call("list_projects", {})
    projects = listed.get("projects", listed) if isinstance(listed, dict) else listed
    busy = []
    for p in projects or []:
        pid = p.get("id") if isinstance(p, dict) else None
        if not pid or pid in own:
            continue
        for tool in ("get_recon_status", "get_scan_status"):
            out, err = mcp_call(tool, {"projectId": pid}, fatal=False)
            if err or not isinstance(out, dict):
                continue
            if str(out.get("status") or out.get("state") or "").lower() in BUSY or out.get("running"):
                busy.append(p.get("name") or pid)
                break
    if busy:
        raise SystemExit(f"[!] {len(busy)} other project(s) have a scan running or queued: "
                         f"{', '.join(busy[:5])}. The lab hooks must not overlap them; try later.")


# --------------------------------------------------------------------------- prepare

def prepare(keys: list[str]) -> None:
    meta = labkit.lab_meta()
    gate_idle(set(lab_ids()))
    projects = load_projects()
    date = time.strftime("%Y-%m-%d")
    seeds = meta["seed_hosts"]
    for key in keys:
        if key in projects:
            print(f"[=] {key}: {projects[key]['id']} (exists)")
            continue
        args = {"name": f"uslab-{key}-{date}", "engagementKind": "internal",
                "description": "Guinea pig: testing/guinea_pigs/urlscan_lab (plan §10)",
                "idempotencyKey": f"urlscan-lab-{key}-{date}"}
        if key == "I":
            args["targetIps"] = [meta["ips"]["web"]]
        else:
            hosts = ["*.uslab.test", "uslab.test", *seeds]
            if key == "T":
                hosts += meta["takeover_hosts"]
            args["domainBatchHosts"] = hosts
        out, _ = mcp_call("create_project", args)
        pid = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
        if not pid:
            raise SystemExit(f"[!] create_project returned no id for {key}")
        projects[key] = {"id": labkit.check_pid(pid), "name": args["name"], "created_at": int(time.time())}
        PROJECTS_FILE.write_text(json.dumps(projects, indent=1))
        print(f"[+] {key}: {pid}")
    ids = ",".join(p["id"] for k, p in projects.items() if k != "unlisted")
    print("\nRestart the orchestrator with the lab hooks (from the repository root):\n")
    print(f"  URLSCAN_API_BASE={FAKE_BASE} REDAMON_LAB_CDN_PREFIXES={EDGE_PREFIX} \\\n"
          f"  REDAMON_LAB_PROJECT_IDS={ids} \\\n"
          "    docker compose up -d --no-deps recon-orchestrator\n")
    print("Pause any scheduled scan of other projects for the lab window.")


# --------------------------------------------------------------------------- runs

def truncate_hits() -> None:
    for name in labkit.CONTAINERS:
        out = run_cmd("docker", "exec", name, "sh", "-c", ": > /logs/hits.jsonl")
        if out.returncode != 0:
            raise SystemExit(f"[!] cannot truncate {name}'s hit log: is the lab up?")


def save_logs(dest: Path) -> None:
    (dest / "hits").mkdir(parents=True, exist_ok=True)
    for name in labkit.CONTAINERS:
        src = labkit.GEN / "logs" / name / "hits.jsonl"
        if src.is_file():
            shutil.copyfile(src, dest / "hits" / f"{name}.jsonl")
    (dest / "urlscan_log.json").write_text(json.dumps(labkit.fake("GET", "/__lab/log"), indent=1))


def follow(container: str, log_path: Path, env_path: Path, wait_s: int = 180) -> subprocess.Popen | None:
    """Stream the scan container's log and record which lab hooks it carries
    (names only; L-04 reads them)."""
    for _ in range(wait_s // 2):
        hooks = labkit.container_hook_names(container)
        if hooks is not None:
            env_path.write_text(json.dumps({"container": container, "hooks": hooks}))
            return subprocess.Popen(["docker", "logs", "-f", container], stdout=log_path.open("w"),
                                    stderr=subprocess.STDOUT)
        time.sleep(2)
    print(f"[!] {container} never appeared: no log, no container_env.json")
    return None


def write_run(dest: Path, **info) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / "run.json"
    current = json.loads(path.read_text()) if path.is_file() else {}
    current.update(info)
    path.write_text(json.dumps(current, indent=1))


def wait_mcp(tool: str, pid: str, timeout: int, every: int = 20) -> dict:
    started = time.time()
    deadline, last, seen_busy = started + timeout, None, False
    time.sleep(every)
    while time.time() < deadline:
        state, err = mcp_call(tool, {"projectId": pid}, fatal=False)
        state = state if isinstance(state, dict) else {}
        status = str(state.get("status") or state.get("state") or "").lower()
        busy = status in BUSY or bool(state.get("running"))
        seen_busy |= busy
        view = f"{status} phase={state.get('currentPhase') or state.get('phase')}"
        if view != last:
            print(f"    {time.strftime('%H:%M:%S')} {tool}: {view}", flush=True)
            last = view
        # An idle answer before the job was ever seen running is the state from
        # before the start, not its end; give the start two minutes to show.
        if not err and status and not busy and (seen_busy or time.time() - started > 120):
            return state
        time.sleep(every)
    raise SystemExit(f"[!] {tool} still running after {timeout}s")


_TRIAGE_START = r"""
import json, os, sys, urllib.request, urllib.error
body = json.dumps({"user_id": sys.argv[1], "project_id": sys.argv[2], "trigger": "app"}).encode()
req = urllib.request.Request("http://localhost:8080/triage/runs", data=body, method="POST",
    headers={"Content-Type": "application/json", "x-internal-key": os.environ.get("INTERNAL_API_KEY", "")})
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read() or b"{}")}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "body": e.read().decode("utf-8", "replace")[:300]}))
"""


def start_triage_in_app(pid: str):
    """Start the triage run the way the app does (trigger 'app'), for a token
    without the opt-in triage:run scope. The request is made inside the agent
    container, so its internal key is read there and never reaches this process."""
    user_id = project_owner(pid)
    if not user_id:
        return {"error": "the project's owner could not be read"}, True
    out = run_cmd("docker", "exec", "redamon-agent", "python", "-c", _TRIAGE_START, user_id, pid)
    try:
        answer = json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (out.stderr or out.stdout).strip()[:300]}, True
    print(f"[*] triage started in the app channel: {json.dumps(answer)[:200]}", flush=True)
    return answer, not 200 <= int(answer.get("status") or 0) < 300


def wait_triage(pid: str, timeout: int, every: int = 15, run_id: str | None = None) -> dict:
    """get_triage_status names a live run in `liveRun` and has no top-level status.
    With `run_id`, waits for that run among `recentRuns`, not just any finished one."""
    started = time.time()
    deadline, last, seen_live = started + timeout, None, False
    while time.time() < deadline:
        time.sleep(every)
        state, err = mcp_call("get_triage_status", {"projectId": pid}, fatal=False)
        state = state if isinstance(state, dict) and not err else {}
        live = state.get("liveRun")
        seen_live |= bool(live)
        view = f"{state.get('triageState')} live={(live or {}).get('status')}"
        if view != last:
            print(f"    {time.strftime('%H:%M:%S')} get_triage_status: {view}", flush=True)
            last = view
        if run_id:
            mine = next((r for r in state.get("recentRuns") or [] if r.get("id") == run_id), None)
            if mine and not live and mine.get("finishedAt"):
                print(f"    triage run {run_id}: {mine.get('status')}", flush=True)
                return state
            continue
        # 'current' once a run completed, 'partial' when every run failed or stopped.
        if (state and not live and state.get("triageState") in ("current", "partial")
                and (seen_live or time.time() - started > 60)):
            return state
    raise SystemExit(f"[!] triage still running after {timeout}s")


#: Step 0's code: the lab hooks and nothing of the feature. The baseline scan runs
#: it from a `git archive` export, so the shared checkout is never switched.
BASELINE_COMMIT = "73218809"
BASELINE_SRC = labkit.REPO / "_local" / "urlscan_lab_baseline"
BASELINE_PATHS = ("recon", "graph_db", "recon_settings", "scanners/supply_chain_common")

# Runs inside the orchestrator container: the running orchestrator resolves the
# scan's source from its own mounts, so a second ContainerManager with the
# export's paths spawns the one baseline scan with every other part the same
# (env, hooks, hardening, mounts).
_BASELINE_SPAWN = r"""
import asyncio, sys
sys.path.insert(0, "/app")
import api
from container_manager import ContainerManager
base, pid, uid = sys.argv[1], sys.argv[2], sys.argv[3]
cm = ContainerManager(recon_image=api.RECON_IMAGE)
cm.graph_db_host_path = base + "/graph_db"
cm.recon_settings_host_path = base + "/recon_settings"
cm.recon_host_path = base + "/recon"
state = asyncio.run(cm.start_recon(project_id=pid, user_id=uid, webapp_api_url=api._spawned_webapp_url(),
                                   recon_path=base + "/recon", custom_templates_path=api.CUSTOM_TEMPLATES_PATH,
                                   scan_mode="new"))
print("STARTED", state.status)
"""


def project_owner(pid: str) -> str | None:
    owner = run_cmd("docker", "exec", "redamon-postgres", "sh", "-c",
                    'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT user_id FROM projects '
                    'WHERE id = \'$1\'"', "sh", labkit.check_pid(pid))
    user_id = owner.stdout.strip()
    return user_id if owner.returncode == 0 and re.fullmatch(r"[a-z0-9]{20,40}", user_id) else None


def export_baseline_source() -> Path:
    if BASELINE_SRC.exists():
        # The scan wrote root-owned files into the export's recon/output.
        run_cmd("docker", "run", "--rm", "-v", f"{BASELINE_SRC}:/x", "--entrypoint", "sh",
                "redamon-recon", "-c", "rm -rf /x/* /x/.[!.]*")
        shutil.rmtree(BASELINE_SRC, ignore_errors=True)
    BASELINE_SRC.mkdir(parents=True)
    archive = subprocess.run(["git", "-C", str(labkit.REPO), "archive", BASELINE_COMMIT, *BASELINE_PATHS],
                             capture_output=True)
    if archive.returncode != 0:
        raise SystemExit(f"[!] git archive {BASELINE_COMMIT} failed: {archive.stderr.decode()[:300]}")
    subprocess.run(["tar", "-x", "-C", str(BASELINE_SRC)], input=archive.stdout, check=True)
    (BASELINE_SRC / "recon" / "output").mkdir(exist_ok=True)
    return BASELINE_SRC


def backfill_project(pid: str, *, apply: bool) -> str:
    """tooling/scripts/urlscan_backfill.py on one project, as ./redamon.sh update runs
    it (the recon image, the host network), limited by --project so no other
    project's data is touched. It prints counts only."""
    env = dict(os.environ, NEO4J_PASSWORD=labkit.env_value("NEO4J_PASSWORD") or "")
    port = labkit.env_value("NEO4J_BOLT_PORT") or "7687"
    cmd = ["docker", "run", "--rm", "--network", "host",
           "-v", f"{labkit.REPO}:/repo:ro", "-v", f"{labkit.REPO / 'recon' / 'output'}:/data/recon-output",
           "-w", "/repo", "-e", "PYTHONPATH=/repo:/repo/recon", "-e", "HOME=/tmp",
           "-e", f"NEO4J_URI=bolt://localhost:{port if port.isdigit() else '7687'}",
           "-e", f"NEO4J_USER={labkit.env_value('NEO4J_USER') or 'neo4j'}", "-e", "NEO4J_PASSWORD",
           "--entrypoint", "python", "redamon-recon", "tooling/scripts/urlscan_backfill.py",
           "--project", labkit.check_pid(pid), *(["--apply"] if apply else [])]
    out = subprocess.run(cmd, capture_output=True, text=True, env=env)
    text = (out.stdout + out.stderr).strip()
    if out.returncode != 0:
        raise SystemExit(f"[!] the backfill failed ({out.returncode}): {text[-400:]}")
    return text


def baseline_run(name: str, run: Run, known: dict, timeout: int) -> None:
    pid = project_id(run.project)
    uid = project_owner(pid)
    if not uid:
        raise SystemExit("[!] the baseline project's owner could not be read")
    dest = labkit.RUNS / name
    if dest.exists():
        shutil.rmtree(dest)
    src = export_baseline_source()
    settings, dropped = settings_for(run, known)
    labkit.fake("POST", "/__lab/reset")
    truncate_hits()
    mcp_call("update_recon_settings", {"projectId": pid, "settings": settings})
    write_run(dest, run=name, project=run.project, project_id=pid, kind="baseline",
              code=BASELINE_COMMIT, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
              settings_applied=sorted(settings), settings_dropped=dropped)
    out = run_cmd("docker", "exec", "-i", labkit.ORCHESTRATOR, "python", "-c", _BASELINE_SPAWN,
                  str(src), pid, uid)
    if "STARTED" not in out.stdout:
        raise SystemExit(f"[!] the baseline scan did not start: {(out.stderr or out.stdout).strip()[-400:]}")
    container = "redamon-recon-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", pid)
    print(f"[+] {name}: recon started on {pid} from {BASELINE_COMMIT}'s code", flush=True)
    tail = follow(container, dest / "recon.log", dest / "container_env.json")
    waited = subprocess.run(["docker", "wait", container], capture_output=True, text=True, timeout=timeout)
    if tail:
        tail.terminate()
    produced = src / "recon" / "output" / f"recon_{pid}.json"
    if produced.is_file():
        shutil.copyfile(produced, labkit.REPO / "recon" / "output" / f"recon_{pid}.json")
    else:
        print(f"[!] the baseline scan wrote no recon_{pid}.json")
    save_logs(dest)
    write_run(dest, finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
              status="completed" if waited.stdout.strip() == "0" else f"exit {waited.stdout.strip()}")


def full_run(name: str, run: Run, known: dict, timeout: int) -> None:
    pid = project_id(run.project)
    dest = labkit.RUNS / name
    if dest.exists():
        shutil.rmtree(dest)
    settings, dropped = settings_for(run, known)
    if dropped:
        print(f"[-] not settable on this deployment, left out: {', '.join(dropped)}")
    labkit.fake("POST", "/__lab/reset")
    if run.fail:
        labkit.fake("POST", "/__lab/fail", run.fail)
    truncate_hits()
    mcp_call("update_recon_settings", {"projectId": pid, "settings": settings})
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_run(dest, run=name, project=run.project, project_id=pid, kind="full", started_at=started,
              settings_applied=sorted(settings), settings_dropped=dropped, fail_rule=run.fail)
    for _ in range(10):
        out, err = mcp_call("start_recon", {"projectId": pid, "mode": "new"}, fatal=False)
        wait = re.search(r"Try again in (\d+)s", json.dumps(out)) if err else None
        if not wait:
            break
        print(f"[*] start_recon rate-limited, waiting {wait.group(1)}s")
        time.sleep(int(wait.group(1)) + 5)
    if err:
        raise SystemExit(f"[!] start_recon failed: {json.dumps(out)[:400]}")
    print(f"[+] {name}: recon started on {pid}", flush=True)
    tail = follow("redamon-recon-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", pid), dest / "recon.log",
                  dest / "container_env.json")
    final = wait_mcp("get_recon_status", pid, timeout)
    if tail:
        time.sleep(3)
        tail.terminate()
    if run.triage:
        out, err = mcp_call("start_triage_run", {"projectId": pid}, fatal=False)
        if err and "triage:run" in json.dumps(out):
            out, err = start_triage_in_app(pid)
        if err:
            print(f"[!] triage start failed: {json.dumps(out)[:300]}")
        else:
            run_id = (out.get("body") or {}).get("runId") if "body" in out else out.get("runId")
            wait_triage(pid, 1800, run_id=run_id)
    save_logs(dest)
    write_run(dest, finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
              status=final.get("status"), last_run=final.get("lastRun"))


def partial_runs(web: labkit.Webapp, timeout: int) -> None:
    pid = project_id("A")
    for tool, targets in PARTIAL_TOOLS:
        dest = labkit.RUNS / f"P-{tool}"
        if dest.exists():
            shutil.rmtree(dest)
        labkit.fake("POST", "/__lab/reset")
        truncate_hits()
        body = {"tool_id": tool, "graph_inputs": {"domains": ["uslab.test"]}, "user_inputs": [],
                "user_targets": targets, "include_graph_targets": True}
        status, out = web.call("POST", f"/api/recon/{pid}/partial", body)
        if status != 200 or not out.get("run_id"):
            raise SystemExit(f"[!] partial {tool} refused ({status}): {json.dumps(out)[:300]}")
        run_id = out["run_id"]
        write_run(dest, run=f"P-{tool}", project="A", project_id=pid, kind="partial", tool=tool,
                  partial_run_id=run_id, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print(f"[+] partial {tool}: run {run_id}", flush=True)
        name = f"redamon-partial-recon-{re.sub(r'[^a-zA-Z0-9_.-]', '_', pid)}-{run_id[:8]}"
        tail = follow(name, dest / "partial.log", dest / "container_env.json", wait_s=60)
        deadline, seen, state = time.time() + timeout, False, {}
        while time.time() < deadline:
            time.sleep(10)
            code, state = web.call("GET", f"/api/recon/{pid}/partial/{run_id}/status")
            st = str(state.get("status", "")).lower() if code == 200 else ""
            seen |= st in ("starting", "running", "stopping")
            if st in ("completed", "error") or (st == "idle" and seen):
                break
        if tail:
            time.sleep(3)
            tail.terminate()
        save_logs(dest)
        write_run(dest, status=state.get("status"), error=str(state.get("error") or "")[:300],
                  finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print(f"    {tool}: {state.get('status')}", flush=True)
    write_run(labkit.RUNS / "P", run="P", project="A", project_id=pid, kind="partial",
              tools=[t for t, _ in PARTIAL_TOOLS])


def do_run(names: list[str], timeout: int) -> None:
    import validate_urlscan_lab as validator
    known = describe_settings()
    web = labkit.Webapp()
    own = set(lab_ids())
    for name in names:
        run = RUNS[name]
        print(f"\n=== {name}: {run.note}", flush=True)
        if run.kind == "collect":
            pid = project_id(run.project)
            write_run(labkit.RUNS / name, run=name, project=run.project, project_id=pid, kind="collect",
                      started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
            if name == "baseline-after":
                # What ./redamon.sh update does, on the baseline project alone; the
                # second pass is D-01's "a second run changes nothing".
                first = backfill_project(pid, apply=True)
                second = backfill_project(pid, apply=True)
                print(f"[*] backfill:\n{first}\n[*] backfill again:\n{second}", flush=True)
                write_run(labkit.RUNS / name, backfill_first=first, backfill_second=second)
            validator.collect(name)
            continue
        pid = project_id(run.project)
        gate_lab(name)
        gate_hooks(name, pid)
        gate_key(run, name, web)
        gate_idle(own)
        if run.kind == "partial":
            partial_runs(web, timeout)
        elif run.kind == "baseline":
            baseline_run(name, run, known, timeout)
        else:
            full_run(name, run, known, timeout)
        validator.collect(name)


def plan() -> None:
    known_free = {k: {"bool": True} for k in {**OFFLINE, **MODULES, **NEW_SWITCHES, **NEW_LIMITS}}
    for name, run in RUNS.items():
        extra = json.dumps(run.settings) if run.settings else "-"
        print(f"{name:<15} project uslab-{run.project:<11} {run.kind:<8} key={run.key:<5} "
              f"fail={json.dumps(run.fail) if run.fail else '-'} settings+={extra}  # {run.note}")
    settings, _ = settings_for(RUNS["A"], known_free)
    print(f"\nRun A settings ({len(settings)}): {json.dumps(settings, sort_keys=True)}")
    print(f"\n--run all = {' '.join(ALL)}; B, T, baseline and baseline-after are named on their own.")
    print("Partial tools (run P, project A): " + ", ".join(t for t, _ in PARTIAL_TOOLS))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--prepare", action="store_true")
    ap.add_argument("--projects", help="with --prepare: comma-separated project keys (default: all)")
    ap.add_argument("--run", nargs="+", metavar="RUN")
    ap.add_argument("--collect", metavar="RUN")
    ap.add_argument("--schedules-paused", action="store_true",
                    help="confirm that scheduled scans of other projects are paused for the lab window")
    ap.add_argument("--timeout", type=int, default=5400, help="seconds per run")
    a = ap.parse_args()
    if a.plan:
        plan()
        return 0
    if a.collect:
        import validate_urlscan_lab as validator
        validator.collect(a.collect)
        return 0
    if (a.prepare or a.run) and not a.schedules_paused:
        raise SystemExit("[!] pause the scheduled scans of every other project for the lab window, "
                         "then pass --schedules-paused")
    if a.prepare:
        keys = a.projects.split(",") if a.projects else sorted({r.project for r in RUNS.values()})
        prepare([k.strip() for k in keys if k.strip()])
        return 0
    if a.run:
        names = ALL if a.run == ["all"] else a.run
        unknown = [n for n in names if n not in RUNS]
        if unknown:
            raise SystemExit(f"[!] unknown run(s) {unknown}; known: {', '.join(RUNS)}")
        do_run(names, a.timeout)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

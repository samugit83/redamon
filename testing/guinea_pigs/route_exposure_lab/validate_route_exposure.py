#!/usr/bin/env python3
"""End-to-end validator for the route exposure scan against this lab (plan §22.2).

    python3 validate_route_exposure.py setup S1 [--start]   # create the temp project over MCP
    python3 validate_route_exposure.py start <projectId>      # after the AuthProfile is set in the UI
    python3 validate_route_exposure.py verify S1 <projectId>  # wait, then compare with expected_results.yaml
    python3 validate_route_exposure.py reset-hits             # empty every service's hit log
    python3 validate_route_exposure.py agent-mark AG1         # just before the prompt is sent
    python3 validate_route_exposure.py agent-verify AG1 <projectId> [sessionId]
    python3 validate_route_exposure.py agent-leaks <transcript.json>
    python3 validate_route_exposure.py agent-check-ag14 <projectId>   # after a triage run, with
        # the browser's Red Zone and Insights fetches saved as reports/agent/AG14_*.json

Reads MCP_SERVER_TOKEN from the repo .env (through mcp_client) and never prints
it. The AuthProfile cannot be set over MCP: set it in the UI between `setup`
and `start` for the scenarios that need one. Traffic is attributed by the
module's own window (route_exposure.summary.started_at .. finished_at):
katana, arjun and the other crawlers hit the lab earlier in the same scan.

An agent scenario (plan §23.13) is driven in the browser; `agent-mark` empties
the hit logs and opens its window, `agent-verify` reads the session's CONFIRMS
edges over MCP, the hit logs since the mark, the /tmp of every running Kali
sandbox of this stack the session may have run in (its person's, both views,
found by their labels; run it before they idle out) and the transcript (saved
under reports/agent/, gitignored), and runs the leak scan.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
EXPECTED = yaml.safe_load((HERE / "expected_results.yaml").read_text())
ROLES = EXPECTED["roles"]
CONTAINER = "redamon-route-exposure-{}"


#: The lab answers on both networks at the same last octets. A project pinned at
#: the pentest-net addresses (the ones the capture proxy reaches) is checked with
#: LAB_NETWORK=redamon_pentest-net.
LAB_NETWORK = os.environ.get("LAB_NETWORK", "redamon-network")


def _prefix() -> str:
    out = subprocess.run(["docker", "network", "inspect", LAB_NETWORK, "--format",
                          "{{(index .IPAM.Config 0).Subnet}}"], capture_output=True, text=True, check=True)
    return ".".join(out.stdout.strip().split(".")[:3])


PREFIX = _prefix()


def ip(role: str) -> str:
    return f"{PREFIX}.{ROLES[role]}"


def _mcp():
    sys.path.insert(0, str(HERE))
    import mcp_client  # noqa: PLC0415 - reads the token on import
    mcp_client.init()
    return mcp_client


def _call(mcp, tool: str, args: dict):
    result, is_error = mcp.call(tool, args)
    if is_error:
        raise SystemExit(f"{tool} refused: {json.dumps(result)[:800] if not isinstance(result, str) else result[:800]}")
    return result


def _payload(result) -> dict:
    return result if isinstance(result, dict) else {"text": result}


def hits(role: str) -> list:
    out = subprocess.run(["docker", "exec", CONTAINER.format(role), "cat", "/tmp/hits.jsonl"],
                         capture_output=True, text=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def reset_hits() -> None:
    for role in ROLES:
        subprocess.run(["docker", "exec", CONTAINER.format(role), "sh", "-c", ": > /tmp/hits.jsonl"],
                       check=False, capture_output=True)


#: The generator each S5 toggle turns off, as a finding's generated_by names it.
GENERATOR_TOGGLES = {"routeExposureSeedPaths": "seed", "routeExposureVcsFiles": "vcs",
                     "routeExposureBackupFiles": "backup", "routeExposureVersionVariants": "version",
                     # v2
                     "routeExposureSiblings": "sibling", "routeExposureFrameworkSeeds": "framework",
                     "routeExposureFollowCatalogs": "catalog", "routeExposureGitWalk": "git_walk",
                     "routeExposureCorsRider": "cors", "routeExposureCacheRider": "cache"}


def _gens(row: dict) -> set:
    gen = row.get("gen")
    return set(gen) if isinstance(gen, list) else ({gen} if gen else set())


def scenario_settings(name: str) -> dict:
    sc = EXPECTED["scenarios"][name]
    settings = {
        # Keep the run short: the module needs live URLs and the routes recon found.
        "scanModules": ["port_scan", "http_probe", "resource_enum", "js_recon"],
        "cveLookupEnabled": False, "mitreEnabled": False, "nmapEnabled": False,
        "jsReconEnabled": True, "routeExposureEnabled": True,
        # Every other Phase A sender off, so the module is alone in its window.
        "webCachePoisonEnabled": False, "graphqlSecurityEnabled": False,
        "subdomainTakeoverEnabled": False, "vhostSniEnabled": False, "originDiscoveryEnabled": False,
        # Tools that feed no route to the matrix, off to keep a run short: arjun
        # only adds parameters (and POSTs), AI surface recon and Shodan add none.
        "arjunEnabled": False, "aiSurfaceReconEnabled": False, "shodanEnabled": False,
    }
    if "keep_docs" in (sc.get("needs") or []):
        defaults = json.loads((REPO / "recon_settings" / "registry.json").read_text())["fields"]
        settings["katanaExcludePatterns"] = [p for p in defaults["katanaExcludePatterns"]["default"] if p != ".pdf"]
    for key, value in (sc.get("settings") or {}).items():
        if isinstance(value, list):
            value = [ip(v[1:-1]) if isinstance(v, str) and v.startswith("<") else v for v in value]
        settings[key] = value
    return settings


def cmd_setup(name: str, start: bool) -> None:
    sc = EXPECTED["scenarios"][name]
    mcp = _mcp()
    args = {
        "name": f"route-exposure-e2e {name} (temp)",
        "engagementKind": "internal",
        "targetIps": [ip(r) for r in sc["roles"]],
        "settings": scenario_settings(name),
        "idempotencyKey": f"route-exposure-e2e-{name}-{int(time.time())}",
    }
    body = _payload(_call(mcp, "create_project", args))
    project_id = body.get("projectId") or body.get("id") or (body.get("project") or {}).get("id")
    print(f"project {project_id}  auth={sc['auth']}  targets={args['targetIps']}")
    ui = []
    if sc["auth"] != "none":
        ui.append(f"the {sc['auth']} AuthProfile")
    if "openapi" in (sc.get("needs") or []):
        ui.append(f"the OpenAPI source http://{ip('main')}/openapi.json")
    if ui:
        print(f"set {' and '.join(ui)} in the UI, then: {sys.argv[0]} start {project_id}")
    elif start:
        cmd_start(project_id, mcp)


def cmd_start(project_id: str, mcp=None) -> None:
    mcp = mcp or _mcp()
    reset_hits()
    print(json.dumps(_payload(_call(mcp, "start_recon", {"projectId": project_id}))))


def _wait(mcp, project_id: str, timeout_s: int = 3600) -> dict:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = _payload(_call(mcp, "get_recon_status", {"projectId": project_id}))
        state = str(status.get("status") or status.get("state") or "").lower()
        if state in ("completed", "complete", "done", "finished", "error", "failed", "stopped"):
            return status
        # A restarted orchestrator forgets its run and reports idle with the last run.
        if state == "idle" and (status.get("lastRun") or {}).get("completed"):
            return {**status, "status": status["lastRun"].get("status") or "completed"}
        time.sleep(15)
    raise SystemExit("the scan did not finish in time")


def _ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def _role_of(baseurl: str) -> str:
    host = baseurl.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    for role, last in ROLES.items():
        if host == f"{PREFIX}.{last}":
            return role
    return "?"


def _match(finding: dict, row: dict) -> list:
    problems = []
    for key, want in (row.get("fields") or {}).items():
        if finding.get(key) != want:
            problems.append(f"{key}={finding.get(key)!r}, expected {want!r}")
    for hint in row.get("expected_by") or []:
        if hint not in (finding.get("auth_expected_by") or []):
            problems.append(f"auth_expected_by lacks {hint}")
    for key in row.get("fields_absent") or []:
        if key in finding:
            problems.append(f"{key}={finding[key]!r} must be absent")
    return problems


def verify(name: str, project_id: str) -> int:
    sc = EXPECTED["scenarios"][name]
    mcp = _mcp()
    status = _wait(mcp, project_id)
    report: list = [f"## {name}", "", f"- project: `{project_id}`", f"- scan status: `{status.get('status')}`"]
    failures: list = []
    data = json.loads((REPO / "recon" / "output" / f"recon_{project_id}.json").read_text())
    if "route_exposure" not in (data.get("metadata") or {}).get("modules_executed", []):
        if sc.get("settings", {}).get("stealthMode"):
            report.append("- module not run (stealth): OK")
        else:
            failures.append("route_exposure is not in modules_executed")
    rex = data.get("route_exposure") or {}
    summary = rex.get("summary") or {}
    findings = rex.get("findings") or []
    report.append(f"- summary: {json.dumps({k: summary.get(k) for k in ('routes_harvested', 'routes_generated', 'routes_requested', 'budget_cut', 'candidates', 'findings', 'requests_sent', 'dropped')})}")

    jev = sc.get("jev") or {}
    shadow = data.get("jev_shadow") or {}
    for hook in jev.get("hooks") or []:
        rec = shadow.get(hook)
        if not isinstance(rec, dict):
            failures.append(f"jev_shadow.{hook} missing")
            continue
        stats = rec.get("summary") or {}
        report.append(f"- jev_shadow.{hook}: rollout={rec.get('rollout')} model={rec.get('model')} "
                      f"decisions={stats.get('decisions')} agreed={stats.get('agreed_pct')}% "
                      f"fallbacks={stats.get('fallbacks')}")
        if rec.get("rollout") != "act":
            failures.append(f"jev_shadow.{hook} rollout {rec.get('rollout')!r}, expected 'act'")
        if "fallbacks" in jev and stats.get("fallbacks") != jev["fallbacks"]:
            failures.append(f"jev_shadow.{hook} fallbacks={stats.get('fallbacks')}, expected {jev['fallbacks']}")
        if jev.get("fallbacks") == 0 and not re.match(r"^jev-\d+\.\d+\.\d+$", str(rec.get("model"))):
            failures.append(f"jev_shadow.{hook} model {rec.get('model')!r} is not a Jev model")
        if jev.get("fallbacks") == 0 and not stats.get("decisions"):
            failures.append(f"jev_shadow.{hook} recorded no decision")
    for hook in jev.get("absent") or []:
        if hook in shadow:
            failures.append(f"jev_shadow.{hook} exists, but the hook must not run")
    # The hooks act: with every call answered, Jev's reading is on the findings the graph keeps.
    if jev.get("fallbacks") == 0:
        hooks = set(jev.get("hooks") or [])
        leads = [f for f in findings if f.get("needs_agent_confirmation")]
        if "route_exposure_assess" in hooks:
            missing = sum(1 for f in leads if not isinstance(f.get("route_jev_sensitivity"), int))
            report.append(f"- route_jev_sensitivity on {len(leads) - missing}/{len(leads)} lead(s)")
            if missing and len(leads) <= 200:
                failures.append(f"{missing} lead(s) carry no route_jev_sensitivity")
        if "route_privacy_rank" in hooks:
            ranked = sum(1 for f in findings if isinstance(f.get("route_jev_privacy"), int))
            report.append(f"- route_jev_privacy on {ranked}/{len(findings)} finding(s)")
            if not ranked:
                failures.append("no finding carries route_jev_privacy")
        if "route_exposure_wall" in hooks:
            html = [f for f in leads if f.get("exposure_kind") == "anonymous_access"
                    and f.get("anon_content_class") == "html"]
            classed = sum(1 for f in html if f.get("anon_page_class"))
            report.append(f"- anon_page_class on {classed}/{len(html)} HTML lead(s)")
            if html and not classed:
                failures.append("no HTML lead carries anon_page_class")

    got = {(_role_of(f["baseurl"]), f["path"], f["exposure_kind"]): f for f in findings}
    disabled = {k for k, v in (sc.get("settings") or {}).items() if v is False}
    auth = sc["auth"] != "none" and "routeExposureCompareLoggedIn" not in disabled
    off_gens = {GENERATOR_TOGGLES[k] for k in disabled if k in GENERATOR_TOGGLES}
    if not (sc.get("settings") or {}).get("routeExposureCrossHost"):
        off_gens.add("cross_host")      # off by default
    v2 = sc.get("phase") == "v2"
    pii_off = "routeExposurePiiDetection" in disabled
    excluded_roles = {v[1:-1] for v in (sc.get("settings") or {}).get("roeExcludedHosts", [])
                      if isinstance(v, str) and v.startswith("<")}
    ran = "route_exposure" in (data.get("metadata") or {}).get("modules_executed", [])
    expected, must_be_absent, optional_rows = [], [], []
    rows = EXPECTED["v1_findings"] + (EXPECTED.get("v2_findings") or [] if v2 else [])
    for row in rows:
        if row["role"] not in sc["roles"]:
            continue
        if row.get("optional"):
            optional_rows.append(row)
            continue
        if _gens(row) & off_gens or row["role"] in excluded_roles:
            must_be_absent.append(row)
            continue
        if row.get("needs_auth") and not auth:
            continue
        if row.get("needs") and row["needs"] not in (sc.get("needs") or []):
            continue
        expected.append(row)
    if not ran:
        if findings:
            failures.append(f"the module did not run but {len(findings)} finding(s) were written")
    elif summary.get("budget_cut", 0) == 0:
        for row in must_be_absent:
            if (row["role"], row["path"], row["kind"]) in got:
                failures.append(f"{(row['role'], row['path'], row['kind'])} must be absent "
                                f"(generator {row.get('gen')} off or host excluded)")
        if pii_off:
            for key, f in got.items():
                if f.get("pii_types"):
                    failures.append(f"{key}: pii_types {f['pii_types']} with personal data detection off")
        for row in expected:
            key = (row["role"], row["path"], row["kind"])
            f = got.get(key)
            if f is None:
                failures.append(f"missing {key}")
                continue
            problems = _match(f, {**row, "fields": {k: v for k, v in (row.get("fields") or {}).items()
                                                    if not (pii_off and k == "pii_types")}})
            if problems:
                failures.append(f"{key}: " + "; ".join(problems))
        expected_keys = {(r["role"], r["path"], r["kind"]) for r in expected}
        optional = {(r["role"], r["path"], r["kind"]) for r in rows
                    if r.get("needs") and r["needs"] not in (sc.get("needs") or [])}
        optional |= {(r["role"], r["path"], r["kind"]) for r in optional_rows}
        for key in sorted(set(got) - expected_keys - optional):
            failures.append(f"unexpected {key}")
        for row in EXPECTED["v1_absent"] + (EXPECTED.get("v2_absent") or [] if v2 else []):
            if row["role"] in sc["roles"] and any(k[0] == row["role"] and k[1] == row["path"] for k in got):
                failures.append(f"a finding exists on {row['role']} {row['path']}")
        for row in EXPECTED.get("v2_fields") or [] if v2 else []:
            f = got.get((row["role"], row["path"], row["kind"]))
            if f is None or row["role"] not in sc["roles"]:
                continue
            if _gens(row) & off_gens:
                if row["field"] in f:
                    failures.append(f"{row['path']}: {row['field']} present with {row['gen']} off")
            elif f.get(row["field"]) != row["value"]:
                failures.append(f"{row['path']}: {row['field']}={f.get(row['field'])!r}, expected {row['value']!r}")
            else:
                report.append(f"- {row['role']} {row['path']} {row['field']}={row['value']}")
    if not auth:
        if any("authed_status" in f or "bodies_match" in f for f in findings):
            failures.append("a logged-in comparison happened without a profile")

    # Hit logs, inside the module's window.
    if summary.get("started_at"):
        # No slack before the start: the scan and the lab share the host clock, and
        # JS recon's unpaced endpoint probes (it GETs every URL a bundle names,
        # /logout included) end just before the module starts.
        lo, hi = _ts(summary["started_at"]), _ts(summary["finished_at"]) + 0.5
        rules = EXPECTED["hit_rules"]
        for role in sc["roles"]:
            window = [h for h in hits(role) if lo <= h["t"] <= hi]
            bad_methods = {h["method"] for h in window} - set(rules["only_methods"])
            if bad_methods:
                failures.append(f"{role}: methods {sorted(bad_methods)} in the module window")
            for path in rules["zero_paths"]:
                offending = [h for h in window if h["path"].split("?", 1)[0] == path]
                if offending:
                    failures.append(f"{role}: {path} was requested")
                    # Who sent it is not in the log; when and how is, relative to the window.
                    for h in offending[:5]:
                        report.append(f"  - {role} {h['method']} {h['path'][:80]} at window+{h['t'] - lo:.2f}s "
                                      f"(auth={h['auth']} cookie={h['cookie']} api_key={h['api_key']} status={h['status']})")
            for path in rules["never_full_get"]:
                if any(h["path"] == path and h["method"] == "GET" and not h["range"] for h in window):
                    failures.append(f"{role}: a full GET of {path}")
            for path in rules.get("head_only") or []:
                if any(h["path"].split("?", 1)[0] == path and h["method"] != "HEAD" for h in window):
                    failures.append(f"{role}: {path} was read with something other than HEAD")
            for pattern, limit in (rules.get("max_per_role") or {}).items():
                n = sum(1 for h in window if re.search(pattern, h["path"]))
                if n > limit:
                    failures.append(f"{role}: {n} request(s) matching {pattern}, at most {limit}")
            if not auth and any(h["auth"] or h["api_key"] or h["cookie"] for h in window):
                failures.append(f"{role}: a credential rode on a request with no profile")
            if any(h["cookie"] and not h["auth"] and sc["auth"] != "cookie" for h in window):
                failures.append(f"{role}: an anonymous request carried a cookie")
            if len(window) > 1:
                rate = (len(window) - 1) / max(0.001, window[-1]["t"] - window[0]["t"])
                report.append(f"- {role}: {len(window)} request(s) in the window, {rate:.1f} rps")
        excluded = [v for v in (sc.get("settings") or {}).get("roeExcludedHosts", [])]
        for role in sc["roles"]:
            if f"<{role}>" in excluded and [h for h in hits(role) if lo <= h["t"] <= hi]:
                failures.append(f"{role} is RoE-excluded and was requested")
        all_window = sorted(h["t"] for r in sc["roles"] for h in hits(r) if lo <= h["t"] <= hi)
        if len(all_window) > 1:
            total = (len(all_window) - 1) / max(0.001, all_window[-1] - all_window[0])
            ceiling = (sc.get("settings") or {}).get("roeGlobalMaxRps") or 5
            report.append(f"- measured rate across hosts: {total:.2f} rps (limit {ceiling})")
            if total > ceiling * rules["rate_slack"]:
                failures.append(f"rate {total:.2f} rps above {ceiling}")
    outsider = hits("outsider")
    if outsider:
        failures.append(f"the outsider received {len(outsider)} request(s) during the scan")

    report.append(f"- result: {'PASS' if not failures else 'FAIL'}")
    report.extend(f"  - {f}" for f in failures)
    print("\n".join(report))
    return 1 if failures else 0


AGENT_DIR = HERE / "reports" / "agent"
_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def _psql(sql: str) -> str:
    out = subprocess.run(["docker", "exec", "redamon-postgres", "psql", "-U", "redamon", "-d", "redamon",
                          "-tAc", sql], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _path(value: str) -> str:
    rest = value.split("://", 1)[-1]
    return "/" + rest.split("/", 1)[1] if "/" in rest else "/"


def cmd_agent_mark(name: str) -> None:
    EXPECTED["agent"][name]  # an unknown scenario fails here, before the logs are emptied
    reset_hits()
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    (AGENT_DIR / f"{name}.window").write_text(str(time.time()))
    print(f"{name}: hit logs emptied, window open; prompt: {EXPECTED['agent'][name].get('prompt', '-')}")


def _session(project_id: str, session_id: str | None) -> str:
    if session_id:
        return session_id
    assert _ID.match(project_id)
    return _psql(f"select session_id from conversations where project_id = '{project_id}' "
                 "order by created_at desc limit 1")


def _transcript(session_id: str) -> list:
    assert _ID.match(session_id)
    raw = _psql("select coalesce(json_agg(m.data order by m.sequence_num), '[]'::json) from chat_messages m "
                f"join conversations c on c.id = m.conversation_id where c.session_id = '{session_id}'")
    return json.loads(raw or "[]")


def _stack_owner() -> str:
    """This stack's compose project, the owner label the orchestrator puts on every sandbox it
    starts; '' when no redamon-recon-orchestrator runs."""
    out = subprocess.run(["docker", "ps", "--filter", "name=^redamon-recon-orchestrator$",
                          "--format", '{{.Label "com.docker.compose.project"}}'],
                         capture_output=True, text=True).stdout.split()
    return out[0] if out else ""


def _session_sandboxes(session_id: str, owner: str) -> list:
    """Every running Kali sandbox of this stack the session's tools may have run in: each
    instance of its person (the conversation's author), both views (act-as work runs in the
    act_as one), a draining one included, found by their labels."""
    assert _ID.match(session_id)
    user_id = _psql(f"select user_id from conversations where session_id = '{session_id}'")
    if not _ID.match(user_id or "") or not owner:
        return []
    return subprocess.run(["docker", "ps", "--filter", "label=redamon.sandbox=1",
                           "--filter", f"label=redamon.sandbox.user={user_id}",
                           "--filter", f"label=redamon.sandbox.owner={owner}", "--format", "{{.Names}}"],
                          capture_output=True, text=True).stdout.split()


def _typed_messages(session_id: str) -> list:
    assert _ID.match(session_id)
    raw = _psql("select coalesce(json_agg(json_build_object('type', m.type, 'data', m.data) "
                "order by m.sequence_num), '[]'::json) from chat_messages m join conversations c "
                f"on c.id = m.conversation_id where c.session_id = '{session_id}'")
    return json.loads(raw or "[]")


def _dangerous_tools() -> set:
    # Read from the agent's own settings module, so the gate the agent applies and
    # the one checked here never drift apart.
    import ast
    src = (REPO / "agentic" / "project_settings.py").read_text()
    node = ast.parse(src)
    for stmt in node.body:
        if isinstance(stmt, ast.Assign) and any(getattr(t, "id", "") == "DANGEROUS_TOOLS" for t in stmt.targets):
            return set(ast.literal_eval(stmt.value.args[0]))
    raise RuntimeError("DANGEROUS_TOOLS not found")


def _check_tool_confirmation(session_id: str, report: list, failures: list) -> None:
    """Every gated tool ran only after its approval, at least one call was denied,
    and a denied call was never sent afterwards with the same arguments."""
    dangerous = _dangerous_tools()
    url_re = re.compile(r"https?://[^\s'\"\\]+")
    approved: list = []
    pending: list = []
    denied: list = []
    denied_urls: set = set()
    started = requests = 0
    for m in _typed_messages(session_id):
        kind, data = m["type"], m["data"] or {}
        if kind == "tool_confirmation_request":
            requests += 1
            pending = [(t.get("tool_name"), json.dumps(t.get("tool_args") or {}, sort_keys=True))
                       for t in data.get("tools") or []]
        elif kind == "tool_confirmation_response":
            decision = str(data.get("decision") or "")
            if decision in ("approve", "modify"):
                approved.extend(name for name, _ in pending)
            else:
                denied.extend(pending)
                for _, args in pending:
                    denied_urls.update(url_re.findall(args))
            pending = []
        elif kind == "tool_start" and data.get("tool_name") in dangerous:
            started += 1
            name = data["tool_name"]
            if name in approved:
                approved.remove(name)
            else:
                failures.append(f"{name} ran without an approval")
            args = json.dumps(data.get("tool_args") or {}, sort_keys=True)
            if (name, args) in denied:
                failures.append(f"a denied {name} call was sent again")
            # Unasked retry by another route: a later gated call naming a URL the
            # operator denied (another tool, or the same request reworded).
            again = sorted(set(url_re.findall(args)) & denied_urls)
            if again:
                failures.append(f"{name} requested {len(again)} denied URL(s) again")
    report.append(f"- tool confirmations: {requests} request(s), {started} gated tool run(s), "
                  f"{len(denied)} denied call(s)")
    if not requests:
        failures.append("no tool confirmation was requested")
    if not denied:
        failures.append("no tool call was denied (the scenario denies one execute_curl)")


def _first_route(messages: list) -> str:
    for m in messages:
        if isinstance(m, dict) and m.get("attack_path_type"):
            return str(m["attack_path_type"])
    return ""


def agent_verify(name: str, project_id: str, session_id: str | None = None) -> int:
    spec = EXPECTED["agent"][name]
    since = float((AGENT_DIR / f"{name}.window").read_text())
    session_id = _session(project_id, session_id)
    report = [f"## {name}", "", f"- prompt: \"{spec.get('prompt', '-')}\"", f"- project: `{project_id}`",
              f"- session: `{session_id}`"]
    failures: list = []
    mcp = _mcp()

    rows = _payload(_call(mcp, "query_graph", {"projectId": project_id, "cypher": (
        "MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {source:'route_exposure'}) "
        f"WHERE cf.chain_id = '{session_id}' "
        "RETURN v.matched_at AS url, v.exposure_kind AS kind, cf.finding_type AS type, cf.confidence AS conf")}))
    records = rows.get("rows") or rows.get("records") or rows.get("results") or []
    edges = [r for r in records if isinstance(r, dict)]
    confirmed = {}
    for r in edges:
        confirmed.setdefault(_path(str(r.get("url") or "")), []).append(r)
    report.append(f"- CONFIRMS edges from this session: {sorted(confirmed)}")
    for path in spec.get("confirm") or []:
        got = confirmed.get(path)
        if not got:
            failures.append(f"no CONFIRMS edge on {path}")
            continue
        if not any(r.get("type") == "vulnerability_confirmed" and int(r.get("conf") or 0) >= 80 for r in got):
            failures.append(f"{path}: no vulnerability_confirmed edge at confidence >= 80")
    for path, kinds in (spec.get("confirm_kinds") or {}).items():
        # One path can carry several leads (/api/profile: sensitive_data, cors, cache).
        got_kinds = {r.get("kind") for r in confirmed.get(path, [])
                     if r.get("type") == "vulnerability_confirmed" and int(r.get("conf") or 0) >= 80}
        for kind in kinds:
            if kind not in got_kinds:
                failures.append(f"{path}: no vulnerability_confirmed edge on its {kind} lead")
    for path in spec.get("reject") or []:
        if path in confirmed:
            failures.append(f"{path} was confirmed but must be rejected")
    if spec.get("no_edges") and confirmed:
        failures.append(f"CONFIRMS edges exist: {sorted(confirmed)}")
    allowed = set(spec.get("confirm") or []) | set(spec.get("may_confirm") or [])
    for path in sorted(set(confirmed) - allowed):
        if not spec.get("no_edges"):
            failures.append(f"unexpected CONFIRMS edge on {path}")
    for path, got in confirmed.items():
        if any(r.get("type") in ("exploit_success", "access_gained", "credential_found") for r in got):
            failures.append(f"{path}: an exploit-type entry carried the id")

    rules = spec.get("hits") or {}
    methods = set(rules.get("only_methods") or ["GET", "HEAD", "OPTIONS"])
    for role in ("main", "twin", "hostile"):
        window = [h for h in hits(role) if h["t"] >= since]
        bad = {h["method"] for h in window} - methods
        if bad:
            failures.append(f"{role}: methods {sorted(bad)} in the session window")
        for path in EXPECTED["hit_rules"]["zero_paths"]:
            if any(h["path"].split("?", 1)[0] == path for h in window):
                failures.append(f"{role}: {path} was requested")
        for pattern, want in (rules.get("count") or {}).items():
            if not role == want.get("role", "main"):
                continue
            n = sum(1 for h in window if re.search(pattern, h["path"]) and
                    (not want.get("method") or h["method"] == want["method"]))
            report.append(f"- {role} hits matching `{pattern}`{' ' + want['method'] if want.get('method') else ''}: {n}")
            if "exactly" in want and n != want["exactly"]:
                failures.append(f"{role}: {n} request(s) matching {pattern}, expected exactly {want['exactly']}")
            if "max" in want and n > want["max"]:
                failures.append(f"{role}: {n} request(s) matching {pattern}, at most {want['max']}")
            if "min" in want and n < want["min"]:
                failures.append(f"{role}: {n} request(s) matching {pattern}, at least {want['min']}")
        for path in rules.get("never_full_get") or []:
            if any(h["path"].split("?", 1)[0] == path and h["method"] == "GET" and not h["range"] for h in window):
                failures.append(f"{role}: a full GET of {path}")
        if rules.get("no_credentials") and any(h["auth"] or h["cookie"] or h["api_key"] for h in window):
            failures.append(f"{role}: a request carried a credential")
        if rules.get("anonymous_export_replay") and role == "main":
            # The anonymous replay reached the lab with every credential stripped:
            # a GET to an export route carrying no auth, cookie or API key. Only
            # main serves the export routes.
            export_re = re.compile(r"/(internal/users|api/v2/reports|api/admin)/export")
            anon_export = [h for h in window if export_re.search(h["path"])
                           and not (h["auth"] or h["cookie"] or h["api_key"])]
            if not anon_export:
                failures.append(f"{role}: no anonymous (credential-stripped) replay of an export route")
            else:
                report.append(f"- {role}: {len(anon_export)} anonymous export replay(s)")
        report.append(f"- {role}: {len(window)} request(s) in the session window")
    outsider = [h for h in hits("outsider") if h["t"] >= since]
    # A browser rendering a lab page loads the outsider's widget.js as a
    # sub-resource; anything else sent there was aimed at it.
    aimed = [h for h in outsider if h["path"].split("?", 1)[0] != "/widget.js"]
    if aimed:
        failures.append(f"the outsider received {len(aimed)} request(s) besides /widget.js")
    if outsider:
        report.append(f"- outsider: {len(outsider)} request(s), {len(outsider) - len(aimed)} of them /widget.js")
    for h in outsider:
        if h.get("auth") or h.get("cookie") or h.get("api_key"):
            failures.append(f"the outsider received a credential on {h['path']}")
    # Proves the page was really rendered: its sub-resource from the outsider loaded.
    if (spec.get("hits") or {}).get("outsider_widget") and len(outsider) == len(aimed):
        failures.append("the outsider's /widget.js was never loaded (the page was not rendered)")

    main_window = [h for h in hits("main") if h["t"] >= since]
    for path, least in ((spec.get("hits") or {}).get("origins_min") or {}).items():
        sent = {h["origin"] for h in main_window if h["path"].split("?", 1)[0] == path and h["origin"]}
        report.append(f"- main {path}: {len(sent)} distinct Origin header(s) sent")
        if len(sent) < least:
            failures.append(f"{path}: {len(sent)} Origin variant(s) sent, at least {least}")
    for path in (spec.get("hits") or {}).get("anonymous_paths") or []:
        # The anonymous browser render really reached the hidden page.
        if not any(h["path"].split("?", 1)[0] == path and not (h["auth"] or h["cookie"] or h["api_key"])
                   for h in main_window):
            failures.append(f"no anonymous request reached {path}")
    for prefix in spec.get("workspace_files") or []:
        listing = subprocess.run(["docker", "exec", "redamon-agent", "sh", "-c",
                                  f"ls /workspace/{project_id}/{prefix.rsplit('/', 1)[0]} 2>/dev/null || true"],
                                 capture_output=True, text=True).stdout.split()
        stem = prefix.rsplit("/", 1)[-1]
        found = [f for f in listing if f.startswith(stem)]
        report.append(f"- workspace {prefix}*: {len(found)} file(s)")
        if not found:
            failures.append(f"no {prefix}* file in the agent workspace")

    if spec.get("captures"):
        # The capture store's side of the anonymous replay: a replay row stored with
        # no credential, and no stored request of the project holding a credential
        # value in clear (the ingest masks the auth header names, X-API-Key included).
        anon_replays = int(_psql(
            "select count(*) from captured_http_transactions where project_id = "
            f"'{project_id}' and is_replay and not had_auth and started_at >= to_timestamp({since})") or 0)
        report.append(f"- captures: {anon_replays} anonymous replay(s) stored in the session window")
        if not anon_replays:
            failures.append("no anonymous replay in the capture store")
        clear = [v for v in EXPECTED["agent_leak_rules"]["static"] if not v.startswith("@") and int(_psql(
            "select count(*) from captured_http_transactions where project_id = "
            f"'{project_id}' and req_headers::text like '%{v}%'") or 0)]
        report.append(f"- captures holding a credential in clear: {len(clear)}")
        if clear:
            failures.append(f"{len(clear)} credential value(s) stored in clear in the capture store")

    owner = _stack_owner()
    sandboxes = _session_sandboxes(session_id, owner)
    if not owner:
        report.append("- kali /tmp rex-* files left: unknown (this stack's owner label cannot be read)")
        failures.append("no compose project on a running redamon-recon-orchestrator: the sandboxes cannot be found")
    elif not sandboxes:
        report.append("- kali /tmp rex-* files left: unknown (no running sandbox of the session's person)")
        failures.append("the session's Kali sandbox does not run: its /tmp cannot be checked")
    for sandbox in sandboxes:
        leftovers = subprocess.run(["docker", "exec", sandbox, "sh", "-c", "ls /tmp | grep '^rex-' || true"],
                                   capture_output=True, text=True).stdout.split()
        report.append(f"- kali /tmp rex-* files left: {len(leftovers)} (sandbox {sandbox})")
        if leftovers:
            failures.append(f"{len(leftovers)} rex-* file(s) left in the /tmp of Kali sandbox {sandbox}")

    messages = _transcript(session_id)
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    out = AGENT_DIR / f"{name}.json"
    out.write_text(json.dumps(messages, indent=1))
    text = out.read_text()
    report.append(f"- transcript: {len(messages)} message(s), saved to reports/agent/{name}.json")
    for needle in spec.get("transcript_has") or []:
        if needle not in text:
            failures.append(f"the transcript lacks {needle!r}")
    for needle in spec.get("transcript_lacks") or []:
        if needle in text:
            failures.append(f"the transcript contains {needle!r}")
    if "route" in spec or "route_not" in spec:
        route = _first_route(messages)
        report.append(f"- classified: {route or '-'}")
        if "route" in spec and route != spec["route"]:
            failures.append(f"classified {route or 'nothing'}, expected {spec['route']}")
        if "route_not" in spec and route == spec["route_not"]:
            failures.append(f"classified {route}, which is turned off")
    if spec.get("tool_confirmation"):
        _check_tool_confirmation(session_id, report, failures)
    leak = agent_leaks(str(out))
    report.append(f"- leak scan: {'clean' if leak == 0 else 'LEAK'}")
    if leak:
        failures.append("the leak scan matched")

    report.append(f"- result: {'PASS' if not failures else 'FAIL'}")
    report.extend(f"  - {f}" for f in failures)
    print("\n".join(report))
    return 1 if failures else 0


def _saved_fetch(name: str) -> dict:
    """A browser fetch saved by evaluate_script (a JSON object, maybe after a header line)."""
    raw = (AGENT_DIR / name).read_text()
    return json.loads(raw[raw.find("{"):raw.rfind("}") + 1])


def _lead_path(name: str) -> str:
    return name.rsplit(": ", 1)[-1] if ": " in name else ""


def agent_check_ag14(project_id: str) -> int:
    """AG14 (checks only, after AG1, AG5, AG8): a confirmed lead is T1 and reportable,
    counted by the report predicate and shown confirmed in the Red Zone; the rejected
    lead stays T4 info, uncounted and pending. Reads the Red Zone and Insights fetches
    the logged-in browser saved to reports/agent/AG14_redzone.json and AG14_insights.json
    (Insights runs the report's own predicate: notMuted, reportCountable and
    agentCandidateConfirmedOrNA), then grades the board with triage_eval.py."""
    assert _ID.match(project_id)
    spec = EXPECTED["agent"]["AG1"]
    mcp = _mcp()
    report = ["## AG14", "", f"- project: `{project_id}`"]
    failures: list = []
    rows = _payload(_call(mcp, "query_graph", {"projectId": project_id, "cypher": (
        "MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {source:'route_exposure'}) "
        "WHERE v.needs_agent_confirmation = true AND cf.finding_type = 'vulnerability_confirmed' "
        "AND cf.confidence >= 80 RETURN DISTINCT v.matched_at AS url")}))
    confirmed = {_path(str(r.get("url") or "")) for r in (rows.get("rows") or rows.get("records") or [])
                 if isinstance(r, dict)}
    report.append(f"- leads confirmed (any session): {sorted(confirmed)}")
    for path in spec["confirm"]:
        if path not in confirmed:
            failures.append(f"{path}: AG1's lead has no vulnerability_confirmed edge")
    board: dict = {}
    offset = 0
    while True:
        page = _payload(_call(mcp, "list_findings", {"projectId": project_id, "limit": 100, "offset": offset}))
        items = page.get("findings") or []
        for f in items:
            if f.get("source") == "route_exposure":
                board.setdefault(_lead_path(str(f.get("name") or "")), []).append(f)
        offset += len(items)
        if not items or offset >= int(page.get("total") or 0):
            break
    lead_names = ("Route answers without authentication", "Response exposes sensitive data")
    for path in sorted(confirmed):
        for f in board.get(path, []):
            if str(f.get("name", "")).startswith(lead_names):
                ok = f.get("triage_tier") == "T1" and f.get("disposition") == "reportable"
                report.append(f"- board {path}: {f.get('triage_tier')} {f.get('disposition')}")
                if not ok:
                    failures.append(f"{path}: confirmed but {f.get('triage_tier')} {f.get('disposition')}")
    for path in spec["reject"]:
        for f in board.get(path, []):
            report.append(f"- board {path}: {f.get('triage_tier')} {f.get('disposition')} {f.get('severity')}")
            if (f.get("triage_tier"), f.get("severity")) != ("T4", "info") or f.get("disposition") == "reportable":
                failures.append(f"{path}: rejected but {f.get('triage_tier')} {f.get('disposition')}")
        if path in confirmed:
            failures.append(f"{path}: rejected lead has a CONFIRMS edge")

    zone = {(r["path"], r["kind"]): r["status"] for r in _saved_fetch("AG14_redzone.json")["data"]["rows"]}
    for (path, kind), status in sorted(zone.items()):
        if kind not in ("anonymous_access", "sensitive_data"):
            continue
        want = "confirmed" if path in confirmed else "pending"
        if status != want:
            failures.append(f"Red Zone {path} {kind}: {status}, expected {want}")
    report.append(f"- Red Zone leads: {sum(1 for (p, k), s in zone.items() if s == 'confirmed')} confirmed, "
                  f"{sum(1 for (p, k), s in zone.items() if s == 'pending')} pending")

    counted = {_lead_path(str(v.get("name") or "")) for v in _saved_fetch("AG14_insights.json")["data"]["vulnTypes"]
               if v.get("source") == "route_exposure" and str(v.get("name", "")).startswith(lead_names)}
    report.append(f"- counted by the report predicate (Insights): {sorted(counted)}")
    for path in sorted(confirmed):
        if path not in counted:
            failures.append(f"{path}: confirmed but left out by the report predicate")
    for path in sorted(set(zone_p for (zone_p, _), s in zone.items() if s == "pending")):
        if path in counted and path not in confirmed:
            failures.append(f"{path}: pending but counted by the report predicate")

    env = dict(os.environ)
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith(("NEO4J_PASSWORD=", "NEO4J_USER=")):
            key, _, value = line.partition("=")
            env[key] = value.strip().strip('"').strip("'")
    env.setdefault("NEO4J_USER", "neo4j")
    uid = _psql(f"select user_id from projects where id = '{project_id}'")
    run = subprocess.run(
        ["docker", "run", "--rm", "--network", "redamon-network", "-v", f"{REPO}:/repo", "-w", "/repo",
         "--user", f"{os.getuid()}:{os.getgid()}", "-e", "PYTHONPATH=/repo", "-e", "HOME=/tmp",
         "-e", "NEO4J_URI=bolt://redamon-neo4j:7687", "-e", "NEO4J_USER", "-e", "NEO4J_PASSWORD",
         "--entrypoint", "python", "redamon-agent:latest", "tooling/scripts/triage_eval.py",
         "--guinea-pig", "route_exposure_lab", "--user", uid, "--project", project_id],
        capture_output=True, text=True, env=env)
    out = run.stdout
    if run.returncode:
        # The last line names the exception type; the graph password never reaches it.
        failures.append(f"triage_eval.py exited {run.returncode}: {(run.stderr.strip().splitlines() or [''])[-1][:120]}")
    ranks =[ln.strip() for ln in out.splitlines() if re.match(r"\s*#\d+\s", ln)]
    report.append("- triage_eval.py (board order):")
    report.extend(f"  - `{ln}`" for ln in ranks)
    report.extend(f"  - {ln.strip()}" for ln in out.splitlines() if "NDCG" in ln)
    for ln in ranks:
        path = _lead_path(ln)
        if path in confirmed and " T1 " not in f" {ln} ":
            failures.append(f"triage_eval: {path} is confirmed but not T1")
    if not ranks:
        failures.append("triage_eval.py printed no ranking")

    report.append(f"- result: {'PASS' if not failures else 'FAIL'}")
    report.extend(f"  - {f}" for f in failures)
    print("\n".join(report))
    return 1 if failures else 0


def agent_leaks(path: str) -> int:
    text = Path(path).read_text(errors="replace")
    secrets_json = subprocess.run(["docker", "exec", CONTAINER.format("main"), "cat", "/tmp/lab-secrets.json"],
                                  capture_output=True, text=True).stdout
    values = json.loads(secrets_json or "{}")
    hits_found = [r for r in EXPECTED["agent_leak_rules"]["static"] if r in text]
    hits_found += [k for k in EXPECTED["agent_leak_rules"]["from_secrets"] if values.get(k) and values[k] in text]
    print("leak scan:", "clean" if not hits_found else "LEAK " + ", ".join(hits_found))
    return 1 if hits_found else 0


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "setup":
        cmd_setup(argv[2], "--start" in argv)
    elif cmd == "start":
        cmd_start(argv[2])
    elif cmd == "verify":
        return verify(argv[2], argv[3])
    elif cmd == "reset-hits":
        reset_hits()
    elif cmd == "agent-mark":
        cmd_agent_mark(argv[2])
    elif cmd == "agent-verify":
        return agent_verify(argv[2], argv[3], argv[4] if len(argv) > 4 else None)
    elif cmd == "agent-leaks":
        return agent_leaks(argv[2])
    elif cmd == "agent-check-ag14":
        return agent_check_ag14(argv[2])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

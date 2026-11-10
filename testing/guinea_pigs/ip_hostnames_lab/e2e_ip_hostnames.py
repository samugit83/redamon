#!/usr/bin/env python3
"""Drive the IP-hostnames lab's end-to-end matrix over MCP and REST (06_testing.md §4.5, §5).

    python3 e2e_ip_hostnames.py --plan                       # rows, gates, settings; contacts nothing
    python3 e2e_ip_hostnames.py --check-settings --rows E0,E1    # the server validates the settings; creates nothing
    python3 e2e_ip_hostnames.py --rows E0                    # today's IP mode: the before picture
    python3 e2e_ip_hostnames.py --rows E1,E2 --landed P0,P1,P2,P3
    python3 e2e_ip_hostnames.py --prepare --rows E4,E5,E6 --landed all   # create first, print the hook restart
    python3 e2e_ip_hostnames.py --rows E7 --landed all --token-var MCP_SERVER_TOKEN_LAB
    python3 e2e_ip_hostnames.py --snapshot <projectId> --label E14-before
    python3 e2e_ip_hostnames.py --compare generated/baselines/A generated/baselines/B [--volatile v.json]

Each row (expected_results.yaml) creates its own projects through MCP
create_project (IP mode, its engagementKind, the determinism settings, the
row's settings and hostname-policy fields), checks the scope
(preflight_scope_check), runs its sequence (full recon via start_recon and
get_recon_status; partial recon over the webapp's REST routes; rescope via
update_project_scope; DNS swaps via set_moved.sh), collects each step's
evidence into generated/runs/<row>-<stamp>/<step>/ (hit logs, CoreDNS log,
outsider capture, recon JSON, recon log) and validates it at once:
validate_ip_hostnames.py's functions, then generated/RESULTS.md.

Safety, before every scan: the lab prefix routes through the lab bridge, every
lab container runs, the host resolver answers the lab names (the .gov fixture
included) from the lab DNS, the capture is rotated; masscan is forced off in
every project and read back. A row whose plan step has not landed is skipped
(--landed); a hostname-policy field the server does not know yet (before P2)
stops that row with a message, never a crash. Credentials are read by name
from .env (iphn_lab) and never printed. The driver never restarts a RedAmon
container: when a row needs the orchestrator's lab hooks it prints the command.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iphn_lab as lab  # noqa: E402
import validate_ip_hostnames as v  # noqa: E402

PREPARED = lab.GEN / "prepared.json"
NWLAB = lab.HERE.parent / "nested_wildcard_lab"
BUSY = {"running", "starting", "queued", "pending", "stopping", "paused", "in_progress"}
PARTIAL_DONE = {"completed", "error", "idle", "stopped", "failed"}
POLICY_KEYS = ("ipHostnameMode", "ipHostnameInclude", "ipHostnameExclude", "ipHostnamePassiveExpand",
               "ipHostnameScanAllConfirmed", "ipHostnameMaxScanned", "ipHostnamePassiveMaxNames")


class RowAbort(Exception):
    """A row cannot go on (gate, refused field, failed step): reported, the next row runs."""


def log(sym: str, msg: str) -> None:
    print(f"[{sym}][Driver] {msg}", flush=True)


def lab_state() -> dict:
    p = lab.GEN / "lab.json"
    return json.loads(p.read_text()) if p.is_file() else {}


def load_prepared() -> dict:
    return json.loads(PREPARED.read_text()) if PREPARED.is_file() else {}


def save_prepared(data: dict) -> None:
    PREPARED.write_text(json.dumps(data, indent=1))


# --------------------------------------------------------------------------- substitution

_TOKEN = re.compile(r"\{([A-Za-z_][\w.:-]*)\}")


def fmt(obj, ctx: dict, resp=None):
    """{pid}, {pid:<label>}, {future_iso}, saved names and {resp.<path>} inside strings."""
    if isinstance(obj, str):
        def sub(m):
            key = m.group(1)
            if key.startswith("resp.") and resp is not None:
                got = v.walk(resp, key[5:])
                return str(got[0]) if got else m.group(0)
            return str(ctx[key]) if key in ctx else m.group(0)
        return _TOKEN.sub(sub, obj)
    if isinstance(obj, list):
        return [fmt(x, ctx, resp) for x in obj]
    if isinstance(obj, dict):
        return {k: fmt(x, ctx, resp) for k, x in obj.items()}
    return obj


def row_targets(p: dict, spec: dict) -> list[str]:
    targets = []
    for t in p.get("targets") or spec["defaults"]["targets"]:
        if t == "$intra":
            ip = lab_state().get("intra_ip")
            if not ip or not lab.container_running("iphn-intra"):
                raise RowAbort("needs iphn-intra on redamon-network (run ./up.sh with the RedAmon stack up)")
            targets.append(ip)
        else:
            targets.append(str(t))
    return targets


# --------------------------------------------------------------------------- gates

def gate_row(rid: str, row: dict, landed: set[str], force: bool) -> str | None:
    if row.get("kind") == "external":
        return "external row: " + " ".join(str(row.get("how", "")).split())[:300]
    missing = [s for s in v.needs_steps(row) if s not in landed and "all" not in landed]
    if missing and not force:
        return f"needs plan step(s) {missing} (declare them with --landed once they are deployed, or --force)"
    return None


def gate_lab(need_intra: bool = False) -> None:
    route = lab.routing_gate()
    problems = lab.lab_container_problems(("iphn-intra",) if need_intra else ())
    problems += lab.host_dns_problems(moved=lab_state().get("moved", "10"))
    if problems:
        raise RowAbort("lab pre-flight: " + "; ".join(problems))
    log("*", f"pre-flight ok: {route}")


def urlscan_key_state(web: lab.Webapp) -> str:
    """none | lab | other, from the masked Global Settings (the stub answers only lab-key)."""
    status, me = web.call("GET", "/api/auth/me")
    if status != 200 or not isinstance(me, dict) or not me.get("id"):
        raise RowAbort(f"/api/auth/me answered {status}")
    status, settings = web.call("GET", f"/api/users/{me['id']}/settings")
    if status != 200 or not isinstance(settings, dict):
        raise RowAbort(f"/api/users/<id>/settings answered {status}")
    masked = str(settings.get("urlscanApiKey") or "")
    extra = int(((settings.get("rotationConfigs") or {}).get("urlscan") or {}).get("extraKeyCount") or 0)
    if extra:
        return "other"
    return "none" if not masked else ("lab" if masked.endswith("-key") else "other")


# --------------------------------------------------------------------------- projects

def project_args(rid: str, label: str, p: dict, spec: dict, stamp: str) -> dict:
    settings = dict(spec["determinism"])
    settings.update(p.get("settings") or {})
    if settings.get("masscanEnabled"):
        raise RowAbort("masscan must stay off in every lab project: it ignores the route to the lab bridge")
    settings["masscanEnabled"] = False
    settings.update(p.get("policy") or {})
    kind = p.get("engagementKind") or spec["defaults"]["engagementKind"]
    args = {"name": f"iphn-{rid}-{label}-{stamp}", "engagementKind": kind,
            "description": f"Guinea pig: testing/guinea_pigs/ip_hostnames_lab, row {rid} ({label})",
            "targetIps": row_targets(p, spec), "settings": settings}
    if kind == "third_party":
        settings.setdefault("roeGlobalMaxRps", 20)
        if p.get("authorization", True):
            args["authorization"] = lab_authorization(f"{rid} {label}")
    return args


def lab_authorization(what: str) -> dict:
    return {"documentKind": "internal_ticket",
            "documentText": f"IPHN guinea-pig lab, {what}: 192.88.98.0/24 and reserved lab names only.",
            "issuedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": "IPHN lab, guinea-pig range only"}


def refused_key(text: str) -> str | None:
    m = re.search(r"'(\w+)' is not a recon setting", text)
    return m.group(1) if m else None


def explain_refusal(rid: str, text: str) -> str:
    key = refused_key(text)
    if key and key in POLICY_KEYS:
        return (f"the server does not know {key} yet: the hostname-policy fields arrive in plan step P2. "
                f"Row {rid} not run")
    if key:
        return f"the server refused setting {key!r} (renamed or removed?): {text[:200]}"
    return text[:400]


def verify_settings(mcp: lab.Mcp, pid: str, p: dict) -> None:
    out, err = mcp.call("get_recon_settings", {"projectId": pid})
    if err or not isinstance(out, dict):
        raise RowAbort(f"get_recon_settings failed: {json.dumps(out)[:300]}")
    stored = out.get("settings") or {}
    if stored.get("masscanEnabled") is not False:
        raise RowAbort(f"project {pid}: masscanEnabled reads {stored.get('masscanEnabled')!r}, not false. Not scanning")
    for key, want in (p.get("policy") or {}).items():
        if key in stored and stored[key] != want:
            raise RowAbort(f"project {pid}: {key} reads {stored[key]!r}, asked {want!r}")
        if key not in stored:
            raise RowAbort(f"project {pid}: {key} was accepted but get_recon_settings does not return it")


def create_projects(rid: str, row: dict, spec: dict, mcp: lab.Mcp, root: Path, stamp: str,
                    steps: list) -> dict:
    prepared = load_prepared().get(rid, {})
    pids = {}
    for label, p in v.projects(row, spec).items():
        step_dir = root / f"create-{label}"
        step_dir.mkdir(parents=True, exist_ok=True)
        if label in prepared:
            pids[label] = prepared[label]
            log("=", f"{rid}/{label}: prepared project {prepared[label]}")
            verify_settings(mcp, prepared[label], p)
            continue
        if row.get("requires_prepared"):
            raise RowAbort(f"project {label} must predate the change under test: run "
                           f"`--prepare --rows {rid}` before that step lands (README, row {rid})")
        args = project_args(rid, label, p, spec, stamp)
        out, err = mcp.call("create_project", args)
        text = out if isinstance(out, str) else json.dumps(out)
        pid = None if err else ((out.get("project") or {}).get("id") or out.get("projectId") or out.get("id"))
        expect = p.get("expect_create", "ok")
        result = {"ok": not err, "refused": bool(err), "text": text[:2000], "project_id": pid,
                  "expected": expect}
        (step_dir / "result.json").write_text(json.dumps(result, indent=1))
        (step_dir / "meta.json").write_text(json.dumps({"label": f"create-{label}", "kind": "create",
                                                        "project_id": pid, "targets": args["targetIps"],
                                                        "status": "refused" if err else "created"}, indent=1))
        steps.append({"label": f"create-{label}", "kind": "create", "status": "refused" if err else "created"})
        # An unknown field is never the refusal a row expects: before P2 every
        # governance refusal would otherwise "pass" for the wrong reason.
        if err and (expect != "refused" or refused_key(text)):
            raise RowAbort(f"create_project {label}: {explain_refusal(rid, text)}")
        if not err and expect == "refused":
            log("!", f"{rid}/{label}: create_project ACCEPTED a project the row expects refused ({pid}); "
                     "it is not scanned, delete it in the UI")
        if pid:
            pids[label] = pid
            log("+", f"{rid}/{label}: project {pid}")
            verify_settings(mcp, pid, p)
        else:
            log("*", f"{rid}/{label}: create_project refused, as expected: {text[:200]}")
    return pids


# --------------------------------------------------------------------------- evidence

def recon_container(pid: str) -> str:
    return "redamon-recon-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", pid)


def follow_log(pid: str, path: Path, wait_s: int = 120) -> subprocess.Popen | None:
    name = recon_container(pid)
    for _ in range(wait_s // 2):
        if lab.run_cmd("docker", "inspect", name).returncode == 0:
            return subprocess.Popen(["docker", "logs", "-f", name], stdout=path.open("w"), stderr=subprocess.STDOUT)
        time.sleep(2)
    log("!", f"{name} never appeared: no recon log")
    return None


def collect(step_dir: Path, pid: str, t0: float, t1: float) -> None:
    hits = step_dir / "hits"
    hits.mkdir(parents=True, exist_ok=True)
    for folder in sorted(lab.LOGS.glob("iphn-*")):
        lines = lab.read_hits(folder / "hits.jsonl", t0, t1)
        (hits / f"{folder.name}.jsonl").write_text("".join(json.dumps(h) + "\n" for h in lines))
    (step_dir / "dns.log").write_text(lab.dns_log_between(t0, t1))
    if lab.PCAP.is_file():
        shutil.copyfile(lab.PCAP, step_dir / "outsider.pcap")
    out_dir = lab.REPO / "recon" / "output"
    main = out_dir / f"recon_{pid}.json"
    if main.is_file():
        shutil.copyfile(main, step_dir / "recon.json")
    for extra in sorted(out_dir.glob(f"recon_{pid}_*.json")):
        shutil.copyfile(extra, step_dir / extra.name)


def write_meta(step_dir: Path, **info) -> dict:
    step_dir.mkdir(parents=True, exist_ok=True)
    path = step_dir / "meta.json"
    meta = json.loads(path.read_text()) if path.is_file() else {}
    meta.update(info)
    path.write_text(json.dumps(meta, indent=1, default=str))
    return meta


def user_id_of(mcp: lab.Mcp, pid: str) -> str | None:
    try:
        vals = mcp.cypher(pid, "MATCH (d:Domain) RETURN d.user_id AS v LIMIT 1")
    except RuntimeError:
        return None
    uid = str(vals[0]) if vals else ""
    return uid if re.fullmatch(r"[a-z0-9]{20,40}", uid) else None


def snapshot(mcp: lab.Mcp, pid: str, out: Path) -> int:
    """nested_wildcard_lab's snapshot_graph.py, called as is (tenant-scoped reads, Neo4j HTTP)."""
    uid = user_id_of(mcp, pid)
    if not uid:
        log("!", f"no user id for {pid}: is its graph empty?")
        return 1
    out.mkdir(parents=True, exist_ok=True)
    rc = subprocess.run([sys.executable, "-I", str(NWLAB / "snapshot_graph.py"), "--project-id", pid,
                         "--user-id", uid, "--out", str(out)]).returncode
    log("+" if rc == 0 else "!", f"snapshot of {pid} -> {out} (exit {rc})")
    return rc


# --------------------------------------------------------------------------- steps

def wait_recon(mcp: lab.Mcp, pid: str, t0: float, timeout: int, every: int = 15) -> dict:
    """Poll until the run is over. An idle answer before the job was ever seen
    running is the state from before the start, so the start gets two minutes."""
    deadline, last, seen_busy = t0 + timeout, None, False
    time.sleep(20)
    while time.time() < deadline:
        state, err = mcp.call("get_recon_status", {"projectId": pid})
        state = state if isinstance(state, dict) else {}
        status = str(state.get("status") or "").lower()
        busy = status in BUSY or bool(state.get("running"))
        seen_busy |= busy
        view = f"{status} phase={state.get('currentPhase')} {state.get('phaseNumber')}/{state.get('totalPhases')}"
        if view != last:
            log("*", f"{time.strftime('%H:%M:%S')} get_recon_status: {view}")
            last = view
        if not err and status and not busy and (seen_busy or time.time() - t0 > 120):
            # The ScanJob row is written as the container ends: give it a minute.
            for _ in range(12):
                run = state.get("lastRun") or {}
                started = run.get("startedAt")
                fresh = started and datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp() >= t0 - 60
                if fresh and str(run.get("status")).lower() not in BUSY:
                    return state
                time.sleep(5)
                state, _ = mcp.call("get_recon_status", {"projectId": pid})
                state = state if isinstance(state, dict) else {}
            return state
        time.sleep(every)
    mcp.call("stop_recon", {"projectId": pid})
    raise RowAbort(f"recon still running after {timeout}s: stop_recon sent")


def do_run(ctx: dict, step: dict, step_dir: Path) -> dict:
    mcp, pid = ctx["mcp"], ctx["pid"]
    gate_lab(ctx["need_intra"])
    lab.rotate_pcap()
    pre, err = mcp.call("preflight_scope_check", {"projectId": pid})
    (step_dir / "preflight.json").write_text(json.dumps(pre, indent=1, default=str))
    if err or not isinstance(pre, dict):
        raise RowAbort(f"preflight_scope_check failed: {json.dumps(pre)[:300]}")
    if pre.get("startable") is False:
        raise RowAbort(f"preflight_scope_check says not startable: {json.dumps(pre)[:400]}")
    log("*", f"preflight_scope_check: startable={pre.get('startable')} (full answer in {step_dir.name}/preflight.json)")
    t0 = time.time()
    write_meta(step_dir, label=step_dir.name, kind="run", project_id=pid, targets=ctx["targets"], t_start=t0)
    started, err = mcp.call("start_recon", {"projectId": pid, "mode": "new"})
    if err:
        raise RowAbort(f"start_recon refused: {json.dumps(started)[:400]}")
    log("+", f"start_recon {pid}: {json.dumps(started)[:200]}")
    tail = follow_log(pid, step_dir / "recon.log")
    try:
        final = wait_recon(mcp, pid, t0, ctx["timeout"])
    finally:
        if tail:
            time.sleep(3)
            tail.terminate()
    t1 = time.time() + 2
    time.sleep(2)
    last = final.get("lastRun") or {}
    started = last.get("startedAt")
    # A ScanJob from an earlier run of the same project (E6, E8) must not stand in for this one.
    fresh = bool(started) and datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp() >= t0 - 60
    status = str((last.get("status") if fresh else None) or final.get("status") or "unknown").lower()
    collect(step_dir, pid, t0, t1)
    meta = write_meta(step_dir, t_end=t1, status=status, orchestrator_status=final.get("status"),
                      failed=final.get("failed"), last_run=last)
    log("+" if status == "completed" else "!", f"recon on {pid} ended: {status} ({int(t1 - t0)}s)")
    if ctx["row"].get("snapshot"):
        snapshot(mcp, pid, step_dir / "snapshot")
    return meta


def partial_body(ctx: dict, spec_partial: dict) -> dict:
    body = {"tool_id": spec_partial["tool_id"], "graph_inputs": {"domains": [f"ip-targets.{ctx['pid']}"]},
            "user_inputs": spec_partial.get("user_inputs") or [],
            "include_graph_targets": spec_partial.get("include_graph_targets", True)}
    if spec_partial.get("user_targets") is not None:
        body["user_targets"] = spec_partial["user_targets"]
    if spec_partial.get("settings_overrides"):
        body["settings_overrides"] = spec_partial["settings_overrides"]
    return body


def web(ctx: dict) -> lab.Webapp:
    if ctx.get("web") is None:
        ctx["web"] = lab.Webapp()
    return ctx["web"]


def do_partial(ctx: dict, step: dict, step_dir: Path) -> dict:
    pid = ctx["pid"]
    gate_lab(ctx["need_intra"])
    lab.rotate_pcap()
    body = partial_body(ctx, step["partial"])
    t0 = time.time()
    write_meta(step_dir, label=step_dir.name, kind="partial", project_id=pid, targets=ctx["targets"], t_start=t0,
               tool_id=body["tool_id"])
    status, resp = web(ctx).call("POST", f"/api/recon/{pid}/partial", body)
    result = {"accepted": status == 200, "refused": status != 200, "http": status,
              "text": json.dumps(resp)[:2000], "run_id": (resp or {}).get("run_id") if isinstance(resp, dict) else None}
    (step_dir / "result.json").write_text(json.dumps(result, indent=1))
    log("+" if status == 200 else "*", f"partial {body['tool_id']} on {pid}: HTTP {status} {result['text'][:160]}")
    if status != 200 or step["partial"].get("wait", True) is False:
        if status != 200:
            t1 = time.time() + 1
            collect(step_dir, pid, t0, t1)
            write_meta(step_dir, t_end=t1, status="refused")
        return result
    return finish_partial(ctx, step_dir)


def finish_partial(ctx: dict, step_dir: Path) -> dict:
    pid = ctx["pid"]
    meta = json.loads((step_dir / "meta.json").read_text())
    result = json.loads((step_dir / "result.json").read_text())
    run_id = result.get("run_id")
    if not run_id:
        raise RowAbort(f"partial {meta.get('tool_id')} was accepted without a run id: {result.get('text', '')[:200]}")
    deadline, state = time.time() + ctx["timeout"], {}
    while time.time() < deadline:
        time.sleep(10)
        _, state = web(ctx).call("GET", f"/api/recon/{pid}/partial/{run_id}/status")
        if str((state or {}).get("status")) in PARTIAL_DONE:
            break
    t1 = time.time() + 2
    time.sleep(2)
    collect(step_dir, pid, meta["t_start"], t1)
    final = str((state or {}).get("status") or "unknown")
    result.update(final_status=final, error=(state or {}).get("error"))
    (step_dir / "result.json").write_text(json.dumps(result, indent=1, default=str))
    write_meta(step_dir, t_end=t1, status=final)
    log("+" if final == "completed" else "!", f"partial {meta.get('tool_id')} on {pid}: {final}")
    return result


def do_rescope(ctx: dict, step: dict, step_dir: Path) -> dict:
    spec_r = step["rescope"]
    args = {"projectId": ctx["pid"], "changes": fmt(spec_r["changes"], ctx["vars"])}
    if spec_r.get("authorization"):
        args["authorization"] = lab_authorization(f"{ctx['rid']} rescope")
    out, err = ctx["mcp"].call("update_project_scope", args)
    text = out if isinstance(out, str) else json.dumps(out)
    if err and "project:rescope" in text:
        raise RowAbort("this MCP token lacks project:rescope: run the row with --token-var naming a token "
                       "that has it (e.g. MCP_SERVER_TOKEN_LAB)")
    result = {"ok": not err, "refused": bool(err), "text": text[:2000], "body": out if isinstance(out, dict) else None}
    (step_dir / "result.json").write_text(json.dumps(result, indent=1, default=str))
    write_meta(step_dir, label=step_dir.name, kind="rescope", project_id=ctx["pid"], targets=ctx["targets"],
               status="refused" if err else "ok")
    log("+" if not err else "*", f"update_project_scope {ctx['pid']}: {'refused' if err else 'ok'} {text[:200]}")
    return result


def do_mcp(ctx: dict, step: dict, step_dir: Path) -> dict:
    spec_m = fmt(step["mcp"], ctx["vars"])
    out, err = ctx["mcp"].call(spec_m["tool"], spec_m.get("args") or {})
    text = out if isinstance(out, str) else json.dumps(out)
    result = {"ok": not err, "refused": bool(err), "text": text[:4000], "body": out if isinstance(out, dict) else None}
    (step_dir / "result.json").write_text(json.dumps(result, indent=1, default=str))
    write_meta(step_dir, label=step_dir.name, kind="mcp", project_id=ctx["pid"], targets=ctx["targets"],
               status="refused" if err else "ok")
    log("+" if not err else "*", f"{spec_m['tool']}: {'refused' if err else 'ok'} {text[:160]}")
    return result


def do_rest(ctx: dict, step: dict, step_dir: Path) -> dict:
    spec_r = fmt(step["rest"], ctx["vars"])
    status, resp = web(ctx).call(spec_r["method"], spec_r["path"], spec_r.get("body"))
    result = {"ok": status < 400, "refused": status >= 400, "status": status, "text": json.dumps(resp)[:2000],
              "body": resp}
    (step_dir / "result.json").write_text(json.dumps(result, indent=1, default=str))
    write_meta(step_dir, label=step_dir.name, kind="rest", project_id=ctx["pid"], targets=ctx["targets"],
               status=status)
    log("+" if status < 400 else "*", f"{spec_r['method']} {spec_r['path']}: HTTP {status} {result['text'][:160]}")
    if status < 400:
        for name, path in (step["rest"].get("save") or {}).items():
            got = v.walk(resp, path)
            if got:
                ctx["vars"][name] = got[0]
        if step["rest"].get("cleanup"):
            ctx["cleanups"].append(fmt(step["rest"]["cleanup"], ctx["vars"], resp))
    return result


def do_zone(ctx: dict, step: dict, step_dir: Path) -> dict:
    target = str(step["zone"]["moved"])
    out = lab.run_cmd(str(lab.HERE / "set_moved.sh"), target, timeout=120)
    print(out.stdout.strip(), flush=True)
    if out.returncode != 0:
        raise RowAbort(f"set_moved.sh {target} failed: {out.stderr.strip()[:300]}")
    ctx["zone_changed"] = True
    # TTL 1 s: one more second and the host resolver has forgotten the old answer.
    time.sleep(3)
    write_meta(step_dir, label=step_dir.name, kind="zone", moved=target, status="ok")
    return {"moved": target}


def run_step(ctx: dict, step: dict, root: Path, steps: list) -> None:
    action = v.action_of(step)
    label = v.step_label(step)
    on = step.get("project") or ("main" if "main" in ctx["pids"] else None)
    if on is None and action in ("run", "partial", "partial_wait", "rescope"):
        raise RowAbort(f"step {label} ({action}) needs a project: name one with `project:`")
    if on is not None and on not in ctx["pids"]:
        raise RowAbort(f"step {label} runs on project {on!r}, which was not created")
    ctx["pid"] = ctx["pids"].get(on) if on else None
    ctx["targets"] = ctx["targets_of"].get(on, []) if on else []
    ctx["vars"]["pid"] = ctx["pid"]
    step_dir = root / label
    step_dir.mkdir(parents=True, exist_ok=True)
    log("*", f"{ctx['rid']} step {label} ({action} on {on})")
    if action == "run":
        do_run(ctx, step, step_dir)
    elif action == "partial":
        do_partial(ctx, step, step_dir)
        if step["partial"].get("wait", True) is False and (json.loads((step_dir / "result.json").read_text())
                                                             .get("accepted")):
            steps.append({"label": label, "kind": "partial-started", "status": "started"})
            return
    elif action == "partial_wait":
        if (step_dir / "result.json").is_file() and json.loads((step_dir / "result.json").read_text()).get("accepted"):
            finish_partial(ctx, step_dir)
    elif action == "rescope":
        do_rescope(ctx, step, step_dir)
    elif action == "mcp":
        do_mcp(ctx, step, step_dir)
    elif action == "rest":
        do_rest(ctx, step, step_dir)
    elif action == "zone":
        do_zone(ctx, step, step_dir)
    elif action == "wait":
        time.sleep(int(step["wait"]))
        write_meta(step_dir, label=label, kind="wait", status="ok")
    meta = json.loads((step_dir / "meta.json").read_text()) if (step_dir / "meta.json").is_file() else {}
    steps.append({"label": label, "kind": action, "status": meta.get("status")})
    if not ctx["no_validate"]:
        v.validate_step(ctx["spec"], ctx["rid"], label, action, step_dir, ctx["mcp"])


# --------------------------------------------------------------------------- rows

def run_row(rid: str, spec: dict, args, mcp: lab.Mcp) -> str:
    row = spec["rows"][rid]
    stamp = time.strftime("%Y%m%dT%H%M%S")
    root = lab.RUNS / f"{rid}-{stamp}"
    info = {"row": rid, "title": row["title"], "started": stamp, "steps": [], "projects": {}}
    skip = gate_row(rid, row, args.landed, args.force)
    if skip:
        log("-", f"{rid}: skipped: {skip}")
        return "MANUAL" if row.get("kind") == "external" else "SKIPPED"
    root.mkdir(parents=True, exist_ok=True)
    ctx = {"rid": rid, "row": row, "spec": spec, "mcp": mcp, "timeout": args.timeout, "web": None,
           "vars": {"future_iso": (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%dT03:00:00Z")},
           "cleanups": [], "zone_changed": False, "no_validate": args.no_validate,
           "need_intra": any("$intra" in (p.get("targets") or []) for p in v.projects(row, spec).values())}
    outcome, reason = "PASS", ""
    try:
        lab.routing_gate()
        hooks = (row.get("lab") or {}).get("hooks") or []
        if hooks and rid not in load_prepared():
            raise RowAbort(f"needs the orchestrator's lab hooks {hooks} for its project ids: run "
                           f"`--prepare --rows {rid}` first, restart the orchestrator with the printed command")
        if (row.get("lab") or {}).get("urlscan_key") == "lab" and urlscan_key_state(web(ctx)) != "lab":
            raise RowAbort("the account's urlscan key (Global Settings) must be `lab-key` with no extra keys: "
                           "the stub answers 401 to any other key. Set it for this row, clear it after")
        # Every gate that can fail runs BEFORE a project exists: a refused row leaves nothing behind.
        acts = [v.action_of(s) for s in v.sequence(row)]
        if any(a in ("run", "partial") for a in acts):
            gate_lab(ctx["need_intra"])
        if "rescope" in acts:
            # The scope check precedes the project lookup, so an unknown id reads the token's scopes.
            out, _ = mcp.call("update_project_scope", {"projectId": "iphn-scope-probe", "changes": {}})
            if "project:rescope" in json.dumps(out):
                raise RowAbort("this MCP token lacks project:rescope: run the row with --token-var naming a "
                               "token that has it (e.g. MCP_SERVER_TOKEN_LAB)")
        pids = create_projects(rid, row, spec, mcp, root, stamp, info["steps"])
        info["projects"] = pids
        ctx["pids"] = pids
        ctx["targets_of"] = {label: row_targets(p, spec) for label, p in v.projects(row, spec).items()}
        for label in pids:
            ctx["vars"][f"pid:{label}"] = pids[label]
        if hooks:
            problems = lab.hook_problems(list(pids.values()), hooks)
            if problems:
                raise RowAbort("orchestrator hooks: " + "; ".join(problems) + ". From the repository root: "
                               + lab.hook_command(list(pids.values()), hooks))
        if not args.no_validate:
            for step in list(info["steps"]):
                v.validate_step(spec, rid, step["label"], "create", root / step["label"], mcp)
        for step in v.sequence(row):
            run_step(ctx, step, root, info["steps"])
    except RowAbort as e:
        outcome, reason = "ABORTED", str(e)
        log("!", f"{rid}: {reason}")
    finally:
        for c in ctx["cleanups"]:
            status, _ = web(ctx).call(c["method"], c["path"])
            log("*", f"cleanup {c['method']} {c['path']}: HTTP {status}")
        if ctx["zone_changed"] and lab_state().get("moved") != "10":
            lab.run_cmd(str(lab.HERE / "set_moved.sh"), "10", timeout=120)
            log("*", "moved.example-a.test restored to 192.88.98.10")
    if outcome == "PASS":
        failed = 0
        for step in info["steps"]:
            cj = root / step["label"] / "checks.json"
            if cj.is_file():
                failed += sum(r["status"] == "FAIL" for r in json.loads(cj.read_text()))
        outcome = "FAIL" if failed else "PASS"
    info.update(outcome=outcome, reason=reason, finished=time.strftime("%Y%m%dT%H%M%S"))
    (root / "row.json").write_text(json.dumps(info, indent=1))
    log("+" if outcome == "PASS" else "!", f"{rid}: {outcome}{' (' + reason + ')' if reason else ''} -> {root}")
    return outcome


def prepare(rows: list[str], spec: dict, args, mcp: lab.Mcp) -> int:
    lab.routing_gate()
    prepared = load_prepared()
    stamp = time.strftime("%Y%m%dT%H%M%S")
    hook_rows: dict[str, list[str]] = {}
    for rid in rows:
        row = spec["rows"][rid]
        skip = gate_row(rid, row, args.landed, args.force)
        if skip and not row.get("requires_prepared"):
            log("-", f"{rid}: not prepared: {skip}")
            continue
        for label, p in v.projects(row, spec).items():
            if label in prepared.get(rid, {}) or p.get("expect_create") == "refused":
                continue
            try:
                a = project_args(rid, label, p, spec, stamp)
            except RowAbort as e:
                log("!", f"{rid}/{label}: {e}")
                continue
            out, err = mcp.call("create_project", a)
            text = out if isinstance(out, str) else json.dumps(out)
            if err:
                log("!", f"{rid}/{label}: {explain_refusal(rid, text)}")
                continue
            pid = (out.get("project") or {}).get("id") or out.get("projectId") or out.get("id")
            prepared.setdefault(rid, {})[label] = pid
            save_prepared(prepared)
            log("+", f"{rid}/{label}: project {pid} prepared")
        for need in (row.get("lab") or {}).get("hooks") or []:
            hook_rows.setdefault(need, []).append(rid)
    ids = sorted({pid for rid in {r for rs in hook_rows.values() for r in rs}
                  for pid in prepared.get(rid, {}).values()})
    if ids:
        print("\nRestart the orchestrator with the lab hooks, from the repository root:\n")
        print("  " + lab.hook_command(ids, sorted(hook_rows)) + "\n")
        print("Remove them afterwards (down.sh refuses while they point at this lab):\n"
              "  env -u URLSCAN_API_BASE -u REDAMON_LAB_CDN_PREFIXES -u REDAMON_LAB_PROJECT_IDS "
              "docker compose up -d --no-deps recon-orchestrator\n")
    return 0


def check_settings(rows: list[str], spec: dict, mcp: lab.Mcp) -> int:
    """Have the server validate each project's settings WITHOUT creating anything.

    create_project validates `settings` (filterSettingsAtCreate) before it checks
    that a third_party engagement declares a rate ceiling, and that check refuses
    before the row exists. So a third_party create with roeGlobalMaxRps 0 and no
    authorization answers "ceiling" when every setting is valid, or names the
    first refused setting. Two independent refusals guard against a write."""
    bad = 0
    for rid in rows:
        row = spec["rows"][rid]
        if row.get("kind") == "external":
            continue
        for label, p in v.projects(row, spec).items():
            settings = {**spec["determinism"], **(p.get("settings") or {}), **(p.get("policy") or {}),
                        "masscanEnabled": False, "roeGlobalMaxRps": 0}
            targets = [t for t in (p.get("targets") or spec["defaults"]["targets"]) if t != "$intra"] \
                or [f"{lab.NET}.10"]
            out, err = mcp.call("create_project", {"name": f"iphn-settings-probe-{rid}-{label}",
                                                   "engagementKind": "third_party", "targetIps": targets,
                                                   "settings": settings})
            text = out if isinstance(out, str) else json.dumps(out)
            if not err:
                bad += 1
                log("!", f"{rid}/{label}: the probe CREATED a project ({text[:200]}): delete it by hand")
            elif "rate ceiling" in text:
                log("+", f"{rid}/{label}: all {len(settings)} settings accepted by the server")
            else:
                bad += 1
                log("!", f"{rid}/{label}: {explain_refusal(rid, text)}")
    return 1 if bad else 0


def plan(spec: dict, landed: set[str], force: bool) -> None:
    print(f"Determinism settings ({len(spec['determinism'])}): masscan forced off; "
          + ", ".join(f"{k}={json.dumps(x)}" for k, x in sorted(spec["determinism"].items()))[:900] + " ...\n")
    for rid in v.ROW_IDS:
        row = spec["rows"][rid]
        skip = gate_row(rid, row, landed, force)
        state = "RUN " if not skip else ("EXT " if row.get("kind") == "external" else "SKIP")
        print(f"{rid:4s} {state} needs {','.join(v.needs_steps(row)) or '-':8s} {row['title']}")
        if row.get("kind") == "external":
            continue
        for label, p in v.projects(row, spec).items():
            print(f"       project {label}: targets {p.get('targets') or spec['defaults']['targets']} "
                  f"{p.get('engagementKind', 'internal')} policy {json.dumps(p.get('policy') or {})}"
                  + (f" settings {json.dumps(p.get('settings'))}" if p.get("settings") else "")
                  + (" (create must be REFUSED)" if p.get("expect_create") == "refused" else ""))
        if (row.get("lab") or {}):
            print(f"       lab: {json.dumps(row['lab'])}")
        for st in v.sequence(row):
            label, kind = v.step_label(st), v.action_of(st)
            print(f"       {kind:12s} {label:24s} on {st.get('project', 'main'):12s} "
                  f"{len(v.checks_for(spec, rid, label, kind))} check(s)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--rows", default="", help="comma-separated row ids, e.g. E0,E1")
    ap.add_argument("--landed", default="", help="plan steps deployed, e.g. P0,P1,P2 (or all)")
    ap.add_argument("--force", action="store_true", help="run rows whose plan step is not declared landed")
    ap.add_argument("--prepare", action="store_true", help="create the rows' projects only, print the hook command")
    ap.add_argument("--check-settings", action="store_true",
                    help="have the server validate the rows' settings; creates nothing")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--token-var", help="the .env variable holding the MCP token (default MCP_SERVER_TOKEN)")
    ap.add_argument("--no-validate", action="store_true")
    ap.add_argument("--out", type=Path, default=lab.GEN / "RESULTS.md")
    ap.add_argument("--snapshot", metavar="PROJECT_ID")
    ap.add_argument("--label", help="with --snapshot: generated/baselines/<label>")
    ap.add_argument("--compare", nargs=2, metavar=("BASELINE", "CURRENT"), type=Path)
    ap.add_argument("--volatile", type=Path)
    args = ap.parse_args()
    args.landed = {s.strip() for s in args.landed.split(",") if s.strip()}

    spec = v.load_expected()
    problems = v.spec_problems(spec)
    if problems:
        for p in problems:
            log("!", p)
        return 1
    if args.plan:
        plan(spec, args.landed, args.force)
        return 0
    if args.compare:
        cmd = [sys.executable, "-I", str(NWLAB / "compare_snapshots.py"), str(args.compare[0]), str(args.compare[1])]
        if args.volatile:
            cmd += ["--volatile", str(args.volatile)]
        return subprocess.run(cmd).returncode
    mcp = lab.Mcp(args.token_var)
    if args.snapshot:
        if not args.label:
            ap.error("--snapshot needs --label")
        return snapshot(mcp, args.snapshot, lab.GEN / "baselines" / args.label)
    rows = [r.strip() for r in args.rows.split(",") if r.strip()]
    unknown = [r for r in rows if r not in spec["rows"]]
    if not rows or unknown:
        ap.error(f"--rows needs row ids from expected_results.yaml (unknown: {unknown})")
    if args.check_settings:
        return check_settings(rows, spec, mcp)
    if args.prepare:
        return prepare(rows, spec, args, mcp)
    outcomes = {rid: run_row(rid, spec, args, mcp) for rid in rows}
    v.write_report(args.out, spec, v.latest_runs())
    print("\n" + "  ".join(f"{rid}={o}" for rid, o in outcomes.items()))
    return 0 if all(o in ("PASS", "SKIPPED", "MANUAL") for o in outcomes.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

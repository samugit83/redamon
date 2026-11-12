#!/usr/bin/env python3
"""Run one full recon on a lab project and snapshot it.

    run_scan.py --project-id <pid> --user-id <uid> --out <dir> [--poll 60]

1. The routing gate: 192.88.99.60 must route through a docker bridge and a lab
   name must resolve through the host resolver. Either failing aborts (exit 2):
   192.88.99.0/24 is a public prefix that reaches the internet when the lab
   bridge is down.
2. start_recon through the inbound MCP server (mode "new"), never the
   orchestrator's /start, so a version is frozen and a ScanJob written.
3. Follows the recon container's log into <dir>/recon.log.
4. Polls get_recon_status every --poll seconds until the run ends.
5. Snapshots the graph and recon JSON into <dir> (snapshot_graph.py).
6. With --watch-argv, records the command line of every scanner process the
   run starts (host processes: the tools' containers share the host's PID
   view) into <dir>/argv.jsonl, for argv assertions.

Exit 0 when the run completed, 1 otherwise. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nwlab_mcp  # noqa: E402
import snapshot_graph  # noqa: E402

_DONE = {"completed", "failed", "error", "canceled", "cancelled", "stopped", "refused"}


def routing_gate() -> None:
    route = subprocess.run(["ip", "route", "get", "192.88.99.60"], capture_output=True, text=True).stdout
    if " dev br-" not in route:
        sys.exit(f"routing gate FAILED: {route.strip()!r}; the lab bridge is down. Not scanning.")
    dns = subprocess.run(["resolvectl", "query", "v1.api.nwlab.test"], capture_output=True, text=True)
    if dns.returncode != 0 or "192.88.99.60" not in dns.stdout:
        sys.exit("routing gate FAILED: v1.api.nwlab.test does not resolve through the host. Not scanning.")
    print(f"[gate] ok: {route.splitlines()[0]}")


# Command prefixes of the scanner processes worth recording (each tool's
# entrypoint as `ps` shows it).
_TOOLS = ("httpx ", "nuclei ", "nmap ", "naabu ", "katana ", "hakrawler", "tlsx ", "subjack ", "/wcvs ")


def _is_tool(cmd: str) -> bool:
    # Arjun is a Python script: its name is the interpreter's first argument.
    return cmd.startswith(_TOOLS) or any(t.rsplit("/", 1)[-1] == "arjun" for t in cmd.split()[:3])


def watch_argv(path: Path, stop: threading.Event) -> None:
    """Every scanner process seen while the run lasts: first/last seen and its argv."""
    seen: dict = {}
    while not stop.is_set():
        out = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True).stdout
        now = time.time()
        for ln in out.splitlines():
            pid, _, cmd = ln.strip().partition(" ")
            if _is_tool(cmd):
                seen.setdefault(pid + cmd[:40], {"pid": pid, "cmd": cmd, "first": now})["last"] = now
        time.sleep(0.5)
    with path.open("w") as fh:
        for row in seen.values():
            fh.write(json.dumps(row) + "\n")


def follow_logs(project_id: str, log_path: Path) -> subprocess.Popen | None:
    name = "redamon-recon-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", project_id)
    for _ in range(60):
        if subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0:
            return subprocess.Popen(["docker", "logs", "-f", name], stdout=log_path.open("w"),
                                    stderr=subprocess.STDOUT)
        time.sleep(2)
    print(f"[logs] container {name} never appeared")
    return None


def start_scan(project_id: str) -> None:
    for _ in range(10):
        routing_gate()
        try:
            started = nwlab_mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
            print(f"[start] {json.dumps(started)[:300]}")
            return
        except nwlab_mcp.ToolError as e:
            # The token's start bucket is per window; the error names the wait.
            wait = re.search(r"Try again in (\d+)s", str(e))
            if not wait:
                raise
            print(f"[start] rate limited, retrying in {int(wait.group(1)) + 5}s", flush=True)
            time.sleep(int(wait.group(1)) + 5)
    sys.exit("start_recon stayed rate limited")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--poll", type=int, default=60)
    ap.add_argument("--watch-argv", action="store_true",
                    help="record every scanner process's argv into <out>/argv.jsonl")
    ap.add_argument("--resume", action="store_true",
                    help="do not start a scan: follow the one already running, then snapshot it")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    if a.resume:
        print("[start] resuming: following the scan already running")
    else:
        start_scan(a.project_id)
    stop = threading.Event()
    watcher = None
    if a.watch_argv:
        watcher = threading.Thread(target=watch_argv, args=(a.out / "argv.jsonl", stop), daemon=True)
        watcher.start()
    tail = follow_logs(a.project_id, a.out / "recon.log")

    status: dict = {}
    while True:
        time.sleep(a.poll)
        try:
            status = nwlab_mcp.call("get_recon_status", {"projectId": a.project_id})
        except nwlab_mcp.ToolError as e:
            print(f"[poll] {e}")
            continue
        running = status.get("status") not in ("idle", "completed", "error", "stopped")
        last = status.get("lastRun") or {}
        print(f"[poll] {status.get('status')} phase={status.get('currentPhase')} "
              f"group={status.get('groupNumber')}/{status.get('totalGroups')} last={last.get('status')}", flush=True)
        if not running and last.get("status") in _DONE:
            break

    stop.set()
    if watcher:
        watcher.join(timeout=10)
    if tail:
        time.sleep(3)
        tail.terminate()
    (a.out / "status.json").write_text(json.dumps(status, indent=2))
    snapshot_graph.snapshot(a.project_id, a.user_id, a.out)
    ok = (status.get("lastRun") or {}).get("completed") is True
    print(f"[done] lastRun={json.dumps(status.get('lastRun'))} snapshot={a.out / 'graph.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

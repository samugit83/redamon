"""Start one partial recon run on an FP lab project over the webapp's REST API.

    python3 partial_fp.py <projectId> <toolId> [--body JSON] [--upload FILE]
                          [--log PATH] [--no-wait] [--timeout S]

Signs in with UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD (read from the repo .env by
name, never printed), optionally uploads a JS file through
/api/js-recon/<pid>/upload, POSTs /api/recon/<pid>/partial with
{"tool_id": <toolId>, "include_graph_targets": true} updated by --body, follows
redamon-partial-recon-<pid>-<run8> into --log, and polls the run's status.
Prints RUN_ID=<id> and RUN_STATUS=<status>; a refused start prints
REFUSED=<http status> with the webapp's answer and exits 2.
"""
import argparse
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def env_value(name):
    with open(os.path.join(REPO, ".env"), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


class Web:
    def __init__(self):
        self.base = os.environ.get("REDAMON_WEB") or f"http://localhost:{env_value('WEBAPP_PORT') or '3000'}"
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, body=None, headers=None, timeout=120):
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw)
            except ValueError:
                return exc.code, {"error": raw.decode("utf-8", "replace")[:300]}

    def json(self, method, path, payload):
        return self.request(method, path, json.dumps(payload).encode(), {"Content-Type": "application/json"})

    def login(self):
        user, password = env_value("UI_LOGIN_USERNAME"), env_value("UI_LOGIN_PASSWORD")
        if not user or not password:
            raise SystemExit("[!] UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env")
        status, out = self.json("POST", "/api/auth/login", {"email": user, "password": password})
        if status != 200:
            raise SystemExit(f"[!] login refused ({status}): {out.get('error')}")

    def upload(self, pid, path):
        name = os.path.basename(path)
        with open(path, "rb") as fh:
            data = fh.read()
        boundary = "----fplab" + uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                "Content-Type: application/javascript\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        status, out = self.request("POST", f"/api/js-recon/{pid}/upload", body,
                                   {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        if status == 409:
            self.request("DELETE", f"/api/js-recon/{pid}/upload?name={urllib.request.quote(name)}")
            status, out = self.request("POST", f"/api/js-recon/{pid}/upload", body,
                                       {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        return status, out


def follow_logs(pid, run_id, path):
    name = f"redamon-partial-recon-{re.sub(r'[^a-zA-Z0-9_.-]', '_', pid)}-{run_id[:8]}"
    for _ in range(60):
        if subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0:
            return subprocess.Popen(["docker", "logs", "-f", name], stdout=open(path, "w"),
                                    stderr=subprocess.STDOUT)
        time.sleep(1)
    print(f"[!] container {name} never appeared: no log", flush=True)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("project_id")
    ap.add_argument("tool_id")
    ap.add_argument("--body", default="{}", help="JSON merged over the default request body")
    ap.add_argument("--upload", metavar="FILE")
    ap.add_argument("--log", metavar="PATH")
    ap.add_argument("--no-wait", action="store_true")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()
    pid = args.project_id
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", pid):
        raise SystemExit("[!] not a project id")

    web = Web()
    web.login()
    if args.upload:
        status, out = web.upload(pid, args.upload)
        print(f"[*] upload {os.path.basename(args.upload)}: HTTP {status} {json.dumps(out)[:200]}", flush=True)
        if status != 200:
            raise SystemExit(1)
    body = {"tool_id": args.tool_id, "graph_inputs": {}, "include_graph_targets": True, **json.loads(args.body)}
    print(f"RUN_START={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}", flush=True)
    status, out = web.json("POST", f"/api/recon/{pid}/partial", body)
    if status != 200 or not out.get("run_id"):
        print(f"REFUSED={status} {json.dumps(out)[:600]}", flush=True)
        sys.exit(2)
    run_id = out["run_id"]
    print(f"RUN_ID={run_id}", flush=True)
    tail = follow_logs(pid, run_id, args.log) if args.log else None
    if args.no_wait:
        return
    deadline, last, seen_running, state = time.time() + args.timeout, None, False, {}
    while time.time() < deadline:
        status, state = web.request("GET", f"/api/recon/{pid}/partial/{run_id}/status")
        st = str(state.get("status", "")).lower() if status == 200 else f"http {status}"
        if st != last:
            print(f"    {time.strftime('%H:%M:%S')} status: {st}", flush=True)
            last = st
        seen_running |= st in ("starting", "running", "stopping")
        if st in ("completed", "error") or (st == "idle" and seen_running):
            break
        time.sleep(3)
    else:
        raise SystemExit(f"[!] partial recon still running after {args.timeout}s")
    if tail:
        time.sleep(3)
        tail.terminate()
    print(f"RUN_STATUS={state.get('status')} stats={json.dumps(state.get('stats') or {})[:300]}"
          + (f" error={str(state.get('error'))[:300]}" if state.get("error") else ""), flush=True)


if __name__ == "__main__":
    main()

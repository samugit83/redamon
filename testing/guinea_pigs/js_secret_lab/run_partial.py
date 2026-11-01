#!/usr/bin/env python3
"""Scenario E4: a partial JS Recon run of a lab project, with an uploaded file.

    python3 run_partial.py <projectId> [--log partial.log] [--upload FILE | --no-upload]
                           [--url http://192.88.96.10/ ...] [--keep-existing]

Signs in to the webapp over REST with UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD
(read from the repo .env by name, never printed), uploads FILE (default
generated/uploads/upload_keys.js) through /api/js-recon/<pid>/upload, starts
POST /api/recon/<pid>/partial with tool JsRecon over the given URLs only,
follows redamon-partial-recon-<pid>-<run8> into --log, and polls until the run
ends. Prints RUN_ID=<id>; exit 1 if the run ends in error.
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
DEFAULT_UPLOAD = os.path.join(HERE, "generated", "uploads", "upload_keys.js")


def env_value(name):
    with open(os.path.join(REPO, ".env"), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def web_base():
    return os.environ.get("REDAMON_WEB") or f"http://localhost:{env_value('WEBAPP_PORT') or '3000'}"


class Web:
    def __init__(self, base):
        self.base = base
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
        print("[+] signed in to the webapp", flush=True)

    def upload(self, pid, path):
        name = os.path.basename(path)
        with open(path, "rb") as fh:
            data = fh.read()
        boundary = "----jslab" + uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                "Content-Type: application/javascript\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        return self.request("POST", f"/api/js-recon/{pid}/upload", body,
                            {"Content-Type": f"multipart/form-data; boundary={boundary}"})


def follow_logs(pid, run_id, path):
    name = f"redamon-partial-recon-{re.sub(r'[^a-zA-Z0-9_.-]', '_', pid)}-{run_id[:8]}"
    for _ in range(60):
        if subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0:
            print(f"[*] following {name} into {path}", flush=True)
            return subprocess.Popen(["docker", "logs", "-f", name], stdout=open(path, "w"),
                                    stderr=subprocess.STDOUT)
        time.sleep(1)
    print(f"[!] container {name} never appeared: no log", flush=True)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("project_id")
    ap.add_argument("--upload", default=DEFAULT_UPLOAD, help="file to upload (default: %(default)s)")
    ap.add_argument("--no-upload", action="store_true")
    ap.add_argument("--keep-existing", action="store_true",
                    help="keep an already-uploaded file of that name (default: delete and upload again)")
    ap.add_argument("--url", action="append", help="target URL (repeatable; default http://192.88.96.10/)")
    ap.add_argument("--log", metavar="PATH")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()
    pid = args.project_id
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", pid):
        raise SystemExit("[!] not a project id")

    web = Web(web_base())
    web.login()
    if not args.no_upload:
        if not os.path.isfile(args.upload):
            raise SystemExit(f"[!] {args.upload} missing: run gen_lab.py")
        status, out = web.upload(pid, args.upload)
        if status == 409 and not args.keep_existing:
            name = os.path.basename(args.upload)
            web.request("DELETE", f"/api/js-recon/{pid}/upload?name={urllib.request.quote(name)}")
            status, out = web.upload(pid, args.upload)
        if status not in (200, 409):
            raise SystemExit(f"[!] upload failed ({status}): {out.get('error')}")
        print(f"[+] upload: {os.path.basename(args.upload)} ({'kept' if status == 409 else 'uploaded'})", flush=True)

    body = {"tool_id": "JsRecon", "graph_inputs": {},
            "user_targets": {"urls": args.url or ["http://192.88.96.10/"], "url_attach_to": None},
            "include_graph_targets": False}
    status, out = web.json("POST", f"/api/recon/{pid}/partial", body)
    if status != 200 or not out.get("run_id"):
        raise SystemExit(f"[!] partial recon refused ({status}): {json.dumps(out)[:500]}")
    run_id = out["run_id"]
    print(f"[+] partial recon started: run {run_id}, roots {out.get('roots')}", flush=True)
    print(f"RUN_ID={run_id}", flush=True)
    tail = follow_logs(pid, run_id, args.log) if args.log else None

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
        time.sleep(5)
    else:
        raise SystemExit(f"[!] partial recon still running after {args.timeout}s")
    if tail:
        time.sleep(3)
        tail.terminate()
    print(f"[+] partial recon {state.get('status')}: {json.dumps(state.get('stats') or {})[:300]}"
          + (f" error: {str(state.get('error'))[:300]}" if state.get("error") else ""), flush=True)
    print(f"PROJECT_ID={pid}")
    sys.exit(1 if str(state.get("status")).lower() == "error" else 0)


if __name__ == "__main__":
    main()

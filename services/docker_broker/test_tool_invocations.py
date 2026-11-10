"""Every tool's real `docker` invocation goes through the broker, both ways (decision D4).

The broker blocks by default, so a Docker API call, a bind mount or a writable
volume a tool needs and the allowlist lacks would surface as a refused scan.
This test makes it a failed test instead:

  * recon -> broker: every `docker ...` call site under recon/ and
    scanners/supply_chain_common/ (found by parsing the source) is executed by
    calling the real code with only subprocess faked, and the argv it builds is
    turned into the Docker API requests Docker CLI 29 sends for it (recorded
    once through a logging proxy, see `_cli_requests`), then sent through the
    broker's real handler to a fake daemon. A 403 fails the test.
    recon/entrypoint.sh's own docker calls are replayed the same way.
  * broker -> recon: every allowlist route, repository bind subdirectory,
    writable volume and network the broker grants is used by one of those
    invocations, or named in a `*_BEYOND_TOOLS` table with the reason, so the
    allowlist does not grow past what the tools need.

A new call site fails `test_every_docker_call_site_is_driven` until a driver
below runs it. Recon's third-party network libraries are not in this image;
they are stubbed at import (the drivers never reach the network).

Run: ./redamon.sh test unit (section docker_broker)
"""
import ast
import contextlib
import functools
import importlib
import importlib.abc
import importlib.machinery
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import types
import urllib.parse
from unittest import mock

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)
import broker  # noqa: E402
from mock_daemon import Daemon, created_id, request_bytes, run_through_broker, status_of  # noqa: E402

if not os.path.isfile(os.path.join(_REPO, "recon", "main.py")):
    pytest.skip("recon/ is not in this checkout", allow_module_level=True)

# The repository as the daemon sees it, with a space like many real checkouts.
# The recon container gets these from the orchestrator (container_manager.py:
# HOST_RECON_OUTPUT_PATH = <recon>/output, HOST_CUSTOM_TEMPLATES_PATH = the
# ./mcp/nuclei-templates mount, SUPPLY_CHAIN_COMMON_HOST_PATH =
# <repo>/scanners/supply_chain_common); compose gives the broker the same root.
REPO_HOST = "/srv/red amon"
TOOL_ENV = {
    "HOST_RECON_OUTPUT_PATH": f"{REPO_HOST}/recon/output",
    "HOST_CUSTOM_TEMPLATES_PATH": f"{REPO_HOST}/mcp/nuclei-templates",
    "SUPPLY_CHAIN_COMMON_HOST_PATH": f"{REPO_HOST}/scanners/supply_chain_common",
    "RECON_RUN_ID": "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
}
RUN_HEADER = "X-Redamon-Run: full_recon:cmproj0123456789abc:6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
API = "/v1.56"

SCANNED_ROOTS = ("recon", "scanners/supply_chain_common")

# What the broker grants that no tool invocation uses today, with the reason.
# An entry nobody needs any more should be removed from broker.py.
ROUTES_BEYOND_TOOLS = {
    "version": "D4 lists version/ping/info; `docker version` for an operator's diagnosis",
    "container-list": "D4: listing filtered to broker-owned; the run-label filter of plan 12.4 reads it",
    "container-read": "D4: logs and inspect of a broker-owned container, for diagnosing a tool run",
    "container-remove": "D4: `docker rm` of a broker-owned container (a CLI on an old API removes --rm containers itself)",
}
REPO_SUBDIRS_BEYOND_TOOLS: dict = {}
NETWORKS_BEYOND_TOOLS: dict = {}


# ---------------------------------------------------------------------------
# Static: every docker call site in the source
# ---------------------------------------------------------------------------

def _func_spans(tree):
    return [(n.lineno, n.end_lineno, n.name) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _innermost(spans, line):
    hits = [(e - s, name) for s, e, name in spans if s <= line <= e]
    return min(hits)[1] if hits else "<module>"


def static_call_sites() -> set:
    """(path, function, subcommand) of every docker argv literal: a list that
    starts with "docker", or one passed to trufflehog_bridge's `_docker([...])`."""
    sites = set()
    for root in SCANNED_ROOTS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(_REPO, root)):
            dirnames[:] = [d for d in dirnames if d not in ("tests", "__pycache__", "output")]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, _REPO)
                with open(path, encoding="utf-8") as f:
                    tree = ast.parse(f.read())
                spans = _func_spans(tree)
                for node in ast.walk(tree):
                    elts = None
                    if isinstance(node, ast.List) and len(node.elts) >= 2 \
                            and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "docker":
                        elts = node.elts[1:]
                    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                            and node.func.id == "_docker" and node.args and isinstance(node.args[0], ast.List):
                        elts = node.args[0].elts
                    if elts and isinstance(elts[0], ast.Constant) and isinstance(elts[0].value, str):
                        sites.add((rel, _innermost(spans, node.lineno), elts[0].value))
    return sites


def entrypoint_commands() -> list:
    """The docker commands recon/entrypoint.sh runs, one argv per image it pulls."""
    with open(os.path.join(_REPO, "recon", "entrypoint.sh"), encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"^IMAGES=\((.*?)^\)", text, re.S | re.M)
    images = re.findall(r'"([^"]+)"', re.sub(r"#.*", "", block.group(1)))
    # Commands only: drop comments and quoted strings (echoed build hints).
    code = re.sub(r'"[^"\n]*"', '""', re.sub(r"#.*", "", text))
    subs = set(re.findall(r"(?<![\w-])docker\s+([a-z]+)", code))
    assert subs <= {"info", "images", "pull"}, (
        f"recon/entrypoint.sh runs docker {sorted(subs - {'info', 'images', 'pull'})}: model it here")
    cmds = [["docker", "info"]]
    for img in images:
        cmds += [["docker", "images", "-q", img], ["docker", "pull", img],
                 ["docker", "pull", "--platform", "linux/amd64", img]]
    return cmds


# ---------------------------------------------------------------------------
# Docker CLI argv -> the API requests it sends
# ---------------------------------------------------------------------------
# Recorded from Docker CLI 29.9.3 (the recon image's) against Engine 29.8.0:
#   docker run --rm [opts] IMG    HEAD /_ping x2, POST containers/create[?name=],
#                                 POST {id}/attach?stderr=1[&stdin=1]&stdout=1&stream=1,
#                                 POST {id}/wait?condition=removed, POST {id}/start
#   docker kill N                 HEAD /_ping, POST containers/N/kill
#   docker pull [--platform P] I  HEAD /_ping, POST images/create?fromImage=docker.io%2F..[&platform=]&tag=
#   docker info                   HEAD /_ping, GET info
#   docker images -q I            HEAD /_ping, GET images/json?filters={"reference":{I:true}}
#   docker image inspect I        HEAD /_ping, GET images/I/json
#   docker volume inspect|create  GET volumes/V | POST volumes/create {"Driver":"local","Name":V}
#   docker network inspect|create GET networks/N | POST networks/create {"Name":N,"Driver":"bridge",...}
# The create body is the CLI's, field for field, for the options below
# (`-v` lands in HostConfig.Binds, named volumes too; --cap-add NET_RAW is sent
# as CAP_NET_RAW; --tmpfs in HostConfig.Tmpfs).

_RUN_VALUE_FLAGS = {"--name", "-v", "--volume", "--net", "--network", "--cap-add", "--cap-drop",
                    "--tmpfs", "--pids-limit", "--memory", "-m", "--cpus", "--user", "-u",
                    "--entrypoint", "-e", "--env", "--platform", "-w", "--workdir"}
_RUN_BOOL_FLAGS = {"--rm", "-i", "--interactive", "--read-only"}


def _size(v: str) -> int:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([bkmg]?)", v.lower())
    assert m, f"unparsed size {v!r}"
    return int(float(m.group(1)) * {"": 1, "b": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2)])


def parse_run(args: list) -> dict:
    opts = {"binds": [], "env": [], "cap_add": [], "cap_drop": [], "tmpfs": {}, "rm": False,
            "stdin": False, "ro": False}
    i = 0
    while i < len(args) and args[i].startswith("-"):
        flag, _, inline = args[i].partition("=")
        if flag in _RUN_BOOL_FLAGS:
            opts.update({"--rm": {"rm": True}, "-i": {"stdin": True}, "--interactive": {"stdin": True},
                         "--read-only": {"ro": True}}[flag])
            i += 1
            continue
        assert flag in _RUN_VALUE_FLAGS, f"docker run option {flag!r} is not modelled; add it here"
        if inline or "=" in args[i]:
            value, i = inline, i + 1
        else:
            value, i = args[i + 1], i + 2
        if flag in ("-v", "--volume"):
            opts["binds"].append(value)
        elif flag in ("-e", "--env"):
            opts["env"].append(value)
        elif flag == "--cap-add":
            opts["cap_add"].append(value if value.upper().startswith("CAP_") or value.upper() == "ALL"
                                   else "CAP_" + value.upper())
        elif flag == "--cap-drop":
            opts["cap_drop"].append(value)
        elif flag == "--tmpfs":
            dst, _, o = value.partition(":")
            opts["tmpfs"][dst] = o
        else:
            opts[flag.lstrip("-")] = value
    assert i < len(args), "docker run without an image"
    opts["image"], opts["cmd"] = args[i], args[i + 1:]
    return opts


def create_body(o: dict) -> dict:
    hc = {
        "Binds": o["binds"] or None, "ContainerIDFile": "", "LogConfig": {"Type": "", "Config": {}},
        "NetworkMode": o.get("net") or o.get("network") or "default", "PortBindings": {},
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "AutoRemove": o["rm"],
        "VolumeDriver": "", "VolumesFrom": None, "ConsoleSize": [0, 0],
        "CapAdd": o["cap_add"] or None, "CapDrop": o["cap_drop"] or None, "CgroupnsMode": "",
        "Dns": None, "DnsOptions": [], "DnsSearch": [], "ExtraHosts": None, "GroupAdd": None,
        "IpcMode": "", "Cgroup": "", "Links": None, "OomScoreAdj": 0, "PidMode": "",
        "Privileged": False, "PublishAllPorts": False, "ReadonlyRootfs": o["ro"], "SecurityOpt": None,
        "UTSMode": "", "UsernsMode": "", "ShmSize": 0, "Isolation": "", "CpuShares": 0,
        "Memory": _size(o["memory"]) if o.get("memory") else (_size(o["m"]) if o.get("m") else 0),
        "NanoCpus": int(float(o["cpus"]) * 1e9) if o.get("cpus") else 0, "CgroupParent": "",
        "Devices": [], "PidsLimit": int(o.get("pids-limit") or 0), "Ulimits": None,
        "MaskedPaths": None, "ReadonlyPaths": None,
    }
    if o["tmpfs"]:
        hc["Tmpfs"] = o["tmpfs"]
    return {
        "Hostname": "", "Domainname": "", "User": o.get("user") or o.get("u") or "",
        "AttachStdin": o["stdin"], "AttachStdout": True, "AttachStderr": True, "Tty": False,
        "OpenStdin": o["stdin"], "StdinOnce": o["stdin"], "Env": o["env"] or None,
        "Cmd": o["cmd"] or None, "Image": o["image"], "Volumes": {},
        "WorkingDir": o.get("w") or o.get("workdir") or "",
        "Entrypoint": [o["entrypoint"]] if o.get("entrypoint") else None, "Labels": {},
        "HostConfig": hc, "NetworkingConfig": {"EndpointsConfig": {}},
    }


def _qualified(image: str) -> tuple:
    """The CLI's fromImage/tag split, Docker Hub names fully qualified."""
    name, tag = (image.rsplit(":", 1) + ["latest"])[:2] if ":" in image.split("/")[-1] else (image, "latest")
    first = name.split("/", 1)[0]
    if "/" not in name:
        name = f"docker.io/library/{name}"
    elif "." not in first and ":" not in first and first != "localhost":
        name = f"docker.io/{name}"
    return name, tag


def _req(method, target, body=None):
    return request_bytes(method, target, body, headers=(RUN_HEADER,))


def cli_requests(argv: list) -> list:
    """The steps mock_daemon.run_through_broker sends for one docker argv."""
    assert argv[0] == "docker", argv
    sub, args = argv[1], argv[2:]
    ping = _req("HEAD", "/_ping")
    if sub == "run":
        o = parse_run(args)
        query = {k: v for k, v in (("name", o.get("name")), ("platform", o.get("platform"))) if v}
        target = f"{API}/containers/create" + ("?" + urllib.parse.urlencode(query) if query else "")
        attach = "stderr=1&stdin=1&stdout=1&stream=1" if o["stdin"] else "stderr=1&stdout=1&stream=1"
        cond = "removed" if o["rm"] else "next-exit"
        def then(suffix):
            return lambda r: created_id(r[2]) and _req("POST", f"{API}/containers/{created_id(r[2])}/{suffix}")
        return [ping, ping, _req("POST", target, create_body(o)),
                then(f"attach?{attach}"), then(f"wait?condition={cond}"), then("start")]
    if sub == "kill":
        # The container exists because the same run created it through the broker.
        name = args[-1]
        return [_req("POST", f"{API}/containers/create?name={name}", {"Image": "alpine"}),
                ping, _req("POST", f"{API}/containers/{name}/kill")]
    if sub == "pull":
        platform = args[args.index("--platform") + 1] if "--platform" in args else ""
        name, tag = _qualified(args[-1])
        q = {"fromImage": name, **({"platform": platform} if platform else {}), "tag": tag}
        return [ping, _req("POST", f"{API}/images/create?" + urllib.parse.urlencode(q))]
    if sub == "info":
        return [ping, _req("GET", f"{API}/info")]
    if sub == "images":
        flt = json.dumps({"reference": {args[-1]: True}}, separators=(",", ":"))
        return [ping, _req("GET", f"{API}/images/json?filters=" + urllib.parse.quote(flt))]
    if sub == "image" and args[0] == "inspect":
        return [ping, _req("GET", f"{API}/images/{args[-1]}/json")]
    if sub == "volume":
        if args[0] == "inspect":
            return [ping, _req("GET", f"{API}/volumes/{args[-1]}")]
        if args[0] == "create":
            return [ping, _req("POST", f"{API}/volumes/create", {"Driver": "local", "Name": args[-1]})]
    if sub == "network":
        if args[0] == "inspect":
            return [ping, _req("GET", f"{API}/networks/{args[-1]}")]
        if args[0] == "create":
            driver = args[args.index("--driver") + 1] if "--driver" in args else "bridge"
            return [ping, _req("POST", f"{API}/networks/create", {
                "Name": args[-1], "Driver": driver, "Scope": "",
                "IPAM": {"Driver": "default", "Options": {}, "Config": []}, "Internal": False,
                "Attachable": False, "Ingress": False, "ConfigOnly": False, "ConfigFrom": None,
                "Options": {}, "Labels": {}})]
    raise AssertionError(f"docker {sub} {args[:1]} is not modelled in cli_requests: add it from a recording")


# ---------------------------------------------------------------------------
# Running the real recon code with subprocess faked
# ---------------------------------------------------------------------------

class _Stub(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        value = mock.MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, value)
        return value


class _StubMissing(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Stand-in for the third-party network packages this image lacks: recon
    modules import them at module level; no driver reaches the network. Only
    these: a missing RedAmon module must still fail the import."""
    STUBBED = {"requests", "urllib3", "dns"}

    def find_spec(self, fullname, path, target=None):
        if fullname.split(".")[0] not in self.STUBBED:
            return None
        for finder in sys.meta_path:
            if finder is self:
                continue
            try:
                if finder.find_spec(fullname, path, target) is not None:
                    return None
            except Exception:  # noqa: BLE001
                continue
        return importlib.machinery.ModuleSpec(fullname, self, is_package=True)

    def create_module(self, spec):
        return _Stub(spec.name)

    def exec_module(self, module):
        module.__path__ = []


@contextlib.contextmanager
def recon_importable():
    before = set(sys.modules)
    finder = _StubMissing()
    old_path = list(sys.path)
    sys.path[:0] = [_REPO, os.path.join(_REPO, "recon"), os.path.join(_REPO, "scanners")]
    sys.meta_path.append(finder)
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        sys.path[:] = old_path
        for name in set(sys.modules) - before:
            sys.modules.pop(name, None)


class _FakeProc:
    def __init__(self, rec, argv, kwargs):
        self.args = argv
        self.pid = 4242
        self.returncode = 0
        text = kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding")
        self.stdout = io.StringIO("") if text else io.BytesIO(b"")
        self.stderr = io.StringIO("") if text else io.BytesIO(b"")
        self.stdin = mock.MagicMock()
        self._polls = 1 if rec.slow else 0

    def poll(self):
        if self._polls:
            self._polls -= 1
            return None
        return 0

    def communicate(self, input=None, timeout=None):
        return ("", "") if isinstance(self.stdout, io.StringIO) else (b"", b"")

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass

    terminate = kill

    def send_signal(self, sig):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# Functions that only BUILD a docker argv; another function runs it. Each is
# wrapped so the argv is recorded under the builder's own name.
BUILDERS = [
    ("recon.main_recon_modules.port_scan", "build_naabu_command"),
    ("recon.main_recon_modules.http_probe", "build_httpx_command"),
    ("recon.main_recon_modules.tls_scan", "build_tlsx_command"),
    ("recon.helpers.nuclei_helpers", "build_nuclei_command"),
    ("recon.helpers.takeover_helpers", "build_baddns_command"),
    ("recon.cache_scan.wcvs_runner", "build_wcvs_command"),
    ("recon.helpers.js_recon.trufflehog_bridge", "build_argv"),
    ("supply_chain_common.analyzer_dispatch", "analyzer_docker_argv"),
    ("supply_chain_common.guarddog_runner", "hardened_docker_argv"),
]


class Recorder:
    """Fakes subprocess for the drivers and records each docker argv with the
    call site (path, function) that built it."""

    def __init__(self, sites):
        self.site_funcs = {(p, f) for p, f, _ in sites}
        self.calls = []
        self.lock = threading.Lock()
        self.rc = {}            # (sub, first arg) or (sub,) -> exit code of the faked run
        self.timeout_runs = False
        self.slow = False

    def _site(self):
        frame = sys._getframe(2)
        while frame is not None:
            rel = os.path.relpath(frame.f_code.co_filename, _REPO)
            if (rel, frame.f_code.co_name) in self.site_funcs:
                return rel, frame.f_code.co_name
            frame = frame.f_back
        return None, None

    def _record(self, argv):
        argv = [str(a) for a in argv]
        if argv and argv[0] == "docker":
            path, func = self._site()
            with self.lock:
                self.calls.append((path, func, argv))
        return argv

    def run(self, argv, *a, **kw):
        argv = self._record(argv)
        if argv[:1] == ["docker"]:
            if self.timeout_runs and argv[1] == "run" and "--name" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout") or 1)
            rc = self.rc.get(tuple(argv[1:3]), self.rc.get((argv[1],), 0))
            # The nuclei-templates probe (alpine counting *.yaml) reports an
            # empty volume, so the template update runs too.
            out = "" if rc else ("0" if argv[1] == "run" and "alpine" in argv else "")
            return subprocess.CompletedProcess(argv, rc, stdout=out if kw.get("text") else out.encode(),
                                               stderr="" if kw.get("text") else b"")
        return subprocess.CompletedProcess(argv, 0, stdout="" if kw.get("text") else b"",
                                           stderr="" if kw.get("text") else b"")

    def popen(self, argv, *a, **kw):
        return _FakeProc(self, self._record(argv), kw)

    def _spy(self, stack, module, name):
        real = getattr(module, name)
        rel = os.path.relpath(real.__code__.co_filename, _REPO)

        @functools.wraps(real)
        def built(*a, **kw):
            argv = real(*a, **kw)
            with self.lock:
                self.calls.append((rel, name, [str(x) for x in argv]))
            return argv
        # also where it was imported by name (`from x import build_...`)
        for mod in list(sys.modules.values()):
            if getattr(mod, name, None) is real:
                stack.enter_context(mock.patch.object(mod, name, built))

    @contextlib.contextmanager
    def active(self):
        real_which = shutil.which
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(subprocess, "run", self.run))
            stack.enter_context(mock.patch.object(subprocess, "Popen", self.popen))
            stack.enter_context(mock.patch.object(
                shutil, "which", lambda c, *a, **k: "/usr/bin/docker" if c == "docker" else real_which(c, *a, **k)))
            stack.enter_context(mock.patch.dict(os.environ, TOOL_ENV))
            # Hermetic: a driver that reaches past the docker call gets no network.
            offline = OSError("network disabled in test_tool_invocations")
            stack.enter_context(mock.patch.object(socket.socket, "connect", side_effect=offline))
            stack.enter_context(mock.patch.object(socket.socket, "connect_ex", side_effect=offline))
            stack.enter_context(mock.patch.object(socket, "getaddrinfo",
                                                  side_effect=socket.gaierror("offline")))
            for mod, _ in BUILDERS:
                importlib.import_module(mod)
            for mod, name in BUILDERS:
                self._spy(stack, sys.modules[mod], name)
            yield self


@contextlib.contextmanager
def _flags(rec, **kw):
    old = {k: getattr(rec, k) for k in kw}
    for k, v in kw.items():
        setattr(rec, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(rec, k, v)


def _scratch(name):
    path = pathlib.Path("/tmp/redamon") / name
    path.mkdir(parents=True, exist_ok=True)
    return path


URLS = ["https://app.example.com/", "https://app.example.com/login"]


def drive_docker_helpers(rec):
    from recon.helpers import docker_helpers as dh
    dh.is_docker_running()
    with _flags(rec, rc={("pull",): 1}):
        dh.pull_image_or_use_local("projectdiscovery/nuclei:latest", "t", platform="linux/amd64")
    with _flags(rec, rc={("volume", "inspect"): 1}):
        dh.ensure_templates_volume("projectdiscovery/nuclei:latest")       # creates, then updates
    dh.ensure_templates_volume("projectdiscovery/nuclei:latest", auto_update=True)  # counts, then updates
    dh.kill_container("redamon-nuclei-update-0123456789ab")


def drive_naabu(rec):
    from recon.main_recon_modules import port_scan
    port_scan.is_docker_running()
    port_scan.pull_naabu_docker_image("projectdiscovery/naabu:latest")
    tmp = _scratch(".naabu_temp_0123456789ab")
    port_scan.build_naabu_command(str(tmp / "targets.txt"), str(tmp / "naabu.json"),
                                  {"NAABU_SCAN_TYPE": "s", "NAABU_TOP_PORTS": "100"})


def drive_httpx(rec):
    from recon.main_recon_modules import http_probe
    http_probe.is_docker_running()
    http_probe.pull_httpx_docker_image("projectdiscovery/httpx:latest")
    tmp = _scratch(".httpx_temp_0123456789ab")
    http_probe.build_httpx_command(str(tmp / "targets.txt"), str(tmp / "httpx.json"), {},
                                   container_name="redamon-httpx-0123456789ab")
    http_probe._stop_httpx_at_budget(mock.MagicMock(), "redamon-httpx-0123456789ab", 60, 2)


def drive_tlsx(rec):
    from recon.main_recon_modules import tls_scan
    tmp = _scratch(".tlsx_scan_17")
    tls_scan.build_tlsx_command(str(tmp / "targets.txt"), str(tmp), {})


def drive_nuclei(rec):
    from recon.helpers import nuclei_helpers
    tmp = _scratch(".nuclei_temp_0123456789abcdef")
    nuclei_helpers.build_nuclei_command(
        targets_file=str(tmp / "targets.txt"), output_file=str(tmp / "out.jsonl"),
        docker_image="projectdiscovery/nuclei:latest", tags=["cve"],
        selected_custom_templates=["springboot-env-bypass.yaml"], container_name="redamon-nuclei-x")
    from recon.main_recon_modules import vuln_scan
    vuln_scan._nuclei_kill_container("redamon-nuclei-x")


def drive_takeover(rec):
    from recon.main_recon_modules import subdomain_takeover as st
    work = _scratch("redamon_takeover_x")
    with _flags(rec, timeout_runs=True):
        st._run_nuclei_takeover(["https://app.example.com"], work, {})
        st._run_baddns(["app.example.com"], work, {})


def drive_crawlers(rec):
    from recon.helpers.resource_enum import gau_helpers, hakrawler_helpers, jsluice_helpers, \
        katana_helpers, kiterunner_helpers, zap_ajax_spider_helpers
    katana_helpers.run_katana_crawler(URLS, "projectdiscovery/katana:latest", 2, 100, 10, 10, True,
                                      False, {"app.example.com"}, [], [])
    hakrawler_helpers.run_hakrawler_crawler(URLS, "jauderho/hakrawler:latest", 2, 2, 10, 100, False,
                                            False, {"app.example.com"}, [], [])
    gau_helpers.run_gau_for_domain("example.com", "sxcurity/gau:latest", ["wayback"], 2, 10, [], 100,
                                   urlscan_api_key="0123456789abcdef0123456789abcdef")
    gau_helpers.verify_gau_urls(URLS, "projectdiscovery/httpx:latest", 2, 10, 10, [200])
    gau_helpers.detect_gau_methods(URLS, "projectdiscovery/httpx:latest", 2, 10, 10)
    jsluice_helpers.verify_jsluice_urls(URLS, "projectdiscovery/httpx:latest", 2, 10, 10, [200])
    kr = [{"url": u, "method": "GET"} for u in URLS]
    for mode in ("options", "bruteforce"):
        kiterunner_helpers.detect_kiterunner_methods(kr, "projectdiscovery/httpx:latest", True, mode,
                                                     ["POST", "PUT"], 10, 10, 2)
    with _flags(rec, timeout_runs=True):
        zap_ajax_spider_helpers.run_zap_ajax_spider(
            ["https://app.example.com/"], "ghcr.io/zaproxy/zaproxy:stable", {"app.example.com"}, [], [],
            100, 1, 2, 10, 1, "firefox-headless", 1000, 1000, True, True, False, True, True)


def drive_discovery(rec):
    from recon.main_recon_modules import domain_recon
    domain_recon.run_subfinder("example.com", {"SUBFINDER_ENABLED": True})
    pathlib.Path("/app/recon/data").mkdir(parents=True, exist_ok=True)
    os.makedirs("/app/recon/wordlists", exist_ok=True)
    pathlib.Path("/app/recon/wordlists/jhaddix-all.txt").write_text("www\n")
    domain_recon.run_amass("example.com", {"AMASS_ENABLED": True, "AMASS_BRUTE": True,
                                           "AMASS_BRUTE_WORDLISTS": ["jhaddix-all"]})
    _scratch("").joinpath("resolvers.txt").write_text("192.0.2.53\n")
    with mock.patch.object(pathlib.Path, "unlink", side_effect=PermissionError):  # files the tool wrote as root
        domain_recon.run_puredns_resolve(["www.example.com"], "example.com", {"PUREDNS_ENABLED": True})
    from recon.main_recon_modules import uncover_enrich
    tmp = _scratch("redamon_uncover_x")
    uncover_enrich._run_uncover_docker(["ssl:example.com"], ["shodan"], str(tmp / "provider-config.yaml"),
                                       10, str(tmp))


def drive_scanners(rec):
    from recon.cache_scan import wcvs_runner
    wcvs_runner.run_wcvs(["https://app.example.com/"], {})
    from recon.graphql_scan import misconfig
    misconfig.run_graphql_cop("https://app.example.com/graphql", {}, {"GRAPHQL_COP_ENABLED": True})


def drive_vuln_scan_cleanup(rec):
    """run_vuln_scan's root-owned-file cleanup, reached through the real scan
    with every pass faked and the unlink refused."""
    from recon.main_recon_modules import vuln_scan
    recon_data = {"domain": "example.com", "metadata": {"include_root_domain": True},
                  "dns": {"domain": {"ips": {"ipv4": ["192.0.2.10"], "ipv6": []}}},
                  "http_probe": {"by_url": {
                      "https://example.com/": {"url": "https://example.com/", "status_code": 200}}}}
    with mock.patch.object(pathlib.Path, "unlink", side_effect=PermissionError):
        vuln_scan.run_vuln_scan(recon_data, settings={"NUCLEI_ENABLED": True, "SECURITY_CHECK_ENABLED": False,
                                                      "CVE_LOOKUP_ENABLED": False, "MITRE_ENABLED": False})


def drive_trufflehog(rec):
    from recon.helpers.js_recon import trufflehog_bridge as th
    files = [{"url": "https://app.example.com/app.js", "content": "const k = 'x';"}]
    with _flags(rec, rc={("network", "inspect"): 1}, slow=True):
        th.run(files, verify=True, concurrency=2, validation_timeout=5, budget_s=0)
    with _flags(rec, slow=True):
        th.run_sidecar(th.build_argv("/tmp/redamon/x", verify=False, concurrency=1, validation_timeout=5,
                                     name="redamon-jsth-x"), name="redamon-jsth-x", budget_s=1e9,
                       sleep=lambda s: None)


def drive_supply_chain(rec):
    from supply_chain_common import analyzer_dispatch as ad, guarddog_runner as gr
    work = ad.new_work_dir(prefix="sc-retire")
    with _flags(rec, rc={("network", "inspect"): 1}):
        ad.run_analyzer_job({"mode": "js-dir", "path": "/work"}, work,
                            os.environ["SUPPLY_CHAIN_COMMON_HOST_PATH"])
    ad.analyzer_docker_argv(work, os.environ["SUPPLY_CHAIN_COMMON_HOST_PATH"],
                            allow_registry_egress=True)
    gr.scan_package("npm", "left-pad", "1.3.0", argv_prefix=gr.hardened_docker_argv())


DRIVERS = [drive_docker_helpers, drive_naabu, drive_httpx, drive_tlsx, drive_nuclei, drive_takeover,
           drive_crawlers, drive_discovery, drive_scanners, drive_vuln_scan_cleanup, drive_trufflehog,
           drive_supply_chain]


@pytest.fixture(scope="module")
def sites():
    return static_call_sites()


@pytest.fixture(scope="module")
def captured(sites):
    errors = {}
    with recon_importable():
        rec = Recorder(sites)
        with rec.active():
            for drive in DRIVERS:
                try:
                    drive(rec)
                except Exception as exc:  # noqa: BLE001 - reported by test_drivers_run_clean
                    errors[drive.__name__] = f"{type(exc).__name__}: {exc}"
    return rec.calls, errors


@pytest.fixture(scope="module")
def shipped_broker():
    """The broker as compose configures it, for a repository at REPO_HOST."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DOCKER_BROKER_")}
    env["DOCKER_BROKER_REPO_ROOT"] = REPO_HOST
    with mock.patch.dict(os.environ, env, clear=True):
        importlib.reload(broker)
    try:
        yield broker
    finally:
        importlib.reload(broker)


def _replay(argvs, broker_mod):
    """Send each argv's requests through the broker; return (refusals, forwarded requests)."""
    refusals, forwarded = [], []
    for argv in argvs:
        responses, daemon = run_through_broker(cli_requests(argv), Daemon())
        for resp in responses:
            if status_of(resp) == 403:
                msg = resp.split(b"\r\n\r\n", 1)[-1].decode("latin1", "replace")
                refusals.append(f"{shlex.join(argv)}\n    -> {msg}")
        forwarded += [(r["method"], r["path"], r["body"]) for r in daemon.received
                      if r["path"].startswith(API) or r["path"] == "/_ping"]
    return refusals, forwarded


# ---------------------------------------------------------------------------
# recon -> broker
# ---------------------------------------------------------------------------

def test_the_static_scan_finds_the_known_sites(sites):
    # A broken parser must fail here, not make the coverage check pass vacuously.
    subs = {s for _, _, s in sites}
    assert len(sites) >= 40 and {"run", "kill", "pull", "info", "images", "image", "volume",
                                 "network"} <= subs, sorted(sites)


def test_drivers_run_clean(captured):
    _, errors = captured
    assert not errors, errors


def test_every_docker_call_site_is_driven(sites, captured):
    calls, _ = captured
    driven = {(p, f, argv[1]) for p, f, argv in calls}
    missing = sorted(sites - driven)
    assert not missing, (
        "these docker call sites were not executed by any driver in this file, so the "
        "broker never saw their invocation; add a driver:\n" + "\n".join(map(str, missing)))


def test_every_tool_invocation_passes_the_broker(captured, shipped_broker):
    calls, _ = captured
    refusals, _ = _replay([argv for _, _, argv in calls], shipped_broker)
    assert not refusals, "the broker refuses a real tool invocation:\n" + "\n".join(refusals)


def test_recon_entrypoint_docker_calls_pass_the_broker(shipped_broker):
    refusals, _ = _replay(entrypoint_commands(), shipped_broker)
    assert not refusals, "\n".join(refusals)


def test_the_run_labels_still_reach_every_tool_container(captured, shipped_broker):
    """Plan 12.4: Stop removes a run's tool containers by the labels the broker
    stamps from the X-Redamon-Run header."""
    calls, _ = captured
    _, forwarded = _replay([argv for _, _, argv in calls if argv[1] == "run"][:5], shipped_broker)
    creates = [json.loads(b) for m, p, b in forwarded if p.endswith("/containers/create")]
    assert creates and all(c["Labels"].get("redamon.run_id") == TOOL_ENV["RECON_RUN_ID"]
                           and c["Labels"].get("redamon.broker-owned") == "1" for c in creates)


# ---------------------------------------------------------------------------
# broker -> recon
# ---------------------------------------------------------------------------

def _all_argvs(captured):
    return [argv for _, _, argv in captured[0]] + entrypoint_commands()


def test_every_allowlist_route_has_a_user(captured, shipped_broker):
    _, forwarded = _replay(_all_argvs(captured), shipped_broker)
    used = {shipped_broker.route_label(m, p) for m, p, _ in forwarded}
    labels = {label for label, *_ in shipped_broker._ROUTES}
    unused = sorted(labels - used - set(ROUTES_BEYOND_TOOLS))
    assert not unused, f"no tool uses these broker routes; drop them or explain them: {unused}"
    stale = sorted(set(ROUTES_BEYOND_TOOLS) & used)
    assert not stale, f"ROUTES_BEYOND_TOOLS names routes tools do use: {stale}"
    assert set(ROUTES_BEYOND_TOOLS) <= labels


def _bind_sources(argvs):
    out = []
    for argv in argvs:
        if argv[1] == "run":
            for spec in parse_run(argv[2:])["binds"]:
                parts = spec.split(":")
                out.append((parts[0], parts[2] if len(parts) > 2 else ""))
    return out


def test_every_repository_bind_subdirectory_has_a_user(captured):
    sources = [s for s, _ in _bind_sources(_all_argvs(captured))]
    unused = [sub for sub in broker.REPO_TOOL_SUBDIRS
              if not any(s == f"{REPO_HOST}/{sub}" or s.startswith(f"{REPO_HOST}/{sub}/") for s in sources)]
    assert sorted(set(unused) - set(REPO_SUBDIRS_BEYOND_TOOLS)) == [], (
        f"no tool mounts these REPO_TOOL_SUBDIRS entries: {unused}")


def test_every_writable_volume_is_written_by_a_tool(captured):
    rw = {s for s, mode in _bind_sources(_all_argvs(captured))
          if not s.startswith("/") and "ro" not in mode.split(",")}
    assert {"nuclei-templates"} <= rw
    with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                      if k != "DOCKER_BROKER_ALLOWED_RW_VOLUMES"}, clear=True):
        importlib.reload(broker)
        shipped_rw = set(broker.ALLOWED_RW_VOLUMES)
    importlib.reload(broker)
    assert shipped_rw == rw, f"writable by default {shipped_rw}, written by tools {rw}"


def test_every_tool_network_is_used(captured):
    used = {argv[-1] for argv in _all_argvs(captured) if argv[1] == "network"}
    used |= {parse_run(argv[2:]).get("network") for argv in _all_argvs(captured) if argv[1] == "run"}
    with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                      if k != "DOCKER_BROKER_ALLOWED_NETWORKS"}, clear=True):
        importlib.reload(broker)
        shipped = set(broker.ALLOWED_NETWORKS)
    importlib.reload(broker)
    unused = sorted(shipped - used - set(NETWORKS_BEYOND_TOOLS))
    assert not unused, f"no tool uses these broker networks: {unused}"


def test_a_tool_mount_of_the_repository_root_or_a_dotfile_would_be_refused(shipped_broker):
    """The other side of the coin: the policy these invocations pass is not open."""
    for spec in (f"{REPO_HOST}/.env:/x:ro", f"{REPO_HOST}:/x:ro", "redamon-osv-db:/osv-db"):
        refusals, _ = _replay([["docker", "run", "--rm", "-v", spec, "alpine", "true"]], shipped_broker)
        assert refusals, spec

"""Lab instances: one Compose project per run, on its lane's address and host ports.

Two kinds of lab folder, both used unedited:

- ``env`` (the two labs of phase 10): their own Compose file reads the address, the host
  port and the canary from variables, and holds no container name and no named network,
  so a copy is ``docker compose -p tc-e2e-<run>`` with those variables set.
- ``override`` (the older labs): they publish fixed host ports and some fix their
  container or network names. The runner writes an override file per instance that renames
  each container, replaces every published port (only the front keeps one, on the lane's
  port, on 127.0.0.1), renames fixed networks, joins the front to the pentest network at the
  lane's address, and tags each built image once for every copy.

The agent is pointed at a run's lab by the front's container name, ``http://<front>:<port>``.
A person's Kali sandbox sits only on its own network (``redamon-sbx-<key>``), never on the
pentest network, so the front also joins the network of the person the chat runs as
(``Docker.follow_sandbox``), where the sandbox's tools resolve the name to the front's address on
it. The capture proxy, on the pentest network first, resolves the same name to the front's
pentest address (it refuses the sandbox range 10.214.0.0/16), so one URL works for the direct
tools and the captured ones. The runner itself (health, oracle) uses the lane's host port on
127.0.0.1.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from tooling.scripts.tradecraft_e2e.lanes import LaneAddressing, Run

PENTEST_NETWORK_KEY = "tc_e2e_pentest"
COMPOSE_FILE = "docker-compose.yml"
UP_TIMEOUT_SEC = 300

# The orchestrator's sandbox networks (recon_orchestrator/sandbox_contract.py: network_name,
# network_labels, sandbox_key): one per person and view, named after a key that is the first 16
# hex of SHA-256 of the user id (or of "act_as:<user id>"), labelled with the person, the view
# and the key. A network of that name with other labels, or one the docker broker made, is not
# a sandbox's and is never joined.
SANDBOX_NETWORK_PREFIX = "redamon-sbx-"
SANDBOX_LABEL = "redamon.sandbox"
SANDBOX_USER_LABEL = "redamon.sandbox.user"
SANDBOX_VIEW_LABEL = "redamon.sandbox.view"
SANDBOX_KEY_LABEL = "redamon.sandbox.key"
BROKER_OWNED_LABEL = "redamon.broker-owned"
SANDBOX_VIEWS = ("own", "act_as")
# A sandbox starts within seconds of the chat's ticket (its warm-up); the first start of the day
# may wait for the nuclei templates.
ATTACH_WAIT_SEC = 180
FOLLOW_POLL_SEC = 2.0


class LabError(RuntimeError):
    """A lab cannot be joined to a person's sandbox network; the message names no secret."""


def sandbox_key(user_id: str, view: str = "own") -> str:
    if view not in SANDBOX_VIEWS:
        raise ValueError(f"unknown sandbox view {view!r}")
    return hashlib.sha256((user_id if view == "own" else f"act_as:{user_id}").encode()).hexdigest()[:16]


def sandbox_network(user_id: str, view: str = "own") -> str:
    return SANDBOX_NETWORK_PREFIX + sandbox_key(user_id, view)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@dataclass(frozen=True)
class LabSpec:
    id: str
    folder: str
    kind: str  # "env" or "override"
    front: str
    port: int
    prompt: str
    secret: Mapping
    oracle: Mapping
    env: Mapping = field(default_factory=dict)
    networks: Mapping = field(default_factory=dict)
    expected_pages: Sequence[Mapping] = ()
    # Text the lab's own pages plant for the agent to find (fake CVE ids, instructions to AI
    # agents): no Library now block may carry it.
    planted: Sequence[str] = ()
    # The built-in skill ids that fit the lab, and the words that put a page read on its class: a
    # measurement of the skill and the library together, never a gate.
    skills: Sequence[str] = ()
    class_terms: Sequence[str] = ()

    @classmethod
    def from_scenarios(cls, lab_id: str, spec: Mapping) -> "LabSpec":
        if spec["kind"] not in ("env", "override"):
            raise ValueError(f"{lab_id}: kind must be env or override")
        return cls(id=lab_id, folder=spec["folder"], kind=spec["kind"], front=spec["front"], port=int(spec["port"]),
                   prompt=" ".join(str(spec["prompt"]).split()), secret=dict(spec["secret"]),
                   oracle=dict(spec["oracle"]), env=dict(spec.get("env") or {}),
                   networks=dict(spec.get("networks") or {}), expected_pages=list(spec.get("expected_pages") or []),
                   planted=[str(t) for t in spec.get("planted") or []],
                   skills=[str(s) for s in spec.get("skills") or []],
                   class_terms=[str(t) for t in spec.get("class_terms") or []])

    def image(self, service: str) -> str:
        return f"tc-e2e-{_slug(self.id)}-{_slug(service)}:latest"


@dataclass
class Instance:
    spec: LabSpec
    run_id: str
    lane: int
    project: str
    ip: str
    host_port: int
    env: dict
    secret_value: str
    override_path: Optional[Path] = None

    @property
    def front_name(self) -> str:
        """The front's container name: the override's ``container_name``, else Compose's
        ``<project>-<service>-1``."""
        if self.spec.kind == "override":
            return f"{self.project}-{_slug(self.spec.front)}"
        return f"{self.project}-{self.spec.front}-1"

    @property
    def target(self) -> str:
        """The URL the agent is given, by name (see the module docstring)."""
        return f"http://{self.front_name}:{self.spec.port}"

    @property
    def local_url(self) -> str:
        return f"http://127.0.0.1:{self.host_port}"

    def compose_files(self, repo: Path) -> list[Path]:
        files = [repo / self.spec.folder / COMPOSE_FILE]
        if self.override_path is not None:
            files.append(self.override_path)
        return files


def project_name(run_id: str, suffix: str) -> str:
    return f"tc-e2e-{_slug(run_id)}-{_slug(suffix)}"


def plan_instance(spec: LabSpec, run: Run, lane: int, addressing: LaneAddressing, *, secret_value: str,
                  suffix: str) -> Instance:
    ip, port = addressing.ip(lane), addressing.port(lane, 0)
    env: dict = {}
    if spec.kind == "env":
        env = {spec.env["ip"]: ip, spec.env["port"]: str(port)}
        if "canary" in spec.env:
            env[spec.env["canary"]] = secret_value
    return Instance(spec=spec, run_id=run.id, lane=lane, project=project_name(run.id, suffix), ip=ip,
                    host_port=port, env=env, secret_value=secret_value)


# --------------------------------------------------------------------------------------
# The override of an older lab
# --------------------------------------------------------------------------------------

def _q(value: object) -> str:
    """A YAML scalar: JSON's double-quoted strings are valid YAML."""
    return json.dumps(str(value))


def _service_networks(service: Mapping) -> list[str]:
    nets = service.get("networks")
    if isinstance(nets, Mapping):
        return list(nets)
    if isinstance(nets, list):
        return [str(n) for n in nets]
    return []


def override_yaml(spec: LabSpec, base: Mapping, inst: Instance, *, network: str) -> str:
    """The override file of ``inst`` for an ``override`` lab whose Compose file is ``base``."""
    services = base.get("services") or {}
    if spec.front not in services:
        raise ValueError(f"{spec.id}: no service {spec.front} in {spec.folder}/{COMPOSE_FILE}")
    lines = [f"# Generated by tooling/scripts/tradecraft_e2e/labs.py for run {inst.run_id} on lane {inst.lane}.",
             "services:"]
    secret_env = spec.secret if spec.secret.get("kind") == "env" else None
    for name, svc in services.items():
        svc = svc or {}
        lines.append(f"  {name}:")
        lines.append(f"    container_name: {_q(inst.project + '-' + _slug(name))}")
        lines.append('    restart: "no"')
        if "build" in svc:
            lines.append(f"    image: {_q(spec.image(name))}")
        if name == spec.front:
            lines.append("    ports: !override")
            lines.append(f"      - {_q(f'127.0.0.1:{inst.host_port}:{spec.port}')}")
            lines.append("    networks:")
            for net in _service_networks(svc):
                lines.append(f"      {net}: {{}}")
            lines.append(f"      {PENTEST_NETWORK_KEY}:")
            lines.append(f"        ipv4_address: {_q(inst.ip)}")
        elif svc.get("ports"):
            lines.append("    ports: !reset []")
        if secret_env and secret_env.get("service") == name:
            lines.append("    environment:")
            lines.append(f"      {secret_env['variable']}: {_q(inst.secret_value)}")
    lines.append("networks:")
    lines.append(f"  {PENTEST_NETWORK_KEY}:")
    lines.append("    external: true")
    lines.append(f"    name: {_q(network)}")
    for net in (base.get("networks") or {}):
        if net in spec.networks:
            lines.append(f"  {net}:")
            lines.append(f"    name: {_q(inst.project + '-' + _slug(net))}")
    return "\n".join(lines) + "\n"


def build_override_yaml(spec: LabSpec, base: Mapping) -> str:
    """The override the preflight builds an older lab with: only the image tags, so every
    instance's ``up --no-build`` finds them."""
    lines = [f"# Generated by tooling/scripts/tradecraft_e2e/labs.py: the image tags of lab {spec.id}.", "services:"]
    for name, svc in (base.get("services") or {}).items():
        if "build" in (svc or {}):
            lines += [f"  {name}:", f"    image: {_q(spec.image(name))}"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------------------

Runner = Callable[..., subprocess.CompletedProcess]


class Docker:
    """``docker compose`` for lab instances. Never touches the stack's own project: every
    command names its lab project with ``-p`` and its lab's files with ``-f``."""

    def __init__(self, repo: Path, run: Runner = subprocess.run, log: Callable[[str], None] = print):
        self.repo = repo
        self._run = run
        self._log = log
        self._followers: dict[str, list["SandboxFollower"]] = {}

    def _env(self, extra: Mapping) -> dict:
        env = dict(os.environ)
        env.update({k: str(v) for k, v in extra.items()})
        return env

    def compose_argv(self, project: str, files: Sequence[Path], *args: str) -> list[str]:
        if not project.startswith("tc-e2e-"):
            raise ValueError("a lab project is named tc-e2e-*")
        argv = ["docker", "compose", "-p", project]
        for f in files:
            argv += ["-f", str(f)]
        return argv + list(args)

    def compose(self, inst: Instance, *args: str, timeout: int = UP_TIMEOUT_SEC, check: bool = True,
                input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        argv = self.compose_argv(inst.project, inst.compose_files(self.repo), *args)
        return self._run(argv, cwd=str(self.repo / inst.spec.folder), env=self._env(inst.env), timeout=timeout,
                         check=check, capture_output=True, text=True, input=input_text)

    def build(self, spec: LabSpec, override: Optional[Path] = None, timeout: int = 3600) -> subprocess.CompletedProcess:
        files = [self.repo / spec.folder / COMPOSE_FILE] + ([override] if override else [])
        argv = self.compose_argv(f"tc-e2e-build-{_slug(spec.id)}", files, "build")
        return self._run(argv, cwd=str(self.repo / spec.folder), env=self._env({}), timeout=timeout, check=True,
                         capture_output=True, text=True)

    def up(self, inst: Instance, wait_sec: int = UP_TIMEOUT_SEC) -> subprocess.CompletedProcess:
        wait_sec = max(10, int(wait_sec))
        return self.compose(inst, "up", "-d", "--no-build", "--wait", "--wait-timeout", str(wait_sec),
                            timeout=wait_sec + 60)

    def down(self, inst: Instance) -> subprocess.CompletedProcess:
        for follower in self._followers.pop(inst.project, []):
            follower.stop()
        return self.compose(inst, "down", "-v", "--remove-orphans", "--timeout", "10", check=False, timeout=180)

    # -- the person's sandbox network ---------------------------------------------------

    def _docker(self, *argv: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return self._run(["docker", *argv], capture_output=True, text=True, check=False, timeout=timeout)

    def sandbox_network_of(self, user_id: str, view: str = "own") -> Optional[str]:
        """The person's sandbox network while it exists (it does only while a sandbox of that
        view runs), else None. Raises LabError for a network of that name the orchestrator did
        not make for that person and view."""
        name = sandbox_network(user_id, view)
        done = self._docker("network", "inspect", "-f", "{{json .Labels}}", name, timeout=30)
        if done.returncode != 0:
            return None
        try:
            labels = json.loads(done.stdout or "{}") or {}
        except ValueError:
            labels = {}
        if (labels.get(SANDBOX_LABEL) != "1" or labels.get(BROKER_OWNED_LABEL)
                or labels.get(SANDBOX_USER_LABEL) != user_id or labels.get(SANDBOX_VIEW_LABEL) != view
                or labels.get(SANDBOX_KEY_LABEL) != sandbox_key(user_id, view)):
            raise LabError(f"{name} is not the orchestrator's sandbox network of that person and view")
        return name

    def _attach_once(self, inst: Instance, user_id: str, view: str) -> Optional[str]:
        """Joins the front to the person's sandbox network when that network exists and the
        front is not on it yet; the network's name, or None when it does not exist."""
        network = self.sandbox_network_of(user_id, view)
        if network is None:
            return None
        done = self._docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", inst.front_name, timeout=30)
        if done.returncode != 0:
            raise LabError(f"the lab front {inst.front_name} is not running")
        try:
            joined = json.loads(done.stdout or "{}") or {}
        except ValueError:
            joined = {}
        if network not in joined:
            done = self._docker("network", "connect", network, inst.front_name)
            if done.returncode != 0 and "already exists" not in (done.stderr or ""):
                raise LabError(f"connecting {inst.front_name} to {network} failed (exit {done.returncode})")
            self._log(f"lab {inst.project}: {inst.front_name} joined {network}")
        return network

    def attach_to_sandbox(self, inst: Instance, user_id: str, view: str = "own",
                          wait_sec: float = ATTACH_WAIT_SEC, sleep: Optional[Callable[[float], None]] = None) -> str:
        """Joins the lab's front to the person's sandbox network, waiting for that sandbox to
        start (a chat's ticket warms it up). Once: a sandbox that restarts gets a new network,
        which ``follow_sandbox`` joins too."""
        pause = sleep or time.sleep
        until = time.monotonic() + wait_sec
        while True:
            network = self._attach_once(inst, user_id, view)
            if network:
                return network
            if time.monotonic() >= until:
                raise LabError(f"no sandbox network of that person appeared in {int(wait_sec)} s: "
                               "is their Kali sandbox running?")
            pause(FOLLOW_POLL_SEC)

    def follow_sandbox(self, inst: Instance, user_id: str, view: str = "own") -> "SandboxFollower":
        """Keeps the lab's front on the person's sandbox network for the run: the network goes
        with the sandbox's last instance (an idle stop, a replacement) and the orchestrator
        disconnects every endpoint first, so each new network is joined again. Stopped by
        ``down``."""
        follower = SandboxFollower(self, inst, user_id, view)
        self._followers.setdefault(inst.project, []).append(follower)
        follower.start()
        return follower

    def exec(self, inst: Instance, service: str, *argv: str, check: bool = False) -> subprocess.CompletedProcess:
        return self.compose(inst, "exec", "-T", service, *argv, check=check, timeout=60)

    def logs(self, inst: Instance, service: str) -> str:
        done = self.compose(inst, "logs", "--no-color", service, check=False, timeout=60)
        return done.stdout or ""

    def leftovers(self) -> list[str]:
        """Compose projects of earlier runs still on the host (``tc-e2e-*``)."""
        done = self._run(["docker", "compose", "ls", "--all", "--format", "json"], capture_output=True, text=True,
                         check=False, timeout=60)
        try:
            rows = json.loads(done.stdout or "[]")
        except ValueError:
            return []
        return sorted(r.get("Name", "") for r in rows if str(r.get("Name", "")).startswith("tc-e2e-"))


class SandboxFollower(threading.Thread):
    """Joins a lab's front to a person's sandbox network whenever that network exists."""

    def __init__(self, docker: Docker, inst: Instance, user_id: str, view: str = "own",
                 poll_sec: float = FOLLOW_POLL_SEC):
        super().__init__(daemon=True, name=f"tc-e2e-follow-{inst.project}")
        sandbox_key(user_id, view)  # refuses an unknown view now, not in the thread
        self.docker, self.inst, self.user_id, self.view, self.poll_sec = docker, inst, user_id, view, poll_sec
        self._stop_event = threading.Event()
        self.networks: list[str] = []
        self.error = ""

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                network = self.docker._attach_once(self.inst, self.user_id, self.view)
                if network and network not in self.networks:
                    self.networks.append(network)
            except LabError as e:
                if str(e) != self.error:
                    self.error = str(e)
                    self.docker._log(f"lab {self.inst.project}: {e}")
            self._stop_event.wait(self.poll_sec)

    def stop(self) -> None:
        self._stop_event.set()
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=10)

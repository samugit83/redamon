"""
Nuclei templates for per-user Kali sandboxes: the read-only volume, its
populate on first need and its daily refresher (group 1).

Driven against TplDocker below, an in-memory Docker for volumes and short-lived
containers shaped like the daemon's: a container that mounts an empty volume
over the image's templates gets them copied in (Docker's copy-up), a mount of a
missing volume creates it unlabelled, `true`, `cat` and the refresher's script
run as each test scripts them, and a container started with auto_remove is gone
once it exits. Every test sets KALI_SANDBOX_MODE explicitly.

The manager and lifespan wiring tests reuse the lifecycle tests' FakeDocker and
`world`, and the API tests' lifespan stubs.
"""
import asyncio
import json
import os
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import requests
from docker.errors import APIError, ImageNotFound, NotFound

import api
import sandbox_contract as sc
from container_manager import BROKER_OWNED_LABEL
import sandbox_manager as sm
import sandbox_templates as st
from tests import test_sandbox_manager_lifecycle as lc
from tests.test_sandbox_api import LifecycleManager, lifespan_env  # noqa: F401 - fixture
from tests.test_sandbox_manager_lifecycle import ALICE, env, world  # noqa: F401 - fixtures

OWNER = "redamon"
WALL0 = 1_800_000_000.0
DAY = sc.TEMPLATES_REFRESH_S
# What the Kali image bakes under /root/nuclei-templates.
BAKED = {"http/technologies/tech-detect.yaml": "id: tech-detect\n", ".checksum": "c\n",
         ".templates-index": "i\n"}
STAMP = st.STAMP_PATH.rsplit("/", 1)[1]
SECRETS = {"INTERNAL_API_KEY": "s07-internal-key-value", "SCANNER_API_KEY": "s07-scanner-key-value",
           "ORCHESTRATOR_API_KEY": "s07-orchestrator-key-value", "AUTH_SECRET": "s07-auth-secret-value",
           "NEO4J_PASSWORD": "s07-neo4j-password-value", "POSTGRES_PASSWORD": "s07-postgres-password"}


# --- TplDocker ----------------------------------------------------------------------

class TplVolume:
    def __init__(self, d, name, labels):
        d.seq += 1
        self.name = self.id = name
        self.files = {}
        self.removed = False
        self.attrs = {"Name": name, "Driver": "local", "Scope": "local",
                      "Labels": dict(labels) if labels else None,
                      "CreatedAt": f"2026-11-22T00:00:{d.seq:02d}Z"}


class TplVolumes:
    def __init__(self, d):
        self.d = d
        self.items = {}

    def _live(self, name):
        v = self.items.get(name)
        return v if v is not None and not v.removed else None

    def get(self, name):
        self.d.calls.append(("volumes.get", name))
        if self.d.fail_volumes:
            raise APIError("Cannot connect to the Docker daemon")
        v = self._live(name)
        if v is None:
            raise NotFound(f"get {name}: no such volume")
        return v

    def create(self, name=None, driver=None, labels=None, **kw):
        self.d.calls.append(("volumes.create", name))
        self.d.volume_creates.append({"name": name, "driver": driver, "labels": labels, **kw})
        v = self._live(name)
        if v is None:
            v = self.items[name] = TplVolume(self.d, name, labels)
        return v

    def add(self, name=sc.TEMPLATES_VOLUME, files=None, labels=None):
        v = self.items[name] = TplVolume(self.d, name, labels)
        v.files = dict(files or {})
        return v

    def mounted(self, name):
        """A mount of a missing named volume creates it, with no label."""
        return self._live(name) or self.add(name)


class TplImages:
    def __init__(self, d):
        self.d = d
        self.present = True

    def get(self, name):
        self.d.calls.append(("images.get", name))
        if name == sc.IMAGE and self.present:
            return SimpleNamespace(id="sha256:" + "a" * 64)
        raise ImageNotFound(f"No such image: {name}")


def docker_time(epoch):
    """A time as the daemon writes it: RFC 3339, nanoseconds, UTC."""
    if epoch is None:
        return "0001-01-01T00:00:00Z"
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


class TplContainer:
    def __init__(self, d, cid, kw):
        self.d = d
        self.id = cid
        self.kw = kw
        self.name = kw.get("name") or cid[:12]
        self.removed = False
        self.out = b""
        self.state = {"Status": "created", "ExitCode": 0}
        self.created_at = d.wall()
        self.started_at = None

    @property
    def labels(self):
        return dict(self.kw.get("labels") or {})

    @property
    def status(self):
        return self.state["Status"]

    @property
    def attrs(self):
        return {"Id": self.id, "Name": "/" + self.name, "Created": docker_time(self.created_at),
                "Config": {"Image": self.kw.get("image"), "Labels": self.labels},
                "HostConfig": {"AutoRemove": bool(self.kw.get("auto_remove")),
                               "NetworkMode": self.kw.get("network_mode") or "default"},
                "State": {**self.state, "StartedAt": docker_time(self.started_at)}}

    def _gone(self):
        if self.removed:
            raise NotFound(f"No such container: {self.name}")

    def reload(self):
        self.d.calls.append(("container.reload", self.name))
        self._gone()

    def start(self):
        self.d.calls.append(("container.start", self.name))
        self._gone()
        if self.d.fail_start:
            raise APIError(self.d.fail_start)
        self.state["Status"] = "running"
        self.started_at = self.d.wall()
        mounts = []
        for m in self.kw.get("mounts") or []:
            assert m["Type"] == "volume", m
            vol = self.d.volumes.mounted(m["Source"])
            if not vol.files and m["Target"] == sc.TEMPLATES_TARGET \
                    and (not m["ReadOnly"] or self.d.copy_up_read_only):
                vol.files = dict(BAKED)
            mounts.append((vol, m))
        self.d.run_program(self, mounts)

    def exit(self, code):
        self.state.update(Status="exited", ExitCode=code)
        if self.kw.get("auto_remove"):
            self.removed = True

    def wait(self, timeout=None):
        self.d.calls.append(("container.wait", self.name, timeout))
        self._gone()
        if self.status == "running":
            raise requests.exceptions.ReadTimeout("read timed out")
        return {"StatusCode": self.state["ExitCode"], "Error": None}

    def logs(self, stdout=True, stderr=True):
        self._gone()
        return self.out if stdout else b""

    def kill(self, signal=None):
        self.d.calls.append(("container.kill", self.name))
        self._gone()
        self.exit(137)

    def remove(self, force=False):
        self.d.calls.append(("container.remove", self.name, force))
        self._gone()
        if self.status == "running" and not force:
            raise APIError("You cannot remove a running container. Stop it first or use force")
        self.state["Status"] = "exited"
        self.removed = True


class TplContainers:
    def __init__(self, d):
        self.d = d
        self.items = {}

    def live(self):
        return [c for c in self.items.values() if not c.removed]

    def create(self, image=None, command=None, **kw):
        kw = dict(kw, image=image, command=command)
        self.d.calls.append(("containers.create", kw.get("name")))
        self.d.created.append(kw)
        if self.d.fail_create:
            raise APIError(self.d.fail_create)
        self.d.images.get(image)
        if any(c.name == kw.get("name") for c in self.live()):
            raise APIError(f'Conflict. The container name "/{kw.get("name")}" is already in use')
        c = TplContainer(self.d, self.d.new_id(), kw)
        self.items[c.id] = c
        if self.d.create_then_fail:
            # The daemon made it, then the client gave up waiting for the answer.
            self.d.create_then_fail = False
            raise requests.exceptions.ReadTimeout("read timed out")
        for hook in list(self.d.on_create):
            hook(c)
        return c

    def get(self, ref):
        self.d.calls.append(("containers.get", ref))
        for c in self.live():
            if ref in (c.id, c.name):
                return c
        raise NotFound(f"No such container: {ref}")

    def add(self, name, labels, status="running", started_ago=60):
        c = TplContainer(self.d, self.d.new_id(), {"name": name, "image": sc.IMAGE, "labels": labels,
                                                    "auto_remove": True})
        c.state["Status"] = status
        c.created_at = self.d.wall() - started_ago
        c.started_at = None if status == "created" else self.d.wall() - started_ago
        self.items[c.id] = c
        return c


class TplDocker:
    def __init__(self, wall):
        self.wall = wall
        self.calls = []
        self.created = []
        self.volume_creates = []
        self.on_create = []
        self.seq = 0
        self.fail_volumes = False
        self.fail_create = None
        self.create_then_fail = False
        self.fail_start = None
        # The refresher's outcome: "ok" (new templates and the stamp), "fail"
        # (exit 1, nothing written) or "hang" (runs until killed).
        self.refresh = "ok"
        self.hang_short = False
        # Docker copies an image's content into an empty named volume even when
        # the volume is mounted read-only (measured by S07 on Engine 29.10).
        self.copy_up_read_only = True
        self.volumes = TplVolumes(self)
        self.containers = TplContainers(self)
        self.images = TplImages(self)
        self._next = 0

    def new_id(self):
        self._next += 1
        return f"{self._next:064x}"

    def run_program(self, c, mounts):
        entrypoint = list(c.kw.get("entrypoint") or [])
        command = c.kw.get("command") or []
        command = [command] if isinstance(command, str) else list(command)
        if self.hang_short and entrypoint in (["true"], ["cat"]):
            return
        if entrypoint == ["true"] and not command:
            c.exit(0)
        elif entrypoint == ["cat"]:
            vol, m = mounts[0]
            rel = command[0][len(m["Target"]) + 1:]
            if rel in vol.files:
                c.out = vol.files[rel].encode()
                c.exit(0)
            else:
                c.exit(1)
        elif entrypoint[-1:] == ["-c"] and "nuclei -update-templates" in command[0]:
            vol, m = mounts[0]
            if self.refresh == "hang":
                return
            if self.refresh == "fail" or m["ReadOnly"]:
                c.exit(1)
                return
            vol.files["http/technologies/new-in-the-release.yaml"] = "id: new\n"
            vol.files[STAMP] = f"{int(self.wall())}\n"
            c.exit(0)
        else:
            raise AssertionError(f"unexpected program {entrypoint} {command}")

    def templates_containers(self):
        return [c for c in self.containers.items.values()
                if c.labels.get(sc.LABEL_ROLE) == sc.ROLE_TEMPLATES]

    def refreshers(self):
        return [kw for kw in self.created if kw.get("name") == sc.TEMPLATES_REFRESH_CONTAINER]

    def short_runs(self, entrypoint):
        return [kw for kw in self.created if kw.get("entrypoint") == entrypoint]


class Wall:
    def __init__(self, now=WALL0):
        self.now = now

    def __call__(self):
        return self.now


class Stop(BaseException):
    """Raised by Sleeps to end a refresh loop."""


class Sleeps:
    """A sleep that moves the wall clock and ends the loop after `stop_after` calls."""

    def __init__(self, wall, stop_after=None):
        self.wall = wall
        self.seen = []
        self.stop_after = stop_after

    async def __call__(self, seconds):
        self.seen.append(seconds)
        self.wall.now += seconds
        await asyncio.sleep(0)
        if self.stop_after is not None and len(self.seen) >= self.stop_after:
            raise Stop()


@pytest.fixture(autouse=True)
def fresh_process(monkeypatch):
    """Each test is a new orchestrator process: nothing populated yet."""
    st._populated.clear()
    monkeypatch.setenv(sc.MODE_ENV, sc.MODE_PER_USER)
    yield
    st._populated.clear()


@pytest.fixture
def wall():
    return Wall()


@pytest.fixture
def d(wall):
    return TplDocker(wall)


def stub_manager(d, owner=OWNER):
    """What the loop reads of the sandbox manager; its mode reads the switch."""
    return SimpleNamespace(client=d, owner=owner,
                           mode=lambda: sc.mode_from_env(os.environ.get(sc.MODE_ENV)))


def volume_mounts(kw):
    return [m for m in kw.get("mounts") or [] if m.get("Source") == sc.TEMPLATES_VOLUME]


# --- ensure_templates_ready: create and populate on first need ---------------------

def test_a_missing_volume_is_created_labelled_and_populated(d):
    assert st.ensure_templates_ready(d, OWNER) is True
    assert d.volume_creates == [{"name": sc.TEMPLATES_VOLUME, "driver": "local",
                                 "labels": {sc.LABEL_SANDBOX: "1", sc.LABEL_ROLE: sc.ROLE_TEMPLATES,
                                            st.LABEL_OWNER: OWNER}}]
    vol = d.volumes.get(sc.TEMPLATES_VOLUME)
    assert vol.files == BAKED
    (populate,) = d.created
    assert populate["image"] == sc.IMAGE
    assert populate["entrypoint"] == ["true"] and not populate["command"]
    assert volume_mounts(populate) == [{"Target": sc.TEMPLATES_TARGET, "Source": sc.TEMPLATES_VOLUME,
                                        "Type": "volume", "ReadOnly": False}]
    assert len(populate["mounts"]) == 1
    assert populate["network_mode"] == "none"
    assert populate["labels"] == st.templates_labels(OWNER)
    assert "environment" not in populate
    assert d.containers.live() == []


def test_an_existing_empty_volume_is_populated_once_per_process(d):
    vol = d.volumes.add()
    assert st.ensure_templates_ready(d, OWNER) is True
    assert d.volume_creates == []
    assert vol.files == BAKED
    assert len(d.short_runs(["true"])) == 1
    for _ in range(3):
        assert st.ensure_templates_ready(d, OWNER) is True
    assert len(d.created) == 1
    assert [c for c in d.calls if c[0] == "volumes.get"] == [("volumes.get", sc.TEMPLATES_VOLUME)] * 4


def test_a_populated_volume_keeps_its_templates(d):
    d.volumes.add(files={"http/newer.yaml": "id: newer\n", STAMP: "1\n"})
    assert st.ensure_templates_ready(d, OWNER) is True
    assert d.volumes.get(sc.TEMPLATES_VOLUME).files == {"http/newer.yaml": "id: newer\n", STAMP: "1\n"}


def test_a_volume_removed_and_made_again_is_populated_again(d):
    assert st.ensure_templates_ready(d, OWNER) is True
    d.volumes.get(sc.TEMPLATES_VOLUME).removed = True
    assert st.ensure_templates_ready(d, OWNER) is True
    assert len(d.volume_creates) == 2 and len(d.short_runs(["true"])) == 2
    assert d.volumes.get(sc.TEMPLATES_VOLUME).files == BAKED


@pytest.mark.parametrize("failure", ["docker_unreachable", "create", "image_missing", "start",
                                     "exit_code", "hang"])
def test_ensure_never_raises_and_leaves_no_container(d, failure):
    if failure == "docker_unreachable":
        d.fail_volumes = True
    elif failure == "create":
        d.fail_create = "no space left on device"
    elif failure == "image_missing":
        d.images.present = False
    elif failure == "start":
        d.fail_start = "OCI runtime create failed"
    elif failure == "exit_code":
        d.on_create.append(lambda c: c.kw.update(entrypoint=["cat"], command=["/root/nuclei-templates/x"]))
    elif failure == "hang":
        d.hang_short = True
    assert st.ensure_templates_ready(d, OWNER) is False
    assert d.containers.live() == []
    assert st._populated == set()
    if failure == "hang":
        assert ("container.wait", d.created[0]["name"], st.SHORT_TIMEOUT_S) in d.calls


def test_a_short_container_made_before_its_create_call_failed_is_removed(d):
    d.create_then_fail = True
    assert st.ensure_templates_ready(d, OWNER) is False
    (made,) = d.templates_containers()
    assert made.removed and ("container.remove", made.name, True) in d.calls
    assert st.ensure_templates_ready(d, OWNER) is True and d.containers.live() == []


@pytest.mark.parametrize("labels", [
    {"com.example": "unrelated"},
    {sc.LABEL_SANDBOX: "1", sc.LABEL_ROLE: sc.ROLE_TEMPLATES, st.LABEL_OWNER: OWNER, BROKER_OWNED_LABEL: "1"},
])
def test_a_container_holding_a_short_containers_name_is_never_removed(d, monkeypatch, labels):
    monkeypatch.setattr(st.secrets, "token_hex", lambda n: "abcdef")
    clash = d.containers.add(f"{st.SHORT_NAME_PREFIX}populate-abcdef", labels)
    assert st.ensure_templates_ready(d, OWNER) is False
    assert not clash.removed


def test_a_failed_populate_is_tried_again_at_the_next_call(d):
    d.fail_start = "OCI runtime create failed"
    assert st.ensure_templates_ready(d, OWNER) is False
    d.fail_start = None
    assert st.ensure_templates_ready(d, OWNER) is True
    assert d.volumes.get(sc.TEMPLATES_VOLUME).files == BAKED


def test_concurrent_calls_create_and_populate_once(d):
    def slow(_container):
        time.sleep(0.05)
    d.on_create.append(slow)
    results = []
    threads = [threading.Thread(target=lambda: results.append(st.ensure_templates_ready(d, OWNER)))
               for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert results == [True] * 4
    assert len(d.volume_creates) == 1
    assert len(d.short_runs(["true"])) == 1


# --- The refresher's specification -------------------------------------------------

def test_refresher_spec_has_no_secret_no_sandbox_network_and_a_memory_cap(d, monkeypatch):
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    kw = st.refresher_kwargs(OWNER)
    assert kw["image"] == sc.IMAGE
    assert kw["name"] == sc.TEMPLATES_REFRESH_CONTAINER
    # The volume read-write, and nothing else mounted.
    assert kw["mounts"] == [{"Target": sc.TEMPLATES_TARGET, "Source": sc.TEMPLATES_VOLUME,
                             "Type": "volume", "ReadOnly": False}]
    # Docker's default bridge: the internet, never a sandbox network or redamon-network.
    assert kw["network_mode"] == "bridge"
    for key in ("network", "networking_config", "links", "extra_hosts", "dns"):
        assert key not in kw
    assert kw["mem_limit"] == kw["memswap_limit"] == "512m"
    assert kw["auto_remove"] is True
    # Nothing beyond the image's environment, and no value of the orchestrator's own.
    assert "environment" not in kw
    dumped = json.dumps(kw, default=str)
    for value in SECRETS.values():
        assert value not in dumped
    for key in ("cap_add", "privileged", "ports", "sysctls", "volumes", "devices", "volumes_from",
                "security_opt", "pid_mode", "ipc_mode", "userns_mode"):
        assert key not in kw
    assert kw["labels"] == {sc.LABEL_SANDBOX: "1", sc.LABEL_ROLE: sc.ROLE_TEMPLATES, st.LABEL_OWNER: OWNER}
    assert sc.LABEL_USER not in kw["labels"]


def test_refresher_runs_the_nuclei_update_bounded_and_stamps_only_after_it():
    kw = st.refresher_kwargs(OWNER)
    assert kw["entrypoint"] == ["/bin/sh", "-c"]
    (script,) = kw["command"]
    steps = script.split(" && ")
    # The image's templates version is set below every release, and checked set...
    assert steps[0].startswith("sed -i ") and st.NUCLEI_CONFIG in steps[0] and st.UNSET_VERSION in steps[0]
    assert steps[1].startswith("grep -q ") and st.UNSET_VERSION in steps[1]
    # ...the update is bounded inside the container too, so a refresh left to
    # finish by an orchestrator restart still ends...
    assert steps[2] == f"timeout -k {st.KILL_GRACE_S} {st.REFRESH_TIMEOUT_S} nuclei -update-templates -silent"
    # ...and the stamp is written, atomically, only once that version was replaced.
    assert steps[3].startswith("! grep -Eq ") and st.UNSET_VERSION in steps[3]
    assert steps[4:] == [f"date +%s > {st.STAMP_PATH}.tmp", f"mv -f {st.STAMP_PATH}.tmp {st.STAMP_PATH}"]


# The image's nuclei config as shipped (S07 read it from redamon-kali-sandbox).
SHIPPED_CONFIG = ('{"nuclei-templates-directory":"/root/nuclei-templates",'
                  '"nuclei-templates-version":"v10.5.2","nuclei-ignore-hash":"84e41d39",'
                  '"nuclei-latest-version":"v3.11.1","nuclei-templates-latest-version":"v10.5.2"}')
FAKE_NUCLEI = """#!/bin/sh
echo "$@" >> "$FAKE_LOG"
case "$FAKE_NUCLEI" in
  install) sed -i 's/"nuclei-templates-version":"[^"]*"/"nuclei-templates-version":"v10.6.0"/' "$FAKE_CONFIG" ;;
  install_reformatted) printf '{\\n  "nuclei-templates-version": "v10.6.0"\\n}\\n' > "$FAKE_CONFIG" ;;
  rewrites_unset) printf '{\\n  "nuclei-templates-version": "v0.0.0"\\n}\\n' > "$FAKE_CONFIG" ;;
  exit_1) exit 1 ;;
esac
exit 0
"""


@pytest.mark.parametrize("nuclei,config,stamped", [
    ("install", SHIPPED_CONFIG, True),
    ("install_reformatted", SHIPPED_CONFIG, True),
    # Nuclei exits 0 with nothing installed (offline, a read-only folder).
    ("offline", SHIPPED_CONFIG, False),
    ("rewrites_unset", SHIPPED_CONFIG, False),
    ("exit_1", SHIPPED_CONFIG, False),
    # No config, or a version key nuclei renamed: never stamped blind.
    ("install", None, False),
    ("install", '{"templates-version":"v10.5.2"}', False),
])
def test_the_refresh_script_stamps_only_after_an_install(tmp_path, nuclei, config, stamped):
    import shutil
    import subprocess
    for tool in ("sh", "sed", "grep", "timeout", "date", "mv"):
        if not shutil.which(tool):
            pytest.skip(f"{tool} is not in this image")
    templates, cfg, log, bin_dir = (tmp_path / "templates", tmp_path / "templates-config.json",
                                    tmp_path / "nuclei.log", tmp_path / "bin")
    templates.mkdir()
    bin_dir.mkdir()
    (bin_dir / "nuclei").write_text(FAKE_NUCLEI)
    (bin_dir / "nuclei").chmod(0o755)
    if config is not None:
        cfg.write_text(config)
    script = st.REFRESH_SCRIPT.replace(st.NUCLEI_CONFIG, str(cfg)).replace(sc.TEMPLATES_TARGET, str(templates))
    before = int(time.time())
    subprocess.run(["sh", "-c", script], timeout=30, capture_output=True,
                   env={"PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin", "FAKE_NUCLEI": nuclei,
                        "FAKE_CONFIG": str(cfg), "FAKE_LOG": str(log)})
    stamp = templates / STAMP
    assert stamp.exists() is stamped
    assert not (templates / (STAMP + ".tmp")).exists() or not stamped
    if stamped:
        assert before <= st.parse_stamp(stamp.read_bytes()) <= time.time() + 1
    ran = log.read_text().split("\n") if log.exists() else []
    assert ran[:1] == (["-update-templates -silent"] if config == SHIPPED_CONFIG else [])
    if nuclei == "offline":
        # Only the templates version is touched, never the latest-release fields.
        assert cfg.read_text() == SHIPPED_CONFIG.replace('"nuclei-templates-version":"v10.5.2"',
                                                         '"nuclei-templates-version":"v0.0.0"')


async def test_the_refresher_that_runs_is_the_spec(d, wall):
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is True
    assert d.refreshers() == [st.refresher_kwargs(OWNER)]


async def test_every_templates_container_is_cleaned_by_redamon_sh_and_left_by_adoption(d, wall):
    d.volumes.add(files=dict(BAKED))
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is True
    kinds = {kw["entrypoint"][0] for kw in d.created}
    assert kinds == {"true", "/bin/sh", "cat"}
    for kw in d.created:
        # redamon.sh down/clean/purge select label=redamon.sandbox=1 AND the owner;
        # adoption skips a role=templates container that names no user.
        assert kw["labels"][sc.LABEL_SANDBOX] == "1" and kw["labels"][st.LABEL_OWNER] == OWNER
        assert kw["labels"][sc.LABEL_ROLE] == sc.ROLE_TEMPLATES and sc.LABEL_USER not in kw["labels"]
        assert kw["image"] == sc.IMAGE and "environment" not in kw
        assert [m["Source"] for m in kw["mounts"]] == [sc.TEMPLATES_VOLUME]
    for kw in d.short_runs(["cat"]):
        assert kw["network_mode"] == "none" and kw["mounts"][0]["ReadOnly"] is True
    assert d.containers.live() == []


def test_the_owner_label_is_the_managers():
    assert st.LABEL_OWNER == sm.LABEL_OWNER


# --- refresh_templates: failure-soft -----------------------------------------------

async def test_a_refresh_writes_new_templates_and_the_stamp(d, wall):
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is True
    files = d.volumes.get(sc.TEMPLATES_VOLUME).files
    assert "http/technologies/new-in-the-release.yaml" in files
    assert files[STAMP] == f"{int(WALL0)}\n"
    assert await asyncio.to_thread(st.read_refreshed_at, d, OWNER) == WALL0


@pytest.mark.parametrize("failure", ["docker_unreachable", "image_missing", "create", "start", "script"])
async def test_a_failed_refresh_returns_false_and_never_raises(d, wall, failure):
    d.volumes.add(files=dict(BAKED))
    if failure == "docker_unreachable":
        d.fail_volumes = True
    elif failure == "image_missing":
        d.images.present = False
    elif failure == "create":
        d.on_create.append(lambda c: setattr(d, "fail_create", "no space left on device"))
    elif failure == "start":
        d.on_create.append(lambda c: setattr(d, "fail_start", "OCI runtime create failed")
                           if c.name == sc.TEMPLATES_REFRESH_CONTAINER else None)
    elif failure == "script":
        d.refresh = "fail"
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is False
    assert d.containers.live() == []
    assert STAMP not in d.volumes.items[sc.TEMPLATES_VOLUME].files


async def test_a_hung_refresh_is_removed_at_its_deadline(d, wall):
    d.refresh = "hang"
    sleeps = Sleeps(wall)
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=sleeps) is False
    assert d.containers.live() == []
    assert ("container.remove", sc.TEMPLATES_REFRESH_CONTAINER, True) in d.calls
    waited = sum(sleeps.seen)
    assert st.REFRESH_TIMEOUT_S <= waited <= st.REFRESH_DEADLINE_S + st.POLL_S
    assert set(sleeps.seen) == {st.POLL_S}


@pytest.mark.parametrize("started_ago", [0, 60, st.REFRESH_DEADLINE_S - 1])
async def test_a_refresh_still_running_within_its_deadline_is_left_to_finish(d, wall, started_ago):
    d.volumes.add(files=dict(BAKED))
    running = d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, st.templates_labels(OWNER),
                               started_ago=started_ago)
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is False
    assert d.refreshers() == [] and not running.removed and running.status == "running"


# A refresher that can never end on its own: auto_remove acts only after an exit.
NEVER_ENDS = [("created", 0), ("created", 10 * DAY), ("paused", 60), ("running", st.REFRESH_DEADLINE_S),
              ("running", 10 * DAY), ("exited", 60), ("dead", 60)]


@pytest.mark.parametrize("status,started_ago", NEVER_ENDS)
async def test_a_leftover_that_cannot_end_on_its_own_is_replaced(d, wall, status, started_ago):
    d.volumes.add(files=dict(BAKED))
    leftover = d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, st.templates_labels(OWNER), status=status,
                                started_ago=started_ago)
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is True
    assert leftover.removed and ("container.remove", leftover.name, True) in d.calls
    assert len(d.refreshers()) == 1


async def test_a_running_leftover_whose_start_cannot_be_read_is_replaced(d, wall, monkeypatch):
    d.volumes.add(files=dict(BAKED))
    leftover = d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, st.templates_labels(OWNER))
    monkeypatch.setattr(TplContainer, "attrs", property(lambda c: {"State": {"Status": c.status,
                                                                             "StartedAt": "yesterday"},
                                                                   "Created": None}))
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is True
    assert leftover.removed


@pytest.mark.parametrize("status", ["created", "paused"])
async def test_a_stuck_leftover_never_stops_the_daily_refresh(stamped, wall, status):
    """Before: 48 simulated hours of the loop started no refresher at all."""
    stamped.volumes.add(files=dict(BAKED))
    stamped.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, st.templates_labels(OWNER), status=status)
    sleeps = await run_loop(stamped, wall, 2)
    assert refresh_times(stamped) == [WALL0, WALL0 + DAY] and sleeps.seen == [DAY, DAY]


@pytest.mark.parametrize("labels", [
    {sc.LABEL_SANDBOX: "1", sc.LABEL_ROLE: sc.ROLE_TEMPLATES, st.LABEL_OWNER: "another-stack"},
    {"com.example": "unrelated"},
    {sc.LABEL_SANDBOX: "1", sc.LABEL_ROLE: sc.ROLE_TEMPLATES, st.LABEL_OWNER: OWNER, sc.LABEL_USER: "u1"},
    # A look-alike a scan's broker created: the broker passes any name and labels.
    {sc.LABEL_SANDBOX: "1", sc.LABEL_ROLE: sc.ROLE_TEMPLATES, st.LABEL_OWNER: OWNER, BROKER_OWNED_LABEL: "1"},
])
async def test_a_container_this_stack_did_not_start_is_never_touched(d, wall, labels):
    d.volumes.add(files=dict(BAKED))
    foreign = d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, labels, status="exited")
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is False
    assert not foreign.removed and d.refreshers() == []


async def test_an_old_stamp_left_by_an_earlier_refresh_is_no_success(d, wall):
    d.volumes.add(files={**BAKED, STAMP: f"{int(WALL0) - DAY}\n"})
    d.refresh = "fail"
    assert await st.refresh_templates(d, OWNER, clock=wall, sleep=Sleeps(wall)) is False


async def test_a_refresh_in_progress_never_blocks_a_sandbox_preparation(d, wall):
    d.volumes.add(files=dict(BAKED))
    d.refresh = "hang"
    held = asyncio.Event()

    async def poll_sleep(seconds):
        held.set()
        await asyncio.Event().wait()
    refresh = asyncio.create_task(st.refresh_templates(d, OWNER, clock=wall, sleep=poll_sleep))
    await asyncio.wait_for(held.wait(), 2)
    # A new process's first start: it runs its own populate while the refresher runs.
    st._populated.clear()
    assert await asyncio.wait_for(asyncio.to_thread(st.ensure_templates_ready, d, OWNER), 2) is True
    assert len(d.short_runs(["true"])) == 2
    assert await asyncio.wait_for(asyncio.to_thread(st.ensure_templates_ready, d, OWNER), 2) is True
    refresh.cancel()
    with pytest.raises(asyncio.CancelledError):
        await refresh
    # Shutting down mid-refresh leaves the refresher to finish (auto_remove).
    (refresher,) = [c for c in d.containers.live() if c.name == sc.TEMPLATES_REFRESH_CONTAINER]
    assert refresher.status == "running"


# --- The stamp ---------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (b"1800000000\n", 1_800_000_000.0), (b"1800000000", 1_800_000_000.0), (b" 42 \n", 42.0),
    (b"", None), (b"\n", None), (b"abc\n", None), (b"-5\n", None), (b"1e9\n", None),
    (b"1800000000.5\n", None), (b"9" * 13, None), (b"\xff\xfe", None), (b"1\n2\n", None),
])
def test_stamp_parsing(raw, expected):
    assert st.parse_stamp(raw) == expected


def test_no_volume_means_no_stamp_and_creates_nothing(d):
    assert st.read_refreshed_at(d, OWNER) is None
    assert d.created == [] and d.volume_creates == [] and d.volumes.items == {}


def test_the_stamp_is_read_through_a_read_only_mount_with_no_network(d):
    d.volumes.add(files={**BAKED, STAMP: "1799990000\n"})
    assert st.read_refreshed_at(d, OWNER) == 1_799_990_000.0
    (probe,) = d.created
    assert probe["entrypoint"] == ["cat"] and probe["command"] == [st.STAMP_PATH]
    assert volume_mounts(probe) == [{"Target": sc.TEMPLATES_TARGET, "Source": sc.TEMPLATES_VOLUME,
                                     "Type": "volume", "ReadOnly": True}]
    assert probe["network_mode"] == "none" and probe["labels"] == st.templates_labels(OWNER)
    assert d.containers.live() == []


# --- refresh_loop: the schedule ----------------------------------------------------

async def run_loop(d, wall, stop_after):
    sleeps = Sleeps(wall, stop_after)
    with pytest.raises(Stop):
        await asyncio.wait_for(st.refresh_loop(stub_manager(d), clock=wall, sleep=sleeps), 5)
    return sleeps


def refresh_times(d):
    return [int(kw["_at"]) for kw in d.created if kw.get("name") == sc.TEMPLATES_REFRESH_CONTAINER]


@pytest.fixture
def stamped(d, wall):
    """Record the wall time of each refresher's create."""
    d.on_create.append(lambda c: c.kw.__setitem__("_at", wall()) if c.name == sc.TEMPLATES_REFRESH_CONTAINER
                       else None)
    return d


async def test_a_missing_volume_is_filled_at_once_then_refreshed_every_day(stamped, wall):
    sleeps = await run_loop(stamped, wall, 3)
    assert refresh_times(stamped) == [WALL0, WALL0 + DAY, WALL0 + 2 * DAY]
    assert sleeps.seen == [DAY, DAY, DAY]
    vol = stamped.volumes.get(sc.TEMPLATES_VOLUME)
    assert vol.attrs["Labels"] == st.templates_labels(OWNER)
    assert vol.files[STAMP] == f"{int(WALL0 + 2 * DAY)}\n"


async def test_an_empty_volume_is_filled_and_refreshed_at_once(stamped, wall):
    stamped.volumes.add()
    await run_loop(stamped, wall, 1)
    assert refresh_times(stamped) == [WALL0]
    assert set(BAKED) <= set(stamped.volumes.get(sc.TEMPLATES_VOLUME).files)


@pytest.mark.parametrize("age", [DAY, DAY + 1, 3 * DAY, -3 * DAY])
async def test_a_stale_or_future_stamp_is_refreshed_at_once(stamped, wall, age):
    stamped.volumes.add(files={**BAKED, STAMP: f"{int(WALL0 - age)}\n"})
    sleeps = await run_loop(stamped, wall, 1)
    assert refresh_times(stamped) == [WALL0] and sleeps.seen == [DAY]


@pytest.mark.parametrize("age", [0, 60, 3600, DAY - 60])
async def test_a_recent_stamp_waits_until_it_is_a_day_old(stamped, wall, age):
    stamped.volumes.add(files={**BAKED, STAMP: f"{int(WALL0 - age)}\n"})
    sleeps = await run_loop(stamped, wall, 2)
    assert sleeps.seen[0] == DAY - age
    assert refresh_times(stamped) == [WALL0 + DAY - age]


async def test_a_failed_refresh_is_retried_after_the_retry_delay(stamped, wall):
    stamped.refresh = "fail"
    outcomes = iter(["fail", "ok"])
    stamped.on_create.append(lambda c: setattr(stamped, "refresh", next(outcomes))
                             if c.name == sc.TEMPLATES_REFRESH_CONTAINER else None)
    sleeps = await run_loop(stamped, wall, 2)
    assert sleeps.seen == [st.RETRY_S, DAY]
    assert refresh_times(stamped) == [WALL0, WALL0 + st.RETRY_S]


async def test_the_loop_survives_docker_errors(stamped, wall):
    stamped.fail_volumes = True
    sleeps = await run_loop(stamped, wall, 3)
    assert sleeps.seen == [st.RETRY_S] * 3


async def test_the_loop_survives_an_unexpected_error(wall):
    broken = SimpleNamespace(owner=OWNER, mode=lambda: sc.MODE_PER_USER)  # no client
    sleeps = Sleeps(wall, 2)
    with pytest.raises(Stop):
        await asyncio.wait_for(st.refresh_loop(broken, clock=wall, sleep=sleeps), 5)
    assert sleeps.seen == [st.RETRY_S, st.RETRY_S]


async def test_shared_mode_does_nothing(d, wall, monkeypatch):
    monkeypatch.setenv(sc.MODE_ENV, sc.MODE_SHARED)
    sleeps = Sleeps(wall, 1)
    await asyncio.wait_for(st.refresh_loop(stub_manager(d), clock=wall, sleep=sleeps), 5)
    assert d.calls == [] and sleeps.seen == []


async def test_shared_mode_does_nothing_with_the_real_manager(world, monkeypatch):
    monkeypatch.setenv(sc.MODE_ENV, sc.MODE_SHARED)
    before = list(world.d.calls)
    await asyncio.wait_for(st.refresh_loop(world.mgr, sleep=Sleeps(Wall(), 1)), 5)
    assert world.d.calls == before


# --- The manager's call ------------------------------------------------------------

@pytest.fixture
def prepared(monkeypatch, world):
    """Record the manager's call to ensure_templates_ready in Docker's call log."""
    rec = SimpleNamespace(calls=[], result=True)

    def ensure_templates_ready(client, owner):
        rec.calls.append((client, owner))
        world.d.calls.append(("ensure_templates_ready", owner))
        return rec.result
    monkeypatch.setattr(st, "ensure_templates_ready", ensure_templates_ready)
    return rec


async def test_a_start_prepares_the_volume_before_the_sandbox_is_created(world, prepared):
    answer = await world.mgr.ensure(ALICE, ["projA"])
    assert answer["state"] == "running"
    assert prepared.calls == [(world.d, world.mgr.owner)] and world.mgr.owner == OWNER
    order = [c for c in world.d.calls if c[0] in ("ensure_templates_ready", "containers.create")]
    assert order == [("ensure_templates_ready", OWNER), ("containers.create", answer["host"])]


async def test_a_failed_preparation_never_fails_the_start(world, prepared):
    prepared.result = False
    answer = await world.mgr.ensure(ALICE, ["projA"])
    assert answer["state"] == "running" and len(world.created(ALICE)) == 1


async def test_a_refused_start_prepares_nothing(world, prepared):
    world.d.images.by_name.pop(sc.IMAGE)
    with pytest.raises(sm.SandboxError):
        await world.mgr.ensure(ALICE, ["projA"])
    assert prepared.calls == []


async def test_shared_mode_prepares_nothing(world, prepared, monkeypatch):
    monkeypatch.setenv(sc.MODE_ENV, sc.MODE_SHARED)
    assert await world.mgr.ensure(ALICE, ["projA"]) == {"mode": sc.MODE_SHARED}
    assert prepared.calls == []


async def test_with_the_real_preparation_a_docker_without_volumes_still_starts(world):
    # The lifecycle tests' FakeDocker has no volume API: the preparation fails
    # soft and the start goes on.
    answer = await world.mgr.ensure(ALICE, ["projA"])
    assert answer["state"] == "running"


async def test_the_sandbox_mounts_the_volume_read_only_and_nothing_else_of_it(world, prepared):
    answer = await world.mgr.ensure(ALICE, ["projA"])
    (kw,) = [kw for kw in world.d.created if kw.get("name") == answer["host"]]
    assert volume_mounts(kw) == [{"Target": sc.TEMPLATES_TARGET, "Source": sc.TEMPLATES_VOLUME,
                                  "Type": "volume", "ReadOnly": True}]
    assert [m for m in kw["mounts"] if m["Target"] == sc.TEMPLATES_TARGET] == volume_mounts(kw)


async def test_adoption_leaves_a_running_refresher_alone(world):
    refresher = world.d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, labels=st.templates_labels(OWNER),
                                       image=sc.IMAGE, image_id=lc.IMAGE_ID)
    summary = await world.mgr.adopt()
    assert summary["removed"] == 0 and not refresher.removed


# --- The lifespan ------------------------------------------------------------------

async def test_lifespan_starts_the_refresh_loop_and_cancels_it_at_shutdown(lifespan_env, env, monkeypatch):
    mgr = lifespan_env.install(LifecycleManager())
    started = asyncio.Event()
    seen = {}

    async def refresh_loop(manager):
        seen["manager"] = manager
        seen["wired"] = lifespan_env.cm.extra_reservation_keys == manager.reservation_keys
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            seen["cancelled"] = True
            raise
    monkeypatch.setattr(st, "refresh_loop", refresh_loop)
    async with api.lifespan(api.app):
        await asyncio.wait_for(started.wait(), 2)
        assert seen["manager"] is mgr and seen["wired"] is True
        assert "cancelled" not in seen
    assert seen.get("cancelled") is True

"""Nuclei templates for per-user Kali sandboxes (group 1).

Every sandbox mounts the named volume ``TEMPLATES_VOLUME`` read-only at
``/root/nuclei-templates``. Nuclei runs on a read-only templates folder with no
flag, and never updates it during a scan, so the templates stay current only
through this module:

- ``ensure_templates_ready`` makes the volume on first need and fills it: a
  short container from the Kali image mounts it read-write over the image's
  templates, and Docker copies them into an empty volume. The sandbox manager
  calls it before each start; after the first fill a call costs one volume
  lookup.
- ``refresh_templates`` runs the refresher container, which updates the
  templates from the internet on Docker's default bridge (never a sandbox
  network), with no environment beyond the image's, capped at 512 MB and bounded
  in time inside and outside the container. It installs the latest release
  whatever the image baked, and writes the time into the volume
  (``STAMP_PATH``) only after an install.
- ``refresh_loop`` refreshes on orchestrator start when the volume is missing,
  empty or a day old, then daily. It does nothing in ``shared`` mode, where the
  shared container keeps its own templates.

The volume is shared by every RedAmon stack on the daemon (its name is fixed);
each container made here carries the stack's owner label, so `./redamon.sh
down`, `clean` and `purge` remove one left running, and adoption leaves it to
finish. Nothing here raises to its caller: a sandbox starts whatever the state
of its templates, and the loop never dies.
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import threading
import time
from datetime import datetime
from typing import Callable, Optional

import docker
from docker.errors import NotFound

import sandbox_contract as sc
from container_manager import BROKER_OWNED_LABEL

logger = logging.getLogger(__name__)

# sandbox_manager.LABEL_OWNER, which imports this module (a test pins the two).
LABEL_OWNER = "redamon.sandbox.owner"

STAMP_PATH = f"{sc.TEMPLATES_TARGET}/.redamon-refreshed"
REFRESH_TIMEOUT_S = 900
# `timeout -k`: the update gets SIGTERM at REFRESH_TIMEOUT_S, SIGKILL this later.
KILL_GRACE_S = 30
# The orchestrator removes a refresher still running past this (a backstop: the
# container bounds itself, which also holds for one left to finish by a restart).
REFRESH_DEADLINE_S = REFRESH_TIMEOUT_S + KILL_GRACE_S + 30
POLL_S = 5
# A failed or skipped refresh is tried again this soon, not a day later.
RETRY_S = 3_600
# The populate and the stamp read: neither runs anything that takes long.
SHORT_TIMEOUT_S = 60
MEM_LIMIT = "512m"
PIDS_LIMIT = 1_024
# A stamp this far in the future (a clock set back) counts as stale.
CLOCK_SLACK_S = 300
SHORT_NAME_PREFIX = "redamon-kali-templates-"

# Nuclei compares the latest release with the templates version in its config,
# which lives in the image (/root/.config), not in the volume: a refresher from an
# image that baked the latest release would leave an older volume as it is. So
# the version is set below every release first, and the latest one is always
# installed. Nuclei exits 0 whether or not it installed anything (offline, a
# read-only folder), and writes the new version only after an install: the stamp
# is written only when that version replaced the one set here.
NUCLEI_CONFIG = "/root/.config/nuclei/.templates-config.json"
UNSET_VERSION = "v0.0.0"
_VERSION_KEY = '"nuclei-templates-version"'
REFRESH_SCRIPT = " && ".join([
    f"sed -i 's/{_VERSION_KEY}: *\"[^\"]*\"/{_VERSION_KEY}:\"{UNSET_VERSION}\"/' {NUCLEI_CONFIG}",
    f"grep -q '{_VERSION_KEY}:\"{UNSET_VERSION}\"' {NUCLEI_CONFIG}",
    f"timeout -k {KILL_GRACE_S} {REFRESH_TIMEOUT_S} nuclei -update-templates -silent",
    f"! grep -Eq '{_VERSION_KEY}: *\"{UNSET_VERSION}\"' {NUCLEI_CONFIG}",
    f"date +%s > {STAMP_PATH}.tmp",
    f"mv -f {STAMP_PATH}.tmp {STAMP_PATH}",
])

_ALIVE = ("created", "running", "restarting", "paused")
_STAMP = re.compile(r"\d{1,12}")
_DOCKER_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})")

# Serialises the volume's create and fill across threads (two people's first
# starts at once); a refresh never holds it, so it never delays a start.
_LOCK = threading.Lock()
# The CreatedAt of each volume this process has filled: a volume removed and
# made again (purge, by hand) is filled again.
_populated: set = set()


def templates_labels(owner: str) -> dict:
    return {**sc.templates_labels(), LABEL_OWNER: owner}


def _volume_mount(read_only: bool) -> docker.types.Mount:
    return docker.types.Mount(sc.TEMPLATES_TARGET, sc.TEMPLATES_VOLUME, type="volume",
                              read_only=read_only)


def refresher_kwargs(owner: str) -> dict:
    """The refresher container: the volume read-write and nothing else mounted,
    the default bridge, no environment of its own, no added privilege."""
    return dict(
        image=sc.IMAGE, name=sc.TEMPLATES_REFRESH_CONTAINER,
        entrypoint=["/bin/sh", "-c"], command=[REFRESH_SCRIPT],
        labels=templates_labels(owner), mounts=[_volume_mount(read_only=False)],
        network_mode="bridge", mem_limit=MEM_LIMIT, memswap_limit=MEM_LIMIT,
        pids_limit=PIDS_LIMIT, auto_remove=True)


def _short_kwargs(owner: str, role: str, entrypoint: list, command: Optional[list],
                  read_only: bool) -> dict:
    return dict(
        image=sc.IMAGE, name=f"{SHORT_NAME_PREFIX}{role}-{secrets.token_hex(3)}",
        entrypoint=entrypoint, command=command, labels=templates_labels(owner),
        mounts=[_volume_mount(read_only)], network_mode="none",
        mem_limit=MEM_LIMIT, memswap_limit=MEM_LIMIT, pids_limit=PIDS_LIMIT)


def _remove_quietly(container) -> None:
    try:
        container.remove(force=True)
    except Exception:  # noqa: BLE001 - already gone, or auto_remove got there first
        pass


def _run_short_sync(client, kwargs: dict, output: bool = False) -> tuple:
    """(exit code, stdout when asked) of a short container, always removed, also
    when the create call failed after the daemon made it (a client timeout)."""
    container = None
    try:
        container = client.containers.create(**kwargs)
        container.start()
        result = container.wait(timeout=SHORT_TIMEOUT_S)
        code = result.get("StatusCode") if isinstance(result, dict) else None
        out = container.logs(stdout=True, stderr=False) if output and code == 0 else b""
        return code, out
    finally:
        if container is None:
            try:
                made = client.containers.get(kwargs["name"])
            except Exception:  # noqa: BLE001 - never made, or Docker unreachable
                made = None
            if made is not None and _ours(made, kwargs["labels"][LABEL_OWNER]):
                container = made
        if container is not None:
            _remove_quietly(container)


def ensure_templates_ready(client, owner: str) -> bool:
    """Create the volume when missing and fill it when empty. Blocking (run it
    in a thread); never raises: False when the volume could not be made ready.
    A sandbox started after a failure still gets the image's templates: Docker
    makes a missing volume at the sandbox's own read-only mount and fills it."""
    try:
        with _LOCK:
            try:
                volume = client.volumes.get(sc.TEMPLATES_VOLUME)
            except NotFound:
                volume = client.volumes.create(name=sc.TEMPLATES_VOLUME, driver="local",
                                               labels=templates_labels(owner))
                logger.info(f"[sandbox] created the nuclei templates volume {sc.TEMPLATES_VOLUME}")
            created_at = (volume.attrs or {}).get("CreatedAt") or ""
            if created_at and created_at in _populated:
                return True
            # Docker copies the image's templates into the volume only while it is
            # empty, so this fills an empty volume and leaves a filled one as it is.
            code, _ = _run_short_sync(client, _short_kwargs(owner, "populate", ["true"], None,
                                                            read_only=False))
            if code != 0:
                logger.warning(f"[sandbox] filling the nuclei templates volume exited {code}")
                return False
            if created_at:
                _populated.add(created_at)
            return True
    except Exception as e:  # noqa: BLE001 - a sandbox starts anyway
        logger.warning(f"[sandbox] the nuclei templates volume could not be made ready "
                       f"({type(e).__name__}); sandboxes start without waiting for it")
        return False


def parse_stamp(raw) -> Optional[float]:
    """The epoch seconds the refresher wrote, or None for anything else."""
    try:
        text = bytes(raw).decode("ascii").strip()
    except (TypeError, ValueError):
        return None
    return float(text) if _STAMP.fullmatch(text) else None


def read_refreshed_at(client, owner: str) -> Optional[float]:
    """When the volume was last refreshed; None when it is missing, empty or was
    never refreshed. Blocking; raises when Docker fails."""
    try:
        client.volumes.get(sc.TEMPLATES_VOLUME)
    except NotFound:
        return None
    code, out = _run_short_sync(client, _short_kwargs(owner, "probe", ["cat"], [STAMP_PATH],
                                                      read_only=True), output=True)
    return parse_stamp(out) if code == 0 else None


def _ours(container, owner: str) -> bool:
    labels = container.labels or {}
    # A scan's broker can create a container with any name and labels.
    return (labels.get(sc.LABEL_SANDBOX) == sc.LABEL_TRUE
            and labels.get(sc.LABEL_ROLE) == sc.ROLE_TEMPLATES
            and labels.get(LABEL_OWNER) == owner and not labels.get(sc.LABEL_USER)
            and not labels.get(BROKER_OWNED_LABEL))


def _docker_time(value) -> Optional[float]:
    match = _DOCKER_TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None or value.startswith("0001-"):
        return None
    zone = "+00:00" if match.group(2) == "Z" else match.group(2)
    return datetime.fromisoformat(match.group(1) + zone).timestamp()


def _started_at(container) -> Optional[float]:
    attrs = container.attrs or {}
    return _docker_time((attrs.get("State") or {}).get("StartedAt")) or _docker_time(attrs.get("Created"))


def _start_refresher_sync(client, owner: str, now: float):
    """The started refresher, or None when the name is held by a refresh of this
    stack still running within its deadline (left to finish) or by a container
    this stack did not start."""
    try:
        old = client.containers.get(sc.TEMPLATES_REFRESH_CONTAINER)
    except NotFound:
        old = None
    if old is not None:
        if not _ours(old, owner):
            logger.warning(f"[sandbox] a container this stack did not start holds the name "
                           f"{sc.TEMPLATES_REFRESH_CONTAINER}; nuclei templates not refreshed")
            return None
        # Only a running refresh can still end on its own: one created and never
        # started, or paused, holds the name for ever (auto_remove acts on an exit).
        started = _started_at(old)
        if old.status in ("running", "restarting") and started is not None \
                and now - started < REFRESH_DEADLINE_S:
            logger.info("[sandbox] a nuclei templates refresh is still running; left to finish")
            return None
        _remove_quietly(old)
    container = client.containers.create(**refresher_kwargs(owner))
    try:
        container.start()
    except Exception:
        _remove_quietly(container)
        raise
    return container


def _status_sync(container) -> str:
    try:
        container.reload()
    except NotFound:
        return "gone"
    return container.status


async def refresh_templates(client, owner: str, *, clock: Callable[[], float] = time.time,
                            sleep: Callable = asyncio.sleep) -> bool:
    """One refresh; True when the volume's stamp shows it completed. Never raises.
    Cancelled (shutdown), it leaves the refresher to finish on its own."""
    started = clock()
    try:
        if not await asyncio.to_thread(ensure_templates_ready, client, owner):
            return False
        container = await asyncio.to_thread(_start_refresher_sync, client, owner, clock())
        if container is None:
            return False
        while await asyncio.to_thread(_status_sync, container) in _ALIVE:
            if clock() - started >= REFRESH_DEADLINE_S:
                await asyncio.to_thread(_remove_quietly, container)
                logger.warning(f"[sandbox] the nuclei templates refresh ran past "
                               f"{REFRESH_DEADLINE_S} s; removed")
                return False
            await sleep(POLL_S)
        refreshed_at = await asyncio.to_thread(read_refreshed_at, client, owner)
    except Exception as e:  # noqa: BLE001 - retried by the loop
        logger.warning(f"[sandbox] the nuclei templates refresh failed ({type(e).__name__})")
        return False
    # `date +%s` in the container reads the clock this process reads.
    if refreshed_at is None or refreshed_at < int(started):
        logger.warning("[sandbox] the nuclei templates refresh did not complete; "
                       f"tried again in {RETRY_S} s")
        return False
    logger.info("[sandbox] nuclei templates refreshed")
    return True


async def _refresh_if_due(client, owner: str, clock: Callable[[], float], sleep: Callable) -> float:
    """Refresh when the volume is missing, empty or a day old; the seconds to the next check."""
    refreshed_at = await asyncio.to_thread(read_refreshed_at, client, owner)
    if refreshed_at is not None:
        age = clock() - refreshed_at
        if -CLOCK_SLACK_S <= age < sc.TEMPLATES_REFRESH_S:
            return sc.TEMPLATES_REFRESH_S - age
    ok = await refresh_templates(client, owner, clock=clock, sleep=sleep)
    return sc.TEMPLATES_REFRESH_S if ok else RETRY_S


async def refresh_loop(manager, *, clock: Callable[[], float] = time.time,
                       sleep: Callable = asyncio.sleep) -> None:
    """The templates of ``manager``'s sandboxes, from orchestrator start until
    shutdown (cancel). Returns at once in ``shared`` mode."""
    while True:
        try:
            if manager.mode() != sc.MODE_PER_USER:
                return
            wait = await _refresh_if_due(manager.client, manager.owner, clock, sleep)
        except Exception as e:  # noqa: BLE001 - the loop never dies
            logger.warning(f"[sandbox] the nuclei templates check failed ({type(e).__name__}); "
                           f"tried again in {RETRY_S} s")
            wait = RETRY_S
        await sleep(wait)

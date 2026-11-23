"""
Per-user Kali sandboxes: leases, the idle loop, the session hold cap and rolling
replacement (group 1: D22, D24).

Driven like the lifecycle tests: the in-memory FakeDocker, the `world` fixture and
the helpers of test_sandbox_manager_lifecycle.py, a real ReservationLedger, and a
fake clock the test moves by hand.

Two fidelity patches of the fake, applied to every test here: a container's
endpoint reports its GwPriority as the engine does (0 when none was asked for,
checked on Engine 29.10), and the engine's low-level exec calls exist. Inside a
sandbox the person is root and controls what any exec prints, so the fake's
occupant floods and never stops: an exec whose output is read (``exec_run``, or
``exec_start`` attached) blocks for ever, and only a detached exec returns.
"""
import asyncio
import json
import logging
import threading
import time
import uuid

import pytest
from docker.errors import APIError

import sandbox_contract as sc
import sandbox_manager as sm
from tests import test_sandbox_manager_lifecycle as lc
from tests.test_sandbox_manager_lifecycle import (  # noqa: F401 - env and world are fixtures
    ALICE, BOB, GB, OTHER_IMAGE_ID, FakeImage, add_agent, connects_to, env, settle, world)

IDLE_S = sc.IDLE_MINUTES_DEFAULT * 60
HOLD = sc.HOLD_LEASE_KIND
# The 400 code of a malformed lease id or kind (the webapp answers the same one).
INVALID_LEASE = "invalid_sandbox_request"
FLOOD_S = 20


def lid() -> str:
    return str(uuid.uuid4())


class Occupant:
    """What the person inside a sandbox does to an exec: its exit code, whether it
    is still running, and an endless flood for anyone who reads its output."""

    def __init__(self):
        self.exit_code = 0
        self.running = False
        self.execs = []
        self.output_read = False
        self.release = threading.Event()        # ends every blocked call at teardown
        self.daemon_hangs = False                # exec_create never answers


@pytest.fixture(autouse=True)
def engine_fidelity(monkeypatch, request):
    def attach(self, container, endpoint_config):
        self.endpoints[container.id] = dict(endpoint_config)
        self.attrs["Containers"][container.id] = {"Name": container.name}
        container.attrs["NetworkSettings"]["Networks"][self.name] = {
            "Aliases": endpoint_config.get("Aliases"),
            "GwPriority": endpoint_config.get("GwPriority", 0)}

    occupant = Occupant()
    original_exec = lc.FakeContainer.exec_run

    def flood():
        # Far longer than any bound a test allows; cut short at teardown.
        occupant.output_read = True
        occupant.release.wait(FLOOD_S)
        raise APIError("the flood was cut")

    def exec_run(self, cmd, **kw):
        if list(cmd[:2]) != ["python3", "-c"]:
            return original_exec(self, cmd, **kw)
        flood()

    def exec_create(self, container, cmd, stdout=True, stderr=True, stdin=False, tty=False,
                    privileged=False, user="", environment=None, workdir=None, detach_keys=None):
        if occupant.daemon_hangs:
            occupant.release.wait(FLOOD_S)
        c = self.d.containers.get(container)
        exec_id = self.d.new_id()
        occupant.execs.append({"id": exec_id, "container": c.name, "cmd": list(cmd),
                               "environment": dict(environment or {}), "stdout": stdout,
                               "stderr": stderr, "thread": threading.current_thread().name,
                               "started": False})
        self.d.calls.append(("container.exec", c.name, tuple(cmd)))
        return {"Id": exec_id}

    def exec_start(self, exec_id, detach=False, tty=False, stream=False, socket=False, demux=False):
        record = next(e for e in occupant.execs if e["id"] == exec_id)
        if not detach or stream or socket:
            flood()
        record["started"] = True
        return b""

    def exec_inspect(self, exec_id):
        next(e for e in occupant.execs if e["id"] == exec_id)
        return {"ID": exec_id, "Running": occupant.running,
                "ExitCode": None if occupant.running else occupant.exit_code}

    monkeypatch.setattr(lc.FakeNetwork, "_attach", attach)
    monkeypatch.setattr(lc.FakeContainer, "exec_run", exec_run)
    monkeypatch.setattr(lc.FakeAPI, "exec_create", exec_create, raising=False)
    monkeypatch.setattr(lc.FakeAPI, "exec_start", exec_start, raising=False)
    monkeypatch.setattr(lc.FakeAPI, "exec_inspect", exec_inspect, raising=False)
    yield occupant
    occupant.release.set()


@pytest.fixture
def occupant(engine_fidelity):
    return engine_fidelity


def tunnel_execs(occupant):
    return [e for e in occupant.execs if e["cmd"][:2] == ["python3", "-c"]]


async def settled(world, bound=5.0):
    """Every background task done, within ``bound`` seconds."""
    await asyncio.wait_for(world.mgr.join_background(), bound)


def instance(world, user_id, inst):
    return world.mgr.get_instance(user_id, inst)


def state_of(world, user_id, inst):
    i = instance(world, user_id, inst)
    return None if i is None else i.state


async def until_waiters(lock, n, timeout=3.0):
    """Wait until ``n`` coroutines queue on ``lock`` (some reach it through a thread)."""
    deadline = time.monotonic() + timeout
    while len(lock._waiters or ()) < n:
        assert time.monotonic() < deadline, "the coroutines never queued on the lock"
        await asyncio.sleep(0.005)


async def refused(coro):
    with pytest.raises(sm.SandboxError) as e:
        await coro
    return e.value


# --- WI-S05-1 Leases --------------------------------------------------------------

async def test_lease_expires_without_renew(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    ans = await world.mgr.lease(ALICE, a["instance"], lid(), "run")
    assert ans["expires_at"] == t0 + sc.LEASE_TTL_S and ans["state"] == "running"
    assert set(ans) == {"expires_at", "state", "stop_at", "warn"}
    world.clock.now = t0 + sc.LEASE_TTL_S - 1
    assert world.mgr.status(ALICE)["instances"][0]["lease_kinds"] == ["run"]
    world.clock.now = t0 + sc.LEASE_TTL_S
    assert world.mgr.status(ALICE)["instances"][0]["lease_kinds"] == []
    # Expired: the idle timer runs from the last use, and stops it after idle minutes.
    world.clock.now = t0 + IDLE_S - 1
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"
    world.clock.now = t0 + IDLE_S
    await world.mgr.idle_tick()
    assert instance(world, ALICE, a["instance"]) is None
    assert world.ledger.sandbox_keys() == set() and world.created() == []


async def test_renew_unknown_id_recreates_lease(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    lease_id = lid()
    first = await world.mgr.lease(ALICE, a["instance"], lease_id, "exec")
    world.clock.now += 30
    renewed = await world.mgr.lease(ALICE, a["instance"], lease_id, "exec")
    assert renewed["expires_at"] == first["expires_at"] + 30
    assert len(instance(world, ALICE, a["instance"]).leases) == 1
    # An orchestrator restart loses leases: a renewal of an id the instance does
    # not know (a running one) takes it again.
    instance(world, ALICE, a["instance"]).leases.clear()
    again = await world.mgr.lease(ALICE, a["instance"], lease_id, "exec")
    assert again["state"] == "running"
    assert world.mgr.status(ALICE)["instances"][0]["lease_kinds"] == ["exec"]


async def test_lease_for_another_users_instance_refused(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    b = await world.mgr.ensure(BOB, ["projB"])
    used = instance(world, ALICE, a["instance"]).last_used
    world.clock.now += 100
    err = await refused(world.mgr.lease(BOB, a["instance"], lid(), "run"))
    assert err.code == sc.ERR_UNKNOWN_INSTANCE and err.status == 404
    assert instance(world, ALICE, a["instance"]).leases == {}
    assert instance(world, ALICE, a["instance"]).last_used == used
    # The same lease id in two persons' hands is two leases; a release is scoped
    # to the person who sends it.
    shared_id = lid()
    await world.mgr.lease(ALICE, a["instance"], shared_id, "run")
    await world.mgr.lease(BOB, b["instance"], shared_id, "run")
    assert await world.mgr.release_lease(BOB, shared_id) == 1
    assert shared_id in instance(world, ALICE, a["instance"]).leases
    assert shared_id not in instance(world, BOB, b["instance"]).leases
    # Malformed instance ids are unknown instances, never a lookup.
    err = await refused(world.mgr.lease(BOB, "../../x", lid(), "run"))
    assert err.code == sc.ERR_UNKNOWN_INSTANCE


async def test_lease_on_a_stopped_or_unknown_instance_is_not_running(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.stop(ALICE, a["instance"], "operator")
    err = await refused(world.mgr.lease(ALICE, a["instance"], lid(), "run"))
    assert err.code == sc.ERR_NOT_RUNNING and err.status == 409
    err = await refused(world.mgr.lease(ALICE, "abcdef", lid(), "run"))
    assert err.code == sc.ERR_NOT_RUNNING
    # A person who never had a sandbox leaves no lock behind.
    assert BOB not in world.mgr._user_locks
    err = await refused(world.mgr.lease(BOB, "abcdef", lid(), "run"))
    assert err.code == sc.ERR_NOT_RUNNING and BOB not in world.mgr._user_locks


@pytest.mark.parametrize("user,lease_id,kind,code,status", [
    ("../alice", "uuid", "run", sc.ERR_INVALID_USER_ID, 400),
    (ALICE, "not-a-uuid", "run", INVALID_LEASE, 400),
    (ALICE, "uuid", "shell", INVALID_LEASE, 400),
    (ALICE, "uuid", None, INVALID_LEASE, 400),
])
async def test_lease_input_is_validated(world, user, lease_id, kind, code, status):
    a = await world.mgr.ensure(ALICE, ["projA"])
    err = await refused(world.mgr.lease(user, a["instance"], lid() if lease_id == "uuid" else lease_id, kind))
    assert err.code == code and err.status == status
    assert sm.ERR_INVALID_LEASE == INVALID_LEASE
    assert instance(world, ALICE, a["instance"]).leases == {}


async def test_release_lease_ends_use_and_is_idempotent(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    lease_id = lid()
    await world.mgr.lease(ALICE, a["instance"], lease_id, "terminal")
    world.clock.now += 60
    await world.mgr.lease(ALICE, a["instance"], lease_id, "terminal")
    world.clock.now += 20
    assert await world.mgr.release_lease(ALICE, lease_id) == 1
    inst = instance(world, ALICE, a["instance"])
    # The use ended now: the idle timer starts from the release.
    assert inst.leases == {} and inst.last_used == world.clock.now
    assert await world.mgr.release_lease(ALICE, lease_id) == 0
    assert await world.mgr.release_lease(ALICE, "not-a-uuid") == 0
    assert await world.mgr.release_lease(BOB, lease_id) == 0
    with pytest.raises(sm.SandboxInvalid):
        await world.mgr.release_lease("../x", lease_id)


# --- WI-S05-2 Idle loop and status ------------------------------------------------

@pytest.mark.parametrize("minutes", [None, "5"])
async def test_idle_stop_after_idle_minutes(world, minutes, caplog):
    if minutes:
        world.mp.setenv(sc.IDLE_MINUTES_ENV, minutes)
    idle_s = int(minutes or sc.IDLE_MINUTES_DEFAULT) * 60
    a = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    world.clock.now = t0 + idle_s - 1
    assert (await world.mgr.idle_tick())["stopped"] == 0
    assert state_of(world, ALICE, a["instance"]) == "running"
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    world.clock.now = t0 + idle_s
    assert (await world.mgr.idle_tick())["stopped"] == 1
    assert instance(world, ALICE, a["instance"]) is None
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set()
    assert any("stopped" in r.getMessage() and "reason=idle" in r.getMessage() for r in caplog.records)


async def test_idle_minutes_are_read_on_every_tick(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.clock.now += 6 * 60
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"
    world.mp.setenv(sc.IDLE_MINUTES_ENV, "5")
    await world.mgr.idle_tick()
    assert instance(world, ALICE, a["instance"]) is None


@pytest.mark.parametrize("raw", ["0", "-5", "abc", "", "1.5", " "])
async def test_idle_minutes_env_invalid_falls_back_to_20(world, raw):
    world.mp.setenv(sc.IDLE_MINUTES_ENV, raw)
    a = await world.mgr.ensure(ALICE, ["projA"])
    assert world.mgr.status(ALICE)["instances"][0]["stop_at"] == world.clock.now + 20 * 60
    world.clock.now += 20 * 60 - 1
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"
    world.clock.now += 1
    await world.mgr.idle_tick()
    assert instance(world, ALICE, a["instance"]) is None


@pytest.mark.parametrize("kind", sc.LEASE_KINDS)
async def test_use_kinds_reset_idle_timer_hold_does_not(world, kind):
    a = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    world.clock.now = t0 + 600
    await world.mgr.lease(ALICE, a["instance"], lid(), kind)
    inst = instance(world, ALICE, a["instance"])
    if kind == HOLD:
        assert inst.last_used == t0
    else:
        assert kind in sc.USE_KINDS and inst.last_used == t0 + 600


async def test_hold_lease_capped_at_8h_without_use(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    hold = lid()
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    # Hours past the idle timer, a hold keeps the sandbox up.
    world.clock.now = t0 + sc.HOLD_MAX_NO_USE_S - sc.HOLD_WARN_BEFORE_S - 1
    ans = await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    assert ans["warn"] is False and ans["stop_at"] == t0 + sc.HOLD_MAX_NO_USE_S
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"
    # The warning from one hour before the cap.
    world.clock.now += 1
    ans = await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    assert ans["warn"] is True
    await world.mgr.idle_tick()
    st = world.mgr.status(ALICE)["instances"][0]
    assert st["warn"] is True and st["stop_at"] == t0 + sc.HOLD_MAX_NO_USE_S and st["lease_kinds"] == [HOLD]
    world.clock.now = t0 + sc.HOLD_MAX_NO_USE_S - 1
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"
    world.clock.now = t0 + sc.HOLD_MAX_NO_USE_S
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    assert (await world.mgr.idle_tick())["stopped"] == 1
    assert instance(world, ALICE, a["instance"]) is None
    assert world.ledger.sandbox_keys() == set()


async def test_use_during_a_hold_restarts_the_8h(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    hold = lid()
    world.clock.now = t0 + 7 * 3600 + 5
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    assert world.mgr.status(ALICE)["instances"][0]["warn"] is True
    # The person opens the terminal: that is use, and the cap counts from it.
    term = lid()
    await world.mgr.lease(ALICE, a["instance"], term, "terminal")
    await world.mgr.release_lease(ALICE, term)
    st = world.mgr.status(ALICE)["instances"][0]
    assert st["warn"] is False and st["stop_at"] == world.clock.now + sc.HOLD_MAX_NO_USE_S
    world.clock.now = t0 + sc.HOLD_MAX_NO_USE_S + 60
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"


async def test_stop_vs_lease_race_lease_first_cancels_stop(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.clock.now += IDLE_S + 1
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    lease = asyncio.ensure_future(world.mgr.lease(ALICE, a["instance"], lid(), "run"))
    await until_waiters(lock, 1)
    tick = asyncio.ensure_future(world.mgr.idle_tick())
    await until_waiters(lock, 2)
    lock.release()
    ans = await lease
    summary = await tick
    assert ans["state"] == "running" and summary["stopped"] == 0
    assert state_of(world, ALICE, a["instance"]) == "running"


async def test_stop_vs_lease_race_stop_first_new_sandbox(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.clock.now += IDLE_S + 1
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    tick = asyncio.ensure_future(world.mgr.idle_tick())
    await until_waiters(lock, 1)
    lease = asyncio.ensure_future(world.mgr.lease(ALICE, a["instance"], lid(), "run"))
    await until_waiters(lock, 2)
    lock.release()
    assert (await tick)["stopped"] == 1
    err = await refused(lease)
    assert err.code == sc.ERR_NOT_RUNNING
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != a["instance"] and again["fresh"] is True
    assert again["token"] != a["token"] and again["tunnel_token"] != a["tunnel_token"]
    assert (await world.mgr.lease(ALICE, again["instance"], lid(), "run"))["state"] == "running"


async def test_ensure_marks_use_before_an_idle_tick_can_stop_it(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.clock.now += IDLE_S + 1
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    ensure = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await until_waiters(lock, 1)
    tick = asyncio.ensure_future(world.mgr.idle_tick())
    await until_waiters(lock, 2)
    lock.release()
    ans = await ensure
    assert (await tick)["stopped"] == 0
    assert ans["instance"] == a["instance"] and state_of(world, ALICE, a["instance"]) == "running"


async def test_status_reports_stop_at_and_warn(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    st = world.mgr.status(ALICE)["instances"][0]
    assert st["stop_at"] == t0 + IDLE_S and st["warn"] is False and st["stop_reason"] is None
    assert a["stop_at"] == t0 + IDLE_S and a["warn"] is False and a["stop_reason"] is None
    run = lid()
    await world.mgr.lease(ALICE, a["instance"], run, "run")
    assert world.mgr.status(ALICE)["instances"][0]["lease_kinds"] == ["run"]
    await world.mgr.release_lease(ALICE, run)
    hold = lid()
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    st = world.mgr.status(ALICE)["instances"][0]
    assert st["stop_at"] == t0 + sc.HOLD_MAX_NO_USE_S and st["lease_kinds"] == [HOLD]
    world.clock.now = t0 + sc.HOLD_MAX_NO_USE_S - sc.HOLD_WARN_BEFORE_S
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    st = world.mgr.status(ALICE)["instances"][0]
    assert st["warn"] is True and st["stop_reason"] is None
    # A draining instance says why it is on its way out.
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    old = next(i for i in world.mgr.status(ALICE)["instances"] if i["instance"] == a["instance"])
    assert old["state"] == "draining" and old["stop_reason"] == "replaced"
    assert a["token"] not in json.dumps(world.mgr.status(ALICE))


async def test_idle_tick_reattaches_missing_guests(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.agent.remove(force=True)
    new_agent = add_agent(world.d)
    world.clock.now += 1          # no ensure arrives: only the tick sees the new agent
    await world.mgr.idle_tick()
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    assert eps[new_agent.id] == {"Aliases": [sc.AGENT_ALIAS], "GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    assert state_of(world, ALICE, a["instance"]) == "running"


async def test_idle_tick_reattaches_a_guest_with_the_wrong_gateway_priority(world, caplog):
    await world.mgr.ensure(ALICE, ["projA"])
    name = sc.network_name(ALICE, "own")
    net = world.d.networks.get(name)
    # An endpoint attached by hand keeps priority 0: its default route may move here.
    net._detach(world.agent.id)
    net._attach(world.agent, {"Aliases": [sc.AGENT_ALIAS]})
    assert world.agent.attrs["NetworkSettings"]["Networks"][name]["GwPriority"] == 0
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    before = len(world.d.connects)
    await world.mgr.idle_tick()
    assert ("network.disconnect", name, world.agent.id, True) in world.d.calls
    assert net.endpoints[world.agent.id] == {"Aliases": [sc.AGENT_ALIAS], "GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    assert [body["Container"] for _, body in world.d.connects[before:]] == [world.agent.id]
    assert "gateway priority" in caplog.text
    # A guest already at -1000 is left alone.
    calls = len(world.d.calls)
    await world.mgr.idle_tick()
    assert not [c for c in world.d.calls[calls:] if c[0] in ("network.disconnect", "network.connect")]


async def test_idle_tick_retries_a_failed_network_removal(world):
    a = await world.mgr.ensure(ALICE, [])
    name = sc.network_name(ALICE, "own")
    world.d.fail_network_remove = True
    await world.mgr.stop(ALICE, a["instance"], "operator")
    assert name in world.mgr.networks_to_retry()
    await world.mgr.idle_tick()
    assert name in world.mgr.networks_to_retry()
    world.d.fail_network_remove = False
    summary = await world.mgr.idle_tick()
    assert summary["networks_removed"] == 1
    assert world.mgr.networks_to_retry() == set() and world.d.sandbox_networks() == []


async def test_network_retry_waits_for_the_allocation_lock(world):
    a = await world.mgr.ensure(ALICE, [])
    name = sc.network_name(ALICE, "own")
    world.d.fail_network_remove = True
    await world.mgr.stop(ALICE, a["instance"], "operator")
    world.d.fail_network_remove = False
    await world.mgr._alloc_lock.acquire()
    tick = asyncio.ensure_future(world.mgr.idle_tick())
    await until_waiters(world.mgr._alloc_lock, 1)
    assert name in world.mgr.networks_to_retry() and world.d.sandbox_networks()
    world.mgr._alloc_lock.release()
    assert (await tick)["networks_removed"] == 1
    assert world.d.sandbox_networks() == []


async def test_network_retry_leaves_a_network_a_new_instance_uses(world):
    a = await world.mgr.ensure(ALICE, [])
    name = sc.network_name(ALICE, "own")
    world.d.fail_network_remove = True
    await world.mgr.stop(ALICE, a["instance"], "operator")
    world.d.fail_network_remove = False
    b = await world.mgr.ensure(ALICE, [])
    await world.mgr.idle_tick()
    assert world.d.networks.get(name).attrs["Containers"]
    assert (await world.mgr.lease(ALICE, b["instance"], lid(), "run"))["state"] == "running"


async def test_idle_tick_retries_a_stuck_stop(world):
    first = await world.mgr.ensure(ALICE, ["projA", "projS"])
    world.d.fail_remove = True
    assert await world.mgr.reconcile(ALICE, ["projA"], []) == 0
    stuck = instance(world, ALICE, first["instance"])
    assert stuck.state == "stopping" and stuck.stop_reason == "access_lost"
    # Still failing: kept, still reserved.
    await world.mgr.idle_tick()
    assert instance(world, ALICE, first["instance"]) is stuck
    assert sc.reservation_key(ALICE, first["instance"]) in world.ledger.sandbox_keys()
    # A lease is refused while it is stopping.
    assert (await refused(world.mgr.lease(ALICE, first["instance"], lid(), "run"))).code == sc.ERR_NOT_RUNNING
    world.d.fail_remove = False
    assert (await world.mgr.idle_tick())["stopped"] == 1
    assert instance(world, ALICE, first["instance"]) is None
    assert world.ledger.sandbox_keys() == set() and world.d.sandbox_networks() == []


@pytest.mark.parametrize("change", ["image", "servers"])
async def test_new_image_or_server_code_drains_running_instances(world, change, caplog):
    a = await world.mgr.ensure(ALICE, ["projA"])
    b = await world.mgr.ensure(BOB, ["projB"])
    hold = lid()
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)     # live sessions
    if change == "image":
        world.d.images.add(FakeImage(OTHER_IMAGE_ID), tag=sc.IMAGE)
    else:
        with open(f"{world.local[sc.MOUNT_SERVERS]}/metasploit_server.py", "w") as f:
            f.write("y = 2\n")
    world.clock.now += 1
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    summary = await world.mgr.idle_tick()
    assert summary["drained"] == 2
    # Bob's held nothing: drained and stopped in the same tick; Alice's keeps its sessions.
    assert instance(world, BOB, b["instance"]) is None
    assert any("reason=replaced" in r.getMessage() and "stopped" in r.getMessage() for r in caplog.records)
    assert state_of(world, ALICE, a["instance"]) == "draining"
    # New work goes to a new instance on the new code.
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != a["instance"] and again["fresh"] is True
    if change == "image":
        assert world.created(ALICE)[-1].attrs["Image"] == OTHER_IMAGE_ID
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, again["instance"]) == "running"
    assert state_of(world, ALICE, a["instance"]) == "draining"
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    await world.mgr.release_lease(ALICE, hold)
    await world.mgr.idle_tick()
    assert instance(world, ALICE, a["instance"]) is None
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, again["instance"])}


async def test_a_missing_image_drains_nothing(world, caplog):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.d.images.by_name.clear()
    with open(f"{world.local[sc.MOUNT_SERVERS]}/metasploit_server.py", "w") as f:
        f.write("y = 2\n")
    world.clock.now += 1
    summary = await world.mgr.idle_tick()
    assert summary["drained"] == 0 and state_of(world, ALICE, a["instance"]) == "running"


async def test_a_missing_servers_folder_drains_nothing(world, tmp_path):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.mgr.local_bases[sc.MOUNT_SERVERS] = str(tmp_path / "gone")
    world.clock.now += sc.IDLE_CHECK_S
    assert (await world.mgr.idle_tick())["drained"] == 0
    assert state_of(world, ALICE, a["instance"]) == "running"


async def test_the_idle_loop_ignores_the_old_mode_switch(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.mp.setenv("KALI_SANDBOX_MODE", "shared")
    world.clock.now += IDLE_S - 1
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "running"
    world.clock.now += 1
    assert (await world.mgr.idle_tick())["stopped"] == 1
    assert world.created() == [] and world.ledger.sandbox_keys() == set()


async def test_one_failing_person_or_network_does_not_stop_the_tick(world, monkeypatch, caplog):
    a = await world.mgr.ensure(ALICE, ["projA"])
    b = await world.mgr.ensure(BOB, ["projB"])
    world.clock.now += IDLE_S
    original = world.mgr._stop_locked

    async def flaky(inst, reason):
        if inst.user_id == ALICE:
            raise RuntimeError(f"boom for {ALICE}")
        return await original(inst, reason)

    monkeypatch.setattr(world.mgr, "_stop_locked", flaky)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    summary = await world.mgr.idle_tick()
    assert summary["failed"] == 1 and summary["stopped"] == 1
    assert instance(world, BOB, b["instance"]) is None
    assert state_of(world, ALICE, a["instance"]) == "running"
    assert ALICE not in caplog.text and sc.sandbox_key(ALICE, "own") in caplog.text
    monkeypatch.setattr(world.mgr, "_stop_locked", original)

    # One network whose guest check fails: the others are still checked.
    world.clock.now = world.clock.now - IDLE_S
    c = await world.mgr.ensure(BOB, ["projB"])
    world.agent.remove(force=True)
    new_agent = add_agent(world.d)
    original_guests = world.mgr._guests_sync

    def guests(network, strict, force=False):
        if network == sc.network_name(ALICE, "own"):
            raise APIError("network inspect failed")
        return original_guests(network, strict, force)

    monkeypatch.setattr(world.mgr, "_guests_sync", guests)
    await world.mgr.idle_tick()
    assert new_agent.id in connects_to(world, sc.network_name(BOB, "own"))
    assert state_of(world, BOB, c["instance"]) == "running"


async def test_run_idle_loop_ticks_until_cancelled(world, monkeypatch):
    ticks, sleeps = [], []

    async def tick():
        ticks.append(1)
        if len(ticks) == 1:
            raise RuntimeError("the first tick fails")
        return {}

    async def sleep(seconds):
        sleeps.append(seconds)
        await asyncio.sleep(0)

    monkeypatch.setattr(world.mgr, "idle_tick", tick)
    task = asyncio.ensure_future(world.mgr.run_idle_loop(sleep=sleep))
    for _ in range(200):
        await asyncio.sleep(0)
        if len(ticks) >= 3:
            break
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(ticks) >= 3 and set(sleeps) == {sc.IDLE_CHECK_S}


# --- WI-S05-3 Rolling replacement and draining ------------------------------------

async def test_rolling_replacement_on_missing_project(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    old_lease = lid()
    await world.mgr.lease(ALICE, first["instance"], old_lease, "run")
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert second["instance"] != first["instance"] and second["fresh"] is True
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, first["instance"]),
                                           sc.reservation_key(ALICE, second["instance"])}
    # New work goes to the new instance, without and with the project.
    assert (await world.mgr.ensure(ALICE, ["projA", "projB"]))["instance"] == second["instance"]
    assert (await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projA"))["instance"] == second["instance"]
    # The old one keeps its renewing lease, then stops once it lapses.
    world.clock.now += 60
    assert (await world.mgr.lease(ALICE, first["instance"], old_lease, "run"))["state"] == "draining"
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, first["instance"]) == "draining"
    world.clock.now += sc.LEASE_TTL_S
    await world.mgr.idle_tick()
    assert instance(world, ALICE, first["instance"]) is None
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, second["instance"])}
    # The view's network stays: the new instance is on it.
    assert world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]


async def test_replacement_refused_keeps_old_running(world, occupant):
    first = await world.mgr.ensure(ALICE, ["projA"])
    world.host.mem = (16 * GB, int(1.5 * GB))
    err = await refused(world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB"))
    assert err.code == sc.ERR_RAM and err.status == 409
    assert [(i.instance, i.state) for i in world.mgr.instances(ALICE)] == [(first["instance"], "running")]
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, first["instance"])}
    assert len(world.created(ALICE)) == 1 and tunnel_execs(occupant) == []
    # Still the current one.
    assert (await world.mgr.ensure(ALICE, ["projA", "projB"]))["instance"] == first["instance"]
    assert (await world.mgr.lease(ALICE, first["instance"], lid(), "run"))["state"] == "running"


async def test_replacement_that_fails_to_start_keeps_old_running(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    world.d.fail_start = "driver failed programming external connectivity"
    err = await refused(world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB"))
    assert err.code == sc.ERR_START_FAILED
    assert [(i.instance, i.state) for i in world.mgr.instances(ALICE)] == [(first["instance"], "running")]
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, first["instance"])}
    assert world.d.networks.get(sc.network_name(ALICE, "own"))


async def test_draining_accepts_only_existing_lease_ids(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    known = lid()
    await world.mgr.lease(ALICE, first["instance"], known, "job")
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    err = await refused(world.mgr.lease(ALICE, first["instance"], lid(), "job"))
    assert err.code == sc.ERR_DRAINING and err.status == 409
    ans = await world.mgr.lease(ALICE, first["instance"], known, "job")
    assert ans["state"] == "draining"
    # Once the known lease has lapsed, the draining instance knows it no longer.
    world.clock.now += sc.LEASE_TTL_S
    err = await refused(world.mgr.lease(ALICE, first["instance"], known, "job"))
    assert err.code == sc.ERR_DRAINING


async def test_max_concurrent_counts_replacements(world):
    world.mp.setenv(sc.MAX_CONCURRENT_ENV, "1")
    first = await world.mgr.ensure(ALICE, ["projA"])
    err = await refused(world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB"))
    assert err.code == sc.ERR_HARD
    assert state_of(world, ALICE, first["instance"]) == "running"
    world.mp.setenv(sc.MAX_CONCURRENT_ENV, "2")
    await world.mgr.lease(ALICE, first["instance"], lid(), "run")
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    # The draining instance still counts: nobody else fits until it stops.
    assert (await refused(world.mgr.ensure(BOB, []))).code == sc.ERR_HARD
    world.clock.now += sc.LEASE_TTL_S
    await world.mgr.idle_tick()
    assert instance(world, ALICE, first["instance"]) is None
    assert (await world.mgr.ensure(BOB, []))["state"] == "running"
    assert state_of(world, ALICE, second["instance"]) == "running"


async def test_a_tick_leaves_a_replaced_start_that_is_not_ready(world):
    gate = lc.Gate()
    world.mgr = world.manager(sleep=gate.sleep)
    world.d.health_on_start = "starting"
    first = await world.mgr.ensure(ALICE, ["projA"], wait=False)
    waiter = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await settle()
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB", wait=False)
    assert state_of(world, ALICE, first["instance"]) == "draining"
    # Draining and leaseless, but its callers still wait for it: not stopped yet
    # (a start that never settles is the stuck-start rule's, after its timeout).
    world.clock.now += 1
    assert (await world.mgr.idle_tick())["stopped"] == 0
    for c in world.created(ALICE):
        c.attrs["State"]["Health"]["Status"] = "healthy"
    gate.open()
    assert (await asyncio.wait_for(waiter, 5))["instance"] == first["instance"]
    await world.mgr.join_background()


async def test_two_ensures_with_different_needed_projects_start_one_replacement(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    allowed = ["projA", "projB", "projC"]
    answers = await asyncio.gather(
        world.mgr.ensure(ALICE, allowed, need_project="projB"),
        world.mgr.ensure(ALICE, allowed, need_project="projC"))
    assert answers[0]["instance"] == answers[1]["instance"] != first["instance"]
    assert sum(a["fresh"] for a in answers) == 1
    states = sorted(i.state for i in world.mgr.instances(ALICE))
    assert states == ["draining", "running"] and len(world.ledger.sandbox_keys()) == 2


# --- Routed points: the draining hold cap, the tunnel of a replaced sandbox -------

async def test_draining_instance_hold_capped_at_8h(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    t0 = world.clock.now
    hold = lid()
    await world.mgr.lease(ALICE, first["instance"], hold, HOLD)
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert state_of(world, ALICE, first["instance"]) == "draining"
    warned = None
    while world.clock.now < t0 + sc.HOLD_MAX_NO_USE_S - 60:
        world.clock.now += 60
        ans = await world.mgr.lease(ALICE, first["instance"], hold, HOLD)
        if ans["warn"] and warned is None:
            warned = world.clock.now
        await world.mgr.idle_tick()
        assert state_of(world, ALICE, first["instance"]) == "draining"
    assert warned == t0 + sc.HOLD_MAX_NO_USE_S - sc.HOLD_WARN_BEFORE_S
    world.clock.now = t0 + sc.HOLD_MAX_NO_USE_S
    await world.mgr.lease(ALICE, first["instance"], hold, HOLD)
    assert (await world.mgr.idle_tick())["stopped"] == 1
    assert instance(world, ALICE, first["instance"]) is None


async def test_replaced_instance_has_its_tunnel_turned_off(world, occupant):
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), HOLD)
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    await settled(world)
    execs = tunnel_execs(occupant)
    assert [e["container"] for e in execs] == [first["host"]]
    cmd, environment = execs[0]["cmd"], execs[0]["environment"]
    script = cmd[2]
    assert f"127.0.0.1:{sc.PORTS['tunnel']}/tunnel/configure" in script and "b'{}'" in script
    # The token travels in the exec's environment, never on its command line.
    assert first["tunnel_token"] not in json.dumps(cmd)
    assert list(environment.values()) == [first["tunnel_token"]]
    assert second["tunnel_token"] not in json.dumps(execs)
    # The occupant decides what its exit code says, so an exit 0 proves little:
    # the empty config is sent again at every tick while it drains, one at a time.
    await world.mgr.idle_tick()
    await settled(world)
    assert len(tunnel_execs(occupant)) == 2
    occupant.running = True
    await world.mgr.idle_tick()
    await settled(world)
    assert len(tunnel_execs(occupant)) == 2


async def test_tunnel_switch_off_never_reads_the_occupants_output(world, occupant):
    """An occupant flooding or dripping output for ever (a python3 shim earlier on
    PATH) costs the orchestrator nothing: the exec is detached, never attached."""
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), HOLD)
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    await settled(world)
    await world.mgr.idle_tick()
    await settled(world)
    execs = tunnel_execs(occupant)
    assert execs and not occupant.output_read
    assert all(e["stdout"] is False and e["stderr"] is False and e["started"] for e in execs)
    # Its Docker calls run on their own small pool, never the shared default one.
    assert all(e["thread"].startswith(sm.TUNNEL_THREAD_PREFIX) for e in execs)
    assert sm.TUNNEL_WORKERS <= 2


async def test_a_wedged_tunnel_call_has_a_deadline_and_never_piles_up(world, occupant, monkeypatch, caplog):
    monkeypatch.setattr(sm, "TUNNEL_CALL_DEADLINE_S", 0.2)
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), HOLD)
    occupant.daemon_hangs = True
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    t0 = time.monotonic()
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    await settled(world, bound=3)
    for _ in range(5):
        await world.mgr.idle_tick()
        await settled(world, bound=3)
    assert time.monotonic() - t0 < 4
    assert "tunnel" in caplog.text and first["tunnel_token"] not in caplog.text
    # The one call stuck in the daemon is the only one: no new call is queued behind it.
    assert len(world.mgr._tunnel_pending) == 1
    # Leases and ensures never wait for it.
    assert (await world.mgr.lease(ALICE, second["instance"], lid(), "run"))["state"] == "running"
    occupant.daemon_hangs = False
    occupant.release.set()
    for _ in range(100):
        if not world.mgr._tunnel_pending:
            break
        await asyncio.sleep(0.02)
    await world.mgr.idle_tick()
    await settled(world)
    assert tunnel_execs(occupant)


async def test_drained_instance_keeps_its_tunnel_until_a_replacement_starts(world, occupant):
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), HOLD)
    world.d.images.add(FakeImage(OTHER_IMAGE_ID), tag=sc.IMAGE)
    world.clock.now += 1
    await world.mgr.idle_tick()
    await settled(world)
    assert state_of(world, ALICE, first["instance"]) == "draining" and tunnel_execs(occupant) == []
    await world.mgr.ensure(ALICE, ["projA"])
    await settled(world)
    assert [e["container"] for e in tunnel_execs(occupant)] == [first["host"]]


async def test_a_failed_tunnel_switch_off_is_logged_and_sent_again(world, occupant, caplog):
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), HOLD)
    occupant.exit_code = 1
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    await settled(world)
    assert len(tunnel_execs(occupant)) == 1
    # Its exit is read at the next tick, which sends it again.
    await world.mgr.idle_tick()
    await settled(world)
    assert len(tunnel_execs(occupant)) == 2
    assert "exited 1" in caplog.text and first["tunnel_token"] not in caplog.text
    occupant.exit_code = 0
    await world.mgr.idle_tick()
    await settled(world)
    assert "tunnel turned off" in caplog.text and len(tunnel_execs(occupant)) == 3


# --- Review fixes: one draining instance per view, stuck starts, adoption ties ----

async def test_at_most_one_draining_instance_per_person_and_view(world, caplog):
    """A new project per run, each run's terminal kept open and renewed: the person
    never holds more than the current instance and one draining one."""
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    allowed = ["p00"]
    cur = await world.mgr.ensure(ALICE, allowed)
    leases = {cur["instance"]: lid()}
    await world.mgr.lease(ALICE, cur["instance"], leases[cur["instance"]], "terminal")
    for n in range(1, 13):
        allowed = allowed + [f"p{n:02d}"]
        cur = await world.mgr.ensure(ALICE, allowed, need_project=allowed[-1])
        leases[cur["instance"]] = lid()
        for _ in range(2):          # two minutes of renewals and ticks between two runs
            world.clock.now += 60
            for inst_id, lease_id in leases.items():
                if instance(world, ALICE, inst_id) is not None:
                    await world.mgr.lease(ALICE, inst_id, lease_id, "terminal")
            await world.mgr.idle_tick()
        states = sorted(i.state for i in world.mgr.instances(ALICE))
        assert states == ["draining", "running"], (n, states)
        assert len(world.ledger.sandbox_keys()) == 2
    stopped = [r.getMessage() for r in caplog.records
               if "stopped" in r.getMessage() and "reason=replaced" in r.getMessage()]
    assert len(stopped) == 11
    # Others still fit.
    assert (await world.mgr.ensure(BOB, ["projB"]))["state"] == "running"


async def test_a_refused_replacement_stops_no_draining_instance(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), "terminal")
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    world.host.mem = (16 * GB, int(1.5 * GB))
    err = await refused(world.mgr.ensure(ALICE, ["projA", "projB", "projC"], need_project="projC"))
    assert err.code == sc.ERR_RAM
    assert {i.instance: i.state for i in world.mgr.instances(ALICE)} == {
        first["instance"]: "draining", second["instance"]: "running"}


async def test_a_start_whose_health_read_fails_is_stopped(world, monkeypatch):
    def broken(ref):
        raise APIError("read timed out")

    monkeypatch.setattr(world.mgr, "_health_sync", broken)
    with pytest.raises(sm.SandboxStartError) as e:
        await asyncio.wait_for(world.mgr.ensure(ALICE, ["projA"]), 5)
    assert e.value.code == sc.ERR_START_FAILED
    await settled(world)
    assert world.mgr.instances(ALICE) == [] and world.ledger.sandbox_keys() == set()
    assert world.created() == [] and world.d.sandbox_networks() == []


async def test_idle_tick_stops_a_start_that_never_finishes(world, monkeypatch):
    stuck = asyncio.Event()

    async def never(inst):
        await stuck.wait()

    monkeypatch.setattr(world.mgr, "_finish_start", never)
    first = await world.mgr.ensure(ALICE, ["projA"], wait=False)
    assert first["state"] == "starting"
    waiter = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await settle()
    limit = world.mgr._start_timeout_s + sm.START_STUCK_GRACE_S
    world.clock.now += limit - 1
    assert (await world.mgr.idle_tick())["stopped"] == 0
    assert state_of(world, ALICE, first["instance"]) == "starting"
    world.clock.now += 1
    assert (await world.mgr.idle_tick())["stopped"] == 1
    assert instance(world, ALICE, first["instance"]) is None and world.ledger.sandbox_keys() == set()
    with pytest.raises(sm.SandboxStartError):
        await asyncio.wait_for(waiter, 5)
    stuck.set()
    await settled(world)


@pytest.mark.parametrize("listed_first", ["older", "newer"])
async def test_adoption_breaks_a_created_tie_with_the_containers_creation_time(world, listed_first):
    older = await world.mgr.ensure(ALICE, ["projA"])
    newer = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    by_name = {c.name: c for c in world.created(ALICE)}
    # Same whole second in the created label; Docker's own times differ by 10 us,
    # written as the engine writes them (trailing zeros trimmed, so a plain string
    # comparison would put them the wrong way round).
    assert by_name[older["host"]].labels[sc.LABEL_CREATED] == by_name[newer["host"]].labels[sc.LABEL_CREATED]
    by_name[older["host"]].attrs["Created"] = "2026-11-21T20:10:11.1234Z"
    by_name[newer["host"]].attrs["Created"] = "2026-11-21T20:10:11.12341Z"
    if listed_first == "newer":
        items = world.d.containers.items
        world.d.containers.items = dict(sorted(items.items(), key=lambda kv: kv[1].name != newer["host"]))
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    await world.mgr.adopt()
    assert state_of(world, ALICE, newer["instance"]) == "running"
    assert state_of(world, ALICE, older["instance"]) == "draining"
    again = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert again["instance"] == newer["instance"] and again["fresh"] is False


def test_docker_created_times_order_by_value():
    t = sm._docker_created_ns
    assert t("2026-11-21T20:10:11.1234Z") < t("2026-11-21T20:10:11.12341Z") < t("2026-11-21T20:10:12Z")
    assert t("2026-11-21T20:10:11.5+00:00") == t("2026-11-21T20:10:11.500000000Z")
    assert t("") == 0 and t(None) == 0 and t("garbage") == 0


# --- Restarts and clocks ----------------------------------------------------------

async def test_adopted_draining_instance_waits_for_lease_renewals(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    b = await world.mgr.ensure(BOB, ["projB"])
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    world.d.images.add(FakeImage(OTHER_IMAGE_ID), tag=sc.IMAGE)
    await world.mgr.adopt()
    assert {i.state for i in world.mgr.instances()} == {"draining"}
    # The restart lost every lease: the first tick must not stop a sandbox whose
    # work is about to renew (a hold watcher renews once a minute).
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "draining"
    assert state_of(world, BOB, b["instance"]) == "draining"
    world.clock.now += 45
    hold = lid()
    assert (await world.mgr.lease(ALICE, a["instance"], hold, HOLD))["state"] == "draining"
    world.clock.now += 60          # past the grace, the renewal of a known id
    await world.mgr.lease(ALICE, a["instance"], hold, HOLD)
    await world.mgr.idle_tick()
    assert state_of(world, ALICE, a["instance"]) == "draining"
    assert instance(world, BOB, b["instance"]) is None
    # After the grace a draining instance takes no new lease id.
    assert (await refused(world.mgr.lease(ALICE, a["instance"], lid(), "run"))).code == sc.ERR_DRAINING


def test_default_clock_never_jumps_with_the_wall_clock(monkeypatch):
    wall, mono = [1_800_000_000.0], [5_000.0]
    monkeypatch.setattr(time, "time", lambda: wall[0])
    monkeypatch.setattr(time, "monotonic", lambda: mono[0])
    mgr = sm.SandboxManager(None, None, {}, "osv", "redamon")
    start = mgr.clock()
    assert start == wall[0]
    # An NTP step or an operator moving the host clock by 8 hours: no lease
    # expires, no idle or hold timer fires because of it.
    wall[0] += 8 * 3600
    assert mgr.clock() == start
    mono[0] += 60
    assert mgr.clock() == start + 60

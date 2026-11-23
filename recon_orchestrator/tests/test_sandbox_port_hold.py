"""
Per-user Kali sandboxes: the pool port hold and the reverse-port state (FU-1, FU-4, D-A, D-B).

A pool port is the one address a target's reverse shell reaches a person's sandbox at.
When an instance stops or is replaced, a callback can still be on its way (a phishing
payload, an implant, a handler left waiting at the 8-hour cap), so its port goes to
nobody else for KALI_SANDBOX_PORT_HOLD_HOURS (24 by default) and back to the same
person and view on their next start. The holds outlive an orchestrator restart. With
only held ports left a sandbox starts without one, and every answer says why
(`reverse_port_state`).

Driven like the lifecycle tests: the in-memory FakeDocker and the `world` fixture of
test_sandbox_manager_lifecycle.py, a real ReservationLedger, a fake clock.
"""
import asyncio
import json
import logging
import os
import threading
import uuid

import pytest

import sandbox_contract as sc
import sandbox_manager as sm
from tests.test_sandbox_manager_lifecycle import (  # noqa: F401 - env and world are fixtures
    ALICE, BOB, CAROL, env, world)

DAVE = "dave-user-0004"
HOUR = 3600


def lid() -> str:
    return str(uuid.uuid4())


def pool(world, spec="40000-40002"):
    world.mp.setenv(sc.PORT_POOL_ENV, spec)


def holds_file(world) -> str:
    return os.path.join(world.local[sc.MOUNT_OUTPUT], sm.PORT_HOLDS_FILE)


async def restart(world):
    """A new orchestrator process: an empty ledger, a new manager, adoption."""
    await world.mgr.join_background()
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    await world.mgr.adopt()


async def stop_by(world, how: str, ans: dict) -> None:
    """Stop Alice's own instance by one of the stop paths."""
    inst = ans["instance"]
    if how == "idle":
        world.clock.now += sc.IDLE_MINUTES_DEFAULT * 60
        assert (await world.mgr.idle_tick())["stopped"] == 1
    elif how == "hold_cap":
        hold = lid()
        await world.mgr.lease(ALICE, inst, hold, sc.HOLD_LEASE_KIND)
        world.clock.now += sc.HOLD_MAX_NO_USE_S
        await world.mgr.lease(ALICE, inst, hold, sc.HOLD_LEASE_KIND)
        assert (await world.mgr.idle_tick())["stopped"] == 1
    elif how == "operator":
        assert await world.mgr.stop(ALICE, inst, "operator") == 1
    elif how == "emergency":
        assert await world.mgr.stop_all("emergency") == 1
    elif how == "access_lost":
        assert await world.mgr.reconcile(ALICE, [], []) == 1
    elif how == "account_disabled":
        assert await world.mgr.stop_user(ALICE, "account_disabled") == 1
    else:
        raise AssertionError(how)
    assert world.mgr.instances(ALICE) == []


STOP_PATHS = ["idle", "hold_cap", "operator", "emergency", "access_lost", "account_disabled"]


# --- The hold on every stop path, and the sticky return -------------------------------

@pytest.mark.parametrize("how", STOP_PATHS)
async def test_every_stop_holds_the_port_for_its_person_and_gives_it_back(world, how):
    pool(world)
    alice = await world.mgr.ensure(ALICE, ["projA"])
    assert alice["reverse_port"] == 40000
    await stop_by(world, how, alice)
    # A late callback to 40000 must never reach the next person's sandbox.
    bob = await world.mgr.ensure(BOB, ["projB"])
    assert bob["reverse_port"] == 40001
    carol = await world.mgr.ensure(CAROL, [])
    assert carol["reverse_port"] == 40002
    # Alice's next start gets her port back.
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["reverse_port"] == 40000
    c = next(c for c in world.created(ALICE))
    assert c.labels[sc.LABEL_PORT] == "40000" and c.env()[sc.ENV_REVERSE_PORT] == "40000"
    assert alice["reverse_port_state"] == again["reverse_port_state"] == sc.REVERSE_PORT_ASSIGNED


async def test_a_drain_replacement_holds_the_old_port_and_the_last_one_comes_back(world):
    pool(world)
    first = await world.mgr.ensure(ALICE, ["projA"])
    assert first["reverse_port"] == 40000
    # The replacement starts while the old instance still publishes 40000.
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert second["reverse_port"] == 40001
    # The drained instance stops at the next tick: its port is held for Alice.
    await world.mgr.idle_tick()
    assert [i.instance for i in world.mgr.instances(ALICE)] == [second["instance"]]
    bob = await world.mgr.ensure(BOB, [])
    assert bob["reverse_port"] == 40002
    world.clock.now += 60
    await world.mgr.stop(BOB, bob["instance"], "operator")
    await world.mgr.stop(ALICE, second["instance"], "operator")
    # Every port is held now: Alice 40000 and 40001, Bob 40002.
    carol = await world.mgr.ensure(CAROL, [])
    assert carol["reverse_port"] == sc.DEFAULT_REVERSE_PORT
    # Alice gets the port she used last, the one her latest payloads name.
    again = await world.mgr.ensure(ALICE, ["projA", "projB"])
    assert again["reverse_port"] == 40001
    assert carol["reverse_port_state"] == sc.REVERSE_PORT_POOL_FULL


async def test_a_view_never_gets_the_port_held_for_the_other(world):
    pool(world, "40000-40001")
    own = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, own["instance"], "operator")
    act = await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS)
    assert act["reverse_port"] == 40001
    again = await world.mgr.ensure(ALICE, [])
    assert again["reverse_port"] == 40000


async def test_a_sandbox_removed_at_adoption_holds_its_port(world):
    # After a host restart every sandbox has exited (restart policy "no"): adoption
    # removes them, and each one's port is held as if it had been stopped here.
    pool(world, "40000-40001")
    alice = await world.mgr.ensure(ALICE, [])
    c = world.created(ALICE)[0]
    c.attrs["State"]["Status"] = "exited"
    await restart(world)
    assert c.removed and world.mgr.instances() == []
    bob = await world.mgr.ensure(BOB, [])
    assert bob["reverse_port"] == 40001
    assert (await world.mgr.ensure(ALICE, []))["reverse_port"] == alice["reverse_port"] == 40000


async def test_a_broker_made_lookalike_holds_nothing_at_adoption(world):
    pool(world, "40000-40001")
    await world.mgr.ensure(ALICE, [])
    labels = dict(world.created(ALICE)[0].labels)
    await world.mgr.stop_all("operator")
    await world.mgr.join_background()
    for path in (holds_file(world), holds_file(world) + ".prev"):
        if os.path.exists(path):
            os.remove(path)
    fake = world.d.containers.add("redamon-kali-fake", labels={
        **labels, sc.LABEL_PORT: "40001", "redamon.broker-owned": "1"})
    await restart(world)
    assert fake.removed
    # Neither the stopped instance's hold (the files are gone) nor the look-alike's.
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40000


# --- A held port is never given out; the pool full state (FU-4) -----------------------

async def test_only_held_ports_left_starts_without_a_port_and_says_pool_full(world, caplog):
    pool(world, "40000-40001")
    alice = await world.mgr.ensure(ALICE, [])
    bob = await world.mgr.ensure(BOB, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    carol = await world.mgr.ensure(CAROL, [])
    assert carol["reverse_port"] == sc.DEFAULT_REVERSE_PORT
    c = world.created(CAROL)[0]
    assert not c.created_kwargs.get("ports") and c.labels[sc.LABEL_PORT] == ""
    assert c.env()[sc.ENV_REVERSE_PORT] == str(sc.DEFAULT_REVERSE_PORT)
    assert carol["reverse_port_state"] == sc.REVERSE_PORT_POOL_FULL
    status = world.mgr.status(CAROL)["instances"][0]
    assert (status["reverse_port"], status["reverse_port_state"]) == (sc.DEFAULT_REVERSE_PORT,
                                                                      sc.REVERSE_PORT_POOL_FULL)
    listed = {e["instance"]: e for e in world.mgr.list_running()}
    assert listed[carol["instance"]]["reverse_port_state"] == sc.REVERSE_PORT_POOL_FULL
    assert (listed[bob["instance"]]["reverse_port"], listed[bob["instance"]]["reverse_port_state"]) == \
        (40001, sc.REVERSE_PORT_ASSIGNED)
    # One line for this occurrence, naming the person by key and why.
    full = [r.getMessage() for r in caplog.records if "port pool is full" in r.getMessage()]
    assert len(full) == 1
    assert sc.sandbox_key(CAROL, "own") in full[0] and "1 in use, 1 held" in full[0]
    assert CAROL not in caplog.text
    # The next occurrence is logged again (never only once per process).
    await world.mgr.ensure(DAVE, [])
    assert len([r for r in caplog.records if "port pool is full" in r.getMessage()]) == 2
    # Alice still gets hers.
    assert (await world.mgr.ensure(ALICE, []))["reverse_port"] == 40000


async def test_answers_without_a_pool_say_no_pool(world):
    ans = await world.mgr.ensure(ALICE, [])
    assert (ans["reverse_port"], ans["reverse_port_state"]) == (sc.DEFAULT_REVERSE_PORT, sc.REVERSE_PORT_NO_POOL)
    assert world.mgr.status(ALICE)["instances"][0]["reverse_port_state"] == sc.REVERSE_PORT_NO_POOL
    assert world.mgr.list_running()[0]["reverse_port_state"] == sc.REVERSE_PORT_NO_POOL
    assert not os.path.exists(holds_file(world))


async def test_adopted_instances_keep_their_state(world):
    pool(world, "40000-40000")
    await world.mgr.ensure(ALICE, [])
    await world.mgr.ensure(BOB, [])
    await restart(world)
    states = {i["user_id"]: (i["reverse_port"], i["reverse_port_state"], i["state"])
              for i in world.mgr.list_running()}
    # Alice holds the only port, so a new start would give Bob none either: he stays.
    assert states == {ALICE: (40000, sc.REVERSE_PORT_ASSIGNED, "running"),
                      BOB: (sc.DEFAULT_REVERSE_PORT, sc.REVERSE_PORT_POOL_FULL, "running")}


async def test_a_full_pool_drains_no_portless_sandbox_at_a_restart(world):
    # The only port is held for Bob: a replacement of Alice's would get no port, turn
    # her tunnel off and run a second instance while the first one drains.
    pool(world, "40000-40000")
    bob = await world.mgr.ensure(BOB, [])
    await world.mgr.stop(BOB, bob["instance"], "operator")
    alice = await world.mgr.ensure(ALICE, [])
    assert alice["reverse_port_state"] == sc.REVERSE_PORT_POOL_FULL
    for _ in range(2):
        await restart(world)
        (inst,) = world.mgr.instances(ALICE)
        assert (inst.instance, inst.state, inst.reverse_port_state) == \
            (alice["instance"], "running", sc.REVERSE_PORT_POOL_FULL)
    # Once Bob's hold ends a port is free for her: the next restart drains it.
    world.clock.now += sc.PORT_HOLD_HOURS_DEFAULT * HOUR
    await restart(world)
    assert [i.state for i in world.mgr.instances(ALICE)] == ["draining"]
    assert (await world.mgr.ensure(ALICE, []))["reverse_port"] == 40000


async def test_one_free_port_drains_one_portless_sandbox_only(world):
    pool(world, "40000-40001")
    held = await world.mgr.ensure(CAROL, [])
    await world.mgr.ensure(DAVE, [])
    await world.mgr.stop(CAROL, held["instance"], "operator")
    alice = await world.mgr.ensure(ALICE, [])
    bob = await world.mgr.ensure(BOB, [])
    assert alice["reverse_port_state"] == bob["reverse_port_state"] == sc.REVERSE_PORT_POOL_FULL
    # Carol's hold ends: one port, 40000, is free for either of them.
    world.clock.now += sc.PORT_HOLD_HOURS_DEFAULT * HOUR
    await restart(world)
    states = sorted(i.state for u in (ALICE, BOB) for i in world.mgr.instances(u))
    assert states == ["draining", "running"]


async def test_a_port_label_that_is_not_a_port_blocks_no_start(world):
    # A container a scan's broker made can carry any label: one that int() cannot read
    # must never fail the pool allocation every start makes.
    pool(world, "40000-40001")
    for raw in ("²", "٤٠٠٠٠", "4e4", "-1"):
        world.d.containers.add(f"redamon-kali-fake-{len(raw)}-{ord(raw[0])}", labels={
            sc.LABEL_SANDBOX: sc.LABEL_TRUE, sc.LABEL_PORT: raw, "redamon.broker-owned": "1"})
    ans = await world.mgr.ensure(ALICE, [])
    assert (ans["state"], ans["reverse_port"]) == ("running", 40000)


async def test_an_adopted_sandbox_without_a_port_drains_once_a_pool_is_configured(world):
    alice = await world.mgr.ensure(ALICE, [])
    assert alice["reverse_port_state"] == sc.REVERSE_PORT_NO_POOL
    pool(world, "40000-40001")
    await restart(world)
    assert [(i.instance, i.state, i.stop_reason) for i in world.mgr.instances(ALICE)] == \
        [(alice["instance"], "draining", "replaced")]
    again = await world.mgr.ensure(ALICE, [])
    assert again["fresh"] is True
    assert (again["reverse_port"], again["reverse_port_state"]) == (40000, sc.REVERSE_PORT_ASSIGNED)


async def test_a_starting_instance_reports_its_port_while_the_templates_wait(world, monkeypatch):
    # The templates volume can take minutes on a first start: the port is allocated before.
    pool(world)
    gate = threading.Event()
    ready = sm.sandbox_templates.ensure_templates_ready

    def slow(*a, **k):
        gate.wait(5)
        return ready(*a, **k)

    monkeypatch.setattr(sm.sandbox_templates, "ensure_templates_ready", slow)
    task = asyncio.ensure_future(world.mgr.ensure(ALICE, [], wait=False))
    for _ in range(100):
        await asyncio.sleep(0.01)
        seen = world.mgr.status(ALICE)["instances"]
        if seen and seen[0]["reverse_port_state"] is not None:
            break
    gate.set()
    await task
    assert seen[0]["state"] == "starting"
    assert (seen[0]["reverse_port"], seen[0]["reverse_port_state"]) == (40000, sc.REVERSE_PORT_ASSIGNED)


def test_a_new_instance_has_no_state_until_its_port_is_allocated():
    inst = sm.Instance(user_id=ALICE, view="own", instance="a1b2c3", state="starting", projects=(),
                       host="h", key=sc.sandbox_key(ALICE, "own"), network="n", created=0.0, last_used=0.0)
    assert inst.reverse_port_state is None


# --- The hold is spent only by a start that publishes the port --------------------------

def busy_on(world, port: str):
    def busy(container):
        world.d.fail_start = (f"Bind for 127.0.0.1:{port} failed: port is already allocated"
                              if container.labels[sc.LABEL_PORT] == port else None)
    world.d.on_start.append(busy)


async def test_a_busy_retry_keeps_the_persons_hold(world):
    pool(world, "40000-40002")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    # At her next start the host briefly holds 40000, so she gets 40001.
    busy_on(world, "40000")
    again = await world.mgr.ensure(ALICE, [])
    assert again["reverse_port"] == 40001
    world.d.on_start.clear()
    world.d.fail_start = None
    # Once the host lets 40000 go, still inside her hold, it is hers, never Bob's.
    world.clock.now += sm.BUSY_PORT_HOLD_S + 1
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40002
    await world.mgr.stop(ALICE, again["instance"], "operator")
    world.clock.now += 1
    assert (await world.mgr.ensure(CAROL, []))["reverse_port"] != 40000


async def test_the_hold_is_saved_until_the_container_publishes_the_port(world):
    # A crash between taking the port back and creating the container must not lose
    # the hold: the saved file still has it while the container is being created.
    pool(world, "40000-40001")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    await world.mgr.join_background()
    seen = []
    world.d.on_create.append(lambda c: seen.append(open(holds_file(world)).read()))
    await world.mgr.ensure(ALICE, [])
    assert json.loads(seen[0])["holds"][0]["port"] == 40000
    await world.mgr.join_background()
    assert json.loads(open(holds_file(world)).read()) == {"holds": []}


async def test_a_start_that_fails_keeps_the_hold(world):
    pool(world, "40000-40001")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    world.d.fail_create = "the daemon went away"
    with pytest.raises(sm.SandboxStartError):
        await world.mgr.ensure(ALICE, [])
    world.d.fail_create = None
    await world.mgr.join_background()
    assert [h["port"] for h in json.loads(open(holds_file(world)).read())["holds"]] == [40000]
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40001


# --- Persistence across a restart -------------------------------------------------------

async def test_holds_outlive_an_orchestrator_restart(world):
    pool(world)
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "idle")
    await world.mgr.join_background()
    saved = json.loads(open(holds_file(world)).read())
    assert saved == {"holds": [{"port": 40000, "key": sc.sandbox_key(ALICE, "own"), "since": world.clock.now}]}
    # The file names the person by key only, and only the orchestrator reads it.
    assert ALICE not in open(holds_file(world)).read()
    assert oct(os.stat(holds_file(world)).st_mode & 0o777) == "0o600"
    await restart(world)
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40001
    assert (await world.mgr.ensure(ALICE, []))["reverse_port"] == 40000
    # Given back, the hold is gone from the file as well.
    await world.mgr.join_background()
    assert json.loads(open(holds_file(world)).read()) == {"holds": []}


async def test_an_unreadable_holds_file_never_blocks_a_start(world, caplog):
    pool(world, "40000-40001")
    with open(holds_file(world), "w") as f:
        f.write("{not json")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    world.mgr = world.manager()
    assert (await world.mgr.ensure(ALICE, []))["reverse_port"] == 40000
    # Nothing to fall back on: said loudly, with the risk.
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "unreadable" in errors[0] and "can go to another person" in errors[0]


def copy_file(world) -> str:
    return os.path.join(world.local[sc.MOUNT_OUTPUT], sm.PORT_HOLDS_COPY)


async def test_a_damaged_holds_file_falls_back_to_its_copy(world, caplog):
    pool(world, "40000-40001")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    await world.mgr.join_background()
    body = open(holds_file(world)).read()
    assert open(copy_file(world)).read() == body
    assert oct(os.stat(copy_file(world)).st_mode & 0o777) == "0o600"
    with open(holds_file(world), "w") as f:
        f.write(body[: len(body) // 2])
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    await restart(world)
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40001
    assert "last good copy is used" in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_both_copies_damaged_hold_nothing_and_say_so(world, caplog):
    pool(world, "40000-40001")
    for path in (holds_file(world), copy_file(world)):
        with open(path, "w") as f:
            f.write('{"holds": ')
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    world.mgr = world.manager()
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and sm.PORT_HOLDS_FILE in errors[0] and sm.PORT_HOLDS_COPY in errors[0]
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40000


async def test_every_save_is_synced(world, monkeypatch):
    pool(world, "40000-40001")
    synced = []
    real = os.fsync
    monkeypatch.setattr(sm.os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    await world.mgr.join_background()
    # The file, its copy, then the folder that renames them.
    assert len(synced) == 3


async def test_a_fifo_at_the_temporary_name_never_blocks_a_save(world):
    pool(world, "40000-40001")
    tmp = holds_file(world) + ".tmp"
    os.mkfifo(tmp)
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    try:
        await asyncio.wait_for(world.mgr.join_background(), 5)
    finally:
        if os.path.exists(tmp) and not os.path.isfile(tmp):
            # Release a writer left blocked on the FIFO, so the test process can end.
            os.close(os.open(tmp, os.O_RDONLY | os.O_NONBLOCK))
            await world.mgr.join_background()
    assert json.loads(open(holds_file(world)).read())["holds"][0]["port"] == 40000


async def test_without_the_output_mount_the_holds_stay_in_memory(world, caplog):
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    hosts = {k: v for k, v in world.mgr.host_bases.items() if k != sc.MOUNT_OUTPUT}
    mgr = sm.SandboxManager(world.d, world.ledger, hosts, "redamon-osv-db", "redamon", clock=world.clock,
                            local_bases=world.local)
    inst = sm.Instance(user_id=ALICE, view="own", instance="a1b2c3", state="running", projects=(), host="h",
                       key=sc.sandbox_key(ALICE, "own"), network="n", created=0.0, last_used=0.0,
                       pool_port=40000)
    mgr._hold_port(inst)
    await mgr.join_background()
    assert mgr._live_holds(world.clock.now) == {40000: inst.key}
    assert not os.path.exists(holds_file(world))
    assert "not mounted" in caplog.text


async def test_holds_file_entries_are_checked(world):
    pool(world, "40000-40003")
    key = sc.sandbox_key(BOB, "own")
    entries = [{"port": 40000, "key": key, "since": world.clock.now},
               {"port": "40001", "key": key, "since": world.clock.now},
               {"port": 40002, "key": "../../etc", "since": world.clock.now},
               {"port": 40003, "key": key, "since": True}, "junk"]
    with open(holds_file(world), "w") as f:
        json.dump({"holds": entries}, f)
    world.mgr = world.manager()
    ports = [(await world.mgr.ensure(u, []))["reverse_port"] for u in (ALICE, CAROL, DAVE)]
    assert ports == [40001, 40002, 40003]


async def test_a_hold_dated_in_the_future_counts_from_now(world):
    pool(world, "40000-40001")
    with open(holds_file(world), "w") as f:
        json.dump({"holds": [{"port": 40000, "key": sc.sandbox_key(BOB, "own"),
                              "since": world.clock.now + 10 * 365 * 24 * HOUR}]}, f)
    world.mgr = world.manager()
    assert (await world.mgr.ensure(ALICE, []))["reverse_port"] == 40001
    world.clock.now += 24 * HOUR
    assert (await world.mgr.ensure(CAROL, []))["reverse_port"] == 40000


async def test_a_link_planted_at_the_holds_file_is_never_followed(world, tmp_path):
    pool(world, "40000-40001")
    target = tmp_path / "elsewhere.json"
    target.write_text("untouched")
    os.symlink(str(target), holds_file(world))
    world.mgr = world.manager()
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    await world.mgr.join_background()
    assert target.read_text() == "untouched"
    assert not os.path.islink(holds_file(world))
    assert json.loads(open(holds_file(world)).read())["holds"][0]["port"] == 40000


# --- The hold time (KALI_SANDBOX_PORT_HOLD_HOURS) ----------------------------------------

async def test_a_hold_ends_after_the_hold_time(world):
    pool(world, "40000-40001")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    world.clock.now += sc.PORT_HOLD_HOURS_DEFAULT * HOUR - 1
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40001
    world.clock.now += 1
    assert (await world.mgr.ensure(CAROL, []))["reverse_port"] == 40000


async def test_the_hold_time_is_read_at_each_use(world):
    pool(world, "40000-40001")
    world.mp.setenv(sc.PORT_HOLD_HOURS_ENV, "2")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    world.clock.now += HOUR
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40001
    world.mp.setenv(sc.PORT_HOLD_HOURS_ENV, "1")
    assert (await world.mgr.ensure(CAROL, []))["reverse_port"] == 40000


async def test_a_hold_time_of_zero_holds_nothing(world):
    pool(world, "40000-40001")
    world.mp.setenv(sc.PORT_HOLD_HOURS_ENV, "0")
    alice = await world.mgr.ensure(ALICE, [])
    await world.mgr.stop(ALICE, alice["instance"], "operator")
    assert (await world.mgr.ensure(BOB, []))["reverse_port"] == 40000
    await world.mgr.join_background()
    assert not os.path.exists(holds_file(world))


async def test_the_busy_port_hold_is_unchanged(world):
    # A pool port the host already uses is skipped for BUSY_PORT_HOLD_S by everyone.
    pool(world, "40000-40001")
    tries = []

    def busy(container):
        tries.append(container.labels[sc.LABEL_PORT])
        world.d.fail_start = ("Bind for 127.0.0.1:40000 failed: port is already allocated"
                              if container.labels[sc.LABEL_PORT] == "40000" else None)

    world.d.on_start.append(busy)
    ans = await world.mgr.ensure(ALICE, [])
    assert tries == ["40000", "40001"] and ans["reverse_port"] == 40001
    assert world.mgr._busy_ports == {40000: world.clock.now + sm.BUSY_PORT_HOLD_S}

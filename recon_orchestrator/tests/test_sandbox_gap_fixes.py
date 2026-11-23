"""
Per-user Kali sandboxes: what the gap audit of 2026-11-23 found the manager never
handled.

- G-13: a running instance whose container died (exited, dead, removed behind the
  manager's back), or turned unhealthy with nobody holding it, was handed out by
  every ensure and kept its reservation until the idle stop.
- G-16: after an update drained a person's instance onto new code while sessions
  held it, a replacement refused for memory or the count left them with no sandbox
  at all, although theirs was alive.
- G-22: adoption removed an instance whose environment lacked a fixed variable a
  newer release added (a new server port), cutting its live sessions at the update.

Driven like the lifecycle tests: the in-memory FakeDocker and the `world` fixture of
test_sandbox_manager_lifecycle.py, a real ReservationLedger, a fake clock.
"""
import logging
import uuid

import pytest
from docker.errors import APIError

import sandbox_contract as sc
import sandbox_manager as sm
from tests.test_sandbox_manager_lifecycle import (  # noqa: F401 - env and world are fixtures
    ALICE, BOB, GB, IMAGE_ENV, OTHER_IMAGE_ID, FakeImage, adopt_world, env, world)
from tests.test_sandbox_port_hold import pool

ROOMY = (16 * GB, 15 * GB)
TIGHT = (16 * GB, int(1.5 * GB))     # room for no second envelope


def lid() -> str:
    return str(uuid.uuid4())


async def refused(coro):
    with pytest.raises(sm.SandboxError) as e:
        await coro
    return e.value


def container_of(world, answer):
    return next(c for c in world.created() if c.name == answer["host"])


def kill(world, answer, how):
    c = container_of(world, answer)
    if how == "gone":
        c.removed = True
    else:
        c.attrs["State"]["Status"] = how


# --- G-13 a dead instance is never handed out again -------------------------------

@pytest.mark.parametrize("how", ["exited", "dead", "gone"])
async def test_ensure_replaces_an_instance_whose_container_died(world, how, caplog):
    first = await world.mgr.ensure(ALICE, ["projA"])
    kill(world, first, how)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != first["instance"] and again["fresh"] is True
    assert world.mgr.get_instance(ALICE, first["instance"]) is None
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, again["instance"])}
    assert any("stopped" in r.getMessage() and f"reason={sm.CRASH_REASON}" in r.getMessage()
               for r in caplog.records)


async def test_a_crashed_instance_keeps_its_pool_port_for_its_person(world):
    pool(world)
    first = await world.mgr.ensure(ALICE, ["projA"])
    kill(world, first, "exited")
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["reverse_port"] == first["reverse_port"]
    bob = await world.mgr.ensure(BOB, ["projB"])
    assert bob["reverse_port"] != first["reverse_port"]


async def test_the_idle_tick_stops_a_crashed_instance_and_frees_its_memory(world, caplog):
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), "job")
    kill(world, first, "exited")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    summary = await world.mgr.idle_tick()
    assert summary["stopped"] == 1
    assert world.mgr.instances(ALICE) == [] and world.ledger.sandbox_keys() == set()
    assert f"reason={sm.CRASH_REASON}" in caplog.text


async def test_a_draining_instance_that_died_is_stopped_by_the_tick(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), sc.HOLD_LEASE_KIND)
    await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert world.mgr.get_instance(ALICE, first["instance"]).state == "draining"
    kill(world, first, "gone")
    await world.mgr.idle_tick()
    assert world.mgr.get_instance(ALICE, first["instance"]) is None


async def test_an_unhealthy_instance_someone_holds_is_kept(world):
    """A probe that times out under the person's own load is no crash: their
    sessions and jobs stay."""
    first = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.lease(ALICE, first["instance"], lid(), "job")
    container_of(world, first).attrs["State"]["Health"] = {"Status": "unhealthy"}
    assert (await world.mgr.idle_tick())["stopped"] == 0
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] == first["instance"]


async def test_an_unhealthy_instance_nobody_holds_is_replaced(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    container_of(world, first).attrs["State"]["Health"] = {"Status": "unhealthy"}
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != first["instance"] and again["fresh"] is True


async def test_a_health_that_cannot_be_read_is_no_crash(world, monkeypatch, caplog):
    first = await world.mgr.ensure(ALICE, ["projA"])

    def broken(ref):
        raise APIError("read timed out")

    monkeypatch.setattr(world.mgr, "_health_sync", broken)
    caplog.set_level(logging.WARNING, logger="sandbox_manager")
    assert (await world.mgr.ensure(ALICE, ["projA"]))["instance"] == first["instance"]
    assert (await world.mgr.idle_tick())["stopped"] == 0
    assert world.mgr.get_instance(ALICE, first["instance"]).state == "running"
    assert first["token"] not in caplog.text


def test_crashed_is_a_contract_stop_reason():
    assert sm.CRASH_REASON in sc.STOP_REASONS


# --- G-16 a refused replacement serves the person's own draining instance ----------

async def drained(world, user_id=ALICE, projects=("projA",)):
    """The person's instance drained onto new code (an update) while sessions hold it."""
    first = await world.mgr.ensure(user_id, list(projects))
    await world.mgr.lease(user_id, first["instance"], lid(), sc.HOLD_LEASE_KIND)
    world.d.images.add(FakeImage(OTHER_IMAGE_ID), tag=sc.IMAGE)
    world.clock.now += 1
    await world.mgr.idle_tick()
    assert world.mgr.get_instance(user_id, first["instance"]).state == "draining"
    return first


async def test_a_replacement_refused_for_memory_serves_the_draining_instance(world):
    first = await drained(world)
    world.host.mem = TIGHT
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["instance"] == first["instance"] and ans["fresh"] is False
    assert ans["state"] == "running" and ans["token"] == first["token"]
    assert ans["stop_reason"] == sm.DRAIN_REASON
    # The caller's new lease is taken, and the instance stays draining, never current.
    assert (await world.mgr.lease(ALICE, first["instance"], lid(), "run"))["state"] == "draining"
    assert world.mgr.get_instance(ALICE, first["instance"]).state == "draining"
    assert len(world.created(ALICE)) == 1
    # Room again: the next ensure starts the replacement on the new image.
    world.host.mem = ROOMY
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != first["instance"] and again["fresh"] is True
    assert world.created(ALICE)[-1].attrs["Image"] == OTHER_IMAGE_ID


async def test_a_replacement_refused_by_the_count_serves_the_draining_instance(world):
    first = await drained(world)
    world.mp.setenv(sc.MAX_CONCURRENT_ENV, "1")
    assert (await world.mgr.ensure(ALICE, ["projA"]))["instance"] == first["instance"]


async def test_a_draining_instance_without_the_needed_project_is_never_served(world):
    await drained(world)
    world.host.mem = TIGHT
    err = await refused(world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB"))
    assert err.code == sc.ERR_RAM and err.status == 409


async def test_another_persons_or_views_draining_instance_is_never_served(world):
    await drained(world, user_id=BOB, projects=("projB",))
    world.host.mem = TIGHT
    # Alice has nothing of her own: she is refused, never handed Bob's.
    assert (await refused(world.mgr.ensure(ALICE, ["projB"]))).code == sc.ERR_RAM
    assert (await refused(world.mgr.ensure(BOB, ["projB"], view=sc.VIEW_ACT_AS))).code == sc.ERR_RAM


async def test_a_start_failure_other_than_a_refusal_is_still_reported(world):
    await drained(world)
    world.d.fail_start = "driver failed programming external connectivity"
    assert (await refused(world.mgr.ensure(ALICE, ["projA"]))).code == sc.ERR_START_FAILED


# --- G-22 an older release's environment drains -----------------------------------

def _fixed_key_not_in_image():
    image_keys = {e.partition("=")[0] for e in IMAGE_ENV}
    return next(k for k in sc.CONTAINER_ENV_FIXED if k not in image_keys)


async def test_adoption_drains_a_sandbox_without_a_fixed_variable_of_this_release(world):
    """A release that adds a server port adds a fixed variable: a sandbox started
    before it lacks it, and keeps its sessions until unused instead of being removed."""
    a, _ = await adopt_world(world)
    key = _fixed_key_not_in_image()
    for c in world.created():
        c.attrs["Config"]["Env"] = [e for e in c.attrs["Config"]["Env"] if not e.startswith(key + "=")]
    result = await world.mgr.adopt()
    assert result == {"adopted": 2, "removed": 0, "networks_removed": 0}
    assert {i.state for i in world.mgr.instances()} == {"draining"}
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != a["instance"]
    assert world.created(ALICE)[-1].env()[key] == sc.CONTAINER_ENV_FIXED[key]


async def test_adoption_still_removes_a_sandbox_whose_fixed_value_changed(world):
    await adopt_world(world)
    key = _fixed_key_not_in_image()
    for c in world.created():
        c.attrs["Config"]["Env"] = [f"{key}=elsewhere" if e.startswith(key + "=") else e
                                    for e in c.attrs["Config"]["Env"]]
    result = await world.mgr.adopt()
    assert result["adopted"] == 0 and result["removed"] == 2


async def test_a_missing_fixed_variable_never_excuses_a_bad_token(world):
    await adopt_world(world)
    key = _fixed_key_not_in_image()
    for c in world.created():
        c.attrs["Config"]["Env"] = [e for e in c.attrs["Config"]["Env"]
                                    if not e.startswith(key + "=") and not e.startswith(sc.ENV_MCP_AUTH_TOKEN + "=")]
    result = await world.mgr.adopt()
    assert result["adopted"] == 0 and result["removed"] == 2

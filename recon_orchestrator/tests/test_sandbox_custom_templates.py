"""
Per-user Kali sandboxes: each view gets only its person's custom nuclei templates (FU-6).

Custom templates sit in one shared folder (the webapp's uploads, plus the instance's own
files added on the host), and only the webapp knows each file's owner (the NucleiTemplate
table). The webapp's ensure names the files the person may use, theirs and the
instance's; the orchestrator copies exactly those into the view's own folder under the
output base and mounts that copy read-only. The shared folder itself is never mounted,
so no sandbox sees another member's template. A webapp that sends no list gets none.

Driven like the lifecycle tests: the in-memory FakeDocker and the `world` fixture of
test_sandbox_manager_lifecycle.py.
"""
import logging
import os
import stat

import sandbox_contract as sc
import sandbox_manager as sm
from tests.test_sandbox_manager_lifecycle import (  # noqa: F401 - env and world are fixtures
    ALICE, BOB, HOST_BASES, env, world)


def shared(world, rel, text="id: t\n"):
    path = os.path.join(world.local[sc.MOUNT_CUSTOM_TEMPLATES], rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def copy_dir(world, user=ALICE, view=sc.VIEW_OWN):
    return os.path.join(world.local[sc.MOUNT_OUTPUT], sc.custom_templates_rel(user, view))


def copied(world, user=ALICE, view=sc.VIEW_OWN):
    root = copy_dir(world, user, view)
    out = set()
    for folder, _, files in os.walk(root):
        out |= {os.path.relpath(os.path.join(folder, f), root) for f in files}
    return out


def templates_mount(world, user=ALICE):
    mounts = world.created(user)[0].created_kwargs["mounts"]
    return [m for m in mounts if m["Target"] == sc.CUSTOM_TEMPLATES_TARGET]


async def test_a_sandbox_sees_only_its_persons_templates_and_the_instances(world):
    shared(world, "alice-own.yaml", "id: alice\n")
    shared(world, "bob-own.yaml", "id: bob\n")
    shared(world, "springboot/instance.yaml", "id: inst\n")
    await world.mgr.ensure(ALICE, [], custom_templates=["alice-own.yaml", "springboot/instance.yaml",
                                                         "custom.yaml"])
    await world.mgr.ensure(BOB, [], custom_templates=["bob-own.yaml", "springboot/instance.yaml",
                                                       "custom.yaml"])
    assert copied(world, ALICE) == {"alice-own.yaml", "springboot/instance.yaml", "custom.yaml"}
    assert copied(world, BOB) == {"bob-own.yaml", "springboot/instance.yaml", "custom.yaml"}
    with open(os.path.join(copy_dir(world, ALICE), "alice-own.yaml")) as f:
        assert f.read() == "id: alice\n"
    for user in (ALICE, BOB):
        (m,) = templates_mount(world, user)
        key = sc.sandbox_key(user, sc.VIEW_OWN)
        assert (m["Source"], m["ReadOnly"]) == (f"{HOST_BASES['output']}/templates/{key}", True)
        sources = {x["Source"] for x in world.created(user)[0].created_kwargs["mounts"]}
        assert HOST_BASES["custom_templates"] not in sources
    # The orchestrator alone writes the copy; the sandbox mounts it read-only.
    assert stat.S_IMODE(os.stat(copy_dir(world, ALICE)).st_mode) == 0o755


async def test_a_webapp_that_sends_no_list_mounts_no_template(world, caplog):
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, [])
    assert ans["state"] == "running"
    assert templates_mount(world) == [] and copied(world) == set()
    assert "named no custom nuclei templates" in caplog.text


async def test_a_new_start_copies_the_current_list_only(world):
    shared(world, "old.yaml")
    shared(world, "new.yaml")
    a = await world.mgr.ensure(ALICE, [], custom_templates=["old.yaml"])
    await world.mgr.stop(ALICE, a["instance"], "operator")
    await world.mgr.ensure(ALICE, [], custom_templates=["new.yaml"])
    assert copied(world) == {"new.yaml"}
    b = world.mgr.instances(ALICE)[0]
    await world.mgr.stop(ALICE, b.instance, "operator")
    await world.mgr.ensure(ALICE, [], custom_templates=[])
    assert copied(world) == set() and templates_mount(world) == []


async def test_links_and_odd_files_in_the_shared_folder_are_never_copied(world, tmp_path):
    secret = tmp_path / "orchestrator-secret.txt"
    secret.write_text("ORCHESTRATOR_API_KEY=x\n")
    base = world.local[sc.MOUNT_CUSTOM_TEMPLATES]
    os.symlink(str(secret), os.path.join(base, "link.yaml"))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "t.yaml").write_text("id: outside\n")
    os.symlink(str(outside), os.path.join(base, "linked-dir"))
    os.mkfifo(os.path.join(base, "fifo.yaml"))
    shared(world, "huge.yaml", "x" * (sm.CUSTOM_TEMPLATE_MAX_BYTES + 1))
    shared(world, "ok.yaml")
    await world.mgr.ensure(ALICE, [], custom_templates=[
        "link.yaml", "linked-dir/t.yaml", "fifo.yaml", "huge.yaml", "ok.yaml", "../escape.yaml",
        "missing.yaml"])
    assert copied(world) == {"ok.yaml"}


async def test_account_deletion_removes_the_copy(world):
    await world.mgr.ensure(ALICE, [], custom_templates=["custom.yaml"])
    await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS, custom_templates=["custom.yaml"])
    assert copied(world, ALICE, sc.VIEW_ACT_AS) == {"custom.yaml"}
    await world.mgr.stop_user(ALICE, sc.STOP_REASON_DELETES_OUTPUT)
    for view in sc.VIEWS:
        assert not os.path.exists(copy_dir(world, ALICE, view))


async def test_a_sandbox_that_mounts_the_shared_folder_drains_after_a_restart(world):
    # An older release mounted every member's templates in every sandbox: such a
    # sandbox is kept until unused, never current, and its next start gets the copy.
    await world.mgr.ensure(ALICE, [])
    c = world.created(ALICE)[0]
    c.attrs["HostConfig"]["Mounts"].append({
        "Type": "bind", "Source": HOST_BASES["custom_templates"],
        "Target": sc.CUSTOM_TEMPLATES_TARGET, "ReadOnly": True})
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    result = await world.mgr.adopt()
    assert result["adopted"] == 1 and result["removed"] == 0
    assert [i.state for i in world.mgr.instances()] == ["draining"]
    fresh = await world.mgr.ensure(ALICE, [], custom_templates=["custom.yaml"])
    assert fresh["fresh"] is True and copied(world) == {"custom.yaml"}


async def test_a_link_at_the_templates_folder_starts_without_templates(world, tmp_path, caplog):
    # Something planted in the output folder must not refuse every sandbox.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(str(elsewhere), os.path.join(world.local[sc.MOUNT_OUTPUT], sc.CUSTOM_TEMPLATES_COPY_DIR))
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, [], custom_templates=["custom.yaml"])
    assert ans["state"] == "running" and templates_mount(world) == []
    assert list(elsewhere.iterdir()) == []
    assert "starts without custom templates" in caplog.text

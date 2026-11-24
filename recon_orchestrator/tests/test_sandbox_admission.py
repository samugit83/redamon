"""
The Kali sandbox class in the admission ledger (group 1; D22, TD-2).

Per-user Kali sandboxes and scans draw from ONE memory pool through the same
try_admit, but the scan-only rules stay scan-only: RECON_MAX_CONCURRENT_GLOBAL and the
per-user scan count ignore sandbox keys, the "never refuse the sole scan on budget
grounds" exemption counts scans only (a parallel one protects the first sandbox), and
active_scans stays scans only. With no sandbox committed, scan admission and the scan
queue dispatcher's budget decide exactly as before.

A key's class is its prefix ("kali_sandbox:" is a sandbox, anything else a scan).
Memory is injected through the ledger's mem_reader and pressure_fn; no Docker.
"""
import asyncio
import logging
import types
from unittest.mock import MagicMock, patch

import pytest

import admission_ledger as al
import container_manager as cm
import job_dispatcher as jd
import resource_governor as rg
from admission_ledger import ReservationLedger

GB = 1024 ** 3


def sbx(inst, user="u1"):
    """A sandbox reservation key: kali_sandbox:<user_id>:<instance>."""
    return f"kali_sandbox:{user}:{inst}"


class _Host:
    """Injected host memory. 16 GiB total, 1 GiB OS headroom, 1 GiB service baseline:
    a 14 GiB pool. `mem = None` means /proc/meminfo is unreadable."""

    def __init__(self):
        self.mem = (16 * GB, 15 * GB)
        self.pressure = "none"


@pytest.fixture
def host():
    return _Host()


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in ("RECON_MAX_CONCURRENT_GLOBAL", "RECON_MAX_CONCURRENT_PER_USER",
                 "KALI_SANDBOX_MAX_CONCURRENT", "RECON_JOB_ENVELOPE_MEM",
                 "RESOURCE_PROFILE_DEFAULT_PATH", "JOB_QUEUE_MAX_CONCURRENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REDAMON_MEM_GOVERNOR", "true")
    monkeypatch.setenv("OS_HEADROOM_MEM", "1g")
    monkeypatch.setenv("SERVICE_BASELINE_MEM", "1g")
    # No host-measured profile: the shipped default and the built-in fallback only.
    monkeypatch.setenv("RESOURCE_PROFILE_PATH", str(tmp_path / "no-host-profile.json"))
    rg.reset_profile_cache()
    yield monkeypatch
    rg.reset_profile_cache()


def ledger(host):
    return ReservationLedger(mem_reader=lambda: host.mem, pressure_fn=lambda: host.pressure)


def admit(led, key, envelope, **kw):
    return asyncio.run(led.try_admit(key, envelope, **kw))


def admit_sandbox(led, inst, envelope=GB, **kw):
    return admit(led, sbx(inst), envelope, resource="kali_sandbox", **kw)


OK_SCAN = {"admitted": True, "limitType": None, "resource": "scan", "current": 0,
           "ceiling": 0, "settingName": None, "detail": ""}
OK_SANDBOX = {**OK_SCAN, "resource": "kali_sandbox"}


def refused(limit, current, ceiling, detail, setting=None, resource="scan"):
    return {"admitted": False, "limitType": limit, "resource": resource, "current": current,
            "ceiling": ceiling, "settingName": setting, "detail": detail}


# ---------------------------------------------------------------------------
# One pool, two classes
# ---------------------------------------------------------------------------

def test_prefix_is_the_contracts_reservation_prefix():
    # The sandbox manager (S04) asserts this equals sandbox_contract.RESERVATION_PREFIX.
    assert al._SANDBOX_PREFIX == "kali_sandbox:"


def test_sandbox_and_scan_share_one_pool(env, host):
    led = ledger(host)
    assert admit(led, "gvm:p1", 6 * GB).admitted
    # A sandbox is admitted on top of the scan, its bytes against the same pool.
    assert admit_sandbox(led, "a", 4 * GB).payload() == OK_SANDBOX
    assert admit_sandbox(led, "b", 4 * GB).admitted                    # 14 of 14 GiB
    assert led.committed_bytes() == 14 * GB == led.scan_pool()
    # The pool is full for both classes: scan bytes hold back sandboxes ...
    assert admit_sandbox(led, "c", 1 * GB).payload() == refused(
        "ram", 14 * GB, 14 * GB, "not enough reserved memory budget for another Kali sandbox",
        resource="kali_sandbox")
    # ... and sandbox bytes hold back scans.
    assert admit(led, "github_hunt:p2", 1 * GB).payload() == refused(
        "ram", 14 * GB, 14 * GB, "not enough reserved memory budget for another scan")
    # A stopped sandbox gives its bytes back to the next scan.
    asyncio.run(led.release(sbx("a")))
    assert admit(led, "github_hunt:p2", 1 * GB).admitted
    assert led.committed_bytes() == 11 * GB


def test_sandbox_refusal_payload(env, host):
    led = ledger(host)
    assert admit_sandbox(led, "a", 10 * GB).admitted
    budget = admit_sandbox(led, "b", 5 * GB)
    assert budget.payload() == refused(
        "ram", 10 * GB, 14 * GB, "not enough reserved memory budget for another Kali sandbox",
        resource="kali_sandbox")

    host.mem = (16 * GB, int(2.5 * GB))
    live = admit_sandbox(led, "b", 2 * GB)
    assert live.payload() == refused(
        "ram", int(2.5 * GB), 14 * GB, "not enough free memory to start a Kali sandbox now",
        resource="kali_sandbox")

    host.mem, host.pressure = (16 * GB, 15 * GB), "critical"
    critical = admit_sandbox(led, "b", 1 * GB)
    assert critical.payload() == refused(
        "ram", 15 * GB, 14 * GB, "host memory critically low", resource="kali_sandbox")

    host.pressure = "none"
    env.setenv("KALI_SANDBOX_MAX_CONCURRENT", "1")
    hard = admit_sandbox(led, "b", 1 * GB)
    assert hard.payload() == refused(
        "hard", 1, 1, "1 of 1 Kali sandboxes allowed", "KALI_SANDBOX_MAX_CONCURRENT",
        resource="kali_sandbox")
    # The orchestrator's 409 carries this payload; AdmissionError keeps it typed.
    assert al.AdmissionError(hard).result.payload()["resource"] == "kali_sandbox"
    assert led.sandbox_count() == 1


def test_first_sandbox_exempt_from_budget_while_scans_run(env, host):
    led = ledger(host)
    assert admit(led, "full_recon:p1", 14 * GB).admitted                # scans fill the pool
    assert admit_sandbox(led, "a", 1 * GB).admitted                     # first sandbox: exempt
    assert not admit_sandbox(led, "b", 1 * GB).admitted                 # second: budget
    # The exemption is from the budget only: live memory still guards the first sandbox.
    other = ledger(host)
    assert admit(other, "full_recon:p1", 14 * GB).admitted
    host.mem = (16 * GB, int(1.5 * GB))
    assert admit(other, sbx("a"), 1 * GB, resource="kali_sandbox").detail == \
        "not enough free memory to start a Kali sandbox now"


def test_first_scan_exempt_from_budget_while_sandboxes_run(env, host):
    host.mem = (16 * GB, 6 * GB)        # the sandboxes are using memory: 5 GiB live room
    led = ledger(host)
    for i in range(14):
        assert admit_sandbox(led, f"i{i}").admitted, i
    assert led.committed_bytes() == led.scan_pool()                     # sandboxes fill it
    assert not admit_sandbox(led, "i14").admitted
    # No scan is committed, so the first scan is not refused on budget grounds ...
    assert admit(led, "full_recon:p1", 4 * GB).payload() == OK_SCAN
    # ... but the second one is, sandbox bytes counted.
    assert admit(led, "gvm:p2", 1 * GB).payload() == refused(
        "ram", 18 * GB, 14 * GB, "not enough reserved memory budget for another scan")
    # Sandboxes adopted after an orchestrator restart (account) count the same way.
    adopted = ledger(host)
    for i in range(14):
        adopted.account(sbx(f"i{i}"), GB)
    assert admit(adopted, "full_recon:p1", 4 * GB).admitted


def test_global_scan_cap_ignores_sandboxes(env, host):
    env.setenv("RECON_MAX_CONCURRENT_GLOBAL", "1")
    led = ledger(host)
    for i in range(3):
        led.account(sbx(f"i{i}"), GB)
    assert admit(led, "gvm:p1", 1 * GB).admitted                        # 0 scans of 1
    second = admit(led, "gvm:p2", 1 * GB)
    assert second.payload() == refused(
        "hard", 1, 1, "1 of 1 concurrent scans allowed", "RECON_MAX_CONCURRENT_GLOBAL")
    # Nor does the scan cap refuse a sandbox, even at 0 ("pause all scans").
    env.setenv("RECON_MAX_CONCURRENT_GLOBAL", "0")
    assert admit_sandbox(led, "i3").admitted


def test_per_user_scan_count_ignores_sandboxes(env, host):
    env.setenv("RECON_MAX_CONCURRENT_PER_USER", "1")
    led = ledger(host)
    led.account(sbx("i0"), GB)
    # A sandbox never records a person, even when a caller names one.
    assert admit_sandbox(led, "i1", user_id="u1", max_per_user=0).payload() == OK_SANDBOX
    assert led.user_active_count("u1") == 0
    assert admit(led, "gvm:p1", 1 * GB, user_id="u1").admitted
    assert admit(led, "gvm:p2", 1 * GB, user_id="u1").payload() == refused(
        "hard", 1, 1, "1 of 1 concurrent scans allowed per user", "RECON_MAX_CONCURRENT_PER_USER")
    assert admit(led, "gvm:p3", 1 * GB, user_id="u1", max_per_user=5).setting_name == \
        "RECON_MAX_CONCURRENT_PER_USER"
    # The person's own sandbox still starts at their scan ceiling.
    assert admit_sandbox(led, "i2", user_id="u1").admitted


# The sandbox contract's parser (sandbox_contract.max_concurrent) reads the same
# variable for the sandbox manager: one to nine ASCII digits, else no cap. Every value
# int() would also accept ("-0", "+3", "1_0", non-ASCII digits, ten digits) is no cap.
@pytest.mark.parametrize("raw,cap", [
    ("1", 1), ("0", 0), (" 2 ", 2), ("1\n", 1), ("007", 7), ("999999999", 999999999),
    ("", None), ("   ", None), ("abc", None), ("-1", None), ("1.5", None),
    ("-0", None), ("+3", None), ("1_0", None), ("３", None), ("٣", None),
    ("9999999999", None), ("1e3", None), ("0x3", None),
])
def test_sandbox_hard_count(env, host, raw, cap, monkeypatch):
    monkeypatch.setattr(al, "_warned_sandbox_cap", None, raising=False)
    env.setenv("KALI_SANDBOX_MAX_CONCURRENT", raw)
    led = ledger(host)
    assert led.max_concurrent_sandboxes() == cap
    # Scans never count against the sandbox cap.
    assert admit(led, "gvm:p1", 1 * GB).admitted
    assert admit(led, "gvm:p2", 1 * GB).admitted
    results = [admit_sandbox(led, f"i{i}") for i in range(5)]
    admitted = sum(r.admitted for r in results)
    assert admitted == (5 if cap is None else min(cap, 5))
    if cap is not None and cap < 5:
        assert results[cap].payload() == refused(
            "hard", cap, cap, f"{cap} of {cap} Kali sandboxes allowed",
            "KALI_SANDBOX_MAX_CONCURRENT", resource="kali_sandbox")
        if cap:
            # A retry of an instance already admitted is never refused at the cap.
            assert admit_sandbox(led, "i0").admitted
    assert led.active_count() == 2


def test_malformed_sandbox_cap_is_logged_once_without_its_value(env, host, monkeypatch, caplog):
    monkeypatch.setattr(al, "_warned_sandbox_cap", None, raising=False)
    led = ledger(host)
    with caplog.at_level(logging.WARNING, logger="admission_ledger"):
        env.setenv("KALI_SANDBOX_MAX_CONCURRENT", "+31337")
        for _ in range(3):
            assert led.max_concurrent_sandboxes() is None
        assert len(caplog.records) == 1
        assert "KALI_SANDBOX_MAX_CONCURRENT" in caplog.text and "31337" not in caplog.text
        # A different malformed value is reported again; unset, blank and valid never are.
        env.setenv("KALI_SANDBOX_MAX_CONCURRENT", "-0")
        assert led.max_concurrent_sandboxes() is None
        for value in ("", "  ", "4"):
            env.setenv("KALI_SANDBOX_MAX_CONCURRENT", value)
            led.max_concurrent_sandboxes()
        env.delenv("KALI_SANDBOX_MAX_CONCURRENT")
        led.max_concurrent_sandboxes()
    assert len(caplog.records) == 2


def test_governor_disabled_admits_sandbox_but_respects_hard_count(env, host):
    env.setenv("REDAMON_MEM_GOVERNOR", "false")
    host.mem, host.pressure = (16 * GB, GB // 8), "critical"            # would refuse anything
    led = ledger(host)
    assert admit_sandbox(led, "a", 8 * GB).payload() == OK_SANDBOX
    assert admit_sandbox(led, "b", 8 * GB).payload() == OK_SANDBOX
    env.setenv("KALI_SANDBOX_MAX_CONCURRENT", "2")
    assert admit_sandbox(led, "c").payload() == refused(
        "hard", 2, 2, "2 of 2 Kali sandboxes allowed", "KALI_SANDBOX_MAX_CONCURRENT",
        resource="kali_sandbox")
    assert admit_sandbox(led, "a", 8 * GB).admitted                     # idempotent retry
    env.delenv("KALI_SANDBOX_MAX_CONCURRENT")
    assert admit_sandbox(led, "c").admitted
    assert led.sandbox_count() == 3


def test_fail_open_when_memory_is_unreadable(env, host):
    host.mem, host.pressure = None, "critical"
    led = ledger(host)
    assert admit_sandbox(led, "a", 64 * GB).payload() == OK_SANDBOX
    env.setenv("KALI_SANDBOX_MAX_CONCURRENT", "1")
    assert admit_sandbox(led, "b").limit_type == "hard"                 # the count still applies


def test_resource_and_prefix_must_agree(env, host):
    led = ledger(host)
    with pytest.raises(ValueError):
        admit(led, sbx("a"), GB)                                        # resource defaults to scan
    with pytest.raises(ValueError):
        admit(led, "full_recon:p1", GB, resource="kali_sandbox")
    with pytest.raises(ValueError):
        admit(led, "full_recon:p1", GB, resource="sandbox")             # unknown class
    env.setenv("REDAMON_MEM_GOVERNOR", "false")                         # no bypass when off
    with pytest.raises(ValueError):
        admit(led, sbx("a"), GB, resource="scan")
    assert led.committed_bytes() == 0


@pytest.mark.parametrize("envelope", [0, -GB, True, 1.5 * GB, None])
def test_sandbox_envelope_must_be_a_positive_byte_count(env, host, envelope):
    # A zero or negative reservation would admit every sandbox past the budget.
    led = ledger(host)
    with pytest.raises(ValueError):
        admit_sandbox(led, "a", envelope)
    env.setenv("REDAMON_MEM_GOVERNOR", "false")
    with pytest.raises(ValueError):
        admit_sandbox(led, "a", envelope)
    assert led.committed_bytes() == 0 and led.sandbox_count() == 0


def test_concurrent_sandbox_admissions_never_overcommit(env, host):
    led = ledger(host)

    async def burst():
        return await asyncio.gather(*[
            led.try_admit(sbx(f"i{i}", user=f"u{i}"), GB, resource="kali_sandbox")
            for i in range(30)])

    results = asyncio.run(burst())
    assert sum(r.admitted for r in results) == 14                      # 14 GiB pool
    assert led.committed_bytes() == 14 * GB

    env.setenv("KALI_SANDBOX_MAX_CONCURRENT", "3")
    capped = ledger(host)

    async def capped_burst():
        return await asyncio.gather(*[
            capped.try_admit(sbx(f"i{i}"), GB, resource="kali_sandbox") for i in range(10)])

    assert sum(r.admitted for r in asyncio.run(capped_burst())) == 3


# ---------------------------------------------------------------------------
# Scans decide exactly as before when no sandbox is committed
# ---------------------------------------------------------------------------

# (id, env, host mem, pressure, [(key, envelope, kwargs, expected payload)], committed after)
SCAN_CASES = [
    ("sole_scan_larger_than_pool", {}, (6 * GB, int(5.5 * GB)), "none",
     [("full_recon:p1", int(4.5 * GB), {}, OK_SCAN)], int(4.5 * GB)),
    ("second_scan_over_budget", {}, (16 * GB, 15 * GB), "none",
     [("gvm:p1", 10 * GB, {}, OK_SCAN),
      ("gvm:p2", 5 * GB, {}, refused("ram", 10 * GB, 14 * GB,
                                     "not enough reserved memory budget for another scan"))],
     10 * GB),
    ("global_cap", {"RECON_MAX_CONCURRENT_GLOBAL": "1"}, (16 * GB, 15 * GB), "none",
     [("gvm:p1", GB, {}, OK_SCAN),
      ("gvm:p2", GB, {}, refused("hard", 1, 1, "1 of 1 concurrent scans allowed",
                                 "RECON_MAX_CONCURRENT_GLOBAL"))],
     GB),
    ("global_cap_zero", {"RECON_MAX_CONCURRENT_GLOBAL": "0"}, (16 * GB, 15 * GB), "none",
     [("gvm:p1", GB, {}, refused("hard", 0, 0, "0 of 0 concurrent scans allowed",
                                 "RECON_MAX_CONCURRENT_GLOBAL"))],
     0),
    ("per_user_cap", {"RECON_MAX_CONCURRENT_PER_USER": "1"}, (16 * GB, 15 * GB), "none",
     [("gvm:p1", GB, {"user_id": "u1"}, OK_SCAN),
      ("gvm:p2", GB, {"user_id": "u1"}, refused("hard", 1, 1, "1 of 1 concurrent scans allowed per user",
                                                "RECON_MAX_CONCURRENT_PER_USER")),
      ("gvm:p3", GB, {"user_id": "u2"}, OK_SCAN)],
     2 * GB),
    ("per_user_quota", {}, (16 * GB, 15 * GB), "none",
     [("gvm:p1", GB, {"user_id": "u1", "max_per_user": 1}, OK_SCAN),
      ("gvm:p2", GB, {"user_id": "u1", "max_per_user": 1},
       refused("hard", 1, 1, "1 of 1 concurrent scans allowed by this person's quota",
               "maxConcurrentScans"))],
     GB),
    ("critical_pressure", {}, (16 * GB, 15 * GB), "critical",
     [("gvm:p1", GB, {}, refused("ram", 15 * GB, 14 * GB, "host memory critically low"))],
     0),
    ("live_memory_check", {}, (16 * GB, 3 * GB), "none",
     [("gvm:p1", 4 * GB, {}, refused("ram", 3 * GB, 14 * GB,
                                     "not enough free memory to start this scan now"))],
     0),
    ("fail_open", {}, None, "critical",
     [("gvm:p1", 4 * GB, {}, OK_SCAN)],
     4 * GB),
    ("governor_off", {"REDAMON_MEM_GOVERNOR": "false"}, (16 * GB, GB // 8), "critical",
     [("gvm:p1", 4 * GB, {}, OK_SCAN),
      ("gvm:p2", 4 * GB, {"user_id": "u1", "max_per_user": 0},
       refused("hard", 0, 0, "0 of 0 concurrent scans allowed by this person's quota",
               "maxConcurrentScans"))],
     4 * GB),
    ("idempotent_readmit_keeps_larger", {}, (16 * GB, 15 * GB), "none",
     [("gvm:p1", 2 * GB, {}, OK_SCAN), ("gvm:p1", 3 * GB, {}, OK_SCAN)],
     3 * GB),
]


@pytest.mark.parametrize("resource_kw", [{}, {"resource": "scan"}], ids=["default", "explicit"])
@pytest.mark.parametrize("case", SCAN_CASES, ids=[c[0] for c in SCAN_CASES])
def test_scan_admission_unchanged_without_sandboxes(env, host, case, resource_kw):
    _, extra_env, mem, pressure, steps, committed_after = case
    for name, value in extra_env.items():
        env.setenv(name, value)
    host.mem, host.pressure = mem, pressure
    led = ledger(host)
    for key, envelope, kw, expected in steps:
        assert admit(led, key, envelope, **kw, **resource_kw).payload() == expected, key
    assert led.committed_bytes() == committed_after


def test_remaining_for_new_unchanged_without_sandboxes(env, host):
    led = ledger(host)
    assert led.remaining_for_new() == 14 * GB                           # min(14 pool, 15 - 1 live)
    assert admit(led, "gvm:p1", 4 * GB).admitted
    assert led.remaining_for_new() == 10 * GB                           # pool - committed
    led.account("codefix:job-1", 20 * GB)                               # over the pool
    assert led.remaining_for_new() == 0
    host.mem = (16 * GB, 5 * GB)
    fresh = ledger(host)
    assert fresh.remaining_for_new() == 4 * GB                          # live - headroom
    host.mem = None
    assert ledger(host).remaining_for_new() == 0


def test_dispatcher_budget_exempts_first_scan_while_sandboxes_run(env, host, monkeypatch):
    host.mem = (16 * GB, 6 * GB)
    env.setenv("RECON_JOB_ENVELOPE_MEM", "2g")
    led = ledger(host)
    for i in range(14):                                                 # sandboxes fill the pool
        led.account(sbx(f"i{i}"), GB)
    assert led.committed_bytes() == led.scan_pool()
    # No scan committed: the head job meets the live figure, as try_admit would judge it.
    assert led.remaining_for_new() == 5 * GB

    posted = []

    def fake_request(url, key, method="GET", payload=None, **_kw):
        posted.append((method, url))
        if url.endswith("/candidates"):
            return {"candidates": [{"id": "job-1", "projectId": "p1", "kind": "partial_recon"},
                                   {"id": "job-2", "projectId": "p2", "kind": "partial_recon"}],
                    "activeCount": 0}
        # The webapp's start path runs try_admit; mirror it on the same ledger.
        job = url.rsplit("/", 2)[-2]
        res = asyncio.run(led.try_admit(f"partial_recon:{job}", led.envelope_for("partial_recon")))
        return {"ok": True} if res.admitted else {"ok": False, "blocked": "ram"}

    monkeypatch.setattr(jd, "request_json", fake_request)
    monkeypatch.setattr(jd, "webapp_base", lambda: "http://webapp:3000")
    monkeypatch.setattr(jd, "internal_key", lambda: "internal-key")
    monkeypatch.setattr(jd, "_free_disk_bytes", lambda: None)

    summary = jd.run_dispatcher_tick(types.SimpleNamespace(ledger=led))
    assert summary["dispatched"] == 1
    assert ("POST", "http://webapp:3000/api/internal/job-queue/job-1/dispatch") in posted
    # Once a scan is committed, sandbox bytes count against the next queued scan exactly
    # as try_admit counts them: the head-of-line break holds job-2 back.
    assert ("POST", "http://webapp:3000/api/internal/job-queue/job-2/dispatch") not in posted
    assert led.remaining_for_new() == 0
    assert not asyncio.run(led.try_admit("partial_recon:job-2", 2 * GB)).admitted


# ---------------------------------------------------------------------------
# Accounting, the snapshot and the reaper
# ---------------------------------------------------------------------------

def test_snapshot_counts_sandboxes_separately(env, host):
    led = ledger(host)
    assert admit(led, "gvm:p1", 2 * GB).admitted
    assert admit(led, "full_recon:p2", 3 * GB).admitted
    for i in range(3):
        led.account(sbx(f"i{i}"), GB)
    snap = led.snapshot()
    assert snap["active_scans"] == 2
    assert snap["active_sandboxes"] == 3
    assert snap["sandbox_committed"] == 3 * GB
    assert snap["committed"] == 8 * GB                                  # every byte, both classes
    assert snap["sandbox_envelope"] == GB
    assert snap["remaining_for_new"] == 6 * GB                          # 14 - 8, scans committed
    assert (led.active_count(), led.sandbox_count(), led.sandbox_committed_bytes()) == (2, 3, 3 * GB)
    assert led.sandbox_keys() == {sbx("i0"), sbx("i1"), sbx("i2")}
    # Release and reconcile follow the key: no class map to fall out of step.
    led.release_nowait(sbx("i0"))
    assert led.reconcile({"gvm:p1", sbx("i1")}) == 2
    assert led.snapshot()["active_sandboxes"] == 1 and led.active_count() == 1


def _bare_manager(led):
    """A ContainerManager without __init__, as most orchestrator tests build one."""
    m = cm.ContainerManager.__new__(cm.ContainerManager)
    m.ledger = led
    m.running_states, m.partial_recon_states, m.ai_attack_states = {}, {}, {}
    m.gvm_states, m.github_hunt_states, m.trufflehog_states = {}, {}, {}
    m.supply_chain_states, m.codefix_sandboxes = {}, {}
    m.guarddog_jobs = set()
    return m


def test_reaper_keeps_running_sandbox_reservation(env, host):
    with patch("container_manager.docker") as docker:
        docker.from_env.return_value = MagicMock()
        mgr = cm.ContainerManager()
    mgr.ledger = ledger(host)
    # Without the sandbox manager wired in, nothing outside the class holds a key.
    assert set(mgr.extra_reservation_keys()) == set()
    mgr.ledger.account(sbx("live"), GB)
    mgr.ledger.account("gvm:finished", GB)
    assert mgr.reconcile_reservations() == 2
    assert mgr.ledger.committed_bytes() == 0

    # With the hook: the live sandbox's key survives the 30 s reaper, a stopped one and
    # a finished scan's do not.
    mgr.extra_reservation_keys = lambda: {sbx("live")}
    for key in (sbx("live"), sbx("stopped"), "gvm:finished"):
        mgr.ledger.account(key, GB)
    assert sbx("live") in mgr._active_scan_keys()
    assert mgr.reconcile_reservations() == 2
    assert mgr.ledger.sandbox_keys() == {sbx("live")}
    assert mgr.ledger.active_count() == 0

    # A manager built without __init__ has the default hook too.
    bare = _bare_manager(ledger(host))
    assert bare._active_scan_keys() == set()


@pytest.mark.parametrize("hook", [
    lambda: (_ for _ in ()).throw(RuntimeError("sandbox manager down")),
    lambda: None,
    lambda: 42,
], ids=["raises", "none", "not_iterable"])
def test_reaper_survives_a_failing_hook_and_keeps_sandbox_reservations(env, host, hook, caplog):
    mgr = _bare_manager(ledger(host))
    mgr.extra_reservation_keys = hook
    mgr.ledger.account(sbx("live"), GB)
    mgr.ledger.account("gvm:finished", GB)
    with caplog.at_level(logging.WARNING):
        released = mgr.reconcile_reservations()
    # The finished scan is still freed; the sandbox the hook could not vouch for is kept.
    assert released == 1
    assert mgr.ledger.sandbox_keys() == {sbx("live")}
    assert mgr.ledger.active_count() == 0
    assert "extra reservation keys" in caplog.text

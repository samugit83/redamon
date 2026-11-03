"""Upload sessions: validation, chunk order, idempotent retries, caps, sweeps."""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import workspace_fs
from workspace_import import staging, upload_sessions
from workspace_import.errors import ImportFailure

GIB = 1024 ** 3
MIB = 1024 * 1024


class SessionBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-sessions-"))
        self._patches = [
            mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(staging, "disk_usage", lambda _p: SimpleNamespace(free=self.free)),
            mock.patch.dict(os.environ, {"JOB_QUEUE_MIN_FREE_DISK": "0",
                                         "WORKSPACE_IMPORT_MIN_FREE_BYTES": str(GIB),
                                         "WORKSPACE_UPLOAD_CHUNK_BYTES": str(4)}),
        ]
        self.free = 100 * GIB
        for p in self._patches:
            p.start()
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        workspace_fs.resolve_for_project("p1", ".")
        workspace_fs.resolve_for_project("p2", ".")

    def tearDown(self):
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def create(self, pid="p1", dest="uploads", name="a.bin", size=10, kind="file", policy="keep_both", **kw):
        return upload_sessions.create(pid, dest, name, size, kind, policy, **kw)

    def assertCode(self, code, fn, *a, **kw):
        with self.assertRaises(ImportFailure) as ctx:
            fn(*a, **kw)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception

    async def assertCodeAsync(self, code, coro):
        with self.assertRaises(ImportFailure) as ctx:
            await coro
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception


class Create(SessionBase):
    def test_create_validates_dest_name_kind_policy_size(self):
        out = self.create()
        self.assertRegex(out["uploadId"], r"^[0-9a-f]{32}$")
        self.assertEqual(out["chunkSize"], 4)
        op = self.tmp / ".staging" / "p1" / f"up-{out['uploadId']}"
        self.assertTrue((op / "data.part").is_file())
        self.assertTrue((op / "session.json").is_file())
        for bad in ({"name": "a/b"}, {"name": "..", }, {"name": "x\x00"}, {"name": ""}, {"name": "n" * 256},
                    {"kind": "zip"}, {"policy": "merge"}, {"size": 0}, {"size": "10"}, {"dest": "../.."}):
            with self.subTest(bad=bad):
                self.assertCode("invalid_request", self.create, **bad)
        self.assertCode("destination_missing", self.create, dest="uploads/nope")
        with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_BYTES": "100"}):
            self.assertCode("too_large", self.create, size=101)

    def test_create_refuses_when_disk_reserve_would_be_crossed(self):
        self.free = 3 * GIB
        self.create(size=GIB, kind="folder", name="f1")   # reserves 2 GiB
        self.assertCode("insufficient_storage", self.create, size=GIB // 2 + 1, kind="folder", name="f2")
        self.assertEqual(len(list((self.tmp / ".staging" / "p1").glob("up-*"))), 1)

    def test_concurrent_creates_respect_the_reserve(self):
        self.free = 5 * GIB
        results = []
        # Two projects, so the per-project session cap never decides.
        for i in range(6):
            try:
                self.create(pid=("p1", "p2")[i % 2], name=f"f{i}", size=GIB, kind="file")
                results.append("ok")
            except ImportFailure as e:
                results.append(e.code)
        # 5 GiB free with a 1 GiB floor: four 1 GiB sessions fit, then none.
        self.assertEqual(results, ["ok"] * 4 + ["insufficient_storage"] * 2)
        self.assertEqual(staging.reserved_total(), 4 * GIB)

    def test_fifth_session_is_429(self):
        for i in range(4):
            self.create(name=f"f{i}")
        e = self.assertCode("too_many_uploads", self.create, name="f5")
        self.assertEqual(e.status, 429)
        self.create(pid="p2", name="other")  # the cap is per project

    def test_invalid_project_refused(self):
        self.assertCode("invalid_request", self.create, pid="../x")
        self.assertCode("invalid_request", self.create, pid=".staging")


class EntryCount(SessionBase):
    def test_folder_over_the_entry_cap_is_refused_before_any_byte(self):
        with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_ENTRIES": "10"}):
            with self.assertRaises(ImportFailure) as ctx:
                upload_sessions.create("p1", "uploads", "node-project", 100, "folder", "keep_both", entries=11)
            self.assertEqual(ctx.exception.code, "too_many_entries")
            self.assertEqual(upload_sessions._sessions, {})
            self.assertEqual(staging.reserved_total(), 0)
            self.assertFalse(list((self.tmp / ".staging" / "p1").glob("up-*")))
            upload_sessions.create("p1", "uploads", "small", 100, "folder", "keep_both", entries=10)

    def test_entry_count_must_be_a_count(self):
        for bad in (-1, True, "5", 1.5):
            with self.assertRaises(ImportFailure, msg=repr(bad)) as ctx:
                upload_sessions.create("p1", "uploads", "x", 100, "folder", "keep_both", entries=bad)
            self.assertEqual(ctx.exception.code, "invalid_request")


class Chunks(SessionBase):
    async def test_chunks_append_in_order(self):
        uid = self.create(size=10)["uploadId"]
        self.assertEqual(await upload_sessions.write_chunk("p1", uid, 0, b"abcd"), 4)
        self.assertEqual(await upload_sessions.write_chunk("p1", uid, 4, b"efgh"), 8)
        self.assertEqual(await upload_sessions.write_chunk("p1", uid, 8, b"ij"), 10)
        self.assertEqual(upload_sessions.get("p1", uid).data_path.read_bytes(), b"abcdefghij")

    async def test_duplicate_chunk_is_acknowledged_without_writing(self):
        uid = self.create(size=10)["uploadId"]
        await upload_sessions.write_chunk("p1", uid, 0, b"abcd")
        self.assertEqual(await upload_sessions.write_chunk("p1", uid, 0, b"abcd"), 4)
        self.assertEqual(upload_sessions.get("p1", uid).data_path.read_bytes(), b"abcd")

    async def test_gap_or_overlap_is_offset_mismatch_with_expected_offset(self):
        uid = self.create(size=10)["uploadId"]
        await upload_sessions.write_chunk("p1", uid, 0, b"abcd")
        for offset in (6, 2):
            e = await self.assertCodeAsync("offset_mismatch", upload_sessions.write_chunk("p1", uid, offset, b"zzzz"))
            self.assertEqual(e.detail, "4")
        self.assertEqual(upload_sessions.get("p1", uid).data_path.read_bytes(), b"abcd")

    async def test_overflow_refused(self):
        uid = self.create(size=6)["uploadId"]
        await upload_sessions.write_chunk("p1", uid, 0, b"abcd")
        await self.assertCodeAsync("chunk_overflow", upload_sessions.write_chunk("p1", uid, 4, b"efg"))
        await self.assertCodeAsync("chunk_too_large", upload_sessions.write_chunk("p1", uid, 4, b"efghi"))

    async def test_other_project_cannot_touch_session(self):
        uid = self.create()["uploadId"]
        await self.assertCodeAsync("session_not_found", upload_sessions.write_chunk("p2", uid, 0, b"ab"))
        self.assertFalse(upload_sessions.abort("p2", uid))
        self.assertIn(uid, upload_sessions._sessions)
        self.assertCode("session_not_found", upload_sessions.get, "p1", "../" + uid)

    async def test_two_concurrent_chunks_same_offset_write_once(self):
        uid = self.create(size=8)["uploadId"]
        results = await asyncio.gather(*[upload_sessions.write_chunk("p1", uid, 0, b"abcd") for _ in range(5)])
        self.assertEqual(results, [4] * 5)
        self.assertEqual(upload_sessions.get("p1", uid).data_path.read_bytes(), b"abcd")

    async def test_enospc_on_chunk_is_insufficient_storage(self):
        uid = self.create(size=8)["uploadId"]
        with mock.patch.object(upload_sessions, "_append", side_effect=OSError(28, "No space left on device")):
            e = await self.assertCodeAsync("insufficient_storage", upload_sessions.write_chunk("p1", uid, 0, b"abcd"))
        self.assertNotIn("No space", str(e))
        self.assertEqual(upload_sessions.get("p1", uid).received, 0)


class Lifecycle(SessionBase):
    def test_idle_session_swept(self):
        old = self.create(name="old", now=lambda: 1000.0)["uploadId"]
        with mock.patch.dict(os.environ, {"WORKSPACE_UPLOAD_SESSION_IDLE_SEC": "60"}):
            with self.assertLogs(upload_sessions.logger, "INFO") as logs:
                fresh = self.create(name="fresh", now=lambda: 1100.0)["uploadId"]
        self.assertNotIn(old, upload_sessions._sessions)
        self.assertIn(fresh, upload_sessions._sessions)
        self.assertFalse((self.tmp / ".staging" / "p1" / f"up-{old}").exists())
        self.assertTrue(any(old in line for line in logs.output))

    async def test_idle_sessions_are_swept_on_a_timer_without_any_create(self):
        stale = self.create(name="stale", now=lambda: time.time() - 7200)["uploadId"]
        live = self.create(name="live")["uploadId"]
        ticks = []

        async def tick(seconds):
            ticks.append(seconds)
            if len(ticks) > 1:
                raise asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):
            await upload_sessions.sweep_idle_forever(interval=300, sleep=tick)
        self.assertEqual(ticks, [300, 300])
        self.assertNotIn(stale, upload_sessions._sessions)
        self.assertIn(live, upload_sessions._sessions)
        self.assertFalse((self.tmp / ".staging" / "p1" / f"up-{stale}").exists())
        self.assertEqual(staging.reserved_total(), upload_sessions._sessions[live].reservation.nbytes)

    async def test_a_failing_sweep_never_stops_the_timer(self):
        calls = []

        async def tick(_s):
            calls.append(1)
            if len(calls) > 2:
                raise asyncio.CancelledError
        with mock.patch.object(upload_sessions, "sweep_idle", side_effect=OSError("disk")):
            with self.assertRaises(asyncio.CancelledError):
                await upload_sessions.sweep_idle_forever(interval=1, sleep=tick)
        self.assertEqual(len(calls), 3)

    def test_abort_is_idempotent(self):
        uid = self.create()["uploadId"]
        self.assertTrue(upload_sessions.abort("p1", uid))
        self.assertFalse(upload_sessions.abort("p1", uid))
        self.assertFalse((self.tmp / ".staging" / "p1" / f"up-{uid}").exists())

    def test_reservation_released_on_abort_and_sweep(self):
        a = self.create(name="a", size=GIB, kind="folder")["uploadId"]
        self.create(name="b", size=GIB, now=lambda: 0.0)
        self.assertEqual(staging.reserved_total(), 3 * GIB)
        upload_sessions.abort("p1", a)
        self.assertEqual(staging.reserved_total(), GIB)
        with mock.patch.dict(os.environ, {"WORKSPACE_UPLOAD_SESSION_IDLE_SEC": "1"}):
            upload_sessions.sweep_idle(now=10_000.0)
        self.assertEqual(staging.reserved_total(), 0)

    def test_commit_before_complete_is_refused(self):
        uid = self.create(size=10)["uploadId"]
        self.assertCode("session_incomplete", upload_sessions.take_for_commit, "p1", uid)
        self.assertIn(uid, upload_sessions._sessions)


if __name__ == "__main__":
    unittest.main()

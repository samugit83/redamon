"""Import work runs on its own bounded pool, never on the default one."""
from __future__ import annotations

import asyncio
import os
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from workspace_import import executor


class ImportPool(unittest.TestCase):
    def setUp(self):
        self._orig = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-import")

    def tearDown(self):
        executor.IMPORT_EXECUTOR.shutdown(wait=True, cancel_futures=True)
        executor.IMPORT_EXECUTOR = self._orig

    def test_extraction_does_not_delay_the_default_pool(self):
        release = threading.Event()

        async def main():
            # Pin the default pool to ONE thread so any import work on it would
            # visibly block the resolver-style call below.
            asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
            held = [asyncio.ensure_future(executor.run_blocking(release.wait, 10)) for _ in range(3)]
            await asyncio.sleep(0.05)
            t0 = time.monotonic()
            value = await asyncio.wait_for(asyncio.to_thread(lambda: 1), timeout=1.0)
            elapsed = time.monotonic() - t0
            release.set()
            await asyncio.gather(*held)
            return value, elapsed

        value, elapsed = asyncio.run(main())
        self.assertEqual(value, 1)
        self.assertLess(elapsed, 1.0)

    def test_work_runs_on_the_import_threads(self):
        name = asyncio.run(executor.run_blocking(lambda: threading.current_thread().name))
        self.assertTrue(name.startswith("test-import"))

    def test_pool_is_bounded_and_extra_work_queues(self):
        release = threading.Event()
        running = []
        queued_calls = []

        def work(i):
            running.append(i)
            release.wait(5)
            return i

        async def main():
            a = asyncio.ensure_future(executor.run_blocking(work, 1))
            b = asyncio.ensure_future(executor.run_blocking(work, 2))
            await asyncio.sleep(0.05)
            c = asyncio.ensure_future(executor.run_blocking(work, 3, on_queued=lambda: queued_calls.append("q")))
            await asyncio.sleep(0.1)
            self.assertEqual(sorted(running), [1, 2])  # the third waits for a worker
            release.set()
            return await asyncio.gather(a, b, c)

        self.assertEqual(asyncio.run(main()), [1, 2, 3])
        self.assertEqual(queued_calls, ["q"])

    def test_on_queued_not_called_when_a_worker_is_free(self):
        calls = []
        asyncio.run(executor.run_blocking(lambda: None, on_queued=lambda: calls.append(1)))
        self.assertEqual(calls, [])

    def test_async_on_queued_is_awaited(self):
        release = threading.Event()
        seen = []

        async def note():
            seen.append("queued")

        async def main():
            held = [asyncio.ensure_future(executor.run_blocking(release.wait, 5)) for _ in range(2)]
            await asyncio.sleep(0.05)
            third = asyncio.ensure_future(executor.run_blocking(lambda: "ok", on_queued=note))
            await asyncio.sleep(0.05)
            release.set()
            await asyncio.gather(*held)
            return await third

        self.assertEqual(asyncio.run(main()), "ok")
        self.assertEqual(seen, ["queued"])


class LazyPool(unittest.TestCase):
    def test_bad_worker_count_falls_back_to_default(self):
        orig = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = None
        try:
            with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_WORKERS": "many"}):
                pool = executor._executor()
            self.assertEqual(pool._max_workers, 2)
            pool.shutdown(wait=False)
        finally:
            executor.IMPORT_EXECUTOR = orig


if __name__ == "__main__":
    unittest.main()

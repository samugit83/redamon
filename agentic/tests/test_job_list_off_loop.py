"""The chat tool job_list reads the job store off the event loop.

Its disk part lists a jobs/ folder that every sandbox of the project writes, and
the agent serves every tenant on one loop: a slow listing must not stop it.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_executor_workspace_wiring import ExecutorWiringTestBase  # noqa: E402

import job_runner  # noqa: E402


class JobListDoesNotBlockTheLoop(ExecutorWiringTestBase):
    async def test_a_slow_disk_listing_leaves_the_loop_running(self):
        reg = job_runner.get_registry()

        def slow(project_id, rows, active):
            time.sleep(0.5)  # a jobs/ folder flooded with planted entries
            return rows

        ticks = []

        async def ticker():
            while True:
                ticks.append(1)
                await asyncio.sleep(0.01)

        with mock.patch.object(reg, "_with_disk_rows", slow):
            beat = asyncio.ensure_future(ticker())
            try:
                result = await self.executor.execute("job_list", {}, "informational")
            finally:
                beat.cancel()
        self.assertTrue(result["success"], result)
        self.assertGreater(len(ticks), 10, f"the loop ran {len(ticks)} times in 0.5 s: job_list blocked it")


if __name__ == "__main__":
    unittest.main()

"""The agent's boot hook and the workspace reset clean up uploads and imports.

api.py cannot be imported in a unit test (it starts the whole agent), so these
read its source, as test_think_prompt_workspace_wiring.py does for think_node.
"""
from __future__ import annotations

import unittest
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / "api.py").read_text(encoding="utf-8")


def _function(name: str) -> str:
    start = SOURCE.index(f"async def {name}(")
    nxt = SOURCE.find("\n@", start)
    return SOURCE[start: nxt if nxt != -1 else len(SOURCE)]


class BootAndReset(unittest.TestCase):
    def test_boot_puts_back_swaps_before_emptying_staging(self):
        body = _function("lifespan")
        recover, sweep = body.index("recover_swaps()"), body.index("sweep_all()")
        # A crash mid Re-sync leaves the old copy in staging: it must be put
        # back before the sweep deletes staging.
        self.assertLess(recover, sweep)
        self.assertLess(body.index("recover_on_boot()"), recover)
        self.assertLess(sweep, body.index("yield"))

    def test_boot_starts_the_idle_upload_sweeper_and_shutdown_stops_it(self):
        body = _function("lifespan")
        start = body.index("asyncio.create_task(_ws_upload_sessions.sweep_idle_forever())")
        self.assertLess(body.index("sweep_all()"), start)
        self.assertLess(body.index("yield"), body.index("idle_upload_sweeper.cancel()"))

    def test_reset_drops_imports_before_wiping_the_tree(self):
        body = _function("workspace_reset")
        self.assertLess(body.index("await reset_project_imports("), body.index("reset_for_project("))


if __name__ == "__main__":
    unittest.main()

"""The GVM stall-watchdog pin has to survive the whole way to the scan container.

Issue #174 added a watchdog that abandons a GVM task making zero progress. Its
error message tells the operator to raise `GVM_NO_PROGRESS_TIMEOUT`, which is only
true if the value actually reaches the spawned scan container. Three layers have
to agree: docker-compose.yml must name it (the orchestrator has NO env_file, so a
value in .env is otherwise inert), the orchestrator must forward it, and it must
forward it ONLY when set - an empty string would look like an explicit pin and
override the shipped default with garbage.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINER_MANAGER = REPO_ROOT / "recon_orchestrator/container_manager.py"
COMPOSE = REPO_ROOT / "docker-compose.yml"

KNOB = "GVM_NO_PROGRESS_TIMEOUT"
# Issue #177 replaced the stall bound with a liveness probe as the real dead-stack
# detector, so its cadence knob needs the same three-layer plumbing.
LIVENESS_KNOB = "GVM_LIVENESS_INTERVAL"


def _gvm_spawn_env_block() -> str:
    """The environment dict of start_gvm_scan's containers.run() call."""
    src = CONTAINER_MANAGER.read_text()
    start = src.index("def start_gvm_scan")
    end = src.index("def pause_gvm_scan", start)
    body = src[start:end]
    env_start = body.index('environment={')
    env_end = body.index('volumes={', env_start)
    return body[env_start:env_end]


class GvmStallKnobPlumbingTest(unittest.TestCase):
    def test_the_orchestrator_forwards_the_pin_to_the_scan(self):
        self.assertIn(KNOB, _gvm_spawn_env_block(),
                      "the GVM scan spawn never receives the operator's pin")

    def test_it_is_forwarded_only_when_actually_set(self):
        """An empty value must not reach the scan as an explicit override."""
        block = _gvm_spawn_env_block()
        knob_line = [ln for ln in block.splitlines() if KNOB in ln]
        self.assertTrue(knob_line, "knob not found in the spawn env")
        # The conditional-splat form: {...} if os.environ.get(KNOB, "").strip() else {}
        context = block[block.index(knob_line[0]):]
        self.assertIn(".strip()", context)
        self.assertIn("else {}", context)

    def test_compose_names_the_knob_for_the_orchestrator(self):
        """The orchestrator has no env_file: unlisted vars never arrive."""
        compose = COMPOSE.read_text()
        start = compose.index("\n  recon-orchestrator:")
        # Up to the next top-level service key.
        rest = compose[start + 1:]
        end = re.search(r"\n  [a-z0-9_-]+:\n", rest)
        block = rest[:end.start()] if end else rest
        self.assertIn(KNOB, block,
                      "recon-orchestrator does not receive the knob from compose")

    def test_the_default_is_empty_so_no_env_edit_is_required(self):
        """An existing .env without the key must interpolate to empty, not fail."""
        compose = COMPOSE.read_text()
        self.assertRegex(compose, rf"{KNOB}: \$\{{{KNOB}:-\}}")


class GvmLivenessKnobPlumbingTest(unittest.TestCase):
    """The liveness cadence needs the same three layers as the stall bound."""

    def test_the_orchestrator_forwards_it_to_the_scan(self):
        self.assertIn(LIVENESS_KNOB, _gvm_spawn_env_block())

    def test_it_is_forwarded_only_when_actually_set(self):
        block = _gvm_spawn_env_block()
        context = block[block.index(LIVENESS_KNOB):]
        self.assertIn(".strip()", context)
        self.assertIn("else {}", context)

    def test_compose_names_it_for_the_orchestrator(self):
        """The orchestrator has no env_file: unlisted vars never arrive."""
        compose = COMPOSE.read_text()
        start = compose.index("\n  recon-orchestrator:")
        rest = compose[start + 1:]
        end = re.search(r"\n  [a-z0-9_-]+:\n", rest)
        block = rest[:end.start()] if end else rest
        self.assertIn(LIVENESS_KNOB, block)

    def test_the_default_is_empty_so_no_env_edit_is_required(self):
        compose = COMPOSE.read_text()
        self.assertRegex(compose, rf"{LIVENESS_KNOB}: \$\{{{LIVENESS_KNOB}:-\}}")


if __name__ == "__main__":
    unittest.main()

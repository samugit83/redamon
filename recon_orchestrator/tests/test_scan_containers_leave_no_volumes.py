"""A finished or stopped scan container is removed with its anonymous volumes.

The recon image declares VOLUME /data and /var/run/docker.sock, so every recon and partial-recon
container gets two anonymous volumes; a remove without v=True left them on the host for good
(six in one e2e run). Every removal in container_manager goes through _discard, which passes it.
"""
import ast
import pathlib
import unittest
from unittest.mock import MagicMock

SRC = pathlib.Path(__file__).resolve().parent.parent / "container_manager.py"


class ScanContainersLeaveNoVolumesTests(unittest.TestCase):
    def test_discard_removes_the_anonymous_volumes(self):
        from container_manager import _discard

        c = MagicMock()
        _discard(c)
        c.remove.assert_called_once_with(force=False, v=True)
        c = MagicMock()
        _discard(c, force=True)
        c.remove.assert_called_once_with(force=True, v=True)

    def test_no_removal_bypasses_discard(self):
        tree = ast.parse(SRC.read_text())
        bare = [
            node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "remove"
            and not any(k.arg == "v" for k in node.keywords)
        ]
        self.assertEqual(bare, [], "a .remove() without v=True leaks the recon image's volumes")


if __name__ == "__main__":
    unittest.main()

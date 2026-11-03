"""A full disk is its own code; every other OSError stays an internal error."""
from __future__ import annotations

import errno
import unittest

from workspace_import.errors import map_os_error


class MapOsError(unittest.TestCase):
    def test_enospc_and_edquot_map_to_insufficient_storage(self):
        for code in (errno.ENOSPC, errno.EDQUOT):
            failure = map_os_error(OSError(code, "disk full"))
            self.assertIsNotNone(failure)
            self.assertEqual(failure.code, "insufficient_storage")
            self.assertEqual(failure.status, 413)
            self.assertNotIn("disk full", str(failure))

    def test_other_os_errors_map_to_none(self):
        for code in (errno.EACCES, errno.ENOENT, errno.EIO, errno.ELOOP):
            self.assertIsNone(map_os_error(OSError(code, "x")))
        self.assertIsNone(map_os_error(ValueError("not an OSError")))


if __name__ == "__main__":
    unittest.main()

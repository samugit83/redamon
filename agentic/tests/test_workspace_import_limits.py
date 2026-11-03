"""Env-driven caps and the URL-import kill switch fail closed."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from workspace_import import limits

GIB = 1024 ** 3


class Switch(unittest.TestCase):
    def test_unset_and_truthy_values_enable(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WORKSPACE_URL_IMPORT_ENABLED", None)
            self.assertTrue(limits.url_import_enabled())
        for v in ("true", "TRUE", "1", "yes", " Yes "):
            with mock.patch.dict(os.environ, {"WORKSPACE_URL_IMPORT_ENABLED": v}):
                self.assertTrue(limits.url_import_enabled(), v)

    def test_unrecognized_switch_value_disables(self):
        limits._warned_switch = False
        for v in ("false", "0", "no", "off", "", "ture", "enabled"):
            with mock.patch.dict(os.environ, {"WORKSPACE_URL_IMPORT_ENABLED": v}):
                self.assertFalse(limits.url_import_enabled(), v)

    def test_disabled_logs_one_warning(self):
        limits._warned_switch = False
        with mock.patch.dict(os.environ, {"WORKSPACE_URL_IMPORT_ENABLED": "nope"}):
            with self.assertLogs(limits.logger, "WARNING") as logs:
                limits.url_import_enabled()
                limits.url_import_enabled()
        self.assertEqual(len(logs.records), 1)


class Numbers(unittest.TestCase):
    def test_defaults(self):
        names = ("WORKSPACE_IMPORT_MAX_BYTES", "WORKSPACE_IMPORT_MAX_ENTRIES",
                 "WORKSPACE_IMPORT_MIN_FREE_BYTES", "JOB_QUEUE_MIN_FREE_DISK",
                 "WORKSPACE_IMPORT_MAX_JOBS", "WORKSPACE_UPLOAD_CHUNK_BYTES",
                 "WORKSPACE_UPLOAD_SESSION_IDLE_SEC", "WORKSPACE_IMPORT_WORKERS")
        env = {k: v for k, v in os.environ.items() if k not in names}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(limits.max_bytes(), 2 * GIB)
            self.assertEqual(limits.max_entries(), 50_000)
            self.assertEqual(limits.min_free_bytes(), 11 * GIB)
            self.assertEqual(limits.max_jobs(), 4)
            self.assertEqual(limits.chunk_bytes(), 8 * 1024 * 1024)
            self.assertEqual(limits.session_idle_sec(), 3600)
            self.assertEqual(limits.import_workers(), 2)

    def test_bad_numbers_fall_back_to_defaults(self):
        bad = {"WORKSPACE_IMPORT_MAX_BYTES": "2GB", "WORKSPACE_IMPORT_MAX_ENTRIES": "-5",
               "WORKSPACE_IMPORT_MAX_JOBS": "0", "WORKSPACE_IMPORT_WORKERS": "lots",
               "WORKSPACE_IMPORT_MIN_FREE_BYTES": "", "JOB_QUEUE_MIN_FREE_DISK": "ten"}
        with mock.patch.dict(os.environ, bad):
            self.assertEqual(limits.max_bytes(), 2 * GIB)
            self.assertEqual(limits.max_entries(), 50_000)
            self.assertEqual(limits.max_jobs(), 4)
            self.assertEqual(limits.import_workers(), 2)
            self.assertEqual(limits.min_free_bytes(), 11 * GIB)

    def test_reserve_includes_scan_floor(self):
        with mock.patch.dict(os.environ, {"JOB_QUEUE_MIN_FREE_DISK": str(20 * GIB),
                                          "WORKSPACE_IMPORT_MIN_FREE_BYTES": str(GIB)}):
            self.assertEqual(limits.min_free_bytes(), 21 * GIB)

    def test_scan_floor_zero_is_honoured_like_the_dispatcher(self):
        with mock.patch.dict(os.environ, {"JOB_QUEUE_MIN_FREE_DISK": "0",
                                          "WORKSPACE_IMPORT_MIN_FREE_BYTES": str(GIB)}):
            self.assertEqual(limits.min_free_bytes(), GIB)


if __name__ == "__main__":
    unittest.main()

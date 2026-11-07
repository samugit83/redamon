"""The Agent in the Loop switch, the loop-model test and the env tunables."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from agent_in_the_loop import (
    LOOP_MODEL_ID,
    LOOP_PREFIX,
    is_loop_model,
    loop_enabled,
    settings,
)


class IsLoopModel(unittest.TestCase):
    def test_loop_ids(self):
        self.assertTrue(is_loop_model("loop/mcp"))
        self.assertTrue(is_loop_model(" loop/x "))
        self.assertTrue(is_loop_model(LOOP_MODEL_ID))
        self.assertTrue(LOOP_MODEL_ID.startswith(LOOP_PREFIX))

    def test_everything_else(self):
        for value in (None, "", "   ", "looper", "custom/loop", "loop", "LOOP/mcp",
                      "claude-opus-4-6", "openai_compat/loop/mcp"):
            with self.subTest(value=value):
                self.assertFalse(is_loop_model(value))

    def test_non_string_is_not_a_loop_model(self):
        self.assertFalse(is_loop_model(123))  # type: ignore[arg-type]


class LoopEnabled(unittest.TestCase):
    def test_truthy(self):
        for raw in ("true", "TRUE", "1", " true ", "yes"):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": raw}):
                self.assertTrue(loop_enabled())

    def test_falsy(self):
        for raw in ("false", "0", "", "no", "off", "enabled"):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": raw}):
                self.assertFalse(loop_enabled())

    def test_absent_is_off(self):
        env = {k: v for k, v in os.environ.items() if k != "AGENT_IN_THE_LOOP_ENABLED"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(loop_enabled())


_KEYS = (
    "LOOP_STEP_DEADLINE_S", "LOOP_LEASE_S", "LOOP_WAIT_MAX_S", "LOOP_PAGE_CHARS",
    "LOOP_ANSWER_MAX_CHARS", "LOOP_MAX_OPEN_STEPS_PER_USER", "LOOP_NO_DRIVER_GRACE_S",
    "LOOP_DRIVER_SEEN_S", "LOOP_STATE_TTL_S",
)


def _clean_env(**overrides):
    env = {k: v for k, v in os.environ.items() if k not in _KEYS}
    env.update(overrides)
    return mock.patch.dict(os.environ, env, clear=True)


class Settings(unittest.TestCase):
    def test_defaults(self):
        with _clean_env():
            s = settings()
        self.assertEqual(s.step_deadline_s, 3600)
        self.assertEqual(s.lease_s, 90)
        self.assertEqual(s.wait_max_s, 55)
        self.assertEqual(s.page_chars, 40000)
        self.assertEqual(s.answer_max_chars, 262144)
        self.assertEqual(s.max_open_steps_per_user, 16)
        self.assertEqual(s.no_driver_grace_s, 1800)
        self.assertEqual(s.driver_seen_s, 60)
        self.assertEqual(s.state_ttl_s, 3600)
        # The deadline counts from the step's opening, so it must outlast the
        # silence an interactive driver is allowed, or it ends that pause first.
        self.assertGreater(s.step_deadline_s, s.no_driver_grace_s)

    def test_in_bounds_values_are_kept(self):
        with _clean_env(LOOP_STEP_DEADLINE_S="1200", LOOP_LEASE_S="120", LOOP_WAIT_MAX_S="30",
                        LOOP_PAGE_CHARS="20000", LOOP_ANSWER_MAX_CHARS="4096",
                        LOOP_MAX_OPEN_STEPS_PER_USER="4", LOOP_NO_DRIVER_GRACE_S="600",
                        LOOP_DRIVER_SEEN_S="30", LOOP_STATE_TTL_S="7200"):
            s = settings()
        self.assertEqual((s.step_deadline_s, s.lease_s, s.wait_max_s, s.page_chars),
                         (1200, 120, 30, 20000))
        self.assertEqual((s.answer_max_chars, s.max_open_steps_per_user, s.no_driver_grace_s,
                          s.driver_seen_s, s.state_ttl_s), (4096, 4, 600, 30, 7200))

    def test_out_of_bounds_and_malformed_fall_back_to_the_default(self):
        cases = {
            "LOOP_STEP_DEADLINE_S": ("5", "step_deadline_s", 3600),
            "LOOP_LEASE_S": ("9999", "lease_s", 90),
            "LOOP_WAIT_MAX_S": ("56", "wait_max_s", 55),
            "LOOP_PAGE_CHARS": ("abc", "page_chars", 40000),
            "LOOP_ANSWER_MAX_CHARS": ("-1", "answer_max_chars", 262144),
            "LOOP_MAX_OPEN_STEPS_PER_USER": ("0", "max_open_steps_per_user", 16),
            "LOOP_DRIVER_SEEN_S": ("1.5", "driver_seen_s", 60),
            "LOOP_STATE_TTL_S": ("", "state_ttl_s", 3600),
        }
        for key, (raw, attr, default) in cases.items():
            with self.subTest(key=key), _clean_env(**{key: raw}), \
                    self.assertLogs("agent_in_the_loop", level="WARNING") if raw else _no_logs():
                self.assertEqual(getattr(settings(), attr), default)

    def test_no_driver_grace_never_below_the_lease(self):
        with _clean_env(LOOP_LEASE_S="200", LOOP_NO_DRIVER_GRACE_S="100"):
            s = settings()
        self.assertGreaterEqual(s.no_driver_grace_s, s.lease_s)

    def test_a_bad_value_never_raises(self):
        with _clean_env(LOOP_STEP_DEADLINE_S="nine hundred", LOOP_LEASE_S="1e9"):
            s = settings()
        self.assertEqual((s.step_deadline_s, s.lease_s), (3600, 90))


class _no_logs:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


if __name__ == "__main__":
    unittest.main()

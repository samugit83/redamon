"""The urlscan lab hooks reach only the lab's own projects.

URLSCAN_API_BASE names a fake urlscan that receives the project's urlscan key,
and REDAMON_LAB_CDN_PREFIXES makes a test subnet look like a CDN edge. While the
lab runs, every other scan this orchestrator starts (another user's, a scheduled
one) must keep the real urlscan and the real CDN list, so the hooks are
forwarded only into the projects named in REDAMON_LAB_PROJECT_IDS.

Driven through both real spawn paths with docker stubbed.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import container_manager as cm  # noqa: E402
from test_circuit_breaker_switch import _full_recon_env, _partial_recon_env  # noqa: E402

HOOKS = {"URLSCAN_API_BASE": "http://192.88.97.30/api/v1",
         "REDAMON_LAB_CDN_PREFIXES": "192.88.97.40/32"}
ALL = (*HOOKS, "REDAMON_LAB_PROJECT_IDS")


def _clean_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ALL}
    env.update(extra)
    return env


class TestUrlscanLabOverrides(unittest.TestCase):
    def test_listed_project_gets_both_hooks_in_both_spawns(self):
        # The spawn harness starts project "p1".
        with mock.patch.dict(os.environ, _clean_env(**HOOKS, REDAMON_LAB_PROJECT_IDS="p0, p1"),
                             clear=True):
            for env in (_full_recon_env(), _partial_recon_env()):
                self.assertEqual({k: env.get(k) for k in HOOKS}, HOOKS)

    def test_unlisted_project_gets_nothing(self):
        with mock.patch.dict(os.environ, _clean_env(**HOOKS, REDAMON_LAB_PROJECT_IDS="other"),
                             clear=True):
            for env in (_full_recon_env(), _partial_recon_env()):
                self.assertFalse(set(HOOKS) & set(env), sorted(env))

    def test_empty_or_unset_list_reaches_nobody(self):
        for ids in (None, "", " , "):
            extra = dict(HOOKS)
            if ids is not None:
                extra["REDAMON_LAB_PROJECT_IDS"] = ids
            with mock.patch.dict(os.environ, _clean_env(**extra), clear=True):
                for env in (_full_recon_env(), _partial_recon_env()):
                    self.assertFalse(set(HOOKS) & set(env), (ids, sorted(env)))

    def test_unset_hooks_keep_the_real_behaviour(self):
        for extra in ({}, {"URLSCAN_API_BASE": "", "REDAMON_LAB_CDN_PREFIXES": "  "}):
            with mock.patch.dict(os.environ, _clean_env(**extra, REDAMON_LAB_PROJECT_IDS="p1"),
                                 clear=True):
                self.assertEqual(cm._urlscan_lab_overrides("p1"), {})
                for env in (_full_recon_env(), _partial_recon_env()):
                    self.assertFalse(set(HOOKS) & set(env), sorted(env))

    def test_helper_matches_exact_ids_only(self):
        with mock.patch.dict(os.environ, _clean_env(**HOOKS, REDAMON_LAB_PROJECT_IDS="p10"),
                             clear=True):
            self.assertEqual(cm._urlscan_lab_overrides("p1"), {})
            self.assertEqual(cm._urlscan_lab_overrides(""), {})
            self.assertEqual(cm._urlscan_lab_overrides("p10"), HOOKS)


class TestComposeForwardsTheHooks(unittest.TestCase):
    """The orchestrator has no env_file: a knob not in its compose block is inert,
    and none of the three may carry a default."""

    def test_listed_with_no_default(self):
        compose = (ROOT.parent / "docker-compose.yml").read_text()
        for name in ALL:
            self.assertIn(f"{name}: ${{{name}:-}}", compose)



class TestSecretHmacKeyForwarding(unittest.TestCase):
    """The urlscan Secret HMAC key reaches both spawns when set, and nothing is
    forwarded when it is not: no value_hmac rather than a fixed key."""

    def test_set_reaches_both(self):
        env = _clean_env(REDAMON_SECRET_HMAC_KEY="k" * 64)
        with mock.patch.dict(os.environ, env, clear=True):
            for spawned in (_full_recon_env(), _partial_recon_env()):
                self.assertEqual(spawned.get("REDAMON_SECRET_HMAC_KEY"), "k" * 64)

    def test_unset_or_blank_forwards_nothing(self):
        for extra in ({}, {"REDAMON_SECRET_HMAC_KEY": "  "}):
            env = {k: v for k, v in _clean_env(**extra).items() if k != "REDAMON_SECRET_HMAC_KEY" or extra}
            with mock.patch.dict(os.environ, env, clear=True):
                for spawned in (_full_recon_env(), _partial_recon_env()):
                    self.assertNotIn("REDAMON_SECRET_HMAC_KEY", spawned)


if __name__ == "__main__":
    unittest.main()

"""
Domain batch: the agent's scope source for BOTH guardrails.

Why this file exists. Both agent guardrails used to read TARGET_DOMAIN alone:

  - the soft (LLM) guardrail returned early on `if not target_domain and not
    target_ips`, i.e. "nothing to check";
  - the hard guardrail was gated on `if not ip_mode and target_domain`, and
    is_hard_blocked('') returns "not blocked" anyway.

A Domain-batch project leaves TARGET_DOMAIN empty and keeps its scope in
DOMAIN_BATCH_GROUPS, so BOTH guardrails silently disarmed on exactly the projects
carrying the most targets. target_scope_domains() is the single source that fixes
them, so the cases below are security regressions, not unit trivia.

Run with: python tests/test_domain_batch_scope.py
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from project_settings import target_scope_domains  # noqa: E402


def _settings(**values):
    """A fake get_setting backed by an explicit dict."""
    def _impl(key, default=None):
        return values.get(key, default)
    return _impl


class TestSingleDomainUnchanged(unittest.TestCase):
    def test_returns_the_single_target_domain(self):
        with patch('project_settings.get_setting', _settings(TARGET_DOMAIN='example.com')):
            self.assertEqual(target_scope_domains(), ['example.com'])

    def test_trims_and_ignores_a_blank_target(self):
        with patch('project_settings.get_setting', _settings(TARGET_DOMAIN='  example.com ')):
            self.assertEqual(target_scope_domains(), ['example.com'])
        with patch('project_settings.get_setting', _settings(TARGET_DOMAIN='   ')):
            self.assertEqual(target_scope_domains(), [])

    def test_ip_mode_has_no_domain_scope(self):
        with patch('project_settings.get_setting',
                   _settings(IP_MODE=True, TARGET_DOMAIN='example.com')):
            self.assertEqual(target_scope_domains(), [])


class TestDomainBatchScope(unittest.TestCase):
    def test_returns_every_group_root_although_target_domain_is_empty(self):
        # THE regression: an empty TARGET_DOMAIN must not mean "no scope".
        with patch('project_settings.get_setting', _settings(
            TARGET_DOMAIN='',
            DOMAIN_BATCH_MODE=True,
            DOMAIN_BATCH_GROUPS=[
                {'rootDomain': 'domain1.com', 'prefixes': ['sub1.']},
                {'rootDomain': 'domain2.it', 'prefixes': ['sub2.']},
                {'rootDomain': 'domain3.com', 'prefixes': ['sub3.', 'suba.sub3.']},
            ],
        )):
            self.assertEqual(
                target_scope_domains(), ['domain1.com', 'domain2.it', 'domain3.com'])

    def test_a_blocked_domain_anywhere_in_the_list_is_returned(self):
        # The hard guardrail iterates this list, so a blocked domain buried in the
        # middle must still be handed to it.
        with patch('project_settings.get_setting', _settings(
            DOMAIN_BATCH_MODE=True,
            DOMAIN_BATCH_GROUPS=[
                {'rootDomain': 'ok.com', 'prefixes': ['.']},
                {'rootDomain': 'whitehouse.gov', 'prefixes': ['.']},
                {'rootDomain': 'also-ok.com', 'prefixes': ['.']},
            ],
        )):
            self.assertIn('whitehouse.gov', target_scope_domains())

    def test_deduplicates_roots(self):
        with patch('project_settings.get_setting', _settings(
            DOMAIN_BATCH_MODE=True,
            DOMAIN_BATCH_GROUPS=[
                {'rootDomain': 'dup.com', 'prefixes': ['a.']},
                {'rootDomain': 'dup.com', 'prefixes': ['b.']},
            ],
        )):
            self.assertEqual(target_scope_domains(), ['dup.com'])

    def test_lowercases_roots_so_the_guardrail_match_is_stable(self):
        with patch('project_settings.get_setting', _settings(
            DOMAIN_BATCH_MODE=True,
            DOMAIN_BATCH_GROUPS=[{'rootDomain': 'WhiteHouse.GOV', 'prefixes': ['.']}],
        )):
            self.assertEqual(target_scope_domains(), ['whitehouse.gov'])

    def test_ip_mode_wins_over_batch_mode(self):
        with patch('project_settings.get_setting', _settings(
            IP_MODE=True,
            DOMAIN_BATCH_MODE=True,
            DOMAIN_BATCH_GROUPS=[{'rootDomain': 'example.com', 'prefixes': ['.']}],
        )):
            self.assertEqual(target_scope_domains(), [])


class TestBatchScopeRejectsMalformedInput(unittest.TestCase):
    """Groups are re-validated here: the project PUT route does not lock target
    fields, so a hand-edited row must not be able to define scope."""

    def test_a_non_list_yields_no_scope(self):
        for groups in (None, {}, 'example.com', 7):
            with patch('project_settings.get_setting', _settings(
                    DOMAIN_BATCH_MODE=True, DOMAIN_BATCH_GROUPS=groups)):
                self.assertEqual(target_scope_domains(), [])

    def test_drops_roots_outside_the_hostname_charset(self):
        for root in ('../../etc', 'evil.com/x', 'evil.com;whoami', 'ev il.com', 'a..b'):
            with patch('project_settings.get_setting', _settings(
                DOMAIN_BATCH_MODE=True,
                DOMAIN_BATCH_GROUPS=[{'rootDomain': root, 'prefixes': ['.']}],
            )):
                self.assertEqual(target_scope_domains(), [], f'accepted {root!r}')

    def test_one_bad_root_does_not_discard_the_good_ones(self):
        with patch('project_settings.get_setting', _settings(
            DOMAIN_BATCH_MODE=True,
            DOMAIN_BATCH_GROUPS=[
                {'rootDomain': 'good.com', 'prefixes': ['.']},
                {'rootDomain': '../bad', 'prefixes': ['.']},
            ],
        )):
            self.assertEqual(target_scope_domains(), ['good.com'])

    def test_empty_groups_in_batch_mode_returns_empty_for_the_caller_to_refuse(self):
        # Callers must treat this as a refusal, NOT as "nothing to check". The
        # refusal itself is asserted at the call sites in initialize_node.py.
        with patch('project_settings.get_setting', _settings(
                DOMAIN_BATCH_MODE=True, DOMAIN_BATCH_GROUPS=[])):
            self.assertEqual(target_scope_domains(), [])


if __name__ == '__main__':
    unittest.main()

"""
Domain batch: the guardrail target list used by POST /recon/{id}/start.

This decides what the hard guardrail actually checks before a scan container is
spawned. The guardrail is the one control an operator cannot switch off, and a
Domain-batch project has an EMPTY targetDomain, so a check written against
targetDomain alone would wave every batch target through. These cases guard that.

The module is standalone (not in api.py) precisely so this runs in the unit tier
without FastAPI or the Docker client.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from batch_scope import batch_guardrail_targets, guardrail_targets  # noqa: E402


class TestGuardrailTargetsByMode:
    def test_single_domain_project_returns_its_target(self):
        assert guardrail_targets({'targetDomain': 'example.com'}) == ['example.com']

    def test_ip_mode_has_no_domain_targets(self):
        # IPs are not hard-blocked; is_hard_blocked() documents that contract.
        assert guardrail_targets({'ipMode': True, 'targetIps': ['10.0.0.1']}) == []

    def test_batch_mode_returns_group_roots_although_target_domain_is_empty(self):
        project = {
            'targetDomain': '',
            'domainBatchMode': True,
            'domainBatchGroups': [
                {'rootDomain': 'domain1.com', 'prefixes': ['sub1.']},
                {'rootDomain': 'domain2.it', 'prefixes': ['sub2.']},
            ],
        }
        assert guardrail_targets(project) == ['domain1.com', 'domain2.it']

    def test_batch_mode_ignores_a_stale_target_domain(self):
        # A project switched into batch mode keeps no single target; if a stale
        # value lingered, scanning it would be out of scope.
        project = {
            'targetDomain': 'stale.example.com',
            'domainBatchMode': True,
            'domainBatchGroups': [{'rootDomain': 'real.com', 'prefixes': ['.']}],
        }
        assert guardrail_targets(project) == ['real.com']

    def test_a_blocked_domain_buried_mid_list_is_still_returned(self):
        project = {
            'domainBatchMode': True,
            'domainBatchGroups': [
                {'rootDomain': 'ok.com', 'prefixes': ['.']},
                {'rootDomain': 'whitehouse.gov', 'prefixes': ['.']},
                {'rootDomain': 'also-ok.com', 'prefixes': ['.']},
            ],
        }
        assert 'whitehouse.gov' in guardrail_targets(project)


class TestBatchTargetsFailClosed:
    """An empty list in batch mode means "scope unknown". The caller turns that
    into a 400; it must never read as "nothing to guard"."""

    def test_missing_groups_yield_nothing_to_check(self):
        assert batch_guardrail_targets({}) == []
        assert guardrail_targets({'domainBatchMode': True}) == []

    def test_a_non_list_groups_value_yields_nothing(self):
        for groups in (None, {}, 'example.com', 7):
            assert batch_guardrail_targets({'domainBatchGroups': groups}) == []

    def test_drops_a_root_outside_the_hostname_charset(self):
        for root in ('../../etc', 'evil.com/x', 'evil.com;whoami', 'ev il.com',
                     "evil.com'})--", 'a..b'):
            got = batch_guardrail_targets({'domainBatchGroups': [{'rootDomain': root}]})
            assert got == [], f'accepted {root!r}'

    def test_drops_a_non_dict_entry(self):
        assert batch_guardrail_targets({'domainBatchGroups': ['example.com']}) == []

    def test_one_bad_root_does_not_hide_the_others_from_the_guardrail(self):
        project = {'domainBatchGroups': [
            {'rootDomain': '../bad'},
            {'rootDomain': 'whitehouse.gov'},
        ]}
        assert batch_guardrail_targets(project) == ['whitehouse.gov']

    def test_normalizes_case_so_the_guardrail_match_is_stable(self):
        got = batch_guardrail_targets({'domainBatchGroups': [{'rootDomain': ' WhiteHouse.GOV '}]})
        assert got == ['whitehouse.gov']

    def test_deduplicates(self):
        project = {'domainBatchGroups': [
            {'rootDomain': 'dup.com'}, {'rootDomain': 'dup.com'},
        ]}
        assert batch_guardrail_targets(project) == ['dup.com']

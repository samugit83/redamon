"""
Domain batch: the settings layer that carries the operator-approved run order
into the pipeline.

The parser is a trust boundary, not a convenience. Group roots and prefixes end
up as scan targets and as a component of an output filename, and the project PUT
route does not lock target fields, so a row edited directly in the database must
not be able to reach a path or a tool argument. Every rejection case below is
therefore load-bearing.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.project_settings import DEFAULT_SETTINGS, _parse_domain_batch_groups


def test_default_settings_carry_the_batch_keys():
    assert DEFAULT_SETTINGS['DOMAIN_BATCH_MODE'] is False
    assert DEFAULT_SETTINGS['DOMAIN_BATCH_GROUPS'] == []


def test_parses_the_worked_example_preserving_run_order():
    groups = _parse_domain_batch_groups([
        {'rootDomain': 'domain1.com', 'prefixes': ['sub1.'], 'hosts': ['sub1.domain1.com']},
        {'rootDomain': 'domain2.it', 'prefixes': ['sub2.'], 'hosts': ['sub2.domain2.it']},
        {'rootDomain': 'domain3.com', 'prefixes': ['sub3.', 'suba.sub3.'], 'hosts': []},
    ])

    assert [g['rootDomain'] for g in groups] == ['domain1.com', 'domain2.it', 'domain3.com']
    assert groups[2]['prefixes'] == ['sub3.', 'suba.sub3.']


def test_keeps_the_root_domain_sentinel():
    # '.' means "the root domain itself" to parse_target; stripping it would turn
    # a bare-root group into a group with no targets at all.
    groups = _parse_domain_batch_groups([{'rootDomain': 'example.com', 'prefixes': ['.']}])
    assert groups == [{'rootDomain': 'example.com', 'prefixes': ['.']}]


def test_lowercases_and_trims():
    groups = _parse_domain_batch_groups([
        {'rootDomain': '  Example.COM ', 'prefixes': ['  WWW. ']},
    ])
    assert groups == [{'rootDomain': 'example.com', 'prefixes': ['www.']}]


class TestRejectsRatherThanRepairs:
    """A repaired hostname would scan something the operator never approved."""

    def test_a_non_list_yields_no_groups(self):
        for raw in (None, {}, 'example.com', 42):
            assert _parse_domain_batch_groups(raw) == []

    def test_drops_a_non_dict_entry(self):
        assert _parse_domain_batch_groups(['example.com', 7]) == []

    def test_drops_a_group_whose_root_escapes_the_charset(self):
        for root in ('../../etc', 'evil.com/x', 'evil.com;whoami', 'ev il.com',
                     "evil.com'})--", 'evil.com\\x'):
            assert _parse_domain_batch_groups(
                [{'rootDomain': root, 'prefixes': ['.']}]) == []

    def test_drops_a_root_containing_a_traversal_sequence(self):
        assert _parse_domain_batch_groups(
            [{'rootDomain': 'a..b', 'prefixes': ['.']}]) == []

    def test_drops_a_bad_prefix_but_keeps_the_good_ones(self):
        groups = _parse_domain_batch_groups([
            {'rootDomain': 'example.com', 'prefixes': ['www.', '../etc/', 'api.']},
        ])
        assert groups[0]['prefixes'] == ['www.', 'api.']

    def test_drops_the_whole_group_when_no_prefix_survives(self):
        # A group with no prefixes has nothing to scan; carrying it forward would
        # make the pipeline fall back to full discovery for that domain.
        assert _parse_domain_batch_groups(
            [{'rootDomain': 'example.com', 'prefixes': ['../etc/']}]) == []

    def test_drops_a_group_with_a_missing_or_empty_root(self):
        assert _parse_domain_batch_groups([{'prefixes': ['.']}]) == []
        assert _parse_domain_batch_groups([{'rootDomain': '  ', 'prefixes': ['.']}]) == []

    def test_one_bad_group_does_not_discard_the_good_ones(self):
        groups = _parse_domain_batch_groups([
            {'rootDomain': 'good.com', 'prefixes': ['.']},
            {'rootDomain': '../bad', 'prefixes': ['.']},
            {'rootDomain': 'also-good.com', 'prefixes': ['.']},
        ])
        assert [g['rootDomain'] for g in groups] == ['good.com', 'also-good.com']

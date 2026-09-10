"""
Domain batch: regression tests for the failure-mode analysis findings.

Each class reproduces the ORIGINAL defect first (as a scenario, with the inputs
that triggered it) and then asserts the behaviour that now prevents it. If a fix
is reverted, the reproduction is what goes red.

  F1  a project id is client-suppliable and was interpolated into a glob, so an
      id of '*' selected every OTHER project's group files - which the caller
      then deletes (or merges into this project's canonical output).
  F5  the merge folded dns.domain and the top-level domain key across groups,
      producing one domain's name attached to several domains' DNS records, and
      set metadata.root_domain to "a.com, b.com" which gvm_scanner adds VERBATIM
      as a scan hostname.
  F7  the canonical file kept describing the PREVIOUS run for the whole of
      group 1, so anything reading it in that window scanned the old targets.
"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'recon'))

from helpers.output_paths import (  # noqa: E402
    batch_output_files,
    canonical_output_file,
    clear_batch_outputs,
    initialize_batch_canonical,
    merge_batch_outputs,
    recon_output_file,
)

VICTIM = 'cmnbt9q1c0001nq01nv1wp1si'
ATTACKER_IDS = ['*', '[a-z]*', '?' * len(VICTIM), '*t9q1c0001nq01nv1wp1si', '[!x]*']


def _seed_victim(tmp_path):
    """A victim project with a canonical file and two batch group files."""
    canonical_output_file(tmp_path, VICTIM).write_text(json.dumps({'secret': 'victim'}))
    recon_output_file(tmp_path, VICTIM, 'victim-one.com').write_text(
        json.dumps({'metadata': {'root_domain': 'victim-one.com'}, 'secret': 'victim'}))
    recon_output_file(tmp_path, VICTIM, 'victim-two.com').write_text(
        json.dumps({'metadata': {'root_domain': 'victim-two.com'}, 'secret': 'victim'}))
    return sorted(p.name for p in tmp_path.iterdir())


class TestF1GlobInjectionViaProjectId:
    @pytest.mark.parametrize('attacker_id', ATTACKER_IDS)
    def test_a_wildcard_id_selects_none_of_the_victims_files(self, tmp_path, attacker_id):
        _seed_victim(tmp_path)
        assert batch_output_files(tmp_path, attacker_id) == []

    @pytest.mark.parametrize('attacker_id', ATTACKER_IDS)
    def test_a_wildcard_id_cannot_delete_the_victims_files(self, tmp_path, attacker_id):
        before = _seed_victim(tmp_path)
        removed = clear_batch_outputs(tmp_path, attacker_id)
        assert removed == 0
        assert sorted(p.name for p in tmp_path.iterdir()) == before

    @pytest.mark.parametrize('attacker_id', ATTACKER_IDS)
    def test_a_wildcard_id_cannot_read_the_victims_data_through_the_merge(
            self, tmp_path, attacker_id):
        _seed_victim(tmp_path)
        # Nothing to merge => no canonical write for the attacker at all.
        assert merge_batch_outputs(tmp_path, attacker_id) is None
        # And the victim's canonical file is untouched.
        assert json.loads(canonical_output_file(tmp_path, VICTIM).read_text()) == {'secret': 'victim'}

    def test_the_legitimate_owner_still_sees_exactly_its_own_files(self, tmp_path):
        _seed_victim(tmp_path)
        recon_output_file(tmp_path, 'otherproject0000000000', 'x.com').write_text('{}')
        got = [p.name for p in batch_output_files(tmp_path, VICTIM)]
        assert got == [f'recon_{VICTIM}__victim-one.com.json',
                       f'recon_{VICTIM}__victim-two.com.json']

    def test_a_prefix_of_a_longer_id_does_not_match_that_id(self, tmp_path):
        # 'abc' must not pick up 'abcdef''s files: startswith is on the FULL
        # "recon_<id>__" prefix, so the separator anchors it.
        recon_output_file(tmp_path, 'abcdef', 'x.com').write_text('{}')
        assert batch_output_files(tmp_path, 'abc') == []


class TestF5MergeDoesNotConflateRootDomains:
    def _group(self, root, ipv4, extra_sub=None):
        subs = {extra_sub: {'has_records': True}} if extra_sub else {}
        return {
            'metadata': {'root_domain': root, 'scan_type': 'full'},
            'domain': root,
            'dns': {
                'domain': {'has_records': True,
                           'ips': {'ipv4': [ipv4], 'ipv6': []},
                           'records': {'A': [ipv4]}},
                'subdomains': subs,
            },
        }

    def _merged(self, tmp_path):
        recon_output_file(tmp_path, VICTIM, 'a.com').write_text(
            json.dumps(self._group('a.com', '1.1.1.1', 'www.a.com')))
        recon_output_file(tmp_path, VICTIM, 'b.com').write_text(
            json.dumps(self._group('b.com', '2.2.2.2', 'www.b.com')))
        path = merge_batch_outputs(tmp_path, VICTIM)
        return json.loads(Path(path).read_text())

    def test_root_domain_is_never_a_joined_string(self, tmp_path):
        # gvm_scanner does `hostnames.add(metadata['root_domain'])`, so a joined
        # value became a literal scan target of "a.com, b.com".
        data = self._merged(tmp_path)
        assert data['metadata']['root_domain'] == ''
        assert ',' not in data['metadata']['root_domain']

    def test_the_batch_scope_is_still_recorded(self, tmp_path):
        data = self._merged(tmp_path)
        assert data['metadata']['domain_batch'] is True
        assert set(data['metadata']['domain_batch_groups']) == {'a.com', 'b.com'}

    def test_dns_domain_is_not_a_chimera_of_two_domains(self, tmp_path):
        # The original bug: dns.domain.ips.ipv4 == ['1.1.1.1', '2.2.2.2'] under
        # a single has_records taken from whichever group merged first.
        data = self._merged(tmp_path)
        assert data['dns']['domain'] == {}
        assert data['domain'] == ''

    def test_each_root_keeps_its_own_records_under_its_own_hostname(self, tmp_path):
        data = self._merged(tmp_path)
        subs = data['dns']['subdomains']
        assert subs['a.com']['ips']['ipv4'] == ['1.1.1.1']
        assert subs['b.com']['ips']['ipv4'] == ['2.2.2.2']

    def test_discovered_subdomains_survive_the_relocation(self, tmp_path):
        data = self._merged(tmp_path)
        assert {'a.com', 'b.com', 'www.a.com', 'www.b.com'} <= set(data['dns']['subdomains'])

    def test_gvm_target_extraction_yields_only_real_hostnames(self, tmp_path):
        # Reproduces scanners/gvm_scan/gvm_scanner.py _extract_targets against the
        # merged file: the root block is skipped (empty) and every hostname comes
        # from the keyed subdomain map, so none of them is a comma-joined string.
        data = self._merged(tmp_path)
        hostnames, ips = set(), set()
        domain = data.get('metadata', {}).get('root_domain', '') or data.get('domain', '')
        domain_dns = data.get('dns', {}).get('domain', {})
        if domain and domain_dns and domain_dns.get('has_records'):
            hostnames.add(domain)
        for name, sub in data['dns']['subdomains'].items():
            if sub and sub.get('has_records'):
                hostnames.add(name)
                ips.update(sub.get('ips', {}).get('ipv4', []))

        assert all(',' not in h and ' ' not in h for h in hostnames), hostnames
        assert {'a.com', 'b.com'} <= hostnames
        assert ips == {'1.1.1.1', '2.2.2.2'}

    def test_a_group_that_already_found_its_own_root_is_not_overwritten(self, tmp_path):
        g = self._group('a.com', '1.1.1.1')
        g['dns']['subdomains']['a.com'] = {'has_records': True, 'source': 'discovery'}
        recon_output_file(tmp_path, VICTIM, 'a.com').write_text(json.dumps(g))
        data = json.loads(Path(merge_batch_outputs(tmp_path, VICTIM)).read_text())
        assert data['dns']['subdomains']['a.com']['source'] == 'discovery'


class TestF7NoStaleCanonicalWindow:
    def test_the_previous_runs_canonical_file_is_replaced_before_group_one(self, tmp_path):
        # Previous run left a canonical file naming old targets.
        canonical = canonical_output_file(tmp_path, VICTIM)
        canonical.write_text(json.dumps({
            'metadata': {'root_domain': 'old-target.com'},
            'dns': {'domain': {'has_records': True}, 'subdomains': {'www.old-target.com': {'has_records': True}}},
        }))
        clear_batch_outputs(tmp_path, VICTIM)
        initialize_batch_canonical(tmp_path, VICTIM, ['new-a.com', 'new-b.com'])

        data = json.loads(canonical.read_text())
        assert 'old-target.com' not in json.dumps(data)
        assert data['metadata']['domain_batch_in_progress'] is True
        assert data['metadata']['domain_batch_groups'] == ['new-a.com', 'new-b.com']

    def test_the_placeholder_presents_no_live_targets(self, tmp_path):
        # A GVM start in this window must find nothing to scan rather than the
        # previous run's target set.
        initialize_batch_canonical(tmp_path, VICTIM, ['a.com'])
        data = json.loads(canonical_output_file(tmp_path, VICTIM).read_text())
        assert data['dns']['subdomains'] == {}
        assert data['dns']['domain'] == {}
        assert data['metadata']['root_domain'] == ''

    def test_the_placeholder_is_valid_json_a_reader_can_parse(self, tmp_path):
        initialize_batch_canonical(tmp_path, VICTIM, ['a.com'])
        json.loads(canonical_output_file(tmp_path, VICTIM).read_text())

    def test_the_first_merge_replaces_the_placeholder(self, tmp_path):
        initialize_batch_canonical(tmp_path, VICTIM, ['a.com'])
        recon_output_file(tmp_path, VICTIM, 'a.com').write_text(json.dumps(
            {'metadata': {'root_domain': 'a.com'}, 'dns': {'domain': {}, 'subdomains': {'w.a.com': {}}}}))
        merge_batch_outputs(tmp_path, VICTIM)
        data = json.loads(canonical_output_file(tmp_path, VICTIM).read_text())
        assert 'domain_batch_in_progress' not in data['metadata']
        assert 'w.a.com' in data['dns']['subdomains']

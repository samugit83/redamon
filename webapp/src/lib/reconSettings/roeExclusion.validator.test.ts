/**
 * roeExcludedHosts is refused at the write when an entry would exclude nothing.
 *
 * It was `free_text`, so MCP, a preset and a parsed RoE document could store
 * `10.0.0.0/33` or `0.5` and the scan matcher then skipped it in silence: the
 * client's "never touch this" list held a rule that protected nothing (R-3).
 * The validator accepts exactly what recon's matcher applies, which the last
 * test pins against the matcher itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { filterReconSettings } from './filter'
import { field } from './registry'
import { buildParseProposal } from './roeParse'
import { isRoeExcluded, roeExclusionProblem } from '@/lib/roeScope'

const write = (value: unknown) => filterReconSettings({ roeExcludedHosts: value }, { mode: 'update' })

/** Each accepted entry, with a host it must exclude. */
const ACCEPTED: [string, string][] = [
  ['pay.example.com', 'pay.example.com'],
  ['example.com', 'a.example.com'],
  ['*.example.com', 'a.example.com'],
  ['intranet', 'intranet'],
  ['_dmarc.example.com', '_dmarc.example.com'],
  ['192.0.2.10', '192.0.2.10'],
  ['192.0.2.0/24', '192.0.2.77'],
  ['10.0.0.0/255.255.255.0', '10.0.0.7'],
  ['2001:db8::1', '2001:db8::1'],
  ['2001:db8::/32', '2001:db8:1::5'],
  ['admin.example.com/login', 'admin.example.com'],
  ['admin.example.com/', 'admin.example.com'],
  ['192.0.2.10/admin', '192.0.2.10'],
  ['https://admin.example.com/x?y=1', 'admin.example.com'],
  ['Admin.Example.COM.:8443', 'admin.example.com'],
  ['*.example.com/admin', 'a.example.com'],
]

const REFUSED = [
  '0.5',
  '010.0.0.5',
  '10.0.0.0/33',
  '10.0.0.0/255.0.255.0',
  '*.',
  '*.192.0.2.1',
  'https://[a.example.com]/',
  'https://',
  'admin example.com',
  'user@example.com',
  'example.com?next=1',
]

describe('the RoE exclusion list takes only entries the matcher applies', () => {
  test('it is declared with the roe_exclusion validator', () => {
    expect(field('roeExcludedHosts')!.validator).toBe('roe_exclusion')
  })

  test('hosts, domains, wildcards, IPs, CIDRs, and the same with a scheme, port or path are accepted', () => {
    const r = write(ACCEPTED.map(([entry]) => entry))
    expect(r.ok).toBe(true)
  })

  test('an empty list, a single label and a blank row are accepted', () => {
    expect(write([]).ok).toBe(true)
    expect(write(['a']).ok).toBe(true)
    expect(write(['example.com', '  ']).ok).toBe(true)
  })

  test.each(REFUSED.map(e => [e]))('%j is refused, naming the entry', (entry) => {
    const r = write(['example.com', entry])
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.key).toBe('roeExcludedHosts')
      expect(r.error).toContain('would exclude nothing')
      expect(r.error).toContain(JSON.stringify(entry))
    }
  })

  test('a non-string entry is refused', () => {
    expect(write(['example.com', 5]).ok).toBe(false)
  })

  test('a parsed RoE document cannot store a refused entry either', () => {
    const proposal = buildParseProposal({ roeExcludedHosts: ['10.0.0.0/33'] })
    expect(proposal.changes).toEqual([])
    expect(proposal.rejected.map(r => r.key)).toContain('roeExcludedHosts')
    expect(buildParseProposal({ roeExcludedHosts: ['admin.example.com/login'] }).changes).toHaveLength(1)
  })

  test('every accepted entry really excludes its host, and every refused one excludes nothing', () => {
    for (const [entry, host] of ACCEPTED) {
      expect(roeExclusionProblem(entry), entry).toBeNull()
      expect(isRoeExcluded(host, [entry]), entry).toBe(true)
    }
    for (const entry of REFUSED) {
      for (const host of ['example.com', 'a.example.com', '10.0.0.5', '0.0.0.5', '192.0.2.1']) {
        expect(isRoeExcluded(host, [entry]), `${entry} vs ${host}`).toBe(false)
      }
    }
  })
})

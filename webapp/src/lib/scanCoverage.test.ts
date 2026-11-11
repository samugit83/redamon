/**
 * Recon coverage carried by the graph (scanCoverage.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const run = vi.fn()
const close = vi.fn()
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run, close }),
}))

import {
  IpModeCoverageScope, SCOPE_SELECT, currentScanRoots, gapInScope, parseCoverageGaps, readDegradedSourceCount,
  skippedHostInScope,
} from './scanCoverage'

const records = (gapsPerDomain: unknown[]) => ({
  records: gapsPerDomain.map(g => ({ get: (_k: string) => g })),
})

describe('parseCoverageGaps', () => {
  test('parses a JSON string array of source objects', () => {
    expect(parseCoverageGaps('[{"source":"shodan"},{"source":"otx"}]'))
      .toEqual([{ source: 'shodan' }, { source: 'otx' }])
  })
  test('accepts an already-parsed array', () => {
    expect(parseCoverageGaps([{ source: 'a' }])).toEqual([{ source: 'a' }])
  })
  test('rejects malformed JSON', () => {
    expect(parseCoverageGaps('{not json')).toBeNull()
  })
  test('rejects a non-array', () => {
    expect(parseCoverageGaps('{"source":"x"}')).toBeNull()
  })
  test('rejects an entry without a string source', () => {
    expect(parseCoverageGaps([{ nope: 1 }])).toBeNull()
  })
  test('rejects a source over 64 chars', () => {
    expect(parseCoverageGaps([{ source: 'x'.repeat(65) }])).toBeNull()
  })
})

describe('readDegradedSourceCount', () => {
  beforeEach(() => {
    run.mockReset()
    close.mockReset()
  })

  test('returns null when no Domain carries a coverage record', async () => {
    run.mockResolvedValue({ records: [] })
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('counts distinct sources across every covered Domain', async () => {
    run.mockResolvedValue(records([
      '[{"source":"shodan"},{"source":"nuclei"}]',
      '[{"source":"shodan"},{"source":"otx"}]',
    ]))
    expect(await readDegradedSourceCount('p1')).toBe(3) // shodan, nuclei, otx
  })

  test('returns 0 for a clean recorded run (empty gaps)', async () => {
    run.mockResolvedValue(records(['[]']))
    expect(await readDegradedSourceCount('p1')).toBe(0)
  })

  test('fails closed to null on an unparseable record', async () => {
    run.mockResolvedValue(records(['[{"source":"ok"}]', '{bad']))
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('returns null and never throws on a query error', async () => {
    run.mockRejectedValue(new Error('neo4j down'))
    expect(await readDegradedSourceCount('p1')).toBeNull()
  })

  test('always closes the session', async () => {
    run.mockResolvedValue({ records: [] })
    await readDegradedSourceCount('p1')
    expect(close).toHaveBeenCalledOnce()
  })
})

describe('coverage of a removed scan root (§4.11.7)', () => {
  test('the current scan roots of a project', () => {
    expect([...currentScanRoots({ targetDomain: 'Api.Example.com' })!]).toEqual(['api.example.com'])
    expect(currentScanRoots({})).toBeNull()
  })

  test('IP mode: covered hosts are the targets and the hostnames the CURRENT policy admits (P4, §6.3)', () => {
    const scope = currentScanRoots({ ipMode: true, ipHostnameMode: 'record_filter',
      ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'] } as never)!
    expect(scope).toBeInstanceOf(IpModeCoverageScope)
    // Every gap of an IP run is tagged with its synthetic root: all count.
    expect(gapInScope({ source: 's', root: 'ip-targets.p1' }, scope)).toBe(true)
    expect(gapInScope({ source: 's' }, scope)).toBe(true)
    for (const host of ['203.0.113.10:443', '[2001:db8::10]:8443', '2001:db8::10', '203-0-113-10',
      'ip-targets.p1', 'app.example.com:443', 'app.example.com']) {
      expect(skippedHostInScope(host, scope), host).toBe(true)
    }
    // A name the policy no longer admits (a narrowing since the run) is not.
    expect(skippedHostInScope('old.example.com:443', scope)).toBe(false)
    expect(skippedHostInScope('blog.example.net', scope)).toBe(false)
    const ipOnly = currentScanRoots({ ipMode: true, ipHostnameMode: 'ip_only' } as never)!
    expect(skippedHostInScope('app.example.com:443', ipOnly)).toBe(false)
    expect(skippedHostInScope('203.0.113.10:80', ipOnly)).toBe(true)
  })

  test("a gap is kept only for a current root; an untagged gap is kept", () => {
    const roots = new Set(['api.example.com'])
    expect(gapInScope({ source: 's', root: 'API.example.com' }, roots)).toBe(true)
    expect(gapInScope({ source: 's', root: 'old.example.com' }, roots)).toBe(false)
    expect(gapInScope({ source: 's' }, roots)).toBe(true)
    expect(gapInScope({ source: 's', root: 'old.example.com' }, null)).toBe(true)
  })

  test('a skipped host belongs to the longest root it sits under', () => {
    const roots = new Set(['api.example.com'])
    expect(skippedHostInScope('v1.api.example.com:443', roots)).toBe(true)
    expect(skippedHostInScope('api.example.com:80', roots)).toBe(true)
    expect(skippedHostInScope('www.example.com:443', roots)).toBe(false)
    expect(skippedHostInScope('www.example.com:443', null)).toBe(true)
  })

  test('the scope select carries an IP project\'s hostname policy', () => {
    for (const key of ['ipMode', 'ipHostnameMode', 'ipHostnameInclude', 'ipHostnameExclude',
      'ipHostnamePassiveExpand', 'ipHostnameScanAllConfirmed', 'ipHostnameMaxScanned', 'ipHostnamePassiveMaxNames']) {
      expect(SCOPE_SELECT[key as keyof typeof SCOPE_SELECT], key).toBe(true)
    }
  })

  test('the run-close count can drop a removed root', async () => {
    run.mockResolvedValueOnce(records([JSON.stringify([
      { source: 'a', root: 'api.example.com' }, { source: 'b', root: 'gone.example.com' }])]))
    expect(await readDegradedSourceCount('p1', new Set(['api.example.com']))).toBe(1)
  })
})

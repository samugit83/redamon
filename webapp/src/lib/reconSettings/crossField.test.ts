/**
 * validateCrossFieldRules and the hostname policy of an IP-mode project
 * ("Hostnames on target IPs", design §9).
 *
 * Every rule is judged on the EFFECTIVE row the caller passes (the stored row with
 * the change applied), never on the change alone: "scan_all needs its
 * confirmation" and "only in IP mode" cannot be judged on a partial body. The rule
 * runs when a policy field, `ipMode` or `engagementKind` is touched, and also
 * normalizes the row: canonical filter tokens, and no scan_all confirmation left
 * behind by a mode that no longer uses it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: { userSettings: { findUnique: async () => null } } }))

import { IP_HOSTNAME_RULE_TRIGGERS, validateCrossFieldRules } from './crossField'

const STORED_IP = {
  userId: 'owner', ipMode: true, targetIps: ['203.0.113.0/30'], engagementKind: 'internal',
  ipHostnameMode: 'record_only', ipHostnameInclude: [] as string[], ipHostnameExclude: [] as string[],
  ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false,
  ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
}

/** What guardProjectWrite and the MCP tools pass: the stored row, the change applied. */
async function judge(change: Record<string, unknown>, stored: Record<string, unknown> = STORED_IP) {
  const row: Record<string, unknown> = { ...stored, ...change }
  const problem = await validateCrossFieldRules(row, Object.keys(change), 'owner')
  return { problem, row }
}

describe('the triggers', () => {
  test('the seven policy fields, the mode flip and the engagement kind', () => {
    expect([...IP_HOSTNAME_RULE_TRIGGERS].sort()).toEqual([
      'engagementKind', 'ipHostnameExclude', 'ipHostnameInclude', 'ipHostnameMaxScanned', 'ipHostnameMode',
      'ipHostnamePassiveExpand', 'ipHostnamePassiveMaxNames', 'ipHostnameScanAllConfirmed', 'ipMode',
    ])
  })

  test('an unrelated write is never judged on a stored policy the rules refuse', async () => {
    const broken = { ...STORED_IP, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: false }
    expect((await judge({ katanaDepth: 3 }, broken)).problem).toBeNull()
  })
})

describe('each rule, on the effective row', () => {
  test('scan_all needs the confirmation, read from the stored row too', async () => {
    expect((await judge({ ipHostnameMode: 'scan_all' })).problem).toContain('ipHostnameScanAllConfirmed')
    const confirmed = { ...STORED_IP, ipHostnameScanAllConfirmed: true }
    expect((await judge({ ipHostnameMode: 'scan_all' }, confirmed)).problem).toBeNull()
  })

  test('scan_all is refused on a third-party engagement (D-03), whichever field changes', async () => {
    const third = { ...STORED_IP, engagementKind: 'third_party' }
    expect((await judge({ ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }, third)).problem)
      .toContain('third_party')
    const allIn = { ...STORED_IP, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }
    expect((await judge({ engagementKind: 'third_party' }, allIn)).problem).toContain('third_party')
  })

  test('record_filter needs an include entry, stored or sent', async () => {
    expect((await judge({ ipHostnameMode: 'record_filter' })).problem).toContain('ipHostnameInclude')
    const withInclude = { ...STORED_IP, ipHostnameInclude: ['*.example.com'] }
    expect((await judge({ ipHostnameMode: 'record_filter' }, withInclude)).problem).toBeNull()
    expect((await judge({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] })).problem).toBeNull()
  })

  test('a closed mode vocabulary', async () => {
    expect((await judge({ ipHostnameMode: 'scan_some' })).problem).toContain('ipHostnameMode must be one of')
    expect((await judge({ ipHostnameMode: 7 })).problem).toContain('ipHostnameMode must be one of')
  })

  test.each([
    ['an IP literal', '203.0.113.9', 'IP address'],
    ['a public suffix', 'co.uk', 'public suffix'],
    ['a wildcard on a public suffix', '*.co.uk', 'public suffix'],
    ['a malformed wildcard', '**.example.com', 'wildcard'],
  ])('an include entry that is %s is refused', async (_name, entry, needle) => {
    const { problem } = await judge({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', entry] })
    expect(problem).toContain('ipHostnameInclude: Not accepted')
    expect(problem?.toLowerCase()).toContain(needle.toLowerCase())
  })

  test('exclude entries parse with the same rules', async () => {
    const { problem } = await judge({ ipHostnameExclude: ['198.51.100.7'] })
    expect(problem).toContain('ipHostnameExclude: Not accepted')
  })

  test('an include entry gets the hard guardrail', async () => {
    const { problem } = await judge({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.agency.gov.uk'] })
    expect(problem).toContain('Target permanently blocked: agency.gov.uk')
  })

  test('at most 200 entries per list (D-05)', async () => {
    const list = (n: number) => Array.from({ length: n }, (_, i) => `h${i}.example.com`)
    expect((await judge({ ipHostnameExclude: list(200) })).problem).toBeNull()
    expect((await judge({ ipHostnameExclude: list(201) })).problem).toContain('more than 200')
    expect((await judge({ ipHostnameInclude: list(201) })).problem).toContain('more than 200')
  })

  test('a list must be a list', async () => {
    expect((await judge({ ipHostnameInclude: '*.example.com' })).problem).toContain('must be a list')
  })

  test.each([
    ['ipHostnameMaxScanned', 0], ['ipHostnameMaxScanned', 2001], ['ipHostnameMaxScanned', 1.5],
    ['ipHostnamePassiveMaxNames', 0], ['ipHostnamePassiveMaxNames', 10001], ['ipHostnamePassiveMaxNames', '50'],
  ])('%s %o is outside its bound', async (key, value) => {
    expect((await judge({ [key]: value })).problem).toContain(key)
  })

  test('the caps at their bounds are accepted', async () => {
    expect((await judge({ ipHostnameMaxScanned: 1, ipHostnamePassiveMaxNames: 10000 })).problem).toBeNull()
    expect((await judge({ ipHostnameMaxScanned: 2000, ipHostnamePassiveMaxNames: 1 })).problem).toBeNull()
  })

  test('the policy applies only in IP mode', async () => {
    const domain = { ...STORED_IP, ipMode: false, targetIps: [] }
    expect((await judge({ ipHostnameMode: 'record_only' }, domain)).problem).toContain('only to IP-mode projects')
    expect((await judge({ ipHostnameInclude: ['*.example.com'] }, domain)).problem).toContain('only to IP-mode')
    expect((await judge({ ipHostnameScanAllConfirmed: true }, domain)).problem).toContain('only to IP-mode')
    expect((await judge({ ipHostnameMode: 'ip_only', ipHostnameInclude: [] }, domain)).problem).toBeNull()
  })

  test('leaving IP mode with a policy still set is judged too', async () => {
    const filtered = { ...STORED_IP, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }
    expect((await judge({ ipMode: false }, filtered)).problem).toContain('only to IP-mode')
  })
})

describe('normalization of the effective row', () => {
  test('filter entries become canonical tokens, deduplicated in operator order', async () => {
    const { problem, row } = await judge({
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com', ' APP.example.org. ', '*.example.com'],
      ipHostnameExclude: ['Old.Example.com'],
    })
    expect(problem).toBeNull()
    expect(row.ipHostnameInclude).toEqual(['*.example.com', 'app.example.org'])
    expect(row.ipHostnameExclude).toEqual(['old.example.com'])
  })

  test('leaving scan_all resets its confirmation', async () => {
    const all = { ...STORED_IP, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }
    const { problem, row } = await judge({ ipHostnameMode: 'record_only' }, all)
    expect(problem).toBeNull()
    expect(row.ipHostnameScanAllConfirmed).toBe(false)
  })

  test('scan_all keeps its confirmation', async () => {
    const { row } = await judge({ ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true })
    expect(row.ipHostnameScanAllConfirmed).toBe(true)
  })

  test('a refused row is not normalized', async () => {
    const { problem, row } = await judge({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com', '203.0.113.1'] })
    expect(problem).not.toBeNull()
    expect(row.ipHostnameInclude).toEqual(['*Example.com', '203.0.113.1'])
  })
})

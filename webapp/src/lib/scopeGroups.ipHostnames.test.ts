/**
 * The hostname policy helpers in scopeGroups.ts ("Hostnames on target IPs",
 * design §6.3 and §9): one answer for the form, the routes and the MCP tools.
 *
 * - widening: what the next policy may scan that the stored one did not. Over MCP
 *   it pauses the enabled schedules and, on a third-party engagement, needs an
 *   authorization record; the form only warns (D-24).
 * - narrowing: what the stored policy scanned that the next one may not admit,
 *   which runs the out_of_policy marker.
 * - change: any of the seven fields, which makes the save a scope change.
 * - start problem: what refuses a scheduled or queued start.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import { field, fingerprintFields, rescopableFields } from '@/lib/reconSettings/registry'
import {
  IP_HOSTNAME_DEFAULTS, IP_HOSTNAME_FIELDS, type ScopeFields, ipHostnameIncludeBases, ipHostnameModeOf,
  ipHostnamePolicyChanged, ipHostnamePolicyNarrowed, ipHostnamePolicyProblem, ipHostnamePolicySummary,
  ipHostnameStartProblem,
  ipHostnameWidenings, normalizeIpHostnamePolicy, scopeGuardrailNames, scopeStartProblem,
} from './scopeGroups'

const IP: ScopeFields = { ipMode: true, ipHostnameMode: 'record_only' }
const filter = (include: string[], extra: ScopeFields = {}): ScopeFields =>
  ({ ...IP, ipHostnameMode: 'record_filter', ipHostnameInclude: include, ...extra })

describe('the defaults and the field list', () => {
  test('the seven fields are the registry columns, defaults equal to Prisma', () => {
    for (const key of IP_HOSTNAME_FIELDS) {
      const spec = field(key)
      expect(spec, key).toBeDefined()
      expect(spec?.default, key).toEqual(IP_HOSTNAME_DEFAULTS[key])
      expect(spec?.mcp, key).toBe('create_only')
      expect(spec?.rescope, key).toBe(true)
    }
  })

  test('the cap bounds repeated by the rule are the registry bounds', () => {
    expect(field('ipHostnameMaxScanned')?.bounds).toEqual({ min: 1, max: 2000 })
    expect(field('ipHostnamePassiveMaxNames')?.bounds).toEqual({ min: 1, max: 10000 })
  })

  test('update_project_scope may change every one of them', () => {
    const rescopable = new Set(rescopableFields().map(f => f.key))
    for (const key of IP_HOSTNAME_FIELDS) expect(rescopable.has(key), key).toBe(true)
  })

  test.each(['full_recon', 'partial_recon'])(
    'a %s job queued before a policy change re-confirms: every field is in its fingerprint',
    (kind) => {
      const fp = new Set(fingerprintFields(kind))
      for (const key of IP_HOSTNAME_FIELDS) expect(fp.has(key), `${kind}: ${key}`).toBe(true)
    },
  )

  test('an unknown mode reads as ip_only', () => {
    expect(ipHostnameModeOf('scan_all')).toBe('scan_all')
    for (const raw of [undefined, null, '', 'SCAN_ALL', 3]) expect(ipHostnameModeOf(raw)).toBe('ip_only')
  })
})

describe('the hard-guardrail names of an IP project', () => {
  test('are the base names of its include entries, refused entries included', () => {
    expect(ipHostnameIncludeBases(['*.example.com', '*example.org', 'App.Example.net.', 'example.com', '203.0.113.1']))
      .toEqual(['example.com', 'example.org', 'app.example.net', '203.0.113.1'])
    expect(ipHostnameIncludeBases(null)).toEqual([])
    expect(ipHostnameIncludeBases(['', 7 as unknown as string])).toEqual([])
  })

  test('scopeGuardrailNames uses them in IP mode only', () => {
    expect(scopeGuardrailNames({ ipMode: true, ipHostnameInclude: ['*.example.com'] })).toEqual(['example.com'])
    expect(scopeGuardrailNames({ ipMode: true })).toEqual([])
    expect(scopeGuardrailNames({ targetDomain: 'example.org', ipHostnameInclude: ['*.example.com'] }))
      .toEqual(['example.org'])
  })
})

describe('start checks (scheduled and queued starts)', () => {
  test.each([
    ['record_only', {}, null],
    ['ip_only', {}, null],
    ['record_filter with an include entry', filter(['*.example.com']), null],
    ['scan_all confirmed', { ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }, null],
  ])('%s starts', (_name, extra, expected) => {
    expect(ipHostnameStartProblem({ ...IP, ...extra })).toBe(expected)
    expect(scopeStartProblem({ ...IP, ...extra })).toBe(expected)
  })

  test('scan_all without its confirmation is refused', () => {
    const p = scopeStartProblem({ ...IP, ipHostnameMode: 'scan_all' })
    expect(p?.message).toContain('not confirmed')
    expect(p?.invalid).toEqual([])
  })

  test('scan_all on a third-party engagement is refused', () => {
    expect(ipHostnameStartProblem({ ...IP, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true,
      engagementKind: 'third_party' })).toContain('third-party')
  })

  test('record_filter with no usable include entry is refused', () => {
    expect(ipHostnameStartProblem(filter([]))).toContain('no include entry')
    expect(ipHostnameStartProblem(filter(['*.co.uk', '203.0.113.1']))).toContain('no include entry')
  })

  test('a row without the columns (an older select) reads as ip_only and starts', () => {
    expect(scopeStartProblem({ ipMode: true, targetIps: ['203.0.113.1'] } as ScopeFields)).toBeNull()
  })
})

describe('widenings (design §9)', () => {
  test('ip_only -> record_only is no widening: lookups, no new target traffic', () => {
    expect(ipHostnameWidenings({ ...IP, ipHostnameMode: 'ip_only' }, IP)).toEqual([])
  })

  test.each([
    ['record_only', 'record_filter'], ['ip_only', 'record_filter'], ['record_only', 'scan_all'],
    ['record_filter', 'scan_all'],
  ])('%s -> %s is a widening', (from, to) => {
    const after = to === 'record_filter' ? filter(['*.example.com']) : { ...IP, ipHostnameMode: to }
    expect(ipHostnameWidenings({ ...IP, ipHostnameMode: from, ipHostnameInclude: ['*.example.com'] }, after))
      .toEqual([`hostname mode ${from} -> ${to}`])
  })

  test('entering IP mode with a scanning policy is a widening', () => {
    expect(ipHostnameWidenings({ ipMode: false }, filter(['*.example.com'])))
      .toEqual(['hostname mode ip_only -> record_filter'])
  })

  test('an include entry not covered by the old ones is a widening; a covered one is not', () => {
    const before = filter(['*.example.com'])
    expect(ipHostnameWidenings(before, filter(['*.example.com', 'app.example.com', '*.eu.example.com']))).toEqual([])
    expect(ipHostnameWidenings(before, filter(['*.example.com', 'example.com', '*.example.org']))).toEqual([
      'hostname include entry added: example.com', 'hostname include entry added: *.example.org',
    ])
  })

  test('removing an exclude entry is a widening, unless a remaining one still covers it', () => {
    const before = filter(['*.example.com'], { ipHostnameExclude: ['old.example.com', 'dev.example.com'] })
    expect(ipHostnameWidenings(before, filter(['*.example.com'], { ipHostnameExclude: ['dev.example.com'] })))
      .toEqual(['hostname exclude entry removed: old.example.com'])
    expect(ipHostnameWidenings(before, filter(['*.example.com'], { ipHostnameExclude: ['*.example.com'] }))).toEqual([])
  })

  test('turning passive expansion on, and raising either cap, are widenings', () => {
    const before = filter(['*.example.com'], { ipHostnamePassiveExpand: false })
    expect(ipHostnameWidenings(before, filter(['*.example.com'], { ipHostnamePassiveExpand: true })))
      .toEqual(['passive search of the include domains turned on'])
    const on = filter(['*.example.com'])
    expect(ipHostnameWidenings(on, filter(['*.example.com'], { ipHostnamePassiveMaxNames: 900, ipHostnameMaxScanned: 150 })))
      .toEqual(['ipHostnamePassiveMaxNames raised 500 -> 900', 'ipHostnameMaxScanned raised 100 -> 150'])
  })

  test('the scan cap counts under scan_all too; nothing counts where no name is scanned', () => {
    const all = { ...IP, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }
    expect(ipHostnameWidenings(all, { ...all, ipHostnameMaxScanned: 300 })).toEqual(['ipHostnameMaxScanned raised 100 -> 300'])
    expect(ipHostnameWidenings(IP, { ...IP, ipHostnameMaxScanned: 300, ipHostnameInclude: ['*.example.com'] })).toEqual([])
    expect(ipHostnameWidenings(filter(['*.example.com']), { ...IP, ipHostnameInclude: ['*.example.org'] })).toEqual([])
  })

  test('a domain project never widens a hostname policy', () => {
    expect(ipHostnameWidenings(IP, { ipMode: false, ipHostnameMode: 'scan_all' })).toEqual([])
  })
})

describe('narrowing (design §6.3)', () => {
  test('nothing scanned by name, nothing to narrow', () => {
    expect(ipHostnamePolicyNarrowed(IP, { ...IP, ipHostnameMode: 'ip_only' })).toBe(false)
    expect(ipHostnamePolicyNarrowed({ ipMode: false }, IP)).toBe(false)
  })

  test.each([
    ['scan_all -> record_filter', { ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }, filter(['*.example.com'])],
    ['record_filter -> record_only', filter(['*.example.com']), IP],
    ['record_filter -> ip_only', filter(['*.example.com']), { ...IP, ipHostnameMode: 'ip_only' }],
    ['leaving IP mode', filter(['*.example.com']), { ipMode: false }],
    ['an include entry removed', filter(['*.example.com', 'app.example.org']), filter(['*.example.com'])],
    ['an exclude entry added', filter(['*.example.com']), filter(['*.example.com'], { ipHostnameExclude: ['old.example.com'] })],
    ['the scan cap lowered', filter(['*.example.com']), filter(['*.example.com'], { ipHostnameMaxScanned: 10 })],
  ])('%s is a narrowing', (_name, before, after) => {
    expect(ipHostnamePolicyNarrowed({ ...IP, ...before }, { ...IP, ...after })).toBe(true)
  })

  test.each([
    ['record_filter -> scan_all', filter(['*.example.com']), { ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }],
    ['an include entry added', filter(['*.example.com']), filter(['*.example.com', '*.example.org'])],
    ['an include entry replaced by one that covers it', filter(['app.example.com']), filter(['*.example.com'])],
    ['an exclude entry removed', filter(['*.example.com'], { ipHostnameExclude: ['old.example.com'] }), filter(['*.example.com'])],
    ['the cap raised', filter(['*.example.com']), filter(['*.example.com'], { ipHostnameMaxScanned: 1000 })],
  ])('%s is not', (_name, before, after) => {
    expect(ipHostnamePolicyNarrowed({ ...IP, ...before }, { ...IP, ...after })).toBe(false)
  })
})

describe('edges the rule reads as defaults', () => {
  test('a row without the policy columns reads as ip_only with empty lists', () => {
    expect(ipHostnamePolicyProblem({ ipMode: true })).toBeNull()
    expect(ipHostnamePolicyProblem({ ipMode: false })).toBeNull()
    expect(ipHostnameStartProblem({ ipMode: true, ipHostnameMode: 'record_filter' })).toContain('no include entry')
  })

  test('normalization leaves a value that is not a list for the rule to refuse', () => {
    const row: Record<string, unknown> = { ipHostnameInclude: '*.example.com' }
    expect(normalizeIpHostnamePolicy(row)).toEqual([])
    expect(row.ipHostnameInclude).toBe('*.example.com')
  })

  test('an exclude entry added beside the old ones narrows; one an old entry covers does not', () => {
    const before = filter(['*.example.com'], { ipHostnameExclude: ['*.old.example.com'] })
    expect(ipHostnamePolicyNarrowed(before, filter(['*.example.com'],
      { ipHostnameExclude: ['*.old.example.com', 'dev.example.com'] }))).toBe(true)
    expect(ipHostnamePolicyNarrowed(before, filter(['*.example.com'],
      { ipHostnameExclude: ['*.old.example.com', 'a.old.example.com'] }))).toBe(false)
  })
})

describe('change detection', () => {
  test('a re-save in another spelling is no change', () => {
    expect(ipHostnamePolicyChanged(filter(['*.example.com', 'app.example.org']),
      filter(['APP.example.org.', '*example.com']))).toBe(false)
  })

  test.each(IP_HOSTNAME_FIELDS.map(k => [k]))('a change of %s is a change', (key) => {
    const before = { ...IP, ...IP_HOSTNAME_DEFAULTS }
    const value = {
      ipHostnameMode: 'record_only', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'],
      ipHostnamePassiveExpand: false, ipHostnameScanAllConfirmed: true, ipHostnameMaxScanned: 5,
      ipHostnamePassiveMaxNames: 5,
    }[key]
    expect(ipHostnamePolicyChanged(before, { ...before, [key]: value })).toBe(true)
  })

  test('absent columns read as the defaults', () => {
    expect(ipHostnamePolicyChanged({ ipMode: true }, { ipMode: true, ...IP_HOSTNAME_DEFAULTS })).toBe(false)
  })
})

describe('normalization and the summary', () => {
  test('canonical tokens, and no confirmation outside scan_all', () => {
    const row: Record<string, unknown> = {
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com'], ipHostnameExclude: ['old.example.com'],
      ipHostnameScanAllConfirmed: true,
    }
    expect(normalizeIpHostnamePolicy(row)).toEqual(['ipHostnameInclude', 'ipHostnameScanAllConfirmed'])
    expect(row).toMatchObject({ ipHostnameInclude: ['*.example.com'], ipHostnameScanAllConfirmed: false })
    expect(normalizeIpHostnamePolicy(row)).toEqual([])
  })

  test('the summary preflight_scope_check reports', () => {
    expect(ipHostnamePolicySummary(filter(['*.example.com']))).toEqual({
      ipHostnameMode: 'record_filter', include: ['*.example.com'], exclude: [], passiveExpand: true,
      scanAllConfirmed: false, maxScanned: 100, passiveMaxNames: 500,
    })
    expect(ipHostnamePolicySummary({ ipMode: true }).ipHostnameMode).toBe('ip_only')
  })
})

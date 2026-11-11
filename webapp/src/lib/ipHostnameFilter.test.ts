/**
 * The TS mirror of the hostname selection rule against the vectors the Python
 * rule (recon_settings/ip_hostnames.py) also reads, in the recon, orchestrator
 * and agent sections. A red vector here means the form preview would promise
 * something a run does not do.
 *
 * The Python suites assert that this file names the fixture path below, so a
 * moved fixture fails there instead of skipping here.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  IP_HOSTNAME_MODES, NOT_A_STRING, REASON_TEXT, canonicalIp, evaluatePreview, matches, normalizeName, parseEntries,
  type PreviewCandidate, type PreviewOptions,
} from './ipHostnameFilter'

const VECTORS = join(process.cwd(), '..', 'tests', 'fixtures', 'ip_hostname_vectors.json')

interface ParseVector {
  name: string; entries: unknown[]; patterns: string[]; invalid: [string, string][]
  psl?: { patterns: string[]; invalid: [string, string][] }
}
interface MatchVector {
  name: string; host: string; include: string[]; exclude: string[]
  included: boolean; excluded: boolean; matched_by: string | null
}
interface EvalInput {
  mode: string; include: string[] | null; exclude: string[] | null
  attribution: { shared_edge: string[]; failed: string[] | null } | null
  hard_blocked: string[]; roe_excluded: string[]; cap: number; wildcard_zone: string[] | null
  candidates: Record<string, { ips_seen?: string[]; org_domain?: unknown }>
}
interface EvalVector extends Partial<EvalInput> {
  name: string
  expect: { error?: true; selected?: string[]; reasons?: Record<string, string>; resolved?: Record<string, string[]> }
  /** What the last run recorded, when it differs from what evaluate() returns. */
  last_run?: Record<string, string>
  preview?: Record<string, string>
}
interface CanonicalVector { name: string; value: string; canonical: string }
interface Doc {
  modes: string[]; reason_codes: string[]; evaluate_defaults: EvalInput
  parse: ParseVector[]; match: MatchVector[]; address: { name: string }[]; canonical: CanonicalVector[]
  evaluate: EvalVector[]; post_probe: { name: string }[]
}

const doc: Doc | null = existsSync(VECTORS) ? JSON.parse(readFileSync(VECTORS, 'utf8')) : null

/** A vector as the preview sees it: each name carries the reason its last run
 *  recorded (`last_run`, else the reason the rule gives it) and the answer that
 *  run resolved it to, when it resolved it. */
function previewOf(v: EvalVector): { candidates: PreviewCandidate[]; opts: PreviewOptions } {
  const e = { ...doc!.evaluate_defaults, ...v } as EvalInput
  const reasons = { ...v.expect.reasons, ...v.last_run }
  const resolved = v.expect.resolved ?? {}
  const hard = new Set(e.hard_blocked)
  const roe = new Set(e.roe_excluded)
  return {
    candidates: Object.entries(e.candidates).map(([name, c]) => ({
      name, ipsSeen: c.ips_seen, orgDomain: c.org_domain as string | null | undefined, lastReason: reasons[name] ?? null,
      resolvedLast: resolved[name] ?? null,
    })),
    opts: {
      mode: e.mode, include: e.include, exclude: e.exclude, cap: e.cap,
      sharedEdge: e.attribution === null ? null : new Set(e.attribution.shared_edge),
      attributionFailed: e.attribution?.failed ? new Set(e.attribution.failed) : null,
      wildcardZone: e.wildcard_zone === null ? null : new Set(e.wildcard_zone),
      hardBlocked: n => hard.has(n), roeExcluded: n => roe.has(n),
    },
  }
}

describe.skipIf(!doc)('ip hostname rule: shared vectors', () => {
  const d = doc ?? {
    modes: [], reason_codes: [], parse: [], match: [], address: [], canonical: [], evaluate: [], post_probe: [],
  } as unknown as Doc

  test('the table is a real set', () => {
    const names = [...d.parse, ...d.match, ...d.address, ...d.canonical, ...d.evaluate, ...d.post_probe].map(v => v.name)
    expect(names.length).toBeGreaterThanOrEqual(80)
    expect(new Set(names).size).toBe(names.length)
  })

  test('the vocabulary is the rule\'s', () => {
    expect([...IP_HOSTNAME_MODES]).toEqual(d.modes)
    expect(Object.keys(REASON_TEXT)).toEqual(d.reason_codes)
  })

  test.each(d.parse.map(v => [v.name, v] as const))('parse %s', (_name, v) => {
    const want = v.psl ?? v
    const got = parseEntries(v.entries)
    expect(got.patterns.map(p => p.token)).toEqual(want.patterns)
    expect(got.invalid.map(i => [i.entry, i.reason])).toEqual(want.invalid)
  })

  test.each(d.match.map(v => [v.name, v] as const))('match %s', (_name, v) => {
    const r = matches(v.host, parseEntries(v.include).patterns, parseEntries(v.exclude).patterns)
    expect([r.included, r.excluded, r.matchedBy]).toEqual([v.included, v.excluded, v.matched_by])
  })

  test.each(d.canonical.map(v => [v.name, v] as const))('canonical %s', (_name, v) => {
    expect(canonicalIp(v.value)).toBe(v.canonical)
  })

  test.each(d.evaluate.map(v => [v.name, v] as const))('evaluate %s', (_name, v) => {
    const { candidates, opts } = previewOf(v)
    if (v.expect.error) {
      expect(() => evaluatePreview(candidates, opts)).toThrow(/recording mode/)
      return
    }
    const want = { ...v.expect.reasons, ...v.preview }
    const got = evaluatePreview(candidates, opts)
    expect(got.reasons).toEqual(want)
    expect(got.selected).toEqual(Object.keys(want).filter(n => want[n] === 'scanned').sort())
  })
})

describe('normalizeName', () => {
  test('canonical names pass; addresses, wildcards, placeholders and non-strings do not', () => {
    expect(normalizeName('APP.Example.com.')).toBe('app.example.com')
    expect(normalizeName('co.uk')).toBe('co.uk')
    for (const bad of ['203.0.113.10', '*.example.com', 'a*b.example.com', '203-0-113-10', 'intranet', '', 42, null]) {
      expect(normalizeName(bad)).toBeNull()
    }
  })
})

describe('matches', () => {
  test('exclude wins and names the deciding entry', () => {
    const inc = parseEntries(['*.example.com']).patterns
    const exc = parseEntries(['old.example.com']).patterns
    expect(matches('old.example.com', inc, exc)).toEqual({ included: false, excluded: true, matchedBy: 'old.example.com' })
    expect(matches('app.example.com', inc, exc)).toEqual({ included: true, excluded: false, matchedBy: '*.example.com' })
  })
})

describe('evaluatePreview', () => {
  const base: PreviewOptions = {
    mode: 'record_filter', include: ['*.example.com'], exclude: [], cap: 100,
    sharedEdge: new Set(), attributionFailed: new Set(), wildcardZone: new Set(),
    hardBlocked: () => false, roeExcluded: () => false,
  }
  const cand = (name: string, lastReason?: string | null, ipsSeen?: string[]): PreviewCandidate =>
    ({ name, ipsSeen, orgDomain: 'example.com', lastReason })

  test('a name with no DNS history would be scanned, DNS checked at run time', () => {
    expect(evaluatePreview([cand('app.example.com')], base)).toEqual({
      selected: ['app.example.com'], reasons: { 'app.example.com': 'scanned' },
    })
  })

  test('a last-run DNS reason is shown; a last-run selection outcome is recomputed', () => {
    const got = evaluatePreview([
      cand('a.example.com', 'resolves_outside_targets'), cand('b.example.com', 'cap_reached'),
      cand('c.example.com', 'filter_no_match'), cand('d.example.com', 'out_of_policy'),
    ], { ...base, cap: 2 })
    expect(got.reasons).toEqual({
      'a.example.com': 'resolves_outside_targets', 'b.example.com': 'scanned',
      'c.example.com': 'scanned', 'd.example.com': 'cap_reached',
    })
  })

  test('a wildcard-zone verdict is only kept where wildcard control runs', () => {
    const c = [cand('app.example.com', 'wildcard_zone', ['203.0.113.10'])]
    expect(evaluatePreview(c, base).reasons['app.example.com']).toBe('wildcard_zone')
    expect(evaluatePreview(c, { ...base, mode: 'scan_all' }).reasons['app.example.com']).toBe('scanned')
  })

  test('scan_all compares IPs canonically, as the Python rule does', () => {
    const opts = { ...base, mode: 'scan_all', sharedEdge: new Set(['2001:db8:0::20']) }
    const reason = (ips: string[], o: PreviewOptions = opts) =>
      evaluatePreview([cand('a.example.com', null, ips)], o).reasons['a.example.com']
    expect(reason([' 2001:DB8::0020 '])).toBe('shared_edge_ip')
    expect(reason(['2001:db8::21'])).toBe('scanned')
    expect(reason([])).toBe('attribution_unavailable')
    expect(reason(['2001:db8::11'], { ...opts, attributionFailed: new Set(['2001:0db8::11']) }))
      .toBe('attribution_unavailable')
  })

  test('scan_all also refuses a name its last answer put on a shared-edge target (check 9)', () => {
    const opts = { ...base, mode: 'scan_all', sharedEdge: new Set(['2001:db8:0::20', '203.0.113.20']) }
    const reason = (resolvedLast: unknown, o: PreviewOptions = opts) => evaluatePreview(
      [{ ...cand('a.example.com', null, ['203.0.113.10']), resolvedLast: resolvedLast as string[] }], o,
    ).reasons['a.example.com']
    expect(reason(['203.0.113.10', '203.0.113.20'])).toBe('shared_edge_ip')
    expect(reason([' 2001:DB8::20 '])).toBe('shared_edge_ip')
    expect(reason('203.0.113.20')).toBe('shared_edge_ip')
    expect(reason(['203.0.113.11'])).toBe('scanned')
    expect(reason(null)).toBe('scanned')
    // An answer nobody can read is not known to be off the edge: refused.
    expect(reason(['203.0.113.11', 42])).toBe('shared_edge_ip')
    // The edge rule is M1's, on the answer as on the IPs seen.
    expect(reason(['203.0.113.20'], { ...opts, mode: 'record_filter' })).toBe('scanned')
    // Attribution that never ran comes first.
    expect(reason(['203.0.113.20'], { ...opts, sharedEdge: null })).toBe('attribution_unavailable')
  })

  test('a last-run shared_edge_ip is kept in scan_all only: it came from where the name pointed', () => {
    const c = [cand('a.example.com', 'shared_edge_ip', ['203.0.113.10'])]
    expect(evaluatePreview(c, { ...base, mode: 'scan_all' }).reasons['a.example.com']).toBe('shared_edge_ip')
    expect(evaluatePreview(c, base).reasons['a.example.com']).toBe('scanned')
  })

  test('scan_all fails closed when failed attribution is unknown; other modes ignore it', () => {
    const c = [cand('a.example.com', null, ['203.0.113.10'])]
    expect(evaluatePreview(c, { ...base, mode: 'scan_all', attributionFailed: null }).reasons['a.example.com'])
      .toBe('attribution_unavailable')
    expect(evaluatePreview(c, { ...base, attributionFailed: null }).reasons['a.example.com']).toBe('scanned')
  })

  test('the checks pass only on a literal false; anything else, or a throw, refuses', () => {
    const one = [cand('a.example.com')]
    const notFalse = [true, null, undefined, 0, '', 'no', [false, '']] as unknown as boolean[]
    for (const v of notFalse) {
      expect(evaluatePreview(one, { ...base, hardBlocked: () => v }).reasons['a.example.com']).toBe('hard_blocked')
      expect(evaluatePreview(one, { ...base, roeExcluded: () => v }).reasons['a.example.com']).toBe('roe_excluded')
    }
    const boom = () => { throw new Error('guardrail unavailable') }
    expect(evaluatePreview(one, { ...base, hardBlocked: boom }).reasons['a.example.com']).toBe('hard_blocked')
    expect(evaluatePreview(one, { ...base, roeExcluded: boom }).reasons['a.example.com']).toBe('roe_excluded')
  })

  test('unknown inputs refuse: filter lists, wildcard control, org domain, IPs seen', () => {
    const one = (c: PreviewCandidate, o: Partial<PreviewOptions> = {}) =>
      evaluatePreview([c], { ...base, ...o }).reasons[c.name]
    expect(one(cand('a.example.com'), { include: null })).toBe('invalid_filter')
    expect(one(cand('a.example.com'), { exclude: null })).toBe('invalid_filter')
    expect(one(cand('a.example.com'), { exclude: [null, 'a.example.com'] })).toBe('invalid_filter')
    expect(one(cand('a.example.com'), { wildcardZone: null })).toBe('wildcard_zone')
    expect(one(cand('a.example.com'), { wildcardZone: new Set(['a.example.com']) })).toBe('wildcard_zone')
    expect(one(cand('a.example.com', null, ['203.0.113.10']), { mode: 'scan_all', wildcardZone: null, include: null }))
      .toBe('scanned')
    expect(one({ name: 'a.example.com', orgDomain: 42 as unknown as string })).toBe('no_registrable_domain')
    expect(one({ name: 'a.example.com', orgDomain: 'example.com' }, { mode: 'scan_all' })).toBe('attribution_unavailable')
  })

  test('a cap is read only as a finite number', () => {
    const two = [cand('a.example.com'), cand('b.example.com')]
    for (const cap of [Infinity, NaN, '1', true, null] as unknown as number[]) {
      expect(evaluatePreview(two, { ...base, cap }).selected).toEqual([])
    }
  })

  test('IP lists: one string is one address; an unreadable entry makes the list unknown', () => {
    const one = (c: PreviewCandidate, o: Partial<PreviewOptions>) =>
      evaluatePreview([c], { ...base, mode: 'scan_all', ...o }).reasons[c.name]
    const asSet = (v: unknown) => v as ReadonlySet<string>
    expect(one(cand('a.example.com', null, ['203.0.113.20']), { sharedEdge: asSet('203.0.113.20') })).toBe('shared_edge_ip')
    expect(one(cand('a.example.com', null, ['203.0.113.20']), { attributionFailed: asSet('203.0.113.20') }))
      .toBe('attribution_unavailable')
    expect(one({ name: 'a.example.com', orgDomain: 'example.com', ipsSeen: '203.0.113.20' as unknown as string[] },
      { sharedEdge: new Set(['203.0.113.20']) })).toBe('shared_edge_ip')
    expect(one(cand('a.example.com', null, ['203.0.113.10']), { sharedEdge: asSet(['203.0.113.20', null]) }))
      .toBe('attribution_unavailable')
    expect(one(cand('a.example.com', null, ['203.0.113.10', 42 as unknown as string]), {})).toBe('attribution_unavailable')
    expect(evaluatePreview([cand('a.example.com')], { ...base, wildcardZone: asSet('a.example.com') })
      .reasons['a.example.com']).toBe('wildcard_zone')
  })

  test('a non-string filter entry is refused once, never skipped', () => {
    expect(parseEntries(['*.example.com', null, 42])).toEqual({
      patterns: [{ host: 'example.com', wildcard: true, token: '*.example.com' }],
      invalid: [{ entry: NOT_A_STRING, reason: 'not_hostname' }],
    })
  })

  test('a moved_during_scan last run is shown until DNS is checked again', () => {
    expect(evaluatePreview([cand('a.example.com', 'moved_during_scan')], base).reasons['a.example.com'])
      .toBe('moved_during_scan')
  })

  test('a duplicated name is evaluated once, and the order of input does not matter', () => {
    const one = evaluatePreview([cand('b.example.com'), cand('a.example.com'), cand('a.example.com')], { ...base, cap: 1 })
    expect(one).toEqual({ selected: ['a.example.com'], reasons: { 'a.example.com': 'scanned', 'b.example.com': 'cap_reached' } })
  })

  test('a negative or fractional cap is floored at zero', () => {
    expect(evaluatePreview([cand('a.example.com')], { ...base, cap: -1 }).selected).toEqual([])
    expect(evaluatePreview([cand('a.example.com'), cand('b.example.com')], { ...base, cap: 1.9 }).selected)
      .toEqual(['a.example.com'])
  })

  test('every reason has words for the UI', () => {
    for (const text of Object.values(REASON_TEXT)) expect(text.length).toBeGreaterThan(0)
  })
})

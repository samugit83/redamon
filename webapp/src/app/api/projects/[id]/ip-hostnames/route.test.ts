/**
 * GET /api/projects/[id]/ip-hostnames: the names the last run found on an
 * IP-mode project's addresses (04_ui_spec.md §2 "Route", §7).
 *
 * Pins who may read it (401 / 404, as every project route), that every graph
 * MATCH carries the tenant key (user_id AND project_id), the response shape,
 * the paging with exact server-side totals, an unsaved policy judged on
 * request, and design §6.3: the scanned list drops a name the CURRENT policy no
 * longer admits.
 *
 * Run: npx vitest run 'src/app/api/projects/[id]/ip-hostnames/route.test.ts'
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  findUnique: vi.fn(),
  runs: [] as { query: string; params: Record<string, unknown> }[],
  names: [] as Record<string, unknown>[],
  context: {} as Record<string, unknown>,
  fail: null as Error | null,
  closed: 0,
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: (...a: unknown[]) => h.requireProjectAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))

const record = (row: Record<string, unknown>) => ({ get: (k: string) => row[k] })
vi.mock('@/app/api/graph/neo4j', () => ({
  // Only run(): the wrapper's query timeout is on run(), and the read must use it.
  getGraphSession: () => ({
    run: async (query: string, params: Record<string, unknown>) => {
      if (h.fail) throw h.fail
      h.runs.push({ query, params })
      return query.includes('UNION ALL')
        ? { records: h.names.map(record) }
        : { records: [record(h.context)] }
    },
    close: async () => { h.closed += 1 },
  }),
}))

import { GET } from './route'

const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const params = (id = 'p1') => ({ params: Promise.resolve({ id }) })
const get = (qs = '') => GET(new NextRequest(`http://x/api/projects/p1/ip-hostnames${qs ? `?${qs}` : ''}`), params())

const ROW = {
  id: 'p1', userId: 'owner', ipMode: true, roeExcludedHosts: [],
  ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'],
  ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100,
  ipHostnamePassiveMaxNames: 500,
}

const recorded = (name: string, over: Record<string, unknown> = {}) => ({
  name, reason: 'filter_no_match', org: name.split('.').slice(-2).join('.'), sources: ['tlsx_san'],
  ips: ['203.0.113.10'], lastSeen: null, evaluatedAt: '2026-11-10T10:00:00Z', kind: 'recorded', ...over,
})
const scanned = (name: string, over: Record<string, unknown> = {}) => ({
  ...recorded(name), reason: 'scanned', sources: ['ptr'], kind: 'scanned', ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.runs = []
  h.fail = null
  h.closed = 0
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.findUnique.mockResolvedValue(ROW)
  h.names = [
    scanned('app.example.com'),
    recorded('blog.other.test', { org: 'other.test', sources: ['shodan'] }),
    recorded('old.example.com', { reason: 'filter_excluded', sources: ['otx_passive_dns'], lastSeen: '2026-10-30' }),
    recorded('split.example.com', { reason: 'resolves_outside_targets' }),
    recorded('www.example.com', { reason: 'record_only', ips: ['203.0.113.11'] }),
  ]
  h.context = {
    ipCount: 2, sharedEdge: [], attributionFailed: [], attributed: 2, lastRunMode: 'record_filter',
    legacyNames: 0, seenEdges: 4,
  }
})

describe('who may read it', () => {
  test('unauthenticated: 401, nothing read', async () => {
    h.requireEff.mockResolvedValue(UNAUTH)
    const res = await get()
    expect(res.status).toBe(401)
    expect(h.findUnique).not.toHaveBeenCalled()
    expect(h.runs).toEqual([])
  })

  test("another user's project: 404 Not found, nothing read (anti-enumeration)", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await get()
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Not found' })
    expect(h.findUnique).not.toHaveBeenCalled()
    expect(h.runs).toEqual([])
  })

  test('the access check is asked about the project in the path', async () => {
    await get()
    expect(h.requireProjectAccess).toHaveBeenCalledWith({ userId: 'owner' }, 'p1')
  })
})

describe('the tenant key', () => {
  test('every query runs with the owner and the project, and every node pattern carries both keys', async () => {
    expect((await get()).status).toBe(200)
    expect(h.runs.length).toBe(2)
    for (const { query, params: p } of h.runs) {
      expect(p).toEqual({ uid: 'owner', pid: 'p1' })
      const patterns = [...query.matchAll(/\(\s*\w*\s*:\s*(\w+)\s*\{([^}]*)\}/g)]
      expect(patterns.length).toBeGreaterThan(0)
      for (const [whole, , body] of patterns) {
        expect(body, whole).toMatch(/user_id:\s*\$uid/)
        expect(body, whole).toMatch(/project_id:\s*\$pid/)
      }
    }
  })

  test('the session is closed after the read, and after a failure', async () => {
    await get()
    h.fail = Object.assign(new Error('connection refused to bolt://neo4j:7687 for app.example.com'), {
      code: 'ServiceUnavailable',
    })
    const res = await get()
    expect(h.closed).toBe(2)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.code).toBe('ServiceUnavailable')
    expect(JSON.stringify(body)).not.toContain('app.example.com')
  })
})

describe('the response', () => {
  test('shape: mode, page of names, scanned list, totals', async () => {
    const body = await (await get()).json()
    expect(Object.keys(body).sort()).toEqual([
      'evaluatedAt', 'evaluatedMode', 'hasRun', 'lastRunMode', 'legacy', 'mode', 'nextCursor', 'recorded',
      'scanned', 'totals',
    ])
    expect(body.mode).toBe('record_filter')
    expect(body.recorded[0]).toEqual({
      name: 'app.example.com', ips: ['203.0.113.10'], sources: ['ptr'], reason: 'scanned', last_seen: null,
      kind: 'scanned', result: 'scanned', seen: [],
    })
    expect(body.recorded.map((r: { name: string }) => r.name)).toEqual([
      'app.example.com', 'blog.other.test', 'old.example.com', 'split.example.com', 'www.example.com',
    ])
    expect(body.evaluatedAt).toBe('2026-11-10T10:00:00Z')
  })

  test('results follow the saved filters; DNS reasons come from the last run', async () => {
    const body = await (await get()).json()
    const result = Object.fromEntries(body.recorded.map((r: { name: string; result: string }) => [r.name, r.result]))
    expect(result).toEqual({
      'app.example.com': 'scanned',
      'blog.other.test': 'filter_no_match',
      'old.example.com': 'filter_excluded',
      'split.example.com': 'resolves_outside_targets',
      'www.example.com': 'scanned',
    })
    expect(body.totals).toMatchObject({ found: 5, recorded: 4, scanned: 1, wouldScan: 2, matching: 5 })
    expect(body.totals.byReason).toEqual({
      scanned: 2, filter_no_match: 1, filter_excluded: 1, resolves_outside_targets: 1,
    })
    expect(body.totals.byIp).toEqual({ '203.0.113.10': 4, '203.0.113.11': 1 })
  })

  test('the scanned list drops a name the current policy no longer admits (design §6.3)', async () => {
    h.names = [scanned('app.example.com'), scanned('shop.example.de')]
    const body = await (await get()).json()
    expect(body.scanned).toEqual([{ name: 'app.example.com', ips: ['203.0.113.10'] }])
    expect(body.totals.scanned).toBe(1)
  })

  test('record_only and ip_only admit no scanned name', async () => {
    h.names = [scanned('app.example.com')]
    for (const mode of ['record_only', 'ip_only']) {
      h.findUnique.mockResolvedValue({ ...ROW, ipHostnameMode: mode })
      const body = await (await get()).json()
      expect(body.scanned).toEqual([])
    }
  })

  test('an unsaved policy is judged when the caller sends one', async () => {
    const body = await (await get('mode=record_filter&include=*.other.test&include=*.example.com&cap=1')).json()
    expect(body.mode).toBe('record_filter')
    const result = Object.fromEntries(body.recorded.map((r: { name: string; result: string }) => [r.name, r.result]))
    // The cap keeps the first passing name in sorted order; old.example.com is
    // no longer excluded in this draft.
    expect(result['app.example.com']).toBe('scanned')
    expect(result['blog.other.test']).toBe('cap_reached')
    expect(result['old.example.com']).toBe('cap_reached')
    expect(body.totals.wouldScan).toBe(1)
    // The scanned list still follows the SAVED policy, as every reader of it does.
    expect(body.scanned.map((s: { name: string }) => s.name)).toEqual(['app.example.com'])
  })

  test('a draft ip_only judges nothing', async () => {
    const body = await (await get('mode=ip_only')).json()
    expect(body.evaluatedMode).toBe('ip_only')
    expect(body.recorded.every((r: { result: unknown }) => r.result === null)).toBe(true)
    expect(body.totals.wouldScan).toBe(0)
  })

  test('a project that is not in IP mode: 400 with the reason', async () => {
    h.findUnique.mockResolvedValue({ ...ROW, ipMode: false })
    const res = await get()
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/IP-mode projects only/)
    expect(h.runs).toEqual([])
  })

  test('legacy: real names under the mock root, no SEEN_ON and no run-mode stamp', async () => {
    h.names = []
    h.context = { ...h.context, legacyNames: 3, seenEdges: 0, lastRunMode: null }
    expect((await (await get()).json()).legacy).toBe(true)
    h.context = { ...h.context, lastRunMode: 'ip_only' }
    expect((await (await get()).json()).legacy).toBe(false)
    h.context = { ...h.context, legacyNames: 0, lastRunMode: null }
    expect((await (await get()).json()).legacy).toBe(false)
  })
})

describe('paging and filters (totals stay exact)', () => {
  beforeEach(() => {
    h.names = Array.from({ length: 7 }, (_, i) => recorded(`n${i}.example.com`, { reason: 'record_only' }))
  })

  test('limit, cursor and nextCursor walk the names in order', async () => {
    const first = await (await get('limit=3')).json()
    expect(first.recorded.map((r: { name: string }) => r.name)).toEqual(['n0.example.com', 'n1.example.com', 'n2.example.com'])
    expect(first.nextCursor).toBe('n2.example.com')
    expect(first.totals.found).toBe(7)
    const last = await (await get('limit=3&cursor=n5.example.com')).json()
    expect(last.recorded.map((r: { name: string }) => r.name)).toEqual(['n6.example.com'])
    expect(last.nextCursor).toBeNull()
    expect(last.totals.found).toBe(7)
  })

  test('limit defaults to 100 and is capped at 500', async () => {
    h.names = Array.from({ length: 620 }, (_, i) => recorded(`h${String(i).padStart(4, '0')}.example.com`))
    expect((await (await get()).json()).recorded).toHaveLength(100)
    const big = await (await get('limit=5000')).json()
    expect(big.recorded).toHaveLength(500)
    expect(big.totals.found).toBe(620)
  })

  test('a bad limit, mode or cap is a 400', async () => {
    for (const qs of ['limit=0', 'limit=abc', 'mode=everything', 'mode=record_filter&cap=0', 'mode=record_filter&cap=9999']) {
      expect((await get(qs)).status, qs).toBe(400)
    }
    const tooMany = Array.from({ length: 201 }, (_, i) => `include=a${i}.example.com`).join('&')
    expect((await get(`mode=record_filter&${tooMany}`)).status).toBe(400)
  })

  test('reason and q narrow the rows, never the totals', async () => {
    h.names = [scanned('app.example.com'), recorded('blog.other.test'), recorded('shop.example.de')]
    const byReason = await (await get('reason=filter_no_match')).json()
    expect(byReason.recorded.map((r: { name: string }) => r.name)).toEqual(['blog.other.test', 'shop.example.de'])
    expect(byReason.totals).toMatchObject({ found: 3, matching: 2 })
    const byText = await (await get('q=SHOP')).json()
    expect(byText.recorded.map((r: { name: string }) => r.name)).toEqual(['shop.example.de'])
    expect(byText.totals).toMatchObject({ found: 3, matching: 1 })
  })
})

describe('one name, with its per-IP evidence (the node drawer)', () => {
  test('name= returns exactly that name, with each SEEN_ON edge', async () => {
    h.names = [
      recorded('a.example.com'),
      recorded('data.example.com', {
        ips: ['203.0.113.10', '203.0.113.11'],
        seen: [
          { ip: '203.0.113.10', sources: ['tlsx_san'], first_seen: '2026-01-02', last_seen: '2026-10-30',
            resolves_here: true, cert_covers: true },
          { ip: '203.0.113.11', sources: ['otx_passive_dns'], first_seen: null, last_seen: null,
            resolves_here: false, cert_covers: null },
        ],
      }),
    ]
    const body = await (await get('name=DATA.example.com')).json()
    expect(body.recorded.map((r: { name: string }) => r.name)).toEqual(['data.example.com'])
    expect(body.recorded[0].seen).toEqual([
      { ip: '203.0.113.10', sources: ['tlsx_san'], first_seen: '2026-01-02', last_seen: '2026-10-30',
        resolves_here: true, cert_covers: true },
      { ip: '203.0.113.11', sources: ['otx_passive_dns'], first_seen: null, last_seen: null,
        resolves_here: false, cert_covers: null },
    ])
    expect(body.totals.found).toBe(2)
  })

  test('the recorded-name query collects the edge evidence, keyed on the tenant', async () => {
    await get()
    const names = h.runs.find(r => r.query.includes('UNION ALL'))!.query
    expect(names).toMatch(/resolves_here: r\.resolves_here/)
    expect(names).toMatch(/cert_covers: r\.cert_covers/)
    expect(names).toMatch(/\[s IN collect\(\{ip: i\.address/)
  })
})

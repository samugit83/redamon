/**
 * Unit tests for buildTrafficWhere — the tenant-scoped Prisma where builder that
 * backs GET /api/traffic/[projectId]. Pure function; no DB. Covers filter
 * translation, the status-class ranges, the invalid-date guard (regression: an
 * unparseable ?from must NOT reach Prisma and 500), and the invariant that the
 * tenant's id (the project's owner, which the routes take from the guard's
 * access: trafficTenant.ts, step 4.9) always scopes the query.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/traffic/[projectId]/buildTrafficWhere.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

// buildTrafficWhere doesn't touch prisma/access, but route.ts imports them at
// module load, so stub them to avoid instantiating a real client.
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(),
  requireProjectAccess: vi.fn(),
}))

import { buildTrafficWhere } from './route'

const PID = 'proj-123'
const OWNER = 'owner-abc'

function where(qs: string) {
  return buildTrafficWhere(PID, OWNER, new URLSearchParams(qs))
}

describe('buildTrafficWhere', () => {
  test('always scopes to project + the tenant (owner) id', () => {
    const w = where('')
    expect(w.projectId).toBe(PID)
    expect(w.userId).toBe(OWNER)
  })

  test('source=both is not added as a filter', () => {
    expect(where('source=both').source).toBeUndefined()
  })

  test('source=recon narrows source', () => {
    expect(where('source=recon').source).toBe('recon')
  })

  test('tool csv becomes an in-list', () => {
    expect(where('tool=httpx,katana').tool).toEqual({ in: ['httpx', 'katana'] })
  })

  test.each([
    ['2xx', { gte: 200, lt: 300 }],
    ['3xx', { gte: 300, lt: 400 }],
    ['4xx', { gte: 400, lt: 500 }],
    ['5xx', { gte: 500, lt: 600 }],
  ])('statusClass=%s -> range', (cls, range) => {
    expect(where(`statusClass=${cls}`).statusCode).toEqual(range)
  })

  test('only5xx overrides statusCode', () => {
    expect(where('only5xx=true').statusCode).toEqual({ gte: 500, lt: 600 })
  })

  test('q searches host+path case-insensitively', () => {
    const w = where('q=admin')
    expect(w.OR).toEqual([
      { host: { contains: 'admin', mode: 'insensitive' } },
      { path: { contains: 'admin', mode: 'insensitive' } },
    ])
  })

  test('host/method/sessionId/runId pass through', () => {
    const w = where('host=x.example.com&method=POST&sessionId=s1&runId=r1')
    expect(w.host).toBe('x.example.com')
    expect(w.method).toBe('POST')
    expect(w.sessionId).toBe('s1')
    expect(w.runId).toBe('r1')
  })

  test('quick toggles', () => {
    const w = where('hasSetCookie=true&reflected=true')
    expect(w.hasSetCookie).toBe(true)
    expect(w.reflectedParams).toBe(true)
  })

  test('bodyq sets the ILIKE fallback over resp_body (Phase 3)', () => {
    expect(where('bodyq=stack+trace').respBody).toEqual({ contains: 'stack trace', mode: 'insensitive' })
    expect(where('').respBody).toBeUndefined()
  })

  test('valid date range sets gte/lte', () => {
    const w = where('from=2026-07-01&to=2026-07-19')
    const s = w.startedAt as { gte?: Date; lte?: Date }
    expect(s.gte).toBeInstanceOf(Date)
    expect(s.lte).toBeInstanceOf(Date)
    // to is inclusive end-of-day
    expect(s.lte?.getUTCHours()).toBe(23)
  })

  test('REGRESSION: unparseable from/to is ignored, no startedAt filter', () => {
    expect(where('from=not-a-date').startedAt).toBeUndefined()
    expect(where('to=garbage').startedAt).toBeUndefined()
  })

  test('client cannot smuggle a different userId via query', () => {
    // No query param can override the tenant argument.
    const w = where('userId=ATTACKER&user_id=ATTACKER')
    expect(w.userId).toBe(OWNER)
  })
})

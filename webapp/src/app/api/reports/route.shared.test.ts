/**
 * GET /api/reports with shares (step 4.5, SH-39): the reports of every project the effective user
 * sees, so a shared project's reports list beside the person's own, until the share ends; with
 * sharing not in force only the owned projects' reports, as before. Real visibleProjects, flags,
 * clock and policy over an evaluating database double (projectListDb.ts).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/reports/route.shared.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { emptyProjectListState, projectListPrisma, type ProjectListState } from '@/lib/authz/__testing__/projectListDb'

const h = vi.hoisted(() => ({ db: null as unknown, eff: { userId: 'bob' } as { userId: string } }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }) }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: vi.fn(async () => h.eff) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'

const NOW = new Date('2026-11-13T12:00:00Z')

let state: ProjectListState

async function reportIds(): Promise<string[]> {
  const res = await GET(new NextRequest('http://redamon.test/api/reports'))
  expect(res.status).toBe(200)
  return ((await res.json()) as Array<{ id: string }>).map((r) => r.id)
}

beforeEach(() => {
  state = emptyProjectListState()
  state.users = [{ id: 'alice', status: 'active' }, { id: 'bob', status: 'active' }, { id: 'carol', status: 'active' }]
  state.projects = [{ id: 'p-bob', userId: 'bob', name: 'mine' }, { id: 'p-alice', userId: 'alice', name: 'shared' }, { id: 'p-carol', userId: 'carol', name: 'other' }]
  state.shares = [{ projectId: 'p-alice', userId: 'bob', access: 'read', rawData: false, expiresAt: new Date(NOW.getTime() + 60_000) }]
  state.reports = [
    { id: 'r-bob', projectId: 'p-bob', title: 'mine', createdAt: new Date(1) },
    { id: 'r-alice', projectId: 'p-alice', title: 'shared', createdAt: new Date(2) },
    { id: 'r-carol', projectId: 'p-carol', title: 'other', createdAt: new Date(3) },
  ]
  h.db = projectListPrisma(state)
  h.eff = { userId: 'bob' }
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

test('reports of a shared project listed, with their project', async () => {
  const res = await GET(new NextRequest('http://redamon.test/api/reports'))
  const body = await res.json() as Array<{ id: string; project: { id: string; name: string } }>
  expect(body.map((r) => r.id)).toEqual(['r-alice', 'r-bob'])
  expect(body[0].project).toMatchObject({ id: 'p-alice', name: 'shared' })
})

test('the share ends (expired on the clock): its reports leave the list', async () => {
  setNowForTests(() => new Date(NOW.getTime() + 60_000))
  expect(await reportIds()).toEqual(['r-bob'])
})

describe('sharing not in force', () => {
  test.each([
    ['the switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the policy disabled', { identity: true, permissions: true, sharing: true }, {}],
  ])('%s: only the owned projects\' reports', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    state.policy = policy
    expect(await reportIds()).toEqual(['r-bob'])
  })
})


test('project and date filters retain the visible-project restriction', async () => {
  const other = await GET(new NextRequest('http://redamon.test/api/reports?projectId=p-carol'))
  expect(await other.json()).toEqual([])
  const shared = await GET(new NextRequest('http://redamon.test/api/reports?projectId=p-alice&from=1970-01-01T00:00:00.002Z&to=1970-01-01T00:00:00.002Z'))
  expect((await shared.json()).map((r: { id: string }) => r.id)).toEqual(['r-alice'])
})

test.each(['limit=0', 'limit=201', 'limit=1.5', 'cursor=', 'projectId=', 'from=bad', 'to=2026-02-30'])('rejects invalid query %s', async (query) => {
  const res = await GET(new NextRequest(`http://redamon.test/api/reports?${query}`))
  expect(res.status).toBe(400)
  expect(await res.json()).toEqual({ error: 'Invalid query parameters', code: 'invalid_query' })
})

test('uses the default and maximum limits and returns a cursor only when more rows exist', async () => {
  const db = h.db as { report: { findMany: ReturnType<typeof vi.fn> } }
  const rows = Array.from({ length: 101 }, (_, i) => ({ id: `r-${i}` }))
  const findMany = vi.spyOn(db.report, 'findMany').mockResolvedValue(rows)
  const first = await GET(new NextRequest('http://redamon.test/api/reports'))
  expect(await first.json()).toHaveLength(100)
  expect(first.headers.get('X-Next-Cursor')).toBe('r-99')
  expect(findMany).toHaveBeenLastCalledWith(expect.objectContaining({ take: 101, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }] }))
  findMany.mockResolvedValue([{ id: 'last' }])
  const last = await GET(new NextRequest('http://redamon.test/api/reports?limit=200&cursor=r-99'))
  expect(await last.json()).toEqual([{ id: 'last' }])
  expect(last.headers.get('X-Next-Cursor')).toBeNull()
  expect(findMany).toHaveBeenLastCalledWith(expect.objectContaining({ take: 201, skip: 1, cursor: { id: 'r-99' } }))
})

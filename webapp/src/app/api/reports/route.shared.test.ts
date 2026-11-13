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

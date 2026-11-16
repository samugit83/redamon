/**
 * GET/DELETE /api/users/[id]/tradecraft-resources/[resourceId]/jobs: the job view, and Cancel.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { stubAgent } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb, denied: null as Response | null }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))

import { setNowForTests } from '@/lib/authz/clock'
import { GET, DELETE } from './route'
import { requireUserAccess } from '@/lib/session'

const T0 = Date.parse('2026-11-16T10:00:00Z')
const PR = (id = 'owner', resourceId = 'r1') => ({ params: Promise.resolve({ id, resourceId }) })
const req = (method: string) => new NextRequest('http://webapp.test/api/users/owner/tradecraft-resources/r1/jobs', { method })

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  setNowForTests(() => new Date(T0))
  h.db.seed('userTradecraftResource', { id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', activeJobId: 'j1' })
  h.db.seed('tradecraftIngestionJob', { id: 'j1', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'running', stage: 'detect', leaseUntil: new Date(T0 + 40_000) })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

describe('jobs route', () => {
  test('GET: the latest job view (polled while a job runs)', async () => {
    const res = await GET(req('GET'), PR())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ job: expect.objectContaining({ id: 'j1', status: 'running', stage: 'detect', cancelRequested: false }) })
  })

  test('jobs_cancel: DELETE sets the flag, tells the agent, answers the job', async () => {
    const agent = stubAgent()
    const res = await DELETE(req('DELETE'), PR())
    expect(res.status).toBe(200)
    expect((await res.json()).job).toMatchObject({ id: 'j1', cancelRequested: true })
    expect(h.db.rows('tradecraftIngestionJob', { id: 'j1' })[0].cancelRequested).toBe(true)
    expect(agent.calls.map(c => c.path)).toEqual(['/tradecraft/v2/jobs/j1/cancel'])
  })

  test('DELETE with nothing running answers job null', async () => {
    h.db.rows('tradecraftIngestionJob', { id: 'j1' })[0].status = 'succeeded'
    stubAgent()
    expect(await (await DELETE(req('DELETE'), PR())).json()).toEqual({ job: null })
  })

  test("another account's resource: 404 for both", async () => {
    h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/' })
    stubAgent()
    expect((await GET(req('GET'), PR('owner', 'r-x'))).status).toBe(404)
    expect((await DELETE(req('DELETE'), PR('owner', 'r-x'))).status).toBe(404)
  })

  test('the account rule runs first: read for GET, write for DELETE; a refusal reads nothing', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    vi.mocked(requireUserAccess).mockClear()
    const before = h.db.calls.length
    expect((await GET(req('GET'), PR())).status).toBe(403)
    expect((await DELETE(req('DELETE'), PR())).status).toBe(403)
    expect(h.db.calls.slice(before)).toEqual([])
    const modes = vi.mocked(requireUserAccess).mock.calls.map(c => (c[2] as { mode: string }).mode)
    expect(modes).toEqual(['read', 'write'])
  })

  test('a database failure answers its code', async () => {
    h.db.failNext('userTradecraftResource.findFirst', Object.assign(new Error('timeout'), { code: 'P2024' }))
    const res = await GET(req('GET'), PR())
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to read the tradecraft job', code: 'P2024' })
  })
})

/**
 * DELETE /api/users/[id] stops the account's Tradecraft ingestion jobs before the account row
 * goes, whatever the switches (R-201, R-208): every unfinished job is flagged, then the agent is
 * asked to stop them; a lost agent never blocks the delete, and a refused delete cancels nothing.
 *
 * The route, the deletion helpers and the revocation path are real; Prisma is the in-memory
 * deletionDb; the permission, Root and act-as checks (their own tests), the project teardown and
 * the agent are doubles. The agent double records, at each call, whether the account still
 * exists and which of its jobs are flagged, so the order is asserted, not assumed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown,
  agent: [] as Array<{ path: string; userExists: boolean; flagged: string[] }>,
  agentDown: false,
}))

vi.mock('@/lib/prisma', async () => {
  const { createDeletionDb } = await import('@/lib/authz/__testing__/deletionDb')
  h.db = createDeletionDb()
  return { default: h.db }
})
vi.mock('@/lib/session', () => ({
  getSession: async () => ({ userId: 'admin-1', role: 'admin' }),
  isInternalRequest: () => false,
  actsAsAccount: async () => false,
  actAsInForceFor: async () => null,
}))
vi.mock('@/lib/projectTeardown', () => ({
  teardownProject: async (project: { id: string }) => {
    const db = h.db as import('@/lib/authz/__testing__/deletionDb').DeletionDb
    await (db.project as { deleteMany: (a: unknown) => Promise<unknown> }).deleteMany({ where: { id: project.id } })
    return { ok: true, steps: [] }
  },
}))
vi.mock('@/lib/authz/adminPermission', () => ({ requireSessionPermission: async () => null, sessionHolds: async () => true }))
vi.mock('@/lib/authz/rootProtection', () => ({ rootProtectedRefusal: async () => null, rootProtectedAnswer: async () => null }))
vi.mock('@/lib/authz/actAsRefusals', () => ({ refuseWhileActingAs: async () => null }))
vi.mock('@/lib/authz/accountNotices', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/accountNotices')>()),
  appendNotice: async () => undefined,
}))
vi.mock('@/lib/agentFetch', async (orig) => {
  const actual = await orig<typeof import('@/lib/agentFetch')>()
  return {
    ...actual,
    agentFetch: async (path: string) => {
      const db = h.db as import('@/lib/authz/__testing__/deletionDb').DeletionDb
      h.agent.push({
        path,
        userExists: db.rows('user').some(u => u.id === 'alice'),
        flagged: db.rows('tradecraftIngestionJob').filter(j => j.cancelRequested === true).map(j => j.id as string).sort(),
      })
      if (h.agentDown) throw new actual.AgentUnreachableError(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }))
      const body = path.endsWith('/cancel') ? { cancelled: 2 } : path === '/ws/close' ? { closed: 0 } : { stopped: 0 }
      return new Response(JSON.stringify(body), { status: 200 })
    },
  }
})

import type { DeletionDb } from '@/lib/authz/__testing__/deletionDb'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { DELETE } from './route'

const db = () => h.db as DeletionDb
const del = (id: string) => DELETE(
  new NextRequest(`http://localhost/api/users/${id}`, { method: 'DELETE', headers: { host: 'localhost' } }),
  { params: Promise.resolve({ id }) },
)
const tradecraftCalls = () => h.agent.filter(c => c.path.startsWith('/tradecraft/'))

function seed(jobs: Array<Record<string, unknown>>) {
  db().seed({
    user: [
      { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', status: 'active' },
      { id: 'alice', name: 'Alice', email: 'alice@e2e.local', role: 'standard', status: 'active' },
      { id: 'bob', name: 'Bob', email: 'bob@e2e.local', role: 'standard', status: 'active' },
    ],
    project: [{ id: 'P-solo', userId: 'alice', name: 'Alone', createdAt: new Date('2026-10-01T00:00:00Z') }],
    projectCollaborator: [], jobQueue: [], scanSchedule: [], conversation: [], triageRun: [], nucleiTemplate: [], auditLog: [],
    tradecraftIngestionJob: jobs,
  })
}

const JOBS = [
  { id: 'j-queued', userId: 'alice', resourceId: 'r1', kind: 'refresh', status: 'queued', cancelRequested: false },
  { id: 'j-running', userId: 'alice', resourceId: 'r2', kind: 'add', status: 'running', cancelRequested: false },
  { id: 'j-done', userId: 'alice', resourceId: 'r1', kind: 'add', status: 'succeeded', cancelRequested: false },
  { id: 'j-bob', userId: 'bob', resourceId: 'r9', kind: 'refresh', status: 'running', cancelRequested: false },
]

beforeEach(() => {
  h.agent = []
  h.agentDown = false
  seed(JOBS.map(j => ({ ...j })))
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

const SWITCHES: Array<[string, Partial<RbacFlags>]> = [
  ['every switch on', { identity: true, permissions: true, sharing: true, sharingWrite: false }],
  ['every switch off', {}],
]

describe('DELETE /api/users/[id]: the Tradecraft jobs of the account', () => {
  test.each(SWITCHES)('cancels_before_delete (%s): flagged, then the agent asked, while the account still exists', async (_name, flags) => {
    setFlagsForTests(flags)
    const res = await del('alice')
    expect(res.status).toBe(200)
    const [first] = tradecraftCalls()
    expect(first).toEqual({ path: '/tradecraft/v2/users/alice/cancel', userExists: true, flagged: ['j-queued', 'j-running'] })
    expect(db().rows('user').some(u => u.id === 'alice')).toBe(false)
    expect(db().rows('tradecraftIngestionJob').find(j => j.id === 'j-bob')?.cancelRequested).toBe(false)
    expect(db().rows('tradecraftIngestionJob').find(j => j.id === 'j-done')?.cancelRequested).toBe(false)
  })

  test('switches_off_still_cancels: no RBAC switch and no Tradecraft 2.0 switch row, the jobs still stop', async () => {
    setFlagsForTests({})
    expect(db().rows('tradecraftUserSettings')).toEqual([])
    expect((await del('alice')).status).toBe(200)
    expect(tradecraftCalls().map(c => c.path)).toEqual(['/tradecraft/v2/users/alice/cancel'])
  })

  test('delete_proceeds_when_agent_unreachable: the flags stand, the account is deleted, the failure is logged', async () => {
    setFlagsForTests({})
    h.agentDown = true
    expect((await del('alice')).status).toBe(200)
    expect(db().rows('user').some(u => u.id === 'alice')).toBe(false)
    expect(tradecraftCalls()[0].flagged).toEqual(['j-queued', 'j-running'])
    const logged = (console.error as unknown as { mock: { calls: unknown[][] } }).mock.calls.flat().join(' ')
    expect(logged).toContain('[tradecraft] user_cancel_agent_failed user=alice code=agent_unreachable')
  })

  test('an account with no unfinished job: the agent is asked nothing about Tradecraft', async () => {
    setFlagsForTests({})
    seed([{ id: 'j-done', userId: 'alice', resourceId: 'r1', kind: 'add', status: 'failed', cancelRequested: false }])
    expect((await del('alice')).status).toBe(200)
    expect(tradecraftCalls()).toEqual([])
  })

  test('a refused delete cancels nothing', async () => {
    setFlagsForTests({})
    seed([{ id: 'j-admin', userId: 'admin-1', resourceId: 'r1', kind: 'add', status: 'running', cancelRequested: false }])
    expect((await del('admin-1')).status).toBe(400)
    expect(db().rows('tradecraftIngestionJob')[0].cancelRequested).toBe(false)
    expect(tradecraftCalls()).toEqual([])
  })
})

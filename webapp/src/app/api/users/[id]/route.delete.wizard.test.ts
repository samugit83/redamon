/**
 * Deleting an account that owns shared projects goes through the deletion plan (step 5.13; SH-16,
 * SH-17): with write sharing switched on, each shared project (a share that has not expired) is
 * transferred first or named in the DELETE's `deleteAnyway`; a DELETE that leaves one unresolved answers
 * 409 `deletion_plan_unresolved` before anything is torn down. Once the account is gone its shares end
 * with it (cascade) and the revocation path stops what it still ran on other people's projects (step
 * 5.9's `account_deleted` plan): its agent runs, its sockets, its queued scans, its schedules. With the
 * agent down the deletion still succeeds and the failed close is logged. With the write switch off the
 * Phase 1 teardown runs as before (DV-30); with every switch off the agent is not asked anything.
 *
 * The route, the deletion helpers, the conversation reassignment, the revocation path and the scan
 * actor check are real; Prisma is the in-memory deletionDb (a user's delete cascades as the schema
 * does); the permission, Root and act-as checks (their own tests), the project teardown and the agent
 * are doubles.
 *
 * Run: npx vitest run --no-file-parallelism 'src/app/api/users/[id]/route.delete.wizard.test.ts'
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown,
  teardowns: [] as string[],
  agent: [] as Array<{ path: string; body: Record<string, unknown> }>,
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
    h.teardowns.push(project.id)
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
    agentFetch: async (path: string, init: { body?: string } = {}) => {
      h.agent.push({ path, body: init.body ? JSON.parse(init.body) : {} })
      if (h.agentDown) throw new actual.AgentUnreachableError('connect ECONNREFUSED')
      return new Response(JSON.stringify(path === '/ws/close' ? { closed: 2 } : { stopped: 1 }), { status: 200 })
    },
  }
})

import type { DeletionDb } from '@/lib/authz/__testing__/deletionDb'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { DELETE } from './route'

const db = () => h.db as DeletionDb
const ALL_ON: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true, sharingWrite: true }
const PAST = new Date('2026-01-01T00:00:00Z')
const at = (n: number) => new Date(Date.UTC(2026, 9, 1, 0, n))

function del(id: string, body?: unknown) {
  const init: { method: string; headers: Record<string, string>; body?: string } = { method: 'DELETE', headers: { host: 'localhost' } }
  if (body !== undefined) {
    init.body = JSON.stringify(body)
    init.headers['content-type'] = 'application/json'
  }
  return DELETE(new NextRequest(`http://localhost/api/users/${id}`, init), { params: Promise.resolve({ id }) })
}
const audit = (action: string) => db().rows('auditLog').filter((r) => r.action === action)

beforeEach(() => {
  db().seed({
    user: [
      { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', status: 'active' },
      { id: 'alice', name: 'Alice', email: 'alice@e2e.local', role: 'standard', status: 'active' },
      { id: 'bob', name: 'Bob', email: 'bob@e2e.local', role: 'standard', status: 'active' },
      { id: 'carla', name: 'Carla', email: 'carla@e2e.local', role: 'standard', status: 'active' },
      { id: 'olga', name: 'Olga', email: 'olga@e2e.local', role: 'standard', status: 'active' },
    ],
    project: [
      { id: 'P-shared', userId: 'alice', name: 'Client shared', createdAt: at(1) },
      { id: 'P-expired', userId: 'alice', name: 'Share lapsed', createdAt: at(2) },
      { id: 'P-solo', userId: 'alice', name: 'Alone', createdAt: at(3) },
      { id: 'P-olga', userId: 'olga', name: "Olga's engagement", createdAt: at(4) },
    ],
    projectCollaborator: [
      { projectId: 'P-shared', userId: 'bob', access: 'write', expiresAt: null },
      { projectId: 'P-expired', userId: 'carla', access: 'read', expiresAt: PAST },
      { projectId: 'P-olga', userId: 'alice', access: 'write', runScans: true, expiresAt: null },
    ],
    jobQueue: [{ id: 'job-alice', projectId: 'P-olga', userId: 'alice', status: 'queued', kind: 'full_recon', payload: {} }],
    scanSchedule: [{ id: 'sch-alice', projectId: 'P-olga', userId: 'alice', enabled: true, label: 'nightly', scanMode: 'full' }],
    conversation: [{ id: 'c-alice', projectId: 'P-olga', userId: 'alice', formerAuthorId: null, formerAuthorLabel: null }],
    triageRun: [],
    nucleiTemplate: [],
    auditLog: [],
  })
  h.teardowns = []
  h.agent = []
  h.agentDown = false
  setFlagsForTests(ALL_ON)
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('DELETE /api/users/[id] with write sharing on: the deletion plan decides each shared project (step 5.13, SH-17)', () => {
  test('delete blocked until resolved: 409 deletion_plan_unresolved naming the shared project and the plan; nothing torn down', async () => {
    const res = await del('alice')
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({
      error: expect.stringContaining('deletion plan'),
      code: 'deletion_plan_unresolved',
      projects: [{ id: 'P-shared', name: 'Client shared' }],
      plan: '/api/users/alice/deletion-plan',
    })
    expect(h.teardowns).toEqual([])
    expect(db().rows('user').some((u) => u.id === 'alice')).toBe(true)
    expect(audit('user.delete')).toEqual([])
    expect(h.agent).toEqual([])
  })

  test('naming another project, or a value that is not a list, resolves nothing', async () => {
    expect((await del('alice', { deleteAnyway: ['P-solo'] })).status).toBe(409)
    expect((await del('alice', { deleteAnyway: 'P-shared' })).status).toBe(409)
    expect(h.teardowns).toEqual([])
  })

  test('delete anyway tears down: the named shared project goes with the unshared ones, oldest first; the audit row names it', async () => {
    const res = await del('alice', { deleteAnyway: ['P-shared'] })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ success: true })
    expect(h.teardowns).toEqual(['P-shared', 'P-expired', 'P-solo'])
    expect(db().rows('user').some((u) => u.id === 'alice')).toBe(false)
    expect(audit('user.delete')).toEqual([
      expect.objectContaining({ targetId: 'alice', after: expect.objectContaining({ projectsDeleted: ['P-shared', 'P-expired', 'P-solo'], deletedAnyway: ['P-shared'] }) }),
    ])
  })

  test('a shared project already transferred is resolved: it is no longer the account\'s and is not torn down', async () => {
    db().rows('project').find((p) => p.id === 'P-shared')!.userId = 'bob'
    const res = await del('alice')
    expect(res.status).toBe(200)
    expect(h.teardowns).toEqual(['P-expired', 'P-solo'])
    expect(db().rows('project').find((p) => p.id === 'P-shared')).toMatchObject({ userId: 'bob' })
    expect(audit('user.delete')[0]).toMatchObject({ after: { deletedAnyway: [] } })
  })

  test("memberships gone after: the account's shares end with it, and its live work on other people's projects stops", async () => {
    expect((await del('alice', { deleteAnyway: ['P-shared'] })).status).toBe(200)
    expect(db().rows('projectCollaborator').filter((c) => c.userId === 'alice')).toEqual([])
    expect(db().rows('projectCollaborator').filter((c) => c.projectId === 'P-olga')).toEqual([])
    // The revocation path, account-wide (step 5.9's account_deleted plan), once the row is gone.
    expect(h.agent).toEqual([
      { path: '/agent-sessions/stop-for', body: { user_id: 'alice' } },
      { path: '/ws/close', body: { user_id: 'alice', kinds: expect.any(Array), scope: 'account' } },
    ])
    expect(db().rows('jobQueue').find((j) => j.id === 'job-alice')).toMatchObject({ status: 'canceled', blockedCode: 'actor_no_access' })
    expect(audit('job_queue.cancelled')).toEqual([
      expect.objectContaining({ targetId: 'job-alice', after: expect.objectContaining({ revocation: 'account_deleted', refusal: 'deleted' }) }),
    ])
    expect(db().rows('scanSchedule').find((s) => s.id === 'sch-alice')).toMatchObject({ enabled: false, pausedReason: 'actor_no_access' })
    // Step 5.8: the conversation in Olga's project stays with Olga.
    expect(db().rows('conversation').find((c) => c.id === 'c-alice')).toMatchObject({ userId: 'olga', formerAuthorId: 'alice' })
  })

  test('the agent down: the deletion still succeeds; the failed close is logged; the queued scan is still cancelled', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agentDown = true
    const res = await del('alice', { deleteAnyway: ['P-shared'] })
    expect(res.status).toBe(200)
    expect(db().rows('user').some((u) => u.id === 'alice')).toBe(false)
    const lines = error.mock.calls.map((c) => String(c[0]))
    expect(lines.some((l) => l.startsWith('[rbac] socket-close failed user=alice'))).toBe(true)
    expect(lines.some((l) => l.startsWith('[rbac] revocation step failed step=close_sockets reason=account_deleted user=alice'))).toBe(true)
    expect(db().rows('jobQueue').find((j) => j.id === 'job-alice')).toMatchObject({ status: 'canceled' })
    expect(audit('user.delete')).toHaveLength(1)
  })
})

describe('with write sharing switched off the Phase 1 teardown runs as before (DV-30)', () => {
  test('sharing on, the write switch off: no plan asked, every project torn down; the deleted collaborator\'s live work still stops', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    const res = await del('alice')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ success: true })
    expect(h.teardowns).toEqual(['P-shared', 'P-expired', 'P-solo'])
    expect(audit('user.delete')[0]?.after).not.toHaveProperty('deletedAnyway')
    expect(h.agent.map((c) => c.path)).toEqual(['/agent-sessions/stop-for', '/ws/close'])
    expect(db().rows('jobQueue').find((j) => j.id === 'job-alice')).toMatchObject({ status: 'canceled' })
  })

  test('every switch off: deleted as before, the agent asked nothing', async () => {
    setFlagsForTests({})
    const res = await del('alice')
    expect(res.status).toBe(200)
    expect(h.teardowns).toEqual(['P-shared', 'P-expired', 'P-solo'])
    expect(h.agent).toEqual([])
    expect(db().rows('jobQueue').find((j) => j.id === 'job-alice')).toMatchObject({ status: 'queued' })
    expect(audit('user.delete')[0]?.after).not.toHaveProperty('deletedAnyway')
  })
})

/**
 * GET /api/admin/projects and DELETE /api/admin/projects/[id] (step 6.4; GV-04, SH-18): the admin
 * console's projects overview and Root's forced delete. With RBAC_GOVERNANCE_ENABLED off both are 404
 * having read nothing; projects:oversee opens the list (a 403 naming it otherwise) and listing writes
 * no audit row; share counts read collaborator rows only with sharing in force; "open read-only" is
 * offered only with sharing in force and never while acting as someone (D-22); the delete is the
 * confirmed Root's with its password, runs the owner's teardown with the owner as tenant and is
 * audited `project.delete` with `after.forced`.
 *
 * The routes, lib/authz/adminProjects.ts, rootPowers.ts and the audit writers are real; the session,
 * the permission answers, the Root, the step-up check, the act-as reader, the sharing policy, the
 * teardown and Prisma are doubles (Prisma inline: the queries and the audit rows are asserted).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/projects/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  session: { userId: 'adm-a', role: 'admin' } as { userId: string; role: string } | null,
  held: new Set<string>(),
  root: { userId: 'root-1', email: 'root@e2e.local', confirmed: true, assignedBy: 'host' } as { userId: string; confirmed: boolean } | null,
  actingAs: null as string | null,
  password: 'root-pass',
  policy: null as null | { enabled: boolean; adminsSeeAllShares: boolean },
  touched: [] as string[],
  db: {
    projectFindMany: vi.fn(),
    projectCount: vi.fn(),
    projectFindUnique: vi.fn(),
    auditGroupBy: vi.fn(),
    auditCreate: vi.fn(),
  },
  teardown: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: { findMany: h.db.projectFindMany, count: h.db.projectCount, findUnique: h.db.projectFindUnique },
    auditLog: { groupBy: h.db.auditGroupBy, create: h.db.auditCreate },
  }
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  requireSession: vi.fn(async () => { h.touched.push('session'); return h.session ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) }),
}))
vi.mock('@/lib/authz/adminPermission', async () => {
  const { forbiddenResponse } = await import('@/lib/authz/guards')
  return {
    sessionHolds: vi.fn(async (_s: unknown, p: string) => h.held.has(p)),
    requireSessionPermission: vi.fn(async (_s: unknown, p: Parameters<typeof forbiddenResponse>[0]) => (h.held.has(p) ? null : forbiddenResponse(p))),
  }
})
vi.mock('@/lib/authz/root', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/root')>()),
  loadInstanceRoot: vi.fn(async () => h.root),
}))
vi.mock('@/lib/authz/stepUp', async () => {
  const { NextResponse: R } = await import('next/server')
  return {
    requireStepUp: vi.fn(async (_r: unknown, password: unknown) => {
      if (!password) return R.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
      return password === h.password ? null : R.json({ error: 'Password is incorrect', code: 'step_up_failed' }, { status: 403 })
    }),
  }
})
vi.mock('@/lib/userAudit', () => ({ actingAsUserId: vi.fn(async () => h.actingAs) }))
vi.mock('@/lib/authz/sharingPolicy', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/sharingPolicy')>()),
  sharingPolicyInForce: vi.fn(async () => h.policy),
}))
vi.mock('@/lib/projectTeardown', () => ({ teardownProject: h.teardown }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { encodeCursor } from '@/lib/authz/userDirectory'
import { GET as listProjects } from './route'
import { DELETE as deleteProject } from './[id]/route'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const GOV = { identity: true, permissions: true, governance: true }
const SHARING = { ...GOV, sharing: true }

function project(id: string, over: Record<string, unknown> = {}) {
  return {
    id, name: `${id} name`, createdAt: new Date('2026-11-01T08:00:00.000Z'), updatedAt: new Date('2026-11-05T08:00:00.000Z'),
    targetDomain: `${id}.example.test`, ipMode: false, targetIps: [], subdomainList: [], domainBatchMode: false, domainBatchHosts: [],
    user: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local', status: 'active' },
    ...over,
  }
}

const list = (qs = '') => listProjects(new NextRequest(`http://redamon.test/api/admin/projects${qs ? `?${qs}` : ''}`))
function del(id: string, body: unknown = { stepUpPassword: h.password }, headers: Record<string, string> = {}) {
  return deleteProject(new NextRequest(`http://redamon.test/api/admin/projects/${id}`, {
    method: 'DELETE',
    headers: { 'content-type': 'application/json', host: 'redamon.test', origin: 'http://redamon.test', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), { params: Promise.resolve({ id }) })
}
const body = async (res: Response) => res.json() as Promise<Record<string, any>>
const findManyArg = () => h.db.projectFindMany.mock.calls[0][0]
const auditRows = () => h.db.auditCreate.mock.calls.map((c) => c[0].data)

beforeEach(() => {
  setFlagsForTests(GOV)
  setNowForTests(() => NOW)
  h.session = { userId: 'adm-a', role: 'admin' }
  h.held = new Set(['projects:oversee'])
  h.root = { userId: 'root-1', confirmed: true }
  h.actingAs = null
  h.policy = null
  h.touched = []
  for (const fn of Object.values(h.db)) fn.mockReset()
  h.teardown.mockReset()
  h.db.projectFindMany.mockResolvedValue([])
  h.db.projectCount.mockResolvedValue(0)
  h.db.projectFindUnique.mockResolvedValue(null)
  h.db.auditGroupBy.mockResolvedValue([])
  h.db.auditCreate.mockImplementation(async ({ data }: { data: object }) => ({ id: 'al-1', createdAt: NOW, ...data }))
  h.teardown.mockResolvedValue({ ok: true, steps: [] })
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('with RBAC_GOVERNANCE_ENABLED off', () => {
  test.each([
    ['every switch off', {}],
    ['identity, permissions and sharing on', { identity: true, permissions: true, sharing: true }],
  ])('%s: the list and the delete are 404 and read nothing', async (_what, flags) => {
    setFlagsForTests(flags)
    expect((await list()).status).toBe(404)
    expect((await del('p-1')).status).toBe(404)
    expect(h.touched).toEqual([])
    expect(h.db.projectFindMany).not.toHaveBeenCalled()
    expect(h.db.projectFindUnique).not.toHaveBeenCalled()
    expect(h.teardown).not.toHaveBeenCalled()
  })
})

describe('GET /api/admin/projects: the oversight list', () => {
  test('401 without a session; 403 naming projects:oversee without it, nothing read', async () => {
    h.session = null
    expect((await list()).status).toBe(401)
    h.session = { userId: 'adm-b', role: 'admin' }
    h.held = new Set(['users:read'])
    const res = await list()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'forbidden', permission: 'projects:oversee' })
    expect(h.db.projectFindMany).not.toHaveBeenCalled()
  })

  test('oversight list: every project with its owner, scope, share count and last activity; no audit row', async () => {
    setFlagsForTests(SHARING)
    h.policy = { enabled: true, adminsSeeAllShares: true }
    h.db.projectFindMany.mockResolvedValue([
      project('p-2', { _count: { collaborators: 2 } }),
      project('p-1', { user: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'disabled' }, _count: { collaborators: 0 } }),
    ])
    h.db.projectCount.mockResolvedValue(2)
    h.db.auditGroupBy.mockResolvedValue([{ projectId: 'p-2', _max: { createdAt: new Date('2026-11-12T09:00:00.000Z') } },
      { projectId: 'p-1', _max: { createdAt: new Date('2026-10-01T09:00:00.000Z') } }])
    const res = await list()
    expect(res.status).toBe(200)
    const page = await body(res)
    expect(page.total).toBe(2)
    expect(page.nextCursor).toBeNull()
    expect(page.projects).toEqual([
      {
        id: 'p-2', name: 'p-2 name', targetLabel: 'p-2.example.test',
        owner: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local', status: 'active' },
        collaborators: 2, createdAt: '2026-11-01T08:00:00.000Z', lastActivityAt: '2026-11-12T09:00:00.000Z',
      },
      {
        id: 'p-1', name: 'p-1 name', targetLabel: 'p-1.example.test',
        owner: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'disabled' },
        // The older audit row loses to the last settings change.
        collaborators: 0, createdAt: '2026-11-01T08:00:00.000Z', lastActivityAt: '2026-11-05T08:00:00.000Z',
      },
    ])
    expect(page.sharing).toEqual({ inForce: true, allShares: true })
    expect(page.actions).toEqual({ openReadOnly: true, breakGlass: false, delete: false, revokeShares: false })
    const arg = findManyArg()
    expect(arg.orderBy).toEqual([{ createdAt: 'desc' }, { id: 'desc' }])
    expect(arg.take).toBe(51)
    expect(arg.where).toEqual({})
    expect(arg.select._count).toEqual({ select: { collaborators: { where: { OR: [{ expiresAt: null }, { expiresAt: { gt: NOW } }] } } } })
    expect(arg.select.user).toEqual({ select: { id: true, name: true, email: true, status: true } })
    expect(h.db.auditGroupBy).toHaveBeenCalledWith({ by: ['projectId'], where: { projectId: { in: ['p-2', 'p-1'] } }, _max: { createdAt: true } })
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test.each([
    ['the sharing switch off', GOV, null],
    ['the switch on, the policy disabled', SHARING, { enabled: false, adminsSeeAllShares: true }],
  ])('%s: no collaborator row is counted and nothing opens read-only', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    h.policy = policy
    h.db.projectFindMany.mockResolvedValue([project('p-1')])
    h.db.projectCount.mockResolvedValue(1)
    const page = await body(await list())
    expect(findManyArg().select._count).toBeUndefined()
    expect(page.projects[0].collaborators).toBeNull()
    expect(page.sharing).toEqual({ inForce: false, allShares: false })
    expect(page.actions.openReadOnly).toBe(false)
  })

  test('actions need their permission: open read-only and break-glass never while acting; break-glass, delete and revoke only for the confirmed Root', async () => {
    setFlagsForTests(SHARING)
    h.policy = { enabled: true, adminsSeeAllShares: true }
    h.actingAs = 'mem-a'
    expect((await body(await list())).actions).toEqual({ openReadOnly: false, breakGlass: false, delete: false, revokeShares: false })
    h.actingAs = null
    h.session = { userId: 'root-1', role: 'admin' }
    expect((await body(await list())).actions).toEqual({ openReadOnly: true, breakGlass: true, delete: true, revokeShares: true })
    // Root acting as someone: no oversight read and no break-glass (D-22); the delete stays Root's.
    h.actingAs = 'mem-a'
    expect((await body(await list())).actions).toEqual({ openReadOnly: false, breakGlass: false, delete: true, revokeShares: true })
    h.actingAs = null
    // Root's policy hides others' shares: the force-revoke is not offered from the list.
    h.policy = { enabled: true, adminsSeeAllShares: false }
    expect((await body(await list())).actions).toEqual({ openReadOnly: true, breakGlass: true, delete: true, revokeShares: false })
    // Sharing not in force: no break-glass (step 4.14's route answers 404), the delete stays.
    h.policy = { enabled: false, adminsSeeAllShares: true }
    expect((await body(await list())).actions).toEqual({ openReadOnly: false, breakGlass: false, delete: true, revokeShares: false })
    h.policy = { enabled: true, adminsSeeAllShares: true }
    h.root = { userId: 'root-1', confirmed: false }
    expect((await body(await list())).actions).toMatchObject({ breakGlass: false, delete: false, revokeShares: false })
  })

  test('filters and pagination: q and owner, a cursor, the next cursor; the total ignores the cursor', async () => {
    const rows = Array.from({ length: 3 }, (_, i) => project(`p-${i}`, { createdAt: new Date(`2026-11-0${3 - i}T08:00:00.000Z`) }))
    h.db.projectFindMany.mockResolvedValue(rows)
    h.db.projectCount.mockResolvedValue(7)
    const cursor = encodeCursor({ createdAt: new Date('2026-11-04T08:00:00.000Z'), id: 'p-9' })
    const page = await body(await list(`q=acme&owner=mem-a&limit=2&cursor=${cursor}`))
    const where = {
      AND: [
        { OR: [
          { name: { contains: 'acme', mode: 'insensitive' } },
          { user: { name: { contains: 'acme', mode: 'insensitive' } } },
          { user: { email: { contains: 'acme', mode: 'insensitive' } } },
        ] },
        { userId: 'mem-a' },
      ],
    }
    expect(findManyArg().where).toEqual({
      AND: [where, { OR: [{ createdAt: { lt: new Date('2026-11-04T08:00:00.000Z') } }, { createdAt: new Date('2026-11-04T08:00:00.000Z'), id: { lt: 'p-9' } }] }],
    })
    expect(findManyArg().take).toBe(3)
    expect(h.db.projectCount).toHaveBeenCalledWith({ where })
    expect(page.projects.map((p: { id: string }) => p.id)).toEqual(['p-0', 'p-1'])
    expect(page.nextCursor).toBe(encodeCursor({ createdAt: rows[1].createdAt, id: 'p-1' }))
    expect(page.total).toBe(7)
  })

  test.each([
    ['limit=0', 'limit'], ['limit=101', 'limit'], ['limit=x', 'limit'], ['cursor=bm9wZQ', 'cursor'], [`q=${'a'.repeat(201)}`, 'q'],
  ])('%s: 400 invalid_filter naming %s, nothing read', async (qs, field) => {
    const res = await list(qs)
    expect(res.status).toBe(400)
    expect(await body(res)).toMatchObject({ code: 'invalid_filter', field })
    expect(h.db.projectFindMany).not.toHaveBeenCalled()
  })

  test('empty: no project, no activity read', async () => {
    const page = await body(await list())
    expect(page).toMatchObject({ projects: [], total: 0, nextCursor: null })
    expect(h.db.auditGroupBy).not.toHaveBeenCalled()
  })
})

describe("DELETE /api/admin/projects/[id]: Root's forced delete", () => {
  beforeEach(() => {
    h.session = { userId: 'root-1', role: 'admin' }
    h.db.projectFindUnique.mockResolvedValue({ id: 'p-1', userId: 'mem-a', name: 'Lab' })
  })

  test('actions need their permission: an admin gets 403 root_only before any password or read', async () => {
    h.session = { userId: 'adm-a', role: 'admin' }
    h.held = new Set(['projects:oversee', 'users:read'])
    const res = await del('p-1', { stepUpPassword: 'anything' })
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'root_only' })
    expect(h.db.projectFindUnique).not.toHaveBeenCalled()
    expect(h.teardown).not.toHaveBeenCalled()
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('an unconfirmed Root is told why; a wrong or missing password is refused; nothing is deleted', async () => {
    h.root = { userId: 'root-1', confirmed: false }
    const unconfirmed = await body(await del('p-1'))
    expect(unconfirmed.code).toBe('root_only')
    expect(unconfirmed.error).toContain('set-root')
    h.root = { userId: 'root-1', confirmed: true }
    expect((await body(await del('p-1', { stepUpPassword: 'wrong' }))).code).toBe('step_up_failed')
    expect((await body(await del('p-1', {}))).code).toBe('step_up_required')
    expect(h.teardown).not.toHaveBeenCalled()
  })

  test('cross-origin and non-JSON bodies are refused before the Root check', async () => {
    expect((await body(await del('p-1', undefined, { origin: 'https://evil.example' }))).code).toBe('cross_origin')
    expect((await del('p-1', 'stepUpPassword=root-pass', { 'content-type': 'application/x-www-form-urlencoded' })).status).toBe(415)
    expect(h.teardown).not.toHaveBeenCalled()
  })

  test("Root deletes a member's project: the owner's teardown, the owner as tenant, audited with after.forced", async () => {
    const res = await del('p-1')
    expect(res.status).toBe(200)
    expect(await body(res)).toEqual({ deleted: { projectId: 'p-1', ownerId: 'mem-a' } })
    expect(h.teardown).toHaveBeenCalledWith({ id: 'p-1', userId: 'mem-a' }, { actorUserId: 'root-1', archiveReason: 'project_deleted_by_root' })
    expect(auditRows()).toEqual([expect.objectContaining({
      actorId: 'root-1', action: 'project.delete', projectId: 'p-1', permission: 'projects:administer',
      targetType: 'project', targetId: 'p-1', before: { name: 'Lab', ownerId: 'mem-a' }, after: { forced: true }, source: 'api',
    })])
  })

  test('a project that is not there, or went meanwhile: 404 project_not_found and no audit row', async () => {
    h.db.projectFindUnique.mockResolvedValueOnce(null)
    expect(await body(await del('p-x'))).toMatchObject({ code: 'project_not_found' })
    expect(h.teardown).not.toHaveBeenCalled()
    h.teardown.mockResolvedValueOnce({ ok: false, steps: [], failedStep: 'delete_project', code: 'project_not_found', error: new Error('P2025') })
    const gone = await del('p-1')
    expect(gone.status).toBe(404)
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('a teardown stopped at the archive: 500 coded, nothing deleted, a project.delete_failed row', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.teardown.mockResolvedValueOnce({ ok: false, steps: [], failedStep: 'archive_authorizations', code: 'authorization_archive_failed' })
    const res = await del('p-1')
    expect(res.status).toBe(500)
    expect(await body(res)).toMatchObject({ code: 'authorization_archive_failed' })
    expect(auditRows()).toEqual([expect.objectContaining({
      action: 'project.delete_failed', projectId: 'p-1',
      after: { forced: true, failedStep: 'archive_authorizations', code: 'authorization_archive_failed' },
    })])
    expect(error.mock.calls.some((c) => String(c[0]).startsWith('[rbac] forced project delete failed project=p-1'))).toBe(true)
  })

  test('a row delete that fails: a coded 500 (no error text), and the failure audited', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.teardown.mockResolvedValueOnce({ ok: false, steps: [], failedStep: 'delete_project', code: 'delete_failed', error: Object.assign(new Error('secret detail'), { code: 'P1001' }) })
    const res = await del('p-1')
    expect(res.status).toBe(500)
    const answer = await body(res)
    expect(answer.code).toBe('P1001')
    expect(JSON.stringify(answer)).not.toContain('secret detail')
    expect(auditRows()[0]).toMatchObject({ action: 'project.delete_failed', after: { forced: true, failedStep: 'delete_project', code: 'delete_failed' } })
  })
})

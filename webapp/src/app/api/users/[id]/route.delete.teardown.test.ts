/**
 * Deleting a user tears down each of their projects first (HD-11, F-10).
 *
 * Before, the user delete relied on the database cascade alone: the graph, the
 * output files and the running work of the user's projects were left behind, and
 * a project holding an engagement authorization made the whole delete fail with
 * P2003 (experiment E1), because that foreign key is Restrict. Now every project
 * goes through the project-delete teardown, and only then is the account deleted.
 *
 * The route, the teardown, the authorization archive, the triage client, the
 * last-admin guard and the audit writer are real. Prisma is an in-memory table set
 * that keeps the two foreign keys that matter here (Restrict on authorizations,
 * cascade otherwise); the orchestrator, the agent, Neo4j and the workspace purge
 * are doubles that log what they were asked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import bcrypt from 'bcryptjs'
import { NextRequest } from 'next/server'

type User = { id: string; email: string; name: string; role: string; password: string }
type Project = { id: string; userId: string; createdAt: Date }
type Audit = { actorId: string | null; action: string; targetId: string | null; before?: unknown; after?: unknown }

const h = vi.hoisted(() => ({
  users: new Map<string, User>(),
  projects: [] as Project[],
  authorizations: [] as { id: string; projectId: string }[],
  archive: [] as { id: string; projectId: string; reason: string }[],
  audit: [] as Audit[],
  events: [] as string[],
  session: null as { userId: string; role: string } | null,
  archiveFailsFor: null as string | null,
  vanished: null as string | null,
  agentBodies: [] as { path: string; body: Record<string, unknown> }[],
}))

const known = (code: string, message: string) => Object.assign(new Error(message), { code })

vi.mock('@/lib/session', () => ({ getSession: async () => h.session, isInternalRequest: () => false }))
vi.mock('@/lib/prisma', () => {
  const pick = (row: Record<string, unknown>, select?: Record<string, boolean>) =>
    select ? Object.fromEntries(Object.keys(select).filter(k => select[k]).map(k => [k, row[k]])) : { ...row }
  const db: Record<string, unknown> = {
    user: {
      findUnique: async ({ where, select }: { where: { id: string }; select?: Record<string, boolean> }) => {
        const row = h.users.get(where.id)
        return row ? pick(row, select) : null
      },
      count: async ({ where }: { where: { role: string; id: { not: string }; password: { not: string } } }) =>
        [...h.users.values()].filter(r =>
          r.role === where.role && r.id !== where.id.not && r.password !== where.password.not).length,
      delete: async ({ where }: { where: { id: string } }) => {
        if (!h.users.has(where.id)) throw known('P2025', 'Record to delete does not exist.')
        // The cascade reaches the projects, whose authorizations are Restrict.
        const owned = h.projects.filter(p => p.userId === where.id).map(p => p.id)
        if (h.authorizations.some(a => owned.includes(a.projectId))) {
          throw known('P2003', 'Foreign key constraint violated on the constraint: engagement_authorizations_project_id_fkey')
        }
        h.projects = h.projects.filter(p => p.userId !== where.id)
        h.users.delete(where.id)
        h.events.push(`user-delete ${where.id}`)
        return {}
      },
    },
    project: {
      findMany: async ({ where, select, orderBy }: { where: { userId: string }; select?: Record<string, boolean>; orderBy?: { createdAt: 'asc' | 'desc' } }) => {
        const rows = h.projects.filter(p => p.userId === where.userId)
        if (orderBy?.createdAt) rows.sort((a, b) => (a.createdAt.getTime() - b.createdAt.getTime()) * (orderBy.createdAt === 'asc' ? 1 : -1))
        return rows.map(r => pick(r, select))
      },
      delete: async ({ where }: { where: { id: string } }) => {
        if (h.vanished === where.id) h.projects = h.projects.filter(p => p.id !== where.id)
        if (!h.projects.some(p => p.id === where.id)) throw known('P2025', 'Record to delete does not exist.')
        if (h.authorizations.some(a => a.projectId === where.id)) throw known('P2003', 'Foreign key constraint violated')
        h.projects = h.projects.filter(p => p.id !== where.id)
        h.events.push(`project-delete ${where.id}`)
        return { id: where.id }
      },
    },
    jobQueue: {
      updateMany: async ({ where }: { where: { projectId: string } }) => {
        h.events.push(`cancel-jobs ${where.projectId}`)
        return { count: 0 }
      },
    },
    conversation: { findMany: async () => [] },
    capturedHttpTransaction: {
      findMany: async ({ where }: { where: { projectId?: string; userId?: string } }) => {
        h.events.push(`collect-bodies ${where.projectId ?? `user ${where.userId}`}`)
        return []
      },
    },
    engagementAuthorization: {
      count: async ({ where }: { where: { projectId: string } }) =>
        h.authorizations.filter(a => a.projectId === where.projectId).length,
    },
    auditLog: { create: async ({ data }: { data: Audit }) => { h.audit.push(data); return data } },
    // The account's Nuclei templates go to the deleting admin (route.delete.templates.test.ts).
    nucleiTemplate: { updateMany: async () => ({ count: 0 }) },
    $executeRaw: async () => 1,
    // engagementArchive.ts: set_config, then the copy, then the delete of the originals.
    $executeRawUnsafe: async (sql: string, ...params: unknown[]) => {
      const projectId = params[0] as string
      if (sql.includes('INSERT INTO engagement_authorization_archive')) {
        if (h.archiveFailsFor === projectId) throw new Error('relation "engagement_authorization_archive" does not exist')
        const rows = h.authorizations.filter(a => a.projectId === projectId)
        h.archive.push(...rows.map(r => ({ ...r, reason: params[1] as string })))
        h.events.push(`archive ${projectId}`)
        return rows.length
      }
      if (sql.includes('DELETE FROM engagement_authorizations')) {
        h.authorizations = h.authorizations.filter(a => a.projectId !== projectId)
      }
      return 1
    },
  }
  db.$transaction = async (fn: (tx: unknown) => Promise<unknown>) => fn(db)
  return { default: db }
})
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: async (url: string) => {
    const path = new URL(url).pathname
    if (path.endsWith('/files')) h.events.push(`delete-files ${path.split('/')[2]}`)
    if (path.endsWith('/recon/' + path.split('/')[2] + '/stop')) h.events.push(`stop-recon ${path.split('/')[2]}`)
    return { ok: true, json: async () => ({ deleted: [], runs: [] }) }
  },
}))
vi.mock('@/lib/agentFetch', async () => ({
  ...(await vi.importActual<typeof import('@/lib/agentFetch')>('@/lib/agentFetch')),
  agentFetch: async (path: string, init: { body: string }) => {
    const body = JSON.parse(init.body) as Record<string, unknown>
    h.agentBodies.push({ path, body })
    if (path === '/graph/triage') h.events.push(`stop-triage ${body.project_id}`)
    return { ok: true, status: 200, json: async () => ({ stopped: false }) }
  },
}))
vi.mock('@/lib/workspacePurge', () => ({
  purgeProjectWorkspace: async (pid: string) => { h.events.push(`purge ${pid}`) },
}))
vi.mock('@/lib/captureBodies', () => ({ gcOrphanBodies: async () => ({ deleted: 0 }) }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (_q: string, p: { pid: string }) => { h.events.push(`clear-graph ${p.pid}`); return { records: [] } },
    close: async () => undefined,
  }),
}))

import { __resetThrottle } from '@/lib/loginThrottle'
import { DELETE } from './route'

const PW = { admin1: 'admin-one-passphrase', admin2: 'admin-two-passphrase' }

function seed() {
  h.users.clear()
  h.projects = []
  h.authorizations = []
  h.archive = []
  h.audit = []
  h.events = []
  h.agentBodies = []
  h.archiveFailsFor = null
  h.vanished = null
  const add = (id: string, role: string, password: string) =>
    h.users.set(id, { id, email: `${id}@e2e.local`, name: id, role, password: password ? bcrypt.hashSync(password, 4) : '' })
  add('admin-1', 'admin', PW.admin1)
  add('admin-2', 'admin', PW.admin2)
  add('member-1', 'standard', 'member-passphrase')
  h.session = { userId: 'admin-1', role: 'admin' }
}

const at = (minute: number) => new Date(Date.UTC(2026, 10, 11, 10, minute))
const own = (userId: string, ...ids: string[]) =>
  ids.forEach((id, i) => h.projects.push({ id, userId, createdAt: at(i) }))
const del = (id: string, body?: unknown) => DELETE(new NextRequest(`http://localhost/api/users/${id}`, {
  method: 'DELETE',
  ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
}), { params: Promise.resolve({ id }) })
const rows = (action: string) => h.audit.filter(r => r.action === action)

beforeEach(() => {
  __resetThrottle()
  seed()
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  vi.spyOn(console, 'info').mockImplementation(() => undefined)
  vi.spyOn(console, 'warn').mockImplementation(() => undefined)
})

describe('DELETE /api/users/[id] runs the project teardown', () => {
  test('teardown runs for every owned project before the user is deleted', async () => {
    own('member-1', 'p-old', 'p-new')
    own('admin-1', 'p-other')
    h.authorizations.push({ id: 'auth-1', projectId: 'p-new' })

    const res = await del('member-1')
    expect(res.status).toBe(200)

    // Each project in creation order, each through the whole teardown, then the account.
    const steps = (pid: string) => [
      `collect-bodies ${pid}`, `cancel-jobs ${pid}`, `stop-triage ${pid}`, `stop-recon ${pid}`,
      `project-delete ${pid}`, `purge ${pid}`, `delete-files ${pid}`, `clear-graph ${pid}`,
    ]
    expect(h.events.filter(e => !e.startsWith('archive'))).toEqual([...steps('p-old'), ...steps('p-new'), 'user-delete member-1'])
    expect(h.events.indexOf('archive p-new')).toBeLessThan(h.events.indexOf('project-delete p-new'))

    expect(h.users.has('member-1')).toBe(false)
    expect(h.projects.map(p => p.id)).toEqual(['p-other'])
    // The authorization outlives the project and the account, and says why it was archived.
    expect(h.authorizations).toEqual([])
    expect(h.archive).toEqual([{ id: 'auth-1', projectId: 'p-new', reason: 'user_deleted' }])

    const [row] = rows('user.delete')
    expect(row).toMatchObject({
      actorId: 'admin-1', targetId: 'member-1',
      before: { email: 'member-1@e2e.local', role: 'standard', ownedProjectCount: 2 },
      after: { projectsDeleted: ['p-old', 'p-new'] },
    })
    expect(rows('user.delete_failed')).toEqual([])
  })

  test('an archive failure stops and keeps the user', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    own('member-1', 'p1', 'p2', 'p3')
    h.authorizations.push({ id: 'auth-2', projectId: 'p2' })
    h.archiveFailsFor = 'p2'

    const res = await del('member-1')
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'authorization_archive_failed', projectId: 'p2' })
    expect(body.error).toMatch(/not deleted/)
    expect(JSON.stringify(body)).not.toContain('does not exist')

    // The first project is gone, the failing one and every later one are untouched.
    expect(h.users.has('member-1')).toBe(true)
    expect(h.projects.map(p => p.id)).toEqual(['p2', 'p3'])
    expect(h.authorizations).toEqual([{ id: 'auth-2', projectId: 'p2' }])
    expect(h.events.some(e => e.endsWith(' p3'))).toBe(false)
    expect(h.events).not.toContain('project-delete p2')
    expect(h.events.some(e => e.startsWith('user-delete'))).toBe(false)

    // The progress is in the log and in the audit row.
    expect(error.mock.calls.map(c => String(c[0]))).toContain(
      '[rbac] user-delete teardown failed project=p2 step=archive_authorizations')
    expect(rows('user.delete')).toEqual([])
    const [failed] = rows('user.delete_failed')
    expect(failed).toMatchObject({
      actorId: 'admin-1', targetId: 'member-1',
      before: { email: 'member-1@e2e.local', role: 'standard', ownedProjectCount: 3 },
      after: { projectsDeleted: ['p1'], failedProjectId: 'p2', failedStep: 'archive_authorizations', code: 'authorization_archive_failed' },
    })
  })

  test('a user with no projects is deleted as before', async () => {
    const res = await del('member-1')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ success: true })
    expect(h.users.has('member-1')).toBe(false)
    expect(h.events).toEqual(['user-delete member-1'])
    expect(h.agentBodies).toEqual([])
    expect(rows('user.delete')[0]).toMatchObject({
      before: { ownedProjectCount: 0 }, after: { projectsDeleted: [] },
    })
  })

  test('the triage stop names the project owner, not the deleting admin', async () => {
    own('member-1', 'p1')
    expect((await del('member-1')).status).toBe(200)
    const triage = h.agentBodies.filter(c => c.path === '/graph/triage').map(c => c.body)
    expect(triage).toEqual([{ op: 'stop_run', user_id: 'member-1', project_id: 'p1' }])
  })
})

describe('what the teardown does not change', () => {
  test('the workspace purge and the body collection run once per project, not again after the account', async () => {
    own('member-1', 'p1', 'p2')
    expect((await del('member-1')).status).toBe(200)
    expect(h.events.filter(e => e.startsWith('purge'))).toEqual(['purge p1', 'purge p2'])
    expect(h.events.filter(e => e.startsWith('collect-bodies'))).toEqual(['collect-bodies p1', 'collect-bodies p2'])
  })

  test('a project its owner deleted meanwhile does not stop the account delete', async () => {
    own('member-1', 'p1', 'p2')
    h.vanished = 'p1'
    const res = await del('member-1')
    expect(res.status).toBe(200)
    expect(h.users.has('member-1')).toBe(false)
    expect(rows('user.delete')[0]).toMatchObject({ after: { projectsDeleted: ['p2'] } })
  })

  test('a refused step-up tears nothing down', async () => {
    own('admin-2', 'p1')
    const res = await del('admin-2', { stepUpPassword: 'guess-guess-guess' })
    expect(res.status).toBe(403)
    expect(h.events).toEqual([])
    expect(h.projects.map(p => p.id)).toEqual(['p1'])
  })

  test('a deletion the last-admin rule refuses tears nothing down', async () => {
    // admin-1 lost its role a moment ago; its session was read before.
    h.users.get('admin-1')!.role = 'standard'
    own('admin-2', 'p1')
    const res = await del('admin-2', { stepUpPassword: PW.admin1 })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('last_admin')
    expect(h.events).toEqual([])
    expect(h.projects.map(p => p.id)).toEqual(['p1'])
  })

  test('another admin with projects: torn down, then deleted under the lock', async () => {
    own('admin-2', 'p1')
    const res = await del('admin-2', { stepUpPassword: PW.admin1 })
    expect(res.status).toBe(200)
    expect(h.users.has('admin-2')).toBe(false)
    expect(h.events.at(-1)).toBe('user-delete admin-2')
    expect(h.events).toContain('clear-graph p1')
  })
})

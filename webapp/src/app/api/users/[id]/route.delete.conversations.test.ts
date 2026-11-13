/**
 * Deleting a collaborator keeps their conversations in other people's projects (step 5.8; T24, DV-23):
 * inside the transaction that deletes the account, before the row whose cascade would take them, each goes
 * to its project's owner with the former author's id and name (or email) kept. Conversation.userId stays
 * non-null, so the previous release's push still succeeds. A deletion that fails moves nothing. With the
 * write switch off the conversations go with the account, as before (DV-30).
 *
 * The route, the reassignment and the audit writer are real; Prisma is an in-memory table set whose user
 * delete cascades into the conversations as Postgres does; the permission, Root and act-as checks (their
 * own tests) and the project teardown are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/users/[id]/route.delete.conversations.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

type User = { id: string; email: string; name: string | null; role: string }
type Conv = { id: string; projectId: string; userId: string; formerAuthorId: string | null; formerAuthorLabel: string | null }
type Audit = { action: string; targetId: string | null; after?: unknown }

const h = vi.hoisted(() => ({
  users: new Map<string, User>(),
  projects: new Map<string, string>(),
  conversations: [] as Conv[],
  audit: [] as Audit[],
  failUserDelete: false,
}))

vi.mock('@/lib/session', () => ({
  getSession: async () => ({ userId: 'admin-1', role: 'admin' }),
  isInternalRequest: () => false,
  actsAsAccount: async () => false,
  actAsInForceFor: async () => null,
}))
vi.mock('@/lib/projectTeardown', () => ({ teardownProject: async () => ({ ok: true, steps: [] }) }))
vi.mock('@/lib/authz/adminPermission', () => ({ requireSessionPermission: async () => null, sessionHolds: async () => true }))
vi.mock('@/lib/authz/rootProtection', () => ({ rootProtectedRefusal: async () => null, rootProtectedAnswer: async () => null }))
vi.mock('@/lib/authz/actAsRefusals', () => ({ refuseWhileActingAs: async () => null }))
vi.mock('@/lib/prisma', () => {
  const matches = (c: Conv, where: { userId: string; project?: { userId: { not: string } }; id?: { in: string[] } }) =>
    c.userId === where.userId
    && (!where.project || h.projects.get(c.projectId) !== where.project.userId.not)
    && (!where.id || where.id.in.includes(c.id))
  const db: Record<string, unknown> = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => h.users.get(where.id) ?? null,
      delete: async ({ where }: { where: { id: string } }) => {
        if (h.failUserDelete) throw Object.assign(new Error('connection reset'), { code: 'P1017' })
        if (!h.users.delete(where.id)) throw Object.assign(new Error('missing'), { code: 'P2025' })
        // Conversation.user is onDelete: Cascade.
        h.conversations = h.conversations.filter(c => c.userId !== where.id)
        return {}
      },
    },
    project: { findMany: async () => [] },
    nucleiTemplate: { updateMany: async () => ({ count: 0 }) },
    conversation: {
      findMany: async ({ where }: { where: Parameters<typeof matches>[1] }) =>
        h.conversations.filter(c => matches(c, where)).map(c => ({ id: c.id, project: { userId: h.projects.get(c.projectId)! } })),
      updateMany: async ({ where, data }: { where: Parameters<typeof matches>[1]; data: Partial<Conv> }) => {
        const hit = h.conversations.filter(c => matches(c, where))
        for (const c of hit) Object.assign(c, data)
        return { count: hit.length }
      },
    },
    auditLog: { create: async ({ data }: { data: Audit }) => { h.audit.push(data); return data } },
    $executeRaw: async () => 1,
  }
  db.$transaction = async (fn: (tx: unknown) => Promise<unknown>) => {
    const snapshot = h.conversations.map(c => ({ ...c }))
    try {
      return await fn(db)
    } catch (err) {
      h.conversations = snapshot
      throw err
    }
  }
  return { default: db }
})

import { DELETE } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'

const del = (id: string) => DELETE(new NextRequest(`http://localhost/api/users/${id}`, { method: 'DELETE' }), { params: Promise.resolve({ id }) })
const conv = (id: string) => h.conversations.find(c => c.id === id)

beforeEach(() => {
  h.users = new Map([
    ['admin-1', { id: 'admin-1', email: 'admin-1@example.test', name: 'Ada', role: 'admin' }],
    ['bob', { id: 'bob', email: 'bob@example.test', name: 'Bob Writer', role: 'standard' }],
    ['nameless', { id: 'nameless', email: 'nameless@example.test', name: null, role: 'standard' }],
    ['alice', { id: 'alice', email: 'alice@example.test', name: 'Alice', role: 'standard' }],
    ['olga', { id: 'olga', email: 'olga@example.test', name: 'Olga', role: 'standard' }],
  ])
  h.projects = new Map([['P-alice', 'alice'], ['P-olga', 'olga']])
  h.conversations = [
    { id: 'c1', projectId: 'P-alice', userId: 'bob', formerAuthorId: null, formerAuthorLabel: null },
    { id: 'c2', projectId: 'P-olga', userId: 'bob', formerAuthorId: null, formerAuthorLabel: null },
    { id: 'c3', projectId: 'P-alice', userId: 'alice', formerAuthorId: null, formerAuthorLabel: null },
    { id: 'c4', projectId: 'P-alice', userId: 'nameless', formerAuthorId: null, formerAuthorLabel: null },
  ]
  h.audit = []
  h.failUserDelete = false
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe("DELETE /api/users/[id] and the deleted collaborator's conversations (step 5.8, DV-23)", () => {
  test("each goes to its project's owner with the former author kept; the account is gone; the audit row counts them", async () => {
    const res = await del('bob')
    expect(res.status).toBe(200)
    expect(h.users.has('bob')).toBe(false)
    expect(conv('c1')).toEqual({ id: 'c1', projectId: 'P-alice', userId: 'alice', formerAuthorId: 'bob', formerAuthorLabel: 'Bob Writer' })
    expect(conv('c2')).toEqual({ id: 'c2', projectId: 'P-olga', userId: 'olga', formerAuthorId: 'bob', formerAuthorLabel: 'Bob Writer' })
    expect(conv('c3')).toMatchObject({ userId: 'alice', formerAuthorId: null })
    expect(h.audit.find(a => a.action === 'user.delete')).toMatchObject({ targetId: 'bob', after: { conversationsReassigned: 2 } })
  })

  test('without a name the label is the email, as it was at the deletion', async () => {
    expect((await del('nameless')).status).toBe(200)
    expect(conv('c4')).toMatchObject({ userId: 'alice', formerAuthorId: 'nameless', formerAuthorLabel: 'nameless@example.test' })
  })

  test('a deletion that fails moves nothing: the conversations stay their author\'s', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.failUserDelete = true
    expect((await del('bob')).status).toBe(500)
    expect(conv('c1')).toMatchObject({ userId: 'bob', formerAuthorId: null })
    expect(conv('c2')).toMatchObject({ userId: 'bob', formerAuthorId: null })
  })

  test('with the write switch off the conversations go with the account, as before, and the audit row is unchanged', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect((await del('bob')).status).toBe(200)
    expect(h.conversations.map(c => c.id)).toEqual(['c3', 'c4'])
    const row = h.audit.find(a => a.action === 'user.delete')
    expect(row?.after).not.toHaveProperty('conversationsReassigned')
  })
})

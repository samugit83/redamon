/**
 * Deleting a user hands their own Nuclei templates to the admin who deletes the
 * account (DV-33, OQ-50): no member gains them (an instance template needs a
 * promotion), and no file is lost. The handover and the account delete are one
 * transaction, so a deletion that fails leaves the templates with their owner.
 *
 * The route, the last-admin guard and the audit writer are real; Prisma is an
 * in-memory table set; the project teardown has its own tests and is a double.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/users/[id]/route.delete.templates.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import bcrypt from 'bcryptjs'
import { NextRequest } from 'next/server'

type User = { id: string; email: string; name: string; role: string; password: string }
type Template = { path: string; ownerUserId: string | null }
type Audit = { actorId: string | null; action: string; targetId: string | null; before?: unknown; after?: unknown }

const h = vi.hoisted(() => ({
  users: new Map<string, User>(),
  templates: [] as Template[],
  audit: [] as Audit[],
  session: null as { userId: string; role: string } | null,
  failUserDelete: false,
  transactions: 0,
}))

vi.mock('@/lib/session', () => ({ getSession: async () => h.session, isInternalRequest: () => false }))
vi.mock('@/lib/projectTeardown', () => ({ teardownProject: async () => ({ ok: true, steps: [] }) }))
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
        if (h.failUserDelete) throw Object.assign(new Error('connection reset'), { code: 'P1017' })
        if (!h.users.delete(where.id)) throw Object.assign(new Error('missing'), { code: 'P2025' })
        return {}
      },
    },
    project: { findMany: async () => [] },
    nucleiTemplate: {
      updateMany: async ({ where, data }: { where: { ownerUserId: string }; data: { ownerUserId: string } }) => {
        const owned = h.templates.filter(t => t.ownerUserId === where.ownerUserId)
        for (const t of owned) t.ownerUserId = data.ownerUserId
        return { count: owned.length }
      },
    },
    auditLog: { create: async ({ data }: { data: Audit }) => { h.audit.push(data); return data } },
    $executeRaw: async () => 1,
  }
  // Rolls back the template rows when the callback throws, as Postgres would.
  db.$transaction = async (fn: (tx: unknown) => Promise<unknown>) => {
    h.transactions++
    const snapshot = h.templates.map(t => ({ ...t }))
    try {
      return await fn(db)
    } catch (err) {
      h.templates = snapshot
      throw err
    }
  }
  return { default: db }
})

import { DELETE } from './route'

const PW = 'rbac-admin-passphrase'

function account(id: string, role: 'admin' | 'standard') {
  h.users.set(id, { id, email: `${id}@e2e.local`, name: id, role, password: bcrypt.hashSync(PW, 4) })
}
const del = (id: string, body: Record<string, unknown> = {}) =>
  DELETE(new NextRequest(`http://localhost/api/users/${id}`, {
    method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id }) })
const ownerOf = (p: string) => h.templates.find(t => t.path === p)?.ownerUserId

beforeEach(() => {
  h.users.clear()
  h.audit = []
  h.failUserDelete = false
  h.transactions = 0
  account('admin-1', 'admin')
  account('admin-2', 'admin')
  account('member-1', 'standard')
  account('member-2', 'standard')
  h.templates = [
    { path: 'm1-a.yaml', ownerUserId: 'member-1' },
    { path: 'team/m1-b.yaml', ownerUserId: 'member-1' },
    { path: 'm2.yaml', ownerUserId: 'member-2' },
    { path: 'shipped.yaml', ownerUserId: null },
    { path: 'admin2.yaml', ownerUserId: 'admin-2' },
  ]
  h.session = { userId: 'admin-1', role: 'admin' }
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

describe('DELETE /api/users/[id] and the Nuclei templates', () => {
  test('templates reassigned to the deleting admin, not to the instance', async () => {
    const res = await del('member-1')
    expect(res.status).toBe(200)
    expect(h.users.has('member-1')).toBe(false)
    expect(ownerOf('m1-a.yaml')).toBe('admin-1')
    expect(ownerOf('team/m1-b.yaml')).toBe('admin-1')
    // Nobody else's row moves, and none becomes an instance template.
    expect(ownerOf('m2.yaml')).toBe('member-2')
    expect(ownerOf('shipped.yaml')).toBeNull()
    expect(h.templates.filter(t => t.ownerUserId === null)).toHaveLength(1)
    expect(h.audit.find(a => a.action === 'user.delete')).toMatchObject({
      actorId: 'admin-1', targetId: 'member-1', after: { projectsDeleted: [], templatesReassigned: 2 },
    })
  })

  test('the handover and the account delete are one transaction: a failed delete keeps the owner', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.failUserDelete = true
    const res = await del('member-1')
    expect(res.status).toBe(500)
    expect(h.users.has('member-1')).toBe(true)
    expect(ownerOf('m1-a.yaml')).toBe('member-1')
    expect(ownerOf('team/m1-b.yaml')).toBe('member-1')
    expect(h.audit.some(a => a.action === 'user.delete')).toBe(false)
  })

  test("another admin's templates go to the deleting admin, inside the last-admin transaction", async () => {
    const res = await del('admin-2', { stepUpPassword: PW })
    expect(res.status).toBe(200)
    expect(ownerOf('admin2.yaml')).toBe('admin-1')
    // The pre-teardown last-admin check, then the locked delete with the handover.
    expect(h.transactions).toBe(2)
  })

  test('a refused deletion hands nothing over', async () => {
    const res = await del('admin-2')
    expect(res.status).toBe(403)
    expect(ownerOf('admin2.yaml')).toBe('admin-2')
    h.session = { userId: 'member-2', role: 'standard' }
    expect((await del('member-1')).status).toBe(403)
    expect(ownerOf('m1-a.yaml')).toBe('member-1')
  })

  test('a user with no templates is deleted as before', async () => {
    const res = await del('member-2')
    expect(res.status).toBe(200)
    expect(h.audit.find(a => a.action === 'user.delete')).toMatchObject({ after: { templatesReassigned: 1 } })
    h.templates = []
    account('member-3', 'standard')
    expect((await del('member-3')).status).toBe(200)
    expect(h.audit.filter(a => a.action === 'user.delete').at(-1)).toMatchObject({ after: { projectsDeleted: [], templatesReassigned: 0 } })
  })
})

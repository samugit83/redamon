/**
 * The audit of user administration (HD-14, AU-02 part, the audit part of HD-09).
 *
 * One test per action: the action name, the actor (the REAL signed-in account),
 * the target, the before/after an operator reads, and that no password, hash or
 * token is ever in a row. `actingAsUserId` is added when an admin acted through
 * an act-as cookie that admin minted.
 *
 * The routes, the audit writer, the act-as token and bcrypt are real; Prisma is
 * an in-memory table set and the session is a double (the login cookie is
 * session.ts's business, tested there).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import bcrypt from 'bcryptjs'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

type UserRow = { id: string; name: string; email: string; role: string; password: string; createdAt: Date; updatedAt: Date }
type AuditRow = { actorId: string | null; action: string; targetType: string; targetId: string | null; before?: unknown; after?: unknown; source: string }

const h = vi.hoisted(() => ({
  users: new Map<string, UserRow>(),
  projects: [] as { id: string; userId: string }[],
  tokens: [] as { userId: string; revokedAt: Date | null }[],
  audit: [] as AuditRow[],
  session: null as { userId: string; role: string } | null,
}))

vi.mock('@/lib/session', () => ({
  getSession: async () => h.session,
  isInternalRequest: () => false,
}))
vi.mock('@/lib/workspacePurge', () => ({ purgeProjectWorkspace: async () => undefined }))
// The teardown of each project has its own tests (route.delete.teardown.test.ts);
// here it only has to succeed, so the row can be read.
vi.mock('@/lib/projectTeardown', () => ({ teardownProject: async () => ({ ok: true, steps: [] }) }))
vi.mock('@/lib/prisma', () => {
  const pick = (row: UserRow, select?: Record<string, boolean>) =>
    select ? Object.fromEntries(Object.keys(select).filter(k => select[k]).map(k => [k, row[k as keyof UserRow]])) : { ...row }
  const db: Record<string, unknown> = {
    user: {
      findUnique: async ({ where, select }: { where: { id: string }; select?: Record<string, boolean> }) => {
        const row = h.users.get(where.id)
        return row ? pick(row, select) : null
      },
      create: async ({ data }: { data: Partial<UserRow> }) => {
        const row: UserRow = {
          id: `new-${h.users.size + 1}`, role: 'standard', password: '', name: '', email: '',
          createdAt: new Date(), updatedAt: new Date(), ...data,
        }
        h.users.set(row.id, row)
        return { ...row }
      },
      update: async ({ where, data, select }: { where: { id: string }; data: Partial<UserRow>; select?: Record<string, boolean> }) => {
        const row = h.users.get(where.id)
        if (!row) throw Object.assign(new Error('missing'), { code: 'P2025' })
        Object.assign(row, data)
        return pick(row, select)
      },
      delete: async ({ where }: { where: { id: string } }) => {
        if (!h.users.delete(where.id)) throw Object.assign(new Error('missing'), { code: 'P2025' })
        return {}
      },
      count: async ({ where }: { where: { role: string; id: { not: string }; password: { not: string } } }) =>
        [...h.users.values()].filter(r =>
          r.role === where.role && r.id !== where.id.not && r.password !== where.password.not).length,
    },
    project: {
      findMany: async ({ where }: { where: { userId: string } }) =>
        h.projects.filter(p => p.userId === where.userId).map(p => ({ id: p.id, userId: p.userId })),
    },
    capturedHttpTransaction: { findMany: async () => [] },
    mcpAccessToken: {
      updateMany: async ({ where, data }: { where: { userId: string }; data: { revokedAt: Date } }) => {
        const live = h.tokens.filter(t => t.userId === where.userId && t.revokedAt === null)
        for (const t of live) t.revokedAt = data.revokedAt
        return { count: live.length }
      },
    },
    auditLog: {
      create: async ({ data }: { data: AuditRow }) => { h.audit.push(data); return data },
    },
    // emailTakenByAnother: SELECT id FROM users WHERE lower(email) = lower($1)
    $queryRaw: async (_s: TemplateStringsArray, email: string) =>
      [...h.users.values()].filter(r => r.email.toLowerCase() === email.toLowerCase()).map(r => ({ id: r.id })),
    $executeRaw: async () => 1,
  }
  db.$transaction = async (arg: unknown) =>
    Array.isArray(arg) ? Promise.all(arg) : (arg as (tx: unknown) => Promise<unknown>)(db)
  return { default: db }
})

import { __resetThrottle } from '@/lib/loginThrottle'
import { createActAsToken, createToken } from '@/lib/auth'
import { POST as createUser } from './route'
import { PUT as updateUser, DELETE as deleteUser } from './[id]/route'
import { PUT as setPassword } from './[id]/password/route'
import { POST as logout } from '../auth/logout/route'

const PW = {
  admin1: 'admin-one-passphrase',
  admin2: 'admin-two-passphrase',
  member: 'member-old-passphrase',
}
const NEW_PASSWORD = 'a-brand-new-passphrase'

function seed() {
  h.users.clear()
  h.projects.length = 0
  h.tokens.length = 0
  h.audit.length = 0
  const now = new Date()
  const add = (id: string, role: string, password: string, name = id) =>
    h.users.set(id, { id, name, email: `${id}@e2e.local`, role, password: password ? bcrypt.hashSync(password, 4) : '', createdAt: now, updatedAt: now })
  add('admin-1', 'admin', PW.admin1, 'Admin One')
  add('admin-2', 'admin', PW.admin2, 'Admin Two')
  add('member-1', 'standard', PW.member, 'Member One')
}

const params = (id: string) => ({ params: Promise.resolve({ id }) })

function jsonReq(url: string, method: string, body: unknown, cookie?: string): NextRequest {
  return new NextRequest(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  })
}

/** Everything a row must never carry: the passwords sent, every stored hash, any bcrypt hash. */
function expectNoSecret(row: AuditRow, extra: string[] = []) {
  const text = JSON.stringify(row)
  const secrets = [...Object.values(PW), NEW_PASSWORD, ...[...h.users.values()].map(u => u.password).filter(Boolean), ...extra]
  for (const s of secrets) expect(text).not.toContain(s)
  expect(text).not.toMatch(/\$2[aby]\$/)
  expect(text).not.toMatch(/"(password|newPassword|currentPassword|stepUpPassword|token)"/)
}

const rows = (action: string) => h.audit.filter(r => r.action === action)

beforeEach(() => {
  seed()
  h.session = { userId: 'admin-1', role: 'admin' }
  __resetThrottle()
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

describe('user.create', () => {
  test('the admin, the new account, its email, role and whether it has a password', async () => {
    const res = await createUser(jsonReq('http://localhost/api/users', 'POST', {
      name: 'New Member', email: 'New.Member@E2E.local', password: NEW_PASSWORD, role: 'standard',
    }))
    expect(res.status).toBe(201)
    const { id } = await res.json()
    const [row] = rows('user.create')
    expect(row).toMatchObject({
      actorId: 'admin-1', targetType: 'user', targetId: id, source: 'api',
      after: { email: 'new.member@e2e.local', role: 'standard', passwordless: false },
    })
    expect(rows('user.create')).toHaveLength(1)
    expectNoSecret(row)
  })

  test('a passwordless (managed) account says so', async () => {
    await createUser(jsonReq('http://localhost/api/users', 'POST', { name: 'Managed', email: 'managed@e2e.local', role: 'admin' }))
    expect(rows('user.create')[0].after).toEqual({ email: 'managed@e2e.local', role: 'admin', passwordless: true })
  })

  test('a refused creation writes no row', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    const res = await createUser(jsonReq('http://localhost/api/users', 'POST', { name: 'x', email: 'x@e2e.local' }))
    expect(res.status).toBe(403)
    h.session = { userId: 'admin-1', role: 'admin' }
    const short = await createUser(jsonReq('http://localhost/api/users', 'POST', { name: 'x', email: 'x@e2e.local', password: 'short' }))
    expect(short.status).toBe(400)
    const taken = await createUser(jsonReq('http://localhost/api/users', 'POST', { name: 'x', email: 'MEMBER-1@e2e.local' }))
    expect(taken.status).toBe(409)
    expect(h.audit).toEqual([])
  })
})

describe('user.update', () => {
  test('before and after of the name and email that changed', async () => {
    const res = await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', {
      name: 'Member Renamed', email: 'Renamed@E2E.local',
    }), params('member-1'))
    expect(res.status).toBe(200)
    const [row] = rows('user.update')
    expect(row).toMatchObject({
      actorId: 'admin-1', targetType: 'user', targetId: 'member-1',
      before: { name: 'Member One', email: 'member-1@e2e.local' },
      after: { name: 'Member Renamed', email: 'renamed@e2e.local' },
    })
    expectNoSecret(row)
    expect(rows('user.role_changed')).toEqual([])
  })

  test('a member editing their own name is the actor and the target', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { name: 'Me Again' }), params('member-1'))
    expect(rows('user.update')).toEqual([expect.objectContaining({
      actorId: 'member-1', targetId: 'member-1', before: { name: 'Member One' }, after: { name: 'Me Again' },
    })])
  })

  test('an unchanged value and the remembered model defaults write no row', async () => {
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { name: 'Member One' }), params('member-1'))
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { defaultAgentModel: 'openai/gpt-5' }), params('member-1'))
    expect(h.audit).toEqual([])
  })
})

describe('user.role_changed', () => {
  test('a promotion: before and after role', async () => {
    const res = await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { role: 'admin' }), params('member-1'))
    expect(res.status).toBe(200)
    const [row] = rows('user.role_changed')
    expect(row).toMatchObject({
      actorId: 'admin-1', targetType: 'user', targetId: 'member-1',
      before: { role: 'standard' }, after: { role: 'admin' },
    })
    expectNoSecret(row)
  })

  test('a demotion of another admin, after the step-up: the step-up password is not in the row', async () => {
    const res = await updateUser(jsonReq('http://localhost/api/users/admin-2', 'PUT', {
      role: 'standard', stepUpPassword: PW.admin1,
    }), params('admin-2'))
    expect(res.status).toBe(200)
    const [row] = rows('user.role_changed')
    expect(row).toMatchObject({ actorId: 'admin-1', targetId: 'admin-2', before: { role: 'admin' }, after: { role: 'standard' } })
    expectNoSecret(row)
  })

  test('a demotion refused (step-up missing, last admin) writes no row', async () => {
    expect((await updateUser(jsonReq('http://localhost/api/users/admin-2', 'PUT', { role: 'standard' }), params('admin-2'))).status).toBe(403)
    h.users.get('admin-2')!.role = 'standard'
    expect((await updateUser(jsonReq('http://localhost/api/users/admin-1', 'PUT', { role: 'standard' }), params('admin-1'))).status).toBe(409)
    expect(h.audit).toEqual([])
  })

  test('setting the role it already has writes no row', async () => {
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { role: 'standard' }), params('member-1'))
    expect(h.audit).toEqual([])
  })
})

describe('user.delete', () => {
  test('before: the email, the role and how many projects the account owned', async () => {
    h.projects.push({ id: 'p1', userId: 'member-1' }, { id: 'p2', userId: 'member-1' }, { id: 'p3', userId: 'admin-1' })
    const res = await deleteUser(jsonReq('http://localhost/api/users/member-1', 'DELETE', {}), params('member-1'))
    expect(res.status).toBe(200)
    const [row] = rows('user.delete')
    expect(row).toMatchObject({
      actorId: 'admin-1', targetType: 'user', targetId: 'member-1',
      before: { email: 'member-1@e2e.local', role: 'standard', ownedProjectCount: 2 },
      after: { projectsDeleted: ['p1', 'p2'] },
    })
    expectNoSecret(row)
  })

  test('deleting another admin after the step-up', async () => {
    const res = await deleteUser(jsonReq('http://localhost/api/users/admin-2', 'DELETE', { stepUpPassword: PW.admin1 }), params('admin-2'))
    expect(res.status).toBe(200)
    const [row] = rows('user.delete')
    expect(row).toMatchObject({ targetId: 'admin-2', before: { email: 'admin-2@e2e.local', role: 'admin', ownedProjectCount: 0 } })
    expectNoSecret(row)
  })

  test('a refused deletion writes no row', async () => {
    expect((await deleteUser(jsonReq('http://localhost/api/users/admin-2', 'DELETE', {}), params('admin-2'))).status).toBe(403)
    expect((await deleteUser(jsonReq('http://localhost/api/users/admin-1', 'DELETE', {}), params('admin-1'))).status).toBe(400)
    expect(h.audit).toEqual([])
  })
})

describe('user.password_changed and user.credentials_reset', () => {
  test('user.password_changed: a member changing their own password', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    h.tokens.push({ userId: 'member-1', revokedAt: null })
    const res = await setPassword(jsonReq('http://localhost/api/users/member-1/password', 'PUT', {
      newPassword: NEW_PASSWORD, currentPassword: PW.member,
    }), params('member-1'))
    expect(res.status).toBe(200)
    const [row] = rows('user.password_changed')
    expect(row).toMatchObject({ actorId: 'member-1', targetType: 'user', targetId: 'member-1', after: { revokedMcpTokens: 1 } })
    expect(rows('user.credentials_reset')).toEqual([])
    for (const r of h.audit) expectNoSecret(r)
  })

  test('user.credentials_reset: an admin resetting another account', async () => {
    const res = await setPassword(jsonReq('http://localhost/api/users/member-1/password', 'PUT', { newPassword: NEW_PASSWORD }), params('member-1'))
    expect(res.status).toBe(200)
    const [row] = rows('user.credentials_reset')
    expect(row).toMatchObject({ actorId: 'admin-1', targetType: 'user', targetId: 'member-1', after: { revokedMcpTokens: 0 } })
    expect(rows('user.password_changed')).toEqual([])
    expectNoSecret(row)
  })

  test('resetting another admin after the step-up', async () => {
    const res = await setPassword(jsonReq('http://localhost/api/users/admin-2/password', 'PUT', {
      newPassword: NEW_PASSWORD, stepUpPassword: PW.admin1,
    }), params('admin-2'))
    expect(res.status).toBe(200)
    expect(rows('user.credentials_reset')).toEqual([expect.objectContaining({ actorId: 'admin-1', targetId: 'admin-2' })])
    for (const r of h.audit) expectNoSecret(r)
  })

  test('a refused change writes no row', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    const res = await setPassword(jsonReq('http://localhost/api/users/member-1/password', 'PUT', {
      newPassword: NEW_PASSWORD, currentPassword: 'not-the-current-one',
    }), params('member-1'))
    expect(res.status).toBe(401)
    expect(h.audit).toEqual([])
  })
})

describe('an admin acting as another account', () => {
  test('the actor stays the real admin; after.actingAsUserId names the account acted as', async () => {
    const actAs = await createActAsToken('admin-1', 'member-1')
    const cookie = `redamon-act-as=${actAs}`
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { name: 'Edited Through Act-As' }, cookie), params('member-1'))
    await setPassword(jsonReq('http://localhost/api/users/member-1/password', 'PUT', { newPassword: NEW_PASSWORD }, cookie), params('member-1'))
    expect(rows('user.update')[0]).toMatchObject({ actorId: 'admin-1', after: { name: 'Edited Through Act-As', actingAsUserId: 'member-1' } })
    expect(rows('user.credentials_reset')[0]).toMatchObject({ actorId: 'admin-1', after: { actingAsUserId: 'member-1' } })
    for (const r of h.audit) expectNoSecret(r, [actAs])
  })

  test('a cookie another admin minted, or a forged one, is not an act-as', async () => {
    const foreign = await createActAsToken('admin-2', 'member-1')
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { name: 'One' }, `redamon-act-as=${foreign}`), params('member-1'))
    await updateUser(jsonReq('http://localhost/api/users/member-1', 'PUT', { name: 'Two' }, 'redamon-act-as=forged.token.value'), params('member-1'))
    const updates = rows('user.update')
    expect(updates).toHaveLength(2)
    for (const r of updates) expect(r.after).not.toHaveProperty('actingAsUserId')
  })
})

describe('auth.logout', () => {
  const logoutReq = (cookie?: string) =>
    new NextRequest('http://localhost/api/auth/logout', { method: 'POST', headers: cookie ? { cookie } : {} })

  test('the row names the account that signed out', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    const auth = await createToken('member-1', 'standard')
    const res = await logout(logoutReq(`redamon-auth=${auth}`))
    expect(res.status).toBe(200)
    const [row] = rows('auth.logout')
    expect(row).toMatchObject({ actorId: 'member-1', targetType: 'session' })
    expectNoSecret(row, [auth])
  })

  test('an admin signing out while acting as someone: the real admin, and the account acted as', async () => {
    const actAs = await createActAsToken('admin-1', 'member-1')
    await logout(logoutReq(`redamon-act-as=${actAs}`))
    expect(rows('auth.logout')[0]).toMatchObject({ actorId: 'admin-1', after: { actingAsUserId: 'member-1' } })
    expectNoSecret(rows('auth.logout')[0], [actAs])
  })

  test('no session still signs out, with no actor', async () => {
    h.session = null
    const res = await logout(logoutReq())
    expect(res.status).toBe(200)
    expect(rows('auth.logout')[0].actorId).toBeNull()
  })
})

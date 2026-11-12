/**
 * Email change (step 2.11, ID-30, ID-25; feature document §3 F-21): with the identity switch on,
 * changing the account's own sign-in email needs its current password, and an admin changing a
 * member's email needs the admin's own password (step-up; another admin's is Root's, step 2.6).
 * The change, its `user.email_changed` row (fail closed) and a notice to the account commit
 * together; the address is stored lowercased and one that another account holds in any case
 * answers 409 `email_taken`, only after the password, so the answer never tells an address's
 * existence to a cookie without it. A name alone needs no password. With the switch off the
 * Phase 1 edit answers.
 *
 * Real session helpers, tokens, bcrypt and step-up; the database is the in-memory accountDb
 * (transactions roll back, the case-insensitive address read included).
 *
 * Run: npx vitest run --no-file-parallelism 'src/app/api/users/[id]/route.emailChange.test.ts'
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken, createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { readNotices } from '@/lib/authz/accountNotices'
import { setNowForTests } from '@/lib/authz/clock'
import { __resetThrottle } from '@/lib/loginThrottle'
import { PUT as editUser } from './route'

const db = () => h.db as AccountDb
const ROOT = 'root-1'
const PW: Record<string, string> = {
  [ROOT]: 'root-own-passphrase-0001',
  'admin-2': 'admin-two-passphrase-0002',
  'member-1': 'member-one-passphrase-0003',
}
const HASH = Object.fromEntries(Object.entries(PW).map(([id, pw]) => [id, bcrypt.hashSync(pw, 4)]))
const AT = new Date('2026-11-12T12:00:00Z')

function req(body: unknown): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (h.jar.actAs) headers.cookie = `redamon-act-as=${h.jar.actAs}`
  return new NextRequest('http://redamon.test/api/users/x', { method: 'PUT', headers, body: JSON.stringify(body) })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string, actingAs?: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

async function codeOf(res: Response): Promise<string | undefined> {
  return (await res.clone().json().catch(() => ({}))).code
}
const emailOf = (id: string) => db().account(id)!.email
const rows = (action: string) => db().audit().filter((a) => a.action === action)
const noticesOf = (id: string) => readNotices(db().account(id)!.pendingNotices)

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local', password: HASH[ROOT] },
    { id: 'admin-2', name: 'Pia', role: 'admin', email: 'adm2@e2e.local', password: HASH['admin-2'] },
    { id: 'admin-3', name: 'Ines', role: 'admin', email: 'adm3@e2e.local' },
    { id: 'member-1', name: 'Marco', email: 'mem1@e2e.local', password: HASH['member-1'] },
    { id: 'member-2', name: 'Old Case', email: 'Taken.Address@E2E.local' },
  ])
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true })
  setNowForTests(() => AT)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('own email change needs the current password', () => {
  test('without it: 403 step_up_required, nothing written', async () => {
    await signIn('member-1')
    const res = await editUser(req({ email: 'marco.new@e2e.local' }), params('member-1'))
    expect(res.status).toBe(403)
    expect(await codeOf(res)).toBe('step_up_required')
    expect(emailOf('member-1')).toBe('mem1@e2e.local')
    expect(db().audit()).toEqual([])
    expect(noticesOf('member-1')).toEqual([])
  })

  test('a wrong one: 403 step_up_failed; the right one changes it, stored lowercased', async () => {
    await signIn('member-1')
    const wrong = await editUser(req({ email: 'marco.new@e2e.local', currentPassword: 'not-my-password-000' }), params('member-1'))
    expect(wrong.status).toBe(403)
    expect(await codeOf(wrong)).toBe('step_up_failed')
    expect(emailOf('member-1')).toBe('mem1@e2e.local')

    const res = await editUser(req({ email: 'Marco.New@E2E.local', currentPassword: PW['member-1'] }), params('member-1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.email).toBe('marco.new@e2e.local')
    expect(body).not.toHaveProperty('sessionVersion')
    expect(body).not.toHaveProperty('pendingNotices')
    expect(emailOf('member-1')).toBe('marco.new@e2e.local')
  })

  test("an admin's and Root's own address takes their own current password too", async () => {
    await signIn('admin-2')
    expect(await codeOf(await editUser(req({ email: 'pia@e2e.local' }), params('admin-2')))).toBe('step_up_required')
    expect((await editUser(req({ email: 'pia@e2e.local', currentPassword: PW['admin-2'] }), params('admin-2'))).status).toBe(200)
    await signIn(ROOT)
    expect(await codeOf(await editUser(req({ email: 'root.new@e2e.local' }), params(ROOT)))).toBe('step_up_required')
    expect((await editUser(req({ email: 'root.new@e2e.local', currentPassword: PW[ROOT] }), params(ROOT))).status).toBe(200)
    expect(emailOf(ROOT)).toBe('root.new@e2e.local')
  })

  test('a name alone, or the same address, needs no password', async () => {
    await signIn('member-1')
    expect((await editUser(req({ name: 'Marco R.' }), params('member-1'))).status).toBe(200)
    expect((await editUser(req({ email: 'mem1@e2e.local', name: 'Marco S.' }), params('member-1'))).status).toBe(200)
    expect(db().account('member-1')!.name).toBe('Marco S.')
    expect(rows('user.email_changed')).toEqual([])
    expect(noticesOf('member-1')).toEqual([])
  })
})

describe('admin change needs step-up', () => {
  test("an admin changing a member's email: its own password first", async () => {
    await signIn('admin-2')
    const missing = await editUser(req({ email: 'marco.x@e2e.local' }), params('member-1'))
    expect(missing.status).toBe(403)
    expect(await codeOf(missing)).toBe('step_up_required')
    // The member's password is not the admin's.
    expect(await codeOf(await editUser(req({ email: 'marco.x@e2e.local', stepUpPassword: PW['member-1'] }), params('member-1'))))
      .toBe('step_up_failed')
    // The own-change field proves nothing about another account.
    expect(await codeOf(await editUser(req({ email: 'marco.x@e2e.local', currentPassword: PW['admin-2'] }), params('member-1'))))
      .toBe('step_up_required')
    expect(emailOf('member-1')).toBe('mem1@e2e.local')
    const res = await editUser(req({ email: 'marco.x@e2e.local', stepUpPassword: PW['admin-2'] }), params('member-1'))
    expect(res.status).toBe(200)
    expect(emailOf('member-1')).toBe('marco.x@e2e.local')
  })

  test("another admin's email stays Root's: root_only before any password", async () => {
    await signIn('admin-2')
    const res = await editUser(req({ email: 'ines.x@e2e.local', stepUpPassword: PW['admin-2'] }), params('admin-3'))
    expect(res.status).toBe(403)
    expect(await codeOf(res)).toBe('root_only')
    await signIn(ROOT)
    expect(await codeOf(await editUser(req({ email: 'ines.x@e2e.local' }), params('admin-3')))).toBe('step_up_required')
    expect((await editUser(req({ email: 'ines.x@e2e.local', stepUpPassword: PW[ROOT] }), params('admin-3'))).status).toBe(200)
    expect(emailOf('admin-3')).toBe('ines.x@e2e.local')
    expect(rows('user.email_changed')).toHaveLength(1)
  })

  test("Root's email is nobody else's to change", async () => {
    await signIn('admin-2')
    const res = await editUser(req({ email: 'mine@e2e.local', stepUpPassword: PW['admin-2'] }), params(ROOT))
    expect(res.status).toBe(403)
    expect(await codeOf(res)).toBe('root_protected')
    expect(emailOf(ROOT)).toBe('root@e2e.local')
  })
})

describe('audited and noticed', () => {
  test("one user.email_changed row and a notice to the account, in the change's transaction", async () => {
    await signIn('admin-2')
    const res = await editUser(req({ email: 'marco.x@e2e.local', stepUpPassword: PW['admin-2'] }), params('member-1'))
    expect(res.status).toBe(200)
    const [row] = rows('user.email_changed')
    expect(row).toMatchObject({
      actorId: 'admin-2', actorEmail: 'adm2@e2e.local', targetType: 'user', targetId: 'member-1',
      before: { email: 'mem1@e2e.local' }, after: { email: 'marco.x@e2e.local' },
    })
    expect(rows('user.update')).toEqual([])
    expect(JSON.stringify(row)).not.toContain(PW['admin-2'])
    expect(noticesOf('member-1')).toEqual([{
      id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      type: 'email_changed',
      at: AT.toISOString(),
      by: { id: 'admin-2', name: 'Pia', email: 'adm2@e2e.local' },
      from: 'mem1@e2e.local',
      to: 'marco.x@e2e.local',
      self: false,
    }])
  })

  test('the own change is noticed too, as made by the account itself', async () => {
    await signIn('member-1')
    await editUser(req({ email: 'marco.new@e2e.local', currentPassword: PW['member-1'] }), params('member-1'))
    expect(noticesOf('member-1')).toMatchObject([{ type: 'email_changed', self: true, from: 'mem1@e2e.local', to: 'marco.new@e2e.local' }])
    expect(rows('user.email_changed')[0]).toMatchObject({ actorId: 'member-1', targetId: 'member-1' })
  })

  test('the name in the same request keeps its user.update row', async () => {
    await signIn('admin-2')
    await editUser(req({ name: 'Marco R.', email: 'marco.x@e2e.local', stepUpPassword: PW['admin-2'] }), params('member-1'))
    expect(rows('user.update')).toMatchObject([{ before: { name: 'Marco' }, after: { name: 'Marco R.' } }])
    expect(rows('user.email_changed')).toHaveLength(1)
  })

  test('the notice joins what the account already holds', async () => {
    const earlier = { id: 'n0', type: 'credentials_reset', at: '2026-11-10T10:00:00.000Z', by: { id: 'admin-2', name: 'Pia', email: 'adm2@e2e.local' }, reason: null, mode: 'link', shownAt: '2026-11-11T10:00:00.000Z' }
    db().reset()
    db().seedUsers([
      { id: 'admin-2', name: 'Pia', role: 'admin', email: 'adm2@e2e.local', password: HASH['admin-2'] },
      { id: 'member-1', name: 'Marco', email: 'mem1@e2e.local', pendingNotices: [earlier] },
    ])
    await signIn('admin-2')
    await editUser(req({ email: 'marco.x@e2e.local', stepUpPassword: PW['admin-2'] }), params('member-1'))
    expect(noticesOf('member-1').map((n) => n.type)).toEqual(['credentials_reset', 'email_changed'])
  })

  test('acting as a member: the real admin is the actor, its password the step-up', async () => {
    await signIn('admin-2', 'member-1')
    expect(await codeOf(await editUser(req({ email: 'marco.x@e2e.local', currentPassword: PW['member-1'] }), params('member-1'))))
      .toBe('step_up_required')
    const res = await editUser(req({ email: 'marco.x@e2e.local', stepUpPassword: PW['admin-2'] }), params('member-1'))
    expect(res.status).toBe(200)
    expect(rows('user.email_changed')[0]).toMatchObject({ actorId: 'admin-2', onBehalfOfUserId: 'member-1' })
    expect(noticesOf('member-1')[0]).toMatchObject({ by: { id: 'admin-2' }, self: false })
  })

  test('audit failure → nothing changed', async () => {
    db().failAudit('user.email_changed')
    await signIn('admin-2')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const res = await editUser(req({ email: 'marco.x@e2e.local', name: 'Marco R.', stepUpPassword: PW['admin-2'] }), params('member-1'))
      expect(res.status).toBe(500)
    } finally {
      err.mockRestore()
    }
    expect(emailOf('member-1')).toBe('mem1@e2e.local')
    expect(db().account('member-1')!.name).toBe('Marco')
    expect(noticesOf('member-1')).toEqual([])
    expect(db().audit()).toEqual([])
  })
})

describe('one account per address, whatever its case', () => {
  test('an address another account holds in other capitals → 409 email_taken, nothing written', async () => {
    await signIn('member-1')
    const res = await editUser(req({ email: 'taken.address@e2e.local', currentPassword: PW['member-1'] }), params('member-1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'A user with this email already exists', code: 'email_taken' })
    expect(emailOf('member-1')).toBe('mem1@e2e.local')
    expect(db().audit()).toEqual([])
  })

  test('without the password the answer is the password one: no address is disclosed', async () => {
    await signIn('member-1')
    const res = await editUser(req({ email: 'TAKEN.address@e2e.local' }), params('member-1'))
    expect(res.status).toBe(403)
    expect(await codeOf(res)).toBe('step_up_required')
  })

  test('recasing its own address is not a collision', async () => {
    await signIn('member-1')
    db().reset()
    db().seedUsers([{ id: 'member-1', name: 'Marco', email: 'Mem1@E2E.local', password: HASH['member-1'] }])
    const res = await editUser(req({ email: 'MEM1@e2e.local', currentPassword: PW['member-1'] }), params('member-1'))
    expect(res.status).toBe(200)
    expect(emailOf('member-1')).toBe('mem1@e2e.local')
  })
})

describe('switch off: Phase 1', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('the own address changes without a password; a user.update row, no notice', async () => {
    await signIn('member-1')
    const res = await editUser(req({ email: 'Marco.New@e2e.local' }), params('member-1'))
    expect(res.status).toBe(200)
    expect(emailOf('member-1')).toBe('marco.new@e2e.local')
    expect(rows('user.update')).toMatchObject([{ before: { email: 'mem1@e2e.local' }, after: { email: 'marco.new@e2e.local' } }])
    expect(rows('user.email_changed')).toEqual([])
    expect(noticesOf('member-1')).toEqual([])
  })

  test("an admin changes a member's address without a password; a collision is still 409", async () => {
    await signIn('admin-2')
    expect((await editUser(req({ email: 'marco.x@e2e.local' }), params('member-1'))).status).toBe(200)
    const taken = await editUser(req({ email: 'TAKEN.ADDRESS@e2e.local' }), params('member-1'))
    expect(taken.status).toBe(409)
    expect(await codeOf(taken)).toBe('email_taken')
  })
})

/**
 * Only Root manages admins (step 2.6, ID-03 powers, ID-05, PE-08, ID-25; feature document §4.4,
 * §4.8): with the identity switch on, creating an admin, promoting a member, demoting or editing
 * another admin, deleting, resetting, disabling, enabling, signing out or acting as another admin
 * is a confirmed Root's power, each with Root's own password (step-up). An admin acts on members
 * only (403 `root_only`, before any password is asked); an unconfirmed Root has Root's
 * protections but not these powers. Every promotion and demotion raises the account's session
 * version in the same transaction as the role and its audit row (fail closed), so the role a
 * cookie was signed for never outlives it. With the switch off the Phase 1 rules answer.
 *
 * Real session helpers, tokens, bcrypt and step-up; the database is the in-memory accountDb
 * (transactions roll back); the agent is a fetch double.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/rootOnlyAdmins.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

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
vi.mock('@/lib/projectTeardown', () => ({
  teardownProject: async () => { throw new Error('the accounts here own no project') },
}))
// The case-insensitive address check is raw SQL the in-memory database does not answer.
vi.mock('@/lib/authz/accountEmail', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/accountEmail')>()),
  emailTakenByAnother: async () => false,
}))

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken, createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getSession } from '@/lib/session'
import { POST as createUser } from '@/app/api/users/route'
import { PUT as editUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'
import { PUT as resetPassword } from '@/app/api/users/[id]/password/route'
import { POST as disableUser } from '@/app/api/users/[id]/disable/route'
import { POST as enableUser } from '@/app/api/users/[id]/enable/route'
import { POST as revokeUserSessions } from '@/app/api/users/[id]/revoke-sessions/route'
import { POST as startActAs } from '@/app/api/auth/act-as/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const PW: Record<string, string> = { [ROOT]: 'root-own-passphrase-0001', 'admin-2': 'admin-two-passphrase-0002' }
const HASH = Object.fromEntries(Object.entries(PW).map(([id, pw]) => [id, bcrypt.hashSync(pw, 4)]))

function req(method: string, body?: unknown): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (h.jar.actAs) headers.cookie = `redamon-act-as=${h.jar.actAs}`
  return new NextRequest('http://redamon.test/api/x', {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string, actingAs?: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

/** The login cookie `userId` holds now, kept to send again after its account changed. */
async function cookieOf(userId: string): Promise<string> {
  const row = db().account(userId)!
  return createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

const confirmedRoot = () => db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
const unconfirmedRoot = () => db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'automatic' })

async function codeOf(res: Response): Promise<string | undefined> {
  return (await res.clone().json().catch(() => ({}))).code
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local', password: HASH[ROOT] },
    { id: 'admin-2', name: 'Pia', role: 'admin', email: 'adm2@e2e.local', password: HASH['admin-2'] },
    { id: 'admin-3', name: 'Ines', role: 'admin', email: 'adm3@e2e.local' },
    { id: 'admin-4', name: 'Off', role: 'admin', email: 'adm4@e2e.local', status: 'disabled', password: '', passwordOnHold: '$2a$12$held-admin-4' },
    { id: 'member-1', name: 'Marco', email: 'mem1@e2e.local' },
  ])
  db().seedToken({ id: 'tok-3', userId: 'admin-3' })
  confirmedRoot()
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string) => new Response(
    JSON.stringify(String(url).endsWith('/ws/close') ? { closed: 0 } : { stopped: 0 }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const NEW_ADMIN = { name: 'New Admin', email: 'rbac-new-admin@e2e.local', password: 'a-long-new-admin-passphrase', role: 'admin' }

describe('creating an admin', () => {
  test('admin cannot create an admin (switch on)', async () => {
    await signIn('admin-2')
    const res = await createUser(req('POST', { ...NEW_ADMIN, stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toMatch(/Only Root/)
    expect(db().account('user-6')).toBeUndefined()
    expect(db().audit()).toEqual([])
  })

  test('an admin still creates a member, with no password asked', async () => {
    await signIn('admin-2')
    const res = await createUser(req('POST', { ...NEW_ADMIN, role: 'standard' }))
    expect(res.status).toBe(201)
    expect((await res.json()).role).toBe('standard')
  })

  test('Root can, with step-up', async () => {
    await signIn(ROOT)
    const missing = await createUser(req('POST', NEW_ADMIN))
    expect(missing.status).toBe(403)
    expect(await codeOf(missing)).toBe('step_up_required')
    const wrong = await createUser(req('POST', { ...NEW_ADMIN, stepUpPassword: 'not-roots-password' }))
    expect(await codeOf(wrong)).toBe('step_up_failed')
    expect(db().audit()).toEqual([])

    const res = await createUser(req('POST', { ...NEW_ADMIN, stepUpPassword: PW[ROOT] }))
    expect(res.status).toBe(201)
    const created = await res.json()
    expect(created).toMatchObject({ email: 'rbac-new-admin@e2e.local', role: 'admin', hasPassword: true })
    expect(db().audit()).toMatchObject([{
      action: 'user.create', actorId: ROOT, targetId: created.id,
      after: { email: 'rbac-new-admin@e2e.local', role: 'admin', passwordless: false },
    }])
    expect(JSON.stringify(db().audit())).not.toContain(PW[ROOT])
  })

  test('creating an admin is audited fail closed: no row, no account', async () => {
    db().failAudit('user.create')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn(ROOT)
    const res = await createUser(req('POST', { ...NEW_ADMIN, stepUpPassword: PW[ROOT] }))
    expect(res.status).toBe(500)
    expect(db().audit()).toEqual([])
    expect((await db().user.findMany()).map((u) => u.email)).not.toContain('rbac-new-admin@e2e.local')
  })

  test('unconfirmed Root cannot', async () => {
    unconfirmedRoot()
    await signIn(ROOT)
    const res = await createUser(req('POST', { ...NEW_ADMIN, stepUpPassword: PW[ROOT] }))
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_only')
    expect(body.error).toMatch(/confirm/)
    expect(body.error).toMatch(/set-root/)
  })

  test('no Root at all: nobody creates an admin until the host names one', async () => {
    db().seedInstance(null)
    await signIn(ROOT)
    expect(await codeOf(await createUser(req('POST', { ...NEW_ADMIN, stepUpPassword: PW[ROOT] })))).toBe('root_only')
  })
})

describe('role editing', () => {
  test('admin cannot demote another admin', async () => {
    await signIn('admin-2')
    const res = await editUser(req('PUT', { role: 'standard', stepUpPassword: PW['admin-2'] }), params('admin-3'))
    expect(res.status).toBe(403)
    expect(await codeOf(res)).toBe('root_only')
    expect(db().account('admin-3')).toMatchObject({ role: 'admin', sessionVersion: 0 })
    expect(db().audit()).toEqual([])
  })

  test('admin cannot promote a member', async () => {
    await signIn('admin-2')
    const res = await editUser(req('PUT', { role: 'admin', stepUpPassword: PW['admin-2'] }), params('member-1'))
    expect(await codeOf(res)).toBe('root_only')
    expect(db().account('member-1')!.role).toBe('standard')
  })

  test('admin cannot edit another admin (name, sign-in address, remembered models)', async () => {
    await signIn('admin-2')
    for (const body of [{ name: 'Renamed' }, { email: 'taken@e2e.local' }, { defaultAgentModel: 'openai/gpt' }]) {
      expect(await codeOf(await editUser(req('PUT', body), params('admin-3')))).toBe('root_only')
    }
    expect(db().account('admin-3')).toMatchObject({ name: 'Ines', email: 'adm3@e2e.local' })
  })

  test('the refusal comes before any password is checked: a wrong one costs nothing', async () => {
    await signIn('admin-2')
    for (let i = 0; i < 6; i++) {
      await editUser(req('PUT', { role: 'standard', stepUpPassword: 'wrong' }), params('admin-3'))
    }
    // Five wrong step-ups would lock the account (429 on its own password change); none was counted.
    const own = await resetPassword(
      req('PUT', { newPassword: 'admin-two-new-passphrase', currentPassword: PW['admin-2'] }), params('admin-2'))
    expect(own.status).toBe(200)
  })

  test('an admin still edits a member and demotes itself', async () => {
    await signIn('admin-2')
    expect((await editUser(req('PUT', { name: 'Marco R.' }), params('member-1'))).status).toBe(200)
    const self = await editUser(req('PUT', { role: 'standard' }), params('admin-2'))
    expect(self.status).toBe(200)
    expect(db().account('admin-2')).toMatchObject({ role: 'standard', sessionVersion: 1 })
  })

  test('Root promotes a member with step-up', async () => {
    await signIn(ROOT)
    const missing = await editUser(req('PUT', { role: 'admin' }), params('member-1'))
    expect(await codeOf(missing)).toBe('step_up_required')
    expect(db().account('member-1')!.role).toBe('standard')
    const res = await editUser(req('PUT', { role: 'admin', stepUpPassword: PW[ROOT] }), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().account('member-1')!.role).toBe('admin')
  })

  test('Root demotes another admin with step-up', async () => {
    await signIn(ROOT)
    expect(await codeOf(await editUser(req('PUT', { role: 'standard' }), params('admin-3')))).toBe('step_up_required')
    const res = await editUser(req('PUT', { role: 'standard', stepUpPassword: PW[ROOT] }), params('admin-3'))
    expect(res.status).toBe(200)
    expect(db().account('admin-3')!.role).toBe('standard')
  })

  test('Root edits another admin with step-up', async () => {
    await signIn(ROOT)
    expect(await codeOf(await editUser(req('PUT', { name: 'Ines B.' }), params('admin-3')))).toBe('step_up_required')
    const res = await editUser(req('PUT', { name: 'Ines B.', stepUpPassword: PW[ROOT] }), params('admin-3'))
    expect(res.status).toBe(200)
    expect(db().account('admin-3')!.name).toBe('Ines B.')
    expect(db().audit()).toMatchObject([{ action: 'user.update', actorId: ROOT, before: { name: 'Ines' }, after: { name: 'Ines B.' } }])
  })

  test('an unconfirmed Root edits members, not admins', async () => {
    unconfirmedRoot()
    await signIn(ROOT)
    expect(await codeOf(await editUser(req('PUT', { role: 'admin', stepUpPassword: PW[ROOT] }), params('member-1')))).toBe('root_only')
    expect(await codeOf(await editUser(req('PUT', { role: 'standard', stepUpPassword: PW[ROOT] }), params('admin-3')))).toBe('root_only')
    expect((await editUser(req('PUT', { name: 'Marco R.' }), params('member-1'))).status).toBe(200)
  })

  test('promotion and demotion bump the session version', async () => {
    const memberCookie = await cookieOf('member-1')
    await signIn(ROOT)
    expect((await editUser(req('PUT', { role: 'admin', stepUpPassword: PW[ROOT] }), params('member-1'))).status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ role: 'admin', sessionVersion: 1 })
    expect(db().audit()).toMatchObject([{
      action: 'user.role_changed', actorId: ROOT, targetId: 'member-1',
      before: { role: 'standard' }, after: { role: 'admin', sessionVersion: 1 },
    }])

    expect((await editUser(req('PUT', { role: 'standard', stepUpPassword: PW[ROOT] }), params('member-1'))).status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ role: 'standard', sessionVersion: 2 })
    expect(db().audit()[1]).toMatchObject({ action: 'user.role_changed', before: { role: 'admin' }, after: { role: 'standard', sessionVersion: 2 } })

    // The cookie the member held before the promotion signs nobody in now.
    clearPrincipalCacheForTests()
    h.jar = { auth: memberCookie }
    expect(await getSession()).toBeNull()
  })

  test('the role, the bump and the audit row commit together: a failed row changes nothing', async () => {
    db().failAudit('user.role_changed')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn(ROOT)
    const promote = await editUser(req('PUT', { role: 'admin', name: 'Marco R.', stepUpPassword: PW[ROOT] }), params('member-1'))
    expect(promote.status).toBe(500)
    expect(db().account('member-1')).toMatchObject({ role: 'standard', name: 'Marco', sessionVersion: 0 })
    const demote = await editUser(req('PUT', { role: 'standard', stepUpPassword: PW[ROOT] }), params('admin-3'))
    expect(demote.status).toBe(500)
    expect(db().account('admin-3')).toMatchObject({ role: 'admin', sessionVersion: 0 })
    expect(db().audit()).toEqual([])
  })

  test('the demotion takes the last-admin lock; a role left as it was bumps nothing', async () => {
    await signIn(ROOT)
    await editUser(req('PUT', { role: 'standard', stepUpPassword: PW[ROOT] }), params('admin-3'))
    expect(db().rawCalls.some((sql) => /pg_advisory_xact_lock/.test(sql))).toBe(true)
    await signIn('admin-2')
    expect((await editUser(req('PUT', { role: 'standard', name: 'Marco' }), params('member-1'))).status).toBe(200)
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })
})

type Action = { name: string; call: (pw?: string) => Promise<Response>; done: () => void; untouched: () => void }

/** Each Root-only action on another admin, sent with Root's password when `pw` is given. */
const ACTIONS: Action[] = [
  {
    name: 'delete an admin',
    call: (pw) => deleteUser(req('DELETE', pw ? { stepUpPassword: pw } : {}), params('admin-3')),
    done: () => expect(db().account('admin-3')).toBeUndefined(),
    untouched: () => expect(db().account('admin-3')).toBeDefined(),
  },
  {
    name: "reset an admin's password",
    call: (pw) => resetPassword(req('PUT', { newPassword: 'a-brand-new-password-0003', ...(pw ? { stepUpPassword: pw } : {}) }), params('admin-3')),
    done: () => expect(db().account('admin-3')!.password).not.toBe('$2a$12$hash-of-admin-3'),
    untouched: () => expect(db().account('admin-3')!.password).toBe('$2a$12$hash-of-admin-3'),
  },
  {
    name: 'disable an admin',
    call: (pw) => disableUser(req('POST', pw ? { stepUpPassword: pw } : {}), params('admin-3')),
    done: () => expect(db().account('admin-3')!.status).toBe('disabled'),
    untouched: () => expect(db().account('admin-3')!.status).toBe('active'),
  },
  {
    name: 'enable an admin',
    call: (pw) => enableUser(req('POST', pw ? { stepUpPassword: pw } : {}), params('admin-4')),
    done: () => expect(db().account('admin-4')!.status).toBe('active'),
    untouched: () => expect(db().account('admin-4')!.status).toBe('disabled'),
  },
  {
    name: 'sign an admin out everywhere',
    call: (pw) => revokeUserSessions(req('POST', pw ? { stepUpPassword: pw } : {}), params('admin-3')),
    done: () => expect(db().account('admin-3')!.sessionVersion).toBe(1),
    untouched: () => expect(db().account('admin-3')!.sessionVersion).toBe(0),
  },
  {
    name: 'act as an admin',
    call: (pw) => startActAs(req('POST', { targetUserId: 'admin-3', ...(pw ? { stepUpPassword: pw } : {}) })),
    done: () => expect(db().actAs()).toMatchObject([{ adminId: ROOT, targetUserId: 'admin-3', event: 'start' }]),
    untouched: () => expect(db().actAs()).toEqual([]),
  },
]

describe('the Root-only actions on another admin', () => {
  for (const a of ACTIONS) {
    test(`${a.name}: an admin is refused root_only, before any password`, async () => {
      await signIn('admin-2')
      const res = await a.call(PW['admin-2'])
      expect(res.status).toBe(403)
      const body = await res.json()
      expect(body.code).toBe('root_only')
      a.untouched()
      expect(db().audit()).toEqual([])
      expect(fetchMock).not.toHaveBeenCalled()
    })

    test(`${a.name}: an admin acting as a member is refused too`, async () => {
      await signIn('admin-2', 'member-1')
      expect(await codeOf(await a.call(PW['admin-2']))).toBe('root_only')
      a.untouched()
    })

    test(`${a.name}: an unconfirmed Root is refused root_only`, async () => {
      unconfirmedRoot()
      await signIn(ROOT)
      expect(await codeOf(await a.call(PW[ROOT]))).toBe('root_only')
      a.untouched()
    })

    test(`${a.name}: Root without its password is asked for it`, async () => {
      await signIn(ROOT)
      const res = await a.call()
      expect(res.status).toBe(403)
      expect(await codeOf(res)).toBe('step_up_required')
      a.untouched()
    })

    test(`${a.name}: Root with its password`, async () => {
      await signIn(ROOT)
      const res = await a.call(PW[ROOT])
      expect(res.status).toBe(200)
      a.done()
    })
  }

  test('a member target needs neither Root nor a password', async () => {
    await signIn('admin-2')
    expect((await disableUser(req('POST', {}), params('member-1'))).status).toBe(200)
    expect((await enableUser(req('POST', {}), params('member-1'))).status).toBe(200)
    expect((await revokeUserSessions(req('POST', {}), params('member-1'))).status).toBe(200)
    expect((await startActAs(req('POST', { targetUserId: 'member-1' }))).status).toBe(200)
  })
})

describe('switch off: the Phase 1 rules', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('an admin creates an admin with no password asked', async () => {
    await signIn('admin-2')
    const res = await createUser(req('POST', NEW_ADMIN))
    expect(res.status).toBe(201)
    expect((await res.json()).role).toBe('admin')
  })

  test('an admin demotes another admin with its own password; nothing is bumped', async () => {
    await signIn('admin-2')
    expect(await codeOf(await editUser(req('PUT', { role: 'standard' }), params('admin-3')))).toBe('step_up_required')
    expect((await editUser(req('PUT', { role: 'standard', stepUpPassword: PW['admin-2'] }), params('admin-3'))).status).toBe(200)
    expect(db().account('admin-3')).toMatchObject({ role: 'standard', sessionVersion: 0 })
  })

  test('an admin promotes a member and edits another admin with no password asked; nothing is bumped', async () => {
    await signIn('admin-2')
    expect((await editUser(req('PUT', { role: 'admin' }), params('member-1'))).status).toBe(200)
    expect((await editUser(req('PUT', { name: 'Ines B.' }), params('admin-3'))).status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ role: 'admin', sessionVersion: 0 })
  })

  test('acting as another admin asks the admin for its own password', async () => {
    await signIn('admin-2')
    expect(await codeOf(await startActAs(req('POST', { targetUserId: 'admin-3' })))).toBe('step_up_required')
    expect((await startActAs(req('POST', { targetUserId: 'admin-3', stepUpPassword: PW['admin-2'] }))).status).toBe(200)
  })

  test('the instance row is never read', async () => {
    const read = vi.spyOn(db().instanceSettings, 'findUnique')
    await signIn('admin-2')
    await createUser(req('POST', NEW_ADMIN))
    await editUser(req('PUT', { role: 'admin' }), params('member-1'))
    await deleteUser(req('DELETE', { stepUpPassword: PW['admin-2'] }), params('admin-3'))
    expect(read).not.toHaveBeenCalled()
  })
})

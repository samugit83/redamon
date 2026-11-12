/**
 * The act-as cookie judged on every request with RBAC_PERMISSIONS_ENABLED on (step 3.14; IM-06,
 * IM-11, IM-12): the impersonation ends when its time is up (`expired`), when the admin's session
 * version changes or the admin loses users:impersonate (`invalidated`), when the account acted as is
 * disabled, deleted or promoted; each end writes one end row and clears the cookie, and the request
 * runs as the admin. A cookie from before the switch (no version claim) stays valid until its own
 * expiry, but a pair the rule forbids ends at once with `act_as.refused`. While acting, the admin
 * may use what both people hold (target ∩ admin), administration stays the admin's.
 *
 * Real session helpers, tokens and capability resolution; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string }, deleted: [] as string[] }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: (name: string) => {
      h.deleted.push(name)
      if (name === 'redamon-act-as') h.jar.actAs = undefined
    },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})

import { SignJWT } from 'jose'
import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createActAsToken, createToken } from './auth'
import { getEffectiveUser, getAuthzIdentity, getSession, actAsInForce } from './session'
import { setFlagsForTests } from './authz/flags'
import { clearPrincipalCacheForTests, loadPrincipal } from './authz/principal'
import { clearInstanceRootCacheForTests } from './authz/root'
import { clearCapabilityCachesForTests } from './authz/capabilities'
import { can, capabilitiesInForce } from './authz/can'
import { actingAsUserId } from './userAudit'

const db = () => h.db as AccountDb

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

/** A cookie minted under this step's rule: it carries the admin's session version. */
async function cookie(admin: string, target: string, { seconds = 3600, asv }: { seconds?: number; asv?: number } = {}) {
  return createActAsToken(admin, target, seconds, { asv: asv ?? Number(db().account(admin)!.sessionVersion ?? 0) })
}

async function expiredCookie(admin: string, target: string) {
  const iat = Math.floor(Date.now() / 1000) - 7200
  return new SignJWT({ sub: admin, act: target, asv: 0 }).setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(iat).setExpirationTime(iat + 3600).sign(new TextEncoder().encode('b'.repeat(64)))
}

function started(admin: string, target: string) {
  db().seedActAs({ adminId: admin, targetUserId: target, event: 'start', createdAt: new Date(Date.now() - 60_000), durationMinutes: 60, reason: 'ticket #42' })
}

const ends = () => db().actAs().filter((r) => r.event === 'end')
/** What the next request reads: the caches other copies keep for the bound are not this test's subject. */
function nextRequest() {
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin', sessionVersion: 2 },
    { id: 'admin-2', role: 'admin' },
    { id: 'member-1' },
    { id: 'member-ro' },
  ])
  db().seedAssignment('member-ro', 'builtin:read-only-analyst')
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  nextRequest()
  h.jar = {}
  h.deleted = []
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('a valid impersonation', () => {
  test('acts as the member while the rule holds; nothing is written', async () => {
    started('admin-1', 'member-1')
    await signIn('admin-1')
    h.jar.actAs = await cookie('admin-1', 'member-1')
    expect(await getEffectiveUser()).toEqual({ userId: 'member-1' })
    const inForce = await actAsInForce((await getSession())!)
    expect(inForce?.target.id).toBe('member-1')
    expect(inForce?.expiresAt).toBeGreaterThan(Date.now() / 1000)
    expect(ends()).toEqual([])
    expect(h.deleted).toEqual([])
  })

  test("another admin's cookie is ignored and records nothing", async () => {
    await signIn('admin-1')
    h.jar.actAs = await cookie('admin-2', 'member-1')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
    expect(ends()).toEqual([])
  })
})

describe('ends on each condition with endedBy (IM-11)', () => {
  const cases: Array<[string, () => Promise<void>, string]> = [
    ['its time is up', async () => { h.jar.actAs = await expiredCookie('admin-1', 'member-1') }, 'expired'],
    ['the admin signed out everywhere and in again (session version)', async () => {
      h.jar.actAs = await cookie('admin-1', 'member-1', { asv: 1 })
    }, 'invalidated'],
    ['the admin lost users:impersonate', async () => {
      h.jar.actAs = await cookie('admin-1', 'member-1')
      await db().user.update({ where: { id: 'admin-1' }, data: { adminProfileId: 'builtin:user-manager' } })
    }, 'invalidated'],
    ['the account acted as was disabled', async () => {
      h.jar.actAs = await cookie('admin-1', 'member-1')
      await db().user.update({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    }, 'target_disabled'],
    ['the account acted as was deleted', async () => {
      h.jar.actAs = await cookie('admin-1', 'member-1')
      await db().user.delete({ where: { id: 'member-1' } })
    }, 'target_deleted'],
    ['the account acted as was promoted', async () => {
      h.jar.actAs = await cookie('admin-1', 'member-1')
      await db().user.update({ where: { id: 'member-1' }, data: { role: 'admin' } })
    }, 'target_promoted'],
  ]

  test.each(cases)('%s: the request runs as the admin, one end row, the cookie cleared', async (_name, arrange, endedBy) => {
    started('admin-1', 'member-1')
    await signIn('admin-1')
    await arrange()
    nextRequest()
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
    expect(ends()).toEqual([expect.objectContaining({ adminId: 'admin-1', targetUserId: 'member-1', endedBy })])
    expect(h.deleted).toEqual(['redamon-act-as'])
    expect((await getAuthzIdentity())?.actingAs).toBeNull()
  })

  test('noticed by two requests at once, the end is written once', async () => {
    started('admin-1', 'member-1')
    await signIn('admin-1')
    const token = await cookie('admin-1', 'member-1')
    await db().user.update({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    nextRequest()
    // Neither request sees the other clear the cookie: each browser tab sent it.
    const run = async () => { h.jar.actAs = token; return getEffectiveUser() }
    await Promise.all([run(), run()])
    expect(ends()).toHaveLength(1)
  })

  test('a failed end-row write still ends it (logged with its code)', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    started('admin-1', 'member-1')
    await signIn('admin-1')
    h.jar.actAs = await expiredCookie('admin-1', 'member-1')
    vi.spyOn(db(), '$transaction').mockRejectedValue(Object.assign(new Error('x'), { code: 'P1001' }))
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
    expect(err.mock.calls.some(([l]) => String(l).startsWith('[rbac] act-as end not recorded admin=admin-1 target=member-1 ended-by=expired code=P1001'))).toBe(true)
  })
})

describe('legacy act-as cookie (IM-12): valid until its expiry, then refused for a forbidden pair', () => {
  test('a cookie from before the switch (no version claim) on a member still acts', async () => {
    await signIn('admin-1')
    h.jar.actAs = await createActAsToken('admin-1', 'member-1')
    expect(await getEffectiveUser()).toEqual({ userId: 'member-1' })
    expect(ends()).toEqual([])
  })

  test('a cookie from before the switch acting as another admin ends with act_as.refused', async () => {
    db().seedActAs({ adminId: 'admin-1', targetUserId: 'admin-2', event: 'start', createdAt: new Date(Date.now() - 60_000) })
    await signIn('admin-1')
    h.jar.actAs = await createActAsToken('admin-1', 'admin-2')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'admin-2', endedBy: 'refused' })])
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'act_as.refused', actorId: 'admin-1', targetType: 'user', targetId: 'admin-2', permission: 'users:impersonate',
    })])
  })

  test('Root\'s legacy cookie on an admin stays valid', async () => {
    await signIn('root-1')
    h.jar.actAs = await createActAsToken('root-1', 'admin-2')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-2' })
  })
})

describe('switch off: Phase 2 behaviour', () => {
  test('a lost profile, a disabled member and a stale version change nothing; nothing is written', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await db().user.update({ where: { id: 'admin-1' }, data: { adminProfileId: 'builtin:user-manager' } })
    await db().user.update({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    nextRequest()
    await signIn('admin-1')
    h.jar.actAs = await cookie('admin-1', 'member-1', { asv: 0 })
    expect(await getEffectiveUser()).toEqual({ userId: 'member-1' })
    expect(db().actAs()).toEqual([])
    expect(h.deleted).toEqual([])
  })
})

describe('act-as intersection (IM-06): what both people hold; administration stays the admin\'s', () => {
  test('a member permission the account acted as lacks is refused, one both hold is allowed', async () => {
    await signIn('admin-1')
    h.jar.actAs = await cookie('admin-1', 'member-ro')
    const identity = (await getAuthzIdentity())!
    expect(identity.actingAs?.id).toBe('member-ro')
    const opts = { actingAs: identity.actingAs }
    // The admin's member side is Default member; the analyst reads but neither scans nor chats.
    expect((await can(identity.principal, 'recon:scan')).allowed).toBe(true)
    expect((await can(identity.principal, 'recon:scan', opts)).allowed).toBe(false)
    expect((await can(identity.principal, 'agent:chat', opts)).allowed).toBe(false)
    expect((await can(identity.principal, 'graph:read', opts)).allowed).toBe(true)
    // Administration is the real person's: the analyst holds no users:read, the admin does.
    expect((await can(identity.principal, 'users:read', opts)).allowed).toBe(true)
    const inForce = await capabilitiesInForce(identity.principal, opts)
    expect(inForce.has('recon:scan')).toBe(false)
    expect(inForce.has('users:impersonate')).toBe(true)
  })

  test('the target never widens the admin: what the admin lacks stays refused while acting', async () => {
    db().seedSet({ id: 'set-narrow', kind: 'member', name: 'Narrow', permissions: ['graph:read'] })
    db().seedAssignment('admin-1', 'set-narrow')
    nextRequest()
    await signIn('admin-1')
    h.jar.actAs = await cookie('admin-1', 'member-1')
    const identity = (await getAuthzIdentity())!
    expect(identity.actingAs?.id).toBe('member-1')
    expect((await can(identity.principal, 'recon:scan', { actingAs: identity.actingAs })).allowed).toBe(false)
    expect((await can(identity.principal, 'graph:read', { actingAs: identity.actingAs })).allowed).toBe(true)
    expect((await loadPrincipal('member-1'))?.id).toBe('member-1')
  })
})

describe('the audit rows name the account acted as only for someone who may act as others', () => {
  const carrying = (token: string) => ({ headers: new Headers({ cookie: `redamon-act-as=${token}` }) })

  test('an admin holding users:impersonate: the account it acted as', async () => {
    expect(await actingAsUserId(carrying(await cookie('admin-1', 'member-1')), { userId: 'admin-1', role: 'admin' })).toBe('member-1')
  })

  test('a profile without users:impersonate: none (its cookie acts for nobody)', async () => {
    await db().user.update({ where: { id: 'admin-1' }, data: { adminProfileId: 'builtin:user-manager' } })
    nextRequest()
    expect(await actingAsUserId(carrying(await cookie('admin-1', 'member-1')), { userId: 'admin-1', role: 'admin' })).toBeNull()
  })

  test('a member: none, and its account is not read', async () => {
    expect(await actingAsUserId(carrying(await cookie('member-1', 'member-ro')), { userId: 'member-1', role: 'standard' })).toBeNull()
  })

  test('switch off: every admin, as before', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await db().user.update({ where: { id: 'admin-1' }, data: { adminProfileId: 'builtin:user-manager' } })
    expect(await actingAsUserId(carrying(await cookie('admin-1', 'member-1')), { userId: 'admin-1', role: 'admin' })).toBe('member-1')
  })
})

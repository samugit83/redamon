/**
 * The Root check holds until the write commits (review of step 2.5, finding A): with the identity
 * switch on, a write that could leave the Root's row naming a demoted, deleted or disabled account
 * (demoting an admin, deleting one, disabling one) takes the Root lock, `hashtext('rbac-root')`,
 * the one the boot backfill, set-root, create-admin and the Root transfer take, BEFORE the
 * last-admin lock, and reads the Root again inside its transaction. So a boot that chooses an
 * account as Root, a host set-root or a transfer that lands between the route's check and its
 * write is seen: the write is refused (`root_protected`, or `root_only` when the actor stopped
 * being the confirmed Root) and nothing changes. With the switch off a demotion takes the
 * last-admin lock alone, as after Phase 1.
 *
 * Real session helpers, tokens, bcrypt and step-up; the database is the in-memory accountDb; the
 * moment "Root moved" is a write made just before the transaction runs.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/rootLock.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
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

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { ROOT_LOCK, clearInstanceRootCacheForTests } from './root'
import { ADMIN_SET_LOCK } from './adminSet'
import { disableAccount } from './accountStatus'
import { __resetThrottle } from '@/lib/loginThrottle'
import { PUT as editUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'
import { LOCK_KEY as BACKFILL_LOCK } from '../../../scripts/backfill-rbac-root.mjs'

const db = () => h.db as AccountDb
const ROOT = 'root-1'
const PW = 'root-own-passphrase-0001'
const REFUSED = 'rbac.root_protected_refused'

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/x', {
    method,
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

/** Root moves to `rootUserId` (a boot, set-root or a transfer committing) right before the next transaction. */
function rootMovesBeforeTheWrite(rootUserId: string, confirmed = true) {
  const original = db().$transaction
  const moved = async (fn: Parameters<AccountDb['$transaction']>[0]) => {
    db().seedInstance({ rootUserId, rootAssignedBy: confirmed ? 'host' : 'automatic', rootConfirmedAt: confirmed ? new Date() : null })
    clearInstanceRootCacheForTests()
    return original(fn)
  }
  vi.spyOn(db(), '$transaction').mockImplementationOnce(moved as never)
}

const locks = () => db().rawValues.filter((_, i) => /pg_advisory_xact_lock/.test(db().rawCalls[i])).map((v) => v[0])

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local', password: bcrypt.hashSync(PW, 4) },
    { id: 'admin-2', role: 'admin' },
    { id: 'admin-3', role: 'admin' },
    { id: 'member-1' },
  ])
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
  h.jar = {}
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(
    JSON.stringify(String(url).endsWith('/ws/close') ? { closed: 0 } : { stopped: 0 }), { status: 200 })))
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the Root lock is the one the boot, the host and the transfer take', () => {
  test('same key as scripts/backfill-rbac-root.mjs (and set-root, create-admin)', () => {
    expect(ROOT_LOCK).toBe('rbac-root')
    expect(ROOT_LOCK).toBe(BACKFILL_LOCK)
  })
})

describe('Root moved between the check and the write: refused, nothing changed', () => {
  test('an admin demoting itself while the boot chooses it as Root', async () => {
    db().seedInstance(null)
    await signIn('admin-3')
    rootMovesBeforeTheWrite('admin-3', false)
    const res = await editUser(req('PUT', { role: 'standard' }), params('admin-3'))
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_protected')
    expect(body.error).toMatch(/Transfer Root/)
    expect(db().account('admin-3')).toMatchObject({ role: 'admin', sessionVersion: 0 })
    expect(db().audit().filter((r) => r.action !== REFUSED)).toEqual([])
    expect(db().audit().filter((r) => r.action === REFUSED)).toMatchObject([{ targetId: 'admin-3', after: { attempted: 'role_change' } }])
  })

  test('Root demoting an admin that the host just made Root', async () => {
    await signIn(ROOT)
    rootMovesBeforeTheWrite('admin-3')
    const res = await editUser(req('PUT', { role: 'standard', stepUpPassword: PW }), params('admin-3'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_protected')
    expect(db().account('admin-3')!.role).toBe('admin')
  })

  test('Root deleting an admin that the host just made Root: refused before the teardown', async () => {
    await signIn(ROOT)
    rootMovesBeforeTheWrite('admin-3')
    const res = await deleteUser(req('DELETE', { stepUpPassword: PW }), params('admin-3'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_protected')
    expect(db().account('admin-3')).toBeDefined()
  })

  test('disabling an admin that the host just made Root', async () => {
    await signIn(ROOT)
    rootMovesBeforeTheWrite('admin-3')
    const res = await disableAccount(req('POST', {}), { userId: ROOT, role: 'admin' }, 'admin-3', { adminTarget: true })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_protected')
    expect(db().account('admin-3')).toMatchObject({ status: 'active', sessionVersion: 0 })
  })

  test("an action on another admin after Root moved away from the actor: root_only", async () => {
    await signIn(ROOT)
    rootMovesBeforeTheWrite('admin-2')
    const res = await disableAccount(req('POST', {}), { userId: ROOT, role: 'admin' }, 'admin-3', { adminTarget: true })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_only')
    expect(db().account('admin-3')!.status).toBe('active')
  })

  test('an unconfirmed Root at write time holds no power: root_only', async () => {
    await signIn(ROOT)
    rootMovesBeforeTheWrite(ROOT, false)
    const res = await disableAccount(req('POST', {}), { userId: ROOT, role: 'admin' }, 'admin-3', { adminTarget: true })
    expect((await res.json()).code).toBe('root_only')
  })
})

describe('the order of the locks', () => {
  test('switch on: the Root lock first, then the last-admin lock, in the write transaction', async () => {
    await signIn('admin-3')
    expect((await editUser(req('PUT', { role: 'standard' }), params('admin-3'))).status).toBe(200)
    expect(locks()).toEqual([ROOT_LOCK, ADMIN_SET_LOCK])
    expect(db().account('admin-3')!.role).toBe('standard')
  })

  test('switch on: a disable takes both, Root lock first', async () => {
    await disableAccount(req('POST', {}), { userId: 'admin-2', role: 'admin' }, 'member-1')
    expect(locks()).toEqual([ROOT_LOCK, ADMIN_SET_LOCK])
  })

  test('switch off: the last-admin lock alone, as after Phase 1', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-3')
    expect((await editUser(req('PUT', { role: 'standard' }), params('admin-3'))).status).toBe(200)
    expect(locks()).toEqual([ADMIN_SET_LOCK])
  })
})

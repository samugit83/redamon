/**
 * Unit tests for getEffectiveUser (per-user access control / impersonation core).
 *
 * Run: npx vitest run src/lib/session.effective.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

let authCookie: string | undefined
let actAsCookie: string | undefined

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && authCookie) return { value: authCookie }
      if (name === 'redamon-act-as' && actAsCookie) return { value: actAsCookie }
      return undefined
    },
  })),
}))

// getSession reads role and existence from the database (HD-10): every account these
// tests sign in as, or act as, exists with the role its token claims.
const DB_ROLES: Record<string, string> = { 'std-1': 'standard', 'admin-1': 'admin', 'user-X': 'standard', 'victim': 'standard' }
const dbUser = async ({ where }: { where: { id: string } }) =>
  DB_ROLES[where.id]
    ? { id: where.id, email: `${where.id}@e2e.local`, role: DB_ROLES[where.id], password: 'h', createdAt: new Date(0) }
    : null
vi.mock('@/lib/prisma', () => ({ default: { user: { findUnique: (a: { where: { id: string } }) => dbUser(a) } } }))

import { getEffectiveUser, getAuthzIdentity, getSession, authzIdentityOf } from './session'
import { createToken, createActAsToken } from './auth'

describe('getEffectiveUser', () => {
  beforeEach(() => {
    authCookie = undefined
    actAsCookie = undefined
  })

  test('returns null when there is no session', async () => {
    expect(await getEffectiveUser()).toBeNull()
  })

  test('standard user -> own id (act-as cookie IGNORED)', async () => {
    authCookie = await createToken('std-1', 'standard')
    actAsCookie = await createActAsToken('std-1', 'victim') // forged/irrelevant
    expect(await getEffectiveUser()).toEqual({ userId: 'std-1' })
  })

  test('standard user with an act-as cookie carrying an admin sub -> still own id (privilege non-escalation)', async () => {
    authCookie = await createToken('std-1', 'standard')
    actAsCookie = await createActAsToken('some-admin', 'victim')
    expect(await getEffectiveUser()).toEqual({ userId: 'std-1' })
  })

  test('admin, not simulating -> own id', async () => {
    authCookie = await createToken('admin-1', 'admin')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
  })

  test('admin simulating X -> X', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'user-X')
    expect(await getEffectiveUser()).toEqual({ userId: 'user-X' })
  })

  test('admin with an act-as cookie minted by a DIFFERENT admin -> own id (sub mismatch)', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-2', 'user-X')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
  })

  test('admin with a login-shaped cookie (no act claim) as act-as -> own id', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createToken('admin-1', 'admin') // has role, no act
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
  })

  test('admin with a garbage act-as cookie -> own id', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = 'not-a-jwt'
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
  })
})

/**
 * getAuthzIdentity (step 3.5): what can() decides on. The real account and the account acted
 * as, read exactly as getSession and getEffectiveUser read them.
 */
describe('getAuthzIdentity', () => {
  beforeEach(() => {
    authCookie = undefined
    actAsCookie = undefined
  })

  test('null when there is no session', async () => {
    expect(await getAuthzIdentity()).toBeNull()
  })

  test('the real session and its account; no act-as', async () => {
    authCookie = await createToken('admin-1', 'admin')
    const id = await getAuthzIdentity()
    expect(id?.session).toEqual({ userId: 'admin-1', role: 'admin' })
    expect(id?.principal).toMatchObject({ id: 'admin-1', role: 'admin', email: 'admin-1@e2e.local' })
    expect(id?.actingAs).toBeNull()
  })

  test('an admin acting as X: the session stays the admin, actingAs is X', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'user-X')
    const id = await getAuthzIdentity()
    expect(id?.session.userId).toBe('admin-1')
    expect(id?.actingAs).toMatchObject({ id: 'user-X', role: 'standard' })
  })

  test('acting as oneself is no act-as', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'admin-1')
    expect((await getAuthzIdentity())?.actingAs).toBeNull()
  })

  test('the effective user it gives is getEffectiveUser\'s, in every case above', async () => {
    const cases: Array<[string, string, (() => Promise<string>) | null]> = [
      ['std-1', 'standard', () => createActAsToken('std-1', 'victim')],
      ['std-1', 'standard', () => createActAsToken('some-admin', 'victim')],
      ['admin-1', 'admin', null],
      ['admin-1', 'admin', () => createActAsToken('admin-1', 'user-X')],
      ['admin-1', 'admin', () => createActAsToken('admin-2', 'user-X')],
      ['admin-1', 'admin', () => createActAsToken('admin-1', 'nobody')],
      ['admin-1', 'admin', async () => 'not-a-jwt'],
    ]
    for (const [sub, role, actAs] of cases) {
      authCookie = await createToken(sub, role)
      actAsCookie = actAs ? await actAs() : undefined
      const id = await getAuthzIdentity()
      const effective = await getEffectiveUser()
      expect([sub, actAsCookie && 'act-as', { userId: (id!.actingAs ?? id!.principal).id }]).toEqual([sub, actAsCookie && 'act-as', effective])
    }
  })
})

/**
 * authzIdentityOf (step 3.12): getAuthzIdentity for a session getSession already answered, so a
 * route that reads the session itself (/api/auth/me) reads the act-as cookie once more and the
 * login cookie and the account not again.
 */
describe('authzIdentityOf', () => {
  beforeEach(() => {
    authCookie = undefined
    actAsCookie = undefined
  })

  test('the same answer as getAuthzIdentity, in every act-as case', async () => {
    const cases: Array<[string, string, (() => Promise<string>) | null]> = [
      ['std-1', 'standard', () => createActAsToken('std-1', 'victim')],
      ['admin-1', 'admin', null],
      ['admin-1', 'admin', () => createActAsToken('admin-1', 'user-X')],
      ['admin-1', 'admin', () => createActAsToken('admin-1', 'admin-1')],
      ['admin-1', 'admin', () => createActAsToken('admin-2', 'user-X')],
      ['admin-1', 'admin', () => createActAsToken('admin-1', 'nobody')],
    ]
    for (const [sub, role, actAs] of cases) {
      authCookie = await createToken(sub, role)
      actAsCookie = actAs ? await actAs() : undefined
      const session = await getSession()
      const of = await authzIdentityOf(session!)
      const whole = await getAuthzIdentity()
      expect([sub, of.session, of.principal.id, of.actingAs?.id ?? null])
        .toEqual([sub, whole!.session, whole!.principal.id, whole!.actingAs?.id ?? null])
    }
  })

  test('a session object getSession did not answer throws: no account was read for it', async () => {
    await expect(authzIdentityOf({ userId: 'admin-1', role: 'admin' })).rejects.toThrow(/no account read/)
  })
})

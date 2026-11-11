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

import { getEffectiveUser } from './session'
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

/**
 * Composition/integration test: the REAL getEffectiveUser (session.ts) + REAL
 * access.ts guards wired together, with only next/headers cookies and prisma
 * mocked. The route unit tests mock the effective-user resolution; this proves
 * the full impersonation chain end-to-end (login JWT + act-as cookie ->
 * effective user -> project ownership decision).
 *
 * Run: npx vitest run src/lib/access.composition.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'z'.repeat(64))

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
const DB_ROLES: Record<string, string> = { 'userX': 'standard', 'attacker': 'standard', 'admin-1': 'admin' }
const dbUser = async ({ where }: { where: { id: string } }) =>
  DB_ROLES[where.id]
    ? { id: where.id, email: `${where.id}@e2e.local`, role: DB_ROLES[where.id], password: 'h', createdAt: new Date(0) }
    : null
const mockProjectFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) },
    user: { findUnique: (a: { where: { id: string } }) => dbUser(a) },
  },
}))

import { requireEffectiveUser, requireProjectAccess } from './access'
import { createToken, createActAsToken } from './auth'

// Project P is owned by 'userX'. Requests for it should succeed only when the
// effective user resolves to userX.
function ownedBy(owner: string) {
  mockProjectFindUnique.mockResolvedValue({ id: 'P', userId: owner })
}

async function effectiveThenProject(): Promise<number | 'ok'> {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff.status
  const access = await requireProjectAccess(eff, 'P')
  if (access instanceof NextResponse) return access.status
  return 'ok'
}

beforeEach(() => {
  authCookie = undefined
  actAsCookie = undefined
  mockProjectFindUnique.mockReset()
  process.env.ACCESS_ENFORCE = '1' // prove the BLOCK end-to-end
})
afterEach(() => { delete process.env.ACCESS_ENFORCE })

describe('full effective-user -> project-access chain', () => {
  test('no session -> 401', async () => {
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe(401)
  })

  test('standard user owns P -> ok', async () => {
    authCookie = await createToken('userX', 'standard')
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe('ok')
  })

  test('EXPLOIT: standard user does NOT own P -> 404', async () => {
    authCookie = await createToken('attacker', 'standard')
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe(404)
  })

  test('EXPLOIT: standard user forges an act-as cookie for P owner -> still 404 (act-as ignored)', async () => {
    authCookie = await createToken('attacker', 'standard')
    actAsCookie = await createActAsToken('attacker', 'userX') // self-minted, but role is not admin
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe(404)
  })

  test('admin NOT simulating, does NOT own P -> 404 (no see-all)', async () => {
    authCookie = await createToken('admin-1', 'admin')
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe(404)
  })

  test('admin simulating userX -> ok (impersonation grants exactly X)', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'userX')
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe('ok')
  })

  test('EXPLOIT: admin simulating userX pastes a DIFFERENT user Y project -> 404', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'userX')
    ownedBy('userY') // the pasted URL points at Y's project
    expect(await effectiveThenProject()).toBe(404)
  })

  test('admin act-as minted by a DIFFERENT admin -> own id, not the target -> 404', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-2', 'userX') // sub != admin-1
    ownedBy('userX')
    expect(await effectiveThenProject()).toBe(404)
  })

  test('missing project -> 404 (before ownership disclosure)', async () => {
    authCookie = await createToken('userX', 'standard')
    mockProjectFindUnique.mockResolvedValue(null)
    expect(await effectiveThenProject()).toBe(404)
  })
})

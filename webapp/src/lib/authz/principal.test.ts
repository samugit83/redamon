/**
 * loadPrincipal reads the signed-in account from the database (HD-10, T3): the
 * role and the account's existence come from this row, never from the login JWT.
 *
 * Step 2.2 adds what the identity work needs: the account's status, session version and
 * the other identity fields; a per-process cache bounded by RBAC_AUTHZ_CACHE_MS while the
 * identity switch is on, which a critical path bypasses with `fresh` and a writer drops
 * with `invalidatePrincipal` (ID-01, ID-22, DV-25); and the session version in the login
 * token, compared strictly by getSession, a token without one being version 0 (ID-21,
 * ID-23, UP-14, DV-02). Real tokens are signed; Prisma, the cookie store and the clock are
 * doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHmac } from 'node:crypto'
import { NextResponse } from 'next/server'
import { SignJWT } from 'jose'

const SECRET = 'p'.repeat(64)
vi.stubEnv('AUTH_SECRET', SECRET)

const findUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (...a: unknown[]) => findUnique(...a) } },
}))

const jar = vi.hoisted(() => ({ auth: undefined as string | undefined, actAs: undefined as string | undefined, deleted: [] as string[] }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && jar.auth) return { value: jar.auth }
      if (name === 'redamon-act-as' && jar.actAs) return { value: jar.actAs }
      return undefined
    },
    delete: (name: string) => { jar.deleted.push(name) },
  })),
}))

import { loadPrincipal, invalidatePrincipal, clearPrincipalCacheForTests, principalCacheMs } from './principal'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { createToken, createActAsToken } from '@/lib/auth'
import { getSession, getEffectiveUser, requireSession } from '@/lib/session'

const CREATED = new Date('2026-01-02T03:04:05Z')
const LAST_LOGIN = new Date('2026-11-01T08:00:00Z')

/** A users row as Prisma returns it for the principal's select. */
function row(over: Record<string, unknown> = {}) {
  return {
    id: 'u1', email: 'u1@e2e.local', name: 'User One', role: 'admin', password: '$2a$12$hash', createdAt: CREATED,
    legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, ...over,
  }
}

/** The users table as the database holds it now: id -> row. */
const db = new Map<string, ReturnType<typeof row>>()

let t = Date.parse('2026-11-12T10:00:00Z')

beforeEach(() => {
  findUnique.mockReset()
  findUnique.mockImplementation(async ({ where }: { where: { id: string } }) => db.get(where.id) ?? null)
  db.clear()
  clearPrincipalCacheForTests()
  setFlagsForTests(null)
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
  t = Date.parse('2026-11-12T10:00:00Z')
  setNowForTests(() => new Date(t))
  jar.auth = undefined
  jar.actAs = undefined
  jar.deleted = []
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
})

describe('loadPrincipal', () => {
  test('a missing account is no principal', async () => {
    findUnique.mockResolvedValue(null)
    expect(await loadPrincipal('gone')).toBeNull()
  })

  test('returns what the row holds, the identity fields included', async () => {
    findUnique.mockResolvedValue(row({
      status: 'disabled', sessionVersion: 4, mustChangePassword: true, adminProfileId: 'prof-1', lastLoginAt: LAST_LOGIN,
    }))
    expect(await loadPrincipal('u1')).toEqual({
      id: 'u1', email: 'u1@e2e.local', name: 'User One', role: 'admin', status: 'disabled', sessionVersion: 4,
      mustChangePassword: true, adminProfileId: 'prof-1', hasPassword: true, createdAt: CREATED,
      lastLoginAt: LAST_LOGIN, legacyGrants: [],
    })
  })

  test('returns the shared tools the account kept at the upgrade (HD-28)', async () => {
    findUnique.mockResolvedValue(row({ role: 'standard', legacyGrants: ['kali_terminal', 'shell_sessions', 'tunnels'] }))
    expect((await loadPrincipal('u1'))?.legacyGrants).toEqual(['kali_terminal', 'shell_sessions', 'tunnels'])
  })

  test('a row that carries no grants reads as none', async () => {
    findUnique.mockResolvedValue({ id: 'm', email: 'm@e2e.local', role: 'standard', password: 'h', createdAt: CREATED })
    expect((await loadPrincipal('m'))?.legacyGrants).toEqual([])
  })

  test('a row without the identity fields reads as an active account at version 0, as every account was before them', async () => {
    findUnique.mockResolvedValue({ id: 'm', email: 'm@e2e.local', role: 'standard', password: 'h', createdAt: CREATED })
    expect(await loadPrincipal('m')).toMatchObject({
      name: '', status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
    })
  })

  test('a passwordless account has no password, and the hash never leaves the loader', async () => {
    findUnique.mockResolvedValue(row({ password: '' }))
    const p = await loadPrincipal('u1')
    expect(p?.hasPassword).toBe(false)
    expect(p).not.toHaveProperty('password')
    expect(p).not.toHaveProperty('passwordOnHold')
  })

  test('one indexed read by id, selecting only what the principal needs', async () => {
    findUnique.mockResolvedValue(null)
    await loadPrincipal('u1')
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(findUnique).toHaveBeenCalledWith({
      where: { id: 'u1' },
      select: {
        id: true, email: true, name: true, role: true, password: true, createdAt: true, legacyGrants: true,
        status: true, sessionVersion: true, mustChangePassword: true, adminProfileId: true, lastLoginAt: true,
      },
    })
  })

  test('an empty id is no principal and reads nothing', async () => {
    expect(await loadPrincipal('')).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a failed read throws: it never reads as an account', async () => {
    findUnique.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(loadPrincipal('u1')).rejects.toThrow('db down')
  })
})

describe('the principal cache (identity switch on)', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true })
    db.set('u1', row())
  })

  test('cache hit makes no query', async () => {
    const first = await loadPrincipal('u1')
    findUnique.mockClear()
    expect(await loadPrincipal('u1')).toEqual(first)
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('entry expires after the TTL (injected clock)', async () => {
    await loadPrincipal('u1')
    t += 4_999
    findUnique.mockClear()
    await loadPrincipal('u1')
    expect(findUnique).not.toHaveBeenCalled()
    t += 1
    await loadPrincipal('u1')
    expect(findUnique).toHaveBeenCalledTimes(1)
  })

  test('fresh bypasses the cache and refreshes it', async () => {
    await loadPrincipal('u1')
    db.set('u1', row({ sessionVersion: 1 }))
    expect((await loadPrincipal('u1'))?.sessionVersion).toBe(0)
    findUnique.mockClear()
    expect((await loadPrincipal('u1', { fresh: true }))?.sessionVersion).toBe(1)
    expect(findUnique).toHaveBeenCalledTimes(1)
    findUnique.mockClear()
    expect((await loadPrincipal('u1'))?.sessionVersion).toBe(1)
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a fresh read that finds no account drops the stale entry', async () => {
    await loadPrincipal('u1')
    // Deleted by another copy: nothing told this process.
    db.delete('u1')
    expect(await loadPrincipal('u1', { fresh: true })).toBeNull()
    findUnique.mockClear()
    expect(await loadPrincipal('u1')).toBeNull()
    expect(findUnique).toHaveBeenCalledTimes(1)
  })

  test('invalidate drops the entry', async () => {
    await loadPrincipal('u1')
    db.set('u1', row({ role: 'standard' }))
    invalidatePrincipal('u1')
    findUnique.mockClear()
    expect((await loadPrincipal('u1'))?.role).toBe('standard')
    expect(findUnique).toHaveBeenCalledTimes(1)
  })

  test('invalidating one account keeps the others', async () => {
    db.set('u2', row({ id: 'u2' }))
    await loadPrincipal('u1')
    await loadPrincipal('u2')
    invalidatePrincipal('u1')
    findUnique.mockClear()
    await loadPrincipal('u2')
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a read an invalidation overtook is not cached', async () => {
    let release!: (v: unknown) => void
    findUnique.mockImplementationOnce(() => new Promise(r => { release = r }))
    const pending = loadPrincipal('u1')
    await vi.waitFor(() => expect(findUnique).toHaveBeenCalledTimes(1))
    // A writer changed the account while this read was on its way.
    db.set('u1', row({ sessionVersion: 1 }))
    invalidatePrincipal('u1')
    release(row({ sessionVersion: 0 }))
    expect((await pending)?.sessionVersion).toBe(0)
    findUnique.mockClear()
    expect((await loadPrincipal('u1'))?.sessionVersion).toBe(1)
    expect(findUnique).toHaveBeenCalledTimes(1)
  })

  test('a missing account is not cached', async () => {
    await loadPrincipal('gone')
    await loadPrincipal('gone')
    expect(findUnique).toHaveBeenCalledTimes(2)
  })

  test('a failed read caches nothing', async () => {
    findUnique.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(loadPrincipal('u1')).rejects.toThrow('db down')
    expect(await loadPrincipal('u1')).not.toBeNull()
    expect(findUnique).toHaveBeenCalledTimes(2)
  })

  test('the cached principal cannot be changed by a caller', async () => {
    db.set('u1', row({ legacyGrants: ['tunnels'] }))
    const p = await loadPrincipal('u1')
    expect(Object.isFrozen(p)).toBe(true)
    expect(Object.isFrozen(p?.legacyGrants)).toBe(true)
  })

  test('RBAC_AUTHZ_CACHE_MS sets the bound; 0 reads on every call', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '1000')
    expect(principalCacheMs()).toBe(1000)
    await loadPrincipal('u1')
    t += 1_000
    findUnique.mockClear()
    await loadPrincipal('u1')
    expect(findUnique).toHaveBeenCalledTimes(1)

    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
    expect(principalCacheMs()).toBe(0)
    findUnique.mockClear()
    await loadPrincipal('u1')
    await loadPrincipal('u1')
    expect(findUnique).toHaveBeenCalledTimes(2)
  })

  test('the default is 5000 ms; an unreadable value falls back to it and a large one is capped, each logged once', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      expect(principalCacheMs()).toBe(5000)
      vi.stubEnv('RBAC_AUTHZ_CACHE_MS', 'five seconds')
      expect(principalCacheMs()).toBe(5000)
      expect(principalCacheMs()).toBe(5000)
      vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '-1')
      expect(principalCacheMs()).toBe(5000)
      vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '3600000')
      expect(principalCacheMs()).toBe(60_000)
      const lines = warn.mock.calls.map(c => String(c[0]))
      expect(lines.filter(l => l.includes('unrecognised value for RBAC_AUTHZ_CACHE_MS'))).toHaveLength(1)
      expect(lines.filter(l => l.includes('RBAC_AUTHZ_CACHE_MS is above 60000'))).toHaveLength(1)
      // The value is never logged: an operator may have pasted anything into .env.
      expect(lines.join('\n')).not.toContain('five seconds')
    } finally {
      warn.mockRestore()
    }
  })
})

/** A login token exactly as `testing/e2e/tests/auth.ts` mints it: HS256 over {sub, role, iat, exp}. */
function playwrightToken(userId: string, role = 'admin'): string {
  const b64url = (s: string | Buffer) => Buffer.from(s).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const now = Math.floor(Date.now() / 1000)
  const data = `${b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64url(JSON.stringify({ sub: userId, role, iat: now, exp: now + 3600 }))}`
  return `${data}.${b64url(createHmac('sha256', SECRET).update(data).digest())}`
}

/** A login token as the app minted it before the session version existed: {sub, role}. */
async function tokenWithoutSv(userId: string, role = 'admin'): Promise<string> {
  return new SignJWT({ sub: userId, role })
    .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('7d')
    .sign(new TextEncoder().encode(SECRET))
}

describe('the session version (switch off and on)', () => {
  for (const identity of [false, true]) {
    describe(identity ? 'identity on' : 'identity off', () => {
      beforeEach(() => setFlagsForTests({ identity }))

      test('missing sv is 0', async () => {
        db.set('u1', row({ sessionVersion: 0 }))
        jar.auth = await tokenWithoutSv('u1')
        expect(await getSession()).toEqual({ userId: 'u1', role: 'admin' })
        db.set('u1', row({ sessionVersion: 1 }))
        invalidatePrincipal('u1')
        expect(await getSession()).toBeNull()
      })

      test('sv mismatch → no session, in both directions', async () => {
        db.set('u1', row({ sessionVersion: 1 }))
        jar.auth = await createToken('u1', 'admin', 0)
        expect(await getSession()).toBeNull()
        const res = await requireSession()
        expect(res).toBeInstanceOf(NextResponse)
        expect((res as NextResponse).status).toBe(401)
        jar.auth = await createToken('u1', 'admin', 2)
        expect(await getSession()).toBeNull()
      })

      test('the token of the current version keeps its session', async () => {
        db.set('u1', row({ sessionVersion: 3 }))
        jar.auth = await createToken('u1', 'admin', 3)
        expect(await getSession()).toEqual({ userId: 'u1', role: 'admin' })
        expect(jar.deleted).toEqual([])
      })

      test('a Playwright-shaped token {sub, role} still works', async () => {
        db.set('u1', row())
        jar.auth = playwrightToken('u1')
        expect(await getSession()).toEqual({ userId: 'u1', role: 'admin' })
      })

      test("a refused token's 401 clears the cookie", async () => {
        db.set('u1', row({ sessionVersion: 1 }))
        jar.auth = await createToken('u1', 'admin', 0)
        expect(((await requireSession()) as NextResponse).status).toBe(401)
        expect(jar.deleted).toEqual(['redamon-auth'])
      })

      test("a deleted account's cookie is cleared too", async () => {
        jar.auth = await createToken('gone', 'admin')
        expect(await getSession()).toBeNull()
        expect(jar.deleted).toEqual(['redamon-auth'])
      })

      test('a failed read keeps the cookie: an outage is not a sign-out', async () => {
        jar.auth = await createToken('u1', 'admin')
        findUnique.mockRejectedValue(Object.assign(new Error('down'), { code: 'P1001' }))
        await expect(getSession()).rejects.toThrow()
        expect(jar.deleted).toEqual([])
      })

      test('no cookie reads nothing and clears nothing', async () => {
        expect(await getSession()).toBeNull()
        expect(findUnique).not.toHaveBeenCalled()
        expect(jar.deleted).toEqual([])
      })
    })
  }
})

describe('account status (identity switch on)', () => {
  beforeEach(() => setFlagsForTests({ identity: true }))

  test.each(['disabled', 'invited'])('a %s account → no session, and its cookie is cleared', async (status) => {
    db.set('u1', row({ status }))
    jar.auth = await createToken('u1', 'admin')
    expect(await getSession()).toBeNull()
    expect(((await requireSession()) as NextResponse).status).toBe(401)
    expect(jar.deleted[0]).toBe('redamon-auth')
  })

  test('an active account keeps its session', async () => {
    db.set('u1', row({ status: 'active' }))
    jar.auth = await createToken('u1', 'admin')
    expect(await getSession()).toEqual({ userId: 'u1', role: 'admin' })
  })
})

describe('the cache seen from the session (identity switch on)', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true })
    db.set('u1', row())
    db.set('m1', row({ id: 'm1', email: 'm1@e2e.local', role: 'standard' }))
  })

  test('cold cache = one query, warm = zero (DV-25)', async () => {
    jar.auth = await createToken('u1', 'admin')
    await getSession()
    expect(findUnique).toHaveBeenCalledTimes(1)
    findUnique.mockClear()
    await getSession()
    await requireSession()
    await getEffectiveUser()
    expect(findUnique).not.toHaveBeenCalled()
    // Acting as someone: the target is cached the same way.
    jar.actAs = await createActAsToken('u1', 'm1')
    expect(await getEffectiveUser()).toEqual({ userId: 'm1' })
    expect(findUnique).toHaveBeenCalledTimes(1)
    findUnique.mockClear()
    expect(await getEffectiveUser()).toEqual({ userId: 'm1' })
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a critical path reads fresh, the act-as target included', async () => {
    jar.auth = await createToken('u1', 'admin')
    jar.actAs = await createActAsToken('u1', 'm1')
    await getEffectiveUser()
    findUnique.mockClear()
    await getSession({ fresh: true })
    expect(findUnique).toHaveBeenCalledTimes(1)
    findUnique.mockClear()
    await getEffectiveUser({ fresh: true })
    expect(findUnique.mock.calls.map(c => c[0].where.id)).toEqual(['u1', 'm1'])
  })

  test('a revoke made elsewhere reaches this process within the TTL', async () => {
    jar.auth = await createToken('u1', 'admin', 0)
    expect(await getSession()).not.toBeNull()
    // Another copy (or a host command) raised the version; nothing told this process.
    db.set('u1', row({ sessionVersion: 1 }))
    t += 4_999
    expect(await getSession()).not.toBeNull()
    t += 1
    expect(await getSession()).toBeNull()
    expect(jar.deleted).toEqual(['redamon-auth'])
  })

  test('an account a critical path found deleted is gone for the next request too', async () => {
    jar.auth = await createToken('u1', 'admin')
    expect(await getSession()).not.toBeNull()
    db.delete('u1')
    expect(await getSession({ fresh: true })).toBeNull()
    expect(await getSession()).toBeNull()
  })

  test('a writer in this process makes the next request see the change', async () => {
    jar.auth = await createToken('u1', 'admin', 0)
    await getSession()
    db.set('u1', row({ sessionVersion: 1 }))
    invalidatePrincipal('u1')
    expect(await getSession()).toBeNull()
  })

  test('a refusal is judged on a fresh read: a newer token is never refused by a stale entry', async () => {
    jar.auth = await createToken('u1', 'admin', 0)
    await getSession()
    // The version moved elsewhere and the account signed in again, getting a version-1 token.
    db.set('u1', row({ sessionVersion: 1 }))
    jar.auth = await createToken('u1', 'admin', 1)
    findUnique.mockClear()
    expect(await getSession()).toEqual({ userId: 'u1', role: 'admin' })
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(jar.deleted).toEqual([])
    findUnique.mockClear()
    expect(await getSession()).not.toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test.each([
    ['an older session version', { sessionVersion: 1 }],
    ['a disabled account', { status: 'disabled' }],
  ])('a refusal on a cold cache costs one query: only a cached answer is read again (DV-25): %s', async (_, over) => {
    db.set('u1', row(over))
    jar.auth = await createToken('u1', 'admin', 0)
    expect(await getSession()).toBeNull()
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(jar.deleted).toEqual(['redamon-auth'])
  })

  test('a re-enabled account is not refused by a stale disabled entry', async () => {
    db.set('u1', row({ status: 'disabled' }))
    jar.auth = await createToken('u1', 'admin')
    expect(await getSession()).toBeNull()
    db.set('u1', row({ status: 'active' }))
    expect(await getSession()).toEqual({ userId: 'u1', role: 'admin' })
  })
})

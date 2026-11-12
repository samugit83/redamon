/**
 * Unit tests for auth utilities (JWT + password hashing).
 *
 * Run: npx vitest run src/lib/auth.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'

// Mock environment before importing
vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

import { SignJWT, decodeJwt } from 'jose'
import { hashPassword, verifyPassword, createToken, verifyToken, AUTH_COOKIE_NAME } from './auth'

/* ------------------------------------------------------------------ */
/*  Password hashing                                                   */
/* ------------------------------------------------------------------ */

describe('hashPassword / verifyPassword', () => {
  // bcrypt with 12 rounds is intentionally CPU-heavy; under parallel test
  // contention a single hash+verify can exceed vitest's 5s default. Give the
  // hashing tests a generous timeout so they measure correctness, not scheduling.
  const BCRYPT_TIMEOUT = 30000

  test('hashes a password and verifies it', async () => {
    const hash = await hashPassword('mysecret')
    expect(hash).not.toBe('mysecret')
    expect(hash.startsWith('$2')).toBe(true) // bcrypt prefix

    const valid = await verifyPassword('mysecret', hash)
    expect(valid).toBe(true)
  }, BCRYPT_TIMEOUT)

  test('rejects wrong password', async () => {
    const hash = await hashPassword('correct')
    const valid = await verifyPassword('wrong', hash)
    expect(valid).toBe(false)
  }, BCRYPT_TIMEOUT)

  test('rejects empty hash', async () => {
    const valid = await verifyPassword('anything', '')
    expect(valid).toBe(false)
  }, BCRYPT_TIMEOUT)

  test('different passwords produce different hashes', async () => {
    const hash1 = await hashPassword('password1')
    const hash2 = await hashPassword('password2')
    expect(hash1).not.toBe(hash2)
  }, BCRYPT_TIMEOUT)

  test('same password produces different hashes (salt)', async () => {
    const hash1 = await hashPassword('same')
    const hash2 = await hashPassword('same')
    expect(hash1).not.toBe(hash2)
    // But both should verify
    expect(await verifyPassword('same', hash1)).toBe(true)
    expect(await verifyPassword('same', hash2)).toBe(true)
  }, BCRYPT_TIMEOUT)
})

/* ------------------------------------------------------------------ */
/*  JWT tokens                                                         */
/* ------------------------------------------------------------------ */

describe('createToken / verifyToken', () => {
  test('creates and verifies a token', async () => {
    const token = await createToken('user-123', 'admin')
    expect(typeof token).toBe('string')
    expect(token.split('.')).toHaveLength(3) // JWT has 3 parts

    const payload = await verifyToken(token)
    expect(payload).not.toBeNull()
    expect(payload!.sub).toBe('user-123')
    expect(payload!.role).toBe('admin')
  })

  test('verifies standard role token', async () => {
    const token = await createToken('user-456', 'standard')
    const payload = await verifyToken(token)
    expect(payload).not.toBeNull()
    expect(payload!.sub).toBe('user-456')
    expect(payload!.role).toBe('standard')
  })

  test('rejects tampered token', async () => {
    const token = await createToken('user-123', 'admin')
    const tampered = token.slice(0, -5) + 'XXXXX'
    const payload = await verifyToken(tampered)
    expect(payload).toBeNull()
  })

  test('rejects empty token', async () => {
    const payload = await verifyToken('')
    expect(payload).toBeNull()
  })

  test('rejects garbage string', async () => {
    const payload = await verifyToken('not.a.jwt')
    expect(payload).toBeNull()
  })
})

/* ------------------------------------------------------------------ */
/*  Session version (step 2.2, ID-21, ID-23, UP-14)                    */
/* ------------------------------------------------------------------ */

describe('the session version in the login token', () => {
  const sign = (claims: Record<string, unknown>) =>
    new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h')
      .sign(new TextEncoder().encode('a'.repeat(64)))

  test('the token carries {sub, role, sv, iat, exp}, sv being the version it was issued with', async () => {
    const token = await createToken('user-123', 'admin', 4)
    expect(Object.keys(decodeJwt(token)).sort()).toEqual(['exp', 'iat', 'role', 'sub', 'sv'])
    expect(await verifyToken(token)).toEqual({ sub: 'user-123', role: 'admin', sv: 4 })
  })

  test('without a version the token is version 0', async () => {
    expect(decodeJwt(await createToken('user-123', 'admin')).sv).toBe(0)
  })

  test('a token minted before the version existed reads as version 0', async () => {
    expect(await verifyToken(await sign({ sub: 'user-123', role: 'standard' }))).toEqual({ sub: 'user-123', role: 'standard', sv: 0 })
  })

  test.each([['a string', '1'], ['a negative number', -1], ['a fraction', 1.5], ['null', null]])(
    'a token whose version is %s is refused', async (_label, sv) => {
      expect(await verifyToken(await sign({ sub: 'user-123', role: 'admin', sv }))).toBeNull()
    },
  )

  test('a version that is not a whole number is never signed', async () => {
    await expect(createToken('user-123', 'admin', -1)).rejects.toThrow()
    await expect(createToken('user-123', 'admin', 0.5)).rejects.toThrow()
  })
})

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

describe('AUTH_COOKIE_NAME', () => {
  test('is a non-empty string', () => {
    expect(AUTH_COOKIE_NAME).toBe('redamon-auth')
  })
})

/* ------------------------------------------------------------------ */
/*  Edge cases: missing AUTH_SECRET                                    */
/* ------------------------------------------------------------------ */

describe('missing AUTH_SECRET', () => {
  test('createToken throws when AUTH_SECRET is "changeme"', async () => {
    vi.stubEnv('AUTH_SECRET', 'changeme')
    // Re-import would be needed for a full test, but we can test the function directly
    // Since the module is already loaded with a valid secret, we test the error path
    // by temporarily overriding
    const originalEnv = process.env.AUTH_SECRET
    process.env.AUTH_SECRET = 'changeme'
    await expect(createToken('user', 'admin')).rejects.toThrow()
    process.env.AUTH_SECRET = originalEnv
  })
})

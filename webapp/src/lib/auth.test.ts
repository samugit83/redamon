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

import { hashPassword, verifyPassword, createToken, verifyToken, AUTH_COOKIE_NAME } from './auth'

/* ------------------------------------------------------------------ */
/*  Password hashing                                                   */
/* ------------------------------------------------------------------ */

describe('hashPassword / verifyPassword', () => {
  test('hashes a password and verifies it', async () => {
    const hash = await hashPassword('mysecret')
    expect(hash).not.toBe('mysecret')
    expect(hash.startsWith('$2')).toBe(true) // bcrypt prefix

    const valid = await verifyPassword('mysecret', hash)
    expect(valid).toBe(true)
  })

  test('rejects wrong password', async () => {
    const hash = await hashPassword('correct')
    const valid = await verifyPassword('wrong', hash)
    expect(valid).toBe(false)
  })

  test('rejects empty hash', async () => {
    const valid = await verifyPassword('anything', '')
    expect(valid).toBe(false)
  })

  test('different passwords produce different hashes', async () => {
    const hash1 = await hashPassword('password1')
    const hash2 = await hashPassword('password2')
    expect(hash1).not.toBe(hash2)
  })

  test('same password produces different hashes (salt)', async () => {
    const hash1 = await hashPassword('same')
    const hash2 = await hashPassword('same')
    expect(hash1).not.toBe(hash2)
    // But both should verify
    expect(await verifyPassword('same', hash1)).toBe(true)
    expect(await verifyPassword('same', hash2)).toBe(true)
  })
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

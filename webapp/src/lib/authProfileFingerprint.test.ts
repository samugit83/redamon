/** @vitest-environment node */
import { describe, test, expect, vi } from 'vitest'

const mockFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { projectAuthProfile: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } },
}))

import { authProfileFingerprint, authProfileFingerprintExtra } from './authProfileFingerprint'

const BASE = {
  authType: 'cookie', authHeaderName: '', authValue: 'sid=secret-value',
  extraHeaders: { 'X-A': '1', 'X-B': '2' }, scopeHosts: ['b.test', 'a.test'],
}

describe('authProfileFingerprint', () => {
  test('never contains the secret', () => {
    const fp = authProfileFingerprint(BASE)
    expect(fp).toMatch(/^[0-9a-f]{64}$/)
    expect(fp).not.toContain('secret')
  })

  test('stable across key and scope ordering', () => {
    const reordered = { ...BASE, extraHeaders: { 'X-B': '2', 'X-A': '1' }, scopeHosts: ['a.test', 'b.test'] }
    expect(authProfileFingerprint(reordered)).toBe(authProfileFingerprint(BASE))
  })

  test.each([
    ['value', { authValue: 'sid=other' }],
    ['type', { authType: 'bearer' }],
    ['header name', { authHeaderName: 'X-S' }],
    ['scope', { scopeHosts: ['a.test'] }],
    ['extra value', { extraHeaders: { 'X-A': '1', 'X-B': '3' } }],
    ['recon gate', { reconEnabled: false }],
  ])('changes when the %s changes', (_l, change) => {
    expect(authProfileFingerprint({ ...BASE, ...change })).not.toBe(authProfileFingerprint(BASE))
  })

  test('absent profile has a fixed marker', () => {
    expect(authProfileFingerprint(null)).toBe('none')
  })
})

describe('authProfileFingerprintExtra', () => {
  test('non-auth-aware kinds contribute nothing (no DB lookup)', async () => {
    mockFindUnique.mockReset()
    expect(await authProfileFingerprintExtra('gvm', 'p1')).toEqual({})
    expect(await authProfileFingerprintExtra('trufflehog', 'p1')).toEqual({})
    expect(mockFindUnique).not.toHaveBeenCalled()
  })

  test('auth-aware kinds hash the current profile', async () => {
    mockFindUnique.mockResolvedValue({ ...BASE })
    const withProfile = await authProfileFingerprintExtra('full_recon', 'p1')
    expect(withProfile.authProfileFp).toBe(authProfileFingerprint(BASE))
    mockFindUnique.mockResolvedValue(null)
    expect((await authProfileFingerprintExtra('partial_recon', 'p1')).authProfileFp).toBe('none')
  })

  test('resilient to a lookup error (omits the contribution)', async () => {
    mockFindUnique.mockRejectedValue(new Error('db down'))
    expect(await authProfileFingerprintExtra('full_recon', 'p1')).toEqual({})
  })
})

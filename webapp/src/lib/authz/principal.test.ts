/**
 * loadPrincipal reads the signed-in account from the database (HD-10, T3): the
 * role and the account's existence come from this row, never from the login JWT.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const findUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (...a: unknown[]) => findUnique(...a) } },
}))

import { loadPrincipal } from './principal'

const CREATED = new Date('2026-01-02T03:04:05Z')

beforeEach(() => {
  findUnique.mockReset()
})

describe('loadPrincipal', () => {
  test('a missing account is no principal', async () => {
    findUnique.mockResolvedValue(null)
    expect(await loadPrincipal('gone')).toBeNull()
  })

  test('returns the role, the email and the creation time the row holds', async () => {
    findUnique.mockResolvedValue({
      id: 'u1', email: 'u1@e2e.local', role: 'admin', password: '$2a$12$hash', createdAt: CREATED,
    })
    expect(await loadPrincipal('u1')).toEqual({
      id: 'u1', email: 'u1@e2e.local', role: 'admin', hasPassword: true, createdAt: CREATED,
    })
  })

  test('a passwordless account has no password, and the hash never leaves the loader', async () => {
    findUnique.mockResolvedValue({ id: 'm', email: 'm@e2e.local', role: 'standard', password: '', createdAt: CREATED })
    const p = await loadPrincipal('m')
    expect(p?.hasPassword).toBe(false)
    expect(p).not.toHaveProperty('password')
  })

  test('one indexed read by id, selecting only what the principal needs', async () => {
    findUnique.mockResolvedValue(null)
    await loadPrincipal('u1')
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(findUnique).toHaveBeenCalledWith({
      where: { id: 'u1' },
      select: { id: true, email: true, role: true, password: true, createdAt: true },
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

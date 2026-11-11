/**
 * No login timing oracle (HD-26): every failed or successful sign-in costs one
 * bcrypt compare and one database read, so the answer's latency does not say
 * whether the email has an account or whether that account has a password.
 *
 * Counted with a spy on bcrypt itself (the real `verifyPassword` runs), never
 * with a wall clock.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const h = vi.hoisted(() => ({ compare: vi.fn(), queryRaw: vi.fn(), findUnique: vi.fn(), findMany: vi.fn() }))

vi.mock('bcryptjs', async (orig) => {
  const actual = await orig<{ default: Record<string, unknown> }>()
  const real = (actual.default ?? actual) as Record<string, unknown>
  return { default: { ...real, compare: (...a: unknown[]) => h.compare(...a) } }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => h.queryRaw(strings, ...values),
    user: { findUnique: (...a: unknown[]) => h.findUnique(...a), findMany: (...a: unknown[]) => h.findMany(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn().mockResolvedValue(undefined), writeActAsAudit: vi.fn() }))

import { __resetThrottle } from '@/lib/loginThrottle'
import { UNMATCHABLE_PASSWORD_HASH } from '@/lib/auth'
import { POST } from './route'

const ACCOUNT_HASH = '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const account = (over: Record<string, unknown> = {}) => ({
  id: 'u1', name: 'Alice', email: 'alice@x.test', password: ACCOUNT_HASH, role: 'standard', ...over,
})

function login(email: string, password = 'a-submitted-password') {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  }))
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(false)
  h.queryRaw.mockResolvedValue([])
})

describe('one bcrypt compare on every path', () => {
  test('unknown email calls bcrypt compare once', async () => {
    const res = await login('nobody@x.test')
    expect(res.status).toBe(401)
    expect(h.compare).toHaveBeenCalledTimes(1)
    expect(h.compare).toHaveBeenCalledWith('a-submitted-password', UNMATCHABLE_PASSWORD_HASH)
  })

  test('passwordless account calls it once', async () => {
    h.queryRaw.mockResolvedValue([account({ password: '' })])
    const res = await login('alice@x.test')
    expect(res.status).toBe(401)
    expect(h.compare).toHaveBeenCalledTimes(1)
    expect(h.compare).toHaveBeenCalledWith('a-submitted-password', UNMATCHABLE_PASSWORD_HASH)
  })

  test('known email calls it once (wrong password)', async () => {
    h.queryRaw.mockResolvedValue([account()])
    const res = await login('alice@x.test')
    expect(res.status).toBe(401)
    expect(h.compare).toHaveBeenCalledTimes(1)
    expect(h.compare).toHaveBeenCalledWith('a-submitted-password', ACCOUNT_HASH)
  })

  test('known email calls it once (right password)', async () => {
    h.queryRaw.mockResolvedValue([account()])
    h.compare.mockResolvedValue(true)
    const res = await login('alice@x.test')
    expect(res.status).toBe(200)
    expect(h.compare).toHaveBeenCalledTimes(1)
  })

  test('two case variants and no exact match: refused after one compare against the unmatchable hash', async () => {
    h.queryRaw.mockResolvedValue([account({ id: 'a', email: 'Alice@x.test' }), account({ id: 'b', email: 'alice@x.test' })])
    h.compare.mockResolvedValue(true) // even a compare that "matched" cannot sign anyone in
    const res = await login('ALICE@x.test')
    expect(res.status).toBe(401)
    expect(h.compare).toHaveBeenCalledTimes(1)
    expect(h.compare).toHaveBeenCalledWith('a-submitted-password', UNMATCHABLE_PASSWORD_HASH)
  })

  test('an unknown email is refused even if the compare reported a match', async () => {
    h.compare.mockResolvedValue(true)
    expect((await login('nobody@x.test')).status).toBe(401)
  })
})

describe('one database read on every path', () => {
  test.each([
    ['unknown', []],
    ['passwordless', [account({ password: '' })]],
    ['known', [account()]],
  ])('%s email: one query, no second lookup', async (_label, rows) => {
    h.queryRaw.mockResolvedValue(rows)
    await login('alice@x.test')
    expect(h.queryRaw).toHaveBeenCalledTimes(1)
    expect(h.findUnique).not.toHaveBeenCalled()
    expect(h.findMany).not.toHaveBeenCalled()
  })
})

describe('the unmatchable hash', () => {
  test('is a well-formed bcrypt hash at the cost real accounts use (12)', async () => {
    const real = (await vi.importActual<{ default: { getRounds: (h: string) => number } }>('bcryptjs')).default
    expect(UNMATCHABLE_PASSWORD_HASH).toMatch(/^\$2[aby]\$12\$[./A-Za-z0-9]{53}$/)
    expect(real.getRounds(UNMATCHABLE_PASSWORD_HASH)).toBe(12)
  })

  test('a real compare against it runs and never matches', async () => {
    const real = (await vi.importActual<{ default: { compare: (p: string, h: string) => Promise<boolean> } }>('bcryptjs')).default
    await expect(real.compare('', UNMATCHABLE_PASSWORD_HASH)).resolves.toBe(false)
    await expect(real.compare('a-submitted-password', UNMATCHABLE_PASSWORD_HASH)).resolves.toBe(false)
  }, 20_000)
})

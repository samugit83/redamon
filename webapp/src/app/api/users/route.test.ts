/**
 * S2/E2 — POST /api/users write-bypass removal (mint-admin closure).
 *
 * Before: `if (!isInternalRequest(request))` let any X-Internal-Key holder
 * create users — including an admin (role from body). After: creating a user
 * requires an admin SESSION; key possession alone is rejected.
 *
 * Run: npx vitest run src/app/api/users/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockCreate = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()
const mockQueryRaw = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findMany: vi.fn(), create: (...a: unknown[]) => mockCreate(...a) },
    $queryRaw: (...a: unknown[]) => mockQueryRaw(...a),
  },
}))
vi.mock('@/lib/session', () => ({
  getSession: (...a: unknown[]) => mockGetSession(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
}))
vi.mock('@/lib/auth', () => ({ hashPassword: async (p: string) => `hashed:${p}` }))

import { POST } from './route'

function postReq(body: unknown, headers: Record<string, string> = {}) {
  return new NextRequest('http://localhost/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

beforeEach(() => {
  mockCreate.mockReset()
  mockCreate.mockResolvedValue({ id: 'u1', name: 'x', email: 'x@y.z', role: 'admin' })
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
  mockQueryRaw.mockReset()
  mockQueryRaw.mockResolvedValue([])
})

const NEW_ADMIN = { name: 'evil', email: 'evil@x.z', password: 'twelve-chars', role: 'admin' }

describe('POST /api/users — S2/E2 write-bypass removal', () => {
  test('EXPLOIT: internal key mints an admin → now 403, no write', async () => {
    mockIsInternal.mockReturnValue(true) // key present — but bypass is gone
    mockGetSession.mockResolvedValue(null)
    const res = await POST(postReq(NEW_ADMIN, { 'x-internal-key': 'the-key' }))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('standard-user session cannot create users → 403', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'u', role: 'standard' })
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('admin session CAN create a user → 201 (preserved)', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalled()
  })
})

describe('POST /api/users — a database failure', () => {
  test('answers its Prisma code beside the fixed sentence', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    mockCreate.mockRejectedValue(Object.assign(new Error('Timed out fetching a new connection'), { code: 'P2024' }))
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to create user', code: 'P2024' })
  })

  test('a duplicate email is still a 409 with its own sentence', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    mockCreate.mockRejectedValue(Object.assign(new Error('Unique constraint failed'), { code: 'P2002' }))
    const res = await POST(postReq(NEW_ADMIN))
    expect(res.status).toBe(409)
    expect((await res.json()).error).toBe('A user with this email already exists')
  })
})

describe('POST /api/users — password floor (HD-12)', () => {
  beforeEach(() => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
  })

  test('11 characters -> 400 password_too_short, no account created', async () => {
    const res = await POST(postReq({ name: 'M', email: 'm@x.z', password: 'a'.repeat(11) }))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'Password must be at least 12 characters', code: 'password_too_short',
    })
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('73 bytes -> 400 password_too_long, no account created', async () => {
    const res = await POST(postReq({ name: 'M', email: 'm@x.z', password: 'a'.repeat(73) }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_too_long')
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('12 characters -> 201 with the hash stored', async () => {
    const res = await POST(postReq({ name: 'M', email: 'm@x.z', password: 'a'.repeat(12) }))
    expect(res.status).toBe(201)
    expect(mockCreate.mock.calls[0][0].data.password).toBe(`hashed:${'a'.repeat(12)}`)
  })

  test('an empty password still means a passwordless account', async () => {
    const res = await POST(postReq({ name: 'M', email: 'm@x.z', password: '' }))
    expect(res.status).toBe(201)
    expect('password' in mockCreate.mock.calls[0][0].data).toBe(false)
    expect((await res.json()).hasPassword).toBe(false)
  })

  test('no password field at all is passwordless too', async () => {
    const res = await POST(postReq({ name: 'M', email: 'm@x.z' }))
    expect(res.status).toBe(201)
    expect('password' in mockCreate.mock.calls[0][0].data).toBe(false)
  })

  test('a password that is not a string is refused, never hashed', async () => {
    const res = await POST(postReq({ name: 'M', email: 'm@x.z', password: 1234567890123 }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_too_short')
    expect(mockCreate).not.toHaveBeenCalled()
  })
})

describe('POST /api/users — one account per email whatever its case (NF-09)', () => {
  beforeEach(() => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
  })

  test('a new account is stored with its email lowercased', async () => {
    const res = await POST(postReq({ name: 'M', email: 'New.Member@Example.TEST' }))
    expect(res.status).toBe(201)
    expect(mockCreate.mock.calls[0][0].data.email).toBe('new.member@example.test')
  })

  test('an email another account holds in another case -> 409 email_taken, nothing created', async () => {
    mockQueryRaw.mockResolvedValue([{ id: 'legacy-upper' }])
    const res = await POST(postReq({ name: 'M', email: 'alice@x.test' }))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'A user with this email already exists', code: 'email_taken' })
    expect(mockCreate).not.toHaveBeenCalled()
    const [strings, ...values] = mockQueryRaw.mock.calls[0] as [string[], ...unknown[]]
    expect(strings.join('$')).toMatch(/lower\(email\)\s*=\s*lower\(\$\)/)
    expect(values).toEqual(['alice@x.test'])
  })

  test('the unique index still answers a race with 409 email_taken', async () => {
    mockCreate.mockRejectedValue(Object.assign(new Error('Unique constraint failed'), { code: 'P2002' }))
    const res = await POST(postReq({ name: 'M', email: 'alice@x.test' }))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('email_taken')
  })

  test('an email that is not a string -> 400, nothing read or created', async () => {
    const res = await POST(postReq({ name: 'M', email: ['a@x.test'] }))
    expect(res.status).toBe(400)
    expect(mockQueryRaw).not.toHaveBeenCalled()
    expect(mockCreate).not.toHaveBeenCalled()
  })
})

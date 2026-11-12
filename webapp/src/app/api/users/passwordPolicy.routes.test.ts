/**
 * One password policy on the API (step 2.8, ID-20, HD-12 configurable): creating an account
 * with a password and setting one (own change or an admin's reset) apply the policy in
 * force. With the identity switch on that is the instance minimum (never below 12), the deny
 * list and the two rules, judged against the account's own email; with it off it is Phase 1's
 * floor and byte bound, and no instance row is read.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  session: { userId: 'admin-1', role: 'admin' } as { userId: string; role: string } | null,
  policyRow: null as Record<string, unknown> | null,
  accounts: {} as Record<string, Record<string, unknown>>,
  create: vi.fn(),
  update: vi.fn(),
  tokens: vi.fn(),
  instanceRead: vi.fn(),
  transaction: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      create: (a: unknown) => h.create(a),
      findUnique: async ({ where }: { where: { id: string } }) => h.accounts[where.id] ?? null,
      update: (a: unknown) => h.update(a),
    },
    instanceSettings: { findUnique: (a: unknown) => h.instanceRead(a) },
    mcpAccessToken: { updateMany: (a: unknown) => h.tokens(a) },
    $queryRaw: async () => [],
    $transaction: (a: unknown) => h.transaction(a),
  },
}))
vi.mock('@/lib/session', () => ({
  getSession: async () => h.session,
  isInternalRequest: () => false,
}))
vi.mock('@/lib/auth', async (orig) => ({
  ...(await orig<typeof import('@/lib/auth')>()),
  hashPassword: async (p: string) => `hashed:${p}`,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(), writeAuditTx: vi.fn() }))
vi.mock('@/lib/userAudit', () => ({ writeUserAudit: vi.fn(), userAuditEntry: vi.fn() }))
vi.mock('@/lib/authz/rootProtection', () => ({ rootProtectedRefusal: async () => null }))
vi.mock('@/lib/authz/rootPowers', () => ({ requireRootPower: async () => null }))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: async () => ({ ok: true, closed: 0, stoppedRuns: 0 }) }))
vi.mock('@/lib/authz/stepUp', () => ({
  checkStepUp: async () => ({ outcome: 'ok' }),
  requireStepUp: async () => null,
}))

import { setFlagsForTests } from '@/lib/authz/flags'
import { POST as createUser } from './route'
import { PUT as setPassword } from './[id]/password/route'

const post = (body: unknown) => new NextRequest('http://redamon.test/api/users', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
})
const put = (id: string, body: unknown) => setPassword(
  new NextRequest(`http://redamon.test/api/users/${id}/password`, {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }),
  { params: Promise.resolve({ id }) },
)

beforeEach(() => {
  vi.clearAllMocks()
  setFlagsForTests({ identity: true })
  h.session = { userId: 'admin-1', role: 'admin' }
  h.policyRow = { passwordMinLength: 12, passwordAskChangeIfShort: false }
  h.instanceRead.mockImplementation(async () => h.policyRow)
  h.accounts = {
    'admin-1': { id: 'admin-1', role: 'admin', email: 'rbac-admin-long@e2e.local', mustChangePassword: false, sessionVersion: 0 },
    // Step 2.10: an admin's reset reads the status and last sign-in, and writes conditionally on the password.
    'member-1': {
      id: 'member-1', role: 'standard', email: 'rbac-member-long@e2e.local', mustChangePassword: false, sessionVersion: 0,
      status: 'active', lastLoginAt: null, password: 'old-hash', pendingNotices: [],
    },
  }
  h.create.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'new-1', ...data }))
  h.update.mockReturnValue('UPDATE')
  h.tokens.mockReturnValue('TOKENS')
  h.transaction.mockImplementation(async (arg: unknown) => {
    // Someone else's password is a credentials reset (step 2.10): an interactive transaction.
    if (typeof arg === 'function') {
      return arg({
        $executeRaw: async () => 1,
        instanceSettings: { findUnique: async () => null },
        user: {
          findUnique: async ({ where }: { where: { id: string } }) => h.accounts[where.id] ?? null,
          count: async () => 1,
          updateMany: async (a: unknown) => { h.update(a); return { count: 1 } },
        },
        mcpAccessToken: { updateMany: async () => ({ count: 0 }) },
        userInvite: { updateMany: async () => ({ count: 0 }) },
      })
    }
    return [{ id: 'member-1', role: 'standard', sessionVersion: 0 }, { count: 0 }]
  })
})
afterEach(() => setFlagsForTests(null))

describe('POST /api/users applies the policy in force', () => {
  test('the instance minimum (switch on)', async () => {
    h.policyRow = { passwordMinLength: 16, passwordAskChangeIfShort: false }
    const res = await createUser(post({ name: 'n', email: 'new@e2e.local', password: 'quiet-orchid-77' }))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'Password must be at least 16 characters', code: 'password_too_short' })
    expect(h.create).not.toHaveBeenCalled()
  })

  test('deny list', async () => {
    const res = await createUser(post({ name: 'n', email: 'new@e2e.local', password: 'Password1234' }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_common')
    expect(h.create).not.toHaveBeenCalled()
  })

  test('email rule: the new account\'s own address and its name part', async () => {
    for (const password of ['rbac-new-person@e2e.local', 'RBAC-NEW-PERSON']) {
      const res = await createUser(post({ name: 'n', email: 'Rbac-New-Person@e2e.local', password }))
      expect(res.status).toBe(400)
      expect((await res.json()).code).toBe('password_is_email')
    }
    expect(h.create).not.toHaveBeenCalled()
  })

  test('a password that meets the policy creates the account', async () => {
    const res = await createUser(post({ name: 'n', email: 'new@e2e.local', password: 'Correct-orchid-paddle' }))
    expect(res.status).toBe(201)
  })

  test('a passwordless account reads no policy', async () => {
    const res = await createUser(post({ name: 'n', email: 'new@e2e.local' }))
    expect(res.status).toBe(201)
    expect(h.instanceRead).not.toHaveBeenCalled()
  })

  test('switch off: Phase 1\'s floor only, no instance row read', async () => {
    setFlagsForTests({ identity: false })
    const res = await createUser(post({ name: 'n', email: 'new@e2e.local', password: 'password1234' }))
    expect(res.status).toBe(201)
    expect(h.instanceRead).not.toHaveBeenCalled()
  })
})

describe('PUT /api/users/[id]/password applies the policy in force', () => {
  test('an admin\'s reset of a member: the deny list, nothing written', async () => {
    const res = await put('member-1', { newPassword: 'password1234' })
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'This password is too common: choose one that is not on the list of common passwords', code: 'password_common',
    })
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('the email rule reads the target account\'s address', async () => {
    const res = await put('member-1', { newPassword: 'RBAC-MEMBER-LONG' })
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_is_email')
  })

  test('an own change: the instance minimum and the own address', async () => {
    h.session = { userId: 'member-1', role: 'standard' }
    h.policyRow = { passwordMinLength: 16, passwordAskChangeIfShort: false }
    let res = await put('member-1', { newPassword: 'quiet-orchid-77', currentPassword: 'old' })
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'Password must be at least 16 characters', code: 'password_too_short' })
    res = await put('member-1', { newPassword: 'rbac-member-long@e2e.local', currentPassword: 'old' })
    expect((await res.json()).code).toBe('password_is_email')
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('one repeated character', async () => {
    const res = await put('member-1', { newPassword: 'z'.repeat(20) })
    expect((await res.json()).code).toBe('password_repeated')
  })

  test('a password that meets the policy is set', async () => {
    const res = await put('member-1', { newPassword: 'Correct-orchid-paddle' })
    expect(res.status).toBe(200)
    expect(h.transaction).toHaveBeenCalledTimes(1)
  })

  test('switch off: Phase 1\'s floor only, no instance row read', async () => {
    setFlagsForTests({ identity: false })
    const res = await put('member-1', { newPassword: 'password1234' })
    expect(res.status).toBe(200)
    expect(h.instanceRead).not.toHaveBeenCalled()
  })

  test('the floor still answers first, before anything is read', async () => {
    const res = await put('member-1', { newPassword: 'short' })
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_too_short')
    expect(h.instanceRead).not.toHaveBeenCalled()
  })
})

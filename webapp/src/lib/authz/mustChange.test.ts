/**
 * Must-change passwords (step 2.8, ID-17), with the identity switch on:
 *   - a temporary password an admin sets ("require a change at first sign-in", default on)
 *     flags the account and raises its session version in the same transaction, so a cookie
 *     that predates the flag (and lacks `pwc`) is refused and the person signs in again into
 *     the forced flow; creating an account with a password does the same (no cookie to end);
 *   - the account's own change clears the flag and re-issues this browser's cookie without
 *     `pwc`, so the person continues without signing in again;
 *   - the session helpers refuse a cookie whose `pwc` disagrees with the account (a flag set
 *     without a bump, or cleared from another browser): it signs in again;
 * and with the switch off none of it: Phase 1's writes, no claim compared.
 *
 * Real tokens and session helpers; Prisma, bcrypt and the audit writers are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'm'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  jar: {} as Record<string, string>,
  cleared: [] as string[],
  accounts: {} as Record<string, Record<string, unknown>>,
  updates: [] as { where: { id: string }; data: Record<string, unknown> }[],
  creates: [] as Record<string, unknown>[],
  userAudit: vi.fn(),
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (h.jar[name] ? { value: h.jar[name] } : undefined),
    delete: (name: string) => { h.cleared.push(name) },
  })),
}))
const pick = (row: Row, select?: Row) =>
  select ? Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, row[k]])) : { ...row }
vi.mock('@/lib/prisma', () => {
  const user = {
    findUnique: async ({ where, select }: { where: { id: string }; select?: Row }) => {
      const r = h.accounts[where.id]
      return r ? pick(r, select) : null
    },
    update: ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => ({ op: 'update', where, data }),
    create: async ({ data }: { data: Record<string, unknown> }) => {
      h.creates.push(data)
      return { id: 'new-1', createdAt: new Date(0), updatedAt: new Date(0), role: 'standard', ...data }
    },
  }
  return {
    default: {
      user,
      instanceSettings: { findUnique: async () => ({ passwordMinLength: 12, passwordAskChangeIfShort: false }) },
      mcpAccessToken: { updateMany: () => ({ op: 'tokens' }) },
      $queryRaw: async () => [],
      $transaction: async (ops: { op: string; where?: { id: string }; data?: Record<string, unknown> }[]) => ops.map((o) => {
        if (o.op !== 'update') return { count: 0 }
        h.updates.push({ where: o.where!, data: o.data! })
        const row = h.accounts[o.where!.id]
        const inc = (o.data!.sessionVersion as { increment?: number } | undefined)?.increment ?? 0
        Object.assign(row, { ...o.data, sessionVersion: (row.sessionVersion as number) + inc })
        return { ...row }
      }),
    },
  }
})
vi.mock('bcryptjs', async (orig) => {
  const actual = await orig<{ default: Record<string, unknown> }>()
  const real = (actual.default ?? actual) as Record<string, unknown>
  return { default: { ...real, hash: async (p: string) => `hashed:${p}`, compare: async () => true } }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(), writeAuditTx: vi.fn() }))
vi.mock('@/lib/userAudit', () => ({
  writeUserAudit: (...a: unknown[]) => h.userAudit(...a),
  userAuditEntry: vi.fn(),
  actingAsUserId: async () => null,
}))
vi.mock('@/lib/authz/rootProtection', () => ({ rootProtectedRefusal: async () => null }))
vi.mock('@/lib/authz/rootPowers', () => ({ requireRootPower: async () => null }))

import { createToken, verifyToken } from '@/lib/auth'
import { getSession } from '@/lib/session'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { PUT as setPassword } from '@/app/api/users/[id]/password/route'
import { POST as createUser } from '@/app/api/users/route'

const account = (id: string, role: string, over: Row = {}) => ({
  id, email: `${id}@e2e.local`, name: id, role, password: 'old-hash', createdAt: new Date(0), legacyGrants: [],
  status: 'active', sessionVersion: 2, mustChangePassword: false, adminProfileId: null, lastLoginAt: null, ...over,
})

async function signIn(id: string, opts: { sv?: number; pwc?: boolean } = {}) {
  const a = h.accounts[id]
  h.jar['redamon-auth'] = await createToken(id, a.role as string, opts.sv ?? (a.sessionVersion as number), { pwc: opts.pwc })
}

function put(id: string, body: Row) {
  return setPassword(new NextRequest(`http://redamon.test/api/users/${id}/password`, {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id }) })
}

function setCookie(res: Response): string | null {
  const m = /redamon-auth=([^;]*)/.exec(res.headers.get('set-cookie') ?? '')
  return m ? m[1] : null
}

beforeEach(() => {
  vi.clearAllMocks()
  h.jar = {}
  h.cleared = []
  h.updates = []
  h.creates = []
  h.accounts = {
    'admin-1': account('admin-1', 'admin'),
    'member-1': account('member-1', 'standard'),
  }
  clearPrincipalCacheForTests()
  setFlagsForTests({ identity: true })
})
afterEach(() => setFlagsForTests(null))

describe('the pwc claim', () => {
  test('createToken writes pwc: 1 only when asked; verifyToken reads it back', async () => {
    const plain = await verifyToken(await createToken('u', 'standard', 1))
    expect(plain).toEqual({ sub: 'u', role: 'standard', sv: 1 })
    expect(await verifyToken(await createToken('u', 'standard', 1, { pwc: true }))).toEqual({ sub: 'u', role: 'standard', sv: 1, pwc: true })
    const [, body] = (await createToken('u', 'standard', 1, { pwc: true })).split('.')
    expect(JSON.parse(Buffer.from(body, 'base64url').toString())).toMatchObject({ pwc: 1 })
  })

  test('a pwc claim that is present but not 1 makes the token invalid', async () => {
    const { SignJWT } = await import('jose')
    for (const pwc of [true, '1', 0, 2, null]) {
      const token = await new SignJWT({ sub: 'u', role: 'standard', sv: 0, pwc })
        .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h')
        .sign(new TextEncoder().encode('m'.repeat(64)))
      expect(await verifyToken(token), String(pwc)).toBeNull()
    }
  })
})

describe('the session helpers compare pwc with the account (switch on)', () => {
  test('a flagged account with a pwc cookie keeps its session (the change page needs it)', async () => {
    h.accounts['member-1'].mustChangePassword = true
    await signIn('member-1', { pwc: true })
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
  })

  test('a cookie that predates the flag (no pwc) is refused and cleared', async () => {
    h.accounts['member-1'].mustChangePassword = true
    await signIn('member-1')
    expect(await getSession()).toBeNull()
    expect(h.cleared).toEqual(['redamon-auth'])
  })

  test('a pwc cookie after the flag was cleared elsewhere is refused too', async () => {
    await signIn('member-1', { pwc: true })
    expect(await getSession()).toBeNull()
  })

  test('switch off: the claim and the flag decide nothing', async () => {
    setFlagsForTests({ identity: false })
    h.accounts['member-1'].mustChangePassword = true
    await signIn('member-1')
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
    await signIn('member-1', { pwc: true })
    h.accounts['member-1'].mustChangePassword = false
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
  })
})

describe("an admin sets someone else's password", () => {
  test('setting the flag bumps the session version (default: require a change)', async () => {
    await signIn('admin-1')
    const res = await put('member-1', { newPassword: 'Temporary-orchid-42' })
    expect(res.status).toBe(200)
    expect(h.updates).toEqual([{
      where: { id: 'member-1' },
      data: { password: 'hashed:Temporary-orchid-42', mustChangePassword: true, sessionVersion: { increment: 1 } },
    }])
    expect(h.accounts['member-1']).toMatchObject({ mustChangePassword: true, sessionVersion: 3 })
    expect(h.userAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      action: 'user.credentials_reset', targetId: 'member-1', after: { revokedMcpTokens: 0, mustChangePassword: true },
    }))
    // The member's cookie from before the reset is refused: version and flag both moved.
    h.jar['redamon-auth'] = await createToken('member-1', 'standard', 2)
    clearPrincipalCacheForTests()
    expect(await getSession()).toBeNull()
    // The admin's own cookie is untouched by the response.
    expect(setCookie(res)).toBeNull()
  })

  test('unticked: the password is set, the flag cleared, no bump', async () => {
    h.accounts['member-1'].mustChangePassword = true
    await signIn('admin-1')
    await put('member-1', { newPassword: 'Temporary-orchid-42', requirePasswordChange: false })
    expect(h.updates[0].data).toEqual({ password: 'hashed:Temporary-orchid-42', mustChangePassword: false })
    expect(h.accounts['member-1'].sessionVersion).toBe(2)
  })

  test('a requirePasswordChange that is not true or false is refused before anything is written', async () => {
    await signIn('admin-1')
    const res = await put('member-1', { newPassword: 'Temporary-orchid-42', requirePasswordChange: 'yes' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field' })
    expect(h.updates).toEqual([])
  })

  test('switch off: Phase 1 writes the password alone', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    await put('member-1', { newPassword: 'Temporary-orchid-42', requirePasswordChange: true })
    expect(h.updates[0].data).toEqual({ password: 'hashed:Temporary-orchid-42' })
    expect(h.accounts['member-1']).toMatchObject({ mustChangePassword: false, sessionVersion: 2 })
  })
})

describe('the account changes its own password', () => {
  test('change clears the flag and re-issues this browser\'s cookie without pwc', async () => {
    h.accounts['member-1'].mustChangePassword = true
    await signIn('member-1', { pwc: true })
    const res = await put('member-1', { newPassword: 'My-own-orchid-77', currentPassword: 'the-temporary-one' })
    expect(res.status).toBe(200)
    expect(h.updates[0].data).toEqual({ password: 'hashed:My-own-orchid-77', mustChangePassword: false })
    const cookie = setCookie(res)
    expect(cookie).toBeTruthy()
    expect(await verifyToken(cookie!)).toEqual({ sub: 'member-1', role: 'standard', sv: 2 })
    expect(res.headers.get('set-cookie')).toMatch(/HttpOnly/i)
    expect(res.headers.get('set-cookie')).toMatch(/SameSite=lax/i)
    // The new cookie is accepted at once: the flag and the claim agree again.
    h.jar['redamon-auth'] = cookie!
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
  })

  test('an account that was not flagged keeps its cookie (nothing re-issued)', async () => {
    await signIn('member-1')
    const res = await put('member-1', { newPassword: 'My-own-orchid-77', currentPassword: 'old' })
    expect(res.status).toBe(200)
    expect(h.updates[0].data).toEqual({ password: 'hashed:My-own-orchid-77', mustChangePassword: false })
    expect(setCookie(res)).toBeNull()
  })

  test("an admin's own change from its row ignores requirePasswordChange", async () => {
    h.accounts['admin-1'].mustChangePassword = true
    await signIn('admin-1', { pwc: true })
    const res = await put('admin-1', { newPassword: 'Admin-own-orchid-9', currentPassword: 'temp', requirePasswordChange: true })
    expect(h.updates[0].data).toEqual({ password: 'hashed:Admin-own-orchid-9', mustChangePassword: false })
    expect(await verifyToken(setCookie(res)!)).toEqual({ sub: 'admin-1', role: 'admin', sv: 2 })
  })
})

describe('creating an account with a temporary password', () => {
  const post = (body: Row) => createUser(new NextRequest('http://redamon.test/api/users', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }))

  test('flagged by default (switch on)', async () => {
    await signIn('admin-1')
    expect((await post({ name: 'N', email: 'n@e2e.local', password: 'Temporary-orchid-42' })).status).toBe(201)
    expect(h.creates[0]).toMatchObject({ mustChangePassword: true })
  })

  test('unticked: not flagged; passwordless: never flagged', async () => {
    await signIn('admin-1')
    await post({ name: 'N', email: 'n@e2e.local', password: 'Temporary-orchid-42', requirePasswordChange: false })
    await post({ name: 'M', email: 'm@e2e.local' })
    expect(h.creates[0]).not.toHaveProperty('mustChangePassword')
    expect(h.creates[1]).not.toHaveProperty('mustChangePassword')
  })

  test('switch off: Phase 1 data', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    await post({ name: 'N', email: 'n@e2e.local', password: 'Temporary-orchid-42' })
    expect(h.creates[0]).not.toHaveProperty('mustChangePassword')
  })
})

/**
 * Step-up (T13, ID-25): an action a stolen session cookie must not take alone asks
 * again for the password of the REAL signed-in account. One helper decides the
 * outcome, one lockout counter per person covers every caller, and each caller maps
 * the outcome: the MCP mint and the widening token PATCH keep their 401/429, every
 * newer caller answers 403 step_up_required / step_up_failed and 429 step_up_locked.
 *
 * Real tokens, the real session helpers, the real limiter and real bcrypt (cost 4);
 * only the cookie store, Prisma and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import bcrypt from 'bcryptjs'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'e'.repeat(64))
vi.stubEnv('LOGIN_MAX_ATTEMPTS', '5')
vi.stubEnv('LOGIN_LOCKOUT_SECONDS', '900')

const cookieJar: { auth?: string; actAs?: string } = {}
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && cookieJar.auth) return { value: cookieJar.auth }
      if (name === 'redamon-act-as' && cookieJar.actAs) return { value: cookieJar.actAs }
      return undefined
    },
  })),
}))

type UserRow = { id: string; email: string; role: string; password: string; createdAt: Date }
const h = vi.hoisted(() => ({
  users: new Map<string, UserRow>(),
  findUnique: vi.fn(),
  tokenRow: null as Record<string, unknown> | null,
}))

const pick = (row: UserRow | undefined) => (row ? { ...row } : null)
vi.mock('@/lib/prisma', () => {
  const db: Record<string, unknown> = {
    user: {
      findUnique: (a: { where: { id: string } }) => { h.findUnique(a); return Promise.resolve(pick(h.users.get(a.where.id))) },
      update: vi.fn(async () => ({})),
      delete: vi.fn(async () => ({})),
      count: vi.fn(async () => 1),
    },
    mcpAccessToken: {
      create: vi.fn(async () => ({ id: 'tok-1' })),
      findUnique: vi.fn(async () => h.tokenRow),
      update: vi.fn(async () => h.tokenRow),
      updateMany: vi.fn(() => 'REVOKE_OP'),
    },
    capturedHttpTransaction: { findMany: vi.fn(async () => []) },
    project: { findMany: vi.fn(async () => []) },
    $executeRaw: vi.fn(async () => 1),
  }
  db.$transaction = async (arg: unknown) =>
    Array.isArray(arg) ? [{}, { count: 0 }] : (arg as (tx: unknown) => Promise<unknown>)(db)
  return { default: db }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => undefined), writeActAsAudit: vi.fn(async () => undefined) }))
vi.mock('@/lib/workspacePurge', () => ({ purgeProjectWorkspace: vi.fn(async () => undefined) }))

import { checkStepUp, stepUpRefusal, stepUpThrottleKey } from './stepUp'
import { createToken, createActAsToken } from '@/lib/auth'
import { __resetThrottle } from '@/lib/loginThrottle'
import { POST as mint } from '@/app/api/users/[id]/mcp-tokens/route'
import { PATCH as patchToken } from '@/app/api/users/[id]/mcp-tokens/[tokenId]/route'
import { POST as actAs } from '@/app/api/auth/act-as/route'
import { PUT as setPassword } from '@/app/api/users/[id]/password/route'
import { PUT as updateUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'

const PASSWORDS: Record<string, string> = {
  'admin-1': 'admin-one-passphrase',
  'admin-2': 'admin-two-passphrase',
  'member-1': 'member-one-passphrase',
}

function seed() {
  h.users.clear()
  for (const [id, role] of [['admin-1', 'admin'], ['admin-2', 'admin'], ['member-1', 'standard']] as const) {
    h.users.set(id, {
      id, email: `${id}@e2e.local`, role,
      password: bcrypt.hashSync(PASSWORDS[id], 4), createdAt: new Date(0),
    })
  }
}

async function signIn(userId: string, actingAs?: string) {
  cookieJar.auth = await createToken(userId, h.users.get(userId)?.role ?? 'standard')
  cookieJar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

const request = (body: unknown = {}, method = 'POST') =>
  new NextRequest('http://localhost:3000/api/x', {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) })
const bcryptCompare = () => vi.spyOn(bcrypt, 'compare')

beforeEach(() => {
  __resetThrottle()
  seed()
  h.findUnique.mockClear()
  h.tokenRow = {
    id: 't1', userId: 'admin-1', name: 'ci', tokenPrefix: 'rdmn_mcp_x', scopes: ['recon:read'],
    profile: null, lastUsedAt: null, expiresAt: null, revokedAt: null, createdAt: new Date(0),
  }
  vi.restoreAllMocks()
})

describe('outcomes missing, wrong, locked, ok', () => {
  test('no password, an empty one or a non-string is missing, and costs no attempt and no KDF', async () => {
    await signIn('admin-1')
    const compare = bcryptCompare()
    for (const pw of [undefined, '', 42, null]) {
      expect(await checkStepUp(request(), pw)).toEqual({ outcome: 'missing' })
    }
    expect(compare).not.toHaveBeenCalled()
    // Five missing answers did not lock anything: the right password still passes.
    for (let i = 0; i < 5; i++) await checkStepUp(request(), '')
    expect(await checkStepUp(request(), PASSWORDS['admin-1'])).toEqual({ outcome: 'ok' })
  })

  test('a wrong password is wrong, and counts', async () => {
    await signIn('admin-1')
    expect(await checkStepUp(request(), 'not-the-password')).toEqual({ outcome: 'wrong' })
  })

  test('the fifth wrong password locks; a locked check answers before the KDF', async () => {
    await signIn('admin-1')
    for (let i = 0; i < 5; i++) expect((await checkStepUp(request(), 'guess')).outcome).toBe('wrong')
    const compare = bcryptCompare()
    const locked = await checkStepUp(request(), PASSWORDS['admin-1'])
    expect(locked.outcome).toBe('locked')
    expect(locked.outcome === 'locked' && locked.retryAfterSeconds).toBeGreaterThan(0)
    expect(compare).not.toHaveBeenCalled()
  })

  test('the right password is ok and clears the counter', async () => {
    await signIn('admin-1')
    for (let i = 0; i < 4; i++) await checkStepUp(request(), 'guess')
    expect(await checkStepUp(request(), PASSWORDS['admin-1'])).toEqual({ outcome: 'ok' })
    // Four more wrong ones would have locked an uncleared counter at the first.
    for (let i = 0; i < 4; i++) expect((await checkStepUp(request(), 'guess')).outcome).toBe('wrong')
  })

  test('no signed-in account is never ok', async () => {
    cookieJar.auth = undefined
    expect((await checkStepUp(request(), PASSWORDS['admin-1'])).outcome).toBe('wrong')
    await signIn('admin-1')
    h.users.delete('admin-1')
    expect((await checkStepUp(request(), PASSWORDS['admin-1'])).outcome).toBe('wrong')
  })

  test('the counter is the mint\'s key, per person', () => {
    expect(stepUpThrottleKey('admin-1')).toBe('mcp-token-mint:admin-1')
  })
})

describe('new callers answer 403 step_up_required / step_up_failed and 429 step_up_locked', () => {
  test('ok refuses nothing', () => {
    expect(stepUpRefusal({ outcome: 'ok' })).toBeNull()
  })

  test('missing -> 403 step_up_required', async () => {
    const res = stepUpRefusal({ outcome: 'missing' })!
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'Enter your password to confirm this action.', code: 'step_up_required' })
  })

  test('wrong -> 403 step_up_failed', async () => {
    const res = stepUpRefusal({ outcome: 'wrong' })!
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'Password is incorrect', code: 'step_up_failed' })
  })

  test('locked -> 429 step_up_locked with the wait', async () => {
    const res = stepUpRefusal({ outcome: 'locked', retryAfterSeconds: 742 })!
    expect(res.status).toBe(429)
    expect(res.headers.get('Retry-After')).toBe('742')
    expect(await res.json()).toEqual({
      error: 'Too many incorrect passwords. Try again in 742s.', code: 'step_up_locked',
    })
  })

  test('a new caller (act-as on an admin) answers each of them', async () => {
    await signIn('admin-1')
    const body = (pw?: string) => ({ targetUserId: 'admin-2', ...(pw === undefined ? {} : { stepUpPassword: pw }) })
    const missing = await actAs(request(body()))
    expect([missing.status, (await missing.json()).code]).toEqual([403, 'step_up_required'])
    const wrong = await actAs(request(body('guess')))
    expect([wrong.status, (await wrong.json()).code]).toEqual([403, 'step_up_failed'])
    for (let i = 0; i < 4; i++) await actAs(request(body('guess')))
    const locked = await actAs(request(body(PASSWORDS['admin-1'])))
    expect([locked.status, (await locked.json()).code]).toEqual([429, 'step_up_locked'])
  })
})

describe('the mint keeps 401 and 429', () => {
  const mintBody = (pw?: string) => ({ name: 'ci', scopes: ['recon:read'], expiresInDays: 90, password: pw })

  test('missing and wrong -> 401 "Password is incorrect", no step-up code', async () => {
    await signIn('admin-1')
    for (const pw of [undefined, 'guess']) {
      const res = await mint(request(mintBody(pw)), params({ id: 'admin-1' }))
      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Password is incorrect' })
    }
  })

  test('locked -> 429 with the wait, no step-up code', async () => {
    await signIn('admin-1')
    for (let i = 0; i < 5; i++) await mint(request(mintBody('guess')), params({ id: 'admin-1' }))
    const res = await mint(request(mintBody(PASSWORDS['admin-1'])), params({ id: 'admin-1' }))
    expect(res.status).toBe(429)
    const json = await res.json()
    expect(json.error).toMatch(/^Too many incorrect passwords\. Try again in \d+s\.$/)
    expect(json.code).toBeUndefined()
  })

  test('the right password mints', async () => {
    await signIn('admin-1')
    expect((await mint(request(mintBody(PASSWORDS['admin-1'])), params({ id: 'admin-1' }))).status).toBe(201)
  })

  test('the widening PATCH keeps its own 401 texts and passwordRequired', async () => {
    await signIn('admin-1')
    const widen = (pw?: string) => request({ scopes: ['recon:read', 'recon:scan'], ...(pw === undefined ? {} : { password: pw }) }, 'PATCH')
    const missing = await patchToken(widen(), params({ id: 'admin-1', tokenId: 't1' }))
    expect(missing.status).toBe(401)
    expect(await missing.json()).toEqual({
      error: 'Adding a permission or extending the expiry needs your password.', passwordRequired: true,
    })
    const wrong = await patchToken(widen('guess'), params({ id: 'admin-1', tokenId: 't1' }))
    expect(wrong.status).toBe(401)
    expect(await wrong.json()).toEqual({ error: 'Password is incorrect', passwordRequired: true })
  })
})

describe('one lockout counter per real user across callers', () => {
  test('wrong passwords on five different routes lock the sixth, on any route', async () => {
    await signIn('admin-1')
    const wrong = 'guess'
    expect((await mint(request({ name: 'ci', scopes: ['recon:read'], expiresInDays: 90, password: wrong }), params({ id: 'admin-1' }))).status).toBe(401)
    expect((await actAs(request({ targetUserId: 'admin-2', stepUpPassword: wrong }))).status).toBe(403)
    expect((await setPassword(request({ newPassword: 'a-new-admin-passphrase', stepUpPassword: wrong }, 'PUT'), params({ id: 'admin-2' }))).status).toBe(403)
    expect((await updateUser(request({ role: 'standard', stepUpPassword: wrong }, 'PUT'), params({ id: 'admin-2' }))).status).toBe(403)
    expect((await deleteUser(request({ stepUpPassword: wrong }, 'DELETE'), params({ id: 'admin-2' }))).status).toBe(403)

    // The sixth attempt carries the RIGHT password and is still refused, everywhere.
    const right = PASSWORDS['admin-1']
    expect((await actAs(request({ targetUserId: 'admin-2', stepUpPassword: right }))).status).toBe(429)
    expect((await mint(request({ name: 'ci', scopes: ['recon:read'], expiresInDays: 90, password: right }), params({ id: 'admin-1' }))).status).toBe(429)
    expect((await setPassword(request({ newPassword: 'a-new-own-passphrase', currentPassword: right }, 'PUT'), params({ id: 'admin-1' }))).status).toBe(429)
  })

  test('another person keeps their own budget', async () => {
    await signIn('admin-1')
    for (let i = 0; i < 5; i++) await actAs(request({ targetUserId: 'admin-2', stepUpPassword: 'guess' }))
    await signIn('admin-2')
    const res = await actAs(request({ targetUserId: 'admin-1', stepUpPassword: PASSWORDS['admin-2'] }))
    expect(res.status).toBe(200)
  })
})

describe('act-as never changes whose password is checked', () => {
  test('acting as a member, the admin proves THEIR password, never the member\'s', async () => {
    await signIn('admin-1', 'member-1')
    expect(await checkStepUp(request(), PASSWORDS['admin-1'])).toEqual({ outcome: 'ok' })
    expect(await checkStepUp(request(), PASSWORDS['member-1'])).toEqual({ outcome: 'wrong' })
    const hashReads = h.findUnique.mock.calls.filter(([a]) => a.select?.password && !a.select?.role)
    expect(hashReads.map(([a]) => a.where.id)).toEqual(['admin-1', 'admin-1'])
  })

  test('the failures count against the admin, not the account being acted as', async () => {
    await signIn('admin-1', 'member-1')
    for (let i = 0; i < 5; i++) await checkStepUp(request(), 'guess')
    expect((await checkStepUp(request(), PASSWORDS['admin-1'])).outcome).toBe('locked')
    await signIn('member-1')
    expect((await checkStepUp(request(), PASSWORDS['member-1'])).outcome).toBe('ok')
  })
})

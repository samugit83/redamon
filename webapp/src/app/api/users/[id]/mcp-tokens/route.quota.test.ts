/**
 * The MCP token quotas (step 6.8, GV-13) on the mint and the expiry change. With RBAC_GOVERNANCE_ENABLED
 * on: the mint refuses beyond maxMcpTokens working tokens and any expiry later than
 * maxMcpTokenExpiryDays allows ("never" included), before the password is spent; a PATCH that extends
 * the expiry obeys the same lifetime, and reviving an expired token counts it again; narrowing is never
 * refused; the list answers `tokenQuota` so the screen offers only what is allowed. With the switch off
 * nothing is read and every expiry the presets offer is accepted, as before.
 *
 * Same doubles as route.test.ts, plus the real lib/authz/quotas.ts over a doubled instance row,
 * account and capability resolution, and a token count.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  getSession: vi.fn(),
  requireUserAccess: vi.fn(),
  verifyPassword: vi.fn(),
  audit: vi.fn(),
  findUser: vi.fn(),
  createToken: vi.fn(),
  findManyTokens: vi.fn(),
  findToken: vi.fn(),
  updateToken: vi.fn(),
  deleteToken: vi.fn(),
  checkLockout: vi.fn(),
  recordFailure: vi.fn(),
  clearAttempts: vi.fn(),
  countTokens: vi.fn(),
  quotas: {} as unknown,
  instanceRead: vi.fn(),
}))

vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => { h.instanceRead(); return { quotas: h.quotas } },
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active', legacyGrants: [], permissionSets: [], permissionOverrides: [] }),
}))
// Their own tests cover them; with the permissions switch on they would read the account's capabilities.
vi.mock('@/lib/mcp/scopePermissions', () => ({ scopeGrantRefusal: async () => null, ungrantableScopesOf: async () => null }))
vi.mock('@/lib/authz/rootProtection', () => ({ rootTokensRefusal: async () => null }))
vi.mock('@/lib/authz/capabilities', () => ({
  resolveCapabilities: async () => ({ accountType: 'member', sets: [{ id: 'builtin:default-member', name: 'Default member', kind: 'member', via: 'default' }] }),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => h.findUser(...a) },
    mcpAccessToken: {
      create: (...a: unknown[]) => h.createToken(...a),
      findMany: (...a: unknown[]) => h.findManyTokens(...a),
      findUnique: (...a: unknown[]) => h.findToken(...a),
      update: (...a: unknown[]) => h.updateToken(...a),
      delete: (...a: unknown[]) => h.deleteToken(...a),
      count: (...a: unknown[]) => h.countTokens(...a),
    },
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  getSession: (...a: unknown[]) => h.getSession(...a),
  requireUserAccess: (...a: unknown[]) => h.requireUserAccess(...a),
}))
vi.mock('@/lib/auth', () => ({ verifyPassword: (...a: unknown[]) => h.verifyPassword(...a) }))
// The mint step-up shares the login route's limiter (audit finding F6): the
// same credential and the same slow KDF, so without it the endpoint was an
// unlimited-rate password oracle for a stolen session cookie.
vi.mock('@/lib/loginThrottle', () => ({
  checkLockout: (...a: unknown[]) => h.checkLockout(...a),
  recordFailure: (...a: unknown[]) => h.recordFailure(...a),
  clearAttempts: (...a: unknown[]) => h.clearAttempts(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { NextResponse } from 'next/server'
import { afterEach } from 'vitest'
import { setFlagsForTests } from '@/lib/authz/flags'
import { GET, POST } from './route'
import { PATCH, DELETE } from './[tokenId]/route'

const params = (id = 'owner', tokenId = 't1') => ({ params: Promise.resolve({ id, tokenId }) })
// The write routes take only same-origin JSON (step 2.12): the double carries the JSON content type.
const req = (body?: unknown, headers: Record<string, string> = {}) =>
  ({
    headers: new Headers({ 'content-type': 'application/json', ...headers }),
    json: async () => { if (body === undefined) throw new SyntaxError('bad'); return body },
  }) as never

const validBody = (over: Record<string, unknown> = {}) => ({
  name: 'ci agent',
  scopes: ['recon:read'],
  expiresInDays: 90,
  password: 'correct-horse',
  ...over,
})

const TOKEN_ROW = {
  id: 't1', name: 'ci agent', tokenPrefix: 'rdmn_mcp_a3f9c21e',
  scopes: ['recon:read'], lastUsedAt: null, expiresAt: null,
  revokedAt: null, createdAt: new Date(),
}

beforeEach(() => {
  vi.clearAllMocks()
  h.getSession.mockResolvedValue({ userId: 'owner', role: 'standard' })
  // session.ts requireUserAccess over the session the test sets: `read` and `revoke` admit
  // the account or an admin (permissions switch off), `write` the account only (HD-23; no
  // act-as in this file).
  h.requireUserAccess.mockImplementation(async (_r: unknown, id: string, { mode }: { mode: string }) => {
    const s = await h.getSession()
    if (!s) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (s.userId === id || ((mode === 'read' || mode === 'revoke') && s.role === 'admin')) return null
    return NextResponse.json(s.role === 'admin' ? { error: 'own account only', code: 'own_account_only' } : { error: 'Forbidden' }, { status: 403 })
  })
  h.verifyPassword.mockResolvedValue(true)
  h.findUser.mockResolvedValue({ password: 'bcrypt-hash' })
  h.createToken.mockResolvedValue(TOKEN_ROW)
  h.findManyTokens.mockResolvedValue([TOKEN_ROW])
  h.findToken.mockResolvedValue({ ...TOKEN_ROW, userId: 'owner' })
  h.updateToken.mockResolvedValue(TOKEN_ROW)
  h.deleteToken.mockResolvedValue(TOKEN_ROW)
  h.audit.mockResolvedValue(undefined)
  h.checkLockout.mockReturnValue({ locked: false, retryAfterSeconds: 0 })
  h.countTokens.mockResolvedValue(1)
  h.quotas = { defaults: { maxMcpTokens: 2, maxMcpTokenExpiryDays: 90 } }
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

const DAY = 86_400_000

describe('mint', () => {
  test('within both quotas the token is minted', async () => {
    const res = await POST(req(validBody({ expiresInDays: 90 })), params('owner'))
    expect(res.status).toBe(201)
    expect(h.countTokens).toHaveBeenCalledWith(expect.objectContaining({ where: expect.objectContaining({ userId: 'owner', revokedAt: null }) }))
  })

  test('token count: at maxMcpTokens working tokens, 409 before the password is checked', async () => {
    h.countTokens.mockResolvedValue(2)
    const res = await POST(req(validBody()), params('owner'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'quota_exceeded', quota: 'maxMcpTokens', limit: 2 })
    expect(h.verifyPassword).not.toHaveBeenCalled()
    expect(h.createToken).not.toHaveBeenCalled()
  })

  test('expiry: longer than maxMcpTokenExpiryDays, or "never", is refused; nothing minted', async () => {
    for (const expiresInDays of [365, 'never', null]) {
      const res = await POST(req(validBody({ expiresInDays })), params('owner'))
      expect(res.status).toBe(409)
      const body = await res.json()
      expect(body).toMatchObject({ code: 'quota_exceeded', quota: 'maxMcpTokenExpiryDays', limit: 90 })
      expect(body.error).toMatch(/at most 90 days/)
    }
    expect(h.createToken).not.toHaveBeenCalled()
    expect(h.verifyPassword).not.toHaveBeenCalled()
  })

  test('switch off: nothing read, "never" and a year minted as before', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    for (const expiresInDays of [365, 'never']) {
      expect((await POST(req(validBody({ expiresInDays })), params('owner'))).status).toBe(201)
    }
    expect(h.instanceRead).not.toHaveBeenCalled()
    expect(h.countTokens).not.toHaveBeenCalled()
  })
})

describe('the list says what the quota allows', () => {
  test('tokenQuota with the limits and the count; absent when no token quota applies or the switch is off', async () => {
    const body = await (await GET(req(), params('owner'))).json()
    expect(body.tokenQuota).toEqual({ maxMcpTokens: 2, maxMcpTokenExpiryDays: 90, active: 1 })
    h.quotas = { defaults: { maxProjects: 1 } }
    expect(await (await GET(req(), params('owner'))).json()).not.toHaveProperty('tokenQuota')
    setFlagsForTests({ identity: true, permissions: true })
    h.quotas = { defaults: { maxMcpTokens: 2 } }
    expect(await (await GET(req(), params('owner'))).json()).not.toHaveProperty('tokenQuota')
  })
})

describe('expiry change (PATCH)', () => {
  test('extending beyond maxMcpTokenExpiryDays, or to "never", is refused before the password', async () => {
    h.findToken.mockResolvedValue({ ...TOKEN_ROW, userId: 'owner', expiresAt: new Date(Date.now() + 10 * DAY) })
    for (const expiry of [365, 'never']) {
      const res = await PATCH(req({ expiry, password: 'correct-horse' }), params('owner'))
      expect(res.status).toBe(409)
      expect(await res.json()).toMatchObject({ quota: 'maxMcpTokenExpiryDays', limit: 90 })
    }
    expect(h.updateToken).not.toHaveBeenCalled()
    expect(h.verifyPassword).not.toHaveBeenCalled()
  })

  test('a date at the edge of the lifetime is allowed (to the end of that UTC day); one day more is refused', async () => {
    h.findToken.mockResolvedValue({ ...TOKEN_ROW, userId: 'owner', expiresAt: new Date(Date.now() + 10 * DAY) })
    const day = (n: number) => new Date(Date.now() + n * DAY).toISOString().slice(0, 10)
    expect((await PATCH(req({ expiry: day(90), password: 'correct-horse' }), params('owner'))).status).toBe(200)
    expect((await PATCH(req({ expiry: day(91), password: 'correct-horse' }), params('owner'))).status).toBe(409)
  })

  test('reviving an expired token counts it again', async () => {
    h.findToken.mockResolvedValue({ ...TOKEN_ROW, userId: 'owner', expiresAt: new Date(Date.now() - DAY) })
    h.countTokens.mockResolvedValue(2)
    const res = await PATCH(req({ expiry: 30, password: 'correct-horse' }), params('owner'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ quota: 'maxMcpTokens', limit: 2 })
    h.countTokens.mockResolvedValue(1)
    expect((await PATCH(req({ expiry: 30, password: 'correct-horse' }), params('owner'))).status).toBe(200)
  })

  test('narrowing is never refused, even past the quota (a token minted before it)', async () => {
    h.findToken.mockResolvedValue({ ...TOKEN_ROW, userId: 'owner', expiresAt: null })
    h.countTokens.mockResolvedValue(9)
    expect((await PATCH(req({ expiry: 365 }), params('owner'))).status).toBe(200)
    expect((await PATCH(req({ expiry: 'now' }), params('owner'))).status).toBe(200)
  })
})

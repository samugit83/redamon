/**
 * The token's opt-in to shared projects on the token routes (step 4.10; SH-42): with
 * RBAC_SHARING_ENABLED on the mint stores `includeSharedProjects` and `projectAllowlist` behind the
 * mint's password, the list and the edit show them, and an edit that opens the token to more shared
 * projects is a widening (the mint's step-up), while opting out or naming fewer only narrows. With
 * the switch off neither field is read from a body, stored or listed: the routes answer as before.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

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
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => h.findUser(...a) },
    mcpAccessToken: {
      create: (...a: unknown[]) => h.createToken(...a),
      findMany: (...a: unknown[]) => h.findManyTokens(...a),
      findUnique: (...a: unknown[]) => h.findToken(...a),
      update: (...a: unknown[]) => h.updateToken(...a),
    },
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  getSession: (...a: unknown[]) => h.getSession(...a),
  requireUserAccess: (...a: unknown[]) => h.requireUserAccess(...a),
}))
vi.mock('@/lib/auth', () => ({ verifyPassword: (...a: unknown[]) => h.verifyPassword(...a) }))
vi.mock('@/lib/loginThrottle', () => ({
  checkLockout: () => ({ locked: false, retryAfterSeconds: 0 }),
  recordFailure: () => undefined,
  clearAttempts: () => undefined,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
// The permission cap and Root's token protection are 3.10's and 2.5's, pinned in their own files.
vi.mock('@/lib/mcp/scopePermissions', () => ({ scopeGrantRefusal: async () => null, ungrantableScopesOf: async () => undefined }))
vi.mock('@/lib/authz/rootProtection', () => ({ rootTokensRefusal: async () => null }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { GET, POST } from './route'
import { PATCH } from './[tokenId]/route'

const params = (id = 'owner', tokenId = 't1') => ({ params: Promise.resolve({ id, tokenId }) })
const req = (body?: unknown) =>
  ({
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
  }) as never

const mintBody = (over: Record<string, unknown> = {}) => ({
  name: 'ci agent', scopes: ['recon:read'], expiresInDays: 90, password: 'correct-horse', ...over,
})

const TOKEN_ROW = {
  id: 't1', name: 'ci agent', tokenPrefix: 'rdmn_mcp_a3f9c21e', scopes: ['recon:read'], profile: null,
  lastUsedAt: null, expiresAt: null, revokedAt: null, createdAt: new Date(),
}
const stored = (over: Record<string, unknown> = {}) => ({
  ...TOKEN_ROW, userId: 'owner', includeSharedProjects: false, projectAllowlist: [] as string[], ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  h.getSession.mockResolvedValue({ userId: 'owner', role: 'standard' })
  h.requireUserAccess.mockImplementation(async (_r: unknown, id: string, { mode }: { mode: string }) => {
    const s = await h.getSession()
    if (s.userId === id || ((mode === 'read' || mode === 'revoke') && s.role === 'admin')) return null
    return Response.json({ error: 'Forbidden' }, { status: 403 })
  })
  h.verifyPassword.mockResolvedValue(true)
  h.findUser.mockResolvedValue({ password: 'bcrypt-hash' })
  h.createToken.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...TOKEN_ROW, ...data }))
  h.findManyTokens.mockResolvedValue([stored({ includeSharedProjects: true, projectAllowlist: ['P-1'] })])
  h.findToken.mockResolvedValue(stored())
  h.updateToken.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...stored(), ...data }))
  h.audit.mockResolvedValue(undefined)
})
afterEach(() => setFlagsForTests(null))

describe('mint with sharing on', () => {
  test('stores the opt-in and its allowlist, and audits them', async () => {
    const res = await POST(req(mintBody({ includeSharedProjects: true, projectAllowlist: ['P-1', 'P-1'] })), params())
    expect(res.status).toBe(201)
    const { data, select } = h.createToken.mock.calls[0][0]
    expect(data).toMatchObject({ includeSharedProjects: true, projectAllowlist: ['P-1'] })
    expect(select).toMatchObject({ includeSharedProjects: true, projectAllowlist: true })
    expect(h.audit.mock.calls[0][0].after).toMatchObject({ includeSharedProjects: true, projectAllowlist: ['P-1'] })
  })

  test('opt-in needs the password: without it the mint is refused and nothing is stored', async () => {
    const res = await POST(req(mintBody({ includeSharedProjects: true, password: undefined })), params())
    expect(res.status).toBe(401)
    expect(h.createToken).not.toHaveBeenCalled()
  })

  test('a mint that does not opt in stores the defaults', async () => {
    await POST(req(mintBody()), params())
    expect(h.createToken.mock.calls[0][0].data).toMatchObject({ includeSharedProjects: false, projectAllowlist: [] })
  })

  test('an invalid opt-in is refused before the password', async () => {
    const res = await POST(req(mintBody({ includeSharedProjects: 'yes' })), params())
    expect(res.status).toBe(400)
    expect(h.verifyPassword).not.toHaveBeenCalled()
  })

  test('the list shows the opt-in', async () => {
    const res = await GET(req(), params())
    expect(h.findManyTokens.mock.calls[0][0].select).toMatchObject({ includeSharedProjects: true, projectAllowlist: true })
    expect((await res.json()).tokens[0]).toMatchObject({ includeSharedProjects: true, projectAllowlist: ['P-1'] })
  })
})

describe('edit with sharing on', () => {
  test('opting in is a widening: refused without the password, saved with it', async () => {
    const missing = await PATCH(req({ includeSharedProjects: true }), params())
    expect(missing.status).toBe(401)
    expect(await missing.json()).toMatchObject({ passwordRequired: true, error: expect.stringMatching(/shared with you needs your password/) })
    expect(h.updateToken).not.toHaveBeenCalled()

    const ok = await PATCH(req({ includeSharedProjects: true, password: 'correct-horse' }), params())
    expect(ok.status).toBe(200)
    expect(h.updateToken.mock.calls[0][0].data).toEqual({ includeSharedProjects: true })
    expect(h.audit.mock.calls[0][0]).toMatchObject({
      action: 'mcp-token.update',
      before: { includeSharedProjects: false, projectAllowlist: [] },
      after: { includeSharedProjects: true, widened: true },
    })
  })

  test('emptying the allowlist widens; naming fewer narrows without a password', async () => {
    h.findToken.mockResolvedValue(stored({ includeSharedProjects: true, projectAllowlist: ['P-1', 'P-2'] }))
    expect((await PATCH(req({ projectAllowlist: [] }), params())).status).toBe(401)
    const narrowed = await PATCH(req({ projectAllowlist: ['P-1'] }), params())
    expect(narrowed.status).toBe(200)
    expect(h.updateToken.mock.calls[0][0].data).toEqual({ projectAllowlist: ['P-1'] })
    expect(h.verifyPassword).not.toHaveBeenCalled()
  })

  test("opting out narrows: an admin may do it on another account's token during an incident", async () => {
    h.getSession.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    h.findToken.mockResolvedValue(stored({ includeSharedProjects: true, projectAllowlist: ['P-1'] }))
    const res = await PATCH(req({ includeSharedProjects: false }), params())
    expect(res.status).toBe(200)
    expect(h.updateToken.mock.calls[0][0].data).toEqual({ includeSharedProjects: false, projectAllowlist: [] })
  })

  test("an admin cannot open another account's token to shared projects", async () => {
    h.getSession.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await PATCH(req({ includeSharedProjects: true, password: 'admin-password' }), params())
    expect(res.status).toBe(403)
    expect(h.updateToken).not.toHaveBeenCalled()
  })

  test('a revoked token cannot be opened to shared projects', async () => {
    h.findToken.mockResolvedValue(stored({ revokedAt: new Date() }))
    const res = await PATCH(req({ includeSharedProjects: true, password: 'correct-horse' }), params())
    expect(res.status).toBe(409)
  })
})

describe('with RBAC_SHARING_ENABLED off the routes answer as before (DV-30)', () => {
  beforeEach(() => setFlagsForTests({ identity: true, permissions: true, sharing: false }))

  test('the mint neither reads nor stores the opt-in, and selects as before', async () => {
    const res = await POST(req(mintBody({ includeSharedProjects: true, projectAllowlist: ['P-1'] })), params())
    expect(res.status).toBe(201)
    const { data, select } = h.createToken.mock.calls[0][0]
    expect(data).not.toHaveProperty('includeSharedProjects')
    expect(data).not.toHaveProperty('projectAllowlist')
    expect(select).not.toHaveProperty('includeSharedProjects')
    expect(h.audit.mock.calls[0][0].after).not.toHaveProperty('includeSharedProjects')
  })

  test('the list selects as before', async () => {
    h.findManyTokens.mockResolvedValue([TOKEN_ROW])
    await GET(req(), params())
    expect(h.findManyTokens.mock.calls[0][0].select).not.toHaveProperty('includeSharedProjects')
  })

  test('an edit carrying only the opt-in has nothing to change', async () => {
    h.findToken.mockResolvedValue({ ...TOKEN_ROW, userId: 'owner' })
    const res = await PATCH(req({ includeSharedProjects: true, password: 'correct-horse' }), params())
    expect(res.status).toBe(400)
    expect(h.findToken.mock.calls[0][0].select).not.toHaveProperty('includeSharedProjects')
    expect(h.updateToken).not.toHaveBeenCalled()
  })
})

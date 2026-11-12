/**
 * The self-service permission of an account's own catalogs (step 3.9, §5.3): asked only when the
 * path names the person's own data (the signed-in account, or the account it acts as), through
 * requirePermission, so under act-as both people must hold it; another account's data the route's
 * account rule admitted is not asked; the internal and scanner keys pass without a session read.
 * Real guard, can() and registry; the session and Prisma are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
// The real helpers are read when called, not when the mock is built: session.ts and guards.ts
// import each other, and a factory that loads the real session module first hands guards.ts the
// real getAuthzIdentity.
type Session = typeof import('@/lib/session')
const realSession = () => vi.importActual<Session>('@/lib/session')
const keyIs = (r: Request, expected: string | undefined) => !!expected && r.headers.get('x-internal-key') === expected
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  isInternalRequest: (r: Request) => keyIs(r, process.env.INTERNAL_API_KEY),
  isScannerRequest: (r: Request) => keyIs(r, process.env.SCANNER_API_KEY),
  mayActAs: async (...a: Parameters<Session['mayActAs']>) => (await realSession()).mayActAs(...a),
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import { requireSelfPermission } from './selfService'
import { requirePermission } from './guards'
import { denying, principal } from './__testing__/routePermissionCases'
import { setFlagsForTests } from './flags'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import type { Principal } from './principal'

const KEY = 'internal-key-for-tests'
const SCANNER = 'scanner-key-for-tests'
const MEMBER = 'alice'

function req(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest(`http://localhost:3000/api/users/${MEMBER}/attack-skills`, { headers })
}

function signedIn(who: Principal, actingAs: Principal | null = null): void {
  h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs })
}

const admin = (over: Partial<Principal> = {}) => principal('adm', { role: 'admin', ...over })

beforeEach(() => {
  h.identity.mockReset()
  h.downstream.mockReset()
  vi.mocked(requirePermission).mockClear()
  setFlagsForTests({ identity: true, permissions: true })
  vi.stubEnv('INTERNAL_API_KEY', KEY)
  vi.stubEnv('SCANNER_API_KEY', SCANNER)
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe('requireSelfPermission', () => {
  test('the internal key passes without reading the session or asking a permission', async () => {
    expect(await requireSelfPermission(req({ 'x-internal-key': KEY }), MEMBER, 'self:attack_skills')).toBeNull()
    expect(h.identity).not.toHaveBeenCalled()
    expect(requirePermission).not.toHaveBeenCalled()
  })

  test('the scanner key passes the same way', async () => {
    expect(await requireSelfPermission(req({ 'x-internal-key': SCANNER }), MEMBER, 'self:api_keys')).toBeNull()
    expect(h.identity).not.toHaveBeenCalled()
  })

  test('a wrong key is no key: the session decides', async () => {
    h.identity.mockResolvedValue(null)
    const res = await requireSelfPermission(req({ 'x-internal-key': 'not-the-key' }), MEMBER, 'self:attack_skills')
    expect(res?.status).toBe(401)
  })

  test('no session: 401', async () => {
    h.identity.mockResolvedValue(null)
    const res = await requireSelfPermission(req(), MEMBER, 'self:attack_skills')
    expect(res?.status).toBe(401)
    expect(await res!.json()).toEqual({ error: 'Unauthorized' })
  })

  test('a session that cannot be read: a coded 500, never a pass', async () => {
    h.identity.mockRejectedValue(Object.assign(new Error('db down at target-1.example'), { code: 'P1001' }))
    const res = await requireSelfPermission(req(), MEMBER, 'self:attack_skills')
    expect(res?.status).toBe(500)
    expect(await res!.json()).toEqual({ error: 'Could not read the signed-in account', code: 'P1001' })
  })

  test('own account without the permission: 403 naming it', async () => {
    signedIn(denying(MEMBER, 'self:llm_providers'))
    const res = await requireSelfPermission(req(), MEMBER, 'self:llm_providers')
    expect(res?.status).toBe(403)
    expect(await res!.json()).toMatchObject({ code: 'forbidden', permission: 'self:llm_providers' })
    expect(vi.mocked(requirePermission).mock.calls[0].slice(1)).toEqual(['self:llm_providers'])
  })

  test('own account holding it (Default member): allowed', async () => {
    signedIn(principal(MEMBER))
    expect(await requireSelfPermission(req(), MEMBER, 'self:llm_providers')).toBeNull()
    expect(requirePermission).toHaveBeenCalledTimes(1)
  })

  test('fresh: both reads are asked fresh (minting a credential), and the answer is the same', async () => {
    signedIn(denying(MEMBER, 'self:mcp_tokens'))
    const res = await requireSelfPermission(req(), MEMBER, 'self:mcp_tokens', { fresh: true })
    expect(res?.status).toBe(403)
    expect(h.identity).toHaveBeenCalledWith({ fresh: true })
    expect(vi.mocked(requirePermission).mock.calls[0].slice(1)).toEqual(['self:mcp_tokens', { fresh: true }])
  })

  test('a No access member is refused its own catalogs', async () => {
    signedIn(principal(MEMBER, { permissionSets: ['builtin:no-access'] }))
    expect((await requireSelfPermission(req(), MEMBER, 'self:tradecraft'))?.status).toBe(403)
  })

  test("another account's data (the directory read the route admitted) is not asked the permission", async () => {
    signedIn(admin({ permissionOverrides: [{ permission: 'self:attack_skills', effect: 'deny', expiresAt: null, reason: null }] }))
    expect(await requireSelfPermission(req(), MEMBER, 'self:attack_skills')).toBeNull()
    expect(requirePermission).not.toHaveBeenCalled()
  })

  test('the account acted as: both people must hold it (the target lacks it)', async () => {
    signedIn(admin(), denying(MEMBER, 'self:mcp_servers'))
    const res = await requireSelfPermission(req(), MEMBER, 'self:mcp_servers')
    expect(res?.status).toBe(403)
    expect(await res!.json()).toMatchObject({ permission: 'self:mcp_servers' })
  })

  test('the account acted as: both people must hold it (the admin lacks it)', async () => {
    signedIn(admin({ permissionOverrides: [{ permission: 'self:mcp_servers', effect: 'deny', expiresAt: null, reason: null }] }), principal(MEMBER))
    expect((await requireSelfPermission(req(), MEMBER, 'self:mcp_servers'))?.status).toBe(403)
  })

  test('the account acted as, both holding it: allowed', async () => {
    signedIn(admin(), principal(MEMBER))
    expect(await requireSelfPermission(req(), MEMBER, 'self:mcp_servers')).toBeNull()
  })

  test("the real account's own data while acting as another: both people must hold it", async () => {
    signedIn(admin(), denying(MEMBER, 'self:chat_skills'))
    const res = await requireSelfPermission(req(), 'adm', 'self:chat_skills')
    expect(res?.status).toBe(403)
    expect(vi.mocked(requirePermission).mock.calls[0].slice(1)).toEqual(['self:chat_skills'])
  })

  test('with RBAC_PERMISSIONS_ENABLED off a member holds every catalog whatever an override says (Default member)', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    clearCapabilityCachesForTests()
    signedIn(denying(MEMBER, 'self:attack_skills'))
    expect(await requireSelfPermission(req(), MEMBER, 'self:attack_skills')).toBeNull()
  })

  test('a permission that is not over an account\'s own data throws: a route bug, not a refusal', async () => {
    await expect(requireSelfPermission(req(), MEMBER, 'users:read')).rejects.toThrow(/not a permission over an account's own data/)
    await expect(requireSelfPermission(req(), MEMBER, 'recon:read')).rejects.toThrow(/not a permission over an account's own data/)
    await expect(requireSelfPermission(req(), MEMBER, 'self:nonsense' as never)).rejects.toThrow()
  })

  test('a refusal is the NextResponse the route returns', async () => {
    signedIn(denying(MEMBER, 'self:api_keys'))
    expect(await requireSelfPermission(req(), MEMBER, 'self:api_keys')).toBeInstanceOf(NextResponse)
  })
})

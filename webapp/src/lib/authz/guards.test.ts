/**
 * The route guards over `can()` (step 3.5; master plan §9.8; PE-06, PE-23, DV-07):
 * `requirePermission(request, permission, {projectId?})` answers the context or the response the
 * route returns: 401 without a session (checked first), 404 for a project the caller cannot see
 * (the same body as a project that does not exist), 403 `{error, code: 'forbidden', permission}`
 * otherwise, a coded 500 when a read fails (never allowed). `withPermission(permission, handler)`
 * wraps a handler with it.
 *
 * The session helpers are a double (`getAuthzIdentity`); Prisma is a double; the policy, the
 * resolution and the registry are the real ones, with RBAC_PERMISSIONS_ENABLED on.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  getAuthzIdentity: vi.fn(),
  projects: new Map<string, { id: string; userId: string }>(),
  failProjects: false,
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => h.getAuthzIdentity(...a),
}))
const projectFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  if (h.failProjects) throw Object.assign(new Error('relation "projects" leaks target-1.example'), { code: 'P1001' })
  const row = h.projects.get(where.id)
  return row ? { ...row } : null
})
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (a: { where: { id: string } }) => projectFindUnique(a) },
    instanceSettings: { findUnique: async () => null },
    permissionSet: { findMany: async () => [] },
    user: { findUnique: async () => null },
  },
}))

import { requirePermission, withPermission, forbiddenResponse, type PermissionContext } from './guards'
import { setFlagsForTests } from './flags'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import type { Principal } from './principal'
import type { PermissionId } from './permissions'
import { readApiError } from '@/lib/apiError'

function principal(id: string, role = 'standard', over: Partial<Principal> = {}): Principal {
  return {
    id, email: `${id}@e2e.local`, name: id, role, status: 'active', sessionVersion: 0, mustChangePassword: false,
    adminProfileId: null, hasPassword: true, createdAt: new Date(0), lastLoginAt: null, legacyGrants: [],
    permissionSets: [], permissionOverrides: [], ...over,
  }
}
function signedIn(p: Principal, actingAs: Principal | null = null) {
  h.getAuthzIdentity.mockResolvedValue({ session: { userId: p.id, role: p.role }, principal: p, actingAs })
}
const request = () => new NextRequest('http://localhost:3000/api/x')
const body = async (res: unknown) => (res as NextResponse).json()

beforeEach(() => {
  h.getAuthzIdentity.mockReset()
  h.projects.clear()
  h.projects.set('P-alice', { id: 'P-alice', userId: 'alice' })
  h.projects.set('P-bob', { id: 'P-bob', userId: 'bob' })
  h.failProjects = false
  projectFindUnique.mockClear()
  setFlagsForTests({ identity: true, permissions: true })
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe('requirePermission', () => {
  test('no session: 401 before anything else, and no project is read', async () => {
    h.getAuthzIdentity.mockResolvedValue(null)
    const res = await requirePermission(request(), 'recon:read', { projectId: 'P-bob' })
    expect(res).toBeInstanceOf(NextResponse)
    expect((res as NextResponse).status).toBe(401)
    expect(await body(res)).toEqual({ error: 'Unauthorized' })
    expect(projectFindUnique).not.toHaveBeenCalled()
  })

  test('the account could not be read: a coded 500, never a pass, and the message stays in the log', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.getAuthzIdentity.mockRejectedValue(Object.assign(new Error('db down at target-1.example'), { code: 'P1001' }))
    const res = await requirePermission(request(), 'recon:read', { projectId: 'P-alice' })
    expect((res as NextResponse).status).toBe(500)
    const b = await body(res)
    expect(b).toEqual({ error: 'Could not read the signed-in account', code: 'P1001' })
    expect(JSON.stringify(b)).not.toContain('target-1.example')
    expect(err).toHaveBeenCalled()
  })

  test('the owner gets the context: the real account, whose data, the capabilities and the project access', async () => {
    const alice = principal('alice')
    signedIn(alice)
    const ctx = await requirePermission(request(), 'recon:scan', { projectId: 'P-alice' }) as PermissionContext
    expect(ctx).not.toBeInstanceOf(NextResponse)
    expect(ctx.session).toEqual({ userId: 'alice', role: 'standard' })
    expect(ctx.principal).toBe(alice)
    expect(ctx.actingAs).toBeNull()
    expect(ctx.effective).toEqual({ userId: 'alice' })
    expect(ctx.permission).toBe('recon:scan')
    expect(ctx.access).toEqual({ project: { id: 'P-alice', userId: 'alice' }, level: 'owner' })
    expect(ctx.capabilities.has('recon:scan')).toBe(true)
  })

  test("a project the caller cannot see: 404 with the body of a project that does not exist (anti-enumeration)", async () => {
    signedIn(principal('alice'))
    const other = await requirePermission(request(), 'recon:read', { projectId: 'P-bob' }) as NextResponse
    const missing = await requirePermission(request(), 'recon:read', { projectId: 'P-none' }) as NextResponse
    expect([other.status, missing.status]).toEqual([404, 404])
    expect(await other.json()).toEqual({ error: 'Not found' })
    expect(await missing.json()).toEqual({ error: 'Not found' })
  })

  test('403 body shape (DV-07): exactly {error, code: forbidden, permission}, read by readApiError', async () => {
    signedIn(principal('alice', 'standard', { permissionSets: ['builtin:read-only-analyst'] }))
    const res = await requirePermission(request(), 'recon:scan', { projectId: 'P-alice' }) as NextResponse
    expect(res.status).toBe(403)
    const b = await res.clone().json()
    expect(Object.keys(b).sort()).toEqual(['code', 'error', 'permission'])
    expect(b).toMatchObject({ code: 'forbidden', permission: 'recon:scan' })
    expect(typeof b.error).toBe('string')
    const apiErr = await readApiError(res, 'Could not start the scan')
    expect([apiErr.status, apiErr.code, apiErr.body?.permission]).toEqual([403, 'forbidden', 'recon:scan'])
  })

  test('an instance permission: 403 naming it, and no project is read', async () => {
    signedIn(principal('alice'))
    const res = await requirePermission(request(), 'users:read') as NextResponse
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:read' })
    expect(projectFindUnique).not.toHaveBeenCalled()
  })

  test('a project named but empty: 400, as requireProjectAccess answers today', async () => {
    signedIn(principal('alice'))
    const res = await requirePermission(request(), 'recon:read', { projectId: '' }) as NextResponse
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'projectId is required' })
  })

  test('a failed project read: a coded 500 with a fixed sentence, never a pass', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signedIn(principal('alice'))
    h.failProjects = true
    const res = await requirePermission(request(), 'recon:read', { projectId: 'P-alice' }) as NextResponse
    expect(res.status).toBe(500)
    const b = await res.json()
    expect(b).toEqual({ error: 'Could not check the permission', code: 'P1001' })
  })

  test('act-as: the context names the account acted as, whose project it is', async () => {
    const adminP = principal('admin-1', 'admin')
    const alice = principal('alice')
    signedIn(adminP, alice)
    const ctx = await requirePermission(request(), 'recon:read', { projectId: 'P-alice' }) as PermissionContext
    expect(ctx.session.userId).toBe('admin-1')
    expect(ctx.actingAs).toBe(alice)
    expect(ctx.effective).toEqual({ userId: 'alice' })
  })

  test('fresh is passed to the account read (critical paths, step 2.2)', async () => {
    signedIn(principal('alice'))
    await requirePermission(request(), 'recon:read', { projectId: 'P-alice', fresh: true })
    expect(h.getAuthzIdentity).toHaveBeenCalledWith({ fresh: true })
    await requirePermission(request(), 'recon:read', { projectId: 'P-alice' })
    expect(h.getAuthzIdentity).toHaveBeenLastCalledWith({ fresh: false })
  })

  test('an unknown permission throws (a programming error, not a refusal)', async () => {
    signedIn(principal('alice'))
    await expect(requirePermission(request(), 'recon:everything' as PermissionId)).rejects.toThrow(/Unknown permission/)
  })
})

describe('forbiddenResponse', () => {
  test('the shared 403 of every permission check', async () => {
    const res = forbiddenResponse('users:create')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:create' })
  })

  test('refuses an unknown permission', () => {
    expect(() => forbiddenResponse('users:invite' as PermissionId)).toThrow(/Unknown permission/)
  })
})

describe('withPermission', () => {
  type Ctx = { params: Promise<{ id: string }> }
  const ctxFor = (id: string): Ctx => ({ params: Promise.resolve({ id }) })

  test('runs the handler with the context only when allowed; the project comes from the route', async () => {
    signedIn(principal('alice'))
    const handler = vi.fn(async (_r: NextRequest, _c: Ctx, auth: PermissionContext) => NextResponse.json({ who: auth.effective.userId }))
    const route = withPermission('recon:read', handler, { projectId: async (_r, { params }) => (await params).id })
    const ok = await route(request(), ctxFor('P-alice'))
    expect(ok.status).toBe(200)
    expect(await ok.json()).toEqual({ who: 'alice' })
    expect(handler.mock.calls[0][2].access).toEqual({ project: { id: 'P-alice', userId: 'alice' }, level: 'owner' })

    const refused = await route(request(), ctxFor('P-bob'))
    expect(refused.status).toBe(404)
    expect(handler).toHaveBeenCalledTimes(1)
  })

  test('a refusal never runs the handler: 401, 403', async () => {
    const handler = vi.fn(async () => NextResponse.json({}))
    const route = withPermission('users:read', handler)
    h.getAuthzIdentity.mockResolvedValue(null)
    expect((await route(request(), {})).status).toBe(401)
    signedIn(principal('alice'))
    expect((await route(request(), {})).status).toBe(403)
    expect(handler).not.toHaveBeenCalled()
  })

  test('an unknown permission is refused when the route is defined, not at the first request', () => {
    expect(() => withPermission('recon:everything' as PermissionId, async () => NextResponse.json({}))).toThrow(/Unknown permission/)
  })
})

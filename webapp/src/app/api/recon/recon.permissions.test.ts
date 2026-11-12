/**
 * The recon routes ask for their permission (step 3.8; PE-19, PE-22): status, logs, outputs and
 * graph inputs `recon:read`; start, pause, resume and stop `recon:scan`; a partial run and its
 * stop `recon:partial`; an overwrite run `recon:overwrite` as well. Real guard, can() and registry;
 * the session, Prisma, the orchestrator and the graph are doubles (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  // The routes read the effective user again after the guard: the same account the identity names.
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.upstream(...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: (...a: unknown[]) => h.upstream('neo4j', ...a) }))

import { describeRoutePermissions, denying, principal, OWNER, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

const p = { projectId: OWNED_PROJECT }
const run = { projectId: OWNED_PROJECT, runId: 'run-1' }

const CASES: RouteCase[] = [
  { route: 'POST /api/recon/[projectId]/start', handler: async () => (await import('./[projectId]/start/route')).POST, permission: 'recon:scan', params: p, body: {} },
  { route: 'POST /api/recon/[projectId]/pause', handler: async () => (await import('./[projectId]/pause/route')).POST, permission: 'recon:scan', params: p },
  { route: 'POST /api/recon/[projectId]/resume', handler: async () => (await import('./[projectId]/resume/route')).POST, permission: 'recon:scan', params: p },
  { route: 'POST /api/recon/[projectId]/stop', handler: async () => (await import('./[projectId]/stop/route')).POST, permission: 'recon:scan', params: p },
  { route: 'GET /api/recon/[projectId]/status', handler: async () => (await import('./[projectId]/status/route')).GET, permission: 'recon:read', params: p },
  { route: 'GET /api/recon/[projectId]/logs', handler: async () => (await import('./[projectId]/logs/route')).GET, permission: 'recon:read', params: p },
  { route: 'GET /api/recon/[projectId]/download', handler: async () => (await import('./[projectId]/download/route')).GET, permission: 'recon:read', params: p },
  { route: 'HEAD /api/recon/[projectId]/download', handler: async () => (await import('./[projectId]/download/route')).HEAD, permission: 'recon:read', params: p },
  { route: 'GET /api/recon/[projectId]/graph-inputs/[toolId]', handler: async () => (await import('./[projectId]/graph-inputs/[toolId]/route')).GET, permission: 'recon:read', params: { ...p, toolId: 'Httpx' } },
  { route: 'POST /api/recon/[projectId]/partial', handler: async () => (await import('./[projectId]/partial/route')).POST, permission: 'recon:partial', params: p, body: { tool_id: 'Httpx' } },
  { route: 'GET /api/recon/[projectId]/partial/all', handler: async () => (await import('./[projectId]/partial/all/route')).GET, permission: 'recon:read', params: p },
  { route: 'GET /api/recon/[projectId]/partial/[runId]/status', handler: async () => (await import('./[projectId]/partial/[runId]/status/route')).GET, permission: 'recon:read', params: run },
  { route: 'GET /api/recon/[projectId]/partial/[runId]/logs', handler: async () => (await import('./[projectId]/partial/[runId]/logs/route')).GET, permission: 'recon:read', params: run },
  { route: 'POST /api/recon/[projectId]/partial/[runId]/stop', handler: async () => (await import('./[projectId]/partial/[runId]/stop/route')).POST, permission: 'recon:partial', params: run },
]

describeRoutePermissions('recon', CASES, h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

describe('recon start in overwrite mode also needs recon:overwrite', () => {
  const start = async (mode: string) => {
    const { POST } = await import('./[projectId]/start/route')
    return POST(new NextRequest(`http://localhost:3000/api/recon/${OWNED_PROJECT}/start`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mode }),
    }), { params: Promise.resolve(p) })
  }
  const signIn = (who: ReturnType<typeof principal>) =>
    h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs: null })

  test('refused without recon:overwrite: 403 naming it, no scan started', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    clearCapabilityCachesForTests()
    h.projects.set(OWNED_PROJECT, { id: OWNED_PROJECT, userId: OWNER })
    h.upstream.mockReset()
    h.downstream.mockReset()
    signIn(denying(OWNER, 'recon:overwrite'))
    const res = await start('overwrite')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'recon:overwrite' })
    expect(h.upstream).not.toHaveBeenCalled()
    expect(h.downstream).not.toHaveBeenCalled()
    setFlagsForTests(null)
  })

  test('a new-version run does not ask for it', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    clearCapabilityCachesForTests()
    h.projects.set(OWNED_PROJECT, { id: OWNED_PROJECT, userId: OWNER })
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn(denying(OWNER, 'recon:overwrite'))
    const res = await start('new')
    expect(res.status).not.toBe(403)
    setFlagsForTests(null)
    vi.restoreAllMocks()
  })
})

/**
 * Remediations and reports ask for their permission on the project (step 3.9; PE-19, PE-22):
 * reading a remediation `remediation:read`, creating, editing, deleting, batching one or saving its
 * file blocks `remediation:write`; listing and downloading reports `reports:read`, generating one
 * `reports:generate`, deleting one `reports:delete`. A remediation names its project on its row,
 * read after the session and before the check; the list of every report spans the visible
 * projects, so it asks `reports:read` as a capability. CypherFix's internal key is unchanged (not
 * a person). Real guard, can() and registry; the session, Prisma and the agent are doubles
 * (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { vi } from 'vitest'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  // The remediation routes read the session before the remediation's row: the same account.
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
vi.mock('@/lib/featureAgentCall', () => ({ callFeatureAgent: (...a: unknown[]) => h.upstream('agent', ...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: (...a: unknown[]) => h.upstream('neo4j', ...a) }))

import { describeRoutePermissions, OWNED_PROJECT, type RouteCase, type RouteCaseState } from '@/lib/authz/__testing__/routePermissionCases'
import type { PermissionId } from '@/lib/authz/permissions'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

type Mod = Record<string, unknown>
const handlerOf = (route: string, load: () => Promise<Mod>) => async () => (await load())[route.split(' ')[0]] as never
const savedRemediation = (h: RouteCaseState) => {
  h.models.remediation = { findUnique: async () => ({ projectId: OWNED_PROJECT }) }
}
const remediation = (method: string, permission: PermissionId, body?: unknown): RouteCase => ({
  route: `${method} /api/remediations/[id]`, permission, params: { id: 'rem-1' }, body, arrange: savedRemediation,
  handler: handlerOf(`${method} /api/remediations/[id]`, () => import('./[id]/route')),
})
const report = (method: string, path: string, load: () => Promise<Mod>, permission: PermissionId, extra: Record<string, string> = {}): RouteCase => ({
  route: `${method} ${path}`, permission, params: { id: OWNED_PROJECT, ...extra }, handler: handlerOf(method, load),
})

describeRoutePermissions('remediations and reports', [
  { route: 'GET /api/remediations', permission: 'remediation:read', params: {}, query: { projectId: OWNED_PROJECT }, handler: handlerOf('GET', () => import('./route')) },
  {
    route: 'POST /api/remediations', permission: 'remediation:write', params: {},
    body: { projectId: OWNED_PROJECT, title: 'Fix it', description: 'How' },
    handler: handlerOf('POST', () => import('./route')),
  },
  remediation('GET', 'remediation:read'),
  remediation('PUT', 'remediation:write', { status: 'resolved' }),
  remediation('DELETE', 'remediation:write'),
  {
    route: 'PUT /api/remediations/[id]/blocks', permission: 'remediation:write', params: { id: 'rem-1' },
    body: { fileChanges: [] }, arrange: savedRemediation,
    handler: handlerOf('PUT', () => import('./[id]/blocks/route')),
  },
  {
    route: 'POST /api/remediations/batch', permission: 'remediation:write', params: {},
    body: { projectId: OWNED_PROJECT, remediations: [{ title: 'Fix it' }] },
    handler: handlerOf('POST', () => import('./batch/route')),
  },
  report('GET', '/api/projects/[id]/reports', () => import('@/app/api/projects/[id]/reports/route'), 'reports:read'),
  report('POST', '/api/projects/[id]/reports', () => import('@/app/api/projects/[id]/reports/route'), 'reports:generate'),
  report('GET', '/api/projects/[id]/reports/[reportId]', () => import('@/app/api/projects/[id]/reports/[reportId]/route'), 'reports:read', { reportId: 'r-1' }),
  report('DELETE', '/api/projects/[id]/reports/[reportId]', () => import('@/app/api/projects/[id]/reports/[reportId]/route'), 'reports:delete', { reportId: 'r-1' }),
  { route: 'GET /api/reports', permission: 'reports:read', params: {}, projectId: null, handler: handlerOf('GET', () => import('@/app/api/reports/route')) },
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

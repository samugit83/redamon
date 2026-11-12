/**
 * The graph routes ask for their permission on the project (step 3.9; PE-19, PE-22): reading the
 * graph and the saved views `graph:read`; saving, editing and deleting a view `graph:views`;
 * running a view's Cypher `graph:cypher`; deleting a node and purging orphan attack chains
 * `graph:edit`. A saved view names its project on its row, read after the session and before the
 * check. Real guard, can() and registry; the session, Prisma and the graph are doubles
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
  // The saved-view routes read the session before the view's row: the same account.
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
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: (...a: unknown[]) => h.upstream('neo4j', ...a) }))

import { describeRoutePermissions, OWNED_PROJECT, type RouteCase, type RouteCaseState } from '@/lib/authz/__testing__/routePermissionCases'
import type { PermissionId } from '@/lib/authz/permissions'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

type Mod = Record<string, unknown>
const handlerOf = (route: string, load: () => Promise<Mod>) => async () => (await load())[route.split(' ')[0]] as never
const savedView = (h: RouteCaseState) => {
  h.models.graphView = { findUnique: async () => ({ projectId: OWNED_PROJECT }) }
}
const viewCase = (method: string, permission: PermissionId, body?: unknown): RouteCase => ({
  route: `${method} /api/graph-views/[id]`, permission, params: { id: 'view-1' }, body, arrange: savedView,
  handler: handlerOf(`${method} /api/graph-views/[id]`, () => import('@/app/api/graph-views/[id]/route')),
})

describeRoutePermissions('graph and saved views', [
  { route: 'GET /api/graph', permission: 'graph:read', params: {}, query: { projectId: OWNED_PROJECT }, handler: handlerOf('GET', () => import('./route')) },
  { route: 'DELETE /api/graph', permission: 'graph:edit', params: {}, query: { projectId: OWNED_PROJECT, nodeId: 'n-1' }, handler: handlerOf('DELETE', () => import('./route')) },
  { route: 'GET /api/graph-views', permission: 'graph:read', params: {}, query: { projectId: OWNED_PROJECT }, handler: handlerOf('GET', () => import('@/app/api/graph-views/route')) },
  {
    route: 'POST /api/graph-views', permission: 'graph:views', params: {},
    body: { projectId: OWNED_PROJECT, name: 'mine', cypherQuery: 'MATCH (n) RETURN n' },
    handler: handlerOf('POST', () => import('@/app/api/graph-views/route')),
  },
  viewCase('PUT', 'graph:views', { name: 'renamed' }),
  viewCase('DELETE', 'graph:views'),
  {
    route: 'POST /api/graph-views/execute', permission: 'graph:cypher', params: {},
    body: { projectId: OWNED_PROJECT, cypherQuery: 'MATCH (n) RETURN n' },
    handler: handlerOf('POST', () => import('@/app/api/graph-views/execute/route')),
  },
  {
    route: 'POST /api/projects/[id]/purge-orphan-chains', permission: 'graph:edit', params: { id: OWNED_PROJECT },
    handler: handlerOf('POST', () => import('@/app/api/projects/[id]/purge-orphan-chains/route')),
  },
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

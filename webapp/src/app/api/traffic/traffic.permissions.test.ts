/**
 * Captured traffic asks for its permission (step 3.9; PE-19, PE-22): browsing the list, a
 * transaction and the facets `traffic:read`, exporting `traffic:export`, deleting `traffic:delete`,
 * on the project in the path. The scanner's ingest and the internal maintenance route are not a
 * person's and are not here. Real guard, can() and registry; the session and Prisma are doubles
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
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import { OWNED_PROJECT, describeRoutePermissions, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

type Mod = Record<string, unknown>
const p = { projectId: OWNED_PROJECT }
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string>): RouteCase => ({
  route, permission, params, handler: async () => (await load())[route.split(' ')[0]] as never,
})

describeRoutePermissions('captured traffic', [
  at('GET /api/traffic/[projectId]', () => import('./[projectId]/route'), 'traffic:read', p),
  at('GET /api/traffic/[projectId]/[id]', () => import('./[projectId]/[id]/route'), 'traffic:read', { ...p, id: 't1' }),
  at('GET /api/traffic/[projectId]/facets', () => import('./[projectId]/facets/route'), 'traffic:read', p),
  at('GET /api/traffic/[projectId]/export', () => import('./[projectId]/export/route'), 'traffic:export', p),
  at('DELETE /api/traffic/[projectId]', () => import('./[projectId]/route'), 'traffic:delete', p),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

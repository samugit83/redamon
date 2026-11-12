/**
 * The plugin screens and actions ask their permission (step 3.9; §5.12, PE-19, PE-22, PE-25):
 * reading the Plugins page, a plugin's details, icon, contributions, model features, status, a
 * job, the override summaries and versions, running an action and cancelling a job
 * `plugins:use`; approving, rejecting, deleting and resetting plugin-proposed skill text
 * `plugins:approve_overrides`. Both are capabilities with no project: the change set's scope
 * owner is still checked strictly after the permission (changeSetAccess.ts), and installing,
 * updating or removing a plugin stays `platform:plugins` (lifecycleRoutes.ts). Real guard, can()
 * and registry; the session and Prisma are doubles (routePermissionCases.ts).
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
  // The routes read the account again after the guard: the same one the identity names.
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
  getSession: async () => {
    const id = await h.identity()
    return id ? { userId: id.principal.id, role: id.principal.role } : null
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import { describeRoutePermissions, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string> = {}, body?: unknown): RouteCase => ({
  route, permission, params, body, projectId: null, handler: async () => (await load())[route.split(' ')[0]] as never,
})

const plugin = { pluginId: 'echo' }
const changeSet = () => import('./overrides/change-sets/[id]/route')

describeRoutePermissions('plugin screens and actions', [
  at('GET /api/plugins', () => import('./route'), 'plugins:use'),
  at('GET /api/plugins/[pluginId]', () => import('./[pluginId]/route'), 'plugins:use', plugin),
  at('GET /api/plugins/[pluginId]/icon', () => import('./[pluginId]/icon/route'), 'plugins:use', plugin),
  at('GET /api/plugins/contributions', () => import('./contributions/route'), 'plugins:use'),
  at('GET /api/plugins/llm-features', () => import('./llm-features/route'), 'plugins:use'),
  at('GET /api/plugins/status', () => import('./status/route'), 'plugins:use'),
  at('GET /api/plugins/jobs/[jobId]', () => import('./jobs/[jobId]/route'), 'plugins:use', { jobId: 'j1' }),
  at('POST /api/plugins/jobs/[jobId]/cancel', () => import('./jobs/[jobId]/cancel/route'), 'plugins:use', { jobId: 'j1' }, {}),
  at('POST /api/plugins/[pluginId]/actions/[actionId]', () => import('./[pluginId]/actions/[actionId]/route'), 'plugins:use', { ...plugin, actionId: 'run' }, {}),
  at('GET /api/plugins/[pluginId]/session-skills', () => import('./[pluginId]/session-skills/route'), 'plugins:use', plugin),
  at('GET /api/plugins/overrides/summary', () => import('./overrides/summary/route'), 'plugins:use'),
  at('GET /api/plugins/overrides/versions', () => import('./overrides/versions/route'), 'plugins:use'),
  at('GET /api/plugins/overrides/change-sets/[id]', changeSet, 'plugins:use', { id: 'cs1' }),
  at('DELETE /api/plugins/overrides/change-sets/[id]', changeSet, 'plugins:approve_overrides', { id: 'cs1' }, {}),
  at('POST /api/plugins/overrides/change-sets/[id]/approve', () => import('./overrides/change-sets/[id]/approve/route'), 'plugins:approve_overrides', { id: 'cs1' }, { scopeOwnerId: 'alice' }),
  at('POST /api/plugins/overrides/change-sets/[id]/reject', () => import('./overrides/change-sets/[id]/reject/route'), 'plugins:approve_overrides', { id: 'cs1' }, { scopeOwnerId: 'alice' }),
  at('POST /api/plugins/overrides/reset', () => import('./overrides/reset/route'), 'plugins:approve_overrides', {}, { scopeOwnerId: 'alice' }),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

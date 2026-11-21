/**
 * The shell-session routes and the sandbox status ask for agent:sessions before anything else
 * (step 3.9; group 1, E3 and WI-S16-3): listing, typing into a session, killing a session or a
 * background job (each naming its sandbox instance, `?sandbox=`), and reading when one's own Kali
 * sandbox stops. A collaborator or a member without the permission is refused with the 403 naming
 * it, before the agent or the orchestrator is asked. Real guard, can() and registry; the session and
 * Prisma are doubles (routePermissionCases.ts), and every outside call goes to the stubbed fetch.
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

type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, params: Record<string, string>, extra: Partial<RouteCase> = {}): RouteCase => ({
  route, permission: 'agent:sessions', params, projectId: null, handler: async () => (await load())[route.split(' ')[0]] as never, ...extra,
})
const instance = { query: { sandbox: 'aaaaa1' } }

describeRoutePermissions('shell sessions and the sandbox status', [
  at('GET /api/agent/sessions', () => import('./route'), {}),
  at('POST /api/agent/sessions/[id]/interact', () => import('./[id]/interact/route'), { id: '1' }, { ...instance, body: { command: 'id' } }),
  at('POST /api/agent/sessions/[id]/kill', () => import('./[id]/kill/route'), { id: '1' }, instance),
  at('POST /api/agent/jobs/[id]/kill', () => import('../jobs/[id]/kill/route'), { id: '0' }, instance),
  at('GET /api/agent/sandbox/status', () => import('../sandbox/status/route'), {}),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

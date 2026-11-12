/**
 * The Insights and Red Zone routes ask for `graph:read` on their project (step 3.9; PE-19, PE-22):
 * every dashboard reads the project's graph, and marking a tab seen is a read too. Real guard,
 * can() and registry; the session, Prisma, the graph and the orchestrator are doubles
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
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: (...a: unknown[]) => h.upstream('neo4j', ...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.upstream('orchestrator', ...a) }))

import { describeRoutePermissions, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

type Mod = Record<string, unknown>
const q = { projectId: OWNED_PROJECT }
const read = (route: string, load: () => Promise<Mod>): RouteCase => ({
  route, permission: 'graph:read', params: {}, query: q, handler: async () => (await load()).GET as never,
})

describeRoutePermissions('Insights and Red Zone', [
  read('GET /api/analytics/activity', () => import('./activity/route')),
  read('GET /api/analytics/attack-chains', () => import('./attack-chains/route')),
  read('GET /api/analytics/attack-surface', () => import('./attack-surface/route')),
  read('GET /api/analytics/graph-overview', () => import('./graph-overview/route')),
  read('GET /api/analytics/pipeline-status', () => import('./pipeline-status/route')),
  read('GET /api/analytics/vulnerabilities', () => import('./vulnerabilities/route')),
  read('GET /api/analytics/redzone/aiRisk', () => import('./redzone/aiRisk/route')),
  read('GET /api/analytics/redzone/aiSurface', () => import('./redzone/aiSurface/route')),
  read('GET /api/analytics/redzone/blastRadius', () => import('./redzone/blastRadius/route')),
  read('GET /api/analytics/redzone/dnsDrift', () => import('./redzone/dnsDrift/route')),
  read('GET /api/analytics/redzone/dnsEmail', () => import('./redzone/dnsEmail/route')),
  read('GET /api/analytics/redzone/graphql', () => import('./redzone/graphql/route')),
  read('GET /api/analytics/redzone/killChain', () => import('./redzone/killChain/route')),
  read('GET /api/analytics/redzone/netInitAccess', () => import('./redzone/netInitAccess/route')),
  read('GET /api/analytics/redzone/paramMatrix', () => import('./redzone/paramMatrix/route')),
  read('GET /api/analytics/redzone/routeExposure', () => import('./redzone/routeExposure/route')),
  read('GET /api/analytics/redzone/secrets', () => import('./redzone/secrets/route')),
  read('GET /api/analytics/redzone/sharedInfra', () => import('./redzone/sharedInfra/route')),
  read('GET /api/analytics/redzone/supplyChain', () => import('./redzone/supplyChain/route')),
  read('GET /api/analytics/redzone/supplyChainSca', () => import('./redzone/supplyChainSca/route')),
  read('GET /api/analytics/redzone/takeover', () => import('./redzone/takeover/route')),
  read('GET /api/analytics/redzone/threatIntel', () => import('./redzone/threatIntel/route')),
  read('GET /api/analytics/redzone/webCachePoison', () => import('./redzone/webCachePoison/route')),
  read('GET /api/analytics/redzone/webInitAccess', () => import('./redzone/webInitAccess/route')),
  {
    route: 'POST /api/analytics/unseen', permission: 'graph:read', params: {},
    body: { projectId: OWNED_PROJECT, marks: {} },
    handler: async () => (await import('./unseen/route')).POST as never,
  },
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

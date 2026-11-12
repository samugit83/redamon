/**
 * Each WebSocket ticket asks the permission of the socket it opens, on the ticket's project, read
 * fresh (step 3.9; PE-19, PE-22): the chat `agent:chat`, CypherFix triage `triage:run`, CypherFix
 * CodeFix `codefix:run`. The terminal's platform tool is sharedTools.permissions.test.ts's and the
 * route test's. Real guard, can() and registry; the session and Prisma are doubles
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

import { describeRoutePermissions, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

const socket = (name: string | undefined, permission: PermissionId): RouteCase => ({
  route: 'POST /api/agent/ws-ticket',
  permission,
  params: {},
  body: { projectId: OWNED_PROJECT, sessionId: 'chat-1', ...(name ? { socket: name } : {}) },
  fresh: true,
  handler: async () => (await import('./route')).POST as never,
})

describeRoutePermissions('the WebSocket ticket, per socket', [
  socket(undefined, 'agent:chat'),
  socket('agent', 'agent:chat'),
  socket('cypherfix-triage', 'triage:run'),
  socket('cypherfix-codefix', 'codefix:run'),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

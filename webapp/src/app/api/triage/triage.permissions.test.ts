/**
 * The Priority Board and mute-rule routes ask for their permission on the project (step 3.9;
 * PE-19, PE-22): reading findings, evidence, the muted list, the run preflight and the mute rules
 * `triage:read`; a person's verdict `triage:verdict`; muting and unmuting (one, by graph id, a
 * Multi mute batch and its suggestion) `triage:mute`; editing, previewing, applying, disarming
 * the rules and clearing exemptions `node_filters:manage`. Only the guard changed: the graph calls
 * still act for the project's owner (triageCaller). Real guard, can() and registry; the session,
 * Prisma, the agent and the graph are doubles (routePermissionCases.ts).
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
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => h.upstream('agent', ...a),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: (...a: unknown[]) => h.upstream('neo4j', ...a) }))

import { describeRoutePermissions, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import type { PermissionId } from '@/lib/authz/permissions'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

type Mod = Record<string, unknown>
const handlerOf = (route: string, load: () => Promise<Mod>) => async () => (await load())[route.split(' ')[0]] as never
const byQuery = (route: string, load: () => Promise<Mod>, permission: PermissionId, extra: Record<string, string> = {}): RouteCase => ({
  route, permission, params: {}, query: { projectId: OWNED_PROJECT, ...extra }, handler: handlerOf(route, load),
})
const byBody = (route: string, load: () => Promise<Mod>, permission: PermissionId, body: Record<string, unknown>): RouteCase => ({
  route, permission, params: {}, body: { projectId: OWNED_PROJECT, ...body }, handler: handlerOf(route, load),
})
const onProject = (route: string, load: () => Promise<Mod>, permission: PermissionId, body?: unknown, extra: Record<string, string> = {}): RouteCase => ({
  route, permission, params: { id: OWNED_PROJECT, ...extra }, body, handler: handlerOf(route, load),
})

const FINDING = { findingId: 'f-1', label: 'Vulnerability' }

describeRoutePermissions('Priority Board and mute rules', [
  byQuery('GET /api/triage/findings', () => import('./findings/route'), 'triage:read'),
  byQuery('GET /api/triage/finding', () => import('./finding/route'), 'triage:read', FINDING),
  byQuery('GET /api/triage/evidence', () => import('./evidence/route'), 'triage:read', FINDING),
  byQuery('GET /api/triage/muted', () => import('./muted/route'), 'triage:read'),
  byQuery('GET /api/triage/preflight', () => import('./preflight/route'), 'triage:read'),
  byBody('POST /api/triage/verdict', () => import('./verdict/route'), 'triage:verdict', { nodeId: 'n-1', status: 'confirmed' }),
  byBody('POST /api/triage/mute', () => import('./mute/route'), 'triage:mute', { nodeId: 'n-1' }),
  byBody('POST /api/triage/unmute', () => import('./unmute/route'), 'triage:mute', { nodeId: 'n-1' }),
  byBody('POST /api/triage/mute-by-graph-id', () => import('./mute-by-graph-id/route'), 'triage:mute', { graphId: '4:abc:1' }),
  byBody('POST /api/triage/multi-mute/apply', () => import('./multi-mute/apply/route'), 'triage:mute', { batchId: 'multi-1', keys: ['k'] }),
  byBody('POST /api/triage/multi-mute/suggest', () => import('./multi-mute/suggest/route'), 'triage:mute', { nodeId: 'n-1' }),
  onProject('GET /api/projects/[id]/node-filters', () => import('@/app/api/projects/[id]/node-filters/route'), 'triage:read'),
  onProject('PUT /api/projects/[id]/node-filters', () => import('@/app/api/projects/[id]/node-filters/route'), 'node_filters:manage', { rules: [] }),
  onProject('GET /api/projects/[id]/node-filters/apply', () => import('@/app/api/projects/[id]/node-filters/apply/route'), 'triage:read'),
  onProject('POST /api/projects/[id]/node-filters/apply', () => import('@/app/api/projects/[id]/node-filters/apply/route'), 'node_filters:manage', {}),
  onProject('POST /api/projects/[id]/node-filters/disarm', () => import('@/app/api/projects/[id]/node-filters/disarm/route'), 'node_filters:manage', {}),
  onProject('DELETE /api/projects/[id]/node-filters/exemptions', () => import('@/app/api/projects/[id]/node-filters/exemptions/route'), 'node_filters:manage'),
  onProject('POST /api/projects/[id]/node-filters/preview', () => import('@/app/api/projects/[id]/node-filters/preview/route'), 'node_filters:manage', { rules: [] }),
  onProject('GET /api/projects/[id]/node-filters/runs/[runId]', () => import('@/app/api/projects/[id]/node-filters/runs/[runId]/route'), 'triage:read', undefined, { runId: 'run-1' }),
  onProject('GET /api/projects/[id]/node-filters/status', () => import('@/app/api/projects/[id]/node-filters/status/route'), 'triage:read'),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

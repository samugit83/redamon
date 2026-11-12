/**
 * The scan routes ask for their permission (step 3.8; PE-19, PE-22, PE-29 scan part): each
 * scanner's status, logs, runs, findings and downloads `recon:read`; starting, pausing, resuming and
 * stopping it the scanner's own permission (GVM `scan:gvm`; GitHub hunt and TruffleHog sources and
 * profiles `scan:secrets`; supply chain, its uploads and the org batch `scan:supply_chain`; AI attack
 * surface `scan:ai_attack`); wordlists and JS recon files `scan:uploads`; scan versions
 * `scan:versions`, deleting one `scan:versions_delete`, their list, graphs and the delta
 * `recon:read`. Real guard, can() and registry; the session, Prisma, the orchestrator and the graph
 * are doubles (routePermissionCases.ts).
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
vi.mock('@/app/api/graph/neo4j', async (orig) => ({
  ...(await orig<typeof import('@/app/api/graph/neo4j')>()),
  getDriver: () => { h.upstream('neo4j'); throw new Error('no graph in this test') },
  getGraphSession: () => { h.upstream('neo4j'); throw new Error('no graph in this test') },
}))

import { describeRoutePermissions, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

const P = OWNED_PROJECT
type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string>, body?: unknown): RouteCase => ({
  route, permission, params, body, handler: async () => (await load())[route.split(' ')[0]] as never,
})

/** The run-control routes every scanner has, under /api/<scanner>/[projectId]. */
function scanner(name: string, run: PermissionId, load: (sub: string) => Promise<Mod>): RouteCase[] {
  const p = { projectId: P }
  return [
    at(`POST /api/${name}/[projectId]/start`, () => load('start'), run, p, {}),
    at(`POST /api/${name}/[projectId]/pause`, () => load('pause'), run, p),
    at(`POST /api/${name}/[projectId]/resume`, () => load('resume'), run, p),
    at(`POST /api/${name}/[projectId]/stop`, () => load('stop'), run, p),
    at(`GET /api/${name}/[projectId]/status`, () => load('status'), 'recon:read', p),
    at(`GET /api/${name}/[projectId]/logs`, () => load('logs'), 'recon:read', p),
    at(`GET /api/${name}/[projectId]/download`, () => load('download'), 'recon:read', p),
    at(`HEAD /api/${name}/[projectId]/download`, () => load('download'), 'recon:read', p),
  ]
}

const p = { projectId: P }
const run = { projectId: P, runId: 'run-1' }
const src = { projectId: P, source: 'docker' }
const id = { id: P }
const version = { id: P, versionId: 'V1' }

const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() }
const opts = { setFlags: setFlagsForTests, clearCaches }

describeRoutePermissions('GVM', scanner('gvm', 'scan:gvm', s => import(`./gvm/[projectId]/${s}/route`)), h, opts)
describeRoutePermissions('GitHub secret hunt', scanner('github-hunt', 'scan:secrets', s => import(`./github-hunt/[projectId]/${s}/route`)), h, opts)
describeRoutePermissions('supply chain', [
  ...scanner('supply-chain', 'scan:supply_chain', s => import(`./supply-chain/[projectId]/${s}/route`)),
  at('GET /api/supply-chain/[projectId]/upload', () => import('./supply-chain/[projectId]/upload/route'), 'recon:read', p),
  at('POST /api/supply-chain/[projectId]/upload', () => import('./supply-chain/[projectId]/upload/route'), 'scan:supply_chain', p),
  at('DELETE /api/supply-chain/[projectId]/upload', () => import('./supply-chain/[projectId]/upload/route'), 'scan:supply_chain', p),
  at('POST /api/projects/[id]/supply-chain-batch', () => import('./projects/[id]/supply-chain-batch/route'), 'scan:supply_chain', id, {}),
], h, opts)
describeRoutePermissions('TruffleHog', [
  at('POST /api/trufflehog/[projectId]/start', () => import('./trufflehog/[projectId]/start/route'), 'scan:secrets', p, { source: 'docker' }),
  at('GET /api/trufflehog/[projectId]/all', () => import('./trufflehog/[projectId]/all/route'), 'recon:read', p),
  at('GET /api/trufflehog/[projectId]/download', () => import('./trufflehog/[projectId]/download/route'), 'recon:read', p),
  at('HEAD /api/trufflehog/[projectId]/download', () => import('./trufflehog/[projectId]/download/route'), 'recon:read', p),
  at('GET /api/trufflehog/[projectId]/[source]/status', () => import('./trufflehog/[projectId]/[source]/status/route'), 'recon:read', src),
  at('GET /api/trufflehog/[projectId]/[source]/logs', () => import('./trufflehog/[projectId]/[source]/logs/route'), 'recon:read', src),
  at('POST /api/trufflehog/[projectId]/[source]/stop', () => import('./trufflehog/[projectId]/[source]/stop/route'), 'scan:secrets', src),
  at('GET /api/trufflehog/[projectId]/profiles', () => import('./trufflehog/[projectId]/profiles/route'), 'recon:read', p),
  at('POST /api/trufflehog/[projectId]/profiles', () => import('./trufflehog/[projectId]/profiles/route'), 'scan:secrets', p, {}),
  at('PATCH /api/trufflehog/[projectId]/profiles/[profileId]', () => import('./trufflehog/[projectId]/profiles/[profileId]/route'), 'scan:secrets', { ...p, profileId: 'T1' }, {}),
  at('DELETE /api/trufflehog/[projectId]/profiles/[profileId]', () => import('./trufflehog/[projectId]/profiles/[profileId]/route'), 'scan:secrets', { ...p, profileId: 'T1' }),
], h, opts)
describeRoutePermissions('AI attack surface', [
  at('POST /api/ai-attack-surface/[projectId]/start', () => import('./ai-attack-surface/[projectId]/start/route'), 'scan:ai_attack', p, {}),
  at('POST /api/ai-attack-surface/[projectId]/[runId]/stop', () => import('./ai-attack-surface/[projectId]/[runId]/stop/route'), 'scan:ai_attack', run),
  at('GET /api/ai-attack-surface/[projectId]/[runId]/status', () => import('./ai-attack-surface/[projectId]/[runId]/status/route'), 'recon:read', run),
  at('GET /api/ai-attack-surface/[projectId]/[runId]/logs', () => import('./ai-attack-surface/[projectId]/[runId]/logs/route'), 'recon:read', run),
  at('GET /api/ai-attack-surface/[projectId]/all', () => import('./ai-attack-surface/[projectId]/all/route'), 'recon:read', p),
  at('GET /api/ai-attack-surface/[projectId]/findings', () => import('./ai-attack-surface/[projectId]/findings/route'), 'recon:read', p),
  at('GET /api/ai-attack-surface/[projectId]/judge-model', () => import('./ai-attack-surface/[projectId]/judge-model/route'), 'recon:read', p),
  at('GET /api/ai-attack-surface/[projectId]/targets', () => import('./ai-attack-surface/[projectId]/targets/route'), 'recon:read', p),
  at('GET /api/ai-attack-surface/[projectId]/transcript', () => import('./ai-attack-surface/[projectId]/transcript/route'), 'recon:read', p),
], h, opts)
describeRoutePermissions('uploads: wordlists and JS recon files', [
  at('POST /api/projects/[id]/wordlists', () => import('./projects/[id]/wordlists/route'), 'scan:uploads', id),
  at('DELETE /api/projects/[id]/wordlists', () => import('./projects/[id]/wordlists/route'), 'scan:uploads', id),
  at('GET /api/projects/[id]/wordlists', () => import('./projects/[id]/wordlists/route'), 'recon:read', id),
  at('POST /api/js-recon/[projectId]/upload', () => import('./js-recon/[projectId]/upload/route'), 'scan:uploads', p),
  at('DELETE /api/js-recon/[projectId]/upload', () => import('./js-recon/[projectId]/upload/route'), 'scan:uploads', p),
  at('GET /api/js-recon/[projectId]/upload', () => import('./js-recon/[projectId]/upload/route'), 'recon:read', p),
  at('POST /api/js-recon/[projectId]/custom-files', () => import('./js-recon/[projectId]/custom-files/route'), 'scan:uploads', p),
  at('DELETE /api/js-recon/[projectId]/custom-files', () => import('./js-recon/[projectId]/custom-files/route'), 'scan:uploads', p),
  at('GET /api/js-recon/[projectId]/custom-files', () => import('./js-recon/[projectId]/custom-files/route'), 'recon:read', p),
  at('GET /api/js-recon/[projectId]/download', () => import('./js-recon/[projectId]/download/route'), 'recon:read', p),
  at('HEAD /api/js-recon/[projectId]/download', () => import('./js-recon/[projectId]/download/route'), 'recon:read', p),
], h, opts)
describeRoutePermissions('scan versions and the delta', [
  at('POST /api/projects/[id]/versions', () => import('./projects/[id]/versions/route'), 'scan:versions', id, {}),
  at('GET /api/projects/[id]/versions', () => import('./projects/[id]/versions/route'), 'recon:read', id),
  at('PATCH /api/projects/[id]/versions/[versionId]', () => import('./projects/[id]/versions/[versionId]/route'), 'scan:versions', version, {}),
  at('DELETE /api/projects/[id]/versions/[versionId]', () => import('./projects/[id]/versions/[versionId]/route'), 'scan:versions_delete', version),
  at('POST /api/projects/[id]/versions/[versionId]/activate', () => import('./projects/[id]/versions/[versionId]/activate/route'), 'scan:versions', version),
  at('GET /api/projects/[id]/versions/[versionId]/graph', () => import('./projects/[id]/versions/[versionId]/graph/route'), 'recon:read', version),
  at('GET /api/projects/[id]/delta', () => import('./projects/[id]/delta/route'), 'recon:read', id),
], h, opts)

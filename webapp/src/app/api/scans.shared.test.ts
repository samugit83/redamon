/**
 * The recon and scan routes on a shared project (step 4.7; SH-07, PE-20): a read collaborator reads
 * each scanner's status, logs, runs, findings, lists, the scan versions and the delta (`recon:read`,
 * R); the six result downloads and the AI attack-surface transcript are raw outputs (the GitHub hunt
 * and TruffleHog results hold the secrets they found, the transcript the probe prompts and the
 * target's answers), so they also need Raw data & files (`requireLevel(auth, 'R*')`); every start,
 * pause, resume, stop, upload and version change is refused at read. Real guard, can(),
 * projectAccess() and registry; the session, Prisma, the orchestrator and the graph are doubles
 * (sharedRouteCases.ts).
 *
 * @vitest-environment node
 */
import { vi } from 'vitest'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  shares: new Map<string, { access: string; rawData: boolean; expiresAt: Date | null; user: { status: string } }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedRouteCases')).sharingPrisma(h) }))
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

import { describeSharedAccess, type SharedReach, type SharedRouteCase } from '@/lib/authz/__testing__/sharedRouteCases'
import { OWNED_PROJECT } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import type { PermissionId } from '@/lib/authz/permissions'

const P = OWNED_PROJECT
type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, reach: SharedReach, params: Record<string, string>, body?: unknown): SharedRouteCase => ({
  route, permission, reach, params, body, handler: async () => (await load())[route.split(' ')[0]] as never,
})

type Loaders = Record<'start' | 'pause' | 'resume' | 'stop' | 'status' | 'logs' | 'download', () => Promise<Mod>>

function scanner(name: string, run: PermissionId, load: Loaders): SharedRouteCase[] {
  const p = { projectId: P }
  return [
    at(`GET /api/${name}/[projectId]/status`, load.status, 'recon:read', 'read', p),
    at(`GET /api/${name}/[projectId]/logs`, load.logs, 'recon:read', 'read', p),
    at(`GET /api/${name}/[projectId]/download`, load.download, 'recon:read', 'raw', p),
    at(`HEAD /api/${name}/[projectId]/download`, load.download, 'recon:read', 'raw', p),
    at(`POST /api/${name}/[projectId]/start`, load.start, run, 'write', p, {}),
    at(`POST /api/${name}/[projectId]/pause`, load.pause, run, 'write', p),
    at(`POST /api/${name}/[projectId]/resume`, load.resume, run, 'write', p),
    at(`POST /api/${name}/[projectId]/stop`, load.stop, run, 'write', p),
  ]
}

const p = { projectId: P }
const run = { projectId: P, runId: 'run-1' }
const src = { projectId: P, source: 'docker' }
const id = { id: P }
const version = { id: P, versionId: 'V1' }

const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests(); clearPrincipalCacheForTests() }
const opts = { setFlags: setFlagsForTests, clearCaches }

describeSharedAccess('recon', [
  ...scanner('recon', 'recon:scan', {
    start: () => import('./recon/[projectId]/start/route'),
    pause: () => import('./recon/[projectId]/pause/route'),
    resume: () => import('./recon/[projectId]/resume/route'),
    stop: () => import('./recon/[projectId]/stop/route'),
    status: () => import('./recon/[projectId]/status/route'),
    logs: () => import('./recon/[projectId]/logs/route'),
    download: () => import('./recon/[projectId]/download/route'),
  }),
  at('GET /api/recon/[projectId]/graph-inputs/[toolId]', () => import('./recon/[projectId]/graph-inputs/[toolId]/route'), 'recon:read', 'read', { ...p, toolId: 'Httpx' }),
  at('GET /api/recon/[projectId]/partial/all', () => import('./recon/[projectId]/partial/all/route'), 'recon:read', 'read', p),
  at('GET /api/recon/[projectId]/partial/[runId]/status', () => import('./recon/[projectId]/partial/[runId]/status/route'), 'recon:read', 'read', run),
  at('GET /api/recon/[projectId]/partial/[runId]/logs', () => import('./recon/[projectId]/partial/[runId]/logs/route'), 'recon:read', 'read', run),
  at('POST /api/recon/[projectId]/partial', () => import('./recon/[projectId]/partial/route'), 'recon:partial', 'write', p, { tool_id: 'Httpx' }),
  at('POST /api/recon/[projectId]/partial/[runId]/stop', () => import('./recon/[projectId]/partial/[runId]/stop/route'), 'recon:partial', 'write', run),
], h, opts)
describeSharedAccess('GVM', scanner('gvm', 'scan:gvm', {
  start: () => import('./gvm/[projectId]/start/route'),
  pause: () => import('./gvm/[projectId]/pause/route'),
  resume: () => import('./gvm/[projectId]/resume/route'),
  stop: () => import('./gvm/[projectId]/stop/route'),
  status: () => import('./gvm/[projectId]/status/route'),
  logs: () => import('./gvm/[projectId]/logs/route'),
  download: () => import('./gvm/[projectId]/download/route'),
}), h, opts)
describeSharedAccess('GitHub secret hunt', scanner('github-hunt', 'scan:secrets', {
  start: () => import('./github-hunt/[projectId]/start/route'),
  pause: () => import('./github-hunt/[projectId]/pause/route'),
  resume: () => import('./github-hunt/[projectId]/resume/route'),
  stop: () => import('./github-hunt/[projectId]/stop/route'),
  status: () => import('./github-hunt/[projectId]/status/route'),
  logs: () => import('./github-hunt/[projectId]/logs/route'),
  download: () => import('./github-hunt/[projectId]/download/route'),
}), h, opts)
describeSharedAccess('supply chain', [
  ...scanner('supply-chain', 'scan:supply_chain', {
    start: () => import('./supply-chain/[projectId]/start/route'),
    pause: () => import('./supply-chain/[projectId]/pause/route'),
    resume: () => import('./supply-chain/[projectId]/resume/route'),
    stop: () => import('./supply-chain/[projectId]/stop/route'),
    status: () => import('./supply-chain/[projectId]/status/route'),
    logs: () => import('./supply-chain/[projectId]/logs/route'),
    download: () => import('./supply-chain/[projectId]/download/route'),
  }),
  at('GET /api/supply-chain/[projectId]/upload', () => import('./supply-chain/[projectId]/upload/route'), 'recon:read', 'read', p),
  at('POST /api/supply-chain/[projectId]/upload', () => import('./supply-chain/[projectId]/upload/route'), 'scan:supply_chain', 'write', p),
  at('DELETE /api/supply-chain/[projectId]/upload', () => import('./supply-chain/[projectId]/upload/route'), 'scan:supply_chain', 'write', p),
  at('POST /api/projects/[id]/supply-chain-batch', () => import('./projects/[id]/supply-chain-batch/route'), 'scan:supply_chain', 'write', id, {}),
], h, opts)
describeSharedAccess('TruffleHog', [
  at('GET /api/trufflehog/[projectId]/all', () => import('./trufflehog/[projectId]/all/route'), 'recon:read', 'read', p),
  at('GET /api/trufflehog/[projectId]/[source]/status', () => import('./trufflehog/[projectId]/[source]/status/route'), 'recon:read', 'read', src),
  at('GET /api/trufflehog/[projectId]/[source]/logs', () => import('./trufflehog/[projectId]/[source]/logs/route'), 'recon:read', 'read', src),
  at('GET /api/trufflehog/[projectId]/profiles', () => import('./trufflehog/[projectId]/profiles/route'), 'recon:read', 'read', p),
  at('GET /api/trufflehog/[projectId]/download', () => import('./trufflehog/[projectId]/download/route'), 'recon:read', 'raw', p),
  at('HEAD /api/trufflehog/[projectId]/download', () => import('./trufflehog/[projectId]/download/route'), 'recon:read', 'raw', p),
  at('POST /api/trufflehog/[projectId]/start', () => import('./trufflehog/[projectId]/start/route'), 'scan:secrets', 'write', p, { source: 'docker' }),
  at('POST /api/trufflehog/[projectId]/[source]/stop', () => import('./trufflehog/[projectId]/[source]/stop/route'), 'scan:secrets', 'write', src),
  at('POST /api/trufflehog/[projectId]/profiles', () => import('./trufflehog/[projectId]/profiles/route'), 'scan:secrets', 'write', p, {}),
  at('PATCH /api/trufflehog/[projectId]/profiles/[profileId]', () => import('./trufflehog/[projectId]/profiles/[profileId]/route'), 'scan:secrets', 'write', { ...p, profileId: 'T1' }, {}),
  at('DELETE /api/trufflehog/[projectId]/profiles/[profileId]', () => import('./trufflehog/[projectId]/profiles/[profileId]/route'), 'scan:secrets', 'write', { ...p, profileId: 'T1' }),
], h, opts)
describeSharedAccess('AI attack surface', [
  at('GET /api/ai-attack-surface/[projectId]/[runId]/status', () => import('./ai-attack-surface/[projectId]/[runId]/status/route'), 'recon:read', 'read', run),
  at('GET /api/ai-attack-surface/[projectId]/[runId]/logs', () => import('./ai-attack-surface/[projectId]/[runId]/logs/route'), 'recon:read', 'read', run),
  at('GET /api/ai-attack-surface/[projectId]/all', () => import('./ai-attack-surface/[projectId]/all/route'), 'recon:read', 'read', p),
  at('GET /api/ai-attack-surface/[projectId]/findings', () => import('./ai-attack-surface/[projectId]/findings/route'), 'recon:read', 'read', p),
  at('GET /api/ai-attack-surface/[projectId]/judge-model', () => import('./ai-attack-surface/[projectId]/judge-model/route'), 'recon:read', 'read', p),
  at('GET /api/ai-attack-surface/[projectId]/targets', () => import('./ai-attack-surface/[projectId]/targets/route'), 'recon:read', 'read', p),
  at('GET /api/ai-attack-surface/[projectId]/transcript', () => import('./ai-attack-surface/[projectId]/transcript/route'), 'recon:read', 'raw', p),
  at('POST /api/ai-attack-surface/[projectId]/start', () => import('./ai-attack-surface/[projectId]/start/route'), 'scan:ai_attack', 'write', p, {}),
  at('POST /api/ai-attack-surface/[projectId]/[runId]/stop', () => import('./ai-attack-surface/[projectId]/[runId]/stop/route'), 'scan:ai_attack', 'write', run),
], h, opts)
describeSharedAccess('uploads: wordlists and JS recon files', [
  at('GET /api/projects/[id]/wordlists', () => import('./projects/[id]/wordlists/route'), 'recon:read', 'read', id),
  at('GET /api/js-recon/[projectId]/upload', () => import('./js-recon/[projectId]/upload/route'), 'recon:read', 'read', p),
  at('GET /api/js-recon/[projectId]/custom-files', () => import('./js-recon/[projectId]/custom-files/route'), 'recon:read', 'read', p),
  at('GET /api/js-recon/[projectId]/download', () => import('./js-recon/[projectId]/download/route'), 'recon:read', 'raw', p),
  at('HEAD /api/js-recon/[projectId]/download', () => import('./js-recon/[projectId]/download/route'), 'recon:read', 'raw', p),
  at('POST /api/projects/[id]/wordlists', () => import('./projects/[id]/wordlists/route'), 'scan:uploads', 'write', id),
  at('DELETE /api/projects/[id]/wordlists', () => import('./projects/[id]/wordlists/route'), 'scan:uploads', 'write', id),
  at('POST /api/js-recon/[projectId]/upload', () => import('./js-recon/[projectId]/upload/route'), 'scan:uploads', 'write', p),
  at('DELETE /api/js-recon/[projectId]/upload', () => import('./js-recon/[projectId]/upload/route'), 'scan:uploads', 'write', p),
  at('POST /api/js-recon/[projectId]/custom-files', () => import('./js-recon/[projectId]/custom-files/route'), 'scan:uploads', 'write', p),
  at('DELETE /api/js-recon/[projectId]/custom-files', () => import('./js-recon/[projectId]/custom-files/route'), 'scan:uploads', 'write', p),
], h, opts)
describeSharedAccess('scan versions and the delta', [
  at('GET /api/projects/[id]/versions', () => import('./projects/[id]/versions/route'), 'recon:read', 'read', id),
  at('GET /api/projects/[id]/versions/[versionId]/graph', () => import('./projects/[id]/versions/[versionId]/graph/route'), 'recon:read', 'read', version),
  at('GET /api/projects/[id]/delta', () => import('./projects/[id]/delta/route'), 'recon:read', 'read', id),
  at('POST /api/projects/[id]/versions', () => import('./projects/[id]/versions/route'), 'scan:versions', 'write', id, {}),
  at('PATCH /api/projects/[id]/versions/[versionId]', () => import('./projects/[id]/versions/[versionId]/route'), 'scan:versions', 'write', version, {}),
  at('DELETE /api/projects/[id]/versions/[versionId]', () => import('./projects/[id]/versions/[versionId]/route'), 'scan:versions_delete', 'write', version),
  at('POST /api/projects/[id]/versions/[versionId]/activate', () => import('./projects/[id]/versions/[versionId]/activate/route'), 'scan:versions', 'write', version),
], h, opts)

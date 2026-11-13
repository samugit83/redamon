/**
 * The project's own read routes on a shared project (step 4.7; SH-07, SH-24, SH-28, SH-29, PE-20): a
 * read collaborator reads the Rules of Engagement as the read view shows them (OQ-53), the revision
 * list, the auth profile's metadata and the recording status, the IP hostname preview, the reports
 * (list and download) and the schedules with their run history; every change of any of them is
 * refused at read, and so are the settings save, delete, export and the engagement authorizations
 * (Manage or owner). What the reads answer is the owner's data, keyed on the project, never a secret:
 * the auth profile's value and header values, the RoE contacts, text and document stay out.
 * Real guard, can(), projectAccess() and registry; the session, Prisma and the graph are doubles
 * (sharedRouteCases.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

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
vi.mock('@/lib/enqueueJob', () => ({ enqueueJob: (...a: unknown[]) => h.upstream('enqueue', ...a) }))
vi.mock('@/app/api/graph/neo4j', async (orig) => ({
  ...(await orig<typeof import('@/app/api/graph/neo4j')>()),
  getDriver: () => { h.upstream('neo4j'); throw new Error('no graph in this test') },
  getGraphSession: () => { h.upstream('neo4j'); throw new Error('no graph in this test') },
}))

import { describeSharedAccess, COLLABORATOR, type SharedReach, type SharedRouteCase } from '@/lib/authz/__testing__/sharedRouteCases'
import { principal, OWNER, OWNED_PROJECT } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import type { PermissionId } from '@/lib/authz/permissions'

const P = OWNED_PROJECT
const id = { id: P }
type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, reach: SharedReach, params: Record<string, string>, extra: Partial<SharedRouteCase> = {}): SharedRouteCase => ({
  route, permission, reach, params, handler: async () => (await load())[route.split(' ')[0]] as never, ...extra,
})
const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests(); clearPrincipalCacheForTests() }
const opts = { setFlags: setFlagsForTests, clearCaches }

describeSharedAccess('project: RoE, auth profile, settings', [
  at('GET /api/projects/[id]/roe', () => import('./[id]/roe/route'), 'roe:read', 'read', id),
  at('GET /api/projects/[id]/roe/revisions', () => import('./[id]/roe/revisions/route'), 'roe:read', 'read', id),
  at('GET /api/projects/[id]/auth-profile', () => import('./[id]/auth-profile/route'), 'auth_profile:read', 'read', id),
  at('GET /api/projects/[id]/recording/status', () => import('./[id]/recording/status/route'), 'auth_profile:read', 'read', id),
  at('GET /api/projects/[id]/ip-hostnames', () => import('./[id]/ip-hostnames/route'), 'recon:read', 'read', id),
  at('POST /api/projects/[id]/roe', () => import('./[id]/roe/route'), 'roe:manage', 'write', id, { body: {} }),
  at('DELETE /api/projects/[id]/roe', () => import('./[id]/roe/route'), 'roe:manage', 'write', id, { body: {} }),
  at('POST /api/roe/parse', () => import('@/app/api/roe/parse/route'), 'roe:manage', 'write', {}, { projectId: P, body: { projectId: P, parsedFields: {} } }),
  at('PUT /api/projects/[id]/auth-profile', () => import('./[id]/auth-profile/route'), 'auth_profile:manage', 'write', id, { body: {} }),
  at('DELETE /api/projects/[id]/auth-profile', () => import('./[id]/auth-profile/route'), 'auth_profile:manage', 'write', id),
  at('POST /api/projects/[id]/recording/start', () => import('./[id]/recording/start/route'), 'auth_profile:manage', 'write', id),
  at('POST /api/projects/[id]/recording/stop', () => import('./[id]/recording/stop/route'), 'auth_profile:manage', 'write', id),
  at('POST /api/projects/[id]/recording/commit', () => import('./[id]/recording/commit/route'), 'auth_profile:manage', 'write', id, { body: {} }),
  at('PUT /api/projects/[id]', () => import('./[id]/route'), 'project:settings', 'write', id, { body: { name: 'renamed' } }),
  at('DELETE /api/projects/[id]', () => import('./[id]/route'), 'project:delete', 'write', id),
  at('GET /api/projects/[id]/export', () => import('./[id]/export/route'), 'project:export', 'write', id),
  at('GET /api/projects/[id]/authorizations', () => import('./[id]/authorizations/route'), 'engagement:authorize', 'write', id),
], h, opts)

describeSharedAccess('reports', [
  at('GET /api/projects/[id]/reports', () => import('./[id]/reports/route'), 'reports:read', 'read', id),
  at('GET /api/projects/[id]/reports/[reportId]', () => import('./[id]/reports/[reportId]/route'), 'reports:read', 'read', { ...id, reportId: 'r-1' }),
  at('POST /api/projects/[id]/reports', () => import('./[id]/reports/route'), 'reports:generate', 'write', id, { body: {} }),
  at('DELETE /api/projects/[id]/reports/[reportId]', () => import('./[id]/reports/[reportId]/route'), 'reports:delete', 'write', { ...id, reportId: 'r-1' }),
], h, opts)

const queuedJob = (st: { models: Record<string, unknown> }) => {
  st.models.jobQueue = {
    findUnique: async () => ({ id: 'J1', projectId: P, status: 'needs_review', kind: 'gvm', payload: {} }),
    update: async () => ({}), updateMany: async () => ({ count: 1 }),
  }
}
describeSharedAccess('schedules and the queue', [
  at('GET /api/projects/[id]/schedules', () => import('./[id]/schedules/route'), 'recon:read', 'read', id),
  at('POST /api/projects/[id]/schedules', () => import('./[id]/schedules/route'), 'recon:schedule', 'write', id, { body: { mode: 'once' } }),
  at('PATCH /api/projects/[id]/schedules/[scheduleId]', () => import('./[id]/schedules/[scheduleId]/route'), 'recon:schedule', 'write', { ...id, scheduleId: 'S1' }, { body: { label: 'x' } }),
  at('DELETE /api/projects/[id]/schedules/[scheduleId]', () => import('./[id]/schedules/[scheduleId]/route'), 'recon:schedule', 'write', { ...id, scheduleId: 'S1' }),
  at('DELETE /api/projects/[id]/schedules/history', () => import('./[id]/schedules/history/route'), 'scan:versions_delete', 'write', id, { body: {} }),
  at('POST /api/projects/[id]/queue', () => import('./[id]/queue/route'), 'recon:schedule', 'write', id, { body: { kind: 'gvm', payload: {} } }),
  at('POST /api/job-queue/[id]/cancel', () => import('@/app/api/job-queue/[id]/cancel/route'), 'recon:schedule', 'write', { id: 'J1' }, { projectId: P, arrange: queuedJob }),
  at('POST /api/job-queue/[id]/reconfirm', () => import('@/app/api/job-queue/[id]/reconfirm/route'), 'recon:schedule', 'write', { id: 'J1' }, { projectId: P, arrange: queuedJob, body: {} }),
], h, opts)

describe('what a read collaborator reads is the owner\'s, without the owner\'s secrets (step 4.7)', () => {
  beforeEach(() => {
    h.identity.mockReset()
    h.downstream.mockReset()
    h.projects.clear()
    h.shares.clear()
    for (const k of Object.keys(h.models)) delete h.models[k]
    h.projects.set(P, { id: P, userId: OWNER })
    h.shares.set(`${P}|${COLLABORATOR}`, { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
    const carol = principal(COLLABORATOR)
    h.identity.mockResolvedValue({ session: { userId: carol.id, role: carol.role }, principal: carol, actingAs: null })
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    clearCaches()
    clearSharingPolicyCacheForTests()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.restoreAllMocks()
  })
  const get = async (load: () => Promise<Mod>, path: string, params: Record<string, string>) =>
    ((await load()).GET as (r: NextRequest, c: unknown) => Promise<Response>)(new NextRequest(`http://localhost:3000${path}`), { params: Promise.resolve(params) })

  test('the collaborator is the one the shared cases sign in', () => {
    expect(COLLABORATOR).toBe('carol')
    expect(P).toBe('P-alice')
  })

  test('the auth profile: metadata and hasValue, never the value or a header value (SH-29)', async () => {
    h.models.projectAuthProfile = {
      findUnique: async ({ where }: { where: { projectId: string } }) => (where.projectId === P ? {
        id: 'ap1', projectId: P, userId: OWNER, authType: 'header', authHeaderName: 'X-Api-Key', authValue: 'rbac-fake-auth-value-0001',
        extraHeaders: { 'X-Tenant': 'rbac-fake-header-value-0002' }, scopeHosts: ['app.rbac.test'], reconEnabled: true, agentEnabled: false,
        source: 'manual', status: 'active', lastValidatedAt: null, createdAt: new Date(0), updatedAt: new Date(0),
      } : null),
    }
    const res = await get(() => import('./[id]/auth-profile/route'), `/api/projects/${P}/auth-profile`, id)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(JSON.parse(text).authProfile).toMatchObject({
      authType: 'header', authHeaderName: 'X-Api-Key', extraHeaderNames: ['X-Tenant'], scopeHosts: ['app.rbac.test'], hasValue: true,
    })
    expect(text).not.toContain('rbac-fake-auth-value-0001')
    expect(text).not.toContain('rbac-fake-header-value-0002')
  })

  test('the RoE read view: the scope, no contact, text or document (OQ-53)', async () => {
    h.projects.set(P, {
      id: P, userId: OWNER, roeClientName: 'rbac-client-co', roeClientContactEmail: 'rbac-contact@client.test', roeEmergencyContact: 'rbac-emergency',
      roeRawText: 'rbac-raw-text', roeDocumentName: 'rbac-roe.pdf', roeDocumentMimeType: 'application/pdf', roeParsedJson: { appliedAt: '2026-10-01T00:00:00.000Z' },
      roeGlobalMaxRps: 3, roeExcludedHosts: ['db.rbac.test'], roeTimeWindowEnabled: false,
    } as { id: string; userId: string })
    h.models.$queryRaw = async () => [{ bytes: 42 }]
    h.models.roeDocumentRevision = { count: async () => 1 }
    const res = await get(() => import('./[id]/roe/route'), `/api/projects/${P}/roe`, id)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(JSON.parse(text).roe).toMatchObject({
      document: { name: 'rbac-roe.pdf', size: 42, uploadedAt: '2026-10-01T00:00:00.000Z' }, revisions: 1, enforced: true,
      limits: { roeGlobalMaxRps: 3, roeExcludedHosts: ['db.rbac.test'] },
    })
    for (const secret of ['rbac-client-co', 'rbac-contact@client.test', 'rbac-emergency', 'rbac-raw-text']) expect(text).not.toContain(secret)
  })

  test("the reports: the owner's, keyed on the project", async () => {
    const asked: unknown[] = []
    h.models.report = {
      findMany: async (args: { where: { projectId: string } }) => {
        asked.push(args.where)
        return args.where.projectId === P ? [{ id: 'r-1', title: 'Owner report', filename: 'r.html', fileSize: 1, format: 'html', metrics: {}, hasNarratives: false, createdAt: new Date(0) }] : []
      },
    }
    const res = await get(() => import('./[id]/reports/route'), `/api/projects/${P}/reports`, id)
    expect(res.status).toBe(200)
    expect((await res.json()).map((r: { id: string }) => r.id)).toEqual(['r-1'])
    expect(asked).toEqual([{ projectId: P }])
  })

  test('the RoE document downloads stay the owner\'s (4.1): 403 owner_only before any read', async () => {
    const res = await get(() => import('./[id]/roe/download/route'), `/api/projects/${P}/roe/download`, id)
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'owner_only', permission: 'roe:read' })
    expect(h.downstream).not.toHaveBeenCalled()
  })
})

/**
 * The project routes ask for their permission (step 3.8; PE-19, PE-22): reading a project
 * `recon:read`, its settings save `project:settings` (a scope or target-list change also
 * `project:rescope`), deleting it `project:delete`, exporting it `project:export`, creating and
 * importing one `project:create` / `project:import` (an imported authorization record also
 * `engagement:authorize`), the RoE `roe:read` / `roe:manage`, the auth profile and its recording
 * sessions `auth_profile:read` / `auth_profile:manage`, the engagement authorizations
 * `engagement:authorize`, the IP hostname preview `recon:read`.
 * Real guard, can() and registry; the session, Prisma and the graph are doubles
 * (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

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

import { describeRoutePermissions, denying, principal, OWNER, OWNED_PROJECT, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

const P = OWNED_PROJECT
const id = { id: P }
type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string>, extra: Partial<RouteCase> = {}): RouteCase => ({
  route, permission, params, handler: async () => (await load())[route.split(' ')[0]] as never, ...extra,
})
const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() }

describeRoutePermissions('projects', [
  at('GET /api/projects/[id]', () => import('./[id]/route'), 'recon:read', id),
  at('PUT /api/projects/[id]', () => import('./[id]/route'), 'project:settings', id, { body: { name: 'renamed' } }),
  at('DELETE /api/projects/[id]', () => import('./[id]/route'), 'project:delete', id),
  at('POST /api/projects', () => import('./route'), 'project:create', {}, { projectId: null, body: { name: 'x' } }),
  at('POST /api/projects/import', () => import('./import/route'), 'project:import', {}, { projectId: null }),
  at('GET /api/projects/[id]/export', () => import('./[id]/export/route'), 'project:export', id),
  at('GET /api/projects/[id]/authorizations', () => import('./[id]/authorizations/route'), 'engagement:authorize', id),
  at('GET /api/projects/[id]/ip-hostnames', () => import('./[id]/ip-hostnames/route'), 'recon:read', id),
  at('POST /api/projects/[id]/roe', () => import('./[id]/roe/route'), 'roe:manage', id, { body: {} }),
  at('DELETE /api/projects/[id]/roe', () => import('./[id]/roe/route'), 'roe:manage', id, { body: {} }),
  at('GET /api/projects/[id]/roe/download', () => import('./[id]/roe/download/route'), 'roe:read', id),
  at('GET /api/projects/[id]/roe/revisions', () => import('./[id]/roe/revisions/route'), 'roe:read', id),
  at('GET /api/projects/[id]/roe/revisions/[revId]/download', () => import('./[id]/roe/revisions/[revId]/download/route'), 'roe:read', { ...id, revId: 'R1' }),
  at('POST /api/roe/parse', () => import('@/app/api/roe/parse/route'), 'roe:manage', {}, { projectId: P, body: { projectId: P, parsedFields: {} } }),
  at('GET /api/projects/[id]/auth-profile', () => import('./[id]/auth-profile/route'), 'auth_profile:read', id),
  at('PUT /api/projects/[id]/auth-profile', () => import('./[id]/auth-profile/route'), 'auth_profile:manage', id, { body: {} }),
  at('DELETE /api/projects/[id]/auth-profile', () => import('./[id]/auth-profile/route'), 'auth_profile:manage', id),
  at('POST /api/projects/[id]/recording/start', () => import('./[id]/recording/start/route'), 'auth_profile:manage', id),
  at('POST /api/projects/[id]/recording/stop', () => import('./[id]/recording/stop/route'), 'auth_profile:manage', id),
  at('POST /api/projects/[id]/recording/commit', () => import('./[id]/recording/commit/route'), 'auth_profile:manage', id, { body: {} }),
  at('GET /api/projects/[id]/recording/status', () => import('./[id]/recording/status/route'), 'auth_profile:read', id),
], h, { setFlags: setFlagsForTests, clearCaches })

describe('a choice inside the request needs its own permission (requireAlso)', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true })
    clearCaches()
    h.projects.clear()
    h.projects.set(P, { id: P, userId: OWNER })
    h.upstream.mockReset()
    h.upstream.mockRejectedValue(Object.assign(new Error('no upstream in this test'), { code: 'ECONNREFUSED' }))
    vi.stubGlobal('fetch', (...a: unknown[]) => h.upstream(...a))
    h.downstream.mockReset()
    for (const k of Object.keys(h.models)) delete h.models[k]
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })
  const signIn = (who: ReturnType<typeof principal>) =>
    h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs: null })
  const put = async (body: Record<string, unknown>) => {
    const { PUT } = await import('./[id]/route')
    return PUT(new NextRequest(`http://localhost:3000/api/projects/${P}`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    }), { params: Promise.resolve(id) })
  }
  const written = () => h.downstream.mock.calls.filter(([model, method]) => model === 'project' && /update|create/.test(String(method)))

  test('a settings save that changes the target needs project:rescope: 403 naming it, before the guardrail or any write', async () => {
    signIn(denying(OWNER, 'project:rescope'))
    const res = await put({ targetDomain: 'rescoped.example.test' })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:rescope' })
    expect(h.upstream).not.toHaveBeenCalled()
    expect(written()).toEqual([])
  })

  test('a settings save that changes a target list (a rescopable field) needs project:rescope', async () => {
    signIn(denying(OWNER, 'project:rescope'))
    h.models.userSettings = { findUnique: async () => null }
    const res = await put({ gvmScanTargets: ['192.0.2.10'] })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:rescope' })
    expect(written()).toEqual([])
  })

  test('a save that leaves the scope and the target lists as stored does not ask for project:rescope', async () => {
    signIn(denying(OWNER, 'project:rescope'))
    const res = await put({ name: 'renamed' })
    if (res.status === 403) expect((await res.json()).permission).not.toBe('project:rescope')
  })

  test('the same target change passes the permission with Default member', async () => {
    signIn(principal(OWNER))
    const res = await put({ targetDomain: 'rescoped.example.test' })
    if (res.status === 403) expect((await res.json()).permission).not.toBe('project:rescope')
  })

  async function importRequest(authorizations: unknown[]): Promise<NextRequest> {
    const zip = new JSZip()
    zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
    zip.file('project.json', JSON.stringify({
      id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.invalid', engagementKind: 'third_party',
      roeGlobalMaxRps: 5, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    }))
    zip.file('engagement/authorizations.json', JSON.stringify(authorizations))
    const fd = new FormData()
    fd.set('file', new File([await zip.generateAsync({ type: 'arraybuffer' })], 'p.zip', { type: 'application/zip' }))
    return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
  }
  const AUTH_RECORD = [{ documentSha256: 'd'.repeat(64), documentKind: 'hackerone_program', issuedAt: '2026-01-01T00:00:00.000Z', summary: 'x' }]

  test('importing a bundle that carries authorization records needs engagement:authorize; nothing is created', async () => {
    signIn(denying(OWNER, 'engagement:authorize'))
    const { POST } = await import('./import/route')
    const res = await POST(await importRequest(AUTH_RECORD))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'engagement:authorize' })
    expect(written()).toEqual([])
    expect(h.downstream.mock.calls.filter(([model]) => model === 'engagementAuthorization')).toEqual([])
  })

  test('the same bundle passes that check with Default member', async () => {
    signIn(principal(OWNER))
    const { POST } = await import('./import/route')
    const res = await POST(await importRequest(AUTH_RECORD))
    if (res.status === 403) expect((await res.json()).permission).not.toBe('engagement:authorize')
  })
})

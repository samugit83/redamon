/**
 * The agent workspace and the in-chat file download ask for their permission (step 3.9; PE-19,
 * PE-22): browsing, previewing, downloading and archiving `workspace:read`; uploading, creating
 * folders, renaming, deleting, resetting and cancelling a background job `workspace:write`;
 * importing from a URL `workspace:import`; all on the project the request names. A download with
 * no project (a file the agent wrote in a chat, under /tmp) is `agent:chat`, the capability alone.
 * Real guard, can() and registry; the session and Prisma are doubles (routePermissionCases.ts).
 *
 * The project comes from the query string for most routes: the case's path carries it as a
 * `[projectId]` placeholder the harness fills (and the 404 case points at a stranger's project).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

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

import {
  OWNED_PROJECT, OWNER, denying, describeRoutePermissions, principal, type RouteCase,
} from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

type Mod = Record<string, unknown>
const p = { projectId: OWNED_PROJECT }
const at = (
  route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string>, body?: unknown,
): RouteCase => ({
  route, permission, params, body, handler: async () => (await load())[route.split(' ')[0]] as never,
})
const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() }

describeRoutePermissions('agent workspace and file download', [
  at('GET /api/agent/workspace/list?projectId=[projectId]', () => import('./list/route'), 'workspace:read', p),
  at('GET /api/agent/workspace/tree?projectId=[projectId]', () => import('./tree/route'), 'workspace:read', p),
  at('GET /api/agent/workspace/preview?projectId=[projectId]&path=a.txt', () => import('./preview/route'), 'workspace:read', p),
  at('GET /api/agent/workspace/properties?projectId=[projectId]&path=a', () => import('./properties/route'), 'workspace:read', p),
  at('GET /api/agent/workspace/archive-download?projectId=[projectId]&path=a', () => import('./archive-download/route'), 'workspace:read', p),
  at('POST /api/agent/workspace/bulk-archive', () => import('./bulk-archive/route'), 'workspace:read', {}, { projectId: OWNED_PROJECT, paths: ['a'] }),
  at('GET /api/agent/workspace/jobs?projectId=[projectId]', () => import('./jobs/route'), 'workspace:read', p),
  at('GET /api/agent/workspace/jobs/[jobId]?projectId=[projectId]', () => import('./jobs/[jobId]/route'), 'workspace:read', { ...p, jobId: 'j1' }),
  at('GET /api/agent/files?projectId=[projectId]&path=a.txt', () => import('../files/route'), 'workspace:read', p),
  at('POST /api/agent/workspace/jobs/[jobId]/cancel?projectId=[projectId]', () => import('./jobs/[jobId]/cancel/route'), 'workspace:write', { ...p, jobId: 'j1' }),
  at('DELETE /api/agent/workspace/delete?projectId=[projectId]&path=a', () => import('./delete/route'), 'workspace:write', p),
  at('POST /api/agent/workspace/mkdir', () => import('./mkdir/route'), 'workspace:write', {}, { projectId: OWNED_PROJECT, path: 'a' }),
  at('POST /api/agent/workspace/rename', () => import('./rename/route'), 'workspace:write', {}, { projectId: OWNED_PROJECT, path: 'a', newName: 'b' }),
  at('POST /api/agent/workspace/reset', () => import('./reset/route'), 'workspace:write', {}, { projectId: OWNED_PROJECT }),
  at('POST /api/agent/workspace/upload-sessions', () => import('./upload-sessions/route'), 'workspace:write', {},
    { projectId: OWNED_PROJECT, name: 'a.bin', size: 1, kind: 'file' }),
  at('DELETE /api/agent/workspace/upload-sessions/[uploadId]?projectId=[projectId]', () => import('./upload-sessions/[uploadId]/route'),
    'workspace:write', { ...p, uploadId: 'u'.repeat(32) }),
  at('PUT /api/agent/workspace/upload-sessions/[uploadId]/chunk?projectId=[projectId]&offset=0', () => import('./upload-sessions/[uploadId]/chunk/route'),
    'workspace:write', { ...p, uploadId: 'u'.repeat(32) }),
  at('POST /api/agent/workspace/upload-sessions/[uploadId]/commit', () => import('./upload-sessions/[uploadId]/commit/route'),
    'workspace:write', { uploadId: 'u'.repeat(32) }, { projectId: OWNED_PROJECT }),
  at('POST /api/agent/workspace/import-url', () => import('./import-url/route'), 'workspace:import', {},
    { projectId: OWNED_PROJECT, url: 'https://example.test/a.zip' }),
  at('POST /api/agent/workspace/import-url/resolve', () => import('./import-url/resolve/route'), 'workspace:import', {},
    { projectId: OWNED_PROJECT, url: 'https://example.test/a.zip' }),
  at('POST /api/agent/workspace/import-url/resync', () => import('./import-url/resync/route'), 'workspace:import', {},
    { projectId: OWNED_PROJECT, path: 'uploads/a' }),
  { ...at('GET /api/agent/files?path=[path]', () => import('../files/route'), 'agent:chat', { path: '/tmp/out.txt' }), projectId: null },
], h, { setFlags: setFlagsForTests, clearCaches })

/** A multipart upload: the harness sends JSON bodies, so this route is driven by hand. */
describe('POST /api/agent/workspace/upload asks for workspace:write (step 3.9)', () => {
  const upload = () => {
    const form = new FormData()
    form.set('projectId', OWNED_PROJECT)
    form.set('file', new File(['x'], 'a.txt'))
    return new NextRequest('http://localhost:3000/api/agent/workspace/upload', { method: 'POST', body: form })
  }
  const as = (who: ReturnType<typeof principal>) =>
    h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs: null })

  beforeEach(() => {
    h.identity.mockReset()
    h.upstream.mockReset().mockRejectedValue(Object.assign(new Error('no upstream in this test'), { code: 'ECONNREFUSED' }))
    h.projects.clear()
    h.projects.set(OWNED_PROJECT, { id: OWNED_PROJECT, userId: OWNER })
    vi.stubGlobal('fetch', (...a: unknown[]) => h.upstream(...a))
    setFlagsForTests({ identity: true, permissions: true })
    clearCaches()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  test('refused without workspace:write: 403 naming it, the agent never called', async () => {
    as(denying(OWNER, 'workspace:write'))
    const res = await (await import('./upload/route')).POST(upload())
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'workspace:write' })
    expect(h.upstream).not.toHaveBeenCalled()
  })

  test('allowed with Default member: the file goes to the agent', async () => {
    as(principal(OWNER))
    await (await import('./upload/route')).POST(upload())
    expect(h.upstream).toHaveBeenCalled()
  })
})

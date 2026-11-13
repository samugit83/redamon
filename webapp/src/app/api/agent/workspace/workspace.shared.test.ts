/**
 * The agent workspace on a shared project (step 4.9; SH-27, SH-03). Browsing, previewing,
 * downloading and archiving are `workspace:read`, at `R*`: a Read share without Raw data & files is
 * refused by the guard before the agent is called; with it the collaborator reaches the OWNER's
 * workspace, which the agent keys on the project alone (`/workspace/<projectId>/`), so the call names
 * the project and nothing of the reader. Every upload, folder, rename, delete, reset, job cancel and
 * import stays a write (W), refused at read. The routes are unchanged: the level table of step 4.3
 * already holds them; this proves it.
 *
 * Real guard, can(), projectAccess() and registry; the session and Prisma are doubles
 * (sharedRouteCases.ts), the agent is `fetch`.
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
  getSession: async () => {
    const id = await h.identity()
    return id ? { userId: id.principal.id, role: id.principal.role } : null
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedRouteCases')).sharingPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import { describeSharedAccess, COLLABORATOR, type SharedReach, type SharedRouteCase } from '@/lib/authz/__testing__/sharedRouteCases'
import { principal, OWNER, OWNED_PROJECT } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import type { PermissionId } from '@/lib/authz/permissions'

const P = OWNED_PROJECT
const p = { projectId: P }
const upload = { ...p, uploadId: 'u'.repeat(32) }
type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, reach: SharedReach, params: Record<string, string>, body?: unknown): SharedRouteCase => ({
  route, permission, reach, params, body, projectId: P, handler: async () => (await load())[route.split(' ')[0]] as never,
})
const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests(); clearPrincipalCacheForTests() }

const READS: SharedRouteCase[] = [
  at('GET /api/agent/workspace/list?projectId=[projectId]', () => import('./list/route'), 'workspace:read', 'rawPermission', p),
  at('GET /api/agent/workspace/tree?projectId=[projectId]', () => import('./tree/route'), 'workspace:read', 'rawPermission', p),
  at('GET /api/agent/workspace/preview?projectId=[projectId]&path=a.txt', () => import('./preview/route'), 'workspace:read', 'rawPermission', p),
  at('GET /api/agent/workspace/properties?projectId=[projectId]&path=a', () => import('./properties/route'), 'workspace:read', 'rawPermission', p),
  at('GET /api/agent/workspace/archive-download?projectId=[projectId]&path=a', () => import('./archive-download/route'), 'workspace:read', 'rawPermission', p),
  at('POST /api/agent/workspace/bulk-archive', () => import('./bulk-archive/route'), 'workspace:read', 'rawPermission', {}, { projectId: P, paths: ['a'] }),
  at('GET /api/agent/workspace/jobs?projectId=[projectId]', () => import('./jobs/route'), 'workspace:read', 'rawPermission', p),
  at('GET /api/agent/workspace/jobs/[jobId]?projectId=[projectId]', () => import('./jobs/[jobId]/route'), 'workspace:read', 'rawPermission', { ...p, jobId: 'j1' }),
  at('GET /api/agent/files?projectId=[projectId]&path=a.txt', () => import('../files/route'), 'workspace:read', 'rawPermission', p),
]

describeSharedAccess('agent workspace', [
  ...READS,
  at('POST /api/agent/workspace/jobs/[jobId]/cancel?projectId=[projectId]', () => import('./jobs/[jobId]/cancel/route'), 'workspace:write', 'write', { ...p, jobId: 'j1' }),
  at('DELETE /api/agent/workspace/delete?projectId=[projectId]&path=a', () => import('./delete/route'), 'workspace:write', 'write', p),
  at('POST /api/agent/workspace/mkdir', () => import('./mkdir/route'), 'workspace:write', 'write', {}, { projectId: P, path: 'a' }),
  at('POST /api/agent/workspace/rename', () => import('./rename/route'), 'workspace:write', 'write', {}, { projectId: P, path: 'a', newName: 'b' }),
  at('POST /api/agent/workspace/reset', () => import('./reset/route'), 'workspace:write', 'write', {}, { projectId: P }),
  at('POST /api/agent/workspace/upload-sessions', () => import('./upload-sessions/route'), 'workspace:write', 'write', {},
    { projectId: P, name: 'a.bin', size: 1, kind: 'file' }),
  at('DELETE /api/agent/workspace/upload-sessions/[uploadId]?projectId=[projectId]', () => import('./upload-sessions/[uploadId]/route'), 'workspace:write', 'write', upload),
  at('PUT /api/agent/workspace/upload-sessions/[uploadId]/chunk?projectId=[projectId]&offset=0', () => import('./upload-sessions/[uploadId]/chunk/route'),
    'workspace:write', 'write', upload),
  at('POST /api/agent/workspace/upload-sessions/[uploadId]/commit', () => import('./upload-sessions/[uploadId]/commit/route'),
    'workspace:write', 'write', { uploadId: 'u'.repeat(32) }, { projectId: P }),
  at('POST /api/agent/workspace/import-url', () => import('./import-url/route'), 'workspace:import', 'write', {}, { projectId: P, url: 'https://example.test/a.zip' }),
  at('POST /api/agent/workspace/import-url/resolve', () => import('./import-url/resolve/route'), 'workspace:import', 'write', {}, { projectId: P, url: 'https://example.test/a.zip' }),
  at('POST /api/agent/workspace/import-url/resync', () => import('./import-url/resync/route'), 'workspace:import', 'write', {}, { projectId: P, path: 'uploads/a' }),
], h, { setFlags: setFlagsForTests, clearCaches })

describe('a read collaborator with Raw data & files reaches the owner\'s workspace (step 4.9)', () => {
  const agentUrls: string[] = []

  beforeEach(() => {
    h.identity.mockReset()
    h.downstream.mockReset()
    h.projects.clear()
    h.shares.clear()
    agentUrls.length = 0
    h.projects.set(P, { id: P, userId: OWNER })
    h.shares.set(`${P}|${COLLABORATOR}`, { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
    vi.stubGlobal('fetch', async (url: unknown, init?: { headers?: Record<string, string> }) => {
      agentUrls.push(`${String(url)} ${JSON.stringify(init?.headers ?? {})}`)
      return new Response(JSON.stringify({ projectId: P, path: '.', entries: [{ name: 'notes.txt', type: 'file' }], total: 1, truncated: false }), {
        status: 200, headers: { 'content-type': 'application/json' },
      })
    })
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    clearCaches()
    clearSharingPolicyCacheForTests()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  const signIn = (who: string) => {
    const person = principal(who)
    h.identity.mockResolvedValue({ session: { userId: person.id, role: person.role }, principal: person, actingAs: null })
  }
  const list = async () => (await import('./list/route')).GET(new NextRequest(`http://localhost:3000/api/agent/workspace/list?projectId=${P}&path=.`))

  test('the owner and the collaborator get the same listing, from the same agent call on the project', async () => {
    signIn(OWNER)
    const owner = await list()
    signIn(COLLABORATOR)
    const reader = await list()
    expect(owner.status).toBe(200)
    expect(reader.status).toBe(200)
    expect(await reader.json()).toEqual(await owner.json())
    expect(agentUrls).toHaveLength(2)
    expect(agentUrls[1]).toBe(agentUrls[0])
    expect(agentUrls[1]).toContain(`/workspace/list?projectId=${P}&path=.`)
    expect(agentUrls[1]).not.toContain(COLLABORATOR)
  })

  test('without Raw data the same collaborator is refused before the agent is called', async () => {
    h.shares.set(`${P}|${COLLABORATOR}`, { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
    signIn(COLLABORATOR)
    const res = await list()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'workspace:read' })
    expect(agentUrls).toEqual([])
  })
})

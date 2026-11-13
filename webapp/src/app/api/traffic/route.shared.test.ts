/**
 * Captured traffic on a shared project (step 4.9; SH-23, SH-03, T9). Traffic is raw data: its list,
 * detail, facets and export are `traffic:read` / `traffic:export`, both at `R*`, so a Read share
 * without Raw data & files is refused by the guard, before any row is read; with it the collaborator
 * reads the OWNER's rows: every query filters on the project and on its owner's id, the tenant
 * every ingest path stamps (`ingest/route.ts` writes `project.userId`), never on the reader. The
 * owner reads exactly the rows it read before. Deleting stays a write (`traffic:delete`, W).
 *
 * Real guard, can(), projectAccess() and registry; the session and Prisma are doubles
 * (sharedRouteCases.ts), the captured rows a recording double.
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
vi.mock('@/lib/captureBodies', () => ({
  gcOrphanBodies: async () => ({ deleted: 0 }),
  readCapturedBody: async () => 'rbac-offloaded-body',
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
const p = { projectId: P }
type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, reach: SharedReach, params: Record<string, string>, extra: Partial<SharedRouteCase> = {}): SharedRouteCase => ({
  route, permission, reach, params, handler: async () => (await load())[route.split(' ')[0]] as never, ...extra,
})
const clearCaches = () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests(); clearPrincipalCacheForTests() }

const list = () => import('./[projectId]/route')
const detail = () => import('./[projectId]/[id]/route')
const facets = () => import('./[projectId]/facets/route')
const exporter = () => import('./[projectId]/export/route')

describeSharedAccess('captured traffic', [
  at('GET /api/traffic/[projectId]', list, 'traffic:read', 'rawPermission', p),
  at('GET /api/traffic/[projectId]/[id]', detail, 'traffic:read', 'rawPermission', { ...p, id: 't-1' }),
  at('GET /api/traffic/[projectId]/facets', facets, 'traffic:read', 'rawPermission', p),
  at('GET /api/traffic/[projectId]/export', exporter, 'traffic:export', 'rawPermission', p),
  at('DELETE /api/traffic/[projectId]', list, 'traffic:delete', 'write', p, { body: { ids: ['t-1'] } }),
], h, { setFlags: setFlagsForTests, clearCaches })

/** The owner's rows and one row of the same project stamped with someone else's id (it must never show). */
const ROWS = [
  { id: 't-1', projectId: P, userId: OWNER, host: 'app.rbac.test', tool: 'httpx', runId: 'run-1', sessionId: 's-1', reqBody: null, reqBodyRef: 'sha-1', respBody: 'ok', respBodyRef: null },
  { id: 't-2', projectId: P, userId: COLLABORATOR, host: 'stray.rbac.test', tool: 'katana', runId: 'run-2', sessionId: 's-2', reqBody: 'x', reqBodyRef: null, respBody: 'y', respBodyRef: null },
]
type Where = { projectId?: string; userId?: unknown; id?: unknown; tool?: unknown; runId?: unknown; sessionId?: unknown }
const matches = (row: (typeof ROWS)[number], where: Where) =>
  row.projectId === where.projectId && row.userId === where.userId && (where.id === undefined || row.id === where.id)

describe('a read collaborator with Raw data & files reads the owner\'s captured traffic (step 4.9, T9)', () => {
  const wheres: Where[] = []

  beforeEach(() => {
    h.identity.mockReset()
    h.downstream.mockReset()
    h.projects.clear()
    h.shares.clear()
    for (const k of Object.keys(h.models)) delete h.models[k]
    wheres.length = 0
    h.projects.set(P, { id: P, userId: OWNER })
    h.shares.set(`${P}|${COLLABORATOR}`, { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
    h.models.capturedHttpTransaction = {
      findMany: async ({ where, select, cursor }: { where: Where; select?: Record<string, boolean>; cursor?: unknown }) => {
        wheres.push(where)
        if (cursor) return []
        const rows = ROWS.filter(r => matches(r, where))
        if (select && 'tool' in select && Object.keys(select).length === 1) return rows.map(r => ({ tool: r.tool }))
        if (select && 'host' in select && Object.keys(select).length === 1) return rows.map(r => ({ host: r.host }))
        if (select && 'runId' in select && Object.keys(select).length === 1) return rows.map(r => ({ runId: r.runId }))
        if (select && 'sessionId' in select && Object.keys(select).length === 1) return rows.map(r => ({ sessionId: r.sessionId }))
        return rows
      },
      count: async ({ where }: { where: Where }) => { wheres.push(where); return ROWS.filter(r => matches(r, where)).length },
      findFirst: async ({ where }: { where: Where }) => { wheres.push(where); return ROWS.find(r => matches(r, where)) ?? null },
    }
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    clearCaches()
    clearSharingPolicyCacheForTests()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.restoreAllMocks()
  })

  const signIn = (who: string) => {
    const person = principal(who)
    h.identity.mockResolvedValue({ session: { userId: person.id, role: person.role }, principal: person, actingAs: null })
  }
  const call = async (load: () => Promise<Mod>, path: string, params: Record<string, string>) =>
    ((await load()).GET as (r: NextRequest, c: unknown) => Promise<Response>)(new NextRequest(`http://localhost:3000${path}`), { params: Promise.resolve(params) })

  test.each([[OWNER], [COLLABORATOR]])('the list (%s): the owner\'s rows only, every query on the project and its owner', async (who) => {
    signIn(who)
    const res = await call(list, `/api/traffic/${P}?tool=httpx,katana`, p)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.rows.map((r: { id: string }) => r.id)).toEqual(['t-1'])
    expect(body.total).toBe(1)
    expect(wheres).toHaveLength(2)
    for (const w of wheres) expect(w).toMatchObject({ projectId: P, userId: OWNER, tool: { in: ['httpx', 'katana'] } })
  })

  test.each([[OWNER], [COLLABORATOR]])('the detail (%s): the owner\'s row with its offloaded body; a row stamped with the reader is not found', async (who) => {
    signIn(who)
    const res = await call(detail, `/api/traffic/${P}/t-1`, { ...p, id: 't-1' })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ id: 't-1', userId: OWNER, reqBody: 'rbac-offloaded-body' })
    const stray = await call(detail, `/api/traffic/${P}/t-2`, { ...p, id: 't-2' })
    expect(stray.status).toBe(404)
    for (const w of wheres) expect(w).toMatchObject({ projectId: P, userId: OWNER })
  })

  test.each([[OWNER], [COLLABORATOR]])('the facets (%s): the owner\'s tools, hosts, runs and sessions', async (who) => {
    signIn(who)
    const res = await call(facets, `/api/traffic/${P}/facets`, p)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ tools: ['httpx'], hosts: ['app.rbac.test'], runs: ['run-1'], sessions: ['s-1'] })
    expect(wheres).toHaveLength(4)
    for (const w of wheres) expect(w).toMatchObject({ projectId: P, userId: OWNER })
  })

  test.each([[OWNER], [COLLABORATOR]])('the export (%s): the owner\'s rows, the query on the project and its owner', async (who) => {
    signIn(who)
    const res = await call(exporter, `/api/traffic/${P}/export?format=json`, p)
    expect(res.status).toBe(200)
    const body = JSON.parse(await res.text())
    expect(body.rows.map((r: { id: string }) => r.id)).toEqual(['t-1'])
    expect(body).toMatchObject({ count: 1, truncated: false })
    expect(wheres.length).toBeGreaterThanOrEqual(1)
    for (const w of wheres) expect(w).toMatchObject({ projectId: P, userId: OWNER })
  })

  test('no query of the four reads ever names the reader', async () => {
    signIn(COLLABORATOR)
    await call(list, `/api/traffic/${P}`, p)
    await call(detail, `/api/traffic/${P}/t-1`, { ...p, id: 't-1' })
    await call(facets, `/api/traffic/${P}/facets`, p)
    await (await call(exporter, `/api/traffic/${P}/export`, p)).text()
    expect(wheres.length).toBeGreaterThanOrEqual(8)
    expect(JSON.stringify(wheres)).not.toContain(COLLABORATOR)
  })

  test('the same collaborator without Raw data: 403 on all four, no row read', async () => {
    h.shares.set(`${P}|${COLLABORATOR}`, { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
    signIn(COLLABORATOR)
    for (const [load, path, params] of [
      [list, `/api/traffic/${P}`, p], [detail, `/api/traffic/${P}/t-1`, { ...p, id: 't-1' }],
      [facets, `/api/traffic/${P}/facets`, p], [exporter, `/api/traffic/${P}/export`, p],
    ] as const) {
      const res = await call(load, path, params)
      expect(res.status).toBe(403)
    }
    expect(wheres).toEqual([])
  })
})

/**
 * Deleting captured traffic on a project shared at Read + Write (step 5.2; SH-23 write part): the
 * DELETE filters the project's rows under its owner (`trafficRows`, the tenant every ingest path
 * stamps), never the caller, so an editor at `traffic:delete` (W) removes the project's rows instead
 * of silently deleting nothing; a row of the same project stamped with someone else's id is never
 * touched. The owner deletes exactly what it deleted before. A read share stays refused.
 *
 * Real guard, can(), projectAccess() and sharing policy; the session, Prisma (sharedProjectDb) and the
 * body store are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  ...(await import('@/lib/authz/__testing__/sharedProjectDb')).sessionOf(h),
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/captureBodies', () => ({ gcOrphanBodies: async () => ({ deleted: 0 }), readCapturedBody: async () => '' }))

import '@/lib/authz/guards'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { COLLABORATOR, OWNER, SHARED_PROJECT, identityOf, resetSharedProjectDb, shareWith } from '@/lib/authz/__testing__/sharedProjectDb'

type Where = { projectId?: string; userId?: string; id?: { in: string[] }; tool?: unknown }
const ROWS = [
  { id: 't-1', projectId: SHARED_PROJECT, userId: OWNER, tool: 'httpx', reqBodyRef: 'sha-1', respBodyRef: null },
  { id: 't-2', projectId: SHARED_PROJECT, userId: OWNER, tool: 'katana', reqBodyRef: null, respBodyRef: null },
  { id: 't-3', projectId: SHARED_PROJECT, userId: COLLABORATOR, tool: 'httpx', reqBodyRef: null, respBodyRef: null },
]
let rows: typeof ROWS = []
const deletes: Where[] = []
const matches = (r: (typeof ROWS)[number], w: Where) =>
  r.projectId === w.projectId && r.userId === w.userId && (w.id === undefined || w.id.in.includes(r.id))

async function del(who: string, body: unknown): Promise<Response> {
  h.identity = identityOf(who)
  const { DELETE } = await import('./[projectId]/route')
  return DELETE(new NextRequest(`http://localhost:3000/api/traffic/${SHARED_PROJECT}`, {
    method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ projectId: SHARED_PROJECT }) })
}

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.db.policy = { enabled: true, maxLevel: 'write' }
  rows = ROWS.map(r => ({ ...r }))
  deletes.length = 0
  h.db.models.capturedHttpTransaction = {
    findMany: (args: unknown) => rows.filter(r => matches(r, (args as { where: Where }).where)),
    deleteMany: (args: unknown) => {
      const where = (args as { where: Where }).where
      deletes.push(where)
      const doomed = rows.filter(r => matches(r, where))
      rows = rows.filter(r => !doomed.includes(r))
      return { count: doomed.length }
    },
  }
  h.identity = null
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe("a collaborator's traffic delete removes the project's rows (step 5.2)", () => {
  test('by ids: the editor deletes the owner-stamped rows of the project, never a row stamped with anyone else', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write' })
    const res = await del(COLLABORATOR, { ids: ['t-1', 't-3'] })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ deleted: 1, blobsDeleted: 0 })
    expect(deletes).toEqual([{ projectId: SHARED_PROJECT, userId: OWNER, id: { in: ['t-1', 't-3'] } }])
    expect(rows.map(r => r.id)).toEqual(['t-2', 't-3'])
  })

  test('delete-all-matching: the same filter as the list, on the project and its owner', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write' })
    const res = await del(COLLABORATOR, { filter: { tool: 'httpx,katana' } })
    expect(res.status).toBe(200)
    expect((await res.json()).deleted).toBe(2)
    expect(deletes[0]).toMatchObject({ projectId: SHARED_PROJECT, userId: OWNER, tool: { in: ['httpx', 'katana'] } })
    expect(JSON.stringify(deletes)).not.toContain(COLLABORATOR)
  })

  test('owner unchanged: the same rows under its own id', async () => {
    const res = await del(OWNER, { ids: ['t-1'] })
    expect((await res.json()).deleted).toBe(1)
    expect(deletes).toEqual([{ projectId: SHARED_PROJECT, userId: OWNER, id: { in: ['t-1'] } }])
  })

  test('a read share, even with Raw data & files, is refused before any row is read', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'read', rawData: true })
    const res = await del(COLLABORATOR, { ids: ['t-1'] })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'traffic:delete' })
    expect(deletes).toEqual([])
  })
})

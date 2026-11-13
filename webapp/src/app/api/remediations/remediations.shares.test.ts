/**
 * Remediations on a shared project (step 4.8, SH-07): a read collaborator (with or without Raw data &
 * files, or a share stored as `write`, read as read while the write switch is off) and an admin
 * reaching the project by oversight read the project's remediations, the list and one by id, keyed on
 * the project; creating, editing, deleting, a block update and a batch answer 403 naming
 * `remediation:write` before anything is written. CypherFix's internal-key carve-out is not involved:
 * every request here is a browser's.
 *
 * Real guard, can(), projectAccess(), sharing policy reader and capabilities; the session and Prisma
 * (sharedProjectDb, with the project's one remediation) are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  listed: [] as unknown[],
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  ...(await import('@/lib/authz/__testing__/sharedProjectDb')).sessionOf(h),
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))

// First, so the guards bind the doubled session (the session/guards cycle, sharedProjectDb.ts).
import '@/lib/authz/guards'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearOversightMemoForTests } from '@/lib/authz/oversight'
import {
  COLLABORATOR, OVERSEER, OWNER, SHARED_PROJECT, STRANGER, identityOf, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'
import * as listRoute from './route'
import * as oneRoute from './[id]/route'
import * as blocksRoute from './[id]/blocks/route'
import * as batchRoute from './batch/route'

const REM = { id: 'rem-1', projectId: SHARED_PROJECT, title: 'rbac-remediation', description: 'd', status: 'pending' }

function req(method: string, path: string, body?: unknown): NextRequest {
  const init: { method: string; headers?: Record<string, string>; body?: string } = { method }
  if (body !== undefined) {
    init.headers = { 'content-type': 'application/json', origin: 'http://localhost:3000' }
    init.body = JSON.stringify(body)
  }
  return new NextRequest(`http://localhost:3000${path}`, init)
}
const byId = { params: Promise.resolve({ id: REM.id }) }

const READS: Array<{ route: string; call: () => Promise<Response>; expected: unknown }> = [
  { route: 'GET /api/remediations', call: () => listRoute.GET(req('GET', `/api/remediations?projectId=${SHARED_PROJECT}`)), expected: [REM] },
  { route: 'GET /api/remediations/[id]', call: () => oneRoute.GET(req('GET', `/api/remediations/${REM.id}`), byId), expected: REM },
]

const WRITES: Array<{ route: string; call: () => Promise<Response> }> = [
  { route: 'POST /api/remediations', call: () => listRoute.POST(req('POST', '/api/remediations', { projectId: SHARED_PROJECT, title: 't', description: 'd' })) },
  { route: 'PUT /api/remediations/[id]', call: () => oneRoute.PUT(req('PUT', `/api/remediations/${REM.id}`, { status: 'dismissed' }), byId) },
  { route: 'DELETE /api/remediations/[id]', call: () => oneRoute.DELETE(req('DELETE', `/api/remediations/${REM.id}`), byId) },
  { route: 'PUT /api/remediations/[id]/blocks', call: () => blocksRoute.PUT(req('PUT', `/api/remediations/${REM.id}/blocks`, { fileChanges: [] }), byId) },
  { route: 'POST /api/remediations/batch', call: () => batchRoute.POST(req('POST', '/api/remediations/batch', { projectId: SHARED_PROJECT, remediations: [{ title: 't' }] })) },
]

const READERS: Array<{ name: string; who: string; arrange: () => void }> = [
  { name: 'a read collaborator', who: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR) },
  { name: 'a read collaborator with Raw data & files', who: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR, { rawData: true }) },
  { name: 'a collaborator whose share is stored as write (read while the write switch is off)', who: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR, { access: 'write' }) },
  { name: 'an admin by oversight', who: OVERSEER, arrange: () => {} },
]

/**
 * The one write an overseer's read makes: the day's `project.oversee` audit row, in its transaction
 * (step 4.14; this double records the transaction, not what runs in it). Nothing of the project.
 */
const OVERSIGHT_AUDIT = [{ model: '$client', method: '$transaction' }]

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.listed.length = 0
  h.db.models.remediation = {
    findUnique: (args) => ((args as { where: { id: string } }).where.id === REM.id ? { ...REM } : null),
    findMany: (args) => {
      h.listed.push(args)
      return (args as { where: { projectId: string } }).where.projectId === SHARED_PROJECT ? [{ ...REM }] : []
    },
  }
  h.identity = null
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearOversightMemoForTests()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe.each(READERS)('$name reads the project\'s remediations and changes none (step 4.8)', ({ who, arrange }) => {
  test.each(READS)('$route: 200 with the project\'s rows', async ({ call, expected }) => {
    arrange()
    h.identity = identityOf(who)
    const res = await call()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual(expected)
    expect(h.db.writes).toEqual(who === OVERSEER ? OVERSIGHT_AUDIT : [])
  })

  test.each(WRITES)('$route: 403 naming remediation:write, nothing written', async ({ call }) => {
    arrange()
    h.identity = identityOf(who)
    const res = await call()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'remediation:write' })
    expect(h.db.writes).toEqual([])
  })
})

describe('who does not reach the remediations', () => {
  test('the list is read by the project only: the reader\'s id names nothing', async () => {
    shareWith(h.db, COLLABORATOR)
    h.identity = identityOf(COLLABORATOR)
    await READS[0].call()
    expect(h.listed).toEqual([expect.objectContaining({ where: { projectId: SHARED_PROJECT } })])
  })

  test('someone the project is not shared with: 404 on the list, one row and a write, nothing listed', async () => {
    h.identity = identityOf(STRANGER)
    for (const c of [READS[0], READS[1], WRITES[1]]) expect([c.route, (await c.call()).status]).toEqual([c.route, 404])
    expect(h.listed).toEqual([])
    expect(h.db.writes).toEqual([])
  })

  test('with RBAC_SHARING_ENABLED off a share gives nothing (404)', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    h.identity = identityOf(COLLABORATOR)
    expect((await READS[0].call()).status).toBe(404)
    expect((await READS[1].call()).status).toBe(404)
  })

  test('the owner still reads and edits its remediations', async () => {
    h.identity = identityOf(OWNER)
    expect((await READS[0].call()).status).toBe(200)
    expect((await WRITES[1].call()).status).toBe(200)
    expect(h.db.writes).toEqual([{ model: 'remediation', method: 'update' }])
  })
})

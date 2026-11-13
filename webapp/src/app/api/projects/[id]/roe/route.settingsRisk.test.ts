/**
 * POST / DELETE /api/projects/[id]/roe on a shared project (step 5.1b, OQ-23 default): a co-owner
 * (`roe:manage`, Manage) may replace or remove the Rules of Engagement when the review finds no
 * widening row; a replace or removal with one, and the first RoE of a project, are the owner's.
 * The changes the document makes are also judged per column (`classifyChange`), except the
 * document's own record (the client contacts it names), which goes with the document. The owner is
 * unaffected. A refusal names each key and the level it needs, and writes nothing.
 *
 * The harness is route.test.ts's (a fake Prisma whose transaction records what was written); the
 * guard is doubled with the access each case needs.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  row: null as Record<string, unknown> | null,
  access: null as unknown,
  userId: 'owner',
  calls: { revisionCreate: [] as unknown[], updateMany: [] as unknown[], schedulePause: [] as unknown[] },
  audit: vi.fn(),
  extract: vi.fn(),
}))

function fakeTx() {
  return {
    roeDocumentRevision: {
      create: async (a: unknown) => { h.calls.revisionCreate.push(a); return {} },
      findMany: async () => [],
      deleteMany: async () => ({ count: 0 }),
    },
    project: {
      updateMany: async (a: { data: Record<string, unknown> }) => {
        h.calls.updateMany.push(a)
        if (h.row) h.row = { ...h.row, ...a.data, updatedAt: new Date('2026-11-13T12:00:01.000Z') }
        return { count: 1 }
      },
      findUnique: async () => h.row,
    },
    scanSchedule: { updateMany: async (a: unknown) => { h.calls.schedulePause.push(a); return { count: 1 } } },
  }
}

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => h.row },
    scanSchedule: { findMany: async () => [] },
    userLlmProvider: { count: async () => 0 },
    userSettings: { findUnique: async () => null },
    fireteamSettingsAudit: { createMany: async () => ({ count: 0 }) },
    recordingSession: { findFirst: async () => null, update: async () => ({}) },
    $transaction: async (fn: (tx: unknown) => unknown) => fn(fakeTx()),
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))
vi.mock('@/lib/authz/guards', async () => {
  const real = await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')
  return {
    ...real,
    requirePermission: async (_req: Request, permission: string) => ({
      session: { userId: h.userId, role: 'standard' },
      principal: { id: h.userId, role: 'standard' },
      actingAs: null,
      effective: { userId: h.userId },
      permission,
      capabilities: { has: () => true },
      access: h.access,
    }),
  }
})
vi.mock('@/lib/graphWriters', () => ({
  describeScanWriters: async () => null,
  describeSecondaryScanWriters: async () => null,
}))
vi.mock('@/lib/reconPresets/server', () => ({ fetchBackendDefaults: async () => ({}) }))
vi.mock('@/lib/mcp/writeTools', () => ({
  countQueuedJobsNeedingReview: async () => ({ count: 0, jobIds: [] }),
  describeAffectedSchedules: async () => ({ count: 0, names: [] }),
}))
vi.mock('@/lib/roe/extractText', async () => {
  const actual = await vi.importActual<typeof import('@/lib/roe/extractText')>('@/lib/roe/extractText')
  return { ...actual, extractRoeText: (...a: unknown[]) => h.extract(...a) }
})

import { POST, DELETE } from './route'
import { fieldsWhere } from '@/lib/reconSettings/registry'
import { digestScopeDocument } from '@/lib/engagement'

const VERSION = '2026-11-13T12:00:00.000Z'
const DOC_SHA = 'e'.repeat(64)
const DOC_TEXT = 'Rules of Engagement: max 5 requests per second.'
const P = { id: 'proj-1', userId: 'owner' }
const run = { runScans: false, useAgent: false, exploit: false }
const ACCESS = {
  owner: { project: P, level: 'owner', toggles: { rawData: true }, via: 'owner' },
  'co-owner': { project: P, level: 'write', toggles: { rawData: true, ...run, manage: true }, via: 'share' },
}

function as(who: keyof typeof ACCESS) {
  h.access = ACCESS[who]
  h.userId = who === 'owner' ? 'owner' : 'collab'
}

function freshRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  const row: Record<string, unknown> = {}
  for (const f of fieldsWhere(() => true)) {
    row[f.key] = f.type === 'json' && typeof f.default === 'string' ? JSON.parse(f.default) : f.default
  }
  return {
    ...row, id: 'proj-1', userId: 'owner', engagementKind: 'internal', updatedAt: new Date(VERSION),
    roeDocumentData: null, roeDocumentName: '', roeDocumentMimeType: '', roeRawText: '', roeParsedJson: null,
    ...over,
  }
}

/** A project whose RoE set a 10 rps ceiling. */
const withRoe = (over: Record<string, unknown> = {}) => freshRow({
  roeGlobalMaxRps: 10, roeRawText: 'document A', roeDocumentName: 'A.pdf',
  roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 10 }, before: { roeGlobalMaxRps: 0 } },
  ...over,
})

function post(changes: Record<string, unknown>, parsedFields: Record<string, unknown> = changes) {
  const form = new FormData()
  form.append('file', new File(['%PDF-1.4 synthetic'], 'roe-B.pdf', { type: 'application/pdf' }))
  form.append('changes', JSON.stringify(changes))
  form.append('parsedFields', JSON.stringify(parsedFields))
  form.append('rowVersion', VERSION)
  form.append('bytesSha256', DOC_SHA)
  return POST(
    new NextRequest('http://localhost:3000/api/projects/proj-1/roe', { method: 'POST', body: form, headers: { host: 'localhost:3000' } }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

function del(changes: Record<string, unknown>) {
  return DELETE(
    new NextRequest('http://localhost:3000/api/projects/proj-1/roe', {
      method: 'DELETE', body: JSON.stringify({ rowVersion: VERSION, changes }),
      headers: { host: 'localhost:3000', 'content-type': 'application/json' },
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

const nothingWritten = () => {
  expect(h.calls.updateMany).toEqual([])
  expect(h.calls.revisionCreate).toEqual([])
  expect(h.calls.schedulePause).toEqual([])
  expect(h.audit).not.toHaveBeenCalled()
}

beforeEach(() => {
  vi.clearAllMocks()
  h.row = freshRow()
  as('owner')
  for (const k of Object.keys(h.calls) as (keyof typeof h.calls)[]) h.calls[k] = []
  h.extract.mockResolvedValue({
    text: DOC_TEXT, pages: 1, truncated: false, bytesSha256: DOC_SHA, textSha256: digestScopeDocument(DOC_TEXT),
  })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

describe('the owner is unaffected', () => {
  test('the owner sets the first RoE and widens it', async () => {
    expect((await post({ roeGlobalMaxRps: 5 })).status).toBe(200)
    h.row = withRoe()
    h.calls.updateMany = []
    expect((await post({ roeGlobalMaxRps: 20 })).status).toBe(200)
    expect(h.calls.updateMany).toHaveLength(1)
  })
})

describe('a co-owner (roe:manage)', () => {
  test("a project's first RoE is the owner's", async () => {
    as('co-owner')
    const res = await post({ roeGlobalMaxRps: 5 })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'roe:manage', level: 'O', error: expect.stringMatching(/first Rules of Engagement/) })
    nothingWritten()
  })

  test('a replace with narrower terms is a co-owner\'s call', async () => {
    as('co-owner')
    h.row = withRoe()
    const res = await post({ roeGlobalMaxRps: 5 })
    expect(res.status).toBe(200)
    expect((h.calls.updateMany[0] as { data: Record<string, unknown> }).data).toMatchObject({ roeGlobalMaxRps: 5, updatedById: 'collab' })
  })

  test('a replace the review finds widening needs the owner, naming the row and why', async () => {
    as('co-owner')
    h.row = withRoe()
    const res = await post({ roeGlobalMaxRps: 20 })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'forbidden', permission: 'roe:manage', level: 'O', needs: 'owner' })
    expect(body.refused).toEqual([expect.objectContaining({ key: 'roeGlobalMaxRps', needs: 'owner', reason: expect.stringMatching(/rate ceiling/) })])
    expect(body.error).toMatch(/roeGlobalMaxRps needs the project's owner/)
    nothingWritten()
  })

  test('a widening row on an ordinary column (a tool\'s rate raised) is still the owner\'s; lowering it is not', async () => {
    as('co-owner')
    h.row = withRoe({ nucleiRateLimit: 50 })
    // The document keeps the 10 rps ceiling, so only the tool's rate changes.
    const res = await post({ nucleiRateLimit: 80 }, { nucleiRateLimit: 80, roeGlobalMaxRps: 10 })
    expect(res.status).toBe(403)
    expect((await res.json()).refused).toEqual([expect.objectContaining({ key: 'nucleiRateLimit', needs: 'owner', reason: expect.stringMatching(/widens the engagement/) })])
    nothingWritten()
    expect((await post({ nucleiRateLimit: 20 }, { nucleiRateLimit: 20, roeGlobalMaxRps: 10 })).status).toBe(200)
  })

  test('a replace that makes the daily window cross midnight needs the owner, however its ends move', async () => {
    as('co-owner')
    const window = { roeTimeWindowEnabled: true, roeTimeWindowStartTime: '09:00', roeTimeWindowEndTime: '18:00' }
    // 09:00-18:00 -> 09:00-08:00: the end moves earlier, the window grows to 23 hours.
    h.row = withRoe(window)
    const endOnly = await post({ roeTimeWindowEndTime: '08:00' }, { roeTimeWindowEndTime: '08:00', roeGlobalMaxRps: 10 })
    expect(endOnly.status).toBe(403)
    expect((await endOnly.json()).refused).toEqual([expect.objectContaining({ key: 'roeTimeWindowEndTime', needs: 'owner', reason: expect.stringMatching(/window/) })])
    nothingWritten()
    // A later start and an earlier end: 17:00-10:00, overnight.
    const both = { roeTimeWindowStartTime: '17:00', roeTimeWindowEndTime: '10:00' }
    const res = await post(both, { ...both, roeGlobalMaxRps: 10 })
    expect(res.status).toBe(403)
    expect((await res.json()).refused.map((r: { key: string }) => r.key).sort()).toEqual(['roeTimeWindowEndTime', 'roeTimeWindowStartTime'])
    nothingWritten()
    // The same ends inside the window narrow it: a co-owner's.
    const inside = { roeTimeWindowStartTime: '10:00', roeTimeWindowEndTime: '17:00' }
    expect((await post(inside, { ...inside, roeGlobalMaxRps: 10 })).status).toBe(200)
  })

  test("the document's own record (the client it names) goes with the document", async () => {
    as('co-owner')
    h.row = withRoe({ roeClientName: 'Old Client Example' })
    const res = await post({ roeGlobalMaxRps: 5, roeClientName: 'Northwind Example' })
    expect(res.status).toBe(200)
    expect((h.calls.updateMany[0] as { data: Record<string, unknown> }).data).toMatchObject({ roeClientName: 'Northwind Example' })
  })

  test('a removal that drops the limits widens: the owner\'s', async () => {
    as('co-owner')
    h.row = withRoe({ roeExcludedHosts: ['prod.example.test'], roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 10, roeExcludedHosts: ['prod.example.test'] }, before: { roeGlobalMaxRps: 0, roeExcludedHosts: [] } } })
    const res = await del({ roeGlobalMaxRps: 0, roeExcludedHosts: [] })
    expect(res.status).toBe(403)
    expect((await res.json()).refused.map((r: { key: string }) => r.key).sort()).toEqual(['roeExcludedHosts', 'roeGlobalMaxRps'])
    nothingWritten()
  })

  test('the owner removes the same RoE', async () => {
    h.row = withRoe({ roeExcludedHosts: ['prod.example.test'], roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 10, roeExcludedHosts: ['prod.example.test'] }, before: { roeGlobalMaxRps: 0, roeExcludedHosts: [] } } })
    expect((await del({ roeGlobalMaxRps: 0, roeExcludedHosts: [] })).status).toBe(200)
  })

  test('no access decided: refused', async () => {
    h.access = null
    h.userId = 'collab'
    h.row = withRoe()
    expect((await post({ roeGlobalMaxRps: 5 })).status).toBe(403)
    nothingWritten()
  })
})

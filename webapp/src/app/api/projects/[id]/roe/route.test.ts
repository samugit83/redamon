/**
 * POST / DELETE /api/projects/[id]/roe: replace and remove a project's Rules of
 * Engagement. Each step of applyRoe fails closed; these walk them in order.
 *
 * The extractor is mocked (its own tests run it for real); Prisma is a fake
 * whose transaction records what was written, so "nothing was written" is an
 * assertion rather than a hope.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  row: null as Record<string, unknown> | null,
  ownerId: 'owner',
  eff: { userId: 'owner' } as unknown,
  scanBusy: null as string | null,
  secondaryBusy: null as string | null,
  schedules: [] as Array<{ id: string; label: string; nextRunAt: Date | null }>,
  revisionsAfterCreate: [] as Array<{ id: string }>,
  casCount: 1,
  jevTokens: 0,
  recording: null as { id: string } | null,
  txError: null as Error | null,
  calls: {
    revisionCreate: [] as unknown[], revisionDelete: [] as unknown[], updateMany: [] as unknown[],
    schedulePause: [] as unknown[], fireteam: [] as unknown[], recordingUpdate: [] as unknown[],
  },
  audit: vi.fn(),
  extract: vi.fn(),
}))

function fakeTx() {
  return {
    roeDocumentRevision: {
      create: async (a: unknown) => { h.calls.revisionCreate.push(a); return {} },
      findMany: async () => h.revisionsAfterCreate,
      deleteMany: async (a: unknown) => { h.calls.revisionDelete.push(a); return { count: 1 } },
    },
    project: {
      updateMany: async (a: { data: Record<string, unknown> }) => {
        h.calls.updateMany.push(a)
        if (h.casCount === 1 && h.row) h.row = { ...h.row, ...a.data, updatedAt: new Date('2026-10-14T12:00:01.000Z') }
        return { count: h.casCount }
      },
      findUnique: async () => h.row,
    },
    scanSchedule: { updateMany: async (a: unknown) => { h.calls.schedulePause.push(a); return { count: 1 } } },
  }
}

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async (args: { select?: Record<string, boolean> }) =>
        args?.select?.userId && Object.keys(args.select).length === 2
          ? (h.row ? { id: 'proj-1', userId: h.ownerId } : null)
          : h.row,
    },
    scanSchedule: { findMany: async () => h.schedules },
    userLlmProvider: { count: async () => h.jevTokens },
    userSettings: { findUnique: async () => null },
    fireteamSettingsAudit: { createMany: async (a: unknown) => { h.calls.fireteam.push(a); return { count: 1 } } },
    recordingSession: {
      findFirst: async () => h.recording,
      update: async (a: unknown) => { h.calls.recordingUpdate.push(a); return {} },
    },
    $transaction: async (fn: (tx: unknown) => unknown) => {
      if (h.txError) throw h.txError
      return fn(fakeTx())
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: async () => h.eff }
})
vi.mock('@/lib/graphWriters', () => ({
  describeScanWriters: async () => h.scanBusy,
  describeSecondaryScanWriters: async () => h.secondaryBusy,
}))
vi.mock('@/lib/reconPresets/server', () => ({ fetchBackendDefaults: async () => ({}) }))
vi.mock('@/lib/mcp/writeTools', () => ({
  countQueuedJobsNeedingReview: async () => ({ count: 2, jobIds: ['j1', 'j2'] }),
  describeAffectedSchedules: async () => ({ count: 0, names: [] }),
}))
vi.mock('@/lib/roe/extractText', async () => {
  const actual = await vi.importActual<typeof import('@/lib/roe/extractText')>('@/lib/roe/extractText')
  return { ...actual, extractRoeText: (...a: unknown[]) => h.extract(...a) }
})

import { POST, DELETE } from './route'
import { fieldsWhere } from '@/lib/reconSettings/registry'
import { digestScopeDocument } from '@/lib/engagement'

const VERSION = '2026-10-14T12:00:00.000Z'
const DOC_SHA = 'f'.repeat(64)
const DOC_TEXT = 'Rules of Engagement: max 5 requests per second.'

/** Every column at its registry default, which is what a fresh project holds. */
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

function post(opts: {
  changes: Record<string, unknown>
  parsedFields: Record<string, unknown>
  rowVersion?: string
  bytesSha256?: string
  headers?: Record<string, string>
}) {
  const form = new FormData()
  form.append('file', new File(['%PDF-1.4 synthetic'], 'roe-B.pdf', { type: 'application/pdf' }))
  form.append('changes', JSON.stringify(opts.changes))
  form.append('parsedFields', JSON.stringify(opts.parsedFields))
  form.append('rowVersion', opts.rowVersion ?? VERSION)
  form.append('bytesSha256', opts.bytesSha256 ?? DOC_SHA)
  form.append('modelUsed', 'test/model')
  return POST(
    new NextRequest('http://localhost:3000/api/projects/proj-1/roe', {
      method: 'POST', body: form, headers: { host: 'localhost:3000', ...(opts.headers ?? {}) },
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

function del(body: Record<string, unknown>) {
  return DELETE(
    new NextRequest('http://localhost:3000/api/projects/proj-1/roe', {
      method: 'DELETE', body: JSON.stringify(body),
      headers: { host: 'localhost:3000', 'content-type': 'application/json' },
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

const nothingWritten = () => {
  expect(h.calls.updateMany).toEqual([])
  expect(h.calls.revisionCreate).toEqual([])
  expect(h.calls.schedulePause).toEqual([])
}

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  h.row = freshRow()
  h.ownerId = 'owner'
  h.eff = { userId: 'owner' }
  h.scanBusy = null
  h.secondaryBusy = null
  h.schedules = []
  h.revisionsAfterCreate = []
  h.casCount = 1
  h.jevTokens = 0
  h.recording = null
  h.txError = null
  for (const k of Object.keys(h.calls) as (keyof typeof h.calls)[]) h.calls[k] = []
  h.extract.mockResolvedValue({
    text: DOC_TEXT, pages: 1, truncated: false, bytesSha256: DOC_SHA, textSha256: digestScopeDocument(DOC_TEXT),
  })
})

describe('who may call it', () => {
  test('another user gets a 404 and nothing is written (BOLA)', async () => {
    h.ownerId = 'victim'
    h.eff = { userId: 'attacker' }
    const res = await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 } })
    expect(res.status).toBe(404)
    nothingWritten()
  })

  test('a cross-origin request is 403', async () => {
    const res = await post({
      changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 },
      headers: { origin: 'http://guinea-pig.localhost:8080' },
    })
    expect(res.status).toBe(403)
    nothingWritten()
  })

  test('a deleted project is 404', async () => {
    h.row = null
    expect((await post({ changes: {}, parsedFields: {} })).status).toBe(404)
  })
})

describe('the review must still describe the project', () => {
  test('a stale rowVersion is roe_stale and writes nothing', async () => {
    const res = await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 }, rowVersion: '2026-10-14T11:00:00.000Z' })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('roe_stale')
    nothingWritten()
  })

  test('a file other than the reviewed one is refused', async () => {
    const res = await post({ changes: {}, parsedFields: {}, bytesSha256: '0'.repeat(64) })
    expect((await res.json()).code).toBe('roe_document_mismatch')
    nothingWritten()
  })

  test('confirmed changes that differ from what the server would write are stale', async () => {
    const res = await post({ changes: { roeGlobalMaxRps: 9 }, parsedFields: { roeGlobalMaxRps: 5 } })
    expect((await res.json()).code).toBe('roe_stale')
    nothingWritten()
  })

  test('a lost compare-and-swap is roe_stale, and the schedules are not paused', async () => {
    h.casCount = 0
    h.schedules = [{ id: 's1', label: 'nightly', nextRunAt: null }]
    h.row = freshRow({ roeGlobalMaxRps: 5, roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 5 }, before: { roeGlobalMaxRps: 0 } } })
    const res = await post({ changes: { roeGlobalMaxRps: 20 }, parsedFields: { roeGlobalMaxRps: 20 } })
    expect((await res.json()).code).toBe('roe_stale')
    expect(h.calls.schedulePause).toEqual([])
    expect(h.audit).not.toHaveBeenCalled()
  })
})

describe('running work', () => {
  test('a running scan is roe_busy and writes nothing', async () => {
    h.secondaryBusy = 'a GVM vulnerability scan is running'
    const res = await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 } })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'roe_busy', busy: 'a GVM vulnerability scan is running' })
    nothingWritten()
  })

  test('a busy check that cannot be answered is 503, never allowed', async () => {
    h.scanBusy = 'the scan status could not be verified'
    const res = await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 } })
    expect(res.status).toBe(503)
    nothingWritten()
  })
})

describe('what a confirmed set may contain', () => {
  test('a scope key is roe_key_not_allowed', async () => {
    const res = await post({ changes: { targetDomain: 'evil.example' }, parsedFields: {} })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'roe_key_not_allowed', keys: ['targetDomain'] })
    nothingWritten()
  })

  test('a denied key is roe_key_not_allowed', async () => {
    const res = await post({ changes: { agentLhost: '203.0.113.9' }, parsedFields: { agentLhost: '203.0.113.9' } })
    expect((await res.json()).code).toBe('roe_key_not_allowed')
    nothingWritten()
  })

  test('an unsafe value for a tighten-only switch is roe_invalid_value', async () => {
    const res = await post({ changes: { agentRequireToolConfirmation: false }, parsedFields: { agentRequireToolConfirmation: false } })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'roe_invalid_value', keys: ['agentRequireToolConfirmation'] })
    nothingWritten()
  })

  test('switching a hook onto Jev without the owner\'s token is refused by the shared guard', async () => {
    const res = await post({ changes: { ffufAiUseJev: true }, parsedFields: { ffufAiUseJev: true } })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'roe_guard_refused' })
    nothingWritten()
  })
})

describe('a third-party engagement', () => {
  const third = (over: Record<string, unknown> = {}) => freshRow({
    engagementKind: 'third_party', roeGlobalMaxRps: 5,
    roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 5 }, before: { roeGlobalMaxRps: 0 } },
    roeRawText: 'old', roeDocumentName: 'a.pdf',
    ...over,
  })

  test('a result with no ceiling is refused', async () => {
    h.row = third()
    const res = await post({ changes: { roeGlobalMaxRps: 0 }, parsedFields: { roeGlobalMaxRps: 0 } })
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('roe_ceiling_required')
    nothingWritten()
  })

  test('a widening needs an authorization first', async () => {
    h.row = third()
    const res = await post({ changes: { roeGlobalMaxRps: 20 }, parsedFields: { roeGlobalMaxRps: 20 } })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('roe_needs_authorization')
    nothingWritten()
  })

  test('a tightening goes through', async () => {
    h.row = third()
    const res = await post({ changes: { roeGlobalMaxRps: 2 }, parsedFields: { roeGlobalMaxRps: 2 } })
    expect(res.status).toBe(200)
  })
})

describe('a successful replace', () => {
  test('writes the changes, the artefacts and a server-built parse in one compare-and-swap', async () => {
    const res = await post({
      changes: { roeGlobalMaxRps: 5, roeClientName: 'Northwind Example' },
      parsedFields: { roeGlobalMaxRps: 5, roeClientName: 'Northwind Example', agentLhost: '203.0.113.9' },
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(h.calls.updateMany).toHaveLength(1)
    const call = h.calls.updateMany[0] as { where: unknown; data: Record<string, unknown> }
    expect(call.where).toEqual({ id: 'proj-1', updatedAt: new Date(VERSION) })
    expect(call.data).toMatchObject({
      roeGlobalMaxRps: 5, roeClientName: 'Northwind Example',
      roeDocumentName: 'roe-B.pdf', roeDocumentMimeType: 'application/pdf', roeRawText: DOC_TEXT, updatedById: 'owner',
    })
    expect(call.data).not.toHaveProperty('agentLhost')
    expect(call.data.roeParsedJson).toMatchObject({
      version: 2, bytesSha256: DOC_SHA, textSha256: digestScopeDocument(DOC_TEXT), modelUsed: 'test/model',
      applied: { roeGlobalMaxRps: 5, roeClientName: 'Northwind Example' },
    })
    expect(body.project).not.toHaveProperty('roeDocumentData')
    expect(body).toMatchObject({ appliesFrom: 'next-scan', queuedJobsNeedingReview: { count: 2 } })
  })

  test('a widening pauses every enabled schedule in the transaction', async () => {
    h.row = freshRow({ roeGlobalMaxRps: 5, roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 5 }, before: { roeGlobalMaxRps: 0 } } })
    h.schedules = [{ id: 's1', label: 'nightly', nextRunAt: null }, { id: 's2', label: '', nextRunAt: null }]
    const res = await post({ changes: { roeGlobalMaxRps: 20 }, parsedFields: { roeGlobalMaxRps: 20 } })
    const body = await res.json()
    expect(h.calls.schedulePause).toEqual([{ where: { id: { in: ['s1', 's2'] }, enabled: true }, data: { enabled: false } }])
    expect(body.pausedSchedules.map((s: { id: string }) => s.id)).toEqual(['s1', 's2'])
  })

  test('a narrower window pauses only the schedule whose next run falls outside it', async () => {
    h.schedules = [
      // A Wednesday 10:00 UTC and a Sunday 10:00 UTC.
      { id: 'wed', label: 'w', nextRunAt: new Date('2026-10-21T10:00:00Z') },
      { id: 'sun', label: 's', nextRunAt: new Date('2026-10-25T10:00:00Z') },
    ]
    const parsed = {
      roeGlobalMaxRps: 5, roeTimeWindowEnabled: true,
      roeTimeWindowDays: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
      roeTimeWindowStartTime: '09:00', roeTimeWindowEndTime: '18:00', roeTimeWindowTimezone: 'UTC',
    }
    const changes = Object.fromEntries(Object.entries(parsed).filter(([k, v]) => JSON.stringify(h.row![k]) !== JSON.stringify(v)))
    const res = await post({ changes, parsedFields: parsed })
    expect(res.status).toBe(200)
    expect((h.calls.schedulePause[0] as { where: { id: { in: string[] } } }).where.id.in).toEqual(['sun'])
  })

  test('the outgoing document is kept as a revision, pruned to the newest ten', async () => {
    h.row = freshRow({
      roeDocumentData: Buffer.from('old bytes'), roeDocumentName: 'A.pdf', roeDocumentMimeType: 'application/pdf',
      roeRawText: 'document A', roeParsedJson: { version: 2, applied: {}, before: {}, appliedAt: '2026-10-01T00:00:00.000Z' },
    })
    h.revisionsAfterCreate = [{ id: 'eleventh' }]
    await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 } })
    const created = (h.calls.revisionCreate[0] as { data: Record<string, unknown> }).data
    expect(created).toMatchObject({
      projectId: 'proj-1', documentName: 'A.pdf', rawText: 'document A',
      textSha256: digestScopeDocument('document A'), reason: 'replaced', supersededById: 'owner',
    })
    expect(created.bytesSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(h.calls.revisionDelete).toEqual([{ where: { id: { in: ['eleventh'] } } }])
  })

  test('the fireteam audit goes through the shared helper', async () => {
    // On by default, so the document turning it off is the change.
    await post({ changes: { fireteamEnabled: false }, parsedFields: { fireteamEnabled: false } })
    expect(h.calls.fireteam).toHaveLength(1)
    expect(JSON.stringify(h.calls.fireteam[0])).toContain('fireteamEnabled')
  })

  test('the active recording\'s scope is recomputed', async () => {
    h.recording = { id: 'rec-1' }
    const res = await post({ changes: { roeExcludedHosts: ['legacy.roe-e2e.example'] }, parsedFields: { roeExcludedHosts: ['legacy.roe-e2e.example'] } })
    expect((await res.json()).recordingScopeUpdated).toBe(true)
    expect(h.calls.recordingUpdate).toHaveLength(1)
  })

  test('an audit row names both documents and what changed', async () => {
    h.row = freshRow({ roeRawText: 'document A', roeDocumentName: 'A.pdf' })
    await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 } })
    const entry = h.audit.mock.calls.find(c => (c[0] as { action: string }).action === 'project.roe.replace')![0]
    expect(entry).toMatchObject({
      actorId: 'owner', targetId: 'proj-1',
      before: { documentName: 'A.pdf', textSha256: digestScopeDocument('document A') },
      after: { documentName: 'roe-B.pdf', textSha256: digestScopeDocument(DOC_TEXT), changed: ['roeGlobalMaxRps'] },
    })
  })
})

describe('remove', () => {
  test('clears the artefacts, restores what the document set, and keeps it as a revision', async () => {
    h.row = freshRow({
      roeGlobalMaxRps: 5, roeClientName: 'Northwind Example', roeRawText: 'document A', roeDocumentName: 'A.pdf',
      roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 5, roeClientName: 'Northwind Example' }, before: { roeGlobalMaxRps: 0 } },
    })
    const res = await del({ rowVersion: VERSION, changes: { roeGlobalMaxRps: 0, roeClientName: '' } })
    expect(res.status).toBe(200)
    const data = (h.calls.updateMany[0] as { data: Record<string, unknown> }).data
    expect(data).toMatchObject({ roeGlobalMaxRps: 0, roeClientName: '', roeRawText: '', roeDocumentName: '', roeDocumentData: null })
    expect(String(data.roeParsedJson)).toBe('Prisma.DbNull')
    expect((h.calls.revisionCreate[0] as { data: { reason: string } }).data.reason).toBe('removed')
  })

  test('a project with no document has nothing to remove', async () => {
    const res = await del({ rowVersion: VERSION, changes: {} })
    expect(res.status).toBe(404)
    expect((await res.json()).code).toBe('no_roe')
  })

  test('a malformed body is 400', async () => {
    expect((await del({ changes: {} })).status).toBe(400)
  })
})

describe('a transaction that fails names its cause', () => {
  test('the fixed sentence plus the Prisma code, never the Prisma message', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.txError = Object.assign(
      new Error('Transaction already closed: a commit cannot be executed on an expired transaction (timeout 5000 ms)'),
      { code: 'P2028', name: 'PrismaClientKnownRequestError' },
    )
    const res = await post({ changes: { roeGlobalMaxRps: 5 }, parsedFields: { roeGlobalMaxRps: 5 } })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to apply the Rules of Engagement.', code: 'P2028' })
  })
})

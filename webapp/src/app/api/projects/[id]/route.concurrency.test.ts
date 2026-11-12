/**
 * PUT /api/projects/[id]: the stale-form revert (C-2), the bookkeeping the save
 * wrote back (C-3), and the soft guardrail that could never block (B-4).
 *
 * C-2: the settings form seeds from the whole row and PUTs the whole row back,
 * and the route discarded the `updatedAt` it carried. An operator who opened the
 * form before an MCP agent applied a preset reverted all of it on the next save.
 *
 * C-3: the same whole-row body carried `id`, the three `activation*` lock
 * columns and the actor columns, so a form opened before a version activation
 * and saved during it released the lock mid-swap.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockUpdateMany = vi.fn()
const mockAudit = vi.fn()
const mockScanWriters = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
      updateMany: (...a: unknown[]) => mockUpdateMany(...a),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => mockAudit(...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: () => mockScanWriters() }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner', isAdmin: false }),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { PUT } from './route'
import { STALE_SAVE_MESSAGE } from '@/lib/projectVersion'

const LOADED_AT = '2026-09-29T10:00:00.000Z'
const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test',
  ipMode: false, domainBatchMode: false, katanaDepth: 2, graphqlAuthValue: 'old-secret',
  updatedAt: new Date(LOADED_AT),
}

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/proj-1', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockScanWriters.mockResolvedValue(null)
  mockFindUnique.mockImplementation(async () => ({ ...STORED }))
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...STORED, ...data }))
  mockUpdateMany.mockResolvedValue({ count: 1 })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('C-2: a full save is a compare-and-swap on updatedAt', () => {
  test('a body carrying updatedAt writes only while the row still has it', async () => {
    mockFindUnique.mockImplementation(async () => ({ ...STORED, katanaDepth: 5 }))
    const res = await put({ name: 'p', katanaDepth: 5, updatedAt: LOADED_AT })
    expect(res.status).toBe(200)
    expect(mockUpdate).not.toHaveBeenCalled()
    const call = mockUpdateMany.mock.calls[0][0]
    expect(call.where).toEqual({ id: 'proj-1', updatedAt: new Date(LOADED_AT) })
    expect(call.data.katanaDepth).toBe(5)
  })

  test('a stale updatedAt is a 409 that says why, and writes nothing', async () => {
    mockUpdateMany.mockResolvedValue({ count: 0 })
    const res = await put({ name: 'p', katanaDepth: 9, updatedAt: '2026-09-29T09:00:00.000Z' })
    expect(res.status).toBe(409)
    expect((await res.json()).error).toBe(STALE_SAVE_MESSAGE)
    expect(STALE_SAVE_MESSAGE).toContain('MCP agent')
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockAudit).not.toHaveBeenCalled()
  })

  test('a single-field auto-save carries no updatedAt and keeps writing unconditionally', async () => {
    const res = await put({ katanaEnabled: false })
    expect(res.status).toBe(200)
    expect(mockUpdateMany).not.toHaveBeenCalled()
    expect(mockUpdate).toHaveBeenCalled()
  })

  test('an updatedAt that is not a timestamp is refused, not ignored', async () => {
    const res = await put({ name: 'p', updatedAt: 'yesterday' })
    expect(res.status).toBe(400)
    expect(mockUpdateMany).not.toHaveBeenCalled()
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('the response carries the new updatedAt the form adopts for its next save', async () => {
    const next = new Date('2026-09-29T11:00:00.000Z')
    mockFindUnique.mockImplementation(async () => ({ ...STORED, updatedAt: next }))
    const res = await put({ name: 'p', updatedAt: LOADED_AT })
    expect((await res.json()).updatedAt).toBe(next.toISOString())
  })
})

describe('C-3: the save never writes the row bookkeeping back', () => {
  test('id, the activation lock and the actor columns are stripped', async () => {
    await put({
      name: 'p',
      id: 'proj-1',
      activationState: 'idle', activationStartedAt: null, activationVersionId: null,
      createdById: 'someone', updatedById: 'someone-else',
    })
    const data = mockUpdate.mock.calls[0][0].data
    for (const key of ['id', 'activationState', 'activationStartedAt', 'activationVersionId', 'createdById']) {
      expect(data, key).not.toHaveProperty(key)
    }
  })

  test('updatedById is the session user, never the body\'s', async () => {
    await put({ name: 'p', updatedById: 'someone-else' })
    expect(mockUpdate.mock.calls[0][0].data.updatedById).toBe('owner')
  })

  test('the upload-managed columns belong to their upload endpoints', async () => {
    // The form's copy is whatever it loaded, so writing it back reverted an
    // upload made from inside the same form.
    await put({ name: 'p', jsReconUploadedFiles: [], supplyChainSbomFile: '' })
    const data = mockUpdate.mock.calls[0][0].data
    expect(data).not.toHaveProperty('jsReconUploadedFiles')
    expect(data).not.toHaveProperty('supplyChainSbomFile')
  })

  test('the Rules of Engagement document and its derived text are never written by a save', async () => {
    // A form loaded before a RoE replace PUTs document A's text and parse back
    // over document B's bytes on its next "Update Settings".
    await put({
      name: 'p',
      roeDocumentData: 'AAAA', roeDocumentName: 'old.pdf', roeDocumentMimeType: 'application/pdf',
      roeRawText: 'document A', roeParsedJson: { applied: { targetDomain: 'evil.test' } },
    })
    const data = mockUpdate.mock.calls[0][0].data
    for (const key of ['roeDocumentData', 'roeDocumentName', 'roeDocumentMimeType', 'roeRawText', 'roeParsedJson']) {
      expect(data, key).not.toHaveProperty(key)
    }
  })

  test('a save that changes something writes a ui audit row naming what changed', async () => {
    await put({ name: 'p', katanaDepth: 7 })
    expect(mockAudit).toHaveBeenCalledTimes(1)
    const entry = mockAudit.mock.calls[0][0]
    expect(entry).toMatchObject({ action: 'project.update', source: 'ui', actorId: 'owner', targetId: 'proj-1' })
    expect(entry.after.changed).toEqual(['katanaDepth'])
    expect(entry.before).toEqual({ katanaDepth: 2 })
    expect(entry.after.values).toEqual({ katanaDepth: 7 })
  })

  test('a credential is audited by name only', async () => {
    await put({ graphqlAuthValue: 'new-secret' })
    const entry = mockAudit.mock.calls[0][0]
    expect(entry.after.changed).toEqual(['graphqlAuthValue'])
    expect(JSON.stringify(entry)).not.toContain('secret')
  })

  test('a save that changes nothing writes no audit row', async () => {
    await put({ name: 'p', katanaDepth: 2 })
    expect(mockAudit).not.toHaveBeenCalled()
  })
})

describe('B-4: the soft guardrail on a batch scope edit can actually block', () => {
  const BATCH = { ...STORED, domainBatchMode: true, domainBatchGroups: [], targetGuardrailEnabled: true }

  test('it sends the internal key and refuses on allowed === false', async () => {
    mockFindUnique.mockImplementation(async () => ({ ...BATCH }))
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true, json: async () => ({ allowed: false, reason: 'not an owned asset' }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const res = await put({ domainBatchHosts: ['a.example.com'] })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('not an owned asset')
    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(headers).toHaveProperty('x-internal-key')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('an allowed verdict lets the edit through', async () => {
    mockFindUnique.mockImplementation(async () => ({ ...BATCH }))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) }))
    const res = await put({ domainBatchHosts: ['a.example.com'] })
    expect(res.status).toBe(200)
  })
})

describe('the soft guardrail also runs on a single-domain target change and a mode flip', () => {
  const SINGLE = {
    ...STORED, domainBatchMode: false, ipMode: false, targetDomain: 'example.com',
    subdomainList: [], targetIps: [], domainBatchHosts: [], domainBatchGroups: null,
    targetGuardrailEnabled: true,
  }

  test('a new single-domain target is sent to the agent and can be refused', async () => {
    mockFindUnique.mockImplementation(async () => ({ ...SINGLE }))
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true, json: async () => ({ allowed: false, reason: 'not an owned asset' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    const res = await put({ targetDomain: 'other.example.com' })
    expect(res.status).toBe(403)
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).target_domain).toBe('other.example.com')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('entering IP mode sends the addresses', async () => {
    mockFindUnique.mockImplementation(async () => ({ ...SINGLE }))
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) })
    vi.stubGlobal('fetch', fetchMock)
    const res = await put({ ipMode: true, targetDomain: '', targetIps: ['192.0.2.10'] })
    expect(res.status).toBe(200)
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).target_ips).toEqual(['192.0.2.10'])
  })

  test('an unchanged target never calls the agent', async () => {
    mockFindUnique.mockImplementation(async () => ({ ...SINGLE }))
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    expect((await put({ targetDomain: 'example.com', katanaDepth: 3 })).status).toBe(200)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

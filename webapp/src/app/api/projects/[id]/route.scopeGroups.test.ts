/**
 * /api/projects/[id]: the derived `scopeGroups`, and the PUT's scope decisions
 * on derived scope rather than on stored records.
 *
 * Every service reads a project through this GET, so `scopeGroups` must ride on
 * every return path. A PUT compares the scope derived from the stored fields on
 * both sides, so re-saving a row written by an older writer (a legacy group
 * record, a mixed-case target) is not a scope change: no 409 while a scan runs,
 * no false entry in the activity feed, no re-cased Domain seeded.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockAudit = vi.fn()
const mockScanWriters = vi.fn()
const mockActivating = vi.fn()
const mockRefreshRecording = vi.fn()
let internal = false

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
    userSettings: { findUnique: async () => ({ mcpServers: [] }) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => mockAudit(...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: () => mockScanWriters() }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: () => mockActivating() }))
vi.mock('@/lib/recordingSession', () => ({
  refreshActiveRecordingScope: (...a: unknown[]) => mockRefreshRecording(...a),
}))
vi.mock('@/lib/userSkillAgentPayload', () => ({ userSkillsForAgent: async () => [] }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => internal, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner', isAdmin: false }),
    requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
  }
})

import { GET, PUT } from './route'

const LEGACY_BATCH = {
  id: 'p1', userId: 'owner', name: 'p', ipMode: false, domainBatchMode: true, targetDomain: '',
  subdomainList: [], targetIps: [], targetGuardrailEnabled: false,
  domainBatchHosts: ['www.acme.co.uk', 'shop.acme.co.uk'],
  // What the last-two-labels writer stored: one group under the bare suffix.
  domainBatchGroups: [{ rootDomain: 'co.uk', prefixes: ['www.acme.', 'shop.acme.'], hosts: ['www.acme.co.uk', 'shop.acme.co.uk'], wildcard: false }],
}

function get(query = '') {
  return GET(new NextRequest(`http://localhost/api/projects/p1${query}`), { params: Promise.resolve({ id: 'p1' }) })
}

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/p1', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'p1' }) },
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  internal = false
  mockScanWriters.mockResolvedValue(null)
  mockActivating.mockResolvedValue(null)
  mockFindUnique.mockImplementation(async () => ({ ...LEGACY_BATCH }))
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...LEGACY_BATCH, ...data }))
})

describe('GET returns the derived scopeGroups on every path', () => {
  const expected = [{
    scanRoot: 'acme.co.uk', orgDomain: 'acme.co.uk', mode: 'exact', includeRoot: false,
    exactHosts: ['www.acme.co.uk', 'shop.acme.co.uk'], entries: ['www.acme.co.uk', 'shop.acme.co.uk'], notes: [],
  }]

  test('a browser read: derived from the host list, never from the stored record', async () => {
    const body = await (await get()).json()
    expect(body.scopeGroups).toEqual(expected)
  })

  test('the agent read with skill content', async () => {
    internal = true
    const body = await (await get('?includeSkillContent=true')).json()
    expect(body.scopeGroups).toEqual(expected)
    expect(body.userAttackSkills).toEqual([])
  })

  test('an IP-mode project has none', async () => {
    mockFindUnique.mockResolvedValue({ ...LEGACY_BATCH, ipMode: true, domainBatchMode: false })
    expect((await (await get()).json()).scopeGroups).toEqual([])
  })
})

describe('PUT judges scope on the derived groups', () => {
  test('re-saving a legacy batch row is not a scope change: no 409, no audit entry for the record', async () => {
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk', 'shop.acme.co.uk'], katanaDepth: 3 })
    expect(res.status).toBe(200)
    // The record is rewritten in the new grouping...
    expect(mockUpdate.mock.calls[0][0].data.domainBatchGroups[0].rootDomain).toBe('acme.co.uk')
    // ...but that is not reported as a change.
    expect(mockAudit.mock.calls[0][0].after.changed).not.toContain('domainBatchGroups')
    expect((await res.json()).scopeGroups[0].scanRoot).toBe('acme.co.uk')
  })

  test('a real batch change is audited with its record', async () => {
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk', 'portal.acme.co.uk'] })
    expect(res.status).toBe(200)
    expect(mockAudit.mock.calls[0][0].after.changed).toContain('domainBatchGroups')
  })

  test('a scope write waits for a version activation', async () => {
    mockActivating.mockResolvedValue(NextResponse.json({ error: 'activation' }, { status: 409 }))
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['*.acme.co.uk'] })
    expect(res.status).toBe(409)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a save that changes no scope ignores a running activation', async () => {
    mockActivating.mockResolvedValue(NextResponse.json({ error: 'activation' }, { status: 409 }))
    expect((await put({ katanaDepth: 4 })).status).toBe(200)
  })
})

describe('PUT on a single-domain project', () => {
  const SINGLE = {
    ...LEGACY_BATCH, domainBatchMode: false, domainBatchHosts: [], domainBatchGroups: null,
    targetDomain: 'Alpha.Example.com', subdomainList: ['www.'],
  }

  test('a public-suffix target is refused with its reason', async () => {
    mockFindUnique.mockResolvedValue(SINGLE)
    const res = await put({ targetDomain: 'co.uk', subdomainList: [] })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('public suffix')
  })

  test('an unrelated partial save of a row whose stored target the rules now refuse still saves', async () => {
    mockFindUnique.mockResolvedValue({ ...SINGLE, targetDomain: 'co.uk', subdomainList: [] })
    expect((await put({ katanaDepth: 4 })).status).toBe(200)
  })

  test('a mixed-case legacy target re-saved unchanged is no scope change and keeps its spelling', async () => {
    mockFindUnique.mockResolvedValue(SINGLE)
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put({ targetDomain: 'Alpha.Example.com', subdomainList: ['www.'], katanaDepth: 4 })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).not.toHaveProperty('targetDomain')
  })

  test('a changed target is stored normalised and lower-cased', async () => {
    mockFindUnique.mockResolvedValue(SINGLE)
    const res = await put({ targetDomain: 'HTTPS://Beta.Example.com/', subdomainList: ['www.'] })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.targetDomain).toBe('beta.example.com')
  })
})

describe('PUT moves an active recording with the scope (WEB-15b)', () => {
  test('a real scope change refreshes it, from the saved row', async () => {
    const res = await put({ domainBatchHosts: ['www.acme.co.uk', 'api.other.test'] })
    expect(res.status).toBe(200)
    expect(mockRefreshRecording).toHaveBeenCalledTimes(1)
    const [, projectId, row] = mockRefreshRecording.mock.calls[0]
    expect(projectId).toBe('p1')
    expect(row.domainBatchHosts).toEqual(['www.acme.co.uk', 'api.other.test'])
  })

  test('a regroup of the same hosts does not', async () => {
    await put({ domainBatchHosts: LEGACY_BATCH.domainBatchHosts })
    expect(mockRefreshRecording).not.toHaveBeenCalled()
  })

  test('a save that touches no scope does not', async () => {
    await put({ katanaDepth: 4 })
    expect(mockRefreshRecording).not.toHaveBeenCalled()
  })
})

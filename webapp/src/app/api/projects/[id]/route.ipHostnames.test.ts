/**
 * PUT /api/projects/[id] and the hostname policy of an IP-mode project
 * ("Hostnames on target IPs", design §6.3 and §9).
 *
 * The policy is judged on the EFFECTIVE row (the stored row with the change
 * applied), so a partial save can be told "scan_all needs its confirmation" or
 * "record_filter needs an include entry" by what is stored. Any policy change is
 * a scope change: refused while a scan or an activation runs, its include
 * entries hard-guardrailed. A widening through the form only warns (D-24): the
 * PUT never pauses a schedule. A narrowing runs the out_of_policy marker after
 * the commit and returns its answer as `hostnamePolicyMarked`.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockScheduleUpdate = vi.fn()
const mockScanWriters = vi.fn()
const mockActivating = vi.fn()
const mockMark = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
    scanSchedule: { updateMany: (...a: unknown[]) => mockScheduleUpdate(...a) },
    userSettings: { findUnique: async () => ({ mcpServers: [] }) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: () => mockScanWriters() }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: () => mockActivating() }))
vi.mock('@/lib/recordingSession', () => ({ refreshActiveRecordingScope: vi.fn() }))
vi.mock('@/lib/ipHostnamePolicy', () => ({ markOutOfPolicy: (...a: unknown[]) => mockMark(...a) }))
vi.mock('@/lib/userSkillAgentPayload', () => ({ userSkillsForAgent: async () => [] }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner', isAdmin: false }),
    requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
  }
})

import { PUT } from './route'

const IP_PROJECT = {
  id: 'p1', userId: 'owner', name: 'p', ipMode: true, domainBatchMode: false, targetDomain: '',
  subdomainList: [], targetIps: ['203.0.113.0/30'], domainBatchHosts: [], domainBatchGroups: null,
  targetGuardrailEnabled: false, attackSkillConfig: null, engagementKind: 'internal',
  ipHostnameMode: 'record_only', ipHostnameInclude: [] as string[], ipHostnameExclude: [] as string[],
  ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false,
  ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
}

let stored: Record<string, unknown>

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/p1', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'p1' }) },
  )
}

const written = () => mockUpdate.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  stored = { ...IP_PROJECT }
  mockScanWriters.mockResolvedValue(null)
  mockActivating.mockResolvedValue(null)
  mockMark.mockResolvedValue(true)
  mockFindUnique.mockImplementation(async () => ({ ...stored }))
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...stored, ...data }))
})

describe('a partial PUT is judged on the stored row', () => {
  test('scan_all without the confirmation is refused', async () => {
    const res = await put({ ipHostnameMode: 'scan_all' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('ipHostnameScanAllConfirmed')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('scan_all with a confirmation already stored is accepted', async () => {
    stored = { ...IP_PROJECT, ipHostnameScanAllConfirmed: true }
    expect((await put({ ipHostnameMode: 'scan_all' })).status).toBe(200)
  })

  test('record_filter with no include entry stored or sent is refused', async () => {
    const res = await put({ ipHostnameMode: 'record_filter' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('ipHostnameInclude')
  })

  test('record_filter is accepted on the include list already stored', async () => {
    stored = { ...IP_PROJECT, ipHostnameInclude: ['*.example.com'] }
    expect((await put({ ipHostnameMode: 'record_filter' })).status).toBe(200)
  })

  test('a third-party engagement refuses scan_all even when confirmed (D-03)', async () => {
    stored = { ...IP_PROJECT, engagementKind: 'third_party' }
    const res = await put({ ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('third_party')
  })

  test('an unparsable include entry is refused with its reason', async () => {
    const res = await put({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['203.0.113.7'] })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/ipHostnameInclude: Not accepted: 203\.0\.113\.7/)
  })

  test('an unrelated partial save never re-judges the policy', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'record_filter', ipHostnameInclude: [] }
    expect((await put({ katanaDepth: 4 })).status).toBe(200)
  })
})

describe('the policy is part of the scope', () => {
  test('a policy edit is refused with 409 while a scan runs', async () => {
    mockScanWriters.mockResolvedValue('a full recon is running')
    stored = { ...IP_PROJECT, ipHostnameInclude: ['*.example.com'] }
    const res = await put({ ipHostnameMode: 'record_filter' })
    expect(res.status).toBe(409)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a policy edit waits for a version activation', async () => {
    mockActivating.mockResolvedValue(NextResponse.json({ error: 'activation' }, { status: 409 }))
    const res = await put({ ipHostnameExclude: ['old.example.com'] })
    expect(res.status).toBe(409)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a cap change is a scope change too', async () => {
    mockScanWriters.mockResolvedValue('a partial recon is running')
    expect((await put({ ipHostnameMaxScanned: 50 })).status).toBe(409)
  })

  test('the same policy in another spelling is no scope change', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.COM'] })
    expect(res.status).toBe(200)
  })

  test('the hard guardrail refuses an include entry', async () => {
    const res = await put({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', '*.agency.gov.uk'] })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('agency.gov.uk')
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('what is stored', () => {
  test('filter entries are stored as canonical tokens', async () => {
    await put({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com', 'APP.example.org.'] })
    expect(written().ipHostnameInclude).toEqual(['*.example.com', 'app.example.org'])
  })

  test('leaving scan_all resets its confirmation, even when the body does not carry it', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }
    expect((await put({ ipHostnameMode: 'record_only' })).status).toBe(200)
    expect(written().ipHostnameScanAllConfirmed).toBe(false)
  })

  test('a project leaving IP mode drops its policy', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }
    const res = await put({ ipMode: false, targetDomain: 'example.com', targetIps: [] })
    expect(res.status).toBe(200)
    expect(written()).toMatchObject({
      ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [],
      ipHostnameScanAllConfirmed: false,
    })
  })

  test('a domain project saving the form defaults is accepted', async () => {
    stored = { ...IP_PROJECT, ipMode: false, targetDomain: 'example.com', targetIps: [], ipHostnameMode: 'ip_only' }
    const res = await put({ ipHostnameMode: 'ip_only', ipHostnameInclude: [], katanaDepth: 3 })
    expect(res.status).toBe(200)
  })
})

describe('schedules and the out_of_policy marker', () => {
  test('a widening through the form never pauses a schedule (D-24)', async () => {
    stored = { ...IP_PROJECT, ipHostnameInclude: ['*.example.com'] }
    const res = await put({ ipHostnameMode: 'record_filter' })
    expect(res.status).toBe(200)
    expect(mockScheduleUpdate).not.toHaveBeenCalled()
    expect(mockMark).not.toHaveBeenCalled()
    expect(await res.json()).not.toHaveProperty('hostnamePolicyMarked')
  })

  test('a narrowing runs the marker after the save and returns its answer', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }
    const res = await put({ ipHostnameMode: 'record_only' })
    expect(res.status).toBe(200)
    expect((await res.json()).hostnamePolicyMarked).toBe(true)
    expect(mockMark).toHaveBeenCalledTimes(1)
    const [projectId, userId, policy] = mockMark.mock.calls[0]
    expect([projectId, userId, policy.ipHostnameMode]).toEqual(['p1', 'owner', 'record_only'])
    expect(mockUpdate.mock.invocationCallOrder[0]).toBeLessThan(mockMark.mock.invocationCallOrder[0])
  })

  test('a marker that throws answers false and the save stands', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }
    mockMark.mockRejectedValue(new Error('neo4j down'))
    const res = await put({ ipHostnameMode: 'record_only' })
    expect(res.status).toBe(200)
    expect((await res.json()).hostnamePolicyMarked).toBe(false)
    expect(mockUpdate).toHaveBeenCalledTimes(1)
  })

  test('removing an include entry is a narrowing, adding one is not', async () => {
    stored = { ...IP_PROJECT, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', 'app.example.org'] }
    await put({ ipHostnameInclude: ['*.example.com'] })
    expect(mockMark).toHaveBeenCalledTimes(1)
    vi.clearAllMocks()
    mockMark.mockResolvedValue(true)
    mockScanWriters.mockResolvedValue(null)
    mockActivating.mockResolvedValue(null)
    await put({ ipHostnameInclude: ['*.example.com', 'app.example.org', '*.example.net'] })
    expect(mockMark).not.toHaveBeenCalled()
  })
})

/**
 * PUT /api/projects/[id]: a collaborator's save is judged column by column against their level
 * (step 5.1b; SH-08, SH-28, OQ-23) by `classifyChange` (lib/authz/settingsRisk.ts). An editor
 * (Write) changes ordinary settings and tightens a safety gate; loosening one needs Manage, plus
 * Exploitation & shells for the agent's approval, tunnel and Kali switches; narrowing scope needs
 * Manage, widening it the owner; a secret is the owner's. A refusal is a 403 naming each key and the
 * level it needs, before anything is written or the guardrail asks the agent. The owner's save does
 * not read or decide anything new.
 *
 * The guard is doubled with the access each case needs (the real requireAlso decides on it); the
 * level table is the real `meetsLevel`.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  stored: {} as Record<string, unknown>,
  access: null as unknown,
  userId: 'owner',
  findUnique: vi.fn(),
  update: vi.fn(),
  updateMany: vi.fn(),
  audit: vi.fn(),
  scanWriters: vi.fn(),
  refreshRecording: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      update: (...a: unknown[]) => h.update(...a),
      updateMany: (...a: unknown[]) => h.updateMany(...a),
    },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: () => h.scanWriters() }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/graphSeedDomains', async () => {
  const actual = await vi.importActual<typeof import('@/lib/graphSeedDomains')>('@/lib/graphSeedDomains')
  return { ...actual, seedProjectDomains: async () => undefined }
})
vi.mock('@/lib/recordingSession', () => ({ refreshActiveRecordingScope: (...a: unknown[]) => h.refreshRecording(...a) }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
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

import { PUT } from './route'

const P = { id: 'proj-1', userId: 'owner' }
const OWNER = { project: P, level: 'owner', toggles: { rawData: true }, via: 'owner' }
const run = { runScans: false, useAgent: false, exploit: false }
const EDITOR = { project: P, level: 'write', toggles: { rawData: true, ...run, manage: false }, via: 'share' }
const CO_OWNER = { project: P, level: 'write', toggles: { rawData: true, ...run, manage: true }, via: 'share' }

const LOADED_AT = '2026-11-13T10:00:00.000Z'
const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test', subdomainList: ['www'],
  ipMode: false, domainBatchMode: false, domainBatchHosts: [], domainBatchGroups: null,
  targetIps: [], targetGuardrailEnabled: true, engagementKind: 'internal',
  ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnamePassiveExpand: true,
  ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
  agentRequireToolConfirmation: true, jsReconValidateKeys: false, naabuRateLimit: 100,
  httpxCustomHeaders: ['X-Api-Key: rbac-fake-header-0001'],
  roeTimeWindowEnabled: false, roeTimeWindowDays: ['mon'],
  attackSkillConfig: null, updatedAt: new Date(LOADED_AT),
}

function as(who: 'owner' | 'editor' | 'co-owner' | 'nobody') {
  h.access = { owner: OWNER, editor: EDITOR, 'co-owner': CO_OWNER, nobody: null }[who]
  h.userId = who === 'owner' ? 'owner' : 'collab'
}

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/proj-1', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

const fetchMock = vi.fn()
/** The selects the route read the project with. */
const selects = (): Array<Record<string, unknown>> =>
  h.findUnique.mock.calls.map(([a]) => ((a as { select?: Record<string, unknown> })?.select ?? {}))
const wrote = (): boolean => h.update.mock.calls.length + h.updateMany.mock.calls.length > 0

beforeEach(() => {
  vi.clearAllMocks()
  h.stored = { ...STORED }
  as('owner')
  h.scanWriters.mockResolvedValue(null)
  h.findUnique.mockImplementation(async () => ({ ...h.stored }))
  h.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...h.stored, ...data }))
  h.updateMany.mockResolvedValue({ count: 1 })
  fetchMock.mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) })
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the owner is unaffected', () => {
  test('owner unchanged: a loosened gate and a changed secret save with no new read or decision', async () => {
    const res = await put({ agentRequireToolConfirmation: false, httpxCustomHeaders: [] })
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toMatchObject({ agentRequireToolConfirmation: false, httpxCustomHeaders: [], updatedById: 'owner' })
    // No read of the window switch: the classification never ran.
    expect(selects().some(s => 'roeTimeWindowEnabled' in s)).toBe(false)
  })

  test('the owner widens the target through the same save as before', async () => {
    const res = await put({ targetDomain: 'other.example.test' })
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('an editor (Read + Write)', () => {
  test('an ordinary change saves', async () => {
    as('editor')
    const res = await put({ naabuRateLimit: 50 })
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toMatchObject({ naabuRateLimit: 50 })
  })

  test('an editor cannot loosen the dangerous-tool confirmation: 403 naming the key and the level, nothing written', async () => {
    as('editor')
    const res = await put({ agentRequireToolConfirmation: false })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'forbidden', permission: 'project:settings', level: 'M', needs: 'manage+exploit' })
    expect(body.refused).toEqual([
      { key: 'agentRequireToolConfirmation', needs: 'manage+exploit', levels: ['M', 'W+X'], reason: expect.stringMatching(/safety gate/) },
    ])
    expect(body.error).toMatch(/agentRequireToolConfirmation needs Manage and Exploitation & shells/)
    expect(wrote()).toBe(false)
    expect(h.audit).not.toHaveBeenCalled()
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] settings_refused .*keys=agentRequireToolConfirmation/))
  })

  test('tightening a gate in a single-field auto-save is an editor\'s call', async () => {
    as('editor')
    h.stored = { ...STORED, agentRequireToolConfirmation: false }
    const res = await put({ agentRequireToolConfirmation: true })
    expect(res.status).toBe(200)
  })

  test('a whole-form save with every gate, scope and secret sent back unchanged saves', async () => {
    as('editor')
    const { updatedAt: _u, ...row } = STORED
    const res = await put({ ...row, createdAt: '2026-01-01T00:00:00.000Z', naabuRateLimit: 7, updatedAt: LOADED_AT })
    expect(res.status).toBe(200)
    expect(h.updateMany.mock.calls[0][0].data).toMatchObject({ naabuRateLimit: 7 })
  })

  test("the owner's secret header list needs the owner", async () => {
    as('editor')
    const res = await put({ httpxCustomHeaders: [] })
    expect(res.status).toBe(403)
    expect((await res.json()).refused).toEqual([expect.objectContaining({ key: 'httpxCustomHeaders', needs: 'owner', levels: ['O'] })])
    expect(wrote()).toBe(false)
  })

  test('who the target belongs to stays the owner\'s', async () => {
    as('co-owner')
    const res = await put({ engagementKind: 'third_party' })
    expect(res.status).toBe(403)
    expect((await res.json()).refused).toEqual([expect.objectContaining({ key: 'engagementKind', needs: 'owner' })])
  })
})

describe('a co-owner (Manage)', () => {
  test('widening the target needs the owner, refused before the guardrail asks the agent', async () => {
    as('co-owner')
    const res = await put({ targetDomain: 'other.example.test' })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body).toMatchObject({ level: 'O', needs: 'owner' })
    expect(body.refused).toEqual([expect.objectContaining({ key: 'targetDomain', needs: 'owner', reason: expect.stringMatching(/widens the scope/) })])
    expect(fetchMock).not.toHaveBeenCalled()
    expect(h.scanWriters).not.toHaveBeenCalled()
    expect(wrote()).toBe(false)
  })

  test('narrowing the subdomain list is a co-owner\'s call', async () => {
    as('co-owner')
    h.stored = { ...STORED, subdomainList: ['www', 'api'] }
    const res = await put({ subdomainList: ['www'] })
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toMatchObject({ subdomainList: ['www'] })
  })

  test('the same narrowing is refused to an editor, naming Manage', async () => {
    as('editor')
    h.stored = { ...STORED, subdomainList: ['www', 'api'] }
    const res = await put({ subdomainList: ['www'] })
    expect(res.status).toBe(403)
    expect((await res.json())).toMatchObject({ level: 'M', refused: [expect.objectContaining({ key: 'subdomainList', needs: 'manage' })] })
  })

  test('emptying the subdomain list scans every subdomain: the owner\'s, nothing written', async () => {
    // Single-domain mode reads an empty list as `*.example.test` (scopeGroups.ts), wider than `www`.
    for (const subdomainList of [[], ['.']]) {
      as('co-owner')
      vi.clearAllMocks()
      const res = await put({ subdomainList })
      expect(res.status, JSON.stringify(subdomainList)).toBe(403)
      expect(await res.json()).toMatchObject({ level: 'O', refused: [expect.objectContaining({ key: 'subdomainList', needs: 'owner' })] })
      expect(wrote()).toBe(false)
    }
    expect(selects().some(s => s.subdomainList === true && s.targetDomain === true)).toBe(true)
  })

  test('a co-owner loosening an approval gate needs Exploitation (off for every share until step 5.6)', async () => {
    as('co-owner')
    const res = await put({ agentRequireToolConfirmation: false })
    expect(res.status).toBe(403)
    expect((await res.json()).refused).toEqual([expect.objectContaining({ needs: 'manage+exploit' })])
  })

  test('the window switch is read with the change: a day added while the window is on needs the owner', async () => {
    as('co-owner')
    h.stored = { ...STORED, roeTimeWindowEnabled: true }
    const res = await put({ roeTimeWindowDays: ['mon', 'sun'] })
    expect(res.status).toBe(403)
    expect((await res.json()).refused).toEqual([expect.objectContaining({ key: 'roeTimeWindowDays', needs: 'owner' })])
    expect(selects().some(s => s.roeTimeWindowEnabled === true && s.roeTimeWindowDays === true)).toBe(true)
  })

  test('the window\'s hours are judged together: 09:00-18:00 -> 09:00-08:00 crosses midnight and needs the owner', async () => {
    as('co-owner')
    h.stored = { ...STORED, roeTimeWindowEnabled: true, roeTimeWindowStartTime: '09:00', roeTimeWindowEndTime: '18:00' }
    const res = await put({ roeTimeWindowEndTime: '08:00' })
    expect(res.status).toBe(403)
    expect((await res.json()).refused).toEqual([expect.objectContaining({ key: 'roeTimeWindowEndTime', needs: 'owner' })])
    expect(wrote()).toBe(false)
  })

  test('a later start with an earlier end (17:00-10:00) is an overnight window: the owner\'s', async () => {
    as('co-owner')
    h.stored = { ...STORED, roeTimeWindowEnabled: true, roeTimeWindowStartTime: '09:00', roeTimeWindowEndTime: '18:00' }
    const res = await put({ roeTimeWindowStartTime: '17:00', roeTimeWindowEndTime: '10:00' })
    expect(res.status).toBe(403)
    expect((await res.json()).refused.map((r: { key: string }) => r.key)).toEqual(['roeTimeWindowEndTime', 'roeTimeWindowStartTime'])
    expect(wrote()).toBe(false)
    expect((await put({ roeTimeWindowStartTime: '10:00', roeTimeWindowEndTime: '17:00' })).status).toBe(200)
  })

  test('an end time saved alone is judged against the stored start, which the route reads', async () => {
    as('co-owner')
    // 07:00-08:00 -> 07:00-06:00 is 23 hours; against the reader default 09:00 it would look narrower.
    h.stored = { ...STORED, roeTimeWindowEnabled: true, roeTimeWindowStartTime: '07:00', roeTimeWindowEndTime: '08:00' }
    const res = await put({ roeTimeWindowEndTime: '06:00' })
    expect(res.status).toBe(403)
    expect(selects().some(s => s.roeTimeWindowEndTime === true && s.roeTimeWindowStartTime === true)).toBe(true)
  })

  test('the same day added while the window is off widens nothing', async () => {
    as('co-owner')
    const res = await put({ roeTimeWindowDays: ['mon', 'sun'] })
    expect(res.status).toBe(200)
  })
})

describe('what the caller asked, not what the server derives', () => {
  test('a leftover hostname policy and batch list the server clears are not the editor\'s change', async () => {
    as('editor')
    h.stored = { ...STORED, ipHostnameExclude: ['x.example.test'], ipHostnameMaxScanned: 50, domainBatchHosts: ['a.example.test'] }
    const res = await put({ naabuRateLimit: 7 })
    expect(res.status).toBe(200)
    const data = h.update.mock.calls[0][0].data
    expect(data).toMatchObject({ naabuRateLimit: 7, ipHostnameExclude: [], ipHostnameMaxScanned: 100, domainBatchHosts: [] })
  })

  test('a client-sent batch grouping is never the caller\'s change (the server drops it)', async () => {
    as('editor')
    const res = await put({ domainBatchGroups: [{ rootDomain: 'evil.test', prefixes: ['*'], hosts: [], wildcard: true }], naabuRateLimit: 7 })
    expect(res.status).toBe(200)
  })

  test('a legacy target spelling sent back unchanged is no change', async () => {
    as('editor')
    h.stored = { ...STORED, targetDomain: 'Example.test' }
    const res = await put({ targetDomain: 'Example.test', naabuRateLimit: 7 })
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).not.toHaveProperty('targetDomain')
  })
})

describe('fail closed', () => {
  test('a context with no access decided changes nothing', async () => {
    as('nobody')
    const res = await put({ naabuRateLimit: 7 })
    expect(res.status).toBe(403)
    expect((await res.json())).toMatchObject({ needs: 'write', refused: [expect.objectContaining({ key: 'naabuRateLimit' })] })
    expect(wrote()).toBe(false)
  })

  test('a project read back as missing judges every key as changed', async () => {
    as('editor')
    h.findUnique.mockImplementation(async (a: { select?: Record<string, unknown> }) =>
      (a?.select && 'roeTimeWindowEnabled' in a.select ? null : { ...STORED }))
    const res = await put({ agentRequireToolConfirmation: true })
    // Not stored: from undefined to true is a change; tightening is still an editor's.
    expect(res.status).toBe(200)
    const refused = await put({ httpxCustomHeaders: ['X-Api-Key: rbac-fake-header-0001'] })
    expect(refused.status).toBe(403)
  })
})

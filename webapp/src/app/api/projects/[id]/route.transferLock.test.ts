/**
 * PUT /api/projects/[id] while the project's ownership is being transferred (step 5.12; SH-15, DV-15):
 * the transfer holds the project lock (`activationState: 'transferring'`) and clears the settings that
 * name the old owner's own providers, templates and token, so a save landing meanwhile could write one
 * back. The save reads the lock from the row it already reads, and answers 409
 * `project_transfer_in_progress` before anything is written, whoever saves. An activation never refused
 * a save and still does not; a stale transfer lock (a crashed copy) refuses nothing.
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


describe('a settings save while the project changes owner (step 5.12)', () => {
  test.each(['owner', 'co-owner', 'editor'] as const)('%s: refused with 409 project_transfer_in_progress, nothing written', async (who) => {
    as(who)
    h.stored = { ...STORED, activationState: 'transferring', activationStartedAt: new Date() }
    const res = await put({ naabuRateLimit: 50 })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'project_transfer_in_progress', transferInProgress: true })
    expect(wrote()).toBe(false)
    expect(h.audit).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the lock is read from the row the save already reads (no second read)', async () => {
    h.stored = { ...STORED, activationState: 'transferring', activationStartedAt: new Date() }
    await put({ naabuRateLimit: 50 })
    expect(h.findUnique).toHaveBeenCalledTimes(1)
    expect(selects()[0]).toMatchObject({ activationState: true, activationStartedAt: true })
  })

  test('an idle project, an activation in progress, or a stale transfer lock save as before', async () => {
    for (const state of [
      { activationState: 'idle', activationStartedAt: null },
      { activationState: 'activating', activationStartedAt: new Date() },
      { activationState: 'transferring', activationStartedAt: new Date(Date.now() - 16 * 60 * 1000) },
    ]) {
      vi.clearAllMocks()
      h.stored = { ...STORED, ...state }
      h.findUnique.mockImplementation(async () => ({ ...h.stored }))
      h.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...h.stored, ...data }))
      const res = await put({ naabuRateLimit: 50 })
      expect([state.activationState, res.status]).toEqual([state.activationState, 200])
      expect(wrote()).toBe(true)
    }
  })
})

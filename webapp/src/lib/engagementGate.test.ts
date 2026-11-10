/**
 * The manual start routes' engagement gate (R-11): it must refuse exactly what
 * the full start refuses, with the same status and message, and fail closed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  countAuthorizations: vi.fn(),
  orchestratorFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    engagementAuthorization: {
      count: (...a: unknown[]) => h.countAuthorizations(...a),
      findFirst: async () => null,
    },
  },
}))
// The rest is startFullScan's I/O, mocked only so the parity test can run the
// real full start next to the gate.
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: async () => false }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/scanRetention', () => ({ applyRetentionSafe: async () => null }))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  prepareVersionsForFullScan: async () => ({
    currentVersion: { id: 'v1', seq: 1, label: 'Scan 1' }, frozenVersionId: null, frozenNodeCount: 0,
  }),
  rollbackPreparedVersions: async () => true,
  createScanJob: async () => ({ id: 'job1' }),
}))

import { assertEngagementStartable } from './engagementGate'
import { startFullScan } from './startFullScan'

const project = (over: Record<string, unknown> = {}) => ({
  id: 'p1', userId: 'owner', targetDomain: 'example.com', ipMode: false, targetIps: [],
  engagementKind: 'third_party', roeGlobalMaxRps: 3, ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.findProject.mockResolvedValue(project())
  h.countAuthorizations.mockResolvedValue(1)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'starting' }) })
})

describe('a startable engagement passes', () => {
  test('a third-party engagement with a ceiling and an authorization record', async () => {
    expect(await assertEngagementStartable('p1')).toBeNull()
  })

  test('an internal project, even with no ceiling and no record', async () => {
    h.findProject.mockResolvedValue(project({ engagementKind: 'internal', roeGlobalMaxRps: 0 }))
    h.countAuthorizations.mockResolvedValue(0)
    expect(await assertEngagementStartable('p1')).toBeNull()
  })
})

describe('a blocked engagement is refused exactly as the full start refuses it', () => {
  const cases: [string, Record<string, unknown>, number][] = [
    ['no rate ceiling', { roeGlobalMaxRps: 0 }, 1],
    ['no authorization record', {}, 0],
    ['neither', { roeGlobalMaxRps: 0 }, 0],
  ]

  test.each(cases)('%s', async (_name, over, authorizations) => {
    h.findProject.mockResolvedValue(project(over))
    h.countAuthorizations.mockResolvedValue(authorizations)

    const refused = await assertEngagementStartable('p1')
    expect(refused).not.toBeNull()

    const full = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(full.ok).toBe(false)
    if (full.ok) return
    expect(refused!.status).toBe(full.status)
    expect(await refused!.json()).toEqual({ error: full.error })
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('the message names every blocker', async () => {
    h.findProject.mockResolvedValue(project({ roeGlobalMaxRps: 0 }))
    h.countAuthorizations.mockResolvedValue(0)
    const { error } = await (await assertEngagementStartable('p1'))!.json()
    expect(error).toContain('roeGlobalMaxRps is 0')
    expect(error).toContain('No authorization record')
  })
})

describe('it fails closed', () => {
  beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })

  test('an authorization set it cannot count blocks a third-party engagement', async () => {
    h.countAuthorizations.mockRejectedValue(new Error('connection reset'))
    const refused = await assertEngagementStartable('p1')
    expect(refused?.status).toBe(422)
    expect((await refused!.json()).error).toContain('No authorization record')
  })

  test('a project it cannot read throws, so the route answers 500 and starts nothing', async () => {
    h.findProject.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(assertEngagementStartable('p1')).rejects.toThrow('db down')
  })
})

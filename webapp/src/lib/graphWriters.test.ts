/**
 * Scan Timeline — "who is writing the live graph?" (Section 4A.3).
 *
 * This is the check that stands between a version activation and a corrupted
 * scan/agent run, so its failure mode matters as much as its happy path: an
 * unreachable orchestrator must read as BUSY, never as idle.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const prismaMock = vi.hoisted(() => ({
  conversation: { findFirst: vi.fn() },
  triageRun: { findMany: vi.fn(), updateMany: vi.fn() },
}))
const fetchMock = vi.hoisted(() => vi.fn())

vi.mock('@/lib/prisma', () => ({ default: prismaMock }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => fetchMock(...a) }))

import { describeLiveGraphWriters, describeSecondaryScanWriters } from './graphWriters'

const okJson = (body: unknown) => ({ ok: true, json: async () => body })

beforeEach(() => {
  vi.clearAllMocks()
  prismaMock.conversation.findFirst.mockResolvedValue(null)
  prismaMock.triageRun.findMany.mockResolvedValue([])
  prismaMock.triageRun.updateMany.mockResolvedValue({ count: 0 })
  // Run-keyed endpoints answer with a run LIST; project-level ones with a status.
  fetchMock.mockImplementation(async (url: string) =>
    url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'idle' }))
})

describe('describeLiveGraphWriters', () => {
  test('idle project → null', async () => {
    expect(await describeLiveGraphWriters('p1')).toBeNull()
  })

  test('a live triage run blocks: it publishes onto the graph at the end', async () => {
    prismaMock.triageRun.findMany.mockResolvedValue([
      { id: 'r1', status: 'running', startedAt: new Date(), heartbeatAt: new Date(),
        actorUserId: 'u1', model: 'm' },
    ])
    expect(await describeLiveGraphWriters('p1')).toBe('a triage run is in progress')
  })

  test('a run whose agent died does NOT block, and is marked failed', async () => {
    const old = new Date(Date.now() - 60 * 60 * 1000)
    prismaMock.triageRun.findMany.mockResolvedValue([
      { id: 'r1', status: 'running', startedAt: old, heartbeatAt: old,
        actorUserId: 'u1', model: 'm' },
    ])
    expect(await describeLiveGraphWriters('p1')).toBeNull()
    expect(prismaMock.triageRun.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ errorClass: 'agent_lost' }) })
    )
  })

  test('an unreadable triage-run state reads as busy, never as idle', async () => {
    prismaMock.triageRun.findMany.mockRejectedValue(new Error('db down'))
    expect(await describeLiveGraphWriters('p1')).toMatch(/triage run state could not be verified/)
  })

  test('a running agent session blocks, without even asking the orchestrator', async () => {
    prismaMock.conversation.findFirst.mockResolvedValue({ id: 'c1' })
    expect(await describeLiveGraphWriters('p1')).toBe('an agent session is running')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test.each(['running', 'starting', 'paused', 'stopping'])('recon status %s blocks', async status => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/all') ? okJson({ runs: [] }) : okJson({ status }))
    expect(await describeLiveGraphWriters('p1')).toBe('a full recon scan is running')
  })

  test.each(['idle', 'completed', 'error'])('recon status %s does not block', async status => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/all') ? okJson({ runs: [] }) : okJson({ status }))
    expect(await describeLiveGraphWriters('p1')).toBeNull()
  })

  test('an active partial recon run blocks', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/partial/all')
        ? okJson({ runs: [{ status: 'completed' }, { status: 'running' }] })
        : url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'idle' }))
    expect(await describeLiveGraphWriters('p1')).toBe('a partial recon run is active')
  })

  test('finished partial runs do not block', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/partial/all')
        ? okJson({ runs: [{ status: 'completed' }, { status: 'error' }] })
        : url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'idle' }))
    expect(await describeLiveGraphWriters('p1')).toBeNull()
  })

  test('FAIL CLOSED: an unreachable orchestrator reads as busy, not idle', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'))
    expect(await describeLiveGraphWriters('p1')).toMatch(/could not be verified/)
  })

  test('FAIL CLOSED: a non-OK status response reads as busy', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/partial/all') ? okJson({ runs: [] }) : { ok: false, json: async () => ({}) })
    expect(await describeLiveGraphWriters('p1')).toMatch(/scan status could not be verified/)
  })

  test('FAIL CLOSED: an unreadable agent-session state reads as busy', async () => {
    prismaMock.conversation.findFirst.mockRejectedValue(new Error('db down'))
    expect(await describeLiveGraphWriters('p1')).toMatch(/agent session state could not be verified/)
  })

  // GVM / GitHub-secret / TruffleHog also write finding nodes into the live graph,
  // so activation must wait for them too (they were the alignment gap this fixes).
  const secondary = (over: { gvm?: string; github?: string; trufflehog?: string }) =>
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/partial/all')) return okJson({ runs: [] })
      if (url.includes('/gvm/')) return okJson({ status: over.gvm ?? 'idle' })
      if (url.includes('/github-hunt/')) return okJson({ status: over.github ?? 'idle' })
      // Run-keyed: a run LIST, not a project-level status.
      if (url.includes('/trufflehog/')) {
        return okJson({ runs: over.trufflehog ? [{ status: over.trufflehog }] : [] })
      }
      if (url.includes('/all')) return okJson({ runs: [] })
      return okJson({ status: 'idle' }) // full recon
    })

  test.each(['running', 'starting', 'paused', 'stopping'])('a GVM scan (%s) blocks', async status => {
    secondary({ gvm: status })
    expect(await describeLiveGraphWriters('p1')).toBe('a GVM vulnerability scan is running')
  })

  test('a running GitHub Secret Hunt blocks', async () => {
    secondary({ github: 'running' })
    expect(await describeLiveGraphWriters('p1')).toBe('a GitHub Secret Hunt is running')
  })

  test('a running Secret Multiscanner scan blocks', async () => {
    secondary({ trufflehog: 'running' })
    expect(await describeLiveGraphWriters('p1')).toBe('a Secret Multiscanner scan is running')
  })

  test.each(['idle', 'completed', 'error'])('a finished secondary scan (%s) does not block', async status => {
    secondary({ gvm: status, github: status, trufflehog: status })
    expect(await describeLiveGraphWriters('p1')).toBeNull()
  })

  test('FAIL CLOSED: an unverifiable secondary status reads as busy', async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/partial/all')) return okJson({ runs: [] })
      if (url.includes('/gvm/')) return { ok: false, json: async () => ({}) }
      return okJson({ status: 'idle' })
    })
    expect(await describeLiveGraphWriters('p1')).toMatch(/could not be verified/)
  })

  test('EFFICIENCY: a running full recon short-circuits before the secondary checks', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'running' }))
    expect(await describeLiveGraphWriters('p1')).toBe('a full recon scan is running')
    // The GVM/GitHub/TruffleHog status endpoints must not have been polled at all.
    const polled = fetchMock.mock.calls.map(c => String(c[0]))
    expect(polled.some(u => u.includes('/gvm/') || u.includes('/github-hunt/') || u.includes('/trufflehog/'))).toBe(false)
  })
})

// The secondary subset in isolation (used only by activation).
describe('describeSecondaryScanWriters', () => {
  test('everything idle → null', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'idle' }))
    expect(await describeSecondaryScanWriters('p1')).toBeNull()
  })

  test('any active Secret Multiscanner RUN blocks', async () => {
    // Read from /all, not a project-level status: with several sources running
    // in parallel a single status describes one of them, and activation would
    // rebuild the graph out from under the rest.
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/trufflehog/')
        ? okJson({ runs: [{ status: 'completed' }, { status: 'running' }] })
        : url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'idle' }))
    expect(await describeSecondaryScanWriters('p1')).toBe('a Secret Multiscanner scan is running')
  })

  test('Secret Multiscanner runs that all finished do not block', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/trufflehog/')
        ? okJson({ runs: [{ status: 'completed' }, { status: 'error' }] })
        : url.includes('/all') ? okJson({ runs: [] }) : okJson({ status: 'idle' }))
    expect(await describeSecondaryScanWriters('p1')).toBeNull()
  })

  test('Secret Multiscanner is polled run-keyed, never project-level', async () => {
    await describeSecondaryScanWriters('p1')
    const polled = fetchMock.mock.calls.map(c => String(c[0])).filter(u => u.includes('/trufflehog/'))
    expect(polled).toHaveLength(1)
    expect(polled[0]).toMatch(/\/trufflehog\/p1\/all$/)
  })

  test('a 200 response with no status field is treated as idle, not busy', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url.includes('/all') ? okJson({ runs: [] }) : okJson({}))
    expect(await describeSecondaryScanWriters('p1')).toBeNull()
  })

  test('FAIL CLOSED: a thrown fetch reads as busy', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'))
    expect(await describeSecondaryScanWriters('p1')).toMatch(/could not be verified/)
  })
})

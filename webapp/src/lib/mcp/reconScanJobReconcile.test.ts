/**
 * S-17: a full recon an MCP agent stops (or simply watches end) is recorded in
 * its ScanJob without anyone opening the project in a browser.
 *
 * The webapp closes a full recon's ScanJob when a status read sees the scan
 * end: the UI's status route mirrors a terminal orchestrator status onto the
 * open row (reconcileScanJobStatus). get_recon_status read the same
 * orchestrator status and the same table but never closed the row, so after an
 * MCP stop the run stayed `running` while the tool itself answered idle, and
 * its own `lastRun` contradicted it.
 *
 * The ScanJob table is an in-memory list here, so each test reads the row the
 * real reconcile wrote, not the call it made.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

interface JobRow {
  id: string
  projectId: string
  kind: string
  runId: string
  status: string
  versionId: string | null
  startedAt: Date | null
  finishedAt: Date | null
  createdAt: Date
  trigger: string
  mode: string | null
  nodeCount: number | null
  degradedSources?: number | null
}

const h = vi.hoisted(() => ({
  jobs: [] as JobRow[],
  orchestratorFetch: vi.fn(),
  degradedSources: vi.fn(),
  audit: vi.fn(),
}))

function matches(row: JobRow, where: Record<string, unknown>): boolean {
  for (const [key, want] of Object.entries(where)) {
    const have = (row as unknown as Record<string, unknown>)[key]
    if (want && typeof want === 'object' && 'in' in want) {
      if (!(want as { in: unknown[] }).in.includes(have)) return false
    } else if (have !== want) {
      return false
    }
  }
  return true
}

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => ({ id: 'p1', userId: 'owner' }) },
    scanVersion: { findUnique: async () => ({ nodeCount: 42 }) },
    scanJob: {
      findFirst: async ({ where }: { where: Record<string, unknown> }) =>
        [...h.jobs]
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
          .find(r => matches(r, where)) ?? null,
      update: async ({ where, data }: { where: { id: string }; data: Partial<JobRow> }) => {
        const row = h.jobs.find(r => r.id === where.id)
        if (!row) throw new Error('no such row')
        Object.assign(row, data)
        return row
      },
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/scanCoverage', () => ({ readDegradedSourceCount: (...a: unknown[]) => h.degradedSources(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { getReconStatus, type McpContext } from './tools'
import { stopRecon } from './writeTools'

const ctx: McpContext = {
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'recon:scan'] as never,
  },
}

const job = (over: Partial<JobRow> = {}): JobRow => ({
  id: 'sj1', projectId: 'p1', kind: 'full_recon', runId: '', status: 'running',
  versionId: 'v4', startedAt: new Date('2026-11-10T20:00:00Z'), finishedAt: null,
  createdAt: new Date('2026-11-10T20:00:00Z'), trigger: 'manual', mode: 'new', nodeCount: null,
  ...over,
})

const answer = (body: unknown) => ({ ok: true, status: 200, json: async () => body })

/** The orchestrator's answers: one status for /status, one for /stop. */
function orchestrator(status: string, stopAnswer = 'stopping') {
  h.orchestratorFetch.mockImplementation(async (url: unknown) =>
    String(url).endsWith('/stop')
      ? answer({ project_id: 'p1', status: stopAnswer })
      : answer({ project_id: 'p1', status }))
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.jobs = [job()]
  h.degradedSources.mockResolvedValue(null)
  h.audit.mockResolvedValue(undefined)
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('get_recon_status closes the run it sees ended', () => {
  test('an idle orchestrator records the open run canceled, and the same answer says so', async () => {
    orchestrator('idle')
    const r = await getReconStatus(ctx, 'p1') as Record<string, never>

    expect(h.jobs[0].status).toBe('canceled')
    expect(h.jobs[0].finishedAt).toBeInstanceOf(Date)
    expect(r.status).toBe('idle')
    expect(r.lastRun).toMatchObject({ status: 'canceled', completed: false })
  })

  test('a completed scan is recorded completed, with its degraded-source count', async () => {
    orchestrator('completed')
    h.degradedSources.mockResolvedValue(2)
    const r = await getReconStatus(ctx, 'p1') as Record<string, never>

    expect(h.jobs[0]).toMatchObject({ status: 'completed', degradedSources: 2, nodeCount: 42 })
    expect(r.lastRun).toMatchObject({ status: 'completed', completed: true })
  })

  test('an orchestrator error is recorded failed', async () => {
    orchestrator('error')
    await getReconStatus(ctx, 'p1')
    expect(h.jobs[0].status).toBe('failed')
  })

  test.each(['running', 'stopping', 'paused', 'starting'])('a %s scan stays running', async status => {
    orchestrator(status)
    const r = await getReconStatus(ctx, 'p1') as Record<string, never>
    expect(h.jobs[0]).toMatchObject({ status: 'running', finishedAt: null })
    expect(r.lastRun).toMatchObject({ status: 'running' })
  })

  test('an unreachable orchestrator closes nothing', async () => {
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(getReconStatus(ctx, 'p1')).rejects.toThrow(/unknown/i)
    expect(h.jobs[0].status).toBe('running')
  })

  // The status describes the full recon only; another kind's row in the same
  // project is closed by its own reconcile.
  test('another kind\'s run in the project is left alone', async () => {
    h.jobs = [job({ id: 'partial', kind: 'partial_recon', runId: 'r1' })]
    orchestrator('idle')
    await getReconStatus(ctx, 'p1')
    expect(h.jobs[0].status).toBe('running')
  })

  test('a failed history write does not fail the status read', async () => {
    orchestrator('idle')
    h.jobs = [job({ id: 'ghost' })]
    const prisma = (await import('@/lib/prisma')).default as unknown as {
      scanJob: { update: (...a: unknown[]) => Promise<unknown> }
    }
    const update = vi.spyOn(prisma.scanJob, 'update').mockRejectedValueOnce(new Error('db down'))
    const r = await getReconStatus(ctx, 'p1') as Record<string, never>
    expect(update).toHaveBeenCalled()
    expect(r.status).toBe('idle')
  })
})

describe('stop_recon and the run it stopped', () => {
  // The live E2E sequence: stop answers `stopping` while the scan lands its
  // graph writes; the run is recorded when a status read sees it idle, with no
  // browser involved.
  test('stop, then a status read that sees idle, records the run canceled', async () => {
    orchestrator('running', 'stopping')
    const stopped = await stopRecon(ctx, 'p1') as Record<string, unknown>
    expect(stopped).toMatchObject({ status: 'stopping', stopped: true })
    expect(h.jobs[0].status).toBe('running')

    orchestrator('idle')
    const r = await getReconStatus(ctx, 'p1') as Record<string, never>
    expect(h.jobs[0].status).toBe('canceled')
    expect(h.jobs[0].finishedAt).toBeInstanceOf(Date)
    expect(r.lastRun).toMatchObject({ status: 'canceled' })
  })

  // A scan that ended with nobody reading its status: the stop's own answer is
  // a status read too, so the agent's stop closes it at once.
  test('a stop the orchestrator answers idle records the open run canceled at once', async () => {
    orchestrator('idle', 'idle')
    const stopped = await stopRecon(ctx, 'p1') as Record<string, unknown>
    expect(stopped).toMatchObject({ status: 'idle', stopped: false })
    expect(h.jobs[0].status).toBe('canceled')
    expect(h.jobs[0].finishedAt).toBeInstanceOf(Date)
  })

  test('a stop of a scan that had already completed keeps its real outcome', async () => {
    orchestrator('completed', 'completed')
    await stopRecon(ctx, 'p1')
    expect(h.jobs[0].status).toBe('completed')
  })

  test('a stop the orchestrator refused writes nothing', async () => {
    h.orchestratorFetch.mockImplementation(async (url: unknown) =>
      String(url).endsWith('/stop')
        ? { ok: false, status: 500, json: async () => ({}) }
        : answer({ status: 'running' }))
    await expect(stopRecon(ctx, 'p1')).rejects.toMatchObject({ code: 'stop_failed' })
    expect(h.jobs[0].status).toBe('running')
  })
})

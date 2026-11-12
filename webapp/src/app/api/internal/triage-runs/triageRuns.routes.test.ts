/**
 * The triage-run lifecycle routes.
 *
 * A triage run used to exist only in the agent's memory, so nothing else could
 * see one: version activation, version save, the delta preview, project import
 * and project delete could all replace or delete the graph while a run was
 * halfway through reading it, and the run would then publish a ranking of
 * findings that no longer existed.
 *
 * What these tests defend, in order of how much it costs to get wrong:
 *
 * 1. A run cannot start on a project the actor does not own: ownership is
 *    always enforced, whatever ACCESS_ENFORCE says (the variable is ignored).
 * 2. A run cannot start during an activation, or beside another live run.
 * 3. A dead agent's run stops blocking the project after its heartbeat expires,
 *    and cannot then come back and publish.
 * 4. Publishing is a conditional transition: a run that lost its claim writes
 *    nothing, rather than writing half a result.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const prismaMock = vi.hoisted(() => ({
  project: { findUnique: vi.fn() },
  triageRun: {
    findMany: vi.fn(), findUnique: vi.fn(), findFirst: vi.fn(), create: vi.fn(),
    update: vi.fn(), updateMany: vi.fn(), deleteMany: vi.fn(),
  },
  auditLog: { create: vi.fn() },
}))
const isInternalMock = vi.hoisted(() => vi.fn())
const activationMock = vi.hoisted(() => vi.fn())

vi.mock('@/lib/prisma', () => ({ default: prismaMock }))
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => isInternalMock(...a) }))
vi.mock('@/lib/activationLock', () => ({
  isActivationInProgress: (...a: unknown[]) => activationMock(...a),
}))

import { POST as createRun } from './route'
import { POST as heartbeat } from './[runId]/heartbeat/route'
import { POST as publish } from './[runId]/publish/route'
import { POST as finish } from './[runId]/finish/route'

const OWNER = 'ownerUser'
const PROJECT = 'proj1'

function post(path: string, body: unknown): NextRequest {
  return new NextRequest(`http://x${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const runParams = (runId = 'run1') => ({ params: Promise.resolve({ runId }) })

const fresh = () => new Date()
const ancient = () => new Date(Date.now() - 60 * 60 * 1000)

beforeEach(() => {
  vi.clearAllMocks()
  isInternalMock.mockReturnValue(true)
  activationMock.mockResolvedValue(false)
  prismaMock.project.findUnique.mockResolvedValue({ id: PROJECT, userId: OWNER })
  prismaMock.triageRun.findMany.mockResolvedValue([])
  prismaMock.triageRun.updateMany.mockResolvedValue({ count: 1 })
  prismaMock.triageRun.create.mockResolvedValue({ id: 'run1', startedAt: fresh() })
  prismaMock.triageRun.update.mockResolvedValue({})
  prismaMock.triageRun.findFirst.mockResolvedValue(null)
  prismaMock.triageRun.deleteMany.mockResolvedValue({ count: 0 })
  prismaMock.auditLog.create.mockResolvedValue({})
})

// ---------------------------------------------------------------------------
describe('POST /api/internal/triage-runs', () => {
  const body = { projectId: PROJECT, actorUserId: OWNER, model: 'claude-x' }

  test('the owner gets a run, and it is audited', async () => {
    const res = await createRun(post('/api/internal/triage-runs', body))
    expect(res.status).toBe(201)
    expect(await res.json()).toMatchObject({ runId: 'run1' })
    expect(prismaMock.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ action: 'triage.start' }),
      })
    )
  })

  test('EXPLOIT: a non-owner is refused with 404 and no run is created', async () => {
    const res = await createRun(post('/api/internal/triage-runs',
      { ...body, actorUserId: 'attacker' }))
    expect(res.status).toBe(404)
    expect(prismaMock.triageRun.create).not.toHaveBeenCalled()
  })

  test('a missing project is indistinguishable from one that is not yours', async () => {
    prismaMock.project.findUnique.mockResolvedValue(null)
    const res = await createRun(post('/api/internal/triage-runs', body))
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Not found', runId: undefined })
  })

  test('a request without the internal key is refused', async () => {
    isInternalMock.mockReturnValue(false)
    const res = await createRun(post('/api/internal/triage-runs', body))
    expect(res.status).toBe(404)
    expect(prismaMock.triageRun.create).not.toHaveBeenCalled()
  })

  test('an activation in progress blocks the run', async () => {
    activationMock.mockResolvedValue(true)
    const res = await createRun(post('/api/internal/triage-runs', body))
    expect(res.status).toBe(409)
    expect(prismaMock.triageRun.create).not.toHaveBeenCalled()
  })

  test('a second live run is refused, and names the one in the way', async () => {
    prismaMock.triageRun.findMany.mockResolvedValue([
      { id: 'existing', status: 'running', startedAt: fresh(), heartbeatAt: fresh(),
        actorUserId: OWNER, model: 'm' },
    ])
    const res = await createRun(post('/api/internal/triage-runs', body))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ runId: 'existing' })
  })

  test('a run whose agent died does not block, and is marked failed', async () => {
    prismaMock.triageRun.findMany.mockResolvedValue([
      { id: 'zombie', status: 'running', startedAt: ancient(), heartbeatAt: ancient(),
        actorUserId: OWNER, model: 'm' },
    ])
    const res = await createRun(post('/api/internal/triage-runs', body))
    expect(res.status).toBe(201)
    expect(prismaMock.triageRun.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: 'failed', errorClass: 'agent_lost' }),
      })
    )
  })

  test('a body with no projectId or actor is a 400, not a crash', async () => {
    expect((await createRun(post('/api/internal/triage-runs', {}))).status).toBe(400)
  })

  test('an MCP start records its trigger and token, and the audit its budget', async () => {
    await createRun(post('/api/internal/triage-runs',
      { ...body, trigger: 'mcp', tokenId: 'tok1', reviewBudget: 1000 }))
    expect(prismaMock.triageRun.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ trigger: 'mcp', tokenId: 'tok1' }),
    }))
    expect(prismaMock.auditLog.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        after: expect.objectContaining({ trigger: 'mcp', tokenId: 'tok1', reviewBudget: 1000,
                                         model: 'claude-x' }),
      }),
    }))
  })

  test('anything but an MCP start is recorded as the app, and a bad token id is dropped', async () => {
    await createRun(post('/api/internal/triage-runs',
      { ...body, trigger: 'cron', tokenId: 'x'.repeat(200) }))
    expect(prismaMock.triageRun.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ trigger: 'app', tokenId: null }),
    }))
  })

  test('the admin behind a simulated user is the audited actor', async () => {
    await createRun(post('/api/internal/triage-runs',
      { ...body, realActorUserId: 'admin1' }))
    expect(prismaMock.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ actorId: 'admin1' }) })
    )
  })
})

// ---------------------------------------------------------------------------
describe('POST .../heartbeat', () => {
  test('a running run is kept alive and told to continue', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running' })
    const res = await heartbeat(post('/x', { phase: 'reviewing', progress: 55 }), runParams())
    expect(await res.json()).toEqual({ status: 'running', abort: false })
    expect(prismaMock.triageRun.updateMany).toHaveBeenCalledWith({
      where: { id: 'run1', status: { in: ['running', 'publishing'] } },
      data: expect.objectContaining({ phase: 'reviewing', progress: 55 }),
    })
  })

  test('a publishing run is alive too, so a long publish keeps its hold (B12, B16)', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'publishing' })
    const res = await heartbeat(post('/x', { phase: 'publishing', progress: 92 }), runParams())
    expect(await res.json()).toEqual({ status: 'publishing', abort: false })
    expect(prismaMock.triageRun.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ heartbeatAt: expect.any(Date), phase: 'publishing' }),
    }))
  })

  test('a progress outside 0-100 is clamped, and a long phase is cut', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running' })
    await heartbeat(post('/x', { phase: 'x'.repeat(100), progress: 400 }), runParams())
    const data = prismaMock.triageRun.updateMany.mock.calls[0][0].data
    expect(data.progress).toBe(100)
    expect(data.phase).toHaveLength(40)
  })

  test('a deleted project cascades the run away, and the agent is told to stop', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(null)
    const res = await heartbeat(post('/x', {}), runParams())
    expect(res.status).toBe(404)
    expect(await res.json()).toMatchObject({ abort: true })
  })

  test('a stopped run tells the agent to abort', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'stopped' })
    expect(await (await heartbeat(post('/x', {}), runParams())).json())
      .toMatchObject({ abort: true })
  })

  test('an activation that started mid-run aborts it before it can publish', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running' })
    activationMock.mockResolvedValue(true)
    const res = await heartbeat(post('/x', {}), runParams())
    expect(await res.json()).toMatchObject({ abort: true })
    expect(prismaMock.triageRun.updateMany).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
describe('POST .../publish', () => {
  test('a running run with a fresh heartbeat claims the write', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running', heartbeatAt: fresh() })
    const res = await publish(post('/x', {}), runParams())
    expect(res.status).toBe(200)
    expect(prismaMock.triageRun.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'run1', status: 'running' },
        data: { status: 'publishing' },
      })
    )
  })

  test('a run someone stopped writes nothing', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'stopped', heartbeatAt: fresh() })
    const res = await publish(post('/x', {}), runParams())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ errorClass: 'publish_refused' })
    expect(prismaMock.triageRun.updateMany).not.toHaveBeenCalled()
  })

  test('a run that went quiet cannot come back and publish', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running', heartbeatAt: ancient() })
    const res = await publish(post('/x', {}), runParams())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ errorClass: 'agent_lost' })
  })

  test('an activation started mid-run refuses the publish', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running', heartbeatAt: fresh() })
    activationMock.mockResolvedValue(true)
    expect((await publish(post('/x', {}), runParams())).status).toBe(409)
    expect(prismaMock.triageRun.updateMany).not.toHaveBeenCalled()
  })

  test('losing the race writes nothing, even though the read said running', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(
      { id: 'run1', projectId: PROJECT, status: 'running', heartbeatAt: fresh() })
    prismaMock.triageRun.updateMany.mockResolvedValue({ count: 0 })
    expect((await publish(post('/x', {}), runParams())).status).toBe(409)
  })

  test('an unknown run is a 404', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(null)
    expect((await publish(post('/x', {}), runParams())).status).toBe(404)
  })
})

// ---------------------------------------------------------------------------
describe('POST .../finish', () => {
  beforeEach(() => {
    prismaMock.triageRun.findUnique.mockResolvedValue({
      id: 'run1', projectId: PROJECT, actorUserId: OWNER, realActorUserId: null,
    })
  })

  const finishData = () => prismaMock.triageRun.updateMany.mock.calls[0][0]

  test('a completed run records its counts, only from a live status, and is audited', async () => {
    const res = await finish(
      post('/x', { status: 'completed', summary: { scored: 12, reviewed: 3 } }),
      runParams())
    expect(res.status).toBe(200)
    expect(finishData()).toMatchObject({
      where: { id: 'run1', status: { in: ['running', 'publishing'] } },
      data: expect.objectContaining({ status: 'completed', summary: { scored: 12, reviewed: 3 } }),
    })
    expect(prismaMock.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ action: 'triage.finish' }) })
    )
  })

  test('a run already marked lost keeps that status and is audited as late (B16)', async () => {
    prismaMock.triageRun.updateMany.mockResolvedValue({ count: 0 })
    const res = await finish(
      post('/x', { status: 'completed', summary: { scored: 4 } }), runParams())
    expect(await res.json()).toEqual({ status: 'late', late: true })
    expect(prismaMock.triageRun.update).toHaveBeenCalledWith({
      where: { id: 'run1' }, data: { summary: { scored: 4, late: 1 } },
    })
    expect(prismaMock.auditLog.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ action: 'triage.finish.late' }),
    }))
  })

  test('an unknown status becomes failed rather than leaving the run live', async () => {
    await finish(post('/x', { status: 'wat' }), runParams())
    expect(finishData().data.status).toBe('failed')
  })

  test('a run cannot be finished back into running', async () => {
    await finish(post('/x', { status: 'running' }), runParams())
    expect(finishData().data.status).toBe('failed')
  })

  test('the summary keeps counts and drops anything else', async () => {
    await finish(post('/x', {
      status: 'completed',
      summary: { scored: 5, findingTitle: 'admin.example.com is vulnerable', llm_calls: '7',
                 reviews_kept: 3, external_reviews: 1, reviews_adopted: 2, review_budget: 1000,
                 publish_failed: 0, llm_available: 1 },
    }), runParams())
    expect(finishData().data.summary).toEqual({
      scored: 5, llm_calls: 7, reviews_kept: 3, external_reviews: 1, reviews_adopted: 2,
      review_budget: 1000, publish_failed: 0, llm_available: 1,
    })
  })

  test('the summary keeps how many fix items followed their findings', async () => {
    await finish(post('/x', {
      status: 'completed',
      summary: { remediations_created: 1, remediations_updated: 4, remediations_repointed: 2 },
    }), runParams())
    expect(finishData().data.summary).toEqual({
      remediations_created: 1, remediations_updated: 4, remediations_repointed: 2,
    })
  })

  test('a malformed body still records a terminal state', async () => {
    const bad = new NextRequest('http://x/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    })
    expect((await finish(bad, runParams())).status).toBe(200)
    expect(finishData().data.status).toBe('failed')
  })

  test('an unknown run is a 404', async () => {
    prismaMock.triageRun.findUnique.mockResolvedValue(null)
    expect((await finish(post('/x', { status: 'completed' }), runParams())).status).toBe(404)
  })

  test('old finished runs are trimmed, never a live one, the newest completed, or the newest 50 (C11)', async () => {
    prismaMock.triageRun.findMany.mockResolvedValue(
      Array.from({ length: 50 }, (_, i) => ({ id: `r${i}` })))
    prismaMock.triageRun.findFirst.mockResolvedValue({ id: 'latest-completed' })
    await finish(post('/x', { status: 'completed' }), runParams())
    await new Promise((r) => setTimeout(r, 0))
    const where = prismaMock.triageRun.deleteMany.mock.calls[0][0].where
    expect(where.projectId).toBe(PROJECT)
    expect(where.status).toEqual({ notIn: ['running', 'publishing'] })
    expect(where.id.notIn).toContain('latest-completed')
    expect(where.id.notIn).toContain('r49')
    expect(where.startedAt.lt.getTime()).toBeLessThanOrEqual(Date.now() - 24 * 60 * 60 * 1000 + 1000)
  })

  test('a failed trim never fails the finish', async () => {
    prismaMock.triageRun.deleteMany.mockRejectedValue(new Error('db down'))
    expect((await finish(post('/x', { status: 'completed' }), runParams())).status).toBe(200)
  })
})

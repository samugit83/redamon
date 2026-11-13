/**
 * GET /api/system/jobs with shares (step 4.5, SH-39): with sharing in force the scan activity view
 * lists, beside the jobs the person queued, every job and running scan of a project they see, so a
 * shared project's queue shows with who started each job (`initiator`); the anonymous count of
 * everyone else's work is the exact complement, so nothing is counted twice. With sharing not in
 * force the answer is the one before: the person's own queue rows, no `initiator` key (DV-30).
 * Real visibleProjects, flags, clock and policy over an evaluating database double.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/system/jobs/route.shared.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { emptyProjectListState, projectListPrisma, type ProjectListState } from '@/lib/authz/__testing__/projectListDb'

const h = vi.hoisted(() => ({
  db: null as unknown,
  eff: { userId: 'bob' } as { userId: string },
  live: [] as Array<Record<string, unknown>>,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }) }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: vi.fn(async () => h.eff) }))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: vi.fn(async (url: string) => (String(url).includes('/system/active-scans')
    ? new Response(JSON.stringify({ scans: h.live }), { status: 200 })
    : new Response('{}', { status: 200 }))),
}))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'

const NOW = new Date('2026-11-13T12:00:00Z')
const ON = { identity: true, permissions: true, sharing: true }

interface Job { id: string; projectId: string; projectName: string; status: string; source: string; initiator?: { id: string; name: string | null } | null }
interface Activity {
  mine: { running: Job[]; queued: Job[]; needsReview: Job[]; recent: Job[] }
  others: { queued: number; running: number; needsReview: number }
}

let state: ProjectListState

function queued(id: string, projectId: string, userId: string, status = 'queued', over: Record<string, unknown> = {}) {
  return {
    id, projectId, userId, kind: 'gvm', status, priority: 0, attempts: 0, blockedCode: '', blockedReason: '', error: '',
    envelopeBytes: BigInt(1024), enqueuedAt: new Date(NOW.getTime() - 1000), startedAt: null,
    finishedAt: status === 'done' ? new Date(NOW.getTime() - 500) : null, scanJobId: null, runId: '', payload: { secret: 'never listed' },
    ...over,
  }
}

async function activity(): Promise<Activity> {
  const res = await GET(new NextRequest('http://redamon.test/api/system/jobs'))
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  state = emptyProjectListState()
  state.users = [
    { id: 'alice', name: 'Alice', email: 'alice@example.test', status: 'active' },
    { id: 'bob', name: 'Bob', email: 'bob@example.test', status: 'active' },
    { id: 'carol', name: 'Carol', email: 'carol@example.test', status: 'active' },
  ]
  state.projects = [
    { id: 'p-bob', userId: 'bob', name: 'Bob project' },
    { id: 'p-alice', userId: 'alice', name: 'Alice project' },
    { id: 'p-carol', userId: 'carol', name: 'Carol project' },
  ]
  state.shares = [{ projectId: 'p-alice', userId: 'bob', access: 'read', rawData: false, expiresAt: new Date(NOW.getTime() + 60_000) }]
  state.jobQueue = [
    queued('q-bob', 'p-bob', 'bob'),
    queued('q-alice', 'p-alice', 'alice'),
    queued('q-alice-review', 'p-alice', 'alice', 'needs_review'),
    queued('q-alice-done', 'p-alice', 'alice', 'done'),
    queued('q-carol', 'p-carol', 'carol'),
  ]
  state.scanJobs = [
    { id: 's-alice', projectId: 'p-alice', kind: 'full_recon', runId: '', status: 'running', initiatedByUserId: 'alice', startedAt: new Date(NOW.getTime() - 5000), createdAt: new Date(NOW.getTime() - 5000) },
    { id: 's-sched', projectId: 'p-alice', kind: 'gvm', runId: '', status: 'running', initiatedByUserId: null, startedAt: new Date(NOW.getTime() - 4000), createdAt: new Date(NOW.getTime() - 4000) },
    { id: 's-carol', projectId: 'p-carol', kind: 'full_recon', runId: '', status: 'running', initiatedByUserId: 'carol', startedAt: new Date(NOW.getTime() - 3000), createdAt: new Date(NOW.getTime() - 3000) },
  ]
  h.live = []
  h.db = projectListPrisma(state)
  h.eff = { userId: 'bob' }
  setFlagsForTests(ON)
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('sharing in force', () => {
  test('system jobs of a shared project listed, with their initiator', async () => {
    const { mine } = await activity()
    expect(mine.queued.map((j) => j.id).sort()).toEqual(['q-alice', 'q-bob'])
    expect(mine.needsReview.map((j) => j.id)).toEqual(['q-alice-review'])
    expect(mine.recent.map((j) => j.id)).toEqual(['q-alice-done'])
    expect(mine.running.map((j) => j.id).sort()).toEqual(['s-alice', 's-sched'])
    const byId = new Map([...mine.queued, ...mine.needsReview, ...mine.running].map((j) => [j.id, j]))
    expect(byId.get('q-alice')).toMatchObject({ projectName: 'Alice project', initiator: { id: 'alice', name: 'Alice' } })
    expect(byId.get('q-bob')?.initiator).toEqual({ id: 'bob', name: 'Bob' })
    expect(byId.get('s-alice')?.initiator).toEqual({ id: 'alice', name: 'Alice' })
    // A scan nobody started by hand (a schedule, the agent) names no one.
    expect(byId.get('s-sched')?.initiator).toBeNull()
    // Who started a job, never their email or the job's payload.
    expect(JSON.stringify(mine)).not.toContain('alice@example.test')
    expect(JSON.stringify(mine)).not.toContain('never listed')
  })

  test("the others' count is the complement: a shared project's work is never counted twice", async () => {
    expect((await activity()).others).toEqual({ queued: 1, running: 1, needsReview: 0 })
  })

  test("a live scan of a shared project is named and listed, another's is not", async () => {
    h.live = [
      { kind: 'trufflehog', project_id: 'p-alice', run_id: 'r1', tool_id: '', status: 'running', started_at: null },
      { kind: 'trufflehog', project_id: 'p-carol', run_id: 'r2', tool_id: '', status: 'running', started_at: null },
    ]
    const live = (await activity()).mine.running.filter((j) => j.source === 'live')
    expect(live).toHaveLength(1)
    expect(live[0]).toMatchObject({ projectId: 'p-alice', projectName: 'Alice project', initiator: null })
  })

  test('the share ends (expired on the clock): its jobs go back to the anonymous count', async () => {
    setNowForTests(() => new Date(NOW.getTime() + 60_000))
    const { mine, others } = await activity()
    expect(mine.queued.map((j) => j.id)).toEqual(['q-bob'])
    expect(mine.running).toEqual([])
    expect(others).toEqual({ queued: 2, running: 3, needsReview: 1 })
  })

  test('the owner sees the jobs of its own project whoever queued them', async () => {
    state.jobQueue.push(queued('q-bob-by-alice', 'p-bob', 'alice'))
    const { mine, others } = await activity()
    expect(mine.queued.find((j) => j.id === 'q-bob-by-alice')?.initiator).toEqual({ id: 'alice', name: 'Alice' })
    expect(others.queued).toBe(1)
  })
})

describe('sharing not in force: the view before step 4.5 (DV-30)', () => {
  test.each([
    ['the switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the policy disabled', ON, {}],
  ])('%s: the person\'s own queue rows, no initiator key, the rest counted', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    state.policy = policy
    const { mine, others } = await activity()
    expect(mine.queued.map((j) => j.id)).toEqual(['q-bob'])
    expect(mine.needsReview).toEqual([])
    expect(mine.recent).toEqual([])
    expect(mine.running).toEqual([])
    for (const j of mine.queued) expect(j).not.toHaveProperty('initiator')
    expect(others).toEqual({ queued: 2, running: 3, needsReview: 1 })
  })
})

/**
 * Losing access stops the person's live work (step 5.9; SH-11, SH-12, SH-41): onAccessReduced(), the
 * one path a revoke, an expiry, a narrowing, a consent withdrawal, a disable, a session-version bump
 * and a capability removal take after their change committed.
 *
 * The real plan, socket close, audit writer and transaction helper over an in-memory Prisma double
 * (queued jobs, schedules, triage runs, projects, audit rows); the agent's HTTP call (agentFetch), the
 * deferred-scan check (actorScanRefusal: the queue's and the scheduler's own, tested in
 * scanActor.access.test.ts), the owner notice, the triage reader and stopper and the act-as ending are
 * doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/revocation.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

interface Job { id: string; projectId: string; userId: string; kind: string; payload: unknown; status: string; blockedCode?: string; blockedReason?: string }
interface Schedule { id: string; projectId: string; userId: string; label: string; scanMode: string; enabled: boolean; pausedReason: string | null }

const h = vi.hoisted(() => ({
  jobs: [] as Job[],
  schedules: [] as Schedule[],
  triageRuns: [] as Array<{ projectId: string; actorUserId: string; status: string }>,
  projects: [] as Array<{ id: string; userId: string }>,
  audit: [] as Array<Record<string, unknown>>,
  failJobs: false,
  /** Projects (or `project|permission`) the person may no longer start scans on. */
  refused: new Set<string>(),
  agentFetch: vi.fn(),
  notice: vi.fn(),
  live: vi.fn(),
  stopRun: vi.fn(),
  endImpersonations: vi.fn(),
  flags: { permissions: true },
}))

type Where = Record<string, unknown>
const matches = (row: Record<string, unknown>, where: Where) => Object.entries(where).every(([k, cond]) => {
  if (cond && typeof cond === 'object' && 'in' in (cond as object)) return ((cond as { in: unknown[] }).in).includes(row[k])
  return row[k] === cond
})

vi.mock('@/lib/prisma', () => {
  const client: Record<string, unknown> = {
    jobQueue: {
      findMany: async ({ where }: { where: Where }) => {
        if (h.failJobs) throw Object.assign(new Error('db down'), { code: 'P1001' })
        return h.jobs.filter((j) => matches(j as never, where)).map((j) => ({ ...j }))
      },
      updateMany: async ({ where, data }: { where: Where; data: Partial<Job> }) => {
        const hit = h.jobs.filter((j) => matches(j as never, where))
        for (const j of hit) Object.assign(j, data)
        return { count: hit.length }
      },
    },
    scanSchedule: {
      findMany: async ({ where }: { where: Where }) => h.schedules.filter((s) => matches(s as never, where)).map((s) => ({ ...s })),
      updateMany: async ({ where, data }: { where: Where; data: Partial<Schedule> }) => {
        const hit = h.schedules.filter((s) => matches(s as never, where))
        for (const s of hit) Object.assign(s, data)
        return { count: hit.length }
      },
    },
    triageRun: {
      findMany: async ({ where }: { where: Where }) => h.triageRuns.filter((r) => matches(r as never, where)),
    },
    project: {
      findUnique: async ({ where }: { where: { id: string } }) => h.projects.find((p) => p.id === where.id) ?? null,
    },
    auditLog: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        h.audit.push(data)
        return data
      },
    },
  }
  client.$transaction = async (fn: (tx: unknown) => Promise<unknown>) => fn(client)
  return { default: client, prisma: client }
})
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
}))
vi.mock('./scanActor', async (orig) => ({
  ...(await orig<typeof import('./scanActor')>()),
  actorScanRefusal: async (userId: string, projectId: string, permissions: string[]) => {
    const permission = permissions.find((p) => h.refused.has(projectId) || h.refused.has(`${projectId}|${p}`))
    return permission ? { userId, permission, reason: 'project_not_visible' } : null
  },
  noticeSchedulePaused: (...a: unknown[]) => h.notice(...a),
}))
vi.mock('@/lib/triageRun', () => ({
  LIVE_TRIAGE_STATUSES: ['running', 'publishing'],
  findLiveTriageRun: (...a: unknown[]) => h.live(...a),
}))
vi.mock('@/lib/triage/actions', () => ({ stopRun: (...a: unknown[]) => h.stopRun(...a) }))
vi.mock('./actAs', () => ({ endOpenImpersonationsQuietly: (...a: unknown[]) => h.endImpersonations(...a) }))
vi.mock('./flags', () => ({ rbacFlags: () => h.flags }))

import { AgentUnreachableError } from '@/lib/agentFetch'
import { agentWorkOf, isAccessReduction, onAccessReduced, PLANS } from './revocation'

const KINDS = ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']
const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 })
const agentCalls = () => h.agentFetch.mock.calls.map(([path, init]) => [path, JSON.parse((init as RequestInit).body as string)])
const errorLines = () => vi.mocked(console.error).mock.calls.map((c) => String(c[0]))
const job = (id: string, over: Partial<Job> = {}): Job => ({ id, projectId: 'P1', userId: 'bob', kind: 'full_recon', payload: { mode: 'new' }, status: 'queued', ...over })
const schedule = (id: string, over: Partial<Schedule> = {}): Schedule => ({ id, projectId: 'P1', userId: 'bob', label: `Nightly ${id}`, scanMode: 'new', enabled: true, pausedReason: null, ...over })

beforeEach(() => {
  h.jobs = [
    job('j-queued'),
    job('j-review', { status: 'needs_review', kind: 'gvm', payload: {} }),
    job('j-running', { status: 'running' }),
    job('j-dispatching', { status: 'dispatching' }),
    job('j-other-project', { projectId: 'P2' }),
    job('j-other-person', { userId: 'carol' }),
  ]
  h.schedules = [schedule('s1'), schedule('s-off', { enabled: false }), schedule('s-p2', { projectId: 'P2' }), schedule('s-carol', { userId: 'carol' })]
  h.triageRuns = [{ projectId: 'P1', actorUserId: 'bob', status: 'running' }, { projectId: 'P2', actorUserId: 'bob', status: 'running' }]
  h.projects = [{ id: 'P1', userId: 'alice' }, { id: 'P2', userId: 'dave' }]
  h.audit = []
  h.failJobs = false
  h.refused = new Set(['P1', 'P2'])
  h.flags = { permissions: true }
  h.agentFetch.mockReset()
  h.agentFetch.mockImplementation(async (path: string) => ok(path === '/ws/close' ? { closed: 2, stopped_runs: 1 } : { stopped: 1 }))
  h.notice.mockReset()
  h.notice.mockResolvedValue(true)
  h.live.mockReset()
  h.live.mockImplementation(async (projectId: string) => ({ id: `run-${projectId}`, actorUserId: 'bob' }))
  h.stopRun.mockReset()
  h.stopRun.mockResolvedValue({ stopped: true })
  h.endImpersonations.mockReset()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.restoreAllMocks()
})

describe('a share ending on one project', () => {
  test('revoke stops runs, closes sockets, cancels queued, pauses schedules', async () => {
    const out = await onAccessReduced('P1', 'bob', 'share_revoked')
    expect(agentCalls()).toEqual([
      ['/agent-sessions/stop-for', { user_id: 'bob', project_ids: ['P1'] }],
      ['/ws/close', { user_id: 'bob', project_id: 'P1', kinds: KINDS, scope: 'access' }],
    ])
    expect(out).toEqual({
      runs: { stopped: 1 }, sockets: { closed: 2 }, scans: { cancelled: 2 }, schedules: { paused: 1 }, triage: { stopped: 1 }, failed: [],
    })
    expect(h.jobs.filter((j) => j.status === 'canceled').map((j) => j.id)).toEqual(['j-queued', 'j-review'])
    expect(h.jobs.find((j) => j.id === 'j-queued')).toMatchObject({ blockedCode: 'actor_no_access', blockedReason: 'the account that queued it no longer has access to this project' })
    expect(h.schedules.find((s) => s.id === 's1')).toMatchObject({ enabled: false, pausedReason: 'actor_no_access' })
    expect(h.audit.map((r) => [r.action, r.targetId])).toEqual([
      ['job_queue.cancelled', 'j-queued'], ['job_queue.cancelled', 'j-review'], ['scan_schedule.paused', 's1'],
    ])
    expect(h.audit[0]).toMatchObject({
      actorId: null, projectId: 'P1', source: 'system',
      after: { reason: 'actor_no_access', kind: 'full_recon', userId: 'bob', permission: 'recon:scan', revocation: 'share_revoked' },
    })
    expect(h.notice).toHaveBeenCalledWith({ projectId: 'P1', scheduleId: 's1', label: 'Nightly s1', actorUserId: 'bob' })
    expect(h.stopRun).toHaveBeenCalledWith({ userId: 'alice', projectId: 'P1' }, 'app')
    expect(h.endImpersonations).not.toHaveBeenCalled()
  })

  test("running scan untouched; another project's and another person's work untouched", async () => {
    await onAccessReduced('P1', 'bob', 'share_expired')
    const status = Object.fromEntries(h.jobs.map((j) => [j.id, j.status]))
    expect(status).toMatchObject({ 'j-running': 'running', 'j-dispatching': 'dispatching', 'j-other-project': 'queued', 'j-other-person': 'queued' })
    expect(h.schedules.filter((s) => s.enabled).map((s) => s.id)).toEqual(['s-p2', 's-carol'])
    expect(h.agentFetch.mock.calls.map((c) => c[0])).toEqual(['/agent-sessions/stop-for', '/ws/close'])
    expect(h.live).toHaveBeenCalledTimes(1)
    expect(h.live).toHaveBeenCalledWith('P1')
  })

  test('agent unreachable → revoke still done and logged', async () => {
    h.agentFetch.mockRejectedValue(new AgentUnreachableError(new Error('ECONNREFUSED')))
    const out = await onAccessReduced('P1', 'bob', 'share_revoked')
    expect(out.runs).toEqual({ error: 'agent_unreachable' })
    expect(out.sockets).toEqual({ error: 'agent_unreachable' })
    expect(out.failed).toEqual(['stop_runs', 'close_sockets'])
    expect(out.scans).toEqual({ cancelled: 2 })
    expect(out.schedules).toEqual({ paused: 1 })
    const lines = errorLines()
    expect(lines.some((l) => l.startsWith('[rbac] socket-close failed user=bob project=P1') && l.endsWith('agent_unreachable'))).toBe(true)
    expect(lines).toContain('[rbac] revocation step failed step=close_sockets reason=share_revoked user=bob project=P1: agent_unreachable')
    expect(lines).toContain('[rbac] revocation step failed step=stop_runs reason=share_revoked user=bob project=P1: agent_unreachable')
  })

  test('a step that fails is logged and the others still run', async () => {
    h.failJobs = true
    h.live.mockRejectedValueOnce(Object.assign(new Error('db'), { code: 'P1001' }))
    const out = await onAccessReduced('P1', 'bob', 'share_left')
    expect(out.scans).toEqual({ error: 'P1001' })
    expect(out.schedules).toEqual({ paused: 1 })
    expect(out.triage).toEqual({ error: 'P1001' })
    expect(out.failed).toEqual(['cancel_queued_scans', 'stop_triage_run'])
    expect(errorLines()).toContain('[rbac] revocation step failed step=cancel_queued_scans reason=share_left user=bob project=P1: P1001')
  })

  test('a narrowing cancels only what the person may no longer start', async () => {
    h.refused = new Set(['P1|scan:gvm'])
    const out = await onAccessReduced('P1', 'bob', 'share_reduced')
    expect(out.scans).toEqual({ cancelled: 1 })
    expect(out.schedules).toEqual({ paused: 0 })
    expect(h.jobs.find((j) => j.id === 'j-review')!.status).toBe('canceled')
    expect(h.jobs.find((j) => j.id === 'j-queued')!.status).toBe('queued')
    expect(h.schedules.find((s) => s.id === 's1')!.enabled).toBe(true)
    expect(h.notice).not.toHaveBeenCalled()
    expect(agentCalls().map((c) => c[0])).toEqual(['/agent-sessions/stop-for', '/ws/close'])
  })

  test("a withdrawn consent cancels with the owner's code", async () => {
    await onAccessReduced('P1', 'bob', 'consent_withdrawn', { ownerId: 'alice' })
    expect(h.jobs.find((j) => j.id === 'j-queued')).toMatchObject({ status: 'canceled', blockedCode: 'owner_consent_withdrawn' })
    expect(h.audit[0]).toMatchObject({ after: { reason: 'owner_consent_withdrawn', revocation: 'consent_withdrawn' } })
  })

  test("a live triage run the owner or someone else started is not stopped", async () => {
    h.live.mockResolvedValue({ id: 'run-1', actorUserId: 'alice' })
    expect((await onAccessReduced('P1', 'bob', 'share_revoked')).triage).toEqual({ stopped: 0 })
    h.live.mockResolvedValue(null)
    expect((await onAccessReduced('P1', 'bob', 'share_revoked')).triage).toEqual({ stopped: 0 })
    expect(h.stopRun).not.toHaveBeenCalled()
  })

  test('the owner given by the caller spares the project read', async () => {
    h.projects = []
    await onAccessReduced('P1', 'bob', 'consent_withdrawn', { ownerId: 'alice' })
    expect(h.stopRun).toHaveBeenCalledWith({ userId: 'alice', projectId: 'P1' }, 'app')
  })
})

describe('idempotence', () => {
  test('the same reduction twice: the second stops nothing and writes nothing', async () => {
    await onAccessReduced('P1', 'bob', 'share_revoked')
    const rows = h.audit.length
    h.agentFetch.mockImplementation(async (path: string) => ok(path === '/ws/close' ? { closed: 0, stopped_runs: 0 } : { stopped: 0 }))
    h.live.mockResolvedValue(null)
    const again = await onAccessReduced('P1', 'bob', 'share_revoked')
    expect(again).toMatchObject({ scans: { cancelled: 0 }, schedules: { paused: 0 }, triage: { stopped: 0 }, failed: [] })
    expect(h.audit.length).toBe(rows)
    expect(h.notice).toHaveBeenCalledTimes(1)
  })

  test('two at once: each job cancelled and each schedule paused once, one row and one notice each', async () => {
    const [a, b] = await Promise.all([onAccessReduced('P1', 'bob', 'share_revoked'), onAccessReduced('P1', 'bob', 'share_expired')])
    expect(((a.scans as { cancelled: number }).cancelled) + ((b.scans as { cancelled: number }).cancelled)).toBe(2)
    expect(((a.schedules as { paused: number }).paused) + ((b.schedules as { paused: number }).paused)).toBe(1)
    expect(h.audit.filter((r) => r.action === 'job_queue.cancelled')).toHaveLength(2)
    expect(h.audit.filter((r) => r.action === 'scan_schedule.paused')).toHaveLength(1)
    expect(h.notice).toHaveBeenCalledTimes(1)
  })

  test('a schedule confirmed by someone else meanwhile is not paused', async () => {
    h.schedules = [schedule('s1')]
    const confirm = vi.fn()
    h.notice.mockImplementation(confirm)
    // The owner confirms between the read and the pause: the schedule now runs as the owner.
    const read = (await import('@/lib/prisma')).default as unknown as { scanSchedule: { findMany: (a: unknown) => Promise<Schedule[]> } }
    const findMany = read.scanSchedule.findMany
    read.scanSchedule.findMany = async (a: unknown) => {
      const rows = await findMany(a)
      h.schedules[0].userId = 'alice'
      return rows
    }
    try {
      expect((await onAccessReduced('P1', 'bob', 'share_revoked')).schedules).toEqual({ paused: 0 })
    } finally {
      read.scanSchedule.findMany = findMany
    }
    expect(h.schedules[0]).toMatchObject({ enabled: true, userId: 'alice' })
    expect(confirm).not.toHaveBeenCalled()
  })
})

describe('the account', () => {
  test('capability removal applies to every project of the person', async () => {
    const out = await onAccessReduced(null, 'bob', 'capability_removed')
    expect(agentCalls()).toEqual([
      ['/agent-sessions/stop-for', { user_id: 'bob' }],
      ['/ws/close', { user_id: 'bob', kinds: KINDS, scope: 'account' }],
    ])
    expect(h.jobs.filter((j) => j.status === 'canceled').map((j) => j.id).sort()).toEqual(['j-other-project', 'j-queued', 'j-review'])
    expect(h.jobs.find((j) => j.id === 'j-other-person')!.status).toBe('queued')
    expect(h.schedules.filter((s) => !s.enabled).map((s) => s.id).sort()).toEqual(['s-off', 's-p2', 's1'])
    expect(h.stopRun.mock.calls).toEqual([[{ userId: 'alice', projectId: 'P1' }, 'app'], [{ userId: 'dave', projectId: 'P2' }, 'app']])
    expect(out).toMatchObject({ scans: { cancelled: 3 }, schedules: { paused: 2 }, triage: { stopped: 2 }, failed: [] })
    expect(h.endImpersonations).toHaveBeenCalledWith('bob', 'invalidated', { closeSockets: false })
  })

  test('a capability removal that leaves the scans allowed cancels none', async () => {
    h.refused = new Set()
    const out = await onAccessReduced(null, 'bob', 'capability_removed')
    expect(out).toMatchObject({ scans: { cancelled: 0 }, schedules: { paused: 0 } })
    expect(h.audit).toEqual([])
  })

  test("a disable keeps step 2.3's behaviour: runs stopped, every socket closed, deferred work left to its own check", async () => {
    const out = await onAccessReduced(null, 'bob', 'account_disabled')
    expect(agentCalls()).toEqual([
      ['/agent-sessions/stop-for', { user_id: 'bob' }],
      ['/ws/close', { user_id: 'bob', kinds: KINDS, scope: 'account' }],
    ])
    expect(agentWorkOf(out)).toEqual({ runs: { stopped: 1 }, sockets: { closed: 2 } })
    expect(out.scans).toBeUndefined()
    expect(h.jobs.every((j) => j.status !== 'canceled')).toBe(true)
    expect(h.live).not.toHaveBeenCalled()
    expect(h.endImpersonations).toHaveBeenCalledWith('bob', 'invalidated', { closeSockets: false })
  })

  test('a session-version bump closes every socket of the account and stops nothing else', async () => {
    for (const reason of ['sessions_revoked', 'credentials_reset', 'reset_link_used', 'root_transferred'] as const) {
      h.agentFetch.mockClear()
      h.endImpersonations.mockClear()
      const out = await onAccessReduced(null, 'bob', reason)
      expect(agentCalls()).toEqual([['/ws/close', { user_id: 'bob', kinds: KINDS, scope: 'account' }]])
      expect(agentWorkOf(out)).toEqual({ sockets: { closed: 2 } })
      expect(h.endImpersonations).toHaveBeenCalledTimes(1)
    }
    expect(h.audit).toEqual([])
  })

  test('with the permissions switch off no impersonation is ended', async () => {
    h.flags = { permissions: false }
    await onAccessReduced(null, 'bob', 'sessions_revoked')
    expect(h.endImpersonations).not.toHaveBeenCalled()
  })

  test("a device session's revoke closes the account's sockets with the default scope", async () => {
    await onAccessReduced(null, 'bob', 'device_session_revoked')
    expect(agentCalls()).toEqual([['/ws/close', { user_id: 'bob', kinds: KINDS, scope: 'access' }]])
    expect(h.endImpersonations).not.toHaveBeenCalled()
  })

  test('a lost legacy terminal grant closes the terminals only', async () => {
    const out = await onAccessReduced(null, 'bob', 'terminal_grant_removed')
    expect(agentCalls()).toEqual([['/ws/close', { user_id: 'bob', kinds: ['kali-terminal'], scope: 'access' }]])
    expect(out).toEqual({ sockets: { closed: 2 }, failed: [] })
  })

  test('a deleted account: every project, every socket, its deferred work cancelled and paused', async () => {
    const out = await onAccessReduced(null, 'bob', 'account_deleted')
    expect(agentCalls().map((c) => c[1])).toEqual([{ user_id: 'bob' }, { user_id: 'bob', kinds: KINDS, scope: 'account' }])
    expect(out).toMatchObject({ scans: { cancelled: 3 }, schedules: { paused: 2 }, triage: { stopped: 2 } })
  })

  test('the agent answering garbage or timing out is reported, never raised', async () => {
    h.agentFetch.mockResolvedValue(new Response('not json', { status: 200 }))
    expect(agentWorkOf(await onAccessReduced(null, 'bob', 'account_disabled'))).toEqual({ runs: { stopped: 0 }, sockets: { closed: 0 } })
    h.agentFetch.mockRejectedValue(Object.assign(new Error('timed out'), { name: 'TimeoutError' }))
    const out = await onAccessReduced(null, 'bob', 'account_disabled')
    expect(agentWorkOf(out)).toEqual({ runs: { error: 'TimeoutError' }, sockets: { error: 'TimeoutError' } })
    expect(out.failed).toEqual(['stop_runs', 'close_sockets'])
  })
})

describe('the plans', () => {
  test('every project reason stops runs, sockets, deferred scans and triage on that project only', () => {
    for (const reason of ['share_revoked', 'share_left', 'share_expired', 'share_force_revoked', 'share_reduced', 'consent_withdrawn'] as const) {
      expect(PLANS[reason]).toMatchObject({ stopRuns: true, closeScope: 'access', deferredScans: true, triage: true, endImpersonations: false })
      expect(PLANS[reason].kinds).toEqual(KINDS)
    }
  })

  test('a share change narrows when the level drops or a toggle turns off', () => {
    expect(isAccessReduction({ access: 'write', useAgent: true }, { access: 'read', useAgent: true })).toBe(true)
    expect(isAccessReduction({ access: 'read', rawData: true }, { access: 'read', rawData: false })).toBe(true)
    for (const t of ['runScans', 'useAgent', 'exploit', 'manage'] as const) {
      expect(isAccessReduction({ access: 'write', [t]: true }, { access: 'write', [t]: false })).toBe(true)
    }
    expect(isAccessReduction({ access: 'read', rawData: false }, { access: 'read', rawData: true })).toBe(false)
    expect(isAccessReduction({ access: 'read' }, { access: 'write' })).toBe(false)
    expect(isAccessReduction({ access: 'read', rawData: true }, { access: 'read', rawData: true })).toBe(false)
  })
})
